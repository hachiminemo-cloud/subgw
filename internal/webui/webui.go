// Package webui 是管理面 HTTP server,内嵌 HTML/JS,登录后访问。
package webui

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/example/subgw/internal/banlist"
	"github.com/example/subgw/internal/cloudip"
	"github.com/example/subgw/internal/config"
	"github.com/example/subgw/internal/notifier"
	"github.com/example/subgw/internal/rules"
	"github.com/example/subgw/internal/store"
	"github.com/example/subgw/internal/token"
)

//go:embed assets/*
var assets embed.FS

type Server struct {
	cfg       *config.Config
	st        *store.Store
	bans      *banlist.List
	hasher    *token.Hasher
	notif     *notifier.Notifier
	cloud     *cloudip.Matcher
	fetcher   *cloudip.Fetcher
	rules     *rules.Manager
	hmacKey   []byte
	sessionMu sync.RWMutex
	sessions  map[string]session
	logger    *slog.Logger
}

type session struct {
	user    string
	expires time.Time
}

func NewServer(cfg *config.Config, st *store.Store, bans *banlist.List, hasher *token.Hasher,
	notif *notifier.Notifier, cloud *cloudip.Matcher, fetcher *cloudip.Fetcher,
	rulesMgr *rules.Manager, logger *slog.Logger) *Server {
	key := []byte(cfg.Admin.SessionKey)
	if len(key) == 0 {
		key = make([]byte, 32)
		_, _ = rand.Read(key)
	}
	return &Server{
		cfg:      cfg,
		st:       st,
		bans:     bans,
		hasher:   hasher,
		notif:    notif,
		cloud:    cloud,
		fetcher:  fetcher,
		rules:    rulesMgr,
		hmacKey:  key,
		sessions: map[string]session{},
		logger:   logger,
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// 静态资源
	sub, _ := fs.Sub(assets, "assets")
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(sub))))

	// 公开
	mux.HandleFunc("/login", s.loginPage)
	mux.HandleFunc("/api/login", s.apiLogin)
	mux.HandleFunc("/api/logout", s.apiLogout)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, map[string]any{"ok": true}) })

	// 需要登录
	mux.Handle("/", s.auth(http.HandlerFunc(s.indexPage)))
	mux.Handle("/api/summary", s.auth(http.HandlerFunc(s.apiSummary)))
	mux.Handle("/api/events", s.auth(http.HandlerFunc(s.apiEvents)))
	mux.Handle("/api/incidents", s.auth(http.HandlerFunc(s.apiIncidents)))
	mux.Handle("/api/bans", s.auth(http.HandlerFunc(s.apiBans)))
	mux.Handle("/api/bans/add", s.auth(http.HandlerFunc(s.apiBanAdd)))
	mux.Handle("/api/bans/remove", s.auth(http.HandlerFunc(s.apiBanRemove)))
	mux.Handle("/api/tenants", s.auth(http.HandlerFunc(s.apiTenants)))
	mux.Handle("/api/config", s.auth(http.HandlerFunc(s.apiConfig)))
	mux.Handle("/api/test-notify", s.auth(http.HandlerFunc(s.apiTestNotify)))
	mux.Handle("/api/notifier", s.auth(http.HandlerFunc(s.apiNotifierGet)))
	mux.Handle("/api/notifier/update", s.auth(http.HandlerFunc(s.apiNotifierUpdate)))
	mux.Handle("/api/hash-token", s.auth(http.HandlerFunc(s.apiHashToken)))

	// UA 规则
	mux.Handle("/api/ua-rules", s.auth(http.HandlerFunc(s.apiUARulesList)))
	mux.Handle("/api/ua-rules/add", s.auth(http.HandlerFunc(s.apiUARulesAdd)))
	mux.Handle("/api/ua-rules/remove", s.auth(http.HandlerFunc(s.apiUARulesRemove)))

	// IP 白名单
	mux.Handle("/api/ip-whitelist", s.auth(http.HandlerFunc(s.apiIPWhitelistList)))
	mux.Handle("/api/ip-whitelist/add", s.auth(http.HandlerFunc(s.apiIPWhitelistAdd)))
	mux.Handle("/api/ip-whitelist/remove", s.auth(http.HandlerFunc(s.apiIPWhitelistRemove)))

	// 云 IP 库
	mux.Handle("/api/cloud-ip", s.auth(http.HandlerFunc(s.apiCloudIP)))
	mux.Handle("/api/cloud-ip/refresh", s.auth(http.HandlerFunc(s.apiCloudIPRefresh)))
	mux.Handle("/api/cloud-ip/check", s.auth(http.HandlerFunc(s.apiCloudIPCheck)))

	return mux
}

// ---------- 认证 ----------

func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("subgw_sess")
		if err != nil || c.Value == "" {
			s.redirectLogin(w, r)
			return
		}
		s.sessionMu.RLock()
		sess, ok := s.sessions[c.Value]
		s.sessionMu.RUnlock()
		if !ok || time.Now().After(sess.expires) {
			s.redirectLogin(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) redirectLogin(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		writeJSON(w, 401, map[string]any{"error": "unauthenticated"})
		return
	}
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (s *Server) apiLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeJSON(w, 405, map[string]any{"error": "POST only"})
		return
	}
	var body struct{ Username, Password string }
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	if body.Username != s.cfg.Admin.Username {
		writeJSON(w, 401, map[string]any{"error": "invalid credentials"})
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(s.cfg.Admin.PasswordHash), []byte(body.Password)); err != nil {
		writeJSON(w, 401, map[string]any{"error": "invalid credentials"})
		return
	}
	// 生成 session id
	raw := make([]byte, 24)
	_, _ = rand.Read(raw)
	id := hex.EncodeToString(raw)
	ttl := s.cfg.Admin.SessionTTL.Std()
	s.sessionMu.Lock()
	s.sessions[id] = session{user: body.Username, expires: time.Now().Add(ttl)}
	// gc 过期
	now := time.Now()
	for k, v := range s.sessions {
		if now.After(v.expires) {
			delete(s.sessions, k)
		}
	}
	s.sessionMu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name:     "subgw_sess",
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(ttl),
	})
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) apiLogout(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("subgw_sess")
	if err == nil {
		s.sessionMu.Lock()
		delete(s.sessions, c.Value)
		s.sessionMu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "subgw_sess", Value: "", Path: "/", MaxAge: -1})
	writeJSON(w, 200, map[string]any{"ok": true})
}

// ---------- API ----------

func (s *Server) apiSummary(w http.ResponseWriter, r *http.Request) {
	tenant := r.URL.Query().Get("tenant")
	winStr := r.URL.Query().Get("window")
	dur, err := time.ParseDuration(winStr)
	if err != nil || dur <= 0 {
		dur = 24 * time.Hour
	}
	st, err := s.st.Summary(r.Context(), tenant, time.Now().Add(-dur))
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, st)
}

func (s *Server) apiEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	winStr := q.Get("window")
	dur, _ := time.ParseDuration(winStr)
	if dur <= 0 {
		dur = 24 * time.Hour
	}
	f := store.EventFilter{
		Tenant:    q.Get("tenant"),
		ClientIP:  q.Get("ip"),
		TokenHash: q.Get("token"),
		Action:    q.Get("action"),
		Since:     time.Now().Add(-dur),
		Limit:     limit,
		Offset:    offset,
	}
	evs, err := s.st.QueryEvents(r.Context(), f)
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, evs)
}

func (s *Server) apiIncidents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	winStr := q.Get("window")
	dur, _ := time.ParseDuration(winStr)
	if dur <= 0 {
		dur = 7 * 24 * time.Hour
	}
	f := store.IncidentFilter{
		Tenant:   q.Get("tenant"),
		Severity: q.Get("severity"),
		Since:    time.Now().Add(-dur),
		Limit:    limit,
		Offset:   offset,
	}
	ins, err := s.st.QueryIncidents(r.Context(), f)
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, ins)
}

func (s *Server) apiBans(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	bs, err := s.st.ListActiveBans(ctx)
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, bs)
}

func (s *Server) apiBanAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeJSON(w, 405, map[string]any{"error": "POST only"})
		return
	}
	var body struct {
		Kind   string `json:"kind"`
		Target string `json:"target"`
		Reason string `json:"reason"`
		TTL    string `json:"ttl"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	if body.Target == "" {
		writeJSON(w, 400, map[string]any{"error": "target is required"})
		return
	}
	var ttl time.Duration
	if body.TTL != "" {
		t, err := time.ParseDuration(body.TTL)
		if err != nil {
			writeJSON(w, 400, map[string]any{"error": "bad ttl: " + err.Error()})
			return
		}
		ttl = t
	}
	var err error
	switch body.Kind {
	case "ip":
		err = s.bans.AddIP(body.Target, body.Reason, ttl, nil, "manual")
	case "token":
		err = s.bans.AddToken(body.Target, body.Reason, ttl, nil, "manual")
	default:
		writeJSON(w, 400, map[string]any{"error": "kind must be ip|token"})
		return
	}
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) apiBanRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeJSON(w, 405, map[string]any{"error": "POST only"})
		return
	}
	var body struct{ Kind, Target string }
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	var err error
	switch body.Kind {
	case "ip":
		err = s.bans.RemoveIP(body.Target)
	case "token":
		err = s.bans.RemoveToken(body.Target)
	default:
		writeJSON(w, 400, map[string]any{"error": "kind must be ip|token"})
		return
	}
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) apiTenants(w http.ResponseWriter, r *http.Request) {
	out := []map[string]string{}
	for _, t := range s.cfg.Tenants {
		out = append(out, map[string]string{"name": t.Name, "host": t.Host, "upstream": t.Upstream})
	}
	writeJSON(w, 200, out)
}

func (s *Server) apiConfig(w http.ResponseWriter, r *http.Request) {
	// 只回显非敏感字段
	out := map[string]any{
		"listen":       s.cfg.Listen,
		"admin_listen": s.cfg.AdminListen,
		"detector": map[string]any{
			"observe_only": s.cfg.Detector.ObserveOnly,
			"rules":        s.cfg.Detector.Rules,
			"whitelist":    s.cfg.Detector.Whitelist,
		},
		"actions": s.cfg.Actions,
		"paths":   s.cfg.Paths,
		"faker":   s.cfg.Faker,
	}
	writeJSON(w, 200, out)
}

func (s *Server) apiTestNotify(w http.ResponseWriter, r *http.Request) {
	if s.notif == nil {
		writeJSON(w, 400, map[string]any{"error": "notifier disabled"})
		return
	}
	if err := s.notif.NotifyTest(); err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// apiNotifierGet 回显当前 Telegram 配置;bot_token 部分脱敏。
func (s *Server) apiNotifierGet(w http.ResponseWriter, r *http.Request) {
	if s.notif == nil {
		writeJSON(w, 200, map[string]any{"enabled": false, "has_token": false, "chat_id": "", "throttle": "5m"})
		return
	}
	en, bot, chat, throttle := s.notif.Snapshot()
	writeJSON(w, 200, map[string]any{
		"enabled":          en,
		"has_token":        bot != "",
		"bot_token_masked": maskToken(bot),
		"chat_id":          chat,
		"throttle":         throttle.String(),
	})
}

// apiNotifierUpdate 持久化 + 热生效。
// body: {enabled, bot_token, chat_id, throttle}。bot_token 为空表示「不修改」(避免误清空)。
// 想真正清空时,传 "__clear__"。
func (s *Server) apiNotifierUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeJSON(w, 405, map[string]any{"error": "POST only"})
		return
	}
	if s.notif == nil {
		writeJSON(w, 400, map[string]any{"error": "notifier unavailable"})
		return
	}
	var body struct {
		Enabled  bool   `json:"enabled"`
		BotToken string `json:"bot_token"`
		ChatID   string `json:"chat_id"`
		Throttle string `json:"throttle"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	// 拿当前值,部分字段没传就保留
	curEn, curBot, curChat, curThrottle := s.notif.Snapshot()

	newBot := curBot
	if body.BotToken == "__clear__" {
		newBot = ""
	} else if body.BotToken != "" {
		newBot = strings.TrimSpace(body.BotToken)
	}
	newChat := strings.TrimSpace(body.ChatID)
	if newChat == "" && curChat != "" && body.ChatID == "" {
		// 没传 → 保留
		newChat = curChat
	}
	newThrottle := curThrottle
	if body.Throttle != "" {
		d, err := time.ParseDuration(body.Throttle)
		if err != nil {
			writeJSON(w, 400, map[string]any{"error": "bad throttle: " + err.Error()})
			return
		}
		newThrottle = d
	}
	_ = curEn // 显式忽略,前端必须传 enabled

	// 落库
	if err := s.st.SetMeta("tg_enabled", boolStr(body.Enabled)); err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	if err := s.st.SetMeta("tg_bot_token", newBot); err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	if err := s.st.SetMeta("tg_chat_id", newChat); err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	if err := s.st.SetMeta("tg_throttle", newThrottle.String()); err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	// 热生效
	s.notif.Configure(body.Enabled, newBot, newChat, newThrottle)
	writeJSON(w, 200, map[string]any{"ok": true})
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func maskToken(t string) string {
	if t == "" {
		return ""
	}
	if len(t) <= 8 {
		return strings.Repeat("*", len(t))
	}
	return t[:4] + strings.Repeat("*", len(t)-8) + t[len(t)-4:]
}

// -------- UA 规则 --------

func (s *Server) apiUARulesList(w http.ResponseWriter, r *http.Request) {
	kind := r.URL.Query().Get("kind") // ""|"blacklist"|"whitelist"
	rs, err := s.st.ListUARules(kind)
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, rs)
}

func (s *Server) apiUARulesAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeJSON(w, 405, map[string]any{"error": "POST only"})
		return
	}
	var body struct {
		Kind, Pattern, Note string
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	if body.Pattern == "" {
		writeJSON(w, 400, map[string]any{"error": "pattern required"})
		return
	}
	if body.Kind != "blacklist" && body.Kind != "whitelist" {
		writeJSON(w, 400, map[string]any{"error": "kind must be blacklist|whitelist"})
		return
	}
	if err := s.rules.AddUARule(body.Kind, body.Pattern, body.Note); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) apiUARulesRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeJSON(w, 405, map[string]any{"error": "POST only"})
		return
	}
	var body struct{ ID int64 }
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	if err := s.rules.DeleteUARule(body.ID); err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// -------- IP 白名单 --------

func (s *Server) apiIPWhitelistList(w http.ResponseWriter, r *http.Request) {
	es, err := s.st.ListIPWhitelist()
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, es)
}

func (s *Server) apiIPWhitelistAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeJSON(w, 405, map[string]any{"error": "POST only"})
		return
	}
	var body struct{ Target, Note string }
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	if err := s.rules.AddIPWhitelist(body.Target, body.Note); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) apiIPWhitelistRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeJSON(w, 405, map[string]any{"error": "POST only"})
		return
	}
	var body struct{ ID int64 }
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	if err := s.rules.DeleteIPWhitelist(body.ID); err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// -------- 云 IP 库 --------

func (s *Server) apiCloudIP(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.cloud.Snapshot())
}

func (s *Server) apiCloudIPRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeJSON(w, 405, map[string]any{"error": "POST only"})
		return
	}
	if s.fetcher == nil {
		writeJSON(w, 503, map[string]any{"error": "fetcher unavailable"})
		return
	}
	// 异步触发,避免 UI 等太久
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		if _, err := s.fetcher.RunOnce(ctx); err != nil {
			s.logger.Warn("cloudip manual refresh failed", "err", err)
		}
	}()
	writeJSON(w, 200, map[string]any{"ok": true, "started": true})
}

// apiCloudIPCheck:给定 IP,查它是否在云 IP 库里
func (s *Server) apiCloudIPCheck(w http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	hit, prov := s.cloud.Match(ip)
	writeJSON(w, 200, map[string]any{"ip": ip, "hit": hit, "provider": prov})
}

// 给原文 token 算 hash,便于管理员手动加 token 封禁
func (s *Server) apiHashToken(w http.ResponseWriter, r *http.Request) {
	tok := r.URL.Query().Get("token")
	writeJSON(w, 200, map[string]any{"hash": s.hasher.Hash(tok)})
}

// ---------- 页面 ----------

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	b, err := assets.ReadFile("assets/login.html")
	if err != nil {
		http.Error(w, "missing login page", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(b)
}

func (s *Server) indexPage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" && !strings.HasPrefix(r.URL.Path, "/static/") && r.URL.Path != "/index.html" {
		http.NotFound(w, r)
		return
	}
	b, err := assets.ReadFile("assets/index.html")
	if err != nil {
		http.Error(w, "missing index page", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(b)
}

// ---------- helpers ----------

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

// 用于将来的 cookie 签名(目前未启用)
func signCookie(key []byte, val string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(val))
	return val + "." + hex.EncodeToString(mac.Sum(nil))
}

// avoid unused warning
var _ = fmt.Sprintf
