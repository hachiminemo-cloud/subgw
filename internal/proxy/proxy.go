// Package proxy 是网关核心 HTTP handler:
// 解析 → banlist → detector.Observe → detector.Evaluate → judge → 执行。
package proxy

import (
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync/atomic"
	"time"

	"github.com/example/subgw/internal/banlist"
	"github.com/example/subgw/internal/config"
	"github.com/example/subgw/internal/detector"
	"github.com/example/subgw/internal/faker"
	"github.com/example/subgw/internal/judge"
	"github.com/example/subgw/internal/notifier"
	"github.com/example/subgw/internal/parser"
	"github.com/example/subgw/internal/store"
	"github.com/example/subgw/internal/token"
)

type Gateway struct {
	cfg      *config.Config
	hasher   *token.Hasher
	st       *store.Store
	bans     *banlist.List
	det      *detector.Detector
	faker    *faker.Renderer
	notif    *notifier.Notifier
	proxies  map[string]*httputil.ReverseProxy // tenant.name -> proxy
	rng      *rand.Rand
	autoBan  AutoBanCfg
	requests atomic.Uint64
	logger   *slog.Logger
}

type AutoBanCfg struct {
	OnRed    bool          // red 级别命中自动加 banlist
	IPTTL    time.Duration // IP 封禁 TTL
	TokenTTL time.Duration // token 封禁 TTL
}

func NewGateway(
	cfg *config.Config, hasher *token.Hasher, st *store.Store, bans *banlist.List,
	det *detector.Detector, fk *faker.Renderer, notif *notifier.Notifier,
	autoBan AutoBanCfg, logger *slog.Logger,
) (*Gateway, error) {
	g := &Gateway{
		cfg: cfg, hasher: hasher, st: st, bans: bans, det: det,
		faker: fk, notif: notif, autoBan: autoBan,
		proxies: map[string]*httputil.ReverseProxy{},
		rng:     rand.New(rand.NewSource(time.Now().UnixNano())),
		logger:  logger,
	}
	for _, t := range cfg.Tenants {
		u, err := url.Parse(t.Upstream)
		if err != nil {
			return nil, fmt.Errorf("tenant %s upstream %s: %w", t.Name, t.Upstream, err)
		}
		rp := httputil.NewSingleHostReverseProxy(u)
		baseDir := rp.Director
		host := u.Host
		rp.Director = func(req *http.Request) {
			baseDir(req)
			req.Host = host
		}
		rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
			logger.Warn("upstream error", "err", err, "host", r.Host)
			http.Error(w, "upstream unavailable", http.StatusBadGateway)
		}
		g.proxies[t.Name] = rp
	}
	return g, nil
}

func (g *Gateway) Requests() uint64 { return g.requests.Load() }

// ServeHTTP 是顶层 handler。
func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g.requests.Add(1)
	start := time.Now()

	pr := parser.Parse(r, g.cfg)

	// 1) tenant 不存在 → 404
	if pr.Tenant == nil {
		http.Error(w, "not found", http.StatusNotFound)
		g.logEvent(pr, "", "deny", http.StatusNotFound, nil, 0, int64(len("not found\n")), start)
		return
	}

	// 2) 非订阅路径 → 404,不透传(防止 V2board 其他端点经我们泄露)
	if !pr.IsSubPath {
		http.Error(w, "not found", http.StatusNotFound)
		g.logEvent(pr, "", "block_path", http.StatusNotFound, []string{"non_sub_path"}, 0, int64(len("not found\n")), start)
		return
	}

	tokenHash := g.hasher.Hash(pr.Token)

	// 3) banlist 检查
	if banned, reason := g.bans.CheckIP(pr.ClientIP); banned {
		g.handleDeny(w, r, pr, tokenHash, "banlist_ip:"+reason, start)
		return
	}
	if banned, reason := g.bans.CheckToken(tokenHash); banned {
		g.handleDeny(w, r, pr, tokenHash, "banlist_token:"+reason, start)
		return
	}

	// 4) detector observe(把当前请求算进窗口)
	g.det.Observe(pr.ClientIP, tokenHash, pr.UA)

	// 5) evaluate
	res := g.det.Evaluate(pr.ClientIP, tokenHash, pr.UA)

	// 6) judge
	dec := judge.Decide(g.cfg, res)

	// 7) 记 incident(如有命中)
	if res.Severity != detector.SevNone {
		g.st.SubmitIncident(store.Incident{
			TS:        time.Now(),
			Tenant:    pr.Tenant.Name,
			Severity:  string(res.Severity),
			ClientIP:  pr.ClientIP,
			TokenHash: tokenHash,
			RuleTags:  res.Tags,
			Action:    string(dec.Action),
			Note:      res.Note,
		})
	}

	// 8) 红色自动封禁
	if res.Severity == detector.SevRed && g.autoBan.OnRed {
		if g.autoBan.IPTTL > 0 {
			_ = g.bans.AddIP(pr.ClientIP, "auto:"+res.Note, g.autoBan.IPTTL, res.Tags, "auto")
		}
		if tokenHash != "" && g.autoBan.TokenTTL > 0 {
			_ = g.bans.AddToken(tokenHash, "auto:"+res.Note, g.autoBan.TokenTTL, res.Tags, "auto")
		}
		if g.notif != nil {
			g.notif.NotifyBan(pr.Tenant.Name, pr.ClientIP, tokenHash, res.Tags, res.Note)
		}
	}

	// 9) 执行
	switch dec.Action {
	case judge.ActPass:
		g.transparentProxyWithLog(w, r, pr, tokenHash, res.Tags, "pass", start)
	case judge.ActSlow:
		// 随机 1-5 秒
		time.Sleep(time.Duration(1000+g.rng.Intn(4000)) * time.Millisecond)
		g.transparentProxyWithLog(w, r, pr, tokenHash, res.Tags, "slow", start)
	case judge.ActFake:
		g.respondFake(w, r, pr, tokenHash, res.Tags, start)
	case judge.ActDeny:
		g.handleDeny(w, r, pr, tokenHash, res.Note, start)
	default:
		g.transparentProxyWithLog(w, r, pr, tokenHash, res.Tags, "pass", start)
	}
}

// 带日志的反代
func (g *Gateway) transparentProxyWithLog(
	w http.ResponseWriter, r *http.Request, pr *parser.Request,
	tokenHash string, tags []string, action string, start time.Time,
) {
	rp := g.proxies[pr.Tenant.Name]
	if rp == nil {
		http.Error(w, "no upstream", http.StatusBadGateway)
		return
	}
	// 标记 X-Forwarded-For
	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		r.Header.Set("X-Forwarded-For", pr.ClientIP)
	} else {
		r.Header.Set("X-Forwarded-For", xff+", "+pr.ClientIP)
	}

	// 用 ResponseWriter wrapper 抓状态码和长度
	rw := &capturingWriter{ResponseWriter: w, status: 200}
	rp.ServeHTTP(rw, r)

	upstreamMS := time.Since(start).Milliseconds()
	g.st.SubmitEvent(store.Event{
		TS:         start,
		Tenant:     pr.Tenant.Name,
		ClientIP:   pr.ClientIP,
		UA:         pr.UA,
		TokenHash:  tokenHash,
		Flag:       pr.Flag,
		Path:       pr.Path,
		Status:     rw.status,
		Action:     action,
		RuleTags:   tags,
		UpstreamMS: upstreamMS,
		RespSize:   rw.size,
	})
}

func (g *Gateway) respondFake(
	w http.ResponseWriter, r *http.Request, pr *parser.Request,
	tokenHash string, tags []string, start time.Time,
) {
	out := g.faker.Render(pr.Flag, pr.UA)
	for k, v := range out.Headers {
		w.Header().Set(k, v)
	}
	w.Header().Set("Content-Type", out.ContentType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(out.Body)

	g.st.SubmitEvent(store.Event{
		TS:        start,
		Tenant:    pr.Tenant.Name,
		ClientIP:  pr.ClientIP,
		UA:        pr.UA,
		TokenHash: tokenHash,
		Flag:      pr.Flag,
		Path:      pr.Path,
		Status:    200,
		Action:    "fake",
		RuleTags:  tags,
		RespSize:  int64(len(out.Body)),
	})
}

func (g *Gateway) handleDeny(
	w http.ResponseWriter, r *http.Request, pr *parser.Request,
	tokenHash string, note string, start time.Time,
) {
	// 默认返回 403。如果想更隐蔽可以改成假节点,这里给配置项决定
	w.WriteHeader(http.StatusForbidden)
	body := []byte("forbidden")
	_, _ = w.Write(body)
	g.logEvent(pr, tokenHash, "deny", http.StatusForbidden, []string{"deny:" + note}, 0, int64(len(body)), start)
}

// logEvent 仅落库,不写响应。
func (g *Gateway) logEvent(
	pr *parser.Request,
	tokenHash, action string, status int, tags []string, upstreamMS int64,
	respSize int64, start time.Time,
) {
	tenantName := ""
	if pr != nil && pr.Tenant != nil {
		tenantName = pr.Tenant.Name
	} else if pr != nil {
		tenantName = "_unmatched"
	}
	clientIP, ua, flag, path := "", "", "", ""
	if pr != nil {
		clientIP, ua, flag, path = pr.ClientIP, pr.UA, pr.Flag, pr.Path
	}
	g.st.SubmitEvent(store.Event{
		TS:         start,
		Tenant:     tenantName,
		ClientIP:   clientIP,
		UA:         ua,
		TokenHash:  tokenHash,
		Flag:       flag,
		Path:       path,
		Status:     status,
		Action:     action,
		RuleTags:   tags,
		UpstreamMS: upstreamMS,
		RespSize:   respSize,
	})
}

// ----- helpers -----

type capturingWriter struct {
	http.ResponseWriter
	status    int
	size      int64
	wroteHead bool
}

func (c *capturingWriter) WriteHeader(code int) {
	c.status = code
	c.wroteHead = true
	c.ResponseWriter.WriteHeader(code)
}

func (c *capturingWriter) Write(p []byte) (int, error) {
	if !c.wroteHead {
		c.status = http.StatusOK
		c.wroteHead = true
	}
	n, err := c.ResponseWriter.Write(p)
	c.size += int64(n)
	return n, err
}

// 静态 healthz
func Healthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, `{"ok":true}`)
}
