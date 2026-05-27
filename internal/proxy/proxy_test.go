package proxy

import (
	"context"
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/example/subgw/internal/banlist"
	"github.com/example/subgw/internal/config"
	"github.com/example/subgw/internal/detector"
	"github.com/example/subgw/internal/faker"
	"github.com/example/subgw/internal/store"
	"github.com/example/subgw/internal/token"
)

func newE2E(t *testing.T, observe bool, extraRules ...config.Rule) (*Gateway, *httptest.Server, *store.Store, *banlist.List, func()) {
	t.Helper()

	// fake upstream
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(200)
		_, _ = io.WriteString(w, "REAL-SUB-FROM-V2BOARD ip="+r.Header.Get("X-Forwarded-For"))
	}))

	upURL, _ := url.Parse(upstream.URL)

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "e2e.db")
	saltPath := filepath.Join(dir, "salt")

	cfg := &config.Config{
		Listen:       "127.0.0.1:0",
		AdminListen:  "127.0.0.1:0",
		HMACSaltFile: saltPath,
		Storage: config.Storage{
			SQLitePath:         dbPath,
			BatchFlushInterval: config.Duration(50 * time.Millisecond),
			BatchFlushSize:     5,
			Retention: config.Retention{
				Events:    config.Duration(time.Hour),
				Incidents: config.Duration(time.Hour),
			},
		},
		RealIP: config.RealIP{
			TrustProxies: []string{"127.0.0.1"},
			TrustHeaders: []string{"X-Real-IP"},
		},
		Paths: config.Paths{Subscribe: []string{"/api/v1/client/subscribe"}},
		Tenants: []config.Tenant{
			{Name: "default", Host: "sub.example.com", Upstream: upURL.String()},
		},
		Detector: config.DetectorCfg{
			ObserveOnly: observe,
			Rules: append([]config.Rule{
				{
					Name: "tf_red", When: config.When{TokenFreq: &config.Cond{Window: config.Duration(time.Minute), GTE: 5}}, Severity: "red",
				},
				{
					Name: "bad_ua", When: config.When{UAMatchAny: []string{"^curl/"}}, Severity: "orange",
				},
			}, extraRules...),
		},
		Actions: config.ActionsCfg{Yellow: "slow", Orange: "fake", Red: "deny"},
		Faker:   config.FakerCfg{NodeCount: 3, BlackholeIPs: []string{"192.0.2.1"}},
	}

	salt, err := token.LoadOrCreateSalt(saltPath)
	if err != nil {
		t.Fatal(err)
	}
	hasher := token.NewHasher(salt)
	st, err := store.Open(dbPath, 50*time.Millisecond, 5)
	if err != nil {
		t.Fatal(err)
	}
	bans := banlist.New(st)
	_ = bans.LoadFromStore(context.Background())
	det, err := detector.New(&cfg.Detector)
	if err != nil {
		t.Fatal(err)
	}
	fk := faker.New(cfg.Faker.BlackholeIPs, cfg.Faker.NodeCount)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	gw, err := NewGateway(cfg, hasher, st, bans, det, fk, nil, AutoBanCfg{OnRed: true, IPTTL: time.Hour, TokenTTL: time.Hour}, logger)
	if err != nil {
		t.Fatal(err)
	}

	cleanup := func() {
		upstream.Close()
		_ = st.Close()
		_ = os.RemoveAll(dir)
	}
	return gw, upstream, st, bans, cleanup
}

func mkSubReq(host, ua, tok, flag, realIP string) *http.Request {
	q := url.Values{}
	if tok != "" {
		q.Set("token", tok)
	}
	if flag != "" {
		q.Set("flag", flag)
	}
	r := httptest.NewRequest("GET", "http://"+host+"/api/v1/client/subscribe?"+q.Encode(), nil)
	r.Host = host
	r.RemoteAddr = "127.0.0.1:55555"
	if ua != "" {
		r.Header.Set("User-Agent", ua)
	}
	if realIP != "" {
		r.Header.Set("X-Real-IP", realIP)
	}
	return r
}

func TestE2EPassNormalRequest(t *testing.T) {
	gw, _, _, _, cleanup := newE2E(t, false)
	defer cleanup()

	w := httptest.NewRecorder()
	gw.ServeHTTP(w, mkSubReq("sub.example.com", "ClashforWindows/0.20", "user1", "clash", "8.8.8.8"))

	if w.Code != 200 {
		t.Errorf("status: %d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "REAL-SUB-FROM-V2BOARD") {
		t.Errorf("did not reach upstream: %q", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "8.8.8.8") {
		t.Errorf("X-Forwarded-For not propagated: %q", w.Body.String())
	}
}

func TestE2EUnknownTenantReturns404(t *testing.T) {
	gw, _, _, _, cleanup := newE2E(t, false)
	defer cleanup()

	w := httptest.NewRecorder()
	gw.ServeHTTP(w, mkSubReq("nope.example.com", "ClashforWindows/0.20", "u", "clash", ""))
	if w.Code != 404 {
		t.Errorf("expected 404 for unknown tenant, got %d", w.Code)
	}
}

func TestE2EBadUAReturnsFake(t *testing.T) {
	gw, _, _, _, cleanup := newE2E(t, false)
	defer cleanup()

	w := httptest.NewRecorder()
	gw.ServeHTTP(w, mkSubReq("sub.example.com", "curl/8.0", "user1", "ss", "9.9.9.9"))
	if w.Code != 200 {
		t.Errorf("fake should return 200, got %d", w.Code)
	}
	if strings.Contains(w.Body.String(), "REAL-SUB-FROM-V2BOARD") {
		t.Error("upstream should not be hit for fake")
	}
	// 验证返回的是有效 SS base64
	if _, err := base64.StdEncoding.DecodeString(w.Body.String()); err != nil {
		t.Errorf("body not valid base64: %v", err)
	}
}

func TestE2EHighTokenFreqRedDenyAndBan(t *testing.T) {
	gw, _, _, bans, cleanup := newE2E(t, false)
	defer cleanup()

	// 5 个请求后触发 red(token_freq >=5)
	for i := 0; i < 5; i++ {
		w := httptest.NewRecorder()
		gw.ServeHTTP(w, mkSubReq("sub.example.com", "ClientApp/1.0", "samesubtoken", "clash", "10.0.0.1"))
	}
	// 第 5 次应当 deny
	// 给点时间让 banlist 持久化
	time.Sleep(50 * time.Millisecond)
	// 第 6 次:IP 应该已经在 banlist
	w := httptest.NewRecorder()
	gw.ServeHTTP(w, mkSubReq("sub.example.com", "ClientApp/1.0", "samesubtoken", "clash", "10.0.0.1"))
	if w.Code != 403 {
		t.Errorf("expected 403 after ban, got %d", w.Code)
	}
	if banned, _ := bans.CheckIP("10.0.0.1"); !banned {
		t.Errorf("IP 10.0.0.1 should be banned")
	}
}

func TestE2EObserveOnly(t *testing.T) {
	gw, _, _, _, cleanup := newE2E(t, true)
	defer cleanup()

	// observe_only 下,curl UA 命中规则但不该 fake
	w := httptest.NewRecorder()
	gw.ServeHTTP(w, mkSubReq("sub.example.com", "curl/8.0", "tok", "ss", ""))
	if w.Code != 200 {
		t.Errorf("status: %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "REAL-SUB-FROM-V2BOARD") {
		t.Errorf("observe_only should pass through, got %q", w.Body.String())
	}
}

func TestE2EManualBan(t *testing.T) {
	gw, _, _, bans, cleanup := newE2E(t, false)
	defer cleanup()

	_ = bans.AddIP("7.7.7.7", "manual", time.Hour, nil, "test")

	w := httptest.NewRecorder()
	gw.ServeHTTP(w, mkSubReq("sub.example.com", "ClashforWindows/0.20", "t", "clash", "7.7.7.7"))
	if w.Code != 403 {
		t.Errorf("expected 403 for banned IP, got %d", w.Code)
	}
}

func TestE2EEventsPersisted(t *testing.T) {
	gw, _, st, _, cleanup := newE2E(t, false)
	defer cleanup()

	w := httptest.NewRecorder()
	gw.ServeHTTP(w, mkSubReq("sub.example.com", "ClashforWindows/0.20", "tttt", "clash", "8.8.8.8"))

	// 等 batch flush
	time.Sleep(200 * time.Millisecond)
	evs, err := st.QueryEvents(context.Background(), store.EventFilter{Tenant: "default"})
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) == 0 {
		t.Fatal("event not persisted")
	}
	e := evs[0]
	if e.ClientIP != "8.8.8.8" || e.Action != "pass" || e.Flag != "clash" {
		t.Errorf("unexpected event: %+v", e)
	}
	// token 必须是 hash,不是原文
	if e.TokenHash == "tttt" || e.TokenHash == "" {
		t.Errorf("token not hashed: %q", e.TokenHash)
	}
	if len(e.TokenHash) != 64 {
		t.Errorf("expected 64-char hex hash, got len=%d", len(e.TokenHash))
	}
}
