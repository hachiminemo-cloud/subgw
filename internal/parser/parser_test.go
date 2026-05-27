package parser

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/example/subgw/internal/config"
)

func mkReq(t *testing.T, host string, remote string, headers map[string]string) *http.Request {
	t.Helper()
	r := httptest.NewRequest("GET", "http://"+host+"/api/v1/client/subscribe?token=abc&flag=clash", nil)
	r.RemoteAddr = remote
	r.Host = host
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func TestExtractClientIPDirect(t *testing.T) {
	r := mkReq(t, "example.com", "8.8.8.8:12345", nil)
	rip := &config.RealIP{TrustHeaders: []string{"X-Real-IP"}, TrustProxies: []string{"127.0.0.1"}}
	// RemoteAddr 不在 trust_proxies 内,直接返回 RemoteAddr
	if got := ExtractClientIP(r, rip); got != "8.8.8.8" {
		t.Errorf("want 8.8.8.8 got %q", got)
	}
}

func TestExtractClientIPFromHeader(t *testing.T) {
	r := mkReq(t, "example.com", "127.0.0.1:55555", map[string]string{
		"X-Real-IP":       "8.8.8.8",
		"X-Forwarded-For": "192.168.0.1, 8.8.8.8",
	})
	rip := &config.RealIP{
		TrustHeaders: []string{"X-Real-IP", "X-Forwarded-For"},
		TrustProxies: []string{"127.0.0.1"},
	}
	if got := ExtractClientIP(r, rip); got != "8.8.8.8" {
		t.Errorf("want 8.8.8.8 got %q", got)
	}
}

func TestExtractClientIPSkipsPrivateInXFF(t *testing.T) {
	r := mkReq(t, "example.com", "127.0.0.1:55555", map[string]string{
		"X-Forwarded-For": "10.0.0.1, 1.2.3.4",
	})
	rip := &config.RealIP{
		TrustHeaders: []string{"X-Forwarded-For"},
		TrustProxies: []string{"127.0.0.1"},
	}
	if got := ExtractClientIP(r, rip); got != "1.2.3.4" {
		t.Errorf("want 1.2.3.4 got %q", got)
	}
}

func TestExtractClientIPSingleHeaderHonorsPrivate(t *testing.T) {
	// X-Real-IP 是单值,即使是私网也应当被采纳(来自可信代理)
	r := mkReq(t, "example.com", "127.0.0.1:55555", map[string]string{
		"X-Real-IP": "10.0.0.1",
	})
	rip := &config.RealIP{
		TrustHeaders: []string{"X-Real-IP"},
		TrustProxies: []string{"127.0.0.1"},
	}
	if got := ExtractClientIP(r, rip); got != "10.0.0.1" {
		t.Errorf("want 10.0.0.1 got %q", got)
	}
}

func TestMatchSubscribePathQuery(t *testing.T) {
	m, tok := MatchSubscribePath("/api/v1/client/subscribe", []string{"/api/v1/client/subscribe"})
	if !m || tok != "" {
		t.Errorf("want match, no token; got m=%v tok=%q", m, tok)
	}
}

func TestMatchSubscribePathPathToken(t *testing.T) {
	m, tok := MatchSubscribePath("/sub/abcXYZ", []string{"/sub/{token}"})
	if !m || tok != "abcXYZ" {
		t.Errorf("want match abcXYZ, got m=%v tok=%q", m, tok)
	}
}

func TestMatchSubscribePathNoMatch(t *testing.T) {
	m, _ := MatchSubscribePath("/something/else", []string{"/api/v1/client/subscribe"})
	if m {
		t.Error("should not match")
	}
}

func TestParseExtractsAll(t *testing.T) {
	cfg := &config.Config{
		RealIP: config.RealIP{TrustProxies: []string{"127.0.0.1"}, TrustHeaders: []string{"X-Real-IP"}},
		Paths:  config.Paths{Subscribe: []string{"/api/v1/client/subscribe"}},
		Tenants: []config.Tenant{
			{Name: "default", Host: "sub.example.com", Upstream: "http://127.0.0.1:7001"},
		},
	}
	r := mkReq(t, "sub.example.com", "127.0.0.1:55555", map[string]string{
		"User-Agent": "ClashforWindows/0.20.0",
		"X-Real-IP":  "1.2.3.4",
	})
	pr := Parse(r, cfg)
	if pr.ClientIP != "1.2.3.4" {
		t.Errorf("ip: %q", pr.ClientIP)
	}
	if pr.Token != "abc" {
		t.Errorf("token: %q", pr.Token)
	}
	if pr.Flag != "clash" {
		t.Errorf("flag: %q", pr.Flag)
	}
	if pr.Tenant == nil || pr.Tenant.Name != "default" {
		t.Errorf("tenant: %+v", pr.Tenant)
	}
	if !pr.IsSubPath {
		t.Errorf("expected sub path match")
	}
}

func TestParseHostWithPort(t *testing.T) {
	cfg := &config.Config{
		RealIP:  config.RealIP{},
		Paths:   config.Paths{Subscribe: []string{"/api/v1/client/subscribe"}},
		Tenants: []config.Tenant{{Name: "x", Host: "sub.example.com", Upstream: "http://127.0.0.1:7001"}},
	}
	r := mkReq(t, "sub.example.com:8443", "1.1.1.1:1", nil)
	pr := Parse(r, cfg)
	if pr.Tenant == nil {
		t.Fatal("tenant should match even with port in host")
	}
}
