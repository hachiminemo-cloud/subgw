// Package parser 从 HTTP 请求里提取 client_ip / token / flag / tenant 等关键字段。
package parser

import (
	"net"
	"net/http"
	"strings"

	"github.com/example/subgw/internal/config"
)

type Request struct {
	ClientIP  string
	UA        string
	Token     string // 原文,使用后立即丢弃
	Flag      string
	Tenant    *config.Tenant
	IsSubPath bool // 是否命中订阅路径
	Path      string
}

// privateBlocks RFC1918 + loopback + link-local
var privateBlocks []*net.IPNet

func init() {
	for _, cidr := range []string{
		"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10",
	} {
		_, b, _ := net.ParseCIDR(cidr)
		privateBlocks = append(privateBlocks, b)
	}
}

func isPrivate(ip net.IP) bool {
	for _, b := range privateBlocks {
		if b.Contains(ip) {
			return true
		}
	}
	return false
}

// ExtractClientIP 根据 trust_headers + trust_proxies 提取真实 IP。
// 若 RemoteAddr 不在 trust_proxies 列表里,直接信 RemoteAddr。
//
// 规则:
//   - 单值 header(如 X-Real-IP / CF-Connecting-IP) → 取首个有效 IP,不区分公私网
//   - 多值 header(X-Forwarded-For 或值含逗号)→ 从左往右取第一个非私网 IP
func ExtractClientIP(r *http.Request, cfg *config.RealIP) string {
	remoteIP := remoteAddrIP(r.RemoteAddr)
	trusted := isTrustedProxy(remoteIP, cfg.TrustProxies)
	if !trusted {
		return remoteIP
	}
	for _, h := range cfg.TrustHeaders {
		v := r.Header.Get(h)
		if v == "" {
			continue
		}
		if strings.Contains(v, ",") {
			// 多值 header,取左侧第一个非私网
			for _, p := range strings.Split(v, ",") {
				cand := strings.TrimSpace(p)
				ip := net.ParseIP(cand)
				if ip != nil && !isPrivate(ip) {
					return ip.String()
				}
			}
			continue
		}
		// 单值 header,只要是合法 IP 就用
		if ip := net.ParseIP(strings.TrimSpace(v)); ip != nil {
			return ip.String()
		}
	}
	return remoteIP
}

func remoteAddrIP(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

func isTrustedProxy(ip string, list []string) bool {
	if len(list) == 0 {
		// 没配置就不信任 header
		return false
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, x := range list {
		if strings.Contains(x, "/") {
			_, b, err := net.ParseCIDR(x)
			if err == nil && b.Contains(parsed) {
				return true
			}
			continue
		}
		if x == ip {
			return true
		}
	}
	return false
}

// MatchSubscribePath 检查路径是否是订阅路径,顺便从 path 抽 token(如 /sub/{token})。
// 返回 (matched, tokenFromPath)
func MatchSubscribePath(path string, patterns []string) (bool, string) {
	path = strings.TrimRight(path, "/")
	for _, p := range patterns {
		if strings.Contains(p, "{token}") {
			prefix := strings.TrimSuffix(p, "/{token}")
			if strings.HasPrefix(path, prefix+"/") {
				rest := strings.TrimPrefix(path, prefix+"/")
				// rest 应该是单段
				if rest != "" && !strings.Contains(rest, "/") {
					return true, rest
				}
			}
			continue
		}
		if path == strings.TrimRight(p, "/") {
			return true, ""
		}
	}
	return false, ""
}

// Parse 入口字段抽取。
func Parse(r *http.Request, cfg *config.Config) *Request {
	ip := ExtractClientIP(r, &cfg.RealIP)
	ua := r.Header.Get("User-Agent")
	flag := r.URL.Query().Get("flag")
	matched, pathToken := MatchSubscribePath(r.URL.Path, cfg.Paths.Subscribe)
	token := r.URL.Query().Get("token")
	if token == "" {
		token = pathToken
	}
	tenant := cfg.TenantByHost(r.Host)
	return &Request{
		ClientIP:  ip,
		UA:        ua,
		Token:     token,
		Flag:      strings.ToLower(flag),
		Tenant:    tenant,
		IsSubPath: matched,
		Path:      r.URL.Path,
	}
}
