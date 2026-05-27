// Package rules 维护 DB 来源的可热更新规则:UA 黑/白名单 + IP 白名单。
//
// 设计:
//   - 启动时从 store 加载,在内存里构建快速匹配结构
//   - CRUD 后立即 Reload
//   - 提供给 detector 的查询函数线程安全
package rules

import (
	"net"
	"regexp"
	"strings"
	"sync"

	"github.com/example/subgw/internal/store"
)

type uaBlacklistEntry struct {
	id      int64
	pattern string
	re      *regexp.Regexp
}

type Manager struct {
	mu sync.RWMutex
	st *store.Store

	// UA 白名单:前缀匹配
	uaWhitelist []string
	// UA 黑名单:正则匹配
	uaBlacklist []uaBlacklistEntry
	// IP 白名单:支持单 IP 和 CIDR
	ipWhitelistSingle map[string]struct{}
	ipWhitelistNets   []*net.IPNet
}

func NewManager(st *store.Store) *Manager {
	return &Manager{
		st:                st,
		ipWhitelistSingle: map[string]struct{}{},
	}
}

// Reload 全量重读 DB。失败时保留旧数据。
func (m *Manager) Reload() error {
	uaRules, err := m.st.ListUARules("")
	if err != nil {
		return err
	}
	ipEntries, err := m.st.ListIPWhitelist()
	if err != nil {
		return err
	}

	var whitelist []string
	var blacklist []uaBlacklistEntry
	for _, r := range uaRules {
		switch r.Kind {
		case "whitelist":
			whitelist = append(whitelist, r.Pattern)
		case "blacklist":
			re, err := regexp.Compile(r.Pattern)
			if err != nil {
				continue // 跳过坏正则
			}
			blacklist = append(blacklist, uaBlacklistEntry{id: r.ID, pattern: r.Pattern, re: re})
		}
	}

	singles := map[string]struct{}{}
	var nets []*net.IPNet
	for _, e := range ipEntries {
		t := strings.TrimSpace(e.Target)
		if strings.Contains(t, "/") {
			_, n, err := net.ParseCIDR(t)
			if err == nil {
				nets = append(nets, n)
			}
		} else {
			singles[t] = struct{}{}
		}
	}

	m.mu.Lock()
	m.uaWhitelist = whitelist
	m.uaBlacklist = blacklist
	m.ipWhitelistSingle = singles
	m.ipWhitelistNets = nets
	m.mu.Unlock()
	return nil
}

// UAWhitelisted 前缀匹配。
func (m *Manager) UAWhitelisted(ua string) bool {
	if ua == "" {
		return false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, p := range m.uaWhitelist {
		if strings.HasPrefix(ua, p) {
			return true
		}
	}
	return false
}

// UABlacklisted 返回 (hit, 命中的正则模式)。
func (m *Manager) UABlacklisted(ua string) (bool, string) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, e := range m.uaBlacklist {
		if e.re.MatchString(ua) {
			return true, e.pattern
		}
	}
	return false, ""
}

// IPWhitelisted 检查 IP 是否在白名单(支持精确和 CIDR)。
func (m *Manager) IPWhitelisted(ip string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if _, ok := m.ipWhitelistSingle[ip]; ok {
		return true
	}
	if len(m.ipWhitelistNets) == 0 {
		return false
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, n := range m.ipWhitelistNets {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}

// ---------- CRUD wrappers(写完触发 Reload) ----------

func (m *Manager) AddUARule(kind, pattern, note string) error {
	if kind == "blacklist" {
		if _, err := regexp.Compile(pattern); err != nil {
			return err
		}
	}
	if err := m.st.AddUARule(store.UARule{Kind: kind, Pattern: pattern, Note: note}); err != nil {
		return err
	}
	return m.Reload()
}

func (m *Manager) DeleteUARule(id int64) error {
	if err := m.st.DeleteUARule(id); err != nil {
		return err
	}
	return m.Reload()
}

func (m *Manager) AddIPWhitelist(target, note string) error {
	t := strings.TrimSpace(target)
	if strings.Contains(t, "/") {
		if _, _, err := net.ParseCIDR(t); err != nil {
			return err
		}
	} else if net.ParseIP(t) == nil {
		return errIPInvalid
	}
	if err := m.st.AddIPWhitelist(t, note); err != nil {
		return err
	}
	return m.Reload()
}

func (m *Manager) DeleteIPWhitelist(id int64) error {
	if err := m.st.DeleteIPWhitelist(id); err != nil {
		return err
	}
	return m.Reload()
}

// errIPInvalid 用于 IP 校验失败。
var errIPInvalid = &simpleErr{"target must be valid IP or CIDR"}

type simpleErr struct{ s string }

func (e *simpleErr) Error() string { return e.s }
