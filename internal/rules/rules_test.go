package rules

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/example/subgw/internal/store"
)

func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "rules.db"), 50*time.Millisecond, 5)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestUAWhitelistAndBlacklist(t *testing.T) {
	st := newTestStore(t)
	m := NewManager(st)

	if err := m.AddUARule("whitelist", "ClashforWindows", "client"); err != nil {
		t.Fatal(err)
	}
	if err := m.AddUARule("blacklist", "^curl/", "curl scanner"); err != nil {
		t.Fatal(err)
	}

	if !m.UAWhitelisted("ClashforWindows/0.20") {
		t.Error("clash should be whitelisted")
	}
	if m.UAWhitelisted("curl/8.0") {
		t.Error("curl should not be whitelisted")
	}
	if hit, _ := m.UABlacklisted("curl/8.0"); !hit {
		t.Error("curl should be blacklisted")
	}
	if hit, _ := m.UABlacklisted("ClashforWindows/0.20"); hit {
		t.Error("clash should not be blacklisted")
	}
}

func TestIPWhitelist(t *testing.T) {
	st := newTestStore(t)
	m := NewManager(st)

	if err := m.AddIPWhitelist("1.2.3.4", "office"); err != nil {
		t.Fatal(err)
	}
	if err := m.AddIPWhitelist("10.0.0.0/8", "internal"); err != nil {
		t.Fatal(err)
	}

	if !m.IPWhitelisted("1.2.3.4") {
		t.Error("1.2.3.4 should be whitelisted")
	}
	if !m.IPWhitelisted("10.20.30.40") {
		t.Error("10.20.30.40 should match CIDR 10/8")
	}
	if m.IPWhitelisted("8.8.8.8") {
		t.Error("8.8.8.8 should not be whitelisted")
	}
}

func TestInvalidBlacklistRegex(t *testing.T) {
	st := newTestStore(t)
	m := NewManager(st)
	err := m.AddUARule("blacklist", "[bad-regex", "")
	if err == nil {
		t.Error("invalid regex should be rejected")
	}
}

func TestInvalidIPWhitelist(t *testing.T) {
	st := newTestStore(t)
	m := NewManager(st)
	if err := m.AddIPWhitelist("not-an-ip", ""); err == nil {
		t.Error("invalid IP should be rejected")
	}
	if err := m.AddIPWhitelist("1.2.3.0/99", ""); err == nil {
		t.Error("invalid CIDR should be rejected")
	}
}

func TestReloadAfterDelete(t *testing.T) {
	st := newTestStore(t)
	m := NewManager(st)
	_ = m.AddUARule("blacklist", "^curl/", "")
	rules, _ := st.ListUARules("blacklist")
	if len(rules) != 1 {
		t.Fatalf("setup: %d", len(rules))
	}
	if err := m.DeleteUARule(rules[0].ID); err != nil {
		t.Fatal(err)
	}
	if hit, _ := m.UABlacklisted("curl/8.0"); hit {
		t.Error("rule should be gone after delete")
	}
}

func TestSeedDefaultsCoversMainClients(t *testing.T) {
	st := newTestStore(t)
	m := NewManager(st)

	if _, err := m.SeedDefaults(); err != nil {
		t.Fatal(err)
	}

	// 白名单覆盖主流客户端
	whitelistedUAs := []string{
		"ClashforWindows/0.20.39",
		"ClashX/1.95.1 (com.west2online.ClashX; build:1.95.1; macOS 14.0)",
		"Clash Verge/v1.3.8",
		"Stash/2.5.6 (com.stashpop.stash; build:2.5.6; iOS 17.0)",
		"Shadowrocket/2068 CFNetwork/1474",
		"v2rayN/6.42",
		"v2rayNG/1.8.18",
		"sing-box 1.10.0",
		"SFI/1.10.0", // sing-box iOS
		"SFA/1.10.0", // sing-box Android
		"mihomo/v1.18.0",
		"Surge iOS/2730",
		"Loon/2.5.0 CFNetwork/1474",
		"Quantumult%20X/1.0.36",
		"NekoBox/1.3.6",
		"FlClash/0.8.61",
		"Hiddify/2.0.5",
	}
	for _, ua := range whitelistedUAs {
		if !m.UAWhitelisted(ua) {
			t.Errorf("UA should be whitelisted: %q", ua)
		}
	}

	// 黑名单覆盖常见扫描器
	blackedUAs := []string{
		"curl/8.0.1",
		"Wget/1.21.3",
		"python-requests/2.31.0",
		"Python/3.11 aiohttp/3.9",
		"Go-http-client/1.1",
		"Java/17.0.5",
		"okhttp/4.10.0",
		"node-fetch/3.3.2",
		"axios/1.6.0",
		"masscan/1.3.2",
		"nuclei/3.0",
		"sqlmap/1.7",
		"",            // 空 UA
		"Mozilla/5.0", // 光秃秃
		"Some Generic Bot/1.0",
		"GenericSpider 2.0",
	}
	for _, ua := range blackedUAs {
		hit, _ := m.UABlacklisted(ua)
		if !hit {
			t.Errorf("UA should be blacklisted: %q", ua)
		}
	}

	// 正常浏览器 UA 不该被黑名单命中
	browserUAs := []string{
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	}
	for _, ua := range browserUAs {
		if hit, pat := m.UABlacklisted(ua); hit {
			t.Errorf("browser UA falsely blacklisted: %q hit pattern %q", ua, pat)
		}
	}
}

func TestSeedDefaultsIfEmpty(t *testing.T) {
	st := newTestStore(t)
	m := NewManager(st)

	// 第一次:空 → 写入
	n, err := m.SeedDefaultsIfEmpty()
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Error("expected seed on empty DB")
	}

	// 第二次:非空 → 不动
	n2, err := m.SeedDefaultsIfEmpty()
	if err != nil {
		t.Fatal(err)
	}
	if n2 != 0 {
		t.Errorf("expected 0 on second call, got %d", n2)
	}
}
