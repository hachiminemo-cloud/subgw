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
