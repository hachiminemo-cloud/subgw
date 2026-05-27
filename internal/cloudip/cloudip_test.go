package cloudip

import (
	"testing"
	"time"

	"github.com/example/subgw/internal/store"
)

func TestMatcherIPv4(t *testing.T) {
	m := NewMatcher()
	m.Load([]store.CloudCIDR{
		{CIDR: "8.8.8.0/24", Provider: "google", UpdatedTS: time.Now()},
		{CIDR: "10.0.0.0/8", Provider: "private", UpdatedTS: time.Now()},
		{CIDR: "2001:db8::/32", Provider: "v6test", UpdatedTS: time.Now()},
	})

	if hit, p := m.Match("8.8.8.8"); !hit || p != "google" {
		t.Errorf("8.8.8.8: hit=%v p=%q", hit, p)
	}
	if hit, p := m.Match("8.8.9.1"); hit {
		t.Errorf("8.8.9.1 should miss, got p=%q", p)
	}
	if hit, p := m.Match("10.1.2.3"); !hit || p != "private" {
		t.Errorf("10.1.2.3: hit=%v p=%q", hit, p)
	}
	if hit, _ := m.Match("not-an-ip"); hit {
		t.Error("garbage input must not match")
	}
}

func TestMatcherIPv6(t *testing.T) {
	m := NewMatcher()
	m.Load([]store.CloudCIDR{
		{CIDR: "2001:db8::/32", Provider: "v6", UpdatedTS: time.Now()},
	})
	if hit, p := m.Match("2001:db8::1"); !hit || p != "v6" {
		t.Errorf("v6: hit=%v p=%q", hit, p)
	}
	if hit, _ := m.Match("2001:1234::1"); hit {
		t.Error("v6 miss")
	}
}

func TestMatcherReload(t *testing.T) {
	m := NewMatcher()
	m.Load([]store.CloudCIDR{{CIDR: "1.1.1.0/24", Provider: "cf", UpdatedTS: time.Now()}})
	if hit, _ := m.Match("1.1.1.1"); !hit {
		t.Fatal("first load missing")
	}
	// 替换
	m.Load([]store.CloudCIDR{{CIDR: "2.2.2.0/24", Provider: "x", UpdatedTS: time.Now()}})
	if hit, _ := m.Match("1.1.1.1"); hit {
		t.Errorf("old data still present")
	}
	if hit, _ := m.Match("2.2.2.2"); !hit {
		t.Errorf("new data not loaded")
	}
}

func TestSnapshot(t *testing.T) {
	m := NewMatcher()
	now := time.Now()
	m.Load([]store.CloudCIDR{
		{CIDR: "8.8.8.0/24", Provider: "google", UpdatedTS: now},
		{CIDR: "8.8.9.0/24", Provider: "google", UpdatedTS: now},
		{CIDR: "1.1.1.0/24", Provider: "cf", UpdatedTS: now.Add(-time.Hour)},
	})
	s := m.Snapshot()
	if s.Total != 3 {
		t.Errorf("total: %d", s.Total)
	}
	if s.Stats["google"] != 2 || s.Stats["cf"] != 1 {
		t.Errorf("stats: %+v", s.Stats)
	}
	if !s.Updated.Equal(now) {
		t.Errorf("updated should be max ts")
	}
}

func TestNormalizeCIDR(t *testing.T) {
	cases := map[string]string{
		"8.8.8.0/24":  "8.8.8.0/24",
		"8.8.8.8":     "8.8.8.8/32",
		"2001:db8::1": "2001:db8::1/128",
		"not-ip":      "",
		"":            "",
		"  1.1.1.1  ": "1.1.1.1/32",
	}
	for in, want := range cases {
		if got := normalizeCIDR(in); got != want {
			t.Errorf("normalizeCIDR(%q) = %q, want %q", in, got, want)
		}
	}
}
