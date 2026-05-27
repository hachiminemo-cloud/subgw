package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadValid(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.yml")
	yml := `
listen: "127.0.0.1:8443"
admin_listen: "127.0.0.1:9090"
hmac_salt_file: "/tmp/salt"
storage:
  sqlite_path: "/tmp/x.db"
tenants:
  - name: t1
    host: sub.example.com
    upstream: http://127.0.0.1:7001
paths:
  subscribe:
    - "/api/v1/client/subscribe"
actions:
  yellow: slow
  orange: fake
  red: deny
`
	if err := os.WriteFile(p, []byte(yml), 0644); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != "127.0.0.1:8443" {
		t.Errorf("listen: %s", c.Listen)
	}
	if len(c.Tenants) != 1 {
		t.Errorf("tenants: %d", len(c.Tenants))
	}
	// defaults
	if c.Storage.BatchFlushSize == 0 {
		t.Error("defaults not applied")
	}
	if c.Faker.NodeCount == 0 {
		t.Error("faker defaults not applied")
	}
}

func TestDurationParseDays(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.yml")
	yml := `
listen: ":1"
hmac_salt_file: "/tmp/salt"
storage:
  sqlite_path: "/tmp/x.db"
  retention:
    events: 7d
tenants:
  - name: t
    host: h.example.com
    upstream: http://127.0.0.1:1
paths:
  subscribe: ["/x"]
actions:
  yellow: pass
  orange: pass
  red: pass
`
	_ = os.WriteFile(p, []byte(yml), 0644)
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Storage.Retention.Events.Std() != 7*24*time.Hour {
		t.Errorf("retention: %v", c.Storage.Retention.Events.Std())
	}
}

func TestLoadMissingTenant(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.yml")
	yml := `
listen: ":1"
hmac_salt_file: "/tmp/salt"
storage:
  sqlite_path: "/tmp/x.db"
paths:
  subscribe: ["/x"]
actions:
  yellow: pass
  orange: pass
  red: pass
`
	_ = os.WriteFile(p, []byte(yml), 0644)
	_, err := Load(p)
	if err == nil {
		t.Error("expected error for missing tenants")
	}
}

func TestLoadDuplicateHost(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.yml")
	yml := `
listen: ":1"
hmac_salt_file: "/tmp/salt"
storage:
  sqlite_path: "/tmp/x.db"
tenants:
  - {name: a, host: h.example.com, upstream: http://127.0.0.1:1}
  - {name: b, host: h.example.com, upstream: http://127.0.0.1:2}
paths:
  subscribe: ["/x"]
actions: {yellow: pass, orange: pass, red: pass}
`
	_ = os.WriteFile(p, []byte(yml), 0644)
	_, err := Load(p)
	if err == nil {
		t.Error("expected duplicate host error")
	}
}

func TestTenantByHost(t *testing.T) {
	c := &Config{Tenants: []Tenant{
		{Name: "a", Host: "Sub.Example.Com", Upstream: "x"},
	}}
	if got := c.TenantByHost("sub.example.com:443"); got == nil || got.Name != "a" {
		t.Errorf("tenant not found")
	}
	if got := c.TenantByHost("other.example.com"); got != nil {
		t.Errorf("unexpected match: %+v", got)
	}
}
