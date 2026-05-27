package config

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Listen       string      `yaml:"listen"`         // gateway 反代监听,如 127.0.0.1:8443
	AdminListen  string      `yaml:"admin_listen"`   // Web UI 监听,如 127.0.0.1:9090
	HMACSaltFile string      `yaml:"hmac_salt_file"` // HMAC salt 文件路径
	Storage      Storage     `yaml:"storage"`
	RealIP       RealIP      `yaml:"real_ip"`
	Tenants      []Tenant    `yaml:"tenants"`
	Paths        Paths       `yaml:"paths"`
	Detector     DetectorCfg `yaml:"detector"`
	Actions      ActionsCfg  `yaml:"actions"`
	Faker        FakerCfg    `yaml:"faker"`
	Notifier     NotifierCfg `yaml:"notifier"`
	Admin        AdminCfg    `yaml:"admin"`
}

type Storage struct {
	SQLitePath         string    `yaml:"sqlite_path"`
	Retention          Retention `yaml:"retention"`
	BatchFlushInterval Duration  `yaml:"batch_flush_interval"`
	BatchFlushSize     int       `yaml:"batch_flush_size"`
}

type Retention struct {
	Events    Duration `yaml:"events"`
	Incidents Duration `yaml:"incidents"`
}

type RealIP struct {
	TrustHeaders []string `yaml:"trust_headers"`
	TrustProxies []string `yaml:"trust_proxies"`
}

type Tenant struct {
	Name     string `yaml:"name"`
	Host     string `yaml:"host"`     // 完全匹配 Host 头
	Upstream string `yaml:"upstream"` // http://host:port
}

type Paths struct {
	Subscribe []string `yaml:"subscribe"` // /api/v1/client/subscribe, /sub/{token}
}

type DetectorCfg struct {
	ObserveOnly bool                `yaml:"observe_only"`
	Windows     map[string]Duration `yaml:"windows"`
	Rules       []Rule              `yaml:"rules"`
	Whitelist   Whitelist           `yaml:"whitelist"`
}

type Rule struct {
	Name     string `yaml:"name"`
	Desc     string `yaml:"desc"`
	When     When   `yaml:"when"`
	Severity string `yaml:"severity"` // yellow|orange|red
}

type When struct {
	TokenFreq        *Cond    `yaml:"token_freq"`
	IPFreq           *Cond    `yaml:"ip_freq"`
	TokenDistinctIPs *Cond    `yaml:"token_distinct_ips"`
	IPDistinctTokens *Cond    `yaml:"ip_distinct_tokens"`
	UAMatchAny       []string `yaml:"ua_match_any"`
	FromCloudIP      bool     `yaml:"from_cloud_ip"` // 命中云厂商 IP 库
}

type Cond struct {
	Window Duration `yaml:"window"`
	GTE    int      `yaml:"gte"`
}

type Whitelist struct {
	UAPrefixes []string `yaml:"ua_prefixes"`
	IPs        []string `yaml:"ips"`
}

type ActionsCfg struct {
	Yellow string `yaml:"yellow"` // pass|slow|fake|deny
	Orange string `yaml:"orange"`
	Red    string `yaml:"red"`
}

type FakerCfg struct {
	BlackholeIPs []string `yaml:"blackhole_ips"`
	NodeCount    int      `yaml:"node_count"`
}

type NotifierCfg struct {
	Telegram TelegramCfg `yaml:"telegram"`
}

type TelegramCfg struct {
	Enabled  bool     `yaml:"enabled"`
	BotToken string   `yaml:"bot_token"`
	ChatID   string   `yaml:"chat_id"`
	Throttle Duration `yaml:"throttle"`
}

type AdminCfg struct {
	Username     string   `yaml:"username"`
	PasswordHash string   `yaml:"password_hash"` // bcrypt
	SessionTTL   Duration `yaml:"session_ttl"`
	SessionKey   string   `yaml:"session_key"` // 用于签 cookie,空则自动生成
}

// Duration 支持 "5m" / "24h" / "30d" 这种字符串
type Duration time.Duration

var dayRe = regexp.MustCompile(`^(\d+)d$`)

func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	s := strings.TrimSpace(node.Value)
	if s == "" {
		*d = 0
		return nil
	}
	if m := dayRe.FindStringSubmatch(s); m != nil {
		days := 0
		fmt.Sscanf(m[1], "%d", &days)
		*d = Duration(time.Duration(days) * 24 * time.Hour)
		return nil
	}
	dur, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(dur)
	return nil
}

func (d Duration) Std() time.Duration { return time.Duration(d) }

func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	c.applyDefaults()
	return &c, nil
}

func (c *Config) validate() error {
	if c.Listen == "" {
		return errors.New("listen is required")
	}
	if c.HMACSaltFile == "" {
		return errors.New("hmac_salt_file is required")
	}
	if c.Storage.SQLitePath == "" {
		return errors.New("storage.sqlite_path is required")
	}
	if len(c.Tenants) == 0 {
		return errors.New("at least one tenant is required")
	}
	seen := map[string]bool{}
	for _, t := range c.Tenants {
		if t.Name == "" || t.Host == "" || t.Upstream == "" {
			return fmt.Errorf("tenant %+v incomplete", t)
		}
		if seen[t.Host] {
			return fmt.Errorf("duplicate tenant host: %s", t.Host)
		}
		seen[t.Host] = true
	}
	if len(c.Paths.Subscribe) == 0 {
		return errors.New("paths.subscribe must list at least one path")
	}
	for _, a := range []string{c.Actions.Yellow, c.Actions.Orange, c.Actions.Red} {
		if !validAction(a) {
			return fmt.Errorf("invalid action %q (want pass|slow|fake|deny)", a)
		}
	}
	return nil
}

func validAction(a string) bool {
	switch a {
	case "pass", "slow", "fake", "deny":
		return true
	}
	return false
}

func (c *Config) applyDefaults() {
	if c.Storage.BatchFlushInterval == 0 {
		c.Storage.BatchFlushInterval = Duration(time.Second)
	}
	if c.Storage.BatchFlushSize == 0 {
		c.Storage.BatchFlushSize = 100
	}
	if c.Storage.Retention.Events == 0 {
		c.Storage.Retention.Events = Duration(30 * 24 * time.Hour)
	}
	if c.Storage.Retention.Incidents == 0 {
		c.Storage.Retention.Incidents = Duration(90 * 24 * time.Hour)
	}
	if c.Admin.SessionTTL == 0 {
		c.Admin.SessionTTL = Duration(12 * time.Hour)
	}
	if len(c.Faker.BlackholeIPs) == 0 {
		c.Faker.BlackholeIPs = []string{
			"192.0.2.1", "192.0.2.2", "192.0.2.3",
			"198.51.100.1", "198.51.100.2",
			"203.0.113.1", "203.0.113.2",
		}
	}
	if c.Faker.NodeCount == 0 {
		c.Faker.NodeCount = 8
	}
	if c.AdminListen == "" {
		c.AdminListen = "127.0.0.1:9090"
	}
}

// TenantByHost 根据 Host 头找 tenant
func (c *Config) TenantByHost(host string) *Tenant {
	host = strings.ToLower(strings.SplitN(host, ":", 2)[0])
	for i := range c.Tenants {
		if strings.ToLower(c.Tenants[i].Host) == host {
			return &c.Tenants[i]
		}
	}
	return nil
}
