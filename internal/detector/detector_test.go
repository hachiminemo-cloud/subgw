package detector

import (
	"testing"
	"time"

	"github.com/example/subgw/internal/config"
)

func mkConfig() *config.DetectorCfg {
	return &config.DetectorCfg{
		Rules: []config.Rule{
			{
				Name: "tf_red",
				When: config.When{
					TokenFreq: &config.Cond{Window: config.Duration(time.Minute), GTE: 5},
				},
				Severity: "red",
			},
			{
				Name: "tmi_orange",
				When: config.When{
					TokenDistinctIPs: &config.Cond{Window: config.Duration(time.Minute), GTE: 3},
				},
				Severity: "orange",
			},
			{
				Name: "ipmt_red",
				When: config.When{
					IPDistinctTokens: &config.Cond{Window: config.Duration(time.Minute), GTE: 3},
				},
				Severity: "red",
			},
			{
				Name: "bad_ua_orange",
				When: config.When{
					UAMatchAny: []string{"^curl/"},
				},
				Severity: "orange",
			},
		},
		Whitelist: config.Whitelist{
			UAPrefixes: []string{"ClashforWindows"},
		},
	}
}

func TestTokenFreqRule(t *testing.T) {
	d, err := New(mkConfig())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		d.Observe("1.1.1.1", "h1", "ua")
	}
	res := d.Evaluate("1.1.1.1", "h1", "ua")
	if res.Severity != SevNone {
		t.Errorf("at 4: want none, got %s", res.Severity)
	}
	d.Observe("1.1.1.1", "h1", "ua")
	res = d.Evaluate("1.1.1.1", "h1", "ua")
	if res.Severity != SevRed {
		t.Errorf("at 5: want red, got %s tags=%v", res.Severity, res.Tags)
	}
}

func TestTokenDistinctIPsRule(t *testing.T) {
	d, _ := New(mkConfig())
	d.Observe("1.1.1.1", "h1", "")
	d.Observe("2.2.2.2", "h1", "")
	res := d.Evaluate("2.2.2.2", "h1", "")
	if res.Severity == SevOrange {
		t.Errorf("at 2 distinct ips should not yet trigger orange")
	}
	d.Observe("3.3.3.3", "h1", "")
	res = d.Evaluate("3.3.3.3", "h1", "")
	if res.Severity != SevOrange {
		t.Errorf("at 3 distinct ips: want orange, got %s", res.Severity)
	}
}

func TestIPDistinctTokens(t *testing.T) {
	d, _ := New(mkConfig())
	d.Observe("1.1.1.1", "h1", "")
	d.Observe("1.1.1.1", "h2", "")
	d.Observe("1.1.1.1", "h3", "")
	res := d.Evaluate("1.1.1.1", "h3", "")
	if res.Severity != SevRed {
		t.Errorf("ip multi token: want red, got %s tags=%v", res.Severity, res.Tags)
	}
}

func TestBadUARule(t *testing.T) {
	d, _ := New(mkConfig())
	d.Observe("1.1.1.1", "", "curl/8.0")
	res := d.Evaluate("1.1.1.1", "", "curl/8.0")
	if res.Severity != SevOrange {
		t.Errorf("curl UA: want orange, got %s", res.Severity)
	}
}

func TestWhitelistedUA(t *testing.T) {
	d, _ := New(mkConfig())
	// UA 白名单只让 UA 黑名单规则不触发,但其他规则(token_freq)依然命中
	for i := 0; i < 100; i++ {
		d.Observe("1.1.1.1", "h1", "ClashforWindows/0.20")
	}
	res := d.Evaluate("1.1.1.1", "h1", "ClashforWindows/0.20")
	if res.Severity != SevRed {
		t.Errorf("UA whitelisted but token_freq should still trigger: %s", res.Severity)
	}
}

func TestUAWhitelistSkipsUABlacklist(t *testing.T) {
	d, _ := New(mkConfig())
	// curl UA 但是 UA 白名单命中(假设白名单是 curl,不真实但测语义)
	d.Observe("1.1.1.1", "", "ClashforWindows/0.20")
	res := d.Evaluate("1.1.1.1", "", "ClashforWindows/0.20")
	if res.Severity != SevNone {
		t.Errorf("UA whitelisted should not trigger bad_ua: %s", res.Severity)
	}
}

func TestCloudIPRule(t *testing.T) {
	cfg := &config.DetectorCfg{
		Rules: []config.Rule{
			{Name: "cloud", When: config.When{FromCloudIP: true}, Severity: "orange"},
		},
	}
	d, _ := New(cfg)
	d.SetCloudLookup(func(ip string) (bool, string) {
		if ip == "8.130.0.1" {
			return true, "aliyun"
		}
		return false, ""
	})
	d.Observe("8.130.0.1", "h1", "ClashforWindows/0.20") // 白名单 UA
	res := d.Evaluate("8.130.0.1", "h1", "ClashforWindows/0.20")
	if res.Severity != SevOrange {
		t.Errorf("cloud IP should trigger orange even with whitelisted UA: %s tags=%v", res.Severity, res.Tags)
	}
}

func TestSeverityRanking(t *testing.T) {
	// 同一请求命中两条规则,应取最高 severity
	cfg := &config.DetectorCfg{
		Rules: []config.Rule{
			{Name: "a", When: config.When{TokenFreq: &config.Cond{Window: config.Duration(time.Minute), GTE: 1}}, Severity: "yellow"},
			{Name: "b", When: config.When{TokenFreq: &config.Cond{Window: config.Duration(time.Minute), GTE: 1}}, Severity: "red"},
		},
	}
	d, _ := New(cfg)
	d.Observe("1.1.1.1", "h1", "")
	res := d.Evaluate("1.1.1.1", "h1", "")
	if res.Severity != SevRed {
		t.Errorf("want red, got %s", res.Severity)
	}
	if len(res.Tags) != 2 {
		t.Errorf("want both tags, got %v", res.Tags)
	}
}
