// Package detector 跑规则引擎,输出命中 tag 集合 + 最高 severity。
package detector

import (
	"regexp"
	"strings"
	"time"

	"github.com/example/subgw/internal/config"
	"github.com/example/subgw/internal/slidingwin"
)

type Severity string

const (
	SevNone   Severity = ""
	SevYellow Severity = "yellow"
	SevOrange Severity = "orange"
	SevRed    Severity = "red"
)

func sevRank(s Severity) int {
	switch s {
	case SevYellow:
		return 1
	case SevOrange:
		return 2
	case SevRed:
		return 3
	}
	return 0
}

type Detector struct {
	cfg         *config.DetectorCfg
	maxWindow   time.Duration
	tokenFreq   *slidingwin.Counter
	ipFreq      *slidingwin.Counter
	tokenIPSet  *slidingwin.DistinctSet
	ipTokenSet  *slidingwin.DistinctSet
	uaPatterns  []*regexp.Regexp
	uaWhitelist []string
	ipWhitelist map[string]struct{}

	// 可选:云 IP 查询函数。nil 时 from_cloud_ip 规则跳过。
	cloudLookup func(ip string) (bool, string)
	// 可选:外部 UA/IP 白名单提供者(热更新)。
	dynamicUAWhitelist func(ua string) bool
	dynamicUABlacklist func(ua string) (hit bool, pattern string)
	dynamicIPWhitelist func(ip string) bool
}

// SetCloudLookup 注入云 IP 查询函数(可热更换)。
func (d *Detector) SetCloudLookup(fn func(ip string) (bool, string)) {
	d.cloudLookup = fn
}

// SetDynamicProviders 注入 DB 来源的 UA/IP 规则查询函数。
func (d *Detector) SetDynamicProviders(
	uaWhitelist func(string) bool,
	uaBlacklist func(string) (bool, string),
	ipWhitelist func(string) bool,
) {
	d.dynamicUAWhitelist = uaWhitelist
	d.dynamicUABlacklist = uaBlacklist
	d.dynamicIPWhitelist = ipWhitelist
}

func New(cfg *config.DetectorCfg) (*Detector, error) {
	// 找出最大窗口
	maxWindow := time.Hour
	for _, r := range cfg.Rules {
		w := r.When
		for _, c := range []*config.Cond{w.TokenFreq, w.IPFreq, w.TokenDistinctIPs, w.IPDistinctTokens} {
			if c != nil && c.Window.Std() > maxWindow {
				maxWindow = c.Window.Std()
			}
		}
	}
	bucket := time.Minute
	if maxWindow < 5*time.Minute {
		bucket = 30 * time.Second
	}

	d := &Detector{
		cfg:         cfg,
		maxWindow:   maxWindow,
		tokenFreq:   slidingwin.NewCounter(bucket, maxWindow),
		ipFreq:      slidingwin.NewCounter(bucket, maxWindow),
		tokenIPSet:  slidingwin.NewDistinctSet(bucket, maxWindow),
		ipTokenSet:  slidingwin.NewDistinctSet(bucket, maxWindow),
		ipWhitelist: map[string]struct{}{},
	}

	// 收集所有 UA 黑名单正则
	seen := map[string]bool{}
	for _, r := range cfg.Rules {
		for _, pat := range r.When.UAMatchAny {
			if seen[pat] {
				continue
			}
			seen[pat] = true
			re, err := regexp.Compile(pat)
			if err != nil {
				return nil, err
			}
			d.uaPatterns = append(d.uaPatterns, re)
		}
	}
	d.uaWhitelist = cfg.Whitelist.UAPrefixes
	for _, ip := range cfg.Whitelist.IPs {
		d.ipWhitelist[ip] = struct{}{}
	}

	return d, nil
}

func (d *Detector) MaxWindow() time.Duration { return d.maxWindow }

func (d *Detector) GCTargets() []interface{ GC() } {
	return []interface{ GC() }{d.tokenFreq, d.ipFreq, d.tokenIPSet, d.ipTokenSet}
}

// Observe 把请求记入计数器(请求落库前调用)。
// tokenHash 可能为空。
func (d *Detector) Observe(ip, tokenHash, ua string) {
	if tokenHash != "" {
		d.tokenFreq.Inc(tokenHash)
		d.tokenIPSet.Add(tokenHash, ip)
		d.ipTokenSet.Add(ip, tokenHash)
	}
	d.ipFreq.Inc(ip)
	_ = ua
}

// Result 检测结果。
type Result struct {
	Severity Severity
	Tags     []string // 命中的规则名
	Note     string
}

// Whitelisted IP 白名单 — 完全跳过所有规则。
// 注意:UA 白名单不在这里,UA 白名单只让 UA 黑名单不触发,
// 行为型规则(频率/多 IP/云 IP)仍然要查。
func (d *Detector) Whitelisted(ip, ua string) bool {
	if _, ok := d.ipWhitelist[ip]; ok {
		return true
	}
	if d.dynamicIPWhitelist != nil && d.dynamicIPWhitelist(ip) {
		return true
	}
	_ = ua
	return false
}

// uaWhitelisted UA 是否在白名单(前缀匹配)。
func (d *Detector) uaWhitelisted(ua string) bool {
	for _, p := range d.uaWhitelist {
		if strings.HasPrefix(ua, p) {
			return true
		}
	}
	if d.dynamicUAWhitelist != nil && d.dynamicUAWhitelist(ua) {
		return true
	}
	return false
}

// Evaluate 运行所有规则。注意 Evaluate 必须在 Observe 之后调用,
// 这样当前请求自身也算进窗口。
func (d *Detector) Evaluate(ip, tokenHash, ua string) Result {
	if d.Whitelisted(ip, ua) {
		return Result{}
	}
	var (
		topSev Severity
		tags   []string
		notes  []string
	)
	for _, r := range d.cfg.Rules {
		hit, note := d.matchRule(r, ip, tokenHash, ua)
		if !hit {
			continue
		}
		tags = append(tags, r.Name)
		if note != "" {
			notes = append(notes, note)
		}
		sev := Severity(r.Severity)
		if sevRank(sev) > sevRank(topSev) {
			topSev = sev
		}
	}
	// 动态(DB)UA 黑名单 — 命中固定 orange,UA 白名单可豁免
	if d.dynamicUABlacklist != nil && !d.uaWhitelisted(ua) {
		if hit, pat := d.dynamicUABlacklist(ua); hit {
			tags = append(tags, "ua_dyn")
			notes = append(notes, "ua_dyn:"+pat)
			if sevRank(SevOrange) > sevRank(topSev) {
				topSev = SevOrange
			}
		}
	}
	return Result{Severity: topSev, Tags: tags, Note: strings.Join(notes, "; ")}
}

func (d *Detector) matchRule(r config.Rule, ip, tokenHash, ua string) (bool, string) {
	w := r.When
	if c := w.TokenFreq; c != nil && tokenHash != "" {
		n := d.tokenFreq.Sum(tokenHash, c.Window.Std())
		if n >= c.GTE {
			return true, formatN("token_freq", n, c)
		}
	}
	if c := w.IPFreq; c != nil {
		n := d.ipFreq.Sum(ip, c.Window.Std())
		if n >= c.GTE {
			return true, formatN("ip_freq", n, c)
		}
	}
	if c := w.TokenDistinctIPs; c != nil && tokenHash != "" {
		n := d.tokenIPSet.Count(tokenHash, c.Window.Std())
		if n >= c.GTE {
			return true, formatN("token_distinct_ips", n, c)
		}
	}
	if c := w.IPDistinctTokens; c != nil {
		n := d.ipTokenSet.Count(ip, c.Window.Std())
		if n >= c.GTE {
			return true, formatN("ip_distinct_tokens", n, c)
		}
	}
	if w.FromCloudIP && d.cloudLookup != nil {
		if hit, prov := d.cloudLookup(ip); hit {
			return true, "cloud_ip:" + prov
		}
	}
	// UA 黑名单类规则:若 UA 白名单命中则跳过
	if len(w.UAMatchAny) > 0 && !d.uaWhitelisted(ua) {
		for _, pat := range w.UAMatchAny {
			for _, re := range d.uaPatterns {
				if re.String() == pat && re.MatchString(ua) {
					return true, "ua_match:" + pat
				}
			}
		}
	}
	return false, ""
}

func formatN(name string, n int, c *config.Cond) string {
	return name + "=" + itoa(n) + ">=" + itoa(c.GTE) + " window=" + c.Window.Std().String()
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
