// Package cloudip 维护云厂商 IP 库,提供"某 IP 是否属于云"的快速查询。
//
// 数据源:
//   - metowolf/iplist(阿里/腾讯/字节/华为/Google Cloud)
//   - RIPE Stat API(按 ASN 拉:UCloud/Azure/DigitalOcean/Vultr)
//   - AWS 官方 ip-ranges.json
//
// 设计:
//   - 启动时从 SQLite 加载已有 CIDR 列表 → 构建 IPv4 桶 + IPv6 列表
//   - 后台 goroutine 每 7 天拉一次
//   - Web UI 可触发立即更新
//
// 匹配性能:IPv4 桶分到 /8(256 个槽位),每个槽位线性扫描该段内 CIDR(平均几百个)。
package cloudip

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/example/subgw/internal/store"
)

type entry struct {
	net      *net.IPNet
	provider string
}

type Matcher struct {
	mu      sync.RWMutex
	v4      [256][]entry // 按第一字节分桶
	v6      []entry
	updated time.Time
	stats   map[string]int
}

func NewMatcher() *Matcher {
	return &Matcher{stats: map[string]int{}}
}

// Load 把当前数据全量替换(原子)。传入空切片 = 清空。
func (m *Matcher) Load(cidrs []store.CloudCIDR) {
	var v4 [256][]entry
	var v6 []entry
	stats := map[string]int{}
	var latest time.Time

	for _, c := range cidrs {
		_, ipnet, err := net.ParseCIDR(c.CIDR)
		if err != nil || ipnet == nil {
			continue
		}
		stats[c.Provider]++
		if c.UpdatedTS.After(latest) {
			latest = c.UpdatedTS
		}
		ent := entry{net: ipnet, provider: c.Provider}
		if ipnet.IP.To4() != nil {
			b := ipnet.IP.To4()[0]
			v4[b] = append(v4[b], ent)
		} else {
			v6 = append(v6, ent)
		}
	}

	m.mu.Lock()
	m.v4 = v4
	m.v6 = v6
	m.stats = stats
	m.updated = latest
	m.mu.Unlock()
}

// Match 返回 (是否云 IP, provider)。
func (m *Matcher) Match(ipStr string) (bool, string) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false, ""
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if v4 := ip.To4(); v4 != nil {
		for _, e := range m.v4[v4[0]] {
			if e.net.Contains(ip) {
				return true, e.provider
			}
		}
		return false, ""
	}
	for _, e := range m.v6 {
		if e.net.Contains(ip) {
			return true, e.provider
		}
	}
	return false, ""
}

// Snapshot 给 Web UI 用。
type Snapshot struct {
	Updated time.Time      `json:"updated"`
	Total   int            `json:"total"`
	Stats   map[string]int `json:"stats"`
}

func (m *Matcher) Snapshot() Snapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := Snapshot{Updated: m.updated, Stats: map[string]int{}}
	for k, v := range m.stats {
		out.Stats[k] = v
		out.Total += v
	}
	return out
}

// ----------------- Fetcher -----------------

type Fetcher struct {
	matcher *Matcher
	st      *store.Store
	hc      *http.Client
	logger  *slog.Logger
	running atomic.Bool
}

func NewFetcher(m *Matcher, st *store.Store, logger *slog.Logger) *Fetcher {
	return &Fetcher{
		matcher: m, st: st, logger: logger,
		hc: &http.Client{Timeout: 30 * time.Second},
	}
}

// ispSources URL 拉纯文本 CIDR/IP 列表(每行一个)
var ispSources = map[string]string{
	"aliyun":      "https://metowolf.github.io/iplist/data/isp/aliyun.txt",
	"tencent":     "https://metowolf.github.io/iplist/data/isp/tencent.txt",
	"bytedance":   "https://metowolf.github.io/iplist/data/isp/bytedance.txt",
	"huawei":      "https://metowolf.github.io/iplist/data/isp/huawei.txt",
	"googlecloud": "https://metowolf.github.io/iplist/data/isp/googlecloud.txt",
}

// asnSources 通过 RIPE Stat API 拉 ASN 的 announced prefixes
var asnSources = map[string]string{
	"ucloud":       "AS135377",
	"azure":        "AS8075",
	"digitalocean": "AS14061",
	"vultr":        "AS20473",
}

const awsURL = "https://ip-ranges.amazonaws.com/ip-ranges.json"

// RunOnce 拉所有源,合并去重,写入 store,重载 matcher。
func (f *Fetcher) RunOnce(ctx context.Context) (int, error) {
	if !f.running.CompareAndSwap(false, true) {
		return 0, fmt.Errorf("update already running")
	}
	defer f.running.Store(false)

	start := time.Now()
	f.logger.Info("cloudip: fetching")

	type partial struct {
		provider string
		items    []string
	}
	results := make(chan partial, 32)
	var wg sync.WaitGroup

	for name, url := range ispSources {
		wg.Add(1)
		go func(name, url string) {
			defer wg.Done()
			items, err := f.fetchLines(ctx, url)
			if err != nil {
				f.logger.Warn("cloudip isp fetch failed", "provider", name, "err", err)
				return
			}
			results <- partial{provider: name, items: items}
		}(name, url)
	}
	for name, asn := range asnSources {
		wg.Add(1)
		go func(name, asn string) {
			defer wg.Done()
			items, err := f.fetchRIPE(ctx, asn)
			if err != nil {
				f.logger.Warn("cloudip ripe fetch failed", "provider", name, "err", err)
				return
			}
			results <- partial{provider: name, items: items}
		}(name, asn)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		items, err := f.fetchAWS(ctx)
		if err != nil {
			f.logger.Warn("cloudip aws fetch failed", "err", err)
			return
		}
		results <- partial{provider: "aws", items: items}
	}()

	go func() { wg.Wait(); close(results) }()

	seen := map[string]string{} // cidr -> first provider
	for p := range results {
		for _, cidr := range p.items {
			cidr = normalizeCIDR(cidr)
			if cidr == "" {
				continue
			}
			if _, ok := seen[cidr]; !ok {
				seen[cidr] = p.provider
			}
		}
	}

	if len(seen) == 0 {
		return 0, fmt.Errorf("all sources failed, keeping existing data")
	}

	items := make([]store.CloudCIDR, 0, len(seen))
	now := time.Now()
	for cidr, prov := range seen {
		items = append(items, store.CloudCIDR{CIDR: cidr, Provider: prov, UpdatedTS: now})
	}
	if err := f.st.ReplaceCloudCIDRs(items); err != nil {
		return 0, fmt.Errorf("store replace: %w", err)
	}
	f.matcher.Load(items)
	if err := f.st.SetMeta("cloudip_last_update", now.Format(time.RFC3339)); err != nil {
		f.logger.Warn("cloudip set meta failed", "err", err)
	}
	f.logger.Info("cloudip: updated", "total", len(items), "took", time.Since(start))
	return len(items), nil
}

// fetchLines 拉纯文本,每行一个 CIDR/IP(忽略 # 注释和空行)
func (f *Fetcher) fetchLines(ctx context.Context, url string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := f.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	var out []string
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, scanner.Err()
}

// fetchRIPE 调 RIPE Stat,JSON 里 data.prefixes[].prefix
func (f *Fetcher) fetchRIPE(ctx context.Context, asn string) ([]string, error) {
	url := "https://stat.ripe.net/data/announced-prefixes/data.json?resource=" + asn
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := f.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	var body struct {
		Data struct {
			Prefixes []struct {
				Prefix string `json:"prefix"`
			} `json:"prefixes"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16*1024*1024)).Decode(&body); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(body.Data.Prefixes))
	for _, p := range body.Data.Prefixes {
		out = append(out, p.Prefix)
	}
	return out, nil
}

// fetchAWS 调 AWS ip-ranges.json,JSON 里 prefixes[].ip_prefix + ipv6_prefixes[].ipv6_prefix
func (f *Fetcher) fetchAWS(ctx context.Context) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", awsURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := f.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	var body struct {
		Prefixes []struct {
			IPPrefix string `json:"ip_prefix"`
		} `json:"prefixes"`
		IPv6Prefixes []struct {
			IPv6Prefix string `json:"ipv6_prefix"`
		} `json:"ipv6_prefixes"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 32*1024*1024)).Decode(&body); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(body.Prefixes)+len(body.IPv6Prefixes))
	for _, p := range body.Prefixes {
		out = append(out, p.IPPrefix)
	}
	for _, p := range body.IPv6Prefixes {
		out = append(out, p.IPv6Prefix)
	}
	return out, nil
}

func normalizeCIDR(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	// 没有 / 视为单 IP,补成 /32 或 /128
	if !strings.Contains(s, "/") {
		ip := net.ParseIP(s)
		if ip == nil {
			return ""
		}
		if ip.To4() != nil {
			return s + "/32"
		}
		return s + "/128"
	}
	_, _, err := net.ParseCIDR(s)
	if err != nil {
		return ""
	}
	return s
}

// RunPeriodic 启动后台周期拉取。第一次启动若 store 里没数据会立即拉一次。
func (f *Fetcher) RunPeriodic(ctx context.Context, interval time.Duration) {
	go func() {
		// 启动检查一次
		cidrs, err := f.st.ListCloudCIDRs()
		if err == nil && len(cidrs) > 0 {
			f.matcher.Load(cidrs)
			f.logger.Info("cloudip: loaded from store", "total", len(cidrs))
		} else {
			f.logger.Info("cloudip: empty store, doing initial fetch")
			fetchCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
			_, _ = f.RunOnce(fetchCtx)
			cancel()
		}
		// 周期拉
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				fetchCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
				_, _ = f.RunOnce(fetchCtx)
				cancel()
			}
		}
	}()
}
