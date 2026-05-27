package rules

import "github.com/example/subgw/internal/store"

// 内置默认 UA 规则。
//
// 白名单(前缀匹配):覆盖 wyx2685/v2board 在 app/Protocols/*.php 中真实识别的所有客户端,
// 加上其它常见客户端(Hiddify / FlClash / NekoBox 等)。
//
// 黑名单(正则匹配):常见扫描器 / HTTP 库 / bot 通用关键字。
//
// 启动时 SeedDefaultsIfEmpty 会在 ua_rules 表为空时一次性塞进去;
// 用户在 Web UI 删了几条又想要回来,可以走 SeedDefaults 强制 upsert。

type DefaultRule struct {
	Pattern string
	Note    string
}

// DefaultUAWhitelist 白名单 = 前缀匹配。UA 以这个开头即被视为合法客户端。
//
// 来源:
//   - V2board ClientController.php 走过的 flag(clash/meta/nyanpasu/verge/...)
//   - 客户端 GitHub README / Issue 区里能查到的实际 UA 样本
var DefaultUAWhitelist = []DefaultRule{
	// --- Clash 系列 ---
	{"ClashforWindows", "Clash for Windows"},
	{"ClashX", "ClashX / ClashX Pro (macOS)"},
	{"Clash Verge", "Clash Verge / Verge Rev"},
	{"Clash-Verge", "Clash Verge 备用 UA 形式"},
	{"clash-verge", "Clash Verge 小写形式"},
	{"Clash.Meta", "Clash.Meta(旧版)"},
	{"ClashMeta", "Clash Meta 无空格写法"},
	{"Clash Meta", "Clash Meta"},
	{"Clash Nyanpasu", "Clash Nyanpasu"},
	{"Clash", "Clash 通用兜底(不在前面规则覆盖到的)"},
	{"mihomo", "mihomo 内核(Clash.Meta 新版)"},
	{"FlClash", "FlClash(跨平台 Clash 客户端)"},
	{"Stash", "Stash (iOS / macOS)"},

	// --- sing-box 系列 ---
	{"sing-box", "sing-box CLI / Windows GUI"},
	{"SFI", "sing-box iOS"},
	{"SFA", "sing-box Android"},
	{"SFM", "sing-box macOS"},
	{"SFT", "sing-box Apple TV"},
	{"Hiddify", "HiddifyNext / Hiddify Manager"},

	// --- V2Ray 系列 ---
	{"v2rayN", "v2rayN (Windows)"},
	{"v2rayNG", "v2rayNG (Android)"},
	{"v2RayTun", "v2RayTun"},
	{"V2RayXS", "V2RayXS"},

	// --- iOS / macOS 老牌 ---
	{"Shadowrocket", "Shadowrocket (iOS)"},
	{"Shadowsocks", "Shadowsocks 通用"},
	{"Loon", "Loon (iOS)"},
	{"Quantumult", "Quantumult / Quantumult X (iOS)"},
	{"Surge", "Surge (iOS / macOS)"},

	// --- Android ---
	{"Surfboard", "Surfboard (Android)"},
	{"SagerNet", "SagerNet (Android)"},
	{"NekoBox", "NekoBox / NekoBoxForAndroid"},
	{"NekoRay", "NekoRay (Windows / Linux)"},

	// --- OpenWrt / 路由器 ---
	{"PassWall", "PassWall (OpenWrt)"},
	{"OpenClash", "OpenClash (OpenWrt)"},
	{"ShellClash", "ShellClash (OpenWrt)"},

	// --- 其他 ---
	{"SSRPlus", "SSRPlus"},
	{"AGH", "AdGuardHome 偶用 UA"},
	{"OneClick", "OneClick"},
	{"FairVPN", "FairVPN"},
	{"Pharos", "Pharos Pro"},
	{"Streisand", "Streisand (iOS)"},
}

// DefaultUABlacklist 黑名单 = 正则匹配。命中即视为扫描/爬虫。
//
// 注:UA 白名单优先,白名单命中会让这里跳过。
// 比如理论上 "okhttp" 也可能出现在合法移动端二次封装客户端里,
// 所以我们写的是 ^okhttp/ 这种锚定开头的形式 — 二次封装通常会改 UA 加前缀。
var DefaultUABlacklist = []DefaultRule{
	// --- 命令行 / 调试 ---
	{`^curl/`, "curl"},
	{`^Wget/`, "wget"},
	{`^HTTPie/`, "httpie"},
	{`^PostmanRuntime`, "Postman"},
	{`^insomnia/`, "Insomnia REST"},

	// --- 编程语言默认 HTTP 客户端 ---
	{`^[Pp]ython-requests`, "Python requests"},
	{`^[Pp]ython-urllib`, "Python urllib"},
	{`^Python/`, "Python 通用"},
	{`^aiohttp/`, "Python aiohttp"},
	{`^httpx/`, "Python httpx"},
	{`^Go-http-client`, "Go 默认客户端"},
	{`^Go-Resty`, "Go resty"},
	{`^Java/`, "Java 默认客户端"},
	{`^Apache-HttpClient`, "Apache HttpClient"},
	{`^okhttp/`, "okhttp 裸客户端"},
	{`^Ktor`, "Kotlin Ktor"},
	{`^libwww-perl`, "Perl libwww"},
	{`^lwp-trivial`, "Perl LWP::Simple"},
	{`^Mojolicious`, "Perl Mojolicious"},
	{`^Ruby$`, "Ruby Net::HTTP"},
	{`^Faraday`, "Ruby Faraday"},
	{`^node-fetch`, "node-fetch"},
	{`^axios/`, "axios"},
	{`^got `, "node got"},
	{`^undici`, "node undici"},
	{`^libcurl`, "libcurl"},
	{`^WinHttp`, "Windows WinHttp"},
	{`^WebRequest$`, "PowerShell Invoke-WebRequest"},

	// --- 安全扫描器 ---
	{`(?i)nmap`, "nmap"},
	{`(?i)masscan`, "masscan"},
	{`(?i)nuclei`, "ProjectDiscovery nuclei"},
	{`(?i)gobuster`, "gobuster"},
	{`(?i)dirbuster`, "DirBuster"},
	{`(?i)dirb`, "dirb"},
	{`(?i)wpscan`, "WPScan"},
	{`(?i)sqlmap`, "sqlmap"},
	{`(?i)nikto`, "Nikto"},
	{`(?i)acunetix`, "Acunetix"},
	{`(?i)burp`, "Burp Suite"},
	{`(?i)zgrab`, "ZMap zgrab"},
	{`(?i)censys`, "Censys"},
	{`(?i)shodan`, "Shodan"},
	{`(?i)wireshark`, "Wireshark"},

	// --- 爬虫 / bot 关键字(宽松匹配) ---
	{`(?i)\bbot\b`, "通用 bot"},
	{`(?i)spider`, "通用 spider"},
	{`(?i)crawler`, "通用 crawler"},
	{`(?i)scrap`, "通用 scrap*"},
	{`(?i)fetcher`, "通用 fetcher"},
	{`(?i)monitor`, "通用 monitor"},
	{`(?i)uptimerobot`, "UptimeRobot"},
	{`(?i)pingdom`, "Pingdom"},
	{`(?i)site24x7`, "Site24x7"},

	// --- 空 UA / 异常 ---
	{`^$`, "空 UA"},
	{`^-$`, "占位 - UA"},
	{`^Mozilla/5\.0$`, "光秃秃的 Mozilla/5.0(几乎一定是脚本)"},
	{`^Mozilla/4\.0$`, "光秃秃的 Mozilla/4.0"},
}

// SeedDefaults 把内置默认 UA 规则写入 DB(idempotent,已存在的不动)。
func (m *Manager) SeedDefaults() (added int, err error) {
	for _, r := range DefaultUAWhitelist {
		if err := m.st.AddUARule(store.UARule{Kind: "whitelist", Pattern: r.Pattern, Note: r.Note}); err != nil {
			return added, err
		}
		added++
	}
	for _, r := range DefaultUABlacklist {
		if err := m.st.AddUARule(store.UARule{Kind: "blacklist", Pattern: r.Pattern, Note: r.Note}); err != nil {
			return added, err
		}
		added++
	}
	return added, m.Reload()
}

// SeedDefaultsIfEmpty 首次启动时调用:DB 为空时种入默认,否则不动。
func (m *Manager) SeedDefaultsIfEmpty() (seeded int, err error) {
	existing, err := m.st.ListUARules("")
	if err != nil {
		return 0, err
	}
	if len(existing) > 0 {
		return 0, nil
	}
	return m.SeedDefaults()
}
