# V2Board 订阅前置网关 - 设计方案 v0.1

> 本文档基于 `1.md` 的需求理解 + 后续讨论整理。
> 范围:设计阶段。**未涉及代码实现**,代码骨架在方案确认后另起文档。

---

## 0. 待拍板的决策点(看这里!)

设计正文按以下默认值推进,如果你不同意,先反馈再改文档:

| 编号 | 决策 | 当前默认 | 你可选的其它 |
|---|---|---|---|
| D1 | 部署位置 |独立机器
| D2 | 主存储 | SQLite(WAL 模式) 
| D3 | 限频存储 | 进程内时间分桶计数器,重启丢统计 
| D4 | 假节点策略 |纯随机 / 蜜罐反追踪 
| D5 | 管理界面 | 一上来就 Web |
| D6 | 告警通道 | Telegram-bot
| D7 | 多面板 | 单网关 + 域名路由 + tenant 字段 
| D8 | MVP 策略 | 第一版就带规则上线 |
| D9 | token 位置 | https://a.b.c.d/api/v1/client/subscribe?token=djidoqwnkfb（范例订阅地址）
| D10 | 网关监听 | （这个位置我不懂  你觉得我怎么弄比较简单就用哪种方式）
| D11 | 如何控制 | 使用webui进行控制  telegram-bot进行通知  不做cli
技术栈我希望使用go   最好是二进制直接部署   部署方式要简洁方便  做完需要生成完整的使用说明、部署教程
---

## 1. 目标与非目标

### 1.1 目标
1. **观察**:对 V2board 订阅接口的所有请求做全量日志,字段足够事后审计
2. **检测**:多维度规则识别扫描/共享/爬取行为
3. **处置**:分级响应(放行 / 限速 / 假节点 / 封禁)
4. **解耦**:不读 V2board DB / 不调 V2board API,token 只作分组键
5. **轻量**:单二进制 + 单文件 DB,可独立跑

### 1.2 非目标(明确不做)
- ❌ 不做用户管理/订单/计费(V2board 自己做)
- ❌ 不验证 token 合法性(透传给 V2board,它自己拒)
- ❌ 不替换 V2board(纯前置)

---

## 2. 架构总览

```
                  ┌─────────────────────────────────────┐
                  │  Cloudflare(可选)                  │
                  └────────────────┬────────────────────┘
                                   │ TLS
                  ┌────────────────▼────────────────────┐
                  │  Nginx / Caddy(已存在)            │
                  │  - TLS 终止                         │
                  │  - 设置 X-Real-IP / CF-Connecting-IP │
                  └────────────────┬────────────────────┘
                                   │ HTTP, 127.0.0.1:8443
                  ┌────────────────▼────────────────────┐
                  │  本网关(Go 单进程)                │
                  │  ┌─────────────────────────────┐    │
                  │  │ a. 入口解析(IP/UA/token/   │    │
                  │  │    flag/path/tenant)        │    │
                  │  │ b. banlist 快速过滤(内存)  │    │
                  │  │ c. 规则引擎(滑动窗口计数)  │    │
                  │  │ d. 决策:pass / fake / deny │    │
                  │  │ e. 反向代理回源 OR 生成假应答│    │
                  │  │ f. 异步落库(SQLite)       │    │
                  │  │ g. 告警(可选 Telegram)    │    │
                  │  └─────────────────────────────┘    │
                  └──┬────────────────────────┬─────────┘
                     │ 正常透传               │ 命中规则
                     ▼                        ▼
            ┌────────────────┐    ┌──────────────────────┐
            │  V2board 后端  │    │  假节点生成器        │
            │  127.0.0.1:xxx │    │  按 flag/UA 选格式   │
            └────────────────┘    └──────────────────────┘

                     旁路:
                     SQLite(events / bans / rules)
                     CLI(stats / ban / unban / tail)
```

---

## 3. 模块拆解

### 3.1 入口解析(parser)
- 路由匹配:`/api/v1/client/subscribe`(默认)和 `/sub/{token}`(可选)
- 字段提取:
  - `client_ip`:优先级 `CF-Connecting-IP` > `X-Real-IP` > `X-Forwarded-For 最左非内网` > `RemoteAddr`
  - `user_agent`:原样保存
  - `token`:从 query 或 path 取出,**立刻 HMAC-SHA256(salt, token)** 得 `token_hash`,原文不出本模块
  - `flag`:`?flag=clash|v2ray|sing-box|...`,用于假节点生成的格式选择
  - `tenant`:从 `Host` 头匹配 upstream 配置
  - `path`、`method`、`query` 等元数据

### 3.2 banlist 快速过滤(banlist)
- 内存中维护两个 set:`banned_ips`、`banned_token_hashes`
- 启动从 SQLite `bans` 表 load,运行时增量同步
- 命中直接走"拒绝"分支,不进规则引擎

### 3.3 规则引擎(detector)
- 多个**滑动窗口计数器**:
  - `freq_by_token[token_hash]`:5min / 1h / 24h 窗口
  - `freq_by_ip[ip]`:同上
  - `ips_per_token[token_hash]`:5min / 1h 不同 IP 计数(用 set 实现)
  - `tokens_per_ip[ip]`:同上(单 IP 探多 token)
  - `ua_blacklist`:正则/前缀匹配
- 计数器实现:**时间分桶 map**,每桶 1 分钟,定期 GC 超出最长窗口的桶
- 每个规则产出 `score` 和 `tags`,汇总决策

### 3.4 决策(judge)
- 输入:规则引擎打分
- 输出:`action ∈ {pass, slow, fake, deny}`
- 配置驱动,YAML 阈值可热加载(SIGHUP 或文件 watch)

### 3.5 反向代理(proxy)
- `net/http/httputil.ReverseProxy`
- `pass` → 直接转发,响应原样返回
- `slow` → 加 `time.Sleep`,再转发
- 透传所有 query,设置正确的 `X-Forwarded-For`
- **响应缓存(可选,Phase 2)**:同一 token + flag 命中 → 304 / 直接返回缓存,减轻 V2board

### 3.6 假节点生成器(faker)
- 按 `flag` / UA 路由到对应 generator:
  - `clash_yaml_gen`:生成合法 Clash YAML,proxies 全是黑洞 IP
  - `v2ray_b64_gen`:生成 base64 编码的 `vmess://` 列表
  - `ss_b64_gen`:base64 编码的 `ss://` 列表
  - `default`:base64 SS 兜底
- 黑洞 IP 池:`127.0.0.1`、`0.0.0.0`、`192.0.2.0/24`(RFC5737 文档专用)
- 端口、密码、名称随机,**Content-Type / 头部 / Profile-Update-Interval 与真订阅一致**
- 设计原则:**让攻击者拿到看似成功的订阅,客户端导入后无法连接**

### 3.7 落库(logger)
- 异步 channel + batch flush(每 100 条或 1s 写一次)
- 写 `events` 表
- 命中规则的额外写 `incidents` 表

### 3.8 告警(notifier)
- 配置开关
- 触发条件:首次封禁某 IP/token、单分钟内 incident > N
- 通道:Telegram bot(复用 Hermes 配置)

### 3.9 CLI 工具
- `gateway serve` 启动服务
- `gateway stats --token=<hash前缀> --window=24h`
- `gateway tail [--filter=ip:1.2.3.4]`
- `gateway ban <ip|token-hash> [--reason=xxx] [--ttl=24h]`
- `gateway unban <ip|token-hash>`
- `gateway dump --since=24h > log.json`
- `gateway vacuum --older-than=30d`

---

## 4. 数据模型(SQLite)

```sql
-- 每个请求一行
CREATE TABLE events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          INTEGER NOT NULL,             -- unix ms
    tenant      TEXT NOT NULL,                -- 域名/品牌标识
    client_ip   TEXT NOT NULL,
    ua          TEXT,
    token_hash  TEXT,                         -- HMAC-SHA256, 可能为空(无 token 请求)
    flag        TEXT,                         -- clash/v2ray/...
    path        TEXT,
    status      INTEGER,                      -- 网关返回的 HTTP 状态
    action      TEXT,                         -- pass/slow/fake/deny
    rule_tags   TEXT,                         -- JSON 数组,命中的规则
    upstream_ms INTEGER,                      -- 回源耗时(命中假节点为 NULL)
    resp_size   INTEGER
);
CREATE INDEX idx_events_ts          ON events(ts);
CREATE INDEX idx_events_token       ON events(token_hash, ts);
CREATE INDEX idx_events_ip          ON events(client_ip, ts);
CREATE INDEX idx_events_action_ts   ON events(action, ts);

-- 封禁清单
CREATE TABLE bans (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    kind       TEXT NOT NULL,                 -- 'ip' | 'token'
    target     TEXT NOT NULL,                 -- ip 或 token_hash
    reason     TEXT,
    rule_tags  TEXT,                          -- JSON
    created_ts INTEGER NOT NULL,
    expires_ts INTEGER,                       -- NULL = 永久
    created_by TEXT,                          -- 'auto' | 'cli:<user>'
    UNIQUE(kind, target)
);
CREATE INDEX idx_bans_target ON bans(kind, target);

-- 异常事件(用于告警和审计,events 的子集)
CREATE TABLE incidents (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         INTEGER NOT NULL,
    tenant     TEXT,
    severity   TEXT,                          -- yellow/orange/red
    client_ip  TEXT,
    token_hash TEXT,
    rule_tags  TEXT,                          -- JSON
    action     TEXT,
    note       TEXT
);
CREATE INDEX idx_incidents_ts ON incidents(ts);

-- 配置元数据(可选,记录规则版本/启动时间)
CREATE TABLE meta (
    k TEXT PRIMARY KEY,
    v TEXT
);
```

**保留策略**:
- `events`:30 天,定时 `DELETE WHERE ts < ?` + `VACUUM`
- `incidents`:90 天
- `bans`:不删,过期由 `expires_ts` 控制,查询时过滤

---

## 5. 规则引擎与判定

### 5.1 规则配置示例(YAML)

```yaml
detector:
  observe_only: true              # MVP-0 阶段,只检测不处置

  windows:
    short: 5m
    mid: 1h
    long: 24h

  rules:
    - name: token_freq_high
      desc: 单 token 高频拉取
      when:
        token_freq:
          window: 1h
          gte: 60
      severity: orange

    - name: token_freq_extreme
      when:
        token_freq:
          window: 5m
          gte: 30
      severity: red

    - name: token_multi_ip
      desc: 单 token 多 IP
      when:
        token_distinct_ips:
          window: 5m
          gte: 5
      severity: orange

    - name: ip_multi_token
      desc: 单 IP 探多 token(撞库特征)
      when:
        ip_distinct_tokens:
          window: 10m
          gte: 3
      severity: red

    - name: bad_ua
      when:
        ua_match_any:
          - "^curl/"
          - "^python-requests"
          - "^Go-http-client"
          - "^$"                  # 空 UA
      severity: orange

  whitelist:
    ua_prefixes:                  # 客户端白名单,即使高频也不杀
      - "ClashforWindows"
      - "ClashX"
      - "Shadowrocket"
      - "v2rayN"
      - "sing-box"

actions:
  yellow: slow                    # 加延迟
  orange: fake                    # 假节点
  red:    deny                    # 直接拒绝并加 banlist
```

### 5.2 判定流程

```
请求进来
  ├─ banlist 命中? ──Y──► action=deny,记 events,返回 403/假
  │  └─N
  ├─ tenant 配置存在? ──N──► 默认 404,记 events
  │  └─Y
  ├─ observe_only? ──Y──► action=pass(正常转发),但规则仍打分到 incidents
  │  └─N
  ├─ 跑全部规则,取最高 severity
  ├─ 按 actions 映射到 pass/slow/fake/deny
  ├─ 若 red,自动写入 bans(带 TTL)
  └─ 执行 action,异步落库
```

### 5.3 阈值的初始猜测(MVP-0 跑完用真实数据校准)

| 规则 | 1h 阈值 | 5min 阈值 |
|---|---|---|
| 单 token 频率 | >60 黄 / >120 橙 / >300 红 | >30 红 |
| 单 IP 频率 | >100 黄 / >500 橙 | >50 橙 |
| 单 token 不同 IP 数 | >5 橙 | — |
| 单 IP 不同 token 数 | >3 红(撞库) | — |

---

## 6. 处置策略详解

### 6.1 pass(放行)
透传到 V2board,响应原样返回。

### 6.2 slow(限速/降速)
- 进入时 `time.Sleep(随机 1-5s)`
- 仍转发到 V2board
- 目的:消耗对方时间,不暴露我们识别了它

### 6.3 fake(假节点)
- **不回源 V2board**
- 按 flag/UA 生成对应格式的合法订阅
- 节点指向黑洞 IP
- 返回 200 + 正确 Content-Type + 正确的 `Subscription-Userinfo`/`Profile-Update-Interval` 头
- 客户端导入后看似正常,但所有连接失败

### 6.4 deny(封禁)
- 写入 `bans` 表(带 TTL,默认 24h)
- 返回 403 + 极简响应(或者也返回假节点,更隐蔽)
- 后续请求被 banlist 直接拦截

### 6.5 关于 L3 封禁(Phase 3)
- 网关把 banlist 导出为文件
- 由 `fail2ban` / `nftables` 监听文件做 IP drop
- 仅对直连有效;CF 后面要走 CF API 加规则
- **MVP 不做**

---

## 7. 多租户 / 多面板

### 7.1 配置
```yaml
listen: "127.0.0.1:8443"
hmac_salt_file: "/etc/gateway/salt"     # 单独文件,权限 600

tenants:
  - name: ergou
    host: "sub.ergou.example.com"
    upstream: "http://127.0.0.1:7001"
    rules_file: "rules.ergou.yml"
  - name: kuaimao
    host: "sub.kuaimao.example.com"
    upstream: "http://127.0.0.1:7002"
    rules_file: "rules.kuaimao.yml"
```

### 7.2 数据隔离
- `events` / `incidents` / `bans` 都带 `tenant` 字段
- CLI 查询默认按 tenant 过滤:`gateway stats --tenant=ergou`
- 全局 banlist 也支持(`tenant='*'`)

---

## 8. 安全 / 隐私

| 项 | 处理 |
|---|---|
| token 存储 | **HMAC-SHA256(salt, token)**,salt 在独立文件,日志库永远没有原文 |
| salt 管理 | 启动时若不存在,自动生成 32 字节随机写入,权限 600 |
| 日志保留 | 默认 30 天,可配 |
| IP 脱敏 | 默认不脱敏(便于排查),配置可开 `/24` 截断 |
| 配置文件权限 | 600,salt 文件 600 |
| CLI 权限 | unix socket + 文件权限控制,或本地 token |
| 假节点泄露 | 黑洞 IP 都是保留段,客户端连不上,不影响第三方 |
| 误杀风险 | 默认 MVP-0 跑观察模式,真实数据校准后再开拦截;白名单 UA;封禁 TTL 而非永久 |

---

## 9. 配置文件示例(完整)

```yaml
# /etc/gateway/config.yml
listen: "127.0.0.1:8443"
hmac_salt_file: "/etc/gateway/salt"

storage:
  sqlite_path: "/var/lib/gateway/gateway.db"
  retention:
    events: 30d
    incidents: 90d
  batch_flush_interval: 1s
  batch_flush_size: 100

real_ip:
  trust_headers:                  # 顺序优先级
    - "CF-Connecting-IP"
    - "X-Real-IP"
    - "X-Forwarded-For"
  trust_proxies:                  # 只接受这些来源的 header
    - "127.0.0.1"
    - "::1"

tenants:
  - name: ergou
    host: "sub.ergou.example.com"
    upstream: "http://127.0.0.1:7001"
    rules_file: "/etc/gateway/rules.ergou.yml"
  - name: kuaimao
    host: "sub.kuaimao.example.com"
    upstream: "http://127.0.0.1:7002"
    rules_file: "/etc/gateway/rules.kuaimao.yml"

paths:
  subscribe:
    - "/api/v1/client/subscribe"     # query token
    - "/sub/{token}"                 # path token(可选)

notifier:
  telegram:
    enabled: true
    bot_token_env: "HERMES_BOT_TOKEN"
    chat_id_env:   "HERMES_CHAT_ID"
    throttle: 5m                     # 同类告警最少间隔
```

---

## 10. 目录结构

```
/root/web_panel/
├── 1.md                          # 你的原始需求
├── 2-design.md                   # 本文档
├── cmd/
│   └── gateway/
│       └── main.go               # 入口
├── internal/
│   ├── config/                   # 配置加载 + 热重载
│   ├── parser/                   # 入口解析
│   ├── detector/                 # 规则引擎
│   ├── judge/                    # 决策
│   ├── proxy/                    # 反向代理
│   ├── faker/                    # 假节点生成
│   │   ├── clash.go
│   │   ├── vmess.go
│   │   └── ss.go
│   ├── store/                    # SQLite + 异步写
│   ├── banlist/                  # 内存 banlist
│   ├── notifier/                 # Telegram
│   └── cli/                      # 子命令
├── pkg/
│   └── slidingwin/               # 时间分桶滑窗,独立可测
├── configs/
│   ├── config.example.yml
│   ├── rules.example.yml
│   └── ua-blacklist.txt
├── scripts/
│   ├── install.sh
│   └── gateway.service           # systemd unit
└── go.mod
```

---

## 11. 分阶段实施计划

### MVP-0:纯观察(0.5 天)
- [ ] 配置加载 + 多 tenant 路由
- [ ] 入口解析(IP/UA/token_hash/flag)
- [ ] 反向代理透传
- [ ] SQLite + 异步落库
- [ ] CLI:`serve` / `tail` / `stats`
- [ ] **不拦截**,但规则跑空打分(写 incidents 用于校准)
- ✅ 上线后跑 3-7 天

### MVP-1:开启拦截(1 天)
- [ ] 规则引擎实装(频率/多 IP/多 token/UA)
- [ ] banlist 内存 + 持久化
- [ ] deny(403)+ slow 两个动作
- [ ] CLI:`ban` / `unban`
- [ ] 配置 `observe_only: false`

### Phase 2:假节点 + 告警(1 天)
- [ ] Clash YAML 生成器
- [ ] V2Ray base64 生成器
- [ ] SS 兜底生成器
- [ ] Content-Type / 头部对齐
- [ ] Telegram 告警接 Hermes

### Phase 3:管理面 + 高级特性(2-3 天)
- [ ] Web UI(看日志、改规则、手动封禁)
- [ ] 时间分布检测(stdev)
- [ ] ASN/数据中心识别(MaxMind GeoLite2)
- [ ] L3 联动(banlist 文件 + fail2ban / CF API)
- [ ] 响应缓存(304 优化)

---

## 12. 风险与坑位

| 风险 | 应对 |
|---|---|
| 误杀正常多设备用户 | observe_only 校准 + UA 白名单 + 封禁 TTL 而非永久 |
| Cloudflare 后真实 IP 错 | 配置 trust_headers + trust_proxies,Nginx 层正确设置 |
| 假节点格式不对暴露网关 | 按 flag/UA 分发生成器,头部/Content-Type 严格对齐真实 V2board 响应,上线前用真客户端导入测试 |
| token 日志泄露 | HMAC + salt 独立文件 + 文件权限 600 |
| SQLite 高并发写 | WAL 模式 + 异步 batch + 单 writer goroutine |
| 规则热加载导致状态丢失 | 计数器单独保留,只替换规则 + 阈值 |
| V2board 升级改 URL | 路由配置化,不写死 |
| 网关本身被打爆 | 限制单连接最大读取 + http.Server.ReadTimeout,内存上限监控 |

---

## 13. 给你确认的清单(最后)

请在动手前回我:
1. **D1-D10** 这 10 个默认值有没有要改的
2. **MVP-0 先观察不拦截** 这个方案你认不认?如果你想第一版就带规则,我把 MVP-0/MVP-1 合并
3. **token 在 URL 哪里**(D9 的细节):你部署的 V2board 是 `?token=` 还是 `/sub/{token}`,还是都要兼容
4. **二狗 + 快喵两个面板的实际域名 / 后端端口** 大致是什么样(用来确认 tenant 配置思路对不对,真实值你不用现在给)
5. **Telegram Hermes** 当前用的什么形式(直接 bot API?自定义 webhook?)—— 决定告警模块怎么接

回完这些,我下一步就出**代码骨架 + 第一个能跑的 MVP-0**。
