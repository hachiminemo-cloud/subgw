# subgw

> **V2Board 订阅前置网关 · 反爬虫 / 反扫描 / 反共享 · 行为分析 + 假节点反侦察**
>
> 单 Go 二进制 · 11MB · 无 CGO · 自带 Web 后台

`subgw` 是一个独立运行的应用层 WAF,架在 V2Board 订阅接口前面。所有订阅请求先经过它,根据 IP / token / UA / 频率 / 多维行为打分,命中可疑/异常时返回**假节点**或直接 403。**不读 V2Board 数据库、不调它的 API**,完全解耦。

```
[订阅客户端 / 扫描器]
        │
        ▼
┌─────────────────┐    ┌─────────────────┐
│  subgw          │ ─→ │  你的 V2Board   │
│  反代 + 检测     │    └─────────────────┘
└─────┬───────────┘
      │
      ├─ SQLite(events / incidents / bans / 云 IP / 规则)
      ├─ 滑动窗口(token / IP / 多维计数)
      ├─ 云 IP 库(9 家厂商,周更)
      ├─ Web 管理后台
      └─ Telegram 告警(可选)
```

---

## ✨ 特性一览

### 检测维度(应用层行为分析)
- **单 token 频率**:Clash 默认 24h 拉一次,5 分钟拉 30 次 = 扫描特征
- **单 token 多 IP**:5 分钟内同一 token 出现在多个 IP = 共享/扫描
- **单 IP 多 token**:10 分钟内单 IP 试多个不同 token = 撞库
- **云 IP 段**:9 家云厂商(AWS / Azure / 阿里 / 腾讯 / 字节 / 华为 / Google / Vultr / DO / UCloud),~17000 条 CIDR,每周自动更新
- **UA 黑名单**:正则匹配可疑客户端,可在 Web UI 动态增删
- **UA 白名单**:前缀匹配主流客户端,可在 Web UI 动态增删

### 处置策略(4 档分级)
| 严重度 | 默认动作 | 说明 |
|---|---|---|
| `yellow` | `slow` | 随机延迟 1-5 秒,消耗对方时间 |
| `orange` | `fake` | **假节点**:返回看似合法但全是黑洞 IP 的订阅 |
| `red` | `deny` | 403 + 自动加 banlist(默认 TTL 24h) |

### 假节点反侦察
按客户端类型自动生成对应格式:
- Clash → 合法的 Clash YAML(proxies + proxy-groups + rules)
- V2Ray / VMess → base64(`vmess://...`)
- sing-box → 合法 sing-box JSON
- Trojan → base64(`trojan://...`)
- 默认 → base64(`ss://...`)

节点 IP 全部从 RFC5737/RFC3330 文档/保留段抽:`192.0.2.x` / `198.51.100.x` / `203.0.113.x`,客户端能导入但永远连不上。响应头 `Content-Type` / `Profile-Update-Interval` / `Subscription-Userinfo` 都跟 V2Board 真订阅一致。

### 安全
- **Token 永远不存原文**:HMAC-SHA256(salt) 处理后才落库,salt 单独文件,权限 600
- **bcrypt 密码** + **HttpOnly cookie session**
- **SQLite WAL 模式**,异步 batch flush
- 假节点用 RFC 文档专用段,不打扰真实业务

### Web 管理后台(10 个标签页)
- 监控:**概览** / **请求日志** / **异常事件**
- 名单:**IP 黑名单** / **Token 黑名单** / **IP 白名单** / **UA 规则**(动态增删,无需重启)
- 检测:**云 IP 库**(看统计 + 手动触发更新)
- 系统:**设置**(Telegram 通知 / 配置回显) / **工具**(token → hash)

### 其他
- 多面板:单进程按 `Host` 头路由到多个 V2Board 后端
- 观察模式:`observe_only: true` 先记录不拦截,跑几天反推真实阈值
- Telegram 告警:Web UI 配置 + 持久化 + 热生效
- 单二进制 11MB,SQLite WAL,无外部依赖

---

## 🚀 快速开始

需要 Go 1.24+(只用来编译)。运行时不依赖 Go。

```bash
# 1. 编译
git clone https://github.com/<your-user>/subgw.git && cd subgw
bash scripts/build.sh

# 2. 生成管理员密码 hash
./dist/subgw-linux-amd64 hashpwd '我的强密码'
# 输出:$2a$10$xxxxxxxxxx... ← 待会儿粘贴到配置

# 3. 准备配置
mkdir -p /etc/subgw /var/lib/subgw
cp configs/config.example.yml /etc/subgw/config.yml
chmod 600 /etc/subgw/config.yml
# 编辑 /etc/subgw/config.yml,至少改这几项:
#   - tenants[].host / upstream  → 你的订阅域名 + V2Board 真实地址
#   - admin.password_hash         → 上一步的输出

# 4. 跑起来
cp dist/subgw-linux-amd64 /usr/local/bin/subgw
subgw -c /etc/subgw/config.yml
# 看到 "subscription gateway listening" + "admin web UI listening" 就好了
```

订阅域名指向 subgw 监听地址(默认 `127.0.0.1:8443`),前面通常挂 Nginx/Caddy 终止 TLS。

---

## 📦 完整部署(Debian/Ubuntu + systemd)

### 1. 一键安装脚本

```bash
cd subgw
sudo bash scripts/install.sh
```

`install.sh` 会做的事:
- 创建系统用户 `subgw`(无 shell,无家目录)
- 建目录 `/etc/subgw/`(配置,权限 0750)和 `/var/lib/subgw/`(数据库 + salt)
- 编译并把二进制装到 `/usr/local/bin/subgw`
- 复制示例配置到 `/etc/subgw/config.yml`
- 装 systemd unit `/etc/systemd/system/subgw.service`(带安全加固:NoNewPrivileges / ProtectSystem 等)

### 2. 配置 / 启动

```bash
# 生成密码 hash
sudo -u subgw subgw hashpwd '你的密码'

# 编辑配置
sudo vi /etc/subgw/config.yml
#   把 tenants / admin.password_hash 改成你的

# 启动
sudo systemctl enable --now subgw

# 看日志
sudo journalctl -u subgw -f
```

### 3. Nginx 反代(生产推荐)

```nginx
# /etc/nginx/sites-available/sub.your-domain.com

# 订阅域名,对外提供 HTTPS
server {
    listen 443 ssl http2;
    server_name sub.your-domain.com;

    ssl_certificate     /etc/letsencrypt/live/sub.your-domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/sub.your-domain.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8443;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

# 管理面 — 强烈建议独立域名 + IP 白名单
server {
    listen 443 ssl http2;
    server_name subgw-admin.your-domain.com;

    ssl_certificate     ...;
    ssl_certificate_key ...;

    allow YOUR.HOME.IP.HERE;
    deny  all;

    location / {
        proxy_pass http://127.0.0.1:9090;
        proxy_set_header Host $host;
    }
}
```

更克制的做法:**管理面只绑 127.0.0.1,用 SSH 端口转发访问**,根本不暴露公网:
```bash
ssh -L 9090:127.0.0.1:9090 your-server
# 浏览器开 http://127.0.0.1:9090
```

### 4. Cloudflare 后面

如果前面挂了 CF,改 `config.yml`:
```yaml
real_ip:
  trust_headers:
    - "CF-Connecting-IP"           # CF 必须放第一位
    - "X-Real-IP"
    - "X-Forwarded-For"
  trust_proxies:
    - "127.0.0.1"
```

Nginx 也要从 CF 的 IP 段取真实 IP(`set_real_ip_from`),具体见 `DEPLOY.md`。

---

## 📖 Web 管理后台使用

启动后访问 `http://<admin_listen>/`(默认 `127.0.0.1:9090`),登录后侧边栏 10 个标签页:

### 监控
| 标签 | 功能 |
|---|---|
| 概览 | 时间窗口内的请求数 / pass-slow-fake-deny 分布 / Top 10 IP / Top 10 token / 异常事件统计 |
| 请求日志 | 按 IP / token / action 过滤,看每条请求的时间/动作/状态/UA/规则命中 |
| 异常事件 | 按 severity (yellow/orange/red) 过滤,看检测器命中详情 |

### 名单(全部可在 UI 增删)
| 标签 | 功能 |
|---|---|
| IP 黑名单 | 手动封禁某 IP,支持 TTL(`24h` / `7d`)或永久;命中自动封禁的也在这里 |
| Token 黑名单 | 输入 V2Board token **原文**自动算 hash 提交,或直接粘 hash |
| IP 白名单 | 单 IP 或 CIDR(`10.0.0.0/8`),命中跳过所有规则 |
| UA 规则 | 黑名单(正则)+ 白名单(前缀)两栏并排;增删后热生效 |

### 检测
| 标签 | 功能 |
|---|---|
| 云 IP 库 | 看 9 家厂商各自的 CIDR 数 / 最后更新时间 / 手动「立即更新」按钮 / 单 IP 查询 |

### 系统
| 标签 | 功能 |
|---|---|
| 设置 | Telegram bot_token / chat_id / throttle 配置(密码框 + 脱敏显示 + 热生效) / 检测规则只读回显 / tenants 配置回显 |
| 工具 | token 原文 → hash 计算器(用于手动封某用户) |

---

## ⚙️ 配置详解

完整范例见 [`configs/config.example.yml`](./configs/config.example.yml)。关键字段:

### tenants — 多面板路由(按 Host 头精确匹配)
```yaml
tenants:
  - name: ergou
    host: sub.ergou.example.com
    upstream: http://10.0.1.10:7001     # 你的 V2Board 内网地址,支持 http/https
  - name: kuaimao
    host: sub.kuaimao.example.com
    upstream: https://panel.kuaimao.com
```

### detector — 检测规则(可热重载的部分在 Web UI 改)
```yaml
detector:
  observe_only: false                    # true=只记录不处置,上线初期推荐 true 跑 3-7 天
  rules:
    - name: from_cloud_ip
      desc: 来自云厂商 IP 段
      when:
        from_cloud_ip: true
      severity: orange

    - name: token_freq_extreme
      desc: 单 token 5 分钟拉 >=30 次
      when:
        token_freq: { window: 5m, gte: 30 }
      severity: red

    - name: token_multi_ip
      desc: 单 token 5 分钟出现在 >=5 个不同 IP
      when:
        token_distinct_ips: { window: 5m, gte: 5 }
      severity: orange

    - name: ip_multi_token
      desc: 单 IP 10 分钟尝试 >=3 个不同 token(撞库)
      when:
        ip_distinct_tokens: { window: 10m, gte: 3 }
      severity: red

    - name: bad_ua_static
      when:
        ua_match_any:
          - "^curl/"
          - "^python-requests"
          - "^Go-http-client"
          - "^Wget/"
          - "^$"
      severity: orange

  whitelist:                              # 静态白名单,Web UI 还可以加动态的
    ua_prefixes: [ClashforWindows, v2rayN, mihomo, Stash, Shadowrocket]

actions:                                  # severity → 动作
  yellow: slow
  orange: fake
  red:    deny
```

### faker — 假节点配置
```yaml
faker:
  blackhole_ips:                          # 默认就是 RFC 文档段,客户端连不上但格式合法
    - "192.0.2.1"
    - "198.51.100.1"
    - "203.0.113.1"
  node_count: 8                           # 每次生成几个假节点
```

### real_ip — 真实 IP 提取
```yaml
real_ip:
  trust_headers:                          # 顺序优先,有 CF 时把 CF-Connecting-IP 放第一
    - "CF-Connecting-IP"
    - "X-Real-IP"
    - "X-Forwarded-For"
  trust_proxies:                          # 只信任来自这些 IP 的 header
    - "127.0.0.1"
    - "10.0.0.0/8"
```

---

## 🔧 命令行

```
subgw -c <config.yml>          启动服务(反代 + Web UI)
subgw hashpwd <password>       生成 admin.password_hash(bcrypt)
subgw version                  打印版本
subgw help                     帮助
```

运维操作走 Web UI,不提供 CLI 子命令(这是设计)。

---

## 🗂 数据布局

| 文件 | 用途 |
|---|---|
| `/etc/subgw/config.yml` | 配置文件(含密码 hash,权限 600) |
| `/var/lib/subgw/salt` | HMAC salt,首次启动自动生成(权限 600) |
| `/var/lib/subgw/subgw.db` | SQLite 数据库(WAL 模式) |

**备份**:
```bash
# 备份 DB
sqlite3 /var/lib/subgw/subgw.db ".backup '/backup/subgw-$(date +%F).db'"

# salt 必须备份!丢了之后 token hash 全部对不上,banlist 失效
cp /var/lib/subgw/salt /backup/subgw-salt
```

---

## 🧪 测试 / 开发

```bash
go test ./...                    # 跑全部单元 + 集成测试
go test -cover ./...             # 看覆盖率
go vet ./...
gofmt -l .
bash scripts/build.sh            # 编译
```

测试覆盖了:配置解析、HMAC、滑窗、解析器、检测器、存储、假节点、反代端到端、Web 认证、动态规则、云 IP 匹配。

---

## 🛡 上线建议

### 1. 先观察后拦截
新上线时把 `detector.observe_only: true`,跑 3-7 天攒数据。

在「概览」标签看 Top token / Top IP / incident 分布,看哪些规则**频繁触发但其实是误判**。

调整 `rules.*.gte` 阈值后,把 `observe_only` 改 `false`,再开拦截。

### 2. UA 白名单要早建
默认配置已经包含 Clash / v2rayN / sing-box / Shadowrocket 等主流客户端。
你看「请求日志」发现新的真实客户端 UA,立刻在「UA 规则 → 白名单」加上,防止误伤。

### 3. 阈值参考
- 单 token / 1 小时 > 30 黄 / > 120 橙 / > 300 红
- 单 token / 5 分钟 > 30 红(明显扫描)
- 单 token 同时多 IP:5 分钟 > 5 个 → 橙(共享/扫描)
- 单 IP 试多 token:10 分钟 > 3 个 → 红(撞库)

### 4. CF 后面 L7 封禁的局限
subgw 命中后返回 403/假节点,但**对方仍能持续打 CF**(没 L3 屏蔽)。
真正掐流量得:
- 调 CF API 加 firewall rule
- 或在 CF 那边配 WAF
- subgw 只负责检测和上报

---

## ❓ FAQ

**Q: Clash 默认 24h 拉一次,为啥还会触发?**
A: 用户手动点更新订阅会立刻拉;多设备同时启动会几秒内连续 3-5 次。设阈值时把这些留够空间。

**Q: 想封禁某个用户?**
A: Web UI → 工具 → 输入 token 原文算 hash;然后「Token 黑名单」→ 新增 → 粘 hash。或者直接在 Token 黑名单页输入原文,会自动算 hash。

**Q: 假节点会不会暴露我用了网关?**
A: 假节点的 Content-Type / Profile-Update-Interval / Subscription-Userinfo 都跟 V2Board 真订阅一致。客户端导入时不会报错,只有连节点时才发现连不上(看起来像节点挂了)。

**Q: 误杀正常用户怎么办?**
A: 「IP 白名单」加他的 IP,「UA 规则 → 白名单」加他的客户端 UA 前缀。封禁默认 TTL 24h,过了就解。

**Q: 多面板能用同一个网关吗?**
A: 能,`tenants[]` 配多个就行,按 Host 头路由到对应的 V2Board 后端。

**Q: SubSieve 跟 subgw 选哪个?**
A:
- 只想拦云 IP / 明显爬虫:SubSieve(nginx 性能更强,但 PHP 后台)
- 担心 token 共享 / 慢速行为型扫描 / 撞库:**subgw**(行为分析维度高一档,SubSieve 没这层)
- 想反侦察让攻击方浪费时间:**subgw**(假节点)
- 部署机器只装 docker 不想装别的:SubSieve
- 部署机器啥都没装,单二进制就行:**subgw**

两者也可以叠层用:nginx 粗筛 → subgw 行为分析 + 假节点 → V2Board。

---

## 📄 协议

MIT
