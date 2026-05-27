# subgw 部署教程

本文档面向**独立机器**部署场景(D1=独立机器)。以 Debian/Ubuntu 为例,其它发行版只是包管理器命令不同。

## 拓扑

```
[互联网]
   │
   │ 443
   ▼
[CDN 可选,Cloudflare] ──┐
                         │ 443
                         ▼
              ┌────────────────────────┐
              │  独立机器(本机)       │
              │                        │
              │ Nginx :443             │
              │   ├─ sub.xxx.com  ──── │ → 127.0.0.1:8443  (subgw 反代)
              │   └─ admin.xxx.com ─── │ → 127.0.0.1:9090  (Web UI,加 IP 白名单)
              │                        │
              │ subgw                  │
              │   ├─ 127.0.0.1:8443    │ → V2Board 主机(跨网络)
              │   └─ 127.0.0.1:9090    │
              └────────────────────────┘
                         │
                         │ HTTP
                         ▼
              [V2Board 后端主机] :7001
```

`tenants[].upstream` 填 V2Board 主机的 HTTP 地址(内网走专线/VPN/公网都行)。

---

## 1. 准备机器

最低配置:1C / 512MB / 5GB 硬盘,够跑几万用户的流量。

```bash
apt update
apt install -y nginx curl ca-certificates
# 时区(可选)
timedatectl set-timezone Asia/Shanghai
```

---

## 2. 安装 Go(如果机器没有)

```bash
# 装 Go 1.24+(本项目用 go 1.24)
curl -fsSL https://go.dev/dl/go1.24.4.linux-amd64.tar.gz -o /tmp/go.tar.gz
tar -C /usr/local -xzf /tmp/go.tar.gz
ln -sf /usr/local/go/bin/go /usr/local/bin/go
ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt
go version
```

> 也可以在自己电脑上交叉编译好二进制再上传,无需在服务器装 Go。
> ```
> # 本地
> GOOS=linux GOARCH=amd64 bash scripts/build.sh
> scp dist/subgw-linux-amd64 server:/tmp/
> ```

---

## 3. 编译 + 安装

```bash
# 把代码丢到服务器,如 /opt/subgw
cd /opt/subgw
sudo bash scripts/install.sh
```

`install.sh` 会:
- 创建 `subgw` 系统用户(无 shell,无家目录)
- 创建 `/etc/subgw/`、`/var/lib/subgw/`(属主 subgw,权限 0750)
- 把二进制装到 `/usr/local/bin/subgw`
- 把示例配置复制到 `/etc/subgw/config.yml`
- 安装 systemd unit

---

## 4. 配置

### 4.1 生成 Web 管理员密码 hash

```bash
sudo -u subgw subgw hashpwd '我的强密码'
# 输出形如:$2a$10$xxx...
```

### 4.2 编辑配置

```bash
sudo vi /etc/subgw/config.yml
```

至少改这些:

```yaml
listen: "127.0.0.1:8443"
admin_listen: "127.0.0.1:9090"

tenants:
  - name: default
    host: "sub.xxx.com"                # ⭐ 你的订阅域名
    upstream: "http://10.0.1.10:7001"  # ⭐ V2Board 后端地址

admin:
  username: "admin"
  password_hash: "$2a$10$xxx..."        # ⭐ 上一步的输出
```

> **多面板**:在 `tenants:` 下追加更多条目,每条对应一个域名 + 一个 V2Board 后端。
> 不同面板共享 banlist 是可选的(默认共享),要隔离的话每个 tenant 部署一个进程。

### 4.3 设置文件权限

```bash
sudo chmod 600 /etc/subgw/config.yml
sudo chown subgw:subgw /etc/subgw/config.yml
```

---

## 5. 启动

```bash
sudo systemctl enable --now subgw
systemctl status subgw
journalctl -u subgw -f
```

看到类似:
```
level=INFO msg="subscription gateway listening" addr=127.0.0.1:8443
level=INFO msg="admin web UI listening" addr=127.0.0.1:9090
```
就是好了。

---

## 6. Nginx 反代

把 `configs/nginx.example.conf` 改一下放到 `/etc/nginx/sites-available/sub.xxx.com`:

```nginx
server {
    listen 443 ssl http2;
    server_name sub.xxx.com;
    ssl_certificate     /etc/letsencrypt/live/sub.xxx.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/sub.xxx.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8443;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

Web 管理面强烈建议**独立域名 + IP 白名单**(或 SSH 转发,根本不暴露):

```nginx
server {
    listen 443 ssl http2;
    server_name subgw-admin.xxx.com;
    ssl_certificate     ...;
    ssl_certificate_key ...;

    allow YOUR.HOME.IP.HERE;
    deny all;

    location / {
        proxy_pass http://127.0.0.1:9090;
        proxy_set_header Host $host;
    }
}
```

或者更简单 —— **不开公网,用 SSH 转发**:
```bash
# 本地电脑
ssh -L 9090:127.0.0.1:9090 your-server
# 然后浏览器打开 http://127.0.0.1:9090
```

```bash
sudo ln -s /etc/nginx/sites-available/sub.xxx.com /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

---

## 7. Cloudflare 注意事项

如果 CDN 启用了:

### real_ip 配置

```yaml
real_ip:
  trust_headers:
    - CF-Connecting-IP    # 优先!
    - X-Real-IP
    - X-Forwarded-For
  trust_proxies:
    - 127.0.0.1
```

### Nginx 取出 CF 真实 IP

把 CF 的 IP 段加到 nginx 的 `set_real_ip_from`,这样 `$remote_addr` 才是用户真实 IP:

```nginx
# /etc/nginx/conf.d/cloudflare.conf
set_real_ip_from 173.245.48.0/20;
set_real_ip_from 103.21.244.0/22;
# ... 完整列表见 https://www.cloudflare.com/ips/
real_ip_header CF-Connecting-IP;
```

### L7 vs L3 封禁

subgw 只能做 L7 封禁(网关层 403)。CF 不会因此把对方 IP 屏蔽掉,
所以攻击方仍能持续打 CF。要 L3 屏蔽:
- 调 CF API 加 firewall rule(Phase 3 计划)
- 或者把对方 IP 推到 nftables/fail2ban

MVP 阶段就 L7,够用。

---

## 8. Telegram 告警(可选)

1. 跟 `@BotFather` 申请 bot,记下 `bot_token`
2. 把 bot 拉进群,或者私聊它一句,获取 `chat_id`(可用 `https://api.telegram.org/bot<TOKEN>/getUpdates` 查)
3. 配置:

```yaml
notifier:
  telegram:
    enabled: true
    bot_token: "1234:ABC..."
    chat_id: "-1001234567890"
    throttle: 5m
```

4. 重启 `systemctl restart subgw`
5. 登录 Web UI → 工具 → 发送测试消息

---

## 9. 启用观察模式(强烈推荐先这样)

第一次上线,建议:

```yaml
detector:
  observe_only: true
```

跑 3-7 天后,Web UI:
- 概览 → 看 Top token / IP 分布
- 异常事件 → 看哪些规则被频繁触发,会不会误伤

调整 `rules.*.gte` 阈值后,改成 `observe_only: false` 开拦截。

---

## 10. 升级 / 回滚

```bash
# 升级
cd /opt/subgw
git pull
sudo bash scripts/install.sh   # 重新编译并替换二进制(不动配置)
sudo systemctl restart subgw

# 回滚
cp /usr/local/bin/subgw.bak /usr/local/bin/subgw   # 假设你备份过旧版
sudo systemctl restart subgw
```

数据(SQLite + salt)在 `/var/lib/subgw/`,跨版本兼容。
Schema 用 `CREATE TABLE IF NOT EXISTS`,新版加表/加列不破坏旧数据。

---

## 11. 日志 / 排错

```bash
# subgw 自身日志
journalctl -u subgw -f
journalctl -u subgw --since "1 hour ago"

# Nginx 访问日志
tail -f /var/log/nginx/access.log

# SQLite 查询(只读)
sqlite3 /var/lib/subgw/subgw.db "SELECT action, COUNT(*) FROM events WHERE ts>strftime('%s','now','-1 hour')*1000 GROUP BY action;"
sqlite3 /var/lib/subgw/subgw.db "SELECT * FROM bans;"
```

---

## 12. 备份

```bash
# 备份数据库(用 sqlite3 的 .backup,在线一致)
sqlite3 /var/lib/subgw/subgw.db ".backup '/backup/subgw-$(date +%F).db'"

# salt 一定要备份!丢了之后 token hash 全部对不上,banlist 失效
cp /var/lib/subgw/salt /backup/subgw-salt
```

---

## 13. 卸载

```bash
sudo systemctl disable --now subgw
sudo rm /etc/systemd/system/subgw.service
sudo systemctl daemon-reload
sudo rm /usr/local/bin/subgw
sudo rm -rf /etc/subgw /var/lib/subgw   # 注意,数据也删了
sudo userdel subgw
```

---

## 排错速查

| 现象 | 原因 / 解决 |
|---|---|
| 启动报 `at least one tenant is required` | 配置文件没填 tenants |
| 启动报 `bad ttl` / 配置解析失败 | YAML 缩进或字段名错 |
| 客户端 504 | `tenants[].upstream` 指向的 V2Board 不可达 |
| 真实 IP 全是 127.0.0.1 | `real_ip.trust_proxies` 漏掉了 Nginx 的 IP |
| Web UI 登录后还是要求登录 | 浏览器 cookie 被禁;或 `admin.session_ttl` 设得太短 |
| 误杀了正常用户 | `whitelist.ua_prefixes` 加上他们用的客户端;调高 `gte` 阈值;或先 `observe_only` |
| Telegram 测试报 401/400 | bot_token 或 chat_id 错;消息体含 MarkdownV2 特殊字符未转义(代码已处理,但你可以看日志确认) |
| SQLite "database is locked" | 应该不会,WAL 模式 + busy_timeout 已设。如真出现,看磁盘是否满 |
