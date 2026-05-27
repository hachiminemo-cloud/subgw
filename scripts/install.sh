#!/usr/bin/env bash
# 一键安装脚本(从源码编译并安装到系统)
# 用法:sudo bash scripts/install.sh
set -e

if [ "$EUID" -ne 0 ]; then
  echo "请用 root 运行(sudo bash scripts/install.sh)"
  exit 1
fi

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"

# 1) 创建用户
if ! id subgw &>/dev/null; then
  echo ">> 创建系统用户 subgw"
  useradd --system --no-create-home --shell /usr/sbin/nologin subgw
fi

# 2) 创建目录
echo ">> 创建目录"
install -d -o subgw -g subgw -m 0750 /etc/subgw /var/lib/subgw

# 3) 编译
echo ">> 编译 subgw"
cd "$REPO_DIR"
bash scripts/build.sh
ARCH="$(go env GOARCH)"
OS="$(go env GOOS)"
install -m 0755 "dist/subgw-${OS}-${ARCH}" /usr/local/bin/subgw
echo ">> 二进制安装到 /usr/local/bin/subgw"

# 4) 配置文件
if [ ! -f /etc/subgw/config.yml ]; then
  install -o subgw -g subgw -m 0640 configs/config.example.yml /etc/subgw/config.yml
  echo ">> 配置文件已生成: /etc/subgw/config.yml"
  echo "   请编辑后再启动!"
else
  echo ">> 已存在 /etc/subgw/config.yml,不覆盖"
fi

# 5) systemd
install -m 0644 scripts/subgw.service /etc/systemd/system/subgw.service
systemctl daemon-reload
echo ">> systemd unit 已安装"

cat <<EOF

================== 安装完成 ==================

下一步:
  1. 生成管理员密码 hash:
     subgw hashpwd '<your-password>'
     把输出粘贴到 /etc/subgw/config.yml 的 admin.password_hash

  2. 编辑配置:
     \$ vi /etc/subgw/config.yml
     调整 tenants(host / upstream)、admin、规则阈值等

  3. 启动并设置开机启动:
     \$ systemctl enable --now subgw

  4. 查看日志:
     \$ journalctl -u subgw -f

  5. 访问 Web UI(默认监听 127.0.0.1:9090):
     用 SSH 端口转发或 Nginx 反代到外部域名访问。
==============================================
EOF
