#!/bin/bash
# vpngate-fwmark 一键安装 / 升级
#
# 一键安装（从 GitHub）：
#   curl -fsSL https://raw.githubusercontent.com/cctv96/vpngate-fwmark/main/install.sh | sudo bash
# 一键升级：
#   curl -fsSL https://raw.githubusercontent.com/cctv96/vpngate-fwmark/main/upgrade.sh | sudo bash
# 本地安装（已克隆仓库）：
#   sudo ./install.sh
#   sudo ./install.sh --upgrade
#
# 升级会保留 /var/lib/vpngate-fwmark 下的状态，包括手动指定的出口，
# 只替换程序本体和 systemd 单元；升级前隧道在运行，升级后会自动重连。
set -euo pipefail

REPO="cctv96/vpngate-fwmark"
BRANCH="${VG_BRANCH:-main}"
UPGRADE=0
if [ "${1:-}" = "--upgrade" ]; then
  UPGRADE=1
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "请用 root 运行：sudo bash install.sh" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$SCRIPT_DIR"
if [ ! -f "$SCRIPT_DIR/vpngate-fwmark.py" ]; then
  # 通过 curl 管道运行时，本地没有源码，从 GitHub 下载 main 分支压缩包。
  TMP_DIR="$(mktemp -d)"
  trap 'rm -rf "$TMP_DIR"' EXIT
  echo "正在从 GitHub 下载 vpngate-fwmark（分支 $BRANCH）……"
  curl -fsSL "https://github.com/$REPO/archive/refs/heads/$BRANCH.tar.gz" -o "$TMP_DIR/repo.tar.gz"
  tar -xzf "$TMP_DIR/repo.tar.gz" -C "$TMP_DIR"
  SRC_DIR="$TMP_DIR/vpngate-fwmark-$BRANCH"
fi

# 升级前记录隧道是否在运行，升级后需要重连。
WAS_RUNNING=0
if [ -f /var/lib/vpngate-fwmark/jp.pid ] || [ -f /var/lib/vpngate-fwmark/kr.pid ]; then
  WAS_RUNNING=1
fi
if [ "$UPGRADE" -eq 1 ] && [ "$WAS_RUNNING" -eq 1 ]; then
  /usr/local/bin/vpngate-fwmark disconnect 2>/dev/null || true
fi

# 安装依赖：Debian/Ubuntu 用 apt，其它发行版用 dnf/yum/pacman。
if command -v apt-get >/dev/null 2>&1; then
  apt-get update
  apt-get install -y openvpn iptables iproute2 python3 curl iputils-ping
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y openvpn iptables iproute2 python3 curl iputils
elif command -v yum >/dev/null 2>&1; then
  yum install -y openvpn iptables iproute2 python3 curl iputils
elif command -v pacman >/dev/null 2>&1; then
  pacman -Sy --noconfirm openvpn iptables iproute2 python curl iputils
else
  echo "未识别的包管理器，请先手动安装 openvpn、iptables、iproute2、python3、curl、ping（iputils-ping）。" >&2
  exit 1
fi

install -m 755 "$SRC_DIR/vpngate-fwmark.py" /usr/local/bin/vpngate-fwmark
mkdir -p /var/lib/vpngate-fwmark /etc/vpngate-fwmark
install -m 644 "$SRC_DIR/vpngate-fwmark-watch.service" /etc/systemd/system/vpngate-fwmark-watch.service
install -m 644 "$SRC_DIR/vpngate-fwmark-watch.timer" /etc/systemd/system/vpngate-fwmark-watch.timer

for u in vpnapp vpnapp-jp vpnapp-kr; do
  id "$u" 2>/dev/null || useradd --system --no-create-home --shell /usr/sbin/nologin "$u"
done

# 路由表起个名字，ip route show table vgjp / vgkr 就能看，比纯数字好认。
grep -q '^201 vgjp' /etc/iproute2/rt_tables 2>/dev/null || echo '201 vgjp' >> /etc/iproute2/rt_tables
grep -q '^202 vgkr' /etc/iproute2/rt_tables 2>/dev/null || echo '202 vgkr' >> /etc/iproute2/rt_tables

modprobe tun 2>/dev/null || true
systemctl daemon-reload 2>/dev/null || true
systemctl enable --now vpngate-fwmark-watch.timer 2>/dev/null || true

if [ "$UPGRADE" -eq 1 ] && [ "$WAS_RUNNING" -eq 1 ]; then
  /usr/local/bin/vpngate-fwmark connect
fi

if [ "$UPGRADE" -eq 1 ]; then
  echo "升级完成，手动指定的出口和状态已保留。"
else
  echo "安装完成。试试："
  echo "  sudo vpngate-fwmark tui                          # 图形界面：自动 / 手动选出口"
  echo "  sudo vpngate-fwmark run --region jp -- curl -s ifconfig.me   # 只这条命令走日本"
  echo "  sudo vpngate-fwmark run --region kr -- curl -s ifconfig.me   # 只这条命令走韩国"
  echo "  curl -s ifconfig.me                               # 本机其它流量不走 VPN"
fi
