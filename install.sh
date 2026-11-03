#!/bin/bash
# vpngate-fwmark v3（Mihomo 版）一键安装 / 升级
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
# 只替换程序本体、Mihomo 二进制和 systemd 单元；升级前实例在运行，
# 升级后会自动重连。
# 从旧版（fwmark / OpenVPN）升级时，会先停掉旧隧道、清理旧的
# fwmark 规则、路由表 201/202、专用用户 vpnapp-* 和旧 .ovpn 配置，
# 因为新版完全不用这些东西了。
set -euo pipefail

REPO="cctv96/vpngate-fwmark"
BRANCH="${VG_BRANCH:-main}"
MIHOMO_VERSION="v1.19.33"
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

# 升级前记录实例是否在运行，升级后需要重连。
WAS_RUNNING=0
if [ -f /var/lib/vpngate-fwmark/jp.pid ] || [ -f /var/lib/vpngate-fwmark/kr.pid ]; then
  WAS_RUNNING=1
fi
if [ "$UPGRADE" -eq 1 ] && [ "$WAS_RUNNING" -eq 1 ]; then
  # 旧版二进制的 disconnect 会停 openvpn 隧道并清 fwmark 规则；
  # 新版二进制的 disconnect 会停 Mihomo 实例。两种都先跑一次，错了也不怕。
  /usr/local/bin/vpngate-fwmark disconnect 2>/dev/null || true
fi

cleanup_legacy() {
  # 旧版 fwmark / OpenVPN 残留：规则、路由表、iptables 标记、路由表名、
  # 专用用户、旧 .ovpn / auth.txt。全部 best-effort，失败忽略。
  for mark in 0x1a01 0x1a02 1 2; do
    ip rule del fwmark "$mark" table 201 2>/dev/null || true
    ip rule del fwmark "$mark" table 202 2>/dev/null || true
    ip rule del fwmark "$mark" table 101 2>/dev/null || true
    ip rule del fwmark "$mark" table 102 2>/dev/null || true
  done
  for tbl in 201 202 101 102; do
    ip route flush table "$tbl" 2>/dev/null || true
  done
  for u in vpnapp vpnapp-jp vpnapp-kr; do
    iptables -t mangle -D OUTPUT -m owner --uid-owner "$u" -j MARK --set-mark 0x1a01 2>/dev/null || true
    iptables -t mangle -D OUTPUT -m owner --uid-owner "$u" -j MARK --set-mark 0x1a02 2>/dev/null || true
    iptables -t mangle -D OUTPUT -m owner --uid-owner "$u" -j MARK --set-mark 1 2>/dev/null || true
    iptables -t mangle -D OUTPUT -m owner --uid-owner "$u" -j MARK --set-mark 2 2>/dev/null || true
  done
  sed -i '/^201 vgjp$/d; /^202 vgkr$/d' /etc/iproute2/rt_tables 2>/dev/null || true
  rm -f /var/lib/vpngate-fwmark/jp.ovpn /var/lib/vpngate-fwmark/kr.ovpn \
        /var/lib/vpngate-fwmark/auth.txt
  if [ "$UPGRADE" -eq 1 ]; then
    for u in vpnapp vpnapp-jp vpnapp-kr; do
      userdel "$u" 2>/dev/null || true
    done
  fi
}

# 安装依赖：Debian/Ubuntu 用 apt，其它发行版用 dnf/yum/pacman。
# 新版不再需要 openvpn、iptables、iproute2，只需要 python3、curl、
# gzip（解压 Mihomo）和 ping（本地延迟实测）。
if command -v apt-get >/dev/null 2>&1; then
  apt-get update
  apt-get install -y python3 curl gzip iputils-ping
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y python3 curl gzip iputils
elif command -v yum >/dev/null 2>&1; then
  yum install -y python3 curl gzip iputils
elif command -v pacman >/dev/null 2>&1; then
  pacman -Sy --noconfirm python curl gzip iputils
else
  echo "未识别的包管理器，请先手动安装 python3、curl、gzip、ping。" >&2
  exit 1
fi

# 下载 Mihomo 二进制（固定版本，架构按 uname 识别）。
case "$(uname -m)" in
  x86_64|amd64) MIHOMO_ARCH="amd64" ;;
  aarch64|arm64) MIHOMO_ARCH="arm64" ;;
  *) echo "不支持的架构：$(uname -m)，Mihomo 没有对应的官方二进制。" >&2; exit 1 ;;
esac
echo "正在下载 Mihomo $MIHOMO_VERSION（linux-$MIHOMO_ARCH）……"
MIHOMO_TMP="$(mktemp -d)"
trap 'rm -rf "$MIHOMO_TMP"' EXIT
curl -fsSL "https://github.com/MetaCubeX/mihomo/releases/download/$MIHOMO_VERSION/mihomo-linux-$MIHOMO_ARCH-$MIHOMO_VERSION.gz" \
  -o "$MIHOMO_TMP/mihomo.gz"
gunzip -f "$MIHOMO_TMP/mihomo.gz"
install -m 755 "$MIHOMO_TMP/mihomo" /usr/local/bin/mihomo
/usr/local/bin/mihomo -v

install -m 755 "$SRC_DIR/vpngate-fwmark.py" /usr/local/bin/vpngate-fwmark
mkdir -p /var/lib/vpngate-fwmark /etc/vpngate-fwmark
install -m 644 "$SRC_DIR/vpngate-fwmark-watch.service" /etc/systemd/system/vpngate-fwmark-watch.service
install -m 644 "$SRC_DIR/vpngate-fwmark-watch.timer" /etc/systemd/system/vpngate-fwmark-watch.timer

if [ "$UPGRADE" -eq 1 ]; then
  cleanup_legacy
fi

systemctl daemon-reload 2>/dev/null || true
systemctl enable --now vpngate-fwmark-watch.timer 2>/dev/null || true

if [ "$UPGRADE" -eq 1 ] && [ "$WAS_RUNNING" -eq 1 ]; then
  /usr/local/bin/vpngate-fwmark connect
fi

if [ "$UPGRADE" -eq 1 ]; then
  echo "升级完成（Mihomo 版），手动指定的出口和状态已保留，旧 fwmark / OpenVPN 残留已清理。"
else
  echo "安装完成。试试："
  echo "  sudo vpngate-fwmark tui                          # 图形界面：回车即切节点"
  echo "  sudo vpngate-fwmark run --region jp -- curl -s ifconfig.me   # 只这条命令走日本（混合端口 7890）"
  echo "  sudo vpngate-fwmark run --region kr -- curl -s ifconfig.me   # 只这条命令走韩国（混合端口 7891）"
  echo "  注意：新版是代理分流，程序要认代理环境变量才走 VPN；浏览器需手动填代理 127.0.0.1:7890（日本）或 7891（韩国）。"
fi
