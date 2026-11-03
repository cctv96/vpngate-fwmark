#!/bin/bash
# vpngate-fwmark 一键卸载
#
#   curl -fsSL https://raw.githubusercontent.com/cctv96/vpngate-fwmark/main/uninstall.sh | sudo bash
#   sudo ./uninstall.sh            # 只删程序和服务，保留状态（可重装恢复）
#   sudo ./uninstall.sh --purge    # 连状态、手动指定、专用用户一起删干净
#
# 卸载会先停掉两个隧道并清理 fwmark 规则和路由表，不会动主路由表。
set -euo pipefail

PURGE=0
if [ "${1:-}" = "--purge" ]; then
  PURGE=1
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "请用 root 运行：sudo bash uninstall.sh" >&2
  exit 1
fi

if [ -x /usr/local/bin/vpngate-fwmark ]; then
  /usr/local/bin/vpngate-fwmark disconnect 2>/dev/null || true
fi

systemctl disable --now vpngate-fwmark-watch.timer 2>/dev/null || true
systemctl disable --now vpngate-fwmark-watch.service 2>/dev/null || true
rm -f /etc/systemd/system/vpngate-fwmark-watch.service \
      /etc/systemd/system/vpngate-fwmark-watch.timer
systemctl daemon-reload 2>/dev/null || true
rm -f /usr/local/bin/vpngate-fwmark

if [ "$PURGE" -eq 1 ]; then
  rm -rf /var/lib/vpngate-fwmark /etc/vpngate-fwmark
  sed -i '/^201 vgjp$/d; /^202 vgkr$/d' /etc/iproute2/rt_tables 2>/dev/null || true
  for u in vpnapp vpnapp-jp vpnapp-kr; do
    userdel "$u" 2>/dev/null || true
  done
  echo "卸载完成（--purge：状态、手动指定和专用用户已一并删除）。"
else
  echo "卸载完成。状态保留在 /var/lib/vpngate-fwmark，重装后可恢复；"
  echo "要彻底删干净请用：sudo ./uninstall.sh --purge"
fi
