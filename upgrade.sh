#!/bin/bash
# vpngate-fwmark 一键升级
#
#   curl -fsSL https://raw.githubusercontent.com/cctv96/vpngate-fwmark/main/upgrade.sh | sudo bash
#
# 本质是重新跑一遍 install.sh --upgrade：替换程序本体和 systemd 单元，
# 保留 /var/lib/vpngate-fwmark 下的状态和手动指定的出口，升级前隧道
# 在运行，升级后会自动重连。
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "请用 root 运行：sudo bash upgrade.sh" >&2
  exit 1
fi

if [ -f "$(dirname "${BASH_SOURCE[0]}")/install.sh" ]; then
  bash "$(dirname "${BASH_SOURCE[0]}")/install.sh" --upgrade
else
  curl -fsSL https://raw.githubusercontent.com/cctv96/vpngate-fwmark/main/install.sh -o /tmp/vpngate-fwmark-install.sh
  bash /tmp/vpngate-fwmark-install.sh --upgrade
  rm -f /tmp/vpngate-fwmark-install.sh
fi
