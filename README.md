# vpngate-fwmark（Mihomo 版）

[![CI](https://github.com/cctv96/vpngate-fwmark/actions/workflows/ci.yml/badge.svg)](https://github.com/cctv96/vpngate-fwmark/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

自动抓 VPN Gate 的日本、韩国出口，交给 Mihomo（Clash Meta）拨号和切换。
只做一件事：让你指定的程序走日本或韩国出口，其它流量不动。

> **v3 说明：旧版（fwmark / OpenVPN）已直接替换，不再保留。**
> 旧版要自己维护 fwmark、路由表、iptables、专用用户、tun 隧道，
> 任何一环没起来就表现为“按了 s 但没连上、连日志都没有”。
> 新版把拨号和切换交给 Mihomo，切换节点是调 Mihomo 控制 API，
> 不用重启、不用重新拨号。

## 它是怎么工作的

1. 从 VPN Gate 公开 API（`http://www.vpngate.net/api/iphone/`）拉服务器列表。
2. 只留：主机名以 `vpn` 开头、排除 `public-vpn-*`、国家只留日本（JP）和韩国（KR）。
3. 把每个服务器的 OpenVPN 配置解析成 Mihomo 的 `type: openvpn` 节点：
   Mihomo v1.19.25 起自带 OpenVPN 出站，支持 VPN Gate 配置里的
   `AES-128-CBC`、`SHA1`、`ca / cert / key` 内联证书、账号密码 `vpn / vpn`，
   且 VPN Gate 配置里没有 `tls-auth / tls-crypt` 这种容易卡住的字段。
4. 起两个 Mihomo 实例，各占一对端口，可以同时跑：

   | 地区 | 混合端口（程序走这里） | 控制端口（切换 API） | 代理组 |
   |---|---|---|---|
   | 日本 | 7890 | 9090 | JP |
   | 韩国 | 7891 | 9091 | KR |

5. 每 6 小时 systemd timer 跑一次 `watch`，配置过期就重新拉取、重启实例；
   手动指定的出口不会被自动换掉（手动服务器下线时回落自动最优）。

## 安装 / 升级 / 卸载

```bash
# 安装
curl -fsSL https://raw.githubusercontent.com/cctv96/vpngate-fwmark/main/install.sh | sudo bash

# 升级（保留手动指定的出口和状态；从旧版升级时会自动清理
# 旧的 fwmark 规则、路由表 201/202、专用用户 vpnapp-* 和旧 .ovpn）
curl -fsSL https://raw.githubusercontent.com/cctv96/vpngate-fwmark/main/upgrade.sh | sudo bash

# 卸载（保留状态，重装可恢复）
curl -fsSL https://raw.githubusercontent.com/cctv96/vpngate-fwmark/main/uninstall.sh | sudo bash
# 彻底卸载
curl -fsSL https://raw.githubusercontent.com/cctv96/vpngate-fwmark/main/uninstall.sh | sudo bash -s -- --purge
```

安装脚本会从 GitHub 下载固定版本的 Mihomo 二进制（v1.19.33，约 60MB，
按 `uname -m` 选 amd64 / arm64），装到 `/usr/local/bin/mihomo`，
并验证 `mihomo -v` 能跑。

## 用法

```bash
sudo vpngate-fwmark tui        # 图形界面：Tab 切换地区，上下选节点，回车即切
sudo vpngate-fwmark connect    # 启动两个实例
sudo vpngate-fwmark disconnect # 停掉两个实例
sudo vpngate-fwmark status     # 当前出口、进程、端口
sudo vpngate-fwmark doctor     # 系统检查：mihomo、配置、实例、控制端口
sudo vpngate-fwmark update     # 手动重新拉取并生成配置（在跑的实例会重启加载）
sudo vpngate-fwmark list       # 候选列表（本地实测延迟 + VPN Gate 公布 Ping）
```

指定程序走 VPN：

```bash
# 只这条命令走日本（run 会给它设代理环境变量，见下面“重要区别”）
sudo vpngate-fwmark run --region jp -- curl -s ifconfig.me
sudo vpngate-fwmark run --region kr -- curl -s ifconfig.me
```

手动指定 / 恢复自动：

```bash
sudo vpngate-fwmark set --region jp --server vpn341881580.opengw.net
sudo vpngate-fwmark set --region jp --auto
```

信誉 / 延迟（和旧版一样，欺诈分是多源综合参考，不是官方判决）：

```bash
sudo vpngate-fwmark reputation --ip 101.111.161.173 --via jp
sudo vpngate-fwmark ping --ip 101.111.161.173
```

TUI 按键：`Tab` 切换地区，`↑/↓` 或 `j/k` 选节点，`回车` 手动指定（API 即切），
`a` 恢复自动，`u` Mihomo 测速选最快，`p` 信誉详情，`r` 刷新列表，`s` 启停实例，`c` 系统检查，
`l` 看日志（最近 20 行），`q` 退出（实例保持运行）。

TUI 是按 Mihomo 逻辑做的，不是按旧的候选列表做的：

- 列表 = Mihomo 代理组的 `all`（实时），不是 VPN Gate 候选前 20 名；
  实例没起时才回落到候选列表。
- 当前节点 = 代理组的 `now`（实时，`●` 标记），不是上次生成配置时
  写进 meta 文件的记录；你在面板或其它工具里切了节点，TUI 下一秒就能看到。
- 延迟 = Mihomo `/delay` 走该节点实测（经隧道拨号后的往返），不是
  本机 ping 服务器 IP；实例没起时才显示本地延迟。
- `u` 是 Mihomo 测速选最快：在已测出的 Mihomo 延迟里挑最小的切过去
  （还没测完时先触发测速，过几秒再按一次 `u`）。
- 地区卡片还显示该组节点数和当前连接数。
- 启动时不再联网拉 VPN Gate（网络一慢 TUI 会卡黑屏）：本地候选
  未加载时按 `r` 刷新，实例在跑时列表直接来自 Mihomo 代理组。

## 重要区别：新版是代理分流，不是包分流

旧版是包级别分流：任何程序（支不支持代理都行）都能走指定出口。
新版是代理级别分流：**程序要走代理才行**。

- `run` 会给这条命令设 `http_proxy / https_proxy`（走混合端口）和
  `all_proxy`（socks5，走混合端口），curl、wget、git、python requests
  这类认环境变量的程序直接就能用。
- 浏览器要在设置里手动填代理：日本填 `127.0.0.1:7890`，韩国填 `127.0.0.1:7891`。
- 不认代理的程序目前走不了，这是换 Mihomo 换来的代价，不是 bug。
  以后如需包级别分流，再考虑 Mihomo TUN 模式。

## 状态文件

都在 `/var/lib/vpngate-fwmark/`：

- `jp.yaml` / `kr.yaml`：生成的 Mihomo 配置
- `jp.json` / `kr.json`：当前选中服务器的元数据
- `jp.pid` / `kr.pid`、`jp.log` / `kr.log`：实例进程和日志
- `candidates.json`：候选列表（全部，用于给 Mihomo 节点补 IP / 速度信息）
- `manual.json`：手动指定的出口
- `reputation.json`：信誉缓存（24 小时，未知结果 5 分钟后可重查）

启动失败时先看 `doctor`，再看对应地区的日志末尾。
Mihomo 日志里如果出现 `dns resolve failed`，说明 Mihomo 解析
VPN Gate 主机名失败：配置里 DNS 已包含 8.8.8.8、1.1.1.1、
223.5.5.5、114.114.114.114 兜底，仍失败请先检查本机 DNS。

## 风险提示（实话）

- VPN Gate 是志愿者服务器，随时可能下线、变慢、换 IP，列表是快照，
  不是长期可用的固定节点；`watch` 每 6 小时刷新一次。
- Mihomo 的 OpenVPN 是 Go 重写版，不是官方 openvpn 二进制，
  和 SoftEther 服务器的握手兼容性需要在真实机器上验证：
  配置校验（`mihomo -t`）通过、控制 API 切换成功，不等于隧道已通。
  验证方法：`run --region jp -- curl -s ifconfig.me` 返回的 IP
  应该是日本出口 IP，而不是本机 IP。
- 欺诈分说明：机房 IP 对 VPN 出口来说是正常的，单独看机房标记
  不能判为脏 IP；重点看欺诈分 / 滥用分是否高。proxycheck 免费端点
  对同一 IP 有时会回 66 有时回 0，程序查两次取最高分，宁可往高了算。

## 开发

```bash
python3 -m py_compile vpngate-fwmark.py
python3 -m unittest discover -s tests -v
bash -n install.sh uninstall.sh upgrade.sh
```

主程序只用 Python 3 标准库，不依赖 PyYAML（Mihomo 配置是程序自己拼的 YAML 文本）。

## License

MIT
