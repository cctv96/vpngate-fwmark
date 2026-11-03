# vpngate-fwmark

[![CI](https://github.com/cctv96/vpngate-fwmark/actions/workflows/ci.yml/badge.svg)](https://github.com/cctv96/vpngate-fwmark/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

从 [VPN Gate](https://www.vpngate.net/cn/) 自动拉取服务器，只让**指定程序**走 VPN，
其它程序的流量完全不动。支持日本、韩国两个独立出口，每个地区有自己的
fwmark 和路由表，图形界面（TUI）里可以自动选出口，也可以在必要时手动指定。

> 新手友好：你不需要手动敲路由命令，隧道连上后应用会自动写好
> fwmark 规则和路由表，断开时也会自动清理。

## 特性

- **只分流指定程序**：以专用用户运行目标程序，其它流量走主路由表。
- **双地区、双出口**：日本、韩国各一条隧道，互不干扰。
- **自动更新**：每 6 小时检查一次，配置过期或隧道失联就换到新的最优服务器。
- **TUI 手动指定**：自动选出口是默认，必要时可以在 TUI 里逐个地区手动换出口。
- **IP 信誉检查**：查出口 IP 的欺诈分、代理 / 机房标记，自动选时可跳过高风险出口。
- **天然 kill-switch**：隧道断了，标记流量无路可走，不会回落到主路由表泄漏。
- **零第三方依赖**：主体是 Python 3 标准库，TUI 用自带 `curses`。

## 快速开始

### 系统要求

- Linux（Debian / Ubuntu 已测试，其它发行版见安装脚本的包管理器分支）
- root 权限
- 内核支持 tun 设备
- 依赖由安装脚本自动安装：`openvpn`、`iptables`、`iproute2`、`python3`、`curl`

### 一键安装

```bash
curl -fsSL https://raw.githubusercontent.com/cctv96/vpngate-fwmark/main/install.sh | sudo bash
```

### 一键升级

升级只替换程序本体和 systemd 单元，保留 `/var/lib/vpngate-fwmark`
下的状态和手动指定的出口；升级前隧道在运行，升级后会自动重连。

```bash
curl -fsSL https://raw.githubusercontent.com/cctv96/vpngate-fwmark/main/upgrade.sh | sudo bash
```

### 一键卸载

```bash
curl -fsSL https://raw.githubusercontent.com/cctv96/vpngate-fwmark/main/uninstall.sh | sudo bash
# 彻底删干净（含状态、手动指定、专用用户）：
curl -fsSL https://raw.githubusercontent.com/cctv96/vpngate-fwmark/main/uninstall.sh | sudo bash -s -- --purge
```

### 本地安装（已克隆仓库）

```bash
git clone https://github.com/cctv96/vpngate-fwmark.git
cd vpngate-fwmark
sudo ./install.sh
sudo ./upgrade.sh   # 升级
sudo ./uninstall.sh # 卸载
```

## 使用方法

### TUI：自动选出口，必要时手动指定

```bash
sudo vpngate-fwmark tui
```

| 按键 | 作用 |
|------|------|
| Tab | 切换日本 / 韩国 |
| 上 / 下（或 j / k） | 在该地区的候选服务器里移动（列表以 IP 为主显示） |
| 回车 | 把选中的服务器设为该地区的手动出口，立即切换隧道 |
| a | 该地区恢复自动选择 |
| p | 查选中 IP 的信誉详情 |
| c | 系统检查（全屏 doctor） |
| l | 看选中地区的日志（最近 20 行） |
| r | 重新拉取服务器列表 |
| s | 启停该地区的隧道 |
| q | 退出 TUI，隧道保持运行 |

TUI 说明：顶栏、地区卡片、运行状态用颜色区分，候选列表按屏幕高度
自动截断并滚动，小终端或窗口缩放时不会崩溃；空列表、刷新后列表
变短、手动换服失败时都不会先断旧隧道。

启动前先系统检查：

```bash
sudo vpngate-fwmark doctor
```

`doctor` 会逐项查 root、openvpn、`/dev/net/tun`、ip / iptables / ping、
状态目录、路由表名、每个地区的配置 / 进程 / 用户 / 日志。
`✗` 是关键问题（缺了隧道起不来），`○` 只是“还没连过”（配置由 connect 生成、
用户启动时自动建、隧道没起日志当然没有），不是故障。
`connect` 和 TUI 启动时也会先过关键项，没过就直接说缺什么，
不再假装“启动中”然后让你去 tail 一个不存在的日志；
启动失败的原因也会写进对应地区的日志文件本身。

每行候选后面都带欺诈分，例如 `欺诈 0.66`，后台线程查（最多 3 个并发），
只查当前屏幕上显示的几行，不卡界面；查到就自动刷新显示，`…` 是正在查，
`未知` 是源没返回分数。24 小时缓存里的结果进 TUI 就直接显示。

延迟列是本地实测，不是 VPN Gate 公布值：CSV 里的 Ping 是 VPN Gate 自己测的
（日本服务器显示 2 ms 很正常），从你的机器看根本不是这个数。TUI 每行显示的
`本地延迟` 是本机到该服务器实测的，先用 `ping`（ICMP），ping 被挡时回落到
TCP 443 握手计时并标 `ms(TCP)`；测不到显示 `测不到`。`list` 也默认实测本地延迟，
并同时保留官方 Ping 一列对照。单独测一个 IP：

```bash
sudo vpngate-fwmark ping --ip 101.111.161.173
```

如果直连打不开信誉接口（在国内常见），不用再搭 HTTP 代理——
直接走已经采集来的 VPN 隧道发请求，隧道本身就是代理：

```bash
# TUI 里自动按地区走隧道：日本节点走 tun-jp，韩国节点走 tun-kr，
# 隧道没起时自动回落直连，隧道启动后“未知”会在 5 分钟内重查。
sudo vpngate-fwmark tui

# 命令行单独查，走指定地区隧道：
sudo vpngate-fwmark reputation --ip 101.111.161.173 --via jp
sudo vpngate-fwmark reputation --ip 182.225.221.34 --via kr
```

原理：信誉请求的 socket 打上该地区的 fwmark（日本 0x1a01 / 韩国 0x1a02），
内核就会按路由表走对应隧道；查的是参数里的 IP，不是出口 IP，
所以走哪个隧道出，结果是一样的，区别只是“能不能发出去”。

HTTP 代理只是备选（比如隧道也没起、直连也被挡时）：

```bash
sudo vpngate-fwmark reputation --ip 101.111.161.173 --force --proxy http://127.0.0.1:7890
# 或 VG_PROXY=http://127.0.0.1:7890 sudo -E vpngate-fwmark tui（sudo 要加 -E 才能传环境变量）
```

不用进 TUI 也能手动指定：

```bash
sudo vpngate-fwmark set --region jp --server vpn341881580.opengw.net
sudo vpngate-fwmark set --region jp --server 124.18.130.154  # 也可以直接用 IP
sudo vpngate-fwmark set --region kr --auto
```

手动指定的地区，定时检查不会把它自动换掉；只有该服务器从列表里
消失时，才会回落到自动最优。

### 只让指定程序走 VPN

```bash
sudo vpngate-fwmark run --region jp -- firefox
sudo vpngate-fwmark run --region kr -- curl -s ifconfig.me
curl -s ifconfig.me  # 本机其它流量不走 VPN
```

### 常用命令

```bash
sudo vpngate-fwmark list                    # 列出日韩 vpn* 候选服务器
sudo vpngate-fwmark connect                 # 启动两个隧道（自动先更新）
sudo vpngate-fwmark disconnect              # 停隧道并清理规则
sudo vpngate-fwmark status                  # 查看两个地区的出口和路由表
sudo vpngate-fwmark update                  # 手动强制更新
sudo vpngate-fwmark update --check-reputation  # 自动选时跳过高风险出口
sudo vpngate-fwmark reputation --ip 101.111.161.173  # 查单个 IP 的信誉
```

## 分流原理

| 地区 | fwmark | 路由表 | 隧道 | 运行用户 |
|------|--------|--------|------|----------|
| 日本 JP | `0x1a01` | 201（`vgjp`） | `tun-jp` | `vpnapp-jp` |
| 韩国 KR | `0x1a02` | 202（`vgkr`） | `tun-kr` | `vpnapp-kr` |

```
目标程序 --(以 vpnapp-jp / vpnapp-kr 运行)-->
  iptables -t mangle OUTPUT -m owner --uid-owner <用户> -j MARK --set-mark 0x1a0x
  ip rule add fwmark 0x1a0x/0xffff table 20x
  ip route add default via <tun 对端网关> dev tun-xx table 20x
其它程序 --> 主路由表，不受影响
OpenVPN 本身以 root 运行、不带标记 --> 走主路由表，不会环路
```

fwmark 不用 1、2：那两个太常用，容易和 Docker、其它 VPN 撞。
新值带 `/0xffff` 全掩码，只精确匹配本应用的标记。

关键点：

- OpenVPN 配置加了 `route-nopull`，不会改全局默认路由。
- 隧道断了，表里没有可用路由，标记流量直接丢弃，不会回落主表泄漏。
- `disconnect` 或 OpenVPN `--down` 钩子会清理规则和路由表。

## 服务器筛选规则

数据源是 VPN Gate 公开 CSV：`http://www.vpngate.net/api/iphone/`。

- 主机名以 `vpn` 开头，排除 `public-vpn-*`
- 国家只限 JP（日本）、KR（韩国）
- 必须带 OpenVPN 配置
- 排序：速度从高到低，Ping 从低到高
- 账号：VPN Gate 公开账号 `vpn` / `vpn`
- 远程地址默认用 DDNS 主机名（`*.opengw.net`），
  `update --use-ip` 可改用 IP

VPN Gate 服务器由志愿者提供，会动态上下线；速度、Ping、会话数
都是抓取那一刻的快照，使用前请在官网确认服务器仍在线。

## IP 信誉检查

```bash
sudo vpngate-fwmark reputation --ip 101.111.161.173
sudo vpngate-fwmark update --check-reputation
```

免费源：

- `ip-api.com`：国家 / ISP / 是否代理 / 是否机房 / 是否移动网络
- `proxycheck.io`：默认欺诈分来源，风险分 0~100（程序里换算成 0~1），无需 Key
- `getipintel`：欺诈分 0~1，仅当设置了 `VG_CONTACT_EMAIL` 为你的真实邮箱时才查。
  注意：它不接受 `example.com` 这类占位邮箱，会返回错误码并封 IP，
  之前欺诈分突然变 `None` 就是这个原因；没设置真实邮箱时程序会明说，
  不再静默失败。

可选付费 Key（有才查）：环境变量 `ABUSEIPDB_KEY`、`IPQS_KEY`，
分别对应 AbuseIPDB（滥用分 0~100）和 IPQualityScore（欺诈分 0~100）。

结果缓存 24 小时，`reputation --force` 可强制重查。旧版缓存（欺诈分为 `None` 的那批）
升级后会自动视为过期重查，不用手动清缓存。

提醒：VPN Gate 本来就是机房服务器，机房标记本身不代表脏 IP，
重点看欺诈分 / 滥用分。自动过滤只跳过“高”风险，不会因为机房
就把所有出口都排除。`ipleak.net` 是网页泄漏测试，没有公开 API，
程序里没法直接调用，所以没有用它。

## 配置文件位置

| 内容 | 位置 |
|------|------|
| 程序本体 | `/usr/local/bin/vpngate-fwmark` |
| 各地区配置 | `/var/lib/vpngate-fwmark/jp.ovpn`、`kr.ovpn` |
| 各地区状态 | `/var/lib/vpngate-fwmark/jp.json`、`kr.json` |
| 候选列表 | `/var/lib/vpngate-fwmark/candidates.json` |
| 手动指定 | `/var/lib/vpngate-fwmark/manual.json` |
| 信誉缓存 | `/var/lib/vpngate-fwmark/reputation.json`（24 小时） |
| 自动更新 | `/etc/systemd/system/vpngate-fwmark-watch.timer`（每 6 小时） |

## 故障排查

| 现象 | 可能原因 / 处理 |
|------|----------------|
| `run` 的程序没网，其它程序正常 | 隧道没起来或标记流量被丢弃是预期行为（kill-switch），先跑 `status` 看隧道和路由表 |
| 隧道起来但还是走本地 IP | 检查是不是用 `run --region` 启动的；直接启动的程序不会被标记 |
| 服务器突然连不上 | 志愿者服务器已下线，跑 `update` 或进 TUI 换一台 |
| DNS 解析不走隧道 | 标记流量里的 DNS 若走本机 127.0.0.53 等本地解析器，解析本身可能不走隧道；对 DNS 敏感的场景请在目标程序里手动指定走隧道内的 DNS |
| `iptables` 报错 | 你的系统可能已完全禁用 iptables，需把 mangle 规则等价改写为 nftables，路由部分不变 |

## 开发

```bash
python3 -m py_compile vpngate-fwmark.py
bash -n install.sh upgrade.sh uninstall.sh
python3 -m unittest discover -s tests -v
```

提交到 `main` 或打 `v*` 标签都会触发 GitHub Actions：

- `test`：多版本 Python 编译 + shell 语法检查 + 单元测试
- `package`：打包 `vpngate-fwmark.zip` 作为构建产物
- `release`：打 `v*` 标签时自动创建 Release 并附上 zip 包

## 安全与合规

- 本项目只使用 VPN Gate 公开的志愿者服务器和公开账号，不提供任何
  私有账号或绕过认证的方法。
- 请遵守你所在地区的法律法规使用 VPN，本项目不对使用方式负责。
- 出口 IP 是志愿者提供的共享 IP，不要用它传输敏感账号或重要数据。

## 致谢

- [VPN Gate](https://www.vpngate.net/)：筑波大学的公开 VPN 研究项目，
  本项目的数据源和服务器均来自该项目。

## 许可证

MIT，见 [LICENSE](LICENSE)。
