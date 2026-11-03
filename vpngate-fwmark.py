#!/usr/bin/env python3
"""
vpngate-fwmark v2: 双地区、双 fwmark、双隧道 + TUI

两个地区，两个完全独立的出口：
  日本 JP: fwmark 0x1a01, 路由表 201, 隧道 tun-jp, 运行用户 vpnapp-jp
  韩国 KR: fwmark 0x1a02, 路由表 202, 隧道 tun-kr, 运行用户 vpnapp-kr

  为什么不用 1、2：1、2 太常用，Docker、其它 VPN、系统服务都可能
  占用，撞上就会互相抢流量。0x1a01 / 0x1a02 是特意挑的不常用值，
  且 ip rule 带 /0xffff 全掩码，只精确匹配这两个标记，不会误伤
  别人打的标记。旧版的 1 / 101、2 / 102 规则在 connect / disconnect
  时会自动清理一次。

  以 vpnapp-jp 运行的程序 -> 标记 1 -> 表 101 -> 日本隧道
  以 vpnapp-kr 运行的程序 -> 标记 2 -> 表 102 -> 韩国隧道
  其它程序 -> 主路由表，不受影响
  OpenVPN 本身以 root 运行、不带标记 -> 走主路由表，不环路

自动选择：
  update / connect / watch 默认给每个地区选速度最高、Ping 最低的
  vpn* 服务器（排除 public-vpn-*），每 6 小时过期重选。

手动指定（TUI）：
  sudo vpngate-fwmark tui
  Tab 切换地区，上下选候选服务器，回车设为该地区的手动出口，
  按 a 恢复该地区自动选择，按 r 重新拉取列表，按 q 退出（隧道保持运行）。

命令行手动指定也可以，不用进 TUI：
  sudo vpngate-fwmark set --region jp --server vpn341881580.opengw.net
  sudo vpngate-fwmark set --region kr --auto

其它用法（需 root）：
  vpngate-fwmark update / list / connect / disconnect / status
  vpngate-fwmark run --region jp -- curl -s ifconfig.me
  vpngate-fwmark run --region kr -- firefox
  vpngate-fwmark watch   # systemd timer 每 6 小时调用

账号：VPN Gate 公开账号 vpn / vpn。配置用 route-nopull，不改全局路由。
"""

import argparse
import base64
import csv
import io
import json
import os
import subprocess
import sys
import threading
import time
import urllib.request

API_URL = "http://www.vpngate.net/api/iphone/"
STATE_DIR = os.environ.get("VG_STATE_DIR", "/var/lib/vpngate-fwmark")
CONFIG_DIR = os.environ.get("VG_CONFIG_DIR", "/etc/vpngate-fwmark")
AUTH_FILE = os.path.join(STATE_DIR, "auth.txt")
CANDIDATES_FILE = os.path.join(STATE_DIR, "candidates.json")
MANUAL_FILE = os.path.join(STATE_DIR, "manual.json")
MAX_AGE = 6 * 3600

# 地区 -> fwmark / 路由表 / 隧道名 / 运行用户
# fwmark 用不常用的 0x1a01 / 0x1a02，路由表用 201 / 202，避开 1、2、100 这种常用值。
REGIONS = {
    "jp": {"name": "日本", "code": "JP", "mark": "0x1a01", "table": 201,
           "dev": "tun-jp", "user": "vpnapp-jp"},
    "kr": {"name": "韩国", "code": "KR", "mark": "0x1a02", "table": 202,
           "dev": "tun-kr", "user": "vpnapp-kr"},
}
# 旧版用过的标记 / 路由表，升级时清理掉，避免新旧规则并存。
LEGACY_MARKS = [(1, 101), (2, 102)]


def fwmark_rule(info):
    """ip rule 用的带全掩码的标记，只精确匹配本应用的标记。"""
    return f"{info['mark']}/0xffff"


def cleanup_legacy():
    for mark, table in LEGACY_MARKS:
        for user in ("vpnapp-jp", "vpnapp-kr", "vpnapp"):
            run(["iptables", "-t", "mangle", "-D", "OUTPUT",
                 "-m", "owner", "--uid-owner", user,
                 "-j", "MARK", "--set-mark", str(mark)])
        run(["ip", "rule", "del", "fwmark", str(mark), "table", str(table)],
            check=False)
        run(["ip", "route", "flush", "table", str(table)], check=False)
DEV_TO_REGION = {v["dev"]: k for k, v in REGIONS.items()}


def run(cmd, check=False):
    return subprocess.run(cmd, text=True, capture_output=True, check=check)


def need_root():
    if os.geteuid() != 0:
        sys.exit("需要 root 权限运行（sudo）。")


def ensure_dirs():
    os.makedirs(STATE_DIR, exist_ok=True)
    os.makedirs(CONFIG_DIR, exist_ok=True)


def region_files(region):
    return {
        "ovpn": os.path.join(STATE_DIR, f"{region}.ovpn"),
        "meta": os.path.join(STATE_DIR, f"{region}.json"),
        "pid": os.path.join(STATE_DIR, f"{region}.pid"),
        "log": os.path.join(STATE_DIR, f"{region}.log"),
    }


def load_json(path, default):
    try:
        return json.load(open(path))
    except Exception:
        return default


def fetch_csv(url=API_URL, timeout=30):
    req = urllib.request.Request(url, headers={"User-Agent": "vpngate-fwmark/2.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="replace")


def parse_servers(text):
    """解析 CSV，过滤 vpn* + 日韩，返回全局按速度/Ping 排好的列表。"""
    lines = text.splitlines()
    header_idx = next(i for i, ln in enumerate(lines) if ln.startswith("#HostName"))
    reader = csv.DictReader(io.StringIO("\n".join(lines[header_idx:])))
    out = []
    for row in reader:
        host = (row.get("#HostName") or "").strip()
        country = (row.get("CountryShort") or "").strip()
        config_b64 = (row.get("OpenVPN_ConfigData_Base64") or "").strip()
        if not host.startswith("vpn") or host.startswith("public-vpn"):
            continue
        if country not in ("JP", "KR"):
            continue
        if not config_b64:
            continue
        try:
            speed = int(row.get("Speed") or 0)
            ping = int(row.get("Ping") or 9999)
            sessions = int(row.get("NumVpnSessions") or 0)
            score = int(row.get("Score") or 0)
        except ValueError:
            continue
        out.append({
            "host": host,
            "fqdn": host if "." in host else host + ".opengw.net",
            "ip": (row.get("IP") or "").strip(),
            "country": country,
            "country_long": (row.get("CountryLong") or "").strip(),
            "ping": ping, "speed_mbps": round(speed / 1_000_000, 2),
            "speed_bps": speed, "sessions": sessions, "score": score,
            "uptime": (row.get("Uptime") or "").strip(),
            "config_b64": config_b64,
        })
    out.sort(key=lambda s: (-s["speed_bps"], s["ping"]))
    return out


def measure_local_latency(ip, timeout=2):
    """本地到 VPN 服务器的延迟，单位 ms，返回 (ms, 方法) 或 (None, None)。
    注意：CSV 里的 Ping 是 VPN Gate 公布的值（它自己测的，日本服务器
    显示 2 ms 很正常），从中国用户机器上看根本不是这个数，所以不能用它
    当本地延迟。这里从本机实测：
      1. 首选 ping 命令（ICMP，最标准；需要 ping 命令，见 install.sh 的
         iputils-ping 依赖；容器里 raw socket 被禁时会失败，走第 2 步）。
      2. 回落 TCP 握手：直连该 IP 的 443 端口计时，端口关了也会回 RST，
         那个往返时间就是延迟；只有超时 / 被防火墙丢包才算测不到。
         TCP 直连不走 HTTP 代理，测的是到服务器本身，不是到代理。
    返回的方法会标出来：'ping' 或 'tcp'，让用户知道这个数是怎么来的。"""
    try:
        out = subprocess.run(["ping", "-c", "1", "-W", str(timeout), ip],
                             capture_output=True, text=True, timeout=timeout + 2)
        if "time=" in out.stdout:
            val = out.stdout.split("time=")[-1].split()[0]
            return float(val), "ping"
    except Exception:
        pass
    try:
        import socket
        start = time.time()
        try:
            with socket.create_connection((ip, 443), timeout=timeout):
                pass
        except ConnectionRefusedError:
            pass  # 端口关了但回了 RST，往返时间仍然有效
        return round((time.time() - start) * 1000, 1), "tcp"
    except Exception:
        return None, None


def candidates_by_region(servers):
    """按地区分组，每组保持速度/Ping 排序。"""
    grouped = {}
    for region, info in REGIONS.items():
        grouped[region] = [s for s in servers if s["country"] == info["code"]]
    return grouped


def build_ovpn(server, region, use_ddns=True):
    """解码官方配置，改成该地区的分流专用配置。"""
    info = REGIONS[region]
    raw = base64.b64decode(server["config_b64"]).decode("utf-8", errors="replace")
    lines, seen_remote, seen_auth, seen_dev = [], False, False, False
    for ln in raw.splitlines():
        stripped = ln.strip()
        if stripped.startswith("remote "):
            if seen_remote:
                continue
            parts = stripped.split()
            port = parts[2] if len(parts) > 2 else "1195"
            target = server["fqdn"] if use_ddns else server["ip"]
            lines.append(f"remote {target} {port}")
            seen_remote = True
        elif stripped.startswith("auth-user-pass"):
            lines.append(f"auth-user-pass {AUTH_FILE}")
            seen_auth = True
        elif stripped.startswith("dev "):
            lines.append(f"dev {info['dev']}")
            seen_dev = True
        elif stripped.startswith(("route ", "redirect-gateway", "dhcp-option")):
            continue
        else:
            lines.append(ln)
    if not seen_dev:
        lines.append(f"dev {info['dev']}")
    if not seen_remote:
        lines.append(f"remote {server['fqdn']} 1195")
    if not seen_auth:
        lines.append(f"auth-user-pass {AUTH_FILE}")
    lines += [
        "route-nopull", "script-security 2",
        f"up {os.path.abspath(__file__)} _up_hook",
        f"down {os.path.abspath(__file__)} _down_hook",
        "persist-tun",
    ]
    return "\n".join(lines) + "\n"


def save_region(region, server, mode, use_ddns=True):
    ensure_dirs()
    files = region_files(region)
    with open(AUTH_FILE, "w") as f:
        f.write("vpn\nvpn\n")
    os.chmod(AUTH_FILE, 0o600)
    with open(files["ovpn"], "w") as f:
        f.write(build_ovpn(server, region, use_ddns=use_ddns))
    meta = {k: v for k, v in server.items() if k != "config_b64"}
    meta["updated_at"] = int(time.time())
    meta["mode"] = mode
    with open(files["meta"], "w") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)
    return meta


def choose_for_region(region, grouped, manual):
    """手动指定的服务器还在列表里就优先用它，否则自动选最优。"""
    cands = grouped.get(region, [])
    if not cands:
        return None, "auto"
    wanted = manual.get(region)
    if wanted:
        for s in cands:
            if s["fqdn"] == wanted or s["host"] == wanted or s["ip"] == wanted:
                return s, "manual"
    return cands[0], "auto"


def cmd_update(args):
    need_root()
    servers = parse_servers(fetch_csv())
    grouped = candidates_by_region(servers)
    if not any(grouped.values()):
        sys.exit("拉取失败：没有符合 vpn* + 日韩条件的服务器。")
    with open(CANDIDATES_FILE, "w") as f:
        json.dump({r: [{k: v for k, v in s.items() if k != "config_b64"}
                        for s in grouped[r][:20]]
                   for r in grouped}, f, ensure_ascii=False, indent=2)
    manual = load_json(MANUAL_FILE, {})
    check_rep = getattr(args, "check_reputation", False)
    for region in REGIONS:
        chosen, mode = choose_for_region(region, grouped, manual)
        if not chosen:
            print(f"{REGIONS[region]['name']}：暂无候选，跳过。")
            continue
        # 可选：自动选时跳过信誉为“高”的出口，最多往后试 5 台。
        # 手动指定的不跳过（用户自己选的，程序不替用户否决），只提示。
        if check_rep and mode == "auto":
            for cand in grouped[region][:5]:
                rep = check_ip_reputation(cand["ip"])
                if rep["risk"] == "高":
                    print(f"跳过高风险出口 {cand['ip']}（{cand['fqdn']}），信誉 {rep['risk']}。")
                    continue
                chosen = cand
                break
        meta = save_region(region, chosen, mode, use_ddns=not getattr(args, "use_ip", False))
        print(f"{meta['country']} 已更新（{mode}）：{meta['fqdn']} "
              f"{meta['speed_mbps']} Mbps / Ping {meta['ping']} ms / "
              f"{meta['sessions']} 会话。")
    return grouped


def cmd_list(args):
    need_root()
    grouped = candidates_by_region(parse_servers(fetch_csv()))
    for region, info in REGIONS.items():
        print(f"\n== {info['name']} {info['code']} "
              f"(fwmark {info['mark']} / 表 {info['table']} / {info['dev']}) ==")
        # 以 IP 为主标识：主机名只是随机编号，看不出地区，IP 才是出口本身。
        # 延迟默认就是本地实测：CSV 里的 Ping 是 VPN Gate 公布值，不是你
        # 的机器到服务器的延迟，用它选服务器会误导，所以 list 并发实测。
        shown = grouped[region][: args.n]
        lat = {}
        if not getattr(args, "no_local_ping", False):
            from concurrent.futures import ThreadPoolExecutor
            with ThreadPoolExecutor(max_workers=5) as ex:
                for s, (ms, _method) in zip(shown, ex.map(
                        lambda x: measure_local_latency(x["ip"]), shown)):
                    lat[s["ip"]] = ms
        print(f"{'IP':<16} {'主机名':<28} {'速度':>10} {'本地延迟':>8} {'官方Ping':>8} {'会话':>5}")
        for s in shown:
            ms = lat.get(s["ip"])
            local = f"{ms:.0f} ms" if ms is not None else "-"
            print(f"{s['ip']:<16} {s['fqdn']:<28} "
                  f"{s['speed_mbps']:>8} Mbps {local:>8} {s['ping']:>6} ms {s['sessions']:>5}")


def cmd_ping(args):
    ms, method = measure_local_latency(args.ip)
    if ms is None:
        print(f"{args.ip} 本地延迟：测不到（ping 被挡且 TCP 443 超时，"
              f"可能是本机网络或对方防火墙丢包）")
    else:
        way = "ping（ICMP）" if method == "ping" else "TCP 握手（ping 被挡时的回落）"
        print(f"{args.ip} 本地延迟：{ms:.1f} ms（{way}，从本机实测，非 VPN Gate 公布值）")


def mark_rules(action, region):
    info = REGIONS[region]
    flag = "-A" if action == "add" else "-D"
    run(["iptables", "-t", "mangle", flag, "OUTPUT",
         "-m", "owner", "--uid-owner", info["user"],
         "-j", "MARK", "--set-mark", str(info["mark"])])


def _apply_up(dev, gateway):
    region = DEV_TO_REGION.get(dev)
    if not region:
        return 1
    info = REGIONS[region]
    run(["ip", "rule", "del", "fwmark", fwmark_rule(info),
         "table", str(info["table"])], check=False)
    run(["ip", "rule", "add", "fwmark", fwmark_rule(info),
         "table", str(info["table"]), "priority", "100"], check=False)
    run(["ip", "route", "flush", "table", str(info["table"])], check=False)
    if gateway:
        run(["ip", "route", "add", "default", "via", gateway,
             "dev", dev, "table", str(info["table"])], check=False)
    mark_rules("add", region)
    return 0


def _up_hook(_args):
    dev = os.environ.get("dev", "")
    gateway = (os.environ.get("ifconfig_remote")
               or os.environ.get("route_vpn_gateway") or "")
    return _apply_up(dev, gateway)


def _down_hook(_args):
    dev = os.environ.get("dev", "")
    region = DEV_TO_REGION.get(dev)
    if not region:
        return 1
    info = REGIONS[region]
    mark_rules("delete", region)
    run(["ip", "rule", "del", "fwmark", fwmark_rule(info),
         "table", str(info["table"])], check=False)
    run(["ip", "route", "flush", "table", str(info["table"])], check=False)
    return 0


def pid_running(region):
    files = region_files(region)
    if os.path.exists(files["pid"]):
        try:
            pid = int(open(files["pid"]).read().strip())
            os.kill(pid, 0)
            return pid
        except (ValueError, ProcessLookupError, PermissionError):
            return None
    return None


def ensure_user(region):
    user = REGIONS[region]["user"]
    if run(["id", user]).returncode != 0:
        run(["useradd", "--system", "--no-create-home",
             "--shell", "/usr/sbin/nologin", user], check=False)


def start_region(region):
    """启动一个地区的隧道。返回 True/False，让调用方能明说失败原因，
    而不是静默地“按了 s 但状态还是未运行”。
    预检失败时把原因写进日志文件本身：以前 openvpn 没装 / 没配置时，
    openvpn 根本没被拉起来，日志文件就不存在，用户去 tail 只能看到
    “文件不存在”，完全不知道为什么。现在至少日志里有原因。"""
    import shutil
    files = region_files(region)
    os.makedirs(STATE_DIR, exist_ok=True)

    def _fail(reason):
        try:
            with open(files["log"], "a") as f:
                f.write(f"启动失败：{reason}\n")
        except Exception:
            pass
        return False

    if shutil.which("openvpn") is None:
        return _fail("本机没有 openvpn，请跑安装脚本装依赖")
    if not os.path.exists("/dev/net/tun"):
        return _fail("没有 /dev/net/tun，内核/容器没给 tun 设备，隧道起不来")
    if pid_running(region):
        return True
    if not os.path.exists(files["ovpn"]):
        return _fail(f"配置文件不存在：{files['ovpn']}，先跑 connect 生成")
    ensure_user(region)
    try:
        subprocess.Popen(["openvpn", "--daemon", "--config", files["ovpn"],
                          "--writepid", files["pid"], "--log", files["log"]])
    except Exception as e:
        return _fail(f"拉起 openvpn 失败：{e}")
    return True


def stop_region(region):
    pid = pid_running(region)
    if pid:
        try:
            os.kill(pid, 15)
        except ProcessLookupError:
            pass
    _down_hook_for_region(region)


def _down_hook_for_region(region):
    info = REGIONS[region]
    mark_rules("delete", region)
    run(["ip", "rule", "del", "fwmark", fwmark_rule(info),
         "table", str(info["table"])], check=False)
    run(["ip", "route", "flush", "table", str(info["table"])], check=False)


def cmd_connect(args):
    need_root()
    ensure_dirs()
    # 启动前先系统检查：openvpn / tun 缺了，隧道根本起不来，
    # 与其假装“启动中”再让用户去找一个不存在的日志，不如直接说缺什么。
    _critical = [c for c in system_checks()
                 if c[1] in ("openvpn", "/dev/net/tun") and not c[0]]
    if _critical:
        for _ok, _name, _detail in _critical:
            print(f"✗ {_name}：{_detail}")
        print("系统检查没过，隧道不会启动。先修上面几项，再跑 connect。")
        return
    cleanup_legacy()
    need_update = False
    for region in REGIONS:
        files = region_files(region)
        if not os.path.exists(files["ovpn"]):
            need_update = True
        elif os.path.exists(files["meta"]):
            try:
                age = time.time() - json.load(open(files["meta"]))["updated_at"]
                if age > MAX_AGE:
                    need_update = True
            except Exception:
                need_update = True
    if need_update:
        cmd_update(args)
    for region in REGIONS:
        start_region(region)
    print("两个隧道启动中，up 钩子会按地区自动写 fwmark 路由。"
          "用 status 查看，用 tui 手动换出口。")


def cmd_disconnect(_args):
    need_root()
    for region in REGIONS:
        stop_region(region)
    cleanup_legacy()
    print("两个隧道已停，fwmark 规则与路由表 201 / 202（及旧版 101 / 102）已清理。")


def system_checks():
    """系统检查：启动前必须过的项，返回 [(通过?, 名称, 说明)]。
    专门解决“按了 s 但隧道没起来、连 jp.log 都不存在”的困惑：
    日志文件只有 openvpn 真正启动后才会创建；如果 openvpn 没装、
    没有 /dev/net/tun、没有配置文件，openvpn 根本没被拉起来，
    日志当然不存在——这时应该先看 doctor，而不是去 tail 一个不存在的日志。
    所以 start_region 在预检失败时，会把失败原因写进日志文件本身，
    让 tail 日志也能看到原因，而不是文件缺失。"""
    import shutil
    checks = []

    def add(ok, name, detail):
        checks.append((bool(ok), name, detail))

    add(os.geteuid() == 0, "root 权限", "当前是 root" if os.geteuid() == 0 else "当前不是 root，请用 sudo")
    ovpn = shutil.which("openvpn")
    if ovpn:
        ver = run(["openvpn", "--version"]).stdout.splitlines()
        add(True, "openvpn", (ver[0].strip() if ver else ovpn))
    else:
        add(False, "openvpn", "未安装：跑安装脚本（apt 装 openvpn）或手动装 openvpn")
    add(os.path.exists("/dev/net/tun"), "/dev/net/tun", "存在" if os.path.exists("/dev/net/tun") else "不存在：内核/容器没给 tun 设备，隧道起不来")
    for cmd in ("ip", "iptables", "ping"):
        add(shutil.which(cmd) is not None, f"命令 {cmd}", "已安装" if shutil.which(cmd) else "未安装")
    try:
        os.makedirs(STATE_DIR, exist_ok=True)
        open(os.path.join(STATE_DIR, ".wtest"), "w").close()
        add(True, "状态目录可写", STATE_DIR)
    except Exception as e:
        add(False, "状态目录可写", f"{STATE_DIR} 写不进去：{e}")
    # 路由表名（install.sh 会写 /etc/iproute2/rt_tables）
    try:
        rt = open("/etc/iproute2/rt_tables").read() if os.path.exists("/etc/iproute2/rt_tables") else ""
        add("201 vgjp" in rt and "202 vgkr" in rt, "路由表名 vgjp/vgkr",
            "已注册" if ("201 vgjp" in rt and "202 vgkr" in rt) else "未注册：ip rule 会显示数字 201/202 而不是 vgjp/vgkr，功能不受影响，重装一次可补")
    except Exception as e:
        add(False, "路由表名 vgjp/vgkr", str(e))
    for region, info in REGIONS.items():
        files = region_files(region)
        add(os.path.exists(files["ovpn"]), f"{info['name']} 配置文件",
            files["ovpn"] if os.path.exists(files["ovpn"]) else "不存在：先跑 connect 或在 TUI 按 s（新版 s 会自动生成）")
        add(os.path.exists(files["meta"]), f"{info['name']} 元数据",
            "存在" if os.path.exists(files["meta"]) else "不存在")
        pid = pid_running(region)
        add(pid is not None, f"{info['name']} 隧道进程",
            f"运行中 pid={pid}" if pid else "未运行")
        add(run(["id", info["user"]]).returncode == 0, f"{info['name']} 运行用户 {info['user']}",
            "存在" if run(["id", info["user"]]).returncode == 0 else "不存在：启动时会自动建")
        if os.path.exists(files["log"]):
            add(True, f"{info['name']} 日志", files["log"])
        else:
            add(False, f"{info['name']} 日志",
                "不存在：openvpn 还没真正启动过——先看上面 openvpn / tun / 配置三项，缺哪项补哪项")
    return checks


CRITICAL_CHECKS = {"root 权限", "openvpn", "/dev/net/tun", "命令 ip", "命令 iptables", "状态目录可写"}


def cmd_doctor(_args):
    checks = system_checks()
    bad = 0
    for ok, name, detail in checks:
        if ok:
            mark = "✓"
        elif name in CRITICAL_CHECKS:
            mark = "✗"
            bad += 1
        else:
            # 配置 / 进程 / 用户 / 日志 / 表名没过不是“系统坏了”，
            # 只是还没连过：配置由 connect 生成，用户启动时自动建，
            # 隧道没起日志当然没有。用 ○ 区分，别把 12 项都算成故障。
            mark = "○"
        print(f"{mark} {name}：{detail}")
    if bad:
        print(f"\n系统检查：{bad} 项关键问题。先修上面带 ✗ 的项再启动，"
              f"否则隧道起不来、日志也不会有。○ 是“还没连过”，不是故障。")
        return 1
    print("\n系统检查：关键项全部通过，可以启动。○ 是“还没连过”，不是故障。")
    return 0


def cmd_status(_args):
    for region, info in REGIONS.items():
        meta = load_json(region_files(region)["meta"], {})
        print(f"{info['name']} {info['code']}: {meta.get('fqdn', '（无）')} "
              f"{meta.get('ip', '')} 模式={meta.get('mode', '-')} "
              f"pid={pid_running(region) or '未运行'} "
              f"fwmark={info['mark']} 表={info['table']} 隧道={info['dev']}")
        print(run(["ip", "route", "show", "table", str(info["table"])]).stdout
              or "  路由表空")


def cmd_set(args):
    """命令行手动指定：--server <主机名> 或 --auto。"""
    need_root()
    region = args.region
    manual = load_json(MANUAL_FILE, {})
    if args.auto:
        manual.pop(region, None)
        print(f"{REGIONS[region]['name']}已恢复自动选择，下次 update 生效。")
    else:
        manual[region] = args.server
        print(f"{REGIONS[region]['name']}已手动指定为 {args.server}，"
              "正在拉取列表并切换（若该服务器已下线会回落自动）。")
    with open(MANUAL_FILE, "w") as f:
        json.dump(manual, f, ensure_ascii=False, indent=2)
    grouped = cmd_update(args)
    # 只重启被手动改动的地区
    stop_region(region)
    time.sleep(2)
    start_region(region)


def cmd_run(args):
    need_root()
    region = args.region
    if args.command and args.command[0] == "--":
        args.command = args.command[1:]
    if not args.command:
        sys.exit("用法：run --region jp -- <命令>，例如 run --region jp -- curl -s ifconfig.me")
    if not pid_running(region):
        cmd_connect(args)
        time.sleep(3)
    user = REGIONS[region]["user"]
    runner = "runuser" if run(["which", "runuser"]).returncode == 0 else "su"
    if runner == "runuser":
        cmd = ["runuser", "-u", user, "--"] + args.command
    else:
        cmd = ["su", user, "-s", "/bin/sh", "-c", " ".join(args.command)]
    sys.exit(subprocess.call(cmd))


def cmd_watch(args):
    need_root()
    before = {r: load_json(region_files(r)["meta"], {}).get("fqdn")
              for r in REGIONS}
    grouped = None
    try:
        grouped = cmd_update(args)
    except SystemExit:
        grouped = None
    if grouped is None:
        return
    for region in REGIONS:
        after = load_json(region_files(region)["meta"], {}).get("fqdn")
        if not pid_running(region):
            start_region(region)
        elif before.get(region) != after:
            stop_region(region)
            time.sleep(2)
            start_region(region)
    print("watch 检查完成：手动指定的地区不会被自动换服。")


# ---------------- IP 信誉检查 ----------------
# 说明：ipleak.net 这类网站是“泄漏测试”网页，没有公开 API，不适合程序调用。
# 这里用的是可程序调用的免费源，外加两个可选的付费 Key（有 Key 才查）：
#   免费：ip-api.com（国家/ISP/是否代理/是否机房/是否移动网络）
#         proxycheck.io（风险分 0~100，无需 Key，只用 vpn=1&risk=1 这一组参数）
#         getipintel（欺诈分 0~1，仅当设置了 VG_CONTACT_EMAIL 时才查）
#   可选：AbuseIPDB（环境变量 ABUSEIPDB_KEY，滥用分 0~100）
#         IPQualityScore（环境变量 IPQS_KEY，欺诈分 0~100）
# 2026-11-04 实测到的故障：getipintel 对 example.com 这类占位邮箱返回
# status=error、result=-5（“IP 被封 / 邮箱无效”），旧代码把这个错误悄悄
# 吞掉，欺诈分就显示 None，用户完全不知道为什么。现在修复为：
#   1. 不再用 example.com 当 contact；没设置真实邮箱就不调 getipintel，
#      并在结果里明说原因，不再静默失败。
#   2. 默认欺诈分改走 proxycheck.io，它无需 Key 就能返回 risk 分。
#   3. 代理 / 机房标记不再单独决定风险：VPN 出口本来就是代理/机房，
#      只看欺诈分 / 滥用分 / proxycheck 风险分。
# 所谓“IP 纯净度”没有统一标准，这里给的是多源综合参考，不是官方判决。

REPUTATION_CACHE_TTL = 24 * 3600
# 缓存版本号：旧版（v1）缓存里欺诈分就是 None，而且没有 fraud_source /
# fraud_error 字段。如果升级后还信任它，用户不加 --force 就会永远看到
# 旧的 None，哪怕新代码已经能查出分数。所以 v1 缓存一律视为过期重查。
REPUTATION_CACHE_VERSION = 2


def reputation_cache_path():
    try:
        os.makedirs(STATE_DIR, exist_ok=True)
        open(os.path.join(STATE_DIR, ".wtest"), "w").close()
        return os.path.join(STATE_DIR, "reputation.json")
    except Exception:
        d = os.path.expanduser("~/.cache/vpngate-fwmark")
        os.makedirs(d, exist_ok=True)
        return os.path.join(d, "reputation.json")


def _marked_connect(host, port, timeout, mark):
    """建一个打了 fwmark 的 socket：先 set SO_MARK 再 connect，
    这样内核查路由表时就会走对应地区的表（201 日本 / 202 韩国），
    请求就从该地区的 VPN 隧道出去，不用再搭一个 HTTP 代理。
    SO_MARK = 36（Linux）。"""
    import socket
    last = None
    for family, socktype, proto, _canon, sockaddr in socket.getaddrinfo(
            host, port, 0, socket.SOCK_STREAM):
        sock = socket.socket(family, socktype, proto)
        try:
            sock.setsockopt(socket.SOL_SOCKET, 36, mark)
            sock.settimeout(timeout)
            sock.connect(sockaddr)
            return sock
        except Exception as e:
            last = e
            sock.close()
    raise last or OSError("marked connect failed")


def fetch_json(url, headers=None, timeout=15, proxy=None, mark=None):
    """查 JSON 接口。
    走法按优先级：
      1. proxy（VG_PROXY / --proxy）：走用户给的 HTTP 代理，备选。
      2. mark（--via jp/kr 或 TUI 按地区自动给）：socket 打上该地区
         的 fwmark，走已经连上的 VPN 隧道发出去。这是首选，不用多此一举
         再搭 HTTP 代理——采集来的 VPN 本身就是代理。
         注意：隧道没起来时，打了标记的流量在专用表里无路可走，
         会失败；这时自动回落到直连一次，直连能通就用直连结果，
         直连也被挡才算失败，不会因为隧道没起就直接报未知。
      3. 都没有：直连（urllib 默认会读 HTTP_PROXY / HTTPS_PROXY）。
    proxycheck / ip-api 查的是参数里的 IP，不是出口 IP，
    所以走哪个隧道出，结果是一样的，区别只是“能不能发出去”。"""
    req = urllib.request.Request(url, headers=headers or {"User-Agent": "vpngate-fwmark/2.0"})
    proxy_url = proxy or os.environ.get("VG_PROXY")
    if proxy_url:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url}))
        with opener.open(req, timeout=timeout) as resp:
            return json.load(resp)
    if mark is not None:
        import http.client

        class _MarkedHTTP(http.client.HTTPConnection):
            def connect(self):
                self.sock = _marked_connect(self.host, self.port or 80, self.timeout, mark)

        class _MarkedHTTPS(http.client.HTTPSConnection):
            def connect(self):
                sock = _marked_connect(self.host, self.port or 443, self.timeout, mark)
                self.sock = self._context.wrap_socket(sock, server_hostname=self.host)

        class _HTTPHandler(urllib.request.HTTPHandler):
            def http_open(self, req):
                return self.do_open(_MarkedHTTP, req)

        class _HTTPSHandler(urllib.request.HTTPSHandler):
            def https_open(self, req):
                return self.do_open(_MarkedHTTPS, req)

        opener = urllib.request.build_opener(_HTTPHandler(), _HTTPSHandler())
        try:
            with opener.open(req, timeout=timeout) as resp:
                return json.load(resp)
        except Exception as marked_err:
            # 隧道没起 / 隧道断了 / 容器里没 CAP_NET_ADMIN 打不了标记：
            # 回落直连一次。注意不能复用同一个 Request 对象，
            # 实测复用会在直连时 RemoteDisconnected，必须新建一个。
            try:
                req2 = urllib.request.Request(url, headers=headers or {"User-Agent": "vpngate-fwmark/2.0"})
                with urllib.request.urlopen(req2, timeout=timeout) as resp:
                    return json.load(resp)
            except Exception:
                raise marked_err
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.load(resp)


def check_ip_reputation(ip, force=False, proxy=None, mark=None, via_region=None):
    if via_region in REGIONS:
        mark = int(REGIONS[via_region]["mark"], 16)
    cache_path = reputation_cache_path()
    cache = load_json(cache_path, {})
    if not force and ip in cache:
        entry = cache[ip]
        if (entry.get("cache_version") == REPUTATION_CACHE_VERSION
                and time.time() - entry.get("checked_at", 0) < REPUTATION_CACHE_TTL):
            entry["cached"] = True
            return entry
        # 旧版缓存：不信任，直接往下重查（不删除文件，重查后会被覆盖）。
    result = {"ip": ip, "country": "", "isp": "", "org": "", "asn": "",
              "proxy": None, "hosting": None, "mobile": None,
              "fraud_score": None, "abuse_score": None, "sources": [],
              "fraud_source": "", "fraud_error": "", "proxy_type": "",
              "cache_version": REPUTATION_CACHE_VERSION}
    # ip-api.com：免费，限速约 45 次/分钟，查候选时不要一次查太多。
    try:
        d = fetch_json(f"http://ip-api.com/json/{ip}?fields=status,message,country,isp,org,as,proxy,hosting,mobile,query", proxy=proxy, mark=mark)
        if d.get("status") == "success":
            result.update({"country": d.get("country", ""), "isp": d.get("isp", ""),
                           "org": d.get("org", ""), "asn": d.get("as", ""),
                           "proxy": d.get("proxy"), "hosting": d.get("hosting"),
                           "mobile": d.get("mobile")})
            result["sources"].append("ip-api.com")
    except Exception:
        pass
    # proxycheck.io：默认欺诈分来源，无需 Key。用且只用 vpn=1&risk=1，
    # 多加 asn/port/seen 等参数时实测会返回不一致的结果，所以不加。
    # 另外实测发现：同一 IP 连查几次，免费端点有时返回 risk 66（Shadowsocks），
    # 有时返回 risk 0（Business），疑似后端负载均衡不一致。安全起见查两次取最高分，
    # 宁可把可疑的往高了算，也不让一次偶然的 0 把风险洗白。结果缓存 24 小时，
    # 不会每次都翻倍消耗免费额度。
    try:
        best = None
        for _ in range(2):
            d = fetch_json(f"https://proxycheck.io/v2/{ip}?vpn=1&risk=1", proxy=proxy, mark=mark)
            entry = d.get(ip) if isinstance(d, dict) else None
            if d.get("status") == "ok" and isinstance(entry, dict) and entry.get("risk") is not None:
                if best is None or float(entry["risk"]) > float(best["risk"]):
                    best = entry
        if best is not None:
            result["fraud_score"] = float(best["risk"]) / 100.0
            result["fraud_source"] = "proxycheck"
            result["proxy_type"] = best.get("type", "")
            if result["proxy"] is None:
                result["proxy"] = best.get("proxy") == "yes"
            result["sources"].append("proxycheck")
    except Exception as e:
        result["fraud_error"] = f"proxycheck 失败：{e}"
    # getipintel：仅当用户设置了真实联系邮箱时才查。
    # 占位邮箱（example.com）会被它判定为无效并封 IP，返回 error/-5，
    # 这就是之前欺诈分突然变 None 的直接原因。
    contact = os.environ.get("VG_CONTACT_EMAIL", "").strip()
    if contact and "@" in contact and not contact.endswith("@example.com"):
        try:
            import urllib.parse
            d = fetch_json("https://check.getipintel.net/check.php?ip="
                           f"{ip}&contact={urllib.parse.quote(contact)}&format=json", proxy=proxy, mark=mark)
            if d.get("status") == "success":
                score = float(d.get("result"))
                if score >= 0:  # 负数是错误码（-5 等），不是分数
                    if result["fraud_score"] is None or score > result["fraud_score"]:
                        result["fraud_score"] = score
                    result["fraud_source"] = (result["fraud_source"] + "+getipintel").strip("+")
                    result["sources"].append("getipintel")
                else:
                    result["fraud_error"] = f"getipintel 返回错误码 {d.get('result')}：{d.get('message', '')}"
            else:
                result["fraud_error"] = f"getipintel 返回 {d.get('status')}：{d.get('message', '')}"
        except Exception as e:
            result["fraud_error"] = f"getipintel 失败：{e}"
    elif not result["fraud_error"]:
        result["fraud_error"] = "getipintel 未调用：请设置 VG_CONTACT_EMAIL 为你的真实邮箱（它要求真实联系邮箱）"
    # 可选：AbuseIPDB
    key = os.environ.get("ABUSEIPDB_KEY")
    if key:
        try:
            d = fetch_json(f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90",
                           headers={"Key": key, "Accept": "application/json"}, proxy=proxy, mark=mark)
            result["abuse_score"] = int(d["data"]["abuseConfidenceScore"])
            result["sources"].append("AbuseIPDB")
        except Exception:
            pass
    # 可选：IPQualityScore（取多源中的最高分，不静默覆盖）
    key = os.environ.get("IPQS_KEY")
    if key:
        try:
            d = fetch_json(f"https://ipqualityscore.com/api/json/ip/{key}/{ip}", proxy=proxy, mark=mark)
            if d.get("success"):
                score = float(d.get("fraud_score", 0)) / 100.0
                if result["fraud_score"] is None or score > result["fraud_score"]:
                    result["fraud_score"] = score
                result["fraud_source"] = (result["fraud_source"] + "+IPQS").strip("+")
                result["sources"].append("IPQualityScore")
        except Exception:
            pass
    fraud = result["fraud_score"]
    abuse = result["abuse_score"]
    # 代理/机房不再单独定风险：VPN 出口本来就是代理/机房，只看分数。
    if (abuse is not None and abuse >= 75) or (fraud is not None and fraud >= 0.9):
        risk = "高"
    elif (abuse is not None and abuse >= 50) or (fraud is not None and fraud >= 0.7):
        risk = "中"
    elif fraud is not None or abuse is not None:
        risk = "低"
    else:
        risk = "未知（免费源未返回分数，仅看国家/ISP/机房标记）"
    result["risk"] = risk
    # 没查到分数的“未知”结果别缓存 24 小时：隧道没起时直连被挡会
    # 留下未知，隧道起来后 5 分钟内就应该能重查走隧道，而不是等一天。
    # 做法是把 checked_at 往前推，只留 5 分钟有效期。
    if fraud is None and abuse is None:
        result["checked_at"] = int(time.time()) - REPUTATION_CACHE_TTL + 300
    else:
        result["checked_at"] = int(time.time())
    result["cached"] = False
    cache[ip] = result
    try:
        with open(cache_path, "w") as f:
            json.dump(cache, f, ensure_ascii=False, indent=2)
    except Exception:
        pass
    return result


def format_reputation(rep):
    def yn(v):
        return "是" if v is True else ("否" if v is False else "未知")
    text = (f"IP {rep['ip']} 信誉：{rep['risk']} | 国家 {rep.get('country') or '-'} | "
            f"ISP {rep.get('isp') or rep.get('org') or '-'} | ASN {rep.get('asn') or '-'} | "
            f"代理 {yn(rep.get('proxy'))} | 机房 {yn(rep.get('hosting'))} | "
            f"欺诈分 {rep.get('fraud_score')}（{rep.get('fraud_source') or '无'}）| "
            f"滥用分 {rep.get('abuse_score')} | "
            f"来源 {','.join(rep.get('sources') or ['无'])}")
    if rep.get("fraud_score") is None and rep.get("fraud_error"):
        text += f" | 说明：{rep['fraud_error']}"
    return text


def cmd_reputation(args):
    rep = check_ip_reputation(args.ip, force=args.force, proxy=getattr(args, "proxy", None),
                              via_region=getattr(args, "via", None))
    via = getattr(args, "via", None)
    if via:
        print(f"（信誉请求走 {REGIONS[via]['name']} 隧道发出去，隧道没起时自动回落直连）")
    print(format_reputation(rep))
    print("提醒：机房 IP 对 VPN 出口来说是正常的，单独看机房标记不能判为脏 IP；"
          "重点看欺诈分 / 滥用分是否高。")


# ---------------- TUI ----------------

def cmd_tui(_args):
    need_root()
    import curses

    def load_candidates():
        cands = load_json(CANDIDATES_FILE, {})
        if cands and any(cands.values()):
            return cands
        # 旧 bug：拉取失败直接抛错，TUI 一打开就崩。现在返回空列表并让界面显示“暂无候选”。
        try:
            grouped = candidates_by_region(parse_servers(fetch_csv()))
        except Exception:
            return {r: [] for r in REGIONS}
        return {r: [{k: v for k, v in s.items() if k != "config_b64"}
                     for s in grouped[r][:20]] for r in grouped}

    def safe_add(stdscr, y, x, text, attr=0):
        """旧 TUI 的最大 bug：终端一窄、消息一长，addstr 就越界崩溃。
        这里先按屏幕宽高截断，越界直接跳过，绝不让 curses 抛错。"""
        try:
            height, width = stdscr.getmaxyx()
        except Exception:
            return
        if y < 0 or y >= height or x < 0 or x >= width:
            return
        text = str(text)[: max(0, width - x - 1)]
        if not text:
            return
        try:
            stdscr.addstr(y, x, text, attr)
        except Exception:
            pass

    def clamp_cursor(cursor_dict, region, lst):
        if not lst:
            cursor_dict[region] = 0
        else:
            cursor_dict[region] = max(0, min(cursor_dict[region], len(lst) - 1))

    # TUI 每行后面的欺诈分：不能一打开就同步查 20 个节点，那会卡住界面
    # 还会被免费接口限速。所以只查当前屏幕上显示的几行，后台线程查，
    # 查到就填上；同时最多 3 个并发，避免一下子打爆 ip-api / proxycheck。
    # 缓存 24 小时的结果进 TUI 就直接显示，不用重新联网。
    rep_scores = {}
    rep_pending = set()
    rep_lock = threading.Lock()
    rep_sem = threading.Semaphore(3)
    rep_proxy = os.environ.get("VG_PROXY")
    try:
        _cached = load_json(reputation_cache_path(), {})
        for _ip, _e in _cached.items():
            if (_e.get("cache_version") == REPUTATION_CACHE_VERSION
                    and _e.get("fraud_score") is not None
                    and time.time() - _e.get("checked_at", 0) < REPUTATION_CACHE_TTL):
                rep_scores[_ip] = f"欺诈 {_e['fraud_score']:.2f}"
    except Exception:
        pass

    # 本地延迟：和欺诈分一样，后台测、只测当前屏幕上的行，不卡界面。
    # 这里显示的才是“你这台机器到 VPN 服务器”的延迟，CSV 里的 Ping
    # 是 VPN Gate 公布值，不能当本地延迟用，所以 TUI 里不再直接用它。
    lat_scores = {}
    lat_pending = set()
    lat_lock = threading.Lock()
    lat_sem = threading.Semaphore(5)

    def lat_text(ip):
        with lat_lock:
            if ip in lat_scores:
                return lat_scores[ip]
            return "本地延迟 …" if ip in lat_pending else "本地延迟 未测"

    def ensure_lat(ip):
        with lat_lock:
            if ip in lat_scores or ip in lat_pending:
                return
            lat_pending.add(ip)

        def _work():
            try:
                with lat_sem:
                    ms, method = measure_local_latency(ip)
                if ms is None:
                    text = "本地延迟 测不到"
                elif method == "tcp":
                    text = f"本地延迟 {ms:.0f} ms(TCP)"
                else:
                    text = f"本地延迟 {ms:.0f} ms"
                with lat_lock:
                    lat_scores[ip] = text
            except Exception:
                with lat_lock:
                    lat_scores[ip] = "本地延迟 测不到"
            finally:
                with lat_lock:
                    lat_pending.discard(ip)

        threading.Thread(target=_work, daemon=True).start()

    def fraud_text(ip):
        with rep_lock:
            if ip in rep_scores:
                return rep_scores[ip]
            return "欺诈 …" if ip in rep_pending else "欺诈 未查"

    def ensure_rep(ip, region=None):
        with rep_lock:
            if ip in rep_scores or ip in rep_pending:
                return
            rep_pending.add(ip)

        def _work():
            try:
                with rep_sem:
                    # 该地区隧道在跑，就走该隧道发信誉请求（SO_MARK）；
                    # 隧道没起就不打标记，直连（直连被挡时 5 分钟后可重查）。
                    via = region if region and pid_running(region) else None
                    rep = check_ip_reputation(ip, proxy=rep_proxy, via_region=via)
                text = (f"欺诈 {rep['fraud_score']:.2f}" if rep.get("fraud_score") is not None
                        else "欺诈 未知")
                with rep_lock:
                    rep_scores[ip] = text
            except Exception:
                with rep_lock:
                    rep_scores[ip] = "欺诈 未知"
            finally:
                with rep_lock:
                    rep_pending.discard(ip)

        threading.Thread(target=_work, daemon=True).start()

    def draw(stdscr, regions, sel_region, cursor, cands, manual, msg):
        stdscr.clear()
        try:
            height, width = stdscr.getmaxyx()
        except Exception:
            height, width = 24, 80
        # 顶栏：短标题 + 状态色块，不再是一行超长中文导致小终端崩溃。
        safe_add(stdscr, 0, 0, " vpngate-fwmark ".ljust(width), curses.color_pair(1) | curses.A_BOLD)
        row = 2
        for idx, region in enumerate(regions):
            info = REGIONS[region]
            meta = load_json(region_files(region)["meta"], {})
            mode = "手动" if region in manual else "自动"
            running = pid_running(region) is not None
            status = "● 运行中" if running else "○ 未运行"
            status_attr = curses.color_pair(3) if running else curses.color_pair(4)
            arrow = "▶" if idx == sel_region else " "
            head = (f"{arrow} {info['name']} {info['code']}  "
                    f"fwmark {info['mark']}  表 {info['table']}  {info['dev']}  [{mode}]")
            head_attr = curses.color_pair(2) | curses.A_BOLD if idx == sel_region else curses.A_BOLD
            safe_add(stdscr, row, 0, head, head_attr)
            safe_add(stdscr, row, max(0, width - 12), status, status_attr)
            row += 1
            safe_add(stdscr, row, 2,
                     f"当前出口 IP：{meta.get('ip', '（无）')}（{meta.get('fqdn', '')}） "
                     f"{meta.get('speed_mbps', '')} Mbps / Ping {meta.get('ping', '')} ms")
            row += 1
            # 地区卡片之间的分隔线，让两个地区一眼分开。
            safe_add(stdscr, row, 0, "─" * max(0, width - 1), curses.color_pair(5))
            row += 1
        # 候选列表：按剩余高度算能显示几行，带滚动，绝不写出屏幕底部。
        footer_rows = 3
        avail = max(1, height - row - footer_rows - 1)
        region = regions[sel_region]
        lst = cands.get(region, [])
        clamp_cursor(cursor, region, lst)
        safe_add(stdscr, row, 0,
                 f"候选服务器 · {REGIONS[region]['name']}（欺诈分在每行后面，后台自动查，p 查详情）",
                 curses.A_BOLD)
        row += 1
        if not lst:
            safe_add(stdscr, row, 2, "暂无候选，按 r 刷新列表。")
        else:
            cur = cursor[region]
            start = 0
            if cur >= start + avail:
                start = cur - avail + 1
            for ci, s in enumerate(lst[start:start + avail]):
                real = start + ci
                mark = ">>" if real == cur else "  "
                attr = curses.color_pair(2) if real == cur else 0
                ensure_rep(s["ip"], region)
                ensure_lat(s["ip"])
                safe_add(stdscr, row, 2,
                         f"{mark} {s['ip']:<15}  {s['fqdn']:<28} "
                         f"{s['speed_mbps']:>7} Mbps  {lat_text(s['ip'])}  {s['sessions']} 会话  {fraud_text(s['ip'])}",
                         attr)
                row += 1
        # 底栏：帮助分两行写，消息最多显示两行并截断。
        safe_add(stdscr, height - 3, 0, "─" * max(0, width - 1), curses.color_pair(5))
        safe_add(stdscr, height - 2, 0,
                 "Tab 切换地区  ↑/↓选服务器  回车手动指定  a 自动  p 信誉  r 刷新  s 启停  c 系统检查  l 看日志  q 退出")
        safe_add(stdscr, height - 1, 0, str(msg)[: max(0, width - 1)])
        try:
            stdscr.refresh()
        except Exception:
            pass

    def main_tui(stdscr):
        try:
            curses.curs_set(0)
        except Exception:
            pass
        # 颜色：单色终端会失败，失败就退回无色，界面照样能用。
        try:
            curses.start_color()
            curses.use_default_colors()
            curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_BLUE)   # 顶栏
            curses.init_pair(2, curses.COLOR_BLACK, curses.COLOR_CYAN)   # 选中行
            curses.init_pair(3, curses.COLOR_GREEN, -1)                  # 运行中
            curses.init_pair(4, curses.COLOR_RED, -1)                    # 未运行
            curses.init_pair(5, curses.COLOR_CYAN, -1)                   # 分隔线
        except Exception:
            pass
        try:
            stdscr.timeout(500)
        except Exception:
            pass
        # 启动时先系统检查：openvpn / tun 缺了，按 s 也起不来，
        # 直接在底栏告诉用户，别让他对着一个不存在的日志发懵。
        _crit = [c for c in system_checks()
                 if c[1] in ("openvpn", "/dev/net/tun") and not c[0]]
        regions = list(REGIONS.keys())
        sel = 0
        cursor = {r: 0 for r in regions}
        manual = load_json(MANUAL_FILE, {})
        cands = load_candidates()
        for r in regions:
            cands.setdefault(r, [])
        msg = ("系统检查没过：" + "；".join(f"{n}：{d}" for _, n, d in _crit) + "，按 c 看完整检查。"
               if _crit else ("已加载候选列表。" if any(cands.values()) else "候选列表拉取失败，按 r 重试。"))
        draw(stdscr, regions, sel, cursor, cands, manual, msg)
        while True:
            key = stdscr.getch()
            if key == -1:
                # 500ms 超时：没有按键也重画一次，让后台查到的欺诈分及时显示。
                draw(stdscr, regions, sel, cursor, cands, manual, msg)
                continue
            region = regions[sel]
            if key in (ord("q"), ord("Q")):
                break
            elif key == curses.KEY_RESIZE:
                pass  # 下一轮 draw 会按新尺寸重画，不再因旧尺寸越界
            elif key == 9:  # Tab
                sel = (sel + 1) % len(regions)
            elif key in (curses.KEY_UP, ord("k")):
                cursor[region] = max(0, cursor[region] - 1)
            elif key in (curses.KEY_DOWN, ord("j")):
                lst = cands.get(region, [])
                cursor[region] = min(max(0, len(lst) - 1), cursor[region] + 1)
            elif key in (curses.KEY_ENTER, 10, 13):
                lst = cands.get(region, [])
                clamp_cursor(cursor, region, lst)
                if lst:
                    chosen = lst[cursor[region]]
                    manual[region] = chosen["fqdn"]
                    with open(MANUAL_FILE, "w") as f:
                        json.dump(manual, f, ensure_ascii=False, indent=2)
                    # 手动切换：需要完整配置数据，重新拉取一次。
                    # 旧 bug：服务器不在列表时也先停了隧道，导致手动换服失败还断网。
                    # 现在是先确认新服务器存在才停旧隧道。
                    try:
                        grouped = candidates_by_region(parse_servers(fetch_csv()))
                        srv, _ = choose_for_region(region, grouped, manual)
                    except Exception as e:
                        srv = None
                        msg = f"拉取列表失败，未切换：{e}"
                    if srv:
                        save_region(region, srv, "manual")
                        stop_region(region)
                        time.sleep(2)
                        start_region(region)
                        msg = f"{REGIONS[region]['name']}已手动切换到 {srv['ip']}（{srv['fqdn']}）。"
                    elif "拉取列表失败" not in msg:
                        msg = "该服务器已不在列表，切换失败，旧隧道未动。"
                else:
                    msg = "暂无候选，按 r 刷新后再选。"
            elif key in (ord("a"), ord("A")):
                manual.pop(region, None)
                with open(MANUAL_FILE, "w") as f:
                    json.dump(manual, f, ensure_ascii=False, indent=2)
                try:
                    grouped = candidates_by_region(parse_servers(fetch_csv()))
                    srv, _ = choose_for_region(region, grouped, manual)
                except Exception as e:
                    srv = None
                    msg = f"拉取列表失败，未切换：{e}"
                if srv:
                    save_region(region, srv, "auto")
                    stop_region(region)
                    time.sleep(2)
                    start_region(region)
                    msg = f"{REGIONS[region]['name']}已恢复自动：{srv['ip']}（{srv['fqdn']}）。"
                elif "拉取列表失败" not in msg:
                    msg = "暂无候选，恢复自动失败。"
            elif key in (ord("r"), ord("R")):
                try:
                    grouped = candidates_by_region(parse_servers(fetch_csv()))
                    cands = {r: [{k: v for k, v in s.items() if k != "config_b64"}
                                 for s in grouped[r][:20]] for r in grouped}
                    for r in regions:
                        cands.setdefault(r, [])
                        clamp_cursor(cursor, r, cands[r])
                    msg = "列表已刷新。"
                except Exception as e:
                    msg = f"刷新失败：{e}"
            elif key in (ord("p"), ord("P")):
                lst = cands.get(region, [])
                clamp_cursor(cursor, region, lst)
                if lst:
                    chosen = lst[cursor[region]]
                    msg = f"正在查 {chosen['ip']} 的信誉……"
                    draw(stdscr, regions, sel, cursor, cands, manual, msg)
                    try:
                        _ms, _m = measure_local_latency(chosen["ip"])
                        _local = f"{_ms:.0f} ms" if _ms is not None else "测不到"
                        rep = check_ip_reputation(chosen["ip"], proxy=rep_proxy, via_region=region if pid_running(region) else None)
                        with rep_lock:
                            rep_scores[chosen["ip"]] = (
                                f"欺诈 {rep['fraud_score']:.2f}" if rep.get("fraud_score") is not None
                                else "欺诈 未知")
                        msg = (f"IP {rep['ip']} 本地延迟 {_local}（官方Ping {chosen.get('ping')} ms） "
                               f"信誉 {rep['risk']} 欺诈分 {rep.get('fraud_score')}（{rep.get('fraud_source') or ''}） "
                               f"滥用分 {rep.get('abuse_score')} 代理 {rep.get('proxy')} 机房 {rep.get('hosting')} "
                               f"ISP {rep.get('isp') or ''}")
                    except Exception as e:
                        msg = f"信誉检查失败：{e}"
                else:
                    msg = "暂无候选，按 r 刷新后再查。"
            elif key in (ord("c"), ord("C")):
                # 全屏系统检查：底栏只有一行，检查结果放不下，必须全屏看。
                stdscr.clear()
                try:
                    _h, _w = stdscr.getmaxyx()
                except Exception:
                    _h, _w = 24, 80
                safe_add(stdscr, 0, 0, "系统检查（doctor）——按任意键返回", curses.A_BOLD)
                _row = 2
                for _ok, _name, _detail in system_checks():
                    _m = '✓' if _ok else ('✗' if _name in CRITICAL_CHECKS else '○')
                    safe_add(stdscr, _row, 0, f"{_m} {_name}：{_detail}")
                    _row += 1
                    if _row >= _h - 2:
                        break
                safe_add(stdscr, _h - 1, 0, "按任意键返回 TUI")
                stdscr.refresh()
                stdscr.timeout(-1)
                stdscr.getch()
                stdscr.timeout(500)
                draw(stdscr, regions, sel, cursor, cands, manual, msg)
                continue
            elif key in (ord("l"), ord("L")):
                # 全屏看日志：只看选中地区最近 20 行；日志不存在就明说
                # openvpn 还没启动过，而不是让用户去 tail 一个不存在的文件。
                stdscr.clear()
                try:
                    _h, _w = stdscr.getmaxyx()
                except Exception:
                    _h, _w = 24, 80
                safe_add(stdscr, 0, 0, f"{REGIONS[region]['name']} 日志（最近 20 行）——按任意键返回", curses.A_BOLD)
                _log = region_files(region)["log"]
                if os.path.exists(_log):
                    try:
                        _lines = open(_log, errors="replace").read().splitlines()[-20:]
                    except Exception as e:
                        _lines = [f"读日志失败：{e}"]
                else:
                    _lines = ["日志文件不存在：openvpn 还没真正启动过。",
                              "先按 c 看系统检查（openvpn / tun / 配置缺哪项），",
                              "再按 s 启动；启动失败的原因也会写进这个日志文件。"]
                _row = 2
                for _ln in _lines:
                    safe_add(stdscr, _row, 0, _ln)
                    _row += 1
                    if _row >= _h - 2:
                        break
                safe_add(stdscr, _h - 1, 0, "按任意键返回 TUI")
                stdscr.refresh()
                stdscr.timeout(-1)
                stdscr.getch()
                stdscr.timeout(500)
                draw(stdscr, regions, sel, cursor, cands, manual, msg)
                continue
            elif key in (ord("s"), ord("S")):
                if pid_running(region):
                    stop_region(region)
                    msg = f"{REGIONS[region]['name']}隧道已停止。"
                else:
                    # 旧 bug：这里只在 ovpn 存在时才启动，不存在就让用户
                    # “按 r 刷新”，但 r 只刷新内存里的候选列表，根本不生成
                    # ovpn，所以按多少次 r 再按 s 还是连不上，死循环。
                    # 现在 s 没配置就直接拉取一次、生成配置再启动。
                    if not os.path.exists(region_files(region)["ovpn"]):
                        msg = f"{REGIONS[region]['name']}还没有配置文件，正在拉取生成……"
                        draw(stdscr, regions, sel, cursor, cands, manual, msg)
                        try:
                            grouped = candidates_by_region(parse_servers(fetch_csv()))
                            srv, _ = choose_for_region(region, grouped, manual)
                            if srv:
                                save_region(region, srv, "manual" if region in manual else "auto")
                                cands[region] = [{k: v for k, v in s.items() if k != "config_b64"}
                                                 for s in grouped[region][:20]]
                                msg = f"{REGIONS[region]['name']}配置已生成（{srv['ip']}），正在启动隧道……"
                            else:
                                msg = f"{REGIONS[region]['name']}拉取列表为空，启动失败。"
                                draw(stdscr, regions, sel, cursor, cands, manual, msg)
                                continue
                        except Exception as e:
                            msg = f"{REGIONS[region]['name']}拉取配置失败：{e}，先在外面跑 sudo vpngate-fwmark connect 看日志。"
                            draw(stdscr, regions, sel, cursor, cands, manual, msg)
                            continue
                    import shutil as _shutil
                    if _shutil.which("openvpn") is None:
                        msg = f"{REGIONS[region]['name']}启动失败：本机没有 openvpn，先跑安装脚本装依赖。"
                    elif start_region(region):
                        with rep_lock:
                            for _s in cands.get(region, []):
                                rep_scores.pop(_s["ip"], None)
                        msg = (f"{REGIONS[region]['name']}隧道启动中，稍等几秒看状态；"
                               f"若一直未运行，退出 TUI 看 /var/lib/vpngate-fwmark/{region}.log 末尾。")
                    else:
                        msg = (f"{REGIONS[region]['name']}启动失败：openvpn 没起来，"
                               f"退出 TUI 看 /var/lib/vpngate-fwmark/{region}.log 末尾（一般是服务器下线/认证/无 tun 设备）。")
            draw(stdscr, regions, sel, cursor, cands, manual, msg)

    curses.wrapper(main_tui)


def main():
    p = argparse.ArgumentParser(prog="vpngate-fwmark")
    sub = p.add_subparsers(dest="action", required=True)
    for name in ("update", "list", "connect", "disconnect", "status", "watch", "tui"):
        sp = sub.add_parser(name)
        if name in ("update", "connect"):
            sp.add_argument("--use-ip", action="store_true")
            sp.add_argument("--check-reputation", action="store_true",
                            help="自动选时跳过信誉为高的出口（会多查几次免费接口，稍慢）")
        if name == "list":
            sp.add_argument("-n", type=int, default=10)
            sp.add_argument("--no-local-ping", action="store_true",
                            help="只显示 VPN Gate 公布的 Ping，不实测本地延迟")
    sub.add_parser("doctor")
    sp = sub.add_parser("ping")
    sp.add_argument("--ip", required=True, help="要测本地延迟的出口 IP，例如 101.111.161.173")
    sp = sub.add_parser("reputation")
    sp.add_argument("--ip", required=True, help="要查的出口 IP，例如 101.111.161.173")
    sp.add_argument("--force", action="store_true", help="不用 24 小时缓存，强制重查")
    sp.add_argument("--proxy", default=None, help="备选：信誉请求走的 HTTP 代理，例如 http://127.0.0.1:7890；也可设 VG_PROXY 环境变量")
    sp.add_argument("--via", choices=list(REGIONS.keys()), default=None,
                    help="首选：信誉请求走哪个地区的 VPN 隧道发出去（jp/kr），不用再搭 HTTP 代理；隧道没起时自动回落直连")
    sp = sub.add_parser("run")
    sp.add_argument("--region", choices=list(REGIONS.keys()), default="jp")
    sp.add_argument("command", nargs=argparse.REMAINDER)
    sp = sub.add_parser("set")
    sp.add_argument("--region", choices=list(REGIONS.keys()), required=True)
    sp.add_argument("--server")
    sp.add_argument("--auto", action="store_true")
    sub.add_parser("_up_hook")
    sub.add_parser("_down_hook")
    args = p.parse_args()
    if args.action == "set" and not args.auto and not args.server:
        p.error("set 需要 --server <主机名> 或 --auto")
    handler = {
        "update": cmd_update, "list": cmd_list, "connect": cmd_connect,
        "disconnect": cmd_disconnect, "status": cmd_status,
        "watch": cmd_watch, "run": cmd_run, "set": cmd_set, "tui": cmd_tui,
        "reputation": cmd_reputation, "ping": cmd_ping, "doctor": cmd_doctor,
        "_up_hook": _up_hook, "_down_hook": _down_hook,
    }[args.action]
    rc = handler(args)
    if rc:
        sys.exit(rc)


if __name__ == "__main__":
    main()
