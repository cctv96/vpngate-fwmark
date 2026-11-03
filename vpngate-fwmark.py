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
        print(f"{'IP':<16} {'主机名':<28} {'速度':>10} {'Ping':>6} {'会话':>5}")
        for s in grouped[region][: args.n]:
            print(f"{s['ip']:<16} {s['fqdn']:<28} "
                  f"{s['speed_mbps']:>8} Mbps {s['ping']:>4} ms {s['sessions']:>5}")


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
    ensure_user(region)
    files = region_files(region)
    if pid_running(region):
        return
    subprocess.Popen(["openvpn", "--daemon", "--config", files["ovpn"],
                      "--writepid", files["pid"], "--log", files["log"]])


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


def fetch_json(url, headers=None, timeout=15):
    req = urllib.request.Request(url, headers=headers or {"User-Agent": "vpngate-fwmark/2.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.load(resp)


def check_ip_reputation(ip, force=False):
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
        d = fetch_json(f"http://ip-api.com/json/{ip}?fields=status,message,country,isp,org,as,proxy,hosting,mobile,query")
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
            d = fetch_json(f"https://proxycheck.io/v2/{ip}?vpn=1&risk=1")
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
                           f"{ip}&contact={urllib.parse.quote(contact)}&format=json")
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
                           headers={"Key": key, "Accept": "application/json"})
            result["abuse_score"] = int(d["data"]["abuseConfidenceScore"])
            result["sources"].append("AbuseIPDB")
        except Exception:
            pass
    # 可选：IPQualityScore（取多源中的最高分，不静默覆盖）
    key = os.environ.get("IPQS_KEY")
    if key:
        try:
            d = fetch_json(f"https://ipqualityscore.com/api/json/ip/{key}/{ip}")
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
    rep = check_ip_reputation(args.ip, force=args.force)
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
                 f"候选服务器 · {REGIONS[region]['name']}（以 IP 为主，回车手动指定，p 查信誉）",
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
                safe_add(stdscr, row, 2,
                         f"{mark} {s['ip']:<15}  {s['fqdn']:<28} "
                         f"{s['speed_mbps']:>7} Mbps  Ping {s['ping']:>4} ms  {s['sessions']} 会话",
                         attr)
                row += 1
        # 底栏：帮助分两行写，消息最多显示两行并截断。
        safe_add(stdscr, height - 3, 0, "─" * max(0, width - 1), curses.color_pair(5))
        safe_add(stdscr, height - 2, 0,
                 "Tab 切换地区  ↑/↓(或j/k)选服务器  回车手动指定  a 自动  p 查信誉  r 刷新  s 启停  q 退出")
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
        regions = list(REGIONS.keys())
        sel = 0
        cursor = {r: 0 for r in regions}
        manual = load_json(MANUAL_FILE, {})
        cands = load_candidates()
        for r in regions:
            cands.setdefault(r, [])
        msg = "已加载候选列表。" if any(cands.values()) else "候选列表拉取失败，按 r 重试。"
        draw(stdscr, regions, sel, cursor, cands, manual, msg)
        while True:
            key = stdscr.getch()
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
                        rep = check_ip_reputation(chosen["ip"])
                        msg = (f"IP {rep['ip']} 信誉 {rep['risk']} 欺诈分 {rep.get('fraud_score')}（{rep.get('fraud_source') or ''}） "
                               f"滥用分 {rep.get('abuse_score')} 代理 {rep.get('proxy')} 机房 {rep.get('hosting')} "
                               f"ISP {rep.get('isp') or ''}")
                    except Exception as e:
                        msg = f"信誉检查失败：{e}"
                else:
                    msg = "暂无候选，按 r 刷新后再查。"
            elif key in (ord("s"), ord("S")):
                if pid_running(region):
                    stop_region(region)
                    msg = f"{REGIONS[region]['name']}隧道已停止。"
                elif os.path.exists(region_files(region)["ovpn"]):
                    start_region(region)
                    msg = f"{REGIONS[region]['name']}隧道启动中。"
                else:
                    msg = f"{REGIONS[region]['name']}还没有配置文件，先按 r 刷新或跑 connect 生成。"
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
    sp = sub.add_parser("reputation")
    sp.add_argument("--ip", required=True, help="要查的出口 IP，例如 101.111.161.173")
    sp.add_argument("--force", action="store_true", help="不用 24 小时缓存，强制重查")
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
        "reputation": cmd_reputation,
        "_up_hook": _up_hook, "_down_hook": _down_hook,
    }[args.action]
    handler(args)


if __name__ == "__main__":
    main()
