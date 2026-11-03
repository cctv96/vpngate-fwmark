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
#         getipintel（欺诈分 0~1，越接近 1 越可疑，无需 Key）
#   可选：AbuseIPDB（环境变量 ABUSEIPDB_KEY，滥用分 0~100）
#         IPQualityScore（环境变量 IPQS_KEY，欺诈分 0~100）
# 注意：VPN Gate 本来就是志愿者机房服务器，hosting=True 很常见，
# 单独因为“机房”就判高风险是错的；高风险只看欺诈分 / 滥用分 / 代理标记。
# 所谓“IP 纯净度”没有统一标准，这里给的是多源综合参考，不是官方判决。

REPUTATION_CACHE_TTL = 24 * 3600


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
        if time.time() - entry.get("checked_at", 0) < REPUTATION_CACHE_TTL:
            entry["cached"] = True
            return entry
    result = {"ip": ip, "country": "", "isp": "", "org": "", "asn": "",
              "proxy": None, "hosting": None, "mobile": None,
              "fraud_score": None, "abuse_score": None, "sources": []}
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
    # getipintel：欺诈分，免费但要求 contact 参数（填一个占位邮箱即可）。
    try:
        d = fetch_json(f"https://check.getipintel.net/check.php?ip={ip}&contact=vpngate-fwmark@example.com&format=json")
        if d.get("status") == "success":
            result["fraud_score"] = float(d.get("result"))
            result["sources"].append("getipintel")
    except Exception:
        pass
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
    # 可选：IPQualityScore
    key = os.environ.get("IPQS_KEY")
    if key:
        try:
            d = fetch_json(f"https://ipqualityscore.com/api/json/ip/{key}/{ip}")
            if d.get("success"):
                result["fraud_score"] = float(d.get("fraud_score", 0)) / 100.0
                result["sources"].append("IPQualityScore")
        except Exception:
            pass
    fraud = result["fraud_score"]
    abuse = result["abuse_score"]
    if (abuse is not None and abuse >= 75) or (fraud is not None and fraud >= 0.9):
        risk = "高"
    elif (abuse is not None and abuse >= 50) or (fraud is not None and fraud >= 0.7) or result["proxy"] is True:
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
    return (f"IP {rep['ip']} 信誉：{rep['risk']} | 国家 {rep.get('country') or '-'} | "
            f"ISP {rep.get('isp') or rep.get('org') or '-'} | ASN {rep.get('asn') or '-'} | "
            f"代理 {yn(rep.get('proxy'))} | 机房 {yn(rep.get('hosting'))} | "
            f"欺诈分 {rep.get('fraud_score')} | 滥用分 {rep.get('abuse_score')} | "
            f"来源 {','.join(rep.get('sources') or ['无'])}")


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
        grouped = candidates_by_region(parse_servers(fetch_csv()))
        return {r: [{k: v for k, v in s.items() if k != "config_b64"}
                     for s in grouped[r][:20]] for r in grouped}

    def draw(stdscr, regions, sel_region, cursor, cands, manual, msg):
        stdscr.clear()
        stdscr.addstr(0, 0, "vpngate-fwmark TUI  |  Tab 切换地区  上下选服务器  回车手动指定  a 自动  p 查IP信誉  r 刷新  s 启停  q 退出")
        row = 2
        for idx, region in enumerate(regions):
            info = REGIONS[region]
            meta = load_json(region_files(region)["meta"], {})
            mode = "手动" if region in manual else "自动"
            running = "运行中" if pid_running(region) else "未运行"
            head = (f"{'>' if idx == sel_region else ' '} {info['name']} {info['code']} "
                    f"fwmark={info['mark']} 表={info['table']} {info['dev']} [{mode}] [{running}]")
            stdscr.addstr(row, 0, head, curses.A_REVERSE if idx == sel_region else 0)
            row += 1
            stdscr.addstr(row, 2, f"当前出口 IP：{meta.get('ip', '（无）')}（{meta.get('fqdn', '')}） "
                                  f"{meta.get('speed_mbps', '')} Mbps / Ping {meta.get('ping', '')} ms")
            row += 1
            if idx == sel_region:
                stdscr.addstr(row, 2, "候选服务器（以 IP 为主区分，回车设为该地区的手动出口，p 查选中 IP 的信誉）：")
                row += 1
                for ci, s in enumerate(cands.get(region, [])[:8]):
                    mark = ">>" if ci == cursor[region] else "  "
                    stdscr.addstr(row, 4, f"{mark} IP {s['ip']}  {s['fqdn']} "
                                          f"{s['speed_mbps']} Mbps / Ping {s['ping']} ms / {s['sessions']} 会话")
                    row += 1
            row += 1
        stdscr.addstr(row + 1, 0, "运行命令：run --region jp -- <命令> 走日本；run --region kr -- <命令> 走韩国")
        stdscr.addstr(row + 2, 0, msg[:180])
        stdscr.refresh()

    def main_tui(stdscr):
        curses.curs_set(0)
        regions = list(REGIONS.keys())
        sel = 0
        cursor = {r: 0 for r in regions}
        manual = load_json(MANUAL_FILE, {})
        cands = load_candidates()
        msg = "已加载候选列表。"
        draw(stdscr, regions, sel, cursor, cands, manual, msg)
        while True:
            key = stdscr.getch()
            region = regions[sel]
            if key in (ord("q"), ord("Q")):
                break
            elif key == 9:  # Tab
                sel = (sel + 1) % len(regions)
            elif key == curses.KEY_UP:
                cursor[region] = max(0, cursor[region] - 1)
            elif key == curses.KEY_DOWN:
                lst = cands.get(region, [])
                cursor[region] = min(max(0, len(lst) - 1), cursor[region] + 1)
            elif key in (curses.KEY_ENTER, 10, 13):
                lst = cands.get(region, [])
                if lst:
                    chosen = lst[cursor[region]]
                    manual[region] = chosen["fqdn"]
                    with open(MANUAL_FILE, "w") as f:
                        json.dump(manual, f, ensure_ascii=False, indent=2)
                    # 手动切换：需要完整配置数据，重新拉取一次
                    grouped = candidates_by_region(parse_servers(fetch_csv()))
                    srv, _ = choose_for_region(region, grouped, manual)
                    if srv:
                        save_region(region, srv, "manual")
                        stop_region(region)
                        time.sleep(2)
                        start_region(region)
                        msg = f"{REGIONS[region]['name']}已手动切换到 {srv['fqdn']}。"
                    else:
                        msg = "该服务器已不在列表，切换失败。"
            elif key in (ord("a"), ord("A")):
                manual.pop(region, None)
                with open(MANUAL_FILE, "w") as f:
                    json.dump(manual, f, ensure_ascii=False, indent=2)
                grouped = candidates_by_region(parse_servers(fetch_csv()))
                srv, _ = choose_for_region(region, grouped, manual)
                if srv:
                    save_region(region, srv, "auto")
                    stop_region(region)
                    time.sleep(2)
                    start_region(region)
                    msg = f"{REGIONS[region]['name']}已恢复自动：{srv['fqdn']}。"
            elif key in (ord("r"), ord("R")):
                cands = load_candidates()
                try:
                    grouped = candidates_by_region(parse_servers(fetch_csv()))
                    cands = {r: [{k: v for k, v in s.items() if k != "config_b64"}
                                 for s in grouped[r][:20]] for r in grouped}
                    msg = "列表已刷新。"
                except Exception as e:
                    msg = f"刷新失败：{e}"
            elif key in (ord("p"), ord("P")):
                lst = cands.get(region, [])
                if lst:
                    chosen = lst[cursor[region]]
                    try:
                        rep = check_ip_reputation(chosen["ip"])
                        msg = (f"IP {rep['ip']} 信誉 {rep['risk']} 欺诈分 {rep.get('fraud_score')} "
                               f"滥用分 {rep.get('abuse_score')} 代理 {rep.get('proxy')} 机房 {rep.get('hosting')} "
                               f"ISP {rep.get('isp') or ''}")
                    except Exception as e:
                        msg = f"信誉检查失败：{e}"
            elif key in (ord("s"), ord("S")):
                if pid_running(region):
                    stop_region(region)
                    msg = f"{REGIONS[region]['name']}隧道已停止。"
                else:
                    start_region(region)
                    msg = f"{REGIONS[region]['name']}隧道启动中。"
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
