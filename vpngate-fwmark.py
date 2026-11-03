#!/usr/bin/env python3
"""
vpngate-fwmark v3: Mihomo 版

直接替换旧版的 fwmark / OpenVPN 实现，不再自己做路由标记：
旧版要自己维护 fwmark、路由表、iptables、专用用户、tun 隧道，
任何一环没起来就表现为“按了 s 但没连上、连日志都没有”。
新版把拨号和切换交给 Mihomo（Clash Meta）：

  日本 JP: Mihomo 实例 1，混合端口 7890，控制端口 9090，代理组 JP
  韩国 KR: Mihomo 实例 2，混合端口 7891，控制端口 9091，代理组 KR

  两个实例可以同时跑，互不干扰；切换节点是调 Mihomo 的控制 API，
  不用重启隧道、不用重新拨号，TUI 里回车就切。

抓取和筛选不变：
  VPN Gate 公开 API，主机名只留 vpn*（排除 public-vpn-*），
  只留日本、韩国，自动选速度最高、Ping 最低的服务器。

为什么 Mihomo 能直接拨 VPN Gate：
  Mihomo v1.19.25 起自带 type: openvpn 出站，支持 VPN Gate 配置里的
  cipher AES-128-CBC、auth SHA1、ca / cert / key 内联证书、用户名密码
  vpn / vpn，且 VPN Gate 配置里没有 tls-auth / tls-crypt 这种
  容易卡住的字段。程序把 .ovpn 解析成 Mihomo 的 proxies，不是
  再去调 openvpn 二进制。

指定程序怎么走 VPN（和旧版的区别，一定要看）：
  旧版是包级别分流：任何程序（支不支持代理都行）都能走指定出口。
  新版是代理级别分流：程序要走代理才行。
    sudo vpngate-fwmark run --region jp -- curl -s ifconfig.me
  run 会给这条命令设好代理环境变量（http/https 走 7890，socks 走
  7890），curl、wget、git、python requests 这类认环境变量的程序
  直接就能用。浏览器要在设置里手动填代理 127.0.0.1:7890，
  或者用支持代理的启动参数；不认代理的程序目前走不了，这是
  换 Mihomo 换来的代价，不是 bug。

用法（需 root，状态在 /var/lib/vpngate-fwmark）：
  vpngate-fwmark update / list / connect / disconnect / status
  vpngate-fwmark run --region jp -- curl -s ifconfig.me
  vpngate-fwmark set --region jp --server vpn341881580.opengw.net
  vpngate-fwmark set --region jp --auto
  vpngate-fwmark tui
  vpngate-fwmark watch   # systemd timer 每 6 小时调用
"""

import argparse
import base64
import csv
import io
import json
import os
import re
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.error

API_URL = "http://www.vpngate.net/api/iphone/"
STATE_DIR = os.environ.get("VG_STATE_DIR", "/var/lib/vpngate-fwmark")
CONFIG_DIR = os.environ.get("VG_CONFIG_DIR", "/etc/vpngate-fwmark")
MIHOMO_BIN = os.environ.get("VG_MIHOMO_BIN", "/usr/local/bin/mihomo")
MIHOMO_VERSION = "v1.19.33"
CANDIDATES_FILE = os.path.join(STATE_DIR, "candidates.json")
MANUAL_FILE = os.path.join(STATE_DIR, "manual.json")
MAX_AGE = 6 * 3600

# 地区 -> 国家码 / 混合端口 / 控制端口 / 代理组名
# 两个实例各占一对端口，同时跑也不冲突。
REGIONS = {
    "jp": {"name": "日本", "code": "JP", "mixed_port": 7890, "controller": 9090, "group": "JP"},
    "kr": {"name": "韩国", "code": "KR", "mixed_port": 7891, "controller": 9091, "group": "KR"},
}


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
        "yaml": os.path.join(STATE_DIR, f"{region}.yaml"),
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
    req = urllib.request.Request(url, headers={"User-Agent": "vpngate-fwmark/3.0"})
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
    grouped = {}
    for region, info in REGIONS.items():
        grouped[region] = [s for s in servers if s["country"] == info["code"]]
    return grouped


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


def proxy_name(server):
    """Mihomo 里的节点名：地区前缀 + 主机名，一眼看出是哪个出口。"""
    return f"{server['country']}-{server['fqdn']}"


def parse_ovpn(server):
    """把 VPN Gate 的 .ovpn 文本解析成 Mihomo openvpn 出站需要的字段。
    只取第一个 remote（VPN Gate 配置里一般就一个），proto 里含 tcp
    就是 tcp，否则按 udp 处理；ca / cert / key 从内联块里取。"""
    raw = base64.b64decode(server["config_b64"]).decode("utf-8", errors="replace")

    def block(name):
        m = re.search(rf"<{name}>(.*?)</{name}>", raw, re.S)
        return m.group(1).strip() if m else ""

    def kv(key):
        m = re.search(rf"^{key}\s+(.+)$", raw, re.M)
        return m.group(1).strip() if m else ""

    remote = kv("remote").split()
    proto_raw = kv("proto") or "tcp"
    proto = "tcp" if "tcp" in proto_raw else "udp"
    return {
        "server": server["fqdn"],
        "port": int(remote[1]) if len(remote) > 1 and remote[1].isdigit() else 1194,
        "proto": proto,
        "cipher": kv("cipher"),
        "auth": kv("auth"),
        "ca": block("ca"),
        "cert": block("cert"),
        "key": block("key"),
    }


def _indent_block(text, spaces):
    pad = " " * spaces
    return "\n".join(pad + ln for ln in text.splitlines())


def build_mihomo_yaml(region, servers, use_ip=False):
    """给一个地区生成 Mihomo 配置。
    servers 是该地区的全部候选（按速度排好），全部放进 proxies，
    这样 TUI / set 切任何一个都不用重新生成配置，API 一调就切。
    代理组只有一个 select 组，MATCH 全指到它：混合端口进来的流量
    全部走这个组，组里当前选中的节点就是出口。"""
    info = REGIONS[region]
    # 手动指定的放最前面：Mihomo select 组默认选第一个，
    # 这样实例刚启动、还没来得及调 API 时，默认出口也是手动那个。
    manual = load_json(MANUAL_FILE, {})
    wanted = manual.get(region)
    ordered = list(servers)
    if wanted:
        ordered.sort(key=lambda s: 0 if (s["fqdn"] == wanted or s["host"] == wanted
                                          or s["ip"] == wanted) else 1)
    lines = [
        f"mixed-port: {info['mixed_port']}",
        "allow-lan: false",
        "mode: rule",
        "log-level: info",
        "ipv6: false",
        f"external-controller: 127.0.0.1:{info['controller']}",
        "dns:",
        "  enable: true",
        # 国内 8.8.8.8 / 1.1.1.1 常被挡或很慢，Mihomo 解析 VPN Gate
        # 主机名（opengw.net）时一旦 DNS 全失败，隧道连握手都开始不了。
        # 加 223.5.5.5（阿里）和 114.114.114.114（114DNS）兜底，
        # 解析的只是公开域名，不是敏感查询。
        "  nameserver:",
        "    - 8.8.8.8",
        "    - 1.1.1.1",
        "    - 223.5.5.5",
        "    - 114.114.114.114",
        "proxies:",
    ]
    names = []
    for s in ordered:
        d = parse_ovpn(s)
        name = proxy_name(s)
        names.append(name)
        if use_ip:
            d["server"] = s["ip"]
        lines.append(f"  - name: {json.dumps(name)}")
        lines.append("    type: openvpn")
        lines.append(f"    server: {json.dumps(d['server'])}")
        lines.append(f"    port: {d['port']}")
        lines.append(f"    proto: {d['proto']}")
        lines.append('    username: "vpn"')
        lines.append('    password: "vpn"')
        if d["cipher"]:
            lines.append(f"    cipher: {json.dumps(d['cipher'])}")
        if d["auth"]:
            lines.append(f"    auth: {json.dumps(d['auth'])}")
        lines.append(f"    udp: {'false' if d['proto'] == 'tcp' else 'true'}")
        if d["ca"]:
            lines.append("    ca: |")
            lines.append(_indent_block(d["ca"], 6))
        if d["cert"]:
            lines.append("    cert: |")
            lines.append(_indent_block(d["cert"], 6))
        if d["key"]:
            lines.append("    key: |")
            lines.append(_indent_block(d["key"], 6))
    lines.append("proxy-groups:")
    lines.append(f"  - name: {json.dumps(info['group'])}")
    lines.append("    type: select")
    lines.append("    proxies:")
    for n in names:
        lines.append(f"      - {json.dumps(n)}")
    lines.append("rules:")
    lines.append(f"  - MATCH,{info['group']}")
    return "\n".join(lines) + "\n"


def save_region(region, servers, mode, use_ip=False):
    """写 Mihomo 配置 + 元数据，返回选中的服务器元数据。"""
    ensure_dirs()
    files = region_files(region)
    manual = load_json(MANUAL_FILE, {})
    grouped = {region: servers}
    chosen, _mode = choose_for_region(region, grouped, manual)
    mode = _mode if chosen else mode
    with open(files["yaml"], "w") as f:
        f.write(build_mihomo_yaml(region, servers, use_ip=use_ip))
    meta = {}
    if chosen:
        meta = {k: v for k, v in chosen.items() if k != "config_b64"}
    meta["updated_at"] = int(time.time())
    meta["mode"] = mode
    meta["mixed_port"] = REGIONS[region]["mixed_port"]
    meta["controller"] = REGIONS[region]["controller"]
    meta["group"] = REGIONS[region]["group"]
    with open(files["meta"], "w") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)
    return meta


def update_all(args):
    """拉取 + 生成两个地区的 Mihomo 配置。已在跑的实例会重启一次
    让新配置生效（Mihomo 不会自动重读配置文件）；没跑的只写配置，
    不自动拉起来。返回 grouped（完整候选）。"""
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
        if check_rep and mode == "auto":
            for cand in grouped[region][:5]:
                rep = check_ip_reputation(cand["ip"])
                if rep["risk"] == "高":
                    print(f"跳过高风险出口 {cand['ip']}（{cand['fqdn']}），信誉 {rep['risk']}。")
                    continue
                chosen = cand
                break
        was_running = pid_running(region) is not None
        meta = save_region(region, grouped[region], mode,
                           use_ip=getattr(args, "use_ip", False))
        if was_running:
            stop_region(region)
            time.sleep(1)
            start_region(region)
        print(f"{meta['country']} 已更新（{mode}）：{meta['fqdn']} "
              f"{meta['speed_mbps']} Mbps / Ping {meta['ping']} ms / "
              f"{meta['sessions']} 会话。")
    return grouped


def cmd_update(args):
    need_root()
    update_all(args)


def measure_local_latency(ip, timeout=2):
    """本地到 VPN 服务器的延迟，单位 ms，返回 (ms, 方法) 或 (None, None)。
    CSV 里的 Ping 是 VPN Gate 公布值，不是本机到服务器的延迟，不能直接用。
    先 ping（ICMP），被挡就回落 TCP 443 握手计时（端口关了回 RST 也算往返）。"""
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
            pass
        return round((time.time() - start) * 1000, 1), "tcp"
    except Exception:
        return None, None


def cmd_list(args):
    need_root()
    grouped = candidates_by_region(parse_servers(fetch_csv()))
    for region, info in REGIONS.items():
        print(f"\n== {info['name']} {info['code']} "
              f"(混合端口 {info['mixed_port']} / 控制端口 {info['controller']} / 组 {info['group']}) ==")
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
        print(f"{args.ip} 本地延迟：测不到（ping 被挡且 TCP 443 超时）")
    else:
        way = "ping（ICMP）" if method == "ping" else "TCP 握手（ping 被挡时的回落）"
        print(f"{args.ip} 本地延迟：{ms:.1f} ms（{way}，从本机实测，非 VPN Gate 公布值）")


# ---------------- Mihomo 控制 API ----------------

def controller_base(region):
    return f"http://127.0.0.1:{REGIONS[region]['controller']}"


def api_get(region, path, timeout=5):
    try:
        req = urllib.request.Request(controller_base(region) + path)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.load(resp)
    except Exception:
        return None


def api_switch(region, proxy_name_value, timeout=10):
    """切代理组当前节点：PUT /proxies/<组名> {"name": "<节点名>"}。
    返回 True/False，失败不抛错，让调用方决定是提示还是走更新重启。"""
    try:
        data = json.dumps({"name": proxy_name_value}).encode()
        req = urllib.request.Request(
            controller_base(region) + "/proxies/" + REGIONS[region]["group"],
            data=data, method="PUT",
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status in (200, 204)
    except Exception:
        return False


def api_current(region):
    data = api_get(region, "/proxies")
    if not data:
        return None
    group = data.get("proxies", {}).get(REGIONS[region]["group"], {})
    return group.get("now")


def wait_controller(region, timeout=15):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if api_get(region, "/proxies", timeout=2):
            return True
        time.sleep(0.5)
    return False


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


def start_region(region):
    """启动一个地区的 Mihomo 实例。返回 True/False，预检失败把原因
    写进该地区日志文件本身（旧版教训：日志不存在时用户完全不知道为什么）。"""
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

    if shutil.which(MIHOMO_BIN) is None and not os.path.exists(MIHOMO_BIN):
        return _fail(f"本机没有 mihomo（{MIHOMO_BIN}），请跑安装脚本")
    if pid_running(region):
        return True
    if not os.path.exists(files["yaml"]):
        return _fail(f"配置文件不存在：{files['yaml']}，先跑 connect 生成")
    try:
        logf = open(files["log"], "a")
        proc = subprocess.Popen([MIHOMO_BIN, "-f", files["yaml"]],
                                stdout=logf, stderr=logf,
                                start_new_session=True, cwd=STATE_DIR)
        with open(files["pid"], "w") as f:
            f.write(str(proc.pid))
    except Exception as e:
        return _fail(f"拉起 mihomo 失败：{e}")
    if not wait_controller(region):
        return _fail("mihomo 启动后控制端口一直没响应，看日志末尾找原因")
    # 启动后按手动指定再切一次：配置文件里手动节点虽然排在最前，
    # 但 API 切一次最保险，避免 Mihomo 默认选了别的节点。
    manual = load_json(MANUAL_FILE, {})
    if manual.get(region):
        meta = load_json(files["meta"], {})
        if meta.get("fqdn"):
            # 节点名 = 地区-主机名，和 build_mihomo_yaml 里一致
            api_switch(region, f"{REGIONS[region]['code']}-{meta['fqdn']}")
    return True


def stop_region(region):
    pid = pid_running(region)
    if pid:
        try:
            os.kill(pid, 15)
            for _ in range(10):
                time.sleep(0.2)
                try:
                    os.kill(pid, 0)
                except ProcessLookupError:
                    break
        except ProcessLookupError:
            pass
    try:
        os.remove(region_files(region)["pid"])
    except Exception:
        pass


def cmd_connect(args):
    need_root()
    ensure_dirs()
    _critical = [c for c in system_checks()
                 if c[1] in ("mihomo", "状态目录可写") and not c[0]]
    if _critical:
        for _ok, _name, _detail in _critical:
            print(f"✗ {_name}：{_detail}")
        print("系统检查没过，实例不会启动。先修上面几项，再跑 connect。")
        return
    need_update = False
    for region in REGIONS:
        files = region_files(region)
        if not os.path.exists(files["yaml"]):
            need_update = True
        elif os.path.exists(files["meta"]):
            try:
                age = time.time() - json.load(open(files["meta"]))["updated_at"]
                if age > MAX_AGE:
                    need_update = True
            except Exception:
                need_update = True
    if need_update:
        update_all(args)
    for region in REGIONS:
        ok = start_region(region)
        info = REGIONS[region]
        print(f"{info['name']}：{'已启动' if ok else '启动失败，看日志 ' + region_files(region)['log']}"
              f"（混合端口 {info['mixed_port']}，控制端口 {info['controller']}）")
    print("用 status 查看当前出口，用 tui 手动换节点（回车即切，不用重启）。")


def cmd_disconnect(_args):
    need_root()
    for region in REGIONS:
        stop_region(region)
    print("两个 Mihomo 实例已停。")


def system_checks():
    import shutil
    checks = []

    def add(ok, name, detail):
        checks.append((bool(ok), name, detail))

    add(os.geteuid() == 0, "root 权限", "当前是 root" if os.geteuid() == 0 else "当前不是 root，请用 sudo")
    if os.path.exists(MIHOMO_BIN):
        ver = run([MIHOMO_BIN, "-v"]).stdout.splitlines()
        add(True, "mihomo", (ver[0].strip() if ver else MIHOMO_BIN))
    else:
        add(False, "mihomo", f"未安装：{MIHOMO_BIN} 不存在，跑安装脚本（它会下载 Mihomo {MIHOMO_VERSION}）")
    add(shutil.which("ping") is not None, "命令 ping", "已安装" if shutil.which("ping") else "未安装（本地延迟实测会回落 TCP）")
    add(shutil.which("curl") is not None, "命令 curl", "已安装" if shutil.which("curl") else "未安装")
    try:
        os.makedirs(STATE_DIR, exist_ok=True)
        open(os.path.join(STATE_DIR, ".wtest"), "w").close()
        add(True, "状态目录可写", STATE_DIR)
    except Exception as e:
        add(False, "状态目录可写", f"{STATE_DIR} 写不进去：{e}")
    for region, info in REGIONS.items():
        files = region_files(region)
        add(os.path.exists(files["yaml"]), f"{info['name']} Mihomo 配置",
            files["yaml"] if os.path.exists(files["yaml"]) else "不存在：先跑 connect 生成")
        pid = pid_running(region)
        add(pid is not None, f"{info['name']} 实例进程",
            f"运行中 pid={pid}" if pid else "未运行")
        cur = api_current(region) if pid else None
        add(cur is not None, f"{info['name']} 控制端口 {info['controller']}",
            f"可达，当前节点 {cur}" if cur else "不可达（实例没起或还没就绪）")
        if os.path.exists(files["log"]):
            add(True, f"{info['name']} 日志", files["log"])
        else:
            add(False, f"{info['name']} 日志",
                "不存在：实例还没真正启动过——先看上面 mihomo / 配置两项")
    return checks


CRITICAL_CHECKS = {"root 权限", "mihomo", "状态目录可写"}


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
            mark = "○"
        print(f"{mark} {name}：{detail}")
    if bad:
        print(f"\n系统检查：{bad} 项关键问题。先修上面带 ✗ 的项再启动。○ 是“还没连过”，不是故障。")
        return 1
    print("\n系统检查：关键项全部通过，可以启动。○ 是“还没连过”，不是故障。")
    return 0


def cmd_status(_args):
    for region, info in REGIONS.items():
        meta = load_json(region_files(region)["meta"], {})
        cur = api_current(region) if pid_running(region) else None
        print(f"{info['name']} {info['code']}: 当前节点={cur or meta.get('fqdn', '（无）')} "
              f"IP={meta.get('ip', '')} 模式={meta.get('mode', '-')} "
              f"pid={pid_running(region) or '未运行'} "
              f"混合端口={info['mixed_port']} 控制端口={info['controller']} 组={info['group']}")


def switch_region(region, server):
    """切一个地区的出口。优先 API 即切（实例在跑且节点已在配置里）；
    API 切不动就走更新重启全套，保证最终状态是对的。"""
    if pid_running(region) and api_switch(region, proxy_name(server)):
        meta = load_json(region_files(region)["meta"], {})
        meta.update({k: v for k, v in server.items() if k != "config_b64"})
        meta["mode"] = "manual"
        with open(region_files(region)["meta"], "w") as f:
            json.dump(meta, f, ensure_ascii=False, indent=2)
        return True
    # API 路径走不通：重新拉取生成配置，启动后再切一次
    try:
        grouped = candidates_by_region(parse_servers(fetch_csv()))
        srv, _ = choose_for_region(region, grouped, load_json(MANUAL_FILE, {}))
        if srv:
            save_region(region, grouped[region], "manual" if region in load_json(MANUAL_FILE, {}) else "auto")
            stop_region(region)
            time.sleep(1)
            if start_region(region):
                return api_switch(region, proxy_name(srv))
    except Exception:
        pass
    return False


def cmd_set(args):
    need_root()
    region = args.region
    manual = load_json(MANUAL_FILE, {})
    if args.auto:
        manual.pop(region, None)
        print(f"{REGIONS[region]['name']}已恢复自动选择。")
    else:
        manual[region] = args.server
        print(f"{REGIONS[region]['name']}已手动指定为 {args.server}，正在切换。")
    with open(MANUAL_FILE, "w") as f:
        json.dump(manual, f, ensure_ascii=False, indent=2)
    grouped = candidates_by_region(parse_servers(fetch_csv()))
    srv, mode = choose_for_region(region, grouped, manual)
    if not srv:
        print("该服务器不在当前列表，切换失败（可能已下线）。")
        return
    if args.auto:
        # 自动：切到列表最优，并把配置里手动顺序恢复（下次 update 生效）
        ok = switch_region(region, srv) if pid_running(region) else False
        if not ok:
            update_all(args)
            start_region(region)
    else:
        ok = switch_region(region, srv)
        print(f"{REGIONS[region]['name']}切换{'成功' if ok else '失败'}：{srv['ip']}（{srv['fqdn']}）"
              f"{'' if ok else '，看日志 ' + region_files(region)['log']}")


def cmd_run(args):
    need_root()
    region = args.region
    if args.command and args.command[0] == "--":
        args.command = args.command[1:]
    if not args.command:
        sys.exit("用法：run --region jp -- <命令>，例如 run --region jp -- curl -s ifconfig.me")
    if not pid_running(region):
        cmd_connect(args)
        time.sleep(2)
    port = REGIONS[region]["mixed_port"]
    env = dict(os.environ)
    env.update({
        "http_proxy": f"http://127.0.0.1:{port}",
        "https_proxy": f"http://127.0.0.1:{port}",
        "HTTP_PROXY": f"http://127.0.0.1:{port}",
        "HTTPS_PROXY": f"http://127.0.0.1:{port}",
        "all_proxy": f"socks5://127.0.0.1:{port}",
        "ALL_PROXY": f"socks5://127.0.0.1:{port}",
        "no_proxy": "localhost,127.0.0.1",
        "NO_PROXY": "localhost,127.0.0.1",
    })
    # sudo 进来的话，程序本身别用 root 跑（浏览器等尤其不能 root），
    # 回到原来那个用户；没有 SUDO_USER 就按当前用户跑。
    sudo_user = os.environ.get("SUDO_USER")
    if os.geteuid() == 0 and sudo_user and sudo_user != "root":
        if run(["which", "runuser"]).returncode == 0:
            cmd = ["runuser", "-u", sudo_user, "--", "env"] + [
                f"{k}={v}" for k, v in env.items()
                if k in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY",
                         "all_proxy", "ALL_PROXY", "no_proxy", "NO_PROXY")] + args.command
            # runuser + env 会丢失其它环境变量，但代理变量已带上，够用。
            sys.exit(subprocess.call(cmd))
        cmd = ["su", sudo_user, "-s", "/bin/sh", "-c",
               " ".join(f"{k}={v}" for k, v in env.items()
                        if k in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY",
                                 "all_proxy", "ALL_PROXY", "no_proxy", "NO_PROXY"))
               + " " + " ".join(args.command)]
        sys.exit(subprocess.call(cmd))
    sys.exit(subprocess.call(args.command, env=env))


def cmd_watch(args):
    need_root()
    before = {r: load_json(region_files(r)["meta"], {}).get("fqdn") for r in REGIONS}
    try:
        update_all(args)
    except SystemExit:
        return
    for region in REGIONS:
        if not pid_running(region):
            start_region(region)
    print(f"watch 检查完成：手动指定的地区不会被自动换服（更新前 {before}）。")


# ---------------- IP 信誉检查 ----------------
# 免费源：ip-api.com、proxycheck.io（默认欺诈分，vpn=1&risk=1 查两次取最高，
# 因为免费端点对同一 IP 有时回 66 有时回 0）；getipintel 仅当设置了真实
# VG_CONTACT_EMAIL 时才查，example.com 占位邮箱会被它封并返回 error/-5。
# 可选 Key：ABUSEIPDB_KEY、IPQS_KEY。代理 / 机房不再单独定风险：
# VPN 出口本来就是代理 / 机房，只看欺诈分 / 滥用分。
# 走法：--via jp/kr 时信誉请求走该地区 Mihomo 的混合端口（HTTP 代理），
# 实例没起就回落直连；也可以用 VG_PROXY / --proxy 指定其它 HTTP 代理。

REPUTATION_CACHE_TTL = 24 * 3600
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


def fetch_json(url, headers=None, timeout=15, proxy=None, via_region=None):
    """查 JSON 接口。proxy 优先级：显式 proxy > via 地区混合端口 >
    VG_PROXY 环境变量；代理走不通回落直连一次（实例没起时就是这条路）。"""
    if via_region in REGIONS:
        proxy = f"http://127.0.0.1:{REGIONS[via_region]['mixed_port']}"
    proxy_url = proxy or os.environ.get("VG_PROXY")
    req = urllib.request.Request(url, headers=headers or {"User-Agent": "vpngate-fwmark/3.0"})
    if proxy_url:
        try:
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url}))
            with opener.open(req, timeout=timeout) as resp:
                return json.load(resp)
        except Exception:
            # 代理没起 / 被挡：回落直连，别因为实例没起就直接报未知。
            req2 = urllib.request.Request(url, headers=headers or {"User-Agent": "vpngate-fwmark/3.0"})
            with urllib.request.urlopen(req2, timeout=timeout) as resp:
                return json.load(resp)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.load(resp)


def check_ip_reputation(ip, force=False, proxy=None, via_region=None):
    cache_path = reputation_cache_path()
    cache = load_json(cache_path, {})
    if not force and ip in cache:
        entry = cache[ip]
        if (entry.get("cache_version") == REPUTATION_CACHE_VERSION
                and time.time() - entry.get("checked_at", 0) < REPUTATION_CACHE_TTL):
            entry["cached"] = True
            return entry
    result = {"ip": ip, "country": "", "isp": "", "org": "", "asn": "",
              "proxy": None, "hosting": None, "mobile": None,
              "fraud_score": None, "abuse_score": None, "sources": [],
              "fraud_source": "", "fraud_error": "", "proxy_type": "",
              "cache_version": REPUTATION_CACHE_VERSION}
    try:
        d = fetch_json(f"http://ip-api.com/json/{ip}?fields=status,message,country,isp,org,as,proxy,hosting,mobile,query",
                       proxy=proxy, via_region=via_region)
        if d.get("status") == "success":
            result.update({"country": d.get("country", ""), "isp": d.get("isp", ""),
                           "org": d.get("org", ""), "asn": d.get("as", ""),
                           "proxy": d.get("proxy"), "hosting": d.get("hosting"),
                           "mobile": d.get("mobile")})
            result["sources"].append("ip-api.com")
    except Exception:
        pass
    try:
        best = None
        for _ in range(2):
            d = fetch_json(f"https://proxycheck.io/v2/{ip}?vpn=1&risk=1",
                           proxy=proxy, via_region=via_region)
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
    contact = os.environ.get("VG_CONTACT_EMAIL", "").strip()
    if contact and "@" in contact and not contact.endswith("@example.com"):
        try:
            import urllib.parse
            d = fetch_json("https://check.getipintel.net/check.php?ip="
                           f"{ip}&contact={urllib.parse.quote(contact)}&format=json",
                           proxy=proxy, via_region=via_region)
            if d.get("status") == "success":
                score = float(d.get("result"))
                if score >= 0:
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
        result["fraud_error"] = "getipintel 未调用：请设置 VG_CONTACT_EMAIL 为你的真实邮箱"
    key = os.environ.get("ABUSEIPDB_KEY")
    if key:
        try:
            d = fetch_json(f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90",
                           headers={"Key": key, "Accept": "application/json"},
                           proxy=proxy, via_region=via_region)
            result["abuse_score"] = int(d["data"]["abuseConfidenceScore"])
            result["sources"].append("AbuseIPDB")
        except Exception:
            pass
    key = os.environ.get("IPQS_KEY")
    if key:
        try:
            d = fetch_json(f"https://ipqualityscore.com/api/json/ip/{key}/{ip}",
                           proxy=proxy, via_region=via_region)
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
    if (abuse is not None and abuse >= 75) or (fraud is not None and fraud >= 0.9):
        risk = "高"
    elif (abuse is not None and abuse >= 50) or (fraud is not None and fraud >= 0.7):
        risk = "中"
    elif fraud is not None or abuse is not None:
        risk = "低"
    else:
        risk = "未知（免费源未返回分数，仅看国家/ISP/机房标记）"
    result["risk"] = risk
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
        print(f"（信誉请求走 {REGIONS[via]['name']} Mihomo 混合端口 {REGIONS[via]['mixed_port']} 发出去，实例没起时自动回落直连）")
    print(format_reputation(rep))
    print("提醒：机房 IP 对 VPN 出口来说是正常的，单独看机房标记不能判为脏 IP；重点看欺诈分 / 滥用分是否高。")


# ---------------- TUI ----------------

def cmd_tui(_args):
    need_root()
    import curses

    def load_candidates():
        cands = load_json(CANDIDATES_FILE, {})
        if cands and any(cands.values()):
            return cands
        try:
            grouped = candidates_by_region(parse_servers(fetch_csv()))
        except Exception:
            return {r: [] for r in REGIONS}
        return {r: [{k: v for k, v in s.items() if k != "config_b64"}
                     for s in grouped[r][:20]] for r in grouped}

    def safe_add(stdscr, y, x, text, attr=0):
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
        safe_add(stdscr, 0, 0, " vpngate-fwmark · Mihomo ".ljust(width), curses.color_pair(1) | curses.A_BOLD)
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
                    f"混合端口 {info['mixed_port']}  组 {info['group']}  [{mode}]")
            head_attr = curses.color_pair(2) | curses.A_BOLD if idx == sel_region else curses.A_BOLD
            safe_add(stdscr, row, 0, head, head_attr)
            safe_add(stdscr, row, max(0, width - 12), status, status_attr)
            row += 1
            safe_add(stdscr, row, 2,
                     f"当前出口 IP：{meta.get('ip', '（无）')}（{meta.get('fqdn', '')}） "
                     f"{meta.get('speed_mbps', '')} Mbps / Ping {meta.get('ping', '')} ms")
            row += 1
            safe_add(stdscr, row, 0, "─" * max(0, width - 1), curses.color_pair(5))
            row += 1
        footer_rows = 3
        avail = max(1, height - row - footer_rows - 1)
        region = regions[sel_region]
        lst = cands.get(region, [])
        clamp_cursor(cursor, region, lst)
        safe_add(stdscr, row, 0,
                 f"候选服务器 · {REGIONS[region]['name']}（回车即切节点，不用重启；欺诈分在每行后面，后台自动查，p 查详情）",
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
        try:
            curses.start_color()
            curses.use_default_colors()
            curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_BLUE)
            curses.init_pair(2, curses.COLOR_BLACK, curses.COLOR_CYAN)
            curses.init_pair(3, curses.COLOR_GREEN, -1)
            curses.init_pair(4, curses.COLOR_RED, -1)
            curses.init_pair(5, curses.COLOR_CYAN, -1)
        except Exception:
            pass
        try:
            stdscr.timeout(500)
        except Exception:
            pass
        _crit = [c for c in system_checks()
                 if c[1] in ("mihomo", "状态目录可写") and not c[0]]
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
                draw(stdscr, regions, sel, cursor, cands, manual, msg)
                continue
            region = regions[sel]
            if key in (ord("q"), ord("Q")):
                break
            elif key == curses.KEY_RESIZE:
                pass
            elif key == 9:
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
                    # 先 API 即切：实例在跑且节点已在配置里，秒切不用重启。
                    # API 切不动（实例没起 / 配置还是旧的）再走更新重启全套。
                    manual[region] = chosen["fqdn"]
                    with open(MANUAL_FILE, "w") as f:
                        json.dump(manual, f, ensure_ascii=False, indent=2)
                    if pid_running(region) and api_switch(region, proxy_name(chosen)):
                        meta = load_json(region_files(region)["meta"], {})
                        meta.update({k: v for k, v in chosen.items() if k != "config_b64"})
                        meta["mode"] = "manual"
                        with open(region_files(region)["meta"], "w") as f:
                            json.dump(meta, f, ensure_ascii=False, indent=2)
                        msg = f"{REGIONS[region]['name']}已手动切换到 {chosen['ip']}（{chosen['fqdn']}），API 即切。"
                    else:
                        try:
                            grouped = candidates_by_region(parse_servers(fetch_csv()))
                            srv, _ = choose_for_region(region, grouped, manual)
                        except Exception as e:
                            srv = None
                            msg = f"拉取列表失败，未切换：{e}"
                        if srv:
                            save_region(region, grouped[region], "manual")
                            stop_region(region)
                            time.sleep(1)
                            if start_region(region) and api_switch(region, proxy_name(srv)):
                                msg = f"{REGIONS[region]['name']}已手动切换到 {srv['ip']}（{srv['fqdn']}）。"
                            else:
                                msg = f"{REGIONS[region]['name']}切换失败，看日志 {region_files(region)['log']}。"
                        elif "拉取列表失败" not in msg:
                            msg = "该服务器已不在列表，切换失败，旧实例未动。"
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
                    if pid_running(region) and api_switch(region, proxy_name(srv)):
                        msg = f"{REGIONS[region]['name']}已恢复自动：{srv['ip']}（{srv['fqdn']}）。"
                    else:
                        save_region(region, grouped[region], "auto")
                        stop_region(region)
                        time.sleep(1)
                        start_region(region)
                        msg = f"{REGIONS[region]['name']}已恢复自动：{srv['ip']}（{srv['fqdn']}）。"
                elif "拉取列表失败" not in msg:
                    msg = "暂无候选，恢复自动失败。"
            elif key in (ord("r"), ord("R")):
                try:
                    class _A:  # update_all 只读 use_ip / check_reputation 两个属性
                        use_ip = False
                        check_reputation = False
                    grouped = update_all(_A())
                    cands = {r: [{k: v for k, v in s.items() if k != "config_b64"}
                                 for s in grouped[r][:20]] for r in grouped}
                    for r in regions:
                        cands.setdefault(r, [])
                        clamp_cursor(cursor, r, cands[r])
                    msg = "列表已刷新，在跑的实例已重启加载新配置。"
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
                        rep = check_ip_reputation(chosen["ip"], proxy=rep_proxy,
                                                  via_region=region if pid_running(region) else None)
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
                    _lines = ["日志文件不存在：实例还没真正启动过。",
                              "先按 c 看系统检查（mihomo / 配置缺哪项），",
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
                    msg = f"{REGIONS[region]['name']}实例已停止。"
                else:
                    if not os.path.exists(region_files(region)["yaml"]):
                        msg = f"{REGIONS[region]['name']}还没有配置文件，正在拉取生成……"
                        draw(stdscr, regions, sel, cursor, cands, manual, msg)
                        try:
                            grouped = candidates_by_region(parse_servers(fetch_csv()))
                            srv, _ = choose_for_region(region, grouped, manual)
                            if srv:
                                save_region(region, grouped[region], "manual" if region in manual else "auto")
                                cands[region] = [{k: v for k, v in s.items() if k != "config_b64"}
                                                 for s in grouped[region][:20]]
                                msg = f"{REGIONS[region]['name']}配置已生成（{srv['ip']}），正在启动实例……"
                            else:
                                msg = f"{REGIONS[region]['name']}拉取列表为空，启动失败。"
                                draw(stdscr, regions, sel, cursor, cands, manual, msg)
                                continue
                        except Exception as e:
                            msg = f"{REGIONS[region]['name']}拉取配置失败：{e}，先在外面跑 sudo vpngate-fwmark connect 看日志。"
                            draw(stdscr, regions, sel, cursor, cands, manual, msg)
                            continue
                    import shutil as _shutil
                    if not os.path.exists(MIHOMO_BIN):
                        msg = f"{REGIONS[region]['name']}启动失败：本机没有 mihomo，先跑安装脚本。"
                    elif start_region(region):
                        with rep_lock:
                            for _s in cands.get(region, []):
                                rep_scores.pop(_s["ip"], None)
                        msg = (f"{REGIONS[region]['name']}实例启动中，稍等几秒看状态；"
                               f"若一直未运行，退出 TUI 看 /var/lib/vpngate-fwmark/{region}.log 末尾。")
                    else:
                        msg = (f"{REGIONS[region]['name']}启动失败，"
                               f"退出 TUI 看 /var/lib/vpngate-fwmark/{region}.log 末尾。")
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
                    help="首选：信誉请求走哪个地区的 Mihomo 混合端口发出去（jp/kr），实例没起时自动回落直连")
    sp = sub.add_parser("run")
    sp.add_argument("--region", choices=list(REGIONS.keys()), default="jp")
    sp.add_argument("command", nargs=argparse.REMAINDER)
    sp = sub.add_parser("set")
    sp.add_argument("--region", choices=list(REGIONS.keys()), required=True)
    sp.add_argument("--server")
    sp.add_argument("--auto", action="store_true")
    args = p.parse_args()
    if args.action == "set" and not args.auto and not args.server:
        p.error("set 需要 --server <主机名> 或 --auto")
    handler = {
        "update": cmd_update, "list": cmd_list, "connect": cmd_connect,
        "disconnect": cmd_disconnect, "status": cmd_status,
        "watch": cmd_watch, "run": cmd_run, "set": cmd_set, "tui": cmd_tui,
        "reputation": cmd_reputation, "ping": cmd_ping, "doctor": cmd_doctor,
    }[args.action]
    rc = handler(args)
    if rc:
        sys.exit(rc)


if __name__ == "__main__":
    main()
