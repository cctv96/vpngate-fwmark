"""Unit tests for vpngate-fwmark v3 (Mihomo edition, stdlib only, no network)."""
import base64
import importlib.util
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SPEC = importlib.util.spec_from_file_location(
    "vg", os.path.join(ROOT, "vpngate-fwmark.py"))
vg = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(vg)


def sample_ovpn():
    return (b"client\ndev tun\nproto tcp\nremote vpn111.opengw.net 1562\n"
            b"cipher AES-128-CBC\nauth SHA1\n"
            b"<ca>\n-----BEGIN CERTIFICATE-----\nCADATA\n-----END CERTIFICATE-----\n</ca>\n"
            b"<cert>\n-----BEGIN CERTIFICATE-----\nCERTDATA\n-----END CERTIFICATE-----\n</cert>\n"
            b"<key>\n-----BEGIN PRIVATE KEY-----\nKEYDATA\n-----END PRIVATE KEY-----\n</key>\n")


def sample_csv():
    cfg = base64.b64encode(sample_ovpn()).decode()
    header = ("#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,"
              "NumVpnSessions,Uptime,TotalUsers,TotalTraffic,LogType,Operator,"
              "Message,OpenVPN_ConfigData_Base64")
    rows = [
        f"public-vpn-9,3.3.3.3,100,1,999999999,Japan,JP,10,100,1,1,2weeks,op,,{cfg}",
        f"vpn111,1.1.1.1,100,20,100000000,Japan,JP,10,100,1,1,2weeks,op,,{cfg}",
        f"vpn222,2.2.2.2,100,10,500000000,Korea,KR,10,100,1,1,2weeks,op,,{cfg}",
        f"vpn333,4.4.4.4,100,10,500000000,United States,US,10,100,1,1,2weeks,op,,{cfg}",
    ]
    return "*vpn_servers\n" + header + "\n" + "\n".join(rows)


class TestFilter(unittest.TestCase):
    def test_only_vpn_jp_kr(self):
        servers = vg.parse_servers(sample_csv())
        hosts = [s["host"] for s in servers]
        self.assertEqual(hosts, ["vpn222", "vpn111"])

    def test_grouped_by_region(self):
        grouped = vg.candidates_by_region(vg.parse_servers(sample_csv()))
        self.assertEqual([s["host"] for s in grouped["jp"]], ["vpn111"])
        self.assertEqual([s["host"] for s in grouped["kr"]], ["vpn222"])

    def test_choose_by_ip(self):
        grouped = vg.candidates_by_region(vg.parse_servers(sample_csv()))
        srv, mode = vg.choose_for_region("jp", grouped, {"jp": "1.1.1.1"})
        self.assertEqual(mode, "manual")
        self.assertEqual(srv["host"], "vpn111")

    def test_regions_have_distinct_ports(self):
        self.assertNotEqual(vg.REGIONS["jp"]["mixed_port"], vg.REGIONS["kr"]["mixed_port"])
        self.assertNotEqual(vg.REGIONS["jp"]["controller"], vg.REGIONS["kr"]["controller"])
        self.assertEqual(vg.REGIONS["jp"]["mixed_port"], 7890)
        self.assertEqual(vg.REGIONS["kr"]["mixed_port"], 7891)


class TestMihomoYaml(unittest.TestCase):
    def test_parse_ovpn(self):
        grouped = vg.candidates_by_region(vg.parse_servers(sample_csv()))
        d = vg.parse_ovpn(grouped["jp"][0])
        self.assertEqual(d["port"], 1562)
        self.assertEqual(d["proto"], "tcp")
        self.assertEqual(d["cipher"], "AES-128-CBC")
        self.assertEqual(d["auth"], "SHA1")
        self.assertIn("CADATA", d["ca"])
        self.assertIn("CERTDATA", d["cert"])
        self.assertIn("KEYDATA", d["key"])

    def test_build_yaml(self):
        grouped = vg.candidates_by_region(vg.parse_servers(sample_csv()))
        yaml_text = vg.build_mihomo_yaml("jp", grouped["jp"])
        self.assertIn("mixed-port: 7890", yaml_text)
        self.assertIn("external-controller: 127.0.0.1:9090", yaml_text)
        self.assertIn("type: openvpn", yaml_text)
        self.assertIn("cipher: \"AES-128-CBC\"", yaml_text)
        self.assertIn("auth: \"SHA1\"", yaml_text)
        self.assertIn("MATCH,JP", yaml_text)
        self.assertIn("CADATA", yaml_text)
        # 旧版残留必须没有：不再有 fwmark、路由表、tun 设备、专用用户
        self.assertNotIn("fwmark", yaml_text)
        self.assertNotIn("tun-jp", yaml_text)
        self.assertNotIn("vpnapp", yaml_text)

    def test_manual_first_in_yaml(self):
        grouped = vg.candidates_by_region(vg.parse_servers(sample_csv()))
        # 造第二个日本节点，手动指定第二个时它应排在最前（默认出口）
        second = dict(grouped["jp"][0])
        second["fqdn"] = "vpn999.opengw.net"
        second["host"] = "vpn999.opengw.net"
        vg.MANUAL_FILE = "/tmp/vg-test-manual.json"
        import json as _json
        with open(vg.MANUAL_FILE, "w") as f:
            _json.dump({"jp": "vpn999.opengw.net"}, f)
        try:
            yaml_text = vg.build_mihomo_yaml("jp", grouped["jp"] + [second])
            self.assertLess(yaml_text.index("vpn999"), yaml_text.index("vpn111"))
        finally:
            vg.MANUAL_FILE = os.path.join(vg.STATE_DIR, "manual.json")


class TestReputation(unittest.TestCase):
    def test_risk_low_when_fraud_low(self):
        orig = vg.fetch_json

        def fake_fetch(url, headers=None, timeout=15, **kw):
            if "proxycheck" in url:
                return {"status": "ok",
                        "101.111.161.173": {"proxy": "no", "type": "Business", "risk": 12}}
            if "ip-api" in url:
                return {"status": "success", "country": "Japan", "isp": "Test",
                        "org": "Test", "as": "AS123", "proxy": False,
                        "hosting": True, "mobile": False}
            return {"status": "success", "result": "0.12"}

        vg.fetch_json = fake_fetch
        try:
            vg.STATE_DIR = "/tmp/vg-test-state"
            rep = vg.check_ip_reputation("101.111.161.173", force=True)
            self.assertEqual(rep["risk"], "低")
            self.assertTrue(rep["hosting"])
            self.assertEqual(rep["fraud_score"], 0.12)
            self.assertEqual(rep["fraud_source"], "proxycheck")
        finally:
            vg.fetch_json = orig

    def test_old_cache_without_version_is_rechecked(self):
        import json as _json, os as _os, time as _time
        orig = vg.fetch_json
        vg.fetch_json = lambda url, headers=None, timeout=15, **kw: (
            {"status": "ok", "101.111.161.173": {"proxy": "no", "type": "Business", "risk": 12}}
            if "proxycheck" in url else
            {"status": "success", "country": "Japan", "isp": "Test",
             "org": "Test", "as": "AS123", "proxy": False,
             "hosting": True, "mobile": False})
        try:
            vg.STATE_DIR = "/tmp/vg-test-state-oldcache"
            _os.makedirs(vg.STATE_DIR, exist_ok=True)
            with open(_os.path.join(vg.STATE_DIR, "reputation.json"), "w") as f:
                _json.dump({"101.111.161.173": {
                    "ip": "101.111.161.173", "fraud_score": None,
                    "sources": ["ip-api.com"], "checked_at": int(_time.time())}}, f)
            rep = vg.check_ip_reputation("101.111.161.173")
            self.assertEqual(rep["fraud_score"], 0.12)
            self.assertFalse(rep.get("cached"))
        finally:
            vg.fetch_json = orig


class TestViaMihomo(unittest.TestCase):
    def test_via_region_passes_mihomo_proxy(self):
        # --via jp 应该把该地区 Mihomo 混合端口当代理传给 fetch_json，
        # 而不是旧版的 fwmark 标记。
        seen = {}
        orig = vg.fetch_json

        def fake(url, headers=None, timeout=15, **kw):
            seen["via_region"] = kw.get("via_region")
            if "proxycheck" in url:
                return {"status": "ok", "1.2.3.4": {"proxy": "no", "type": "Business", "risk": 10}}
            return {"status": "success", "country": "Japan", "isp": "Test",
                    "org": "Test", "as": "AS123", "proxy": False,
                    "hosting": True, "mobile": False}

        vg.fetch_json = fake
        try:
            vg.STATE_DIR = "/tmp/vg-test-via"
            rep = vg.check_ip_reputation("1.2.3.4", force=True, via_region="jp")
            self.assertEqual(seen["via_region"], "jp")
            self.assertEqual(rep["fraud_score"], 0.10)
        finally:
            vg.fetch_json = orig


class TestMihomoApi(unittest.TestCase):
    def test_parse_api_proxies(self):
        data = {"proxies": {
            "JP": {"name": "JP", "type": "Selector", "now": "JP-vpn111.opengw.net",
                  "all": ["JP-vpn111.opengw.net", "JP-vpn222.opengw.net"]},
            "JP-vpn111.opengw.net": {"name": "JP-vpn111.opengw.net", "type": "OpenVPN",
                                     "history": [{"time": "2026-11-04T00:00:00Z", "delay": 123}]},
            "JP-vpn222.opengw.net": {"name": "JP-vpn222.opengw.net", "type": "OpenVPN",
                                     "history": [{"time": "2026-11-04T00:00:00Z", "delay": 0}]},
        }}
        nodes, current = vg.parse_api_proxies(data, "JP")
        self.assertEqual(current, "JP-vpn111.opengw.net")
        self.assertEqual([n["name"] for n in nodes],
                         ["JP-vpn111.opengw.net", "JP-vpn222.opengw.net"])
        self.assertEqual(nodes[0]["history_delay"], 123)
        # delay 0 = 测不到，不是 0 ms
        self.assertIsNone(nodes[1]["history_delay"])

    def test_parse_api_proxies_missing_group(self):
        nodes, current = vg.parse_api_proxies({"proxies": {}}, "JP")
        self.assertEqual(nodes, [])
        self.assertIsNone(current)


class TestLocalLatency(unittest.TestCase):
    def test_ping_output_parsed(self):
        orig_run = vg.subprocess.run

        class FakeOut:
            stdout = "64 bytes from 1.2.3.4: icmp_seq=1 ttl=50 time=23.4 ms\n"

        vg.subprocess.run = lambda *a, **kw: FakeOut()
        try:
            ms, method = vg.measure_local_latency("1.2.3.4")
            self.assertIsNotNone(ms)
            self.assertEqual(method, "ping")
        finally:
            vg.subprocess.run = orig_run

    def test_tcp_refused_still_counts_as_rtt(self):
        orig_run = vg.subprocess.run
        vg.subprocess.run = lambda *a, **kw: (_ for _ in ()).throw(FileNotFoundError())
        import socket as _socket
        orig_conn = _socket.create_connection

        def fake_conn(addr, timeout=None):
            raise ConnectionRefusedError()

        _socket.create_connection = fake_conn
        try:
            ms, method = vg.measure_local_latency("1.2.3.4")
            self.assertIsNotNone(ms)
            self.assertEqual(method, "tcp")
        finally:
            vg.subprocess.run = orig_run
            _socket.create_connection = orig_conn


if __name__ == "__main__":
    unittest.main()
