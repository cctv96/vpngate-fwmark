"""Unit tests for vpngate-fwmark (stdlib only, no network in tests)."""
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


def sample_csv():
    cfg = base64.b64encode(b"client\ndev tun\nproto tcp\nremote 1.2.3.4 1562\n").decode()
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

    def test_build_ovpn_per_region(self):
        grouped = vg.candidates_by_region(vg.parse_servers(sample_csv()))
        for region, dev in (("jp", "tun-jp"), ("kr", "tun-kr")):
            ovpn = vg.build_ovpn(grouped[region][0], region)
            self.assertIn(f"dev {dev}", ovpn)
            self.assertIn("route-nopull", ovpn)
            self.assertIn("auth-user-pass", ovpn)

    def test_marks_do_not_collide(self):
        self.assertNotEqual(vg.REGIONS["jp"]["mark"], vg.REGIONS["kr"]["mark"])
        self.assertNotEqual(vg.REGIONS["jp"]["table"], vg.REGIONS["kr"]["table"])
        self.assertEqual(vg.fwmark_rule(vg.REGIONS["jp"]), "0x1a01/0xffff")
        self.assertEqual(vg.fwmark_rule(vg.REGIONS["kr"]), "0x1a02/0xffff")

    def test_choose_by_ip(self):
        grouped = vg.candidates_by_region(vg.parse_servers(sample_csv()))
        srv, mode = vg.choose_for_region("jp", grouped, {"jp": "1.1.1.1"})
        self.assertEqual(mode, "manual")
        self.assertEqual(srv["host"], "vpn111")


class TestReputation(unittest.TestCase):
    def test_risk_low_when_fraud_low(self):
        orig = vg.fetch_json

        def fake_fetch(url, headers=None, timeout=15):
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
        # 模拟升级前的旧缓存：欺诈分 None、无 cache_version，不加 --force
        # 也必须重查，不能把旧的 None 原样返回。
        import json as _json, os as _os, time as _time
        orig = vg.fetch_json
        vg.fetch_json = lambda url, headers=None, timeout=15: (
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


if __name__ == "__main__":
    unittest.main()
