"""Tests du connecteur SIEM/EDR (gate air-gapped, config, normalisation multi-format)."""
import json

from app.core.bus import EventBus
from app.modules.siem import SiemModule
from app.runtime import runtime


class _Conn:
    def __init__(self, val=None):
        self._val = val
    def get(self, name):
        return self._val


def test_status_not_configured():
    m = SiemModule(EventBus(), _Conn(None))
    st = m.status()
    assert st["configured"] is False


def test_status_configured():
    cfg = json.dumps({"type": "wazuh", "url": "https://wazuh:55000/alerts", "token": "x"})
    m = SiemModule(EventBus(), _Conn(cfg))
    st = m.status()
    assert st["configured"] is True and st["type"] == "wazuh" and st["url"].startswith("https://")


def test_gate_airgapped(monkeypatch):
    cfg = json.dumps({"type": "generic", "url": "https://siem/x", "token": "x"})
    m = SiemModule(EventBus(), _Conn(cfg))
    monkeypatch.setattr(runtime, "airgapped", True)
    res = m.alerts()
    assert res["available"] is False and "air-gapped" in res["reason"]


def test_gate_not_configured(monkeypatch):
    m = SiemModule(EventBus(), _Conn(None))
    monkeypatch.setattr(runtime, "airgapped", False)
    res = m.alerts()
    assert res["available"] is False and "non configuré" in res["reason"]


def test_build_search_url():
    b = SiemModule.build_search_url
    assert b({"url": "https://wazuh:9200", "type": "wazuh"}) == ("https://wazuh:9200/wazuh-alerts-*/_search", True)
    assert b({"url": "https://es:9200/", "type": "elastic"}) == ("https://es:9200/_search", True)
    assert b({"url": "https://x/logs.json", "type": "generic"}) == ("https://x/logs.json", False)
    assert b({"url": "https://x/idx/_search", "type": "wazuh"}) == ("https://x/idx/_search", True)


def test_normalize_formats():
    # Elastic
    el = {"hits": {"hits": [{"_source": {"@timestamp": "t1", "message": "evt", "level": "3"}}]}}
    n = SiemModule._normalize(el, "elastic")
    assert n and n[0]["time"] == "t1" and n[0]["rule"] == "evt"
    # Wazuh
    wz = {"data": {"affected_items": [{"timestamp": "t2", "rule": {"level": 7, "description": "brute force"}, "agent": {"name": "srv1"}}]}}
    n = SiemModule._normalize(wz, "wazuh")
    assert n[0]["level"] == "7" and n[0]["rule"] == "brute force" and n[0]["agent"] == "srv1"
    # générique (liste directe)
    n = SiemModule._normalize([{"time": "t3", "description": "x"}], "generic")
    assert n[0]["time"] == "t3"
