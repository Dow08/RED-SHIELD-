"""Tests du module Vulnérabilités des processus (croisement produit/version ↔ NVD en ligne, mocké)."""
from fastapi.testclient import TestClient

from app.core.bus import EventBus
from app.main import create_app
from app.modules import cve as cve_online
from app.modules.procvuln import ProcVulnModule


def _fake_lookup(product: str, version: str = "") -> dict:
    if "openssh" in (product or "").lower():
        return {"available": True, "cves": [{"cve": "CVE-2023-38408", "cvss": 9.8, "severity": "critical",
                "summary": "x", "url": "https://nvd.nist.gov/vuln/detail/CVE-2023-38408"}]}
    return {"available": True, "cves": []}


def test_match_known_product(monkeypatch):
    monkeypatch.setattr(cve_online, "lookup", _fake_lookup)
    m = ProcVulnModule(EventBus())
    m.start()
    assert any(c.cve.startswith("CVE-") for c in m._match("OpenSSH", "8.2p1"))


def test_match_unknown_or_empty(monkeypatch):
    monkeypatch.setattr(cve_online, "lookup", _fake_lookup)
    m = ProcVulnModule(EventBus())
    m.start()
    assert m._match("Google Chrome", "150.0") == []   # inconnu du mock
    assert m._match("", "1.0") == []                   # pas de produit → aucun appel


def test_run_with_mocked_env(monkeypatch):
    monkeypatch.setattr(cve_online, "lookup", _fake_lookup)
    m = ProcVulnModule(EventBus())
    m.start()
    monkeypatch.setattr(ProcVulnModule, "_connected_exes",
                        staticmethod(lambda: {"C:/app/sshd.exe": {"process": "sshd.exe", "pid": 42}}))
    monkeypatch.setattr(ProcVulnModule, "_versions",
                        staticmethod(lambda exes: {"C:/app/sshd.exe": {"product": "OpenSSH", "version": "8.2p1"}}))
    m._run()
    res = m.get()
    assert res.scanned == 1
    app = res.apps[0]
    assert app.process == "sshd.exe" and app.product == "OpenSSH"
    assert len(app.cves) >= 1


def test_procvuln_endpoint_live():
    app = create_app()
    with TestClient(app) as client:
        assert client.get("/procvuln").status_code == 200
        assert "procvuln" in {mm["name"] for mm in client.get("/modules").json()}
