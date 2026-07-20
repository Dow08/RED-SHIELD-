"""Tests du module Vulnérabilités des processus (croisement produit/version ↔ CVE locale)."""
from fastapi.testclient import TestClient

from app.core.bus import EventBus
from app.main import create_app
from app.modules.procvuln import ProcVulnModule


def _mod():
    m = ProcVulnModule(EventBus())
    m.start()  # charge la base CVE locale
    return m


def test_match_known_product():
    m = _mod()
    cves = m._match("OpenSSH", "8.2p1")            # produit + version présents dans la base
    assert any(c.cve.startswith("CVE-") for c in cves)


def test_match_unknown_product_is_empty():
    m = _mod()
    assert m._match("Google Chrome", "120.0.0") == []   # aucune invention : rien dans la base
    assert m._match("", "1.0") == [] and m._match("OpenSSH", "") == []


def test_run_with_mocked_env(monkeypatch):
    m = _mod()
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
