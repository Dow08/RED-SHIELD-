"""Tests connecteurs / intel / osint : gating air-gapped + statuts."""
from app.core.bus import EventBus
from app.modules.connectors import ConnectorsModule
from app.modules.intel import IntelModule
from app.modules.osint import OsintModule
from app.runtime import runtime


def test_intel_gated_by_airgapped():
    runtime.airgapped = True
    mod = IntelModule(EventBus(), ConnectorsModule(EventBus()))
    mod.start()
    res = mod.lookup_ip("8.8.8.8")
    assert res["available"] is False  # aucun appel externe sous air-gapped


def test_osint_gated_by_airgapped():
    runtime.airgapped = True
    mod = OsintModule(EventBus())
    mod.start()
    res = mod.subdomains("example.com")
    assert res["available"] is False


def test_connectors_status_shape():
    mod = ConnectorsModule(EventBus())
    mod.start()
    status = mod.status()
    names = [s["name"] for s in status]
    assert "virustotal" in names and "llm" in names
    assert all("connected" in s for s in status)


def test_connectors_reject_unknown_name():
    """Liste blanche : un nom hors ALLOWED est refusé (pas de pollution du trousseau)."""
    import pytest
    mod = ConnectorsModule(EventBus())
    mod.start()
    with pytest.raises(ValueError):
        mod.set("../evil", "x")
    with pytest.raises(ValueError):
        mod.delete("arbitraire")
    assert mod.get("inconnu") is None
    # les connecteurs à config JSON restent autorisés
    assert "siem" in __import__("app.modules.connectors", fromlist=["ALLOWED"]).ALLOWED
