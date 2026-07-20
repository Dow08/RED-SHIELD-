"""Tests du module Windows Defender (parsing du JSON PowerShell, sans exécuter PowerShell)."""
import json
import sys

from fastapi.testclient import TestClient

from app.core.bus import EventBus
from app.main import create_app
from app.modules import defender as dmod
from app.modules.defender import DefenderModule

_STATUS = json.dumps({
    "AntivirusEnabled": True, "RealTimeProtectionEnabled": True, "AntispywareEnabled": True,
    "IsTamperProtected": True, "AntivirusSignatureVersion": "1.415.0.0", "AntivirusSignatureAge": 1,
    "QuickScanEndTime": "2026-07-20T06:00:00", "FullScanEndTime": "",
})
_THREATS = json.dumps([
    {"InitialDetectionTime": "2026-07-19T22:10:00", "ThreatName": "Trojan:Win32/Test",
     "SeverityID": 5, "CleaningActionID": 2, "Resources": ["file:C:\\tmp\\x.exe"]},
])


def test_defender_parses_status_and_threats(monkeypatch):
    def fake_ps(cmd, timeout=25):
        return (True, _THREATS if "ThreatDetection" in cmd else _STATUS)
    monkeypatch.setattr(dmod, "_ps", fake_ps)
    st = DefenderModule(EventBus())._collect()
    assert st.available is True
    assert st.antivirus_enabled is True and st.realtime_protection is True and st.tamper_protection is True
    assert st.signature_version == "1.415.0.0" and st.signature_age_days == 1.0
    assert len(st.threats) == 1
    t = st.threats[0]
    assert t.threat == "Trojan:Win32/Test" and t.severity == "critique" and t.action == "quarantaine"


def test_defender_degraded_when_ps_fails(monkeypatch):
    monkeypatch.setattr(dmod, "_ps", lambda cmd, timeout=25: (False, ""))
    st = DefenderModule(EventBus())._collect()
    assert st.available is False and st.reason


def test_defender_endpoint_live():
    app = create_app()
    with TestClient(app) as client:
        assert client.get("/defender").status_code == 200
        mods = {m["name"] for m in client.get("/modules").json()}
        assert "defender" in mods
