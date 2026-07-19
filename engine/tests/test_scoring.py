"""Tests du scoring de risque et de la corrélation MITRE."""
from fastapi.testclient import TestClient

from app.core.bus import EventBus
from app.main import create_app
from app.modules.scoring import ScoringModule
from app.modules.shield import Connection
from app.scoring.mitre import mitre_tags
from app.scoring.rules import score_connection, severity_of


def mkconn(**kw) -> Connection:
    base = dict(
        pid=1, process="chrome.exe", exe="", lineage="", local_addr="",
        remote_addr="8.8.8.8", remote_dns="dns.google", dns_resolved=True,
        port=443, protocol="tcp", status="ESTABLISHED",
    )
    base.update(kw)
    return Connection(**base)


def test_safe_connection_low_risk():
    risk, _ = score_connection(mkconn())
    assert severity_of(risk) == "safe"


def test_c2_pattern_is_critical():
    conn = mkconn(
        process="wscript.exe",
        exe=r"C:\Users\x\AppData\Local\Temp\upd.js",
        remote_addr="193.106.94.7", remote_dns=None, dns_resolved=True, port=4444,
    )
    risk, reasons = score_connection(conn)
    assert risk >= 80
    assert severity_of(risk) == "crit"
    assert reasons


def test_mitre_tags_for_c2():
    conn = mkconn(process="wscript.exe", remote_addr="193.106.94.7",
                  remote_dns=None, dns_resolved=True, port=4444)
    ids = [t["id"] for t in mitre_tags(conn)]
    assert "TA0011" in ids and "T1571" in ids and "T1059.005" in ids


def test_unresolved_dns_not_penalized():
    # DNS pas encore résolu (async) ne doit PAS déclencher "aucune résolution DNS".
    conn = mkconn(remote_addr="45.83.220.11", remote_dns=None, dns_resolved=False, port=443)
    risk, reasons = score_connection(conn)
    assert not any("aucune résolution" in r for r in reasons)


def test_exposure_summary():
    mod = ScoringModule(EventBus())
    mod.start()
    conns = [
        mkconn(),
        mkconn(process="wscript.exe", exe=r"C:\...\Temp\x.js",
               remote_addr="193.106.94.7", remote_dns=None, dns_resolved=True, port=4444),
    ]
    summary = mod.exposure_summary(mod.score_connections(conns))
    assert summary.total == 2
    assert summary.counts["crit"] >= 1
    assert summary.score > 0


def test_exposure_endpoint():
    app = create_app()
    with TestClient(app) as client:
        resp = client.get("/exposure")
        assert resp.status_code == 200
        body = resp.json()
        assert "score" in body and "band" in body and "counts" in body
