"""Tests Diagnostic, Persistence et rapport Markdown."""
from fastapi.testclient import TestClient

from app.core.bus import EventBus
from app.main import create_app
from app.modules.diagnostic import DiagnosticModule
from app.modules.persistence import PersistenceModule
from app.modules.scoring import ScoringModule, ExposureSummary
from app.report.markdown import build_markdown
from tests.test_scoring import mkconn


def test_diagnostic_captures_bus_logs():
    bus = EventBus()
    diag = DiagnosticModule(bus)
    diag.start()
    bus.publish("log", {"level": "error", "module": "canary", "message": "boom"})
    logs = diag.get_logs(level="error")
    assert any(e.message == "boom" and e.module == "canary" for e in logs)
    assert "boom" in diag.export_text()


def test_persistence_snapshot_history(tmp_path):
    db = f"sqlite:///{tmp_path.as_posix()}/red_test.db"
    persist = PersistenceModule(EventBus(), db_url=db)
    persist.start()
    summary = ExposureSummary(score=42, band="elevee", total=3,
                              counts={"safe": 2, "watch": 1, "suspect": 0, "crit": 0})
    persist.record_snapshot(summary)
    persist.add_audit("test", "ok")
    hist = persist.history()
    assert len(hist) == 1
    assert hist[0].exposure_score == 42


def test_markdown_report_contains_findings():
    scoring = ScoringModule(EventBus())
    scoring.start()
    conns = [
        mkconn(),
        mkconn(process="wscript.exe", exe=r"C:\...\Temp\x.js",
               remote_addr="193.106.94.7", remote_dns=None, dns_resolved=True, port=4444),
    ]
    scored = scoring.score_connections(conns)
    summary = scoring.exposure_summary(scored)
    md = build_markdown(summary, scored)
    assert "# Rapport RED" in md
    assert "Score d'exposition" in md
    assert "wscript.exe" in md
    assert "TA0011" in md


def test_config_exposes_real_retention_settings():
    """La carte « Rétention » lit /config : les vrais réglages doivent y être."""
    app = create_app()
    with TestClient(app) as client:
        cfg = client.get("/config").json()
        assert set(cfg) >= {"airgapped", "purge_on_exit", "storage_budget_go", "sample_interval"}
        assert isinstance(cfg["purge_on_exit"], bool)
        assert cfg["storage_budget_go"] > 0
        assert cfg["sample_interval"] > 0
