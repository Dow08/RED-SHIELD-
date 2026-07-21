"""Tests du module GRC (auto-évaluation factuelle, override manuel, scores, export)."""
import app.modules.grc as grc
from app.core.bus import EventBus
from app.modules.grc import GrcModule


def test_auto_conforme_and_a_traiter():
    sig = {"exposed_ports": 0, "clear_flows": 3, "audit_logging": True, "monitoring": True}
    post = grc.evaluate(sig, {})
    by = {c["id"]: c for c in post["controls"]}
    assert by["surface-exposition"]["status"] == "conforme"
    assert by["surface-exposition"]["source"] == "auto"
    assert by["chiffrement-flux"]["status"] == "a_traiter"
    assert "3" in by["chiffrement-flux"]["finding"]
    assert by["journalisation"]["status"] == "conforme"


def test_av_edr_states():
    assert grc._auto("av_edr", {"av_enabled": True, "rt_protection": True})[0] == "conforme"
    assert grc._auto("av_edr", {"av_enabled": True, "rt_protection": False})[0] == "a_traiter"
    assert grc._auto("av_edr", {"av_enabled": False, "rt_protection": False})[0] == "non_conforme"
    # signal indisponible → jamais de conformité inventée
    assert grc._auto("av_edr", {})[0] == "manuel"


def test_manual_control_unassessed_by_default():
    post = grc.evaluate({}, {})
    by = {c["id"]: c for c in post["controls"]}
    assert by["mfa"]["status"] == "manuel" and by["mfa"]["signal"] is None


def test_override_wins_and_scores(tmp_path, monkeypatch):
    store = tmp_path / "grc_state.json"
    monkeypatch.setattr(grc, "_store_path", lambda: store)
    grc.save_override("mfa", "conforme", "MFA activé sur tous les comptes admin")
    ov = grc.load_overrides()
    assert ov["mfa"]["status"] == "conforme"
    post = grc.evaluate({"exposed_ports": 0}, ov)
    mfa = next(c for c in post["controls"] if c["id"] == "mfa")
    assert mfa["status"] == "conforme" and mfa["note"].startswith("MFA")
    # revert to auto
    grc.save_override("mfa", "auto", "")
    assert "mfa" not in grc.load_overrides()


def test_scores_weighting():
    # conforme=1, a_traiter=0.5 ; na/manuel exclus du dénominateur
    controls = [
        {"status": "conforme", "families": ["CIS"]},
        {"status": "a_traiter", "families": ["CIS"]},
        {"status": "na", "families": ["CIS"]},
        {"status": "manuel", "families": ["CIS"]},
    ]
    scores = grc._scores(controls)
    cis = next(s for s in scores if s["framework"] == "CIS")
    # (1 + 0.5) / 2 évalués = 75
    assert cis["assessed"] == 2 and cis["score"] == 75


def test_export_markdown_contains_frameworks():
    post = grc.evaluate({"exposed_ports": 2, "clear_flows": 0}, {})
    md = grc.export_markdown(post)
    assert "Rapport de conformité" in md and "ISO" in md and "NIST" in md and "CIS" in md


def test_module_posture_and_set(tmp_path, monkeypatch):
    monkeypatch.setattr(grc, "_store_path", lambda: tmp_path / "s.json")
    m = GrcModule(EventBus(), lambda: {"exposed_ports": 0, "clear_flows": 0})
    post = m.posture()
    assert post["scores"] and post["controls"]
    m.set_control("sauvegardes", "non_conforme", "Pas de test de restauration")
    post2 = m.posture()
    bkp = next(c for c in post2["controls"] if c["id"] == "sauvegardes")
    assert bkp["status"] == "non_conforme"


def test_set_control_rejects_bad_input(tmp_path, monkeypatch):
    monkeypatch.setattr(grc, "_store_path", lambda: tmp_path / "s.json")
    m = GrcModule(EventBus(), lambda: {})
    try:
        m.set_control("inconnu", "conforme")
        assert False, "aurait dû lever"
    except ValueError:
        pass
    try:
        m.set_control("mfa", "n_importe_quoi")
        assert False, "aurait dû lever"
    except ValueError:
        pass
