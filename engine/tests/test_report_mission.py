"""Tests de l'assemblage du rapport de mission (factuel, gabarits, tri par sévérité)."""
from fastapi.testclient import TestClient

from app.main import create_app
from app.report.mission import build_model


def _raw():
    return {
        "exposure": {"score": 62, "band": "elevee", "counts": {"safe": 40, "watch": 5, "suspect": 2, "crit": 1}},
        "exposed_ports": 16,
        "grc": {
            "controls": [
                {"id": "antimalware-edr", "title": "Protection anti-malware / EDR", "why": "…", "finding": "Antivirus inactif.",
                 "remediation": "Activer Defender.", "refs": {"ISO": "A.8.7"}, "status": "non_conforme"},
                {"id": "gestion-correctifs", "title": "Correctifs", "why": "…", "finding": "3 MAJ en attente.",
                 "remediation": "Installer les MAJ.", "refs": {"CIS": "7.3"}, "status": "a_traiter"},
                {"id": "mfa", "title": "MFA", "why": "…", "status": "conforme"},  # ignoré
            ],
            "scores": [
                {"framework": "ISO", "label": "ISO/IEC 27001:2022", "score": 70, "counts": {"a_traiter": 1, "non_conforme": 1}},
                {"framework": "GLOBAL", "label": "Global", "score": 70, "counts": {}},  # exclu
            ],
        },
        "procvuln": {"apps": [
            {"process": "openssh.exe", "product": "OpenSSH", "version": "8.2",
             "cves": [{"cve": "CVE-2021-41617", "cvss": 7.0, "summary": "priv esc"}]},
        ]},
    }


def test_build_model_is_factual_and_sorted():
    m = build_model(_raw())
    assert m.score == 62 and m.band == "elevee" and m.band_label == "Exposition élevée"
    assert m.kpis["exposes"] == 16
    # 3 findings : antimalware(crit) + openssh(haut) + correctifs(moyen), triés crit d'abord
    assert [f.severity for f in m.findings] == ["crit", "haut", "moyen"]
    assert m.kpis["findings"] == 3 and m.kpis["critiques"] == 1
    # le contrôle conforme (mfa) n'est PAS un finding
    assert all("MFA" not in f.title for f in m.findings)
    # conformité sans GLOBAL
    assert [c.framework for c in m.conformity] == ["ISO"] and m.conformity[0].ecarts == 2
    # verdict mentionne le critique, sans rien inventer
    assert "critique" in m.verdict and "62/100" in m.verdict


def test_build_model_empty_is_clean():
    m = build_model({"exposure": {"score": 10, "band": "faible", "counts": {}}})
    assert m.findings == [] and m.kpis["findings"] == 0
    assert "saine" in m.verdict


def test_default_meta_reference_and_date():
    m = build_model({})
    assert m.meta.marque == "DP Cyber Consulting"
    assert m.meta.reference.startswith("DPC-") and "/" in m.meta.date


def test_endpoint_returns_model():
    app = create_app()
    with TestClient(app) as client:
        r = client.post("/report/mission", json={"meta": {"client": "ACME SAS"}})
        assert r.status_code == 200
        d = r.json()
        assert d["meta"]["client"] == "ACME SAS"
        assert "findings" in d and "verdict" in d and "conformity" in d
