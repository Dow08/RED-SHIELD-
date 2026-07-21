"""Test de fumée des endpoints : garantit qu'aucune route ne renvoie 5xx (crash serveur).

Filet de sécurité pour les refactors de main.py : un 503 « module indisponible » est
acceptable, mais un 500 (NameError, mauvais attribut, exception non gérée) est un échec.
Mode air-gapped actif par défaut → aucun appel réseau externe pendant le test.
"""
from fastapi.testclient import TestClient

from app.main import create_app

# Endpoints GET sûrs et rapides (renvoient des données réelles ou l'état « non connecté »).
GET_ENDPOINTS = [
    "/health", "/config", "/modules",
    "/shield/connections", "/shield/top-talkers", "/shield/listeners",
    "/shield/metrics", "/shield/geo",
    "/bandwidth", "/throughput/status", "/throughput/processes",
    "/exposure", "/diagnostic/logs", "/history",
    "/trace", "/scan", "/procvuln", "/hids", "/defender",
    "/imap/status", "/connectors", "/siem/status",
    "/analytics/timeline", "/analytics/beaconing",
    "/health/report", "/updater/list", "/grc", "/lan/devices",
]


def test_get_endpoints_never_5xx():
    app = create_app()
    with TestClient(app) as client:
        for path in GET_ENDPOINTS:
            r = client.get(path)
            assert r.status_code < 500, f"{path} → {r.status_code} : {r.text[:200]}"


def test_grc_shape():
    app = create_app()
    with TestClient(app) as client:
        d = client.get("/grc").json()
        assert "scores" in d and "controls" in d and len(d["controls"]) == 16


def test_airgapped_toggle_roundtrip():
    app = create_app()
    with TestClient(app) as client:
        assert client.post("/config/airgapped", json={"airgapped": False}).json()["airgapped"] is False
        assert client.post("/config/airgapped", json={"airgapped": True}).json()["airgapped"] is True


def test_export_endpoints_are_markdown():
    app = create_app()
    with TestClient(app) as client:
        for path in ("/report/markdown", "/grc/export", "/diagnostic/logs/export"):
            r = client.get(path)
            assert r.status_code == 200 and len(r.text) > 0


def test_action_endpoints_dry_run_no_side_effect():
    """Les POST d'action en dry-run ne modifient rien et ne renvoient jamais 5xx."""
    app = create_app()
    with TestClient(app) as client:
        # firewall : dry-run → aperçu de la commande, aucune règle posée
        r = client.post("/firewall/block", json={"ip": "203.0.113.9", "dry_run": True})
        assert r.status_code < 500
        # nettoyage santé : dry-run → calcul du récupérable, aucune suppression
        r = client.post("/health/clean", json={"category": "temp", "dry_run": True})
        assert r.status_code < 500
        if r.status_code == 200:
            assert r.json().get("dry_run") is True and r.json().get("deleted_files", 0) == 0


def test_grc_control_rejects_bad_id():
    app = create_app()
    with TestClient(app) as client:
        assert client.post("/grc/control", json={"id": "inconnu", "status": "conforme"}).status_code == 400


def test_connector_rejects_unknown_name():
    app = create_app()
    with TestClient(app) as client:
        assert client.post("/connectors/arbitraire", json={"key": "x"}).status_code == 400
