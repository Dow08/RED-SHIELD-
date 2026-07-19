"""Tests de la coquille : l'API démarre et un module défaillant reste isolé."""
from fastapi.testclient import TestClient

from app.main import create_app
from app.modules.base import Module


def test_health_ok():
    app = create_app()
    with TestClient(app) as client:
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["service"] == "RED"


class _FailingModule(Module):
    name = "canary"
    version = "0.1.0"
    description = "module qui plante volontairement (test d'isolation)"

    def start(self) -> None:
        raise RuntimeError("boom")


def test_failing_module_is_isolated():
    """Un module qui plante au démarrage passe ERROR sans faire tomber l'appli."""
    app = create_app()
    app.state.registry.register(_FailingModule(app.state.bus))
    with TestClient(app) as client:
        # startup a lancé start_all() -> canary a planté mais l'API répond toujours
        assert client.get("/health").status_code == 200
        modules = client.get("/modules").json()
        canary = next(m for m in modules if m["name"] == "canary")
        assert canary["status"] == "error"
        assert "boom" in canary["message"]
