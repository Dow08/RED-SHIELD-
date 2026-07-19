"""Tests des modules Bouclier et Bande passante (données réelles psutil)."""
from fastapi.testclient import TestClient

from app.core.bus import EventBus
from app.main import create_app
from app.modules.bandwidth import BandwidthModule
from app.modules.shield import ShieldModule


def test_shield_returns_real_connections():
    mod = ShieldModule(EventBus())
    mod.start()
    conns = mod.get_connections(resolve_dns=False)
    assert isinstance(conns, list)
    for c in conns:  # structure attendue sur chaque connexion réelle
        assert c.remote_addr
        assert c.port > 0
        assert c.protocol in ("tcp", "udp")


def test_bandwidth_rates_shape():
    mod = BandwidthModule(EventBus())
    mod.start()
    rates = mod.get_rates()
    assert rates.down_bps >= 0.0 and rates.up_bps >= 0.0
    assert rates.down_mo_s >= 0.0 and rates.up_mo_s >= 0.0


def test_endpoints_live():
    app = create_app()
    with TestClient(app) as client:
        assert client.get("/shield/connections").status_code == 200
        assert client.get("/shield/top-talkers").status_code == 200
        assert client.get("/bandwidth").status_code == 200
        mods = {m["name"]: m for m in client.get("/modules").json()}
        assert mods["shield"]["status"] == "active"
        assert mods["bandwidth"]["status"] == "active"
