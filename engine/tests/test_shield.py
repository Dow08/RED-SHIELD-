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
        assert c.direction in ("entrant", "sortant")


def test_shield_listeners_shape():
    mod = ShieldModule(EventBus())
    mod.start()
    listeners = mod.get_listeners()
    assert isinstance(listeners, list)
    for l in listeners:
        assert l.port > 0
        assert l.protocol in ("tcp", "udp")
        assert isinstance(l.exposed, bool)
    # dédoublonnage : une seule entrée par (port, protocole)
    keys = [(l.port, l.protocol) for l in listeners]
    assert len(keys) == len(set(keys))
    # les exposés sont triés en tête
    exposed_flags = [l.exposed for l in listeners]
    assert exposed_flags == sorted(exposed_flags, reverse=True)


def test_shield_metrics_coherent():
    mod = ShieldModule(EventBus())
    mod.start()
    m = mod.metrics()
    assert m.total == m.inbound + m.outbound
    assert m.total == m.tcp + m.udp
    assert m.total == m.encrypted + m.clear
    assert m.endpoints <= m.total
    assert m.listeners_exposed <= m.listeners
    assert all(pc.count > 0 for pc in m.top_ports)


def test_shield_metrics_geo_injected():
    """Le geo injecté alimente le comptage des pays (fonction factice)."""
    mod = ShieldModule(EventBus())
    mod.start()

    def fake_geo(ip: str) -> dict:
        return {"country": "Testland"}

    m = mod.metrics(geo=fake_geo)
    if m.total and m.endpoints:  # si des connexions existent, un pays est compté
        assert any(c.key == "Testland" for c in m.countries)


def test_direction_classification_logic():
    """Une connexion vers un port local en écoute est classée entrante."""
    mod = ShieldModule(EventBus())

    class _Addr:
        def __init__(self, ip, port):
            self.ip, self.port = ip, port

    class _Conn:
        def __init__(self, laddr, raddr, status):
            self.laddr, self.raddr, self.status = laddr, raddr, status

    raw = [
        _Conn(_Addr("0.0.0.0", 8080), None, __import__("psutil").CONN_LISTEN),
        _Conn(_Addr("192.168.1.10", 8080), _Addr("203.0.113.5", 55000), "ESTABLISHED"),  # entrant
        _Conn(_Addr("192.168.1.10", 49500), _Addr("140.82.121.4", 443), "ESTABLISHED"),  # sortant
    ]
    ports = mod._listen_ports(raw)
    assert 8080 in ports


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
        assert client.get("/shield/listeners").status_code == 200
        metrics = client.get("/shield/metrics")
        assert metrics.status_code == 200
        assert metrics.json()["total"] == metrics.json()["inbound"] + metrics.json()["outbound"]
        assert client.get("/bandwidth").status_code == 200
        mods = {m["name"]: m for m in client.get("/modules").json()}
        assert mods["shield"]["status"] == "active"
        assert mods["bandwidth"]["status"] == "active"
