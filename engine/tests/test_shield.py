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


class _Addr:
    def __init__(self, ip, port):
        self.ip, self.port = ip, port


class _Conn:
    def __init__(self, laddr, raddr, status, ctype):
        self.laddr, self.raddr, self.status = laddr, raddr, status
        self.type, self.pid = ctype, None


def _fake_raw():
    import socket as _s
    import psutil as _p
    return [
        _Conn(_Addr("0.0.0.0", 8080), None, _p.CONN_LISTEN, _s.SOCK_STREAM),           # écoute exposée
        _Conn(_Addr("127.0.0.1", 5000), None, _p.CONN_LISTEN, _s.SOCK_STREAM),         # écoute locale
        _Conn(_Addr("192.168.1.10", 8080), _Addr("203.0.113.5", 55000), "ESTABLISHED", _s.SOCK_STREAM),   # ENTRANT (vers 8080 en écoute)
        _Conn(_Addr("192.168.1.10", 49500), _Addr("140.82.121.4", 443), "ESTABLISHED", _s.SOCK_STREAM),   # sortant chiffré
        _Conn(_Addr("192.168.1.10", 49600), _Addr("93.184.216.34", 80), "ESTABLISHED", _s.SOCK_STREAM),   # sortant clair
        _Conn(_Addr("127.0.0.1", 49700), _Addr("127.0.0.1", 9000), "ESTABLISHED", _s.SOCK_STREAM),        # loopback (ignoré)
        _Conn(_Addr("0.0.0.0", 5353), None, "NONE", _s.SOCK_DGRAM),                                        # socket UDP (sans destinataire)
    ]


def test_direction_and_metrics_deterministic(monkeypatch):
    """psutil simulé : classification entrant/sortant + métriques exactes."""
    import psutil
    monkeypatch.setattr(psutil, "net_connections", lambda kind="inet": _fake_raw())
    mod = ShieldModule(EventBus())

    conns = mod.get_connections(resolve_dns=False)
    assert len(conns) == 3  # 3 établies non-loopback (le loopback est exclu)
    by_remote = {c.remote_addr: c for c in conns}
    assert by_remote["203.0.113.5"].direction == "entrant"
    assert by_remote["140.82.121.4"].direction == "sortant"
    assert by_remote["93.184.216.34"].direction == "sortant"

    listeners = mod.get_listeners()
    assert {(l.port, l.exposed) for l in listeners} == {(8080, True), (5000, False)}

    m = mod.metrics(geo=lambda ip: {"country": "US"})
    assert m.total == 3 and m.inbound == 1 and m.outbound == 2
    assert m.encrypted == 1 and m.clear == 2       # 443 chiffré ; 80 + 55000 clairs
    assert m.listeners == 2 and m.listeners_exposed == 1
    assert m.endpoints == 3
    assert m.udp_sockets == 1                        # le socket UDP est compté même sans destinataire
    us = next(c for c in m.countries if c.key == "US")
    assert us.count == 3
    assert sum(p.count for p in us.processes) == 3   # les process sont ventilés par pays
    top = {pc.port: pc for pc in m.top_ports}
    assert top[443].encrypted is True and top[443].service == "https"
    assert top[80].encrypted is False


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
