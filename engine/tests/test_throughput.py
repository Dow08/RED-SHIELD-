"""Tests du module Débit/process (pktmon).

La capture live exige admin+Windows ; ces tests couvrent ce qui est certifiable
sans privilège : le parseur (isolé) et la dégradation gracieuse.
"""
from fastapi.testclient import TestClient

from app.core.bus import EventBus
from app.main import create_app
from app.modules.throughput import ThroughputModule, parse_realtime_line


def test_parse_compact_realtime():
    r = parse_realtime_line("14:04:12.729500 1 Rx Ethernet IPv4 TCP 20.190.160.14:443 -> 192.168.1.5:49764 Len 1466")
    assert r["direction"] == "rx"
    assert r["proto"] == "tcp"
    assert r["length"] == 1466
    assert ("20.190.160.14", 443) in r["endpoints"]
    assert ("192.168.1.5", 49764) in r["endpoints"]


def test_parse_dotted_port_and_tx():
    r = parse_realtime_line("14:04:12 2 Tx IPv4 UDP 192.168.1.5.55000 8.8.8.8.53 Length 74")
    assert r["direction"] == "tx" and r["proto"] == "udp" and r["length"] == 74
    assert ("8.8.8.8", 53) in r["endpoints"]


def test_parse_verbose_etl2txt():
    line = ("PktGroupId 3, Direction Tx, IPv4 SourceAddress 192.168.1.5, "
            "TCP SourcePort 49764, DestinationAddress 140.82.112.25, DestinationPort 443, "
            "Total Length = 66")
    r = parse_realtime_line(line)
    assert r is not None
    assert r["direction"] == "tx"
    assert ("192.168.1.5", 49764) in r["endpoints"]
    assert ("140.82.112.25", 443) in r["endpoints"]
    assert r["length"] == 66


def test_parse_rejects_noise():
    assert parse_realtime_line("random log line without packet") is None
    assert parse_realtime_line("") is None
    assert parse_realtime_line("TCP but no endpoints here") is None


def test_module_degrades_gracefully_without_admin():
    """Sans admin (cas de la CI/tests), le module ne plante pas et reste lisible."""
    mod = ThroughputModule(EventBus())
    mod.start()  # ne doit jamais lever
    st = mod.status()
    assert st.available is False
    assert st.reason  # message explicatif présent
    assert mod.processes() == []
    mod.stop()


def test_throughput_endpoints_live():
    app = create_app()
    with TestClient(app) as client:
        assert client.get("/throughput/status").status_code == 200
        assert client.get("/throughput/processes").status_code == 200
        mods = {m["name"]: m for m in client.get("/modules").json()}
        assert "throughput" in mods  # module enregistré même si dégradé
