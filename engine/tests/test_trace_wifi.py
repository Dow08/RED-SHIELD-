"""Tests du traceroute (parsing + géo) et de l'audit WiFi (parsing netsh)."""
from app.core.bus import EventBus
from app.modules.trace import TraceModule
from app.modules.wifi import WifiModule

SAMPLE_TRACERT = """
Détermination de l'itinéraire vers one.one.one.one [1.1.1.1]

  1    <1 ms    <1 ms    <1 ms  192.168.1.1
  2     *        *        *     Délai d'attente de la demande dépassé.
  3    12 ms    11 ms    12 ms  1.1.1.1

Itinéraire déterminé.
"""

SAMPLE_NETSH = """
Interface name : Wi-Fi
There are 2 networks currently visible.

SSID 1 : Freebox-8A2C
    Authentication          : WPA3-Personal
    Encryption              : CCMP
    BSSID 1                 : aa:bb:cc:dd:ee:ff
         Signal             : 82%
         Channel            : 36
SSID 2 : FreeWifi_open
    Authentication          : Open
    Encryption              : None
    BSSID 1                 : 11:22:33:44:55:66
         Signal             : 40%
         Channel            : 1
"""


def test_trace_parse_extracts_hops():
    mod = TraceModule(EventBus())
    hops = mod.parse(SAMPLE_TRACERT)
    ips = [h.ip for h in hops]
    assert ips == ["192.168.1.1", "1.1.1.1"]  # le saut en timeout est ignoré
    assert hops[0].private is True
    assert hops[1].private is False


def test_trace_valid_target():
    assert TraceModule.valid_target("1.1.1.1")
    assert TraceModule.valid_target("example.com")
    assert not TraceModule.valid_target("1.1.1.1; rm -rf /")
    assert not TraceModule.valid_target("a b")
    assert not TraceModule.valid_target("-h")   # pas de cible commençant par « - »


def test_wifi_parse_classifies_security():
    mod = WifiModule(EventBus())
    nets = mod.parse_networks(SAMPLE_NETSH)
    by = {n.ssid: n for n in nets}
    assert by["Freebox-8A2C"].risk == "safe"
    assert by["FreeWifi_open"].risk == "crit"
    assert by["Freebox-8A2C"].signal == 82
