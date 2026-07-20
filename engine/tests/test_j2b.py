"""Tests J2 : beaconing, firewall (dry-run), découverte LAN."""
from collections import deque

from app.core.bus import EventBus
from app.modules.analytics import AnalyticsModule
from app.modules.firewall import FirewallModule
from app.modules.lan import LanModule

SAMPLE_ARP = """
Interface : 192.168.1.24 --- 0x5
  Adresse Internet      Adresse physique      Type
  192.168.1.1           00-24-d4-11-22-33     dynamique
  192.168.1.20          fc-fb-fb-aa-bb-cc     dynamique
  192.168.1.255         ff-ff-ff-ff-ff-ff     statique
"""


def test_beaconing_detects_regular_interval():
    mod = AnalyticsModule(EventBus(), shield=None, scoring=None)
    mod._appearances[("evil.exe", "45.83.220.11")] = deque([100.0, 160.0, 220.0, 280.0, 340.0])  # 60s pile
    mod._appearances[("chrome.exe", "8.8.8.8")] = deque([10.0, 12.0, 90.0, 300.0])  # irrégulier
    beacons = mod.beaconing()
    remotes = {b.remote for b in beacons}
    assert "45.83.220.11" in remotes
    assert "8.8.8.8" not in remotes
    b = next(b for b in beacons if b.remote == "45.83.220.11")
    assert round(b.period_s) == 60


def test_firewall_dry_run_and_validation():
    fw = FirewallModule(EventBus())
    fw.start()
    dry = fw.block("45.83.220.11", dry_run=True)
    assert dry["ok"] and dry.get("dry_run") and "netsh" in dry["command"] and "45.83.220.11" in dry["command"]
    bad = fw.block("not-an-ip", dry_run=True)
    assert not bad["ok"]


def test_firewall_block_port_dry_run():
    fw = FirewallModule(EventBus())
    fw.start()
    dry = fw.block_port(445, "tcp", dry_run=True)
    assert dry["ok"] and dry.get("dry_run")
    assert "dir=in" in dry["command"] and "action=block" in dry["command"]
    assert "protocol=TCP" in dry["command"] and "localport=445" in dry["command"]
    assert not fw.block_port(70000, "tcp", dry_run=True)["ok"]   # port hors bornes
    assert not fw.block_port(80, "icmp", dry_run=True)["ok"]      # protocole invalide


def test_lan_parse_arp():
    mod = LanModule(EventBus())
    devs = mod.parse(SAMPLE_ARP)
    ips = [d.ip for d in devs]
    assert "192.168.1.1" in ips and "192.168.1.20" in ips
    assert "192.168.1.255" not in ips  # broadcast ignoré
    by = {d.ip: d for d in devs}
    assert by["192.168.1.1"].vendor == "Free (Freebox)"
    assert by["192.168.1.20"].vendor == "Apple"
