"""Tests du scan nmap : parsing XML + croisement CVE local."""
from app.core.bus import EventBus
from app.modules.scan import ScanModule

SAMPLE_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <hostnames><hostname name="lab.local"/></hostnames>
    <ports>
      <port protocol="tcp" portid="21"><state state="open"/><service name="ftp" product="vsftpd" version="2.3.4"/></port>
      <port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="8.2p1"/></port>
      <port protocol="tcp" portid="443"><state state="open"/><service name="https" product="nginx" version="1.24.0"/></port>
      <port protocol="tcp" portid="139"><state state="closed"/><service name="netbios-ssn"/></port>
    </ports>
  </host>
</nmaprun>"""


def test_scan_parse_and_cve():
    mod = ScanModule(EventBus())
    mod.start()  # charge la base CVE locale
    hosts = mod.parse(SAMPLE_XML)
    assert len(hosts) == 1
    h = hosts[0]
    assert h.ip == "10.0.0.5" and h.hostname == "lab.local"
    open_ports = {p.port: p for p in h.ports}
    assert set(open_ports) == {21, 22, 443}  # le port fermé est exclu
    # vsftpd 2.3.4 -> CVE backdoor
    assert any(c.cve == "CVE-2011-2523" for c in open_ports[21].cves)
    # OpenSSH 8.2p1 -> CVE (préfixe 8.2)
    assert any(c.cve == "CVE-2023-38408" for c in open_ports[22].cves)
    # nginx -> aucune CVE en base locale
    assert open_ports[443].cves == []
    # OSI : 443 = présentation (TLS), 22 = application
    assert open_ports[443].osi_layer == 6
    assert open_ports[22].osi_layer == 7
    # conformité + suggestions présentes sur ssh/ftp
    assert any(c.framework == "ANSSI" for c in open_ports[22].compliance)
    assert any("hydra" in s for s in open_ports[21].suggestions)


def test_scan_valid_target():
    assert ScanModule.valid_target("192.168.1.0/24")
    assert ScanModule.valid_target("scanme.nmap.org")
    assert not ScanModule.valid_target("1.1.1.1; whoami")
