"""Tests du scan nmap : parsing XML + croisement CVE (NVD en ligne, mocké)."""
from app.core.bus import EventBus
from app.modules import cve as cve_online
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
      <port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Apache httpd" version="2.4.7"/></port>
      <port protocol="tcp" portid="139"><state state="closed"/><service name="netbios-ssn"/></port>
    </ports>
  </host>
</nmaprun>"""

_DB = {
    "openssh": ("CVE-2023-38408", 9.8, "critical"),
    "vsftpd": ("CVE-2011-2523", 9.8, "critical"),
    "apache": ("CVE-2021-41773", 7.5, "high"),
}


def _fake_lookup(product: str, version: str = "") -> dict:
    """Simule NVD : renvoie une CVE pour les produits connus, [] sinon."""
    p = (product or "").lower()
    for k, (cid, cvss, sev) in _DB.items():
        if k in p:
            return {"available": True, "cves": [{"cve": cid, "cvss": cvss, "severity": sev,
                    "summary": "exemple", "url": f"https://nvd.nist.gov/vuln/detail/{cid}"}]}
    return {"available": True, "cves": []}


def test_scan_parse_and_cve(monkeypatch):
    monkeypatch.setattr(cve_online, "lookup", _fake_lookup)
    mod = ScanModule(EventBus())
    mod.start()
    hosts = mod.parse(SAMPLE_XML)
    assert len(hosts) == 1
    h = hosts[0]
    assert h.ip == "10.0.0.5" and h.hostname == "lab.local"
    open_ports = {p.port: p for p in h.ports}
    assert set(open_ports) == {21, 22, 443, 80}  # le port fermé (139) est exclu
    # CVE via NVD (mocké)
    assert any(c.cve == "CVE-2011-2523" for c in open_ports[21].cves)   # vsftpd
    assert any(c.cve == "CVE-2023-38408" for c in open_ports[22].cves)  # OpenSSH
    assert open_ports[443].cves == []                                    # nginx inconnu du mock → aucune
    assert any(c.cve == "CVE-2021-41773" for c in open_ports[80].cves)   # Apache
    # OSI : 443 = présentation (TLS), 22 = application
    assert open_ports[443].osi_layer == 6
    assert open_ports[22].osi_layer == 7
    # conformité + suggestions présentes sur ssh/ftp
    assert any(c.framework == "ANSSI" for c in open_ports[22].compliance)
    assert any("hydra" in s for s in open_ports[21].suggestions)


def test_match_cves_gated_airgapped(monkeypatch):
    # Sous air-gapped, aucune requête NVD → aucune CVE (jamais inventé).
    from app.runtime import runtime
    monkeypatch.setattr(runtime, "airgapped", True)
    mod = ScanModule(EventBus())
    mod.start()
    assert mod.match_cves("OpenSSH", "8.2p1") == []


def test_scan_valid_target():
    assert ScanModule.valid_target("192.168.1.0/24")
    assert ScanModule.valid_target("scanme.nmap.org")
    assert not ScanModule.valid_target("1.1.1.1; whoami")
