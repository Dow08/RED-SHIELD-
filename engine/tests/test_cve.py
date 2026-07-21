"""Tests du module CVE en ligne (parseur NVD + gate air-gapped, sans réseau)."""
from app.modules import cve
from app.runtime import runtime

_NVD_SAMPLE = {
    "vulnerabilities": [
        {"cve": {
            "id": "CVE-2021-41773",
            "descriptions": [{"lang": "fr", "value": "ignorer"}, {"lang": "en", "value": "Path traversal in Apache 2.4.49"}],
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.5}, "baseSeverity": "HIGH"}]},
        }},
        {"cve": {
            "id": "CVE-2011-2523",
            "descriptions": [{"lang": "en", "value": "vsftpd backdoor"}],
            "metrics": {"cvssMetricV2": [{"cvssData": {"baseScore": 10.0}}]},
        }},
    ]
}


def test_parse_nvd():
    cves = cve.parse_nvd(_NVD_SAMPLE)
    assert len(cves) == 2
    # triés par CVSS décroissant
    assert cves[0]["cve"] == "CVE-2011-2523" and cves[0]["cvss"] == 10.0
    apache = next(c for c in cves if c["cve"] == "CVE-2021-41773")
    assert apache["cvss"] == 7.5 and apache["severity"] == "high"
    assert apache["summary"].startswith("Path traversal")   # description EN choisie
    assert apache["url"].endswith("CVE-2021-41773")


def test_lookup_gated_airgapped(monkeypatch):
    monkeypatch.setattr(runtime, "airgapped", True)
    res = cve.lookup("OpenSSH", "8.2p1")
    assert res["available"] is False and "air-gapped" in res["reason"] and res["cves"] == []


def test_severity_from_score():
    assert cve._severity_from_score(9.9) == "critical"
    assert cve._severity_from_score(7.0) == "high"
    assert cve._severity_from_score(4.0) == "medium"
    assert cve._severity_from_score(1.0) == "low"
    assert cve._severity_from_score(0) == ""
