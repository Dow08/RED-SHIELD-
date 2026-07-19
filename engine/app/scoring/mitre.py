"""Corrélation MITRE ATT&CK : tags automatiques sur motifs connus.

Base (Jalon 1) : règles simples. Le mapping complet arrive au Jalon 3.
"""
from __future__ import annotations

from app.scoring.rules import COMMON_PORTS, C2_PORTS, _is_private

_TECH = {
    "TA0011": ("Command and Control", "https://attack.mitre.org/tactics/TA0011/"),
    "T1571": ("Non-Standard Port", "https://attack.mitre.org/techniques/T1571/"),
    "T1059.005": ("Command and Scripting Interpreter: Visual Basic", "https://attack.mitre.org/techniques/T1059/005/"),
    "T1059.001": ("Command and Scripting Interpreter: PowerShell", "https://attack.mitre.org/techniques/T1059/001/"),
    "T1218.005": ("System Binary Proxy Execution: Mshta", "https://attack.mitre.org/techniques/T1218/005/"),
}


def _tag(tid: str) -> dict:
    name, url = _TECH[tid]
    return {"id": tid, "name": name, "url": url}


def mitre_tags(conn) -> list[dict]:
    tags: list[dict] = []
    process = conn.process.lower()
    public = not _is_private(conn.remote_addr)

    if conn.port in C2_PORTS:
        tags.append(_tag("TA0011"))
        tags.append(_tag("T1571"))
    elif public and conn.port not in COMMON_PORTS and conn.dns_resolved and conn.remote_dns is None:
        tags.append(_tag("T1571"))

    if process in ("wscript.exe", "cscript.exe"):
        tags.append(_tag("T1059.005"))
    elif process in ("powershell.exe", "pwsh.exe"):
        tags.append(_tag("T1059.001"))
    elif process == "mshta.exe":
        tags.append(_tag("T1218.005"))

    return tags
