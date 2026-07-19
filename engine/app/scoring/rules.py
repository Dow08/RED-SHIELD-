"""Règles de scoring d'une connexion → risque (0-100) + raisons lisibles.

Règles simples et tunables (pas de « détection magique »). Chaque règle ajoute
des points et une raison en langage clair.
"""
from __future__ import annotations

import ipaddress

# Ports légitimes courants (ne pénalise pas).
COMMON_PORTS = {80, 443, 53, 22, 123, 143, 110, 465, 587, 993, 995, 853, 3478, 5228, 3479}
# Ports fréquemment associés à du C2 / des backdoors.
C2_PORTS = {4444, 1337, 31337, 5555, 6667, 12345, 1234, 9001}
# Hôtes de script pouvant servir d'exécution malveillante.
SCRIPT_HOSTS = {"wscript.exe", "cscript.exe", "mshta.exe", "powershell.exe", "pwsh.exe"}
TEMP_MARKERS = ("\\temp\\", "\\tmp\\", "\\appdata\\local\\temp", "/tmp/")


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def score_connection(conn, is_new: bool = False) -> tuple[int, list[str]]:
    """Retourne (risque 0-100, raisons)."""
    risk = 0
    reasons: list[str] = []

    public = not _is_private(conn.remote_addr)

    # DNS réellement absent (résolu mais sans PTR) sur une IP publique.
    if public and conn.dns_resolved and conn.remote_dns is None:
        risk += 25
        reasons.append("aucune résolution DNS (IP publique brute)")

    if conn.port in C2_PORTS:
        risk += 45
        reasons.append(f"port {conn.port} fréquemment associé au C2")
    elif public and conn.port not in COMMON_PORTS:
        risk += 18
        reasons.append(f"port non standard ({conn.port})")

    if conn.process in ("?", ""):
        risk += 20
        reasons.append("process non identifié")

    exe = (conn.exe or "").lower()
    if any(mark in exe for mark in TEMP_MARKERS):
        risk += 30
        reasons.append("exécutable lancé depuis un dossier temporaire")

    if conn.process.lower() in SCRIPT_HOSTS and public:
        risk += 22
        reasons.append("hôte de script avec connexion sortante")

    if is_new and public:
        risk += 10
        reasons.append("connexion inhabituelle (hors baseline)")

    return min(risk, 100), reasons


def severity_of(risk: int) -> str:
    if risk >= 80:
        return "crit"
    if risk >= 60:
        return "suspect"
    if risk >= 30:
        return "watch"
    return "safe"
