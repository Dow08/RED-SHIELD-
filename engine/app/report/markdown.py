"""Rapport Markdown structuré (vu → problème → correctif), lisible humain ET IA."""
from __future__ import annotations

from datetime import datetime, timezone


def build_markdown(summary, scored) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines: list[str] = [
        "# Rapport RED — exposition réseau",
        "",
        f"_Généré le {now}_",
        "",
        "## Synthèse",
        f"- **Score d'exposition** : {summary.score}/100 ({summary.band})",
        f"- Connexions analysées : {summary.total}",
        (
            f"- Répartition : {summary.counts.get('safe', 0)} saines · "
            f"{summary.counts.get('watch', 0)} à surveiller · "
            f"{summary.counts.get('suspect', 0)} suspectes · "
            f"{summary.counts.get('crit', 0)} critiques"
        ),
        "",
    ]

    risky = sorted(
        (s for s in scored if s.severity in ("suspect", "crit")),
        key=lambda s: -s.risk,
    )
    if risky:
        lines += ["## Connexions à traiter en priorité", ""]
        for s in risky:
            lines.append(
                f"### {s.process} (PID {s.pid}) → {s.remote_addr}:{s.port} "
                f"— risque {s.risk}/100 ({s.severity})"
            )
            if s.lineage:
                lines.append(f"- **Arbre de processus** : {s.lineage}")
            if s.exe:
                lines.append(f"- **Exécutable** : `{s.exe}`")
            if s.reasons:
                lines.append("- **Ce qui a été vu** : " + " ; ".join(s.reasons))
            if s.mitre:
                lines.append(
                    "- **MITRE ATT&CK** : "
                    + ", ".join(f"[{t['id']} — {t['name']}]({t['url']})" for t in s.mitre)
                )
            lines.append(
                "- **Remédiation** : investiguer le process, vérifier sa légitimité et sa "
                "persistance ; couper la connexion si elle est confirmée non autorisée."
            )
            lines.append("")
    else:
        lines += [
            "## Aucune connexion suspecte",
            "",
            "Aucune action critique requise au moment du rapport.",
            "",
        ]

    lines += [
        "---",
        "*Rapport lisible par un humain et par une IA. Données réelles, aucune valeur inventée.*",
    ]
    return "\n".join(lines)
