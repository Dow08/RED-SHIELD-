"""Module GRC — assistant CISO : suivi de conformité réel, factuel et traçable.

Catalogue de contrôles dérivés de trois référentiels reconnus :
 - ISO/IEC 27001:2022 (Annexe A),
 - NIST Cybersecurity Framework 2.0,
 - CIS Controls v8.

Chaque contrôle est :
 - **AUTO-ÉVALUÉ** quand RED dispose d'un signal réel de la machine (ports
   exposés, flux en clair, antivirus/EDR, correctifs en attente, connexions
   suspectes, journalisation, surveillance) → le statut est déduit de l'état
   factuel, jamais inventé ;
 - ou **MANUEL** (contrôle organisationnel : MFA, revue des accès, sauvegardes,
   sensibilisation, réponse à incident…) : l'utilisateur fixe le statut et joint
   une preuve/justification, persistée localement (jamais partagée).

Statuts : ``conforme`` / ``a_traiter`` (partiel) / ``non_conforme`` /
``na`` (non applicable) / ``manuel`` (pas encore évalué).

Score par référentiel = moyenne pondérée sur les contrôles **évalués** et
applicables (conforme = 1, à traiter = 0.5, non conforme = 0 ; na et manuel
non évalués sont exclus). Export Markdown pour un rapport d'audit.

Aucun appel réseau : la conformité se calcule sur des données locales déjà
collectées par les autres modules → fonctionne aussi en mode air-gapped.
"""
from __future__ import annotations

import json
from pathlib import Path

from app.core.bus import EventBus
from app.modules.base import Module, ModuleStatus

FRAMEWORKS: dict[str, str] = {
    "ISO": "ISO/IEC 27001:2022",
    "NIST": "NIST CSF 2.0",
    "CIS": "CIS Controls v8",
}

STATUSES = ("conforme", "a_traiter", "non_conforme", "na", "manuel")
_WEIGHT = {"conforme": 1.0, "a_traiter": 0.5, "non_conforme": 0.0}

# ── Catalogue de contrôles ────────────────────────────────────────────────
# signal = clé du dict de signaux réels (None → contrôle organisationnel manuel).
CONTROLS: list[dict] = [
    {
        "id": "surface-exposition",
        "domain": "Réseau",
        "title": "Réduction de la surface d'exposition",
        "why": "Chaque service en écoute sur une adresse réseau (0.0.0.0/::) est une porte "
               "joignable depuis le LAN ou Internet. En fermer ou en justifier le maximum "
               "réduit d'autant les points d'entrée exploitables.",
        "refs": {"ISO": "A.8.20 / A.8.22", "NIST": "PR.AA-05", "CIS": "4.4 / 4.8"},
        "signal": "exposed_ports",
        "remediation": "Fermer ou justifier chaque service exposé (onglet Carte réseau → écoutes), "
                       "et filtrer au pare-feu ce qui n'a pas à être joignable.",
    },
    {
        "id": "chiffrement-flux",
        "domain": "Données",
        "title": "Chiffrement des communications",
        "why": "Un flux en clair peut être intercepté ou modifié en transit. Le chiffrement "
               "(TLS) protège la confidentialité et l'intégrité des échanges.",
        "refs": {"ISO": "A.8.24 / A.5.14", "NIST": "PR.DS-02", "CIS": "3.10"},
        "signal": "clear_flows",
        "remediation": "Forcer TLS/HTTPS, remplacer les protocoles en clair (HTTP, FTP, Telnet) "
                       "et vérifier les flux signalés en clair (onglet Graphe).",
    },
    {
        "id": "antimalware-edr",
        "domain": "Postes",
        "title": "Protection anti-malware / EDR",
        "why": "Un antivirus/EDR avec protection en temps réel bloque et détecte les codes "
               "malveillants avant exécution. Sans lui, une compromission passe inaperçue.",
        "refs": {"ISO": "A.8.7", "NIST": "PR.PS-05 / DE.CM-01", "CIS": "10.1 / 10.7"},
        "signal": "av_edr",
        "remediation": "Activer Microsoft Defender (ou un EDR) et sa protection temps réel "
                       "(onglet Santé / Defender).",
    },
    {
        "id": "gestion-correctifs",
        "domain": "Postes",
        "title": "Gestion des correctifs (patch management)",
        "why": "Les vulnérabilités connues sont massivement exploitées tant qu'elles ne sont "
               "pas corrigées. Appliquer les mises à jour ferme ces failles.",
        "refs": {"ISO": "A.8.8", "NIST": "ID.RA-01 / PR.PS-02", "CIS": "7.3 / 7.4"},
        "signal": "pending_updates",
        "remediation": "Installer les mises à jour en attente (onglet Santé → mises à jour), "
                       "puis planifier une cadence régulière.",
    },
    {
        "id": "detection-anomalies",
        "domain": "Détection",
        "title": "Détection des anomalies & réponse",
        "why": "Repérer tôt une connexion suspecte (beaconing, destination à risque) limite "
               "l'impact d'une intrusion. RED note et classe chaque connexion.",
        "refs": {"ISO": "A.8.16", "NIST": "DE.AE-02 / DE.CM-01", "CIS": "13.1 / 13.6"},
        "signal": "suspect_conns",
        "remediation": "Investiguer les connexions notées « suspect » / « critique » "
                       "(onglet Remédiation) et couper/autoriser après vérification.",
    },
    {
        "id": "journalisation",
        "domain": "Détection",
        "title": "Journalisation & traçabilité",
        "why": "Sans journaux, impossible d'investiguer un incident ni de prouver ce qui s'est "
               "passé. RED conserve un journal d'audit horodaté des événements et actions.",
        "refs": {"ISO": "A.8.15", "NIST": "PR.PS-04 / DE.AE-03", "CIS": "8.2 / 8.5"},
        "signal": "audit_logging",
        "remediation": "Conserver et protéger les journaux (onglet Diagnostic) ; centraliser "
                       "vers un SIEM pour la corrélation.",
    },
    {
        "id": "surveillance-continue",
        "domain": "Détection",
        "title": "Surveillance réseau continue",
        "why": "Une observation en continu des connexions permet de détecter les écarts par "
               "rapport à la normale. RED SHIELD assure cette surveillance en temps réel.",
        "refs": {"ISO": "A.8.16", "NIST": "DE.CM-01", "CIS": "13.11"},
        "signal": "monitoring",
        "remediation": "Maintenir RED SHIELD actif ; définir une baseline et des seuils "
                       "d'alerte (onglet Analytics).",
    },
    {
        "id": "inventaire-actifs",
        "domain": "Gouvernance",
        "title": "Inventaire des actifs & logiciels",
        "why": "On ne protège que ce que l'on connaît. Un inventaire à jour des machines et "
               "logiciels conditionne la gestion des vulnérabilités et des accès.",
        "refs": {"ISO": "A.5.9", "NIST": "ID.AM-01 / ID.AM-02", "CIS": "1.1 / 2.1"},
        "signal": None,
        "remediation": "Tenir un inventaire des équipements (onglet LAN) et des logiciels "
                       "installés, et le revoir périodiquement.",
    },
    {
        "id": "mfa",
        "domain": "Accès",
        "title": "Authentification multifacteur (MFA)",
        "why": "Le MFA neutralise l'essentiel des attaques par mot de passe volé ou deviné. "
               "C'est l'un des contrôles au meilleur rapport efficacité/coût.",
        "refs": {"ISO": "A.8.5", "NIST": "PR.AA-02 / PR.AA-03", "CIS": "6.3 / 6.5"},
        "signal": None,
        "remediation": "Activer le MFA sur les comptes sensibles (messagerie, admin, VPN, cloud).",
    },
    {
        "id": "gestion-acces",
        "domain": "Accès",
        "title": "Gestion des accès & moindre privilège",
        "why": "Limiter les droits au strict nécessaire réduit ce qu'un compte compromis peut "
               "atteindre. Les comptes à privilèges doivent être rares et suivis.",
        "refs": {"ISO": "A.5.15 / A.8.2", "NIST": "PR.AA-05", "CIS": "5.4 / 6.8"},
        "signal": None,
        "remediation": "Revue périodique des droits, suppression des comptes inutiles, "
                       "séparation des comptes admin.",
    },
    {
        "id": "sauvegardes",
        "domain": "Résilience",
        "title": "Sauvegardes & récupération",
        "why": "Des sauvegardes testées et isolées sont le dernier rempart contre un "
               "rançongiciel ou une perte de données. Non testées, elles sont illusoires.",
        "refs": {"ISO": "A.8.13", "NIST": "PR.DS-11 / RC.RP-01", "CIS": "11.1 / 11.3"},
        "signal": None,
        "remediation": "Sauvegardes régulières, hors-ligne/immuables, et test de restauration.",
    },
    {
        "id": "reponse-incident",
        "domain": "Résilience",
        "title": "Plan de réponse à incident",
        "why": "Sous stress, on suit un plan préparé ou on improvise mal. Un processus défini "
               "(détecter, contenir, éradiquer, rétablir) réduit l'impact d'un incident.",
        "refs": {"ISO": "A.5.24 / A.5.26", "NIST": "RS.MA-01 / RC.RP-01", "CIS": "17.1 / 17.4"},
        "signal": None,
        "remediation": "Rédiger un plan de réponse, désigner les rôles, tester par un exercice.",
    },
    {
        "id": "sensibilisation",
        "domain": "Gouvernance",
        "title": "Sensibilisation & formation",
        "why": "L'humain est la première cible (phishing, ingénierie sociale). Des utilisateurs "
               "formés détectent et signalent les tentatives.",
        "refs": {"ISO": "A.6.3", "NIST": "PR.AT-01 / PR.AT-02", "CIS": "14.1 / 14.2"},
        "signal": None,
        "remediation": "Sensibilisation régulière, simulations de phishing, procédure de signalement.",
    },
    {
        "id": "protection-donnees",
        "domain": "Données",
        "title": "Protection des données personnelles (RGPD)",
        "why": "Au-delà du risque, la protection des données personnelles est une obligation "
               "légale (RGPD) : registre, minimisation, durée de conservation, sécurité.",
        "refs": {"ISO": "A.5.34 / A.8.11", "NIST": "GV.OC-03", "CIS": "3.1 / 3.4"},
        "signal": None,
        "remediation": "Cartographier les données personnelles, tenir un registre, chiffrer/"
                       "pseudonymiser, définir les durées de conservation.",
    },
    {
        "id": "config-securisee",
        "domain": "Postes",
        "title": "Configuration sécurisée des systèmes",
        "why": "Les réglages par défaut sont rarement sûrs (services superflus, comptes par "
               "défaut). Durcir la configuration réduit la surface d'attaque locale.",
        "refs": {"ISO": "A.8.9", "NIST": "PR.PS-01", "CIS": "4.1 / 4.6"},
        "signal": None,
        "remediation": "Appliquer un référentiel de durcissement (CIS Benchmarks / ANSSI), "
                       "désactiver services et comptes inutiles.",
    },
    {
        "id": "gestion-fournisseurs",
        "domain": "Gouvernance",
        "title": "Sécurité des fournisseurs & tiers",
        "why": "Une compromission passe souvent par un prestataire ou un service tiers. Évaluer "
               "et encadrer les tiers limite ce risque de chaîne d'approvisionnement.",
        "refs": {"ISO": "A.5.19 / A.5.21", "NIST": "GV.SC-01 / GV.SC-04", "CIS": "15.1"},
        "signal": None,
        "remediation": "Inventorier les prestataires/services, évaluer leur sécurité, "
                       "contractualiser les exigences.",
    },
]

_BY_ID = {c["id"]: c for c in CONTROLS}


# ── Auto-évaluation à partir des signaux réels ────────────────────────────
def _auto(signal: str, s: dict) -> tuple[str, str]:
    """Renvoie (statut, constat factuel) pour un contrôle auto-évaluable.

    Statut ``manuel`` si le signal est indisponible (jamais de conformité inventée).
    """
    if signal == "exposed_ports":
        n = s.get("exposed_ports")
        if n is None:
            return "manuel", "Écoutes réseau indisponibles."
        return ("conforme", "Aucun service exposé au réseau.") if n == 0 else \
               ("a_traiter", f"{n} service(s) en écoute exposé(s) au réseau.")
    if signal == "clear_flows":
        n = s.get("clear_flows")
        if n is None:
            return "manuel", "Métriques de flux indisponibles."
        return ("conforme", "Aucun flux en clair détecté.") if n == 0 else \
               ("a_traiter", f"{n} connexion(s) en clair (non chiffrées).")
    if signal == "av_edr":
        av, rt = s.get("av_enabled"), s.get("rt_protection")
        if av is None and rt is None:
            return "manuel", "État de l'antivirus indisponible."
        if av and rt:
            return "conforme", "Antivirus actif, protection temps réel activée."
        if av and not rt:
            return "a_traiter", "Antivirus actif mais protection temps réel désactivée."
        return "non_conforme", "Antivirus/EDR inactif."
    if signal == "pending_updates":
        n = s.get("pending_updates")
        if n is None:
            return "manuel", "État des mises à jour indisponible."
        return ("conforme", "Système à jour.") if n == 0 else \
               ("a_traiter", f"{n} mise(s) à jour en attente.")
    if signal == "suspect_conns":
        n = s.get("suspect_conns")
        if n is None:
            return "manuel", "Connexions non évaluées."
        return ("conforme", "Aucune connexion suspecte en cours.") if n == 0 else \
               ("a_traiter", f"{n} connexion(s) à surveiller (suspect/critique).")
    if signal == "audit_logging":
        return ("conforme", "Journal d'audit RED actif et horodaté.") if s.get("audit_logging") else \
               ("a_traiter", "Journalisation à activer.")
    if signal == "monitoring":
        return ("conforme", "Surveillance réseau continue assurée par RED SHIELD.") if s.get("monitoring") else \
               ("non_conforme", "Surveillance inactive.")
    return "manuel", ""


def _families(refs: dict) -> list[str]:
    return [f for f in ("ISO", "NIST", "CIS") if refs.get(f)]


def evaluate(signals: dict, overrides: dict) -> dict:
    """Construit la posture complète : contrôles évalués + scores par référentiel."""
    signals = signals or {}
    overrides = overrides or {}
    controls: list[dict] = []
    for c in CONTROLS:
        ov = overrides.get(c["id"]) or {}
        note = str(ov.get("note", ""))
        if ov.get("status") in STATUSES:
            status, finding, source = ov["status"], "", "manuel"
        elif c.get("signal"):
            status, finding = _auto(c["signal"], signals)
            source = "auto"
        else:
            status, finding, source = "manuel", "", "manuel"
        controls.append({
            "id": c["id"], "domain": c["domain"], "title": c["title"], "why": c["why"],
            "refs": c["refs"], "remediation": c["remediation"], "families": _families(c["refs"]),
            "signal": c.get("signal"), "status": status, "finding": finding,
            "note": note, "source": source,
        })
    return {
        "frameworks": FRAMEWORKS,
        "scores": _scores(controls),
        "controls": controls,
        "summary": _summary(controls),
    }


def _scores(controls: list[dict]) -> list[dict]:
    """Score pondéré (%) et décompte par référentiel + global."""
    out: list[dict] = []
    for fam in ("ISO", "NIST", "CIS", "GLOBAL"):
        sel = controls if fam == "GLOBAL" else [c for c in controls if fam in c["families"]]
        counts = {k: 0 for k in STATUSES}
        for c in sel:
            counts[c["status"]] = counts.get(c["status"], 0) + 1
        assessed = counts["conforme"] + counts["a_traiter"] + counts["non_conforme"]
        weighted = counts["conforme"] * 1.0 + counts["a_traiter"] * 0.5
        score = round(100 * weighted / assessed) if assessed else 0
        out.append({
            "framework": fam,
            "label": "Global" if fam == "GLOBAL" else FRAMEWORKS[fam],
            "score": score, "assessed": assessed, "total": len(sel), "counts": counts,
        })
    return out


def _summary(controls: list[dict]) -> dict:
    counts = {k: 0 for k in STATUSES}
    for c in controls:
        counts[c["status"]] = counts.get(c["status"], 0) + 1
    return {"total": len(controls), "counts": counts,
            "a_traiter_ids": [c["id"] for c in controls if c["status"] in ("a_traiter", "non_conforme")]}


# ── Persistance locale des évaluations manuelles ──────────────────────────
def _store_path() -> Path:
    return Path(__file__).resolve().parents[2] / "data" / "grc_state.json"


def load_overrides() -> dict:
    p = _store_path()
    if not p.exists():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_override(control_id: str, status: str, note: str) -> dict:
    ov = load_overrides()
    if status == "auto":          # revenir à l'auto-évaluation
        ov.pop(control_id, None)
    else:
        ov[control_id] = {"status": status, "note": note[:1000]}
    p = _store_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(ov, ensure_ascii=False, indent=2), encoding="utf-8")
    return ov


# ── Export Markdown (rapport d'audit) ─────────────────────────────────────
_STATUS_LABEL = {
    "conforme": "✅ Conforme", "a_traiter": "🟠 À traiter",
    "non_conforme": "🔴 Non conforme", "na": "⚪ Non applicable", "manuel": "◻️ À évaluer",
}


def export_markdown(posture: dict) -> str:
    lines = ["# RED SHIELD — Rapport de conformité (assistant CISO)", ""]
    for sc in posture["scores"]:
        lines.append(f"- **{sc['label']}** : {sc['score']}/100 "
                     f"({sc['counts']['conforme']} conforme, {sc['counts']['a_traiter']} à traiter, "
                     f"{sc['counts']['non_conforme']} non conforme, sur {sc['total']} contrôles)")
    lines += ["", "| Contrôle | Domaine | ISO | NIST | CIS | Statut | Constat |",
              "|---|---|---|---|---|---|---|"]
    for c in posture["controls"]:
        detail = c["finding"] or c["note"] or ""
        lines.append(f"| {c['title']} | {c['domain']} | {c['refs'].get('ISO','—')} | "
                     f"{c['refs'].get('NIST','—')} | {c['refs'].get('CIS','—')} | "
                     f"{_STATUS_LABEL.get(c['status'], c['status'])} | {detail.replace('|', '/')} |")
    lines += ["", "_Référentiels : ISO/IEC 27001:2022, NIST CSF 2.0, CIS Controls v8. "
              "Contrôles auto-évalués depuis l'état réel de la machine ; contrôles "
              "organisationnels à évaluer manuellement._"]
    return "\n".join(lines)


class GrcModule(Module):
    name = "grc"
    version = "0.1.0"
    description = "Assistant CISO — conformité ISO 27001 / NIST CSF / CIS"
    consumes = ["shield", "scoring", "defender", "updater"]

    def __init__(self, bus: EventBus, signal_provider=None) -> None:
        super().__init__(bus)
        self._signals = signal_provider  # callable() -> dict

    def start(self) -> None:
        self.set_status(ModuleStatus.ACTIVE)

    def _collect_signals(self) -> dict:
        if not callable(self._signals):
            return {}
        try:
            return self._signals() or {}
        except Exception:
            return {}

    def posture(self) -> dict:
        return evaluate(self._collect_signals(), load_overrides())

    def set_control(self, control_id: str, status: str, note: str = "") -> dict:
        if control_id not in _BY_ID:
            raise ValueError("contrôle inconnu")
        if status not in STATUSES and status != "auto":
            raise ValueError("statut invalide")
        save_override(control_id, status, note or "")
        return self.posture()

    def export(self) -> str:
        return export_markdown(self.posture())
