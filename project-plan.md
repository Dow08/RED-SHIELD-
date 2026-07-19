# Red — Plan d'action Jalon 1 (project-plan.md)

> **Jalon 1 (MVP) = « Bouclier local » en observation** (variante A hybridée).
> **Ne rien coder avant ta validation explicite de ce plan.**
> Convention : chaque tâche = un incrément testable + un commit git.
> Règle dure : **zéro donnée inventée**, tout testé de bout en bout.

---

## Pré-requis (à confirmer)
- [ ] Git installé + repo initialisé dans `Red/`
- [ ] Python 3.11+ dispo (`python --version`)
- [ ] Node.js 18+ dispo (`node --version`)
- [ ] Windows (cible de test initiale) — le bouclier lit TES propres connexions, aucune cible tierce

---

## Étape 0 — Fondations
- [ ] T0.1 — `git init`, `.gitignore` (venv, node_modules, `*.db`, `.env`), `README.md`
- [ ] T0.2 — `CLAUDE.md` (stack figée, conventions, palette, style Command Center, cadre d'usage, règle « zéro donnée inventée »)
- [ ] T0.3 — `.env.example` (mode air-gapped par défaut, chemins DB, clés API vides)
- *Commit : « chore: scaffold projet + conventions »*

## Étape 1 — Coquille modulaire (le socle)
- [ ] T1.1 — `engine/` : `requirements.txt` (fastapi, uvicorn, pydantic, psutil, sqlmodel, keyring), venv
- [ ] T1.2 — `app/main.py` : FastAPI + `GET /health`
- [ ] T1.3 — `app/modules/base.py` : **contrat de module** (name, status, produces/consumes, health, requires)
- [ ] T1.4 — `app/core/registry.py` : registre + enregistrement des modules
- [ ] T1.5 — `app/core/bus.py` : bus d'événements simple (pub/sub in-process)
- [ ] T1.6 — `app/core/watchdog.py` : superviseur (attrape les crashs, marque 🔴, journalise)
- [ ] T1.7 — Route `GET /modules` : liste + états 🟢🔴⚪
- [ ] Test : un module qui lève une exception passe 🔴 **sans faire tomber l'API**
- *Commit : « feat(engine): coquille modulaire (registre + bus + watchdog) »*

## Étape 2 — Module Bouclier (connexions live) + Bande passante
- [ ] T2.1 — `app/modules/shield.py` : psutil → connexions actives (**résolution PID → process/exe/chemin**, local/remote, port, protocole)
- [ ] T2.2 — Résolution DNS inverse + cache
- [ ] T2.3 — Route `GET /shield/connections`
- [ ] T2.4 — Garde-fou « machine autorisée » + écriture `AuditLog`
- [ ] T2.5 — `app/modules/bandwidth.py` : `net_io_counters` → débit ↓/↑ temps réel + route `GET /bandwidth`
- [ ] T2.6 — **Arbre de processus parent-enfant** (psutil `ppid`, dégradation gracieuse si process protégé) + exposition via l'API
- [ ] Test : connexions réelles cohérentes avec `netstat` ; débit cohérent avec le gestionnaire de tâches ; lignée d'un process affichée
- *Commit : « feat(shield): connexions (PID→app) + bande passante + arbre process »*

## Étape 3 — Scoring + corrélation MITRE
- [ ] T3.1 — `app/scoring/rules.py` : règles (port sensible/non standard, absence DNS, process inconnu, géo/ASN)
- [ ] T3.2 — `app/scoring/baseline.py` : baseline utilisateur (connexions habituelles) → écart
- [ ] T3.3 — Score par connexion (0-100) + sévérité (safe/watch/suspect/crit)
- [ ] T3.4 — Score global d'exposition (0-100) + bande couleur
- [ ] T3.5 — `app/scoring/mitre.py` : tag ATT&CK sur motifs connus (ex. 4444→TA0011/C2, port non standard sans DNS→T1571) + tentative de corrélation pour PID non identifié
- [ ] Test : port 4444 sans DNS → sévérité critique + tag MITRE attendus
- *Commit : « feat(scoring): risque + score global + corrélation MITRE »*

## Étape 4 — Module Diagnostic (logs, rétention & auto-surveillance)
- [ ] T4.1 — `app/modules/diagnostic.py` : logs structurés par sévérité (info/warn/error) en base
- [ ] T4.2 — Capture des erreurs des autres modules (via le watchdog/bus)
- [ ] T4.3 — Routes `GET /diagnostic/logs` (avec **filtre date/heure**) + `GET /diagnostic/logs/export`
- [ ] T4.4 — **Rétention** : purge à la fermeture (option) + budget **≤ 1 Go** avec rotation auto + indicateur d'usage
- [ ] Test : une erreur d'un module apparaît dans le journal ; le filtre date/heure renvoie la bonne fenêtre ; la rotation respecte le budget
- *Commit : « feat(diagnostic): journal filtrable + rétention/purge/1Go »*

## Étape 5 — Persistance (historique & projets)
- [ ] T5.1 — `app/db.py` + `app/models.py` : SQLite + modèles (Project, Host, Snapshot, Connection, Connector, ModuleState, AuditLog, AppLog)
- [ ] T5.2 — Enregistrer chaque relevé du bouclier en `Snapshot` + `Connection`
- [ ] T5.3 — Routes historique (lister snapshots d'un host)
- [ ] Test : deux relevés successifs → deux snapshots relisibles
- *Commit : « feat(engine): persistance SQLite + historique »*

## Étape 6 — Export rapport Markdown
- [ ] T6.1 — `app/report/markdown.py` : template **vu → problème → correctif**, structuré, lisible IA
- [ ] T6.2 — Route `GET /report/markdown` (télécharge le `.md`)
- [ ] Test : le rapport contient score, connexions suspectes, remédiations priorisées
- *Commit : « feat(report): export Markdown orienté remédiation »*

## Étape 7 — Frontend : base + thème Command Center
- [ ] T7.1 — `ui/` : init Vite + React + TS + Tailwind
- [ ] T7.2 — `theme.ts` + Tailwind : palette noir/or/vert/rouge, style Command Center (panneaux bordés, en-têtes or)
- [ ] T7.3 — `api/client.ts` : appels API + gestion d'erreurs + état de chargement
- [ ] Test : l'UI démarre et lit `/health` + `/modules`
- *Commit : « feat(ui): scaffold React + thème Command Center »*

## Étape 8 — Dashboard MVP (pages dédiées : Bouclier / Remédiation / Diagnostic)
- [ ] T8.1 — Navigation multi-pages (routage par onglet) + en-tête : marque RED + jauge + toggle air-gapped + **bande passante ↓/↑** + indicateur stockage
- [ ] T8.1b — Page **Dashboard** (1er onglet) : cockpit récapitulatif (score, bande passante, aperçu connexions, mini-carte, santé modules, top remédiations, journal récent) avec liens vers chaque onglet + **panneaux repliables** (flèche ▾/▸ par carte)
- [ ] T8.1c — Widget **Bande passante** avec **sous-onglets Débit / Top process** (processus les plus consommateurs)
- [ ] T8.2 — Page **Bouclier** : tableau **connexions** (process→app, PID+chemin, IP, DNS, port, géo, risque, sévérité) + **tags MITRE**
- [ ] T8.3 — **Filtres via menu déroulant à cocher** (tout coché par défaut) + recherche + tri par risque
- [ ] T8.4 — Carte **Modules** avec états 🟢🔴⚪
- [ ] T8.5 — Page **Remédiation** dédiée : explications détaillées, étapes, **liens MITRE + CVE (NVD)** cliquables + **mode « explique-moi »** (bibliothèque statique) + affichage de l'**arbre de processus**
- [ ] T8.6 — Bouton **Exporter le rapport (Markdown)**
- [ ] T8.7 — Page **Diagnostic & réglages** : logs (filtre date/heure) + modes (Recon/Diagnostic) + rétention/stockage + mise à jour
- [ ] Test responsive : lisible et utilisable sur mobile/tablette
- *Commit : « feat(ui): dashboard multi-pages bouclier/remédiation/diagnostic »*

## Étape 9 — Tests, sécurité & finalisation
- [ ] T9.1 — Tests moteur (scoring, parsing connexions, watchdog isolation) : nominal + edge + erreurs
- [ ] T9.2 — Revue sécurité : validation des entrées, aucun shell libre, secrets en env/keyring, air-gapped effectif, disclaimer + audit
- [ ] T9.3 — `README.md` : setup pas à pas (commandes exactes), démarrage documenté, accès mobile sur le LAN
- [ ] Test end-to-end : de l'ouverture du dashboard au rapport Markdown exporté
- *Commit : « test+docs: couverture utile + guide de setup »*

---

## Auto-vérification de fin de Jalon 1
- [ ] Le moteur + l'UI démarrent avec des commandes documentées
- [ ] Les connexions réelles s'affichent live (process/PID/IP/DNS/port/risque) — vérifié contre `netstat`
- [ ] Score global + 3 remédiations priorisées affichés
- [ ] Un module en échec passe 🔴 sans faire tomber l'appli
- [ ] Rapport Markdown exportable, historique OK, disclaimer + audit présents
- [ ] Mode air-gapped actif par défaut, aucun secret en dur, **aucune donnée inventée**
- [ ] Tests passent

---

## Ce qu'on NE fait PAS au Jalon 1 (rappel)
Graphe, temps réel poussé, connecteurs/VirusTotal, action couper/autoriser, modules déplaçables → **J2**.
Scan nmap, OSI, CVE, TLS, MITRE ATT&CK → **J3**.
WiFi/aircrack, gobuster, SIEM/EDR, ATLAS/prompt-injection → **J4**.
