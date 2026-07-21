# Contribuer à RED SHIELD — conventions & architecture

Contexte, stack et conventions du projet, à lire avant toute session de travail sur RED.

## Ce qu'est RED
Bouclier réseau modulaire **red + blue** : observe les connexions d'une machine en temps réel, les note (score 0-100), les explique, propose des remédiations priorisées, et s'étend par modules (recon offensif, graphe, connecteurs SIEM/EDR). Voir `spec.md`, `project-plan.md`, `analysis.md`.

**Cadre d'usage** : strictement sur cibles/machines autorisées (propriété ou autorisation écrite ; pentest/lab). Disclaimer + journal d'audit obligatoires.

## Stack (figée)
- **Backend / moteur** : Python 3.11+ (ici **3.14**, lancer avec **`py`** — la commande `python` est le stub Microsoft Store), **FastAPI** + Uvicorn, **psutil** (connexions/process natifs Win+Linux), **SQLModel/SQLite**, **keyring** (clés chiffrées).
- **Frontend** : React + Vite + TypeScript + Tailwind ; Recharts (jauge), Cytoscape.js (graphe), react-grid-layout (modules déplaçables).
- **Déploiement** : app web locale ; API liée à `127.0.0.1` par défaut ; mobile = consultation sur le LAN (opt-in + jeton).

## Architecture modulaire (règle d'or)
Coquille stable (registre de modules + bus d'événements + watchdog) qui accueille des modules **isolés** : un module qui plante passe 🔴 **sans faire tomber l'appli**. Chaque module implémente le **contrat de module** (name, status, produces/consumes, health, requires). Les modules communiquent via le **bus**, jamais en direct.

## Principes non négociables
- **Zéro donnée inventée** : un module affiche du réel ou l'état `non connecté`. Jamais de fausse donnée de démo.
- **Tout testé de bout en bout** ; aucun lien mort, aucun endpoint mort.
- **Mode air-gapped par défaut** : coupe tout appel externe ; enrichissements (VirusTotal, géo, rapport IA…) inertes tant qu'il est actif.
- **Sécurité** : validation stricte des entrées, aucun shell libre depuis l'UI, liste blanche de commandes, moindre privilège, secrets en keyring/env (jamais en dur).
- **Performance** : lecture async + échantillonnage ; ne pas ralentir l'hôte.
- Actions système (couper une connexion, SOAR-lite) : **aperçu (dry-run) + confirmation + annulation + audit**.

## Style visuel (retenu : « mix moderne »)
Layout **bento** + cartes **verre givré** (glassmorphism) + **orbes de gradient** ambiants + **équerres/labels HUD** monospace. Fond teal-black (#080a0f), accent **cyan/teal** (#2fe0d0), rouge marque RED, sémantique vert=sain / ambre=à surveiller / rouge=critique. **Radars/visualisations (radar, graphe, bande passante, carte du monde) : ne pas modifier leur rendu.** Repli sans `backdrop-filter` sur matériel modeste.

## Jalons
- **J1 (en cours)** : bouclier local (connexions psutil + PID→app + arbre process), bande passante (Débit/Top process), score + corrélation MITRE de base, filtres (menu déroulant), onglet Dashboard récap, Remédiation, Diagnostic (logs + rétention ≤1 Go + purge), historique SQLite, export Markdown, panneaux repliables.
- **J2** : graphe (vues Sortant/Entrant/Local/Tous + DNS par endpoint), traceroute carte du monde (hors-ligne, géoloc embarquée), connecteurs, VirusTotal, action couper/autoriser, beaconing/baseline/DNS analytics, timeline, SOAR-lite, rapport IA.
- **J3** : recon nmap + OSI + CVE (→NVD) + TLS + MITRE ATT&CK + conformité CIS/ANSSI/NIST.
- **J4** : WiFi/aircrack (Linux + auto-test), gobuster, SIEM/EDR, ATLAS/prompt-injection, temps réel avancé.

## Conventions
- Commits : messages clairs, un incrément testable par commit (voir `project-plan.md`).
- Fichiers : moteur dans `engine/`, frontend dans `ui/`. Un module = un fichier sous `engine/app/modules/`.
- Lancer le backend avec `py`, pas `python`.
