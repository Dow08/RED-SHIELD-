# RED — Network Shield & Recon

Bouclier réseau modulaire **red + blue** : observe les connexions de ta machine en temps réel, les note (score 0-100), les explique (corrélation MITRE ATT&CK) et propose des remédiations priorisées — dans un dashboard sombre moderne, extensible par modules.

> ⚠️ **Usage autorisé uniquement** : sur des machines/réseaux dont tu es propriétaire ou pour lesquels tu détiens une autorisation écrite (pentest, lab). Le Jalon 1 n'observe que **ta propre machine** (aucune cible tierce).

## État — Jalon 1 (MVP) fonctionnel ✅
Bouclier local : connexions live (PID→app, lignée, DNS), bande passante, score d'exposition + corrélation MITRE, journal/diagnostic, historique SQLite, export Markdown. Dashboard React (style « mix moderne »). 14 tests verts.
Suite : voir [`project-plan.md`](project-plan.md), [`spec.md`](spec.md), [`analysis.md`](analysis.md).

## Prérequis
- **Python 3.11+** (testé 3.14 — utiliser le lanceur `py` sous Windows ; `python` est le stub Microsoft Store)
- **Node.js 18+** (testé v24)
- *(nmap : seulement pour le Jalon 3)*

## Lancement (2 terminaux)

**Terminal 1 — moteur (backend)**
```bash
cd engine
py -m venv .venv
.venv\Scripts\activate                 # Windows (Linux : source .venv/bin/activate)
pip install -r requirements.txt
py -m uvicorn app.main:app --port 8787
```

**Terminal 2 — dashboard (frontend)**
```bash
cd ui
npm install
npm run dev
```
Puis ouvrir **http://localhost:5173**. Le dashboard proxifie `/api` vers le moteur (127.0.0.1:8787).
Consultation mobile/tablette : le dev server écoute aussi sur le LAN (adresse `Network:` affichée par Vite).

Copier `.env.example` en `.env` pour personnaliser (mode air-gapped, port, budget stockage…).

## Tests
```bash
cd engine
.venv\Scripts\python.exe -m pytest -q
```

## Sécurité (revue Jalon 1)
- **Aucune exécution shell** : le J1 lit uniquement l'état système via `psutil` (pas de `subprocess`).
- **Validation des entrées** : paramètres d'API typés par FastAPI ; aucune donnée utilisateur exécutée.
- **API liée à `127.0.0.1`** par défaut ; exposition LAN opt-in (dev server) pour la consultation mobile.
- **Secrets** : `.env` hors versionnement ; clés API prévues via keyring (Jalon 2) ; rien en dur.
- **Mode air-gapped** actif par défaut. Le J1 ne fait **aucun appel à une API tierce**. Seule exception réseau : la **résolution DNS inverse** via le résolveur système (local), utilisée pour nommer les IP — choix assumé (hygiène réseau, pas de partage de données à un tiers).
- **Isolation** : un module qui plante passe en erreur sans faire tomber l'application (watchdog).
- **Zéro donnée inventée** : chaque valeur affichée provient d'une mesure réelle.

## Architecture
Coquille (registre + bus d'événements + watchdog) accueillant des modules isolés (`engine/app/modules/`). Frontend React/Vite/Tailwind (`ui/`). Détail et conventions : [`CLAUDE.md`](CLAUDE.md).
