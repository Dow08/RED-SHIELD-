<div align="center">

<img src="ui/public/red-shield-512.png" alt="RED SHIELD" width="120" />

# RED SHIELD

**Bouclier réseau modulaire *red + blue* — surveillance locale, recon & remédiation.**

Observe les connexions de ta machine en temps réel · les note (score 0-100) · les explique (MITRE ATT&CK) · propose des remédiations priorisées — dans un dashboard cyber, 100 % local, extensible par modules.

[![Licence : PolyForm Noncommercial](https://img.shields.io/badge/licence-PolyForm%20Noncommercial%201.0.0-orange)](LICENSE)
[![Sécurité : Trivy](https://img.shields.io/badge/s%C3%A9curit%C3%A9-Trivy%20CI-blue)](.github/workflows/trivy.yml)
![Tests](https://img.shields.io/badge/tests-43%20verts-brightgreen)
![Backend](https://img.shields.io/badge/backend-Python%203.11%2B%20·%20FastAPI-3776AB)
![Frontend](https://img.shields.io/badge/frontend-React%2018%20·%20Vite%20·%20Tailwind-61DAFB)
![Air-gapped](https://img.shields.io/badge/air--gapped-par%20défaut-success)

</div>

> [!WARNING]
> **Usage autorisé uniquement.** RED SHIELD s'utilise sur **ta propre machine** ou sur des cibles pour lesquelles tu détiens une **autorisation écrite** (pentest, lab). Le recon actif (nmap, traceroute) ne doit viser que des cibles autorisées. Un journal d'audit est tenu localement.

> [!NOTE]
> **À des fins non commerciales.** RED SHIELD est fourni pour être **téléchargé, testé et étudié**. Sa **vente et toute utilisation commerciale sont interdites** — voir [Licence](#-licence).

---

## 📑 Sommaire
- [Captures d'écran](#-captures-décran)
- [Fonctionnalités](#-fonctionnalités)
- [Architecture](#-architecture)
- [Stack technique](#-stack-technique)
- [Installation & lancement](#-installation--lancement)
- [Sécurité & confidentialité](#-sécurité--confidentialité)
- [Tests](#-tests)
- [Licence](#-licence)
- [Avertissement](#-avertissement)

---

## 📸 Captures d'écran

> _Les captures seront ajoutées ici. Dépose les fichiers PNG dans [`docs/screenshots/`](docs/screenshots/) aux noms indiqués ci-dessous._

| Dashboard (Command Grid) | Carte réseau & traceroute |
|:---:|:---:|
| ![Dashboard](docs/screenshots/01-dashboard.png) | ![Carte réseau](docs/screenshots/02-carte-reseau.png) |
| **Bouclier — connexions notées** | **Recon (nmap + CVE)** |
| ![Bouclier](docs/screenshots/03-bouclier.png) | ![Recon](docs/screenshots/04-recon.png) |
| **SOC local (HIDS + Mail)** | **Remédiation (MITRE / threat-intel)** |
| ![SOC](docs/screenshots/05-soc.png) | ![Remédiation](docs/screenshots/06-remediation.png) |

---

## ✨ Fonctionnalités

### 🛡️ Surveillance locale (blue team)
- **Bouclier temps réel** : toutes les connexions (process → PID → exécutable → lignée), résolution DNS inverse, **sens entrant/sortant**, score de risque 0-100 avec explications et **corrélation MITRE ATT&CK**.
- **Métriques réseau** : entrant/sortant, TCP/UDP, **chiffré/clair**, **ports en écoute** (surface d'exposition, exposé vs local), **pays distincts géolocalisés hors-ligne**, top ports.
- **Débit par processus** (Mo/s ↓/↑) et **capture des paquets entrants** via `pktmon` (Windows, admin).
- **Bande passante live** + top process.
- **Carte réseau interactive** (canvas : zoom / pan / survol) — vues **Sortant / Entrant / Local (LAN) / Tous**.
- **Traceroute géolocalisé** sur carte du monde, **100 % hors-ligne** (base GeoIP embarquée), détection de VPN, IP publique et **sauts**.
- **Découverte LAN** (ARP), **beaconing C2**, **timeline**, historique **SQLite**, **export Markdown** (lisible humain & IA).

### 🎯 Recon & offensif (red team)
- **Scan nmap** + **croisement CVE** local (liens NVD) + **décomposition OSI** + **conformité CIS/ANSSI/NIST** + suggestions d'énumération.
- **Audit WiFi** (`netsh`, alternative légère à aircrack sous Windows).
- **Cracker de hash** (md5 / sha1 / sha256 / pbkdf2, pur Python) + **OSINT** sous-domaines (crt.sh).

### 🚨 SOC local & remédiation
- **HIDS-lite** : événements Windows sensibles (services, échecs d'auth, comptes, Defender/Sysmon).
- **Mail Security** : analyse `.eml` (SPF/DKIM/DMARC, désalignement, liens et pièces jointes à risque) → verdict + remédiation.
- **Remédiation** priorisée (MITRE/CVE), **réputation threat-intel** (VirusTotal/AbuseIPDB), **couper/autoriser** une connexion (pare-feu Windows : *dry-run + confirmation + annulation + audit*).

### 🔌 Extensibilité
- **Connecteurs** : clés API **chiffrées via keyring** (jamais en clair) ; **analyse IA** (LLM local Ollama ou API) sur scan / logs / mail.
- **Thèmes live** (Command Grid par défaut) + fond cyber animé, modules du dashboard **réorganisables**.

---

## 🧩 Architecture

Une **coquille stable** (registre de modules + bus d'événements + watchdog) accueille des **modules isolés** : un module qui plante passe 🔴 **sans faire tomber l'application**. Les modules communiquent via le bus, jamais en direct, et respectent un **contrat** commun (`name`, `status`, `produces/consumes`, `health`).

```
RED SHIELD
├── engine/                 # Moteur Python (FastAPI)
│   └── app/
│       ├── core/           # bus · registry · watchdog
│       ├── modules/        # 19 modules isolés (shield, scan, trace, hids, mail, throughput…)
│       ├── scoring/        # règles de risque · baseline · MITRE
│       └── main.py         # API + endpoints
└── ui/                     # Dashboard React / Vite / Tailwind
    └── src/                # App.tsx · viz.tsx (canvas) · api.ts
```

Détails et conventions : [`CLAUDE.md`](CLAUDE.md) · [`HANDOFF.md`](HANDOFF.md) · [`spec.md`](spec.md).

---

## 🛠️ Stack technique
- **Moteur** : Python 3.11+ · **FastAPI** + Uvicorn · **psutil** · **SQLModel/SQLite** · **keyring** · **maxminddb** (GeoIP hors-ligne) · httpx · pydantic.
- **Frontend** : **React 18** · **Vite 6** · **TypeScript** · **Tailwind 4** · visualisations **canvas** (aucune lib graphique lourde).
- **Sécurité** : API liée à `127.0.0.1`, secrets en keyring, mode **air-gapped** par défaut, validation stricte, moindre privilège.

---

## 🚀 Installation & lancement

### Prérequis
- **Python 3.11+** (testé 3.14 — sous Windows, lancer avec `py` ; `python` est le stub Microsoft Store)
- **Node.js 18+** (testé v24)
- *nmap* (optionnel, pour l'onglet Recon)

### Installation rapide
```powershell
# Windows
./setup.ps1
```
```bash
# Linux / macOS
./setup.sh
```

### Lancement (2 terminaux)
```bash
# Terminal 1 — moteur
cd engine
.venv/Scripts/python.exe -m uvicorn app.main:app --port 8787    # Windows
# (Linux : .venv/bin/python -m uvicorn app.main:app --port 8787)

# Terminal 2 — dashboard
cd ui
npm run dev
```
Puis ouvre **http://localhost:5173**. Le dashboard proxifie `/api` vers le moteur (`127.0.0.1:8787`).

### Capture de débit par processus (optionnel, Windows)
La capture `pktmon` nécessite les **droits administrateur**. Lance le moteur élevé via le helper fourni :
```powershell
./run-admin.ps1      # auto-élévation UAC
```
Sans admin, l'application fonctionne normalement et retombe sur le proxy « nombre de connexions ».

---

## 🔒 Sécurité & confidentialité
- **Mode air-gapped par défaut** : coupe **tout appel à une API tierce** (réputation, OSINT, LLM distant). Les analyses restent **sur ta machine**.
- **Zéro donnée inventée** : chaque valeur affichée provient d'une **mesure réelle** (psutil, nmap, pktmon, base GeoIP embarquée…) ou de l'état « non connecté ». Aucune donnée de démo.
- **Secrets** : jamais en clair — stockés via **keyring / Credential Manager**. `.env` hors versionnement, `.env.example` sans valeur.
- **Analyse de sécurité continue** : **Trivy** scanne chaque push (vulnérabilités, secrets, mauvaises configurations) — voir [`.github/workflows/trivy.yml`](.github/workflows/trivy.yml).
- **Actions système** (couper une connexion, pare-feu) : **dry-run + confirmation + annulation + audit**.
- **API** liée à `127.0.0.1` ; exposition LAN opt-in (consultation mobile) uniquement.

---

## 🧪 Tests
```bash
cd engine
.venv/Scripts/python.exe -m pytest -q      # 43 tests
```

---

## 📄 Licence

Distribué sous **[PolyForm Noncommercial License 1.0.0](LICENSE)**.

✅ Autorisé : télécharger, exécuter, étudier, modifier, tester, partager — **à des fins non commerciales**.
❌ Interdit : **vendre**, commercialiser ou utiliser le logiciel à des fins commerciales.

© 2026 Dorian Poncelet (Dow08).

---

## ⚠️ Avertissement
RED SHIELD est un outil éducatif et défensif fourni « en l'état », **sans aucune garantie**. L'utilisateur est seul responsable de son usage et doit respecter la législation applicable ainsi que les autorisations nécessaires avant tout scan ou analyse d'une cible. Les auteurs déclinent toute responsabilité en cas d'usage abusif.
