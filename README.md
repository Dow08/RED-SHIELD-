<div align="center">

<img src="ui/public/red-shield-512.png" alt="RED SHIELD" width="120" />

# RED SHIELD

**Plateforme d'audit cyber tout-en-un — *red + blue*, modulaire, 100 % locale.**

Observer le réseau et le poste, corréler les risques, produire le livrable client — du capteur au rapport, dans une seule interface.

[![Licence : PolyForm Noncommercial](https://img.shields.io/badge/licence-PolyForm%20Noncommercial%201.0.0-orange)](LICENSE)
[![Sécurité : Trivy](https://img.shields.io/badge/s%C3%A9curit%C3%A9-Trivy%20CI-blue)](.github/workflows/trivy.yml)
![Tests](https://img.shields.io/badge/tests-112%20pytest%20%2B%207%20vitest-brightgreen)
![Backend](https://img.shields.io/badge/backend-Python%20·%20FastAPI-3776AB)
![Frontend](https://img.shields.io/badge/frontend-React%20·%20Vite%20·%20Tailwind-61DAFB)
![Desktop](https://img.shields.io/badge/desktop-Tauri%20v2-24C8DB)
![Air-gapped](https://img.shields.io/badge/air--gapped-par%20défaut-success)

📄 **[Fiche projet](docs/PRESENTATION.md)** · [Journal des modifications](docs/CHANGELOG.md) · [Sécurité](docs/SECURITY.md) · [Contribuer](docs/CONTRIBUTING.md)

</div>

> [!WARNING]
> **Usage autorisé uniquement.** RED SHIELD s'utilise sur votre **propre machine** ou sur des cibles couvertes par une **autorisation écrite** (pentest, lab). La reconnaissance active (nmap, traceroute, scan) ne vise que des cibles autorisées, avec un garde-fou de périmètre et un **journal d'audit local**. Un [modèle de mandat](docs/MANDAT-AUTORISATION.md) est fourni.

> [!NOTE]
> **Usage non commercial.** Le logiciel peut être téléchargé, exécuté, étudié et modifié à des fins non commerciales. Sa **vente et toute exploitation commerciale sont interdites** — voir [Licence](#-licence).

---

## Présentation

Un audit de sécurité oblige aujourd'hui à jongler entre une dizaine d'outils disjoints — scan, monitoring réseau, veille CVE, conformité, SIEM — puis à **tout ré-agréger à la main** dans un rapport. C'est lent, dispersé et source d'erreurs.

**RED SHIELD agrège et corrèle** ce que ces outils produisent, plutôt que de les réimplémenter, autour d'une colonne vertébrale unique :

```
   CAPTEURS                →          CERVEAU                →          LIVRABLE
 scan · recon · santé            scoring · MITRE ATT&CK             rapport de mission
 connexions · e-mails            CVE/NVD · conformité GRC            éditable + export PDF
```

Deux moitiés du métier réunies dans une même interface :

- **Défensive (blue team)** — observer, noter, expliquer et corriger ce qui se passe sur le réseau et le poste ;
- **Offensive / reconnaissance (red team)** — cartographier, scanner, énumérer, tester ;
- **GRC** par-dessus — rattacher le tout à des référentiels reconnus (ISO 27001, NIST CSF, CIS).

Un principe non négociable : **zéro donnée inventée**. Chaque valeur affichée est une **mesure réelle**, ou l'état explicite « non connecté » — jamais de donnée de démonstration.

---

## 📑 Sommaire

- [Captures d'écran](#-captures-décran)
- [Fonctionnalités](#-fonctionnalités)
- [Architecture](#-architecture)
- [Stack technique](#️-stack-technique)
- [Installation & lancement](#-installation--lancement)
- [Sécurité & confidentialité](#-sécurité--confidentialité)
- [Statut & feuille de route](#-statut--feuille-de-route)
- [Tests](#-tests)
- [Licence](#-licence)
- [Avertissement](#-avertissement)

---

## 📸 Captures d'écran

*Thème « Command Grid », données réelles (rien d'inventé), mode air-gapped actif.*

| Dashboard — vue d'ensemble temps réel | Bouclier — connexions notées & MITRE |
|:---:|:---:|
| ![Dashboard](docs/screenshots/01-dashboard.png) | ![Bouclier](docs/screenshots/04-bouclier.png) |
| **Carte réseau — graphe interactif** | **Carte du monde — traceroute géolocalisé** |
| ![Carte réseau](docs/screenshots/02-carte-reseau.png) | ![Carte du monde](docs/screenshots/03-carte-monde.png) |
| **Ports en écoute — surface d'exposition** | **Recon — nmap + CVE (NVD) + LAN** |
| ![Ports en écoute](docs/screenshots/10-ports-ecoute.png) | ![Recon](docs/screenshots/05-recon.png) |
| **SOC local — Mail, HIDS & Defender** | **Santé — bilan du poste** |
| ![SOC](docs/screenshots/06-soc.png) | ![Santé](docs/screenshots/07-sante.png) |
| **Connecteurs — VT / SIEM / IMAP / LLM chiffrés** | **Diagnostic — journal, beaconing, timeline** |
| ![Connecteurs](docs/screenshots/08-connecteurs.png) | ![Diagnostic](docs/screenshots/09-diagnostic.png) |

> Les vues Remédiation, Conformité (GRC) et Offensif sont accessibles directement dans l'application.

---

## ✨ Fonctionnalités

### 🛡️ Vue d'ensemble & bouclier — *blue team*

- **Dashboard « Command Grid »** — score d'exposition **0-100** en direct (jauge + sparkline), répartition saines / à surveiller / suspectes, débit et top process, raccourcis vers les actions prioritaires.
- **Bouclier temps réel** — chaque connexion avec sa lignée complète **process → PID → exécutable → arbre parent**, résolution **DNS inverse**, sens **entrant / sortant**, et un **score de risque expliqué** corrélé à **MITRE ATT&CK**.
- **Métriques réseau agrégées** — entrant/sortant, TCP/UDP, **chiffré vs clair**, **ports en écoute** (exposé au réseau vs local), **pays distincts géolocalisés hors-ligne** avec les process à l'origine des flux.
- **Débit par processus** (Mo/s ↓/↑) et **capture des paquets entrants** via **`pktmon`** (natif Windows, mode admin) — sans pilote tiers.
- **Cartes réseau** — graphe interactif (canvas maison : zoom / pan / survol, DNS sous les nœuds) en 4 vues (Sortant / Entrant / Local / Tous), et **carte du monde** avec **traceroute géolocalisé 100 % hors-ligne**, flux entrants/sortants, détection **VPN/tunnel**, points cliquables.
- **Analyse comportementale** — découverte **LAN** (ARP), détection de **beaconing C2** (périodicité), **timeline** des événements, **historique** (snapshots SQLite) et **export Markdown**.

### 🎯 Reconnaissance & offensif — *red team*

- **Scan nmap** enrichi — croisement **CVE en ligne (API NVD)**, décomposition par **couche OSI**, mapping **conformité CIS / ANSSI / NIST** par port, suggestions d'énumération.
- **Cartographie native (sans nmap)** — moteur de reconnaissance portable en **sockets purs** : découverte d'hôtes (TCP + **SSDP/UPnP** pour identifier box / IoT / imprimantes), scan de ports avec empreinte de services, **énumération web** façon *ffuf / gobuster* et **audit TLS** (protocoles/chiffrements faibles, certificat expiré).
- **Garde-fou de périmètre** — déclaration des **cibles autorisées** ; tout scan hors périmètre exige une confirmation et est **journalisé** (traçabilité de mission).
- **Vulnérabilités applicatives** — versions réelles des process croisées avec les **CVE NVD**.
- **Audit WiFi** (`netsh`) — réseaux, chiffrement, canaux, évaluation du risque.
- **Cracker de hash** — md5 / sha1 / sha256 / sha512 / PBKDF2, identification automatique, attaque par dictionnaire, 100 % local.
- **OSINT passif** — énumération de **sous-domaines** (crt.sh), hors air-gapped.

### 🚨 SOC local & remédiation

- **HIDS-lite** — lecture des **événements Windows sensibles** (services, échecs d'authentification, création de comptes, Defender / Sysmon).
- **Microsoft Defender** — état réel de l'AV/EDR intégré (protection temps réel, signatures, scans, menaces), en **lecture seule**.
- **Mail Security** — analyse d'un `.eml` (**SPF / DKIM / DMARC**, désalignement, liens et pièces jointes à risque) → **verdict + remédiation** ; fonctionne aussi hors-ligne côté mobile.
- **Connecteur IMAP** — relève d'une boîte réelle (mot de passe d'application en keyring, **auto-détection serveur/port**) pour scorer les derniers messages.
- **Remédiation priorisée** — investigation d'une connexion (arbre de process, techniques **MITRE ATT&CK**, **réputation threat-intel** VirusTotal / AbuseIPDB) et **couper / autoriser** via le **pare-feu Windows**, toujours en **dry-run → confirmation → annulation → audit**.

### 📋 Conformité — assistant CISO (GRC)

- **Suivi de conformité réel**, pas une auto-déclaration : **16 contrôles** classés par domaine et mappés à **ISO/IEC 27001:2022**, **NIST CSF 2.0** et **CIS Controls v8**, chacun avec un **« pourquoi »** et une **recommandation** en clair.
- **Contrôles techniques auto-évalués** depuis l'état réel de la machine (ports exposés, flux en clair, AV/EDR, correctifs, connexions suspectes, journalisation) — le verdict calculé fait foi.
- **Contrôles organisationnels** (MFA, accès, sauvegardes, réponse à incident, RGPD, fournisseurs…) **évalués manuellement avec preuve** : justification texte **+ pièces jointes** (compressées automatiquement), indépendantes du statut et persistées localement.
- **Score pondéré par référentiel** + global, statuts *conforme / à traiter / non conforme / N-A / à évaluer*, **export Markdown**. Fonctionne **en air-gapped**.

### 📄 Rapport de mission — *le livrable*

- **Assemblage factuel** en un clic depuis les **données réelles** (score d'exposition, constats issus du GRC + CVE, conformité) — une section vide est masquée.
- **Document vivant, éditable directement** dans l'aperçu : réécriture de **n'importe quel texte** (titres compris) avec **mise en forme riche**, **annotation** de chaque constat, masquage/réordonnancement, **sections libres** et **captures** jointes.
- **Marque personnalisable** (nom, logo, référence d'autorisation), **synthèse assistée par IA** optionnelle, **brouillon sauvegardé**.
- **Export PDF** (couverture éditoriale + intérieur sobre, A4) via l'impression navigateur. Un [rapport d'exemple](docs/exemple-rapport-mission.md) est fourni.

### 🩺 Santé du poste

- **Espace disque récupérable** (temp, caches Chrome/Edge/Firefox, miniatures, corbeille, Windows Update) avec **donut avant/après** et nettoyage **dry-run + confirmation** — sans toucher au registre.
- **Programmes au démarrage** (activation/désactivation réversible), **mises à jour applicatives via winget** (détection + installation guidée), **point de restauration**, RAM et top process, gros fichiers.

### 🔌 Connecteurs, IA & extensibilité

- **Connecteurs** — clés API **chiffrées via keyring** (jamais en clair), **auto-détection** des réglages IMAP.
- **SIEM / EDR** — client **Wazuh** réel (auth sur l'indexeur, requête `wazuh-alerts-*/_search`), prêt pour un lab ; les alertes remontent dans le SOC.
- **Analyse IA** — **LLM local (Ollama)** ou API au choix, appliqué aux scans, logs, mails et à la synthèse de timeline — hors air-gapped uniquement.
- **Sauvegarde / restauration** — export/import de l'**état de travail** (évaluations GRC + brouillon de rapport), **sans les secrets** (les clés restent dans le trousseau).
- **Détection de mise à jour** — signale la publication d'une version plus récente (releases GitHub, hors air-gapped).

### 📱 Édition mobile autonome

Le mobile embarque ses **propres moteurs, côté client, sans le moteur Python** :

- **Recon natif (Rust)** — cartographie du réseau (découverte TCP + **SSDP/UPnP**), scan de ports et empreinte, énumération web, via un plugin **Tauri natif** et sans root. L'interface bascule en **mode terrain** (onglets Recon + Offensif).
- **Analyses hors-ligne** ([`ui/src/mobile/offline.ts`](ui/src/mobile/offline.ts)) — e-mails `.eml` (SPF/DKIM/DMARC) et hash (md5/sha1/sha256/sha512 via Web Crypto).

Empaqueté en **APK Android** par la CI (Tauri v2), 100 % hors-ligne.

---

## 🧩 Architecture

Une **coquille stable** — **registre de modules + bus d'événements + watchdog** — accueille des **briques isolées**. Un module en échec passe 🔴 **sans faire tomber l'application** ; les modules communiquent **par le bus**, jamais en direct, et respectent tous le même **contrat** (`name`, `status`, `produces/consumes`, `health`). Une brique = un fichier.

```
RED SHIELD
├── engine/                 # Moteur Python (FastAPI)
│   └── app/
│       ├── core/           # bus · registry · watchdog · proc · http
│       ├── modules/        # 27 briques isolées : shield, scan, netrecon, trace, hids,
│       │                   #   defender, mail, imapmail, siem, grc, health, updater…
│       ├── scoring/        # règles de risque · baseline · MITRE
│       └── main.py         # API + endpoints
├── ui/                     # Dashboard React / Vite / Tailwind
│   ├── src/                # App.tsx · viz.tsx (canvas) · api.ts · mobile/offline.ts
│   └── src-tauri/          # empaquetage desktop/mobile (Tauri v2 + sidecar · recon.rs)
└── .github/workflows/      # Trivy · build desktop · build mobile (Android)
```

Détails et conventions : [`CONTRIBUTING.md`](docs/CONTRIBUTING.md) · [`HANDOFF.md`](docs/HANDOFF.md) · [`spec.md`](docs/spec.md).

---

## 🛠️ Stack technique

| Couche | Technologies |
|---|---|
| **Moteur** | Python 3.11+ · FastAPI + Uvicorn · psutil · SQLModel/SQLite · keyring · maxminddb (GeoIP hors-ligne) · httpx · pydantic · PyInstaller (sidecar) |
| **Frontend** | React 18 · Vite · TypeScript · Tailwind · visualisations **canvas maison** (graphe, carte du monde, jauges) · Vitest |
| **Desktop / mobile** | Tauri v2 (Rust) — installeur Windows NSIS et APK Android ; moteur Python en sidecar (desktop), recon natif Rust (mobile) |
| **Outils exploités** | nmap · pktmon · netsh · winget · PowerShell (Defender) · API NVD · Wazuh · VirusTotal / AbuseIPDB · crt.sh · Ollama |
| **CI / qualité** | Trivy (vulnérabilités / secrets / configs) · Dependabot · builds desktop & mobile · typage strict |

---

## 🚀 Installation & lancement

### Prérequis
- **Python 3.11+** (testé 3.14 — sous Windows, lancer avec `py` ; `python` est le stub Microsoft Store)
- **Node.js 18+**
- *nmap* (optionnel, onglet Recon)

### Installation
```powershell
./setup.ps1      # Windows
```
```bash
./setup.sh       # Linux / macOS
```

### Lancement (2 terminaux)
```bash
# Terminal 1 — moteur
cd engine
.venv/Scripts/python.exe -m uvicorn app.main:app --port 8787     # Windows
# (Linux : .venv/bin/python -m uvicorn app.main:app --port 8787)

# Terminal 2 — dashboard
cd ui
npm run dev
```
Ouvrir **http://localhost:5173** — le dashboard proxifie `/api` vers le moteur (`127.0.0.1:8787`).

### Capture de débit par processus (optionnel, Windows)
`pktmon` demande les **droits administrateur** :
```powershell
./run-admin.ps1      # auto-élévation UAC
```
Sans admin, l'application fonctionne et retombe sur le proxy « nombre de connexions ».

### Packages installables
Les launchers sont compilés en **CI GitHub Actions** (Actions → choisir le workflow → **Run workflow**) :
- **Desktop** — *Build desktop (Tauri + sidecar)* → installeur Windows **NSIS**.
- **Mobile** — *Build mobile (Android APK)* → **APK Android** autonome.

La chaîne de **signature de code** est prête (voir [`docs/SIGNING.md`](docs/SIGNING.md)).

---

## 🔒 Sécurité & confidentialité

- **Mode air-gapped par défaut** — coupe **tout appel à une API tierce** (NVD, réputation, OSINT, LLM distant, SIEM) ; les analyses restent sur la machine.
- **Zéro donnée inventée** — chaque valeur provient d'une mesure réelle, ou affiche « non connecté ».
- **Secrets** — jamais en clair (keyring / Credential Manager) ; jamais journalisés ni exportés. `.env` hors versionnement.
- **Exécution système durcie** — validation stricte des entrées, listes blanches de commandes, **aucun `shell` libre**, API liée à `127.0.0.1`.
- **Interface durcie** — **CSP stricte** sur la WebView (aucun script ni appel externe non autorisé).
- **Actions système** (couper une connexion, pare-feu, nettoyage, mise à jour) — **dry-run → confirmation → annulation → audit**.
- **Analyse continue** — **Trivy** et **Dependabot** à chaque push ; voir [`.github/workflows/trivy.yml`](.github/workflows/trivy.yml) et [`SECURITY.md`](docs/SECURITY.md).

---

## 🧭 Statut & feuille de route

| État | Éléments |
|---|---|
| ✅ **Livré** | 27 modules · dashboard complet · GRC · rapport de mission · recon natif · installeur desktop (CI) · durcissement sécurité · sauvegarde |
| 🔄 **En cours** | build & test mobile (Android) · signature de code · certification terrain des fonctions admin (pktmon, Wazuh, IMAP) |

Détail dans le [journal des modifications](docs/CHANGELOG.md).

---

## 🧪 Tests

```bash
cd engine && .venv/Scripts/python.exe -m pytest -q      # 112 tests (backend)
cd ui && npx vitest run                                  # 7 tests (frontend)
```

Garde-fou de build : `tsc --noEmit && vite build`.

---

## 📄 Licence

Distribué sous **[PolyForm Noncommercial License 1.0.0](LICENSE)**.

- ✅ **Autorisé** : télécharger, exécuter, étudier, modifier, tester, partager — à des fins **non commerciales**.
- ❌ **Interdit** : vendre, commercialiser ou exploiter le logiciel à des fins commerciales.

© 2026 Dorian Poncelet (DP Cyber Consulting).

---

## ⚠️ Avertissement

RED SHIELD est un outil éducatif et défensif fourni « en l'état », **sans aucune garantie**. L'utilisateur est seul responsable de son usage et doit respecter la législation applicable ainsi que les autorisations nécessaires avant tout scan ou analyse d'une cible. Les auteurs déclinent toute responsabilité en cas d'usage abusif.
