# RED — Document de continuité (HANDOFF)

> **But** : tout ce qu'il faut savoir pour reprendre le projet RED dans une nouvelle
> fenêtre de contexte. Écrit le 2026-07-20. Voir aussi `spec.md`, `project-plan.md`,
> `analysis.md`, `CONTRIBUTING.md`.

---

## 1. Ce qu'est RED (vision)
**Bouclier réseau modulaire red + blue**, pour Dorian (reconversion cyber, cible GRC/SOAR).
Il observe les connexions d'une machine en temps réel, les **note** (score 0-100), les
**explique** (MITRE ATT&CK), propose des **remédiations**, et s'étend par **modules** :
recon offensif (scan nmap+CVE, WiFi, OSINT, cracker), SOC local (HIDS + Mail), connecteurs
(threat-intel, LLM). Dashboard sombre moderne, extensible.

**Principes non négociables** (respectés partout) :
- **Zéro donnée inventée** : un module affiche du réel ou l'état `non connecté`/`aucun`.
- **Mode air-gapped** (défaut ACTIF) : coupe TOUT appel réseau externe ; enrichissements inertes tant qu'il est actif. Bascule live via la pastille en-tête (Ollama local reste autorisé).
- **Sécurité** : pas de shell libre, validation stricte, secrets en keyring (jamais en clair/en dur), API liée à `127.0.0.1`, moindre privilège, actions système = dry-run + confirmation + undo + audit.
- **Tolérance aux pannes** : un module qui plante passe 🔴 sans faire tomber l'appli (watchdog).
- **Usage autorisé uniquement** (pentest/lab) ; disclaimer + audit.

---

## 2. Comment lancer (2 terminaux)
Prérequis : **Python 3.14** (lancer avec **`py`** ; la commande `python` est le stub MS Store), **Node 24**, git. nmap installé (`C:\Program Files (x86)\Nmap\`).

```
# Terminal 1 — moteur (depuis engine/)
cd engine
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8787

# Terminal 2 — dashboard (depuis ui/)
cd ui
npm run dev            # http://localhost:5173 (proxifie /api -> 127.0.0.1:8787)
```
Tests : `cd engine; .\.venv\Scripts\python.exe -m pytest -q` (**32 tests verts**).
Build UI : `cd ui; npm run build`. Scripts d'install : `setup.ps1` (Windows) / `setup.sh` (Linux).

---

## 3. Architecture
**Coquille** (`engine/app/core/`) stable qui accueille des **modules isolés** :
- `bus.py` : bus d'événements pub/sub (topic `log` surtout). Un abonné qui plante est isolé.
- `registry.py` : enregistre/démarre/arrête/liste les modules, sous supervision.
- `watchdog.py` : `supervise()` attrape tout crash d'un module → statut ERROR + log, appli continue.
- `modules/base.py` : **contrat de module** (`Module` : name/version/description/status, `start/stop/health/info`). Statuts : active / inactive / error / not_connected / not_installed.
- `runtime.py` : état mutable (air-gapped) modifiable sans redémarrer.
- `main.py` : `create_app()` FastAPI (lifespan démarre/arrête les modules), `register_modules()` construit et enregistre tout, + tous les endpoints.

**Modèle de déploiement** : app web locale. Moteur sur la machine ; dashboard dans le navigateur (mobile = consultation sur le LAN via l'adresse Network de Vite).

---

## 4. Stack
- **Backend** : Python 3.14 · FastAPI + Uvicorn · **psutil** (connexions/process natifs) · SQLModel/SQLite · **keyring** (clés chiffrées) · **maxminddb** (GeoIP) · httpx · pydantic.
- **Frontend** : React 18 + Vite 6 + TypeScript + Tailwind 4 (`@tailwindcss/vite`). Canvas maison pour toutes les visualisations (pas de lib graphe).
- Dépendances système : **nmap** (scan), **worldmap.jpg** (bundlé), base **GeoIP DB-IP** (`engine/data/dbip-city-lite.mmdb`, gitignore).

---

## 5. Backend — modules & endpoints
Ordre d'enregistrement dans `register_modules()` : diagnostic (1er, capte les logs), shield, bandwidth, scoring, persistence, trace, wifi, cracker, scan, hids, mail, connectors, intel, osint, llm, analytics. **~16 modules actifs.**

| Module (`engine/app/modules/`) | Rôle | Endpoints |
|---|---|---|
| `shield.py` | Connexions live psutil (PID→app, exe, lignée parent-enfant, DNS inverse via **threads DAEMON** + queue, loopback filtré) + `dns_resolved` (distingue « pas encore résolu » de « pas de PTR ») | `GET /shield/connections` (scored), `GET /shield/top-talkers` |
| `bandwidth.py` | Débit ↓/↑ via `net_io_counters` | `GET /bandwidth` |
| `scoring.py` + `scoring/` (rules, baseline, mitre) | Risque/connexion (règles : port sensible/non standard, DNS absent, process inconnu, exe %TEMP%, script host), sévérité safe/watch/suspect/crit, **corrélation MITRE**, score global 0-100 (bandes faible/elevee/critique) | `GET /exposure` |
| `diagnostic.py` | Journal (deque bornée, purgé à la fermeture), filtre date/heure, capte les logs du bus | `GET /diagnostic/logs`, `GET /diagnostic/logs/export` |
| `persistence.py` | Snapshots + audit SQLite (`engine/data/red.db`), budget ≤1 Go + rotation | `POST /snapshot`, `GET /history` |
| `report/markdown.py` | Rapport Markdown (vu→problème→correctif) | `GET /report/markdown` |
| `trace.py` | **Traceroute géolocalisé hors-ligne** : `tracert`/`traceroute` + GeoIP (maxminddb) + détection VPN (adaptateur : nord/tun/wireguard…) + IP publique. Background+cache. Localise la base par `__file__` | `GET /trace?target=`, `POST /trace/run` |
| `wifi.py` | **Audit WiFi** natif Windows (`netsh wlan show networks`) = alternative aircrack (scan, pas de crack). Message honnête si wlansvc arrêté | `GET /wifi/networks` |
| `cracker.py` | Cracker de hash dictionnaire (md5/sha1/sha256/pbkdf2), pur Python — repris du toolkit de la collègue | `POST /crack` |
| `scan.py` + `data/cve_local.json` | **Scan nmap** (`-sT -sV -Pn`, auto-localise nmap même hors PATH, parse XML, background+cache) + **CVE locale** (croisement service+version → NVD) + **OSI** (L4/L6/L7) + **conformité** CIS/ANSSI/NIST + **suggestions d'attaque** (sk-recon) | `GET /scan`, `POST /scan/run` |
| `hids.py` | **HIDS-lite** : `Get-WinEvent` (services 7045/7040, échecs 4625, comptes 4720, Defender 1116/1117, Sysmon 1/3). Security = admin requis (astuce affichée). Background+cache | `GET /hids`, `POST /hids/run` |
| `mail.py` | **Mail Security (.eml)** : parse SPF/DKIM/DMARC (Authentication-Results), désalignement From/Return-Path, liens suspects (IP/punycode/TLD), pièces jointes à risque → verdict+reasons+remédiation. Sans credential | `POST /mail/analyze` |
| `analytics.py` | **Beaconing C2** (intervalles réguliers d'apparition) + **timeline** (échantillonne shield+scoring toutes ~8s, diff apparition/fermeture/alerte). Reçoit shield+scoring en ctor | `GET /analytics/beaconing`, `GET /analytics/timeline` |
| `lan.py` | Découverte LAN (`arp -a`, IP/MAC/fabricant OUI partiel, multicast/broadcast filtrés) | `GET /lan/devices` |
| `firewall.py` | **Couper/autoriser** (`netsh advfirewall`), **dry-run** par défaut + admin pour appliquer + audit | `POST /firewall/block`, `POST /firewall/unblock`, `GET /firewall/rules` |
| `connectors.py` | Clés API chiffrées via **keyring** (service `RED-connectors`) : virustotal/abuseipdb/greynoise/shodan/llm | `GET /connectors`, `POST /connectors/{name}`, `DELETE /connectors/{name}` |
| `intel.py` | Réputation IP (VirusTotal + AbuseIPDB), gated air-gapped + clé | `GET /intel/ip?ip=` |
| `osint.py` | **OSINT passif** sous-domaines via **crt.sh** (sans clé), gated air-gapped | `POST /osint/subdomains` |
| `llm.py` | Analyse IA (Ollama local **ou** Anthropic/OpenAI). Config JSON en keyring (`llm`). Ollama autorisé sous air-gapped, API distantes non | `POST /llm/analyze` |
| — config/santé | air-gapped runtime + santé | `GET /health`, `GET /config`, `POST /config/airgapped`, `GET /modules` |

**Important — modèles de requête POST** : à cause de `from __future__ import annotations` dans `main.py`, les modèles Pydantic passés en body doivent être définis **au niveau module** (pas locaux dans `create_app`), sinon FastAPI les prend pour des query params. Modèles existants : `CrackRequest`, `MailRequest`, `FwRequest`, `ScanRequest`, `AirgapReq`, `KeyReq`, `OsintReq`, `LlmReq`.

---

## 6. Frontend (`ui/src/`)
- `main.tsx` → `App.tsx` (tout : barre du haut, nav, routage par onglet, composants).
- `api.ts` : client (`/api` proxifié), types, helpers `get`/`post`.
- `hooks.ts` : `usePolling(fn, intervalMs)`.
- `viz.tsx` : composants canvas — `Sparkline`, `BandwidthChart`, `NetworkGraph` (graphe réel, zoom/pan molette+glisser, survol=tooltip, clic=onSelect→traceroute, vue Entrant via trace), `TraceMap` (mappemonde image `worldmap.jpg` + hops géolocalisés + zoom/pan + destination pulsante + destLabel process). **Les canvas lisent les variables CSS (`--accent`…) à chaque frame → recolorés auto par le thème.**
- `index.css` : design system (variables `:root`), thèmes `[data-theme=...]`, polish (scrollbars, survols, focus, responsive).

**Onglets** (dans `TABS`) : Dashboard (bento + cartes déplaçables drag&drop + mini-carte + mini-traceroute + score + bande passante Débit/Top-process), Bouclier (table connexions + filtres dropdown + tri + recherche + export + snapshot), Carte réseau (graphe multi-vues Sortant/Entrant/Local/Tous + traceroute mondial), Remédiation (findings + MITRE + CutButton + ReputationButton), Recon & WiFi (scan nmap+CVE+OSI+conformité+suggestions+presets + audit WiFi + LAN + aircrack-note), Offensif (cracker + OSINT crt.sh), SOC local (Mail Security .eml + HIDS-lite), Connecteurs (clés keyring + LLM), Diagnostic (logs+filtre+timeline+beaconing+historique+réglages + analyse IA).
**Composants réutilisables** : `Card` (repliable, chevron en coin), `ThemeSelector`, `AiAnalyzeButton`, `ScanAiButton`, `CutButton`, `ReputationButton`, `Reorderable` (drag&drop, ordre en localStorage), `OsintCard`, `Gauge`, `ConnRow`.

**Thèmes live** (`ThemeSelector`, pastille en-tête) : `mix` (Teal, défaut), `aurora` (violet), `signal` (lime, plat), `holo` (cyan HUD). Persistés en localStorage (`red-theme`), appliqués via `data-theme` sur `<html>`.

---

## 7. État par jalon
- **J1 (MVP)** ✅ : bouclier, score+MITRE, bande passante, diagnostic+rétention, SQLite, export MD, dashboard.
- **J2** ✅ : traceroute mondial hors-ligne, beaconing, timeline, couper/autoriser, découverte LAN, drag&drop, graphe interactif, audit WiFi, connecteurs (threat-intel/OSINT/LLM + air-gapped toggle).
- **J3** ✅ : scan nmap + CVE→NVD + OSI + conformité CIS/ANSSI/NIST + suggestions d'attaque.
- **SOC local** ✅ : HIDS-lite (Event Log) + Mail Security (.eml).
- **Offensif** ✅ : cracker de hash + OSINT passif.
- **Analyse IA** ✅ : sur scan, logs Diagnostic, mail (via connecteur LLM Ollama/API).
- **UI** ✅ : style « mix moderne » (bento + verre givré + HUD), 4 thèmes live, harmonisée.

### Reste à faire (dépend de ressources/environnement)
- **aircrack** (capture/crack handshake) → **Linux + carte WiFi monitor** (impossible sous Windows).
- **Connecteurs SIEM/EDR** (Wazuh/Defender) → instances existantes à brancher.
- **Threat-intel / LLM distant** → l'utilisateur fournit ses **clés API** (onglet Connecteurs) + désactive air-gapped. **Je ne génère aucun compte/clé.** Ollama local = alternative gratuite hors-ligne.
- Idées discutées non construites : JA3/JA4, honeypot, GeoIP threat-map animée, profils/espaces de travail, packaging PyInstaller.

---

## 8. Pièges connus (à ne pas re-découvrir)
- **Python** : utiliser `py` / `engine\.venv\Scripts\python.exe`, jamais `python` (stub Store).
- **DNS inverse** : threads **daemon** (pas ThreadPoolExecutor) — sinon pytest se fige 120 s à la sortie (gethostbyaddr lents non-daemon joints par atexit).
- **curl + PowerShell** : `'{\"k\":\"v\"}'` en simple-quote garde parfois les `\` littéraux → JSON invalide. Utiliser `curl --data @fichier.json` ou le Bash tool pour tester les POST.
- **FastAPI + `from __future__ import annotations`** : modèles body au niveau module obligatoire (cf. §5).
- **WiFi** : `netsh wlan` renvoie 0 si le service **wlansvc** est arrêté (machine sur Ethernet) — c'est réel, pas un bug.
- **HIDS Security log (4625…)** : nécessite de lancer RED en **administrateur** ; sinon vide (astuce affichée).
- **firewall block/unblock** : nécessite l'**admin** pour appliquer réellement (dry-run marche sans).
- **Backend en arrière-plan** : `Start-Process -WindowStyle Hidden` a été instable ; préférer la tâche de fond (run_in_background) ou lancer dans un vrai terminal.
- **Fins de ligne** : warnings LF→CRLF à chaque commit (Windows), inoffensifs.

---

## 9. Où est quoi
- Docs : `spec.md` (spéc), `project-plan.md` (plan J1), `analysis.md` (concurrence + scoring des plus-values), `CONTRIBUTING.md` (conventions), **ce fichier**.
- Config : `.env.example` (copier en `.env`), `engine/config.py` (settings), `engine/app/runtime.py`.
- Prompts de travail : `prompts/` (les 5 prompts de brainstorming ; on utilise le style Prompt 3 « builder itératif »).
- Base CVE curée : `engine/data/cve_local.json`. Base GeoIP : `engine/data/dbip-city-lite.mmdb` (gitignore, ~130 Mo).
- Maquettes UI publiées en artifact durant le design (3 styles + vision finale v1→v6 + graphe animé) — historique, non nécessaires au code.

---

## 10. Historique git (22 commits, du plus récent au plus ancien)
```
a081e48 feat(ui): selecteur de theme live (Teal/Aurora/Signal/Holo)
d719a87 polish(ui): harmonisation des onglets
769182d polish(ui): scrollbars, survols, en-tetes, transitions, focus, responsive
82bd566 feat(ia): 'Analyser avec l'IA' sur logs Diagnostic + Mail
46bd339 feat(connecteurs): air-gapped runtime, connecteurs keyring, intel, OSINT, LLM, install
63c4bc2 feat(soc): HIDS-lite + Mail Security (.eml) + fix DNS threads daemon
187ffa0 feat(ui): apercu traceroute Dashboard, vue Entrant, tooltip air-gapped, presets scan
31ac136 feat(j3): scan enrichi OSI + conformite + suggestions d'attaque
a6cd82b feat(j3): scan nmap + CVE local + UI Recon
adbf046 feat(j2): beaconing+timeline, couper/autoriser, LAN, drag&drop
0d44c1d feat(j2): nodes cliquables->traceroute, mappemonde image, onglet Offensif (cracker)
23de654 feat(ui/j2): carte reseau fonctionnelle, traceroute monde, audit WiFi, retrait radar invente
f9c7d02 feat(j2): traceroute geolocalise + audit WiFi (netsh)
8621128 chore(deps): GeoIP DB-IP + maxminddb + A_INSTALLER
52b0d2b docs: guide de lancement + revue securite (J1 termine)
4176797 feat(ui): dashboard React (style mix) branche sur l'API reelle
6f728ab feat(engine): diagnostic+retention, SQLite, export Markdown
9cf8fbd feat(scoring): risque + MITRE + /exposure
6bab2e3 feat(shield): connexions live + bande passante
f8134f8 feat(engine): coquille modulaire + /health + /modules
23b51c5 chore: scaffold projet + conventions
```
*(Le repo n'a pas de remote GitHub configuré — local uniquement.)*

---

## 11. Reprendre : check-list rapide
1. Lancer moteur + UI (§2), ouvrir http://localhost:5173.
2. `pytest -q` doit être vert (32 tests).
3. Ajouter un module = créer `engine/app/modules/xxx.py` (hérite de `Module`), l'enregistrer dans `register_modules()`, ajouter l'endpoint dans `main.py` (modèle body au niveau module !), une méthode dans `ui/src/api.ts`, l'UI dans `App.tsx`, un test.
4. Respecter : zéro donnée inventée, gating air-gapped pour tout appel externe, keyring pour les secrets, actions système avec dry-run+confirm+undo.
