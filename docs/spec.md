# Red — Spécification (spec.md)

> Statut : **validée pour build** (Prompt 1, étapes 2-3).
> Design retenu : **RED Shield — variante A hybridée** (score conception 10/10, cf. `analysis.md`).
> Style visuel retenu : **02 · Command Center (SOC)**.
> Dernière mise à jour : 2026-07-19.

---

## 1. Objectif & persona

**Objectif (1 phrase)**
Red est un **bouclier réseau modulaire** (red + blue) qui observe en temps réel toutes les connexions d'une machine, les note, les explique, propose des remédiations priorisées, et s'étend par modules (recon offensif, graphe, connecteurs SIEM/EDR) — le tout dans un dashboard sombre, lisible et responsive.

**Persona principal**
Pentester / analyste en reconversion cyber (profil red + blue) qui veut, en mission autorisée ou en lab, passer vite d'un résultat brut à une décision : *« qu'est-ce qui parle à quoi, est-ce légitime, quel risque, quoi corriger d'abord »*.

**Positionnement (ce qui différencie Red)**
- Ne recrache pas une liste brute : il **priorise et raconte**.
- **Red + Blue réunis** avec double lecture (attaquant / protection).
- **Score d'exposition unique** (0-100) mémorable.
- **Rapport Markdown orienté remédiation**, lisible par un humain ET par une IA.
- **Architecture modulaire tolérante aux pannes** : chaque brique vit et meurt seule.

---

## 2. Cadre d'usage & principes non négociables

- Usage **strictement sur cibles/machines autorisées** (propriété ou autorisation écrite).
- **Disclaimer** au lancement + **journal d'audit** (qui a fait quoi, quand).
- **Mode air-gapped** (interrupteur global) : coupe tout appel externe ; aucune donnée envoyée à un tiers.
- **Règle dure « zéro donnée inventée »** : un module affiche du réel ou l'état `non connecté`. Jamais de fausse donnée de démo.
- **Tout testé de bout en bout** : une brique n'est « livrée » que si elle fonctionne réellement.
- Clés API **chiffrées** (keyring), masquées dans l'UI, jamais en dur.
- Modules privilégiés (couper une connexion, WiFi/capture) **isolés**, confirmés, réversibles.

---

## 3. Architecture modulaire (cœur du design)

**Principe** : une **coquille** stable accueille des **modules** indépendants.

```
            ┌─────────────────────────────────────────┐
            │              DASHBOARD (React)           │
            │  onglets · cartes modules · drag&drop    │
            └───────────────┬─────────────────────────┘
                            │ REST + WebSocket
            ┌───────────────┴─────────────────────────┐
            │            COQUILLE (FastAPI)            │
            │  Registre de modules · Bus d'événements  │
            │  Watchdog (superviseur) · Audit · Config │
            └───┬───────┬───────┬───────┬───────┬──────┘
                │       │       │       │       │
             ┌──┴─┐  ┌──┴─┐  ┌──┴─┐  ┌──┴─┐  ┌──┴─┐   ← chaque module isolé
             │Bouc│  │Diag│  │Répu│  │Recon│ │SIEM│      (frontière d'erreur)
             │lier│  │nost│  │tati│  │nmap │ │/EDR│
             └────┘  └────┘  └────┘  └────┘  └────┘
```

**Contrat de module (manifeste)** — chaque module déclare :
- `name`, `version`, `description`
- `status` : 🟢 `active` / 🔴 `error` / ⚪ `not_connected` / ⚪ `not_installed`
- `produces` / `consumes` (ce qu'il publie / lit sur le bus)
- `health()` : auto-diagnostic
- `requires` : dépendances (outil externe, clé API, privilège)

**Garanties**
- Les modules **ne s'appellent pas directement** : ils passent par le **bus d'événements**.
- Le **watchdog** attrape tout crash d'un module, le journalise, marque son état 🔴 — **l'appli entière ne tombe jamais**.
- Ajouter un module futur = implémenter le contrat + s'enregistrer. Rien d'autre à toucher.

---

## 4. Stack technique (figée)

| Couche | Choix | Justification |
|--------|-------|---------------|
| Backend / coquille | **Python 3.11 + FastAPI + Uvicorn** | Écosystème sécu riche, REST + WebSocket natif, lisible en vibe coding |
| Accès réseau natif | **psutil** | Connexions + process + PID, identique Windows/Linux, sans privilège lourd |
| Wrappers outils | `subprocess` (nmap, gobuster, PowerShell) | On enveloppe l'existant, on ne réinvente rien |
| Base de données | **SQLite** (SQLModel/SQLAlchemy) | Fichier unique, zéro config, historique/projets |
| Frontend | **React + Vite + TypeScript + Tailwind** | Rapide, thème sombre facile, vibe-coding friendly |
| Jauge / charts | **Recharts** | Score, sparklines, rendu sombre soigné |
| Graphe réseau | **Cytoscape.js** | Graphe interactif nœuds/liens (J2) |
| Modules déplaçables | **react-grid-layout** | Dashboard personnalisable, layout sauvegardé (J2) |
| Clés API | **keyring** + chiffrement local | Secrets jamais en clair |
| Packaging (plus tard) | PyInstaller (+ wrapper Tauri éventuel) | Distribuable en 1 exécutable |

**Modèle de déploiement** : app web locale. Le moteur tourne sur la machine (Windows/Linux) ; le dashboard s'ouvre dans le navigateur, **y compris depuis mobile/tablette sur le réseau local** (consultation). Le mobile ne fait jamais tourner le moteur.

---

## 5. Style visuel — Mix moderne (bento + verre givré + touches HUD)

> Style retenu après exploration de 3 directions ultra-modernes (Aurora Glass / Bento Signal / Holo HUD). **Les radars/visualisations (radar réseau, graphe, bande passante, carte du monde) restent inchangés** — seul l'habillage de l'interface est modernisé.
- **Layout bento** (grille modulaire asymétrique) — clair et moderne.
- **Cartes en verre givré** (glassmorphism : `backdrop-filter` + translucide) sur fond sombre avec **orbes de gradient ambiants** (teal/violet/bleu, subtils).
- **Équerres HUD** discrètes aux coins + **labels monospace** en petites capitales espacées (identité cyber).
- Palette : fond **teal-black** (#080a0f), accent **cyan/teal** (#2fe0d0), **rouge** conservé pour la marque RED ; sémantique **vert** = sain / **ambre** = à surveiller / **rouge** = critique.
- Performance : `backdrop-filter` coûteux GPU → prévoir un repli sans flou sur matériel modeste.
- **À appliquer** à la maquette de travail complète (encore en style Command Center) une fois la direction validée.
- Onglets : **Dashboard** (récap, J1) · **Bouclier** (J1) · **Carte réseau** (J2) · **Remédiation** (J1/J2) · **Recon &amp; WiFi** (J3/J4) · **Connecteurs** (J2) · **Diagnostic &amp; réglages** (J1).
- **Dashboard** = cockpit : score, bande passante (Débit/Top process), aperçu connexions, mini-carte, santé modules, top remédiations, journal récent — chaque bloc renvoie à son onglet.
- Le **tracé de connexion (traceroute sur carte du monde, hors-ligne)** vit dans l'onglet **Carte réseau** (sous le graphe), pas sur le Dashboard.
- **Panneaux repliables** : chaque carte/panneau se cache/réaffiche via une flèche (▾/▸) — l'utilisateur compose sa vue.
- Responsive : grille qui passe en 1 colonne sur mobile.
- Réf. visuelle : maquette publiée (style 02).

**Module Graphe réseau (J2) — direction visuelle validée**
- Inspiration : **carte neurale** (nœud "cet appareil" à gauche irradiant vers l'amas d'endpoints, fond blueprint, équerres, libellés monospace) + **flux animé façon FortiView/FortiGate** (particules circulant sur les arêtes = trafic temps réel, pulsation rouge sur les liens suspects).
- Couleur **sémantique** (vert sain / or à surveiller / rouge suspect), pas l'or/cyan de la référence.
- Implémentation retenue : **Cytoscape.js** (graphe interactif : layout, zoom, clic → détail) + **couche Canvas** par-dessus pour les particules de flux.
- Maquette animée de référence publiée en artifact.

---

## 6. Modèle de données

**Project** — `id`, `name`, `description`, `created_at`
**Host** — `id`, `project_id`, `address`, `label`, `authorized` (bool + note), `os`, `created_at`
**Snapshot** — `id`, `host_id`, `taken_at`, `exposure_score` (0-100), `source` (bouclier/recon)
**Connection** — `id`, `snapshot_id`, `pid`, `process`, `exe_path`, `local_addr`, `remote_addr`, `remote_dns`, `port`, `protocol`, `geo`, `risk` (0-100), `severity` (safe/watch/suspect/crit), `verdict_reason`
**Finding** — `id`, `snapshot_id`, `osi_layer`, `type`, `detail` (recon, J3)
**Cve** — `id`, `finding_id`, `cve_id`, `cvss`, `severity`, `summary`, `remediation_url` (J3)
**Connector** — `id`, `kind` (virustotal/wazuh/…), `status`, `key_ref` (référence keyring, jamais la clé)
**ModuleState** — `id`, `name`, `status`, `last_health`, `message`
**AuditLog** — `id`, `action`, `target`, `mode`, `timestamp`, `user`
**AppLog** — `id`, `level` (info/warn/error), `module`, `message`, `timestamp` (module Diagnostic)

---

## 7. Modèle de score

**Score global 0-100** (plus haut = plus exposé). Bandes : **0-30 vert**, **31-70 or**, **71-100 rouge**.
**Score par connexion** (façon CVSS), à partir de règles au départ, enrichi par la réputation (J2) :
- Port sensible / non standard, absence de DNS, destination géo/ASN à risque, process inconnu, écart à la baseline utilisateur.
J3 ajoute la dimension vulnérabilités (CVE pondérées CVSS) + OSI + TLS + firewall/DNS.

---

## 8. Jalons

### Jalon 1 — MVP « Bouclier local » (observation)
Coquille modulaire + module **Bouclier** (connexions live via psutil : **résolution PID → application** nom+chemin, IP, DNS, port) + **onglet Dashboard récapitulatif** (1er onglet : cockpit synthétisant tous les autres onglets, avec liens vers chacun) + module **Bande passante** (↓/↑ temps réel via `net_io_counters`, **sous-onglets Débit / Top process** = processus les plus consommateurs) + **score par connexion** (règles + baseline) + **score global** + **filtres/tri via menu déroulant à cocher** (tout coché par défaut : sévérité + colonnes risque/géo/port/DNS + recherche) + **corrélation MITRE de base** (tags ATT&CK auto : port 4444/C2, port non standard sans DNS, script depuis %TEMP%, process non identifié) + **onglet Remédiation dédié** (explications détaillées + étapes) + **module Diagnostic** (logs/erreurs, visionneuse, filtre date/heure, téléchargement) + **arbre de processus parent-enfant** (lignée via psutil ppid, dégradation gracieuse) + **mode « explique-moi » de base** (bibliothèque d'explications statiques) + **historique SQLite** + **export rapport Markdown** + disclaimer/audit + thème Command Center responsive **avec pages dédiées par onglet**. **Natif Windows, zéro privilège lourd, aucune cible tierce.**

**Critères d'acceptation**
- Depuis le dashboard (y compris mobile via le réseau local), je vois en temps réel toutes les connexions de ma machine : process, PID, IP/DNS distant, port, score de risque, sévérité colorée.
- Je **filtre et trie** la liste (désactiver des sévérités, masquer des colonnes, rechercher) pour affiner quand il y a trop de lignes.
- Une connexion à motif connu (ex. port 4444 vers IP sans DNS) reçoit un **tag MITRE ATT&CK** ; un PID non identifié déclenche une **tentative de corrélation** (accès inhabituel / C2).
- Un score global 0-100 coloré + 3 remédiations priorisées s'affichent.
- Un module qui échoue passe 🔴 **sans faire tomber le reste**.
- J'exporte un **rapport Markdown** structuré (vu → problème → correctif).
- Historique consultable ; **journal filtrable par date/heure** ; disclaimer + audit présents ; mode air-gapped actif par défaut.
- Aucune donnée inventée ; tout testé de bout en bout.

### Jalon 2 — « Contexte & action »
Graphe réseau (Cytoscape + couche Canvas de flux) avec **vues sélectionnables : Sortant / Entrant / Local (LAN) / Tous** + **résolution DNS affichée sur chaque endpoint** (nom résolu plutôt qu'IP brute) + **module Tracé de connexion (traceroute) sur carte du monde** (chaque saut appareil → passerelle → FAI → VPN → destination **géolocalisé et affiché à sa position sur une mappemonde**, avec **IP publique** et **détection/statut VPN**). **100 % hors-ligne / sans API externe** : géoloc via **base IP embarquée** (MaxMind GeoLite2-City ou DB-IP Lite / IP2Location LITE, `.mmdb`/CSV, lookups locaux) + fond de carte **GeoJSON Natural Earth embarqué** (projection équirectangulaire, aucune tuile externe). IP publique déduite du trace lui-même / de l'interface VPN (pas de service « what's my IP »). Le seul accès réseau optionnel est le **rafraîchissement périodique de la base** (téléchargement d'un fichier, jamais une requête par lookup) → **entièrement compatible air-gapped au runtime**. + rafraîchissement temps réel (WebSocket) + **module Découverte LAN** (balayage du sous-réseau autorisé → endpoints WiFi/LAN sur la carte, avec **IP/MAC/fabricant** + alertes connexion/déconnexion + appareils non approuvés, inspiré NetGuard) + **agrégation DNS** + **onglet Connecteurs** (clés chiffrées) + **réputation VirusTotal/AbuseIPDB/Shodan** + géo/ASN + **action couper/autoriser** (confirm + undo) + whitelist + **diff temporel** + bouton **« explique-moi »** + **modules déplaçables** (react-grid-layout) + profils/espaces de travail.
Plus-values NDR/SOC (garde-fous inscrits au §14) : **détection de beaconing C2** (seuil + whitelist), **baseline comportementale** (fenêtre d'apprentissage), **analytics DNS de base** (DGA/domaines récents, heuristiques + whitelist), **score threat-intel unifié** (VT/AbuseIPDB/GreyNoise/Shodan, air-gapped + cache), **timeline / rejeu d'incident**, **SOAR-lite** (confinement 1 clic : kill+block+quarantaine, avec dry-run + confirm + undo + audit), **rapport IA embarqué** (opt-in, coupé par air-gapped, option LLM local).

**Critères d'acceptation**
- Graphe « qui parle à quoi » avec code couleur risque, flux animé, et **sélecteur de vue (Sortant/Entrant/Local/Tous)**.
- Le beaconing, la baseline et l'analytics DNS produisent des alertes tunables (seuils + whitelist) sans faux positifs bloquants.
- Le rapport IA et le threat-intel restent **inertes tant que le mode air-gapped est actif**.
- Toute action SOAR-lite affiche un aperçu, demande confirmation, est réversible et journalisée.
- Sur un WiFi/LAN autorisé, tous les endpoints découverts apparaissent (IP/MAC/fabricant) ; un appareil inconnu est signalé.
- Couper/autoriser une connexion demande confirmation et est réversible + journalisé.
- VirusTotal ne s'active que si air-gapped désactivé + clé fournie.
- Je réarrange les modules et le layout est sauvegardé.

### Jalon 3 — « Volet offensif »
Wrapper **nmap** (ports/services/versions/OS) + **décomposition OSI** + **CVE** (locale + NVD, **lien auto vers la fiche NVD**) + **TLS** + firewall/DNS + mapping **MITRE ATT&CK** + score d'exposition enrichi.
Plus-values NDR/SOC (garde-fous au §14) : **mapping conformité CIS / ANSSI / NIST** (tables curées, mention « indicatif »), **beaconing C2 complet** et **baseline comportementale complète** (enrichis par l'historique).

**Critères d'acceptation**
- Scan d'une cible autorisée → findings OSI + CVE triées (chacune liée à sa fiche NVD) + technique ATT&CK cliquable + score mis à jour.
- Chaque finding est relié à un contrôle CIS/ANSSI/NIST (indicatif) le cas échéant.

### Jalon 4 — « Modules avancés » (isolés)
Suggestions **AI/LLM contextuelles** (MITRE ATLAS + prompt-injection) · **WiFi/aircrack** (Linux + carte monitor, **avec auto-test du service** : vérifie interface monitor + dépendances + cible autorisée avant toute action, et signale si non opérationnel) · **gobuster** · connecteurs **SIEM/EDR** (Wazuh, Defender…) · flux temps réel avancé · **speed test intégré** (ping/download/upload) et **scan de ports par appareil LAN** (idées reprises de NetGuard).

> **Source d'inspiration** : dépôt existant de l'utilisateur `Dow08/AI-Automation/netguard-surveillance` (Flask, monitoring Freebox) — réutilisation des idées : bande passante live, MAC/fabricant, agrégation DNS, alertes connexion/déconnexion, rétention locale, speed test.

**Critères d'acceptation**
- Chaque module activable/désactivable indépendamment, vérifie son environnement avant de tourner, affiche `non connecté`/`non installé` si indisponible.

---

## 9. Retiré du périmètre (traçabilité)
- **Optimisation / libération mémoire de l'hôte** → hors périmètre sécurité, risqué, dilue l'identité. **Retiré.**
- **Reconfiguration réseau automatique** → transformée en **recommandations** (l'outil conseille, ne reconfigure pas seul).

---

## 10. Points de vigilance actés
- Exécution privilégiée isolée, **liste blanche de commandes**, jamais de shell libre depuis l'UI.
- Multi-OS : Linux complet ; Windows sous-ensemble (bouclier, recon, dashboard) ; WiFi/capture = Linux only.
- Mobile = consultation ; moteur toujours sur la machine.
- APIs externes opt-in, clés chiffrées, coupées par le mode air-gapped.
- Faux positifs : règles + réputation + baseline, pas de « détection magique ».

## 11. Exigences non fonctionnelles — sécurité & performance (contraintes dures)
> L'outil manipule des accès réseau et parfois administrateur : il ne doit **jamais** devenir lui-même un risque ou un ralentissement.
- **Sécurité** : validation stricte des entrées, aucune exécution shell libre, principe du moindre privilège (n'élever les droits que pour l'action précise qui l'exige, jamais globalement), liste blanche de commandes, secrets en keyring/chiffrés, API locale liée à `127.0.0.1` par défaut (exposition LAN opt-in + jeton), en-têtes de sécurité, dépendances auditées.
- **Performance** : lecture des connexions **asynchrone** + échantillonnage (intervalle configurable), pas de blocage de l'UI, résolution DNS/géo en cache, traitement en tâche de fond, budget CPU/mémoire raisonnable. Le bouclier ne doit pas ralentir la machine hôte.
- **Isolation** : un module lourd/lent ne bloque pas les autres (bus + tâches supervisées).

## 12. Installation & mise à jour
- **Installation** simple (script de setup + dépendances) ; packaging visé en 1 exécutable (PyInstaller) plus tard.
- **Mise à jour directe sans tout réinstaller** : deux voies possibles, au choix de l'utilisateur —
  1. **MAJ des dépendances / du code** en place (git pull / pip + build UI), ou
  2. **re-téléchargement du client** puis réinstallation propre si l'utilisateur le décide.
- Vérification de version au démarrage (opt-in, respecte le mode air-gapped) + changelog.
- Aucune MAJ silencieuse : toujours confirmée par l'utilisateur.

## 13. Rétention & stockage des journaux
- **Filtre par date/heure** pour ne consulter que la fenêtre utile (pas de relevé intégral forcé).
- **Purge à la fermeture de l'application** (journal de session), activable/désactivable.
- **Budget de stockage local ≤ 1 Go** sur l'appareil : rotation automatique (éviction du plus ancien) + indicateur d'usage dans l'UI.
- Distinction : logs applicatifs/erreurs (éphémères, purgeables) vs historique de snapshots (persistant pour le diff, soumis au même budget global).

## 14. Plus-values NDR/SOC retenues (score 9-10) & garde-fous
> Sélectionnées via la boucle de scoring (cf. `analysis.md §7`) après vérification des frictions. Aucune friction bloquante ; chaque garde-fou est inscrit ci-dessous.

| # | Plus-value | Jalon | Garde-fou intégré (friction neutralisée) |
|---|-----------|-------|------------------------------------------|
| 1 | Détection de beaconing C2 (intervalles réguliers) | J2 (base) / J3 (complet) | Seuil réglable + whitelist + « nécessite N relevés » |
| 2 | Rapport IA embarqué (synthèse + remédiation) | J2 | **Opt-in**, coupé par air-gapped, option **LLM local** (Ollama), jamais par défaut |
| 3 | Score threat-intel unifié (VT/AbuseIPDB/GreyNoise/Shodan) | J2 | Air-gapped + cache + opt-in + états « non connecté » |
| 4 | Mapping conformité CIS / ANSSI / NIST | J3 | Tables curées, mention « indicatif », IDs de contrôle cités |
| 5 | SOAR-lite : confinement 1 clic + playbooks | J2 | **Dry-run + confirmation + annulation + audit**, moindre privilège |
| 6 | Baseline comportementale par process | J2 (base) / J3 (complet) | Fenêtre d'apprentissage + état « en apprentissage » + seuils |
| 7 | Analytics DNS (DGA + tunneling + domaines récents) | J2 | Heuristiques + whitelist ; tunneling avancé (privilège) différé |
| 8 | Arbre de processus parent-enfant | **J1** | Dégradation gracieuse si process protégé (sans admin) |
| 9 | Timeline / rejeu d'incident | J2 | Profondeur bornée par le budget 1 Go (rétention configurable) |
| 10 | Mode pédagogique « explique-moi » + ATT&CK | J1 (base) / J2 (enrichi) | Bibliothèque d'explications **statiques** ; LLM optionnel (mêmes garde-fous que #2) |

**Principe transverse** : toute plus-value qui appelle un service externe (2, 3, 10-LLM) est **inerte sous air-gapped** ; toute plus-value qui agit sur le système (5) exige aperçu + confirmation + annulation + audit.
