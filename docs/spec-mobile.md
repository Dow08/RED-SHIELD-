# Spec — RED SHIELD Mobile (outil de terrain)

_Issu du brainstorming du 2026-07-23. À valider avant tout code._

## Objectif (1 phrase)
Un **outil d'audit réseau de terrain** sur tablette/téléphone Android qui, en quelques minutes sur un réseau inconnu, **cartographie le réseau du client, en révèle les faiblesses, et produit le livrable** — le tout dans la même app que RED SHIELD desktop (même cerveau : scoring, MITRE, CVE, GRC, rapport).

## Persona & contexte
**Dorian / DP Cyber Consulting**, en **mission de consulting** sur site client. Trois usages, tous actifs :
1. **Audit assis avec le client** — écran démonstratif, temps réel (effet pédagogie/vente) ;
2. **Balade discrète** — collecte rapide et silencieuse en se déplaçant ;
3. **Poste posé** — la tablette branchée capture/scanne pendant qu'il fait autre chose.

## Le fil rouge (anti-dispersion)
Même principe que le desktop : **capteurs → cerveau → livrable**. Le mobile ajoute un nouveau **capteur natif**, il ne réinvente ni le scoring, ni le rapport, ni le GRC (déjà construits).

## ⚠️ La vérité technique à acter
Le moteur mobile actuel est du **TypeScript dans une WebView** → il ne peut PAS ouvrir de sockets TCP, scanner des ports, ni capturer le trafic. **Tout ce qui suit exige une couche native** :
- **Rust** (plugin Tauri v2 mobile) pour le recon réseau — marche **sans root** ;
- **Kotlin** pour la capture VpnService (spécifique Android) ;
- l'**offensif WiFi** (aircrack) exige **root + NetHunter + dongle WiFi USB** → on **orchestre** les outils existants, on ne les réécrit pas.
C'est le vrai chantier : la couche native. Le reste est déjà là.

## Fonctionnalités — priorisation MoSCoW
**MUST (v1)**
- **Couche recon native (Rust)** : socle du plugin Tauri mobile.
- **Cartographie du réseau** : découverte des hôtes (TCP connect + **mDNS/SSDP/UPnP**), **scan de ports**, **empreinte des services** (bannières), **estimation d'OS**, identification IoT/NAS/imprimantes/caméras.
- **Énumération web** (façon **ffuf/gobuster**) : sur chaque service HTTP(S) trouvé → brute-force **répertoires / vhosts** (wordlist embarquée) — pur HTTP, sans root.
- **Branchement au cerveau** : scoring, sévérité, affichage carte/liste (réutilise l'onglet Recon).

**SHOULD**
- **Audit TLS** des services (émetteur, expiration, algos faibles).
- **Posture WiFi** : réseaux à portée, chiffrement (ouvert/WEP/WPA2/WPA3), faiblesses (lecture, non-offensif).
- **Croisement CVE** (NVD en ligne) sur les services/versions détectés.
- **Rapport de mission sur mobile** (réutilise le générateur déjà construit).

**COULD**
- **Capture de trafic** (VpnService, Kotlin) : ce que les apps de la tablette envoient — Bouclier mobile.
- Fingerprinting appareil, géoloc IP, export brut.

**WON'T (v1 — plus tard, tier « rooté »)**
- **Crack WiFi / injection / déauth** (aircrack) : réservé à l'extension **root + NetHunter + dongle**.

## Contrainte structurante — build progressif
**Une seule app** :
- **tier « stock »** (tablette non rootée) : tout le MUST + SHOULD + COULD ci-dessus ;
- **tier « rooté »** (détecté au lancement) : débloque l'offensif WiFi en orchestrant NetHunter/aircrack.

## Stack
- **UI** : React existant, empaqueté **Tauri v2 Android** (réutilise onglets Recon + Rapport, adaptés mobile).
- **Natif recon** : **plugin Tauri v2 en Rust** (commandes : scan TCP, mDNS/SSDP, HTTP enum, TLS, WiFi info).
- **Capture** : Kotlin/VpnService (COULD).
- **Réutilisé tel quel** : scoring, MITRE, CVE/NVD, GRC, générateur de rapport, thème.

## Architecture
```
[ Plugin natif Rust ]  →  commandes recon (scan, mDNS, http-enum, tls, wifi)
        │  (Tauri invoke)
[ UI React (Android) ]  →  Recon (carte/liste) + Rapport
        │
[ Cerveau partagé ]  scoring · MITRE · CVE · GRC · rapport   (déjà écrit)
```

## Modèle de données (recon mobile)
- **Host** { ip, mac?, vendor?, hostname?, os_guess?, source(mdns/ssdp/tcp) }
- **Service** { host, port, proto, service, product?, version?, banner?, tls? }
- **WebFinding** { url, status, type(dir/vhost), size }  ← énumération
- **WifiNet** { ssid, bssid, channel, auth, signal, risk }
- **TlsInfo** { host, port, issuer, not_after, weak[] }
Ces objets alimentent le scoring/rapport existants (mêmes formes que le desktop autant que possible).

## Jalons (3 max, du plus simple au plus complet)
### Jalon M1 — Le socle « je vois le réseau » _(non rooté)_
Plugin Rust + **cartographie** (hôtes via TCP+mDNS/SSDP, ports, empreinte service, OS-guess), affichée sur carte/liste.
**Acceptation** : sur un réseau test, l'app liste les hôtes actifs + leurs ports/services ouverts en < 3 min, sur tablette non rootée.

### Jalon M2 — La profondeur « je vois ce que Fing ne voit pas »
**Énumération web** (ffuf/gobuster-lite) + **audit TLS** + **posture WiFi** + **croisement CVE**.
**Acceptation** : sur un service web de test, l'app remonte des chemins découverts + un verdict TLS ; un service versionné remonte ses CVE.

### Jalon M3 — Le livrable « rapport depuis le terrain »
**Rapport de mission sur mobile** (réutilise le générateur) + capture **VpnService** (option).
**Acceptation** : depuis une collecte, l'app génère le PDF DP Cyber Consulting sur l'appareil.

### Extension (hors 3 jalons) — Offensif rooté
Orchestration aircrack/NetHunter si environnement rooté détecté. Cadré, journalisé, périmètre autorisé.

## Critères de succès (mesurables)
- **Vitesse** : carte complète du réseau en **< 2-3 min**.
- **Profondeur** : détecte IoT/caméra/NAS + service exposé + CVE + WiFi faible **là où Fing s'arrête à la liste d'IP**.
- **Livrable** : rapport client prêt **sans repasser par le PC**.
- **Démo** : le client comprend son risque en regardant l'écran.

## Risques
- **Couche native Tauri mobile** = le vrai coût/inconnu (plugin Rust Android à mettre en place, tester on-device).
- **Limites Android** (ARP verrouillé ≥10, throttle scan WiFi ≥9) → contournés par sondage actif.
- **Cadre légal** : scan sur réseau tiers = autorisation écrite obligatoire (garde-fou périmètre déjà conçu, à porter sur mobile).
- **Build APK** : via CI (SDK/NDK), déjà câblé.
