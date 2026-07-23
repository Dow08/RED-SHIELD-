# RED SHIELD — version mobile (téléphone / tablette)

> Moteur **autonome embarqué** : tourne entièrement sur l'appareil, **sans serveur**, y compris
> hors-ligne. Coquille **Tauri v2 (Android/iOS)**, logique métier en **TypeScript** exécutée dans
> l'app. Build en CI (le toolchain mobile ne s'installe pas sur la machine de dev).

## Pourquoi ce choix d'architecture
Deux contraintes **dures**, pas des choix :
1. **Sandbox iOS/Android** : une app ne peut PAS voir les connexions des *autres* applications,
   capturer les paquets système, lire le registre ni piloter le pare-feu. Le cœur « surveillance
   système » du desktop est donc **impossible** sur mobile — on n'invente pas une capacité bloquée par l'OS.
2. **Compilation Rust indisponible en local** (Smart App Control bloque les build-scripts). Un gros
   moteur Rust mobile serait **non testable** → contraire à la règle « tout vérifié ».

➡️ Le moteur mobile = **fonctions calculatoires portées en TypeScript** (`ui/src/mobile/offline.ts`),
pures, **testées (Vitest)**, exécutées dans la WebView de l'appareil. 100 % autonome et hors-ligne.

## Périmètre mobile (réaliste et factuel)
**Faisable sur l'appareil (implémenté / prévu) :**
- ✅ **Analyse anti-phishing d'un mail** (.eml partagé/collé) — SPF/DKIM/DMARC, alignement, liens & pièces jointes suspects. *(fait, testé)*
- ✅ **Cracker de hash** md5/sha1/sha256/sha512 (Web Crypto + MD5 local). *(fait, testé)*
- ⏳ **CVE** : recherche produit/version dans la base locale embarquée.
- ⏳ **Threat-intel / OSINT** (air-gapped OFF) : réputation IP, sous-domaines.
- ⏳ **Posture réseau propre à l'appareil** : SSID Wi-Fi (permission), IP publique, DNS.

**Impossible sur mobile (sandbox) — reste desktop :**
- ❌ Connexions/écoute des autres apps, capture pktmon, pare-feu, registre, HIDS, bilan santé disque.

## Fonctionnement du repli
`api.mailAnalyze` et `api.crack` tentent d'abord le moteur (desktop) ; s'il est absent (cas mobile)
ils basculent **automatiquement** sur le moteur local `offline.ts`. Même UI, résultat identique.

## Build (CI)
- Cible **Android** : `tauri android init` puis `tauri android build` (nécessite Android Studio + SDK + NDK,
  et `rustup target add aarch64-linux-android …`). Fait sur un runner CI (workflow à ajouter :
  `build-mobile.yml`, sur le modèle de `build-desktop.yml`).
- **iOS** : nécessite macOS + Xcode (build sur runner macOS).
- L'UI est adaptée « mobile » (onglets desktop-only masqués) selon la plateforme détectée.

## Tests
```bash
cd ui && npm test      # Vitest : moteur hors-ligne (mail, hash)
```
