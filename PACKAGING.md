# RED SHIELD — Packaging en application native (Tauri v2)

> **État :** plan prêt à dérouler. Le build réel nécessite d'installer le **toolchain Rust**
> (+ outils de build MSVC ; + Android SDK/NDK pour le mobile) — non installé automatiquement
> pour éviter un changement système lourd sans validation. Suis les étapes ci-dessous.

## 🎯 Objectif
Transformer RED SHIELD en **vraie application** :
- fenêtre native dédiée, **sans navigateur ni `localhost` visibles** pour l'utilisateur ;
- **deux exécutables** : desktop (Windows prioritaire, puis Linux) et **mobile** (Android/iOS) ;
- **lancement au démarrage** de Windows + exécution en **administrateur** (pour pktmon / pare-feu).

## 🧱 Architecture retenue
```
┌─────────────────────────── Fenêtre Tauri (Rust, léger) ───────────────────────────┐
│  WebView (WebView2 sur Windows) → charge l'UI React buildée (ui/dist)               │
│         │  appels /api                                                              │
│         ▼                                                                            │
│  Sidecar « moteur » = backend Python empaqueté (PyInstaller) lancé par Tauri        │
│  écoute sur 127.0.0.1:8787 EN INTERNE (encapsulé, invisible pour l'utilisateur)     │
└─────────────────────────────────────────────────────────────────────────────────────┘
```
- **Frontend Tauri** = `ui/dist` (déjà produit par `npm run build`).
- **Backend** = moteur FastAPI empaqueté en binaire via **PyInstaller**, déclaré comme
  **sidecar** (`bundle.externalBin`) que Tauri démarre/arrête avec la fenêtre.
- L'UI continue de parler à `http://127.0.0.1:8787/api` — mais c'est **interne à l'app**,
  l'utilisateur ne voit jamais d'URL.

## ✅ Prérequis à installer

### Desktop (Windows)
1. **Rust** : https://rustup.rs (`rustup-init.exe`) → installe `rustc` + `cargo`.
2. **Visual Studio Build Tools** (charge de travail « Développement Desktop C++ » → MSVC + Windows SDK).
3. **WebView2** : préinstallé sur Windows 11 (sinon Evergreen Runtime de Microsoft).
4. **Node.js** : déjà présent (v24).
5. **PyInstaller** : `engine/.venv/Scripts/python.exe -m pip install pyinstaller`.

### Desktop (Linux — plus tard)
`libwebkit2gtk-4.1-dev`, `build-essential`, `libssl-dev`, `librsvg2-dev`, patchelf.

### Mobile
- **Android** : Android Studio + SDK + **NDK** ; cibles Rust :
  `rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android`.
- **iOS** : **macOS + Xcode** obligatoires (pas de build iOS depuis Windows).
- ⚠️ Le sidecar Python n'est pas trivial sur mobile : prévoir soit un moteur réécrit/allégé,
  soit un mode « consultation » mobile se connectant au moteur desktop sur le LAN (opt-in + jeton),
  conforme au plan initial (« mobile = consultation »).

## 🚀 Étapes (desktop Windows)

### 1. Empaqueter le moteur en sidecar (PyInstaller)
```powershell
cd engine
.venv\Scripts\python.exe -m PyInstaller --onefile --name red-engine `
  --collect-all app --add-data "data;data" run_engine.py
# → dist/red-engine.exe  (à copier en src-tauri/binaries/red-engine-x86_64-pc-windows-msvc.exe)
```
*(`run_engine.py` = petit lanceur : `uvicorn.run("app.main:app", host="127.0.0.1", port=8787)`.)*

### 2. Initialiser Tauri v2 dans le repo
```powershell
npm create tauri-app@latest        # ou : cargo install tauri-cli ; cargo tauri init
# frontendDist = ../ui/dist ; devUrl = http://localhost:5173
```

### 3. Déclarer le sidecar + l'élévation admin (src-tauri/tauri.conf.json)
```jsonc
{
  "bundle": {
    "externalBin": ["binaries/red-engine"],
    "windows": { "webviewInstallMode": { "type": "embedBootstrapper" } }
  },
  "app": { "windows": [{ "title": "RED SHIELD", "width": 1400, "height": 900 }] }
}
```
- **Admin** : ajouter un manifeste UAC `requireAdministrator` (via `tauri.conf` › bundle ›
  windows › `nsis`/`wix`, ou un manifest embarqué) pour que l'app se lance élevée.
- **Icône** : réutiliser `ui/public/favicon.ico` (déjà généré).

### 4. Lancer le sidecar au démarrage de l'app (src-tauri/src/main.rs)
Au `setup()`, démarrer le sidecar `red-engine` avec `tauri_plugin_shell` et l'arrêter à la fermeture.

### 5. Build final
```powershell
npm run tauri build     # → src-tauri/target/release/bundle/ (.msi / .exe NSIS)
```

### 6. Démarrage automatique de Windows
- Simple : plugin **`tauri-plugin-autostart`** (ajoute l'app au démarrage, activable depuis les réglages).
- Ou : tâche planifiée « au logon » avec privilèges les plus élevés (cohérent avec l'admin requis).

## 📋 Reste à trancher avec l'utilisateur
- Feu vert pour **installer le toolchain Rust + MSVC** (changement système, ~1–2 Go).
- Stratégie **mobile** : app Tauri mobile autonome (moteur allégé) **vs** app de consultation LAN
  se connectant au moteur desktop (recommandé, conforme au plan « mobile = consultation »).
- Signature de code (certificat) pour éviter les alertes SmartScreen à l'installation.

## 🔒 Rappels sécurité conservés dans le packaging
- Moteur lié à `127.0.0.1` (jamais exposé hors de l'app).
- Secrets en keyring, mode air-gapped par défaut, actions système en dry-run+confirm.
