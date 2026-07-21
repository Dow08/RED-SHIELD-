# Audit RED SHIELD — architecture & sécurité

_Revue menée dans une posture d'ingénieur logiciel senior puis de DevSecOps, avant les
builds des launchers. Objectif : simplifier, fiabiliser et durcir sans rien casser._

Périmètre : moteur `engine/` (26 briques + coquille), API `main.py`, frontend `ui/`.
État de référence : **86 tests pytest + 7 Vitest verts** à l'issue de l'audit.

---

## 1. Points forts (à conserver)

- **Coquille claire et minimale** : `bus` (pub/sub avec isolation des erreurs), `registry`,
  `watchdog` (un module qui plante passe en `ERROR` sans faire tomber l'app). Contrat de
  module homogène (`base.py`). C'est une bonne fondation, peu couplée.
- **Isolation réelle des briques** : communication par le bus, une brique = un fichier,
  tailles raisonnables (médiane ~110 lignes).
- **Principes tenus** : mode *air-gapped* par défaut (gate systématique avant tout appel
  externe), *zéro donnée inventée* (réel mesuré ou état « non connecté »), secrets en keyring.

---

## 2. Corrections appliquées ce cycle

| # | Sujet | Avant | Après |
|---|-------|-------|-------|
| 1 | **Exécution de commandes** | `subprocess.run(...)` dupliqué dans **11 modules**, sans `CREATE_NO_WINDOW` (console qui clignote), flags incohérents | Point unique **`core/proc.py`** : jamais `shell=True`, liste d'arguments only, timeout obligatoire, no-window, erreurs isolées. 11 modules migrés. |
| 2 | **Couplage `main.py`** | 6 blocs d'audit identiques ; accès aux **attributs privés** de `trace` (`_geo_lookup`, `geo_available`) | Helpers `_audit()` et `_geo()` + accesseur public `TraceModule.geo_lookup_fn()`. |
| 3 | **Filet de régression** | Un seul test TestClient (`/config`) | **`test_api_smoke.py`** : aucun endpoint GET ne renvoie 5xx + formes clés (grc, exports, toggle). |
| 4 | **Connecteurs (keyring)** | `set/get/delete` **sans validation** du nom (pollution possible du trousseau via l'URL) ; `KNOWN` incomplet | Liste blanche **`ALLOWED`** (inclut `imap`/`siem`) ; noms hors liste refusés (400) ; jamais de log de la valeur. |
| 5 | **Persistance GRC packagée** | Chemin basé sur `__file__` → dossier temporaire non persistant en bundle PyInstaller | `frozen` → `%LOCALAPPDATA%\RED-SHIELD`, sinon `engine/data`. |

**Validation des entrées sensibles (revue, déjà saine)** : cibles nmap/tracert filtrées par
regex stricte (`scan.valid_target`, `trace.valid_target`) ; `updater.upgrade` gardé par
`_ID_RE` ; `firewall` par validation IP ; `osint` par regex domaine ; `health.clean` limité à
une **liste blanche** de dossiers (catégorie inconnue = no-op). Interpolations PowerShell sur
données internes ou échappées (`procvuln`, `health`). Aucun secret en dur, aucun
`eval/exec/pickle/yaml.load`. CORS restreint aux origines locales (`localhost`/`tauri`), API
liée à `127.0.0.1`.

---

## 3. Recommandations — ✅ toutes traitées

Chantiers décidés et **appliqués** (commits `a402465` → `49330d1`), sans régression.

1. ✅ **Découper `App.tsx`** — passé de **1566 à 155 lignes** : primitives partagées dans
   `src/shared.tsx`, **un fichier par onglet** sous `src/tabs/` (11 fichiers). Code déplacé
   verbatim (script) → aucun changement de comportement ; les 11 onglets rendent, 0 erreur
   console. Bonus : `tsc --noEmit` devient un **vrai garde-fou** (target/lib ES2022,
   `vite-env.d.ts`, type nullable corrigé) et `npm run build` lance `tsc && vite build`.
2. ✅ **Normaliser l'accès aux modules dans `main.py`** — helper `_optional(name, method,
   fallback)` ; ~19 endpoints « get-or-fallback » réduits à une ligne ; convention explicitée
   (**lecture souple / action stricte**).
3. ✅ **`core/http.py`** — point unique des appels réseau (timeout, erreurs isolées, en-tête
   UA, flag `local=True` pour Ollama/Wazuh). 5 modules migrés ; `httpx` centralisé.
4. ✅ **`health.clean` — garde anti-symlink** — ne descend jamais dans un lien/jonction et
   ignore les fichiers-liens.
5. ✅ **Tests des actions** — POST dry-run (firewall, health/clean) + rejets 400 (grc, connecteur).
6. ✅ **Journalisation** — vérifié : déjà bornée (deque `maxlen=5000`) + purge à la fermeture ;
   rien à ajouter.

**Suivi tests** : 93 pytest + 7 vitest, `tsc --noEmit` sans erreur, build front OK.

---

## 4. Verdict

Base **saine et bien architecturée**. Les corrections de ce cycle réduisent la dette
(centralisation des commandes, dédup API) et renforcent la sécurité (surface d'exécution
maîtrisée, liste blanche connecteurs) **sans régression**. Les chantiers restants (§3) sont
des améliorations de confort/robustesse à planifier, pas des correctifs urgents.
