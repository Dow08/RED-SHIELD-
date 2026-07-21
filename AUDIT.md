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

## 3. Recommandations à arbitrer (avant les builds)

Classées par rapport valeur / risque. Rien ici n'est bloquant ; ce sont des chantiers à
décider ensemble.

1. **Découper `App.tsx` (~1450 lignes)** — _valeur haute, risque moyen_. Le frontend est
   monolithique : extraire un fichier par onglet (`Dashboard.tsx`, `Grc.tsx`, `Health.tsx`,
   `Diagnostic.tsx`…) + un dossier `components/`. À faire posément, écran par écran, avec
   vérif visuelle — d'où le report volontaire.
2. **Normaliser l'accès aux modules dans `main.py`** — _valeur moyenne, risque faible_. Deux
   styles coexistent : `_require` (503 si inactif) et `registry.get(...) or fallback` (dégradé
   souple). Fixer une convention explicite (ex. **lecture = souple**, **action = stricte**) et
   introduire un helper `_optional(name, method, fallback)` pour collapser les ~15 endpoints
   « get-or-fallback » restants.
3. **`core/http.py`** — _valeur moyenne_. Faire pour les appels réseau (`httpx`) ce que
   `proc.py` a fait pour les commandes : un point unique qui applique timeout, gate
   air-gapped et gestion proxy (NVD, VirusTotal, crt.sh, Wazuh, Ollama passent aujourd'hui
   chacun leur propre `httpx.get/post`).
4. **`health.clean` — suivi des liens symboliques** — _durcissement_. La suppression itère
   des dossiers en liste blanche ; ajouter une garde « ne pas suivre un lien pointant hors du
   dossier ciblé » avant `os.remove` (défense en profondeur contre un cache piégé).
5. **Couverture de tests des actions** — étendre au-delà du smoke : tester les POST d'action
   (firewall dry-run, health/clean dry-run, grc/control) en bout-en-bout.
6. **Journalisation** — envisager un niveau `debug` désactivé par défaut et une rotation
   explicite des logs applicatifs (la rétention SQLite ≤ 1 Go existe déjà pour les snapshots).

---

## 4. Verdict

Base **saine et bien architecturée**. Les corrections de ce cycle réduisent la dette
(centralisation des commandes, dédup API) et renforcent la sécurité (surface d'exécution
maîtrisée, liste blanche connecteurs) **sans régression**. Les chantiers restants (§3) sont
des améliorations de confort/robustesse à planifier, pas des correctifs urgents.
