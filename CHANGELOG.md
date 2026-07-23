# Journal des modifications

Format inspiré de [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/).
Ce projet suit [SemVer](https://semver.org/lang/fr/).

## [Non publié]

### Sécurité
- Validation stricte de l'IP dans le module threat-intel (anti-injection de chemin).
- Sanitisation HTML du rapport appliquée aussi au rendu (défense XSS).
- Cibles `scan`/`trace` : refus d'une valeur commençant par `-` (anti-injection d'argument).
- CSP stricte pour la WebView Tauri (remplace `csp: null`).
- Tuyauterie de signature de code Windows (inerte tant qu'aucun certificat n'est fourni).

### Ajouté
- **Sauvegarde / restauration** de l'état de travail (évaluations GRC + brouillon de
  rapport) — export/import JSON, sans secrets. Onglet Connecteurs.
- **Détection de mise à jour** : bannière quand une release GitHub plus récente existe
  (gated air-gapped, install manuelle).
- Politique de sécurité (`SECURITY.md`), Dependabot, modèle de mandat d'autorisation
  (`docs/MANDAT-AUTORISATION.md`), guide de signature (`docs/SIGNING.md`).

## [0.1.0] — 2026-07-23

Première version fonctionnelle complète.

### Ajouté
- **Bouclier réseau** : connexions live (PID→app), direction entrant/sortant,
  ports en écoute exposés, bande passante temps réel, débit par processus (pktmon).
- **Scoring d'exposition** 0-100 + corrélation MITRE ATT&CK, snapshots/historique.
- **Cartographie** : carte réseau interactive, traceroute géolocalisé hors-ligne
  (DB-IP), carte du monde des connexions, détection VPN.
- **Recon** : scan nmap (ports/services/CVE NVD en ligne, OSI, conformité), moteur
  recon natif sans nmap (découverte + scan + empreinte + énum web + audit TLS).
- **Offensif** : cracker de hash, audit WiFi, OSINT passif (crt.sh).
- **SOC local** : HIDS-lite (Event Log), Mail Security (.eml + IMAP), Windows Defender.
- **Conformité (GRC)** : contrôles ISO 27001 / NIST CSF / CIS v8, auto-évaluation +
  preuves, score, export.
- **Rapport de mission** : générateur PDF éditable (données réelles, synthèse IA
  optionnelle, annexes, sections libres).
- **Santé** : disques, nettoyage temp/caches (dry-run), démarrage, point de restauration.
- **Connecteurs** : clés API chiffrées (keyring), SIEM (Wazuh), threat-intel.
- **Packaging** : desktop Tauri (installeur NSIS via CI) + APK Android (recon natif Rust).

### Sécurité
- Exécution de commandes centralisée et durcie (`core/proc.py`, jamais `shell=True`).
- Mode air-gapped, secrets jamais affichés, licence non commerciale (PolyForm).
- CI Trivy (vulnérabilités + secrets), zéro donnée inventée.
