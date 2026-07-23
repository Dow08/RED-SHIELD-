# RED SHIELD — Fiche projet

> **Plateforme d'audit cyber tout-en-un** : observer le réseau, corréler les risques,
> produire le livrable client. Un outil de consultant, du capteur au rapport.
>
> Projet conçu et développé par **Dorian Poncelet — DP Cyber Consulting**.
> Dépôt : <https://github.com/Dow08/RED-SHIELD-> · Version **0.1.0** · Licence non commerciale (PolyForm).

---

## Le problème

Un audit de sécurité oblige aujourd'hui à jongler entre une dizaine d'outils
disjoints (scan, monitoring réseau, veille CVE, conformité, SIEM…) puis à
**tout ré-agréger à la main** dans un rapport. C'est lent, dispersé, source d'erreurs.

## La proposition de valeur

RED SHIELD **agrège et corrèle** ce que les outils du marché produisent, plutôt que
de les réimplémenter. Une seule interface, une colonne vertébrale claire :

```
   CAPTEURS              →        CERVEAU               →       LIVRABLE
 (scan, recon, santé,          (scoring, MITRE ATT&CK,        (rapport de mission
  connexions, mails)            CVE/NVD, conformité GRC)        éditable + PDF)
```

**Principe directeur : « zéro donnée inventée ».** Tout ce qui est affiché est mesuré
(psutil, nmap, pktmon, Event Log, DB-IP, NVD…) — jamais simulé.

## Fonctionnalités clés

- **Bouclier réseau** — connexions live (processus → application), direction, ports
  exposés, bande passante et débit par processus, **score d'exposition 0-100**.
- **Cartographie** — carte réseau interactive, traceroute géolocalisé **hors-ligne**,
  carte du monde des connexions, détection VPN.
- **Reconnaissance** — scan nmap (services/versions/CVE en ligne, OSI, conformité) et
  **moteur recon natif sans nmap** (découverte, ports, empreinte, énum web, TLS).
- **SOC local** — HIDS-lite (journaux Windows), analyse anti-phishing e-mail
  (SPF/DKIM/DMARC), Windows Defender.
- **Conformité (assistant CISO)** — contrôles **ISO 27001 · NIST CSF · CIS v8**,
  auto-évalués depuis l'état réel de la machine ou évalués manuellement avec preuves,
  score par référentiel.
- **Rapport de mission** — générateur d'un premier jet factuel, **éditable en direct**,
  synthèse assistée IA optionnelle, export PDF (« DP Cyber Consulting »).
- **Santé du poste**, **connecteurs** (SIEM Wazuh, threat-intel — clés chiffrées),
  **sauvegarde/restauration** de l'état de travail.

## Posture sécurité & DevSecOps

Un outil de sécurité se doit d'être exemplaire sur sa propre sécurité :

- Exécution de commandes **centralisée et durcie** (jamais `shell=True`, arguments
  validés, timeouts) ; entrées validées (anti-injection).
- **Secrets** dans le trousseau de l'OS, jamais affichés ni journalisés ni exportés.
- **CSP stricte** pour l'interface, mode **air-gapped** (aucune sortie réseau tant
  qu'il n'est pas explicitement désactivé).
- **Scan actif encadré** : garde-fou de périmètre + journalisation, et
  [modèle de mandat d'autorisation](MANDAT-AUTORISATION.md) à faire signer.
- **CI** : Trivy (vulnérabilités + secrets), Dependabot, 112 tests automatisés,
  typage strict. Chaîne de **signature de code** prête ([SIGNING.md](SIGNING.md)).

## Architecture & stack

- **Backend** : Python 3 · FastAPI · architecture modulaire (coquille registre/bus +
  ~26 modules isolés à contrat).
- **Interface** : React · Vite · TypeScript · Tailwind.
- **Desktop** : Tauri v2 (moteur Python encapsulé en sidecar) → installeur Windows via CI.
- **Mobile** : portage du moteur recon en **Rust natif** (Android, en cours de validation).

## Statut

- ✅ Fonctionnellement complet et durci ; installeur desktop produit en CI.
- 🔄 En cours : build/test mobile, signature de code, certification terrain.

## Pourquoi ce projet

Développé dans le cadre de ma reconversion en cybersécurité (orientation **GRC / SOAR**),
RED SHIELD me sert de terrain d'application concret : de la collecte technique à la
**traduction en risques et en conformité**, jusqu'au **livrable exploitable par un client**.
