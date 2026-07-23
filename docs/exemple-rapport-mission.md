# Rapport de mission — audit de sécurité (EXEMPLE)

> ⚠️ **DOCUMENT D'EXEMPLE.** Client, données et constats sont **fictifs**, produits
> pour illustrer le type de livrable généré et curé avec RED SHIELD. Aucune donnée
> réelle. Toute ressemblance avec une organisation existante est fortuite.

---

**Prestataire** : DP Cyber Consulting — Dorian Poncelet
**Client** : ACME Industrie (fictif)
**Périmètre** : `192.168.10.0/24` (réseau bureautique siège) + `acme-corp.example`
**Référence mandat** : MAND-2026-014 (autorisation écrite signée le 12/03/2026)
**Date de la mission** : 18–19 mars 2026
**Confidentialité** : Diffusion restreinte — ACME Industrie

---

## 1. Synthèse pour la direction

L'audit du réseau bureautique du siège d'ACME Industrie révèle une **posture globale
moyenne** : les fondamentaux défensifs sont présents (antivirus actif, pare-feu en
place), mais **trois écarts prioritaires** exposent l'organisation à un risque
d'intrusion et de latéralisation. Le score d'exposition mesuré s'établit à **58/100**
(bande « à surveiller »).

Les corrections proposées sont majoritairement **organisationnelles et à faible coût**.
Leur mise en œuvre ramènerait le score en zone maîtrisée sous 4 à 6 semaines.

| Indicateur | Valeur |
|---|---|
| Score d'exposition | 58 / 100 (à surveiller) |
| Hôtes actifs découverts | 27 |
| Services exposés critiques | 2 |
| Constats — critiques / élevés / moyens | 1 / 2 / 3 |
| Conformité ISO 27001:2022 | 71 / 100 |

## 2. Méthodologie

Audit mené avec **RED SHIELD** (reconnaissance passive et active sur périmètre
autorisé), complété par une revue de conformité :

1. **Cartographie** du réseau (découverte d'hôtes, ports, empreinte de services).
2. **Analyse d'exposition** et corrélation MITRE ATT&CK.
3. **Croisement CVE** des services versionnés (base NVD).
4. **Revue de conformité** ISO 27001:2022 / NIST CSF 2.0 / CIS v8.

Chaque constat est **factuel** (donnée mesurée) ; les criticités suivent une échelle
qualitative (critique / élevé / moyen / faible).

## 3. Constats et recommandations

### 🔴 CRITIQUE — Service RDP exposé sans restriction (192.168.10.24:3389)

- **Constat** : le service Bureau à distance (RDP) est ouvert et accessible depuis
  l'ensemble du sous-réseau, sans filtrage ni authentification renforcée.
- **Impact** : vecteur d'intrusion et de latéralisation privilégié (rançongiciels).
- **Recommandation** : restreindre l'accès RDP (VPN ou passerelle dédiée), activer le
  **MFA**, et journaliser les connexions.
- **Références** : ISO 27001 A.8.20 ·  CIS v8 4.6 · MITRE ATT&CK T1021.001.

### 🟠 ÉLEVÉ — Version obsolète d'OpenSSH (192.168.10.5:22)

- **Constat** : OpenSSH 7.4 détecté ; plusieurs CVE publiées (dont CVE-2018-15473,
  énumération d'utilisateurs).
- **Impact** : reconnaissance facilitée, exposition à des vulnérabilités connues.
- **Recommandation** : mettre à jour vers une version supportée, désactiver
  l'authentification par mot de passe au profit des clés.
- **Références** : ISO 27001 A.8.8 · CIS v8 7.3.

### 🟠 ÉLEVÉ — Flux internes en clair (HTTP) sur l'intranet

- **Constat** : l'application intranet (`192.168.10.30:80`) transmet des identifiants
  en HTTP non chiffré.
- **Impact** : interception possible sur le réseau local.
- **Recommandation** : forcer HTTPS (TLS 1.2+), rediriger le port 80, HSTS.
- **Références** : ISO 27001 A.8.24 · NIST CSF PR.DS-2.

### 🟡 MOYEN — Absence de MFA sur la messagerie

- **Recommandation** : activer le MFA sur l'ensemble des comptes de messagerie.
- **Références** : ISO 27001 A.8.5 · CIS v8 6.3.

### 🟡 MOYEN — Journalisation incomplète des postes

- **Recommandation** : centraliser les journaux (SIEM) et activer Sysmon.
- **Références** : ISO 27001 A.8.15 · NIST CSF DE.AE.

### 🟡 MOYEN — Correctifs applicatifs en retard

- **Constat** : plusieurs applications tierces avec mises à jour disponibles.
- **Recommandation** : processus de gestion des correctifs mensuel.
- **Références** : ISO 27001 A.8.8 · CIS v8 7.

## 4. Conformité (extrait)

| Référentiel | Score | Contrôles conformes / à traiter |
|---|---|---|
| ISO 27001:2022 | 71/100 | 12 / 5 |
| NIST CSF 2.0 | 68/100 | 10 / 6 |
| CIS Controls v8 | 74/100 | 13 / 4 |

## 5. Plan d'action priorisé

| Priorité | Action | Effort | Délai visé |
|---|---|---|---|
| 1 | Restreindre + MFA sur RDP | Faible | 1 semaine |
| 2 | Migrer l'intranet en HTTPS | Moyen | 2 semaines |
| 3 | Mettre à jour OpenSSH | Faible | 2 semaines |
| 4 | MFA messagerie | Faible | 3 semaines |
| 5 | Centraliser les journaux (SIEM) | Moyen | 6 semaines |

## 6. Annexes

- Cartographie réseau complète (27 hôtes) — annexe A.
- Détail des services et versions — annexe B.
- Journal d'audit des actions menées durant la mission — annexe C.

---

*Rapport généré à partir de données factuelles puis curé par le consultant.
DP Cyber Consulting — document d'exemple, non contractuel.*
