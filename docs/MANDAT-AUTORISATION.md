# Mandat d'autorisation d'audit / test d'intrusion

> **Modèle à faire signer AVANT toute action active** (scan, énumération, test
> d'intrusion). Sans ce document signé, un scan actif est illégal (art. 323-1 et
> suivants du Code pénal français). Adaptez, faites relire par un juriste pour les
> missions à enjeu, et conservez l'exemplaire signé pendant toute la durée légale.

---

## 1. Parties

**Prestataire (auditeur)**
- Raison sociale : DP Cyber Consulting
- Représentant : Dorian Poncelet
- Coordonnées : ________________________

**Client (donneur d'ordre)**
- Raison sociale : ________________________
- Représentant habilité (doit avoir autorité sur les systèmes visés) : ____________
- Fonction : ________________________
- Coordonnées : ________________________

Le représentant du client **déclare être propriétaire des systèmes ci-dessous, ou
dûment habilité par leur propriétaire à en autoriser l'audit** (hébergeur, tiers,
services cloud inclus — voir §7).

## 2. Objet et nature de la mission

- [ ] Cartographie / reconnaissance réseau
- [ ] Scan de ports et de services
- [ ] Énumération web (répertoires, fichiers)
- [ ] Audit de configuration / conformité (ISO 27001, NIST, CIS, ANSSI)
- [ ] Test d'intrusion (préciser : externe / interne / boîte noire / grise / blanche)
- [ ] Autre : ________________________

Outil principal utilisé : **RED SHIELD**.

## 3. Périmètre autorisé (exhaustif)

Seuls les éléments listés ci-dessous sont dans le périmètre. **Tout ce qui n'y
figure pas est hors périmètre et interdit.**

| Type | Valeur (IP / plage CIDR / domaine / URL) |
|------|-------------------------------------------|
| IP / plages | ________________________ |
| Domaines / sous-domaines | ________________________ |
| Applications / URL | ________________________ |
| Exclusions explicites | ________________________ |

## 4. Fenêtre d'intervention

- Date/heure de début autorisée : ____________________
- Date/heure de fin autorisée : ______________________
- Créneaux imposés (ex. hors heures ouvrées) : _______________________

## 5. Limitations et interdits

- Pas de déni de service (DoS/DDoS), pas de test de charge destructif.
- Pas d'exfiltration de données réelles au-delà de la preuve minimale nécessaire.
- Pas de modification/suppression de données de production.
- Arrêt immédiat en cas d'incident (voir §6).
- Autres restrictions client : ________________________

## 6. Contacts d'urgence et procédure d'incident

- Contact technique client (24/7 pendant la fenêtre) : ______________________
- En cas d'indisponibilité de service ou d'incident : arrêt immédiat des tests +
  notification sans délai du contact ci-dessus.

## 7. Systèmes tiers / hébergés

Si le périmètre inclut des ressources hébergées chez un tiers (cloud, hébergeur,
SaaS), le client confirme avoir obtenu les autorisations nécessaires auprès de ce
tiers (certains imposent une déclaration préalable) :
- [ ] Non applicable  [ ] Autorisations tierces obtenues (préciser) : ____________

## 8. Confidentialité et livrables

- Les résultats et données collectées sont **confidentiels**, remis au seul client.
- Livrable : rapport de mission (constats, criticité, recommandations).
- Données personnelles éventuellement traitées (IP, identifiants) : traitées pour
  la seule finalité de l'audit, conservées ________ puis détruites (RGPD).

## 9. Responsabilité

Le prestataire agit dans les strictes limites du présent mandat. Le client reconnaît
que des tests de sécurité comportent un risque résiduel malgré les précautions.

## 10. Signatures

Le présent mandat vaut **autorisation expresse et écrite** au sens de la loi.

| | Client | Prestataire |
|---|--------|-------------|
| Nom | ____________ | Dorian Poncelet |
| Fonction | ____________ | DP Cyber Consulting |
| Date | ____________ | ____________ |
| Signature | ____________ | ____________ |

---

> **Rappel produit** : reporter le périmètre du §3 dans le garde-fou de périmètre
> de RED SHIELD (onglet Recon) et la référence de ce mandat dans le champ
> « autorisation » de la couverture du rapport de mission.
