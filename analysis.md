# Red — Analyse concurrentielle & boucle de scoring (analysis.md)

> Étape de cadrage stratégique avant maquettes & code.
> Date : 2026-07-19.

---

## 1. Outils existants équivalents (par volet)

### Bouclier réseau temps réel / connexions locales
- **GlassWire** (Windows, commercial) : monitor réseau par application, alertes, joli. Faiblesse : pas offensif, pas de scoring de risque, fermé.
- **Portmaster / Safing** (open source, multi-OS) : firewall applicatif + filtrage DNS + monitoring, bonne UI. Faiblesse : pur défensif, pas de recon, pas de rapport orienté remédiation.
- **Little Snitch** (macOS) / **OpenSnitch** (Linux) : firewall sortant par process, contrôle des connexions. Faiblesse : mono-OS, pas de visualisation graphe, pas de scoring.
- **Sysinternals TCPView** (Windows) : liste brute des connexions. Faiblesse : brut, aucune interprétation.

### Scan de vulnérabilités / exposition
- **Nessus / Tenable**, **OpenVAS / Greenbone**, **Qualys**, **Rapid7 InsightVM** : scanners de vulnérabilités matures. Faiblesse : lourds, chers ou complexes, rapports peu pédagogiques, pas de vue défensive temps réel.
- **nmap (+ Vulners/NSE)** : le moteur de référence. Faiblesse : CLI, pas de dashboard ni de score agrégé.

### Surface d'attaque / exposition
- **Shodan / Censys** : exposition Internet, look "cyber". Faiblesse : externe/Internet, pas ta machine locale, pas de remédiation guidée.

### Visualisation / graphe
- **BloodHound** : graphe de chemins d'attaque Active Directory. Faiblesse : spécifique AD, pas réseau/connexions live.
- **Maltego** : graphe OSINT. Faiblesse : orienté investigation, pas monitoring.

### SIEM / EDR
- **Wazuh** (open source XDR/SIEM), **Security Onion**, **Elastic SIEM**, **Splunk** : collecte et corrèlent les logs. Faiblesse : lourds à déployer, courbe d'apprentissage forte, pas de volet recon offensif intégré.

### Agrégation / orchestration pentest
- **Faraday** : agrège la sortie de nombreux outils, collaboratif. Faiblesse : orienté équipe/rapport, pas de bouclier live ni de scoring d'exposition mémorable.
- **Dradis / AttackForge** : reporting pentest. Faiblesse : reporting uniquement.
- **Sn1per / recon frameworks** : enchaînent des outils. Faiblesse : opaques, pas de dashboard clair.

---

## 2. Ce qui manque partout (→ à incorporer dans Red)
- **Un pont red + blue dans une seule interface** : presque tous les outils sont soit offensifs, soit défensifs, jamais les deux proprement reliés.
- **Un score d'exposition unique et lisible** (façon "score de crédit") agrégeant tout — quasi inexistant côté grand public.
- **Un rapport exportable orienté remédiation, lisible par un humain ET par une IA** (Markdown structuré : vu → problème → correctif). Les rapports existants sont bruts ou payants.
- **Une classification native / suspect appuyée sur réputation + baseline**, pas juste une liste de connexions.
- **Une architecture modulaire grand public** où l'on active/désactive des briques sans tout casser — les suites pro sont monolithiques.
- **Une vraie simplicité d'usage** : la plupart des outils puissants sont hostiles aux débutants.

## 3. La plus-value de Red (ce qui le rend unique)
- **"Voir tout ce qui parle à quoi" + le noter + dire quoi faire** — en un dashboard sombre lisible, pas une CLI.
- **Score 0-100 + priorisation par impact** ("corrige/coupe ÇA d'abord").
- **Export Markdown orienté remédiation** analysable par IA → colle au profil GRC/pédagogie.
- **Modulaire par conception** : chaque brique vit et meurt seule, on empile dans le temps.
- **Red + Blue réunis** avec double lecture (ce que voit l'attaquant / comment c'est protégé).
- **"Zéro donnée inventée"** : un module montre du réel ou dit "non connecté".

## 4. Points de friction observés ailleurs (→ à NE PAS reproduire)
- **Couper la mauvaise connexion = perte réseau** (Little Snitch/Portmaster génèrent de la frustration). → toujours confirmation + annulation + mode observation d'abord.
- **Faux positifs sur "suspect"** (les EDR crient au loup). → commencer par des règles simples + réputation + baseline utilisateur, pas de "détection magique".
- **Lourdeur de déploiement** (Wazuh, Nessus). → démarrage en une commande, dépendances minimales.
- **Rapports illisibles** (sortie brute nmap/OpenVAS). → template Markdown pédagogique.
- **Dépendance à un écosystème** (Faraday sans outils connectés = vide). → le socle doit être utile *seul*, sans rien brancher.
- **Monolithe fragile** (un bug fait tout tomber). → frontières d'erreur par module + watchdog.
- **Clés API en clair / secrets exposés**. → stockage chiffré, masquage UI, mode air-gapped.

---

## 5. Boucle itérative de scoring (0→10)

**Rubrique** (5 critères × 2 pts) :
- **C1** Faisabilité vibe-coding & délai
- **C2** Valeur immédiate dès le jalon 1
- **C3** Différenciation / plus-value
- **C4** Maîtrise des frictions (légal, privilèges, faux positifs, dépendances)
- **C5** Extensibilité modulaire & maintenabilité

> Note : "10/10" = design dont on a évacué toutes les frictions *maîtrisables* avant build. Ce n'est pas une garantie de perfection à l'exécution, mais une mesure de solidité de conception.

### VARIANTE A — "RED Shield" (défensif-first, moteur natif local)
Démarre par le bouclier live local (connexions via API natives Windows), coquille modulaire, moteur maison, puis scan offensif + graphe + connecteurs.

| Itération | Décision appliquée (friction retirée) | Note |
|-----------|----------------------------------------|------|
| A0 | Baseline (temps réel + coupure + détection suspect + moteur maison partout) | 6/10 |
| A1 | Retirer la coupure du scope initial → **observation seule**, action plus tard avec confirm+undo | 7/10 |
| A2 | Remplacer la "détection magique" par **règles + réputation + baseline** | 8/10 |
| A3 | **Coquille modulaire + watchdog + contrat de module + états de santé** | 9/10 |
| A4 | Séquencer : **J1 = observation locale pure** (zéro friction légale/privilège, natif Windows) ; modules lourds (push temps réel, WiFi, SIEM) différés en plugins isolés | **10/10** |

### VARIANTE B — "RED Hub" (agrégateur/orchestrateur-first)
Ne réinvente pas les moteurs : couche d'agrégation + intelligence + rapport par-dessus des outils existants (nmap, Wazuh, VirusTotal, données natives OS). Différenciateur = scoring + rapport Markdown + dashboard unifié.

| Itération | Décision appliquée (friction retirée) | Note |
|-----------|----------------------------------------|------|
| B0 | Baseline (dépend d'outils tiers installés) | 6/10 |
| B1 | **J1 ne dépend que des données natives OS** (nmap/Wazuh optionnels) → pas de dashboard vide | 7/10 |
| B2 | Positionner **l'intelligence (score + rapport Markdown) comme produit cœur**, connecteurs = enrichissement | 8/10 |
| B3 | **Coquille modulaire + gestionnaire de connecteurs (clés chiffrées) + états de santé** | 9/10 |
| B4 | **Contrat de module + états "non connecté" honnêtes + modules lourds différés** | **10/10** |

### Comparaison & synthèse (garder le meilleur)
- Les deux atteignent 10/10 sur la rubrique, mais **A est plus robuste** : son socle délivre de la valeur **dès le jour 1 sans dépendre de l'écosystème externe** de l'utilisateur (B risque un dashboard "vide" si rien n'est branché).
- **B apporte une meilleure philosophie pour les modules périphériques** : ne pas réinventer nmap/Wazuh mais les **envelopper** (wrappers fins).
- **Décision : gagnant = A, hybridé avec la philosophie de B.**
  - Socle = moteur défensif local maison (toujours utile seul).
  - Modules offensifs/SIEM/EDR = **wrappers fins** sur outils existants (esprit B), pas de réinvention.
  - Coquille modulaire + watchdog + contrat de module + connecteurs chiffrés + "zéro donnée inventée" + export Markdown = commun aux deux, conservé.

---

## 6. Verdict
Design **validé à 10/10 (rubrique)** : **RED Shield hybridé**.
Socle défensif local autonome → empilage de modules (offensif, graphe, connecteurs) en wrappers fins, tous isolés par frontières d'erreur.

---

## 7. Plus-values évaluées via la boucle de scoring (2026-07-19)
Rubrique /10 : C1 faisabilité vibe-coding · C2 valeur immédiate · C3 différenciation · C4 maîtrise des frictions · C5 extensibilité.
Inspiration concurrence : NDR modernes (beaconing, DNS analytics, JA3, baseline comportementale), EDR/DFIR open source (OpenEDR, Velociraptor), MITRE ATT&CK natif.

| # | Proposition | Note base | Ajustement (friction retirée) | Note finale | Jalon |
|---|-------------|-----------|-------------------------------|-------------|-------|
| 1 | **Détection de beaconing C2** (analyse d'intervalles réguliers) | 8 | Sur historique de snapshots + seuil réglable + whitelist | **9,5** | J2-J3 |
| 2 | **Rapport IA embarqué** (export MD → LLM → synthèse exécutive + remédiation) | 8,5 | Opt-in, air-gapped-safe, option LLM local | **9,5** | J2 |
| 3 | **Score threat-intel unifié** (VirusTotal + AbuseIPDB + GreyNoise + Shodan) | 8 | Cache + air-gapped + états "non connecté" | **9** | J2 |
| 4 | **Mapping conformité** (CIS / ANSSI / NIST) + ATT&CK | 8,5 | Tables statiques + aligné profil GRC | **9,5** | J3 |
| 5 | **SOAR-lite** : confinement en 1 clic + playbooks + undo | 8 | Confirmation + annulation + audit (privilège maîtrisé) | **9** | J2 |
| 6 | **Baseline comportementale** / anomalie par process | 8 | Apprentissage sur historique + seuils | **9** | J2-J3 |
| 7 | **Analytics DNS** (DGA + tunneling + domaines récents) | 8,5 | Entropie + heuristiques locales + whitelist | **9** | J2 |
| 8 | **Arbre de processus parent-enfant** (lignée du process suspect) | 9 | psutil ppid, faible friction | **9,5** | J1 |
| 9 | **Timeline / rejeu d'incident** | 8,5 | Reconstruit depuis l'historique | **9** | J2 |
| 10 | **Mode pédagogique « explique-moi »** + contexte ATT&CK | 9 | Aligné formation/portfolio | **9,5** | J1-J2 |
| 11 | Carte mondiale GeoIP animée (arcs) | 8 | — (surtout esthétique) | 8 | J3 (option) |
| 12 | Fingerprint TLS JA3/JA4 | 6,5 | Nécessite inspection paquets/TLS | 7 | J4 |
| 13 | Honeypot / canary léger | 6,5 | Ouvre des ports (risque) | 7 | J4 |
| 14 | Capture de paquets à la demande (pcap) | 5,5 | npcap + privilèges | 6 | J4 |
| 15 | Alertes desktop / webhook / email | 7 | Commodité, peu différenciant | 7 | J2 (option) |

**Retenus (note 9-10) → à intégrer** : #1, #2, #3, #4, #5, #6, #7, #8, #9, #10.
Non retenus pour l'instant (< 9) : #11 à #15 (gardés en options/jalons ultérieurs, non abandonnés).

## 8. Verdict global
Design **validé à 10/10 (rubrique)** + **10 plus-values retenues à 9-10** qui hissent Red au niveau NDR/SOC tout en restant faisable en vibe coding et aligné sur le profil GRC/SOAR.
