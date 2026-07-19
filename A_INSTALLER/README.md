# À installer — dépendances externes de RED

Ce dossier liste ce que je ne peux pas installer automatiquement à ta place. Le reste
(dépendances Python, Node, et la base GeoIP) est déjà récupéré et en place.

## ✅ Déjà fait automatiquement
- **Python** : dépendances installées dans `engine/.venv` (dont `maxminddb`).
- **Node** : dépendances installées dans `ui/node_modules`.
- **Base GeoIP** (traceroute géolocalisé hors-ligne) : `engine/data/dbip-city-lite.mmdb`
  téléchargée depuis DB-IP (gratuite, licence CC-BY, ~131 Mo, aucun compte requis).
  À rafraîchir ~1×/mois (nouvelle version DB-IP), sinon rien à faire.

## 🔧 À installer par toi (au moment voulu)

### 1. nmap — pour le scan de vulnérabilités (Jalon 3)
Non requis avant le Jalon 3. Deux options :
- **winget** (le plus simple) : `winget install Insecure.Nmap`
- ou télécharger l'installeur : https://nmap.org/download.html (section Windows)

Vérifier ensuite : `nmap --version`

### 2. Clés API des connecteurs — pour l'enrichissement (Jalon 2)
Optionnel. À renseigner dans `.env` (copié depuis `.env.example`) **et** passer
`RED_AIRGAPPED=false` pour les activer. Comptes gratuits :
- VirusTotal : https://www.virustotal.com/gui/my-apikey
- AbuseIPDB : https://www.abuseipdb.com/account/api
- Shodan : https://account.shodan.io/
- GreyNoise : https://viz.greynoise.io/account/api-key

### 3. WiFi offensif (aircrack) — Jalon 4, Linux uniquement
Impossible sous Windows : nécessite **Linux** (Kali/Parrot) + une **carte WiFi
compatible mode monitor**. Ce module restera « indisponible » sous Windows, par conception.

---
*Rappel : mode air-gapped ACTIF par défaut = aucun appel externe. Les connecteurs ne
s'activent que si tu le désactives explicitement.*
