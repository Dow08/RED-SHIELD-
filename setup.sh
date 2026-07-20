#!/usr/bin/env bash
# RED — script d'installation Linux (Kali/Parrot/Debian). Lancer : bash setup.sh
set -e
echo "=== Installation de RED (Linux) ==="

ask() { read -r -p "$1 [o/N] " r; [[ "$r" =~ ^([oO]|[yY]) ]]; }

command -v python3 >/dev/null && echo "[OK] python3" || echo "[!] python3 manquant (apt install python3 python3-venv)"
command -v node >/dev/null && echo "[OK] node" || echo "[!] node manquant (https://nodejs.org)"

# Backend
if [ ! -d engine/.venv ] && ask "Créer le venv + installer les dépendances Python ?"; then
  python3 -m venv engine/.venv
  engine/.venv/bin/pip install -r engine/requirements.txt
fi

# Frontend
if [ ! -d ui/node_modules ] && ask "npm install (frontend) ?"; then ( cd ui && npm install ); fi

# nmap
command -v nmap >/dev/null && echo "[OK] nmap" || { ask "Installer nmap ?" && sudo apt-get install -y nmap; }

# GeoIP
if [ ! -f engine/data/dbip-city-lite.mmdb ] && ask "Télécharger la base GeoIP (DB-IP, ~130 Mo) ?"; then
  mkdir -p engine/data
  m=$(date +%Y-%m)
  curl -L "https://download.db-ip.com/free/dbip-city-lite-$m.mmdb.gz" -o engine/data/dbip.mmdb.gz
  gunzip -f engine/data/dbip.mmdb.gz && mv engine/data/dbip.mmdb engine/data/dbip-city-lite.mmdb 2>/dev/null || \
    engine/.venv/bin/python -c "import gzip,os; open('engine/data/dbip-city-lite.mmdb','wb').write(gzip.open('engine/data/dbip.mmdb.gz','rb').read()); os.remove('engine/data/dbip.mmdb.gz')"
fi

# WiFi offensif (Linux only)
if ask "Installer aircrack-ng (WiFi offensif — nécessite une carte en mode monitor) ?"; then
  sudo apt-get install -y aircrack-ng
fi

echo "=== Terminé. Lancer : (T1) engine/.venv/bin/python -m uvicorn app.main:app --port 8787  (T2) cd ui && npm run dev ==="
