# RED — script d'installation Windows (à lancer une fois).
# Vérifie et propose (opt-in) de récupérer les dépendances selon l'OS.
# Usage :  powershell -ExecutionPolicy Bypass -File setup.ps1

$ErrorActionPreference = "Stop"
Write-Host "=== Installation de RED (Windows) ===" -ForegroundColor Cyan

function Ask($q) { (Read-Host "$q [o/N]") -match '^(o|y)' }

# 1. Python
try { py -3 --version | Out-Null; Write-Host "[OK] Python présent" -ForegroundColor Green }
catch { Write-Host "[!] Python 3.11+ manquant : https://www.python.org/downloads/ (coche 'Add to PATH')" -ForegroundColor Yellow }

# 2. Node
try { node --version | Out-Null; Write-Host "[OK] Node présent" -ForegroundColor Green }
catch { Write-Host "[!] Node.js 18+ manquant : https://nodejs.org" -ForegroundColor Yellow }

# 3. Dépendances backend
if (Test-Path ".\engine\requirements.txt") {
  if (-not (Test-Path ".\engine\.venv")) {
    if (Ask "Créer le venv et installer les dépendances Python ?") {
      py -m venv .\engine\.venv
      & .\engine\.venv\Scripts\python.exe -m pip install -r .\engine\requirements.txt
    }
  } else { Write-Host "[OK] venv backend présent" -ForegroundColor Green }
}

# 4. Dépendances frontend
if ((Test-Path ".\ui\package.json") -and -not (Test-Path ".\ui\node_modules")) {
  if (Ask "Installer les dépendances frontend (npm install) ?") { Push-Location .\ui; npm install; Pop-Location }
} else { Write-Host "[OK] node_modules présent" -ForegroundColor Green }

# 5. nmap (scan — Jalon 3)
if (-not (Get-Command nmap -ErrorAction SilentlyContinue) -and -not (Test-Path "C:\Program Files (x86)\Nmap\nmap.exe")) {
  if (Ask "Installer nmap (scan de vulnérabilités) via winget ?") { winget install --id Insecure.Nmap -e --accept-package-agreements --accept-source-agreements }
} else { Write-Host "[OK] nmap présent" -ForegroundColor Green }

# 6. Base GeoIP (traceroute géolocalisé)
if (-not (Test-Path ".\engine\data\dbip-city-lite.mmdb")) {
  if (Ask "Télécharger la base GeoIP (DB-IP, ~130 Mo, hors-ligne) ?") {
    New-Item -ItemType Directory -Force -Path .\engine\data | Out-Null
    $month = (Get-Date).ToString("yyyy-MM")
    Invoke-WebRequest "https://download.db-ip.com/free/dbip-city-lite-$month.mmdb.gz" -OutFile .\engine\data\dbip.mmdb.gz
    & .\engine\.venv\Scripts\python.exe -c "import gzip,shutil,os; open('engine/data/dbip-city-lite.mmdb','wb').write(gzip.open('engine/data/dbip.mmdb.gz','rb').read()); os.remove('engine/data/dbip.mmdb.gz')"
  }
} else { Write-Host "[OK] base GeoIP présente" -ForegroundColor Green }

# 7. WiFi offensif — non applicable sous Windows
Write-Host "[i] aircrack (capture/crack WiFi) = Linux uniquement. Sous Windows, utilise l'Audit WiFi intégré." -ForegroundColor DarkGray

Write-Host "`n=== Terminé. Lancer :  T1) cd engine; .\.venv\Scripts\python.exe -m uvicorn app.main:app --port 8787   T2) cd ui; npm run dev ===" -ForegroundColor Cyan
