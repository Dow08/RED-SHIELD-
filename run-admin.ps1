# RED — lancement du moteur en ADMINISTRATEUR
# Nécessaire pour la capture de paquets pktmon (débit par processus + trafic entrant).
# Usage : clic droit > « Exécuter avec PowerShell », ou : powershell -ExecutionPolicy Bypass -File run-admin.ps1

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$py = Join-Path $root "engine\.venv\Scripts\python.exe"

# Auto-élévation si le script n'est pas déjà lancé en admin.
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "Élévation des privilèges (UAC)..." -ForegroundColor Yellow
    Start-Process powershell -Verb RunAs -ArgumentList "-ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`""
    exit
}

if (-not (Test-Path $py)) {
    Write-Host "Environnement Python introuvable : $py" -ForegroundColor Red
    Write-Host "Lance d'abord l'installation (setup.ps1)." -ForegroundColor Red
    Read-Host "Entrée pour fermer"
    exit 1
}

Write-Host "RED — moteur en ADMIN (capture pktmon active) sur http://127.0.0.1:8787" -ForegroundColor Green
Set-Location (Join-Path $root "engine")
& $py -m uvicorn app.main:app --host 127.0.0.1 --port 8787
