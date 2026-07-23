# Signature de code — RED SHIELD (Windows)

La tuyauterie de signature est **déjà câblée** dans la CI. Il ne manque que le
certificat. Ce document explique quoi acheter, comment le déposer, et ce que la
signature résout (et ne résout pas).

## Ce que la signature résout — et ne résout pas

- ✅ **Distribution** : plus d'avertissement SmartScreen effrayant quand un client
  installe l'application. C'est le vrai gain.
- ⚠️ **Smart App Control (SAC)** : SAC (Windows 11, mode *Enforce*) exige signature
  **ET** réputation. Un exécutable fraîchement signé peut rester bloqué tant qu'il
  n'a pas de réputation Microsoft. Seul un certificat **EV** donne une confiance
  plus immédiate — sans garantie d'instantanéité sous SAC. **Sur une machine SAC
  Enforce, le plus fiable reste de lancer depuis les sources** (le mode dev).

## Quel certificat prendre

| Type | Prix indicatif | SmartScreen | SAC | Remarque |
|------|----------------|-------------|-----|----------|
| **OV** (Organization Validation) | ~200-400 €/an | réputation à construire | souvent bloqué au début | validation d'identité de l'entité |
| **EV** (Extended Validation) | ~300-600 €/an | confiance immédiate | meilleur, sans garantie | jeton matériel (HSM/clé USB) ou HSM cloud |

Émetteurs courants : DigiCert, Sectigo, GlobalSign, SSL.com. Pour DP Cyber
Consulting, prévoir la **validation d'identité de l'entreprise** (extrait Kbis /
justificatifs selon la CA).

> ⚠️ Depuis juin 2023, les certificats OV/EV doivent résider sur un support
> cryptographique (jeton matériel ou HSM cloud). Un simple fichier `.pfx`
> exportable n'est possible que via une offre **HSM cloud avec export** ou un
> ancien certificat. Vérifier l'option « signature automatisée / CI » à l'achat.

## Déposer le certificat dans la CI

La CI attend **deux secrets** de dépôt (Settings → Secrets and variables → Actions) :

1. `WINDOWS_CERTIFICATE` — le fichier PFX encodé en **base64**.
2. `WINDOWS_CERTIFICATE_PASSWORD` — le mot de passe du PFX.

Encoder le PFX en base64 (PowerShell) :

```powershell
[Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\chemin\vers\cert.pfx")) | Set-Clipboard
```

Coller le résultat dans le secret `WINDOWS_CERTIFICATE`.

> Si la CA impose un jeton matériel (pas de PFX exportable), la signature ne peut
> pas passer par un secret PFX : il faut un **runner self-hosted** avec le jeton
> branché, ou l'**HSM cloud** de la CA (signature via API). Dans ce cas, adapter
> l'étape « Signature » du workflow au client de signature fourni par la CA.

## Ce qui se passe au build

Le workflow [`build-desktop.yml`](../.github/workflows/build-desktop.yml) contient
une étape **« Signature (sidecar + config installeur) »** :

- **Sans les secrets** → l'étape est **sautée** : build non signé, exactement comme
  aujourd'hui (aucune régression).
- **Avec les secrets** → l'étape :
  1. décode et importe le PFX, récupère l'empreinte (thumbprint) ;
  2. signe le **sidecar** `red-engine.exe` avec `signtool` (Tauri ne signe pas les
     `externalBin`, donc on le fait explicitement) ;
  3. injecte l'empreinte dans `tauri.conf.json` → **Tauri signe l'installeur NSIS**
     au build.

Horodatage RFC3161 via `http://timestamp.digicert.com` (la signature reste valide
après expiration du certificat).

Rien n'est signé côté dépôt : `tauri.conf.json` ne contient **pas** de config de
signature (elle est injectée en CI uniquement), et aucun certificat/secret n'est
versionné.

## Vérifier une signature (après build)

```powershell
Get-AuthenticodeSignature "RED SHIELD_x.y.z_x64-setup.exe" | Format-List
signtool verify /pa /v "RED SHIELD_x.y.z_x64-setup.exe"
```

## Test local (facultatif, certificat auto-signé)

Un certificat auto-signé permet de **tester la mécanique** mais **ne satisfait ni
SmartScreen ni SAC** — inutile pour distribuer.

```powershell
$c = New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=DP Cyber Consulting (TEST)" `
     -CertStoreLocation Cert:\CurrentUser\My
$pw = ConvertTo-SecureString "test1234" -AsPlainText -Force
Export-PfxCertificate -Cert $c -FilePath test-cert.pfx -Password $pw
# puis signer un exe :
# signtool sign /sha1 $($c.Thumbprint) /fd sha256 mon.exe
```
