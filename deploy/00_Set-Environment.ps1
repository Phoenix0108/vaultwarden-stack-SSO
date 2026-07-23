#Requires -Version 5.1
<#
=================================================================================
 00_Set-Environment.ps1
 Charge deploy/environment.env (copie remplie de 00_environment.env.example) dans
 les variables d'environnement de la session PowerShell COURANTE. DOT-SOURCE
 OBLIGATOIRE (". .\deploy\00_Set-Environment.ps1"), sinon les variables ne
 survivent pas au retour du script -- un simple ".\00_Set-Environment.ps1"
 (sans le point) les definit dans un sous-processus qui disparait aussitot.
 Tous les autres scripts PowerShell de ce depot (deploy/04_kerberos, deploy/01_tls,
 deploy/06_gpo) lisent leurs parametres par defaut depuis ces variables : executer
 ce script UNE FOIS par session avant les autres, plutot que de retaper le
 realm/l'IP du DC/etc. sur chaque commande.
 Format attendu dans environment.env : KEY=VALUE par ligne, '#' = commentaire,
 lignes vides ignorees. Script 100% ASCII.
---------------------------------------------------------------------------------
 EXEMPLE :
  . .\deploy\00_Set-Environment.ps1
  . .\deploy\00_Set-Environment.ps1 -Path C:\vaultwarden-stack-SSO\deploy\environment.env
=================================================================================
#>
param(
    [string] $Path = (Join-Path $PSScriptRoot 'environment.env')
)

if (-not (Test-Path $Path)) {
    Write-Host "[FAIL] Fichier de configuration introuvable : $Path" -ForegroundColor Red
    Write-Host "       Copier deploy\00_environment.env.example vers deploy\environment.env et le renseigner d'abord." -ForegroundColor Red
    return
}

$count = 0
Get-Content -Path $Path | ForEach-Object {
    $line = $_.Trim()
    if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith('#')) { return }
    $idx = $line.IndexOf('=')
    if ($idx -lt 1) { return }
    $key = $line.Substring(0, $idx).Trim()
    $value = $line.Substring($idx + 1).Trim()
    Set-Item -Path "Env:$key" -Value $value
    $count++
}

Write-Host "[ OK ] $count variable(s) chargee(s) depuis $Path dans cette session PowerShell." -ForegroundColor Green
Write-Host "       Verifier : `$env:REALM, `$env:DC_IP, `$env:VAULT_HOSTNAME, `$env:AUTH_HOSTNAME, `$env:CLIENT_SUBNETS" -ForegroundColor Cyan
if ($env:CA_ROOT_THUMBPRINT -eq 'CHANGE_ME_SHA1_THUMBPRINT') {
    Write-Host "[WARN] CA_ROOT_THUMBPRINT est encore au placeholder -- deploy/environment.env n'a pas ete renseigne." -ForegroundColor Yellow
}
