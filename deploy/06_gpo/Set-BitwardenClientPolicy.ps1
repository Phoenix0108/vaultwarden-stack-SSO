#Requires -Version 5.1
<#
=================================================================================
 Set-BitwardenClientPolicy.ps1
 Pre-provisioning du serveur self-host (baseURL) pour l'extension navigateur
 Bitwarden (Chrome, Edge, Firefox), EN LOCAL sur la machine ou ce script est
 execute -- alternative/complement a la GPO fleet
 (deploy/06_gpo/Deploy-KerberosSSO-GPO.ps1) pour un test manuel poste par poste,
 ou une machine hors perimetre GPO. Remplace l'ancien Deploy-BitwardenClients.reg
 statique (une valeur -VaultBaseUrl en dur par site = pas reutilisable) par un
 script parametre, coherent avec deploy/environment.env comme les autres.
---------------------------------------------------------------------------------
 Portee : UNIQUEMENT l'extension navigateur. Le client desktop Bitwarden
 (Electron) n'a pas de mecanisme officiel equivalent a la date de redaction :
 laisser la saisie manuelle unique du serveur (persistee par profil).

 A verifier avant deploiement : ces chemins de registre suivent le mecanisme
 documente par Bitwarden (cle "3rdparty" / storage.managed) au moment de la
 redaction ; revalider contre la version d'extension deployee avant usage en
 masse (bitwarden.com/help/managed-browser-extension).
---------------------------------------------------------------------------------
 EXEMPLE :
  . .\deploy\00_Set-Environment.ps1
  .\deploy\06_gpo\Set-BitwardenClientPolicy.ps1        # -VaultBaseUrl pris depuis l'environnement

  # ou explicitement :
  .\deploy\06_gpo\Set-BitwardenClientPolicy.ps1 -VaultBaseUrl 'https://vault.example.local'
=================================================================================
#>
[CmdletBinding()]
param(
    [string] $VaultBaseUrl = $(if ($env:VAULT_HOSTNAME) { "https://$($env:VAULT_HOSTNAME)" } else { $null }),
    [string] $BitwardenChromeExtId = 'nngceckbapebfimnlniiiahkandclblb',   # meme ID Chrome et Edge (store Chromium)
    [string] $BitwardenFirefoxExtId = '{446900e4-71c2-419f-a6a7-df9c091e268b}'
)
$ErrorActionPreference = 'Stop'
function Info($m){ Write-Host "[INFO] $m" -ForegroundColor Cyan }
function Ok($m){ Write-Host "[ OK ] $m" -ForegroundColor Green }

if ([string]::IsNullOrWhiteSpace($VaultBaseUrl)) {
    throw "-VaultBaseUrl requis : le passer explicitement, ou executer d'abord '. .\deploy\00_Set-Environment.ps1' (deploy\environment.env rempli)."
}

Info "Pre-provisioning local de l'extension Bitwarden : base = $VaultBaseUrl"
$envJson = (@{ base = $VaultBaseUrl } | ConvertTo-Json -Compress)

$targets = @(
    "HKLM:\SOFTWARE\Policies\Google\Chrome\3rdparty\extensions\$BitwardenChromeExtId\policy",
    "HKLM:\SOFTWARE\Policies\Microsoft\Edge\3rdparty\extensions\$BitwardenChromeExtId\policy",
    "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\3rdparty\Extensions\$BitwardenFirefoxExtId"
)
foreach ($key in $targets) {
    New-Item -Path $key -Force | Out-Null
    Set-ItemProperty -Path $key -Name 'environment' -Value $envJson -Type String
    Ok "Applique : $key"
}

Write-Host ""
Ok "Extension Bitwarden pre-provisionnee localement (Chrome, Edge, Firefox) : base = $VaultBaseUrl"
