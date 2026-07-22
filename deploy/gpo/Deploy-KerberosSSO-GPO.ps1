#Requires -Version 5.1
#Requires -Modules GroupPolicy
<#
=================================================================================
 Deploy-KerberosSSO-GPO.ps1
 Cree/met a jour une GPO qui permet aux navigateurs des postes du domaine de
 negocier Kerberos vers Authentik (auth.vaultwardensso.local) sans invite de
 mot de passe, et pre-provisionne le serveur pour l'extension navigateur
 Bitwarden. A executer depuis un poste/serveur avec RSAT GPMC (typiquement
 le DC). Script 100% ASCII. Splatting uniquement.
---------------------------------------------------------------------------------
 Couvre (via Set-GPRegistryValue, verifie contre la documentation officielle
 au moment de la redaction) :
  - Zone Intranet (IE/Edge legacy engine) : Site to Zone Assignment List.
  - Chrome/Edge : AuthServerAllowlist = auth.vaultwardensso.local.
  - Extension navigateur Bitwarden (Chrome/Edge/Firefox) : cle "3rdparty"
    pre-provisionnant le serveur self-host (evite la saisie manuelle du
    baseURL au premier lancement de l'extension). Source verifiee :
    bitwarden.com/help (registre "environment" sous 3rdparty\extensions).
 NE couvre PAS (limitations documentees, actions manuelles requises) :
  - Firefox network.negotiate-auth.trusted-uris : le schema de registre exact
    de l'ADMX Mozilla n'est pas assez stable/documente pour etre pousse en
    aveugle ici. Utiliser deploy/gpo/firefox-policies.json (GPO Files
    preference vers distribution\policies.json), cf. WARN en fin de script.
  - Client desktop Bitwarden (Electron) : aucun mecanisme officiel de
    pre-provisioning du baseURL via registre a la date de redaction ; laisser
    la saisie manuelle unique (persistee par profil) ou s'appuyer sur un lien
    de connexion direct.
  - AuthNegotiateDelegateAllowlist : delibinerement NON configure (pas de
    delegation Kerberos = pas de surface KCD supplementaire).
---------------------------------------------------------------------------------
 EXEMPLE :
  .\Deploy-KerberosSSO-GPO.ps1 -TargetOuDn 'OU=Postes,DC=vaultwardensso,DC=local' `
     -AuthHostname 'auth.vaultwardensso.local' -VaultBaseUrl 'https://vault.vaultwardensso.local'
=================================================================================
#>
[CmdletBinding()]
param(
    [string] $GpoName = 'Kerberos-SSO-Browsers',
    [Parameter(Mandatory)] [string] $TargetOuDn,           # DN de l'OU contenant les postes clients
    [string] $AuthHostname = 'auth.vaultwardensso.local',
    [string] $VaultBaseUrl = 'https://vault.vaultwardensso.local',
    [string] $BitwardenChromeExtId = 'nngceckbapebfimnlniiiahkandclblb',   # meme ID Chrome et Edge (store Chromium)
    [string] $BitwardenFirefoxExtId = '{446900e4-71c2-419f-a6a7-df9c091e268b}'
)
$ErrorActionPreference = 'Stop'
function Info($m){ Write-Host "[INFO] $m" -ForegroundColor Cyan }
function Ok($m){ Write-Host "[ OK ] $m" -ForegroundColor Green }
function Warn($m){ Write-Host "[WARN] $m" -ForegroundColor Yellow }

Import-Module GroupPolicy

# --- 0. GPO : creation idempotente ---------------------------------------------
$gpo = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue
if (-not $gpo) {
    Info "Creation de la GPO '$GpoName'"
    $gpo = New-GPO -Name $GpoName -Comment 'Negociation Kerberos navigateurs + pre-provisioning extension Bitwarden (SSO passwordless)'
} else {
    Info "GPO '$GpoName' existante, mise a jour des valeurs"
}

# --- 1. Lien sur l'OU cible (idempotent) ---------------------------------------
$existingLink = (Get-GPInheritance -Target $TargetOuDn).GpoLinks | Where-Object { $_.GpoId -eq $gpo.Id }
if (-not $existingLink) {
    Info "Lien de '$GpoName' sur $TargetOuDn"
    New-GPLink -Guid $gpo.Id -Target $TargetOuDn -LinkEnabled Yes | Out-Null
} else {
    Ok "GPO deja liee a $TargetOuDn"
}

# --- 2. Zone Intranet (IE/Edge legacy engine) : Site to Zone Assignment List ---
# Domaine parent + hote, ex: vaultwardensso.local / auth -> zone 1 (Intranet)
$parts = $AuthHostname.Split('.', 2)
$hostLabel = $parts[0]
$parentDomain = $parts[1]
$zoneKey = "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\$parentDomain\$hostLabel"
Info "Site to Zone Assignment : $AuthHostname -> Zone 1 (Intranet)"
Set-GPRegistryValue -Name $GpoName -Key $zoneKey -ValueName 'https' -Type DWord -Value 1 | Out-Null
Ok "Zone assignment applique (cle unique, pas de wildcard *.local)"

# --- 3. Chrome / Edge : AuthServerAllowlist ------------------------------------
Info "Chrome/Edge AuthServerAllowlist = $AuthHostname (allowlist stricte, un seul FQDN)"
Set-GPRegistryValue -Name $GpoName -Key 'HKLM\SOFTWARE\Policies\Google\Chrome' -ValueName 'AuthServerAllowlist' -Type String -Value $AuthHostname | Out-Null
Set-GPRegistryValue -Name $GpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Edge' -ValueName 'AuthServerAllowlist' -Type String -Value $AuthHostname | Out-Null
Ok "AuthServerAllowlist applique (Chrome + Edge)"
Warn "AuthNegotiateDelegateAllowlist volontairement NON configure (pas de delegation Kerberos)."

# --- 4. Extension Bitwarden : pre-provisioning du serveur self-host -----------
# Cle "3rdparty\extensions\<id>\policy\environment" -> valeur "base" = URL serveur.
# Permet a l'extension de ne pas redemander l'URL au premier lancement.
Info "Pre-provisioning extension Bitwarden (Chrome, Edge, Firefox) : base = $VaultBaseUrl"
$envJson = (@{ base = $VaultBaseUrl } | ConvertTo-Json -Compress)

$chromeExtKey = "HKLM\SOFTWARE\Policies\Google\Chrome\3rdparty\extensions\$BitwardenChromeExtId\policy"
Set-GPRegistryValue -Name $GpoName -Key $chromeExtKey -ValueName 'environment' -Type String -Value $envJson | Out-Null

$edgeExtKey = "HKLM\SOFTWARE\Policies\Microsoft\Edge\3rdparty\extensions\$BitwardenChromeExtId\policy"
Set-GPRegistryValue -Name $GpoName -Key $edgeExtKey -ValueName 'environment' -Type String -Value $envJson | Out-Null

$ffExtKey = "HKLM\SOFTWARE\Policies\Mozilla\Firefox\3rdparty\Extensions\$BitwardenFirefoxExtId"
Set-GPRegistryValue -Name $GpoName -Key $ffExtKey -ValueName 'environment' -Type String -Value $envJson | Out-Null
Ok "Cles 3rdparty appliquees (Chrome, Edge, Firefox)"

Write-Host ""
Ok "GPO '$GpoName' configuree et liee. gpupdate /force sur un poste test avant validation."
Warn "Firefox network.negotiate-auth.trusted-uris NON automatise ici : deployer"
Warn "  deploy/gpo/firefox-policies.json vers %ProgramFiles%\Mozilla Firefox\distribution\policies.json"
Warn "  (GPO Files preference ou script de connexion) puis verifier about:policies sur un poste test."
Warn "Desktop Bitwarden (Electron) : pas de pre-provisioning baseURL automatise, saisie manuelle unique."
Warn "GATE : gpresult /r sur un poste test + DevTools -> en-tete 'Authorization: Negotiate' sur la requete vers $AuthHostname."
