#Requires -Version 5.1
#Requires -Modules ActiveDirectory, ADFS
<#
=================================================================================
 Deploy-VaultwardenAdfs.ps1
 Automatise la configuration AD FS pour le SSO OIDC Vaultwarden.
 Script 100% ASCII (evite le piege d'encodage PS 5.1 / UTF-8 sans BOM).
---------------------------------------------------------------------------------
 SECURITY BY DESIGN :
  - Moindre privilege : mode 'Group' restreint l'acces au seul groupe cible ;
    n'emet que le claim email (pas de deversement d'attributs via allatclaims).
  - Idempotent autant que possible ; verifie l'existant avant de creer.
  - N'ecrit AUCUN secret dans un log ; le secret client est retourne UNE fois.
  - Active l'audit d'emission (event 501) pour la tracabilite / SIEM.
---------------------------------------------------------------------------------
 EXEMPLES :
  # Mode groupe restreint (recommande)
  .\Deploy-VaultwardenAdfs.ps1 -VaultFqdn 'vault.vaultwardensso.local' `
     -AccessMode Group -GroupName 'grp-vaultwarden'

  # Mode tous les utilisateurs du domaine
  .\Deploy-VaultwardenAdfs.ps1 -VaultFqdn 'vault.vaultwardensso.local' `
     -AccessMode Everyone
=================================================================================
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $VaultFqdn,                 # ex. vault.vaultwardensso.local
    [string] $AppGroupName   = 'Vaultwarden',
    [ValidateSet('Group','Everyone')] [string] $AccessMode = 'Group',
    [string] $GroupName      = 'grp-vaultwarden',               # utilise si AccessMode=Group
    [switch] $EnableMfa,                                        # impose MFA par RP (recommande, obligatoire en mode Everyone)
    [switch] $ResetSecret                                       # regenere le secret client
)

$ErrorActionPreference = 'Stop'
function Info($m){ Write-Host "[INFO] $m" -ForegroundColor Cyan }
function Ok($m){ Write-Host "[ OK ] $m" -ForegroundColor Green }
function Warn($m){ Write-Host "[WARN] $m" -ForegroundColor Yellow }

$RedirectUri = "https://$VaultFqdn/identity/connect/oidc-signin"

# --- 0. Controles prealables ----------------------------------------------------
Info "Verification des modules et de la ferme AD FS"
Import-Module ActiveDirectory, ADFS
$svc = Get-Service adfssrv -ErrorAction SilentlyContinue
if (-not $svc -or $svc.Status -ne 'Running') { throw "Service adfssrv absent ou arrete. Configurer la ferme AD FS d'abord." }

if ($AccessMode -eq 'Group') {
    $grp = Get-ADGroup -Identity $GroupName -ErrorAction SilentlyContinue
    if (-not $grp) { throw "Groupe '$GroupName' introuvable. Le creer et y ajouter les membres avant." }
    $grpSid = $grp.SID.Value
    Ok "Mode Group : acces restreint a '$GroupName' (SID $grpSid)"
} else {
    Warn "Mode Everyone : TOUS les comptes AD activés pourront s'authentifier. MFA fortement recommande (-EnableMfa)."
}

# --- 1. Application Group + Server Application ----------------------------------
$grpApp = Get-AdfsApplicationGroup -Name $AppGroupName -ErrorAction SilentlyContinue
if (-not $grpApp) {
    Info "Creation de l'Application Group '$AppGroupName'"
    New-AdfsApplicationGroup -Name $AppGroupName | Out-Null
}

$srvApp = Get-AdfsServerApplication -Name "$AppGroupName Server" -ErrorAction SilentlyContinue
if (-not $srvApp) {
    Info "Creation de la Server Application (client confidentiel)"
    $clientId = [guid]::NewGuid().ToString()
    Add-AdfsServerApplication -Name "$AppGroupName Server" -ApplicationGroupIdentifier $AppGroupName `
        -Identifier $clientId -RedirectUri $RedirectUri -GenerateClientSecret | Out-Null
    $srvApp = Get-AdfsServerApplication -Name "$AppGroupName Server"
    Ok "Server Application creee. Client ID = $($srvApp.Identifier)"
} else {
    Info "Server Application existante (Client ID = $($srvApp.Identifier))"
    # S'assurer que le Redirect URI est correct
    if ($srvApp.RedirectUri -notcontains $RedirectUri) {
        Set-AdfsServerApplication -TargetIdentifier $srvApp.Identifier -RedirectUri $RedirectUri
        Ok "Redirect URI mis a jour : $RedirectUri"
    }
}
$clientId = $srvApp.Identifier

# --- 2. Secret client -----------------------------------------------------------
if ($ResetSecret) {
    Warn "Regeneration du secret client (revoque l'ancien immediatement)"
    $new = Set-AdfsServerApplication -TargetIdentifier $clientId -ResetClientSecret -PassThru
    $script:ClientSecret = $new.ClientSecret
}

# --- 3. Web API -----------------------------------------------------------------
$webApi = Get-AdfsWebApiApplication -Name "$AppGroupName Web API" -ErrorAction SilentlyContinue
if (-not $webApi) {
    Info "Creation du Web API"
    Add-AdfsWebApiApplication -Name "$AppGroupName Web API" -ApplicationGroupIdentifier $AppGroupName `
        -Identifier $clientId | Out-Null
    $webApi = Get-AdfsWebApiApplication -Name "$AppGroupName Web API"
}

# --- 4. Regle d'emission des claims (email uniquement, moindre privilege) --------
Info "Application de la regle d'emission (email depuis l'attribut mail)"
$rules = @'
@RuleTemplate = "LdapClaims"
@RuleName = "Vaultwarden email"
c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"]
 => issue(store = "Active Directory",
    types = ("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"),
    query = ";mail;{0}", param = c.Value);
'@
Set-AdfsWebApiApplication -TargetIdentifier $clientId -IssuanceTransformRules $rules
# NOTE : on N'emet PAS email_verified (AD FS le serialise en string -> Vaultwarden rejette).
#        Couvert par SSO_ALLOW_UNKNOWN_EMAIL_VERIFICATION=true cote Vaultwarden.

# --- 5. Politique d'acces (selon le mode) ---------------------------------------
if ($AccessMode -eq 'Group') {
    Info "Politique d'acces : Permit $GroupName only"
    $authz = @"
@RuleTemplate = "Authorization"
@RuleName = "Permit $GroupName only"
c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid", Value == "$grpSid"]
 => issue(Type = "http://schemas.microsoft.com/authorization/claims/permit", Value = "PermitUsersWithClaim");
"@
    Set-AdfsWebApiApplication -TargetIdentifier $clientId -IssuanceAuthorizationRules $authz
} else {
    Info "Politique d'acces : Permit everyone (mode Everyone)"
    $authzAll = '=> issue(Type = "http://schemas.microsoft.com/authorization/claims/permit", Value = "true");'
    Set-AdfsWebApiApplication -TargetIdentifier $clientId -IssuanceAuthorizationRules $authzAll
}

# --- 6. Scopes : openid email profile offline_access + allatclaims (CRITIQUE) ----
Info "Configuration des scopes (dont allatclaims - indispensable pour l'emission des claims custom)"
$perm = Get-AdfsApplicationPermission | Where-Object { $_.ClientRoleIdentifier -eq $clientId }
$wanted = @('openid','email','profile','offline_access','allatclaims')
if (-not $perm) {
    Grant-AdfsApplicationPermission -ClientRoleIdentifier $clientId -ServerRoleIdentifier $clientId -ScopeNames $wanted | Out-Null
} else {
    # La permission existe : AJOUTER les scopes manquants (Grant- echouerait en MSIS7626)
    foreach ($s in $wanted) {
        if ($perm.ScopeNames -notcontains $s) {
            Set-AdfsApplicationPermission -TargetIdentifier $perm.ObjectIdentifier -AddScope $s
        }
    }
}
$perm = Get-AdfsApplicationPermission | Where-Object { $_.ClientRoleIdentifier -eq $clientId }
Ok "Scopes : $($perm.ScopeNames -join ', ')"

# --- 7. Durcissement : Extranet Smart Lockout + MFA + audit ---------------------
Info "Durcissement IdP"
try {
    Set-AdfsProperties -EnableExtranetLockout $true -ExtranetLockoutThreshold 5 `
        -ExtranetObservationWindow (New-TimeSpan -Minutes 15) -ExtranetLockoutMode ADFSSmartLockoutLogOnly
    Ok "Extranet Smart Lockout active (mode observation)"
} catch { Warn "Extranet Lockout non applique : $($_.Exception.Message)" }

if ($EnableMfa -or $AccessMode -eq 'Everyone') {
    Info "Activation MFA par relying party (recommande ; obligatoire en mode Everyone)"
    $mfaRule = if ($AccessMode -eq 'Group') {
@"
c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid", Value == "$grpSid"]
 => issue(Type = "http://schemas.microsoft.com/ws/2008/06/identity/claims/authnmethodsreferences",
          Value = "http://schemas.microsoft.com/claims/multipleauthn");
"@
    } else {
@'
=> issue(Type = "http://schemas.microsoft.com/ws/2008/06/identity/claims/authnmethodsreferences",
         Value = "http://schemas.microsoft.com/claims/multipleauthn");
'@
    }
    try { Set-AdfsWebApiApplication -TargetIdentifier $clientId -AdditionalAuthenticationRules $mfaRule; Ok "MFA impose" }
    catch { Warn "MFA non applique (provider MFA configure ?) : $($_.Exception.Message)" }
}

# Audit d'emission de jeton (event 501 - diagnostic + SIEM), via GUID insensible a la langue
try {
    auditpol /set /subcategory:"{0CCE9222-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable | Out-Null
    Ok "Audit 'Application Generated' active (event 501)"
} catch { Warn "Audit non active : $($_.Exception.Message)" }

# --- 8. Redemarrage + restitution ------------------------------------------------
Info "Redemarrage du service AD FS (micro-coupure d'auth)"
Restart-Service adfssrv

Write-Host ""
Write-Host "================= RESULTAT =================" -ForegroundColor Green
Write-Host "CLIENT_ID     = $clientId"
if ($ResetSecret) {
    Write-Host "CLIENT_SECRET = $script:ClientSecret   (AFFICHE UNE FOIS - stocker en coffre)" -ForegroundColor Yellow
} else {
    Write-Host "CLIENT_SECRET = (inchange ; relancer avec -ResetSecret pour regenerer)"
}
Write-Host "AUTHORITY     = https://$((Get-AdfsProperties).HostName)/adfs   (reporter la CASSE EXACTE)"
Write-Host "REDIRECT_URI  = $RedirectUri"
Write-Host "SCOPES        = $($perm.ScopeNames -join ', ')"
Write-Host "ACCESS_MODE   = $AccessMode $(if($AccessMode -eq 'Group'){"($GroupName)"})"
Write-Host "===========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Prochaines etapes cote Vaultwarden : renseigner CLIENT_ID/SECRET/AUTHORITY," 
Write-Host "scopes 'email profile offline_access', SSO_ALLOW_UNKNOWN_EMAIL_VERIFICATION=true."
