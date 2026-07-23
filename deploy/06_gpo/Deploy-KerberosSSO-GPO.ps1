#Requires -Version 5.1
#Requires -Modules GroupPolicy
<#
=================================================================================
 Deploy-KerberosSSO-GPO.ps1
 Cree/met a jour une GPO qui permet aux navigateurs des postes du domaine de
 negocier Kerberos vers Authentik (AuthHostname) sans invite de mot de passe,
 et pre-provisionne le serveur pour l'extension navigateur Bitwarden. A
 executer depuis un poste/serveur avec RSAT GPMC (typiquement le DC).
 Parametres par defaut lus depuis deploy/environment.env (via
 . .\deploy\00_Set-Environment.ps1). Script 100% ASCII. Splatting uniquement.
---------------------------------------------------------------------------------
 Couvre (via Set-GPRegistryValue, verifie contre la documentation officielle
 au moment de la redaction) :
  - Zone Intranet (IE/Edge legacy engine) : Site to Zone Assignment List.
  - Chrome/Edge : AuthServerAllowlist = AuthHostname.
  - Extension navigateur Bitwarden (Chrome/Edge/Firefox) : cle "3rdparty"
    pre-provisionnant le serveur self-host (evite la saisie manuelle du
    baseURL au premier lancement de l'extension). Source verifiee :
    bitwarden.com/help (registre "environment" sous 3rdparty\extensions).
  - Signet gere Chrome (ManagedBookmarks) / Edge (ManagedFavorites) pointant
    vers $VaultBaseUrl/#/sso?identifier=... : ce lien declenche l'auto-submit
    cote client (sso.component.ts, bitwarden/clients) et court-circuite les
    ecrans email + identifiant SSO du web-vault -- poste du domaine = SPNEGO
    immediat au clic, aucune saisie. La valeur du parametre "identifier" DOIT
    rester l'identifiant magique '00000000-01DC-01DC-01DC-000000000000' --
    voir le commentaire sur $SsoIdentifier ci-dessous, piege deja rencontre
    avec une valeur lisible qui casse l'enrollment TDE en aval.
    Le formulaire email/mot de passe classique reste intact et accessible
    (poste hors domaine, break-glass) -- ce signet est un raccourci, pas une
    restriction serveur (SSO_ONLY reste sous le controle du gate Phase 5.7).
  - Firefox network.negotiate-auth.trusted-uris + signet SSO : genere
    dynamiquement (a partir de $AuthHostname/$SsoDeepLink, PAS d'un fichier
    fige) et deploye directement dans SYSVOL (\\<DomainDns>\SYSVOL\<DomainDns>
    \scripts\firefox-policies.json) -- voir etape 6 plus bas. Il ne reste plus
    qu'a router ce fichier vers distribution\policies.json sur les postes
    (GPO Files preference ou script de connexion, cf. WARN en fin de script) ;
    deploy/06_gpo/firefox-policies.json.example montre juste le resultat attendu,
    ce n'est plus lui qui est deploye.
 NE couvre PAS (limitations documentees, actions manuelles requises) :
  - Client desktop Bitwarden (Electron) : aucun mecanisme officiel de
    pre-provisioning du baseURL via registre a la date de redaction ; laisser
    la saisie manuelle unique (persistee par profil) ou s'appuyer sur un lien
    de connexion direct.
  - AuthNegotiateDelegateAllowlist : delibinerement NON configure (pas de
    delegation Kerberos = pas de surface KCD supplementaire).
---------------------------------------------------------------------------------
 EXEMPLE :
  . .\deploy\00_Set-Environment.ps1
  cd deploy\06_gpo
  .\Deploy-KerberosSSO-GPO.ps1                       # tout pris depuis l'environnement

  # ou explicitement, sans config prealable :
  .\Deploy-KerberosSSO-GPO.ps1 -TargetOuDn 'OU=Postes,DC=example,DC=local' `
     -AuthHostname 'auth.example.local' -VaultBaseUrl 'https://vault.example.local' `
     -DomainDns 'example.local'
=================================================================================
#>
[CmdletBinding()]
param(
    [string] $GpoName = 'Kerberos-SSO-Browsers',
    [string] $TargetOuDn = $env:GPO_TARGET_OU_DN,           # DN de l'OU contenant les postes clients
    [string] $AuthHostname = $env:AUTH_HOSTNAME,
    [string] $VaultBaseUrl = $(if ($env:VAULT_HOSTNAME) { "https://$($env:VAULT_HOSTNAME)" } else { $null }),
    [string] $DomainDns = $env:DOMAIN_DNS,                  # pour le depot SYSVOL de firefox-policies.json (etape 6)
    [string] $BitwardenChromeExtId = 'nngceckbapebfimnlniiiahkandclblb',   # meme ID Chrome et Edge (store Chromium)
    [string] $BitwardenFirefoxExtId = '{446900e4-71c2-419f-a6a7-df9c091e268b}',
    # NE PAS CHANGER cette valeur pour un texte lisible (piege deja rencontre : une
    # valeur arbitraire comme "vaultwardensso" satisfait bien /connect/authorize
    # -- mono-instance/mono-IdP, aucune validation server-side a ce stade -- MAIS
    # casse l'etape suivante de l'enrollment TDE. OIDCWarden expose une route
    # dediee, sans garde d'appartenance a l'organisation, UNIQUEMENT sur cet
    # identifiant magique exact :
    #   GET /organizations/00000000-01DC-01DC-01DC-000000000000/policies/master-password
    # (cf. src/api/core/organizations.rs, get_dummy_master_password_policy, rank=1).
    # Avec toute autre valeur, cette requete tombe sur la route generique (rank=2)
    # qui exige une adhesion CONFIRMEE a l'organisation -- or au moment de cet appel
    # l'utilisateur est seulement invite (pending), pas confirme : 401 "Error
    # getting the organization id", ecran de creation du mot de passe principal qui
    # ne se charge jamais. Confirme en lab.
    [string] $SsoIdentifier = $(if ($env:SSO_ORG_ENROLLMENT_IDENTIFIER) { $env:SSO_ORG_ENROLLMENT_IDENTIFIER } else { '00000000-01DC-01DC-01DC-000000000000' })
)
foreach ($p in @('TargetOuDn','AuthHostname','VaultBaseUrl','DomainDns')) {
    if ([string]::IsNullOrWhiteSpace((Get-Variable -Name $p -ValueOnly))) {
        throw "-$p requis : le passer explicitement, ou executer d'abord '. .\deploy\00_Set-Environment.ps1' (deploy\environment.env rempli)."
    }
}
# Lien direct qui court-circuite l'ecran email + l'ecran "identifiant d'organisation"
# du web-vault : sso.component.ts declenche un submit() automatique des le ngOnInit
# quand le query param "identifier" est present (comportement documente comme
# "IdP-initiated SSO" par Bitwarden). Poste du domaine => Kerberos SPNEGO prend le
# relais sans aucune saisie. Le formulaire email/mot de passe classique reste
# accessible normalement (poste hors domaine, break-glass) : ce lien n'est qu'un
# raccourci, il ne desactive rien cote serveur.
$SsoDeepLink = "$VaultBaseUrl/#/sso?identifier=$SsoIdentifier"
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

# --- 5. Signet navigateur : acces direct au flow SSO (sans email/identifiant) --
# N'ecrase pas les signets existants de l'utilisateur : ManagedBookmarks/ManagedFavorites
# ajoute un dossier gere en plus, il ne remplace pas la barre de signets locale.
Info "Signet gere -> $SsoDeepLink (court-circuite l'ecran email + identifiant SSO)"
$bookmarksJson = (@(
    @{ toplevel_name = 'Vaultwarden' },
    @{ name = 'Vaultwarden (SSO)'; url = $SsoDeepLink }
) | ConvertTo-Json -Compress)

Set-GPRegistryValue -Name $GpoName -Key 'HKLM\SOFTWARE\Policies\Google\Chrome' -ValueName 'ManagedBookmarks' -Type String -Value $bookmarksJson | Out-Null
Set-GPRegistryValue -Name $GpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Edge' -ValueName 'ManagedFavorites' -Type String -Value $bookmarksJson | Out-Null
Ok "Signet gere applique (Chrome: ManagedBookmarks, Edge: ManagedFavorites)"

# --- 6. Firefox : network.negotiate-auth.trusted-uris + signet, genere et depose
#    dans SYSVOL (pas de registre ADMX Mozilla assez stable pour Set-GPRegistryValue
#    -- Firefox lit sa policy depuis distribution\policies.json). Genere ICI a
#    partir des memes variables que le reste du script -- deploy/06_gpo/firefox-
#    policies.json.example n'est qu'une illustration statique, plus la source
#    reellement deployee. --------------------------------------------------------
Info "Generation de firefox-policies.json ($AuthHostname trusted, signet SSO)"
$firefoxPolicy = [ordered]@{
    policies = [ordered]@{
        NegotiateAuth = @{ Trusted = @("https://$AuthHostname") }
        Bookmarks = @(
            [ordered]@{
                Title     = 'Vaultwarden (SSO)'
                URL       = $SsoDeepLink
                Placement = 'toolbar'
                Folder    = 'Vaultwarden'
            }
        )
    }
} | ConvertTo-Json -Depth 6

$sysvolScriptsDir = "\\$DomainDns\SYSVOL\$DomainDns\scripts"
try {
    New-Item -ItemType Directory -Force -Path $sysvolScriptsDir -ErrorAction Stop | Out-Null
    Set-Content -Path (Join-Path $sysvolScriptsDir 'firefox-policies.json') -Value $firefoxPolicy -Encoding ascii -ErrorAction Stop
    Ok "firefox-policies.json depose dans $sysvolScriptsDir (reproduit sur SYSVOL, disponible sur tous les DC apres convergence)"
} catch {
    Warn "Depot SYSVOL echoue ($_) -- generer/copier firefox-policies.json manuellement (voir ci-dessous)."
}

Write-Host ""
Ok "GPO '$GpoName' configuree et liee. gpupdate /force sur un poste test avant validation."
Warn "Firefox : copier $sysvolScriptsDir\firefox-policies.json vers"
Warn "  %ProgramFiles%\Mozilla Firefox\distribution\policies.json sur chaque poste"
Warn "  (GPO Files preference ou script de connexion) puis verifier about:policies sur un poste test."
Warn "Desktop Bitwarden (Electron) : pas de pre-provisioning baseURL automatise, saisie manuelle unique."
Warn "GATE : gpresult /r sur un poste test + DevTools -> en-tete 'Authorization: Negotiate' sur la requete vers $AuthHostname."
Warn "GATE signet : ouvrir $SsoDeepLink sur un poste test -> aucun ecran email/identifiant, redirection SPNEGO immediate."
