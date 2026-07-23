#Requires -Version 5.1
#Requires -Modules ActiveDirectory
<#
=================================================================================
 Setup-LDAPBind-DC.ps1
 Provisionne le compte de bind LDAP utilise par la Source LDAP d'Authentik
 (provisioning/synchronisation des comptes utilisateurs -- distinct du compte
 SPNEGO svc-authentik-krb, qui ne sert qu'a valider les tickets Kerberos et ne
 doit jamais etre utilise pour un bind). A executer sur le DC. Parametres par
 defaut lus depuis deploy/environment.env (via . .\deploy\Set-Environment.ps1).
 Script 100% ASCII. Splatting uniquement.
---------------------------------------------------------------------------------
 Pourquoi ce script existe : deploy/authentik/README.md et kerberos-sso-blueprint.yaml
 supposent depuis le debut "une source LDAP existante (scope OU=Vaultwarden)"
 comme prerequis -- mais rien dans ce depot ne la provisionne. Sur un domaine
 reparti de zero, ce prerequis n'existe pas encore : ce script le cree.
---------------------------------------------------------------------------------
 Ce que fait ce script :
  - Cree l'OU cible (OU=Vaultwarden par defaut) si absente -- c'est le perimetre
    de recherche (base DN) que la Source LDAP interrogera. Les VRAIS comptes
    utilisateurs a synchroniser doivent y etre deplaces/crees separement (hors
    perimetre de ce script).
  - Cree svc-authentik-ldap : mot de passe aleatoire fort (jamais affiche/logge),
    PasswordNeverExpires, CannotChangePassword, AccountNotDelegated, membre de
    Domain Users UNIQUEMENT + groupe deny-interactive-logon (meme groupe que
    svc-authentik-krb, reutilise -- pas de logon interactif pour un compte de
    service, quel qu'il soit).
  - Place DELIBEREMENT ce compte HORS de l'OU cible (CN=Users par defaut, comme
    svc-authentik-krb) : s'il atterrissait dans le perimetre que la Source LDAP
    synchronise, Authentik tenterait de provisionner un "utilisateur" pour le
    compte de service lui-meme.
  - Aucune permission AD supplementaire accordee : les droits de lecture par
    defaut d'un compte authentifie (sAMAccountName, mail, memberOf, etc.)
    suffisent a un bind LDAP standard. Si l'ACL du domaine a ete durcie
    au-dela des defauts (AdminSDHolder, deny ACE explicites), l'ajuster
    manuellement -- hors perimetre de ce script.
  - Ecrit le mot de passe dans un fichier local a ACL restreinte (jamais affiche
    dans la console, jamais journalise) pour transfert via le meme canal
    smbclient deja utilise pour le keytab -- jamais retape a la main.
 Ce que ce script NE fait PAS (hors perimetre / actions manuelles requises) :
  - La configuration de la Source LDAP cote Authentik (Directory -> Federation
    & Social login -> Create -> LDAP Source) reste une action GUI manuelle
    (secret jamais transmis a un tiers scriptable) -- voir deploy/authentik/README.md.
  - Le peuplement de l'OU cible avec les vrais comptes utilisateurs a synchroniser.
  - Le transfert du fichier de mot de passe vers le Debian et sa suppression du
    DC APRES usage restent des etapes manuelles distinctes (meme discipline que
    le keytab Phase 2).
---------------------------------------------------------------------------------
 EXEMPLE :
  . .\deploy\Set-Environment.ps1
  cd deploy\kerberos
  .\Setup-LDAPBind-DC.ps1                   # -Realm/-Domain pris depuis l'environnement

  # ou explicitement :
  .\Setup-LDAPBind-DC.ps1 -Realm 'EXAMPLE.LOCAL' -Domain 'EXAMPLE'
=================================================================================
#>
[CmdletBinding()]
param(
    # Defauts lus depuis les variables d'environnement chargees par
    # ". .\deploy\Set-Environment.ps1" (deploy\environment.env).
    [string] $ServiceAccountName = $(if ($env:LDAP_BIND_ACCOUNT) { $env:LDAP_BIND_ACCOUNT } else { 'svc-authentik-ldap' }),
    [string] $TargetOuName = $(if ($env:LDAP_SYNC_OU_NAME) { $env:LDAP_SYNC_OU_NAME } else { 'Vaultwarden' }),   # OU=<TargetOuName> a la racine du domaine
    [string] $Realm = $env:REALM,                            # ex: EXAMPLE.LOCAL (force en MAJUSCULES)
    [string] $Domain = $env:DOMAIN_NETBIOS,                   # NetBIOS, ex: EXAMPLE
    [string] $DenyInteractiveGroup = $(if ($env:DENY_INTERACTIVE_GROUP) { $env:DENY_INTERACTIVE_GROUP } else { 'GG-SvcAccounts-DenyInteractiveLogon' }),
    [string] $PasswordOutFile = 'C:\authentik-ldap-bind.txt',
    [int] $PasswordLength = 28,
    [string] $DcIp = $env:DC_IP    # informatif uniquement (message final) -- pas utilise pour la creation du compte
)
$ErrorActionPreference = 'Stop'
function Info($m){ Write-Host "[INFO] $m" -ForegroundColor Cyan }
function Ok($m){ Write-Host "[ OK ] $m" -ForegroundColor Green }
function Warn($m){ Write-Host "[WARN] $m" -ForegroundColor Yellow }

foreach ($p in @('Realm','Domain')) {
    if ([string]::IsNullOrWhiteSpace((Get-Variable -Name $p -ValueOnly))) {
        throw "-$p requis : le passer explicitement, ou executer d'abord '. .\deploy\Set-Environment.ps1' (deploy\environment.env rempli)."
    }
}

$Realm = $Realm.ToUpperInvariant()

Import-Module ActiveDirectory

# --- 0. OU cible : creation idempotente ----------------------------------------
$domainDn = (Get-ADDomain).DistinguishedName
$ouDn = "OU=$TargetOuName,$domainDn"
Info "Verification de l'OU cible '$ouDn' (perimetre de recherche de la Source LDAP)"
$ou = Get-ADOrganizationalUnit -Filter "Name -eq '$TargetOuName'" -SearchBase $domainDn -SearchScope OneLevel -ErrorAction SilentlyContinue
if (-not $ou) {
    New-ADOrganizationalUnit -Name $TargetOuName -Path $domainDn -ProtectedFromAccidentalDeletion $true `
        -Description 'Perimetre des comptes utilisateurs synchronises par la Source LDAP Authentik (Vaultwarden SSO)'
    Ok "OU '$ouDn' creee"
} else {
    Ok "OU '$ouDn' deja presente"
}
$userCount = (Get-ADUser -Filter * -SearchBase $ouDn -SearchScope Subtree -ErrorAction SilentlyContinue | Measure-Object).Count
if ($userCount -eq 0) {
    Warn "OU '$ouDn' vide : aucun compte utilisateur a synchroniser pour l'instant. Deplacer/creer les comptes cibles avant de tester la synchronisation Authentik."
} else {
    Ok "$userCount compte(s) utilisateur trouve(s) dans '$ouDn'"
}

# --- 1. Groupe deny-interactive-logon : reutilise tel quel (idempotent) --------
Info "Verification du groupe de securite '$DenyInteractiveGroup' (cible GPO deny-logon)"
$grp = Get-ADGroup -Filter "Name -eq '$DenyInteractiveGroup'" -ErrorAction SilentlyContinue
if (-not $grp) {
    $grpArgs = @{
        Name = $DenyInteractiveGroup
        GroupScope = 'Global'
        GroupCategory = 'Security'
        Description = 'Comptes de service pour lesquels SeDenyInteractiveLogonRight/SeDenyRemoteInteractiveLogonRight doit etre applique via GPO'
    }
    New-ADGroup @grpArgs
    Ok "Groupe '$DenyInteractiveGroup' cree"
} else {
    Ok "Groupe '$DenyInteractiveGroup' deja present (reutilise depuis Setup-KerberosSPNEGO-DC.ps1)"
}

# --- 2. Generation du mot de passe (compatible PS 5.1 / .NET Framework 4.x) ---
Info "Generation du mot de passe (jamais affiche, jamais journalise)"
$charset = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_+=@#'
$rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
$bytes = New-Object byte[] $PasswordLength
$rng.GetBytes($bytes)
$rng.Dispose()
$plainPassword = -join ($bytes | ForEach-Object { $charset[$_ % $charset.Length] })
$securePassword = ConvertTo-SecureString -String $plainPassword -AsPlainText -Force
Ok "Mot de passe genere ($PasswordLength caracteres)"

# --- 3. Creation du compte de bind (moindre privilege, HORS de l'OU cible) -----
$existingUser = Get-ADUser -Filter "SamAccountName -eq '$ServiceAccountName'" -ErrorAction SilentlyContinue
if ($existingUser) {
    throw "Le compte $ServiceAccountName existe deja. STOP : ce script ne gere que la creation initiale (relancer regenererait un mot de passe deja configure cote Authentik sans coordination -- utiliser Set-ADAccountPassword manuellement pour une rotation)."
}

Info "Creation du compte de bind '$ServiceAccountName' (delibinerement hors de '$ouDn')"
$userArgs = @{
    Name = $ServiceAccountName
    SamAccountName = $ServiceAccountName
    UserPrincipalName = "$ServiceAccountName@$Realm"
    AccountPassword = $securePassword
    Enabled = $true
    PasswordNeverExpires = $true
    CannotChangePassword = $true
    AccountNotDelegated = $true
    Description = "Compte de bind LDAP pour la Source LDAP Authentik (lecture seule, perimetre OU=$TargetOuName). Ne pas utiliser pour un logon interactif."
}
New-ADUser @userArgs
Ok "Compte '$ServiceAccountName' cree (Domain Users uniquement, aucune delegation, aucune ACL supplementaire)"

Add-ADGroupMember -Identity $DenyInteractiveGroup -Members $ServiceAccountName
Ok "Compte ajoute a '$DenyInteractiveGroup'"

$bindDn = (Get-ADUser -Identity $ServiceAccountName).DistinguishedName

# --- 4. Ecriture du mot de passe dans un fichier a ACL restreinte --------------
if (Test-Path $PasswordOutFile) { throw "$PasswordOutFile existe deja. STOP : supprimer/deplacer l'ancien fichier avant de continuer." }
Set-Content -Path $PasswordOutFile -Value $plainPassword -NoNewline -Encoding ASCII
& icacls.exe $PasswordOutFile /inheritance:r /grant:r "Administrators:F" /grant:r "SYSTEM:F" | Out-Null
Ok "Mot de passe ecrit dans $PasswordOutFile (ACL restreinte, jamais affiche a l'ecran)"

# Effacement immediat du mot de passe en clair de la memoire du process
$plainPassword = ('0' * $PasswordLength)
Remove-Variable plainPassword -ErrorAction SilentlyContinue
[System.GC]::Collect()

Write-Host ""
Ok "Compte de bind '$ServiceAccountName' provisionne."
Info "Bind DN  : $bindDn"
Info "Base DN  : $ouDn"
Warn "PROCHAINE ETAPE MANUELLE : transferer $PasswordOutFile vers le Debian via smbclient (jamais RDP clipboard),"
Warn "  coller Bind DN + Base DN + mot de passe dans Authentik (Directory -> Federation & Social login -> Create -> LDAP Source),"
Warn "  puis supprimer $PasswordOutFile du DC (et le fichier transitoire cote Debian) une fois la Source LDAP validee."
Warn "Utiliser ldaps://${DcIp}:636 cote Authentik (jamais LDAP non chiffre 389 pour un bind avec mot de passe,"
Warn "  et jamais 'disable full TLS validation'). Si l'AC interne a l'autoenrollment 'Domain Controller Authentication'"
Warn "  actif (courant sur une AD CS Enterprise), le DC porte deja un certificat Schannel emis par la meme racine que"
Warn "  vault.crt/auth.crt -- verifier via certlm.msc (Personal store) sinon en emettre un manuellement avant de configurer"
Warn "  la Source LDAP cote Authentik. Gate : 'openssl s_client -connect ${DcIp}:636 -CAfile adcs-root.crt' depuis"
Warn "  le Debian doit retourner 'Verify return code: 0'."
