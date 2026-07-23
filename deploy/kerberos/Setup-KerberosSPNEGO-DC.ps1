#Requires -Version 5.1
#Requires -Modules ActiveDirectory
<#
=================================================================================
 Setup-KerberosSPNEGO-DC.ps1
 Provisionne le compte de service Kerberos utilise par Authentik pour le SPNEGO
 (HTTP/auth.vaultwardensso.local). A executer sur le DC (192.168.100.76).
 Script 100% ASCII. Splatting uniquement (pas de backtick de continuation).
---------------------------------------------------------------------------------
 Ce que fait ce script :
  - Gate anti-doublon SPN (setspn -Q) AVANT toute creation.
  - Cree svc-authentik-krb : mot de passe aleatoire fort (jamais affiche/logge),
    PasswordNeverExpires, CannotChangePassword, AccountNotDelegated,
    membre de Domain Users UNIQUEMENT.
  - AES only (msDS-SupportedEncryptionTypes = 24 = AES128+AES256). Jamais RC4/DES.
  - Enregistre le SPN HTTP/<SpnHostname> sur le compte (setspn -S, verifie deux fois).
  - Genere le keytab via ktpass (le mot de passe genere ICI est reutilise pour que
    la reinitialisation operee par ktpass n'introduise pas de derive).
  - Verifie le kvno post-generation, hache le keytab en SHA-256 (a comparer cote
    Debian apres transfert smbclient), et restreint son ACL au strict minimum.
 Ce que ce script NE fait PAS (hors perimetre / actions manuelles requises) :
  - Le refus de logon interactif/RDP (SeDenyInteractiveLogonRight /
    SeDenyRemoteInteractiveLogonRight) est un User Right Assignment : il se
    configure via GPO, pas via New-ADUser. Ce script cree/alimente le groupe
    de securite cible ; RATTACHER LA GPO A CE GROUPE reste une action manuelle
    (voir le WARN affiche en fin d'execution).
  - Le transfert du keytab vers le Debian (smbclient) et sa suppression du DC
    APRES verification du hash restent des etapes manuelles distinctes (cf. brief
    Phase 2, "Transfert du keytab").
---------------------------------------------------------------------------------
 EXEMPLE :
  .\Setup-KerberosSPNEGO-DC.ps1 -SpnHostname 'auth.vaultwardensso.local' `
     -Realm 'VAULTWARDENSSO.LOCAL' -Domain 'VAULTWARDENSSO'
=================================================================================
#>
[CmdletBinding()]
param(
    [string] $ServiceAccountName = 'svc-authentik-krb',
    [Parameter(Mandatory)] [string] $SpnHostname,        # ex: auth.vaultwardensso.local
    [Parameter(Mandatory)] [string] $Realm,               # ex: VAULTWARDENSSO.LOCAL (force en MAJUSCULES)
    [Parameter(Mandatory)] [string] $Domain,               # NetBIOS, ex: VAULTWARDENSSO
    [string] $DenyInteractiveGroup = 'GG-SvcAccounts-DenyInteractiveLogon',
    [string] $KeytabPath = 'C:\authentik.keytab',
    [int] $PasswordLength = 28
)
$ErrorActionPreference = 'Stop'
function Info($m){ Write-Host "[INFO] $m" -ForegroundColor Cyan }
function Ok($m){ Write-Host "[ OK ] $m" -ForegroundColor Green }
function Warn($m){ Write-Host "[WARN] $m" -ForegroundColor Yellow }

$Realm = $Realm.ToUpperInvariant()
$Spn = "HTTP/$SpnHostname"
$Principal = "$Spn@$Realm"

Import-Module ActiveDirectory

# --- 0. Gate anti-doublon SPN AVANT toute action -------------------------------
Info "Gate anti-doublon : recherche d'enregistrements existants pour $Spn"
$existingSpn = & setspn.exe -Q $Spn 2>&1 | Out-String
if ($existingSpn -match 'Existing SPN found') {
    Write-Host $existingSpn
    throw "SPN $Spn deja enregistre ailleurs. STOP : un doublon provoque un KRB_AP_ERR_MODIFIED silencieux. Resoudre le doublon avant de continuer."
}
Ok "Aucun doublon pour $Spn"

# --- 1. Generation du mot de passe (compatible PS 5.1 / .NET Framework 4.x) ---
# NB retrospective connue : RandomNumberGenerator::Fill() est absent en .NET
# Framework 4.x (PS 5.1) et produit un tableau de zeros. On utilise donc
# RNGCryptoServiceProvider.GetBytes(), disponible depuis .NET 2.0.
Info "Generation du mot de passe (jamais affiche, jamais journalise)"
$charset = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_+=@#'
$rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
$bytes = New-Object byte[] $PasswordLength
$rng.GetBytes($bytes)
$rng.Dispose()
$plainPassword = -join ($bytes | ForEach-Object { $charset[$_ % $charset.Length] })
$securePassword = ConvertTo-SecureString -String $plainPassword -AsPlainText -Force
Ok "Mot de passe genere ($PasswordLength caracteres, alphabet restreint compatible ligne de commande ktpass)"

# --- 2. Groupe cible pour le refus de logon interactif (moindre privilege) ----
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
    Ok "Groupe '$DenyInteractiveGroup' deja present"
}

# --- 3. Creation du compte de service (moindre privilege, AES only, no deleg) -
$existingUser = Get-ADUser -Filter "SamAccountName -eq '$ServiceAccountName'" -ErrorAction SilentlyContinue
if ($existingUser) {
    throw "Le compte $ServiceAccountName existe deja. STOP : ce script ne gere que la creation initiale (relancer ktpass reinitialiserait un secret deja distribue sans coordination)."
}

Info "Creation du compte de service '$ServiceAccountName'"
$userArgs = @{
    Name = $ServiceAccountName
    SamAccountName = $ServiceAccountName
    UserPrincipalName = "$ServiceAccountName@$Realm"
    AccountPassword = $securePassword
    Enabled = $true
    PasswordNeverExpires = $true
    CannotChangePassword = $true
    AccountNotDelegated = $true
    Description = 'Compte de service SPNEGO Authentik (HTTP/auth.vaultwardensso.local). Ne pas utiliser pour un logon interactif.'
}
New-ADUser @userArgs
Ok "Compte '$ServiceAccountName' cree (Domain Users uniquement, aucune delegation, aucun autre groupe)"

Add-ADGroupMember -Identity $DenyInteractiveGroup -Members $ServiceAccountName
Ok "Compte ajoute a '$DenyInteractiveGroup'"

# --- 4. AES only : jamais RC4/DES ----------------------------------------------
Info "Application de msDS-SupportedEncryptionTypes = 24 (AES128 + AES256, jamais RC4/DES)"
Set-ADUser -Identity $ServiceAccountName -Replace @{ 'msDS-SupportedEncryptionTypes' = 24 }
$enc = (Get-ADUser -Identity $ServiceAccountName -Properties msDS-SupportedEncryptionTypes).'msDS-SupportedEncryptionTypes'
if ($enc -ne 24) { throw "msDS-SupportedEncryptionTypes = $enc (attendu 24). STOP." }
Ok "msDS-SupportedEncryptionTypes confirme = 24"

# --- 5. Enregistrement du SPN --------------------------------------------------
Info "Enregistrement du SPN $Spn sur $ServiceAccountName"
& setspn.exe -S $Spn "$Domain\$ServiceAccountName"
if ($LASTEXITCODE -ne 0) { throw "setspn -S a echoue (code $LASTEXITCODE). STOP." }
$verify = & setspn.exe -L $ServiceAccountName 2>&1 | Out-String
if ($verify -notmatch [regex]::Escape($Spn)) { throw "SPN non retrouve apres enregistrement. STOP : verifier manuellement avant de continuer." }
Ok "SPN $Spn confirme sur $ServiceAccountName"

# --- 6. Generation du keytab (ktpass) ------------------------------------------
# ktpass REINITIALISE le mot de passe du compte : on lui passe le meme mot de
# passe que celui utilise a la creation, pour que le keytab produit reste le
# seul valide sans introduire de derive de secret non maitrisee.
Info "Generation du keytab via ktpass (principal $Principal)"
if (Test-Path $KeytabPath) { throw "$KeytabPath existe deja. STOP : supprimer/deplacer l'ancien keytab avant de regenerer (kvno doit rester coherent avec un seul fichier valide)." }

$ktpassArgs = @(
    '-princ', $Principal,
    '-mapuser', "$Domain\$ServiceAccountName",
    '-crypto', 'AES256-SHA1',
    # KRB5_NT_SRV_HST (pas KRB5_NT_PRINCIPAL) : confirme en lab par lecture du code
    # source Authentik (authentik/sources/kerberos/models.py) -- la recherche de
    # l'entree keytab cote serveur se fait avec gssapi NameType.hostbased_service
    # (= KRB5_NT_SRV_HST cote MIT krb5). Un keytab genere en KRB5_NT_PRINCIPAL est
    # rejete avec "No key table entry found" meme si le principal textuel est
    # identique -- le name_type fait partie de la cle de recherche.
    '-ptype', 'KRB5_NT_SRV_HST',
    '-pass', $plainPassword,
    '-out', $KeytabPath
)
& ktpass.exe @ktpassArgs
if ($LASTEXITCODE -ne 0) { throw "ktpass a echoue (code $LASTEXITCODE). STOP." }

# Effacement immediat du mot de passe en clair de la memoire du process
$plainPassword = ('0' * $PasswordLength)
Remove-Variable plainPassword -ErrorAction SilentlyContinue
[System.GC]::Collect()
Ok "Keytab genere : $KeytabPath (mot de passe en clair efface de la session)"

# --- 7. Verification post-generation : kvno + hash + ACL -----------------------
$kvno = (Get-ADUser -Identity $ServiceAccountName -Properties msDS-KeyVersionNumber).'msDS-KeyVersionNumber'
Info "kvno post-generation = $kvno (le keytab genere doit correspondre a ce kvno)"

$hash = (Get-FileHash -Path $KeytabPath -Algorithm SHA256).Hash
Info "SHA-256 du keytab (a comparer avec 'sha256sum' cote Debian apres transfert) : $hash"

Info "Restriction ACL du keytab (Administrators uniquement, avant transfert)"
& icacls.exe $KeytabPath /inheritance:r /grant:r "Administrators:F" /grant:r "SYSTEM:F" | Out-Null
Ok "ACL restreinte sur $KeytabPath"

Write-Host ""
Ok "Compte '$ServiceAccountName' provisionne. SPN=$Spn Realm=$Realm kvno=$kvno"
Warn "klist cote DC n'est PAS une validation suffisante : la validation reelle du SPNEGO se fait Phase 3 (Authentik)."
Warn "ACTION MANUELLE REQUISE : lier une GPO (User Rights Assignment) appliquant SeDenyInteractiveLogonRight"
Warn "  et SeDenyRemoteInteractiveLogonRight au groupe '$DenyInteractiveGroup', puis 'gpupdate /force'."
Warn "PROCHAINE ETAPE MANUELLE : transferer $KeytabPath vers le Debian via smbclient (jamais RDP clipboard),"
Warn "  comparer le SHA-256 des deux cotes, puis supprimer $KeytabPath du DC une fois l'integrite confirmee."
