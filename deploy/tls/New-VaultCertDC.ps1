#Requires -Version 5.1
<#
=================================================================================
 New-VaultCertDC.ps1
 Genere et exporte le certificat serveur (SAN couvrant vault.vaultwardensso.local
 ET auth.vaultwardensso.local -- tout passe par Caddy, un seul certificat suffit
 pour les deux vhosts) + la racine AD CS, en une seule execution de script (le
 decalage de session entre certreq -new et -accept rend le certificat orphelin
 -- vecu en pratique lors des essais manuels ; un script atomique elimine ce
 risque par construction).
 A executer sur le DC, PowerShell 5.1 en administrateur. Script 100% ASCII,
 splatting, idempotent (nettoie les artefacts d'une precedente tentative avant
 de regenerer -- une requete en attente orpheline de session n'est de toute
 facon pas recuperable, cf. rencontre en pratique).
---------------------------------------------------------------------------------
 Menace couverte : cle privee jamais en clair hors du magasin machine ou d'un
 PFX protege par mot de passe ; mot de passe genere aleatoirement, jamais
 affiche, transporte en fichier (jamais retape a la main -- source d'echecs
 constatee : mismatch de saisie entre sessions/claviers differents).
 Privilege minimal : le script ne cree ni ne modifie aucun compte AD, il ne
 touche qu'au magasin de certificats local et au systeme de fichiers.
 Supervision : voir docs/03_supervision_siem.md pour les evenements a
 collecter autour de l'emission de certificats AD CS.
---------------------------------------------------------------------------------
 EXEMPLE :
  .\New-VaultCertDC.ps1
  .\New-VaultCertDC.ps1 -CaConfig 'AUTRE-SERVEUR\Autre-CA'   # si la CA a change
---------------------------------------------------------------------------------
 -CaConfig est epingle a la valeur connue de cet environnement par defaut (pas
 de decouverte automatique : une version precedente parsait `certutil -ADCA`
 par regex et produisait un config string tronque -- ex. "S\v" -- provoquant
 RPC_S_SERVER_UNAVAILABLE sur -submit ; mieux vaut une valeur fixe, correcte
 et documentee qu'une decouverte fragile). Si la CA change, relancer avec
 -CaConfig explicite : `certutil -ADCA` donne le nom de la CA (premier CN= de
 cACertificateDN) et le nom de la machine CA (entree ACL <DOMAINE>\<MACHINE>$).
=================================================================================
#>
[CmdletBinding()]
param(
    [string] $SpnHostname = 'vault.vaultwardensso.local',
    [string] $AuthHostname = 'auth.vaultwardensso.local',
    [string] $CaConfig = 'SRVADTEST\vaultwardensso-srvadtest-CA',
    [string] $CertTemplate = 'WebServer',
    [string] $RootThumbprint = '473BAAC9189D52715E3E73CED9BEC691293BED10',
    [string] $WorkDir = 'C:\',
    [switch] $SkipCleanup
)
$ErrorActionPreference = 'Stop'
function Info($m){ Write-Host "[INFO] $m" -ForegroundColor Cyan }
function Ok($m){ Write-Host "[ OK ] $m" -ForegroundColor Green }
function Warn($m){ Write-Host "[WARN] $m" -ForegroundColor Yellow }
function Fail($m){ Write-Host "[FAIL] $m" -ForegroundColor Red; exit 1 }

Set-Location $WorkDir
$prefix = 'vault-new'

# --- 0. Nettoyage idempotent ---------------------------------------------------
if (-not $SkipCleanup) {
    Info "Nettoyage des artefacts d'une precedente tentative (idempotent)"
    Remove-Item "$prefix.inf","$prefix.csr","$prefix.cer","$prefix.pfx","$prefix.pfxpass.txt","adcs-root.cer" -Force -ErrorAction SilentlyContinue
}

# --- 1. CSR ----------------------------------------------------------------------
try {
    Info "Generation de la CSR pour CN=$SpnHostname (SAN : $SpnHostname, $AuthHostname)"
    $inf = @"
[Version]
Signature="`$Windows NT`$"
[NewRequest]
Subject = "CN=$SpnHostname"
KeyLength = 2048
KeySpec = 1
Exportable = TRUE
MachineKeySet = TRUE
SMIME = FALSE
PrivateKeyArchive = FALSE
UserProtected = FALSE
UseExistingKeySet = FALSE
ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
ProviderType = 12
RequestType = PKCS10
KeyUsage = 0xa0
[EnhancedKeyUsageExtension]
OID=1.3.6.1.5.5.7.3.1
[Extensions]
2.5.29.17 = "{text}"
_continue_ = "dns=$SpnHostname&"
_continue_ = "dns=$AuthHostname&"
"@
    $inf | Out-File -Encoding ascii "$prefix.inf"
    certreq -new -machine "$prefix.inf" "$prefix.csr" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "certreq -new a echoue (code $LASTEXITCODE)" }
    Ok "CSR generee : $prefix.csr"
} catch {
    Fail "Etape CSR : $_"
}

# --- 2. CA cible -------------------------------------------------------------------
# Valeur epinglee (parametre -CaConfig), pas de decouverte automatique -- voir
# l'en-tete du script pour pourquoi (regex sur certutil -ADCA s'est averee
# fragile en pratique).
Info "CA cible : $CaConfig"

# --- 3. Submit puis Accept, meme session ------------------------------------------
try {
    Info "Soumission de la CSR a $CaConfig (gabarit $CertTemplate)"
    # -submit n'accepte PAS -machine sur ce build : le contexte machine est deja
    # fixe par -new -machine ; -submit se contente de poster le CSR a la CA.
    certreq -submit -attrib "CertificateTemplate:$CertTemplate" -config $CaConfig "$prefix.csr" "$prefix.cer" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "certreq -submit a echoue (code $LASTEXITCODE) -- gabarit ou CA incorrect ?" }
    Ok "Certificat emis : $prefix.cer"

    Info "Acceptation dans le magasin machine (meme session que -new)"
    certreq -accept -machine "$prefix.cer" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "certreq -accept a echoue (code $LASTEXITCODE)" }
} catch {
    Fail "Etape submit/accept : $_"
}

# --- 4. Verification du binding + export PFX --------------------------------------
try {
    $thumb = (Get-PfxCertificate -FilePath "$prefix.cer").Thumbprint
    $cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Thumbprint -eq $thumb } | Select-Object -First 1
    if (-not $cert) { throw "Certificat absent de Cert:\LocalMachine\My juste apres -accept -- requete orpheline, relancer le script en entier (pas de reprise partielle possible)." }
    Ok "Certificat lie a sa cle privee dans le magasin machine"

    Info "Generation du mot de passe d'export et export du PFX"
    $pfxPassPlain = -join ((48..57)+(65..90)+(97..122) | Get-Random -Count 24 | ForEach-Object { [char]$_ })
    $pfxPass = ConvertTo-SecureString -String $pfxPassPlain -AsPlainText -Force
    Export-PfxCertificate -Cert $cert -FilePath "$prefix.pfx" -Password $pfxPass | Out-Null

    # Get-PfxCertificate -Password absent sur ce PowerShell 5.1 : verification
    # via le constructeur .NET direct, independant de la version du cmdlet.
    $verif = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2("$WorkDir$prefix.pfx", $pfxPassPlain)
    if ($verif.Subject -ne "CN=$SpnHostname") { throw "Sujet inattendu apres export : $($verif.Subject)" }
    Ok "PFX exporte et verifie : $prefix.pfx (sujet $($verif.Subject))"

    Set-Content -Path "$prefix.pfxpass.txt" -Value $pfxPassPlain -NoNewline -Encoding ascii
    Ok "Mot de passe ecrit dans $prefix.pfxpass.txt (a transferer avec le PFX, jamais retape a la main)"
} catch {
    Fail "Etape export PFX : $_"
}

# --- 5. Export de la racine AD CS ---------------------------------------------------
try {
    Info "Export de la racine AD CS (empreinte $RootThumbprint)"
    $root = Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Thumbprint -eq $RootThumbprint } | Select-Object -First 1
    if (-not $root) { throw "Racine avec l'empreinte $RootThumbprint introuvable dans Cert:\LocalMachine\Root" }
    Export-Certificate -Cert $root -FilePath 'adcs-root.cer' -Type CERT | Out-Null
    Ok "Racine exportee : adcs-root.cer"
} catch {
    Fail "Etape export racine : $_"
}

Write-Host ""
Ok "Termine. Fichiers prets dans ${WorkDir} : $prefix.pfx, $prefix.pfxpass.txt, $prefix.cer, adcs-root.cer"
Warn "Transferer ces 4 fichiers vers l'hote Docker (smbclient), puis executer deploy/tls/install-vault-cert.sh la-bas."
Warn "Purger ensuite $prefix.pfx et $prefix.pfxpass.txt du DC (secrets) une fois le transfert confirme."
