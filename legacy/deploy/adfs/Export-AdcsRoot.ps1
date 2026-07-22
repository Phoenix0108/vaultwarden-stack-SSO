#Requires -Version 5.1
<#
=================================================================================
 Export-AdcsRoot.ps1
 Exporte la CA racine AD CS (partie PUBLIQUE uniquement) pour l'embarquer dans
 l'image Vaultwarden (confiance TLS vers AD FS).
---------------------------------------------------------------------------------
 SECURITE : n'exporte JAMAIS la cle privee. Affiche l'empreinte SHA-1 a comparer
 apres transfert vers l'hote Docker (integrite de l'ancre de confiance).
---------------------------------------------------------------------------------
 EXEMPLE :
  .\Export-AdcsRoot.ps1 -CaRootCn 'vaultwardensso-SRVADTEST-CA' -OutFile C:\adcs-root.cer
=================================================================================
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $CaRootCn,        # CN de l'AC racine
    [string] $OutFile = 'C:\adcs-root.cer'
)
$ErrorActionPreference = 'Stop'

$root = Get-ChildItem Cert:\LocalMachine\Root |
        Where-Object { $_.Subject -match [regex]::Escape($CaRootCn) -and $_.Subject -eq $_.Issuer } |
        Select-Object -First 1
if (-not $root) { throw "AC racine '$CaRootCn' introuvable dans Cert:\LocalMachine\Root (ou non auto-signee)." }

Export-Certificate -Cert $root -FilePath $OutFile -Type CERT | Out-Null

Write-Host "Racine exportee : $OutFile" -ForegroundColor Green
$root | Format-List Subject, Issuer, @{n='SHA1';e={$_.Thumbprint}}, NotAfter
Write-Host ""
Write-Host "APRES transfert vers l'hote Docker, verifier l'integrite :" -ForegroundColor Yellow
Write-Host "  openssl x509 -inform der -in adcs-root.cer -out adcs-root.crt"
Write-Host "  openssl x509 -in adcs-root.crt -noout -fingerprint -sha1"
Write-Host "  -> doit correspondre a SHA1 = $($root.Thumbprint)"
