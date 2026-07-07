#Requires -Version 5.1
<#
=================================================================================
 Prepare-AdfsHost.ps1
 Prerequis systeme/reseau du serveur AD FS pour le SSO Vaultwarden.
 Script 100% ASCII. A executer sur le serveur AD FS (SRVADTEST).
---------------------------------------------------------------------------------
 Corrige les embuches recensees :
  - DNS de la NIC (evite la fuite OPSEC + fiabilise NLA)
  - NLA en demarrage differe (categorisation DomainAuthenticated fiable au boot)
  - Regle pare-feu inbound 443 SCOPEE (moindre privilege ; jamais Any)
  - Controle de coherence upn==mail (appariement OIDC)
---------------------------------------------------------------------------------
 EXEMPLE :
  .\Prepare-AdfsHost.ps1 -InterfaceAlias 'Ethernet' -DcIp '192.168.100.93' `
     -ClientSubnet '192.168.100.0/24'
=================================================================================
#>
[CmdletBinding()]
param(
    [string] $InterfaceAlias = 'Ethernet',
    [Parameter(Mandatory)] [string] $DcIp,             # IP reelle du DC/AD FS
    [Parameter(Mandatory)] [string] $ClientSubnet,     # subnet autorise a joindre AD FS:443
    [switch] $BounceNic                                # forcer la re-evaluation NLA (coupe le reseau brievement)
)
$ErrorActionPreference = 'Stop'
function Info($m){ Write-Host "[INFO] $m" -ForegroundColor Cyan }
function Ok($m){ Write-Host "[ OK ] $m" -ForegroundColor Green }
function Warn($m){ Write-Host "[WARN] $m" -ForegroundColor Yellow }

# --- 1. DNS de la NIC (IP reelle en primaire, loopback en secours) ---------------
Info "Configuration DNS de la carte '$InterfaceAlias'"
Set-DnsClientServerAddress -InterfaceAlias $InterfaceAlias -ServerAddresses $DcIp,'127.0.0.1'
Ok "DNS = $DcIp, 127.0.0.1 (aucun resolveur externe -> pas de fuite de noms internes)"

# --- 2. NLA en demarrage differe ------------------------------------------------
Info "NLA en AutomaticDelayedStart (categorisation apres l'annuaire au boot)"
& sc.exe config NlaSvc start= delayed-auto | Out-Null
Start-Service NlaSvc -ErrorAction SilentlyContinue
$svc = Get-CimInstance Win32_Service -Filter "Name='NlaSvc'"
Ok "NlaSvc : StartMode=$($svc.StartMode) DelayedAutoStart=$($svc.DelayedAutoStart) State=$($svc.State)"

if ($BounceNic) {
    Warn "Bounce de la NIC (coupe le reseau ~15s) - a lancer en CONSOLE LOCALE si RDP sur cette carte"
    Disable-NetAdapter -Name $InterfaceAlias -Confirm:$false
    Start-Sleep 3
    Enable-NetAdapter -Name $InterfaceAlias
    Start-Sleep 10
}
$cat = (Get-NetConnectionProfile -InterfaceAlias $InterfaceAlias).NetworkCategory
if ($cat -eq 'DomainAuthenticated') { Ok "NetworkCategory = DomainAuthenticated" }
else { Warn "NetworkCategory = $cat (attendu DomainAuthenticated). Relancer avec -BounceNic en console locale." }

# --- 3. Pare-feu : posture explicite + regle inbound 443 scopee ------------------
Info "Posture pare-feu explicite (sortie du NotConfigured)"
Set-NetFirewallProfile -Name Domain,Private,Public -DefaultInboundAction Block -DefaultOutboundAction Allow

$ruleName = 'ADFS-HTTPS-Inbound-Clients'
$existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
if ($existing) {
    Info "Mise a jour de la regle existante (scope source = $ClientSubnet)"
    Set-NetFirewallRule -DisplayName $ruleName -RemoteAddress $ClientSubnet -Profile Domain -Enabled True
} else {
    Info "Creation de la regle inbound 443 scopee"
    $fw = @{
        DisplayName=$ruleName; Direction='Inbound'; Action='Allow'; Protocol='TCP'
        LocalPort=443; RemoteAddress=$ClientSubnet; Profile='Domain'; Enabled='True'
        Description='Front + back-channel OIDC Vaultwarden - subnet client uniquement'
    }
    New-NetFirewallRule @fw | Out-Null
}
Set-NetFirewallProfile -Name Domain -LogBlocked True
Ok "Regle 443 scopee a $ClientSubnet (profil Domain, fail-safe). NE JAMAIS utiliser Any."

# --- 4. Controle de coherence upn == mail (appariement OIDC) --------------------
Info "Controle de coherence upn <-> mail (impacte l'appariement)"
$divergents = Get-ADUser -Filter {Enabled -eq $true} -Properties mail,userPrincipalName |
    Where-Object { $_.mail -and ($_.mail -ne $_.userPrincipalName) }
if ($divergents) {
    Warn "Comptes avec upn != mail (rupture d'appariement potentielle) :"
    $divergents | Select-Object SamAccountName, mail, userPrincipalName | Format-Table -AutoSize
} else {
    Ok "upn == mail pour tous les comptes actifs (appariement coherent)"
}

Write-Host ""
Ok "Prerequis AD FS appliques. Verifier NetworkCategory=DomainAuthenticated avant de continuer."
