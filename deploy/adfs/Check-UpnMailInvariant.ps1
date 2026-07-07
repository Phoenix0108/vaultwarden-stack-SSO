#Requires -Version 5.1
<#
=================================================================================
 Check-UpnMailInvariant.ps1
 Controle compensatoire : detecte toute rupture de l'invariant upn == mail.
---------------------------------------------------------------------------------
 CONTEXTE (Security by Design) :
  L'appariement OIDC repose sur l'email (attribut mail). Si un flux devait un jour
  s'appuyer sur upn (deroga), un compte avec upn != mail creerait un risque
  d'appariement errone -> acces croise a un coffre. Ce controle, planifie
  quotidiennement, ecrit un event Windows collectable par le SIEM en cas de rupture.
---------------------------------------------------------------------------------
 INSTALLATION (tache planifiee quotidienne) :
  New-EventLog -LogName Application -Source 'VaultwardenSSO' -ErrorAction SilentlyContinue
  $act = New-ScheduledTaskAction -Execute 'powershell.exe' `
     -Argument '-NonInteractive -File C:\scripts\Check-UpnMailInvariant.ps1'
  $trg = New-ScheduledTaskTrigger -Daily -At 6am
  Register-ScheduledTask -TaskName 'VW-Check-UpnMail' -Action $act -Trigger $trg `
     -User 'SYSTEM' -RunLevel Highest
=================================================================================
#>
[CmdletBinding()]
param(
    [string] $LogName = 'Application',
    [string] $Source  = 'VaultwardenSSO',
    [int]    $EventId = 9001
)
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

New-EventLog -LogName $LogName -Source $Source -ErrorAction SilentlyContinue

$divergents = Get-ADUser -Filter {Enabled -eq $true} -Properties mail,userPrincipalName |
    Where-Object { $_.mail -and ($_.mail -ne $_.userPrincipalName) }

if ($divergents) {
    $list = ($divergents | ForEach-Object { "$($_.SamAccountName) (mail=$($_.mail) ; upn=$($_.userPrincipalName))" }) -join "`n"
    $msg  = "Rupture de l'invariant upn==mail detectee sur $($divergents.Count) compte(s) :`n$list"
    Write-EventLog -LogName $LogName -Source $Source -EventId $EventId -EntryType Warning -Message $msg
    Write-Host "[WARN] $($divergents.Count) compte(s) divergent(s) - event $EventId ecrit." -ForegroundColor Yellow
    exit 1
} else {
    Write-Host "[ OK ] upn == mail pour tous les comptes actifs." -ForegroundColor Green
    exit 0
}
