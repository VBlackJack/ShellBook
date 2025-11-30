---
tags:
  - scripts
  - powershell
  - security
  - audit
  - windows
---

# Audit-LocalAdmins.ps1

:material-star::material-star: **Niveau : Intermédiaire**

Audit des membres du groupe Administrateurs local sur des serveurs distants.

---

## Description

Ce script permet de lister tous les membres du groupe **Administrateurs** local sur un ou plusieurs serveurs Windows. Il est particulièrement utile pour :

- Audits de sécurité périodiques
- Vérification de conformité (CIS, ANSSI)
- Détection de comptes non autorisés
- Inventaire des accès privilégiés

---

## Prérequis

```powershell
# PowerShell 5.1+ ou PowerShell 7+
$PSVersionTable.PSVersion

# WinRM activé sur les serveurs distants
Enable-PSRemoting -Force

# Droits administrateur sur les serveurs cibles
# Membre du groupe "Remote Management Users" minimum
```

---

## Script

```powershell
#Requires -Version 5.1
<#
.SYNOPSIS
    Audit members of the local Administrators group on remote servers.

.DESCRIPTION
    This script connects to one or more Windows servers and retrieves
    all members of the local Administrators group. Results are exported
    as PSCustomObjects with server name, account, and account type.

.PARAMETER ComputerName
    One or more computer names to audit.

.PARAMETER InputFile
    Path to a text file containing server names (one per line).

.PARAMETER Credential
    PSCredential object for authentication.

.PARAMETER ExportPath
    Path to export results (CSV format).

.PARAMETER IncludeDisabled
    Include disabled accounts in the report.

.PARAMETER Timeout
    Connection timeout in seconds (default: 30).

.EXAMPLE
    .\Audit-LocalAdmins.ps1 -ComputerName "SERVER01", "SERVER02"
    Audit local admins on specified servers.

.EXAMPLE
    .\Audit-LocalAdmins.ps1 -InputFile "servers.txt" -ExportPath "admins.csv"
    Audit servers from file and export to CSV.

.EXAMPLE
    $cred = Get-Credential
    .\Audit-LocalAdmins.ps1 -ComputerName "SERVER01" -Credential $cred
    Audit with specific credentials.

.NOTES
    Author: ShellBook
    Version: 1.0
#>

[CmdletBinding(DefaultParameterSetName = 'Direct')]
param(
    [Parameter(ParameterSetName = 'Direct', Mandatory = $true, Position = 0)]
    [string[]]$ComputerName,

    [Parameter(ParameterSetName = 'File', Mandatory = $true)]
    [ValidateScript({ Test-Path $_ -PathType Leaf })]
    [string]$InputFile,

    [Parameter()]
    [PSCredential]$Credential,

    [Parameter()]
    [string]$ExportPath,

    [Parameter()]
    [switch]$IncludeDisabled,

    [Parameter()]
    [int]$Timeout = 30
)

#region Configuration
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Colors for output
$colors = @{
    Success = 'Green'
    Warning = 'Yellow'
    Error   = 'Red'
    Info    = 'Cyan'
}
#endregion

#region Functions
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('Success', 'Warning', 'Error', 'Info')]
        [string]$Level = 'Info'
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $prefix = switch ($Level) {
        'Success' { '[OK]  ' }
        'Warning' { '[WARN]' }
        'Error'   { '[FAIL]' }
        'Info'    { '[INFO]' }
    }

    Write-Host "$prefix " -ForegroundColor $colors[$Level] -NoNewline
    Write-Host $Message
}

function Test-ServerConnectivity {
    param(
        [string]$Server,
        [int]$TimeoutSeconds
    )

    # Test WinRM connectivity
    try {
        $testParams = @{
            ComputerName = $Server
            Count        = 1
            Quiet        = $true
        }

        if (-not (Test-Connection @testParams)) {
            return @{ Success = $false; Error = "Ping failed" }
        }

        # Test WinRM port
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $connect = $tcpClient.BeginConnect($Server, 5985, $null, $null)
        $wait = $connect.AsyncWaitHandle.WaitOne($TimeoutSeconds * 1000, $false)

        if (-not $wait) {
            $tcpClient.Close()
            return @{ Success = $false; Error = "WinRM port 5985 not responding" }
        }

        $tcpClient.EndConnect($connect)
        $tcpClient.Close()

        return @{ Success = $true; Error = $null }
    }
    catch {
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

function Get-LocalAdminMembers {
    param(
        [string]$Server,
        [PSCredential]$Credential,
        [bool]$IncludeDisabled
    )

    $results = @()

    # Script block to execute remotely
    $scriptBlock = {
        param($IncludeDisabled)

        $members = @()

        try {
            # Get local Administrators group (works with any language)
            $adminGroup = Get-LocalGroup | Where-Object { $_.SID -eq 'S-1-5-32-544' }

            if (-not $adminGroup) {
                throw "Administrators group not found"
            }

            $groupMembers = Get-LocalGroupMember -Group $adminGroup -ErrorAction Stop

            foreach ($member in $groupMembers) {
                # Get additional info for local users
                $isDisabled = $false
                $lastLogon = $null
                $description = ""

                if ($member.ObjectClass -eq 'User' -and $member.PrincipalSource -eq 'Local') {
                    try {
                        $localUser = Get-LocalUser -SID $member.SID -ErrorAction SilentlyContinue
                        if ($localUser) {
                            $isDisabled = -not $localUser.Enabled
                            $lastLogon = $localUser.LastLogon
                            $description = $localUser.Description
                        }
                    }
                    catch { }
                }

                # Skip disabled accounts if not included
                if ($isDisabled -and -not $IncludeDisabled) {
                    continue
                }

                $members += [PSCustomObject]@{
                    Name            = $member.Name
                    ObjectClass     = $member.ObjectClass
                    PrincipalSource = $member.PrincipalSource
                    SID             = $member.SID.Value
                    IsDisabled      = $isDisabled
                    LastLogon       = $lastLogon
                    Description     = $description
                }
            }
        }
        catch {
            throw "Failed to enumerate group members: $_"
        }

        return $members
    }

    # Build session parameters
    $sessionParams = @{
        ComputerName = $Server
        ScriptBlock  = $scriptBlock
        ArgumentList = $IncludeDisabled
        ErrorAction  = 'Stop'
    }

    if ($Credential) {
        $sessionParams['Credential'] = $Credential
    }

    try {
        $members = Invoke-Command @sessionParams

        foreach ($member in $members) {
            # Determine account type for reporting
            $accountType = switch ($member.PrincipalSource) {
                'Local'          { 'Local Account' }
                'ActiveDirectory' { 'Domain Account' }
                default          { $member.ObjectClass }
            }

            if ($member.ObjectClass -eq 'Group') {
                $accountType = if ($member.PrincipalSource -eq 'Local') {
                    'Local Group'
                } else {
                    'Domain Group'
                }
            }

            $results += [PSCustomObject]@{
                Server          = $Server
                Account         = $member.Name
                Type            = $accountType
                ObjectClass     = $member.ObjectClass
                SID             = $member.SID
                IsDisabled      = $member.IsDisabled
                LastLogon       = $member.LastLogon
                Description     = $member.Description
                AuditDate       = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            }
        }
    }
    catch {
        # Return error entry
        $results += [PSCustomObject]@{
            Server          = $Server
            Account         = "ERROR"
            Type            = "ERROR"
            ObjectClass     = "ERROR"
            SID             = ""
            IsDisabled      = $false
            LastLogon       = $null
            Description     = $_.Exception.Message
            AuditDate       = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        }
    }

    return $results
}
#endregion

#region Main
Write-Host ""
Write-Host ("=" * 70) -ForegroundColor Cyan
Write-Host "  LOCAL ADMINISTRATORS AUDIT" -ForegroundColor Green
Write-Host ("=" * 70) -ForegroundColor Cyan
Write-Host "  Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host ("-" * 70) -ForegroundColor Cyan

# Load servers from file if specified
if ($PSCmdlet.ParameterSetName -eq 'File') {
    $ComputerName = Get-Content -Path $InputFile | Where-Object { $_ -match '\S' -and $_ -notmatch '^\s*#' }
    Write-Log "Loaded $($ComputerName.Count) servers from $InputFile" -Level Info
}

# Remove duplicates and sort
$ComputerName = $ComputerName | Sort-Object -Unique
Write-Log "Auditing $($ComputerName.Count) server(s)" -Level Info

# Process each server
$allResults = @()
$successCount = 0
$failCount = 0

foreach ($server in $ComputerName) {
    Write-Host ""
    Write-Log "Processing: $server" -Level Info

    # Test connectivity first
    $connTest = Test-ServerConnectivity -Server $server -TimeoutSeconds $Timeout
    if (-not $connTest.Success) {
        Write-Log "$server - Connection failed: $($connTest.Error)" -Level Error
        $allResults += [PSCustomObject]@{
            Server          = $server
            Account         = "CONNECTION_FAILED"
            Type            = "ERROR"
            ObjectClass     = "ERROR"
            SID             = ""
            IsDisabled      = $false
            LastLogon       = $null
            Description     = $connTest.Error
            AuditDate       = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        }
        $failCount++
        continue
    }

    # Get local admin members
    $members = Get-LocalAdminMembers -Server $server -Credential $Credential -IncludeDisabled $IncludeDisabled

    if ($members | Where-Object { $_.Type -eq 'ERROR' }) {
        Write-Log "$server - Error during enumeration" -Level Error
        $failCount++
    }
    else {
        Write-Log "$server - Found $($members.Count) admin member(s)" -Level Success
        $successCount++

        # Display members
        foreach ($member in $members) {
            $typeColor = switch ($member.Type) {
                'Local Account'  { 'Yellow' }
                'Domain Account' { 'Green' }
                'Local Group'    { 'Cyan' }
                'Domain Group'   { 'Magenta' }
                default          { 'White' }
            }

            $disabled = if ($member.IsDisabled) { " (DISABLED)" } else { "" }
            Write-Host "       - $($member.Account) [$($member.Type)]$disabled" -ForegroundColor $typeColor
        }
    }

    $allResults += $members
}

# Summary
Write-Host ""
Write-Host ("=" * 70) -ForegroundColor Cyan
Write-Host "  SUMMARY" -ForegroundColor Green
Write-Host ("=" * 70) -ForegroundColor Cyan

$totalMembers = ($allResults | Where-Object { $_.Type -ne 'ERROR' }).Count
$uniqueAccounts = ($allResults | Where-Object { $_.Type -ne 'ERROR' } | Select-Object -ExpandProperty Account -Unique).Count

Write-Host "  Servers audited: $($ComputerName.Count)"
Write-Host "    - " -NoNewline; Write-Host "Success: $successCount" -ForegroundColor Green
Write-Host "    - " -NoNewline; Write-Host "Failed: $failCount" -ForegroundColor Red
Write-Host "  Total admin members: $totalMembers"
Write-Host "  Unique accounts: $uniqueAccounts"

# Export to CSV if requested
if ($ExportPath) {
    try {
        $allResults | Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8
        Write-Host ""
        Write-Log "Results exported to: $ExportPath" -Level Success
    }
    catch {
        Write-Log "Failed to export: $_" -Level Error
    }
}

# Return results for pipeline usage
Write-Output $allResults
#endregion
```

---

## Utilisation

### Audit d'un serveur unique

```powershell
# Serveur local
.\Audit-LocalAdmins.ps1 -ComputerName "localhost"

# Serveur distant
.\Audit-LocalAdmins.ps1 -ComputerName "SERVER01"
```

### Audit de plusieurs serveurs

```powershell
# Liste directe
.\Audit-LocalAdmins.ps1 -ComputerName "SERVER01", "SERVER02", "SERVER03"

# Depuis un fichier
.\Audit-LocalAdmins.ps1 -InputFile "C:\Admin\servers.txt"
```

### Export des résultats

```powershell
# Export CSV
.\Audit-LocalAdmins.ps1 -ComputerName "SERVER01" -ExportPath "C:\Reports\admins.csv"

# Pipeline vers Out-GridView
.\Audit-LocalAdmins.ps1 -ComputerName "SERVER01" | Out-GridView
```

### Avec authentification spécifique

```powershell
# Demande interactive des credentials
$cred = Get-Credential -Message "Entrez les credentials admin"
.\Audit-LocalAdmins.ps1 -ComputerName "SERVER01" -Credential $cred

# Credentials stockés
$cred = New-Object PSCredential("DOMAIN\admin", (ConvertTo-SecureString "P@ssw0rd" -AsPlainText -Force))
.\Audit-LocalAdmins.ps1 -InputFile "servers.txt" -Credential $cred -ExportPath "audit.csv"
```

### Options avancées

```powershell
# Inclure les comptes désactivés
.\Audit-LocalAdmins.ps1 -ComputerName "SERVER01" -IncludeDisabled

# Timeout personnalisé
.\Audit-LocalAdmins.ps1 -ComputerName "SERVER01" -Timeout 60
```

---

## Sortie exemple

```
======================================================================
  LOCAL ADMINISTRATORS AUDIT
======================================================================
  Date: 2024-11-30 14:30:22
----------------------------------------------------------------------
[INFO] Auditing 3 server(s)

[INFO] Processing: SERVER01
[OK]   SERVER01 - Found 4 admin member(s)
       - DOMAIN\Domain Admins [Domain Group]
       - BUILTIN\Administrator [Local Account]
       - DOMAIN\svc_backup [Domain Account]
       - SERVER01\LocalAdmin [Local Account]

[INFO] Processing: SERVER02
[OK]   SERVER02 - Found 3 admin member(s)
       - DOMAIN\Domain Admins [Domain Group]
       - BUILTIN\Administrator [Local Account] (DISABLED)
       - DOMAIN\admin.user [Domain Account]

[INFO] Processing: SERVER03
[FAIL] SERVER03 - Connection failed: WinRM port 5985 not responding

======================================================================
  SUMMARY
======================================================================
  Servers audited: 3
    - Success: 2
    - Failed: 1
  Total admin members: 7
  Unique accounts: 6
```

---

## Format du fichier servers.txt

```text
# Commentaires ignorés
SERVER01
SERVER02.domain.local
192.168.1.100

# Serveurs de production
PRODSRV01
PRODSRV02
```

---

!!! danger "Contrôleurs de domaine"
    **N'exécutez PAS ce script sur des contrôleurs de domaine (DC) !**

    Sur un DC, le groupe "Administrators" local **n'existe pas** de la même façon.
    Les privilèges sont gérés via les groupes de domaine :

    - `Domain Admins`
    - `Enterprise Admins`
    - `Builtin\Administrators` (groupe de domaine)

    Pour auditer les admins d'un domaine AD, utilisez plutôt :

    ```powershell
    Get-ADGroupMember -Identity "Domain Admins" -Recursive
    Get-ADGroupMember -Identity "Enterprise Admins" -Recursive
    ```

!!! warning "Prérequis WinRM"
    Le service WinRM doit être activé et configuré sur les serveurs distants :

    ```powershell
    # Sur chaque serveur cible (en admin)
    Enable-PSRemoting -Force
    Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force
    ```

    En environnement Active Directory, les GPO peuvent déployer cette configuration automatiquement.

---

## Voir Aussi

- [Test-ADHealth.ps1](Test-ADHealth.md) - Health check Active Directory
- [Get-ServiceStatus.ps1](Get-ServiceStatus.md) - Audit des services Windows
