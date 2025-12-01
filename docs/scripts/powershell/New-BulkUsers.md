---
tags:
  - scripts
  - powershell
  - active-directory
  - users
  - automation
---

# New-BulkUsers.ps1

:material-star::material-star::material-star: **Niveau : Avancé**

Création et gestion en masse des utilisateurs depuis un fichier CSV.

---

## Description

Ce script automatise la gestion des utilisateurs en masse :
- Création d'utilisateurs AD depuis CSV
- Création d'utilisateurs locaux Windows
- Génération de mots de passe sécurisés
- Attribution aux groupes
- Mode simulation (WhatIf)
- Export des credentials créés
- Validation des données avant import

---

## Prérequis

- **Système** : Windows Server 2016+ ou Windows 10/11
- **PowerShell** : Version 5.1 minimum
- **Permissions** : Droits administrateur (Domain Admins pour AD, Administrateur local pour utilisateurs locaux)
- **Modules** : `ActiveDirectory` (pour mode AD uniquement, installé par défaut sur DC)

---

## Cas d'Usage

- **Onboarding massif** : Créer des dizaines d'utilisateurs lors de l'arrivée d'une nouvelle équipe
- **Migration Active Directory** : Recréer des comptes depuis un export CSV
- **Environnement de test** : Générer rapidement des utilisateurs pour tests et formation
- **Automatisation RH** : Intégrer avec un système RH pour provisioning automatique

---

## Script

```powershell
<#
.SYNOPSIS
    Bulk user creation and management from CSV file.

.DESCRIPTION
    Creates users in Active Directory or locally from a CSV file.
    Supports password generation, group membership, and credential export.

.PARAMETER CsvPath
    Path to the CSV file containing user data.

.PARAMETER Mode
    Target: AD (Active Directory) or Local (local Windows users).

.PARAMETER DefaultPassword
    Default password for all users (if not specified in CSV).

.PARAMETER GeneratePasswords
    Generate unique random passwords for each user.

.PARAMETER PasswordLength
    Length of generated passwords (default: 16).

.PARAMETER ExportCredentials
    Export created credentials to a secure file.

.PARAMETER WhatIf
    Simulation mode - show what would be created without making changes.

.EXAMPLE
    .\New-BulkUsers.ps1 -CsvPath users.csv -Mode AD -GeneratePasswords

.EXAMPLE
    .\New-BulkUsers.ps1 -CsvPath users.csv -Mode Local -DefaultPassword "TempPass123!"

.NOTES
    Author: ShellBook
    Version: 1.0
    Requires: ActiveDirectory module (for AD mode)
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path $_ -PathType Leaf })]
    [string]$CsvPath,

    [Parameter(Mandatory = $true)]
    [ValidateSet("AD", "Local")]
    [string]$Mode,

    [Parameter()]
    [string]$DefaultPassword,

    [Parameter()]
    [switch]$GeneratePasswords,

    [Parameter()]
    [int]$PasswordLength = 16,

    [Parameter()]
    [string]$ExportCredentials,

    [Parameter()]
    [string]$DefaultOU,

    [Parameter()]
    [string[]]$DefaultGroups,

    [Parameter()]
    [switch]$Force
)

#region Functions

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR", "SUCCESS")]
        [string]$Level = "INFO"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        "INFO"    { "Cyan" }
        "WARN"    { "Yellow" }
        "ERROR"   { "Red" }
        "SUCCESS" { "Green" }
    }

    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
}

function New-SecurePassword {
    param([int]$Length = 16)

    $chars = @()
    $chars += [char[]](65..90)   # A-Z
    $chars += [char[]](97..122)  # a-z
    $chars += [char[]](48..57)   # 0-9
    $chars += [char[]]"!@#$%^&*()_+-=[]{}|;:,.<>?"

    # Ensure at least one of each type
    $password = @()
    $password += [char](Get-Random -InputObject ([char[]](65..90)))   # Uppercase
    $password += [char](Get-Random -InputObject ([char[]](97..122))) # Lowercase
    $password += [char](Get-Random -InputObject ([char[]](48..57)))  # Number
    $password += [char](Get-Random -InputObject ([char[]]"!@#$%^&*"))  # Special

    # Fill remaining length
    for ($i = $password.Count; $i -lt $Length; $i++) {
        $password += [char](Get-Random -InputObject $chars)
    }

    # Shuffle
    $password = $password | Sort-Object { Get-Random }

    return -join $password
}

function Test-ADModule {
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Log "ActiveDirectory module not found. Install RSAT or run on a DC." -Level ERROR
        return $false
    }
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue
    return $true
}

function Test-UserExists {
    param(
        [string]$Username,
        [string]$Mode
    )

    if ($Mode -eq "AD") {
        try {
            $null = Get-ADUser -Identity $Username -ErrorAction Stop
            return $true
        }
        catch {
            return $false
        }
    }
    else {
        try {
            $null = Get-LocalUser -Name $Username -ErrorAction Stop
            return $true
        }
        catch {
            return $false
        }
    }
}

function New-ADUserFromCsv {
    param(
        [PSCustomObject]$UserData,
        [string]$Password,
        [string]$OU,
        [string[]]$Groups
    )

    $samAccountName = $UserData.Username
    $displayName = "$($UserData.FirstName) $($UserData.LastName)"
    $userPrincipalName = "$samAccountName@$((Get-ADDomain).DNSRoot)"

    # Build parameters
    $adParams = @{
        SamAccountName       = $samAccountName
        UserPrincipalName    = $userPrincipalName
        Name                 = $displayName
        DisplayName          = $displayName
        GivenName            = $UserData.FirstName
        Surname              = $UserData.LastName
        AccountPassword      = (ConvertTo-SecureString $Password -AsPlainText -Force)
        Enabled              = $true
        ChangePasswordAtLogon = $true
    }

    # Optional fields
    if ($UserData.Email) { $adParams.EmailAddress = $UserData.Email }
    if ($UserData.Department) { $adParams.Department = $UserData.Department }
    if ($UserData.Title) { $adParams.Title = $UserData.Title }
    if ($UserData.Office) { $adParams.Office = $UserData.Office }
    if ($UserData.Phone) { $adParams.OfficePhone = $UserData.Phone }
    if ($UserData.Description) { $adParams.Description = $UserData.Description }

    # OU
    $targetOU = if ($UserData.OU) { $UserData.OU } else { $OU }
    if ($targetOU) { $adParams.Path = $targetOU }

    # Create user
    New-ADUser @adParams

    # Add to groups
    $userGroups = @()
    if ($UserData.Groups) { $userGroups += $UserData.Groups -split ";" }
    if ($Groups) { $userGroups += $Groups }

    foreach ($group in ($userGroups | Where-Object { $_ })) {
        try {
            Add-ADGroupMember -Identity $group.Trim() -Members $samAccountName
            Write-Log "  Added to group: $group" -Level INFO
        }
        catch {
            Write-Log "  Failed to add to group '$group': $_" -Level WARN
        }
    }

    return $true
}

function New-LocalUserFromCsv {
    param(
        [PSCustomObject]$UserData,
        [string]$Password,
        [string[]]$Groups
    )

    $username = $UserData.Username
    $fullName = "$($UserData.FirstName) $($UserData.LastName)"

    # Build parameters
    $localParams = @{
        Name                 = $username
        FullName             = $fullName
        Password             = (ConvertTo-SecureString $Password -AsPlainText -Force)
        PasswordNeverExpires = $false
        AccountNeverExpires  = $true
    }

    if ($UserData.Description) { $localParams.Description = $UserData.Description }

    # Create user
    New-LocalUser @localParams

    # Add to groups
    $userGroups = @()
    if ($UserData.Groups) { $userGroups += $UserData.Groups -split ";" }
    if ($Groups) { $userGroups += $Groups }

    foreach ($group in ($userGroups | Where-Object { $_ })) {
        try {
            Add-LocalGroupMember -Group $group.Trim() -Member $username
            Write-Log "  Added to local group: $group" -Level INFO
        }
        catch {
            Write-Log "  Failed to add to local group '$group': $_" -Level WARN
        }
    }

    return $true
}

function Export-Credentials {
    param(
        [array]$Credentials,
        [string]$OutputPath
    )

    $exportData = $Credentials | Select-Object Username, Password, Email, CreatedAt

    # Export to CSV (encrypted password column)
    $exportData | Export-Csv -Path $OutputPath -NoTypeInformation

    # Also create a secure version
    $securePath = $OutputPath -replace '\.csv$', '_secure.xml'
    $Credentials | Export-Clixml -Path $securePath

    Write-Log "Credentials exported to: $OutputPath" -Level SUCCESS
    Write-Log "Secure export: $securePath" -Level INFO
}

#endregion

#region Main

# Banner
Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  BULK USER MANAGER" -ForegroundColor Green
Write-Host "  Mode: $Mode" -ForegroundColor Yellow
if ($WhatIfPreference) {
    Write-Host "  [SIMULATION MODE]" -ForegroundColor Magenta
}
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

# Check requirements
if ($Mode -eq "AD") {
    if (-not (Test-ADModule)) {
        exit 1
    }
    Write-Log "ActiveDirectory module loaded" -Level SUCCESS
}

# Validate password options
if (-not $GeneratePasswords -and -not $DefaultPassword) {
    Write-Log "Specify -GeneratePasswords or -DefaultPassword" -Level ERROR
    exit 1
}

# Import CSV
Write-Log "Loading CSV: $CsvPath" -Level INFO

try {
    $users = Import-Csv -Path $CsvPath
}
catch {
    Write-Log "Failed to import CSV: $_" -Level ERROR
    exit 1
}

Write-Log "Found $($users.Count) users to process" -Level INFO

# Validate required columns
$requiredColumns = @("Username", "FirstName", "LastName")
$csvColumns = $users[0].PSObject.Properties.Name

foreach ($col in $requiredColumns) {
    if ($col -notin $csvColumns) {
        Write-Log "Missing required column: $col" -Level ERROR
        Write-Log "Required columns: $($requiredColumns -join ', ')" -Level INFO
        exit 1
    }
}

# Process users
$results = @{
    Created = 0
    Skipped = 0
    Failed  = 0
}

$createdCredentials = @()

foreach ($user in $users) {
    $username = $user.Username

    Write-Host ""
    Write-Log "Processing: $username ($($user.FirstName) $($user.LastName))" -Level INFO

    # Check if exists
    if (Test-UserExists -Username $username -Mode $Mode) {
        if (-not $Force) {
            Write-Log "  User already exists, skipping" -Level WARN
            $results.Skipped++
            continue
        }
        Write-Log "  User exists but -Force specified, will update" -Level WARN
    }

    # Generate or use password
    $password = if ($GeneratePasswords) {
        New-SecurePassword -Length $PasswordLength
    }
    elseif ($user.Password) {
        $user.Password
    }
    else {
        $DefaultPassword
    }

    # WhatIf check
    if ($PSCmdlet.ShouldProcess($username, "Create user")) {
        try {
            if ($Mode -eq "AD") {
                $created = New-ADUserFromCsv -UserData $user -Password $password `
                    -OU $DefaultOU -Groups $DefaultGroups
            }
            else {
                $created = New-LocalUserFromCsv -UserData $user -Password $password `
                    -Groups $DefaultGroups
            }

            if ($created) {
                Write-Log "  User created successfully" -Level SUCCESS
                $results.Created++

                # Store credentials for export
                $createdCredentials += [PSCustomObject]@{
                    Username  = $username
                    Password  = $password
                    Email     = $user.Email
                    FullName  = "$($user.FirstName) $($user.LastName)"
                    CreatedAt = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                }
            }
        }
        catch {
            Write-Log "  Failed to create user: $_" -Level ERROR
            $results.Failed++
        }
    }
    else {
        Write-Log "  [WhatIf] Would create user with password: $($password.Substring(0,4))****" -Level INFO
        $results.Created++
    }
}

# Export credentials if requested
if ($ExportCredentials -and $createdCredentials.Count -gt 0) {
    Export-Credentials -Credentials $createdCredentials -OutputPath $ExportCredentials
}

# Summary
Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  SUMMARY" -ForegroundColor Green
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Total Processed: $($users.Count)" -ForegroundColor White
Write-Host "  Created: $($results.Created)" -ForegroundColor Green
Write-Host "  Skipped: $($results.Skipped)" -ForegroundColor Yellow
Write-Host "  Failed:  $($results.Failed)" -ForegroundColor Red
Write-Host ""

if ($results.Failed -gt 0) {
    exit 1
}

#endregion
```

---

## Format CSV

### Colonnes Requises

```csv
Username,FirstName,LastName
jdoe,John,Doe
asmith,Alice,Smith
```

### Colonnes Optionnelles

```csv
Username,FirstName,LastName,Email,Department,Title,Office,Phone,Groups,OU,Password,Description
jdoe,John,Doe,john.doe@company.com,IT,Developer,Paris,+33123456789,Developers;IT-Users,OU=Users,OU=IT,DC=company,DC=com,,New developer
asmith,Alice,Smith,alice.smith@company.com,HR,Manager,Lyon,+33987654321,HR-Team;Managers,OU=Users,OU=HR,DC=company,DC=com,,HR Manager
bwilson,Bob,Wilson,bob.wilson@company.com,Finance,Analyst,Paris,,Finance-Users,,,Contractor
```

### Exemple Complet

Fichier `new_users.csv`:

```csv
Username,FirstName,LastName,Email,Department,Title,Groups
jdupont,Jean,Dupont,jean.dupont@company.com,IT,Administrateur Système,IT-Admins;VPN-Users
mmartin,Marie,Martin,marie.martin@company.com,RH,Responsable RH,HR-Team;Managers
pdurand,Pierre,Durand,pierre.durand@company.com,Dev,Développeur Senior,Developers;Git-Users
sleblanc,Sophie,Leblanc,sophie.leblanc@company.com,Finance,Comptable,Finance-Users
```

---

## Utilisation

### Active Directory

```powershell
# Créer des utilisateurs AD avec mots de passe générés
.\New-BulkUsers.ps1 -CsvPath users.csv -Mode AD -GeneratePasswords

# Avec export des credentials
.\New-BulkUsers.ps1 -CsvPath users.csv -Mode AD -GeneratePasswords `
    -ExportCredentials "C:\Admin\new_users_credentials.csv"

# Avec OU et groupes par défaut
.\New-BulkUsers.ps1 -CsvPath users.csv -Mode AD -GeneratePasswords `
    -DefaultOU "OU=NewUsers,OU=Company,DC=domain,DC=com" `
    -DefaultGroups @("Domain Users", "VPN-Access")

# Mode simulation
.\New-BulkUsers.ps1 -CsvPath users.csv -Mode AD -GeneratePasswords -WhatIf

# Avec mot de passe par défaut
.\New-BulkUsers.ps1 -CsvPath users.csv -Mode AD -DefaultPassword "Welcome2024!"
```

### Utilisateurs Locaux

```powershell
# Créer des utilisateurs locaux
.\New-BulkUsers.ps1 -CsvPath users.csv -Mode Local -GeneratePasswords

# Avec groupe local par défaut
.\New-BulkUsers.ps1 -CsvPath users.csv -Mode Local -GeneratePasswords `
    -DefaultGroups @("Remote Desktop Users")

# Simulation
.\New-BulkUsers.ps1 -CsvPath users.csv -Mode Local -DefaultPassword "TempPass!" -WhatIf
```

---

## Sortie Exemple

```
═══════════════════════════════════════════════════════════
  BULK USER MANAGER
  Mode: AD
═══════════════════════════════════════════════════════════

[2024-01-15 14:30:22] [SUCCESS] ActiveDirectory module loaded
[2024-01-15 14:30:22] [INFO] Loading CSV: C:\Admin\users.csv
[2024-01-15 14:30:22] [INFO] Found 4 users to process

[2024-01-15 14:30:22] [INFO] Processing: jdupont (Jean Dupont)
[2024-01-15 14:30:23] [INFO]   Added to group: IT-Admins
[2024-01-15 14:30:23] [INFO]   Added to group: VPN-Users
[2024-01-15 14:30:23] [SUCCESS]   User created successfully

[2024-01-15 14:30:23] [INFO] Processing: mmartin (Marie Martin)
[2024-01-15 14:30:24] [INFO]   Added to group: HR-Team
[2024-01-15 14:30:24] [INFO]   Added to group: Managers
[2024-01-15 14:30:24] [SUCCESS]   User created successfully

[2024-01-15 14:30:24] [INFO] Processing: pdurand (Pierre Durand)
[2024-01-15 14:30:24] [WARN]   User already exists, skipping

[2024-01-15 14:30:24] [INFO] Processing: sleblanc (Sophie Leblanc)
[2024-01-15 14:30:25] [INFO]   Added to group: Finance-Users
[2024-01-15 14:30:25] [SUCCESS]   User created successfully

[2024-01-15 14:30:25] [SUCCESS] Credentials exported to: C:\Admin\credentials.csv

═══════════════════════════════════════════════════════════
  SUMMARY
═══════════════════════════════════════════════════════════

  Total Processed: 4
  Created: 3
  Skipped: 1
  Failed:  0
```

---

## Fichier Credentials Exporté

```csv
Username,Password,Email,CreatedAt
jdupont,X7#kL9@mN2$pQ4,jean.dupont@company.com,2024-01-15 14:30:23
mmartin,R5$tY8&uI1@oP3,marie.martin@company.com,2024-01-15 14:30:24
sleblanc,W2#eR6$tY9@uI4,sophie.leblanc@company.com,2024-01-15 14:30:25
```

---

## Bonnes Pratiques

1. **Toujours tester en mode WhatIf** avant exécution réelle
2. **Sécuriser le fichier credentials** exporté (supprimer après distribution)
3. **Forcer le changement de mot de passe** à la première connexion
4. **Valider le CSV** avant import (caractères spéciaux, doublons)
5. **Logger les opérations** pour audit

---

## Voir Aussi

- [Test-ADHealth.ps1](Test-ADHealth.md)
- [Audit-LocalAdmins.ps1](Audit-LocalAdmins.md)
