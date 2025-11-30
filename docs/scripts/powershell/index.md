---
tags:
  - scripts
  - powershell
  - windows
---

# Scripts PowerShell

Collection de scripts PowerShell pour l'administration Windows et cross-platform. **23 scripts disponibles.**

---

## Audit & Découverte

| Script | Description | Niveau |
|--------|-------------|--------|
| [Invoke-ServerAudit.ps1](Invoke-ServerAudit.md) | **God Script** - Audit complet serveur (Markdown) | :material-star::material-star::material-star: |

## Système

| Script | Description | Niveau |
|--------|-------------|--------|
| [Get-SystemInfo.ps1](Get-SystemInfo.md) | Informations système complètes | :material-star: |
| [Test-DiskSpace.ps1](Test-DiskSpace.md) | Vérification espace disque avec alertes | :material-star: |
| [Get-PendingReboot.ps1](Get-PendingReboot.md) | Détection redémarrages en attente | :material-star: |
| [Export-EventLogs.ps1](Export-EventLogs.md) | Export journaux Windows (CSV/JSON/EVTX) | :material-star::material-star: |

## Réseau

| Script | Description | Niveau |
|--------|-------------|--------|
| [Test-NetworkConnectivity.ps1](Test-NetworkConnectivity.md) | Test de connectivité réseau | :material-star: |

## Sécurité & Certificats

| Script | Description | Niveau |
|--------|-------------|--------|
| [Test-SSLCertificates.ps1](Test-SSLCertificates.md) | Vérification certificats SSL/TLS multi-endpoints | :material-star::material-star: |
| [Audit-LocalAdmins.ps1](Audit-LocalAdmins.md) | Audit des administrateurs locaux | :material-star::material-star: |

## Fichiers & Backup

| Script | Description | Niveau |
|--------|-------------|--------|
| [Backup-Directory.ps1](Backup-Directory.md) | Backup avec rotation | :material-star::material-star: |
| [Find-LargeFiles.ps1](Find-LargeFiles.md) | Recherche fichiers volumineux | :material-star: |

## Active Directory & Utilisateurs

| Script | Description | Niveau |
|--------|-------------|--------|
| [New-BulkUsers.ps1](New-BulkUsers.md) | Création utilisateurs en masse (AD + Local) | :material-star::material-star: |

## Services

| Script | Description | Niveau |
|--------|-------------|--------|
| [Get-ServiceStatus.ps1](Get-ServiceStatus.md) | Gestion des services Windows | :material-star: |

## Patch Management

| Script | Description | Niveau |
|--------|-------------|--------|
| [Get-WindowsUpdateStatus.ps1](Get-WindowsUpdateStatus.md) | Diagnostic complet WU/WSUS/SCCM | :material-star::material-star: |
| [Invoke-PrePatchPreparation.ps1](Invoke-PrePatchPreparation.md) | Préparation pré-patching (nettoyage, vérifications) | :material-star::material-star::material-star: |
| [Repair-WindowsUpdate.ps1](Repair-WindowsUpdate.md) | Réparation automatique Windows Update | :material-star::material-star::material-star: |
| [Get-PatchCompliance.ps1](Get-PatchCompliance.md) | Rapport conformité patchs avec scoring | :material-star::material-star::material-star: |

## Infrastructure Windows

| Script | Description | Niveau |
|--------|-------------|--------|
| [Test-WSUSHealth.ps1](Test-WSUSHealth.md) | Vérification santé serveur WSUS | :material-star::material-star: |
| [Test-ADHealth.ps1](Test-ADHealth.md) | Vérification complète Active Directory | :material-star::material-star::material-star: |
| [Test-DNSServer.ps1](Test-DNSServer.md) | Vérification serveur DNS Windows | :material-star::material-star: |
| [Test-DHCPServer.ps1](Test-DHCPServer.md) | Vérification serveur DHCP Windows | :material-star::material-star: |
| [Test-SQLServer.ps1](Test-SQLServer.md) | Vérification instance SQL Server | :material-star::material-star: |
| [Test-IISHealth.ps1](Test-IISHealth.md) | Vérification serveur IIS | :material-star::material-star: |
| [Test-PKIHealth.ps1](Test-PKIHealth.md) | Vérification PKI / AD CS | :material-star::material-star::material-star: |

---

## Template de Script

```powershell
#Requires -Version 5.1
<#
.SYNOPSIS
    Description courte du script.

.DESCRIPTION
    Description détaillée du script et de son fonctionnement.

.PARAMETER Param1
    Description du paramètre 1.

.PARAMETER Param2
    Description du paramètre 2.

.EXAMPLE
    .\Script-Name.ps1 -Param1 "Value"
    Description de l'exemple.

.NOTES
    Author: ShellBook
    Version: 1.0
    Date: 2024-01-01
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$Param1 = "Default",

    [Parameter(Mandatory = $false)]
    [switch]$Verbose
)

#region Configuration
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
#endregion

#region Functions
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Warning', 'Error')]
        [string]$Level = 'Info'
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $colors = @{
        'Info'    = 'Green'
        'Warning' = 'Yellow'
        'Error'   = 'Red'
    }

    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $colors[$Level]
}
#endregion

#region Main
try {
    Write-Log "Script démarré" -Level Info

    # Code principal ici

    Write-Log "Script terminé" -Level Info
}
catch {
    Write-Log "Erreur: $_" -Level Error
    exit 1
}
#endregion
```

---

## Bonnes Pratiques PowerShell

### Paramètres

```powershell
# Utiliser CmdletBinding pour les fonctionnalités avancées
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory, ValueFromPipeline)]
    [ValidateNotNullOrEmpty()]
    [string]$Path,

    [Parameter()]
    [ValidateRange(1, 100)]
    [int]$Threshold = 80
)
```

### Gestion d'erreurs

```powershell
try {
    # Code à risque
    $result = Get-Item -Path $Path -ErrorAction Stop
}
catch [System.IO.FileNotFoundException] {
    Write-Warning "Fichier non trouvé: $Path"
}
catch {
    Write-Error "Erreur inattendue: $_"
    throw
}
finally {
    # Nettoyage
}
```

### Output Formaté

```powershell
# Créer des objets pour un output propre
[PSCustomObject]@{
    Name      = $item.Name
    Size      = "{0:N2} MB" -f ($item.Length / 1MB)
    Modified  = $item.LastWriteTime
    Status    = "OK"
}
```

---

## Voir Aussi

- [Scripts Bash](../bash/index.md)
- [Scripts Python](../python/index.md)
