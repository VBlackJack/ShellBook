---
tags:
  - windows
  - powershell
  - training
  - workshop
---

# Workshop PowerShell : Les Bonnes Pratiques

Ce workshop compile les meilleures techniques issues de scripts professionnels.
*Source : Analyse des démos de formation (Thomas Boutry).*

## 1. La Gestion des Erreurs (`ErrorAction`)

En production, un script ne doit pas planter silencieusement ou afficher du rouge effrayant sans explication.

### Stop, Continue, SilentlyContinue

```powershell
# Arrête tout si le fichier n'existe pas (Critical)
Get-Item "C:\Config\Secret.conf" -ErrorAction Stop

# Continue même si ça échoue (Non-Critical, ex: cleanup de fichiers temp)
Remove-Item "C:\Temp\*.tmp" -ErrorAction SilentlyContinue

# Capture l'erreur dans une variable sans l'afficher
Get-Service "ServiceInconnu" -ErrorAction SilentlyContinue -ErrorVariable MonErreur

if ($MonErreur) {
    Write-Warning "Le service n'existe pas, mais on continue..."
}
```

## 2. Le Pipeline et les Objets

La force de PowerShell est de manipuler des **Objets**, pas du texte.

### Filtrer avant de traiter (Performance)

*   **Mauvais** (Récupère tout, puis filtre) :
    ```powershell
    Get-Service | Where-Object { $_.Status -eq 'Stopped' }
    ```
*   **Bon** (Filtre à la source, si la Cmdlet le permet) :
    ```powershell
    Get-Service -Name "sql*"
    ```

### Créer ses propres objets (Custom Object)

Idéal pour l'export CSV ou JSON.

```powershell
$Rapport = @()

foreach ($Disk in Get-CimInstance Win32_LogicalDisk) {
    # On crée un objet propre avec juste ce qu'on veut
    $Info = [PSCustomObject]@{
        Lettre       = $Disk.DeviceID
        TailleGB     = [math]::Round($Disk.Size / 1GB, 2)
        EspaceLibre  = [math]::Round($Disk.FreeSpace / 1GB, 2)
        Pourcentage  = [math]::Round(($Disk.FreeSpace / $Disk.Size) * 100, 1)
    }
    $Rapport += $Info
}

# Export facile
$Rapport | Export-Csv "C:\Logs\DiskReport.csv" -NoTypeInformation
```

## 3. `WhatIf` et `Confirm`

Toujours implémenter ces switchs pour les actions destructrices.

```powershell
function Remove-VieuxLogs {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param (
        [string]$Path
    )

    # La magie est ici : $PSCmdlet.ShouldProcess
    if ($PSCmdlet.ShouldProcess($Path, "Supprimer les fichiers de plus de 30 jours")) {
        Get-ChildItem $Path | Where-Object LastWriteTime -lt (Get-Date).AddDays(-30) | Remove-Item
    }
}

# Utilisation sans risque
Remove-VieuxLogs -Path "C:\Logs" -WhatIf
```
