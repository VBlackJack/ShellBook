---
tags:
  - scripts
  - powershell
  - fichiers
  - système
---

# Find-LargeFiles.ps1

:material-star: **Niveau : Débutant**

Recherche des fichiers volumineux sur le système.

---

## Description

Ce script identifie les fichiers volumineux :
- Recherche par taille minimum
- Filtrage par extension
- Tri par taille ou date
- Export des résultats

---

## Script

```powershell
#Requires -Version 5.1
<#
.SYNOPSIS
    Find large files.

.DESCRIPTION
    Identifie les fichiers volumineux avec options de filtrage
    et d'export.

.PARAMETER Path
    Chemin de recherche (défaut: C:\).

.PARAMETER MinSize
    Taille minimum (ex: 100MB, 1GB).

.PARAMETER TopN
    Nombre de résultats (défaut: 20).

.PARAMETER Extension
    Filtrer par extension (ex: .log, .bak).

.PARAMETER SortBy
    Trier par: Size, Date, Name.

.EXAMPLE
    .\Find-LargeFiles.ps1 -Path "C:\" -MinSize 100MB

.EXAMPLE
    .\Find-LargeFiles.ps1 -Path "D:\Data" -Extension ".log" -TopN 50

.NOTES
    Author: ShellBook
    Version: 1.0
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$Path = "C:\",

    [Parameter()]
    [long]$MinSize = 100MB,

    [Parameter()]
    [int]$TopN = 20,

    [Parameter()]
    [string]$Extension,

    [Parameter()]
    [ValidateSet('Size', 'Date', 'Name')]
    [string]$SortBy = 'Size',

    [Parameter()]
    [ValidateSet('Console', 'CSV', 'GridView')]
    [string]$OutputFormat = 'Console'
)

#region Functions
function Format-FileSize {
    param([long]$Bytes)

    switch ($Bytes) {
        { $_ -ge 1TB } { return "{0:N2} TB" -f ($_ / 1TB) }
        { $_ -ge 1GB } { return "{0:N2} GB" -f ($_ / 1GB) }
        { $_ -ge 1MB } { return "{0:N2} MB" -f ($_ / 1MB) }
        { $_ -ge 1KB } { return "{0:N2} KB" -f ($_ / 1KB) }
        default { return "$_ B" }
    }
}

function Get-SizeColor {
    param([long]$Bytes)

    switch ($Bytes) {
        { $_ -ge 1GB } { return 'Red' }
        { $_ -ge 500MB } { return 'Yellow' }
        { $_ -ge 100MB } { return 'Cyan' }
        default { return 'White' }
    }
}
#endregion

#region Main
Write-Host ""
Write-Host ("=" * 70) -ForegroundColor Cyan
Write-Host "  FIND LARGE FILES" -ForegroundColor Green
Write-Host ("=" * 70) -ForegroundColor Cyan
Write-Host "  Path: $Path"
Write-Host "  Min Size: $(Format-FileSize $MinSize)"
Write-Host "  Top: $TopN results"
if ($Extension) { Write-Host "  Extension: $Extension" }
Write-Host ("-" * 70) -ForegroundColor Cyan
Write-Host ""
Write-Host "  Searching..." -ForegroundColor Yellow

# Recherche
$searchParams = @{
    Path        = $Path
    Recurse     = $true
    File        = $true
    ErrorAction = 'SilentlyContinue'
}

if ($Extension) {
    $searchParams['Filter'] = "*$Extension"
}

$files = Get-ChildItem @searchParams |
    Where-Object { $_.Length -ge $MinSize }

# Tri
$sortProperty = switch ($SortBy) {
    'Size' { 'Length' }
    'Date' { 'LastWriteTime' }
    'Name' { 'Name' }
}

$results = $files |
    Sort-Object -Property $sortProperty -Descending |
    Select-Object -First $TopN |
    ForEach-Object {
        [PSCustomObject]@{
            Name         = $_.Name
            FullPath     = $_.FullName
            Size         = $_.Length
            SizeFormatted = Format-FileSize $_.Length
            Modified     = $_.LastWriteTime
            Extension    = $_.Extension
        }
    }

if (-not $results) {
    Write-Host "  No files found matching criteria." -ForegroundColor Yellow
    exit 0
}

# Output
switch ($OutputFormat) {
    'CSV' {
        $results | Select-Object Name, FullPath, Size, Modified |
            ConvertTo-Csv -NoTypeInformation
    }

    'GridView' {
        $results | Out-GridView -Title "Large Files"
    }

    default {
        Write-Host ""
        Write-Host ("  {0,-10} {1,-20} {2}" -f "SIZE", "MODIFIED", "FILE") -ForegroundColor Cyan
        Write-Host ("  {0,-10} {1,-20} {2}" -f "----", "--------", "----") -ForegroundColor Cyan

        foreach ($file in $results) {
            $color = Get-SizeColor -Bytes $file.Size
            $modified = $file.Modified.ToString("yyyy-MM-dd HH:mm")

            Write-Host ("  {0,-10}" -f $file.SizeFormatted) -ForegroundColor $color -NoNewline
            Write-Host (" {0,-20}" -f $modified) -NoNewline
            Write-Host " $($file.FullPath)"
        }

        # Statistiques
        $totalSize = ($results | Measure-Object -Property Size -Sum).Sum
        $totalCount = $results.Count

        Write-Host ""
        Write-Host ("-" * 70) -ForegroundColor Cyan
        Write-Host "  Found: $totalCount files | Total: $(Format-FileSize $totalSize)" -ForegroundColor Green
        Write-Host ("=" * 70) -ForegroundColor Cyan
    }
}
#endregion
```

---

## Utilisation

```powershell
# Recherche par défaut
.\Find-LargeFiles.ps1

# Chemin et taille spécifiques
.\Find-LargeFiles.ps1 -Path "D:\Data" -MinSize 500MB

# Filtrer par extension
.\Find-LargeFiles.ps1 -Path "C:\Logs" -Extension ".log" -MinSize 50MB

# Top 50 triés par date
.\Find-LargeFiles.ps1 -TopN 50 -SortBy Date

# Export CSV
.\Find-LargeFiles.ps1 -OutputFormat CSV | Out-File large-files.csv

# Affichage GridView (interactif)
.\Find-LargeFiles.ps1 -OutputFormat GridView
```

---

## Sortie Exemple

```
======================================================================
  FIND LARGE FILES
======================================================================
  Path: C:\
  Min Size: 100.00 MB
  Top: 20 results
----------------------------------------------------------------------

  Searching...

  SIZE       MODIFIED             FILE
  ----       --------             ----
  4.52 GB    2024-01-10 15:30     C:\Windows\MEMORY.DMP
  2.34 GB    2024-01-15 08:00     C:\hiberfil.sys
  1.89 GB    2024-01-14 22:15     C:\pagefile.sys
  856.45 MB  2024-01-12 10:45     C:\Users\Admin\Downloads\installer.exe
  534.21 MB  2024-01-08 16:20     C:\Backup\database.bak
  423.78 MB  2024-01-15 09:30     C:\Windows\SoftwareDistribution\Download\abc.cab
  312.45 MB  2024-01-11 14:00     C:\Temp\logs.zip

----------------------------------------------------------------------
  Found: 7 files | Total: 10.82 GB
======================================================================
```

---

## Voir Aussi

- [Test-DiskSpace.ps1](Test-DiskSpace.md)
- [Clear-SystemCache.ps1](Clear-SystemCache.md)
