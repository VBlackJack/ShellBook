---
tags:
  - formation
  - windows-server
  - powershell
  - cheatsheet
---

# Cheatsheet PowerShell

Guide de référence rapide pour PowerShell sur Windows Server.

---

## Navigation & Fichiers

```powershell
# Navigation
Get-Location                    # pwd - Répertoire courant
Set-Location C:\Windows         # cd - Changer de répertoire
Push-Location / Pop-Location    # Empiler/dépiler l'emplacement

# Lister
Get-ChildItem                   # ls, dir
Get-ChildItem -Recurse -Filter *.log
Get-ChildItem -Hidden           # Fichiers cachés

# Fichiers
New-Item -Path file.txt -ItemType File
New-Item -Path folder -ItemType Directory
Copy-Item src.txt dest.txt
Move-Item old.txt new.txt
Remove-Item file.txt -Force
Rename-Item old.txt new.txt

# Contenu
Get-Content file.txt            # cat
Get-Content file.txt -Tail 10   # Dernières lignes
Set-Content file.txt "contenu"
Add-Content file.txt "ajout"

# Chemins
Test-Path C:\Windows            # Existe ?
Join-Path C:\Users Admin        # C:\Users\Admin
Split-Path C:\Windows\file.txt  # C:\Windows
Resolve-Path .\file.txt         # Chemin absolu
```

---

## Aide & Découverte

```powershell
# Aide
Get-Help Get-Process            # Aide basique
Get-Help Get-Process -Examples  # Exemples
Get-Help Get-Process -Full      # Complète
Get-Help *process*              # Recherche
Update-Help                     # Mettre à jour

# Commandes
Get-Command                     # Toutes
Get-Command -Verb Get           # Par verbe
Get-Command -Noun Process       # Par nom
Get-Command -Module ActiveDirectory

# Propriétés et méthodes
Get-Process | Get-Member        # Voir les membres
Get-Process | Get-Member -MemberType Property
```

---

## Pipeline & Objets

```powershell
# Filtrer
Get-Process | Where-Object CPU -gt 10
Get-Service | Where-Object { $_.Status -eq "Running" }

# Sélectionner
Get-Process | Select-Object Name, CPU, Id
Get-Process | Select-Object -First 5
Get-Process | Select-Object * -ExcludeProperty *64

# Trier
Get-Process | Sort-Object CPU -Descending
Get-Process | Sort-Object CPU -Descending | Select-Object -First 10

# Grouper
Get-Service | Group-Object Status

# Compter
Get-Process | Measure-Object
Get-Process | Measure-Object CPU -Sum -Average

# Boucle
Get-Service | ForEach-Object { $_.Name }
1..10 | ForEach-Object { $_ * 2 }
```

---

## Variables & Types

```powershell
# Variables
$var = "valeur"
[string]$name = "John"
[int]$count = 10
[array]$list = @(1, 2, 3)
[hashtable]$hash = @{key = "value"}

# Chaînes
"Variable: $var"                # Interpolation
'Littéral: $var'                # Pas d'interpolation
"Date: $(Get-Date)"             # Sous-expression
$str.ToUpper()
$str.Replace("old", "new")
$str.Split(",")

# Tableaux
$arr = @(1, 2, 3)
$arr[0]                         # Premier
$arr[-1]                        # Dernier
$arr += 4                       # Ajouter
$arr.Count                      # Taille

# Hashtables
$hash = @{Name="John"; Age=30}
$hash["Name"]                   # Accès
$hash.Age                       # Accès
$hash.Add("City", "Paris")      # Ajouter
$hash.Keys                      # Clés
```

---

## Conditions & Boucles

```powershell
# If/Else
if ($condition) {
    # code
} elseif ($autre) {
    # code
} else {
    # code
}

# Switch
switch ($value) {
    "A" { "Option A" }
    "B" { "Option B" }
    default { "Autre" }
}

# ForEach
foreach ($item in $collection) {
    Write-Host $item
}

# For
for ($i = 0; $i -lt 10; $i++) {
    Write-Host $i
}

# While
while ($condition) {
    # code
}

# Do-While
do {
    # code
} while ($condition)
```

---

## Opérateurs

```powershell
# Comparaison
-eq    # Égal
-ne    # Différent
-gt    # Supérieur
-lt    # Inférieur
-ge    # Supérieur ou égal
-le    # Inférieur ou égal
-like  # Wildcard (*, ?)
-match # Regex
-contains # Tableau contient
-in    # Valeur dans tableau

# Logiques
-and   # ET
-or    # OU
-not   # NON
!      # NON (alias)

# Texte
-split # Diviser
-join  # Joindre
-replace # Remplacer (regex)
```

---

## Services & Processus

```powershell
# Services
Get-Service
Get-Service -Name Spooler
Start-Service -Name Spooler
Stop-Service -Name Spooler
Restart-Service -Name Spooler
Set-Service -Name Spooler -StartupType Automatic

# Processus
Get-Process
Get-Process -Name notepad
Start-Process notepad.exe
Stop-Process -Name notepad
Stop-Process -Id 1234 -Force
```

---

## Active Directory

```powershell
# Module
Import-Module ActiveDirectory

# Utilisateurs
Get-ADUser -Filter *
Get-ADUser -Identity jdoe -Properties *
New-ADUser -Name "John Doe" -SamAccountName jdoe
Set-ADUser -Identity jdoe -Department "IT"
Remove-ADUser -Identity jdoe
Enable-ADAccount -Identity jdoe
Disable-ADAccount -Identity jdoe
Unlock-ADAccount -Identity jdoe

# Groupes
Get-ADGroup -Filter *
Get-ADGroupMember -Identity "Domain Admins"
New-ADGroup -Name "IT-Team" -GroupScope Global
Add-ADGroupMember -Identity "IT-Team" -Members jdoe
Remove-ADGroupMember -Identity "IT-Team" -Members jdoe

# Ordinateurs
Get-ADComputer -Filter *
Get-ADComputer -Identity PC001 -Properties *

# OU
Get-ADOrganizationalUnit -Filter *
New-ADOrganizationalUnit -Name "Corp"
Move-ADObject -Identity $user -TargetPath "OU=Users,DC=corp,DC=local"

# Recherche
Get-ADUser -Filter {Department -eq "IT"}
Get-ADUser -Filter * -SearchBase "OU=Users,DC=corp,DC=local"
Get-ADObject -Filter * -SearchBase "DC=corp,DC=local" -SearchScope Subtree
```

---

## Réseau

```powershell
# Configuration
Get-NetAdapter
Get-NetIPAddress
Get-NetIPConfiguration

# Configurer IP
New-NetIPAddress -InterfaceAlias Ethernet -IPAddress 192.168.1.10 -PrefixLength 24 -DefaultGateway 192.168.1.1
Set-DnsClientServerAddress -InterfaceAlias Ethernet -ServerAddresses 192.168.1.1,8.8.8.8

# Diagnostic
Test-NetConnection 192.168.1.1
Test-NetConnection google.com -Port 443
Test-Connection google.com -Count 4
Resolve-DnsName google.com

# Firewall
Get-NetFirewallRule
New-NetFirewallRule -DisplayName "HTTP" -Direction Inbound -Protocol TCP -LocalPort 80 -Action Allow
Enable-NetFirewallRule -DisplayName "HTTP"
Disable-NetFirewallRule -DisplayName "HTTP"
```

---

## Gestion Serveur

```powershell
# Features
Get-WindowsFeature
Install-WindowsFeature -Name Web-Server -IncludeManagementTools
Uninstall-WindowsFeature -Name Web-Server

# GPO
Get-GPO -All
New-GPO -Name "Security"
New-GPLink -Name "Security" -Target "OU=Computers,DC=corp,DC=local"
Backup-GPO -All -Path C:\GPOBackup

# Disques
Get-Disk
Get-Partition
Get-Volume
Initialize-Disk -Number 1 -PartitionStyle GPT
New-Partition -DiskNumber 1 -UseMaximumSize -AssignDriveLetter
Format-Volume -DriveLetter E -FileSystem NTFS

# Partages
Get-SmbShare
New-SmbShare -Name "Data" -Path C:\Data -FullAccess "Administrators"
Remove-SmbShare -Name "Data" -Force
```

---

## Remote

```powershell
# PSRemoting
Enable-PSRemoting -Force
Enter-PSSession -ComputerName SRV01
Exit-PSSession
Invoke-Command -ComputerName SRV01 -ScriptBlock { Get-Service }
Invoke-Command -ComputerName SRV01,SRV02 -ScriptBlock { hostname }

# Credentials
$cred = Get-Credential
Enter-PSSession -ComputerName SRV01 -Credential $cred
```

---

## Export & Import

```powershell
# CSV
Get-Process | Export-Csv process.csv -NoTypeInformation
Import-Csv process.csv

# JSON
Get-Process | ConvertTo-Json | Out-File process.json
Get-Content process.json | ConvertFrom-Json

# XML
Get-Process | Export-Clixml process.xml
Import-Clixml process.xml

# HTML
Get-Process | ConvertTo-Html | Out-File report.html
```

---

## Erreurs

```powershell
# Try/Catch
try {
    Get-Item "C:\noexist" -ErrorAction Stop
} catch {
    Write-Host "Erreur: $_"
} finally {
    Write-Host "Fin"
}

# ErrorAction
-ErrorAction SilentlyContinue  # Ignorer
-ErrorAction Stop              # Exception
-ErrorAction Continue          # Afficher, continuer

# Vérification
if (-not $?) { Write-Host "Dernière commande échouée" }
$Error[0]  # Dernière erreur
$Error.Clear()
```

---

**Retour au :** [Programme de la Formation](index.md)
