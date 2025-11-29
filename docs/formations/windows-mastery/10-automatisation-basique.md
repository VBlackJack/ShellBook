---
tags:
  - formation
  - windows-server
  - automatisation
  - scripts
  - wmi
---

# Module 10 : Automatisation Basique

## Objectifs du Module

Ce module couvre les bases de l'automatisation Windows Server :

- Créer des scripts de maintenance
- Utiliser WMI/CIM pour interroger le système
- Planifier des tâches avec Task Scheduler
- Générer des rapports automatisés
- Envoyer des notifications par email

**Durée :** 7 heures

**Niveau :** Administration

---

## 1. Scripts de Maintenance

### 1.1 Nettoyage Système

```powershell
# CleanupSystem.ps1 - Script de maintenance
param(
    [int]$DaysToKeep = 30,
    [string]$LogPath = "C:\Logs\cleanup.log"
)

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Add-Content -Path $LogPath
}

Write-Log "=== Début du nettoyage ==="

# Nettoyer les fichiers temporaires
$tempPaths = @(
    "$env:TEMP",
    "C:\Windows\Temp",
    "C:\Windows\SoftwareDistribution\Download"
)

foreach ($path in $tempPaths) {
    if (Test-Path $path) {
        $sizeBefore = (Get-ChildItem $path -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
        Get-ChildItem $path -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-$DaysToKeep) } |
            Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
        $sizeAfter = (Get-ChildItem $path -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
        $freed = [math]::Round(($sizeBefore - $sizeAfter) / 1MB, 2)
        Write-Log "Nettoyé $path : $freed MB libérés"
    }
}

# Vider la corbeille
Clear-RecycleBin -Force -ErrorAction SilentlyContinue
Write-Log "Corbeille vidée"

# Nettoyer les anciens logs
Get-ChildItem "C:\Logs" -Filter "*.log" |
    Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-90) } |
    Remove-Item -Force

Write-Log "=== Nettoyage terminé ==="
```

### 1.2 Vérification de Santé

```powershell
# HealthCheck.ps1
$report = @()

# CPU
$cpu = (Get-Counter '\Processor(_Total)\% Processor Time').CounterSamples.CookedValue
$report += [PSCustomObject]@{
    Check = "CPU"
    Value = "$([math]::Round($cpu, 2))%"
    Status = if ($cpu -gt 80) { "WARNING" } else { "OK" }
}

# Mémoire
$mem = Get-CimInstance Win32_OperatingSystem
$memUsed = [math]::Round(100 - ($mem.FreePhysicalMemory / $mem.TotalVisibleMemorySize * 100), 2)
$report += [PSCustomObject]@{
    Check = "Memory"
    Value = "$memUsed%"
    Status = if ($memUsed -gt 80) { "WARNING" } else { "OK" }
}

# Disques
Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | ForEach-Object {
    $used = [math]::Round(100 - ($_.FreeSpace / $_.Size * 100), 2)
    $report += [PSCustomObject]@{
        Check = "Disk $($_.DeviceID)"
        Value = "$used%"
        Status = if ($used -gt 85) { "WARNING" } else { "OK" }
    }
}

# Services critiques
$criticalServices = @("DNS", "Netlogon", "W32Time")
foreach ($svc in $criticalServices) {
    $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
    $report += [PSCustomObject]@{
        Check = "Service: $svc"
        Value = $service.Status
        Status = if ($service.Status -eq "Running") { "OK" } else { "CRITICAL" }
    }
}

# Afficher le rapport
$report | Format-Table -AutoSize
```

---

## 2. WMI/CIM

### 2.1 Requêtes CIM

```powershell
# Système d'exploitation
Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, LastBootUpTime

# Processeur
Get-CimInstance Win32_Processor | Select-Object Name, NumberOfCores, MaxClockSpeed

# Mémoire
Get-CimInstance Win32_PhysicalMemory | Select-Object Manufacturer, Capacity, Speed

# Disques
Get-CimInstance Win32_DiskDrive | Select-Object Model, Size, MediaType

# Cartes réseau
Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=$true" |
    Select-Object Description, IPAddress, MACAddress

# Logiciels installés
Get-CimInstance Win32_Product | Select-Object Name, Version, Vendor

# Utilisateurs connectés
Get-CimInstance Win32_LoggedOnUser
```

### 2.2 Requêtes sur Serveurs Distants

```powershell
# CIM sur serveur distant
$servers = @("SRV01", "SRV02", "SRV03")

foreach ($server in $servers) {
    $os = Get-CimInstance Win32_OperatingSystem -ComputerName $server
    [PSCustomObject]@{
        Server = $server
        OS = $os.Caption
        Uptime = (Get-Date) - $os.LastBootUpTime
        FreeRAM = [math]::Round($os.FreePhysicalMemory / 1MB, 2)
    }
}
```

---

## 3. Tâches Planifiées Avancées

### 3.1 Création Complète

```powershell
# Créer une tâche de maintenance hebdomadaire
$taskName = "Weekly-Maintenance"

# Action
$action = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-ExecutionPolicy Bypass -File C:\Scripts\CleanupSystem.ps1"

# Trigger (dimanche à 3h)
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At "03:00"

# Principal (compte SYSTEM)
$principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" `
    -LogonType ServiceAccount -RunLevel Highest

# Settings
$settings = New-ScheduledTaskSettingsSet `
    -ExecutionTimeLimit (New-TimeSpan -Hours 2) `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 5) `
    -StartWhenAvailable `
    -RunOnlyIfNetworkAvailable

# Créer la tâche
Register-ScheduledTask -TaskName $taskName `
    -Action $action `
    -Trigger $trigger `
    -Principal $principal `
    -Settings $settings `
    -Description "Maintenance hebdomadaire du système"
```

### 3.2 Gestion des Tâches

```powershell
# Lister les tâches personnalisées
Get-ScheduledTask | Where-Object { $_.TaskPath -eq "\" }

# Exécuter une tâche
Start-ScheduledTask -TaskName "Weekly-Maintenance"

# Historique d'exécution
Get-ScheduledTaskInfo -TaskName "Weekly-Maintenance"

# Exporter la configuration
Export-ScheduledTask -TaskName "Weekly-Maintenance" | Out-File "C:\Backup\task.xml"

# Importer une tâche
Register-ScheduledTask -Xml (Get-Content "C:\Backup\task.xml" | Out-String) -TaskName "Imported-Task"
```

---

## 4. Rapports et Notifications

### 4.1 Générer un Rapport HTML

```powershell
# ServerReport.ps1
$css = @"
<style>
body { font-family: Arial; }
table { border-collapse: collapse; width: 100%; }
th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
th { background-color: #4CAF50; color: white; }
tr:nth-child(even) { background-color: #f2f2f2; }
.ok { color: green; }
.warning { color: orange; }
.critical { color: red; }
</style>
"@

$body = @"
<h1>Rapport Serveur - $env:COMPUTERNAME</h1>
<p>Généré le: $(Get-Date)</p>
"@

# Informations système
$os = Get-CimInstance Win32_OperatingSystem
$body += $os | Select-Object Caption, Version, LastBootUpTime | ConvertTo-Html -Fragment -PreContent "<h2>Système</h2>"

# Disques
$disks = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" |
    Select-Object DeviceID,
        @{N="SizeGB";E={[math]::Round($_.Size/1GB,2)}},
        @{N="FreeGB";E={[math]::Round($_.FreeSpace/1GB,2)}},
        @{N="UsedPercent";E={[math]::Round(100-($_.FreeSpace/$_.Size*100),2)}}
$body += $disks | ConvertTo-Html -Fragment -PreContent "<h2>Disques</h2>"

# Services
$services = Get-Service | Where-Object StartType -eq "Automatic" |
    Select-Object Name, Status, StartType
$body += $services | ConvertTo-Html -Fragment -PreContent "<h2>Services Automatiques</h2>"

# Créer le rapport
$html = ConvertTo-Html -Head $css -Body $body -Title "Server Report"
$html | Out-File "C:\Reports\ServerReport_$(Get-Date -Format 'yyyyMMdd').html"
```

### 4.2 Envoi d'Email

```powershell
# Envoyer un rapport par email
$params = @{
    SmtpServer = "smtp.corp.local"
    From = "monitoring@corp.local"
    To = "admin@corp.local"
    Subject = "Rapport Serveur - $env:COMPUTERNAME - $(Get-Date -Format 'yyyy-MM-dd')"
    Body = "Veuillez trouver le rapport en pièce jointe."
    Attachments = "C:\Reports\ServerReport_$(Get-Date -Format 'yyyyMMdd').html"
}

Send-MailMessage @params

# Avec authentification
$credential = Get-Credential
Send-MailMessage @params -Credential $credential -UseSsl
```

---

## 5. Exercice Pratique

### Système de Monitoring Complet

```powershell
# DailyMonitoring.ps1
# À planifier quotidiennement

$alertThreshold = @{
    CPU = 80
    Memory = 85
    Disk = 90
}

$alerts = @()

# Vérifier CPU
$cpu = (Get-Counter '\Processor(_Total)\% Processor Time').CounterSamples.CookedValue
if ($cpu -gt $alertThreshold.CPU) {
    $alerts += "CPU: $([math]::Round($cpu,2))%"
}

# Vérifier Mémoire
$mem = Get-CimInstance Win32_OperatingSystem
$memUsed = 100 - ($mem.FreePhysicalMemory / $mem.TotalVisibleMemorySize * 100)
if ($memUsed -gt $alertThreshold.Memory) {
    $alerts += "Memory: $([math]::Round($memUsed,2))%"
}

# Vérifier Disques
Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | ForEach-Object {
    $used = 100 - ($_.FreeSpace / $_.Size * 100)
    if ($used -gt $alertThreshold.Disk) {
        $alerts += "Disk $($_.DeviceID): $([math]::Round($used,2))%"
    }
}

# Envoyer alerte si nécessaire
if ($alerts.Count -gt 0) {
    $body = "Alertes sur $env:COMPUTERNAME:`n" + ($alerts -join "`n")
    Send-MailMessage -To "admin@corp.local" -From "monitor@corp.local" `
        -Subject "ALERT: $env:COMPUTERNAME" -Body $body -SmtpServer "smtp.corp.local"
}
```

---

## Quiz

1. **Quelle cmdlet interroge WMI/CIM ?**
   - [ ] A. Get-WmiObject (legacy)
   - [ ] B. Get-CimInstance (moderne)
   - [ ] C. Les deux

2. **Quelle cmdlet enregistre une tâche planifiée ?**
   - [ ] A. New-ScheduledTask
   - [ ] B. Register-ScheduledTask
   - [ ] C. Add-ScheduledTask

**Réponses :** 1-C (B recommandé), 2-B

---

**Précédent :** [Module 09 : Réseau & DNS/DHCP](09-reseau-dns-dhcp.md)

**Suivant :** [Module 11 : Active Directory Core](11-active-directory-core.md)

---

**Fin du Niveau 2 - Administration**

Vous maîtrisez maintenant l'administration quotidienne de Windows Server. Le Niveau 3 approfondit Active Directory, la sécurité et les services réseau avancés.
