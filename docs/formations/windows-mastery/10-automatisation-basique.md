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

## Exercice : À Vous de Jouer

!!! example "Mise en Pratique"
    **Objectif** : Créer un système de rapports automatisés multi-serveurs

    **Contexte** : Vous devez créer un système qui génère quotidiennement un rapport HTML sur l'état de santé de 3 serveurs (CPU, mémoire, disques, services) et l'envoie par email aux administrateurs.

    **Tâches à réaliser** :

    1. Créer un script qui interroge plusieurs serveurs via CIM/WMI
    2. Collecter les métriques : CPU, RAM, espace disque, services critiques
    3. Générer un rapport HTML avec CSS intégré
    4. Créer une tâche planifiée quotidienne à 6h00
    5. Configurer l'envoi du rapport par email
    6. Implémenter des alertes pour les valeurs critiques

    **Critères de validation** :

    - [ ] Le script interroge correctement plusieurs serveurs
    - [ ] Toutes les métriques sont collectées
    - [ ] Le rapport HTML est bien formaté avec code couleur
    - [ ] La tâche planifiée s'exécute quotidiennement
    - [ ] L'email est envoyé avec le rapport en pièce jointe
    - [ ] Les alertes sont générées pour les seuils dépassés

??? quote "Solution"
    ```powershell
    # Generate-ServerReport.ps1
    # Génération de rapport multi-serveurs

    param(
        [string[]]$Servers = @("localhost"),
        [string]$ReportPath = "C:\Reports\ServerHealth_$(Get-Date -Format 'yyyyMMdd').html",
        [string]$SmtpServer = "smtp.corp.local",
        [string]$EmailTo = "admin@corp.local",
        [string]$EmailFrom = "monitoring@corp.local"
    )

    # CSS pour le rapport
    $css = @"
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        h1 { color: #333; border-bottom: 3px solid #0066cc; padding-bottom: 10px; }
        h2 { color: #0066cc; margin-top: 30px; }
        table { border-collapse: collapse; width: 100%; margin: 20px 0; background-color: white; }
        th { background-color: #0066cc; color: white; padding: 12px; text-align: left; }
        td { padding: 10px; border-bottom: 1px solid #ddd; }
        tr:hover { background-color: #f5f5f5; }
        .ok { color: green; font-weight: bold; }
        .warning { color: orange; font-weight: bold; }
        .critical { color: red; font-weight: bold; }
        .info { background-color: #e7f3ff; padding: 10px; margin: 10px 0; border-left: 4px solid #0066cc; }
    </style>
"@

    $alerts = @()
    $htmlBody = ""

    foreach ($server in $Servers) {
        Write-Host "Collecte des données de $server..." -ForegroundColor Yellow

        try {
            # Informations système
            $os = Get-CimInstance Win32_OperatingSystem -ComputerName $server
            $cs = Get-CimInstance Win32_ComputerSystem -ComputerName $server

            # CPU
            $cpu = (Get-Counter "\\$server\Processor(_Total)\% Processor Time" -ErrorAction SilentlyContinue).CounterSamples.CookedValue
            $cpuStatus = if ($cpu -gt 80) {
                $alerts += "CPU élevé sur $server : $([math]::Round($cpu,2))%"
                "critical"
            } elseif ($cpu -gt 60) { "warning" } else { "ok" }

            # Mémoire
            $memUsed = [math]::Round(100 - ($os.FreePhysicalMemory / $os.TotalVisibleMemorySize * 100), 2)
            $memStatus = if ($memUsed -gt 85) {
                $alerts += "Mémoire élevée sur $server : $memUsed%"
                "critical"
            } elseif ($memUsed -gt 70) { "warning" } else { "ok" }

            # Disques
            $disks = Get-CimInstance Win32_LogicalDisk -ComputerName $server -Filter "DriveType=3" | ForEach-Object {
                $usedPercent = [math]::Round(100 - ($_.FreeSpace / $_.Size * 100), 2)
                $status = if ($usedPercent -gt 90) {
                    $alerts += "Disque $($_.DeviceID) plein sur $server : $usedPercent%"
                    "critical"
                } elseif ($usedPercent -gt 80) { "warning" } else { "ok" }

                [PSCustomObject]@{
                    Disque = $_.DeviceID
                    TailleGB = [math]::Round($_.Size/1GB, 2)
                    LibreGB = [math]::Round($_.FreeSpace/1GB, 2)
                    Utilise = "$usedPercent%"
                    Statut = "<span class='$status'>$usedPercent%</span>"
                }
            }

            # Services critiques
            $services = @("DNS", "Netlogon", "W32Time") | ForEach-Object {
                $svc = Get-Service -Name $_ -ComputerName $server -ErrorAction SilentlyContinue
                if ($svc) {
                    $status = if ($svc.Status -eq "Running") { "ok" } else {
                        $alerts += "Service $_ arrêté sur $server"
                        "critical"
                    }
                    [PSCustomObject]@{
                        Service = $svc.Name
                        Statut = "<span class='$status'>$($svc.Status)</span>"
                        Demarrage = $svc.StartType
                    }
                }
            }

            # Générer le HTML pour ce serveur
            $htmlBody += @"
            <h2>$server</h2>
            <div class="info">
                <strong>OS:</strong> $($os.Caption) | <strong>Uptime:</strong> $([math]::Round(((Get-Date) - $os.LastBootUpTime).TotalDays, 2)) jours |
                <strong>CPU:</strong> <span class="$cpuStatus">$([math]::Round($cpu,2))%</span> |
                <strong>RAM:</strong> <span class="$memStatus">$memUsed%</span>
            </div>

            <h3>Disques</h3>
            $(($disks | ConvertTo-Html -Fragment) -replace '<table>', '<table>' -replace '<td>','<td>' -replace '<th>','<th>')

            <h3>Services Critiques</h3>
            $(($services | ConvertTo-Html -Fragment) -replace '<table>', '<table>')
"@

        } catch {
            $htmlBody += "<h2>$server</h2><p class='critical'>Erreur lors de la collecte: $($_.Exception.Message)</p>"
            $alerts += "Erreur de collecte sur $server"
        }
    }

    # Assembler le rapport complet
    $htmlReport = @"
    <!DOCTYPE html>
    <html>
    <head>
        <title>Rapport de Santé Serveurs</title>
        $css
    </head>
    <body>
        <h1>Rapport de Santé des Serveurs</h1>
        <p>Généré le $(Get-Date -Format "dd/MM/yyyy à HH:mm")</p>

        $(if ($alerts.Count -gt 0) {
            "<div class='info'><strong>Alertes ($($alerts.Count)):</strong><br>" + ($alerts -join "<br>") + "</div>"
        } else {
            "<div class='info' style='border-left-color: green;'><strong>Aucune alerte - Tous les systèmes fonctionnent normalement</strong></div>"
        })

        $htmlBody
    </body>
    </html>
"@

    # Sauvegarder le rapport
    $reportDir = Split-Path $ReportPath -Parent
    if (-not (Test-Path $reportDir)) {
        New-Item -Path $reportDir -ItemType Directory -Force
    }
    $htmlReport | Out-File $ReportPath -Encoding UTF8

    Write-Host "`nRapport généré: $ReportPath" -ForegroundColor Green
    Write-Host "Alertes détectées: $($alerts.Count)" -ForegroundColor $(if ($alerts.Count -gt 0) { "Red" } else { "Green" })

    # Envoi par email
    $emailParams = @{
        To = $EmailTo
        From = $EmailFrom
        Subject = "Rapport Serveurs - $(Get-Date -Format 'dd/MM/yyyy') - $($alerts.Count) alerte(s)"
        Body = if ($alerts.Count -gt 0) { "Attention: $($alerts.Count) alerte(s) détectée(s). Voir le rapport en pièce jointe." } else { "Tous les systèmes fonctionnent normalement." }
        Attachments = $ReportPath
        SmtpServer = $SmtpServer
    }

    Send-MailMessage @emailParams
    Write-Host "Email envoyé à $EmailTo" -ForegroundColor Green

    # Tâche planifiée
    $taskScript = @"
    \$task = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File C:\Scripts\Generate-ServerReport.ps1"
    \$trigger = New-ScheduledTaskTrigger -Daily -At "06:00"
    \$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
    Register-ScheduledTask -TaskName "Daily-ServerReport" -Action \$task -Trigger \$trigger -Principal \$principal
"@
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
