---
tags:
  - windows
  - performance
  - monitoring
  - troubleshooting
---

# Performance Monitoring Windows

Outils et techniques de monitoring des performances Windows.

## Outils Intégrés

```text
OUTILS DE PERFORMANCE WINDOWS
══════════════════════════════════════════════════════════

Task Manager      Monitoring temps réel rapide
Resource Monitor  Détails CPU, mémoire, disque, réseau
Performance Monitor (perfmon)  Compteurs détaillés, historique
Reliability Monitor   Historique de stabilité système
Windows Admin Center  Interface web moderne
```

---

## Performance Monitor (Perfmon)

### Compteurs Essentiels

```powershell
# Lister les compteurs disponibles
Get-Counter -ListSet * | Select-Object CounterSetName

# Compteurs CPU
Get-Counter '\Processor(_Total)\% Processor Time'
Get-Counter '\System\Processor Queue Length'

# Compteurs Mémoire
Get-Counter '\Memory\Available MBytes'
Get-Counter '\Memory\Pages/sec'
Get-Counter '\Memory\% Committed Bytes In Use'

# Compteurs Disque
Get-Counter '\PhysicalDisk(_Total)\% Disk Time'
Get-Counter '\PhysicalDisk(_Total)\Avg. Disk Queue Length'
Get-Counter '\PhysicalDisk(_Total)\Disk Reads/sec'
Get-Counter '\PhysicalDisk(_Total)\Disk Writes/sec'

# Compteurs Réseau
Get-Counter '\Network Interface(*)\Bytes Total/sec'
Get-Counter '\TCPv4\Connections Established'

# Monitoring continu
Get-Counter -Counter "\Processor(_Total)\% Processor Time","\Memory\Available MBytes" -Continuous -SampleInterval 5
```

### Data Collector Sets

```powershell
# Créer un Data Collector Set
$name = "Server-Baseline"
logman create counter $name -c `
    "\Processor(_Total)\% Processor Time" `
    "\Memory\Available MBytes" `
    "\PhysicalDisk(_Total)\% Disk Time" `
    "\Network Interface(*)\Bytes Total/sec" `
    -si 15 `
    -f bincirc `
    -max 500 `
    -o "C:\PerfLogs\$name"

# Démarrer la collecte
logman start $name

# Arrêter
logman stop $name

# Voir les Data Collector Sets
logman query

# Supprimer
logman delete $name
```

### Alertes Performance

```powershell
# Créer une alerte (via perfmon GUI ou)
# Task Scheduler + script de monitoring

# Script d'alerte simple
$threshold = 90
$cpu = (Get-Counter '\Processor(_Total)\% Processor Time').CounterSamples.CookedValue

if ($cpu -gt $threshold) {
    Send-MailMessage -To "admin@corp.local" -From "alert@corp.local" `
        -Subject "CPU Alert: $([math]::Round($cpu))%" `
        -Body "CPU usage exceeded $threshold% on $env:COMPUTERNAME" `
        -SmtpServer "smtp.corp.local"
}
```

---

## Resource Monitor

```powershell
# Lancer Resource Monitor
resmon

# Informations disponibles :
# - CPU : Processus, services, handles
# - Memory : Working set, shareable, private
# - Disk : I/O par processus, temps de réponse
# - Network : Connexions TCP, ports, processus
```

---

## PowerShell Monitoring

### CPU et Processus

```powershell
# Top processus CPU
Get-Process | Sort-Object CPU -Descending | Select-Object -First 10 Name, CPU, WorkingSet64

# Processus par utilisation mémoire
Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 10 Name, @{N='MemoryMB';E={[math]::Round($_.WorkingSet64/1MB)}}

# Handles et threads
Get-Process | Sort-Object Handles -Descending | Select-Object -First 10 Name, Handles, Threads
```

### Mémoire

```powershell
# Informations mémoire système
Get-CimInstance Win32_OperatingSystem | Select-Object `
    @{N='TotalMemoryGB';E={[math]::Round($_.TotalVisibleMemorySize/1MB,2)}},
    @{N='FreeMemoryGB';E={[math]::Round($_.FreePhysicalMemory/1MB,2)}},
    @{N='UsedPercent';E={[math]::Round((($_.TotalVisibleMemorySize - $_.FreePhysicalMemory)/$_.TotalVisibleMemorySize)*100)}}

# Détail mémoire
systeminfo | findstr /i "memory"
```

### Disque

```powershell
# Espace disque
Get-PSDrive -PSProvider FileSystem | Select-Object Name, @{N='UsedGB';E={[math]::Round($_.Used/1GB)}}, @{N='FreeGB';E={[math]::Round($_.Free/1GB)}}

# Performance disque
Get-Counter '\PhysicalDisk(*)\Avg. Disk sec/Read','\PhysicalDisk(*)\Avg. Disk sec/Write'

# IOPS
Get-Counter '\PhysicalDisk(_Total)\Disk Reads/sec','\PhysicalDisk(_Total)\Disk Writes/sec' -SampleInterval 5 -MaxSamples 12 |
    ForEach-Object { $_.CounterSamples | Select-Object Path, CookedValue }
```

### Réseau

```powershell
# Connexions réseau
Get-NetTCPConnection | Group-Object State | Select-Object Name, Count

# Connexions établies par processus
Get-NetTCPConnection -State Established |
    Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess,
    @{N='Process';E={(Get-Process -Id $_.OwningProcess).Name}}

# Bande passante par interface
Get-NetAdapterStatistics | Select-Object Name, ReceivedBytes, SentBytes
```

---

## Diagnostic Automatisé

### Script de Health Check

```powershell
function Get-SystemHealth {
    $health = [PSCustomObject]@{
        Timestamp = Get-Date
        ComputerName = $env:COMPUTERNAME
        CPU_Percent = [math]::Round((Get-Counter '\Processor(_Total)\% Processor Time').CounterSamples.CookedValue, 2)
        Memory_AvailableGB = [math]::Round((Get-Counter '\Memory\Available MBytes').CounterSamples.CookedValue / 1024, 2)
        Memory_UsedPercent = [math]::Round((Get-CimInstance Win32_OperatingSystem | ForEach-Object { (($_.TotalVisibleMemorySize - $_.FreePhysicalMemory) / $_.TotalVisibleMemorySize) * 100 }), 2)
        Disk_C_FreeGB = [math]::Round((Get-PSDrive C).Free / 1GB, 2)
        Uptime_Days = [math]::Round(((Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime).TotalDays, 2)
    }
    return $health
}

# Utilisation
Get-SystemHealth | Format-List
```

### Baseline et Alertes

```powershell
# Collecter une baseline
$baseline = 1..60 | ForEach-Object {
    Start-Sleep -Seconds 60
    Get-SystemHealth
}
$baseline | Export-Csv "C:\Baseline\system-baseline.csv" -NoTypeInformation

# Comparer avec la baseline
$current = Get-SystemHealth
$avgBaseline = Import-Csv "C:\Baseline\system-baseline.csv" | Measure-Object CPU_Percent -Average

if ($current.CPU_Percent -gt ($avgBaseline.Average * 1.5)) {
    Write-Warning "CPU 50% au-dessus de la baseline normale"
}
```

---

## Windows Admin Center

```powershell
# Installation (sur Windows Server)
# Télécharger depuis Microsoft, puis :
msiexec /i WindowsAdminCenter.msi /qn /L*v log.txt SME_PORT=443 SSL_CERTIFICATE_OPTION=generate

# Fonctionnalités :
# - Dashboard serveurs
# - Monitoring temps réel
# - Gestion à distance
# - Intégration Azure
```

---

## Bonnes Pratiques

```yaml
Checklist Monitoring:
  Baseline:
    - [ ] Collecter metrics normaux (1 semaine)
    - [ ] Documenter les seuils acceptables
    - [ ] Identifier les heures de pointe

  Alertes:
    - [ ] CPU > 90% pendant 5 min
    - [ ] Mémoire disponible < 10%
    - [ ] Disque < 20% libre
    - [ ] Queue disque > 2

  Collecte:
    - [ ] Data Collector Set configuré
    - [ ] Rétention définie
    - [ ] Centralisation des données
```

---

**Voir aussi :**

- [Event Logs](event-logs.md) - Journaux d'événements
- [Disk Management](disk-management.md) - Gestion des disques
- [Network Troubleshooting](network-troubleshooting.md) - Diagnostic réseau
