---
tags:
  - windows
  - monitoring
  - prometheus
  - observability
  - metrics
---

# Windows Exporter

Windows Exporter expose les métriques système Windows au format Prometheus. C'est l'équivalent de `node_exporter` pour Linux.

## Vue d'Ensemble

```
ARCHITECTURE WINDOWS EXPORTER
══════════════════════════════════════════════════════════════════════

┌─────────────────────────────────────────────────────────────────┐
│                      SERVEUR WINDOWS                            │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              Windows Exporter (port 9182)                │   │
│  │  ┌─────────┬─────────┬─────────┬─────────┬─────────┐   │   │
│  │  │   CPU   │ Memory  │  Disk   │   Net   │ Service │   │   │
│  │  └────┬────┴────┬────┴────┬────┴────┬────┴────┬────┘   │   │
│  │       │         │         │         │         │         │   │
│  │  ┌────▼─────────▼─────────▼─────────▼─────────▼────┐   │   │
│  │  │        Windows Performance Counters              │   │   │
│  │  │              WMI / PDH / Registry                │   │   │
│  │  └──────────────────────────────────────────────────┘   │   │
│  └─────────────────────────────────────────────────────────┘   │
└───────────────────────────────┬─────────────────────────────────┘
                                │ :9182/metrics
                                ▼
                    ┌───────────────────────┐
                    │      Prometheus       │
                    │    (scrape target)    │
                    └───────────┬───────────┘
                                │
                                ▼
                    ┌───────────────────────┐
                    │       Grafana         │
                    │    (dashboards)       │
                    └───────────────────────┘
```

---

## Installation

### Via MSI (Recommandé)

```powershell
# Télécharger la dernière version
$version = "0.25.1"
$url = "https://github.com/prometheus-community/windows_exporter/releases/download/v$version/windows_exporter-$version-amd64.msi"
Invoke-WebRequest -Uri $url -OutFile "windows_exporter.msi"

# Installation avec collectors par défaut
msiexec /i windows_exporter.msi /qn

# Installation avec collectors spécifiques
msiexec /i windows_exporter.msi /qn ENABLED_COLLECTORS="cpu,memory,logical_disk,net,os,service,iis"

# Avec options supplémentaires
msiexec /i windows_exporter.msi /qn `
    ENABLED_COLLECTORS="cpu,memory,logical_disk,net,os,service" `
    LISTEN_ADDR="0.0.0.0" `
    LISTEN_PORT="9182" `
    METRICS_PATH="/metrics"
```

### Via Chocolatey

```powershell
# Installation simple
choco install prometheus-windows-exporter -y

# Avec paramètres
choco install prometheus-windows-exporter -y --params '"/EnabledCollectors:cpu,memory,logical_disk,net,os,service"'
```

### Via Binaire Standalone

```powershell
# Télécharger l'exe
$version = "0.25.1"
$url = "https://github.com/prometheus-community/windows_exporter/releases/download/v$version/windows_exporter-$version-amd64.exe"
Invoke-WebRequest -Uri $url -OutFile "C:\Tools\windows_exporter.exe"

# Exécuter manuellement (test)
& "C:\Tools\windows_exporter.exe" --collectors.enabled "cpu,memory,logical_disk,net,os,service"

# Créer un service Windows
New-Service -Name "windows_exporter" `
    -BinaryPathName 'C:\Tools\windows_exporter.exe --collectors.enabled "cpu,memory,logical_disk,net,os,service"' `
    -DisplayName "Prometheus Windows Exporter" `
    -StartupType Automatic `
    -Description "Exports Windows metrics for Prometheus"

Start-Service windows_exporter
```

### Vérification

```powershell
# Vérifier le service
Get-Service windows_exporter

# Tester les métriques
Invoke-WebRequest -Uri "http://localhost:9182/metrics" -UseBasicParsing | Select-Object -ExpandProperty Content | Select-String "windows_os"

# Ou via curl
curl http://localhost:9182/metrics
```

---

## Collectors Disponibles

### Collectors Système (Activés par Défaut)

| Collector | Description | Métriques Clés |
|-----------|-------------|----------------|
| `cpu` | Utilisation CPU | `windows_cpu_time_total` |
| `cs` | Computer System | `windows_cs_hostname`, `windows_cs_physical_memory_bytes` |
| `logical_disk` | Disques logiques | `windows_logical_disk_free_bytes`, `windows_logical_disk_read_bytes_total` |
| `memory` | Mémoire RAM | `windows_memory_available_bytes`, `windows_memory_cache_bytes` |
| `net` | Interfaces réseau | `windows_net_bytes_total`, `windows_net_packets_total` |
| `os` | Système d'exploitation | `windows_os_info`, `windows_os_time` |
| `service` | Services Windows | `windows_service_state`, `windows_service_start_mode` |
| `system` | Système global | `windows_system_context_switches_total`, `windows_system_threads` |

### Collectors Optionnels

| Collector | Description | Cas d'Usage |
|-----------|-------------|-------------|
| `ad` | Active Directory | Domain Controllers |
| `adcs` | AD Certificate Services | PKI |
| `adfs` | AD Federation Services | SSO/Fédération |
| `dhcp` | DHCP Server | Serveurs DHCP |
| `dns` | DNS Server | Serveurs DNS |
| `exchange` | Microsoft Exchange | Serveurs mail |
| `hyperv` | Hyper-V | Hôtes de virtualisation |
| `iis` | Internet Information Services | Serveurs web |
| `msmq` | Message Queuing | Applications messaging |
| `mssql` | SQL Server | Bases de données |
| `netframework_clrexceptions` | .NET CLR | Applications .NET |
| `process` | Processus | Monitoring applicatif |
| `scheduled_task` | Tâches planifiées | Automation |
| `tcp` | Connexions TCP | Réseau avancé |
| `terminal_services` | RDS/Terminal Services | Serveurs RDS |
| `textfile` | Fichiers texte custom | Métriques personnalisées |
| `vmware` | VMware Guest | VMs VMware |

---

## Configuration

### Fichier de Configuration YAML

```yaml
# C:\ProgramData\windows_exporter\config.yml
collectors:
  enabled: cpu,memory,logical_disk,net,os,service,iis,mssql

collector:
  service:
    # Services spécifiques à monitorer
    include: "nginx|apache|mysql|mssql.*|iisadmin|w3svc"
    # Ou exclure certains services
    # exclude: "TrustedInstaller|wuauserv"

  process:
    # Processus à monitorer
    include: "nginx|httpd|sqlservr|w3wp"

  iis:
    # Sites IIS spécifiques
    site-include: "Default Web Site|Production.*"

  logical_disk:
    # Disques à inclure (regex)
    include: "C:|D:|E:"

  scheduled_task:
    # Tâches planifiées à monitorer
    include: ".*Backup.*|.*Maintenance.*"

log:
  level: info
  # level: debug  # Pour troubleshooting

telemetry:
  addr: ":9182"
  path: /metrics
  max-requests: 5
```

### Démarrage avec Configuration

```powershell
# Via ligne de commande
& "C:\Tools\windows_exporter.exe" --config.file="C:\ProgramData\windows_exporter\config.yml"

# Modifier le service existant
$servicePath = 'C:\Program Files\windows_exporter\windows_exporter.exe --config.file="C:\ProgramData\windows_exporter\config.yml"'
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\windows_exporter" -Name "ImagePath" -Value $servicePath
Restart-Service windows_exporter
```

---

## Collectors Détaillés

### CPU

```promql
# Utilisation CPU par mode
windows_cpu_time_total{mode="idle"}
windows_cpu_time_total{mode="user"}
windows_cpu_time_total{mode="privileged"}  # kernel
windows_cpu_time_total{mode="interrupt"}
windows_cpu_time_total{mode="dpc"}         # Deferred Procedure Calls

# Calcul du % CPU utilisé (rate sur 5min)
100 - (avg by (instance) (rate(windows_cpu_time_total{mode="idle"}[5m])) * 100)

# CPU par core
sum by (core) (rate(windows_cpu_time_total{mode!="idle"}[5m])) * 100

# Queue du processeur (saturation)
windows_system_processor_queue_length
```

### Mémoire

```promql
# RAM disponible
windows_memory_available_bytes

# RAM totale (depuis cs collector)
windows_cs_physical_memory_bytes

# % mémoire utilisée
100 - (windows_memory_available_bytes / windows_cs_physical_memory_bytes * 100)

# Page file
windows_memory_swap_page_operations_total
windows_os_paging_limit_bytes
windows_os_paging_free_bytes

# Cache et buffers
windows_memory_cache_bytes
windows_memory_pool_nonpaged_bytes
windows_memory_pool_paged_bytes
```

### Disques

```promql
# Espace disque
windows_logical_disk_free_bytes{volume="C:"}
windows_logical_disk_size_bytes{volume="C:"}

# % espace utilisé
100 - (windows_logical_disk_free_bytes / windows_logical_disk_size_bytes * 100)

# IOPS
rate(windows_logical_disk_reads_total[5m])
rate(windows_logical_disk_writes_total[5m])

# Throughput
rate(windows_logical_disk_read_bytes_total[5m])
rate(windows_logical_disk_write_bytes_total[5m])

# Latence
rate(windows_logical_disk_read_seconds_total[5m]) / rate(windows_logical_disk_reads_total[5m])
rate(windows_logical_disk_write_seconds_total[5m]) / rate(windows_logical_disk_writes_total[5m])

# Queue disque (saturation)
windows_logical_disk_current_disk_queue_length
```

### Réseau

```promql
# Bande passante
rate(windows_net_bytes_received_total[5m])
rate(windows_net_bytes_sent_total[5m])

# Paquets
rate(windows_net_packets_received_total[5m])
rate(windows_net_packets_sent_total[5m])

# Erreurs et drops
rate(windows_net_packets_received_errors_total[5m])
rate(windows_net_packets_outbound_errors_total[5m])
rate(windows_net_packets_received_discarded_total[5m])

# Bande passante de l'interface
windows_net_current_bandwidth_bytes
```

### Services Windows

```promql
# État des services (1 = running, 0 = stopped)
windows_service_state{state="running"}

# Services critiques arrêtés
windows_service_state{name=~"wuauserv|bits|w3svc",state="running"} == 0

# Start mode
windows_service_start_mode{start_mode="auto"}

# Processus du service
windows_service_process_id
```

### IIS (Internet Information Services)

```powershell
# Activer le collector IIS
# ENABLED_COLLECTORS inclut "iis"
```

```promql
# Requêtes par seconde
rate(windows_iis_requests_total[5m])

# Par site
rate(windows_iis_requests_total{site="Default Web Site"}[5m])

# Connexions actives
windows_iis_current_connections

# Erreurs HTTP
rate(windows_iis_requests_total{status_code=~"5.."}[5m])

# Latence
rate(windows_iis_request_wait_time_total[5m]) / rate(windows_iis_requests_total[5m])

# Worker processes
windows_iis_worker_current_requests
windows_iis_worker_active_threads
```

### SQL Server

```powershell
# Activer le collector mssql
# Nécessite que SQL Server soit installé
```

```promql
# Connexions utilisateur
windows_mssql_connections{database="mydb"}

# Transactions par seconde
rate(windows_mssql_transactions_total[5m])

# Buffer cache hit ratio
windows_mssql_buffer_cache_hit_ratio

# Latence des pages
windows_mssql_page_io_latch_wait_seconds_total

# Deadlocks
rate(windows_mssql_deadlocks_total[5m])

# Espace base de données
windows_mssql_databases_data_files_size_bytes
windows_mssql_databases_log_files_size_bytes
```

### Active Directory

```powershell
# Sur un Domain Controller uniquement
# Activer le collector "ad"
```

```promql
# Réplication
windows_ad_replication_sync_requests_total
windows_ad_replication_pending_synchronizations

# Authentifications
rate(windows_ad_authentications_total[5m])

# LDAP
windows_ad_ldap_client_sessions
rate(windows_ad_ldap_searches_total[5m])

# Kerberos
rate(windows_ad_kerberos_authentication_requests_total[5m])
```

---

## Intégration Prometheus

### Configuration Prometheus

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'windows'
    static_configs:
      - targets:
        - 'windows-server-01:9182'
        - 'windows-server-02:9182'
        - 'windows-dc-01:9182'
    relabel_configs:
      - source_labels: [__address__]
        target_label: instance
        regex: '(.+):\d+'
        replacement: '${1}'

  # Windows avec découverte DNS
  - job_name: 'windows-dns-discovery'
    dns_sd_configs:
      - names:
        - '_prometheus._tcp.corp.local'
        type: 'SRV'
    relabel_configs:
      - source_labels: [__meta_dns_name]
        target_label: datacenter

  # Windows avec file-based discovery
  - job_name: 'windows-file-discovery'
    file_sd_configs:
      - files:
        - '/etc/prometheus/targets/windows/*.json'
        refresh_interval: 5m
```

### Fichier de Découverte

```json
// /etc/prometheus/targets/windows/servers.json
[
  {
    "targets": ["win-web-01:9182", "win-web-02:9182"],
    "labels": {
      "env": "production",
      "role": "webserver",
      "os": "windows"
    }
  },
  {
    "targets": ["win-db-01:9182"],
    "labels": {
      "env": "production",
      "role": "database",
      "os": "windows"
    }
  }
]
```

---

## Alertes Prometheus

### Règles d'Alerte Windows

```yaml
# /etc/prometheus/rules/windows.yml
groups:
  - name: windows_alerts
    rules:
      # CPU élevé
      - alert: WindowsHighCPU
        expr: 100 - (avg by (instance) (rate(windows_cpu_time_total{mode="idle"}[5m])) * 100) > 85
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "High CPU usage on {{ $labels.instance }}"
          description: "CPU usage is above 85% (current: {{ $value | printf \"%.1f\" }}%)"

      # Mémoire faible
      - alert: WindowsLowMemory
        expr: (windows_memory_available_bytes / windows_cs_physical_memory_bytes * 100) < 10
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Low memory on {{ $labels.instance }}"
          description: "Available memory is below 10% (current: {{ $value | printf \"%.1f\" }}%)"

      # Disque plein
      - alert: WindowsDiskSpaceLow
        expr: (windows_logical_disk_free_bytes / windows_logical_disk_size_bytes * 100) < 15
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Low disk space on {{ $labels.instance }} volume {{ $labels.volume }}"
          description: "Free space is below 15% (current: {{ $value | printf \"%.1f\" }}%)"

      - alert: WindowsDiskSpaceCritical
        expr: (windows_logical_disk_free_bytes / windows_logical_disk_size_bytes * 100) < 5
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "Critical disk space on {{ $labels.instance }} volume {{ $labels.volume }}"

      # Service arrêté
      - alert: WindowsServiceDown
        expr: windows_service_state{name=~"w3svc|mssqlserver|nginx",state="running"} == 0
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "Windows service {{ $labels.name }} is down on {{ $labels.instance }}"

      # Exporter down
      - alert: WindowsExporterDown
        expr: up{job="windows"} == 0
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Windows exporter is down on {{ $labels.instance }}"

      # Uptime faible (redémarrage récent)
      - alert: WindowsRecentReboot
        expr: windows_system_system_up_time < 600
        for: 0m
        labels:
          severity: info
        annotations:
          summary: "Windows server {{ $labels.instance }} was recently rebooted"

      # Queue disque élevée
      - alert: WindowsDiskQueueHigh
        expr: windows_logical_disk_current_disk_queue_length > 10
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High disk queue on {{ $labels.instance }} volume {{ $labels.volume }}"

      # Erreurs réseau
      - alert: WindowsNetworkErrors
        expr: rate(windows_net_packets_received_errors_total[5m]) > 100
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Network errors detected on {{ $labels.instance }}"
```

---

## Dashboards Grafana

### Dashboard ID Recommandés

| Dashboard | Grafana ID | Description |
|-----------|------------|-------------|
| Windows Node | 14694 | Vue d'ensemble complète |
| Windows Server | 2129 | Classique et complet |
| Windows IIS | 12112 | Métriques IIS détaillées |
| Windows AD | 14950 | Active Directory |
| Windows SQL Server | 9386 | SQL Server metrics |

### Importer un Dashboard

```bash
# Via API Grafana
curl -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $GRAFANA_TOKEN" \
  -d '{
    "dashboard": {"id": null, "uid": null, "title": "Windows Nodes"},
    "folderId": 0,
    "overwrite": true,
    "inputs": [{"name": "DS_PROMETHEUS", "type": "datasource", "value": "Prometheus"}]
  }' \
  "http://grafana:3000/api/dashboards/import"
```

### Panels Personnalisés

```json
// Panel CPU utilization
{
  "title": "CPU Utilization",
  "type": "gauge",
  "targets": [
    {
      "expr": "100 - (avg by (instance) (rate(windows_cpu_time_total{mode=\"idle\",instance=\"$instance\"}[5m])) * 100)",
      "legendFormat": "CPU %"
    }
  ],
  "fieldConfig": {
    "defaults": {
      "thresholds": {
        "steps": [
          {"color": "green", "value": null},
          {"color": "yellow", "value": 70},
          {"color": "red", "value": 85}
        ]
      },
      "unit": "percent",
      "max": 100
    }
  }
}
```

---

## Textfile Collector

### Métriques Personnalisées

```powershell
# Créer le répertoire pour les métriques custom
$metricsDir = "C:\ProgramData\windows_exporter\textfile_inputs"
New-Item -ItemType Directory -Path $metricsDir -Force

# Script pour métriques applicatives
# C:\Scripts\custom-metrics.ps1

$outputFile = "C:\ProgramData\windows_exporter\textfile_inputs\custom.prom"

# Exemple : nombre de fichiers dans un dossier
$fileCount = (Get-ChildItem "D:\Data\Incoming" -File).Count
"app_incoming_files_total $fileCount" | Out-File $outputFile -Encoding ASCII

# Exemple : âge du plus vieux fichier
$oldestFile = Get-ChildItem "D:\Data\Incoming" -File |
    Sort-Object LastWriteTime |
    Select-Object -First 1
if ($oldestFile) {
    $ageSeconds = [int]((Get-Date) - $oldestFile.LastWriteTime).TotalSeconds
    "app_oldest_file_age_seconds $ageSeconds" | Out-File $outputFile -Append -Encoding ASCII
}

# Exemple : résultat d'une requête SQL
$connectionString = "Server=localhost;Database=mydb;Integrated Security=True"
$query = "SELECT COUNT(*) FROM Orders WHERE Status = 'Pending'"
$result = Invoke-Sqlcmd -ConnectionString $connectionString -Query $query
"app_pending_orders_total $($result.Column1)" | Out-File $outputFile -Append -Encoding ASCII

# Timestamp de la dernière mise à jour
$timestamp = [int][double]::Parse((Get-Date -UFormat %s))
"app_metrics_last_update_timestamp $timestamp" | Out-File $outputFile -Append -Encoding ASCII
```

```powershell
# Planifier l'exécution
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File C:\Scripts\custom-metrics.ps1"
$trigger = New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Minutes 1) -Once -At (Get-Date)
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount
Register-ScheduledTask -TaskName "Custom Prometheus Metrics" -Action $action -Trigger $trigger -Principal $principal
```

### Activer le Collector Textfile

```powershell
# Via ligne de commande
& "windows_exporter.exe" `
    --collectors.enabled "cpu,memory,logical_disk,net,os,service,textfile" `
    --collector.textfile.directory "C:\ProgramData\windows_exporter\textfile_inputs"

# Ou dans la config YAML
# collector:
#   textfile:
#     directory: C:\ProgramData\windows_exporter\textfile_inputs
```

---

## Déploiement à Grande Échelle

### GPO pour Déploiement

```powershell
# Script de déploiement via GPO
# À placer dans SYSVOL\domain\scripts\

$installerPath = "\\domain.local\SYSVOL\domain.local\Software\windows_exporter.msi"
$installedVersion = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" |
    Where-Object { $_.DisplayName -like "*windows_exporter*" }).DisplayVersion

$targetVersion = "0.25.1"

if ($installedVersion -ne $targetVersion) {
    Start-Process msiexec.exe -ArgumentList "/i `"$installerPath`" /qn ENABLED_COLLECTORS=`"cpu,memory,logical_disk,net,os,service`"" -Wait
}

# Configurer le firewall
New-NetFirewallRule -DisplayName "Windows Exporter" `
    -Direction Inbound -Protocol TCP -LocalPort 9182 `
    -Action Allow -Profile Domain
```

### Ansible Playbook

```yaml
# deploy_windows_exporter.yml
---
- name: Deploy Windows Exporter
  hosts: windows_servers
  gather_facts: yes
  vars:
    exporter_version: "0.25.1"
    exporter_collectors: "cpu,memory,logical_disk,net,os,service"
    exporter_port: 9182

  tasks:
    - name: Create temp directory
      win_file:
        path: C:\Temp\exporter
        state: directory

    - name: Download Windows Exporter
      win_get_url:
        url: "https://github.com/prometheus-community/windows_exporter/releases/download/v{{ exporter_version }}/windows_exporter-{{ exporter_version }}-amd64.msi"
        dest: C:\Temp\exporter\windows_exporter.msi

    - name: Install Windows Exporter
      win_package:
        path: C:\Temp\exporter\windows_exporter.msi
        arguments: 'ENABLED_COLLECTORS="{{ exporter_collectors }}" LISTEN_PORT="{{ exporter_port }}"'
        state: present

    - name: Ensure service is running
      win_service:
        name: windows_exporter
        state: started
        start_mode: auto

    - name: Configure firewall rule
      win_firewall_rule:
        name: Windows Exporter
        localport: "{{ exporter_port }}"
        action: allow
        direction: in
        protocol: tcp
        state: present
        enabled: yes
```

### DSC Configuration

```powershell
Configuration WindowsExporterConfig {
    param (
        [string]$Version = "0.25.1",
        [string]$Collectors = "cpu,memory,logical_disk,net,os,service"
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName xPSDesiredStateConfiguration

    Node $AllNodes.NodeName {

        File ExporterDirectory {
            Ensure = "Present"
            Type = "Directory"
            DestinationPath = "C:\Program Files\windows_exporter"
        }

        xRemoteFile DownloadExporter {
            Uri = "https://github.com/prometheus-community/windows_exporter/releases/download/v$Version/windows_exporter-$Version-amd64.exe"
            DestinationPath = "C:\Program Files\windows_exporter\windows_exporter.exe"
            DependsOn = "[File]ExporterDirectory"
        }

        xService ExporterService {
            Name = "windows_exporter"
            State = "Running"
            StartupType = "Automatic"
            Path = "C:\Program Files\windows_exporter\windows_exporter.exe --collectors.enabled `"$Collectors`""
            DependsOn = "[xRemoteFile]DownloadExporter"
        }

        xFirewall ExporterFirewall {
            Name = "Windows Exporter"
            Ensure = "Present"
            Enabled = "True"
            Direction = "Inbound"
            LocalPort = "9182"
            Protocol = "TCP"
            Action = "Allow"
        }
    }
}
```

---

## Troubleshooting

### Diagnostics de Base

```powershell
# Vérifier le service
Get-Service windows_exporter | Select-Object Name, Status, StartType

# Vérifier le port
Test-NetConnection -ComputerName localhost -Port 9182
netstat -ano | findstr "9182"

# Logs du service
Get-EventLog -LogName Application -Source windows_exporter -Newest 20

# Tester les métriques
Invoke-RestMethod "http://localhost:9182/metrics" | Select-String "windows_os_info"

# Vérifier les collectors actifs
Invoke-RestMethod "http://localhost:9182/metrics" | Select-String "# HELP windows_"

# Debug mode
& "C:\Program Files\windows_exporter\windows_exporter.exe" --log.level=debug
```

### Problèmes Courants

```powershell
# Erreur: "Access Denied" sur certains collectors
# → Exécuter en tant que SYSTEM ou compte avec privilèges

# Le collector IIS ne remonte pas de métriques
# → Vérifier que IIS Management Scripts sont installés
Install-WindowsFeature Web-Scripting-Tools

# Métriques SQL Server manquantes
# → Vérifier les permissions sur SQL Server
# Le compte du service doit avoir VIEW SERVER STATE

# Collectors AD non fonctionnels
# → Uniquement sur les Domain Controllers
# → Vérifier que le service tourne en tant que SYSTEM

# Métriques réseau incomplètes
# → Certaines interfaces virtuelles peuvent poser problème
# → Filtrer avec collector.net.nic-include
```

### Performance

```powershell
# Si l'exporter consomme trop de ressources
# Réduire les collectors activés
# Augmenter l'intervalle de scrape Prometheus

# Exclure les disques non pertinents
--collector.logical_disk.volume-include="C:|D:"

# Limiter les services monitorés
--collector.service.include="w3svc|mssql.*|nginx"
```

---

## Bonnes Pratiques

```yaml
Checklist Windows Exporter:
  Installation:
    - [ ] Version à jour depuis GitHub releases
    - [ ] Installation via MSI pour les mises à jour faciles
    - [ ] Collectors adaptés au rôle du serveur
    - [ ] Firewall configuré (port 9182)

  Configuration:
    - [ ] Filtrer les services/disques pertinents
    - [ ] Configurer le textfile collector si besoin
    - [ ] Log level approprié (info en prod)
    - [ ] Tester les métriques après install

  Sécurité:
    - [ ] Accès restreint au port 9182 (firewall)
    - [ ] TLS si exposition externe (reverse proxy)
    - [ ] Compte de service avec privilèges minimaux
    - [ ] Pas d'exposition directe sur Internet

  Monitoring:
    - [ ] Alertes sur exporter down
    - [ ] Dashboard Grafana configuré
    - [ ] Alertes sur métriques critiques
    - [ ] Retention Prometheus adaptée

  Maintenance:
    - [ ] Mise à jour régulière
    - [ ] Monitoring des logs d'erreur
    - [ ] Documentation des collectors utilisés
```

---

**Voir aussi :**

- [Observability Stack](../devops/observability-stack.md) - Prometheus & Grafana
- [Observability Advanced](../devops/observability-advanced.md) - Métriques avancées
- [Performance Monitoring](performance-monitoring.md) - Perfmon Windows
- [Event Logs](event-logs.md) - Logs Windows
