---
tags:
  - windows
  - wmi
  - cim
  - powershell
  - scripting
---

# WMI et CIM

Requêtes et gestion système avec WMI (Windows Management Instrumentation) et CIM (Common Information Model).

## Concepts

```text
ARCHITECTURE WMI/CIM
══════════════════════════════════════════════════════════

Application / Script PowerShell
            │
            ▼
┌─────────────────────────────────────────────────────────┐
│                    WMI Service                          │
│                  (winmgmt.exe)                          │
├─────────────────────────────────────────────────────────┤
│                   CIM Repository                        │
│              (C:\Windows\System32\wbem)                 │
├─────────────────────────────────────────────────────────┤
│                    Providers                            │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐             │
│  │  Win32    │ │   MSFT    │ │  Custom   │             │
│  │ Provider  │ │ Provider  │ │ Providers │             │
│  └───────────┘ └───────────┘ └───────────┘             │
└─────────────────────────────────────────────────────────┘
            │
            ▼
      Système / Hardware

Namespaces courants :
• root\cimv2         Classes Win32_* (OS, hardware, processes)
• root\Microsoft\Windows  Classes MSFT_* modernes
• root\SecurityCenter2   Antivirus, firewall status
• root\StandardCimv2    Réseau moderne
```

### WMI vs CIM Cmdlets

```text
COMPARAISON WMI ET CIM
══════════════════════════════════════════════════════════

WMI Cmdlets (Legacy):            CIM Cmdlets (Moderne):
Get-WmiObject                    Get-CimInstance
Set-WmiInstance                  Set-CimInstance
Invoke-WmiMethod                 Invoke-CimMethod
Remove-WmiObject                 Remove-CimInstance
                                 New-CimInstance
                                 Get-CimClass

Différences clés :
• CIM utilise WS-Man (WinRM) par défaut
• WMI utilise DCOM (ports RPC)
• CIM plus performant et moderne
• CIM recommandé pour nouveau code
```

---

## Requêtes de Base

### Get-CimInstance (Recommandé)

```powershell
# Informations système
Get-CimInstance -ClassName Win32_OperatingSystem

# Sélectionner des propriétés
Get-CimInstance -ClassName Win32_OperatingSystem |
    Select-Object Caption, Version, BuildNumber, OSArchitecture

# Filtrer avec -Filter (WQL)
Get-CimInstance -ClassName Win32_Process -Filter "Name = 'notepad.exe'"

# Filtrer avec -Query (WQL complet)
Get-CimInstance -Query "SELECT * FROM Win32_Service WHERE State = 'Running'"

# Sur une machine distante
Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName Server01

# Avec credentials
$cred = Get-Credential
$session = New-CimSession -ComputerName Server01 -Credential $cred
Get-CimInstance -ClassName Win32_OperatingSystem -CimSession $session
```

### Get-WmiObject (Legacy)

```powershell
# Même syntaxe mais avec DCOM
Get-WmiObject -Class Win32_OperatingSystem
Get-WmiObject -Class Win32_Process -Filter "Name = 'notepad.exe'"
Get-WmiObject -Class Win32_Service -ComputerName Server01
```

---

## Classes Essentielles

### Système d'Exploitation

```powershell
# OS Info
Get-CimInstance Win32_OperatingSystem |
    Select-Object Caption, Version, BuildNumber, LastBootUpTime,
    @{N='UptimeDays';E={((Get-Date) - $_.LastBootUpTime).Days}}

# Computer System
Get-CimInstance Win32_ComputerSystem |
    Select-Object Name, Domain, Manufacturer, Model,
    @{N='MemoryGB';E={[math]::Round($_.TotalPhysicalMemory/1GB)}}

# BIOS
Get-CimInstance Win32_BIOS |
    Select-Object Manufacturer, Name, SerialNumber, SMBIOSBIOSVersion

# Time Zone
Get-CimInstance Win32_TimeZone | Select-Object Caption, Bias
```

### Processus et Services

```powershell
# Processus
Get-CimInstance Win32_Process |
    Select-Object ProcessId, Name, CommandLine, CreationDate |
    Sort-Object Name

# Top processus par mémoire
Get-CimInstance Win32_Process |
    Select-Object Name, ProcessId, @{N='MemoryMB';E={[math]::Round($_.WorkingSetSize/1MB)}} |
    Sort-Object MemoryMB -Descending |
    Select-Object -First 10

# Services
Get-CimInstance Win32_Service |
    Select-Object Name, DisplayName, State, StartMode |
    Where-Object State -eq "Running"

# Service spécifique
Get-CimInstance Win32_Service -Filter "Name = 'WinRM'" |
    Select-Object Name, State, StartMode, PathName, StartName
```

### Hardware

```powershell
# Processeur
Get-CimInstance Win32_Processor |
    Select-Object Name, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed

# Mémoire
Get-CimInstance Win32_PhysicalMemory |
    Select-Object BankLabel, Capacity, Speed, Manufacturer |
    ForEach-Object { $_.Capacity = [math]::Round($_.Capacity/1GB); $_ }

# Disques physiques
Get-CimInstance Win32_DiskDrive |
    Select-Object Model, @{N='SizeGB';E={[math]::Round($_.Size/1GB)}}, InterfaceType

# Volumes logiques
Get-CimInstance Win32_LogicalDisk -Filter "DriveType = 3" |
    Select-Object DeviceID, FileSystem,
    @{N='SizeGB';E={[math]::Round($_.Size/1GB)}},
    @{N='FreeGB';E={[math]::Round($_.FreeSpace/1GB)}},
    @{N='FreePercent';E={[math]::Round($_.FreeSpace/$_.Size*100)}}
```

### Réseau

```powershell
# Adaptateurs réseau
Get-CimInstance Win32_NetworkAdapter -Filter "NetEnabled = True" |
    Select-Object Name, MACAddress, Speed

# Configuration IP
Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled = True" |
    Select-Object Description, IPAddress, IPSubnet, DefaultIPGateway, DNSServerSearchOrder

# Classes modernes (préférées)
Get-CimInstance -Namespace root/StandardCimv2 -ClassName MSFT_NetIPAddress |
    Select-Object InterfaceAlias, IPAddress, PrefixLength
```

### Utilisateurs et Sessions

```powershell
# Comptes utilisateurs locaux
Get-CimInstance Win32_UserAccount -Filter "LocalAccount = True" |
    Select-Object Name, Disabled, PasswordRequired, SID

# Groupes locaux
Get-CimInstance Win32_Group -Filter "LocalAccount = True" |
    Select-Object Name, SID

# Sessions de connexion
Get-CimInstance Win32_LogonSession |
    Where-Object LogonType -in 2,10 |  # 2=Interactive, 10=RemoteInteractive
    Select-Object LogonId, LogonType, StartTime

# Utilisateurs connectés
Get-CimInstance Win32_LoggedOnUser |
    Select-Object -ExpandProperty Antecedent |
    Select-Object Name, Domain -Unique
```

---

## Méthodes WMI/CIM

### Invoquer des Méthodes

```powershell
# Terminer un processus
$process = Get-CimInstance Win32_Process -Filter "Name = 'notepad.exe'"
Invoke-CimMethod -InputObject $process -MethodName Terminate

# Créer un processus
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{
    CommandLine = "notepad.exe"
}

# Changer le mode de démarrage d'un service
$service = Get-CimInstance Win32_Service -Filter "Name = 'Spooler'"
Invoke-CimMethod -InputObject $service -MethodName ChangeStartMode -Arguments @{
    StartMode = "Disabled"
}

# Démarrer/Arrêter un service
Invoke-CimMethod -InputObject $service -MethodName StartService
Invoke-CimMethod -InputObject $service -MethodName StopService
```

### Explorer les Méthodes Disponibles

```powershell
# Voir les méthodes d'une classe
Get-CimClass Win32_Process | Select-Object -ExpandProperty CimClassMethods

# Détails d'une méthode
(Get-CimClass Win32_Process).CimClassMethods["Create"]

# Paramètres d'une méthode
(Get-CimClass Win32_Process).CimClassMethods["Create"].Parameters
```

---

## WQL (WMI Query Language)

### Syntaxe de Base

```powershell
# SELECT basique
Get-CimInstance -Query "SELECT * FROM Win32_Service"

# Sélectionner des colonnes
Get-CimInstance -Query "SELECT Name, State FROM Win32_Service"

# Filtrer avec WHERE
Get-CimInstance -Query "SELECT * FROM Win32_Service WHERE State = 'Running'"

# Opérateurs
Get-CimInstance -Query "SELECT * FROM Win32_LogicalDisk WHERE FreeSpace < 10737418240"  # < 10GB
Get-CimInstance -Query "SELECT * FROM Win32_Process WHERE Name LIKE 'chrome%'"
Get-CimInstance -Query "SELECT * FROM Win32_Service WHERE State = 'Running' AND StartMode = 'Auto'"

# NULL check
Get-CimInstance -Query "SELECT * FROM Win32_NetworkAdapterConfiguration WHERE DefaultIPGateway IS NOT NULL"
```

### Requêtes Avancées

```powershell
# Associations (relations entre objets)
Get-CimInstance -Query "ASSOCIATORS OF {Win32_LogicalDisk.DeviceID='C:'} WHERE AssocClass = Win32_LogicalDiskToPartition"

# Références
Get-CimInstance -Query "REFERENCES OF {Win32_ComputerSystem.Name='$env:COMPUTERNAME'}"

# Events (WMI Eventing)
$query = "SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_Process'"
Register-CimIndicationEvent -Query $query -SourceIdentifier ProcessCreated
```

---

## Sessions CIM

### Connexions Distantes

```powershell
# Session avec WS-Man (défaut, recommandé)
$session = New-CimSession -ComputerName Server01

# Session avec DCOM (legacy, si WinRM non disponible)
$sessionOption = New-CimSessionOption -Protocol Dcom
$session = New-CimSession -ComputerName Server01 -SessionOption $sessionOption

# Avec credentials
$cred = Get-Credential
$session = New-CimSession -ComputerName Server01 -Credential $cred

# Utiliser la session
Get-CimInstance -CimSession $session -ClassName Win32_OperatingSystem

# Sessions multiples
$servers = "Server01","Server02","Server03"
$sessions = New-CimSession -ComputerName $servers
Get-CimInstance -CimSession $sessions -ClassName Win32_OperatingSystem

# Fermer les sessions
Remove-CimSession -CimSession $session
Get-CimSession | Remove-CimSession  # Toutes
```

---

## Namespaces

### Explorer les Namespaces

```powershell
# Lister les namespaces root
Get-CimInstance -Namespace root -ClassName __Namespace | Select-Object Name

# Namespaces enfants
Get-CimInstance -Namespace root\Microsoft -ClassName __Namespace | Select-Object Name

# Classes d'un namespace
Get-CimClass -Namespace root\cimv2 | Select-Object CimClassName | Sort-Object CimClassName

# Rechercher une classe
Get-CimClass -Namespace root\cimv2 -ClassName *Network*
```

### Namespaces Utiles

```powershell
# SecurityCenter2 (antivirus, firewall)
Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntivirusProduct
Get-CimInstance -Namespace root\SecurityCenter2 -ClassName FirewallProduct

# Microsoft\Windows (classes modernes)
Get-CimInstance -Namespace root\Microsoft\Windows\Storage -ClassName MSFT_Disk
Get-CimInstance -Namespace root\Microsoft\Windows\Defender -ClassName MSFT_MpComputerStatus

# StandardCimv2 (réseau moderne)
Get-CimInstance -Namespace root\StandardCimv2 -ClassName MSFT_NetAdapter
Get-CimInstance -Namespace root\StandardCimv2 -ClassName MSFT_NetIPAddress
```

---

## Scripts Pratiques

### Inventaire Système

```powershell
function Get-SystemInventory {
    param([string[]]$ComputerName = $env:COMPUTERNAME)

    foreach ($computer in $ComputerName) {
        try {
            $session = New-CimSession -ComputerName $computer -ErrorAction Stop

            $os = Get-CimInstance -CimSession $session -ClassName Win32_OperatingSystem
            $cs = Get-CimInstance -CimSession $session -ClassName Win32_ComputerSystem
            $cpu = Get-CimInstance -CimSession $session -ClassName Win32_Processor
            $disk = Get-CimInstance -CimSession $session -ClassName Win32_LogicalDisk -Filter "DriveType=3"

            [PSCustomObject]@{
                ComputerName = $computer
                OS = $os.Caption
                Version = $os.Version
                Manufacturer = $cs.Manufacturer
                Model = $cs.Model
                CPU = $cpu.Name
                Cores = $cpu.NumberOfCores
                MemoryGB = [math]::Round($cs.TotalPhysicalMemory/1GB)
                DiskFreeGB = [math]::Round(($disk | Measure-Object FreeSpace -Sum).Sum/1GB)
                LastBoot = $os.LastBootUpTime
            }

            Remove-CimSession -CimSession $session
        }
        catch {
            Write-Warning "Cannot connect to $computer : $_"
        }
    }
}

# Utilisation
Get-SystemInventory -ComputerName Server01,Server02 | Format-Table
```

### Monitoring des Processus

```powershell
function Watch-ProcessCreation {
    param([scriptblock]$Action)

    $query = "SELECT * FROM __InstanceCreationEvent WITHIN 2 WHERE TargetInstance ISA 'Win32_Process'"

    Register-CimIndicationEvent -Query $query -SourceIdentifier ProcessWatch -Action $Action

    Write-Host "Watching for new processes. Press Ctrl+C to stop."
    while ($true) { Start-Sleep -Seconds 1 }
}

# Utilisation
Watch-ProcessCreation -Action {
    $process = $event.SourceEventArgs.NewEvent.TargetInstance
    Write-Host "New process: $($process.Name) (PID: $($process.ProcessId))"
}
```

### Health Check Serveurs

```powershell
function Get-ServerHealth {
    param([string[]]$ComputerName)

    $results = foreach ($computer in $ComputerName) {
        try {
            $session = New-CimSession -ComputerName $computer -ErrorAction Stop

            $cpu = (Get-CimInstance -CimSession $session -ClassName Win32_Processor).LoadPercentage
            $mem = Get-CimInstance -CimSession $session -ClassName Win32_OperatingSystem
            $disk = Get-CimInstance -CimSession $session -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'"

            $memUsed = [math]::Round((($mem.TotalVisibleMemorySize - $mem.FreePhysicalMemory) / $mem.TotalVisibleMemorySize) * 100)
            $diskFree = [math]::Round($disk.FreeSpace / $disk.Size * 100)

            [PSCustomObject]@{
                Computer = $computer
                Status = "Online"
                CPU = "$cpu%"
                Memory = "$memUsed%"
                DiskC_Free = "$diskFree%"
                Alert = if ($cpu -gt 80 -or $memUsed -gt 90 -or $diskFree -lt 10) { "YES" } else { "No" }
            }

            Remove-CimSession -CimSession $session
        }
        catch {
            [PSCustomObject]@{
                Computer = $computer
                Status = "Offline"
                CPU = "N/A"
                Memory = "N/A"
                DiskC_Free = "N/A"
                Alert = "YES"
            }
        }
    }

    return $results
}

# Utilisation
Get-ServerHealth -ComputerName Server01,Server02,Server03 | Format-Table
```

---

## Troubleshooting

### Diagnostics WMI

```powershell
# Vérifier le service WMI
Get-Service Winmgmt

# Tester WMI local
Get-CimInstance Win32_OperatingSystem

# Tester WMI distant
Test-WSMan -ComputerName Server01
Get-CimInstance Win32_OperatingSystem -ComputerName Server01

# Réparer le repository WMI
winmgmt /verifyrepository
winmgmt /salvagerepository  # Si corruption détectée

# Rebuild complet (dernier recours)
# winmgmt /resetrepository
```

### Erreurs Courantes

```powershell
# "Access Denied"
# → Vérifier les permissions, exécuter en admin

# "RPC Server unavailable"
# → Firewall, DCOM non configuré
# → Utiliser CIM avec WinRM à la place

# "Invalid class"
# → La classe n'existe pas dans ce namespace
# → Vérifier avec Get-CimClass

# Timeout
$option = New-CimSessionOption -Protocol Wsman -OperationTimeout 120
$session = New-CimSession -ComputerName Server01 -SessionOption $option
```

---

## Bonnes Pratiques

```yaml
Checklist WMI/CIM:
  Code:
    - [ ] Utiliser CIM (pas WMI) pour nouveau code
    - [ ] Réutiliser les CimSession
    - [ ] Fermer les sessions après usage
    - [ ] Gérer les erreurs de connexion

  Performance:
    - [ ] Filtrer côté serveur (-Filter, -Query)
    - [ ] Sélectionner uniquement les propriétés nécessaires
    - [ ] Utiliser des sessions pour requêtes multiples
    - [ ] Paralléliser avec sessions multiples

  Sécurité:
    - [ ] Credentials sécurisés (pas en clair)
    - [ ] Préférer WS-Man à DCOM
    - [ ] Limiter les permissions WMI si nécessaire
```

---

**Voir aussi :**

- [PowerShell Foundations](powershell-foundations.md) - Bases PowerShell
- [PowerShell Remoting](powershell-remoting.md) - WinRM et sessions
- [Performance Monitoring](performance-monitoring.md) - Compteurs de performance
