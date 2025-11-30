---
tags:
  - windows
  - powershell
  - cheatsheet
  - survival-guide
---

# PowerShell Survival Guide

Commandes essentielles pour le dépannage quotidien.

---

## Navigation & Aide

```powershell
# Aide sur une commande
Get-Help Get-Process -Full
Get-Help Get-Process -Examples
Get-Help *service*                    # Rechercher dans l'aide

# Découvrir les commandes
Get-Command *process*
Get-Command -Module ActiveDirectory
Get-Command -Verb Get -Noun *User*

# Propriétés et méthodes d'un objet
Get-Process | Get-Member
Get-Service | Get-Member -MemberType Property

# Alias
Get-Alias ls
Get-Alias -Definition Get-ChildItem
```

---

## Système & Processus

### Informations Système

```powershell
# Infos système
Get-ComputerInfo
Get-ComputerInfo | Select-Object CsName, OsName, OsVersion, OsArchitecture

# Hostname et domaine
$env:COMPUTERNAME
$env:USERDOMAIN
[System.Net.Dns]::GetHostName()

# Uptime
(Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime

# Version Windows
[System.Environment]::OSVersion
(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").DisplayVersion

# Hardware
Get-CimInstance Win32_Processor | Select-Object Name, NumberOfCores
Get-CimInstance Win32_PhysicalMemory | Measure-Object Capacity -Sum
Get-CimInstance Win32_DiskDrive | Select-Object Model, Size
```

### Processus

```powershell
# Lister les processus
Get-Process
Get-Process -Name chrome
Get-Process | Sort-Object CPU -Descending | Select-Object -First 10

# Processus par utilisation mémoire
Get-Process | Sort-Object WorkingSet64 -Descending |
    Select-Object -First 10 Name, @{N='Mem(MB)';E={[math]::Round($_.WorkingSet64/1MB,2)}}

# Tuer un processus
Stop-Process -Name notepad
Stop-Process -Id 1234 -Force
Get-Process -Name chrome | Stop-Process

# Processus avec ligne de commande
Get-CimInstance Win32_Process |
    Select-Object ProcessId, Name, CommandLine |
    Where-Object { $_.CommandLine -like "*python*" }

# Processus par utilisateur
Get-Process -IncludeUserName | Select-Object Name, UserName, CPU
```

### Services

```powershell
# Lister les services
Get-Service
Get-Service -Name wuauserv
Get-Service | Where-Object Status -eq Running
Get-Service | Where-Object StartType -eq Automatic | Where-Object Status -ne Running

# Gérer un service
Start-Service -Name Spooler
Stop-Service -Name Spooler
Restart-Service -Name Spooler
Set-Service -Name Spooler -StartupType Automatic

# Services avec leur compte
Get-CimInstance Win32_Service |
    Select-Object Name, State, StartName |
    Where-Object { $_.StartName -notlike "LocalSystem" }

# Dépendances
Get-Service -Name LanmanWorkstation -DependentServices
Get-Service -Name LanmanWorkstation -RequiredServices
```

---

## Fichiers & Répertoires

### Navigation

```powershell
# Lister
Get-ChildItem                          # ls
Get-ChildItem -Force                   # Inclure cachés
Get-ChildItem -Recurse -Filter *.log
Get-ChildItem -Path C:\Logs -Recurse | Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) }

# Taille des dossiers
Get-ChildItem -Path C:\Users -Recurse -Force -ErrorAction SilentlyContinue |
    Measure-Object -Property Length -Sum

# Trouver les gros fichiers
Get-ChildItem -Path C:\ -Recurse -File -ErrorAction SilentlyContinue |
    Sort-Object Length -Descending |
    Select-Object -First 20 FullName, @{N='Size(MB)';E={[math]::Round($_.Length/1MB,2)}}
```

### Opérations sur Fichiers

```powershell
# Créer
New-Item -Path C:\Temp\test.txt -ItemType File
New-Item -Path C:\Temp\NewFolder -ItemType Directory
Set-Content -Path C:\Temp\test.txt -Value "Hello World"

# Copier / Déplacer
Copy-Item -Path C:\source\* -Destination C:\dest\ -Recurse
Move-Item -Path C:\old\file.txt -Destination C:\new\
Rename-Item -Path C:\file.txt -NewName newfile.txt

# Supprimer
Remove-Item -Path C:\Temp\*.log
Remove-Item -Path C:\Temp\OldFolder -Recurse -Force

# Lire
Get-Content -Path C:\log.txt
Get-Content -Path C:\log.txt -Tail 50               # Dernières 50 lignes
Get-Content -Path C:\log.txt -Wait                  # tail -f
```

### Recherche

```powershell
# Rechercher dans les fichiers (grep)
Select-String -Path C:\Logs\*.log -Pattern "error"
Select-String -Path C:\Logs\*.log -Pattern "error" -CaseSensitive
Get-ChildItem -Recurse -Filter *.log | Select-String -Pattern "Exception"

# Rechercher des fichiers
Get-ChildItem -Path C:\ -Recurse -Filter "*.config" -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\ -Recurse | Where-Object { $_.Name -like "*backup*" }
```

---

## Réseau

### Configuration IP

```powershell
# Adresses IP
Get-NetIPAddress
Get-NetIPAddress -AddressFamily IPv4 | Select-Object InterfaceAlias, IPAddress, PrefixLength
Get-NetIPConfiguration

# Interfaces
Get-NetAdapter
Get-NetAdapter | Where-Object Status -eq Up
Enable-NetAdapter -Name "Ethernet"
Disable-NetAdapter -Name "Wi-Fi"

# DNS
Get-DnsClientServerAddress
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses "8.8.8.8","8.8.4.4"
Clear-DnsClientCache
Resolve-DnsName google.com
Resolve-DnsName -Name server01 -Type A
```

### Diagnostic Réseau

```powershell
# Ping
Test-Connection -ComputerName google.com
Test-Connection -ComputerName server01 -Count 4
Test-Connection -ComputerName server01 -Quiet       # True/False seulement

# Test de port
Test-NetConnection -ComputerName server01 -Port 3389
Test-NetConnection -ComputerName server01 -Port 443 -InformationLevel Detailed
1..1024 | ForEach-Object { Test-NetConnection -ComputerName server01 -Port $_ -WarningAction SilentlyContinue } | Where-Object TcpTestSucceeded

# Traceroute
Test-NetConnection -ComputerName google.com -TraceRoute

# Connexions actives
Get-NetTCPConnection | Where-Object State -eq Established
Get-NetTCPConnection -State Listen | Select-Object LocalPort, OwningProcess
Get-NetTCPConnection | Where-Object { $_.RemotePort -eq 443 }

# Processus par port
Get-NetTCPConnection -LocalPort 80 |
    Select-Object LocalPort, OwningProcess, @{N='Process';E={(Get-Process -Id $_.OwningProcess).Name}}
```

### Firewall

```powershell
# Statut
Get-NetFirewallProfile | Select-Object Name, Enabled

# Règles
Get-NetFirewallRule | Where-Object Enabled -eq True
Get-NetFirewallRule -DisplayName "*Remote Desktop*"

# Créer une règle
New-NetFirewallRule -DisplayName "Allow HTTPS" -Direction Inbound -Protocol TCP -LocalPort 443 -Action Allow

# Activer/Désactiver
Enable-NetFirewallRule -DisplayName "Allow HTTPS"
Disable-NetFirewallRule -DisplayName "Allow HTTPS"
```

---

## Active Directory

!!! warning "Module requis"
    ```powershell
    Import-Module ActiveDirectory
    # Ou installer: Install-WindowsFeature RSAT-AD-PowerShell
    ```

### Utilisateurs

```powershell
# Rechercher un utilisateur
Get-ADUser -Identity jdupont
Get-ADUser -Filter "Name -like '*dupont*'"
Get-ADUser -Filter * -SearchBase "OU=Users,DC=domain,DC=local"
Get-ADUser -Identity jdupont -Properties *

# Utilisateurs désactivés
Get-ADUser -Filter { Enabled -eq $false }

# Utilisateurs non connectés depuis 90 jours
$date = (Get-Date).AddDays(-90)
Get-ADUser -Filter { LastLogonDate -lt $date } -Properties LastLogonDate |
    Select-Object Name, LastLogonDate

# Créer un utilisateur
New-ADUser -Name "Jean Dupont" -SamAccountName "jdupont" -UserPrincipalName "jdupont@domain.local" -Enabled $true -AccountPassword (ConvertTo-SecureString "P@ssw0rd!" -AsPlainText -Force)

# Modifier
Set-ADUser -Identity jdupont -Description "IT Admin"
Enable-ADAccount -Identity jdupont
Disable-ADAccount -Identity jdupont
Unlock-ADAccount -Identity jdupont

# Reset mot de passe
Set-ADAccountPassword -Identity jdupont -Reset -NewPassword (ConvertTo-SecureString "NewP@ss!" -AsPlainText -Force)
```

### Groupes

```powershell
# Lister les groupes
Get-ADGroup -Filter *
Get-ADGroup -Filter "Name -like 'IT*'"

# Membres d'un groupe
Get-ADGroupMember -Identity "Domain Admins"
Get-ADGroupMember -Identity "Domain Admins" -Recursive

# Groupes d'un utilisateur
Get-ADPrincipalGroupMembership -Identity jdupont | Select-Object Name

# Ajouter/Retirer d'un groupe
Add-ADGroupMember -Identity "IT-Admins" -Members jdupont
Remove-ADGroupMember -Identity "IT-Admins" -Members jdupont -Confirm:$false
```

### Ordinateurs

```powershell
# Lister
Get-ADComputer -Filter *
Get-ADComputer -Filter * -Properties OperatingSystem |
    Select-Object Name, OperatingSystem

# Ordinateurs inactifs
$date = (Get-Date).AddDays(-90)
Get-ADComputer -Filter { LastLogonDate -lt $date } -Properties LastLogonDate

# Chercher un ordinateur
Get-ADComputer -Filter "Name -like 'SRV*'"
Get-ADComputer -Identity "SRV-DC01" -Properties *
```

### OUs et GPOs

```powershell
# Lister les OUs
Get-ADOrganizationalUnit -Filter * | Select-Object Name, DistinguishedName

# GPOs liées
Get-GPO -All | Select-Object DisplayName, GpoStatus
Get-GPInheritance -Target "OU=Servers,DC=domain,DC=local"
```

---

## Event Logs

```powershell
# Lister les logs disponibles
Get-EventLog -List
Get-WinEvent -ListLog *

# Derniers événements
Get-EventLog -LogName System -Newest 20
Get-EventLog -LogName Application -EntryType Error -Newest 50

# WinEvent (plus puissant)
Get-WinEvent -LogName System -MaxEvents 100
Get-WinEvent -LogName Security -MaxEvents 50

# Filtrer par ID
Get-WinEvent -FilterHashtable @{LogName='System'; ID=6005,6006}   # Startup/Shutdown
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624}      # Logon events
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625}      # Failed logons

# Filtrer par date
$start = (Get-Date).AddHours(-24)
Get-WinEvent -FilterHashtable @{LogName='Application'; StartTime=$start; Level=2}

# Rechercher dans le message
Get-WinEvent -LogName Application |
    Where-Object { $_.Message -like "*error*" } |
    Select-Object -First 20

# Exporter
Get-EventLog -LogName System -Newest 1000 | Export-Csv C:\Logs\system.csv -NoTypeInformation
```

---

## Remote Management

### Sessions PowerShell

```powershell
# Session interactive
Enter-PSSession -ComputerName server01
Enter-PSSession -ComputerName server01 -Credential (Get-Credential)

# Exécution à distance
Invoke-Command -ComputerName server01 -ScriptBlock { Get-Service }
Invoke-Command -ComputerName server01,server02 -ScriptBlock { Get-Process }
Invoke-Command -ComputerName server01 -FilePath C:\Scripts\deploy.ps1

# Session persistante
$session = New-PSSession -ComputerName server01
Invoke-Command -Session $session -ScriptBlock { Get-Process }
Remove-PSSession $session

# Copier des fichiers
Copy-Item -Path C:\local\file.txt -Destination C:\remote\ -ToSession $session
Copy-Item -Path C:\remote\file.txt -Destination C:\local\ -FromSession $session
```

### CIM/WMI à Distance

```powershell
# Infos distantes
Get-CimInstance -ComputerName server01 -ClassName Win32_OperatingSystem
Get-CimInstance -ComputerName server01 -ClassName Win32_Service | Where-Object State -eq Running

# Redémarrer un service à distance
Get-Service -ComputerName server01 -Name Spooler | Restart-Service
```

---

## Scheduled Tasks

```powershell
# Lister les tâches
Get-ScheduledTask
Get-ScheduledTask | Where-Object State -eq Running
Get-ScheduledTask -TaskName "Backup*"

# Détails d'une tâche
Get-ScheduledTaskInfo -TaskName "\Microsoft\Windows\WindowsUpdate\Scheduled Start"

# Exécuter manuellement
Start-ScheduledTask -TaskName "MyBackupTask"

# Activer/Désactiver
Enable-ScheduledTask -TaskName "MyTask"
Disable-ScheduledTask -TaskName "MyTask"

# Créer une tâche
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-File C:\Scripts\backup.ps1"
$trigger = New-ScheduledTaskTrigger -Daily -At 3am
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 1)
Register-ScheduledTask -TaskName "DailyBackup" -Action $action -Trigger $trigger -Settings $settings -User "SYSTEM"
```

---

## Disques & Stockage

```powershell
# Espace disque
Get-PSDrive -PSProvider FileSystem
Get-Volume | Select-Object DriveLetter, FileSystemLabel, @{N='Size(GB)';E={[math]::Round($_.Size/1GB,2)}}, @{N='Free(GB)';E={[math]::Round($_.SizeRemaining/1GB,2)}}

# Disques physiques
Get-Disk
Get-PhysicalDisk | Select-Object FriendlyName, MediaType, Size, HealthStatus

# Partitions
Get-Partition | Select-Object DiskNumber, PartitionNumber, DriveLetter, Size

# Shares
Get-SmbShare
Get-SmbSession
Get-SmbOpenFile
```

---

## Utilisateurs Locaux

```powershell
# Lister
Get-LocalUser
Get-LocalUser | Where-Object Enabled -eq $true

# Créer
New-LocalUser -Name "admin2" -Password (ConvertTo-SecureString "P@ssw0rd!" -AsPlainText -Force)
Add-LocalGroupMember -Group "Administrators" -Member "admin2"

# Modifier
Set-LocalUser -Name "admin2" -Description "Backup Admin"
Disable-LocalUser -Name "admin2"
Enable-LocalUser -Name "admin2"

# Groupes locaux
Get-LocalGroup
Get-LocalGroupMember -Group "Administrators"
```

---

## One-Liners Utiles

### Diagnostic Rapide

```powershell
# Uptime
(Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime | Select-Object Days, Hours, Minutes

# Top 10 CPU
Get-Process | Sort-Object CPU -Desc | Select-Object -First 10 Name, CPU, @{N='Mem(MB)';E={[math]::Round($_.WS/1MB)}}

# Services en échec
Get-Service | Where-Object { $_.StartType -eq 'Automatic' -and $_.Status -ne 'Running' }

# Espace disque critique (<10%)
Get-Volume | Where-Object { $_.SizeRemaining/$_.Size -lt 0.1 } | Select-Object DriveLetter, @{N='Free%';E={[math]::Round($_.SizeRemaining/$_.Size*100,1)}}

# Dernières erreurs système
Get-WinEvent -FilterHashtable @{LogName='System';Level=2} -MaxEvents 10 | Format-Table TimeCreated, Id, Message -Wrap

# Ports en écoute
Get-NetTCPConnection -State Listen | Sort-Object LocalPort | Select-Object LocalPort, @{N='Process';E={(Get-Process -Id $_.OwningProcess).Name}} | Sort-Object LocalPort -Unique

# Connexions établies par process
Get-NetTCPConnection -State Established | Group-Object OwningProcess | ForEach-Object { [PSCustomObject]@{Process=(Get-Process -Id $_.Name).Name; Count=$_.Count} } | Sort-Object Count -Desc
```

### Active Directory

```powershell
# Comptes verrouillés
Search-ADAccount -LockedOut | Select-Object Name, SamAccountName

# Mots de passe expirés
Search-ADAccount -PasswordExpired | Select-Object Name, SamAccountName

# Comptes qui expirent bientôt (7 jours)
Search-ADAccount -AccountExpiring -TimeSpan 7.00:00:00 | Select-Object Name, AccountExpirationDate

# Admins du domaine
Get-ADGroupMember "Domain Admins" -Recursive | Select-Object Name, SamAccountName

# Dernières modifications d'un utilisateur
Get-ADUser -Identity jdupont -Properties whenChanged, PasswordLastSet | Select-Object Name, whenChanged, PasswordLastSet
```

### Réseau

```powershell
# Scanner de ports basique
$ports = 22,80,443,3389,5985
$ports | ForEach-Object { [PSCustomObject]@{Port=$_; Open=(Test-NetConnection -ComputerName server01 -Port $_ -WarningAction SilentlyContinue).TcpTestSucceeded} }

# IPs connectées
Get-NetTCPConnection -State Established | Select-Object RemoteAddress -Unique | Where-Object { $_.RemoteAddress -notlike "127.*" -and $_.RemoteAddress -notlike "::*" }

# Résolution DNS en masse
"server01","server02","server03" | ForEach-Object { [PSCustomObject]@{Name=$_; IP=(Resolve-DnsName $_ -ErrorAction SilentlyContinue).IPAddress} }
```

---

## Formatage & Export

```powershell
# Tableau
Get-Process | Format-Table Name, CPU, WorkingSet -AutoSize

# Liste
Get-Service -Name wuauserv | Format-List *

# Sélection de colonnes
Get-Process | Select-Object Name, CPU, @{N='Mem(MB)';E={[math]::Round($_.WS/1MB,2)}}

# Export CSV
Get-ADUser -Filter * | Export-Csv C:\users.csv -NoTypeInformation

# Export JSON
Get-Process | Select-Object Name, CPU | ConvertTo-Json | Out-File C:\processes.json

# Export HTML
Get-Service | ConvertTo-Html | Out-File C:\services.html

# GridView (GUI)
Get-Process | Out-GridView
Get-Process | Out-GridView -PassThru | Stop-Process    # Sélection interactive
```

---

## Voir Aussi

- [PowerShell Bases](powershell-foundations.md) - Fondamentaux
- [Execution Policy](powershell-execution.md) - Politiques d'exécution
- [Remoting & WinRM](powershell-remoting.md) - Administration à distance
- [Event Logs](event-logs.md) - Journaux Windows
