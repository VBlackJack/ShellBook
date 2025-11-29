---
tags:
  - formation
  - windows-server
  - services
  - processus
---

# Module 07 : Services & Processus

## Objectifs du Module

Ce module couvre la gestion des services et processus Windows :

- Comprendre les services Windows
- Gérer les services avec PowerShell et sc.exe
- Monitorer et gérer les processus
- Configurer le démarrage automatique
- Dépanner les services problématiques

**Durée :** 7 heures

**Niveau :** Administration

---

## 1. Services Windows

### 1.1 Types de Services

```
SERVICE TYPES
─────────────
• Win32OwnProcess    - Processus isolé
• Win32ShareProcess  - Processus partagé (svchost.exe)
• InteractiveProcess - Interface utilisateur (legacy)
• KernelDriver       - Pilote noyau
• FileSystemDriver   - Pilote système de fichiers

STARTUP TYPES
─────────────
• Automatic          - Démarre au boot
• Automatic (Delayed)- Démarre après le boot
• Manual             - Démarrage manuel
• Disabled           - Désactivé
```

### 1.2 Gestion avec PowerShell

```powershell
# Lister tous les services
Get-Service

# Filtrer par état
Get-Service | Where-Object Status -eq "Running"
Get-Service | Where-Object Status -eq "Stopped"

# Services automatiques arrêtés (problème potentiel)
Get-Service | Where-Object { $_.StartType -eq "Automatic" -and $_.Status -ne "Running" }

# Détails d'un service
Get-Service -Name "Spooler" | Select-Object *

# Actions sur les services
Start-Service -Name "Spooler"
Stop-Service -Name "Spooler"
Restart-Service -Name "Spooler"
Suspend-Service -Name "Spooler"  # Pause (si supporté)
Resume-Service -Name "Spooler"

# Modifier le type de démarrage
Set-Service -Name "Spooler" -StartupType Automatic
Set-Service -Name "Spooler" -StartupType Disabled

# Créer un service
New-Service -Name "MonService" `
            -BinaryPathName "C:\Apps\monapp.exe" `
            -DisplayName "Mon Service Personnalisé" `
            -StartupType Automatic `
            -Description "Service de démonstration"

# Supprimer un service
Remove-Service -Name "MonService"  # PowerShell 6+
sc.exe delete "MonService"         # Toutes versions
```

### 1.3 Dépendances de Services

```powershell
# Voir les dépendances
Get-Service -Name "Spooler" | Select-Object -ExpandProperty DependentServices
Get-Service -Name "Spooler" | Select-Object -ExpandProperty ServicesDependedOn

# Services qui dépendent d'un autre
Get-Service | Where-Object { $_.ServicesDependedOn -contains "LanmanWorkstation" }
```

### 1.4 Comptes de Service

```powershell
# Voir le compte d'exécution
Get-CimInstance Win32_Service | Select-Object Name, StartName | Where-Object Name -eq "Spooler"

# Changer le compte d'exécution
$credential = Get-Credential
Set-Service -Name "MonService" -Credential $credential

# Comptes intégrés
# LocalSystem (NT AUTHORITY\SYSTEM) - Privilèges maximaux
# LocalService (NT AUTHORITY\LOCAL SERVICE) - Privilèges limités
# NetworkService (NT AUTHORITY\NETWORK SERVICE) - Accès réseau

# Configurer avec sc.exe
sc.exe config "MonService" obj= "NT AUTHORITY\NETWORK SERVICE"
```

---

## 2. Processus Windows

### 2.1 Gestion avec PowerShell

```powershell
# Lister les processus
Get-Process

# Filtrer par nom
Get-Process -Name "explorer"
Get-Process -Name "powershell*"

# Détails complets
Get-Process -Name "explorer" | Select-Object *

# Top 10 CPU
Get-Process | Sort-Object CPU -Descending | Select-Object -First 10 Name, Id, CPU

# Top 10 Mémoire
Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 10 Name, Id, @{N="MemoryMB";E={[math]::Round($_.WorkingSet64/1MB,2)}}

# Terminer un processus
Stop-Process -Name "notepad"
Stop-Process -Id 1234 -Force

# Démarrer un processus
Start-Process "notepad.exe"
Start-Process "notepad.exe" -ArgumentList "C:\file.txt"
Start-Process "powershell.exe" -Verb RunAs  # Élévation
```

### 2.2 Processus et Services

```powershell
# Trouver le processus d'un service
Get-CimInstance Win32_Service -Filter "Name='Spooler'" | Select-Object Name, ProcessId

# Processus svchost et leurs services
Get-Process svchost | ForEach-Object {
    $pid = $_.Id
    $services = Get-CimInstance Win32_Service -Filter "ProcessId=$pid" | Select-Object -ExpandProperty Name
    [PSCustomObject]@{
        PID = $pid
        MemoryMB = [math]::Round($_.WorkingSet64/1MB, 2)
        Services = $services -join ", "
    }
}
```

---

## 3. Tâches Planifiées

### 3.1 Gestion avec PowerShell

```powershell
# Lister les tâches
Get-ScheduledTask

# Créer une tâche
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-File C:\Scripts\backup.ps1"
$trigger = New-ScheduledTaskTrigger -Daily -At "02:00"
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
Register-ScheduledTask -TaskName "DailyBackup" -Action $action -Trigger $trigger -Principal $principal

# Exécuter manuellement
Start-ScheduledTask -TaskName "DailyBackup"

# Désactiver/Activer
Disable-ScheduledTask -TaskName "DailyBackup"
Enable-ScheduledTask -TaskName "DailyBackup"

# Supprimer
Unregister-ScheduledTask -TaskName "DailyBackup" -Confirm:$false
```

---

## 4. Exercice Pratique

### Moniteur de Services

```powershell
# Script de monitoring des services critiques
$criticalServices = @("DNS", "Netlogon", "W32Time", "LanmanServer")

foreach ($svc in $criticalServices) {
    $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($service) {
        $status = if ($service.Status -eq "Running") { "OK" } else { "ALERT" }
        $color = if ($status -eq "OK") { "Green" } else { "Red" }
        Write-Host "[$status] $($service.DisplayName)" -ForegroundColor $color
    }
}
```

---

## Quiz

1. **Quelle cmdlet arrête un service ?**
   - [ ] A. End-Service
   - [ ] B. Stop-Service
   - [ ] C. Terminate-Service

2. **Quel compte a les privilèges maximaux ?**
   - [ ] A. LocalService
   - [ ] B. NetworkService
   - [ ] C. LocalSystem

**Réponses :** 1-B, 2-C

---

**Précédent :** [Module 06 : Rôles & Features](06-roles-features.md)

**Suivant :** [Module 08 : Stockage & Disques](08-stockage-disques.md)
