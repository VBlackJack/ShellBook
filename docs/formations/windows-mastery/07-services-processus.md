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

```text
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

## Exercice : À Vous de Jouer

!!! example "Mise en Pratique"
    **Objectif** : Créer un système de surveillance automatique des services critiques

    **Contexte** : Votre entreprise a besoin d'un système qui surveille les services Windows critiques et les redémarre automatiquement s'ils s'arrêtent. Vous devez créer une tâche planifiée qui s'exécute toutes les 5 minutes pour vérifier l'état des services et générer des logs.

    **Tâches à réaliser** :

    1. Créer un script PowerShell qui surveille 5 services critiques (W3SVC, Spooler, DNS, Netlogon, W32Time)
    2. Le script doit redémarrer automatiquement tout service arrêté
    3. Générer un fichier de log avec horodatage des actions effectuées
    4. Créer une tâche planifiée qui exécute le script toutes les 5 minutes
    5. Tester le système en arrêtant manuellement un service

    **Critères de validation** :

    - [ ] Le script surveille correctement les 5 services spécifiés
    - [ ] Les services arrêtés sont automatiquement redémarrés
    - [ ] Un fichier de log est créé dans C:\Logs\ServiceMonitor.log
    - [ ] La tâche planifiée s'exécute toutes les 5 minutes
    - [ ] Le test de redémarrage automatique fonctionne

??? quote "Solution"
    Voici la solution complète :

    **Étape 1 : Créer le script de monitoring**

    ```powershell
    # Monitor-CriticalServices.ps1
    # Script de surveillance des services critiques

    param(
        [string]$LogPath = "C:\Logs\ServiceMonitor.log"
    )

    # Fonction de logging
    function Write-Log {
        param([string]$Message, [string]$Level = "INFO")

        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $logMessage = "[$timestamp] [$Level] $Message"

        # Créer le répertoire si nécessaire
        $logDir = Split-Path $LogPath -Parent
        if (-not (Test-Path $logDir)) {
            New-Item -Path $logDir -ItemType Directory -Force | Out-Null
        }

        # Écrire dans le fichier
        Add-Content -Path $LogPath -Value $logMessage

        # Afficher aussi à l'écran
        $color = switch ($Level) {
            "ERROR" { "Red" }
            "WARNING" { "Yellow" }
            "SUCCESS" { "Green" }
            default { "White" }
        }
        Write-Host $logMessage -ForegroundColor $color
    }

    # Services critiques à surveiller
    $criticalServices = @(
        "W3SVC",       # IIS
        "Spooler",     # Print Spooler
        "DNS",         # DNS Server
        "Netlogon",    # Netlogon
        "W32Time"      # Windows Time
    )

    Write-Log "=== Démarrage de la surveillance des services ==="

    $issuesFound = 0
    $servicesRestarted = 0

    foreach ($serviceName in $criticalServices) {
        try {
            $service = Get-Service -Name $serviceName -ErrorAction Stop

            if ($service.Status -ne "Running") {
                Write-Log "Service '$serviceName' est $($service.Status) - Tentative de redémarrage..." "WARNING"
                $issuesFound++

                try {
                    # Vérifier si le service est configuré en automatique
                    if ($service.StartType -eq "Disabled") {
                        Write-Log "Service '$serviceName' est désactivé - Activation..." "WARNING"
                        Set-Service -Name $serviceName -StartupType Automatic
                    }

                    # Redémarrer le service
                    Start-Service -Name $serviceName -ErrorAction Stop

                    # Vérifier que le service a bien démarré
                    Start-Sleep -Seconds 2
                    $service = Get-Service -Name $serviceName

                    if ($service.Status -eq "Running") {
                        Write-Log "Service '$serviceName' redémarré avec succès" "SUCCESS"
                        $servicesRestarted++
                    } else {
                        Write-Log "Échec du redémarrage de '$serviceName' - Statut: $($service.Status)" "ERROR"
                    }
                } catch {
                    Write-Log "Erreur lors du redémarrage de '$serviceName': $($_.Exception.Message)" "ERROR"
                }
            } else {
                Write-Log "Service '$serviceName' fonctionne correctement (PID: $($service.Id))"
            }

            # Informations supplémentaires
            $startType = (Get-CimInstance Win32_Service -Filter "Name='$serviceName'").StartMode
            Write-Log "  → Compte: $($service.ServicesDependedOn.Count) dépendances | Type démarrage: $startType"

        } catch {
            Write-Log "Erreur lors de la vérification de '$serviceName': $($_.Exception.Message)" "ERROR"
            $issuesFound++
        }
    }

    # Résumé
    Write-Log "=== Résumé de la surveillance ==="
    Write-Log "Services vérifiés: $($criticalServices.Count)"
    Write-Log "Problèmes détectés: $issuesFound"
    Write-Log "Services redémarrés: $servicesRestarted"

    # Si des problèmes ont été trouvés, retourner un code d'erreur
    if ($issuesFound -gt 0) {
        exit 1
    } else {
        exit 0
    }
    ```

    **Étape 2 : Créer la tâche planifiée**

    ```powershell
    # Create-MonitoringTask.ps1
    # Script pour créer la tâche planifiée de surveillance

    $scriptPath = "C:\Scripts\Monitor-CriticalServices.ps1"
    $taskName = "Monitor-CriticalServices"

    # Créer le répertoire des scripts si nécessaire
    $scriptDir = Split-Path $scriptPath -Parent
    if (-not (Test-Path $scriptDir)) {
        New-Item -Path $scriptDir -ItemType Directory -Force
    }

    # Copier le script de monitoring (supposant qu'il est dans le répertoire courant)
    Copy-Item -Path ".\Monitor-CriticalServices.ps1" -Destination $scriptPath -Force

    # Vérifier si la tâche existe déjà
    $existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if ($existingTask) {
        Write-Host "Suppression de la tâche existante..." -ForegroundColor Yellow
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    }

    # Créer l'action (exécution du script)
    $action = New-ScheduledTaskAction `
        -Execute "powershell.exe" `
        -Argument "-ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -File `"$scriptPath`""

    # Créer le trigger (toutes les 5 minutes)
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5)

    # Créer le principal (exécution avec compte SYSTEM)
    $principal = New-ScheduledTaskPrincipal `
        -UserId "NT AUTHORITY\SYSTEM" `
        -LogonType ServiceAccount `
        -RunLevel Highest

    # Paramètres de la tâche
    $settings = New-ScheduledTaskSettingsSet `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -StartWhenAvailable `
        -RunOnlyIfNetworkAvailable:$false `
        -MultipleInstances IgnoreNew

    # Créer la tâche
    Register-ScheduledTask `
        -TaskName $taskName `
        -Action $action `
        -Trigger $trigger `
        -Principal $principal `
        -Settings $settings `
        -Description "Surveillance automatique des services Windows critiques - Exécution toutes les 5 minutes"

    Write-Host "`nTâche planifiée créée avec succès!" -ForegroundColor Green
    Write-Host "Nom: $taskName"
    Write-Host "Fréquence: Toutes les 5 minutes"
    Write-Host "Script: $scriptPath"
    Write-Host "Logs: C:\Logs\ServiceMonitor.log"

    # Afficher les détails de la tâche
    Get-ScheduledTask -TaskName $taskName | Format-List TaskName, State, LastRunTime, NextRunTime
    ```

    **Étape 3 : Script de test**

    ```powershell
    # Test-ServiceMonitoring.ps1
    # Script pour tester le système de surveillance

    Write-Host "=== Test du système de surveillance ===" -ForegroundColor Cyan

    # 1. Vérifier que le script existe
    $scriptPath = "C:\Scripts\Monitor-CriticalServices.ps1"
    if (Test-Path $scriptPath) {
        Write-Host "[OK] Script de monitoring présent" -ForegroundColor Green
    } else {
        Write-Host "[ERREUR] Script de monitoring introuvable" -ForegroundColor Red
        exit 1
    }

    # 2. Vérifier que la tâche planifiée existe
    $task = Get-ScheduledTask -TaskName "Monitor-CriticalServices" -ErrorAction SilentlyContinue
    if ($task) {
        Write-Host "[OK] Tâche planifiée configurée" -ForegroundColor Green
        Write-Host "    État: $($task.State)"
        Write-Host "    Dernière exécution: $($task.LastRunTime)"
    } else {
        Write-Host "[ERREUR] Tâche planifiée non trouvée" -ForegroundColor Red
        exit 1
    }

    # 3. Test en arrêtant le service Spooler
    Write-Host "`nTest de redémarrage automatique..." -ForegroundColor Yellow
    Write-Host "Arrêt du service Spooler..."

    Stop-Service -Name Spooler -Force
    Start-Sleep -Seconds 2

    $serviceBefore = Get-Service -Name Spooler
    Write-Host "Service Spooler: $($serviceBefore.Status)"

    # 4. Exécuter le script de monitoring manuellement
    Write-Host "`nExécution du script de monitoring..."
    & $scriptPath

    # 5. Vérifier que le service a été redémarré
    Start-Sleep -Seconds 2
    $serviceAfter = Get-Service -Name Spooler

    if ($serviceAfter.Status -eq "Running") {
        Write-Host "`n[SUCCES] Le service Spooler a été redémarré automatiquement!" -ForegroundColor Green
    } else {
        Write-Host "`n[ERREUR] Le service n'a pas été redémarré" -ForegroundColor Red
    }

    # 6. Afficher les dernières lignes du log
    $logPath = "C:\Logs\ServiceMonitor.log"
    if (Test-Path $logPath) {
        Write-Host "`nDernières entrées du log:" -ForegroundColor Cyan
        Get-Content $logPath -Tail 10 | ForEach-Object {
            Write-Host "  $_"
        }
    }

    # 7. Démarrer la tâche planifiée pour vérifier qu'elle fonctionne
    Write-Host "`nDémarrage manuel de la tâche planifiée..."
    Start-ScheduledTask -TaskName "Monitor-CriticalServices"
    Start-Sleep -Seconds 5

    Write-Host "`n=== Test terminé ===" -ForegroundColor Cyan
    ```

    **Déploiement complet** :

    ```powershell
    # Déploiement en une commande

    # 1. Sauvegarder le script de monitoring
    # (Copier le contenu de Monitor-CriticalServices.ps1)

    # 2. Créer la tâche planifiée
    # (Exécuter Create-MonitoringTask.ps1)

    # 3. Tester le système
    # (Exécuter Test-ServiceMonitoring.ps1)

    # 4. Surveiller les logs en temps réel
    Get-Content "C:\Logs\ServiceMonitor.log" -Wait -Tail 20
    ```

    **Points clés de la solution** :

    - Script robuste avec gestion d'erreurs complète
    - Logging détaillé pour faciliter le débogage
    - Redémarrage automatique avec vérification du type de démarrage
    - Tâche planifiée configurée pour s'exécuter même sur batterie
    - Utilisation du compte SYSTEM pour les privilèges nécessaires
    - Script de test complet pour valider le fonctionnement
    - Monitoring des dépendances de services

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

---

## Navigation

| | |
|:---|---:|
| [← Module 06 : Rôles & Features](06-roles-features.md) | [Module 08 : Stockage & Disques →](08-stockage-disques.md) |

[Retour au Programme](index.md){ .md-button }
