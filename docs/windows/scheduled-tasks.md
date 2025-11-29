---
tags:
  - windows
  - scheduled-tasks
  - automation
  - powershell
---

# Task Scheduler Avancé

Automatisation avec le Planificateur de tâches Windows : création, triggers, et gestion via PowerShell.

## Concepts

```
ARCHITECTURE TASK SCHEDULER
══════════════════════════════════════════════════════════

Task Scheduler Service (Schedule)
        │
        ├── Task Definitions (.xml)
        │   └── Stockées dans C:\Windows\System32\Tasks\
        │
        ├── Triggers (déclencheurs)
        │   ├── Time-based (horaire, quotidien, hebdo)
        │   ├── Event-based (event log trigger)
        │   ├── Logon/Startup
        │   ├── Idle
        │   └── Registration (à la création)
        │
        ├── Actions
        │   ├── Start a program
        │   ├── Send email (deprecated)
        │   └── Display message (deprecated)
        │
        └── Conditions & Settings
            ├── Run only if idle
            ├── Wake computer
            ├── Run on battery
            └── Kill if runs too long
```

---

## Gestion via PowerShell

### Lister et Consulter

```powershell
# Lister toutes les tâches
Get-ScheduledTask

# Tâches d'un dossier
Get-ScheduledTask -TaskPath "\Microsoft\Windows\*"

# Tâches en cours d'exécution
Get-ScheduledTask | Where-Object State -eq "Running"

# Tâches désactivées
Get-ScheduledTask | Where-Object State -eq "Disabled"

# Détails d'une tâche
Get-ScheduledTask -TaskName "MyTask" | Format-List *

# Informations sur la dernière exécution
Get-ScheduledTaskInfo -TaskName "MyTask"

# Historique d'exécution (Event Log)
Get-WinEvent -LogName "Microsoft-Windows-TaskScheduler/Operational" -MaxEvents 50 |
    Where-Object { $_.Message -like "*MyTask*" }
```

### Créer une Tâche Simple

```powershell
# Créer une action
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
    -Argument "-NoProfile -WindowStyle Hidden -File C:\Scripts\backup.ps1"

# Créer un trigger (tous les jours à 2h)
$trigger = New-ScheduledTaskTrigger -Daily -At "02:00"

# Créer la tâche
Register-ScheduledTask -TaskName "DailyBackup" `
    -Action $action `
    -Trigger $trigger `
    -Description "Backup quotidien" `
    -User "SYSTEM" `
    -RunLevel Highest
```

### Tâche avec Credentials

```powershell
# Exécuter en tant qu'utilisateur spécifique
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
    -Argument "-File C:\Scripts\report.ps1"

$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At "08:00"

# Demander le mot de passe
$cred = Get-Credential -UserName "CORP\svc_reports" -Message "Service account password"

Register-ScheduledTask -TaskName "WeeklyReport" `
    -Action $action `
    -Trigger $trigger `
    -User $cred.UserName `
    -Password $cred.GetNetworkCredential().Password `
    -RunLevel Highest

# Ou avec stockage du password
Register-ScheduledTask -TaskName "WeeklyReport" `
    -Action $action `
    -Trigger $trigger `
    -User "CORP\svc_reports" `
    -Password "P@ssw0rd" `
    -RunLevel Highest
```

### Types de Triggers

```powershell
# Horaire précis
$trigger = New-ScheduledTaskTrigger -Once -At "2024-02-01 10:00"

# Quotidien
$trigger = New-ScheduledTaskTrigger -Daily -At "02:00"

# Quotidien avec répétition
$trigger = New-ScheduledTaskTrigger -Daily -At "08:00"
$trigger.Repetition.Interval = (New-TimeSpan -Hours 1)
$trigger.Repetition.Duration = (New-TimeSpan -Hours 10)

# Hebdomadaire
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday,Wednesday,Friday -At "09:00"

# Mensuel (1er et 15 du mois)
$trigger = New-ScheduledTaskTrigger -Monthly -DaysOfMonth 1,15 -At "06:00"

# Au démarrage
$trigger = New-ScheduledTaskTrigger -AtStartup

# À la connexion
$trigger = New-ScheduledTaskTrigger -AtLogOn
$trigger = New-ScheduledTaskTrigger -AtLogOn -User "CORP\julien"

# Sur événement (Event Log)
$trigger = New-ScheduledTaskTrigger -AtStartup  # placeholder
$CIMTriggerClass = Get-CimClass -ClassName MSFT_TaskEventTrigger -Namespace Root/Microsoft/Windows/TaskScheduler
$trigger = New-CimInstance -CimClass $CIMTriggerClass -ClientOnly
$trigger.Enabled = $true
$trigger.Subscription = @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">*[System[EventID=4625]]</Select>
  </Query>
</QueryList>
"@
```

### Settings et Conditions

```powershell
# Créer des settings personnalisés
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -RunOnlyIfNetworkAvailable `
    -WakeToRun `
    -ExecutionTimeLimit (New-TimeSpan -Hours 2) `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 5) `
    -MultipleInstances IgnoreNew

# Appliquer à la tâche
Register-ScheduledTask -TaskName "MyTask" `
    -Action $action `
    -Trigger $trigger `
    -Settings $settings `
    -User "SYSTEM"

# Modifier les settings d'une tâche existante
Set-ScheduledTask -TaskName "MyTask" -Settings $settings
```

### Actions Multiples

```powershell
# Plusieurs actions séquentielles
$action1 = New-ScheduledTaskAction -Execute "PowerShell.exe" `
    -Argument "-File C:\Scripts\step1.ps1"

$action2 = New-ScheduledTaskAction -Execute "PowerShell.exe" `
    -Argument "-File C:\Scripts\step2.ps1"

$action3 = New-ScheduledTaskAction -Execute "cmd.exe" `
    -Argument "/c echo Done >> C:\Logs\task.log"

Register-ScheduledTask -TaskName "MultiStep" `
    -Action $action1,$action2,$action3 `
    -Trigger $trigger `
    -User "SYSTEM"
```

---

## Gestion des Tâches

### Modifier une Tâche

```powershell
# Récupérer la tâche
$task = Get-ScheduledTask -TaskName "MyTask"

# Modifier le trigger
$task.Triggers[0].StartBoundary = "2024-02-01T03:00:00"
Set-ScheduledTask -InputObject $task

# Modifier l'action
$task.Actions[0].Arguments = "-File C:\Scripts\new-script.ps1"
Set-ScheduledTask -InputObject $task

# Activer/Désactiver
Enable-ScheduledTask -TaskName "MyTask"
Disable-ScheduledTask -TaskName "MyTask"

# Exécuter immédiatement
Start-ScheduledTask -TaskName "MyTask"

# Arrêter
Stop-ScheduledTask -TaskName "MyTask"
```

### Supprimer une Tâche

```powershell
# Supprimer
Unregister-ScheduledTask -TaskName "MyTask" -Confirm:$false

# Supprimer toutes les tâches d'un dossier
Get-ScheduledTask -TaskPath "\MyCompany\*" |
    Unregister-ScheduledTask -Confirm:$false
```

### Exporter/Importer

```powershell
# Exporter en XML
Export-ScheduledTask -TaskName "MyTask" | Out-File "C:\Backup\MyTask.xml"

# Exporter toutes les tâches personnalisées
Get-ScheduledTask -TaskPath "\MyCompany\*" | ForEach-Object {
    $_ | Export-ScheduledTask | Out-File "C:\Backup\$($_.TaskName).xml"
}

# Importer
Register-ScheduledTask -TaskName "MyTask" -Xml (Get-Content "C:\Backup\MyTask.xml" -Raw)

# Importer avec nouveau nom/utilisateur
Register-ScheduledTask -TaskName "MyTask-Copy" `
    -Xml (Get-Content "C:\Backup\MyTask.xml" -Raw) `
    -User "SYSTEM"
```

---

## Patterns Courants

### Tâche de Maintenance

```powershell
# Nettoyage des fichiers temporaires
$cleanupScript = @'
$paths = @(
    "C:\Windows\Temp",
    "C:\Users\*\AppData\Local\Temp"
)

$cutoff = (Get-Date).AddDays(-7)

foreach ($path in $paths) {
    Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -lt $cutoff } |
        Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
}
'@

$cleanupScript | Out-File "C:\Scripts\Cleanup-TempFiles.ps1" -Encoding UTF8

$action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File C:\Scripts\Cleanup-TempFiles.ps1"

$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At "03:00"

$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -DontStopIfGoingOnBatteries

Register-ScheduledTask -TaskName "Cleanup-TempFiles" `
    -TaskPath "\Maintenance\" `
    -Action $action `
    -Trigger $trigger `
    -Settings $settings `
    -User "SYSTEM" `
    -Description "Nettoyage hebdomadaire des fichiers temporaires"
```

### Tâche Déclenchée par Event

```powershell
# Réagir à un échec de connexion (Event 4625)
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
    -Argument "-File C:\Scripts\Alert-FailedLogon.ps1"

# Trigger sur événement
$CIMTriggerClass = Get-CimClass -ClassName MSFT_TaskEventTrigger `
    -Namespace Root/Microsoft/Windows/TaskScheduler
$trigger = New-CimInstance -CimClass $CIMTriggerClass -ClientOnly
$trigger.Enabled = $true
$trigger.Subscription = @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] and EventID=4625]]
    </Select>
  </Query>
</QueryList>
"@

Register-ScheduledTask -TaskName "Alert-FailedLogon" `
    -Action $action `
    -Trigger $trigger `
    -User "SYSTEM"
```

### Tâche avec Retry

```powershell
# Tâche qui réessaie en cas d'échec
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
    -Argument "-File C:\Scripts\sync-data.ps1"

$trigger = New-ScheduledTaskTrigger -Daily -At "06:00"

$settings = New-ScheduledTaskSettingsSet `
    -StartWhenAvailable `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 10) `
    -ExecutionTimeLimit (New-TimeSpan -Hours 1)

Register-ScheduledTask -TaskName "Sync-Data" `
    -Action $action `
    -Trigger $trigger `
    -Settings $settings `
    -User "SYSTEM"
```

### Tâche avec Logging

```powershell
# Script wrapper avec logging
$wrapperScript = @'
param($ScriptPath)

$logFile = "C:\Logs\Tasks\$(Split-Path $ScriptPath -Leaf)_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

try {
    Start-Transcript -Path $logFile
    & $ScriptPath
    $exitCode = 0
}
catch {
    Write-Error $_
    $exitCode = 1
}
finally {
    Stop-Transcript
}

exit $exitCode
'@

$wrapperScript | Out-File "C:\Scripts\Task-Wrapper.ps1" -Encoding UTF8

# Utiliser le wrapper
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
    -Argument "-NoProfile -File C:\Scripts\Task-Wrapper.ps1 -ScriptPath C:\Scripts\my-task.ps1"
```

---

## Déploiement via GPO

### Preferences Scheduled Tasks

```
Computer Configuration > Preferences > Control Panel Settings > Scheduled Tasks

Actions possibles :
• Create : Crée si n'existe pas
• Replace : Remplace systématiquement
• Update : Met à jour si existe
• Delete : Supprime

Avantages :
• Déploiement centralisé
• Item-level targeting
• Variables GPO (%LogonUser%, %ComputerName%)
```

### Script de Déploiement

```powershell
# Script de déploiement pour GPO Startup
# Vérifie et crée les tâches si nécessaire

$tasks = @(
    @{
        Name = "Maintenance-Cleanup"
        Action = "PowerShell.exe"
        Arguments = "-File \\corp.local\NETLOGON\Scripts\cleanup.ps1"
        Trigger = "Daily"
        Time = "03:00"
    },
    @{
        Name = "Security-Audit"
        Action = "PowerShell.exe"
        Arguments = "-File \\corp.local\NETLOGON\Scripts\audit.ps1"
        Trigger = "Weekly"
        DaysOfWeek = "Monday"
        Time = "06:00"
    }
)

foreach ($t in $tasks) {
    $existing = Get-ScheduledTask -TaskName $t.Name -ErrorAction SilentlyContinue

    if (-not $existing) {
        $action = New-ScheduledTaskAction -Execute $t.Action -Argument $t.Arguments

        if ($t.Trigger -eq "Daily") {
            $trigger = New-ScheduledTaskTrigger -Daily -At $t.Time
        }
        elseif ($t.Trigger -eq "Weekly") {
            $trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek $t.DaysOfWeek -At $t.Time
        }

        Register-ScheduledTask -TaskName $t.Name `
            -TaskPath "\Corp\" `
            -Action $action `
            -Trigger $trigger `
            -User "SYSTEM" `
            -RunLevel Highest

        Write-EventLog -LogName Application -Source "TaskDeployment" -EventId 1000 `
            -Message "Created scheduled task: $($t.Name)"
    }
}
```

---

## Monitoring et Troubleshooting

### Vérifier l'État

```powershell
# Dashboard des tâches
Get-ScheduledTask | ForEach-Object {
    $info = Get-ScheduledTaskInfo -TaskName $_.TaskName -TaskPath $_.TaskPath -ErrorAction SilentlyContinue
    [PSCustomObject]@{
        Name = $_.TaskName
        Path = $_.TaskPath
        State = $_.State
        LastRun = $info.LastRunTime
        LastResult = $info.LastTaskResult
        NextRun = $info.NextRunTime
    }
} | Format-Table -AutoSize

# Tâches en échec (LastTaskResult != 0)
Get-ScheduledTask | ForEach-Object {
    $info = Get-ScheduledTaskInfo -TaskName $_.TaskName -TaskPath $_.TaskPath -ErrorAction SilentlyContinue
    if ($info.LastTaskResult -ne 0) {
        [PSCustomObject]@{
            Name = $_.TaskName
            LastRun = $info.LastRunTime
            ResultCode = "0x{0:X}" -f $info.LastTaskResult
        }
    }
}
```

### Event Logs

```powershell
# Activer l'historique détaillé
wevtutil set-log Microsoft-Windows-TaskScheduler/Operational /enabled:true

# Consulter les événements
Get-WinEvent -LogName "Microsoft-Windows-TaskScheduler/Operational" -MaxEvents 100 |
    Select-Object TimeCreated, Id, Message |
    Format-Table -Wrap

# Events importants :
# 100 : Task started
# 101 : Task start failed
# 102 : Task completed
# 103 : Action start failed
# 106 : Task registered
# 107 : Task triggered
# 110 : Task launched
# 111 : Task terminated
# 140 : Task updated
# 141 : Task deleted
# 200 : Action completed
# 201 : Action failed
```

### Codes de Retour Courants

```
CODES DE RÉSULTAT (LastTaskResult)
══════════════════════════════════════════════════════════

0x0 (0)       : Succès
0x1 (1)       : Fonction incorrecte (souvent script erreur)
0x41301       : Tâche en cours d'exécution
0x41302       : Tâche désactivée
0x41303       : Tâche pas encore exécutée
0x41304       : Plus d'exécutions planifiées
0x41306       : Tâche terminée par l'utilisateur
0x8004131F    : Credentials incorrects
0x800704DD    : Service non disponible
0x80070005    : Accès refusé
```

---

## Bonnes Pratiques

```yaml
Checklist Task Scheduler:
  Création:
    - [ ] Utiliser des comptes de service dédiés
    - [ ] Éviter les mots de passe dans les scripts
    - [ ] Définir un timeout (ExecutionTimeLimit)
    - [ ] Configurer les retries si nécessaire

  Sécurité:
    - [ ] Run avec privilèges minimum
    - [ ] Stocker les scripts en lecture seule
    - [ ] Auditer les modifications de tâches
    - [ ] Pas de credentials en clair

  Opérations:
    - [ ] Logging dans chaque script
    - [ ] Monitoring des échecs
    - [ ] Documentation des tâches
    - [ ] Sauvegarde des définitions XML

  Performance:
    - [ ] Éviter les heures de pointe
    - [ ] Répartir les tâches dans le temps
    - [ ] Surveiller la consommation ressources
```

---

**Voir aussi :**

- [PowerShell Foundations](powershell-foundations.md) - Scripting PowerShell
- [Event Logs](event-logs.md) - Journaux d'événements
- [Windows Security](windows-security.md) - Sécurité Windows
