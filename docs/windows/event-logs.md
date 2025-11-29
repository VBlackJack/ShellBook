---
tags:
  - windows
  - event-logs
  - monitoring
  - troubleshooting
---

# Event Logs Windows

Gestion et analyse des journaux d'événements Windows.

## Architecture des Logs

```
STRUCTURE DES EVENT LOGS
══════════════════════════════════════════════════════════

Logs classiques (evtx) :
├── Application      Messages des applications
├── Security         Audit de sécurité (logon, accès fichiers)
├── System           Événements système, drivers, services
├── Setup            Installation Windows et rôles
└── Forwarded Events Événements collectés d'autres machines

Logs Applications & Services :
├── Microsoft-Windows-*
│   ├── PowerShell/Operational
│   ├── TaskScheduler/Operational
│   ├── Windows Defender/Operational
│   ├── Sysmon/Operational
│   └── ...
└── Répertoire : C:\Windows\System32\winevt\Logs\
```

---

## Consultation des Logs

### PowerShell

```powershell
# Lister les logs disponibles
Get-WinEvent -ListLog * | Select-Object LogName, RecordCount, IsEnabled | Sort-Object RecordCount -Descending

# Lire les derniers événements
Get-WinEvent -LogName "System" -MaxEvents 50

# Filtrer par niveau
Get-WinEvent -FilterHashtable @{
    LogName = 'System'
    Level = 1,2  # 1=Critical, 2=Error, 3=Warning, 4=Info
} -MaxEvents 100

# Filtrer par Event ID
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4624,4625  # Logon success/failure
} -MaxEvents 100

# Filtrer par date
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    StartTime = (Get-Date).AddHours(-24)
} -MaxEvents 500

# Recherche dans le message
Get-WinEvent -LogName "Application" -MaxEvents 1000 |
    Where-Object { $_.Message -like "*error*" }

# Format personnalisé
Get-WinEvent -LogName "System" -MaxEvents 20 |
    Select-Object TimeCreated, Id, LevelDisplayName, Message |
    Format-Table -Wrap
```

### Event Viewer GUI

```
eventvwr.msc
• Vues personnalisées
• Filtres avancés
• Tâches attachées aux événements
```

---

## Event IDs Importants

### Sécurité

| Event ID | Description |
|----------|-------------|
| 4624 | Logon réussi |
| 4625 | Logon échoué |
| 4634 | Logoff |
| 4648 | Logon avec credentials explicites |
| 4672 | Privilèges spéciaux assignés |
| 4688 | Nouveau processus créé |
| 4689 | Processus terminé |
| 4720 | Compte utilisateur créé |
| 4722 | Compte activé |
| 4723 | Tentative changement mot de passe |
| 4724 | Reset mot de passe |
| 4725 | Compte désactivé |
| 4726 | Compte supprimé |
| 4728 | Membre ajouté à un groupe global |
| 4732 | Membre ajouté à un groupe local |
| 4756 | Membre ajouté à un groupe universel |

### Système

| Event ID | Source | Description |
|----------|--------|-------------|
| 1074 | User32 | Shutdown/Restart initié |
| 6005 | EventLog | Service EventLog démarré (boot) |
| 6006 | EventLog | Service EventLog arrêté (shutdown) |
| 7045 | Service Control Manager | Nouveau service installé |
| 41 | Kernel-Power | Crash/BSOD inattendu |

---

## Configuration de l'Audit

### Audit Policy

```powershell
# Voir la politique d'audit actuelle
auditpol /get /category:*

# Configurer l'audit des logons
auditpol /set /subcategory:"Logon" /success:enable /failure:enable

# Activer l'audit des processus
auditpol /set /subcategory:"Process Creation" /success:enable

# Via GPO (recommandé)
# Computer Configuration > Policies > Windows Settings >
# Security Settings > Advanced Audit Policy Configuration
```

### Audit des Commandes PowerShell

```powershell
# Activer le logging PowerShell
# GPO : Administrative Templates > Windows Components > Windows PowerShell

# Script Block Logging
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
New-Item -Path $regPath -Force
Set-ItemProperty -Path $regPath -Name "EnableScriptBlockLogging" -Value 1

# Module Logging
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
New-Item -Path $regPath -Force
Set-ItemProperty -Path $regPath -Name "EnableModuleLogging" -Value 1

# Transcription
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
New-Item -Path $regPath -Force
Set-ItemProperty -Path $regPath -Name "EnableTranscripting" -Value 1
Set-ItemProperty -Path $regPath -Name "OutputDirectory" -Value "C:\PSLogs"
```

---

## Event Forwarding (WEF)

### Collecteur (Collector)

```powershell
# Activer le service Windows Event Collector
wecutil qc

# Ou via PowerShell
Set-Service -Name Wecsvc -StartupType Automatic
Start-Service Wecsvc

# Créer un abonnement
wecutil cs subscription.xml
```

### Source (Forwarder)

```powershell
# Configurer WinRM
winrm quickconfig

# Ajouter le collecteur aux sources autorisées
# GPO : Computer Configuration > Administrative Templates >
# Windows Components > Event Forwarding > Configure target Subscription Manager
# → Server=http://collector.corp.local:5985/wsman/SubscriptionManager/WEC
```

### Exemple de Subscription

```xml
<!-- subscription.xml -->
<Subscription xmlns="http://schemas.microsoft.com/2006/03/windows/events/subscription">
    <SubscriptionId>Security-Events</SubscriptionId>
    <SubscriptionType>SourceInitiated</SubscriptionType>
    <Description>Security events from all servers</Description>
    <Enabled>true</Enabled>
    <Uri>http://schemas.microsoft.com/wbem/wsman/1/windows/EventLog</Uri>
    <ConfigurationMode>Normal</ConfigurationMode>
    <Query>
        <![CDATA[
        <QueryList>
            <Query Path="Security">
                <Select>*[System[(EventID=4624 or EventID=4625 or EventID=4648)]]</Select>
            </Query>
        </QueryList>
        ]]>
    </Query>
    <ReadExistingEvents>false</ReadExistingEvents>
    <TransportName>HTTP</TransportName>
    <CredentialsType>Default</CredentialsType>
</Subscription>
```

---

## Analyse et Recherche

### Requêtes Utiles

```powershell
# Échecs de connexion par utilisateur
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} |
    ForEach-Object {
        [PSCustomObject]@{
            Time = $_.TimeCreated
            User = $_.Properties[5].Value
            IP = $_.Properties[19].Value
            Reason = $_.Properties[8].Value
        }
    } | Group-Object User | Sort-Object Count -Descending

# Nouveaux services installés
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} |
    Select-Object TimeCreated, @{N='ServiceName';E={$_.Properties[0].Value}}, @{N='ImagePath';E={$_.Properties[1].Value}}

# Processus créés (si audit activé)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} -MaxEvents 100 |
    Select-Object TimeCreated, @{N='Process';E={$_.Properties[5].Value}}, @{N='CommandLine';E={$_.Properties[8].Value}}

# Comptes créés récemment
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4720; StartTime=(Get-Date).AddDays(-7)} |
    Select-Object TimeCreated, @{N='NewUser';E={$_.Properties[0].Value}}, @{N='CreatedBy';E={$_.Properties[4].Value}}
```

### Export pour SIEM

```powershell
# Export CSV
Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=(Get-Date).AddHours(-24)} |
    Select-Object TimeCreated, Id, LevelDisplayName, Message |
    Export-Csv -Path "C:\Exports\security-events.csv" -NoTypeInformation

# Export JSON
Get-WinEvent -LogName "Security" -MaxEvents 1000 |
    ConvertTo-Json -Depth 5 |
    Out-File "C:\Exports\security-events.json"

# Export evtx
wevtutil epl Security C:\Exports\security.evtx /q:"*[System[TimeCreated[timediff(@SystemTime) <= 86400000]]]"
```

---

## Gestion des Logs

```powershell
# Taille et rétention
wevtutil gl Security
# ou
Get-WinEvent -ListLog Security | Select-Object LogName, MaximumSizeInBytes, LogMode

# Modifier la taille max
wevtutil sl Security /ms:1073741824  # 1GB

# Via PowerShell
Limit-EventLog -LogName Security -MaximumSize 1GB

# Archiver et vider
wevtutil cl Security /bu:C:\Archives\Security-$(Get-Date -Format yyyyMMdd).evtx

# Vider un log
wevtutil cl Application
Clear-EventLog -LogName Application
```

---

## Bonnes Pratiques

```yaml
Checklist Event Logs:
  Configuration:
    - [ ] Audit Policy configurée (4624, 4625, 4688...)
    - [ ] PowerShell logging activé
    - [ ] Taille des logs augmentée
    - [ ] Rétention définie

  Centralisation:
    - [ ] WEF ou agent SIEM
    - [ ] Logs critiques collectés
    - [ ] Alertes configurées

  Analyse:
    - [ ] Baseline normale documentée
    - [ ] Requêtes de détection prêtes
    - [ ] Revue régulière des événements critiques
```

---

**Voir aussi :**

- [Windows Security](windows-security.md) - Sécurité Windows
- [Performance Monitoring](performance-monitoring.md) - Monitoring
- [PowerShell Remoting](powershell-remoting.md) - Collecte à distance
