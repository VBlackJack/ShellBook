---
tags:
  - windows
  - powershell
  - remoting
  - winrm
---

# PowerShell Remoting

Configuration et utilisation de PowerShell Remoting (WinRM) pour l'administration à distance.

## Architecture

```
POWERSHELL REMOTING ARCHITECTURE
══════════════════════════════════════════════════════════

Client                          Serveur
  │                               │
  │    WS-Management (WinRM)      │
  │  ──────────────────────────►  │
  │      HTTP(S) / 5985-5986      │
  │                               │
  │   ┌─────────────────────┐     │
  │   │  Session PowerShell │     │
  │   │  - Invoke-Command   │     │
  │   │  - Enter-PSSession  │     │
  │   │  - New-PSSession    │     │
  │   └─────────────────────┘     │
```

---

## Configuration WinRM

### Activer le Remoting

```powershell
# Activer WinRM (run as admin)
Enable-PSRemoting -Force

# Ou via winrm
winrm quickconfig

# Ce que fait Enable-PSRemoting :
# 1. Démarre le service WinRM
# 2. Configure le service en démarrage auto
# 3. Crée un listener HTTP sur 5985
# 4. Configure le firewall
# 5. Enregistre les configurations de session

# Vérifier la configuration
Get-PSSessionConfiguration
winrm enumerate winrm/config/listener
```

### Configuration du Listener

```powershell
# Voir les listeners
Get-WSManInstance -ResourceURI winrm/config/listener -Enumerate

# Créer un listener HTTPS
$cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object Subject -like "*$(hostname)*"
New-WSManInstance -ResourceURI winrm/config/listener -SelectorSet @{Transport="HTTPS"; Address="*"} `
    -ValueSet @{CertificateThumbprint=$cert.Thumbprint}

# Supprimer un listener
Remove-WSManInstance -ResourceURI winrm/config/listener -SelectorSet @{Transport="HTTP"; Address="*"}
```

### Configuration Avancée

```powershell
# Voir toute la configuration
winrm get winrm/config

# Augmenter les limites
Set-WSManQuickConfig
Set-Item WSMan:\localhost\Shell\MaxMemoryPerShellMB 1024
Set-Item WSMan:\localhost\Shell\MaxConcurrentUsers 10
Set-Item WSMan:\localhost\MaxTimeoutms 1800000

# Configurer le nombre max de connexions
Set-Item WSMan:\localhost\Service\MaxConnections 100

# TrustedHosts (hors domaine)
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "server01,server02,10.10.1.*"
# Ou tout autoriser (non recommandé)
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*"
```

---

## Utilisation de Base

### Sessions Interactives

```powershell
# Session interactive
Enter-PSSession -ComputerName server01

# Avec credentials
$cred = Get-Credential
Enter-PSSession -ComputerName server01 -Credential $cred

# Session HTTPS
Enter-PSSession -ComputerName server01 -UseSSL

# Quitter la session
Exit-PSSession
```

### Invoke-Command

```powershell
# Exécuter une commande à distance
Invoke-Command -ComputerName server01 -ScriptBlock { Get-Process }

# Plusieurs serveurs
Invoke-Command -ComputerName server01,server02,server03 -ScriptBlock { Get-Service }

# Avec credentials
Invoke-Command -ComputerName server01 -Credential $cred -ScriptBlock { whoami }

# Passer des paramètres
$serviceName = "WinRM"
Invoke-Command -ComputerName server01 -ScriptBlock {
    param($name)
    Get-Service -Name $name
} -ArgumentList $serviceName

# Utiliser $using: (plus simple)
$serviceName = "WinRM"
Invoke-Command -ComputerName server01 -ScriptBlock {
    Get-Service -Name $using:serviceName
}

# Exécuter un script local sur une machine distante
Invoke-Command -ComputerName server01 -FilePath "C:\Scripts\Audit.ps1"
```

### Sessions Persistantes

```powershell
# Créer une session
$session = New-PSSession -ComputerName server01

# Utiliser la session
Invoke-Command -Session $session -ScriptBlock { $var = "test" }
Invoke-Command -Session $session -ScriptBlock { $var }  # Variable persistante

# Sessions multiples
$sessions = New-PSSession -ComputerName server01,server02,server03
Invoke-Command -Session $sessions -ScriptBlock { hostname }

# Copier des fichiers via session
Copy-Item -Path "C:\local\file.txt" -Destination "C:\remote\" -ToSession $session
Copy-Item -Path "C:\remote\file.txt" -Destination "C:\local\" -FromSession $session

# Fermer les sessions
Remove-PSSession -Session $session
Get-PSSession | Remove-PSSession
```

---

## Sessions Disconnected

```powershell
# Créer une session déconnectable
$session = New-PSSession -ComputerName server01 -Name "LongTask"

# Lancer une tâche longue
Invoke-Command -Session $session -ScriptBlock {
    Start-Sleep -Seconds 3600
    Get-Process
} -AsJob

# Déconnecter
Disconnect-PSSession -Session $session

# Reconnecter (depuis n'importe quel poste)
$session = Get-PSSession -ComputerName server01 -Name "LongTask" -State Disconnected
Connect-PSSession -Session $session

# Récupérer les résultats
Receive-PSSession -Session $session
```

---

## Authentification

### Kerberos (Défaut en Domaine)

```powershell
# Authentification Kerberos automatique
Invoke-Command -ComputerName server01.corp.local -ScriptBlock { whoami }

# Vérifier le type d'auth
$session = New-PSSession -ComputerName server01
$session.Runspace.ConnectionInfo.AuthenticationMechanism
```

### CredSSP (Délégation)

```powershell
# Activer CredSSP sur le client
Enable-WSManCredSSP -Role Client -DelegateComputer "server01.corp.local"

# Activer CredSSP sur le serveur
Enable-WSManCredSSP -Role Server

# Utiliser CredSSP (permet double-hop)
$cred = Get-Credential
Invoke-Command -ComputerName server01 -Credential $cred -Authentication CredSSP -ScriptBlock {
    # Peut accéder à d'autres ressources réseau
    Get-ChildItem \\fileserver\share
}

# ⚠️ CredSSP stocke les credentials en mémoire - risque de vol
# Préférer Kerberos constrained delegation ou Resource-Based Constrained Delegation
```

### Certificats

```powershell
# Authentification par certificat
$cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object Subject -like "*admin*"

Invoke-Command -ComputerName server01 -CertificateThumbprint $cert.Thumbprint -ScriptBlock {
    whoami
}
```

---

## JEA (Just Enough Administration)

### Créer une Configuration JEA

```powershell
# Créer le dossier de module
$modulePath = "C:\Program Files\WindowsPowerShell\Modules\JEA-DNSAdmin"
New-Item -Path $modulePath -ItemType Directory
New-Item -Path "$modulePath\RoleCapabilities" -ItemType Directory

# Fichier de capacités de rôle
New-PSRoleCapabilityFile -Path "$modulePath\RoleCapabilities\DNSAdmin.psrc" `
    -VisibleCmdlets @(
        "Get-DnsServer*",
        "Add-DnsServerResourceRecord*",
        "Remove-DnsServerResourceRecord*"
    ) `
    -VisibleFunctions @("Get-Date", "Write-Output") `
    -VisibleExternalCommands @("C:\Windows\System32\nslookup.exe")

# Configuration de session
New-PSSessionConfigurationFile -Path "$modulePath\DNSAdmin.pssc" `
    -SessionType RestrictedRemoteServer `
    -RunAsVirtualAccount `
    -RoleDefinitions @{
        "CORP\DNS-Admins" = @{ RoleCapabilities = "DNSAdmin" }
    } `
    -TranscriptDirectory "C:\Transcripts" `
    -LanguageMode RestrictedLanguage

# Enregistrer la configuration
Register-PSSessionConfiguration -Name "DNSAdmin" -Path "$modulePath\DNSAdmin.pssc" -Force

# Utiliser JEA
Enter-PSSession -ComputerName server01 -ConfigurationName DNSAdmin
```

### Audit JEA

```powershell
# Les transcriptions sont dans C:\Transcripts
Get-ChildItem C:\Transcripts

# Voir les sessions JEA
Get-PSSessionConfiguration | Where-Object { $_.RunAsVirtualAccount }
```

---

## Configuration GPO

### Déploiement WinRM

```
Computer Configuration > Policies > Administrative Templates >
Windows Components > Windows Remote Management (WinRM)

WinRM Client:
  - Trusted Hosts (si nécessaire)

WinRM Service:
  - Allow remote server management through WinRM
  - Specify channel binding token hardening level

Windows Remote Shell:
  - Allow Remote Shell Access
```

### Firewall

```powershell
# Règles firewall requises
New-NetFirewallRule -DisplayName "WinRM HTTP" -Direction Inbound -Protocol TCP -LocalPort 5985 -Action Allow
New-NetFirewallRule -DisplayName "WinRM HTTPS" -Direction Inbound -Protocol TCP -LocalPort 5986 -Action Allow

# Ou activer le groupe prédéfini
Enable-NetFirewallRule -DisplayGroup "Windows Remote Management"
```

---

## Troubleshooting

### Diagnostics

```powershell
# Tester la connectivité WinRM
Test-WSMan -ComputerName server01

# Test avec authentification
Test-WSMan -ComputerName server01 -Authentication Negotiate -Credential $cred

# Voir les erreurs détaillées
$DebugPreference = "Continue"
Enter-PSSession -ComputerName server01

# Logs WinRM
Get-WinEvent -LogName "Microsoft-Windows-WinRM/Operational" -MaxEvents 50

# Vérifier le service
Get-Service WinRM
Get-Service WinRM -ComputerName server01
```

### Erreurs Courantes

```powershell
# "Access Denied"
# → Vérifier les permissions et le groupe Remote Management Users
Get-LocalGroupMember -Group "Remote Management Users"

# "WinRM cannot complete the operation"
# → Vérifier TrustedHosts (hors domaine)
Get-Item WSMan:\localhost\Client\TrustedHosts

# "The WinRM client cannot process the request"
# → Vérifier le firewall
Test-NetConnection -ComputerName server01 -Port 5985

# Kerberos double-hop
# → Utiliser CredSSP ou configurer delegation
```

---

## Bonnes Pratiques

```yaml
Checklist Remoting:
  Sécurité:
    - [ ] HTTPS en production si possible
    - [ ] Éviter TrustedHosts = "*"
    - [ ] Préférer Kerberos à CredSSP
    - [ ] Utiliser JEA pour limiter les droits
    - [ ] Activer la transcription

  Performance:
    - [ ] Sessions persistantes pour tâches répétées
    - [ ] Parallélisation avec -ThrottleLimit
    - [ ] Fan-out raisonnable (pas 1000 serveurs en parallèle)

  Opérations:
    - [ ] Tester sur un serveur avant déploiement
    - [ ] Capturer les erreurs avec -ErrorAction
    - [ ] Logging des actions administratives
```

---

**Voir aussi :**

- [PowerShell DSC](powershell-dsc.md) - Desired State Configuration
- [Event Logs](event-logs.md) - Audit des actions
- [Windows Security](windows-security.md) - Sécurité Windows
