---
tags:
  - formation
  - windows
  - securite
  - hardening
  - services
---

# Module 2 : Services & Protocoles

## Objectifs du Module

- Identifier et désactiver les services non nécessaires
- Sécuriser SMB, RDP et WinRM
- Configurer les protocoles d'authentification
- Durcir PowerShell et les scripts

**Durée :** 2 heures

---

## 1. Audit des Services

### 1.1 Services à Désactiver

```powershell
# Services généralement inutiles sur un serveur
$ServicesToDisable = @(
    "RemoteRegistry",      # Accès distant au registre
    "Fax",                 # Service de fax
    "XblAuthManager",      # Xbox Live
    "XblGameSave",         # Xbox Live
    "XboxGipSvc",          # Xbox Gamepad
    "XboxNetApiSvc",       # Xbox Live Networking
    "WMPNetworkSvc",       # Windows Media Player Sharing
    "icssvc",              # Windows Mobile Hotspot
    "WSearch",             # Windows Search (si non utilisé)
    "DiagTrack",           # Telemetry (Connected User Experience)
    "dmwappushservice",    # WAP Push
    "MapsBroker",          # Downloaded Maps Manager
    "lfsvc",               # Geolocation
    "SharedAccess"         # Internet Connection Sharing
)

# Vérifier l'état actuel
foreach ($svc in $ServicesToDisable) {
    $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($service) {
        Write-Host "$svc : $($service.Status) - $($service.StartType)"
    }
}
```

### 1.2 Script de Désactivation

```powershell
# disable-services.ps1
param(
    [switch]$WhatIf,
    [switch]$Force
)

$ServicesToDisable = @(
    "RemoteRegistry",
    "Fax",
    "XblAuthManager",
    "XblGameSave",
    "XboxGipSvc",
    "XboxNetApiSvc"
)

foreach ($svc in $ServicesToDisable) {
    $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($service) {
        if ($WhatIf) {
            Write-Host "[WHATIF] Would disable: $svc"
        } else {
            try {
                Stop-Service -Name $svc -Force -ErrorAction Stop
                Set-Service -Name $svc -StartupType Disabled
                Write-Host "[OK] Disabled: $svc" -ForegroundColor Green
            } catch {
                Write-Host "[ERROR] $svc : $_" -ForegroundColor Red
            }
        }
    }
}
```

### 1.3 Services Critiques à Protéger

```powershell
# Services à NE PAS désactiver
$CriticalServices = @(
    "EventLog",            # Journalisation
    "W3SVC",               # IIS (si serveur web)
    "MSSQLSERVER",         # SQL Server (si BDD)
    "DNS",                 # DNS Server
    "Netlogon",            # Authentification AD
    "NTDS",                # AD Domain Services
    "Dnscache",            # DNS Client
    "LanmanWorkstation",   # SMB Client
    "LanmanServer",        # SMB Server
    "CryptSvc",            # Cryptographic Services
    "WinRM"                # Windows Remote Management
)

# Vérifier qu'ils tournent
foreach ($svc in $CriticalServices) {
    $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($service -and $service.Status -ne "Running") {
        Write-Warning "$svc is not running!"
    }
}
```

---

## 2. Sécurisation SMB

### 2.1 Désactiver SMBv1

```powershell
# Vérifier l'état de SMBv1
Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol

# Désactiver SMBv1 (recommandé)
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart

# Alternative via registre
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -Value 0 -Type DWord

# Vérifier côté serveur
Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol, EnableSMB2Protocol
```

### 2.2 Configurer SMB Signing et Encryption

```powershell
# Activer la signature SMB (obligatoire)
Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
Set-SmbServerConfiguration -EnableSecuritySignature $true -Force

# Activer le chiffrement SMB 3.0
Set-SmbServerConfiguration -EncryptData $true -Force

# Rejeter les connexions non chiffrées (strict)
Set-SmbServerConfiguration -RejectUnencryptedAccess $true -Force

# Vérifier la configuration
Get-SmbServerConfiguration | Select-Object `
    EnableSMB1Protocol,
    EnableSMB2Protocol,
    RequireSecuritySignature,
    EnableSecuritySignature,
    EncryptData,
    RejectUnencryptedAccess
```

### 2.3 Restreindre les Partages

```powershell
# Lister les partages
Get-SmbShare

# Supprimer les partages inutiles
Remove-SmbShare -Name "ShareName" -Force

# Désactiver les partages administratifs (attention!)
# Non recommandé sur DC, mais possible sur postes
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AutoShareWks" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AutoShareServer" -Value 0 -Type DWord
```

---

## 3. Sécurisation RDP

### 3.1 Network Level Authentication (NLA)

```powershell
# Activer NLA
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name "UserAuthentication" -Value 1

# Via GPO (recommandé)
# Computer Configuration > Administrative Templates > Windows Components >
# Remote Desktop Services > Remote Desktop Session Host > Security
# "Require user authentication for remote connections by using NLA" = Enabled

# Vérifier
(Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp').UserAuthentication
```

### 3.2 Niveau de Chiffrement

```powershell
# Configurer le niveau de sécurité
# 0 = RDP Security Layer
# 1 = Negotiate
# 2 = SSL (TLS 1.0) - Recommandé minimum

Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name "SecurityLayer" -Value 2

# Niveau de chiffrement
# 1 = Low
# 2 = Client Compatible
# 3 = High
# 4 = FIPS Compliant

Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name "MinEncryptionLevel" -Value 3
```

### 3.3 Restreindre l'Accès RDP

```powershell
# Lister les utilisateurs autorisés
Get-LocalGroupMember -Group "Remote Desktop Users"

# Ajouter/Retirer des utilisateurs
Add-LocalGroupMember -Group "Remote Desktop Users" -Member "DOMAIN\AdminGroup"
Remove-LocalGroupMember -Group "Remote Desktop Users" -Member "DOMAIN\User"

# Timeout de session (via GPO ou registre)
# Déconnecter les sessions inactives après 15 minutes
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name "MaxIdleTime" -Value 900000 -Type DWord

# Timeout de session déconnectée
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name "MaxDisconnectionTime" -Value 60000 -Type DWord
```

---

## 4. Sécurisation WinRM

### 4.1 Configuration HTTPS

```powershell
# Vérifier la configuration actuelle
winrm get winrm/config

# Créer un certificat auto-signé (dev/test uniquement)
$cert = New-SelfSignedCertificate -DnsName $env:COMPUTERNAME -CertStoreLocation Cert:\LocalMachine\My

# Configurer le listener HTTPS
winrm create winrm/config/Listener?Address=*+Transport=HTTPS "@{Hostname=`"$env:COMPUTERNAME`";CertificateThumbprint=`"$($cert.Thumbprint)`"}"

# Supprimer le listener HTTP (production)
winrm delete winrm/config/Listener?Address=*+Transport=HTTP

# Vérifier les listeners
winrm enumerate winrm/config/Listener
```

### 4.2 Restreindre WinRM

```powershell
# Activer WinRM uniquement pour certaines IPs
Set-Item WSMan:\localhost\Service\IPv4Filter -Value "192.168.1.0/24,10.0.0.0/8"

# Désactiver l'authentification Basic
Set-Item WSMan:\localhost\Service\Auth\Basic -Value $false

# Activer uniquement Kerberos (environnement AD)
Set-Item WSMan:\localhost\Service\Auth\Kerberos -Value $true
Set-Item WSMan:\localhost\Service\Auth\Negotiate -Value $true

# Désactiver l'exécution non chiffrée
Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $false
```

---

## 5. Sécurisation PowerShell

### 5.1 Execution Policy

```powershell
# Vérifier la politique actuelle
Get-ExecutionPolicy -List

# Configurer (recommandé: AllSigned ou RemoteSigned)
Set-ExecutionPolicy -ExecutionPolicy AllSigned -Scope LocalMachine

# Politique par scope
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### 5.2 Constrained Language Mode

```powershell
# Vérifier le mode actuel
$ExecutionContext.SessionState.LanguageMode

# Forcer le Constrained Language Mode via AppLocker ou WDAC
# Crée un fichier __PSLockdownPolicy dans System32

# Alternative : variable d'environnement (moins sécurisé)
[Environment]::SetEnvironmentVariable('__PSLockdownPolicy', '4', 'Machine')
```

### 5.3 Logging PowerShell

```powershell
# Activer le Module Logging
$BasePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
New-Item -Path $BasePath -Force
Set-ItemProperty -Path $BasePath -Name "EnableModuleLogging" -Value 1
New-Item -Path "$BasePath\ModuleNames" -Force
Set-ItemProperty -Path "$BasePath\ModuleNames" -Name "*" -Value "*"

# Activer le Script Block Logging
$SBPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
New-Item -Path $SBPath -Force
Set-ItemProperty -Path $SBPath -Name "EnableScriptBlockLogging" -Value 1
Set-ItemProperty -Path $SBPath -Name "EnableScriptBlockInvocationLogging" -Value 1

# Activer Transcription
$TransPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
New-Item -Path $TransPath -Force
Set-ItemProperty -Path $TransPath -Name "EnableTranscripting" -Value 1
Set-ItemProperty -Path $TransPath -Name "OutputDirectory" -Value "C:\PSLogs"
Set-ItemProperty -Path $TransPath -Name "EnableInvocationHeader" -Value 1
```

---

## 6. Protocoles d'Authentification

### 6.1 Désactiver NTLM (si possible)

```powershell
# Auditer l'utilisation de NTLM d'abord
# GPO: Computer Configuration > Windows Settings > Security Settings >
#      Local Policies > Security Options
# "Network security: Restrict NTLM: Audit NTLM authentication in this domain"

# Registre pour logging NTLM
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "AuditReceivingNTLMTraffic" -Value 1

# Vérifier les logs
Get-WinEvent -LogName "Microsoft-Windows-NTLM/Operational" -MaxEvents 100
```

### 6.2 Configurer Kerberos

```powershell
# Forcer le chiffrement AES pour Kerberos
# GPO: Computer Configuration > Windows Settings > Security Settings >
#      Local Policies > Security Options
# "Network security: Configure encryption types allowed for Kerberos"

# Via registre
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" -Name "SupportedEncryptionTypes" -Value 0x18 -Type DWord
# 0x18 = AES128 + AES256 uniquement
```

---

## 7. Exercice : À Vous de Jouer

!!! example "Mise en Pratique : Sécuriser Services et Protocoles"
    **Objectif** : Auditer et sécuriser les services et protocoles d'un serveur Windows.

    **Contexte** : Votre serveur de fichiers expose des services obsolètes détectés lors d'un audit de sécurité.

    **Tâches à réaliser** :

    1. Auditer et désactiver les services inutiles (Fax, XPS, Print Spooler si non utilisé)
    2. Désactiver SMBv1 et activer le signing/encryption SMB
    3. Configurer NLA et le chiffrement TLS 1.2+ pour RDP
    4. Activer le logging PowerShell complet (ScriptBlock + Module)

    **Critères de validation** :

    - [ ] SMBv1 désactivé
    - [ ] SMB Signing activé
    - [ ] NLA activé pour RDP
    - [ ] PowerShell logging activé

??? quote "Solution"
    ```powershell
    # 1. Désactiver les services inutiles
    $ServicesToDisable = @("Fax", "XblGameSave", "XblAuthManager")
    foreach ($Service in $ServicesToDisable) {
        Stop-Service -Name $Service -Force -ErrorAction SilentlyContinue
        Set-Service -Name $Service -StartupType Disabled -ErrorAction SilentlyContinue
    }

    # 2. Désactiver SMBv1 et activer signing
    Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
    Set-SmbServerConfiguration -RequireSecuritySignature $true -EnableSecuritySignature $true -Force

    # 3. Configurer NLA pour RDP
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name "UserAuthentication" -Value 1

    # 4. Activer PowerShell logging
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1
    ```

    **Script de vérification** :

    ```powershell
    $Checks = @()

    # SMBv1
    $SMB1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
    $Checks += [PSCustomObject]@{ Check = "SMBv1 Disabled"; Status = if ($SMB1.State -eq "Disabled") { "PASS" } else { "FAIL" } }

    # SMB Signing
    $SMBConfig = Get-SmbServerConfiguration
    $Checks += [PSCustomObject]@{ Check = "SMB Signing Required"; Status = if ($SMBConfig.RequireSecuritySignature) { "PASS" } else { "FAIL" } }

    # NLA
    $NLA = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp').UserAuthentication
    $Checks += [PSCustomObject]@{ Check = "RDP NLA Enabled"; Status = if ($NLA -eq 1) { "PASS" } else { "FAIL" } }

    $Checks | Format-Table -AutoSize
    ```

---

## Quiz

1. **Pourquoi désactiver SMBv1 ?**
   - [ ] A. Il est plus lent
   - [ ] B. Vulnérabilités critiques (EternalBlue, WannaCry)
   - [ ] C. Il consomme trop de mémoire

2. **Que fait NLA pour RDP ?**
   - [ ] A. Chiffre la connexion
   - [ ] B. Authentifie avant d'établir la session
   - [ ] C. Compresse les données

**Réponses :** 1-B, 2-B

---

**Précédent :** [Module 1 - Security Baselines](01-module.md)

**Suivant :** [Module 3 - Réseau & Firewall](03-module.md)
