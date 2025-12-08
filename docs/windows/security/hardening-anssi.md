---
tags:
  - hardening
  - gpo
  - anssi
  - secnumcloud
  - audit
  - logging
---

# Hardening ANSSI & Audit

GPO de sécurité, Event Viewer et conformité SecNumCloud.

---

## GPO Hardening (SecNumCloud)

### Désactiver LLMNR et NBT-NS

**Problème :** LLMNR et NBT-NS sont des protocoles de résolution de noms legacy qui permettent le poisoning (attaque Responder).

```
┌─────────────────────────────────────────────────────────────┐
│                  ATTAQUE RESPONDER                           │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  1. Victime cherche \\fileserver (typo, serveur down)       │
│  2. Broadcast LLMNR/NBT-NS sur le réseau                    │
│  3. Attaquant répond "C'est moi fileserver !"               │
│  4. Victime envoie son hash NTLMv2 à l'attaquant            │
│  5. Attaquant casse le hash offline (Hashcat)               │
│  6. Attaquant récupère le mot de passe en clair             │
│                                                              │
│  Solution : Désactiver LLMNR/NBT-NS via GPO                 │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

**GPO : Désactiver LLMNR**

```
GPO Path: Computer Configuration → Policies → Administrative Templates
          → Network → DNS Client

Paramètre :
└── Turn off multicast name resolution → Enabled
```

**GPO : Désactiver NBT-NS**

```
GPO Path: Computer Configuration → Preferences → Windows Settings
          → Registry

Créer une nouvelle clé :
└── Action: Update
    Hive: HKEY_LOCAL_MACHINE
    Key Path: SYSTEM\CurrentControlSet\Services\NetBT\Parameters
    Value Name: NodeType
    Value Type: REG_DWORD
    Value Data: 2
```

**Via PowerShell (sans GPO) :**

```powershell
# Désactiver LLMNR
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
    -Name "EnableMulticast" -Value 0 -Type DWord

# Désactiver NBT-NS sur toutes les interfaces
$Adapters = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.TcpipNetbiosOptions -ne $null }
foreach ($Adapter in $Adapters) {
    $Adapter.SetTcpipNetbios(2)  # 2 = Disable
}

# Vérifier
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast"
Get-WmiObject Win32_NetworkAdapterConfiguration | Select-Object Description, TcpipNetbiosOptions
```

---

### Désactiver SMBv1 (WannaCry Legacy)

**Problème :** SMBv1 est un protocole obsolète avec de nombreuses vulnérabilités (EternalBlue, WannaCry, NotPetya).

```
┌─────────────────────────────────────────────────────────────┐
│                  POURQUOI DÉSACTIVER SMBv1 ?                 │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ✗ Vulnérabilités critiques (EternalBlue/MS17-010)          │
│  ✗ Pas de chiffrement                                       │
│  ✗ Pas d'authentification forte                             │
│  ✗ Performance inférieure                                   │
│                                                              │
│  ✓ SMBv2/v3 sont sécurisés et performants                   │
│  ✓ SMBv3 supporte le chiffrement AES-CCM/AES-GCM            │
│                                                              │
│  SecNumCloud : SMBv1 DOIT être désactivé                    │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

**Via PowerShell :**

```powershell
# Vérifier l'état SMBv1
Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol

# Désactiver SMBv1 (Client + Serveur)
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart

# Ou via DISM
dism /online /Disable-Feature /FeatureName:SMB1Protocol /NoRestart

# Vérifier la configuration
Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol

# Output attendu :
# EnableSMB1Protocol
# ------------------
# False

# Audit des connexions SMB (pour détecter des clients legacy)
Get-SmbConnection | Select-Object ServerName, Dialect, UserName
```

---

### Forcer AES-256 pour Kerberos

**Windows supporte encore RC4 par défaut, qui est faible. Forcer AES-256.**

```powershell
# Forcer AES-256 pour Kerberos (désactiver RC4 et DES)
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" -Force | Out-Null

Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" `
    -Name "SupportedEncryptionTypes" -Value 0x18 -Type DWord

# Valeurs :
# 0x1  = DES-CBC-CRC (OBSOLÈTE)
# 0x2  = DES-CBC-MD5 (OBSOLÈTE)
# 0x4  = RC4-HMAC (FAIBLE)
# 0x8  = AES128-CTS-HMAC-SHA1-96
# 0x10 = AES256-CTS-HMAC-SHA1-96
# 0x18 = AES128 + AES256 (RECOMMANDÉ)
```

**GPO :**

```
GPO Path: Computer Configuration → Policies → Windows Settings
          → Security Settings → Local Policies → Security Options

Paramètre :
└── Network security: Configure encryption types allowed for Kerberos
    ✅ AES128_HMAC_SHA1
    ✅ AES256_HMAC_SHA1
    ❌ DES_CBC_CRC
    ❌ DES_CBC_MD5
    ❌ RC4_HMAC_MD5
```

---

### Désactiver TLS 1.0 et TLS 1.1

**TLS 1.0/1.1 sont obsolètes et vulnérables (BEAST, POODLE). Forcer TLS 1.2/1.3.**

```powershell
# Désactiver TLS 1.0/1.1, Activer TLS 1.2
$protocols = @(
    @{Version = "TLS 1.0"; Enabled = 0},
    @{Version = "TLS 1.1"; Enabled = 0},
    @{Version = "TLS 1.2"; Enabled = 1}
)

foreach ($p in $protocols) {
    $basePath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$($p.Version)"

    foreach ($role in @("Server", "Client")) {
        New-Item -Path "$basePath\$role" -Force | Out-Null
        Set-ItemProperty -Path "$basePath\$role" -Name "Enabled" -Value $p.Enabled -Type DWord
        Set-ItemProperty -Path "$basePath\$role" -Name "DisabledByDefault" -Value ([int]!$p.Enabled) -Type DWord
    }
}

Write-Host "[+] TLS 1.0/1.1 désactivés, TLS 1.2 activé" -ForegroundColor Green
```

**Tester TLS après redémarrage :**

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri "https://www.howsmyssl.com/a/check" | Select-Object -ExpandProperty Content | ConvertFrom-Json
```

---

## Event Viewer & Audit

### Get-WinEvent (Moderne et Rapide)

```powershell
# Logs disponibles
Get-WinEvent -ListLog * | Select-Object LogName, RecordCount

# Logs Security (les 100 derniers)
Get-WinEvent -LogName Security -MaxEvents 100

# Filtrer par ID d'événement
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4624
} -MaxEvents 50
```

!!! tip "Get-WinEvent vs Get-EventLog"
    `Get-WinEvent` est plus rapide et supporte les logs modernes (EVTX).
    `Get-EventLog` est obsolète mais encore présent.

### IDs d'Événements Critiques (Security)

| Event ID | Description | Criticité |
|----------|-------------|-----------|
| **4624** | Logon Success | Info |
| **4625** | Logon Failed | Attention (bruteforce) |
| **4634** | Logoff | Info |
| **4648** | Explicit Logon (RunAs) | Attention |
| **4672** | Special Privileges Assigned | Audit privilèges |
| **4688** | Process Created | Forensic (avec cmdline) |
| **4720** | User Account Created | Audit |
| **4722** | User Account Enabled | Audit |
| **4725** | User Account Disabled | Audit |
| **4726** | User Account Deleted | Audit |
| **4728** | Member Added to Security Group | Audit |
| **4732** | Member Added to Local Group | Audit |

### Requêtes d'Audit

```powershell
# Échecs de connexion (bruteforce detection)
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4625
    StartTime = (Get-Date).AddHours(-24)
} | Select-Object TimeCreated,
    @{N='User';E={$_.Properties[5].Value}},
    @{N='SourceIP';E={$_.Properties[19].Value}}

# Connexions réussies
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4624
    StartTime = (Get-Date).AddHours(-1)
} | Select-Object TimeCreated,
    @{N='User';E={$_.Properties[5].Value}},
    @{N='LogonType';E={$_.Properties[8].Value}}

# Comptes créés
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4720
} | Select-Object TimeCreated,
    @{N='NewUser';E={$_.Properties[0].Value}},
    @{N='CreatedBy';E={$_.Properties[4].Value}}
```

### Logon Types

| Type | Description |
|------|-------------|
| 2 | Interactive (console) |
| 3 | Network (partage, WinRM) |
| 4 | Batch (tâche planifiée) |
| 5 | Service |
| 7 | Unlock |
| 10 | RemoteInteractive (RDP) |
| 11 | CachedInteractive |

```powershell
# Connexions RDP (Type 10)
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4624
} -MaxEvents 1000 | Where-Object {
    $_.Properties[8].Value -eq 10
} | Select-Object TimeCreated,
    @{N='User';E={$_.Properties[5].Value}},
    @{N='SourceIP';E={$_.Properties[18].Value}}
```

### Audit Process Creation (Event ID 4688)

**Event ID 4688 = Création de processus avec ligne de commande complète.**

```powershell
# Activer l'audit de création de processus
auditpol /set /subcategory:"Process Creation" /success:enable

# Activer la capture de la ligne de commande
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
    -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord

# Vérifier la configuration
auditpol /get /category:"Detailed Tracking"
```

**GPO :**

```
GPO Path 1: Computer Configuration → Policies → Windows Settings
            → Security Settings → Advanced Audit Policy Configuration
            → System Audit Policies → Detailed Tracking

Paramètre :
└── Audit Process Creation → ✅ Success

GPO Path 2: Computer Configuration → Policies → Administrative Templates
            → System → Audit Process Creation

Paramètre :
└── Include command line in process creation events → ✅ Enabled
```

!!! warning "Attention : Volumétrie des Logs"
    L'activation de tous ces audits génère **beaucoup de logs** (plusieurs GB/jour sur serveurs actifs).

    ```powershell
    # Augmenter la taille du log Security à 1 GB
    wevtutil sl Security /ms:1073741824
    ```

---

## Surface d'Attaque : Services à Désactiver

```powershell
# Services à désactiver sur un serveur (baseline ANSSI)

# Print Spooler (vecteur d'attaque PrintNightmare)
Stop-Service -Name Spooler -Force
Set-Service -Name Spooler -StartupType Disabled

# Xbox Services (inutile sur un serveur)
Get-Service -Name "Xbox*" | Stop-Service -Force
Get-Service -Name "Xbox*" | Set-Service -StartupType Disabled

# Bluetooth (inutile sur serveur datacenter)
Stop-Service -Name "bthserv" -Force
Set-Service -Name "bthserv" -StartupType Disabled

# Remote Registry (accès distant au registre = risque)
Stop-Service -Name "RemoteRegistry" -Force
Set-Service -Name "RemoteRegistry" -StartupType Disabled

# Vérifier l'état
$servicesToDisable = @("Spooler", "bthserv", "RemoteRegistry")
Get-Service -Name $servicesToDisable -ErrorAction SilentlyContinue |
    Select-Object Name, Status, StartType
```

!!! tip "Services Critiques à NE PAS Désactiver"
    **Ne JAMAIS désactiver :**
    - `DNS Client` (dnscache) - Résolution DNS
    - `Netlogon` - Authentification domaine
    - `Windows Time` (W32Time) - Synchronisation horaire (critique pour Kerberos)
    - `Windows Defender Antivirus Service` (WinDefend)
    - `Windows Event Log` (EventLog)

---

## Session : Timeouts RDP

**Éviter les sessions RDP ouvertes indéfiniment (risque de hijacking).**

```powershell
# Déconnexion automatique après 15 minutes d'inactivité
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
    -Name "MaxIdleTime" -Value 900000 -Type DWord  # 15 min en ms

# Déconnexion automatique après 2 heures de session totale
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
    -Name "MaxConnectionTime" -Value 7200000 -Type DWord  # 2 heures en ms

# Déconnexion automatique des sessions déconnectées après 5 minutes
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
    -Name "MaxDisconnectionTime" -Value 300000 -Type DWord  # 5 min en ms
```

---

## Checklist Complète ANSSI

| Catégorie | Action | Commande/GPO | Priorité |
|-----------|--------|--------------|----------|
| **Services** | Désactiver Print Spooler | `Set-Service Spooler -StartupType Disabled` | 🔴 Critique |
| **Services** | Désactiver Remote Registry | `Set-Service RemoteRegistry -StartupType Disabled` | 🔴 Critique |
| **Protocoles** | Désactiver SMBv1 | `Disable-WindowsOptionalFeature -FeatureName SMB1Protocol` | 🔴 Critique |
| **Protocoles** | Désactiver LLMNR | Clé registre `EnableMulticast=0` | 🔴 Critique |
| **Protocoles** | Désactiver NBT-NS | `SetTcpipNetbios(2)` | 🔴 Critique |
| **Chiffrement** | Forcer AES-256 Kerberos | GPO "Configure encryption types" | 🟠 Important |
| **Chiffrement** | Désactiver TLS 1.0/1.1 | Clés registre SCHANNEL | 🟠 Important |
| **Audit** | Activer Event ID 4688 | `auditpol /set /subcategory:"Process Creation"` | 🟠 Important |
| **Session** | Déconnexion auto RDP 15min | GPO "Session Time Limits" | 🟡 Recommandé |
| **Tâches** | Désactiver télémétrie | `Disable-ScheduledTask` | 🟡 Recommandé |

---

## Script PowerShell d'Application Automatique

```powershell
# ============================================================
# Script de Hardening ANSSI - Windows Server
# Compatible : Server 2019, 2022, 2025
# ============================================================

Write-Host "[+] Début du hardening ANSSI..." -ForegroundColor Green

# 1. Désactiver services inutiles
Write-Host "[*] Désactivation des services..." -ForegroundColor Yellow
$servicesToDisable = @("Spooler", "RemoteRegistry", "bthserv")
foreach ($svc in $servicesToDisable) {
    Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
    Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue
    Write-Host "    [OK] $svc désactivé" -ForegroundColor Green
}

# 2. Désactiver SMBv1
Write-Host "[*] Désactivation de SMBv1..." -ForegroundColor Yellow
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue
Write-Host "    [OK] SMBv1 désactivé" -ForegroundColor Green

# 3. Désactiver LLMNR
Write-Host "[*] Désactivation de LLMNR..." -ForegroundColor Yellow
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0
Write-Host "    [OK] LLMNR désactivé" -ForegroundColor Green

# 4. Désactiver NBT-NS
Write-Host "[*] Désactivation de NBT-NS..." -ForegroundColor Yellow
$Adapters = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.TcpipNetbiosOptions -ne $null }
foreach ($Adapter in $Adapters) {
    $Adapter.SetTcpipNetbios(2) | Out-Null
}
Write-Host "    [OK] NBT-NS désactivé" -ForegroundColor Green

# 5. Forcer AES-256 Kerberos
Write-Host "[*] Configuration Kerberos AES-256..." -ForegroundColor Yellow
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" -Name "SupportedEncryptionTypes" -Value 0x18
Write-Host "    [OK] Kerberos AES-256 activé" -ForegroundColor Green

# 6. Désactiver TLS 1.0/1.1
Write-Host "[*] Désactivation TLS 1.0/1.1..." -ForegroundColor Yellow
foreach ($version in @("TLS 1.0", "TLS 1.1")) {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$version\Server" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$version\Server" -Name "Enabled" -Value 0
}
Write-Host "    [OK] TLS 1.0/1.1 désactivés" -ForegroundColor Green

# 7. Activer audit Process Creation
Write-Host "[*] Activation Event ID 4688..." -ForegroundColor Yellow
auditpol /set /subcategory:"Process Creation" /success:enable | Out-Null
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1
Write-Host "    [OK] Event ID 4688 activé" -ForegroundColor Green

# 8. Configurer timeouts RDP
Write-Host "[*] Configuration timeouts RDP..." -ForegroundColor Yellow
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "MaxIdleTime" -Value 900000
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "MaxDisconnectionTime" -Value 300000
Write-Host "    [OK] Timeouts RDP configurés" -ForegroundColor Green

Write-Host "[+] Hardening ANSSI terminé avec succès !" -ForegroundColor Green
Write-Host "[!] REDÉMARRAGE REQUIS pour appliquer tous les changements" -ForegroundColor Red
```

---

!!! info "À lire aussi"
    - [Firewall & Defender](firewall-defender.md) - Protection périmétrique
    - [LAPS](laps.md) - Rotation des mots de passe Admin
    - [BitLocker](bitlocker.md) - Chiffrement disque
