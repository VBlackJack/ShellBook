# Windows Hardening & Security

`#defender` `#firewall` `#bitlocker` `#laps` `#gpo` `#secnumcloud` `#logging`

Sécurisation et audit des systèmes Windows (Blue Team) : LAPS, GPO Hardening, BitLocker avancé.

---

## Windows Firewall (NetSecurity)

### Profils Firewall

| Profil | Description | Quand actif |
|--------|-------------|-------------|
| **Domain** | Réseau d'entreprise | Connecté à un domaine AD |
| **Private** | Réseau de confiance | Réseau marqué "Privé" |
| **Public** | Réseau non fiable | WiFi public, par défaut |

```powershell
# État des profils
Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction

# Configurer la politique par défaut (RECOMMANDÉ)
Set-NetFirewallProfile -Profile Domain,Private,Public `
    -DefaultInboundAction Block `
    -DefaultOutboundAction Allow `
    -Enabled True
```

### Gestion des Règles

```powershell
# Lister toutes les règles
Get-NetFirewallRule

# Règles actives entrantes
Get-NetFirewallRule -Direction Inbound -Enabled True |
    Select-Object Name, DisplayName, Action

# Rechercher une règle par nom
Get-NetFirewallRule -DisplayName "*Remote Desktop*"

# Détails complets d'une règle (avec ports)
Get-NetFirewallRule -DisplayName "Remote Desktop*" |
    Get-NetFirewallPortFilter
```

### Créer des Règles

```powershell
# Autoriser un port entrant (ex: SSH)
New-NetFirewallRule `
    -DisplayName "Allow SSH" `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort 22 `
    -Action Allow `
    -Profile Domain,Private

# Autoriser une application
New-NetFirewallRule `
    -DisplayName "Allow MyApp" `
    -Direction Inbound `
    -Program "C:\Program Files\MyApp\app.exe" `
    -Action Allow

# Bloquer une IP spécifique
New-NetFirewallRule `
    -DisplayName "Block Malicious IP" `
    -Direction Inbound `
    -RemoteAddress "1.2.3.4" `
    -Action Block

# Autoriser un sous-réseau
New-NetFirewallRule `
    -DisplayName "Allow LAN" `
    -Direction Inbound `
    -RemoteAddress "192.168.1.0/24" `
    -Action Allow

# Autoriser une plage de ports
New-NetFirewallRule `
    -DisplayName "Allow High Ports" `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort 49152-65535 `
    -Action Allow
```

### Modifier / Supprimer

```powershell
# Désactiver une règle
Disable-NetFirewallRule -DisplayName "Allow SSH"

# Activer une règle
Enable-NetFirewallRule -DisplayName "Allow SSH"

# Supprimer une règle
Remove-NetFirewallRule -DisplayName "Allow SSH"

# Modifier une règle
Set-NetFirewallRule -DisplayName "Allow SSH" -LocalPort 2222
```

---

## Windows Defender

### État et Informations

```powershell
# État complet de Defender
Get-MpComputerStatus

# Propriétés importantes
Get-MpComputerStatus | Select-Object `
    AntivirusEnabled,
    RealTimeProtectionEnabled,
    AntivirusSignatureLastUpdated,
    QuickScanAge,
    FullScanAge

# Préférences actuelles
Get-MpPreference
```

### Scans

```powershell
# Scan rapide
Start-MpScan -ScanType QuickScan

# Scan complet
Start-MpScan -ScanType FullScan

# Scan d'un chemin spécifique
Start-MpScan -ScanPath "C:\Users\Public\Downloads"

# Mettre à jour les signatures
Update-MpSignature
```

### Gestion des Exclusions

!!! warning "Exclusions : À utiliser avec parcimonie"
    Chaque exclusion est une brèche potentielle. Documenter et justifier chaque exclusion.

```powershell
# Voir les exclusions actuelles
Get-MpPreference | Select-Object -ExpandProperty ExclusionPath
Get-MpPreference | Select-Object -ExpandProperty ExclusionProcess
Get-MpPreference | Select-Object -ExpandProperty ExclusionExtension

# Ajouter une exclusion de chemin
Add-MpPreference -ExclusionPath "C:\DevTools"

# Ajouter une exclusion de processus
Add-MpPreference -ExclusionProcess "devenv.exe"

# Ajouter une exclusion d'extension
Add-MpPreference -ExclusionExtension ".log"

# Supprimer une exclusion
Remove-MpPreference -ExclusionPath "C:\DevTools"
```

### Menaces Détectées

```powershell
# Historique des menaces
Get-MpThreatDetection

# Détails des menaces
Get-MpThreat

# Supprimer les menaces actives
Remove-MpThreat
```

---

## Windows LAPS (Local Admin Password Solution)

### Qu'est-ce que LAPS ?

**LAPS = Rotation automatique du mot de passe Administrateur local stocké dans l'Active Directory**

```
┌─────────────────────────────────────────────────────────────┐
│                     LE PROBLÈME                              │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Scénario classique (BAD PRACTICE) :                        │
│  ────────────────────────────────────                        │
│  1. Installation Windows avec Admin local "Password123!"    │
│  2. Même mot de passe sur TOUS les serveurs/postes          │
│  3. Un attaquant compromet un poste                         │
│  4. Il utilise Pass-the-Hash pour accéder à TOUS            │
│     les autres postes avec le même Admin local              │
│                                                              │
│  Résultat : Mouvement latéral trivial                       │
│                                                              │
├─────────────────────────────────────────────────────────────┤
│                     LA SOLUTION : LAPS                       │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  1. LAPS génère un mot de passe aléatoire unique par PC     │
│  2. Le mot de passe est stocké dans l'AD (attribut)         │
│  3. Rotation automatique tous les X jours                   │
│  4. Seuls les admins AD peuvent lire le mot de passe        │
│                                                              │
│  Résultat : Chaque machine a un mot de passe unique         │
│             → Mouvement latéral bloqué                      │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Distinction Version : Legacy vs Natif

| Aspect | Legacy LAPS (2019/2022) | Windows LAPS (Natif 2025+) |
|--------|-------------------------|---------------------------|
| **Disponibilité** | Agent MSI à installer | Intégré dans l'OS |
| **Extension schéma AD** | Requise (admpwd.dll) | Requise (nouveau schéma) |
| **Attributs AD** | `ms-Mcs-AdmPwd` (texte clair) | `msLAPS-Password` (chiffré) |
| **Cmdlets PowerShell** | Module AdmPwd.PS | Module Windows LAPS (natif) |
| **Chiffrement** | Non (stockage texte clair dans AD) | Oui (AES 256, chiffré dans AD) |
| **Azure AD Support** | Non | Oui (Azure AD Join) |
| **Compte géré** | Administrateur local uniquement | Admin + autres comptes |
| **Historique** | Non | Oui (rotation trackée) |

### LAPS Legacy (2019/2022) : Installation

**Prérequis :**
- Domain Controller Windows Server 2019/2022
- Clients Windows 10/11 ou Server

**Étape 1 : Étendre le schéma Active Directory**

```powershell
# Sur le Domain Controller (en tant que Schema Admin)

# Télécharger LAPS depuis Microsoft
# https://www.microsoft.com/en-us/download/details.aspx?id=46899

# Installer les outils d'administration LAPS
msiexec /i LAPS.x64.msi /quiet

# Importer le module PowerShell
Import-Module AdmPwd.PS

# Étendre le schéma AD (ajoute les attributs ms-Mcs-AdmPwd, etc.)
Update-AdmPwdADSchema

# Accorder les permissions au domaine pour écrire les mots de passe
Set-AdmPwdComputerSelfPermission -Identity "Computers"

# Accorder les permissions de lecture aux admins (groupe)
Set-AdmPwdReadPasswordPermission -Identity "Computers" -AllowedPrincipals "Domain Admins"

# Refuser les permissions de lecture à tout le monde sauf admins
Set-AdmPwdResetPasswordPermission -Identity "Computers" -AllowedPrincipals "Domain Admins"
```

**Étape 2 : Déployer via GPO**

```
GPO Path: Computer Configuration → Policies → Administrative Templates
          → LAPS (après installation du ADMX)

Paramètres à configurer :
├── Enable local admin password management    → Enabled
├── Password Settings
│   ├── Password Complexity                   → Large letters + small letters + numbers + specials
│   ├── Password Length                       → 14 caractères minimum
│   └── Password Age (Days)                   → 30 jours
└── Name of administrator account to manage   → Administrator (ou autre)
```

**Étape 3 : Installer l'agent sur les clients**

```powershell
# Déployer le MSI sur tous les clients (GPO Software Installation)
msiexec /i LAPS.x64.msi /quiet

# Forcer la mise à jour GPO
gpupdate /force

# Vérifier que LAPS fonctionne
Get-AdmPwdPassword -ComputerName "CLIENT01"
```

**Lecture du mot de passe (Admin AD) :**

```powershell
# Via PowerShell
Import-Module AdmPwd.PS
Get-AdmPwdPassword -ComputerName "SRV-WEB01"

# Output:
# ComputerName        Password            ExpirationTimestamp
# ------------        --------            -------------------
# SRV-WEB01           Kp8#mX2@qL9!vZ3     2024-02-15 14:32:11

# Via GUI (LAPS UI)
# Installer "LAPS UI" (inclus dans le MSI)
# Outil graphique pour rechercher et afficher les mots de passe
```

### Windows LAPS Natif (2025 + Updates 2022)

**Disponibilité :**
- Windows Server 2025 (natif)
- Windows Server 2022 (avec KB5025230 ou supérieur)
- Windows 11 22H2+

**Avantages du LAPS Natif :**
- ✅ Intégré dans l'OS (pas d'agent MSI)
- ✅ Chiffrement AES 256 du mot de passe dans l'AD
- ✅ Support Azure AD (pas seulement AD on-prem)
- ✅ Historique des rotations
- ✅ Gestion de plusieurs comptes (pas que Administrateur)

**Étape 1 : Étendre le schéma AD (nouveau schéma)**

```powershell
# Sur le Domain Controller (Schema Admin)

# Vérifier que Windows LAPS est disponible
Get-Command *LAPS*

# Étendre le schéma (nouveau schéma, différent de Legacy)
Update-LapsADSchema -Verbose

# Accorder les permissions
Set-LapsADComputerSelfPermission -Identity "Computers"
Set-LapsADReadPasswordPermission -Identity "Computers" -AllowedPrincipals "Domain Admins"
```

**Étape 2 : Configuration via GPO**

```
GPO Path: Computer Configuration → Policies → Administrative Templates
          → System → LAPS

Paramètres à configurer :
├── Configure password backup directory       → Enabled
│   └── Backup directory: Active Directory     (ou Azure AD)
├── Password Settings
│   ├── Password Complexity                   → 4 (Large + Small + Numbers + Specials)
│   ├── Password Length                       → 16 caractères minimum
│   └── Password Age (Days)                   → 30 jours
├── Post-authentication actions
│   └── Post-authentication action period     → 24 hours (grace period après rotation)
└── Name of administrator account to manage   → Administrator (ou personnalisé)
```

**Étape 3 : Lecture du mot de passe (nouvelles cmdlets)**

```powershell
# Lire le mot de passe (cmdlet native)
Get-LapsADPassword -Identity "SRV-WEB01" -AsPlainText

# Output:
# ComputerName        Password                      ExpirationTime
# ------------        --------                      --------------
# SRV-WEB01           Xz9#Lp2@Qm5!Vk8$Rt4           2024-02-15 14:32:11

# Forcer la rotation immédiate
Reset-LapsADPassword -Identity "SRV-WEB01" -Verbose

# Historique des mots de passe (NOUVEAU)
Get-LapsADPassword -Identity "SRV-WEB01" -IncludeHistory

# Chiffrer le mot de passe (pour stockage sécurisé)
Get-LapsADPassword -Identity "SRV-WEB01" -AsPlainText |
    ConvertTo-SecureString -AsPlainText -Force
```

### LAPS + Azure AD (Hybrid Join)

**Pour les environnements hybrides (AD + Azure AD) :**

```powershell
# Configuration via Intune (Azure Portal)
# Endpoint Manager → Devices → Configuration profiles → Create profile
# Platform: Windows 10 and later
# Profile type: Templates → Local Admin Password Solution (LAPS)

# Settings:
# - Backup directory: Azure AD
# - Password age: 30 days
# - Password length: 16
# - Administrator account name: Administrator

# Lecture du mot de passe (Azure AD)
# Via Azure Portal → Devices → All devices → SRV-WEB01 → Local administrator password

# Ou via PowerShell (avec module AzureAD)
Get-AzureADDevice -ObjectId <DeviceObjectId> |
    Get-AzureADDeviceRegisteredOwner |
    Get-LapsAADPassword
```

### Audit LAPS (Qui a lu les mots de passe ?)

**Activer l'audit dans AD :**

```powershell
# Activer l'audit des accès aux attributs LAPS
$ComputersOU = "OU=Computers,DC=corp,DC=local"

# Audit des lectures de mot de passe
$AuditRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    [System.Security.Principal.SecurityIdentifier]"S-1-1-0",  # Everyone
    [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty,
    [System.Security.AccessControl.AuditFlags]::Success,
    [Guid]"ms-Mcs-AdmPwd"  # Attribut LAPS
)

$ACL = Get-Acl -Path "AD:\$ComputersOU"
$ACL.AddAuditRule($AuditRule)
Set-Acl -Path "AD:\$ComputersOU" -AclObject $ACL

# Lire les logs d'audit
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4662  # Object Access
} | Where-Object {
    $_.Message -like "*ms-Mcs-AdmPwd*"
} | Select-Object TimeCreated,
    @{N='User';E={$_.Properties[1].Value}},
    @{N='Computer';E={$_.Properties[6].Value}}
```

!!! tip "Astuce SecNumCloud"
    LAPS est **obligatoire** pour la conformité SecNumCloud (rotation automatique des mots de passe privilégiés).

    Recommandations :
    - **Rotation : 30 jours maximum**
    - **Longueur : 16 caractères minimum**
    - **Audit : Activer les logs d'accès aux mots de passe**
    - **Chiffrement : Utiliser Windows LAPS Natif (AES 256) sur Server 2025**

---

## GPO Hardening (SecNumCloud)

### Désactiver LLMNR et NBT-NS (Empêcher Responder Poisoning)

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

**Via PowerShell (recommandé) :**

```powershell
# Vérifier l'état SMBv1
Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol

# Désactiver SMBv1 (Client + Serveur)
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart

# Ou via DISM
dism /online /Disable-Feature /FeatureName:SMB1Protocol /NoRestart

# Redémarrer le serveur
Restart-Computer
```

**Via GPO :**

```
GPO Path: Computer Configuration → Preferences → Windows Settings
          → Registry

Créer une nouvelle clé :
└── Action: Update
    Hive: HKEY_LOCAL_MACHINE
    Key Path: SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters
    Value Name: SMB1
    Value Type: REG_DWORD
    Value Data: 0
```

**Vérifier que SMBv1 est bien désactivé :**

```powershell
# Vérifier la configuration SMB
Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol

# Output attendu :
# EnableSMB1Protocol
# ------------------
# False

# Audit des connexions SMB (pour détecter des clients legacy)
Get-SmbConnection | Select-Object ServerName, Dialect, UserName
# Dialect : SMB 2.0, SMB 2.1, SMB 3.0, SMB 3.1.1 (OK)
# Si vous voyez "SMB 1.0" → Un client utilise encore SMBv1 !
```

### Audit Policy : Logs Détaillés (Process Creation 4688)

**Problème :** Par défaut, Windows ne log pas assez de détails pour la forensic (ligne de commande des processus manquante).

**GPO : Activer l'audit des créations de processus avec ligne de commande**

```
GPO Path 1: Computer Configuration → Policies → Windows Settings
            → Security Settings → Advanced Audit Policy Configuration
            → System Audit Policies → Detailed Tracking

Paramètre :
└── Audit Process Creation → Success

GPO Path 2: Computer Configuration → Policies → Administrative Templates
            → System → Audit Process Creation

Paramètre :
└── Include command line in process creation events → Enabled
```

**Résultat : Event ID 4688 avec ligne de commande complète**

```powershell
# Lire les logs de création de processus
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4688
} -MaxEvents 10 | Select-Object TimeCreated, Message

# Exemple d'output :
# TimeCreated          Message
# -----------          -------
# 2024-01-15 14:32:11  A new process has been created.
#                      Process Name: C:\Windows\System32\cmd.exe
#                      Process Command Line: cmd.exe /c whoami
#                      Creator Process: C:\Windows\explorer.exe
```

**Autres Event IDs importants à activer :**

| Event ID | Description | GPO Audit Category |
|----------|-------------|-------------------|
| **4688** | Process Creation | Detailed Tracking → Process Creation |
| **4689** | Process Exit | Detailed Tracking → Process Termination |
| **4697** | Service Installed | System → Security System Extension |
| **4698** | Scheduled Task Created | Object Access → Other Object Access Events |
| **4702** | Scheduled Task Updated | Object Access → Other Object Access Events |
| **5140** | Network Share Accessed | Object Access → File Share |
| **5142** | Network Share Created | Object Access → File Share |

**Script PowerShell pour activer tous les audits recommandés :**

```powershell
# Activer les audits de sécurité (SecNumCloud)
auditpol /set /subcategory:"Process Creation" /success:enable
auditpol /set /subcategory:"Process Termination" /success:enable
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Logoff" /success:enable
auditpol /set /subcategory:"Account Lockout" /failure:enable
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable
auditpol /set /subcategory:"File Share" /success:enable /failure:enable

# Activer la ligne de commande dans les logs 4688
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
    -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord

# Vérifier la configuration
auditpol /get /category:*
```

!!! warning "Attention : Volumétrie des Logs"
    L'activation de tous ces audits génère **beaucoup de logs** (plusieurs GB/jour sur serveurs actifs).

    **Actions requises :**
    - Augmenter la taille du log Security (recommandé : 1 GB minimum)
    - Configurer le forwarding vers SIEM (Splunk, ELK, Wazuh)
    - Activer la rotation automatique (overwrite old events)

    ```powershell
    # Augmenter la taille du log Security à 1 GB
    wevtutil sl Security /ms:1073741824
    ```

---

## BitLocker (Chiffrement Disque)

### Vérifier l'État

```powershell
# État de tous les volumes
Get-BitLockerVolume

# Output:
# VolumeType  MountPoint  VolumeStatus   EncryptionPercentage  KeyProtector
# ----------  ----------  ------------   --------------------  ------------
# OperatingSystem C:      FullyEncrypted 100                   {Tpm, RecoveryPassword}

# Détails d'un volume
Get-BitLockerVolume -MountPoint "C:" | Format-List *
```

### Activer BitLocker

```powershell
# Vérifier le TPM
Get-Tpm

# Activer sur le disque système (avec TPM)
Enable-BitLocker -MountPoint "C:" `
    -EncryptionMethod XtsAes256 `
    -TpmProtector `
    -RecoveryPasswordProtector

# Activer sur un disque de données
Enable-BitLocker -MountPoint "D:" `
    -EncryptionMethod XtsAes256 `
    -RecoveryPasswordProtector

# Avec mot de passe (sans TPM)
$password = Read-Host -AsSecureString "Enter BitLocker password"
Enable-BitLocker -MountPoint "D:" `
    -EncryptionMethod XtsAes256 `
    -PasswordProtector `
    -Password $password
```

### Sauvegarder la Clé de Récupération

```powershell
# Récupérer l'ID du protecteur
(Get-BitLockerVolume -MountPoint "C:").KeyProtector

# Sauvegarder dans Active Directory
Backup-BitLockerKeyProtector -MountPoint "C:" `
    -KeyProtectorId "{GUID-DU-PROTECTEUR}"

# Exporter vers un fichier
(Get-BitLockerVolume -MountPoint "C:").KeyProtector |
    Where-Object KeyProtectorType -eq "RecoveryPassword" |
    Select-Object KeyProtectorId, RecoveryPassword |
    Export-Csv "BitLocker_Recovery_Keys.csv" -NoTypeInformation
```

!!! danger "Clés de récupération"
    - **Toujours** sauvegarder les clés AVANT de chiffrer
    - Stocker dans AD ou coffre-fort sécurisé
    - Sans la clé = données perdues définitivement

### Gestion BitLocker

```powershell
# Suspendre temporairement (pour BIOS update)
Suspend-BitLocker -MountPoint "C:" -RebootCount 1

# Reprendre
Resume-BitLocker -MountPoint "C:"

# Désactiver et déchiffrer
Disable-BitLocker -MountPoint "C:"

# Verrouiller un volume
Lock-BitLocker -MountPoint "D:"

# Déverrouiller
Unlock-BitLocker -MountPoint "D:" -RecoveryPassword "123456-789012-..."
```

### Network Unlock (Déverrouillage Automatique sur LAN)

**Network Unlock = Déverrouiller BitLocker automatiquement si le serveur est sur le réseau d'entreprise**

```
┌─────────────────────────────────────────────────────────────┐
│                  PROBLÈME SANS NETWORK UNLOCK                │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Serveur avec BitLocker + PIN au démarrage :                │
│  1. Panne de courant                                        │
│  2. Serveur redémarre                                       │
│  3. Bloqué sur l'écran "Entrer le PIN BitLocker"            │
│  4. Admin doit se déplacer physiquement au datacenter       │
│  5. Entrer le PIN manuellement                              │
│  6. Serveur démarre enfin                                   │
│                                                              │
│  Downtime : Plusieurs heures (déplacement admin)            │
│                                                              │
├─────────────────────────────────────────────────────────────┤
│                  SOLUTION : NETWORK UNLOCK                   │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  1. Panne de courant                                        │
│  2. Serveur redémarre                                       │
│  3. Serveur contacte le serveur WDS sur le LAN (DHCP)       │
│  4. WDS fournit la clé de déverrouillage réseau             │
│  5. BitLocker déverrouillé automatiquement                  │
│  6. Serveur démarre normalement                             │
│                                                              │
│  Downtime : Quelques minutes (automatique)                  │
│                                                              │
│  Sécurité : Si le serveur est volé (hors LAN), le PIN       │
│             est toujours requis                             │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

**Prérequis :**
- Windows Server 2019/2022/2025 (Datacenter ou Standard)
- Serveur WDS (Windows Deployment Services) sur le réseau
- Certificat PKI pour WDS
- TPM 1.2+ sur les serveurs à protéger

**Étape 1 : Configurer le serveur WDS**

```powershell
# Sur le serveur WDS (rôle dédié ou DC)

# Installer WDS
Install-WindowsFeature -Name WDS -IncludeManagementTools

# Initialiser WDS (si pas déjà fait)
wdsutil /initialize-server /remInst:"C:\RemoteInstall"

# Créer un certificat pour Network Unlock (via CA interne)
# Ou générer un certificat auto-signé (lab uniquement)
$Cert = New-SelfSignedCertificate -DnsName "wds.corp.local" `
    -CertStoreLocation "Cert:\LocalMachine\My" `
    -KeyUsage KeyEncipherment, DataEncipherment `
    -Type SSLServerAuthentication

# Exporter le certificat (publique + privée)
$CertPassword = ConvertTo-SecureString -String "P@ssw0rd" -Force -AsPlainText
Export-PfxCertificate -Cert $Cert -FilePath "C:\WDS-NetworkUnlock.pfx" -Password $CertPassword

# Configurer WDS pour Network Unlock
wdsutil /Set-Server /AutoAddPolicy /Policy:AdminApproval
```

**Étape 2 : Configurer via GPO**

```
GPO Path: Computer Configuration → Policies → Windows Settings
          → Security Settings → Public Key Policies → BitLocker Drive Encryption

Sous-menu : Operating System Drives

Paramètres :
├── Require additional authentication at startup  → Enabled
│   ├── Allow BitLocker without a compatible TPM  → Unchecked
│   ├── Configure TPM startup                      → Allow TPM
│   ├── Configure TPM startup PIN                  → Require startup PIN with TPM
│   └── Configure TPM startup key                  → Do not allow startup key with TPM
│
└── Network Unlock (nouvelle option)              → Enabled
    ├── Network Unlock Certificate                 → Importer le certificat WDS
    └── Allow Network Unlock on this domain        → Enabled
```

**Étape 3 : Déployer le certificat sur les serveurs**

```powershell
# Sur chaque serveur BitLocker

# Importer le certificat WDS (partie publique)
Import-Certificate -FilePath "\\wds\share\WDS-NetworkUnlock.cer" `
    -CertStoreLocation "Cert:\LocalMachine\Root"

# Activer Network Unlock sur le volume C:
Enable-BitLocker -MountPoint "C:" `
    -EncryptionMethod XtsAes256 `
    -TpmProtector `
    -RecoveryPasswordProtector `
    -SkipHardwareTest

# Ajouter le protecteur Network Unlock
Add-BitLockerKeyProtector -MountPoint "C:" `
    -NetworkUnlockProtector
```

**Étape 4 : Tester Network Unlock**

```powershell
# Vérifier que Network Unlock est configuré
Get-BitLockerVolume -MountPoint "C:" | Select-Object -ExpandProperty KeyProtector

# Output attendu :
# KeyProtectorType           KeyProtectorId
# ----------------           --------------
# Tpm                        {GUID-1}
# RecoveryPassword           {GUID-2}
# NetworkUnlock              {GUID-3}

# Redémarrer le serveur pour tester
Restart-Computer

# Au boot, si le serveur est sur le LAN :
# → Déverrouillage automatique (pas de PIN demandé)

# Au boot, si le serveur est hors LAN (volé, déplacé) :
# → PIN demandé
```

**Débogage Network Unlock :**

```powershell
# Activer les logs détaillés BitLocker
wevtutil sl Microsoft-Windows-BitLocker/BitLocker Management /e:true /l:5

# Lire les logs Network Unlock
Get-WinEvent -LogName "Microsoft-Windows-BitLocker/BitLocker Management" |
    Where-Object { $_.Message -like "*Network Unlock*" } |
    Select-Object TimeCreated, Id, Message

# Event IDs importants :
# 853 : Network Unlock réussi
# 854 : Network Unlock échoué (serveur WDS inaccessible)
# 855 : Network Unlock désactivé (hors LAN)
```

**Scénarios d'Usage :**

| Scénario | PIN Requis ? | Network Unlock ? |
|----------|-------------|------------------|
| Boot normal sur le LAN entreprise | Non | Oui (automatique) |
| Boot hors LAN (datacenter distant) | Oui | Non (WDS inaccessible) |
| Serveur volé (hors LAN) | Oui | Non (sécurité préservée) |
| Panne électrique + redémarrage auto | Non | Oui (serveur démarre seul) |

!!! tip "Astuce Production"
    Network Unlock est **idéal pour** :

    - **Datacenters** : Éviter les déplacements physiques pour entrer le PIN après une panne
    - **Serveurs critiques** : Redémarrage automatique sans intervention humaine
    - **Clusters** : Les nœuds peuvent redémarrer automatiquement après un failover

    **Sécurité maintenue :** Si le serveur est volé et déplacé hors du réseau, le PIN reste requis.

---

## PKI : Bootstrap Certificat (Offline)

### Le Problème : "Chicken & Egg"

**Scénario classique dans les environnements SecNumCloud :**

```
┌─────────────────────────────────────────────────────────────┐
│                    PROBLÈME "CHICKEN & EGG"                  │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  1. Nouvelle machine Windows (non jointe au domaine)        │
│  2. Pour rejoindre le domaine → Besoin de se connecter au VPN│
│  3. Pour se connecter au VPN → Besoin d'un certificat machine│
│  4. Pour obtenir un certificat → Besoin de l'auto-enrollment AD│
│  5. Pour l'auto-enrollment → Besoin d'être joint au domaine │
│                                                              │
│  ➜ Boucle impossible !                                      │
│                                                              │
├─────────────────────────────────────────────────────────────┤
│                      SOLUTION : BOOTSTRAP                    │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  1. Générer un CSR manuellement (certreq + fichier .inf)    │
│  2. Soumettre le CSR à la CA (via processus offline)        │
│  3. Installer le certificat signé sur la machine            │
│  4. La machine peut maintenant se connecter au VPN           │
│  5. Une fois connectée au VPN → Jointure au domaine         │
│  6. Auto-enrollment activé → Rotation automatique des certs │
│                                                              │
│  ✓ Le certificat "bootstrap" permet l'amorçage du cycle     │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

!!! tip "Cas d'usage typiques"
    - **Postes nomades** : Laptops devant se connecter au VPN avant la jointure domaine
    - **Serveurs DMZ** : Isolation réseau stricte (pas d'accès direct à l'AD)
    - **Zero Trust** : Authentification par certificat obligatoire (pas de VPN username/password)
    - **Provisioning automatique** : Scripts de déploiement Ansible/Terraform nécessitant un certificat initial

---

### Template INF : ECDSA P-384 (ANSSI Recommandé)

**Pourquoi ECDSA P-384 ?**

| Critère | RSA 4096 | ECDSA P-384 (Recommandé ANSSI) |
|---------|----------|-------------------------------|
| **Sécurité équivalente** | 4096 bits | 384 bits (même niveau de sécurité) |
| **Taille de la clé** | 4096 bits | 384 bits (10x plus compact) |
| **Performance CPU** | Lent (génération & signature) | Rapide (moins de calculs) |
| **Taille du certificat** | ~2 KB | ~500 octets |
| **Support matériel** | Universel | TPM 2.0+ (natif) |
| **Standard ANSSI** | Acceptable | **Recommandé** (SecNumCloud) |

!!! success "ECDSA P-384 : Standard Moderne"
    ECDSA (Elliptic Curve Digital Signature Algorithm) avec courbe P-384 offre une sécurité équivalente à RSA 7680 bits avec une clé de seulement 384 bits. C'est le choix recommandé par l'ANSSI pour les infrastructures SecNumCloud.

**Fichier INF pour Bootstrap Certificate :**

```ini
[Version]
Signature="$Windows NT$"

[NewRequest]
; === Informations du Sujet ===
; IMPORTANT : Le FQDN doit être ANTICIPÉ (la machine n'est pas encore jointe au domaine)
Subject = "CN=WKS-LAPTOP-01.corp.mycorp.internal,O=MyCorp,C=FR"

; === Algorithme de Clé : ECDSA P-384 (ANSSI) ===
KeyAlgorithm = ECDSA
KeyLength = 384
; Courbes supportées :
;   - ECDSA_P256 (256 bits) : Acceptable
;   - ECDSA_P384 (384 bits) : RECOMMANDÉ ANSSI
;   - ECDSA_P521 (521 bits) : Maximum (overkill)

; === Paramètres de la Clé Privée ===
Exportable = FALSE
; FALSE = La clé privée reste dans le TPM (sécurité maximale)
; TRUE  = Exportable en PFX (uniquement si migration nécessaire)

MachineKeySet = TRUE
; TRUE  = Certificat machine (stocké dans LocalMachine\My)
; FALSE = Certificat utilisateur (stocké dans CurrentUser\My)
; CRITIQUE : MachineKeySet=TRUE est OBLIGATOIRE pour :
;   - VPN Machine Authentication
;   - Services système (IIS, LDAPS, etc.)
;   - Authentification avant logon utilisateur

ProviderName = "Microsoft Software Key Storage Provider"
; Pour TPM 2.0, utiliser : "Microsoft Platform Crypto Provider"
; Cela force le stockage de la clé dans le TPM matériel

RequestType = PKCS10
; Format standard pour les CSR

KeyUsage = 0xa0
; 0xa0 = 0x80 (Digital Signature) + 0x20 (Key Encipherment)
; Requis pour l'authentification TLS/SSL client

; === Algorithme de Hachage ===
HashAlgorithm = SHA384
; SHA384 est recommandé avec ECDSA P-384 (cohérence de sécurité)
; SHA256 est acceptable mais SHA384 est préféré

; === Extensions : Enhanced Key Usage (EKU) ===
[EnhancedKeyUsageExtension]
OID=1.3.6.1.5.5.7.3.2     ; Client Authentication (VPN, 802.1X)
OID=1.3.6.1.5.5.7.3.1     ; Server Authentication (optionnel, si dual-use)

; Client Authentication (1.3.6.1.5.5.7.3.2) est OBLIGATOIRE pour :
;   - VPN Client (IPsec, SSL VPN, WireGuard)
;   - 802.1X Network Access Control (NAC)
;   - Mutual TLS (mTLS) authentication

; === Extensions : Subject Alternative Name (SAN) ===
[Extensions]
2.5.29.17 = "{text}"
_continue_ = "dns=WKS-LAPTOP-01.corp.mycorp.internal&"
_continue_ = "dns=WKS-LAPTOP-01&"

; Le SAN doit inclure :
;   - FQDN complet (dns=hostname.domain.com)
;   - Hostname court (dns=hostname) pour compatibilité

[RequestAttributes]
; Ne PAS spécifier de CertificateTemplate pour un bootstrap offline
; Le template sera appliqué par la CA lors de la signature manuelle
```

**Explications détaillées :**

| Paramètre | Valeur | Justification |
|-----------|--------|---------------|
| `KeyAlgorithm = ECDSA` | ECDSA | Courbes elliptiques (moderne, rapide, compact) |
| `KeyLength = 384` | 384 bits | Courbe P-384 (ANSSI recommandé, équivalent RSA 7680 bits) |
| `Exportable = FALSE` | Non exportable | Clé privée protégée dans TPM (impossible à voler) |
| `MachineKeySet = TRUE` | Machine | Certificat accessible par les services système (VPN, IIS) |
| `KeyUsage = 0xa0` | Digital Signature + Key Encipherment | Requis pour authentification TLS client/serveur |
| `HashAlgorithm = SHA384` | SHA-384 | Cohérence avec ECDSA P-384 (niveau de sécurité équivalent) |
| `OID 1.3.6.1.5.5.7.3.2` | Client Authentication | **OBLIGATOIRE** pour VPN et 802.1X |

---

### Workflow PowerShell

#### Bloc A : Génération du CSR

**Fonction automatisée pour générer le CSR avec ECDSA P-384 :**

```powershell
function New-BootstrapCSR {
    <#
    .SYNOPSIS
        Génère un CSR bootstrap pour certificat machine (ECDSA P-384).

    .DESCRIPTION
        Crée un fichier .inf dynamiquement et génère un CSR avec certreq.
        Le certificat résultant permet l'authentification VPN AVANT la jointure domaine.

    .PARAMETER Hostname
        Nom court de la machine (ex: WKS-LAPTOP-01)

    .PARAMETER DomainFQDN
        FQDN du domaine (ex: corp.mycorp.internal)
        IMPORTANT : Doit être le domaine cible (même si la machine n'est pas encore jointe)

    .PARAMETER OutputPath
        Répertoire de sortie pour les fichiers .inf et .req

    .EXAMPLE
        New-BootstrapCSR -Hostname "WKS-LAPTOP-01" -DomainFQDN "corp.mycorp.internal" -OutputPath "C:\Temp"

    .NOTES
        Auteur : SecOps Team MyCorp
        Prérequis : Exécuter en tant qu'Administrateur local
        TPM 2.0 recommandé (pour stockage sécurisé de la clé)
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Hostname,

        [Parameter(Mandatory = $true)]
        [ValidatePattern("^[a-z0-9\-\.]+\.[a-z]{2,}$")]
        [string]$DomainFQDN,

        [Parameter(Mandatory = $false)]
        [string]$OutputPath = "C:\Temp\Bootstrap"
    )

    # Créer le répertoire de sortie
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
        Write-Host "[+] Répertoire créé : $OutputPath" -ForegroundColor Green
    }

    # Construire le FQDN complet (ANTICIPÉ)
    $MachineFQDN = "$Hostname.$DomainFQDN"

    # Chemins des fichiers
    $InfFile = Join-Path $OutputPath "$Hostname-Bootstrap.inf"
    $ReqFile = Join-Path $OutputPath "$Hostname-Bootstrap.req"

    Write-Host "[*] Génération du fichier INF pour $MachineFQDN..." -ForegroundColor Cyan

    # Contenu du fichier .inf (ECDSA P-384)
    $InfContent = @"
[Version]
Signature="`$Windows NT`$"

[NewRequest]
Subject = "CN=$MachineFQDN,O=MyCorp,C=FR"

; === ECDSA P-384 (ANSSI Recommandé) ===
KeyAlgorithm = ECDSA
KeyLength = 384
Exportable = FALSE
MachineKeySet = TRUE
ProviderName = "Microsoft Software Key Storage Provider"
RequestType = PKCS10
KeyUsage = 0xa0
HashAlgorithm = SHA384

[EnhancedKeyUsageExtension]
OID=1.3.6.1.5.5.7.3.2     ; Client Authentication (VPN)
OID=1.3.6.1.5.5.7.3.1     ; Server Authentication (optionnel)

[Extensions]
2.5.29.17 = "{text}"
_continue_ = "dns=$MachineFQDN&"
_continue_ = "dns=$Hostname&"
"@

    # Écrire le fichier .inf
    Set-Content -Path $InfFile -Value $InfContent -Encoding ASCII
    Write-Host "[+] Fichier INF créé : $InfFile" -ForegroundColor Green

    # Générer le CSR avec certreq
    Write-Host "[*] Génération du CSR avec certreq..." -ForegroundColor Cyan
    $certreqOutput = certreq -new $InfFile $ReqFile 2>&1

    if ($LASTEXITCODE -eq 0) {
        Write-Host "[+] CSR généré avec succès : $ReqFile" -ForegroundColor Green

        # Afficher le contenu du CSR
        Write-Host "`n[*] Contenu du CSR (à soumettre à la CA) :" -ForegroundColor Cyan
        Get-Content $ReqFile | Write-Host -ForegroundColor Yellow

        # Vérifier le CSR
        Write-Host "`n[*] Vérification du CSR..." -ForegroundColor Cyan
        certutil -dump $ReqFile

        Write-Host "`n[✓] Prochaines étapes :" -ForegroundColor Green
        Write-Host "  1. Transférer le fichier CSR vers une machine avec accès à la CA" -ForegroundColor White
        Write-Host "     (ex: via clé USB, partage réseau temporaire, ou email sécurisé)" -ForegroundColor Gray
        Write-Host "  2. Soumettre le CSR à la CA interne (certreq -submit ou Web Enrollment)" -ForegroundColor White
        Write-Host "  3. Télécharger le certificat signé (format .cer)" -ForegroundColor White
        Write-Host "  4. Utiliser Install-BootstrapCertificate pour installer le certificat" -ForegroundColor White

    } else {
        Write-Error "❌ Échec de la génération du CSR"
        Write-Host "Sortie de certreq :" -ForegroundColor Red
        $certreqOutput | ForEach-Object { Write-Host $_ -ForegroundColor Red }
    }
}
```

!!! tip "FQDN Anticipé : Planification Critique"
    **Le FQDN doit être déterminé AVANT la génération du CSR !**

    Si votre politique de nommage est `WKS-LAPTOP-01.corp.mycorp.internal`, vous DEVEZ spécifier exactement ce FQDN dans le CSR, même si la machine n'est pas encore jointe au domaine.

    **Mauvaise pratique :** Générer un CSR avec le hostname court (`WKS-LAPTOP-01`) puis changer le nom après jointure → Le certificat ne matchera plus !

    **Bonne pratique :** Planifier le FQDN complet en amont (via convention de nommage stricte).

**Utilisation :**

```powershell
# Générer un CSR pour WKS-LAPTOP-01.corp.mycorp.internal
New-BootstrapCSR -Hostname "WKS-LAPTOP-01" -DomainFQDN "corp.mycorp.internal" -OutputPath "C:\Temp\Bootstrap"

# Sortie :
# [+] Répertoire créé : C:\Temp\Bootstrap
# [*] Génération du fichier INF pour WKS-LAPTOP-01.corp.mycorp.internal...
# [+] Fichier INF créé : C:\Temp\Bootstrap\WKS-LAPTOP-01-Bootstrap.inf
# [*] Génération du CSR avec certreq...
# [+] CSR généré avec succès : C:\Temp\Bootstrap\WKS-LAPTOP-01-Bootstrap.req
#
# [*] Contenu du CSR (à soumettre à la CA) :
# -----BEGIN NEW CERTIFICATE REQUEST-----
# MIIBYDCCAQcCAQAwRjELMAkGA1UEBhMCRlIxDzANBgNVBAoTBk15Q29ycDEmMCQG
# ...
# -----END NEW CERTIFICATE REQUEST-----
```

---

#### Bloc B : Installation du Certificat

**Fonction pour installer le certificat signé et vérifier les EKU :**

```powershell
function Install-BootstrapCertificate {
    <#
    .SYNOPSIS
        Installe un certificat bootstrap et vérifie les EKU pour VPN.

    .DESCRIPTION
        Installe le certificat signé par la CA et vérifie que :
        - Le certificat est bien dans LocalMachine\My
        - L'EKU "Client Authentication" (1.3.6.1.5.5.7.3.2) est présent
        - La chaîne de certification est valide

    .PARAMETER CertificatePath
        Chemin vers le fichier .cer (certificat signé par la CA)

    .EXAMPLE
        Install-BootstrapCertificate -CertificatePath "C:\Temp\WKS-LAPTOP-01-Bootstrap.cer"

    .NOTES
        Auteur : SecOps Team MyCorp
        Prérequis : Exécuter en tant qu'Administrateur local
        Le CSR doit avoir été généré sur CETTE machine (sinon keyset error)
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({Test-Path $_})]
        [string]$CertificatePath
    )

    Write-Host "[*] Installation du certificat bootstrap..." -ForegroundColor Cyan

    # Installer le certificat avec certreq -accept
    $certreqOutput = certreq -accept $CertificatePath 2>&1

    if ($LASTEXITCODE -eq 0) {
        Write-Host "[+] Certificat installé avec succès !" -ForegroundColor Green

        # Extraire le Subject CN du certificat
        $CertInfo = certutil -dump $CertificatePath | Out-String
        if ($CertInfo -match 'Subject:.*CN=([^,]+)') {
            $SubjectCN = $matches[1]
            Write-Host "[*] Subject CN : $SubjectCN" -ForegroundColor Cyan
        }

        # Vérifier la présence du certificat dans LocalMachine\My
        Write-Host "`n[*] Vérification dans LocalMachine\My..." -ForegroundColor Cyan
        $InstalledCert = Get-ChildItem Cert:\LocalMachine\My | Where-Object {
            $_.Subject -like "*$SubjectCN*"
        } | Select-Object -First 1

        if ($InstalledCert) {
            Write-Host "[+] Certificat trouvé dans LocalMachine\My" -ForegroundColor Green
            Write-Host "    Thumbprint  : $($InstalledCert.Thumbprint)" -ForegroundColor Gray
            Write-Host "    Subject     : $($InstalledCert.Subject)" -ForegroundColor Gray
            Write-Host "    Issuer      : $($InstalledCert.Issuer)" -ForegroundColor Gray
            Write-Host "    NotBefore   : $($InstalledCert.NotBefore)" -ForegroundColor Gray
            Write-Host "    NotAfter    : $($InstalledCert.NotAfter)" -ForegroundColor Gray

            # Vérifier les Enhanced Key Usages (EKU)
            Write-Host "`n[*] Vérification des Enhanced Key Usages (EKU)..." -ForegroundColor Cyan

            $ClientAuthOID = "1.3.6.1.5.5.7.3.2"  # Client Authentication
            $ServerAuthOID = "1.3.6.1.5.5.7.3.1"  # Server Authentication

            $EKUs = $InstalledCert.EnhancedKeyUsageList
            $HasClientAuth = $EKUs | Where-Object { $_.ObjectId -eq $ClientAuthOID }
            $HasServerAuth = $EKUs | Where-Object { $_.ObjectId -eq $ServerAuthOID }

            if ($HasClientAuth) {
                Write-Host "[+] Client Authentication (1.3.6.1.5.5.7.3.2) : ✓ PRÉSENT" -ForegroundColor Green
                Write-Host "    → Certificat valide pour VPN Client" -ForegroundColor Gray
            } else {
                Write-Warning "⚠️  Client Authentication MANQUANT ! Le VPN peut ne pas fonctionner."
            }

            if ($HasServerAuth) {
                Write-Host "[+] Server Authentication (1.3.6.1.5.5.7.3.1) : ✓ PRÉSENT" -ForegroundColor Green
            }

            # Vérifier la chaîne de certification
            Write-Host "`n[*] Vérification de la chaîne de certification..." -ForegroundColor Cyan
            $ChainStatus = $InstalledCert.Verify()

            if ($ChainStatus) {
                Write-Host "[+] Chaîne de certification valide ✓" -ForegroundColor Green
            } else {
                Write-Warning "⚠️  Chaîne de certification invalide ! Vérifier que les CA Root/Intermediate sont installées."
                Write-Host "    Installer les certificats CA dans Cert:\LocalMachine\Root et Cert:\LocalMachine\CA" -ForegroundColor Yellow
            }

            # Résumé
            Write-Host "`n[✓] Installation terminée avec succès !" -ForegroundColor Green
            Write-Host "`n[*] Prochaines étapes :" -ForegroundColor Cyan
            Write-Host "  1. Configurer le client VPN pour utiliser l'authentification par certificat" -ForegroundColor White
            Write-Host "  2. Se connecter au VPN avec le certificat machine" -ForegroundColor White
            Write-Host "  3. Rejoindre le domaine Active Directory (Add-Computer)" -ForegroundColor White
            Write-Host "  4. Activer l'auto-enrollment via GPO pour les futurs renouvellements" -ForegroundColor White

        } else {
            Write-Error "❌ Certificat non trouvé dans LocalMachine\My après installation !"
            Write-Host "Vérifier manuellement avec : Get-ChildItem Cert:\LocalMachine\My" -ForegroundColor Yellow
        }

    } else {
        Write-Error "❌ Échec de l'installation du certificat"
        Write-Host "Sortie de certreq :" -ForegroundColor Red
        $certreqOutput | ForEach-Object { Write-Host $_ -ForegroundColor Red }

        Write-Host "`n[!] Erreurs courantes :" -ForegroundColor Yellow
        Write-Host "  - 'Keyset does not exist' : Le CSR n'a pas été généré sur CETTE machine" -ForegroundColor Gray
        Write-Host "  - 'Cannot find object'    : Fichier .cer corrompu ou format invalide" -ForegroundColor Gray
        Write-Host "  - 'Access denied'         : Exécuter en tant qu'Administrateur" -ForegroundColor Gray
    }
}
```

**Utilisation :**

```powershell
# Après avoir récupéré le certificat signé de la CA
Install-BootstrapCertificate -CertificatePath "C:\Temp\WKS-LAPTOP-01-Bootstrap.cer"

# Sortie attendue :
# [*] Installation du certificat bootstrap...
# [+] Certificat installé avec succès !
# [*] Subject CN : WKS-LAPTOP-01.corp.mycorp.internal
#
# [*] Vérification dans LocalMachine\My...
# [+] Certificat trouvé dans LocalMachine\My
#     Thumbprint  : A1B2C3D4E5F6789012345678901234567890ABCD
#     Subject     : CN=WKS-LAPTOP-01.corp.mycorp.internal, O=MyCorp, C=FR
#     Issuer      : CN=MyCorp-CA, DC=corp, DC=mycorp, DC=internal
#     NotBefore   : 2025-01-22 10:00:00
#     NotAfter    : 2026-01-22 10:00:00
#
# [*] Vérification des Enhanced Key Usages (EKU)...
# [+] Client Authentication (1.3.6.1.5.5.7.3.2) : ✓ PRÉSENT
#     → Certificat valide pour VPN Client
# [+] Server Authentication (1.3.6.1.5.5.7.3.1) : ✓ PRÉSENT
#
# [*] Vérification de la chaîne de certification...
# [+] Chaîne de certification valide ✓
#
# [✓] Installation terminée avec succès !
```

---

### Workflow Complet : Du CSR à la Connexion VPN

```
┌─────────────────────────────────────────────────────────────┐
│                   WORKFLOW BOOTSTRAP PKI                     │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  [ÉTAPE 1 : Génération CSR - Machine Offline]               │
│  ───────────────────────────────────────────                │
│  PS> New-BootstrapCSR -Hostname "WKS-01" `                  │
│         -DomainFQDN "corp.mycorp.internal"                   │
│                                                              │
│  Output : WKS-01-Bootstrap.req (fichier CSR)                │
│                                                              │
│  [ÉTAPE 2 : Transfert CSR - USB/Email Sécurisé]             │
│  ────────────────────────────────────────────                │
│  Copier le fichier .req vers une machine avec accès CA      │
│                                                              │
│  [ÉTAPE 3 : Soumission CA - Machine avec Accès AD]          │
│  ──────────────────────────────────────────────              │
│  Option A : Web Enrollment                                   │
│    → https://srv-ca-01.corp.mycorp.internal/certsrv         │
│    → Advanced Request → Submit CSR                           │
│                                                              │
│  Option B : Ligne de commande                                │
│    PS> certreq -submit -config "srv-ca-01\MyCorp-CA" `      │
│           WKS-01-Bootstrap.req WKS-01-Bootstrap.cer          │
│                                                              │
│  [ÉTAPE 4 : Transfert Certificat - USB/Email Sécurisé]      │
│  ───────────────────────────────────────────────             │
│  Copier le fichier .cer vers la machine offline             │
│                                                              │
│  [ÉTAPE 5 : Installation - Machine Offline]                 │
│  ────────────────────────────────────────────                │
│  PS> Install-BootstrapCertificate `                          │
│         -CertificatePath "WKS-01-Bootstrap.cer"              │
│                                                              │
│  [ÉTAPE 6 : Configuration VPN]                              │
│  ──────────────────────────────                              │
│  - Client VPN : Utiliser "Machine Certificate"              │
│  - Sélectionner le certificat dans LocalMachine\My          │
│  - Se connecter au VPN                                       │
│                                                              │
│  [ÉTAPE 7 : Jointure Domaine]                               │
│  ─────────────────────────────                               │
│  PS> Add-Computer -DomainName "corp.mycorp.internal" `      │
│         -Credential (Get-Credential) -Restart                │
│                                                              │
│  [ÉTAPE 8 : Auto-Enrollment (Post-Jointure)]                │
│  ────────────────────────────────────────────                │
│  - GPO appliquée automatiquement                             │
│  - Certificats futurs gérés via auto-enrollment             │
│  - Le certificat bootstrap peut être révoqué après 30 jours │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

### Troubleshooting

**Erreur : "Keyset does not exist" lors de certreq -accept**

```powershell
# Cause : Le CSR n'a pas été généré sur cette machine
# Solution : Le CSR et l'installation doivent être sur la MÊME machine

# Vérifier les requests en attente
certutil -store request

# Si la request n'existe pas : regénérer le CSR sur cette machine
New-BootstrapCSR -Hostname "WKS-01" -DomainFQDN "corp.mycorp.internal"
```

**Le certificat est installé mais le VPN refuse la connexion**

```powershell
# Vérifier que l'EKU "Client Authentication" est présent
$Cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object Subject -like "*WKS-01*"
$Cert.EnhancedKeyUsageList

# Output attendu :
# FriendlyName                            ObjectId
# ------------                            --------
# Client Authentication                   1.3.6.1.5.5.7.3.2

# Si manquant : Le certificat a été émis sans le bon template
# Regénérer le CSR avec le bon EKU dans le fichier .inf
```

**Erreur : "Cannot find certificate request" après certreq -new**

```powershell
# Cause : Le fichier .inf contient une erreur de syntaxe
# Vérifier le fichier .inf

Get-Content "C:\Temp\Bootstrap\WKS-01-Bootstrap.inf"

# Erreurs courantes :
# - Guillemets manquants dans Signature="$Windows NT$"
# - Espaces dans les valeurs OID
# - Encodage du fichier (doit être ASCII, pas UTF-8 BOM)

# Regénérer le fichier avec Set-Content -Encoding ASCII
```

**Le FQDN du certificat ne correspond pas après la jointure domaine**

```powershell
# Problème : La machine a été jointe avec un nom différent
# Exemple : CSR pour "WKS-LAPTOP-01.corp.mycorp.internal"
#           Mais jointure avec "WKS-01.corp.mycorp.internal"

# Solution 1 : Renommer la machine AVANT l'installation du certificat
Rename-Computer -NewName "WKS-LAPTOP-01" -Force -Restart

# Solution 2 : Révoquer le certificat et en générer un nouveau
# (après la jointure domaine, utiliser l'auto-enrollment)
```

---

### Checklist Bootstrap Certificate

- [ ] Planifier le FQDN complet (ex: `WKS-LAPTOP-01.corp.mycorp.internal`)
- [ ] Générer le CSR avec `New-BootstrapCSR` (ECDSA P-384)
- [ ] Vérifier le CSR avec `certutil -dump WKS-01-Bootstrap.req`
- [ ] Transférer le CSR vers une machine avec accès à la CA
- [ ] Soumettre le CSR à la CA (Web Enrollment ou certreq -submit)
- [ ] Télécharger le certificat signé (.cer)
- [ ] Transférer le certificat vers la machine offline
- [ ] Installer avec `Install-BootstrapCertificate`
- [ ] Vérifier l'EKU "Client Authentication" (1.3.6.1.5.5.7.3.2)
- [ ] Vérifier la chaîne de certification (Root + Intermediate CA installées)
- [ ] Configurer le client VPN pour utiliser le certificat machine
- [ ] Se connecter au VPN
- [ ] Rejoindre le domaine Active Directory
- [ ] Activer l'auto-enrollment via GPO pour les renouvellements futurs

!!! success "Production Ready"
    Avec ce workflow, vous pouvez provisionner des machines Windows dans des environnements Zero Trust sans aucun accès réseau initial. Le certificat bootstrap permet l'amorçage du cycle de confiance.

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
| **4720** | User Account Created | Audit |
| **4722** | User Account Enabled | Audit |
| **4725** | User Account Disabled | Audit |
| **4726** | User Account Deleted | Audit |
| **4728** | Member Added to Security Group | Audit |
| **4732** | Member Added to Local Group | Audit |
| **4756** | Member Added to Universal Group | Audit |

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

# Modifications de groupes privilégiés
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4728, 4732, 4756
    StartTime = (Get-Date).AddDays(-7)
}
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

### Export pour SIEM

```powershell
# Export CSV pour analyse
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    StartTime = (Get-Date).AddDays(-1)
} | Select-Object TimeCreated, Id, Message |
    Export-Csv "Security_Events_24h.csv" -NoTypeInformation

# Export JSON
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4625
    StartTime = (Get-Date).AddHours(-24)
} | ConvertTo-Json | Out-File "FailedLogons.json"
```

---

## Hardening Serveur (Checklist ANSSI)

### Surface d'Attaque : Désactiver Services Inutiles

**Principe :** Réduire la surface d'attaque en désactivant les services qui ne sont pas nécessaires.

```powershell
# ============================================================
# Services à désactiver sur un serveur (baseline ANSSI)
# ============================================================

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

# Windows Media Player Network Sharing (inutile)
Stop-Service -Name "WMPNetworkSvc" -Force -ErrorAction SilentlyContinue
Set-Service -Name "WMPNetworkSvc" -StartupType Disabled -ErrorAction SilentlyContinue

# Vérifier l'état
$servicesToDisable = @("Spooler", "XblAuthManager", "XblGameSave", "XboxGipSvc", "XboxNetApiSvc", "bthserv", "RemoteRegistry", "WMPNetworkSvc")
Get-Service -Name $servicesToDisable -ErrorAction SilentlyContinue |
    Select-Object Name, Status, StartType
```

**Résultat attendu :**

```
Name              Status  StartType
----              ------  ---------
Spooler           Stopped Disabled
bthserv           Stopped Disabled
RemoteRegistry    Stopped Disabled
```

### Tâches Planifiées : Désactiver les Tâches par Défaut

**Certaines tâches planifiées Windows peuvent être exploitées ou fuiter des informations :**

```powershell
# Désactiver les tâches de télémétrie Microsoft
Get-ScheduledTask -TaskPath "\Microsoft\Windows\Application Experience\" |
    Disable-ScheduledTask

Get-ScheduledTask -TaskPath "\Microsoft\Windows\Customer Experience Improvement Program\" |
    Disable-ScheduledTask

# Désactiver les tâches de diagnostics non critiques
Disable-ScheduledTask -TaskName "Microsoft Compatibility Appraiser" -TaskPath "\Microsoft\Windows\Application Experience\"
Disable-ScheduledTask -TaskName "ProgramDataUpdater" -TaskPath "\Microsoft\Windows\Application Experience\"
Disable-ScheduledTask -TaskName "Consolidator" -TaskPath "\Microsoft\Windows\Customer Experience Improvement Program\"
Disable-ScheduledTask -TaskName "UsbCeip" -TaskPath "\Microsoft\Windows\Customer Experience Improvement Program\"

# Lister les tâches désactivées
Get-ScheduledTask | Where-Object {$_.State -eq "Disabled"} |
    Select-Object TaskName, TaskPath, State
```

!!! tip "Services Critiques à NE PAS Désactiver"
    **Ne JAMAIS désactiver :**
    - `DNS Client` (dnscache) - Résolution DNS
    - `Netlogon` - Authentification domaine
    - `Windows Time` (W32Time) - Synchronisation horaire (critique pour Kerberos)
    - `Windows Defender Antivirus Service` (WinDefend)
    - `Windows Event Log` (EventLog)

### Protocoles Faibles : Désactiver SMBv1, LLMNR, NBT-NS

**Ces protocoles sont obsolètes et exploitables par des attaquants (Responder, EternalBlue).**

#### 1. Désactiver SMBv1 (WannaCry/EternalBlue)

```powershell
# Vérifier l'état de SMBv1
Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol

# Désactiver SMBv1 (Client + Serveur)
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart

# Via DISM (alternative)
dism /online /Disable-Feature /FeatureName:SMB1Protocol /NoRestart

# Vérifier la configuration
Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol

# Output attendu :
# EnableSMB1Protocol
# ------------------
# False

# Redémarrer le serveur pour appliquer
Restart-Computer -Force
```

#### 2. Désactiver LLMNR (Empêcher Responder Poisoning)

```powershell
# Désactiver LLMNR via registre
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
    -Name "EnableMulticast" -Value 0 -Type DWord

# Vérifier
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast"

# Output :
# EnableMulticast : 0
```

#### 3. Désactiver NBT-NS (NetBIOS Name Service)

```powershell
# Désactiver NBT-NS sur toutes les interfaces réseau
$Adapters = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.TcpipNetbiosOptions -ne $null }
foreach ($Adapter in $Adapters) {
    $Adapter.SetTcpipNetbios(2)  # 0=Default, 1=Enable, 2=Disable
}

# Vérifier
Get-WmiObject Win32_NetworkAdapterConfiguration |
    Where-Object { $_.IPEnabled -eq $true } |
    Select-Object Description, TcpipNetbiosOptions

# Output attendu :
# Description                          TcpipNetbiosOptions
# -----------                          -------------------
# Intel(R) Ethernet Connection         2  (Disabled)
```

**Via GPO (recommandé en entreprise) :**

```
GPO Path: Computer Configuration → Preferences → Windows Settings → Registry

Créer ces clés :

1. LLMNR :
   Hive: HKEY_LOCAL_MACHINE
   Key Path: SOFTWARE\Policies\Microsoft\Windows NT\DNSClient
   Value Name: EnableMulticast
   Value Type: REG_DWORD
   Value Data: 0

2. NBT-NS :
   Hive: HKEY_LOCAL_MACHINE
   Key Path: SYSTEM\CurrentControlSet\Services\NetBT\Parameters
   Value Name: NodeType
   Value Type: REG_DWORD
   Value Data: 2
```

### Chiffrement : Forcer AES-256 pour Kerberos

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

# Vérifier
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" `
    -Name "SupportedEncryptionTypes"

# Output :
# SupportedEncryptionTypes : 24 (0x18 = AES128 + AES256)
```

**Appliquer via GPO :**

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
    ❌ Future encryption types
```

### Chiffrement : Désactiver TLS 1.0 et TLS 1.1

**TLS 1.0/1.1 sont obsolètes et vulnérables (BEAST, POODLE). Forcer TLS 1.2/1.3.**

```powershell
# ============================================================
# Désactiver TLS 1.0
# ============================================================

# Client
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" `
    -Name "Enabled" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" `
    -Name "DisabledByDefault" -Value 1 -Type DWord

# Serveur
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" `
    -Name "Enabled" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" `
    -Name "DisabledByDefault" -Value 1 -Type DWord

# ============================================================
# Désactiver TLS 1.1
# ============================================================

# Client
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" `
    -Name "Enabled" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" `
    -Name "DisabledByDefault" -Value 1 -Type DWord

# Serveur
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" `
    -Name "Enabled" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" `
    -Name "DisabledByDefault" -Value 1 -Type DWord

# ============================================================
# Activer TLS 1.2 (obligatoire)
# ============================================================

# Client
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" `
    -Name "Enabled" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" `
    -Name "DisabledByDefault" -Value 0 -Type DWord

# Serveur
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" `
    -Name "Enabled" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" `
    -Name "DisabledByDefault" -Value 0 -Type DWord

# Redémarrer pour appliquer
Restart-Computer -Force
```

**Tester TLS après redémarrage :**

```powershell
# Tester avec PowerShell (doit utiliser TLS 1.2)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri "https://www.howsmyssl.com/a/check" | Select-Object -ExpandProperty Content | ConvertFrom-Json

# Output attendu :
# tls_version : TLS 1.2
```

### Audit : Activer Process Creation (Event ID 4688)

**Event ID 4688 = Création de processus avec ligne de commande complète.**

```powershell
# Activer l'audit de création de processus
auditpol /set /subcategory:"Process Creation" /success:enable

# Activer la capture de la ligne de commande dans les logs 4688
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
    -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord

# Vérifier la configuration
auditpol /get /category:*

# Output attendu (extrait) :
# System Audit Policy
# Category/Subcategory                      Setting
# Detailed Tracking
#   Process Creation                        Success
```

**Via GPO :**

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

**Tester :**

```powershell
# Exécuter une commande
whoami

# Lire les logs Event ID 4688
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4688
} -MaxEvents 5 | Select-Object TimeCreated, Message

# Output attendu :
# TimeCreated          Message
# -----------          -------
# 2024-01-15 14:32:11  A new process has been created.
#                      Process Name: C:\Windows\System32\whoami.exe
#                      Process Command Line: whoami
#                      Creator Process: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

### Session : Déconnexion Automatique RDP après Inactivité

**Éviter les sessions RDP ouvertes indéfiniment (risque de hijacking).**

```powershell
# Déconnexion automatique après 15 minutes d'inactivité
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
    -Name "MaxIdleTime" -Value 900000 -Type DWord  # 15 min en millisecondes (15 * 60 * 1000)

# Déconnexion automatique après 2 heures de session totale
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
    -Name "MaxConnectionTime" -Value 7200000 -Type DWord  # 2 heures en ms

# Déconnexion automatique des sessions déconnectées après 5 minutes
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
    -Name "MaxDisconnectionTime" -Value 300000 -Type DWord  # 5 min en ms

# Vérifier
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" |
    Select-Object MaxIdleTime, MaxConnectionTime, MaxDisconnectionTime
```

**Via GPO :**

```
GPO Path: Computer Configuration → Policies → Administrative Templates
          → Windows Components → Remote Desktop Services
          → Remote Desktop Session Host → Session Time Limits

Paramètres :
├── Set time limit for active but idle Remote Desktop Services sessions
│   → ✅ Enabled : 15 minutes
├── Set time limit for active Remote Desktop Services sessions
│   → ✅ Enabled : 2 hours
└── Set time limit for disconnected sessions
    → ✅ Enabled : 5 minutes
```

**Tester :**

```powershell
# Voir les sessions RDP actives
query user

# Output :
# USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME
# >admin                rdp-tcp#0           1  Active          .  1/15/2024 2:00 PM
#  jdupont              rdp-tcp#1           2  Active      00:16  1/15/2024 1:45 PM

# Après 15 minutes d'inactivité, la session de jdupont sera déconnectée automatiquement
```

### Checklist Complète ANSSI (Résumé)

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
| **Tâches** | Désactiver télémétrie | `Disable-ScheduledTask -TaskPath "\Microsoft\Windows\CEIP\"` | 🟡 Recommandé |

**Script PowerShell d'Application Automatique :**

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
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
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
    $Adapter.SetTcpipNetbios(2)
}
Write-Host "    [OK] NBT-NS désactivé" -ForegroundColor Green

# 5. Forcer AES-256 Kerberos
Write-Host "[*] Configuration Kerberos AES-256..." -ForegroundColor Yellow
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" -Name "SupportedEncryptionTypes" -Value 0x18
Write-Host "    [OK] Kerberos AES-256 activé" -ForegroundColor Green

# 6. Désactiver TLS 1.0/1.1
Write-Host "[*] Désactivation TLS 1.0/1.1..." -ForegroundColor Yellow
# TLS 1.0
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name "Enabled" -Value 0
# TLS 1.1
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Name "Enabled" -Value 0
Write-Host "    [OK] TLS 1.0/1.1 désactivés" -ForegroundColor Green

# 7. Activer audit Process Creation
Write-Host "[*] Activation Event ID 4688..." -ForegroundColor Yellow
auditpol /set /subcategory:"Process Creation" /success:enable
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

## Quick Reference

```powershell
# === FIREWALL ===
Get-NetFirewallProfile                            # État des profils
Get-NetFirewallRule -Direction Inbound -Enabled True
New-NetFirewallRule -DisplayName "Allow SSH" -Direction Inbound -Protocol TCP -LocalPort 22 -Action Allow
Remove-NetFirewallRule -DisplayName "Allow SSH"

# === DEFENDER ===
Get-MpComputerStatus                              # État
Start-MpScan -ScanType QuickScan                  # Scan rapide
Update-MpSignature                                # MAJ signatures
Add-MpPreference -ExclusionPath "C:\Path"         # Exclusion

# === BITLOCKER ===
Get-BitLockerVolume                               # État
Enable-BitLocker -MountPoint "C:" -TpmProtector -RecoveryPasswordProtector
Backup-BitLockerKeyProtector -MountPoint "C:" -KeyProtectorId "{GUID}"

# === EVENTS ===
Get-WinEvent -LogName Security -MaxEvents 100
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625}  # Failed logons
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624}  # Success logons
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4720}  # User created

# === CERTIFICATS ===
certreq -new request.inf request.req     # Générer CSR
certreq -accept certificate.crt          # Installer Certificat
Get-ChildItem Cert:\LocalMachine\My      # Lister Certs Machine
certutil -dump certificate.cer           # Vérifier Certificat
certutil -store request                  # Lister Requests Pending
```
