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
```
