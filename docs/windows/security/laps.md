---
tags:
  - laps
  - passwords
  - active-directory
  - security
---

# Windows LAPS (Local Admin Password Solution)

Rotation automatique du mot de passe Administrateur local stocké dans l'Active Directory.

---

## Pourquoi LAPS ?

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

---

## Legacy vs Natif

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

---

## LAPS Legacy (2019/2022)

### Installation

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

### Lecture du mot de passe

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

---

## Windows LAPS Natif (2025+)

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

### Configuration

**Étape 1 : Étendre le schéma AD**

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

### Utilisation

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

---

## LAPS + Azure AD (Hybrid Join)

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
```

---

## Audit LAPS

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

---

!!! tip "Astuce SecNumCloud"
    LAPS est **obligatoire** pour la conformité SecNumCloud (rotation automatique des mots de passe privilégiés).

    Recommandations :
    - **Rotation : 30 jours maximum**
    - **Longueur : 16 caractères minimum**
    - **Audit : Activer les logs d'accès aux mots de passe**
    - **Chiffrement : Utiliser Windows LAPS Natif (AES 256) sur Server 2025**

---

!!! info "À lire aussi"
    - [Hardening ANSSI](hardening-anssi.md) - GPO de sécurité complètes
    - [Active Directory](../active-directory.md) - Administration AD
