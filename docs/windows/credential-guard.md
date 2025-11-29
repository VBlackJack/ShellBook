---
tags:
  - windows
  - security
  - credential-guard
  - virtualization
---

# Credential Guard et Device Guard

Protection des credentials et intégrité du code via la virtualisation (VBS - Virtualization Based Security).

## Credential Guard

### Concept

```
CREDENTIAL GUARD - PROTECTION DES CREDENTIALS
══════════════════════════════════════════════════════════

Sans Credential Guard :
───────────────────────
┌─────────────────────────────────────┐
│           Windows OS                │
│  ┌─────────────────────────────┐   │
│  │         LSASS               │   │  ← Mimikatz peut
│  │  [NTLM Hashes] [Kerberos]   │   │    extraire les
│  │  [Passwords] [Tickets]      │   │    credentials
│  └─────────────────────────────┘   │
└─────────────────────────────────────┘

Avec Credential Guard :
───────────────────────
┌─────────────────────────────────────────────────────┐
│                  Hypervisor (VBS)                   │
│  ┌──────────────────┐  ┌──────────────────────────┐│
│  │   Windows OS     │  │  Isolated LSA (LSAIso)   ││
│  │                  │  │  [NTLM] [Kerberos]       ││
│  │   LSASS (proxy)  │  │  ← Protégé par          ││
│  │                  │  │    l'hyperviseur        ││
│  └──────────────────┘  └──────────────────────────┘│
└─────────────────────────────────────────────────────┘

Mimikatz ne peut PAS accéder à LSAIso (isolation matérielle)
```

### Prérequis

```powershell
# Vérifier les prérequis
# - CPU avec virtualisation (Intel VT-x / AMD-V)
# - UEFI avec Secure Boot
# - TPM 2.0 (recommandé)
# - Windows 10/11 Enterprise ou Education

# Vérifier le support matériel
systeminfo | findstr /i "virtualization"

# Vérifier via PowerShell
Get-ComputerInfo | Select-Object *Hyper*

# Vérifier si VBS est disponible
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
```

### Activation

```powershell
# Méthode 1 : Via GPO (recommandé)
# Computer Configuration > Administrative Templates >
# System > Device Guard > Turn On Virtualization Based Security
#
# Options :
# - Select Platform Security Level : Secure Boot and DMA Protection
# - Credential Guard Configuration : Enabled with UEFI lock
# - Secure Launch Configuration : Enabled

# Méthode 2 : Via PowerShell/Registry
# Activer les features requises
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-Hypervisor -All -NoRestart

# Configurer via Registry
$path = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"
Set-ItemProperty -Path $path -Name "EnableVirtualizationBasedSecurity" -Value 1
Set-ItemProperty -Path $path -Name "RequirePlatformSecurityFeatures" -Value 3  # Secure Boot + DMA

$lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
Set-ItemProperty -Path $lsaPath -Name "LsaCfgFlags" -Value 1  # Enabled with UEFI lock

# Redémarrer
Restart-Computer
```

### Vérification

```powershell
# Vérifier l'état de Credential Guard
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard |
    Select-Object -ExpandProperty SecurityServicesRunning

# 1 = Credential Guard running
# 2 = HVCI running

# Ou via msinfo32
msinfo32
# Chercher : "Credential Guard" dans la section Virtualization-based security

# Via ligne de commande
systeminfo | findstr /i "credential"
```

---

## Device Guard (HVCI)

### Concept

```
HVCI - HYPERVISOR-PROTECTED CODE INTEGRITY
══════════════════════════════════════════════════════════

Protège contre :
• Drivers malveillants non signés
• Kernel exploits
• Code injection dans le kernel

Vérifie que TOUT le code kernel est :
• Signé par Microsoft ou un éditeur de confiance
• Conforme à la politique WDAC/CI
```

### Activation

```powershell
# Via GPO (même emplacement que Credential Guard)
# Virtualization Based Protection of Code Integrity : Enabled with UEFI lock

# Via Registry
$path = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
New-Item -Path $path -Force
Set-ItemProperty -Path $path -Name "Enabled" -Value 1
Set-ItemProperty -Path $path -Name "Locked" -Value 1  # UEFI lock

Restart-Computer
```

---

## Windows Defender Application Control (WDAC)

### Créer une Policy

```powershell
# Scanner le système pour créer une baseline
New-CIPolicy -Level Publisher -FilePath "C:\Policies\BasePolicy.xml" -UserPEs

# Ajouter des règles
Add-SignerRule -FilePath "C:\Policies\BasePolicy.xml" -CertificatePath "C:\Certs\Trusted.cer" -User

# Convertir en binaire
ConvertFrom-CIPolicy -XmlFilePath "C:\Policies\BasePolicy.xml" -BinaryFilePath "C:\Windows\System32\CodeIntegrity\SIPolicy.p7b"

# Mode Audit d'abord (recommandé)
Set-RuleOption -FilePath "C:\Policies\BasePolicy.xml" -Option 3  # Audit Mode
```

### Déployer via GPO

```
Computer Configuration > Administrative Templates >
System > Device Guard > Deploy Windows Defender Application Control
→ Spécifier le chemin de la policy
```

---

## Remote Credential Guard

```
REMOTE CREDENTIAL GUARD
══════════════════════════════════════════════════════════

Protège les credentials lors des connexions RDP.
Les credentials ne quittent JAMAIS la machine source.

Sans Remote Credential Guard :
  Client → [Credentials] → Serveur RDP
  Si serveur compromis, credentials volés

Avec Remote Credential Guard :
  Client → [Tickets Kerberos temporaires] → Serveur RDP
  Credentials restent sur le client
```

```powershell
# Sur le client (GPO ou registry)
$path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation"
New-Item -Path $path -Force
Set-ItemProperty -Path $path -Name "RestrictedRemoteAdministration" -Value 1
Set-ItemProperty -Path $path -Name "RestrictedRemoteAdministrationType" -Value 2  # Remote Credential Guard

# Connexion RDP avec Remote Credential Guard
mstsc /remoteGuard /v:server.corp.local

# Ou via PowerShell
Enter-PSSession -ComputerName server.corp.local -Credential (Get-Credential) -Authentication CredSSP
```

---

## Troubleshooting

```powershell
# Event logs VBS
Get-WinEvent -LogName "Microsoft-Windows-DeviceGuard/Operational" -MaxEvents 20

# Vérifier les erreurs de drivers incompatibles
Get-WinEvent -FilterHashtable @{
    LogName = "Microsoft-Windows-CodeIntegrity/Operational"
    Level = 2,3
} -MaxEvents 50

# Vérifier l'état complet
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard | Format-List *

# Mode compatibilité (désactiver temporairement)
bcdedit /set hypervisorlaunchtype off
# Réactiver :
bcdedit /set hypervisorlaunchtype auto
```

---

## Bonnes Pratiques

```yaml
Checklist Credential Guard:
  Prérequis:
    - [ ] UEFI + Secure Boot
    - [ ] TPM 2.0
    - [ ] Virtualisation CPU activée
    - [ ] Windows Enterprise/Education

  Déploiement:
    - [ ] Tester en mode Audit d'abord
    - [ ] Vérifier compatibilité drivers
    - [ ] Déployer via GPO
    - [ ] UEFI Lock pour production

  Compléments:
    - [ ] Remote Credential Guard pour RDP
    - [ ] HVCI activé
    - [ ] WDAC si possible
```

---

**Voir aussi :**

- [Windows Security](windows-security.md) - Sécurité Windows
- [BitLocker](bitlocker.md) - Chiffrement disque
- [AppLocker](applocker.md) - Contrôle des applications
