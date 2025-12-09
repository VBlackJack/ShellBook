---
tags:
  - windows
  - bitlocker
  - encryption
  - security
---

# BitLocker

Chiffrement de disques avec BitLocker : configuration, TPM, et récupération.

## Prérequis

```text
PRÉREQUIS BITLOCKER
══════════════════════════════════════════════════════════

Matériel :
• TPM 1.2 ou 2.0 (recommandé)
• UEFI/BIOS compatible Secure Boot
• Partition système EFI ou réservée

Logiciel :
• Windows Pro, Enterprise ou Education
• Rôle BitLocker activé (serveur)

Sans TPM (non recommandé) :
• Nécessite GPO pour autoriser
• Mot de passe ou clé USB au boot
```

---

## Installation et Activation

### Vérifier le Statut TPM

```powershell
# Vérifier le TPM
Get-Tpm

# Détails TPM
Get-WmiObject -Namespace "Root\CIMv2\Security\MicrosoftTpm" -Class Win32_Tpm

# État BitLocker actuel
Get-BitLockerVolume
```

### Activer BitLocker (Disque Système)

```powershell
# Avec TPM uniquement (boot automatique)
Enable-BitLocker -MountPoint "C:" `
    -TpmProtector `
    -EncryptionMethod XtsAes256 `
    -UsedSpaceOnly

# Avec TPM + PIN (recommandé)
$pin = ConvertTo-SecureString "123456" -AsPlainText -Force
Enable-BitLocker -MountPoint "C:" `
    -TpmAndPinProtector `
    -Pin $pin `
    -EncryptionMethod XtsAes256

# Ajouter une clé de récupération
Add-BitLockerKeyProtector -MountPoint "C:" -RecoveryPasswordProtector

# Sauvegarder la clé dans AD
Backup-BitLockerKeyProtector -MountPoint "C:" -KeyProtectorId (
    (Get-BitLockerVolume -MountPoint "C:").KeyProtector |
    Where-Object { $_.KeyProtectorType -eq "RecoveryPassword" }
).KeyProtectorId

# Démarrer le chiffrement
Resume-BitLocker -MountPoint "C:"
```

### Activer BitLocker (Disque de Données)

```powershell
# Avec mot de passe
$pwd = ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force
Enable-BitLocker -MountPoint "D:" `
    -PasswordProtector `
    -Password $pwd `
    -EncryptionMethod XtsAes256

# Auto-unlock (déverrouillage automatique avec le disque système)
Enable-BitLockerAutoUnlock -MountPoint "D:"
```

---

## Gestion des Protecteurs

```powershell
# Lister les protecteurs
(Get-BitLockerVolume -MountPoint "C:").KeyProtector

# Types de protecteurs :
# - Tpm
# - TpmAndPin
# - TpmAndStartupKey
# - TpmAndPinAndStartupKey
# - RecoveryPassword
# - Password
# - ExternalKey (USB)

# Ajouter un protecteur de récupération
Add-BitLockerKeyProtector -MountPoint "C:" -RecoveryPasswordProtector

# Ajouter un protecteur USB
Add-BitLockerKeyProtector -MountPoint "C:" -StartupKeyProtector -StartupKeyPath "E:"

# Supprimer un protecteur
Remove-BitLockerKeyProtector -MountPoint "C:" -KeyProtectorId "{GUID}"

# Changer le PIN
$newPin = ConvertTo-SecureString "654321" -AsPlainText -Force
Add-BitLockerKeyProtector -MountPoint "C:" -TpmAndPinProtector -Pin $newPin
```

---

## Récupération

### Obtenir la Clé de Récupération

```powershell
# Depuis le volume local
(Get-BitLockerVolume -MountPoint "C:").KeyProtector |
    Where-Object { $_.KeyProtectorType -eq "RecoveryPassword" } |
    Select-Object KeyProtectorId, RecoveryPassword

# Depuis Active Directory (sur le DC)
Get-ADObject -Filter 'objectClass -eq "msFVE-RecoveryInformation"' `
    -SearchBase "CN=COMPUTERNAME,OU=Computers,DC=corp,DC=local" `
    -Properties msFVE-RecoveryPassword |
    Select-Object -ExpandProperty msFVE-RecoveryPassword

# Ou via RSAT BitLocker
Get-ADComputer -Identity "COMPUTERNAME" | Get-ADFineGrainedPasswordPolicy
```

### Déverrouiller avec la Clé

```powershell
# Déverrouiller avec mot de passe de récupération
Unlock-BitLocker -MountPoint "D:" -RecoveryPassword "123456-789012-345678-..."

# Déverrouiller avec clé USB
Unlock-BitLocker -MountPoint "D:" -RecoveryKeyPath "E:\recovery.bek"
```

---

## Configuration GPO

### Paramètres Clés

```text
Computer Configuration > Administrative Templates >
Windows Components > BitLocker Drive Encryption

Paramètres importants :
─────────────────────────────────────────────────────────
Operating System Drives:
  • Require additional authentication at startup
    → Configure TPM + PIN

  • Choose how BitLocker-protected drives can be recovered
    → Save to AD DS
    → Do not enable BitLocker until recovery info stored in AD

Fixed Data Drives:
  • Configure use of passwords
  • Configure use of smart cards

Removable Data Drives:
  • Control use of BitLocker on removable drives
  • Deny write access to removable drives not protected by BitLocker
```

### Exiger le Stockage AD

```powershell
# Via Registry (équivalent GPO)
$path = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
New-Item -Path $path -Force
Set-ItemProperty -Path $path -Name "OSRecoveryPassword" -Value 2  # Required
Set-ItemProperty -Path $path -Name "OSRequireActiveDirectoryBackup" -Value 1
```

---

## BitLocker To Go (USB)

```powershell
# Chiffrer une clé USB
$pwd = ConvertTo-SecureString "USBPass123!" -AsPlainText -Force
Enable-BitLocker -MountPoint "E:" `
    -PasswordProtector `
    -Password $pwd `
    -EncryptionMethod XtsAes128

# Lecteurs amovibles peuvent utiliser AES-CBC pour compatibilité
Enable-BitLocker -MountPoint "E:" -EncryptionMethod Aes128
```

---

## Monitoring et Troubleshooting

```powershell
# État du chiffrement
Get-BitLockerVolume | Select-Object MountPoint, VolumeStatus, EncryptionPercentage, ProtectionStatus

# Event logs
Get-WinEvent -LogName "Microsoft-Windows-BitLocker/BitLocker Management" -MaxEvents 20

# Vérifier le status TPM
manage-bde -tpm -turnon

# Réparer un volume
manage-bde -repair C: -RecoveryPassword 123456-789012-...

# Forcer le chiffrement complet (pas seulement espace utilisé)
manage-bde -on C: -UsedSpaceOnly:$false
```

---

## Bonnes Pratiques

```yaml
Checklist BitLocker:
  Configuration:
    - [ ] TPM 2.0 + PIN pour système
    - [ ] XtsAes256 pour disques internes
    - [ ] Clé de récupération dans AD
    - [ ] Auto-unlock pour disques de données

  Sécurité:
    - [ ] PIN de 6+ caractères
    - [ ] Secure Boot activé
    - [ ] Politique de récupération documentée

  Opérations:
    - [ ] Test de récupération régulier
    - [ ] Monitoring du statut
    - [ ] Procédure de décommissionnement
```

---

**Voir aussi :**

- [Windows Security](windows-security.md) - Sécurité Windows
- [Credential Guard](credential-guard.md) - Protection des credentials
- [GPO](ad-gpo.md) - Déploiement via GPO
