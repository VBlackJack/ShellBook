# Windows Hardening & Security

`#defender` `#firewall` `#bitlocker` `#logging`

Sécurisation et audit des systèmes Windows (Blue Team).

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
