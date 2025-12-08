---
tags:
  - defender
  - firewall
  - windows
  - security
---

# Windows Firewall & Defender

Protection périmétrique Windows : Firewall et antivirus intégré.

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

## Référence Rapide

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
```

---

!!! tip "À lire aussi"
    - [Hardening ANSSI](hardening-anssi.md) - GPO de sécurité et audit
    - [BitLocker](bitlocker.md) - Chiffrement des disques
