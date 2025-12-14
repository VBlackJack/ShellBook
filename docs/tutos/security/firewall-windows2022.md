---
tags:
  - tutos
  - firewall
  - security
  - windows
---

# Windows Firewall sur Windows Server 2022

Configuration du **Windows Defender Firewall** avec PowerShell.

| Composant | Version |
|-----------|---------|
| Windows Server | 2022 |
| Windows Firewall | Intégré |

**Durée estimée :** 20 minutes

---

## 1. Vérifier l'état

```powershell
# État du firewall
Get-NetFirewallProfile | Select-Object Name, Enabled

# Profil actif
Get-NetConnectionProfile
```

---

## 2. Activer/Désactiver le firewall

```powershell
# Activer tous les profils
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

# Désactiver (déconseillé en prod)
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False

# Activer un profil spécifique
Set-NetFirewallProfile -Profile Domain -Enabled True
```

---

## 3. Politique par défaut

```powershell
# Bloquer tout en entrée, autoriser en sortie
Set-NetFirewallProfile -Profile Domain,Public,Private `
    -DefaultInboundAction Block `
    -DefaultOutboundAction Allow

# Vérifier
Get-NetFirewallProfile | Select-Object Name, DefaultInboundAction, DefaultOutboundAction
```

---

## 4. Créer des règles

### Par port

```powershell
# Autoriser un port TCP entrant
New-NetFirewallRule -DisplayName "HTTP (80)" `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort 80 `
    -Action Allow

# HTTPS
New-NetFirewallRule -DisplayName "HTTPS (443)" `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort 443 `
    -Action Allow

# Plage de ports
New-NetFirewallRule -DisplayName "App Ports" `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort 3000-3100 `
    -Action Allow

# Port UDP
New-NetFirewallRule -DisplayName "DNS" `
    -Direction Inbound `
    -Protocol UDP `
    -LocalPort 53 `
    -Action Allow
```

### Par programme

```powershell
# Autoriser une application
New-NetFirewallRule -DisplayName "Mon Application" `
    -Direction Inbound `
    -Program "C:\Apps\myapp.exe" `
    -Action Allow
```

### Par adresse IP

```powershell
# Autoriser un réseau source
New-NetFirewallRule -DisplayName "SQL from LAN" `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort 1433 `
    -RemoteAddress 192.168.1.0/24 `
    -Action Allow

# Bloquer une IP
New-NetFirewallRule -DisplayName "Block Attacker" `
    -Direction Inbound `
    -RemoteAddress 10.0.0.50 `
    -Action Block
```

---

## 5. Gérer les règles existantes

```powershell
# Lister toutes les règles
Get-NetFirewallRule | Select-Object DisplayName, Enabled, Direction, Action

# Règles entrantes activées
Get-NetFirewallRule -Direction Inbound -Enabled True |
    Select-Object DisplayName, Action |
    Sort-Object DisplayName

# Chercher une règle
Get-NetFirewallRule -DisplayName "*SQL*"

# Activer/Désactiver une règle
Enable-NetFirewallRule -DisplayName "HTTP (80)"
Disable-NetFirewallRule -DisplayName "HTTP (80)"

# Supprimer une règle
Remove-NetFirewallRule -DisplayName "HTTP (80)"
```

---

## 6. Règles de service Windows

```powershell
# Activer les règles prédéfinies
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
Enable-NetFirewallRule -DisplayGroup "File and Printer Sharing"
Enable-NetFirewallRule -DisplayGroup "Windows Remote Management"

# Lister les groupes
Get-NetFirewallRule |
    Select-Object -ExpandProperty Group |
    Sort-Object -Unique
```

---

## 7. Logging

```powershell
# Activer le logging
Set-NetFirewallProfile -Profile Domain,Public,Private `
    -LogFileName "C:\Windows\System32\LogFiles\Firewall\pfirewall.log" `
    -LogMaxSizeKilobytes 32768 `
    -LogBlocked True `
    -LogAllowed False

# Voir les logs
Get-Content "C:\Windows\System32\LogFiles\Firewall\pfirewall.log" -Tail 50
```

---

## 8. Configuration serveur type

### Serveur Web IIS

```powershell
# HTTP/HTTPS
New-NetFirewallRule -DisplayName "HTTP" -Direction Inbound -Protocol TCP -LocalPort 80 -Action Allow
New-NetFirewallRule -DisplayName "HTTPS" -Direction Inbound -Protocol TCP -LocalPort 443 -Action Allow

# Management (limité au LAN)
New-NetFirewallRule -DisplayName "RDP from LAN" -Direction Inbound -Protocol TCP -LocalPort 3389 -RemoteAddress 192.168.1.0/24 -Action Allow
New-NetFirewallRule -DisplayName "WinRM from LAN" -Direction Inbound -Protocol TCP -LocalPort 5985,5986 -RemoteAddress 192.168.1.0/24 -Action Allow
```

### Serveur SQL

```powershell
New-NetFirewallRule -DisplayName "SQL Server" -Direction Inbound -Protocol TCP -LocalPort 1433 -RemoteAddress 192.168.1.0/24 -Action Allow
New-NetFirewallRule -DisplayName "SQL Browser" -Direction Inbound -Protocol UDP -LocalPort 1434 -RemoteAddress 192.168.1.0/24 -Action Allow
```

### Domain Controller

```powershell
# AD DS
Enable-NetFirewallRule -DisplayGroup "Active Directory Domain Services"
Enable-NetFirewallRule -DisplayGroup "DNS Service"
Enable-NetFirewallRule -DisplayGroup "Kerberos Key Distribution Center"

# Ou manuellement
$adPorts = @(53, 88, 135, 389, 445, 464, 636, 3268, 3269)
foreach ($port in $adPorts) {
    New-NetFirewallRule -DisplayName "AD Port $port" -Direction Inbound -Protocol TCP -LocalPort $port -Action Allow
}
```

---

## 9. IPsec

```powershell
# Créer une règle avec authentification IPsec
New-NetFirewallRule -DisplayName "Secure SQL" `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort 1433 `
    -Authentication Required `
    -Encryption Required `
    -Action Allow
```

---

## 10. Export/Import

```powershell
# Exporter les règles
netsh advfirewall export "C:\backup\firewall-rules.wfw"

# Importer
netsh advfirewall import "C:\backup\firewall-rules.wfw"

# Export en PowerShell
Get-NetFirewallRule | Export-Clixml "C:\backup\firewall-rules.xml"

# Import PowerShell
Import-Clixml "C:\backup\firewall-rules.xml" | Set-NetFirewallRule
```

---

## 11. GPO Firewall

```powershell
# Les règles via GPO sont prioritaires
# Configuration via: Computer Configuration > Policies > Windows Settings > Security Settings > Windows Defender Firewall

# Voir les règles GPO
Get-NetFirewallRule | Where-Object {$_.PolicyStoreSource -ne "PersistentStore"}
```

---

## Dépannage

```powershell
# Tester la connectivité
Test-NetConnection -ComputerName 192.168.1.10 -Port 80

# Voir les connexions actives
Get-NetTCPConnection -State Established

# Ports en écoute
Get-NetTCPConnection -State Listen

# Reset du firewall
netsh advfirewall reset

# Vérifier si une règle bloque
Get-NetFirewallRule -Direction Inbound |
    Where-Object {$_.Enabled -eq 'True' -and $_.Action -eq 'Block'}

# Logs événements
Get-WinEvent -LogName "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall" -MaxEvents 50
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
