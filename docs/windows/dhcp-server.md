---
tags:
  - windows
  - dhcp
  - infrastructure
  - networking
---

# DHCP Server Windows

Le serveur DHCP Windows attribue automatiquement les configurations IP aux clients du réseau.

## Installation et Configuration

### Installer le Rôle

```powershell
# Installer DHCP Server
Install-WindowsFeature -Name DHCP -IncludeManagementTools

# Autoriser le serveur DHCP dans AD (obligatoire)
Add-DhcpServerInDC -DnsName "DC01.corp.local" -IPAddress 10.10.1.10

# Vérifier l'autorisation
Get-DhcpServerInDC

# Configurer les groupes de sécurité
Set-DhcpServerDnsCredential -Credential (Get-Credential)

# Désactiver l'avertissement de configuration
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\ServerManager\Roles\12" `
    -Name ConfigurationState -Value 2
```

### Créer un Scope

```powershell
# Créer un scope IPv4
Add-DhcpServerv4Scope -Name "LAN-Paris" `
    -StartRange 10.10.1.100 `
    -EndRange 10.10.1.200 `
    -SubnetMask 255.255.255.0 `
    -State Active `
    -LeaseDuration (New-TimeSpan -Days 8)

# Configurer les options du scope
Set-DhcpServerv4OptionValue -ScopeId 10.10.1.0 `
    -Router 10.10.1.1 `
    -DnsServer 10.10.1.10,10.10.1.11 `
    -DnsDomain "corp.local"

# Ajouter des serveurs NTP (option 42)
Set-DhcpServerv4OptionValue -ScopeId 10.10.1.0 `
    -OptionId 42 `
    -Value 10.10.1.10

# Lister les scopes
Get-DhcpServerv4Scope
```

### Exclusions et Réservations

```powershell
# Exclure une plage (serveurs, imprimantes)
Add-DhcpServerv4ExclusionRange -ScopeId 10.10.1.0 `
    -StartRange 10.10.1.1 `
    -EndRange 10.10.1.50

# Créer une réservation
Add-DhcpServerv4Reservation -ScopeId 10.10.1.0 `
    -IPAddress 10.10.1.150 `
    -ClientId "00-11-22-33-44-55" `
    -Name "Printer-RDC" `
    -Description "Imprimante RDC"

# Lister les réservations
Get-DhcpServerv4Reservation -ScopeId 10.10.1.0

# Supprimer une réservation
Remove-DhcpServerv4Reservation -ScopeId 10.10.1.0 -IPAddress 10.10.1.150
```

---

## DHCP Failover

### Configuration Haute Disponibilité

```text
DHCP FAILOVER MODES
══════════════════════════════════════════════════════════

Hot Standby :
─────────────
• 1 serveur actif, 1 en standby
• Failover automatique
• Idéal pour sites distants

    Primary (Active)     Secondary (Standby)
    ┌────────────┐       ┌────────────┐
    │   DHCP01   │──────►│   DHCP02   │
    │  100% load │       │  0% load   │
    └────────────┘       └────────────┘

Load Balancing :
────────────────
• Les 2 serveurs actifs
• Répartition configurable (50/50 par défaut)
• Idéal pour même site

    Primary (50%)        Secondary (50%)
    ┌────────────┐       ┌────────────┐
    │   DHCP01   │◄─────►│   DHCP02   │
    │  50% load  │       │  50% load  │
    └────────────┘       └────────────┘
```

```powershell
# Configurer le failover Hot Standby
Add-DhcpServerv4Failover -Name "Paris-Failover" `
    -ScopeId 10.10.1.0 `
    -PartnerServer "DHCP02.corp.local" `
    -Mode HotStandby `
    -ReservePercent 5 `
    -ServerRole Active `
    -SharedSecret "SecretP@ss123!"

# Configurer le failover Load Balancing
Add-DhcpServerv4Failover -Name "Paris-LB" `
    -ScopeId 10.10.1.0 `
    -PartnerServer "DHCP02.corp.local" `
    -Mode LoadBalance `
    -LoadBalancePercent 50 `
    -SharedSecret "SecretP@ss123!"

# Vérifier le failover
Get-DhcpServerv4Failover

# Forcer la réplication
Invoke-DhcpServerv4FailoverReplication -Name "Paris-Failover"

# Supprimer le failover
Remove-DhcpServerv4Failover -Name "Paris-Failover"
```

---

## Superscopes et Split Scope

### Superscope

```powershell
# Créer plusieurs scopes
Add-DhcpServerv4Scope -Name "VLAN10-A" -StartRange 10.10.1.100 -EndRange 10.10.1.200 -SubnetMask 255.255.255.0
Add-DhcpServerv4Scope -Name "VLAN10-B" -StartRange 10.10.2.100 -EndRange 10.10.2.200 -SubnetMask 255.255.255.0

# Créer un superscope
Add-DhcpServerv4Superscope -SuperscopeName "VLAN10-All" `
    -ScopeId 10.10.1.0,10.10.2.0

# Voir les superscopes
Get-DhcpServerv4Superscope
```

### Split Scope (Alternative au Failover)

```powershell
# Sur DHCP01 : 80% de la plage
Add-DhcpServerv4Scope -Name "LAN-DHCP01" `
    -StartRange 10.10.1.1 `
    -EndRange 10.10.1.200 `
    -SubnetMask 255.255.255.0

# Sur DHCP02 : 20% de la plage
Add-DhcpServerv4Scope -Name "LAN-DHCP02" `
    -StartRange 10.10.1.201 `
    -EndRange 10.10.1.254 `
    -SubnetMask 255.255.255.0

# Ajuster le delay sur DHCP02 pour que DHCP01 réponde en premier
Set-DhcpServerv4Scope -ScopeId 10.10.1.0 -Delay 500
```

---

## DHCP Policies

### Filtrage par Attribut

```powershell
# Policy basée sur le Vendor Class (HP Printers)
Add-DhcpServerv4Policy -Name "HP-Printers" `
    -ScopeId 10.10.1.0 `
    -Condition OR `
    -VendorClass EQ,"HP*"

# Assigner une plage d'IP spécifique
Set-DhcpServerv4Policy -Name "HP-Printers" `
    -ScopeId 10.10.1.0 `
    -IPRange 10.10.1.230-10.10.1.250

# Policy basée sur le MAC address prefix
Add-DhcpServerv4Policy -Name "Cisco-Phones" `
    -ScopeId 10.10.1.0 `
    -MacAddress EQ,"00-1B-D5-*","00-1E-F7-*"

# Lister les policies
Get-DhcpServerv4Policy -ScopeId 10.10.1.0
```

### Classes de Client

```powershell
# Créer une User Class
Add-DhcpServerv4Class -Name "VIP-Users" `
    -Type User `
    -Data "VIP" `
    -Description "VIP Users with longer lease"

# Policy utilisant la User Class
Add-DhcpServerv4Policy -Name "VIP-Policy" `
    -ScopeId 10.10.1.0 `
    -UserClass EQ,"VIP-Users"

# Lease duration différente pour VIP
Set-DhcpServerv4Policy -Name "VIP-Policy" `
    -ScopeId 10.10.1.0 `
    -LeaseDuration (New-TimeSpan -Days 30)
```

---

## Intégration DNS

### Configuration DDNS

```powershell
# Activer les mises à jour DNS dynamiques
Set-DhcpServerv4DnsSetting -ScopeId 10.10.1.0 `
    -DynamicUpdates Always `
    -DeleteDnsRROnLeaseExpiry $true `
    -UpdateDnsRRForOlderClients $true

# Configurer les credentials DNS (pour Secure Updates)
$cred = Get-Credential
Set-DhcpServerDnsCredential -Credential $cred

# Forcer l'enregistrement PTR
Set-DhcpServerv4DnsSetting -ScopeId 10.10.1.0 `
    -NameProtection $true

# Vérifier les paramètres DNS
Get-DhcpServerv4DnsSetting -ScopeId 10.10.1.0
```

---

## Monitoring et Troubleshooting

### Statistiques et Leases

```powershell
# Statistiques du serveur
Get-DhcpServerv4Statistics

# Statistiques par scope
Get-DhcpServerv4ScopeStatistics -ScopeId 10.10.1.0

# Lister les baux actifs
Get-DhcpServerv4Lease -ScopeId 10.10.1.0

# Filtrer par état
Get-DhcpServerv4Lease -ScopeId 10.10.1.0 | Where-Object { $_.AddressState -eq "Active" }

# Trouver un bail par MAC
Get-DhcpServerv4Lease -ScopeId 10.10.1.0 -ClientId "00-11-22-33-44-55"

# Supprimer un bail
Remove-DhcpServerv4Lease -ScopeId 10.10.1.0 -IPAddress 10.10.1.150
```

### Audit et Logs

```powershell
# Activer l'audit
Set-DhcpServerAuditLog -Enable $true -Path "C:\DHCP-Logs"

# Voir les logs d'audit
Get-Content "C:\Windows\System32\dhcp\DhcpSrvLog-*.log" | Select-Object -Last 100

# Event Viewer
Get-WinEvent -LogName "Microsoft-Windows-DHCP Server Events/Operational" -MaxEvents 50

# Événements d'erreur
Get-WinEvent -FilterHashtable @{
    LogName = "Microsoft-Windows-DHCP Server Events/Operational"
    Level = 2
} -MaxEvents 20
```

### Dépannage Client

```powershell
# Sur le client - Libérer/Renouveler
ipconfig /release
ipconfig /renew

# Voir la configuration DHCP
ipconfig /all

# Diagnostiquer
Get-NetIPConfiguration
Test-NetConnection -ComputerName DHCP01 -Port 67

# Vérifier le service DHCP Client
Get-Service -Name Dhcp
```

---

## Backup et Migration

### Backup

```powershell
# Backup de la configuration DHCP
Backup-DhcpServer -Path "C:\DHCP-Backup"

# Export en XML
Export-DhcpServer -File "C:\DHCP-Backup\dhcp-config.xml" -Leases

# Backup automatique (tâche planifiée)
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
    -Argument "-Command Backup-DhcpServer -Path 'C:\DHCP-Backup\$(Get-Date -Format yyyyMMdd)'"
$trigger = New-ScheduledTaskTrigger -Daily -At "02:00"
Register-ScheduledTask -TaskName "DHCP-Backup" -Action $action -Trigger $trigger
```

### Migration

```powershell
# Sur l'ancien serveur - Export
Export-DhcpServer -File "\\share\dhcp-export.xml" -Leases

# Sur le nouveau serveur - Import
Import-DhcpServer -File "\\share\dhcp-export.xml" -BackupPath "C:\DHCP-Backup" -Leases

# Autoriser le nouveau serveur
Add-DhcpServerInDC -DnsName "DHCP-NEW.corp.local"

# Retirer l'ancien serveur
Remove-DhcpServerInDC -DnsName "DHCP-OLD.corp.local"
```

---

## Bonnes Pratiques

```yaml
Checklist DHCP:
  Configuration:
    - [ ] Serveur autorisé dans AD
    - [ ] Exclusions pour IPs statiques
    - [ ] Réservations documentées
    - [ ] Options (DNS, Gateway) configurées

  Haute Disponibilité:
    - [ ] Failover ou Split-Scope
    - [ ] Test de basculement
    - [ ] Monitoring des deux serveurs

  Sécurité:
    - [ ] Audit activé
    - [ ] Policies de filtrage si nécessaire
    - [ ] Credentials DNS sécurisés

  Maintenance:
    - [ ] Backup automatique
    - [ ] Monitoring utilisation scopes
    - [ ] Alertes seuil 80%
```

---

**Voir aussi :**

- [DNS Server](dns-server.md) - Configuration DNS
- [Active Directory](active-directory.md) - Intégration AD
- [Network Troubleshooting](network-troubleshooting.md) - Diagnostic réseau
