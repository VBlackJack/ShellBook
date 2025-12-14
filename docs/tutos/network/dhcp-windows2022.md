---
tags:
  - tutos
  - dhcp
  - windows
  - network
---

# Serveur DHCP sur Windows Server 2022

Configuration du rôle **DHCP Server** sur Windows Server 2022.

| Composant | Version |
|-----------|---------|
| Windows Server | 2022 |
| DHCP Server | Intégré |

**Durée estimée :** 25 minutes

**Prérequis :**

- Windows Server 2022 installé
- Accès Administrateur
- IP statique configurée

---

## 1. Installation du rôle DHCP

### Via PowerShell

```powershell
# Installer le rôle DHCP
Install-WindowsFeature -Name DHCP -IncludeManagementTools

# Vérifier l'installation
Get-WindowsFeature -Name DHCP
```

### Autoriser dans Active Directory (si AD)

```powershell
# Autoriser le serveur DHCP dans AD
Add-DhcpServerInDC -DnsName "srv-dhcp.example.lan" -IPAddress 192.168.1.10

# Vérifier l'autorisation
Get-DhcpServerInDC
```

### Compléter la configuration post-installation

```powershell
# Supprimer l'alerte de configuration
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\ServerManager\Roles\12" -Name "ConfigurationState" -Value 2

# Redémarrer le service
Restart-Service -Name DHCPServer
```

---

## 2. Créer une étendue DHCP

### Étendue de base

```powershell
# Créer une étendue
Add-DhcpServerv4Scope -Name "LAN Principal" `
    -StartRange 192.168.1.100 `
    -EndRange 192.168.1.200 `
    -SubnetMask 255.255.255.0 `
    -LeaseDuration 1.00:00:00 `
    -State Active

# Vérifier
Get-DhcpServerv4Scope
```

### Configurer les options d'étendue

```powershell
# Passerelle par défaut (Router)
Set-DhcpServerv4OptionValue -ScopeId 192.168.1.0 -Router 192.168.1.1

# Serveurs DNS
Set-DhcpServerv4OptionValue -ScopeId 192.168.1.0 -DnsServer 192.168.1.10, 8.8.8.8

# Nom de domaine DNS
Set-DhcpServerv4OptionValue -ScopeId 192.168.1.0 -DnsDomain "example.lan"

# Serveur NTP (option 42)
Set-DhcpServerv4OptionValue -ScopeId 192.168.1.0 -OptionId 42 -Value 192.168.1.10

# Vérifier les options
Get-DhcpServerv4OptionValue -ScopeId 192.168.1.0
```

---

## 3. Plages d'exclusion

```powershell
# Exclure une plage (serveurs, imprimantes, etc.)
Add-DhcpServerv4ExclusionRange -ScopeId 192.168.1.0 `
    -StartRange 192.168.1.1 `
    -EndRange 192.168.1.20

# Vérifier les exclusions
Get-DhcpServerv4ExclusionRange -ScopeId 192.168.1.0
```

---

## 4. Réservations DHCP

### Créer une réservation

```powershell
# Réserver une IP pour un client spécifique
Add-DhcpServerv4Reservation -ScopeId 192.168.1.0 `
    -IPAddress 192.168.1.50 `
    -ClientId "00-11-22-33-44-55" `
    -Name "srv-web" `
    -Description "Serveur Web"

# Autre réservation
Add-DhcpServerv4Reservation -ScopeId 192.168.1.0 `
    -IPAddress 192.168.1.51 `
    -ClientId "00-11-22-33-44-56" `
    -Name "srv-db" `
    -Description "Serveur Base de données"

# Lister les réservations
Get-DhcpServerv4Reservation -ScopeId 192.168.1.0
```

### Options spécifiques à une réservation

```powershell
# Définir un DNS spécifique pour une réservation
Set-DhcpServerv4OptionValue -ReservedIP 192.168.1.50 -DnsServer 192.168.1.10
```

---

## 5. Vérifier le service

```powershell
# Statut du service
Get-Service -Name DHCPServer

# Statistiques
Get-DhcpServerv4Statistics

# Statistiques par étendue
Get-DhcpServerv4ScopeStatistics -ScopeId 192.168.1.0
```

---

## 6. Voir les baux actifs

```powershell
# Lister tous les baux
Get-DhcpServerv4Lease -ScopeId 192.168.1.0

# Baux actifs uniquement
Get-DhcpServerv4Lease -ScopeId 192.168.1.0 | Where-Object {$_.AddressState -eq "Active"}

# Exporter en CSV
Get-DhcpServerv4Lease -ScopeId 192.168.1.0 | Export-Csv -Path "C:\dhcp-leases.csv" -NoTypeInformation
```

---

## 7. Configuration du Firewall

```powershell
# Les règles sont normalement créées automatiquement
# Vérifier
Get-NetFirewallRule -DisplayName "*DHCP*" | Select-Object DisplayName, Enabled

# Si nécessaire, activer manuellement
Enable-NetFirewallRule -DisplayGroup "DHCP Server"
```

---

## 8. Options DHCP avancées

### Options au niveau serveur

```powershell
# Options globales (s'appliquent à toutes les étendues)
Set-DhcpServerv4OptionValue -DnsServer 192.168.1.10
Set-DhcpServerv4OptionValue -DnsDomain "example.lan"

# Voir les options serveur
Get-DhcpServerv4OptionValue
```

### Options personnalisées

```powershell
# Créer une option personnalisée
Add-DhcpServerv4OptionDefinition -OptionId 150 -Name "TFTP Server" -Type IPv4Address -MultiValued

# Appliquer l'option
Set-DhcpServerv4OptionValue -ScopeId 192.168.1.0 -OptionId 150 -Value 192.168.1.10
```

### PXE Boot

```powershell
# Configurer le boot PXE (options 66 et 67)
Set-DhcpServerv4OptionValue -ScopeId 192.168.1.0 -OptionId 66 -Value "192.168.1.10"
Set-DhcpServerv4OptionValue -ScopeId 192.168.1.0 -OptionId 67 -Value "pxelinux.0"
```

---

## 9. DHCP Failover (Haute disponibilité)

### Configurer le failover

```powershell
# Créer une relation failover (sur le serveur primaire)
Add-DhcpServerv4Failover -Name "DHCP-Failover" `
    -PartnerServer "srv-dhcp2.example.lan" `
    -ScopeId 192.168.1.0 `
    -SharedSecret "MotDePasseSecret123!" `
    -Mode LoadBalance `
    -LoadBalancePercent 50

# Vérifier la configuration
Get-DhcpServerv4Failover
```

### Modes disponibles

| Mode | Description |
|------|-------------|
| LoadBalance | Les deux serveurs répondent (50/50 par défaut) |
| HotStandby | Un actif, un passif |

---

## 10. Sauvegarde et restauration

### Sauvegarder

```powershell
# Sauvegarder la configuration DHCP
Backup-DhcpServer -Path "C:\DHCP-Backup"

# Exporter en XML
Export-DhcpServer -File "C:\dhcp-config.xml" -Leases
```

### Restaurer

```powershell
# Restaurer depuis une sauvegarde
Restore-DhcpServer -Path "C:\DHCP-Backup"

# Importer depuis XML
Import-DhcpServer -File "C:\dhcp-config.xml" -Leases -BackupPath "C:\DHCP-Backup-Before-Import"
```

---

## 11. Intégration DNS

### Mise à jour DNS dynamique

```powershell
# Activer la mise à jour DNS
Set-DhcpServerv4DnsSetting -ScopeId 192.168.1.0 `
    -DynamicUpdates Always `
    -DeleteDnsRROnLeaseExpiry $true `
    -UpdateDnsRRForOlderClients $true

# Vérifier
Get-DhcpServerv4DnsSetting -ScopeId 192.168.1.0
```

---

## 12. Commandes utiles

```powershell
# Lister toutes les étendues
Get-DhcpServerv4Scope

# Activer/Désactiver une étendue
Set-DhcpServerv4Scope -ScopeId 192.168.1.0 -State Active
Set-DhcpServerv4Scope -ScopeId 192.168.1.0 -State Inactive

# Supprimer un bail
Remove-DhcpServerv4Lease -ScopeId 192.168.1.0 -IPAddress 192.168.1.150

# Supprimer une étendue
Remove-DhcpServerv4Scope -ScopeId 192.168.1.0 -Force

# Audit logs
Get-DhcpServerAuditLog
```

---

## Dépannage

### Le service ne démarre pas

```powershell
# Vérifier les événements
Get-WinEvent -LogName "Microsoft-Windows-DHCP Server Events/Operational" -MaxEvents 20

# Vérifier la configuration
Get-DhcpServerSetting
```

### Clients ne reçoivent pas d'adresse

```powershell
# Vérifier que l'étendue est active
Get-DhcpServerv4Scope | Select-Object ScopeId, State

# Vérifier les adresses disponibles
Get-DhcpServerv4ScopeStatistics

# Tester la connectivité
Test-NetConnection -ComputerName 192.168.1.10 -Port 67
```

### Conflit d'adresse IP

```powershell
# Voir les conflits
Get-DhcpServerv4Lease -ScopeId 192.168.1.0 | Where-Object {$_.AddressState -eq "Declined"}

# Libérer les baux problématiques
Remove-DhcpServerv4Lease -ScopeId 192.168.1.0 -IPAddress 192.168.1.150
```

---

## Script de déploiement complet

```powershell
# Script de déploiement DHCP
$ScopeId = "192.168.1.0"
$StartRange = "192.168.1.100"
$EndRange = "192.168.1.200"
$Gateway = "192.168.1.1"
$DnsServer = "192.168.1.10"
$Domain = "example.lan"

# Installer le rôle
Install-WindowsFeature -Name DHCP -IncludeManagementTools

# Créer l'étendue
Add-DhcpServerv4Scope -Name "LAN Principal" `
    -StartRange $StartRange `
    -EndRange $EndRange `
    -SubnetMask 255.255.255.0 `
    -State Active

# Configurer les options
Set-DhcpServerv4OptionValue -ScopeId $ScopeId -Router $Gateway
Set-DhcpServerv4OptionValue -ScopeId $ScopeId -DnsServer $DnsServer
Set-DhcpServerv4OptionValue -ScopeId $ScopeId -DnsDomain $Domain

# Exclure les 20 premières adresses
Add-DhcpServerv4ExclusionRange -ScopeId $ScopeId -StartRange "192.168.1.1" -EndRange "192.168.1.20"

Write-Host "DHCP Server configured!" -ForegroundColor Green
Get-DhcpServerv4Scope
```

---

## Pour aller plus loin

- [DNS Windows Server 2022](dns-windows2022.md)
- [Active Directory](../../windows/active-directory.md)
- [DHCP Rocky 9](dhcp-rocky9.md)

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale - Windows Server 2022 DHCP |
