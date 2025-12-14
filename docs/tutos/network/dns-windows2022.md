---
tags:
  - tutos
  - dns
  - windows
  - network
  - active-directory
---

# Serveur DNS sur Windows Server 2022

Configuration d'un serveur **DNS Windows** standalone ou intégré à Active Directory.

| Composant | Version |
|-----------|---------|
| Windows Server | 2022 |
| DNS Server | Intégré |

**Durée estimée :** 30 minutes

**Prérequis :**

- Windows Server 2022 installé
- Accès Administrateur
- IP statique configurée
- Nom de domaine à gérer (ex: `example.lan`)

---

## 1. Installation du rôle DNS

### Via PowerShell (recommandé)

```powershell
# Installer le rôle DNS Server
Install-WindowsFeature -Name DNS -IncludeManagementTools

# Vérifier l'installation
Get-WindowsFeature -Name DNS
```

### Vérifier le service

```powershell
# Statut du service
Get-Service -Name DNS

# Démarrer si nécessaire
Start-Service -Name DNS

# Configurer le démarrage automatique
Set-Service -Name DNS -StartupType Automatic
```

---

## 2. Configuration du Firewall

```powershell
# Le rôle DNS configure automatiquement le firewall
# Vérifier les règles
Get-NetFirewallRule -DisplayName "*DNS*" | Select-Object DisplayName, Enabled

# Si nécessaire, activer manuellement
Enable-NetFirewallRule -DisplayGroup "DNS Service"
```

---

## 3. Configurer les paramètres du serveur DNS

### Forwarders (redirecteurs)

```powershell
# Ajouter des forwarders
Add-DnsServerForwarder -IPAddress 8.8.8.8
Add-DnsServerForwarder -IPAddress 8.8.4.4

# Vérifier les forwarders
Get-DnsServerForwarder

# Supprimer un forwarder
# Remove-DnsServerForwarder -IPAddress 8.8.8.8
```

### Paramètres globaux

```powershell
# Activer le round-robin (load balancing DNS)
Set-DnsServerSetting -RoundRobin $true

# Configurer le scavenging (nettoyage automatique)
Set-DnsServerScavenging -ScavengingState $true -RefreshInterval 7.00:00:00 -NoRefreshInterval 7.00:00:00

# Désactiver la récursion (si serveur autoritaire uniquement)
# Set-DnsServerRecursion -Enable $false
```

---

## 4. Créer une zone forward

### Zone primaire

```powershell
# Créer la zone forward
Add-DnsServerPrimaryZone -Name "example.lan" -ZoneFile "example.lan.dns" -DynamicUpdate None

# Vérifier
Get-DnsServerZone -Name "example.lan"
```

### Si intégré à Active Directory

```powershell
# Zone intégrée AD (recommandé avec AD)
Add-DnsServerPrimaryZone -Name "example.lan" -ReplicationScope Domain -DynamicUpdate Secure
```

---

## 5. Créer une zone reverse

```powershell
# Zone reverse pour 192.168.1.0/24
Add-DnsServerPrimaryZone -NetworkId "192.168.1.0/24" -ZoneFile "1.168.192.in-addr.arpa.dns" -DynamicUpdate None

# Vérifier
Get-DnsServerZone -Name "1.168.192.in-addr.arpa"
```

---

## 6. Ajouter des enregistrements DNS

### Enregistrements A (Host)

```powershell
# Serveur de noms
Add-DnsServerResourceRecordA -ZoneName "example.lan" -Name "ns1" -IPv4Address "192.168.1.10" -CreatePtr

# Serveurs applicatifs
Add-DnsServerResourceRecordA -ZoneName "example.lan" -Name "srv-web" -IPv4Address "192.168.1.20" -CreatePtr
Add-DnsServerResourceRecordA -ZoneName "example.lan" -Name "srv-db" -IPv4Address "192.168.1.21" -CreatePtr
Add-DnsServerResourceRecordA -ZoneName "example.lan" -Name "srv-mail" -IPv4Address "192.168.1.22" -CreatePtr

# Vérifier les enregistrements
Get-DnsServerResourceRecord -ZoneName "example.lan" -RRType A
```

### Enregistrements CNAME (Alias)

```powershell
# Créer des alias
Add-DnsServerResourceRecordCName -ZoneName "example.lan" -Name "www" -HostNameAlias "srv-web.example.lan"
Add-DnsServerResourceRecordCName -ZoneName "example.lan" -Name "mysql" -HostNameAlias "srv-db.example.lan"
Add-DnsServerResourceRecordCName -ZoneName "example.lan" -Name "mail" -HostNameAlias "srv-mail.example.lan"

# Vérifier
Get-DnsServerResourceRecord -ZoneName "example.lan" -RRType CName
```

### Enregistrement MX (Mail)

```powershell
# Ajouter l'enregistrement MX
Add-DnsServerResourceRecordMX -ZoneName "example.lan" -Name "." -MailExchange "srv-mail.example.lan" -Preference 10

# Vérifier
Get-DnsServerResourceRecord -ZoneName "example.lan" -RRType MX
```

### Enregistrement NS

```powershell
# Le NS @ est créé automatiquement, mais pour en ajouter un secondaire :
Add-DnsServerResourceRecord -ZoneName "example.lan" -NS -Name "." -NameServer "ns2.example.lan"
```

---

## 7. Configurer les enregistrements PTR

```powershell
# Si -CreatePtr n'a pas été utilisé, ajouter manuellement
Add-DnsServerResourceRecordPtr -ZoneName "1.168.192.in-addr.arpa" -Name "10" -PtrDomainName "ns1.example.lan"
Add-DnsServerResourceRecordPtr -ZoneName "1.168.192.in-addr.arpa" -Name "20" -PtrDomainName "srv-web.example.lan"

# Vérifier
Get-DnsServerResourceRecord -ZoneName "1.168.192.in-addr.arpa" -RRType PTR
```

---

## 8. Tests DNS

### Depuis le serveur

```powershell
# Test résolution forward
Resolve-DnsName -Name srv-web.example.lan -Server localhost

# Test résolution reverse
Resolve-DnsName -Name 192.168.1.20 -Server localhost

# Test CNAME
Resolve-DnsName -Name www.example.lan -Server localhost

# Test MX
Resolve-DnsName -Name example.lan -Type MX -Server localhost

# Avec nslookup
nslookup srv-web.example.lan localhost
nslookup -type=mx example.lan localhost
```

### Configurer un client Windows

```powershell
# Configurer le DNS sur une interface
$adapter = Get-NetAdapter | Where-Object {$_.Status -eq "Up"}
Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses "192.168.1.10"

# Vérifier
Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex

# Tester
Resolve-DnsName srv-web.example.lan
```

---

## 9. Commandes de gestion

### Gestion des zones

```powershell
# Lister toutes les zones
Get-DnsServerZone

# Exporter une zone
Export-DnsServerZone -Name "example.lan" -FileName "example.lan.backup.dns"

# Recharger une zone
Sync-DnsServerZone -Name "example.lan"

# Supprimer une zone
# Remove-DnsServerZone -Name "example.lan" -Force
```

### Gestion des enregistrements

```powershell
# Lister tous les enregistrements d'une zone
Get-DnsServerResourceRecord -ZoneName "example.lan"

# Modifier un enregistrement A
$old = Get-DnsServerResourceRecord -ZoneName "example.lan" -Name "srv-web" -RRType A
$new = $old.Clone()
$new.RecordData.IPv4Address = [System.Net.IPAddress]::Parse("192.168.1.25")
Set-DnsServerResourceRecord -ZoneName "example.lan" -OldInputObject $old -NewInputObject $new

# Supprimer un enregistrement
Remove-DnsServerResourceRecord -ZoneName "example.lan" -Name "old-server" -RRType A -Force
```

### Cache et statistiques

```powershell
# Vider le cache DNS du serveur
Clear-DnsServerCache

# Voir les statistiques
Get-DnsServerStatistics

# Voir le cache
Show-DnsServerCache
```

---

## 10. Logging et diagnostic

### Activer le logging DNS

```powershell
# Activer le debug logging
Set-DnsServerDiagnostics -All $true

# Ou sélectivement
Set-DnsServerDiagnostics -Queries $true -Answers $true -LogFilePath "C:\Windows\System32\dns\dns.log" -MaxMBFileSize 50

# Vérifier
Get-DnsServerDiagnostics
```

### Event Viewer

```powershell
# Voir les événements DNS récents
Get-WinEvent -LogName "DNS Server" -MaxEvents 50 | Format-Table TimeCreated, Message -Wrap
```

---

## 11. Zone secondaire (optionnel)

### Autoriser le transfert sur le primaire

```powershell
# Autoriser le transfert vers le serveur secondaire
Set-DnsServerPrimaryZone -Name "example.lan" -SecureSecondaries TransferToSecureServers -SecondaryServers "192.168.1.11"
```

### Créer la zone secondaire

```powershell
# Sur le serveur secondaire
Add-DnsServerSecondaryZone -Name "example.lan" -ZoneFile "example.lan.dns" -MasterServers "192.168.1.10"

# Forcer le transfert
Start-DnsServerZoneTransfer -Name "example.lan" -FullTransfer
```

---

## 12. Intégration Active Directory

### Convertir une zone en zone intégrée AD

```powershell
# Convertir une zone existante
ConvertTo-DnsServerPrimaryZone -Name "example.lan" -ReplicationScope Domain -PassThru

# Activer les mises à jour dynamiques sécurisées
Set-DnsServerPrimaryZone -Name "example.lan" -DynamicUpdate Secure
```

### Vérifier la réplication

```powershell
# Vérifier l'étendue de réplication
Get-DnsServerZone -Name "example.lan" | Select-Object ZoneName, ZoneType, IsDsIntegrated, ReplicationScope
```

---

## Dépannage

### Le service DNS ne démarre pas

```powershell
# Vérifier les événements
Get-WinEvent -LogName "DNS Server" -MaxEvents 20

# Vérifier les dépendances
Get-Service -Name DNS -DependentServices
```

### Résolution échoue

```powershell
# Tester la connectivité
Test-NetConnection -ComputerName 192.168.1.10 -Port 53

# Vérifier que le DNS écoute
Get-NetTCPConnection -LocalPort 53
Get-NetUDPEndpoint -LocalPort 53

# Vérifier les forwarders
Test-DnsServer -IPAddress 8.8.8.8
```

### Zone non répliquée (AD)

```powershell
# Forcer la réplication AD
repadmin /syncall /AeD

# Vérifier la réplication
Get-DnsServerZone -Name "example.lan" | Select-Object *
```

---

## Script complet de déploiement

```powershell
# Script de déploiement DNS complet
$domain = "example.lan"
$network = "192.168.1"
$dnsServer = "192.168.1.10"

# Installer le rôle
Install-WindowsFeature -Name DNS -IncludeManagementTools

# Configurer les forwarders
Add-DnsServerForwarder -IPAddress 8.8.8.8
Add-DnsServerForwarder -IPAddress 8.8.4.4

# Créer les zones
Add-DnsServerPrimaryZone -Name $domain -ZoneFile "$domain.dns"
Add-DnsServerPrimaryZone -NetworkId "$network.0/24" -ZoneFile "$network.in-addr.arpa.dns"

# Ajouter les enregistrements
Add-DnsServerResourceRecordA -ZoneName $domain -Name "ns1" -IPv4Address $dnsServer -CreatePtr
Add-DnsServerResourceRecordA -ZoneName $domain -Name "srv-web" -IPv4Address "$network.20" -CreatePtr
Add-DnsServerResourceRecordA -ZoneName $domain -Name "srv-db" -IPv4Address "$network.21" -CreatePtr

Add-DnsServerResourceRecordCName -ZoneName $domain -Name "www" -HostNameAlias "srv-web.$domain"
Add-DnsServerResourceRecordCName -ZoneName $domain -Name "mysql" -HostNameAlias "srv-db.$domain"

Write-Host "DNS Server configured successfully!" -ForegroundColor Green
```

---

## Pour aller plus loin

- [DHCP Windows Server 2022](dhcp-windows2022.md)
- [Active Directory](../../windows/active-directory.md)
- [DNS Bind Rocky 9](dns-bind-rocky9.md)

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale - Windows Server 2022 DNS |
