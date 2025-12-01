---
tags:
  - formation
  - windows-server
  - reseau
  - dns
  - dhcp
---

# Module 09 : Réseau & DNS/DHCP

## Objectifs du Module

Ce module couvre la configuration réseau et les services DNS/DHCP :

- Configurer les interfaces réseau avec PowerShell
- Installer et configurer le rôle DNS Server
- Installer et configurer le rôle DHCP Server
- Comprendre les zones DNS et les enregistrements
- Gérer les scopes DHCP et les réservations

**Durée :** 7 heures

**Niveau :** Administration

---

## 1. Configuration Réseau

### 1.1 Interfaces Réseau

```powershell
# Lister les adaptateurs
Get-NetAdapter

# Détails d'une interface
Get-NetAdapter -Name "Ethernet" | Select-Object *

# Configuration IP
Get-NetIPAddress -InterfaceAlias "Ethernet"
Get-NetIPConfiguration

# Configurer une IP statique
New-NetIPAddress -InterfaceAlias "Ethernet" `
                 -IPAddress "192.168.1.10" `
                 -PrefixLength 24 `
                 -DefaultGateway "192.168.1.1"

# Configurer le DNS
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" `
                           -ServerAddresses "192.168.1.10", "8.8.8.8"

# Passer en DHCP
Set-NetIPInterface -InterfaceAlias "Ethernet" -Dhcp Enabled
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ResetServerAddresses

# Activer/Désactiver une interface
Enable-NetAdapter -Name "Ethernet"
Disable-NetAdapter -Name "Ethernet"
```

### 1.2 Diagnostic Réseau

```powershell
# Test de connectivité
Test-NetConnection 192.168.1.1
Test-NetConnection google.com -Port 443
Test-NetConnection -ComputerName DC01 -CommonTCPPort RDP

# Résolution DNS
Resolve-DnsName google.com
Resolve-DnsName DC01.corp.local -Type A

# Table de routage
Get-NetRoute
New-NetRoute -DestinationPrefix "10.0.0.0/8" -InterfaceAlias "Ethernet" -NextHop "192.168.1.254"

# Cache DNS
Get-DnsClientCache
Clear-DnsClientCache

# Statistiques
Get-NetAdapterStatistics
```

---

## 2. DNS Server

### 2.1 Installation

```powershell
# Installer le rôle DNS
Install-WindowsFeature -Name DNS -IncludeManagementTools
```

### 2.2 Gestion des Zones

```powershell
# Lister les zones
Get-DnsServerZone

# Créer une zone primaire
Add-DnsServerPrimaryZone -Name "corp.local" `
                          -ZoneFile "corp.local.dns" `
                          -DynamicUpdate Secure

# Créer une zone de recherche inversée
Add-DnsServerPrimaryZone -NetworkId "192.168.1.0/24" `
                          -ZoneFile "1.168.192.in-addr.arpa.dns"

# Créer une zone secondaire
Add-DnsServerSecondaryZone -Name "corp.local" `
                            -ZoneFile "corp.local.dns" `
                            -MasterServers "192.168.1.10"

# Créer un forwarder conditionnel
Add-DnsServerConditionalForwarderZone -Name "partner.com" `
                                       -MasterServers "10.0.0.1"
```

### 2.3 Gestion des Enregistrements

```powershell
# Lister les enregistrements
Get-DnsServerResourceRecord -ZoneName "corp.local"

# Créer un enregistrement A
Add-DnsServerResourceRecordA -ZoneName "corp.local" `
                              -Name "srv01" `
                              -IPv4Address "192.168.1.20"

# Créer un enregistrement CNAME
Add-DnsServerResourceRecordCName -ZoneName "corp.local" `
                                  -Name "www" `
                                  -HostNameAlias "srv01.corp.local"

# Créer un enregistrement MX
Add-DnsServerResourceRecordMX -ZoneName "corp.local" `
                               -Name "." `
                               -MailExchange "mail.corp.local" `
                               -Preference 10

# Créer un enregistrement PTR (reverse)
Add-DnsServerResourceRecordPtr -ZoneName "1.168.192.in-addr.arpa" `
                                -Name "20" `
                                -PtrDomainName "srv01.corp.local"

# Supprimer un enregistrement
Remove-DnsServerResourceRecord -ZoneName "corp.local" -RRType A -Name "oldserver"
```

---

## 3. DHCP Server

### 3.1 Installation

```powershell
# Installer le rôle DHCP
Install-WindowsFeature -Name DHCP -IncludeManagementTools

# Autoriser le serveur DHCP dans AD
Add-DhcpServerInDC -DnsName "DC01.corp.local" -IPAddress "192.168.1.10"

# Configurer les groupes de sécurité
Add-DhcpServerSecurityGroup
```

### 3.2 Configuration des Scopes

```powershell
# Créer un scope
Add-DhcpServerv4Scope -Name "LAN Principal" `
                       -StartRange "192.168.1.100" `
                       -EndRange "192.168.1.200" `
                       -SubnetMask "255.255.255.0" `
                       -State Active

# Configurer les options du scope
Set-DhcpServerv4OptionValue -ScopeId "192.168.1.0" `
                             -DnsDomain "corp.local" `
                             -DnsServer "192.168.1.10" `
                             -Router "192.168.1.1"

# Ajouter une exclusion
Add-DhcpServerv4ExclusionRange -ScopeId "192.168.1.0" `
                                -StartRange "192.168.1.1" `
                                -EndRange "192.168.1.50"

# Créer une réservation
Add-DhcpServerv4Reservation -ScopeId "192.168.1.0" `
                             -IPAddress "192.168.1.150" `
                             -ClientId "00-15-5D-01-02-03" `
                             -Name "PRINTER01"

# Lister les baux actifs
Get-DhcpServerv4Lease -ScopeId "192.168.1.0"
```

### 3.3 Failover DHCP

```powershell
# Configurer le failover
Add-DhcpServerv4Failover -Name "DHCP-Failover" `
                          -PartnerServer "DHCP02.corp.local" `
                          -ScopeId "192.168.1.0" `
                          -SharedSecret "P@ssw0rd123!" `
                          -Mode HotStandby `
                          -ReservePercent 5
```

---

## 4. Exercice Pratique

### Infrastructure Réseau Complète

```powershell
# 1. Installer DNS et DHCP
Install-WindowsFeature -Name DNS, DHCP -IncludeManagementTools

# 2. Créer la zone DNS
Add-DnsServerPrimaryZone -Name "lab.local" -ZoneFile "lab.local.dns"

# 3. Ajouter des enregistrements
Add-DnsServerResourceRecordA -ZoneName "lab.local" -Name "dc01" -IPv4Address "192.168.1.10"
Add-DnsServerResourceRecordA -ZoneName "lab.local" -Name "srv01" -IPv4Address "192.168.1.20"

# 4. Créer le scope DHCP
Add-DhcpServerv4Scope -Name "Lab Network" `
                       -StartRange "192.168.1.100" `
                       -EndRange "192.168.1.150" `
                       -SubnetMask "255.255.255.0"

Set-DhcpServerv4OptionValue -ScopeId "192.168.1.0" `
                             -DnsServer "192.168.1.10" `
                             -DnsDomain "lab.local" `
                             -Router "192.168.1.1"

# 5. Vérifier
Get-DnsServerZone
Get-DhcpServerv4Scope
```

---

## Exercice : À Vous de Jouer

!!! example "Mise en Pratique"
    **Objectif** : Déployer une infrastructure réseau complète avec DNS et DHCP redondants

    **Contexte** : Vous devez configurer les services réseau pour un nouveau site avec 100 postes de travail. Le réseau est 192.168.10.0/24 et nécessite DNS et DHCP redondants pour garantir la haute disponibilité.

    **Tâches à réaliser** :

    1. Configurer une adresse IP statique sur le serveur (192.168.10.10/24)
    2. Installer et configurer les rôles DNS et DHCP
    3. Créer la zone DNS "lab.local" avec 5 enregistrements A
    4. Créer un scope DHCP 192.168.10.100-200 avec les options appropriées
    5. Créer 3 réservations DHCP pour des équipements critiques
    6. Tester la résolution DNS et l'attribution DHCP

    **Critères de validation** :

    - [ ] L'adresse IP statique est configurée correctement
    - [ ] Les rôles DNS et DHCP sont installés et actifs
    - [ ] La zone DNS contient au moins 5 enregistrements
    - [ ] Le scope DHCP est actif avec les options DNS et passerelle configurées
    - [ ] Les 3 réservations DHCP sont créées
    - [ ] Les tests de résolution DNS fonctionnent

??? quote "Solution"
    ```powershell
    # Deploy-NetworkServices.ps1
    # Déploiement complet des services réseau

    # 1. Configuration IP statique
    Write-Host "Configuration de l'adresse IP statique..." -ForegroundColor Yellow
    $adapter = Get-NetAdapter | Where-Object Status -eq "Up" | Select-Object -First 1
    New-NetIPAddress -InterfaceAlias $adapter.Name `
        -IPAddress "192.168.10.10" `
        -PrefixLength 24 `
        -DefaultGateway "192.168.10.1" `
        -ErrorAction SilentlyContinue

    Set-DnsClientServerAddress -InterfaceAlias $adapter.Name `
        -ServerAddresses "192.168.10.10", "8.8.8.8"

    # 2. Installation des rôles
    Write-Host "Installation DNS et DHCP..." -ForegroundColor Yellow
    Install-WindowsFeature -Name DNS, DHCP -IncludeManagementTools

    # 3. Configuration DNS
    Write-Host "Configuration du serveur DNS..." -ForegroundColor Yellow
    Add-DnsServerPrimaryZone -Name "lab.local" -ZoneFile "lab.local.dns"

    # Créer les enregistrements A
    $dnsRecords = @{
        "dc01" = "192.168.10.10"
        "srv01" = "192.168.10.20"
        "srv02" = "192.168.10.21"
        "web01" = "192.168.10.30"
        "db01" = "192.168.10.40"
    }

    foreach ($record in $dnsRecords.GetEnumerator()) {
        Add-DnsServerResourceRecordA -ZoneName "lab.local" `
            -Name $record.Key `
            -IPv4Address $record.Value
        Write-Host "  Enregistrement créé: $($record.Key).lab.local -> $($record.Value)" -ForegroundColor Green
    }

    # 4. Configuration DHCP
    Write-Host "Configuration du serveur DHCP..." -ForegroundColor Yellow

    # Créer le scope
    Add-DhcpServerv4Scope -Name "Lab Network" `
        -StartRange "192.168.10.100" `
        -EndRange "192.168.10.200" `
        -SubnetMask "255.255.255.0" `
        -State Active

    # Configurer les options
    Set-DhcpServerv4OptionValue -ScopeId "192.168.10.0" `
        -DnsServer "192.168.10.10" `
        -DnsDomain "lab.local" `
        -Router "192.168.10.1"

    # 5. Créer les réservations
    Write-Host "Création des réservations DHCP..." -ForegroundColor Yellow
    $reservations = @(
        @{IP="192.168.10.50"; MAC="00-15-5D-00-01-01"; Name="PRINTER01"}
        @{IP="192.168.10.51"; MAC="00-15-5D-00-01-02"; Name="SCANNER01"}
        @{IP="192.168.10.52"; MAC="00-15-5D-00-01-03"; Name="CAMERA01"}
    )

    foreach ($res in $reservations) {
        Add-DhcpServerv4Reservation -ScopeId "192.168.10.0" `
            -IPAddress $res.IP `
            -ClientId $res.MAC `
            -Name $res.Name
        Write-Host "  Réservation: $($res.Name) -> $($res.IP)" -ForegroundColor Green
    }

    # 6. Tests de validation
    Write-Host "`n=== TESTS DE VALIDATION ===" -ForegroundColor Cyan

    # Test DNS
    Write-Host "`nTest de résolution DNS:" -ForegroundColor Yellow
    foreach ($record in $dnsRecords.Keys) {
        $result = Resolve-DnsName "$record.lab.local" -Server 127.0.0.1 -ErrorAction SilentlyContinue
        if ($result) {
            Write-Host "  [OK] $record.lab.local -> $($result.IPAddress)" -ForegroundColor Green
        } else {
            Write-Host "  [ECHEC] $record.lab.local" -ForegroundColor Red
        }
    }

    # Vérifier DHCP
    Write-Host "`nÉtat du scope DHCP:" -ForegroundColor Yellow
    Get-DhcpServerv4Scope | Format-Table ScopeId, Name, State, StartRange, EndRange

    Write-Host "`nRéservations DHCP:" -ForegroundColor Yellow
    Get-DhcpServerv4Reservation -ScopeId "192.168.10.0" | Format-Table IPAddress, ClientId, Name

    Write-Host "`n=== Configuration terminée! ===" -ForegroundColor Green
    ```

---

## Quiz

1. **Quel type d'enregistrement DNS associe un nom à une IP ?**
   - [ ] A. CNAME
   - [ ] B. A
   - [ ] C. MX

2. **Quelle commande crée un scope DHCP ?**
   - [ ] A. New-DhcpScope
   - [ ] B. Add-DhcpServerv4Scope
   - [ ] C. Create-DhcpScope

**Réponses :** 1-B, 2-B

---

**Précédent :** [Module 08 : Stockage & Disques](08-stockage-disques.md)

**Suivant :** [Module 10 : Automatisation Basique](10-automatisation-basique.md)
