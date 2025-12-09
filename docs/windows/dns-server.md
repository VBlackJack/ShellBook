---
tags:
  - windows
  - dns
  - infrastructure
  - networking
---

# DNS Server Windows

Le service DNS Windows est essentiel pour Active Directory et la résolution de noms en entreprise.

## Architecture DNS Windows

### Intégration Active Directory

```text
DNS ET ACTIVE DIRECTORY
══════════════════════════════════════════════════════════

AD-Integrated DNS (recommandé) :
────────────────────────────────
• Zones stockées dans AD (pas de fichiers)
• Réplication via AD (sécurisée)
• Multi-master (tous les DCs peuvent écrire)
• Secure Dynamic Updates

┌─────────────────────────────────────────────────────────┐
│                    Active Directory                      │
│  ┌─────────────────────────────────────────────────┐   │
│  │           DNS Zone: corp.local                   │   │
│  │                                                  │   │
│  │   DC01 ◄───────────────────────► DC02           │   │
│  │    │          Réplication         │             │   │
│  │    └───────────────┬──────────────┘             │   │
│  │                    │                             │   │
│  │   ┌────────────────┼────────────────┐           │   │
│  │   ▼                ▼                ▼           │   │
│  │ _ldap._tcp    _kerberos._tcp    A records       │   │
│  │ _gc._tcp      _kpasswd._tcp     SRV records     │   │
│  └─────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

### Types de Zones

| Type | Description | Cas d'usage |
|------|-------------|-------------|
| **Primary** | Zone maître, lecture/écriture | Serveur principal |
| **Secondary** | Copie lecture seule | Redondance, performance |
| **Stub** | NS et SOA uniquement | Délégation, résolution |
| **AD-Integrated** | Stockée dans AD | Domaines AD (recommandé) |

---

## Installation et Configuration

### Installer le Rôle DNS

```powershell
# Installer le rôle DNS Server
Install-WindowsFeature -Name DNS -IncludeManagementTools

# Vérifier l'installation
Get-WindowsFeature DNS

# Sur un DC, DNS est généralement installé automatiquement
```

### Créer des Zones

```powershell
# Créer une zone primaire intégrée AD
Add-DnsServerPrimaryZone -Name "corp.local" `
    -ReplicationScope "Forest" `
    -DynamicUpdate "Secure"

# Créer une zone de recherche inversée
Add-DnsServerPrimaryZone -NetworkId "10.10.0.0/16" `
    -ReplicationScope "Forest" `
    -DynamicUpdate "Secure"

# Créer une zone secondaire
Add-DnsServerSecondaryZone -Name "partner.com" `
    -ZoneFile "partner.com.dns" `
    -MasterServers 10.20.1.10

# Créer une zone stub
Add-DnsServerStubZone -Name "subsidiary.corp" `
    -MasterServers 10.30.1.10 `
    -ReplicationScope "Forest"

# Lister les zones
Get-DnsServerZone
```

### Configurer les Enregistrements

```powershell
# Enregistrement A (Host)
Add-DnsServerResourceRecordA -Name "srv-web-01" `
    -ZoneName "corp.local" `
    -IPv4Address "10.10.1.100"

# Enregistrement AAAA (IPv6)
Add-DnsServerResourceRecordAAAA -Name "srv-web-01" `
    -ZoneName "corp.local" `
    -IPv6Address "2001:db8::100"

# Enregistrement CNAME (Alias)
Add-DnsServerResourceRecordCName -Name "www" `
    -ZoneName "corp.local" `
    -HostNameAlias "srv-web-01.corp.local"

# Enregistrement MX (Mail)
Add-DnsServerResourceRecordMX -Name "." `
    -ZoneName "corp.local" `
    -MailExchange "mail.corp.local" `
    -Preference 10

# Enregistrement TXT
Add-DnsServerResourceRecordTxt -Name "_dmarc" `
    -ZoneName "corp.local" `
    -DescriptiveText "v=DMARC1; p=quarantine;"

# Enregistrement SRV
Add-DnsServerResourceRecord -ZoneName "corp.local" `
    -Name "_http._tcp" `
    -Srv `
    -DomainName "srv-web-01.corp.local" `
    -Priority 0 `
    -Weight 100 `
    -Port 80

# Enregistrement PTR (reverse)
Add-DnsServerResourceRecordPtr -Name "100" `
    -ZoneName "1.10.10.in-addr.arpa" `
    -PtrDomainName "srv-web-01.corp.local"
```

### Gérer les Enregistrements

```powershell
# Lister les enregistrements d'une zone
Get-DnsServerResourceRecord -ZoneName "corp.local"

# Filtrer par type
Get-DnsServerResourceRecord -ZoneName "corp.local" -RRType A
Get-DnsServerResourceRecord -ZoneName "corp.local" -RRType CNAME

# Rechercher un enregistrement
Get-DnsServerResourceRecord -ZoneName "corp.local" -Name "srv-web-01"

# Modifier un enregistrement
$old = Get-DnsServerResourceRecord -ZoneName "corp.local" -Name "srv-web-01" -RRType A
$new = $old.Clone()
$new.RecordData.IPv4Address = [System.Net.IPAddress]::Parse("10.10.1.101")
Set-DnsServerResourceRecord -ZoneName "corp.local" -OldInputObject $old -NewInputObject $new

# Supprimer un enregistrement
Remove-DnsServerResourceRecord -ZoneName "corp.local" -Name "old-server" -RRType A -Force
```

---

## Forwarders et Conditional Forwarders

### Forwarders (Redirecteurs)

```powershell
# Configurer les forwarders (DNS externes)
Set-DnsServerForwarder -IPAddress "8.8.8.8","8.8.4.4" -PassThru

# Ajouter un forwarder
Add-DnsServerForwarder -IPAddress "1.1.1.1"

# Supprimer un forwarder
Remove-DnsServerForwarder -IPAddress "8.8.4.4"

# Voir les forwarders
Get-DnsServerForwarder

# Désactiver les root hints si forwarders configurés
Set-DnsServerForwarder -UseRootHint $false
```

### Conditional Forwarders

```powershell
# Forwarder conditionnel pour un domaine partenaire
Add-DnsServerConditionalForwarderZone -Name "partner.com" `
    -MasterServers 10.20.1.10,10.20.1.11 `
    -ReplicationScope "Forest"

# Pour un trust AD
Add-DnsServerConditionalForwarderZone -Name "trusted-forest.com" `
    -MasterServers 172.16.1.10 `
    -ReplicationScope "Forest"

# Lister les conditional forwarders
Get-DnsServerZone | Where-Object { $_.ZoneType -eq "Forwarder" }

# Modifier
Set-DnsServerConditionalForwarderZone -Name "partner.com" `
    -MasterServers 10.20.1.10,10.20.1.11,10.20.1.12

# Supprimer
Remove-DnsServerZone -Name "old-partner.com" -Force
```

---

## Dynamic Updates

### Configuration

```text
DYNAMIC UPDATES
══════════════════════════════════════════════════════════

Types :
• None           - Pas de mise à jour dynamique
• NonsecureAndSecure - Tous peuvent mettre à jour (risqué!)
• Secure         - Authentification Kerberos requise (recommandé)

Secure Dynamic Update (AD-Integrated) :
• Seuls les comptes AD authentifiés peuvent créer/modifier
• Le créateur devient propriétaire de l'enregistrement
• Utilise GSS-TSIG (Kerberos)
```

```powershell
# Configurer Secure Dynamic Updates (recommandé)
Set-DnsServerPrimaryZone -Name "corp.local" -DynamicUpdate Secure

# Vérifier la configuration
Get-DnsServerZone -Name "corp.local" | Select-Object ZoneName, DynamicUpdate

# Configurer le scavenging (nettoyage des enregistrements obsolètes)
Set-DnsServerZoneAging -Name "corp.local" `
    -Aging $true `
    -NoRefreshInterval (New-TimeSpan -Days 7) `
    -RefreshInterval (New-TimeSpan -Days 7)

# Activer le scavenging au niveau serveur
Set-DnsServerScavenging -ScavengingState $true -ScavengingInterval (New-TimeSpan -Days 7)

# Forcer le scavenging
Start-DnsServerScavenging
```

### Enregistrement des Clients

```powershell
# Sur un client, forcer l'enregistrement DNS
ipconfig /registerdns

# Vérifier l'enregistrement
nslookup pc001.corp.local

# Sur le serveur DNS, voir les enregistrements dynamiques
Get-DnsServerResourceRecord -ZoneName "corp.local" |
    Where-Object { $_.Timestamp -ne $null } |
    Select-Object HostName, RecordType, Timestamp
```

---

## DNSSEC

### Signer une Zone

```powershell
# Signer une zone avec DNSSEC
Invoke-DnsServerZoneSign -ZoneName "corp.local" -SignWithDefault

# Vérifier la signature
Get-DnsServerDnsSecZoneSetting -ZoneName "corp.local"

# Voir les clés
Get-DnsServerSigningKey -ZoneName "corp.local"

# Configurer le rollover automatique des clés
Set-DnsServerSigningKey -ZoneName "corp.local" `
    -KeyType KeySigningKey `
    -RolloverPeriod (New-TimeSpan -Days 365)
```

### Trust Anchors

```powershell
# Configurer les Trust Anchors (pour validation DNSSEC)
Add-DnsServerTrustAnchor -Name "corp.local" `
    -CryptoAlgorithm RsaSha256 `
    -KeyTag 12345 `
    -DigestType Sha256 `
    -Digest "ABCD1234..."

# Lister les Trust Anchors
Get-DnsServerTrustAnchor

# Activer la validation DNSSEC
Set-DnsServerRecursion -SecureResponse $true
```

---

## DNS Policies

### Filtrage par Requête

```powershell
# Bloquer un domaine (malware, etc.)
Add-DnsServerQueryResolutionPolicy -Name "Block-Malware" `
    -Action DENY `
    -Fqdn "EQ,*.malware.com"

# Rediriger vers un sinkhole
Add-DnsServerQueryResolutionPolicy -Name "Sinkhole-Phishing" `
    -Action DENY `
    -Fqdn "EQ,*.phishing-domain.com" `
    -ZoneName "corp.local"

# Lister les policies
Get-DnsServerQueryResolutionPolicy

# Supprimer une policy
Remove-DnsServerQueryResolutionPolicy -Name "Block-Malware"
```

### Split-Brain DNS

```powershell
# Réponse différente selon le subnet source

# Créer les scopes de zone
Add-DnsServerZoneScope -ZoneName "corp.local" -Name "Internal"
Add-DnsServerZoneScope -ZoneName "corp.local" -Name "External"

# Ajouter des enregistrements par scope
Add-DnsServerResourceRecord -ZoneName "corp.local" -ZoneScope "Internal" `
    -A -Name "www" -IPv4Address "10.10.1.100"

Add-DnsServerResourceRecord -ZoneName "corp.local" -ZoneScope "External" `
    -A -Name "www" -IPv4Address "203.0.113.100"

# Créer les subnets clients
Add-DnsServerClientSubnet -Name "InternalSubnet" -IPv4Subnet "10.0.0.0/8"
Add-DnsServerClientSubnet -Name "ExternalSubnet" -IPv4Subnet "0.0.0.0/0"

# Créer les policies de résolution
Add-DnsServerQueryResolutionPolicy -Name "InternalPolicy" `
    -Action ALLOW `
    -ClientSubnet "EQ,InternalSubnet" `
    -ZoneScope "Internal,1" `
    -ZoneName "corp.local"

Add-DnsServerQueryResolutionPolicy -Name "ExternalPolicy" `
    -Action ALLOW `
    -ClientSubnet "EQ,ExternalSubnet" `
    -ZoneScope "External,1" `
    -ZoneName "corp.local"
```

---

## Diagnostic et Troubleshooting

### Commandes de Base

```powershell
# Tester la résolution
Resolve-DnsName "srv-web-01.corp.local"
Resolve-DnsName "srv-web-01.corp.local" -Server DC01
Resolve-DnsName "corp.local" -Type SOA

# nslookup interactif
nslookup
> server DC01.corp.local
> set type=any
> corp.local

# Vérifier les enregistrements SRV AD
Resolve-DnsName "_ldap._tcp.dc._msdcs.corp.local" -Type SRV
Resolve-DnsName "_kerberos._tcp.dc._msdcs.corp.local" -Type SRV

# Test de connectivité DNS
Test-DnsServer -IPAddress 10.10.1.10 -ZoneName "corp.local"
```

### Statistiques et Cache

```powershell
# Statistiques du serveur DNS
Get-DnsServerStatistics

# Voir le cache
Show-DnsServerCache

# Vider le cache
Clear-DnsServerCache

# Sur un client
ipconfig /displaydns
ipconfig /flushdns
```

### Event Logs

```powershell
# Activer le logging DNS
Set-DnsServerDiagnostics -All $true

# Ou logging sélectif
Set-DnsServerDiagnostics -Queries $true `
    -Answers $true `
    -Notifications $true `
    -Update $true `
    -LogFilePath "C:\DNS-Logs\dns.log" `
    -MaxMBFileSize 100

# Voir les événements DNS
Get-WinEvent -LogName "DNS Server" -MaxEvents 50

# Événements d'erreur
Get-WinEvent -FilterHashtable @{
    LogName = "DNS Server"
    Level = 2  # Error
} -MaxEvents 20
```

### DCDiag pour DNS

```powershell
# Tests DNS via DCDiag
dcdiag /test:dns /v

# Test spécifique d'enregistrement
dcdiag /test:RegisterInDNS

# Vérifier les enregistrements AD
nltest /dsgetdc:corp.local
nltest /dclist:corp.local
```

---

## Haute Disponibilité

### Configuration Recommandée

```text
HAUTE DISPONIBILITÉ DNS
══════════════════════════════════════════════════════════

Option 1 : AD-Integrated (recommandé)
─────────────────────────────────────
• Tous les DCs = serveurs DNS
• Réplication automatique via AD
• Multi-master writes

Option 2 : Primary + Secondary
──────────────────────────────
• 1 Primary (read/write)
• N Secondary (read-only)
• Zone transfer pour réplication

Configuration clients :
───────────────────────
• 2 serveurs DNS minimum par client
• DNS primaire = DC local
• DNS secondaire = DC autre site
```

```powershell
# Configurer les transferts de zone (si non AD-integrated)
Set-DnsServerPrimaryZone -Name "corp.local" `
    -SecureSecondaries TransferToSecureServers `
    -SecondaryServers 10.10.2.10,10.10.2.11

# Notifier les secondaires
Set-DnsServerPrimaryZone -Name "corp.local" `
    -Notify NotifyServers `
    -NotifyServers 10.10.2.10,10.10.2.11

# Sur le secondaire, configurer le transfert
Set-DnsServerSecondaryZone -Name "corp.local" `
    -MasterServers 10.10.1.10
```

---

## Bonnes Pratiques

```yaml
Checklist DNS Windows:
  Configuration:
    - [ ] DNS intégré AD (pas de fichiers de zone)
    - [ ] Réplication scope = Forest ou Domain
    - [ ] Secure Dynamic Updates uniquement
    - [ ] Scavenging activé (7 jours)

  Sécurité:
    - [ ] Forwarders = DNS de confiance
    - [ ] Conditional forwarders pour trusts
    - [ ] DNSSEC si exposition externe
    - [ ] Policies de blocage malware

  Performance:
    - [ ] DNS sur tous les DCs
    - [ ] 2 DNS par client (sites différents)
    - [ ] Cache suffisamment grand

  Monitoring:
    - [ ] Logs activés
    - [ ] Alertes sur erreurs
    - [ ] Test régulier des résolutions
```

---

## Références

- [Microsoft Docs - DNS Server](https://docs.microsoft.com/en-us/windows-server/networking/dns/dns-top)
- [Microsoft Docs - DNSSEC](https://docs.microsoft.com/en-us/windows-server/networking/dns/deploy/dns-security)
- [DNS Best Practices](https://docs.microsoft.com/en-us/windows-server/networking/dns/dns-best-practices)

---

**Voir aussi :**

- [Active Directory](active-directory.md) - DNS et AD
- [DHCP Server](dhcp-server.md) - Configuration DHCP
- [Network Troubleshooting](network-troubleshooting.md) - Diagnostic réseau
