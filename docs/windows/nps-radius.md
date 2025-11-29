---
tags:
  - windows
  - nps
  - radius
  - 802.1x
  - network-access
---

# NPS - Network Policy Server (RADIUS)

Configuration du serveur RADIUS Windows pour l'authentification réseau 802.1X et VPN.

## Concepts

```
ARCHITECTURE NPS/RADIUS
══════════════════════════════════════════════════════════

                    ┌─────────────────┐
                    │   Supplicant    │
                    │   (Client)      │
                    │  PC, téléphone  │
                    └────────┬────────┘
                             │ 802.1X / EAP
                             ▼
                    ┌─────────────────┐
                    │  Authenticator  │
                    │ Switch / AP /   │
                    │  VPN Server     │
                    └────────┬────────┘
                             │ RADIUS
                             ▼
                    ┌─────────────────┐
                    │  NPS Server     │
                    │  (RADIUS)       │
                    └────────┬────────┘
                             │
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
       ┌──────────┐   ┌──────────┐   ┌──────────┐
       │   AD DS  │   │    PKI   │   │  DHCP/   │
       │(Accounts)│   │ (Certs)  │   │  VLAN    │
       └──────────┘   └──────────┘   └──────────┘

Flux RADIUS:
1. Client demande accès au réseau
2. Switch/AP envoie requête au NPS
3. NPS vérifie credentials dans AD
4. NPS applique les policies (VLAN, etc.)
5. NPS répond Accept/Reject au switch
6. Switch accorde/refuse l'accès
```

### Protocoles EAP

```
MÉTHODES EAP COURANTES
══════════════════════════════════════════════════════════

EAP-TLS:
• Certificat client ET serveur
• Plus sécurisé
• Nécessite PKI complète
• Recommandé pour machines/utilisateurs

PEAP-MSCHAPv2:
• Certificat serveur uniquement
• Client utilise username/password
• Plus simple à déployer
• Bon compromis sécurité/facilité

EAP-TTLS:
• Similaire à PEAP
• Moins courant sous Windows
• Supporte plus de méthodes internes

EAP-TLS > PEAP-MSCHAPv2 > autres (sécurité)
```

---

## Installation

### Rôle NPS

```powershell
# Installer NPS
Install-WindowsFeature NPAS -IncludeManagementTools

# Inclut :
# - Network Policy Server
# - RADIUS Server
# - RADIUS Proxy
# - Health Registration Authority (HRA)

# Vérifier l'installation
Get-WindowsFeature NPAS

# Console de gestion
nps.msc
```

### Enregistrement dans AD

```powershell
# NPS doit être enregistré dans AD pour lire les propriétés dial-in des utilisateurs
# Nécessite les droits Domain Admins

# Via PowerShell
netsh ras add registeredserver

# Ou via la console NPS :
# Clic droit sur "NPS (Local)" > "Register server in Active Directory"

# Vérifier l'enregistrement
Get-ADGroupMember "RAS and IAS Servers"
```

---

## Configuration RADIUS Clients

### Ajouter un Client RADIUS

```powershell
# Un client RADIUS = un équipement qui envoie des requêtes RADIUS (switch, AP, VPN)

# Via PowerShell
New-NpsRadiusClient -Name "Switch-Core-01" `
    -Address "10.10.1.10" `
    -SharedSecret "SuperSecretKey123!" `
    -VendorName "Cisco"

# Plage d'adresses
New-NpsRadiusClient -Name "Access-Points" `
    -Address "10.10.2.0/24" `
    -SharedSecret "APSecret456!"

# Lister les clients
Get-NpsRadiusClient

# Modifier un client
Set-NpsRadiusClient -Name "Switch-Core-01" -SharedSecret "NewSecret789!"

# Supprimer
Remove-NpsRadiusClient -Name "OldSwitch"
```

### Templates de Clients

```powershell
# Créer un template (via GUI recommandé)
# Console NPS > Templates Management > Shared Secrets

# Utiliser le template
New-NpsRadiusClient -Name "Switch-02" `
    -Address "10.10.1.11" `
    -SharedSecretTemplateName "Switches-Template"
```

---

## Policies NPS

### Connection Request Policies

```powershell
# Définit comment NPS traite les requêtes entrantes
# - Traiter localement
# - Forwarder à un autre RADIUS (proxy)

# Voir les policies
Get-NpsConnectionRequestPolicy

# La policy par défaut traite tout localement
```

### Network Policies

```powershell
# Network Policies = règles d'accès
# Conditions → Contraintes → Settings

# Exemple : Policy 802.1X pour machines du domaine
# Via PowerShell (complexe, GUI recommandé pour création initiale)

# Exporter les policies
Export-NpsConfiguration -Path "C:\NPS\nps-config.xml"

# Importer sur un autre serveur
Import-NpsConfiguration -Path "C:\NPS\nps-config.xml"
```

### Structure d'une Policy

```
NETWORK POLICY STRUCTURE
══════════════════════════════════════════════════════════

1. CONDITIONS (qui est concerné):
   • Windows Groups (Domain Computers, Domain Users)
   • Machine Groups
   • NAS Port Type (Ethernet, Wireless, VPN)
   • Client IPv4 Address
   • Time/Day restrictions
   • HCAP (health)

2. CONSTRAINTS (comment s'authentifier):
   • Authentication Methods (EAP-TLS, PEAP)
   • Idle Timeout
   • Session Timeout
   • Called/Calling Station ID

3. SETTINGS (quoi faire après auth):
   • RADIUS Attributes (VLAN, Filter-Id)
   • NAP Enforcement
   • Routing and Remote Access
   • Encryption
```

---

## 802.1X Wired (Ethernet)

### Configuration NPS pour 802.1X

```powershell
# 1. Créer une Network Policy pour 802.1X filaire

# Via GUI (nps.msc):
# Policies > Network Policies > New

# Conditions:
# - NAS Port Type = "Ethernet"
# - Windows Groups = "Domain Computers" (pour machines)

# Constraints:
# - Authentication Methods:
#   - EAP-TLS (si certificats machines)
#   - ou PEAP-MSCHAPv2 (si username/password)

# Settings:
# - RADIUS Attributes > Standard:
#   - Tunnel-Type = "Virtual LANs (VLAN)"
#   - Tunnel-Medium-Type = "802"
#   - Tunnel-Pvt-Group-ID = "100" (numéro du VLAN)
```

### Attribution de VLAN Dynamique

```powershell
# Exemple de policies pour différents VLANs

# Policy 1: Ordinateurs du domaine → VLAN 100 (Corp)
# Conditions: Windows Groups = "Domain Computers"
# Settings: Tunnel-Pvt-Group-ID = 100

# Policy 2: Utilisateurs invités → VLAN 200 (Guest)
# Conditions: Windows Groups = "Guests"
# Settings: Tunnel-Pvt-Group-ID = 200

# Policy 3: Imprimantes → VLAN 300 (Printers)
# Conditions: Windows Groups = "Printers"
# Settings: Tunnel-Pvt-Group-ID = 300

# L'ordre des policies est important (première qui match = appliquée)
```

### Configuration Switch (Cisco exemple)

```
! Configuration globale
aaa new-model
aaa authentication dot1x default group radius
aaa authorization network default group radius
dot1x system-auth-control

! Configuration RADIUS
radius server NPS-01
 address ipv4 10.10.1.50 auth-port 1812 acct-port 1813
 key SuperSecretKey123!

! Configuration interface
interface GigabitEthernet0/1
 switchport mode access
 switchport access vlan 100
 authentication port-control auto
 dot1x pae authenticator
 spanning-tree portfast
```

---

## 802.1X Wireless (WiFi)

### Configuration NPS pour WiFi

```powershell
# Conditions spécifiques au WiFi
# - NAS Port Type = "Wireless - IEEE 802.11"
# - Called Station ID = SSID (optionnel)

# Exemple policy WiFi Corporate (WPA2-Enterprise)
# Conditions:
# - NAS Port Type = "Wireless - IEEE 802.11"
# - Windows Groups = "Domain Users"
# - Called Station ID contains "CorpWiFi" (optionnel)

# Constraints:
# - Authentication Methods = "Microsoft: Protected EAP (PEAP)"
#   - Inner method = "Secured password (EAP-MSCHAPv2)"
# - NAS Port Type = "Wireless - IEEE 802.11"

# Settings:
# - RADIUS Attributes:
#   - Tunnel-Pvt-Group-ID = 100
```

### Configuration WiFi Controller

```
# Exemple sur contrôleur Cisco WLC

# RADIUS Authentication Servers
config radius auth add 1 10.10.1.50 1812 ascii SuperSecretKey123!
config radius auth add 2 10.10.1.51 1812 ascii SuperSecretKey123!

# WLAN Configuration
config wlan create 1 CorpWiFi CorpWiFi
config wlan security wpa akm 802.1x enable 1
config wlan radius_server auth add 1 1
config wlan enable 1
```

---

## VPN RADIUS

### Configuration pour VPN

```powershell
# NPS peut authentifier les connexions VPN (RRAS, Always On VPN, VPN tiers)

# Conditions:
# - NAS Port Type = "Virtual (VPN)"
# - Windows Groups = "VPN-Users"

# Constraints:
# - Authentication Methods:
#   - EAP-TLS (certificats) - recommandé
#   - ou PEAP-MSCHAPv2

# Settings:
# - Framed-Protocol = PPP
# - Service-Type = Framed
# - Vendor-Specific (selon VPN vendor)
```

### Always On VPN avec NPS

```powershell
# Always On VPN utilise IKEv2 avec EAP

# Prérequis:
# - Certificat serveur sur le VPN server
# - Certificat machine ou user sur les clients
# - NPS configuré pour authentifier

# Conditions:
# - NAS Port Type = "Virtual (VPN)"
# - Windows Groups = "Domain Computers" et/ou "Domain Users"

# Constraints:
# - Authentication Methods = "Microsoft: Smart Card or other certificate"
#   ou "Microsoft: Protected EAP (PEAP)"
```

---

## Certificats et EAP-TLS

### Certificat Serveur NPS

```powershell
# Le serveur NPS a besoin d'un certificat pour PEAP/EAP-TLS

# Template recommandé: "RAS and IAS Server"
# Ou créer un template custom avec:
# - Server Authentication EKU (1.3.6.1.5.5.7.3.1)
# - Subject = FQDN du serveur NPS

# Enroller le certificat
$template = "RASandIASServer"
$cert = Get-Certificate -Template $template -CertStoreLocation Cert:\LocalMachine\My

# Vérifier
Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.EnhancedKeyUsageList -like "*Server Authentication*" }
```

### Certificats Clients (EAP-TLS)

```powershell
# Pour EAP-TLS, les clients ont besoin de certificats

# Machines: Template "Workstation Authentication" ou "Computer"
# Utilisateurs: Template "User" ou custom

# Auto-enrollment via GPO:
# Computer Configuration > Windows Settings > Security Settings >
# Public Key Policies > Certificate Services Client - Auto-Enrollment
```

---

## RADIUS Proxy

### Configuration Proxy

```powershell
# NPS peut forwarder les requêtes à d'autres serveurs RADIUS

# Créer un groupe de serveurs RADIUS distant
# Console NPS > RADIUS Clients and Servers > Remote RADIUS Server Groups

# Créer une Connection Request Policy pour proxy
# - Match sur realm (user@domain.com → forward à domain.com NPS)
# - Match sur Called-Station-ID
```

### Load Balancing

```powershell
# Configurer plusieurs serveurs NPS en haute disponibilité

# Sur chaque client RADIUS (switch, AP):
# - Configurer 2 serveurs RADIUS (primaire et secondaire)
# - Timeout et failover appropriés

# Exemple Cisco:
# radius server NPS-01
#  address ipv4 10.10.1.50
# radius server NPS-02
#  address ipv4 10.10.1.51
#
# aaa group server radius NPS-GROUP
#  server name NPS-01
#  server name NPS-02
```

---

## Logging et Audit

### Configuration des Logs

```powershell
# Activer le logging RADIUS
# Console NPS > Accounting

# Options de logging:
# - Log to text file (IAS format ou DTS)
# - Log to SQL Server
# - Windows Event Log

# Emplacement par défaut: C:\Windows\System32\LogFiles

# Configurer via PowerShell
Set-NpsAccountingConfig -LogPath "D:\NPS-Logs" -MaxLogFileSize 100MB
```

### Event Logs

```powershell
# NPS utilise plusieurs logs

# Security Event Log (authentifications)
Get-WinEvent -LogName Security -MaxEvents 100 |
    Where-Object { $_.Id -in 6272,6273,6274,6275,6276,6277,6278,6279,6280 }

# Event IDs NPS:
# 6272 : Network Policy Server granted access
# 6273 : Network Policy Server denied access
# 6274 : Network Policy Server discarded request
# 6275-6280 : Autres événements d'accès

# NPS Operational Log
Get-WinEvent -LogName "Microsoft-Windows-NetworkPolicies/Operational" -MaxEvents 50
```

### Rapport d'Accès

```powershell
# Script de rapport
function Get-NpsAccessReport {
    param(
        [int]$Hours = 24
    )

    $startTime = (Get-Date).AddHours(-$Hours)

    $events = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        Id = 6272,6273
        StartTime = $startTime
    }

    $events | ForEach-Object {
        $xml = [xml]$_.ToXml()
        [PSCustomObject]@{
            Time = $_.TimeCreated
            EventId = $_.Id
            Result = if ($_.Id -eq 6272) { "Granted" } else { "Denied" }
            User = ($xml.Event.EventData.Data | Where-Object Name -eq "SubjectUserName").'#text'
            NASIPAddress = ($xml.Event.EventData.Data | Where-Object Name -eq "NASIPAddress").'#text'
            AuthType = ($xml.Event.EventData.Data | Where-Object Name -eq "AuthenticationProvider").'#text'
        }
    }
}

Get-NpsAccessReport -Hours 24 | Format-Table
Get-NpsAccessReport -Hours 24 | Export-Csv "C:\Reports\nps-access.csv" -NoTypeInformation
```

---

## Troubleshooting

### Diagnostics

```powershell
# Vérifier le service NPS
Get-Service IAS

# Tester la connectivité RADIUS
# Utiliser NTRadPing ou RadiusTest (outils tiers)

# Vérifier les événements
Get-WinEvent -LogName "Security" -MaxEvents 20 |
    Where-Object { $_.Id -in 6272,6273 } |
    Select-Object TimeCreated, Id, Message

# Debug logging
# Console NPS > Enable verbose logging (via registry)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\IAS\Parameters" `
    -Name "Ping User-Name" -Value 1
```

### Problèmes Courants

```
TROUBLESHOOTING NPS
══════════════════════════════════════════════════════════

"Access-Reject" reçu:
1. Vérifier les credentials (username/password)
2. Vérifier le groupe AD dans les conditions
3. Vérifier le type de port NAS
4. Vérifier la méthode d'authentification

"No response from RADIUS":
1. Vérifier la connectivité réseau (port 1812/1813)
2. Vérifier le shared secret
3. Vérifier que le client RADIUS est configuré dans NPS

Certificat non accepté:
1. Vérifier que le certificat NPS est valide
2. Vérifier la chaîne de confiance sur le client
3. Vérifier les EKU du certificat

VLAN non appliqué:
1. Vérifier les attributs RADIUS dans la policy
2. Vérifier la config du switch (VLAN existe?)
3. Vérifier les logs du switch
```

---

## Bonnes Pratiques

```yaml
Checklist NPS:
  Infrastructure:
    - [ ] Au moins 2 serveurs NPS (HA)
    - [ ] Enregistrement dans AD fait
    - [ ] Certificat serveur valide
    - [ ] Shared secrets forts (20+ caractères)

  Policies:
    - [ ] Policies ordonnées correctement
    - [ ] Conditions spécifiques (pas de wildcard)
    - [ ] Méthodes EAP sécurisées
    - [ ] VLAN dynamique si applicable

  Sécurité:
    - [ ] EAP-TLS préféré à PEAP
    - [ ] Groupes AD dédiés (pas "Domain Users")
    - [ ] Logging activé
    - [ ] Audit des accès

  Opérations:
    - [ ] Backup de la config NPS
    - [ ] Monitoring des échecs d'auth
    - [ ] Test régulier du failover
```

---

**Voir aussi :**

- [Certificate Services](certificate-services.md) - PKI pour certificats
- [Active Directory](active-directory.md) - Groupes et utilisateurs
- [Windows Firewall](windows-firewall.md) - Règles RADIUS
