---
tags:
  - windows
  - network
  - troubleshooting
  - diagnostics
---

# Network Troubleshooting Windows

Outils et techniques de diagnostic réseau avancé sous Windows.

## Outils de Diagnostic

```text
OUTILS RÉSEAU WINDOWS
══════════════════════════════════════════════════════════

ping          Test de connectivité ICMP
tracert       Trace du chemin réseau
pathping      Combinaison ping + tracert avec stats
nslookup      Requêtes DNS interactives
ipconfig      Configuration IP
netstat       Connexions et ports ouverts
route         Table de routage
arp           Cache ARP
netsh         Configuration réseau avancée
Test-NetConnection (PowerShell)  Test complet
```

---

## Diagnostic de Base

### Connectivité

```powershell
# Test de connectivité basique
Test-Connection -ComputerName "server01" -Count 4

# Test avec détails
Test-NetConnection -ComputerName "server01" -InformationLevel Detailed

# Test d'un port spécifique
Test-NetConnection -ComputerName "server01" -Port 443

# Traceroute PowerShell
Test-NetConnection -ComputerName "8.8.8.8" -TraceRoute

# Ping continu avec timestamp
ping -t server01 | ForEach-Object { "$(Get-Date -Format 'HH:mm:ss') $_" }
```

### Configuration IP

```powershell
# Configuration complète
Get-NetIPConfiguration

# Adresses IP
Get-NetIPAddress | Where-Object AddressFamily -eq IPv4

# Passerelle par défaut
Get-NetRoute -DestinationPrefix "0.0.0.0/0"

# Serveurs DNS
Get-DnsClientServerAddress

# Libérer/Renouveler DHCP
ipconfig /release
ipconfig /renew

# Vider le cache DNS
Clear-DnsClientCache
# ou
ipconfig /flushdns
```

---

## Diagnostic DNS

### Requêtes DNS

```powershell
# Résolution simple
Resolve-DnsName "www.google.com"

# Type de record spécifique
Resolve-DnsName "corp.local" -Type MX
Resolve-DnsName "corp.local" -Type NS
Resolve-DnsName "_ldap._tcp.dc._msdcs.corp.local" -Type SRV

# Utiliser un serveur DNS spécifique
Resolve-DnsName "www.google.com" -Server "8.8.8.8"

# nslookup interactif
nslookup
> server 8.8.8.8
> set type=MX
> corp.local
```

### Troubleshooting DNS

```powershell
# Voir le cache DNS local
Get-DnsClientCache

# Vérifier la configuration DNS
Get-DnsClientServerAddress -InterfaceAlias "Ethernet"

# Tester la résolution depuis différents serveurs
$servers = @("10.10.1.10", "10.10.1.11", "8.8.8.8")
foreach ($srv in $servers) {
    Write-Host "Server: $srv"
    Resolve-DnsName "www.corp.local" -Server $srv -ErrorAction SilentlyContinue
}

# Vérifier les enregistrements SRV AD
Resolve-DnsName "_ldap._tcp.corp.local" -Type SRV
Resolve-DnsName "_kerberos._tcp.corp.local" -Type SRV
```

---

## Diagnostic Ports et Connexions

### Connexions Actives

```powershell
# Toutes les connexions établies
Get-NetTCPConnection -State Established

# Connexions par processus
Get-NetTCPConnection -State Established |
    Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess,
    @{N='Process';E={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name}}

# Ports en écoute
Get-NetTCPConnection -State Listen |
    Select-Object LocalAddress, LocalPort, @{N='Process';E={(Get-Process -Id $_.OwningProcess).Name}}

# Connexions UDP
Get-NetUDPEndpoint | Select-Object LocalAddress, LocalPort, OwningProcess

# netstat classique
netstat -ano | findstr LISTENING
netstat -ano | findstr :443
```

### Test de Ports

```powershell
# Test si un port est ouvert
Test-NetConnection -ComputerName "server01" -Port 3389

# Tester plusieurs ports
$ports = @(22, 80, 443, 3389, 5985)
foreach ($port in $ports) {
    $result = Test-NetConnection -ComputerName "server01" -Port $port -WarningAction SilentlyContinue
    [PSCustomObject]@{
        Port = $port
        Open = $result.TcpTestSucceeded
    }
}

# Scanner rapide (attention: pas un vrai scanner de sécurité)
1..1024 | ForEach-Object {
    $result = Test-NetConnection -ComputerName "server01" -Port $_ -WarningAction SilentlyContinue
    if ($result.TcpTestSucceeded) { "Port $_ open" }
}
```

---

## Diagnostic Réseau Physique

### Adaptateurs Réseau

```powershell
# Lister les adaptateurs
Get-NetAdapter

# Détails d'un adaptateur
Get-NetAdapter -Name "Ethernet" | Format-List *

# Statistiques
Get-NetAdapterStatistics

# Propriétés avancées (offload, vitesse, etc.)
Get-NetAdapterAdvancedProperty -Name "Ethernet"

# Désactiver/Activer
Disable-NetAdapter -Name "Ethernet" -Confirm:$false
Enable-NetAdapter -Name "Ethernet"

# Vérifier le lien physique
Get-NetAdapter | Select-Object Name, Status, LinkSpeed
```

### Diagnostics Matériels

```powershell
# État physique
Get-NetAdapter | Select-Object Name, Status, MediaConnectionState, LinkSpeed

# Erreurs de transmission
Get-NetAdapterStatistics | Select-Object Name, ReceivedDiscards, OutboundDiscards, ReceivedErrors, OutboundErrors

# Driver info
Get-NetAdapter | Select-Object Name, DriverVersion, DriverDate, DriverProvider

# Événements réseau
Get-WinEvent -LogName "Microsoft-Windows-NetworkProfile/Operational" -MaxEvents 20
```

---

## Diagnostic Routage

### Table de Routage

```powershell
# Voir les routes
Get-NetRoute

# Routes IPv4 uniquement
Get-NetRoute -AddressFamily IPv4 | Sort-Object DestinationPrefix

# Route vers une destination
Find-NetRoute -RemoteIPAddress "8.8.8.8"

# Ajouter une route statique
New-NetRoute -DestinationPrefix "10.20.0.0/16" -InterfaceAlias "Ethernet" -NextHop "10.10.1.1"

# Supprimer une route
Remove-NetRoute -DestinationPrefix "10.20.0.0/16" -Confirm:$false

# Traceroute
tracert -d 8.8.8.8
Test-NetConnection -ComputerName "8.8.8.8" -TraceRoute
```

### Pathping (Analyse de Chemin)

```cmd
REM Pathping combine ping et tracert avec statistiques de perte
pathping -n 8.8.8.8

REM Sortie :
REM - Liste des sauts
REM - Statistiques de perte par saut
REM - Latence par saut
```

---

## Diagnostic Firewall

### Vérifier les Règles

```powershell
# Règles bloquant un port
Get-NetFirewallRule -Enabled True -Direction Inbound |
    Get-NetFirewallPortFilter |
    Where-Object LocalPort -eq 443

# Vérifier si le firewall bloque
# Test depuis une autre machine + vérifier les logs
Get-Content "C:\Windows\System32\LogFiles\Firewall\pfirewall.log" -Tail 50 |
    Where-Object { $_ -match "DROP" }

# Profil actif
Get-NetConnectionProfile
Get-NetFirewallProfile | Select-Object Name, Enabled
```

### Désactiver Temporairement

```powershell
# Désactiver (pour test uniquement!)
Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled False

# Réactiver
Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True
```

---

## Diagnostic Avancé

### Capture de Paquets

```powershell
# Capture avec netsh (intégré)
netsh trace start capture=yes tracefile=C:\capture.etl maxsize=500

# Arrêter
netsh trace stop

# Convertir en pcap (nécessite Microsoft Message Analyzer ou etl2pcapng)
# etl2pcapng.exe C:\capture.etl C:\capture.pcapng

# Packet Monitor (pktmon) - Windows 10/Server 2019+
pktmon start --capture --file C:\pktmon.etl
pktmon stop
pktmon etl2pcap C:\pktmon.etl --out C:\capture.pcap
```

### Network Diagnostics

```powershell
# Diagnostic automatique Windows
msdt.exe /id NetworkDiagnosticsWeb
msdt.exe /id NetworkDiagnosticsNetworkAdapter

# Test de bande passante (iperf requis)
# Serveur: iperf3 -s
# Client: iperf3 -c server01

# Test MTU
ping -f -l 1472 server01  # 1472 + 28 (headers) = 1500
```

### Wireshark Filters Utiles

```text
FILTRES WIRESHARK COURANTS
══════════════════════════════════════════════════════════

ip.addr == 10.10.1.50       Trafic vers/depuis IP
tcp.port == 443             Port TCP spécifique
dns                         Requêtes DNS
http                        Trafic HTTP
tcp.flags.syn == 1          Connexions TCP (SYN)
tcp.analysis.retransmission Retransmissions
kerberos                    Authentification Kerberos
smb2                        Trafic SMB
ldap                        Requêtes LDAP
```

---

## Scénarios Courants

### "Pas d'accès réseau"

```powershell
# 1. Vérifier la configuration IP
Get-NetIPConfiguration

# 2. Vérifier le DHCP
Get-NetIPAddress | Where-Object PrefixOrigin -eq "Dhcp"

# 3. Ping la passerelle
Test-Connection (Get-NetRoute -DestinationPrefix "0.0.0.0/0").NextHop

# 4. Ping DNS
Test-Connection (Get-DnsClientServerAddress -AddressFamily IPv4).ServerAddresses[0]

# 5. Ping externe
Test-Connection 8.8.8.8

# 6. Test DNS
Resolve-DnsName "www.google.com"
```

### "Impossible de joindre un serveur"

```powershell
# 1. Résolution DNS
Resolve-DnsName "server01"

# 2. Test ICMP
Test-Connection server01

# 3. Test du port requis
Test-NetConnection server01 -Port 443

# 4. Traceroute
Test-NetConnection server01 -TraceRoute

# 5. Vérifier le firewall local
Get-NetFirewallRule -Direction Outbound -Enabled True |
    Where-Object Action -eq "Block"
```

### "Lenteurs réseau"

```powershell
# 1. Statistiques interface
Get-NetAdapterStatistics | Select-Object Name, *Error*, *Discard*

# 2. Latence
Test-Connection server01 -Count 20 | Measure-Object ResponseTime -Average -Maximum

# 3. Vérifier les retransmissions (capture réseau)
# Wireshark: tcp.analysis.retransmission

# 4. Vérifier la bande passante
Get-Counter '\Network Interface(*)\Bytes Total/sec' -SampleInterval 5 -MaxSamples 10
```

---

## Scripts de Diagnostic

### Health Check Réseau

```powershell
function Test-NetworkHealth {
    param($Gateway, $DNS, $External = "8.8.8.8")

    $results = @()

    # Test passerelle
    $results += [PSCustomObject]@{
        Test = "Gateway"
        Target = $Gateway
        Result = (Test-Connection $Gateway -Count 1 -Quiet)
    }

    # Test DNS
    $results += [PSCustomObject]@{
        Test = "DNS Server"
        Target = $DNS
        Result = (Test-Connection $DNS -Count 1 -Quiet)
    }

    # Test externe
    $results += [PSCustomObject]@{
        Test = "External"
        Target = $External
        Result = (Test-Connection $External -Count 1 -Quiet)
    }

    # Test résolution
    $results += [PSCustomObject]@{
        Test = "DNS Resolution"
        Target = "www.google.com"
        Result = [bool](Resolve-DnsName "www.google.com" -ErrorAction SilentlyContinue)
    }

    return $results
}

# Utilisation
$config = Get-NetIPConfiguration | Where-Object IPv4DefaultGateway
Test-NetworkHealth -Gateway $config.IPv4DefaultGateway.NextHop -DNS $config.DNSServer.ServerAddresses[0]
```

---

## Bonnes Pratiques

```yaml
Checklist Troubleshooting:
  Méthodologie:
    - [ ] Commencer par le plus simple (ping)
    - [ ] Procéder par couche (physique → app)
    - [ ] Documenter chaque test
    - [ ] Comparer avec une machine qui fonctionne

  Outils:
    - [ ] PowerShell pour l'automatisation
    - [ ] Wireshark pour l'analyse profonde
    - [ ] Event logs pour le contexte
    - [ ] Perfmon pour les tendances

  Documentation:
    - [ ] Baseline réseau connue
    - [ ] Schéma réseau à jour
    - [ ] Contacts équipe réseau
    - [ ] Procédures d'escalade
```

---

**Voir aussi :**

- [Windows Firewall](windows-firewall.md) - Configuration firewall
- [Event Logs](event-logs.md) - Journaux d'événements
- [DNS Server](dns-server.md) - Configuration DNS
