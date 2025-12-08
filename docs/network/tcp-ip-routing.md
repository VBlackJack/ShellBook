---
tags:
  - tcp
  - ip
  - routing
  - networking
---

# TCP/IP & Routing

![OSI Model](../assets/infographics/network/osi-model-attacks.jpeg)

Protocoles fondamentaux et routage réseau.

---

## Modèle OSI vs TCP/IP

```
OSI Model                    TCP/IP Model
═════════                    ════════════

┌─────────────┐
│ Application │   7         ┌─────────────┐
├─────────────┤             │ Application │  HTTP, DNS, SSH
│ Presentation│   6         │             │
├─────────────┤             └──────┬──────┘
│   Session   │   5                │
├─────────────┤             ┌──────┴──────┐
│  Transport  │   4         │  Transport  │  TCP, UDP
├─────────────┤             └──────┬──────┘
│   Network   │   3         ┌──────┴──────┐
├─────────────┤             │   Internet  │  IP, ICMP
│  Data Link  │   2         └──────┬──────┘
├─────────────┤             ┌──────┴──────┐
│  Physical   │   1         │Network Access│ Ethernet, Wi-Fi
└─────────────┘             └─────────────┘
```

---

## TCP (Transmission Control Protocol)

### Caractéristiques

| Aspect | Description |
|--------|-------------|
| **Type** | Orienté connexion |
| **Fiabilité** | Garantie de livraison (ACK) |
| **Ordre** | Garantie d'ordre (numéros de séquence) |
| **Contrôle de flux** | Fenêtre glissante |
| **Cas d'usage** | HTTP, SSH, FTP, SMTP |

### Three-Way Handshake

```
Client                    Server
   |                         |
   |   SYN (seq=100)         |
   |------------------------>|
   |                         |
   |   SYN-ACK (seq=300,     |
   |           ack=101)      |
   |<------------------------|
   |                         |
   |   ACK (seq=101,         |
   |        ack=301)         |
   |------------------------>|
   |                         |
   |   Connexion établie     |
```

### États TCP

```bash
# Voir les connexions TCP
ss -tan

# États courants
LISTEN      # Serveur attend des connexions
ESTABLISHED # Connexion active
TIME_WAIT   # Attente avant fermeture (2*MSL)
CLOSE_WAIT  # Attente de fermeture côté application
FIN_WAIT_1  # Envoyé FIN, attend ACK
FIN_WAIT_2  # Reçu ACK de FIN, attend FIN distant
```

### Fermeture de Connexion (4-Way)

```
Client                    Server
   |                         |
   |   FIN                   |
   |------------------------>|
   |                         |
   |   ACK                   |
   |<------------------------|
   |                         |
   |   FIN                   |
   |<------------------------|
   |                         |
   |   ACK                   |
   |------------------------>|
   |                         |
   |   TIME_WAIT (2*MSL)     |
   |   puis CLOSED           |
```

---

## UDP (User Datagram Protocol)

### Caractéristiques

| Aspect | Description |
|--------|-------------|
| **Type** | Sans connexion |
| **Fiabilité** | Aucune garantie |
| **Ordre** | Non garanti |
| **Overhead** | Minimal (8 bytes header) |
| **Cas d'usage** | DNS, VoIP, Gaming, Streaming |

### Comparaison TCP vs UDP

| Critère | TCP | UDP |
|---------|-----|-----|
| Connexion | Orienté connexion | Sans connexion |
| Fiabilité | Garantie | Best effort |
| Ordre | Garanti | Non garanti |
| Vitesse | Plus lent | Plus rapide |
| Header | 20-60 bytes | 8 bytes |
| Contrôle congestion | Oui | Non |
| Cas d'usage | Web, Email, Files | DNS, VoIP, Games |

---

## Adressage IP

### IPv4

```
IP Address:      192.168.1.100
Subnet Mask:     255.255.255.0    (/24)
                 ────────────     ─────
Network Part:    192.168.1.       (24 bits)
Host Part:       .100             (8 bits)

Binary:
192.168.1.100  = 11000000.10101000.00000001.01100100
255.255.255.0  = 11111111.11111111.11111111.00000000

Network ID:      192.168.1.0      (host part = 0)
Broadcast:       192.168.1.255    (host part = all 1s)
Usable Hosts:    192.168.1.1 - 192.168.1.254 (254 hosts)
```

### Classes d'Adresses (Historique)

| Classe | Plage | Masque par défaut | Usage |
|--------|-------|-------------------|-------|
| A | 1.0.0.0 - 126.255.255.255 | /8 | Grandes organisations |
| B | 128.0.0.0 - 191.255.255.255 | /16 | Moyennes organisations |
| C | 192.0.0.0 - 223.255.255.255 | /24 | Petits réseaux |
| D | 224.0.0.0 - 239.255.255.255 | - | Multicast |
| E | 240.0.0.0 - 255.255.255.255 | - | Réservé |

### IPv6

```
IPv6 Address: 2001:0db8:85a3:0000:0000:8a2e:0370:7334
Simplified:   2001:db8:85a3::8a2e:370:7334

Format: 8 groupes de 4 caractères hexadécimaux
Total: 128 bits (vs 32 bits pour IPv4)

Types d'adresses:
- ::1              → Loopback
- fe80::/10        → Link-local
- fc00::/7         → Unique local (privé)
- 2000::/3         → Global unicast (routable)
```

---

## Routage

### Table de Routage

```bash
# Linux
ip route show
route -n

# Exemple de table
default via 192.168.1.1 dev eth0 proto static metric 100
10.0.0.0/8 via 192.168.1.254 dev eth0
192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.100
```

### Lecture de la Table

| Destination | Gateway | Interface | Signification |
|-------------|---------|-----------|---------------|
| default | 192.168.1.1 | eth0 | Route par défaut |
| 10.0.0.0/8 | 192.168.1.254 | eth0 | Via ce routeur |
| 192.168.1.0/24 | 0.0.0.0 | eth0 | Réseau local (direct) |

### Gestion des Routes

```bash
# Ajouter une route statique
sudo ip route add 10.10.0.0/16 via 192.168.1.254

# Supprimer une route
sudo ip route del 10.10.0.0/16

# Changer la route par défaut
sudo ip route del default
sudo ip route add default via 192.168.1.1

# Route persistante (Debian/Ubuntu)
# /etc/netplan/01-netcfg.yaml
network:
  ethernets:
    eth0:
      routes:
        - to: 10.0.0.0/8
          via: 192.168.1.254
```

### Diagnostic de Routage

```bash
# Tracer la route vers une destination
traceroute 8.8.8.8
traceroute -n 8.8.8.8    # Sans résolution DNS
mtr 8.8.8.8              # Interactive (meilleur)

# Voir quelle route sera utilisée
ip route get 8.8.8.8

# Output:
# 8.8.8.8 via 192.168.1.1 dev eth0 src 192.168.1.100 uid 1000
```

---

## NAT (Network Address Translation)

### Types de NAT

```
SNAT (Source NAT)
─────────────────
Réseau Privé → Routeur NAT → Internet
192.168.1.100:54321 → 203.0.113.1:12345 → 8.8.8.8:53

DNAT (Destination NAT) / Port Forwarding
────────────────────────────────────────
Internet → Routeur NAT → Réseau Privé
Client:80 → 203.0.113.1:80 → 192.168.1.50:80

PAT (Port Address Translation)
───────────────────────────────
Multiple clients internes partagent une IP publique
avec différents ports source.
```

### Configuration iptables

```bash
# SNAT (Masquerade pour connexion dynamique)
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

# SNAT (IP publique fixe)
iptables -t nat -A POSTROUTING -o eth0 -j SNAT --to-source 203.0.113.1

# DNAT (Port forwarding)
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 \
    -j DNAT --to-destination 192.168.1.50:80

# Activer le forwarding IP
echo 1 > /proc/sys/net/ipv4/ip_forward
```

---

## Ports et Services

### Ports Well-Known (0-1023)

| Port | Service | Protocole |
|------|---------|-----------|
| 20/21 | FTP | TCP |
| 22 | SSH | TCP |
| 23 | Telnet | TCP |
| 25 | SMTP | TCP |
| 53 | DNS | TCP/UDP |
| 67/68 | DHCP | UDP |
| 80 | HTTP | TCP |
| 110 | POP3 | TCP |
| 143 | IMAP | TCP |
| 443 | HTTPS | TCP |
| 445 | SMB | TCP |
| 3306 | MySQL | TCP |
| 5432 | PostgreSQL | TCP |
| 6379 | Redis | TCP |

### Vérifier les Ports

```bash
# Ports en écoute
ss -tlnp              # TCP
ss -ulnp              # UDP
netstat -tlnp         # Ancien

# Tester un port distant
nc -zv 192.168.1.1 22
telnet 192.168.1.1 80

# Scanner les ports
nmap -p 1-1000 192.168.1.1
nmap -sV 192.168.1.1       # Détection de version
```

---

## ICMP (Internet Control Message Protocol)

### Messages ICMP Courants

| Type | Code | Message |
|------|------|---------|
| 0 | 0 | Echo Reply (réponse ping) |
| 3 | 0 | Destination Unreachable: Network |
| 3 | 1 | Destination Unreachable: Host |
| 3 | 3 | Destination Unreachable: Port |
| 8 | 0 | Echo Request (ping) |
| 11 | 0 | Time Exceeded (TTL) |

### Utilisation

```bash
# Ping basique
ping -c 4 8.8.8.8

# Ping avec taille de paquet
ping -c 4 -s 1472 8.8.8.8   # MTU discovery

# Ping sans fragmentation
ping -c 4 -M do -s 1472 8.8.8.8
```

---

## Dépannage Réseau

### Workflow de Diagnostic

```
1. Interface UP?
   └─ ip link show
       └─ DOWN? → ip link set eth0 up

2. IP configurée?
   └─ ip addr show
       └─ Pas d'IP? → DHCP ou config statique

3. Gateway joignable?
   └─ ping 192.168.1.1
       └─ Échec? → Problème L2 ou câble

4. DNS fonctionne?
   └─ nslookup google.com
       └─ Échec? → Vérifier /etc/resolv.conf

5. Internet accessible?
   └─ ping 8.8.8.8
       └─ Échec? → Problème de routage ou firewall

6. Service accessible?
   └─ curl https://example.com
       └─ Échec? → Firewall, port fermé, ou service down
```

### Commandes de Base

```bash
# Voir les interfaces
ip link show
ip addr show

# Voir la table de routage
ip route show

# Voir les connexions
ss -tan
ss -uan

# Capturer le trafic
tcpdump -i eth0
tcpdump -i eth0 port 80
tcpdump -i eth0 host 192.168.1.100

# Statistiques réseau
ip -s link show eth0
netstat -s
```

---

## Référence Rapide

```bash
# === INTERFACES ===
ip link show                     # Lister interfaces
ip addr show                     # Voir IP
ip link set eth0 up/down         # Activer/désactiver

# === ROUTAGE ===
ip route show                    # Table de routage
ip route get 8.8.8.8            # Route vers destination
ip route add 10.0.0.0/8 via GW  # Ajouter route
traceroute 8.8.8.8              # Tracer la route

# === CONNEXIONS ===
ss -tan                          # Connexions TCP
ss -tlnp                         # Ports en écoute
nc -zv host port                 # Tester port

# === DIAGNOSTIC ===
ping -c 4 host                   # Test ICMP
mtr host                         # Traceroute interactif
tcpdump -i eth0                  # Capture paquets
```

---

!!! info "À lire aussi"
    - [DNS Fundamentals](dns-fundamentals.md) - Résolution de noms
    - [Network Fundamentals](fundamentals.md) - CIDR, DMZ
    - [Linux Network Management](../linux/network-management.md)
