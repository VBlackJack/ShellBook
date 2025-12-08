---
tags:
  - network
  - fundamentals
  - infrastructure
---

# Réseau

Fondamentaux et guides réseau pour l'administration système.

---

## Vue d'Ensemble

```
NETWORK STACK
═════════════

┌─────────────────────────────────────────────────────────────┐
│                    APPLICATION LAYER                         │
│  HTTP, DNS, SSH, SMTP, FTP, DHCP                            │
│  → Ce que l'utilisateur voit                                │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    TRANSPORT LAYER                           │
│  TCP (fiable, ordonné) │ UDP (rapide, best-effort)          │
│  → Ports, connexions, contrôle de flux                      │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    NETWORK LAYER                             │
│  IP, ICMP, Routing, NAT                                     │
│  → Adressage logique, acheminement                          │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                   DATA LINK + PHYSICAL                       │
│  Ethernet, Wi-Fi, ARP, MAC addresses                        │
│  → Connexion physique, transmission                         │
└─────────────────────────────────────────────────────────────┘
```

---

## Guides Disponibles

| Guide | Description | Niveau |
|-------|-------------|--------|
| [Fundamentals](fundamentals.md) | CIDR, IPs privées, Load Balancing L4/L7, DMZ | Débutant |
| [TCP/IP & Routing](tcp-ip-routing.md) | TCP/UDP, routage, NAT, diagnostic | Intermédiaire |
| [DNS Fundamentals](dns-fundamentals.md) | Résolution DNS, types d'enregistrements, outils | Intermédiaire |

---

## Concepts Clés

### Modèle OSI

| Couche | Nom | Protocoles | Équipement |
|--------|-----|------------|------------|
| 7 | Application | HTTP, DNS, SSH | Reverse Proxy |
| 6 | Présentation | SSL/TLS, JPEG | - |
| 5 | Session | NetBIOS, RPC | - |
| 4 | Transport | TCP, UDP | Firewall L4 |
| 3 | Réseau | IP, ICMP, OSPF | Router |
| 2 | Liaison | Ethernet, ARP | Switch |
| 1 | Physique | Câbles, Wi-Fi | Hub |

### Aide-mémoire CIDR

| CIDR | Masque | Hôtes | Usage |
|------|--------|-------|-------|
| /32 | 255.255.255.255 | 1 | Hôte unique |
| /30 | 255.255.255.252 | 2 | Point-à-point |
| /24 | 255.255.255.0 | 254 | LAN standard |
| /16 | 255.255.0.0 | 65,534 | VPC/Entreprise |
| /8 | 255.0.0.0 | 16M | Très grand réseau |

### Plages IP Privées (RFC 1918)

| Plage | CIDR | Usage |
|-------|------|-------|
| 10.0.0.0 - 10.255.255.255 | 10.0.0.0/8 | Grandes entreprises, VPCs |
| 172.16.0.0 - 172.31.255.255 | 172.16.0.0/12 | Réseaux moyens, Docker |
| 192.168.0.0 - 192.168.255.255 | 192.168.0.0/16 | LANs domestiques |

---

## Outils Essentiels

### Diagnostic

```bash
# Connectivité
ping -c 4 8.8.8.8
traceroute google.com
mtr google.com

# DNS
dig example.com
nslookup example.com

# Ports et connexions
ss -tlnp                 # Ports en écoute
nc -zv host 22           # Tester un port
nmap -sV host            # Scanner ports

# Capture
tcpdump -i eth0 port 80
wireshark
```

### Configuration

```bash
# Interfaces
ip link show
ip addr show
ip addr add 192.168.1.100/24 dev eth0

# Routage
ip route show
ip route add 10.0.0.0/8 via 192.168.1.1

# DNS
cat /etc/resolv.conf
systemd-resolve --status
```

---

## Voir Aussi

- [Linux Network Management](../linux/network-management.md) - Configuration réseau Linux
- [SSH Tunnels](../linux/ssh-tunnels.md) - Tunnels et port forwarding
- [VPN WireGuard](../linux/vpn-wireguard.md) - VPN moderne
- [Load Balancing](../devops/load-balancing.md) - HAProxy, Nginx
- [Scripts Bash Réseau](../scripts/bash/index.md) - Scripts d'administration
