---
tags:
  - network
  - fundamentals
  - infrastructure
---

# Réseau

Fondamentaux et guides réseau pour l'administration système.

---

## Guides Disponibles

| Guide | Description | Niveau |
|-------|-------------|--------|
| [Fundamentals](fundamentals.md) | Fondamentaux réseau : OSI, TCP/IP, routage | :material-star: |

---

## Concepts Clés

### Modèle OSI

| Couche | Nom | Protocoles |
|--------|-----|------------|
| 7 | Application | HTTP, DNS, SSH |
| 4 | Transport | TCP, UDP |
| 3 | Réseau | IP, ICMP |
| 2 | Liaison | Ethernet, ARP |
| 1 | Physique | Câbles, Wi-Fi |

### Outils Essentiels

- `ip` / `ifconfig` - Configuration interfaces
- `ss` / `netstat` - Connexions réseau
- `tcpdump` / `wireshark` - Capture paquets
- `nmap` - Scan réseau
- `dig` / `nslookup` - Requêtes DNS

---

## Voir Aussi

- [Scripts Bash Réseau](../scripts/bash/index.md#réseau) - Scripts d'administration réseau
- [Linux Network Management](../linux/network-management.md) - Configuration réseau Linux
