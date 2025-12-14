---
tags:
  - tutos
  - network
  - dns
  - dhcp
---

# Tutoriels Réseau

## DNS

| Tutoriel | OS | Service | Status |
|----------|-----|---------|--------|
| [DNS Bind9](dns-bind-rocky9.md) | Rocky 9 | Bind 9.16 | Disponible |
| [DNS Bind9](dns-bind-debian12.md) | Debian 12 | Bind 9.18 | Disponible |
| [Windows DNS](dns-windows2022.md) | Windows 2022 | DNS Server | Disponible |

## DHCP

| Tutoriel | OS | Service | Status |
|----------|-----|---------|--------|
| [DHCP Server](dhcp-rocky9.md) | Rocky 9 | ISC DHCP 4.4 | Disponible |
| [DHCP Server](dhcp-debian12.md) | Debian 12 | ISC DHCP 4.4 | Disponible |
| [Windows DHCP](dhcp-windows2022.md) | Windows 2022 | DHCP Server | Disponible |

## NTP / Time Sync

| Tutoriel | OS | Service | Status |
|----------|-----|---------|--------|
| Chrony NTP | Rocky 9 | chronyd | Planifié |
| Chrony NTP | Debian 12 | chronyd | Planifié |
| Windows Time | Windows 2022 | W32Time | Planifié |

## Mail Server

| Tutoriel | OS | Service | Status |
|----------|-----|---------|--------|
| [Postfix + Dovecot](postfix-rocky9.md) | Rocky 9 | Postfix, Dovecot | Disponible |
| [Postfix + Dovecot](postfix-debian12.md) | Debian 12 | Postfix, Dovecot | Disponible |

## Annuaire LDAP

| Tutoriel | OS | Service | Status |
|----------|-----|---------|--------|
| [OpenLDAP](openldap-rocky9.md) | Rocky 9 | OpenLDAP 2.6 | Disponible |
| [OpenLDAP](openldap-debian12.md) | Debian 12 | OpenLDAP 2.5 | Disponible |

## VPN

| Tutoriel | OS | Service | Status |
|----------|-----|---------|--------|
| WireGuard VPN | Rocky 9 | WireGuard | Planifié |
| WireGuard VPN | Debian 12 | WireGuard | Planifié |
| OpenVPN | Rocky 9 | OpenVPN | Planifié |

## Intégrations

| Tutoriel | Description | Status |
|----------|-------------|--------|
| DNS + DHCP DDNS | Mise à jour DNS dynamique | Planifié |
| PXE Boot | Boot réseau avec DHCP/TFTP | Planifié |

## Comparatif des solutions

### DNS

| Critère | BIND | Windows DNS |
|---------|------|-------------|
| Plateformes | Linux/BSD | Windows |
| Intégration AD | Non | Oui |
| Performance | Excellente | Bonne |
| Configuration | Fichiers texte | GUI + PowerShell |
| Réplication | Master/Slave | AD-intégrée |

### DHCP

| Critère | ISC DHCP | Windows DHCP |
|---------|----------|--------------|
| Plateformes | Linux/BSD | Windows |
| Failover | Manuel | Intégré |
| DDNS | Oui | Oui (AD) |
| Configuration | Fichiers texte | GUI + PowerShell |
