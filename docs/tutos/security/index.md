---
tags:
  - tutos
  - security
  - firewall
  - hardening
---

# Tutoriels Sécurité

## Firewall

| Tutoriel | OS | Outil | Status |
|----------|-----|-------|--------|
| [Firewalld](firewalld-rocky9.md) | Rocky 9 | firewalld | Disponible |
| [UFW](ufw-debian12.md) | Debian 12 | ufw | Disponible |
| [Windows Firewall](firewall-windows2022.md) | Windows 2022 | WF | Disponible |

## Protection contre les intrusions

| Tutoriel | OS | Outil | Status |
|----------|-----|-------|--------|
| [Fail2ban](fail2ban-rocky9.md) | Rocky 9 | fail2ban | Disponible |
| [Fail2ban](fail2ban-debian12.md) | Debian 12 | fail2ban | Disponible |
| CrowdSec | Rocky 9 | CrowdSec | Planifié |

## Certificats SSL/TLS

| Tutoriel | OS | Outil | Status |
|----------|-----|-------|--------|
| [Let's Encrypt (Certbot)](certbot-rocky9.md) | Rocky 9 | certbot | Disponible |
| [Let's Encrypt (Certbot)](certbot-debian12.md) | Debian 12 | certbot | Disponible |
| [Let's Encrypt (win-acme)](winacme-windows2022.md) | Windows 2022 | win-acme | Disponible |

## Hardening

| Tutoriel | OS | Focus | Status |
|----------|-----|-------|--------|
| SSH Hardening | Rocky 9 | OpenSSH | Planifié |
| SSH Hardening | Debian 12 | OpenSSH | Planifié |
| CIS Benchmark | Rocky 9 | OS Hardening | Planifié |
| Windows Security Baselines | Windows 2022 | GPO | Planifié |

## Audit & Logs

| Tutoriel | OS | Outil | Status |
|----------|-----|-------|--------|
| Auditd | Rocky 9 | auditd | Planifié |
| Rsyslog centralisé | Rocky 9 | rsyslog | Planifié |
| Windows Event Forwarding | Windows 2022 | WEF | Planifié |

## Comparatif Firewalls

| Critère | Firewalld | UFW | Windows FW |
|---------|-----------|-----|------------|
| Complexité | Moyenne | Simple | Moyenne |
| Zones | Oui | Non | Profils |
| Backend | nftables | iptables/nftables | WFP |
| GUI | firewall-config | gufw | wf.msc |
| PowerShell/CLI | firewall-cmd | ufw | NetFirewall* |
