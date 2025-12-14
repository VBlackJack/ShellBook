---
tags:
  - tutos
  - tutoriels
  - pratique
---

# Tutoriels Pratiques

Guides step-by-step pour déployer des solutions complètes. Chaque tutoriel est testé et maintenu à jour.

## Philosophie

- **Reproductibles** : Commandes copier-coller qui fonctionnent
- **Actualisés** : Versions LTS et stables uniquement
- **Complets** : De l'installation à la sécurisation
- **Multi-OS** : Rocky Linux 9, Debian 12, Windows Server 2022

## Systèmes Couverts

| OS | Version | Support | Usage |
|----|---------|---------|-------|
| Rocky Linux | 9.x | 2032 | Prod RHEL-like |
| Debian | 12 Bookworm | 2028 | Prod stable |
| Windows Server | 2022 | 2031 | Infra Microsoft |

## Catégories

<div class="grid cards" markdown>

-   :material-web:{ .lg .middle } **Serveurs Web**

    ---

    LAMP, LEMP, IIS, reverse proxy, SSL/TLS

    [:octicons-arrow-right-24: Voir les tutos](web-servers/)

-   :material-database:{ .lg .middle } **Bases de Données**

    ---

    MariaDB, PostgreSQL, SQL Server, réplication

    [:octicons-arrow-right-24: Voir les tutos](databases/)

-   :material-server-network:{ .lg .middle } **Réseau**

    ---

    DNS, DHCP, NTP, VPN, Firewall

    [:octicons-arrow-right-24: Voir les tutos](network/)

-   :material-harddisk:{ .lg .middle } **Stockage**

    ---

    NFS, SMB/CIFS, iSCSI, File Server

    [:octicons-arrow-right-24: Voir les tutos](storage/)

-   :material-docker:{ .lg .middle } **Conteneurs**

    ---

    Podman, Docker, registries

    [:octicons-arrow-right-24: Voir les tutos](containers/)

-   :material-chart-line:{ .lg .middle } **Monitoring**

    ---

    Prometheus, Grafana, Zabbix, SNMP

    [:octicons-arrow-right-24: Voir les tutos](monitoring/)

-   :material-shield-lock:{ .lg .middle } **Sécurité**

    ---

    Firewall, hardening, certificats, audit

    [:octicons-arrow-right-24: Voir les tutos](security/)

</div>

## Roadmap des Tutoriels

### Serveurs Web

| Tutoriel | Rocky 9 | Debian 12 | Windows 2022 |
|----------|:-------:|:---------:|:------------:|
| LAMP (Apache + MariaDB + PHP) | [x] | [x] | - |
| LEMP (Nginx + MariaDB + PHP) | [x] | [x] | - |
| IIS + PHP | - | - | [x] |
| Reverse Proxy Nginx | [x] | [x] | - |
| HAProxy Load Balancer | [x] | [x] | - |
| Let's Encrypt SSL | [x] | [x] | [x] |

### Bases de Données

| Tutoriel | Rocky 9 | Debian 12 | Windows 2022 |
|----------|:-------:|:---------:|:------------:|
| MariaDB Standalone | [x] | [x] | - |
| PostgreSQL Standalone | [x] | [x] | - |
| Redis Cache | [x] | [x] | - |
| SQL Server Express | - | - | [ ] |

### Réseau

| Tutoriel | Rocky 9 | Debian 12 | Windows 2022 |
|----------|:-------:|:---------:|:------------:|
| DNS (Bind/Windows DNS) | [x] | [x] | [x] |
| DHCP | [x] | [x] | [x] |
| NTP/Chrony | [x] | [x] | [x] |
| WireGuard VPN | [x] | [x] | - |
| Squid Proxy | [x] | [x] | - |
| Gitea Git Server | [x] | [x] | - |
| Nextcloud | [x] | [x] | - |
| Ansible | [x] | [x] | - |

### Stockage

| Tutoriel | Rocky 9 | Debian 12 | Windows 2022 |
|----------|:-------:|:---------:|:------------:|
| NFS Server | [x] | [x] | - |
| Samba/SMB | [x] | [x] | - |
| File Server + DFS | - | - | [x] |
| iSCSI Target | [x] | [x] | - |
| Borg Backup | [x] | [x] | - |
| GlusterFS Cluster | [x] | [x] | - |

### Conteneurs & Virtualisation

| Tutoriel | Rocky 9 | Debian 12 | Windows 2022 |
|----------|:-------:|:---------:|:------------:|
| Podman Rootless | [x] | [x] | - |
| Docker CE | [x] | [x] | [x] |
| KVM/QEMU | [x] | [x] | - |
| K3s Kubernetes | [x] | [x] | - |

### Monitoring

| Tutoriel | Rocky 9 | Debian 12 | Windows 2022 |
|----------|:-------:|:---------:|:------------:|
| Prometheus + Grafana | [x] | [x] | - |
| ELK Stack | [x] | [x] | - |
| Windows Exporter | - | - | [ ] |

### Services Réseau Avancés

| Tutoriel | Rocky 9 | Debian 12 | Windows 2022 |
|----------|:-------:|:---------:|:------------:|
| Mail Server (Postfix) | [x] | [x] | - |
| OpenLDAP | [x] | [x] | - |

### Sécurité

| Tutoriel | Rocky 9 | Debian 12 | Windows 2022 |
|----------|:-------:|:---------:|:------------:|
| Firewall (firewalld/ufw/WF) | [x] | [x] | [x] |
| Fail2ban | [x] | [x] | - |
| Let's Encrypt (Certbot/win-acme) | [x] | [x] | [x] |
| SSH Hardening | [x] | [x] | - |
| CrowdSec IDS | [x] | [x] | - |
| Auditd Audit | [x] | [x] | - |

## Conventions

| Élément | Signification |
|---------|---------------|
| `#` | Commande root |
| `$` | Commande utilisateur |
| `PS>` | Commande PowerShell |
| `[x.x.x]` | Remplacer par la version actuelle |
| `<valeur>` | Remplacer par votre valeur |

!!! warning "Environnement de test"
    Testez toujours sur un environnement de développement avant la production.

## Ressources Externes

Sites de référence pour compléter :

- [Server-World](https://www.server-world.info/en/) - Encyclopédie admin système multi-OS (inspiration principale)
- [DigitalOcean Tutorials](https://www.digitalocean.com/community/tutorials) - Guides cloud et serveurs
- [Linode Docs](https://www.linode.com/docs/) - Documentation Linux complète
