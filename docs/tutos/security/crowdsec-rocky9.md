---
tags:
  - tutos
  - security
  - crowdsec
  - ids
  - rocky
---

# CrowdSec sur Rocky Linux 9

Installation de **CrowdSec**, IDS/IPS collaboratif moderne.

| Composant | Version |
|-----------|---------|
| Rocky Linux | 9.x |
| CrowdSec | 1.5+ |

**Durée estimée :** 30 minutes

---

## CrowdSec vs Fail2ban

| Critère | CrowdSec | Fail2ban |
|---------|----------|----------|
| Partage | Communautaire | Local uniquement |
| Performance | Optimisé Go | Python |
| Détection | Scénarios YAML | Regex |
| Bouncers | Multiple | Actions système |
| Dashboard | Console web | Aucun |

---

## Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Logs      │────►│  CrowdSec   │────►│  Bouncers   │
│  (nginx,    │     │  (agent)    │     │  (firewall, │
│   ssh...)   │     │             │     │   nginx...) │
└─────────────┘     └──────┬──────┘     └─────────────┘
                          │
                   ┌──────▼──────┐
                   │ CrowdSec    │
                   │ Cloud (CTI) │
                   └─────────────┘
```

---

## 1. Installation

```bash
# Ajouter le repo
curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.rpm.sh | bash

# Installer l'agent
dnf install -y crowdsec

# Version
cscli version
```

---

## 2. Configuration initiale

```bash
# Démarrer
systemctl enable --now crowdsec

# Statut
cscli metrics
```

### Enregistrer sur la console (optionnel)

```bash
# Créer un compte sur https://app.crowdsec.net
cscli console enroll <ENROLLMENT_KEY>
```

---

## 3. Collections (parsers + scénarios)

### Lister les collections disponibles

```bash
cscli collections list
```

### Installer les collections nécessaires

```bash
# SSH (installé par défaut)
cscli collections install crowdsecurity/sshd

# Nginx
cscli collections install crowdsecurity/nginx

# Apache
cscli collections install crowdsecurity/apache2

# Linux base
cscli collections install crowdsecurity/linux

# WordPress
cscli collections install crowdsecurity/wordpress
```

### Vérifier les installations

```bash
cscli collections list
cscli parsers list
cscli scenarios list
```

---

## 4. Acquisition des logs

```bash
vim /etc/crowdsec/acquis.yaml
```

```yaml
# SSH (journald)
filenames: []
journalctl_filter:
  - "_SYSTEMD_UNIT=sshd.service"
labels:
  type: syslog
---
# Nginx
filenames:
  - /var/log/nginx/access.log
  - /var/log/nginx/error.log
labels:
  type: nginx
---
# Apache
filenames:
  - /var/log/httpd/access_log
  - /var/log/httpd/error_log
labels:
  type: apache2
---
# Auth logs
filenames:
  - /var/log/secure
labels:
  type: syslog
```

```bash
systemctl reload crowdsec
```

---

## 5. Bouncers (actions)

### Bouncer Firewall (firewalld/iptables)

```bash
# Installer
dnf install -y crowdsec-firewall-bouncer-iptables

# Générer une API key
cscli bouncers add firewall-bouncer

# Configurer
vim /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml
```

```yaml
mode: iptables  # ou nftables, firewalld
api_url: http://127.0.0.1:8080
api_key: <GENERATED_API_KEY>
update_frequency: 10s
deny_action: DROP
deny_log: true
```

```bash
systemctl enable --now crowdsec-firewall-bouncer
```

### Bouncer Nginx

```bash
# Télécharger
dnf install -y crowdsec-nginx-bouncer

# API key
cscli bouncers add nginx-bouncer
```

### Vérifier les bouncers

```bash
cscli bouncers list
```

---

## 6. Gestion des décisions

### Voir les décisions actives

```bash
cscli decisions list
```

### Bannir manuellement une IP

```bash
cscli decisions add --ip 1.2.3.4 --duration 24h --reason "manual ban"
```

### Débannir une IP

```bash
cscli decisions delete --ip 1.2.3.4
```

### Whitelist

```bash
vim /etc/crowdsec/parsers/s02-enrich/whitelist.yaml
```

```yaml
name: crowdsecurity/whitelist
description: "Whitelist custom"
whitelist:
  reason: "Private IP ranges"
  ip:
    - "192.168.1.0/24"
    - "10.0.0.0/8"
```

---

## 7. Alertes et notifications

### Discord/Slack

```bash
cscli notifications list
cscli notifications configure slack
```

```yaml
# /etc/crowdsec/notifications/slack.yaml
type: slack
name: slack_alerts
log_level: info
format: |
  {{range . -}}
  {{.Text}}
  {{end}}
webhook: "https://hooks.slack.com/services/xxx/yyy/zzz"
```

```bash
# Activer dans profiles.yaml
vim /etc/crowdsec/profiles.yaml
```

```yaml
name: default_ip_remediation
filters:
  - Alert.Remediation == true && Alert.GetScope() == "Ip"
decisions:
  - type: ban
    duration: 4h
notifications:
  - slack_alerts
on_success: break
```

---

## 8. Console Web (LAPI)

### Dashboard local

```bash
cscli dashboard setup
# Accès : http://localhost:3000
```

### Console CrowdSec (cloud)

```bash
# S'inscrire sur https://app.crowdsec.net
cscli console enroll <KEY>
systemctl restart crowdsec
```

---

## 9. Métriques et monitoring

```bash
# Métriques globales
cscli metrics

# Alertes récentes
cscli alerts list

# Détail d'une alerte
cscli alerts inspect <ID>

# Hub status
cscli hub list
```

### Prometheus

```bash
# Endpoint disponible
curl http://127.0.0.1:6060/metrics
```

---

## 10. Mise à jour

```bash
# Mettre à jour les collections
cscli hub update
cscli hub upgrade

# Mettre à jour CrowdSec
dnf update crowdsec crowdsec-firewall-bouncer-*
```

---

## Commandes utiles

```bash
# Status
cscli metrics
cscli alerts list
cscli decisions list
cscli bouncers list

# Collections
cscli collections list
cscli collections install <collection>
cscli collections remove <collection>

# Simulation (dry-run)
cscli explain --file /var/log/nginx/access.log --type nginx

# Parser test
cscli parsers test
```

---

## Dépannage

```bash
# Logs
journalctl -u crowdsec -f
tail -f /var/log/crowdsec.log

# Debug
cscli config show
cscli machines list

# Tester un parser
cscli explain --file /var/log/secure --type syslog
```

| Problème | Solution |
|----------|----------|
| Pas de décisions | Vérifier acquis.yaml |
| Bouncer non connecté | Vérifier API key |
| Faux positifs | Ajouter whitelist |

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
