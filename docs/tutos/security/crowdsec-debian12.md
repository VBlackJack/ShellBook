---
tags:
  - tutos
  - security
  - crowdsec
  - ids
  - debian
---

# CrowdSec sur Debian 12

Installation de **CrowdSec** sur Debian 12 Bookworm.

| Composant | Version |
|-----------|---------|
| Debian | 12 Bookworm |
| CrowdSec | 1.5+ |

**Durée estimée :** 25 minutes

---

## 1. Installation

```bash
curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | bash
apt install -y crowdsec

cscli version
```

---

## 2. Démarrer

```bash
systemctl enable --now crowdsec
cscli metrics
```

---

## 3. Collections

```bash
# SSH
cscli collections install crowdsecurity/sshd

# Nginx
cscli collections install crowdsecurity/nginx

# Linux
cscli collections install crowdsecurity/linux

# Vérifier
cscli collections list
```

---

## 4. Acquisition

```bash
vim /etc/crowdsec/acquis.yaml
```

```yaml
filenames:
  - /var/log/auth.log
labels:
  type: syslog
---
filenames:
  - /var/log/nginx/access.log
  - /var/log/nginx/error.log
labels:
  type: nginx
```

```bash
systemctl reload crowdsec
```

---

## 5. Bouncer Firewall

```bash
apt install -y crowdsec-firewall-bouncer-iptables

cscli bouncers add firewall-bouncer
vim /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml
```

```yaml
mode: iptables
api_url: http://127.0.0.1:8080
api_key: <API_KEY>
deny_action: DROP
```

```bash
systemctl enable --now crowdsec-firewall-bouncer
```

---

## 6. Gestion

```bash
# Décisions actives
cscli decisions list

# Bannir
cscli decisions add --ip 1.2.3.4 --duration 24h --reason "attack"

# Débannir
cscli decisions delete --ip 1.2.3.4
```

---

## 7. Whitelist

```bash
vim /etc/crowdsec/parsers/s02-enrich/whitelist.yaml
```

```yaml
name: crowdsecurity/whitelist
description: "Whitelist"
whitelist:
  reason: "Private"
  ip:
    - "192.168.1.0/24"
```

---

## 8. Console Cloud

```bash
# https://app.crowdsec.net
cscli console enroll <ENROLLMENT_KEY>
systemctl restart crowdsec
```

---

## 9. Métriques

```bash
cscli metrics
cscli alerts list
cscli bouncers list
```

---

## Comparatif Rocky vs Debian

| Aspect | Rocky 9 | Debian 12 |
|--------|---------|-----------|
| Package | script.rpm.sh | script.deb.sh |
| Logs SSH | /var/log/secure | /var/log/auth.log |
| Bouncer | iptables/nftables | iptables/nftables |

---

## Commandes

```bash
cscli metrics              # Métriques
cscli alerts list          # Alertes
cscli decisions list       # Décisions
cscli collections list     # Collections
cscli hub update           # Mise à jour hub
cscli hub upgrade          # Upgrade composants
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
