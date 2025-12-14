---
tags:
  - tutos
  - ntp
  - chrony
  - time
  - debian
---

# Chrony NTP sur Debian 12

Configuration de **Chrony** pour la synchronisation temps sur Debian 12.

| Composant | Version |
|-----------|---------|
| Debian | 12 Bookworm |
| Chrony | 4.x |

**Durée estimée :** 15 minutes

---

## 1. Installation

```bash
apt update
apt install -y chrony

systemctl enable --now chrony
systemctl status chrony
```

---

## 2. Configuration client

```bash
vim /etc/chrony/chrony.conf
```

```ini
# Serveurs NTP Debian
pool 2.debian.pool.ntp.org iburst

# Fichier drift
driftfile /var/lib/chrony/chrony.drift

# Corrections au démarrage
makestep 1.0 3

# RTC sync
rtcsync

# Logs
logdir /var/log/chrony
```

```bash
systemctl restart chrony
```

---

## 3. Configuration serveur NTP

```bash
vim /etc/chrony/chrony.conf
```

```ini
# Sources externes
pool 2.debian.pool.ntp.org iburst

# Autoriser le réseau local
allow 192.168.1.0/24
allow 10.0.0.0/8

# Mode local si déconnecté
local stratum 10

driftfile /var/lib/chrony/chrony.drift
makestep 1.0 3
rtcsync
```

### Firewall

```bash
ufw allow ntp
ufw reload
```

---

## 4. Commandes

```bash
# Sources
chronyc sources
chronyc sources -v

# Tracking
chronyc tracking

# Sync immédiate
chronyc makestep

# Clients (mode serveur)
chronyc clients

# Activité
chronyc activity
```

---

## 5. Vérification

```bash
systemctl status chrony
chronyc sources
chronyc tracking
timedatectl
```

---

## 6. NTS (Network Time Security)

```ini
# Serveurs avec NTS
server time.cloudflare.com iburst nts
server nts.sth1.ntp.se iburst nts

ntsdumpdir /var/lib/chrony
```

---

## Comparatif Rocky vs Debian

| Aspect | Rocky 9 | Debian 12 |
|--------|---------|-----------|
| Service | chronyd | chrony |
| Config | /etc/chrony.conf | /etc/chrony/chrony.conf |
| Pool par défaut | rocky.pool.ntp.org | debian.pool.ntp.org |

---

## Dépannage

```bash
chronyc sources -v
chronyc tracking
journalctl -u chrony -f
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
