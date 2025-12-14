---
tags:
  - tutos
  - firewall
  - ufw
  - security
  - debian
---

# UFW sur Debian 12

Configuration du firewall **UFW** (Uncomplicated Firewall).

| Composant | Version |
|-----------|---------|
| Debian | 12 Bookworm |
| UFW | 0.36 |

**Durée estimée :** 15 minutes

---

## 1. Installation et activation

```bash
apt update
apt install -y ufw

# IMPORTANT: Autoriser SSH avant d'activer
ufw allow ssh

# Activer
ufw enable

# Vérifier
ufw status verbose
```

---

## 2. Politique par défaut

```bash
# Bloquer tout en entrée, autoriser en sortie
ufw default deny incoming
ufw default allow outgoing

# Vérifier
ufw status verbose
```

---

## 3. Autoriser des services

```bash
# Par nom de service
ufw allow ssh
ufw allow http
ufw allow https

# Ou par port
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp

# Service avec profil d'application
ufw allow 'Nginx Full'
ufw allow 'OpenSSH'

# Lister les profils disponibles
ufw app list
```

---

## 4. Règles par port

```bash
# Port TCP
ufw allow 8080/tcp

# Port UDP
ufw allow 53/udp

# Plage de ports
ufw allow 3000:3100/tcp

# Port TCP et UDP
ufw allow 1194
```

---

## 5. Règles par IP source

```bash
# Autoriser une IP
ufw allow from 192.168.1.100

# Autoriser un réseau
ufw allow from 192.168.1.0/24

# IP + port spécifique
ufw allow from 192.168.1.0/24 to any port 22

# IP + service
ufw allow from 192.168.1.0/24 to any port 3306 proto tcp

# Bloquer une IP
ufw deny from 10.0.0.50
```

---

## 6. Règles vers une interface

```bash
# Autoriser sur une interface spécifique
ufw allow in on eth0 to any port 80

# Autoriser entre interfaces
ufw allow in on eth1 out on eth0
```

---

## 7. Supprimer des règles

```bash
# Par numéro
ufw status numbered
ufw delete 3

# Par règle
ufw delete allow 8080/tcp
ufw delete allow from 192.168.1.0/24
```

---

## 8. Règles avancées

```bash
# Limiter les connexions (protection brute-force)
ufw limit ssh

# Équivalent à: max 6 connexions en 30 secondes

# Logging
ufw logging on
ufw logging medium  # off, low, medium, high, full

# Voir les logs
tail -f /var/log/ufw.log
```

---

## 9. Configuration serveur type

### Serveur Web

```bash
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow http
ufw allow https
ufw enable
```

### Serveur de base de données

```bash
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow from 192.168.1.0/24 to any port 3306
ufw allow from 192.168.1.0/24 to any port 5432
ufw enable
```

### Serveur multi-services

```bash
ufw default deny incoming
ufw default allow outgoing

# SSH limité
ufw limit ssh

# Web
ufw allow http
ufw allow https

# DNS
ufw allow 53

# Mail
ufw allow 25/tcp
ufw allow 587/tcp
ufw allow 993/tcp

ufw enable
ufw status verbose
```

---

## 10. Gestion

```bash
# Statut détaillé
ufw status verbose
ufw status numbered

# Recharger
ufw reload

# Désactiver
ufw disable

# Reset complet
ufw reset
```

---

## 11. Fichiers de configuration

```bash
# Configuration principale
/etc/ufw/ufw.conf

# Règles utilisateur
/etc/ufw/user.rules      # IPv4
/etc/ufw/user6.rules     # IPv6

# Configuration avant/après les règles
/etc/ufw/before.rules
/etc/ufw/after.rules
```

### Règles personnalisées (before.rules)

```bash
# Éditer /etc/ufw/before.rules pour des règles iptables avancées

# Exemple: bloquer ping
# -A ufw-before-input -p icmp --icmp-type echo-request -j DROP
```

---

## 12. Comparatif UFW vs Firewalld

| Aspect | UFW | Firewalld |
|--------|-----|-----------|
| Complexité | Simple | Moyenne |
| Zones | Non | Oui |
| Rich rules | Limité | Oui |
| Rechargement | Bloquant | Non-bloquant |
| Backend | iptables/nftables | nftables |
| Distro | Debian/Ubuntu | RHEL/Fedora |

---

## Dépannage

```bash
# Logs
tail -f /var/log/ufw.log
journalctl -k | grep UFW

# Vérifier iptables
iptables -L -n -v

# Mode verbose
ufw --verbose status

# Reset si problème
ufw reset
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw enable
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
