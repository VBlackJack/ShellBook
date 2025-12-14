---
tags:
  - tutos
  - security
  - fail2ban
  - intrusion-prevention
  - rocky
---

# Fail2ban sur Rocky Linux 9

Protection contre les attaques brute-force avec **Fail2ban**.

| Composant | Version |
|-----------|---------|
| Rocky Linux | 9.x |
| Fail2ban | 1.0+ |

**Durée estimée :** 20 minutes

---

## Concepts

Fail2ban surveille les logs et bloque les IP après X tentatives échouées.

```
Logs → Fail2ban → iptables/firewalld → IP bloquée
```

### Terminologie

| Terme | Description |
|-------|-------------|
| **Jail** | Configuration pour un service (SSH, Apache...) |
| **Filter** | Regex pour détecter les échecs |
| **Action** | Commande exécutée lors d'un ban |
| **Ban time** | Durée du blocage |
| **Max retry** | Nombre d'échecs avant ban |
| **Find time** | Fenêtre de temps pour compter les échecs |

---

## 1. Installation

```bash
# EPEL requis
dnf install -y epel-release
dnf install -y fail2ban fail2ban-firewalld

# Activer et démarrer
systemctl enable --now fail2ban

# Vérifier
systemctl status fail2ban
fail2ban-client status
```

---

## 2. Configuration de base

Ne jamais modifier `/etc/fail2ban/jail.conf` directement. Utiliser `.local` :

```bash
vim /etc/fail2ban/jail.local
```

```ini
[DEFAULT]
# Backend de log
backend = systemd

# Ignorer ces IP (whitelist)
ignoreip = 127.0.0.1/8 ::1 192.168.1.0/24

# Temps de ban (10 minutes)
bantime = 10m

# Fenêtre de détection
findtime = 10m

# Échecs avant ban
maxretry = 5

# Action par défaut (firewalld)
banaction = firewallcmd-rich-rules
banaction_allports = firewallcmd-rich-rules

# Email (optionnel)
# destemail = admin@example.com
# sender = fail2ban@example.com
# mta = sendmail
# action = %(action_mwl)s
```

---

## 3. Jail SSH (sshd)

```bash
vim /etc/fail2ban/jail.local
```

Ajouter :

```ini
[sshd]
enabled = true
port = ssh
filter = sshd
backend = systemd
maxretry = 3
bantime = 1h
findtime = 10m
```

```bash
systemctl restart fail2ban
fail2ban-client status sshd
```

---

## 4. Jail Apache/HTTP

```ini
# Protection authentification Apache
[apache-auth]
enabled = true
port = http,https
filter = apache-auth
logpath = /var/log/httpd/*error_log
maxretry = 5
bantime = 1h

# Protection contre les bots malveillants
[apache-badbots]
enabled = true
port = http,https
filter = apache-badbots
logpath = /var/log/httpd/*access_log
maxretry = 2
bantime = 24h

# Protection brute-force wp-login
[apache-overflows]
enabled = true
port = http,https
filter = apache-overflows
logpath = /var/log/httpd/*error_log
maxretry = 2
```

---

## 5. Jail Nginx

```ini
[nginx-http-auth]
enabled = true
port = http,https
filter = nginx-http-auth
logpath = /var/log/nginx/*error.log
maxretry = 5
bantime = 1h

[nginx-botsearch]
enabled = true
port = http,https
filter = nginx-botsearch
logpath = /var/log/nginx/*access.log
maxretry = 2
bantime = 24h

[nginx-limit-req]
enabled = true
port = http,https
filter = nginx-limit-req
logpath = /var/log/nginx/*error.log
maxretry = 10
bantime = 1h
```

---

## 6. Jail MariaDB/MySQL

```ini
[mysqld-auth]
enabled = true
port = 3306
filter = mysqld-auth
logpath = /var/log/mariadb/mariadb.log
maxretry = 5
bantime = 1h
```

---

## 7. Jail Postfix/Dovecot

```ini
[postfix]
enabled = true
port = smtp,465,submission
filter = postfix
logpath = /var/log/maillog
maxretry = 5

[dovecot]
enabled = true
port = pop3,pop3s,imap,imaps
filter = dovecot
logpath = /var/log/maillog
maxretry = 5

[postfix-sasl]
enabled = true
port = smtp,465,submission,imap,imaps,pop3,pop3s
filter = postfix-sasl
logpath = /var/log/maillog
maxretry = 3
bantime = 24h
```

---

## 8. Créer un filtre personnalisé

Exemple : bloquer les scans WordPress.

```bash
vim /etc/fail2ban/filter.d/wordpress.conf
```

```ini
[Definition]
failregex = ^<HOST> .* "POST /wp-login.php
            ^<HOST> .* "POST /xmlrpc.php
ignoreregex =
```

```bash
vim /etc/fail2ban/jail.local
```

```ini
[wordpress]
enabled = true
port = http,https
filter = wordpress
logpath = /var/log/nginx/*access.log
maxretry = 3
bantime = 24h
findtime = 1h
```

### Tester le filtre

```bash
fail2ban-regex /var/log/nginx/access.log /etc/fail2ban/filter.d/wordpress.conf
```

---

## 9. Ban progressif (récidive)

```ini
[recidive]
enabled = true
filter = recidive
logpath = /var/log/fail2ban.log
action = firewallcmd-rich-rules[actiontype=<allports>]
bantime = 1w
findtime = 1d
maxretry = 3
```

---

## 10. Commandes de gestion

```bash
# Status global
fail2ban-client status

# Status d'une jail
fail2ban-client status sshd

# Bannir manuellement
fail2ban-client set sshd banip 10.0.0.50

# Débannir
fail2ban-client set sshd unbanip 10.0.0.50

# Liste des IP bannies
fail2ban-client get sshd banned

# Recharger la configuration
fail2ban-client reload

# Recharger une jail spécifique
fail2ban-client reload sshd

# Voir la regex d'un filtre
fail2ban-client get sshd failregex
```

---

## 11. Vérifier les logs

```bash
# Logs Fail2ban
tail -f /var/log/fail2ban.log

# Bans récents
grep "Ban" /var/log/fail2ban.log | tail -20

# IP les plus bannies
grep "Ban" /var/log/fail2ban.log | awk '{print $NF}' | sort | uniq -c | sort -rn | head -10
```

---

## 12. Action email

```bash
vim /etc/fail2ban/jail.local
```

```ini
[DEFAULT]
destemail = admin@example.com
sender = fail2ban@server.example.com
mta = sendmail

# Actions disponibles :
# action_       : ban seulement
# action_mw     : ban + mail avec whois
# action_mwl    : ban + mail avec whois + logs

action = %(action_mwl)s
```

---

## 13. Intégration firewalld

Fail2ban utilise firewalld par défaut sur Rocky 9.

```bash
# Vérifier les règles firewalld
firewall-cmd --list-rich-rules

# Exemple de règle créée par fail2ban
# rule family="ipv4" source address="10.0.0.50" reject type="icmp-port-unreachable"
```

---

## Configuration complète exemple

```bash
vim /etc/fail2ban/jail.local
```

```ini
[DEFAULT]
backend = systemd
ignoreip = 127.0.0.1/8 ::1 192.168.1.0/24
bantime = 1h
findtime = 10m
maxretry = 5
banaction = firewallcmd-rich-rules
banaction_allports = firewallcmd-rich-rules

[sshd]
enabled = true
port = ssh
maxretry = 3
bantime = 24h

[nginx-http-auth]
enabled = true
port = http,https
filter = nginx-http-auth
logpath = /var/log/nginx/*error.log
maxretry = 5

[nginx-botsearch]
enabled = true
port = http,https
filter = nginx-botsearch
logpath = /var/log/nginx/*access.log
maxretry = 2
bantime = 24h

[recidive]
enabled = true
filter = recidive
logpath = /var/log/fail2ban.log
bantime = 1w
findtime = 1d
maxretry = 3
```

```bash
systemctl restart fail2ban
fail2ban-client status
```

---

## Vérification

```bash
# Services actifs
fail2ban-client status

# Test SSH (depuis une autre machine)
# Faire X tentatives échouées et vérifier le ban

# Vérifier
fail2ban-client status sshd
firewall-cmd --list-rich-rules
```

---

## Dépannage

| Problème | Solution |
|----------|----------|
| Jail non démarrée | Vérifier `enabled = true` |
| IP non bannie | Vérifier le chemin des logs |
| Regex ne matche pas | Tester avec `fail2ban-regex` |
| Firewalld non mis à jour | Vérifier `banaction` |

```bash
# Debug
fail2ban-client -d

# Tester un filtre
fail2ban-regex /var/log/secure /etc/fail2ban/filter.d/sshd.conf --print-all-matched

# Status détaillé
fail2ban-client status sshd
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
