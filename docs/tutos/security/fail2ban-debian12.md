---
tags:
  - tutos
  - security
  - fail2ban
  - intrusion-prevention
  - debian
---

# Fail2ban sur Debian 12

Protection contre les attaques brute-force avec **Fail2ban** sur Debian 12.

| Composant | Version |
|-----------|---------|
| Debian | 12 Bookworm |
| Fail2ban | 1.0+ |

**Durée estimée :** 20 minutes

---

## 1. Installation

```bash
apt update
apt install -y fail2ban

# Activer et démarrer
systemctl enable --now fail2ban

# Vérifier
systemctl status fail2ban
fail2ban-client status
```

---

## 2. Configuration de base

```bash
# Copier la configuration par défaut
cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local

# Ou créer une configuration minimale
vim /etc/fail2ban/jail.local
```

```ini
[DEFAULT]
# Backend
backend = systemd

# Whitelist
ignoreip = 127.0.0.1/8 ::1 192.168.1.0/24

# Paramètres de ban
bantime = 10m
findtime = 10m
maxretry = 5

# Action (iptables par défaut sur Debian)
banaction = iptables-multiport
banaction_allports = iptables-allports

# Email (optionnel)
# destemail = admin@example.com
# sender = fail2ban@example.com
# action = %(action_mwl)s
```

---

## 3. Jail SSH

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

## 4. Jails Nginx

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
```

---

## 5. Jails Apache

```ini
[apache-auth]
enabled = true
port = http,https
filter = apache-auth
logpath = /var/log/apache2/*error.log
maxretry = 5

[apache-badbots]
enabled = true
port = http,https
filter = apache-badbots
logpath = /var/log/apache2/*access.log
maxretry = 2
bantime = 24h

[apache-noscript]
enabled = true
port = http,https
filter = apache-noscript
logpath = /var/log/apache2/*error.log
maxretry = 5

[apache-overflows]
enabled = true
port = http,https
filter = apache-overflows
logpath = /var/log/apache2/*error.log
maxretry = 2
```

---

## 6. Jail MariaDB

```ini
[mysqld-auth]
enabled = true
port = 3306
filter = mysqld-auth
logpath = /var/log/mysql/error.log
maxretry = 5
bantime = 1h
```

---

## 7. Jails Mail (Postfix/Dovecot)

```ini
[postfix]
enabled = true
port = smtp,465,submission
filter = postfix[mode=more]
logpath = /var/log/mail.log
maxretry = 5

[dovecot]
enabled = true
port = pop3,pop3s,imap,imaps
filter = dovecot
logpath = /var/log/mail.log
maxretry = 5

[postfix-sasl]
enabled = true
port = smtp,465,submission,imap,imaps,pop3,pop3s
filter = postfix[mode=auth]
logpath = /var/log/mail.log
maxretry = 3
bantime = 24h
```

---

## 8. Créer un filtre personnalisé

### Exemple : protection WordPress

```bash
vim /etc/fail2ban/filter.d/wordpress.conf
```

```ini
[Definition]
failregex = ^<HOST> .* "POST /wp-login.php
            ^<HOST> .* "POST /xmlrpc.php
            ^<HOST> .* "POST /wp-admin/admin-ajax.php
ignoreregex =
```

```ini
# Dans jail.local
[wordpress]
enabled = true
port = http,https
filter = wordpress
logpath = /var/log/nginx/access.log
          /var/log/apache2/access.log
maxretry = 3
bantime = 24h
findtime = 1h
```

### Tester le filtre

```bash
fail2ban-regex /var/log/nginx/access.log /etc/fail2ban/filter.d/wordpress.conf
```

---

## 9. Récidive (ban progressif)

```ini
[recidive]
enabled = true
filter = recidive
logpath = /var/log/fail2ban.log
action = iptables-allports[name=recidive, protocol=all]
bantime = 1w
findtime = 1d
maxretry = 3
```

---

## 10. Commandes utiles

```bash
# Status global
fail2ban-client status

# Status d'une jail
fail2ban-client status sshd

# Bannir manuellement
fail2ban-client set sshd banip 10.0.0.50

# Débannir
fail2ban-client set sshd unbanip 10.0.0.50

# Liste des bannis
fail2ban-client get sshd banned

# Recharger
fail2ban-client reload

# Voir les filtres
fail2ban-client get sshd failregex
```

---

## 11. Intégration UFW

Si vous utilisez UFW au lieu d'iptables :

```bash
vim /etc/fail2ban/jail.local
```

```ini
[DEFAULT]
banaction = ufw
banaction_allports = ufw
```

Ou créer l'action UFW :

```bash
vim /etc/fail2ban/action.d/ufw.conf
```

```ini
[Definition]
actionstart =
actionstop =
actioncheck =
actionban = ufw insert 1 deny from <ip> to any
actionunban = ufw delete deny from <ip> to any
```

---

## 12. Notifications email

```ini
[DEFAULT]
destemail = admin@example.com
sender = fail2ban@server.example.com
mta = sendmail

# Actions :
# action_       : ban seulement
# action_mw     : ban + mail avec whois
# action_mwl    : ban + mail avec whois + logs
action = %(action_mwl)s
```

Installer sendmail si nécessaire :

```bash
apt install -y sendmail
```

---

## 13. Logs et monitoring

```bash
# Logs fail2ban
tail -f /var/log/fail2ban.log

# Bans récents
grep "Ban" /var/log/fail2ban.log | tail -20

# Top IP bannies
grep "Ban" /var/log/fail2ban.log | awk '{print $NF}' | sort | uniq -c | sort -rn | head

# Vérifier iptables
iptables -L f2b-sshd -n -v
```

---

## Configuration complète

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
banaction = iptables-multiport

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
action = iptables-allports[name=recidive]
bantime = 1w
findtime = 1d
maxretry = 3
```

```bash
systemctl restart fail2ban
fail2ban-client status
```

---

## Comparatif Rocky 9 vs Debian 12

| Aspect | Rocky 9 | Debian 12 |
|--------|---------|-----------|
| Installation | dnf + epel | apt |
| Firewall par défaut | firewalld | iptables/nftables |
| banaction | firewallcmd-rich-rules | iptables-multiport |
| Logs Apache | /var/log/httpd/ | /var/log/apache2/ |
| Logs mail | /var/log/maillog | /var/log/mail.log |

---

## Dépannage

```bash
# Mode debug
fail2ban-client -d

# Tester un filtre
fail2ban-regex /var/log/auth.log /etc/fail2ban/filter.d/sshd.conf

# Vérifier la syntaxe
fail2ban-client --test

# Status détaillé
fail2ban-client status sshd
```

| Problème | Solution |
|----------|----------|
| Jail non active | Vérifier `enabled = true` et chemin logs |
| Regex ne matche pas | `fail2ban-regex` pour tester |
| IP non bannie | Vérifier `ignoreip`, `maxretry` |

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
