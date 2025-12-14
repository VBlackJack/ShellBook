---
tags:
  - tutos
  - mail
  - postfix
  - smtp
  - debian
---

# Serveur Mail Postfix sur Debian 12

Installation d'un serveur mail avec **Postfix** et **Dovecot** sur Debian 12.

| Composant | Version |
|-----------|---------|
| Debian | 12 Bookworm |
| Postfix | 3.7+ |
| Dovecot | 2.3+ |

**Durée estimée :** 60 minutes

---

## Prérequis DNS

- **A** : `mail.example.com` → IP serveur
- **MX** : `example.com` → `mail.example.com` (priorité 10)
- **PTR** : IP → `mail.example.com`
- **SPF** : `v=spf1 mx -all`

---

## 1. Installation

```bash
apt update
apt install -y postfix postfix-pcre dovecot-core dovecot-imapd dovecot-pop3d

# Pendant l'installation de Postfix :
# - Type: Internet Site
# - System mail name: example.com
```

---

## 2. Configuration Postfix

```bash
vim /etc/postfix/main.cf
```

```ini
# Identité
smtpd_banner = $myhostname ESMTP
myhostname = mail.example.com
mydomain = example.com
myorigin = $mydomain

# Réseau
mynetworks = 127.0.0.0/8, 192.168.1.0/24
inet_interfaces = all
inet_protocols = ipv4

# Destinations
mydestination = $myhostname, localhost.$mydomain, localhost, $mydomain

# Maildir
home_mailbox = Maildir/

# Limites
message_size_limit = 52428800
mailbox_size_limit = 0

# TLS
smtpd_tls_cert_file = /etc/ssl/certs/mail.example.com.crt
smtpd_tls_key_file = /etc/ssl/private/mail.example.com.key
smtpd_tls_security_level = may
smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtp_tls_security_level = may

# SASL
smtpd_sasl_type = dovecot
smtpd_sasl_path = private/auth
smtpd_sasl_auth_enable = yes
smtpd_sasl_security_options = noanonymous

# Restrictions
smtpd_helo_required = yes
smtpd_recipient_restrictions =
    permit_mynetworks,
    permit_sasl_authenticated,
    reject_unauth_destination,
    reject_unknown_recipient_domain

smtpd_sender_restrictions =
    permit_mynetworks,
    permit_sasl_authenticated,
    reject_unknown_sender_domain

# Sécurité
disable_vrfy_command = yes
```

### master.cf

```bash
vim /etc/postfix/master.cf
```

Décommenter :

```ini
submission inet n       -       y       -       -       smtpd
  -o syslog_name=postfix/submission
  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_tls_auth_only=yes
  -o smtpd_recipient_restrictions=permit_sasl_authenticated,reject

smtps     inet  n       -       y       -       -       smtpd
  -o syslog_name=postfix/smtps
  -o smtpd_tls_wrappermode=yes
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_recipient_restrictions=permit_sasl_authenticated,reject
```

---

## 3. Configuration Dovecot

### Principal

```bash
vim /etc/dovecot/dovecot.conf
```

```ini
protocols = imap pop3 lmtp
listen = *, ::
```

### Authentification

```bash
vim /etc/dovecot/conf.d/10-auth.conf
```

```ini
disable_plaintext_auth = yes
auth_mechanisms = plain login
```

### Mail

```bash
vim /etc/dovecot/conf.d/10-mail.conf
```

```ini
mail_location = maildir:~/Maildir
mail_privileged_group = mail
```

### SSL

```bash
vim /etc/dovecot/conf.d/10-ssl.conf
```

```ini
ssl = required
ssl_cert = </etc/ssl/certs/mail.example.com.crt
ssl_key = </etc/ssl/private/mail.example.com.key
ssl_min_protocol = TLSv1.2
```

### SASL pour Postfix

```bash
vim /etc/dovecot/conf.d/10-master.conf
```

Ajouter dans `service auth` :

```ini
service auth {
  unix_listener /var/spool/postfix/private/auth {
    mode = 0660
    user = postfix
    group = postfix
  }
}
```

---

## 4. Certificats SSL

### Auto-signé

```bash
openssl req -new -x509 -days 365 -nodes \
    -out /etc/ssl/certs/mail.example.com.crt \
    -keyout /etc/ssl/private/mail.example.com.key \
    -subj "/CN=mail.example.com"

chmod 600 /etc/ssl/private/mail.example.com.key
```

### Let's Encrypt

```bash
apt install -y certbot
certbot certonly --standalone -d mail.example.com

# Mettre à jour les chemins
# /etc/letsencrypt/live/mail.example.com/fullchain.pem
# /etc/letsencrypt/live/mail.example.com/privkey.pem
```

---

## 5. Utilisateurs

```bash
# Créer utilisateur mail
useradd -m -s /bin/bash user1
passwd user1

# Créer Maildir
mkdir -p /home/user1/Maildir/{cur,new,tmp}
chown -R user1:user1 /home/user1/Maildir
chmod -R 700 /home/user1/Maildir
```

---

## 6. Firewall

```bash
ufw allow 25/tcp    # SMTP
ufw allow 465/tcp   # SMTPS
ufw allow 587/tcp   # Submission
ufw allow 993/tcp   # IMAPS
ufw allow 995/tcp   # POP3S
ufw reload
```

---

## 7. Démarrer les services

```bash
systemctl restart postfix dovecot
systemctl enable postfix dovecot
systemctl status postfix dovecot
```

---

## 8. Tests

### Envoi local

```bash
apt install -y mailutils
echo "Test" | mail -s "Test local" user1@example.com

cat /home/user1/Maildir/new/*
```

### Test SMTP

```bash
telnet localhost 25
EHLO localhost
MAIL FROM:<test@example.com>
RCPT TO:<user1@example.com>
DATA
Subject: Test SMTP
Test
.
QUIT
```

### Test IMAP

```bash
openssl s_client -connect localhost:993
a LOGIN user1 password
a SELECT INBOX
a LOGOUT
```

---

## 9. SpamAssassin

```bash
apt install -y spamassassin spamc

# Activer
systemctl enable --now spamassassin

# Intégrer à Postfix
vim /etc/postfix/master.cf
```

```ini
spamassassin unix - n n - - pipe
  user=debian-spamd argv=/usr/bin/spamc -f -e /usr/sbin/sendmail -oi -f ${sender} ${recipient}
```

---

## 10. DKIM

```bash
apt install -y opendkim opendkim-tools

# Générer clé
mkdir -p /etc/opendkim/keys/example.com
opendkim-genkey -b 2048 -d example.com -D /etc/opendkim/keys/example.com -s default -v

# Configuration
vim /etc/opendkim.conf
```

```ini
Domain                  example.com
KeyFile                 /etc/opendkim/keys/example.com/default.private
Selector                default
Socket                  inet:8891@localhost
```

```bash
# Intégrer à Postfix
postconf -e "milter_protocol = 6"
postconf -e "milter_default_action = accept"
postconf -e "smtpd_milters = inet:localhost:8891"
postconf -e "non_smtpd_milters = inet:localhost:8891"

systemctl restart opendkim postfix
```

Ajouter l'enregistrement DNS :

```
default._domainkey.example.com. IN TXT "v=DKIM1; k=rsa; p=VOTRE_CLE_PUBLIQUE"
```

---

## Comparatif Rocky vs Debian

| Aspect | Rocky 9 | Debian 12 |
|--------|---------|-----------|
| Postfix version | 3.5 | 3.7 |
| SELinux | Oui | Non (AppArmor) |
| Logs | /var/log/maillog | /var/log/mail.log |
| Firewall | firewalld | ufw |
| DKIM | opendkim | opendkim |

---

## Dépannage

```bash
# Logs
tail -f /var/log/mail.log

# Queue
postqueue -p
postqueue -f

# Config
postfix check
postconf -n

# Dovecot
doveadm log errors
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
