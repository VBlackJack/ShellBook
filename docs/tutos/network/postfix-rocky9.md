---
tags:
  - tutos
  - mail
  - postfix
  - smtp
  - rocky
---

# Serveur Mail Postfix sur Rocky Linux 9

Installation d'un serveur mail avec **Postfix** (SMTP) et **Dovecot** (IMAP/POP3).

| Composant | Version |
|-----------|---------|
| Rocky Linux | 9.x |
| Postfix | 3.5+ |
| Dovecot | 2.3+ |

**Durée estimée :** 60 minutes

---

## Architecture

```
                          ┌─────────────┐
    Internet ────────────►│   Postfix   │◄──── Envoi (SMTP)
                          │   :25/587   │
                          └──────┬──────┘
                                 │
                          ┌──────▼──────┐
                          │   Dovecot   │◄──── Réception (IMAP)
                          │   :993/995  │
                          └──────┬──────┘
                                 │
                          ┌──────▼──────┐
                          │   Maildir   │
                          └─────────────┘
```

---

## Prérequis

- Nom de domaine configuré (MX record)
- Enregistrements DNS :
  - **A** : `mail.example.com` → IP
  - **MX** : `example.com` → `mail.example.com`
  - **PTR** : IP → `mail.example.com` (reverse DNS)
  - **SPF** : `v=spf1 mx -all`

---

## 1. Installation

```bash
dnf install -y postfix postfix-pcre dovecot cyrus-sasl cyrus-sasl-plain

# Désactiver sendmail si présent
systemctl disable --now sendmail 2>/dev/null
alternatives --set mta /usr/sbin/sendmail.postfix
```

---

## 2. Configuration Postfix

### Configuration principale

```bash
vim /etc/postfix/main.cf
```

```ini
# Identité
myhostname = mail.example.com
mydomain = example.com
myorigin = $mydomain

# Réseaux autorisés
mynetworks = 127.0.0.0/8, 192.168.1.0/24

# Destinations locales
mydestination = $myhostname, localhost.$mydomain, localhost, $mydomain

# Format Maildir
home_mailbox = Maildir/

# Taille limite (50MB)
message_size_limit = 52428800
mailbox_size_limit = 0

# Interface d'écoute
inet_interfaces = all
inet_protocols = ipv4

# TLS/SSL
smtpd_tls_cert_file = /etc/pki/tls/certs/mail.example.com.crt
smtpd_tls_key_file = /etc/pki/tls/private/mail.example.com.key
smtpd_tls_security_level = may
smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtp_tls_security_level = may

# SASL (authentification)
smtpd_sasl_type = dovecot
smtpd_sasl_path = private/auth
smtpd_sasl_auth_enable = yes
smtpd_sasl_security_options = noanonymous
smtpd_sasl_local_domain = $myhostname

# Restrictions
smtpd_helo_required = yes
smtpd_recipient_restrictions =
    permit_mynetworks,
    permit_sasl_authenticated,
    reject_unauth_destination,
    reject_invalid_hostname,
    reject_unknown_recipient_domain

smtpd_sender_restrictions =
    permit_mynetworks,
    permit_sasl_authenticated,
    reject_unknown_sender_domain

# Anti-spam basique
disable_vrfy_command = yes
smtpd_delay_reject = yes
```

### Configuration master.cf

```bash
vim /etc/postfix/master.cf
```

Décommenter/ajouter :

```ini
# Submission (port 587)
submission inet n       -       n       -       -       smtpd
  -o syslog_name=postfix/submission
  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_tls_auth_only=yes
  -o smtpd_reject_unlisted_recipient=no
  -o smtpd_recipient_restrictions=permit_sasl_authenticated,reject
  -o milter_macro_daemon_name=ORIGINATING

# SMTPS (port 465)
smtps     inet  n       -       n       -       -       smtpd
  -o syslog_name=postfix/smtps
  -o smtpd_tls_wrappermode=yes
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_reject_unlisted_recipient=no
  -o smtpd_recipient_restrictions=permit_sasl_authenticated,reject
```

---

## 3. Configuration Dovecot

### Configuration principale

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

### Mail location

```bash
vim /etc/dovecot/conf.d/10-mail.conf
```

```ini
mail_location = maildir:~/Maildir
mail_privileged_group = mail
```

### SSL/TLS

```bash
vim /etc/dovecot/conf.d/10-ssl.conf
```

```ini
ssl = required
ssl_cert = </etc/pki/tls/certs/mail.example.com.crt
ssl_key = </etc/pki/tls/private/mail.example.com.key
ssl_min_protocol = TLSv1.2
```

### Master config (pour SASL)

```bash
vim /etc/dovecot/conf.d/10-master.conf
```

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

### Auto-signé (test)

```bash
openssl req -new -x509 -days 365 -nodes \
    -out /etc/pki/tls/certs/mail.example.com.crt \
    -keyout /etc/pki/tls/private/mail.example.com.key \
    -subj "/CN=mail.example.com"

chmod 600 /etc/pki/tls/private/mail.example.com.key
```

### Let's Encrypt (production)

```bash
dnf install -y certbot
certbot certonly --standalone -d mail.example.com

# Mettre à jour les chemins dans Postfix et Dovecot
# smtpd_tls_cert_file = /etc/letsencrypt/live/mail.example.com/fullchain.pem
# smtpd_tls_key_file = /etc/letsencrypt/live/mail.example.com/privkey.pem
```

---

## 5. Créer des utilisateurs

```bash
# Utilisateur système = compte mail
useradd -m user1
passwd user1

# Créer le Maildir
mkdir -p /home/user1/Maildir
chown -R user1:user1 /home/user1/Maildir
```

---

## 6. Firewall

```bash
firewall-cmd --permanent --add-service=smtp
firewall-cmd --permanent --add-service=smtps
firewall-cmd --permanent --add-port=587/tcp
firewall-cmd --permanent --add-service=imap
firewall-cmd --permanent --add-service=imaps
firewall-cmd --permanent --add-service=pop3
firewall-cmd --permanent --add-service=pop3s
firewall-cmd --reload
```

---

## 7. SELinux

```bash
# Autoriser Postfix à écrire dans les homes
setsebool -P allow_postfix_local_write_mail_spool 1

# Contexte pour Maildir
semanage fcontext -a -t mail_home_rw_t '/home/[^/]+/Maildir(/.*)?'
restorecon -Rv /home/*/Maildir
```

---

## 8. Démarrer les services

```bash
systemctl enable --now postfix dovecot
systemctl status postfix dovecot
```

---

## 9. Test

### Envoi local

```bash
echo "Test mail" | mail -s "Test" user1@example.com

# Vérifier
ls /home/user1/Maildir/new/
```

### Test SMTP

```bash
# Telnet
telnet localhost 25
EHLO test
MAIL FROM:<root@example.com>
RCPT TO:<user1@example.com>
DATA
Subject: Test
Test message
.
QUIT
```

### Test IMAP

```bash
openssl s_client -connect mail.example.com:993
a LOGIN user1 password
a LIST "" "*"
a SELECT INBOX
a LOGOUT
```

---

## 10. DNS Records

```
; MX Record
example.com.        IN  MX  10 mail.example.com.

; A Record
mail.example.com.   IN  A   192.168.1.10

; SPF
example.com.        IN  TXT "v=spf1 mx -all"

; DKIM (si configuré)
default._domainkey  IN  TXT "v=DKIM1; k=rsa; p=..."

; DMARC
_dmarc.example.com. IN  TXT "v=DMARC1; p=quarantine; rua=mailto:admin@example.com"
```

---

## 11. SpamAssassin (optionnel)

```bash
dnf install -y spamassassin

# Activer dans Postfix
postconf -e "content_filter = spamassassin"

# Ajouter dans master.cf
spamassassin unix - n n - - pipe
  user=spamd argv=/usr/bin/spamc -f -e /usr/sbin/sendmail -oi -f ${sender} ${recipient}

systemctl enable --now spamassassin
systemctl restart postfix
```

---

## Dépannage

```bash
# Logs Postfix
tail -f /var/log/maillog

# Queue
postqueue -p
postqueue -f  # Forcer l'envoi

# Vérifier configuration
postfix check
postconf -n

# Dovecot
doveadm log errors
```

| Problème | Solution |
|----------|----------|
| Connection refused | Vérifier firewall, SELinux |
| Authentication failed | Vérifier SASL, mot de passe |
| Relay access denied | Vérifier mynetworks, SASL |
| Certificate error | Vérifier chemins SSL |

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
