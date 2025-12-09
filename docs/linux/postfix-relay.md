---
tags:
  - linux
  - mail
  - postfix
  - smtp
  - relay
---

# Postfix - Relay Mail

Configuration de Postfix en tant que relay SMTP pour centraliser et router les emails sortants des serveurs d'infrastructure.

## Architecture Relay Mail

```text
ARCHITECTURE RELAY MAIL
══════════════════════════════════════════════════════════════════════

┌─────────────────────────────────────────────────────────────────────┐
│                        INFRASTRUCTURE                               │
│                                                                     │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                │
│  │  Serveur 1  │  │  Serveur 2  │  │  Serveur 3  │                │
│  │  (cron,     │  │  (monitoring│  │  (apps,     │                │
│  │   logs)     │  │   alertes)  │  │   scripts)  │                │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘                │
│         │                │                │                        │
│         │ SMTP :25       │ SMTP :25       │ SMTP :25               │
│         └────────────────┼────────────────┘                        │
│                          ▼                                          │
│              ┌───────────────────────┐                             │
│              │    POSTFIX RELAY      │                             │
│              │   relay.corp.local    │                             │
│              │      (port 25)        │                             │
│              └───────────┬───────────┘                             │
│                          │                                          │
└──────────────────────────┼──────────────────────────────────────────┘
                           │ SMTP :25/587
                           ▼
              ┌───────────────────────┐
              │   SERVEUR MAIL        │
              │   (Exchange, O365,    │
              │    Smarthost, SMTP    │
              │    externe)           │
              └───────────────────────┘
                           │
                           ▼
                    ┌─────────────┐
                    │ Destinataire│
                    └─────────────┘

Avantages du relay centralisé:
├── Point unique de sortie (firewall simplifié)
├── Logs centralisés
├── Configuration uniforme
├── Authentification centralisée vers le smarthost
├── Queue de retry en cas d'indisponibilité
└── Filtrage/rewriting possible
```

---

## Installation

### RHEL/Rocky/AlmaLinux

```bash
# Installer Postfix
sudo dnf install postfix mailx cyrus-sasl-plain -y

# Désactiver sendmail si présent
sudo systemctl stop sendmail
sudo systemctl disable sendmail
sudo alternatives --set mta /usr/sbin/sendmail.postfix

# Activer et démarrer Postfix
sudo systemctl enable --now postfix

# Vérifier
sudo systemctl status postfix
postconf mail_version
```

### Debian/Ubuntu

```bash
# Installer Postfix
sudo apt update
sudo apt install postfix mailutils libsasl2-modules -y

# Pendant l'installation, choisir "Satellite system" ou "Internet with smarthost"
# Ou reconfigurer après
sudo dpkg-reconfigure postfix

# Activer
sudo systemctl enable --now postfix
```

---

## Configuration Relay Simple

### Configuration de Base

```bash
# /etc/postfix/main.cf

# Identification du serveur
myhostname = relay.corp.local
mydomain = corp.local
myorigin = $mydomain

# Interfaces d'écoute
# Écouter sur toutes les interfaces internes
inet_interfaces = all
inet_protocols = ipv4

# Réseaux autorisés à relayer
# IMPORTANT: Restreindre aux réseaux internes uniquement
mynetworks = 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16

# Destination finale (ce serveur ne reçoit pas de mail)
mydestination = $myhostname, localhost.$mydomain, localhost

# Relay vers le smarthost
relayhost = [smtp.corp.local]:25

# Désactiver la réception de mail depuis l'extérieur
# Ce serveur est uniquement un relay sortant
smtpd_recipient_restrictions =
    permit_mynetworks,
    reject_unauth_destination

# Taille max des messages (50MB)
message_size_limit = 52428800

# Queue settings
maximal_queue_lifetime = 3d
bounce_queue_lifetime = 3d

# Logging
maillog_file = /var/log/maillog
```

### Appliquer la Configuration

```bash
# Vérifier la syntaxe
sudo postfix check

# Recharger la configuration
sudo postfix reload

# Ou redémarrer
sudo systemctl restart postfix

# Vérifier les paramètres actifs
postconf -n
```

---

## Relay avec Authentification (Smarthost)

### Configuration SASL

```bash
# /etc/postfix/main.cf

# Smarthost avec port (587 pour submission)
relayhost = [smtp.office365.com]:587

# Authentification SASL
smtp_sasl_auth_enable = yes
smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd
smtp_sasl_security_options = noanonymous
smtp_sasl_tls_security_options = noanonymous

# TLS obligatoire
smtp_use_tls = yes
smtp_tls_security_level = encrypt
smtp_tls_CAfile = /etc/pki/tls/certs/ca-bundle.crt
# Debian/Ubuntu: /etc/ssl/certs/ca-certificates.crt

# Logging TLS (debug)
smtp_tls_loglevel = 1
```

### Fichier de Credentials

```bash
# Créer le fichier de mots de passe
sudo nano /etc/postfix/sasl_passwd

# Format: [serveur]:port utilisateur:mot_de_passe
[smtp.office365.com]:587 relay@corp.com:MotDePasseSecret

# Ou pour Gmail
[smtp.gmail.com]:587 compte@gmail.com:app-password

# Sécuriser et hasher
sudo chmod 600 /etc/postfix/sasl_passwd
sudo postmap /etc/postfix/sasl_passwd

# Vérifier que le fichier .db est créé
ls -la /etc/postfix/sasl_passwd*

# Recharger Postfix
sudo postfix reload
```

### Exemple Office 365 / Microsoft 365

```bash
# /etc/postfix/main.cf - Configuration O365

myhostname = relay.corp.local
mydomain = corp.local
myorigin = $mydomain

inet_interfaces = all
inet_protocols = ipv4

mynetworks = 127.0.0.0/8, 10.0.0.0/8

mydestination = $myhostname, localhost.$mydomain, localhost

# Office 365 SMTP
relayhost = [smtp.office365.com]:587

# SASL Authentication
smtp_sasl_auth_enable = yes
smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd
smtp_sasl_security_options = noanonymous

# TLS
smtp_use_tls = yes
smtp_tls_security_level = encrypt
smtp_tls_CAfile = /etc/pki/tls/certs/ca-bundle.crt

# Important pour O365: vérifier le certificat
smtp_tls_verify_cert_match = hostname
smtp_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1

smtpd_recipient_restrictions = permit_mynetworks, reject_unauth_destination
```

### Exemple Gmail

```bash
# /etc/postfix/main.cf - Configuration Gmail

relayhost = [smtp.gmail.com]:587

smtp_sasl_auth_enable = yes
smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd
smtp_sasl_security_options = noanonymous

smtp_use_tls = yes
smtp_tls_security_level = encrypt
smtp_tls_CAfile = /etc/pki/tls/certs/ca-bundle.crt

# Gmail nécessite un "App Password" si 2FA activé
# https://myaccount.google.com/apppasswords
```

---

## Relay Interne (Sans Auth)

### Vers un Serveur Exchange Interne

```bash
# /etc/postfix/main.cf

myhostname = relay.corp.local
mydomain = corp.local
myorigin = $mydomain

inet_interfaces = all
inet_protocols = ipv4

# Réseaux internes autorisés
mynetworks = 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16

mydestination = $myhostname, localhost.$mydomain, localhost

# Relay vers Exchange interne (pas d'auth nécessaire si IP whitelistée)
relayhost = [exchange.corp.local]:25

# Pas de TLS si réseau interne sécurisé
# smtp_use_tls = no

# Ou TLS opportuniste
smtp_tls_security_level = may

smtpd_recipient_restrictions = permit_mynetworks, reject_unauth_destination
```

### Configuration Exchange pour Accepter le Relay

```powershell
# Sur Exchange, créer un Receive Connector pour le relay Linux
New-ReceiveConnector -Name "Linux Relay" `
    -TransportRole FrontendTransport `
    -Usage Custom `
    -Bindings 0.0.0.0:25 `
    -RemoteIPRanges 10.0.0.0/8 `
    -AuthMechanism None `
    -PermissionGroups AnonymousUsers

# Autoriser le relay
Set-ReceiveConnector "Linux Relay" -RelayControlEnabled $true
```

---

## Réécriture d'Adresses

### Réécriture de l'Expéditeur

```bash
# /etc/postfix/main.cf

# Réécrire le From pour tous les mails sortants
smtp_generic_maps = hash:/etc/postfix/generic

# Optionnel: réécrire aussi l'enveloppe
sender_canonical_maps = hash:/etc/postfix/sender_canonical
```

```bash
# /etc/postfix/generic
# Format: adresse_locale    adresse_reelle

root@relay.corp.local           noreply@corp.com
www-data@relay.corp.local       noreply@corp.com
cron@relay.corp.local           noreply@corp.com
nagios@relay.corp.local         monitoring@corp.com
@relay.corp.local               noreply@corp.com

# Hasher
sudo postmap /etc/postfix/generic
sudo postfix reload
```

### Réécriture par Expression Régulière

```bash
# /etc/postfix/main.cf
smtp_generic_maps = regexp:/etc/postfix/generic_regexp

# /etc/postfix/generic_regexp
# Réécrire tous les mails de serveurs internes
/^(.*)@srv[0-9]+\.corp\.local$/    ${1}@corp.com
/^root@(.*)$/                       admin@corp.com
/^(.*)@localhost$/                  noreply@corp.com
```

### Header Rewriting

```bash
# /etc/postfix/main.cf
smtp_header_checks = regexp:/etc/postfix/header_checks

# /etc/postfix/header_checks
# Modifier le header From
/^From:.*<.*@localhost>$/   REPLACE From: "Server Notifications" <noreply@corp.com>

# Supprimer les headers sensibles
/^X-Originating-IP:/        IGNORE
/^Received:.*localhost/     IGNORE
```

---

## Transport Maps (Routage Conditionnel)

### Router selon le Domaine

```bash
# /etc/postfix/main.cf
transport_maps = hash:/etc/postfix/transport

# /etc/postfix/transport
# Format: domaine    transport:destination

# Mails internes vers Exchange
corp.local              smtp:[exchange.corp.local]:25
corp.com                smtp:[exchange.corp.local]:25

# Partenaires via relay spécifique
partner.com             smtp:[smtp.partner.com]:25

# Tout le reste via le smarthost par défaut
*                       smtp:[smtp.office365.com]:587

# Hasher
sudo postmap /etc/postfix/transport
sudo postfix reload
```

### Router selon l'Expéditeur

```bash
# /etc/postfix/main.cf
sender_dependent_relayhost_maps = hash:/etc/postfix/sender_relay

# /etc/postfix/sender_relay
# Les alertes monitoring passent par un autre relay
nagios@corp.local       [smtp-alerts.corp.local]:25
zabbix@corp.local       [smtp-alerts.corp.local]:25

# Hasher
sudo postmap /etc/postfix/sender_relay
```

---

## Sécurité

### Restrictions d'Accès

```bash
# /etc/postfix/main.cf

# Restrictions sur les clients SMTP
smtpd_client_restrictions =
    permit_mynetworks,
    reject_unknown_client_hostname,
    reject_rbl_client zen.spamhaus.org

# Restrictions sur les commandes HELO
smtpd_helo_required = yes
smtpd_helo_restrictions =
    permit_mynetworks,
    reject_invalid_helo_hostname,
    reject_non_fqdn_helo_hostname

# Restrictions sur l'expéditeur
smtpd_sender_restrictions =
    permit_mynetworks,
    reject_non_fqdn_sender,
    reject_unknown_sender_domain

# Restrictions sur le destinataire
smtpd_recipient_restrictions =
    permit_mynetworks,
    reject_unauth_destination,
    reject_non_fqdn_recipient,
    reject_unknown_recipient_domain

# Limiter le rate
smtpd_client_message_rate_limit = 100
smtpd_client_recipient_rate_limit = 100

# Banner personnalisé (masquer la version)
smtpd_banner = $myhostname ESMTP
```

### TLS pour les Connexions Entrantes

```bash
# /etc/postfix/main.cf

# Certificat du serveur
smtpd_tls_cert_file = /etc/pki/tls/certs/relay.corp.local.crt
smtpd_tls_key_file = /etc/pki/tls/private/relay.corp.local.key

# TLS opportuniste pour les clients
smtpd_tls_security_level = may

# Protocoles et ciphers
smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1

# Logging
smtpd_tls_loglevel = 1
smtpd_tls_received_header = yes
```

### Firewall

```bash
# Firewalld (RHEL/Rocky)
sudo firewall-cmd --permanent --add-service=smtp
sudo firewall-cmd --reload

# Ou limiter aux réseaux internes
sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="10.0.0.0/8" service name="smtp" accept'
sudo firewall-cmd --reload

# UFW (Debian/Ubuntu)
sudo ufw allow from 10.0.0.0/8 to any port 25 proto tcp
sudo ufw reload

# iptables
iptables -A INPUT -p tcp --dport 25 -s 10.0.0.0/8 -j ACCEPT
iptables -A INPUT -p tcp --dport 25 -j DROP
```

---

## Configuration des Clients

### Configuration Linux (Serveurs Internes)

```bash
# /etc/postfix/main.cf (sur les serveurs clients)

# Relay via le serveur Postfix central
relayhost = [relay.corp.local]:25

# Identification
myhostname = serveur1.corp.local
myorigin = $myhostname

# Écouter uniquement en local
inet_interfaces = loopback-only

# Pas de réception de mail
mydestination =
```

### Alternative: Utiliser msmtp (Léger)

```bash
# Installation
sudo dnf install msmtp msmtp-mta    # RHEL
sudo apt install msmtp msmtp-mta    # Debian

# /etc/msmtprc
defaults
auth           off
tls            off
logfile        /var/log/msmtp.log

account        default
host           relay.corp.local
port           25
from           %U@serveur1.corp.local

# Lier à sendmail
sudo ln -sf /usr/bin/msmtp /usr/sbin/sendmail
```

### Configuration Applicative

```bash
# PHP (php.ini)
sendmail_path = "/usr/sbin/sendmail -t -i"

# Python
import smtplib
server = smtplib.SMTP('relay.corp.local', 25)
server.sendmail(from_addr, to_addr, message)

# Cron (envoyer les sorties par mail)
MAILTO=admin@corp.com
* * * * * /path/to/script.sh 2>&1
```

---

## Monitoring et Logs

### Analyse des Logs

```bash
# Voir les logs en temps réel
sudo tail -f /var/log/maillog        # RHEL
sudo tail -f /var/log/mail.log       # Debian

# Chercher les erreurs
sudo grep -i "error\|warning\|fatal\|reject" /var/log/maillog

# Statistiques avec pflogsumm
sudo dnf install postfix-perl-scripts    # RHEL
sudo apt install pflogsumm              # Debian

sudo pflogsumm /var/log/maillog

# Messages en queue
mailq
postqueue -p

# Nombre de messages en queue
mailq | tail -1

# Forcer le traitement de la queue
sudo postqueue -f

# Supprimer un message de la queue
sudo postsuper -d MESSAGE_ID

# Vider toute la queue (attention!)
sudo postsuper -d ALL
```

### Script de Monitoring

```bash
#!/bin/bash
# /usr/local/bin/check_postfix.sh

# Vérifier le service
if ! systemctl is-active --quiet postfix; then
    echo "CRITICAL: Postfix is not running"
    exit 2
fi

# Vérifier la queue
QUEUE_SIZE=$(mailq | grep -c "^[A-F0-9]" 2>/dev/null || echo 0)
DEFERRED=$(mailq | grep -c "deferred" 2>/dev/null || echo 0)

if [ "$QUEUE_SIZE" -gt 1000 ]; then
    echo "WARNING: Mail queue has $QUEUE_SIZE messages ($DEFERRED deferred)"
    exit 1
fi

# Vérifier la connectivité vers le smarthost
SMARTHOST=$(postconf -h relayhost | tr -d '[]' | cut -d: -f1)
if [ -n "$SMARTHOST" ]; then
    if ! nc -z -w5 "$SMARTHOST" 25 2>/dev/null; then
        echo "CRITICAL: Cannot connect to smarthost $SMARTHOST"
        exit 2
    fi
fi

echo "OK: Postfix running, queue size: $QUEUE_SIZE"
exit 0
```

### Intégration Prometheus

```yaml
# Avec postfix_exporter
# https://github.com/kumina/postfix_exporter

# Installation
wget https://github.com/kumina/postfix_exporter/releases/download/v0.3.0/postfix_exporter-0.3.0.linux-amd64.tar.gz
tar xzf postfix_exporter-*.tar.gz
sudo mv postfix_exporter /usr/local/bin/

# Service systemd
# /etc/systemd/system/postfix_exporter.service
[Unit]
Description=Postfix Exporter
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/postfix_exporter --postfix.logfile_path=/var/log/maillog
Restart=always

[Install]
WantedBy=multi-user.target
```

---

## Troubleshooting

### Commandes de Diagnostic

```bash
# Tester l'envoi de mail
echo "Test message" | mail -s "Test from $(hostname)" admin@corp.com

# Test avec mailx verbose
echo "Test" | mailx -v -s "Test" admin@corp.com

# Tester la connexion SMTP manuellement
telnet relay.corp.local 25
# ou
nc -v relay.corp.local 25

# Test avec openssl (TLS)
openssl s_client -connect smtp.office365.com:587 -starttls smtp

# Vérifier la configuration
postconf -n                    # Paramètres modifiés
postconf -d                    # Paramètres par défaut
postconf mail_version          # Version

# Vérifier la syntaxe
sudo postfix check

# Voir les maps
postmap -q "test@corp.local" hash:/etc/postfix/generic
```

### Problèmes Courants

```bash
# ERREUR: "Relay access denied"
# → Vérifier mynetworks inclut l'IP du client
postconf mynetworks

# ERREUR: "Connection timed out"
# → Vérifier le firewall et la connectivité
telnet smtp.office365.com 587
traceroute smtp.office365.com

# ERREUR: "SASL authentication failed"
# → Vérifier les credentials
cat /etc/postfix/sasl_passwd
sudo postmap -q "[smtp.office365.com]:587" hash:/etc/postfix/sasl_passwd

# ERREUR: "TLS required but not available"
# → Vérifier smtp_use_tls et les certificats CA
openssl s_client -connect smtp.office365.com:587 -starttls smtp

# Messages bloqués en queue "deferred"
mailq
postcat -q MESSAGE_ID          # Voir le contenu
sudo postsuper -r MESSAGE_ID   # Retenter

# Voir les détails d'un message en queue
sudo find /var/spool/postfix -name "MESSAGE_ID*" -exec cat {} \;
```

### Debug Mode

```bash
# Activer le debug pour un domaine
# /etc/postfix/main.cf
debug_peer_list = smtp.office365.com
debug_peer_level = 3

# Recharger et tester
sudo postfix reload
echo "test" | mail -s "debug test" user@office365.com
sudo tail -f /var/log/maillog
```

---

## Haute Disponibilité

### Deux Relays avec MX

```bash
# DNS
relay1.corp.local    A     10.0.0.10
relay2.corp.local    A     10.0.0.11
relay.corp.local     MX 10 relay1.corp.local
relay.corp.local     MX 20 relay2.corp.local

# Configuration identique sur les deux serveurs
# Les clients utilisent relay.corp.local
```

### Avec Keepalived (VIP)

```bash
# /etc/keepalived/keepalived.conf (sur relay1 - MASTER)
vrrp_instance POSTFIX_VIP {
    state MASTER
    interface eth0
    virtual_router_id 51
    priority 100
    advert_int 1

    authentication {
        auth_type PASS
        auth_pass secret123
    }

    virtual_ipaddress {
        10.0.0.100/24
    }

    track_script {
        check_postfix
    }
}

vrrp_script check_postfix {
    script "/usr/local/bin/check_postfix.sh"
    interval 5
    weight -20
}
```

---

## Bonnes Pratiques

```yaml
Checklist Postfix Relay:
  Configuration:
    - [ ] mynetworks restreint aux IPs internes
    - [ ] relayhost configuré vers smarthost
    - [ ] TLS activé (smtp_use_tls)
    - [ ] Credentials sécurisés (chmod 600)

  Sécurité:
    - [ ] smtpd_recipient_restrictions configuré
    - [ ] Firewall limitant l'accès au port 25
    - [ ] Banner personnalisé (masquer version)
    - [ ] Pas d'open relay!

  Réécriture:
    - [ ] Adresses From cohérentes
    - [ ] generic_maps si nécessaire
    - [ ] Headers sensibles supprimés

  Monitoring:
    - [ ] Alertes sur queue > seuil
    - [ ] Monitoring service Postfix
    - [ ] Logs centralisés
    - [ ] Rotation des logs

  Maintenance:
    - [ ] Test d'envoi régulier
    - [ ] Purge queue si nécessaire
    - [ ] Mises à jour de sécurité
    - [ ] Documentation des flux
```

---

**Voir aussi :**

- [Boot & Services](boot-and-services.md) - Gestion systemd
- [SSH Hardening](ssh-hardening.md) - Sécurisation
- [Firewall UFW](firewall-ufw.md) - Configuration firewall
- [NXLog](../windows/nxlog.md) - Envoi de logs (alertes mail)
