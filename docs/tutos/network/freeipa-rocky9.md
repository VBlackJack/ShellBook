---
tags:
  - tutos
  - network
  - freeipa
  - ldap
  - kerberos
  - rocky
---

# FreeIPA sur Rocky Linux 9

Installation de **FreeIPA** pour l'identity management centralisé.

| Composant | Version |
|-----------|---------|
| Rocky Linux | 9.x |
| FreeIPA | 4.10+ |

**Durée estimée :** 50 minutes

---

## Composants FreeIPA

| Service | Description |
|---------|-------------|
| **389 Directory Server** | LDAP |
| **MIT Kerberos** | Authentification SSO |
| **Dogtag** | PKI / Certificats |
| **DNS (Bind)** | DNS intégré |
| **NTP (Chrony)** | Synchronisation temps |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      FreeIPA Server                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │    LDAP     │  │  Kerberos   │  │     DNS     │        │
│  │  389-DS     │  │    KDC      │  │    Bind     │        │
│  └─────────────┘  └─────────────┘  └─────────────┘        │
│  ┌─────────────┐  ┌─────────────┐                         │
│  │     PKI     │  │   Web UI    │                         │
│  │   Dogtag    │  │   :443      │                         │
│  └─────────────┘  └─────────────┘                         │
└─────────────────────────────────────────────────────────────┘
                           │
         ┌─────────────────┼─────────────────┐
         ▼                 ▼                 ▼
   ┌──────────┐      ┌──────────┐      ┌──────────┐
   │  Client  │      │  Client  │      │  Client  │
   │  Linux   │      │  Linux   │      │  Linux   │
   └──────────┘      └──────────┘      └──────────┘
```

---

## 1. Prérequis

### Hostname FQDN

```bash
hostnamectl set-hostname ipa.example.com

# Vérifier
hostname -f
```

### /etc/hosts

```bash
cat >> /etc/hosts << 'EOF'
192.168.1.10 ipa.example.com ipa
EOF
```

### Firewall

```bash
firewall-cmd --permanent --add-service={freeipa-ldap,freeipa-ldaps,dns,ntp,http,https,kerberos,kpasswd}
firewall-cmd --reload
```

### Synchronisation temps

```bash
dnf install -y chrony
systemctl enable --now chronyd
```

---

## 2. Installation Serveur

```bash
dnf install -y ipa-server ipa-server-dns

# Installation interactive
ipa-server-install
```

### Installation non-interactive

```bash
ipa-server-install \
    --realm=EXAMPLE.COM \
    --domain=example.com \
    --ds-password=DirectoryManagerPassword \
    --admin-password=AdminPassword \
    --hostname=ipa.example.com \
    --ip-address=192.168.1.10 \
    --setup-dns \
    --forwarder=8.8.8.8 \
    --no-reverse \
    --unattended
```

---

## 3. Vérification

```bash
# Obtenir un ticket Kerberos
kinit admin
klist

# Tester
ipa user-find admin

# Interface web
# https://ipa.example.com
# Login: admin
```

---

## 4. Gestion des utilisateurs

### Créer un utilisateur

```bash
ipa user-add jdupont \
    --first=Jean \
    --last=Dupont \
    --email=jdupont@example.com \
    --password
```

### Lister les utilisateurs

```bash
ipa user-find
ipa user-show jdupont
```

### Modifier un utilisateur

```bash
ipa user-mod jdupont --shell=/bin/zsh
```

### Supprimer un utilisateur

```bash
ipa user-del jdupont
```

---

## 5. Groupes

```bash
# Créer un groupe
ipa group-add developers --desc="Development team"

# Ajouter un membre
ipa group-add-member developers --users=jdupont

# Lister
ipa group-find
ipa group-show developers
```

---

## 6. Politiques de mot de passe

```bash
# Voir la politique
ipa pwpolicy-show

# Modifier
ipa pwpolicy-mod \
    --maxlife=90 \
    --minlife=1 \
    --history=5 \
    --minlength=12 \
    --minclasses=3
```

---

## 7. Client FreeIPA (Rocky/RHEL)

### Installation

```bash
dnf install -y ipa-client
```

### Enregistrement

```bash
ipa-client-install \
    --domain=example.com \
    --realm=EXAMPLE.COM \
    --server=ipa.example.com \
    --mkhomedir \
    --unattended \
    --principal=admin \
    --password=AdminPassword
```

### Vérifier

```bash
# Se connecter avec un utilisateur IPA
ssh jdupont@client.example.com

# Vérifier l'authentification
id jdupont
getent passwd jdupont
```

---

## 8. HBAC (Host-Based Access Control)

```bash
# Créer une règle
ipa hbacrule-add allow_developers

# Ajouter des utilisateurs/groupes
ipa hbacrule-add-user allow_developers --groups=developers

# Ajouter des hôtes
ipa hbacrule-add-host allow_developers --hosts=devserver.example.com

# Ajouter des services
ipa hbacrule-add-service allow_developers --hbacsvcs=sshd

# Activer
ipa hbacrule-enable allow_developers
```

---

## 9. Sudo Rules

```bash
# Créer une règle sudo
ipa sudorule-add developers_sudo

# Ajouter des commandes
ipa sudocmd-add /usr/bin/systemctl
ipa sudorule-add-allow-command developers_sudo --sudocmds=/usr/bin/systemctl

# Ajouter des utilisateurs
ipa sudorule-add-user developers_sudo --groups=developers

# Ajouter des hôtes
ipa sudorule-add-host developers_sudo --hosts=devserver.example.com
```

---

## 10. DNS

```bash
# Ajouter une zone
ipa dnszone-add internal.example.com

# Ajouter un enregistrement A
ipa dnsrecord-add example.com webserver --a-rec=192.168.1.50

# Ajouter un CNAME
ipa dnsrecord-add example.com www --cname-rec=webserver.example.com.

# Lister les zones
ipa dnszone-find
```

---

## 11. Certificats

```bash
# Demander un certificat
ipa-getcert request \
    -f /etc/pki/tls/certs/server.crt \
    -k /etc/pki/tls/private/server.key \
    -N CN=server.example.com \
    -D server.example.com

# Lister les certificats
ipa-getcert list

# Status
ipa-getcert status -f /etc/pki/tls/certs/server.crt
```

---

## 12. Réplication (HA)

### Second serveur IPA

```bash
# Sur le second serveur
dnf install -y ipa-server ipa-server-dns

ipa-replica-install \
    --setup-dns \
    --forwarder=8.8.8.8 \
    --principal=admin \
    --admin-password=AdminPassword
```

### Vérifier la réplication

```bash
ipa-replica-manage list
ipa-csreplica-manage list
```

---

## 13. Trust Active Directory

```bash
# Installer le composant
dnf install -y ipa-server-trust-ad

# Configurer le trust
ipa-adtrust-install

# Créer le trust
ipa trust-add --type=ad ad.example.com --admin Administrator --password
```

---

## Backup et Restore

```bash
# Backup complet
ipa-backup

# Backup données uniquement
ipa-backup --data

# Restore
ipa-restore /var/lib/ipa/backup/ipa-full-2024-12-15-12-00-00
```

---

## Commandes utiles

```bash
# Kerberos
kinit admin
klist
kdestroy

# Utilisateurs
ipa user-find
ipa user-show username
ipa passwd username

# Groupes
ipa group-find
ipa group-show groupname

# Hosts
ipa host-find
ipa host-show hostname

# Services
ipactl status
ipactl restart
```

---

## Dépannage

```bash
# Logs
journalctl -u ipa
tail -f /var/log/dirsrv/slapd-EXAMPLE-COM/errors
tail -f /var/log/krb5kdc.log

# Test LDAP
ldapsearch -x -H ldap://ipa.example.com -b "dc=example,dc=com"

# Test Kerberos
kinit admin
kvno admin@EXAMPLE.COM
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
