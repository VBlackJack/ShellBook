---
tags:
  - tutos
  - network
  - freeipa
  - ldap
  - kerberos
  - debian
---

# FreeIPA Client sur Debian 12

Configuration du client **FreeIPA** sur Debian 12 Bookworm.

| Composant | Version |
|-----------|---------|
| Debian | 12 Bookworm |
| FreeIPA Client | 4.9+ |

**Durée estimée :** 20 minutes

!!! note "Serveur FreeIPA"
    FreeIPA Server est optimisé pour RHEL/Rocky. Pour le serveur, utilisez Rocky Linux 9. Ce guide couvre l'intégration des clients Debian.

---

## 1. Prérequis

### Hostname FQDN

```bash
hostnamectl set-hostname client.example.com
```

### /etc/hosts

```bash
cat >> /etc/hosts << 'EOF'
192.168.1.10 ipa.example.com ipa
EOF
```

### DNS

```bash
# Configurer le DNS vers le serveur IPA
vim /etc/resolv.conf
```

```
nameserver 192.168.1.10
search example.com
```

---

## 2. Installation Client

```bash
apt update
apt install -y freeipa-client
```

---

## 3. Enregistrement

```bash
ipa-client-install \
    --domain=example.com \
    --realm=EXAMPLE.COM \
    --server=ipa.example.com \
    --mkhomedir \
    --principal=admin \
    --password=AdminPassword \
    --unattended
```

### Options importantes

| Option | Description |
|--------|-------------|
| `--mkhomedir` | Créer le home à la connexion |
| `--force-ntpd` | Forcer la config NTP |
| `--no-ntp` | Ne pas configurer NTP |
| `--enable-dns-updates` | Mises à jour DNS dynamiques |

---

## 4. Vérification

```bash
# Obtenir un ticket Kerberos
kinit admin
klist

# Vérifier un utilisateur
id ipauser
getent passwd ipauser

# SSH avec utilisateur IPA
ssh ipauser@localhost
```

---

## 5. Configuration SSSD

```bash
vim /etc/sssd/sssd.conf
```

```ini
[sssd]
domains = example.com
services = nss, pam, ssh, sudo
config_file_version = 2

[domain/example.com]
cache_credentials = True
krb5_store_password_if_offline = True
ipa_domain = example.com
id_provider = ipa
auth_provider = ipa
access_provider = ipa
ipa_hostname = client.example.com
chpass_provider = ipa
ipa_server = ipa.example.com
ldap_tls_cacert = /etc/ipa/ca.crt
```

```bash
systemctl restart sssd
```

---

## 6. Sudo centralisé

```bash
# Vérifier que sudo est dans les services SSSD
vim /etc/sssd/sssd.conf
# services = nss, pam, ssh, sudo

# Configurer nsswitch
vim /etc/nsswitch.conf
```

```
sudoers: files sss
```

```bash
systemctl restart sssd
```

---

## 7. Création home automatique

```bash
# PAM mkhomedir
vim /etc/pam.d/common-session
```

Ajouter :
```
session required pam_mkhomedir.so skel=/etc/skel umask=0077
```

---

## 8. Firewall

```bash
ufw allow 88/tcp    # Kerberos
ufw allow 88/udp
ufw allow 464/tcp   # kpasswd
ufw allow 464/udp
ufw allow 389/tcp   # LDAP
ufw allow 636/tcp   # LDAPS
ufw reload
```

---

## Comparatif Rocky vs Debian

| Aspect | Rocky 9 | Debian 12 |
|--------|---------|-----------|
| Serveur IPA | Oui (recommandé) | Non supporté |
| Client IPA | Oui | Oui |
| Package | ipa-client | freeipa-client |
| SSSD | Intégré | Manuel |

---

## Commandes

```bash
kinit admin                    # Obtenir ticket
klist                          # Lister tickets
id username                    # Info utilisateur
getent passwd username         # Lookup LDAP
ipa-client-install --uninstall # Désinscrire
```

---

## Dépannage

```bash
# Logs SSSD
journalctl -u sssd
tail -f /var/log/sssd/sssd_example.com.log

# Test Kerberos
kinit admin
kvno admin@EXAMPLE.COM

# Test LDAP
ldapsearch -x -H ldap://ipa.example.com -b "dc=example,dc=com"

# Cache SSSD
sss_cache -E
systemctl restart sssd
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
