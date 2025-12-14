---
tags:
  - tutos
  - ldap
  - openldap
  - directory
  - debian
---

# OpenLDAP sur Debian 12

Installation d'un serveur d'annuaire **OpenLDAP** sur Debian 12.

| Composant | Version |
|-----------|---------|
| Debian | 12 Bookworm |
| OpenLDAP | 2.5+ |

**Durée estimée :** 40 minutes

---

## 1. Installation

```bash
apt update

# L'installation demande la configuration initiale
apt install -y slapd ldap-utils

# Reconfigurer si nécessaire
dpkg-reconfigure slapd
```

Réponses lors de la configuration :
- Omit OpenLDAP server configuration? **No**
- DNS domain name: **example.com**
- Organization name: **Example Company**
- Administrator password: **votre_mot_de_passe**
- Database backend: **MDB**
- Remove database when purged? **No**
- Move old database? **Yes**

---

## 2. Vérifier l'installation

```bash
systemctl status slapd

# Tester
ldapsearch -x -b "dc=example,dc=com" -D "cn=admin,dc=example,dc=com" -W
```

---

## 3. Créer la structure

```bash
cat > /tmp/base.ldif << 'EOF'
# OU Users
dn: ou=users,dc=example,dc=com
objectClass: organizationalUnit
ou: users

# OU Groups
dn: ou=groups,dc=example,dc=com
objectClass: organizationalUnit
ou: groups

# OU Services
dn: ou=services,dc=example,dc=com
objectClass: organizationalUnit
ou: services
EOF

ldapadd -x -D "cn=admin,dc=example,dc=com" -W -f /tmp/base.ldif
```

---

## 4. Ajouter des utilisateurs

### Générer un mot de passe

```bash
slappasswd -s "motdepasse"
```

### Créer les utilisateurs

```bash
cat > /tmp/users.ldif << 'EOF'
dn: uid=user1,ou=users,dc=example,dc=com
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: user1
cn: User One
sn: One
givenName: User
mail: user1@example.com
uidNumber: 10001
gidNumber: 10001
homeDirectory: /home/user1
loginShell: /bin/bash
userPassword: {SSHA}HASH_ICI

dn: uid=user2,ou=users,dc=example,dc=com
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: user2
cn: User Two
sn: Two
givenName: User
mail: user2@example.com
uidNumber: 10002
gidNumber: 10001
homeDirectory: /home/user2
loginShell: /bin/bash
userPassword: {SSHA}HASH_ICI
EOF

ldapadd -x -D "cn=admin,dc=example,dc=com" -W -f /tmp/users.ldif
```

---

## 5. Ajouter des groupes

```bash
cat > /tmp/groups.ldif << 'EOF'
dn: cn=admins,ou=groups,dc=example,dc=com
objectClass: posixGroup
cn: admins
gidNumber: 10001
memberUid: user1

dn: cn=developers,ou=groups,dc=example,dc=com
objectClass: posixGroup
cn: developers
gidNumber: 10002
memberUid: user1
memberUid: user2
EOF

ldapadd -x -D "cn=admin,dc=example,dc=com" -W -f /tmp/groups.ldif
```

---

## 6. Requêtes LDAP

```bash
# Lister tout
ldapsearch -x -b "dc=example,dc=com"

# Chercher un utilisateur
ldapsearch -x -b "dc=example,dc=com" "(uid=user1)"

# Chercher par mail
ldapsearch -x -b "dc=example,dc=com" "(mail=*@example.com)" cn mail

# Lister les groupes
ldapsearch -x -b "ou=groups,dc=example,dc=com" "(objectClass=posixGroup)" cn memberUid

# Format compact
ldapsearch -x -LLL -b "dc=example,dc=com" "(uid=user1)" cn mail
```

---

## 7. Modifier des entrées

```bash
# Modifier un attribut
cat > /tmp/modify.ldif << 'EOF'
dn: uid=user1,ou=users,dc=example,dc=com
changetype: modify
replace: mail
mail: new.email@example.com
EOF

ldapmodify -x -D "cn=admin,dc=example,dc=com" -W -f /tmp/modify.ldif

# Ajouter un membre au groupe
cat > /tmp/add-member.ldif << 'EOF'
dn: cn=admins,ou=groups,dc=example,dc=com
changetype: modify
add: memberUid
memberUid: user2
EOF

ldapmodify -x -D "cn=admin,dc=example,dc=com" -W -f /tmp/add-member.ldif
```

---

## 8. TLS/SSL

### Certificats

```bash
mkdir -p /etc/ldap/ssl

openssl req -new -x509 -days 365 -nodes \
    -out /etc/ldap/ssl/ldap.crt \
    -keyout /etc/ldap/ssl/ldap.key \
    -subj "/CN=ldap.example.com"

chown openldap:openldap /etc/ldap/ssl/*
chmod 600 /etc/ldap/ssl/ldap.key
```

### Configurer TLS

```bash
cat > /tmp/tls.ldif << 'EOF'
dn: cn=config
changetype: modify
add: olcTLSCACertificateFile
olcTLSCACertificateFile: /etc/ldap/ssl/ldap.crt
-
add: olcTLSCertificateFile
olcTLSCertificateFile: /etc/ldap/ssl/ldap.crt
-
add: olcTLSCertificateKeyFile
olcTLSCertificateKeyFile: /etc/ldap/ssl/ldap.key
EOF

ldapmodify -Y EXTERNAL -H ldapi:/// -f /tmp/tls.ldif
```

### Activer LDAPS

```bash
vim /etc/default/slapd
```

```ini
SLAPD_SERVICES="ldap:/// ldapi:/// ldaps:///"
```

```bash
systemctl restart slapd
```

---

## 9. Firewall

```bash
ufw allow 389/tcp   # LDAP
ufw allow 636/tcp   # LDAPS
ufw reload
```

---

## 10. Client LDAP

### Sur un autre serveur Debian

```bash
apt install -y libnss-ldapd libpam-ldapd ldap-utils

# Configuration interactive
# LDAP URI: ldap://ldap.example.com
# Base: dc=example,dc=com
```

### Ou avec SSSD

```bash
apt install -y sssd-ldap

cat > /etc/sssd/sssd.conf << 'EOF'
[sssd]
services = nss, pam
domains = LDAP

[domain/LDAP]
id_provider = ldap
auth_provider = ldap
ldap_uri = ldap://ldap.example.com
ldap_search_base = dc=example,dc=com
ldap_default_bind_dn = cn=admin,dc=example,dc=com
ldap_default_authtok = password
cache_credentials = true
EOF

chmod 600 /etc/sssd/sssd.conf
systemctl enable --now sssd
```

---

## 11. phpLDAPadmin (GUI)

```bash
apt install -y phpldapadmin

# Configurer
vim /etc/phpldapadmin/config.php
```

```php
$servers->setValue('server','name','LDAP Server');
$servers->setValue('server','host','127.0.0.1');
$servers->setValue('server','base',array('dc=example,dc=com'));
$servers->setValue('login','bind_id','cn=admin,dc=example,dc=com');
```

Accès : `http://serveur/phpldapadmin`

---

## Comparatif Rocky vs Debian

| Aspect | Rocky 9 | Debian 12 |
|--------|---------|-----------|
| Package | openldap-servers | slapd |
| Config initiale | Manuelle | dpkg-reconfigure |
| Certs path | /etc/openldap/certs | /etc/ldap/ssl |
| User | ldap | openldap |
| Startup config | /etc/sysconfig/slapd | /etc/default/slapd |

---

## Vérification

```bash
systemctl status slapd
ldapsearch -x -b "dc=example,dc=com" "(objectClass=*)" dn
slapcat -n 1 | head -50
```

---

## Dépannage

```bash
# Logs
journalctl -u slapd -f

# Debug
slapd -d 1

# Vérifier config
slaptest -u

# Export
slapcat -n 1 > backup.ldif
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
