---
tags:
  - tutos
  - ldap
  - openldap
  - directory
  - rocky
---

# OpenLDAP sur Rocky Linux 9

Installation d'un serveur d'annuaire **OpenLDAP** sur Rocky Linux 9.

| Composant | Version |
|-----------|---------|
| Rocky Linux | 9.x |
| OpenLDAP | 2.6+ |

**Durée estimée :** 45 minutes

---

## Concepts LDAP

| Terme | Description |
|-------|-------------|
| **DN** | Distinguished Name (chemin complet) |
| **DC** | Domain Component |
| **OU** | Organizational Unit |
| **CN** | Common Name |
| **objectClass** | Type d'entrée |

### Structure type

```
dc=example,dc=com
├── ou=users
│   ├── cn=user1
│   └── cn=user2
├── ou=groups
│   └── cn=admins
└── ou=services
```

---

## 1. Installation

```bash
dnf install -y openldap-servers openldap-clients

# Démarrer le service
systemctl enable --now slapd
systemctl status slapd
```

---

## 2. Configuration initiale

### Mot de passe admin

```bash
# Générer le hash du mot de passe
slappasswd
# Copier le hash généré : {SSHA}xxxxx
```

### Configurer le suffix et admin

```bash
cat > /tmp/db.ldif << 'EOF'
dn: olcDatabase={2}mdb,cn=config
changetype: modify
replace: olcSuffix
olcSuffix: dc=example,dc=com
-
replace: olcRootDN
olcRootDN: cn=admin,dc=example,dc=com
-
replace: olcRootPW
olcRootPW: {SSHA}VOTRE_HASH_ICI
EOF

ldapmodify -Y EXTERNAL -H ldapi:/// -f /tmp/db.ldif
```

### Importer les schémas

```bash
ldapadd -Y EXTERNAL -H ldapi:/// -f /etc/openldap/schema/cosine.ldif
ldapadd -Y EXTERNAL -H ldapi:/// -f /etc/openldap/schema/nis.ldif
ldapadd -Y EXTERNAL -H ldapi:/// -f /etc/openldap/schema/inetorgperson.ldif
```

---

## 3. Créer la structure de base

```bash
cat > /tmp/base.ldif << 'EOF'
# Organisation
dn: dc=example,dc=com
objectClass: top
objectClass: dcObject
objectClass: organization
o: Example Company
dc: example

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

```bash
cat > /tmp/users.ldif << 'EOF'
# User 1
dn: cn=user1,ou=users,dc=example,dc=com
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
cn: user1
sn: User
givenName: Premier
uid: user1
uidNumber: 10001
gidNumber: 10001
homeDirectory: /home/user1
loginShell: /bin/bash
mail: user1@example.com
userPassword: {SSHA}HASH_MOT_DE_PASSE

# User 2
dn: cn=user2,ou=users,dc=example,dc=com
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
cn: user2
sn: User
givenName: Deuxieme
uid: user2
uidNumber: 10002
gidNumber: 10001
homeDirectory: /home/user2
loginShell: /bin/bash
mail: user2@example.com
userPassword: {SSHA}HASH_MOT_DE_PASSE
EOF

ldapadd -x -D "cn=admin,dc=example,dc=com" -W -f /tmp/users.ldif
```

### Générer un mot de passe utilisateur

```bash
slappasswd -s "motdepasse"
```

---

## 5. Ajouter des groupes

```bash
cat > /tmp/groups.ldif << 'EOF'
# Groupe admins
dn: cn=admins,ou=groups,dc=example,dc=com
objectClass: posixGroup
cn: admins
gidNumber: 10001
memberUid: user1

# Groupe users
dn: cn=users,ou=groups,dc=example,dc=com
objectClass: posixGroup
cn: users
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
ldapsearch -x -b "dc=example,dc=com" -D "cn=admin,dc=example,dc=com" -W

# Chercher un utilisateur
ldapsearch -x -b "dc=example,dc=com" "(uid=user1)"

# Chercher dans une OU
ldapsearch -x -b "ou=users,dc=example,dc=com" "(objectClass=inetOrgPerson)"

# Chercher par email
ldapsearch -x -b "dc=example,dc=com" "(mail=user1@example.com)"

# Attributs spécifiques
ldapsearch -x -b "dc=example,dc=com" "(uid=user1)" cn mail uidNumber
```

---

## 7. Modifier des entrées

### Modifier un attribut

```bash
cat > /tmp/modify.ldif << 'EOF'
dn: cn=user1,ou=users,dc=example,dc=com
changetype: modify
replace: mail
mail: newmail@example.com
EOF

ldapmodify -x -D "cn=admin,dc=example,dc=com" -W -f /tmp/modify.ldif
```

### Ajouter un attribut

```bash
cat > /tmp/add-attr.ldif << 'EOF'
dn: cn=user1,ou=users,dc=example,dc=com
changetype: modify
add: telephoneNumber
telephoneNumber: +33123456789
EOF

ldapmodify -x -D "cn=admin,dc=example,dc=com" -W -f /tmp/add-attr.ldif
```

### Supprimer un attribut

```bash
cat > /tmp/del-attr.ldif << 'EOF'
dn: cn=user1,ou=users,dc=example,dc=com
changetype: modify
delete: telephoneNumber
EOF

ldapmodify -x -D "cn=admin,dc=example,dc=com" -W -f /tmp/del-attr.ldif
```

---

## 8. Supprimer des entrées

```bash
ldapdelete -x -D "cn=admin,dc=example,dc=com" -W "cn=user2,ou=users,dc=example,dc=com"
```

---

## 9. TLS/SSL

### Générer les certificats

```bash
mkdir -p /etc/openldap/certs

openssl req -new -x509 -days 365 -nodes \
    -out /etc/openldap/certs/ldap.crt \
    -keyout /etc/openldap/certs/ldap.key \
    -subj "/CN=ldap.example.com"

chown ldap:ldap /etc/openldap/certs/*
chmod 600 /etc/openldap/certs/ldap.key
```

### Configurer TLS

```bash
cat > /tmp/tls.ldif << 'EOF'
dn: cn=config
changetype: modify
add: olcTLSCACertificateFile
olcTLSCACertificateFile: /etc/openldap/certs/ldap.crt
-
add: olcTLSCertificateFile
olcTLSCertificateFile: /etc/openldap/certs/ldap.crt
-
add: olcTLSCertificateKeyFile
olcTLSCertificateKeyFile: /etc/openldap/certs/ldap.key
EOF

ldapmodify -Y EXTERNAL -H ldapi:/// -f /tmp/tls.ldif
```

### Activer LDAPS

```bash
vim /etc/sysconfig/slapd
```

```ini
SLAPD_URLS="ldapi:/// ldap:/// ldaps:///"
```

```bash
systemctl restart slapd
```

---

## 10. Firewall

```bash
firewall-cmd --permanent --add-service=ldap
firewall-cmd --permanent --add-service=ldaps
firewall-cmd --reload
```

---

## 11. SELinux

```bash
# Contexte pour les certificats
restorecon -Rv /etc/openldap/certs/

# Boolean si nécessaire
setsebool -P allow_ypbind 1
```

---

## 12. Client LDAP (autre serveur)

### Installation client

```bash
dnf install -y openldap-clients nss-pam-ldapd

authselect select sssd with-mkhomedir --force
```

### Configuration sssd

```bash
vim /etc/sssd/sssd.conf
```

```ini
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
ldap_tls_reqcert = allow
cache_credentials = true
```

```bash
chmod 600 /etc/sssd/sssd.conf
systemctl enable --now sssd
```

---

## Vérification

```bash
# Status
systemctl status slapd

# Tester
ldapsearch -x -b "dc=example,dc=com" "(objectClass=*)" dn

# Vérifier config
slaptest -u

# Logs
journalctl -u slapd -f
```

---

## Dépannage

| Problème | Solution |
|----------|----------|
| Invalid credentials | Vérifier mot de passe admin |
| No such object | Vérifier DN, créer la base |
| TLS error | Vérifier certificats, permissions |

```bash
# Debug
slapd -d 1

# Vérifier config
slapcat -n 0
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
