---
tags:
  - tutos
  - samba
  - smb
  - storage
  - rocky-linux
---

# Serveur Samba sur Rocky Linux 9

Configuration d'un serveur de fichiers **Samba** (SMB/CIFS).

| Composant | Version |
|-----------|---------|
| Rocky Linux | 9.x |
| Samba | 4.x |

**Durée estimée :** 30 minutes

---

## 1. Installation

```bash
dnf install -y samba samba-client samba-common

# Vérifier
smbd --version
```

---

## 2. Configuration du Firewall

```bash
firewall-cmd --permanent --add-service=samba
firewall-cmd --reload
```

---

## 3. Configuration de base

### Sauvegarder et créer smb.conf

```bash
cp /etc/samba/smb.conf /etc/samba/smb.conf.bak

cat > /etc/samba/smb.conf << 'EOF'
[global]
    workgroup = WORKGROUP
    server string = Samba Server %v
    netbios name = srv-files
    security = user
    map to guest = Bad User
    dns proxy = no

    # Logging
    log file = /var/log/samba/log.%m
    max log size = 50

    # Performance
    socket options = TCP_NODELAY IPTOS_LOWDELAY SO_RCVBUF=131072 SO_SNDBUF=131072

    # Sécurité minimum SMB2
    server min protocol = SMB2
    client min protocol = SMB2

[share]
    comment = Partage commun
    path = /srv/samba/share
    browsable = yes
    writable = yes
    guest ok = no
    valid users = @smbgroup
    create mask = 0664
    directory mask = 0775

[public]
    comment = Partage public
    path = /srv/samba/public
    browsable = yes
    writable = yes
    guest ok = yes
    create mask = 0666
    directory mask = 0777
EOF
```

---

## 4. Créer les répertoires

```bash
mkdir -p /srv/samba/{share,public}
chmod 2775 /srv/samba/share
chmod 2777 /srv/samba/public
```

---

## 5. Créer les utilisateurs Samba

```bash
# Créer un groupe
groupadd smbgroup

# Créer un utilisateur système
useradd -M -s /sbin/nologin smbuser
usermod -aG smbgroup smbuser

# Définir le mot de passe Samba
smbpasswd -a smbuser

# Activer l'utilisateur
smbpasswd -e smbuser

# Permissions
chown -R :smbgroup /srv/samba/share
```

---

## 6. SELinux

```bash
# Autoriser Samba
setsebool -P samba_enable_home_dirs on
setsebool -P samba_export_all_rw on

# Contexte des répertoires
semanage fcontext -a -t samba_share_t "/srv/samba(/.*)?"
restorecon -Rv /srv/samba
```

---

## 7. Démarrer les services

```bash
systemctl enable --now smb nmb
systemctl status smb nmb

# Tester la configuration
testparm
```

---

## 8. Accès client

### Linux

```bash
# Lister les partages
smbclient -L //192.168.1.10 -U smbuser

# Monter un partage
mount -t cifs //192.168.1.10/share /mnt/samba -o username=smbuser,password=xxx

# fstab
echo "//192.168.1.10/share /mnt/samba cifs credentials=/root/.smbcreds,_netdev 0 0" >> /etc/fstab

# Fichier credentials
cat > /root/.smbcreds << EOF
username=smbuser
password=xxx
EOF
chmod 600 /root/.smbcreds
```

### Windows

```
\\192.168.1.10\share
```

---

## 9. Intégration Active Directory

```bash
# Installer les paquets
dnf install -y realmd sssd oddjob oddjob-mkhomedir adcli samba-common-tools

# Joindre le domaine
realm join -U Administrator example.lan

# Modifier smb.conf
# security = ads
# realm = EXAMPLE.LAN
# workgroup = EXAMPLE
```

---

## Dépannage

```bash
# Logs
tail -f /var/log/samba/log.smbd

# Tester connexion
smbclient //localhost/share -U smbuser

# Lister les utilisateurs Samba
pdbedit -L

# Vérifier SELinux
ausearch -m avc -ts recent | grep smb
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
