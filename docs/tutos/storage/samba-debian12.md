---
tags:
  - tutos
  - samba
  - smb
  - storage
  - debian
---

# Serveur Samba sur Debian 12

Configuration d'un serveur de fichiers **Samba** (SMB/CIFS).

| Composant | Version |
|-----------|---------|
| Debian | 12 Bookworm |
| Samba | 4.x |

**Durée estimée :** 25 minutes

---

## 1. Installation

```bash
apt update
apt install -y samba samba-common-bin
```

---

## 2. Configuration du Firewall

```bash
ufw allow samba
ufw status
```

---

## 3. Configuration

```bash
cp /etc/samba/smb.conf /etc/samba/smb.conf.bak

cat > /etc/samba/smb.conf << 'EOF'
[global]
    workgroup = WORKGROUP
    server string = Samba Server %v
    security = user
    map to guest = Bad User
    log file = /var/log/samba/log.%m
    max log size = 50
    server min protocol = SMB2

[share]
    comment = Partage commun
    path = /srv/samba/share
    browsable = yes
    writable = yes
    guest ok = no
    valid users = @sambashare
    create mask = 0664
    directory mask = 0775

[public]
    comment = Partage public
    path = /srv/samba/public
    browsable = yes
    writable = yes
    guest ok = yes
EOF
```

---

## 4. Créer les répertoires et utilisateurs

```bash
# Répertoires
mkdir -p /srv/samba/{share,public}
chmod 2775 /srv/samba/share
chmod 2777 /srv/samba/public

# Groupe et utilisateur
groupadd sambashare
useradd -M -s /usr/sbin/nologin -G sambashare smbuser

# Mot de passe Samba
smbpasswd -a smbuser
smbpasswd -e smbuser

# Permissions
chown -R :sambashare /srv/samba/share
```

---

## 5. Démarrer le service

```bash
systemctl restart smbd nmbd
systemctl enable smbd nmbd
systemctl status smbd

# Tester
testparm
```

---

## 6. Client

```bash
# Lister les partages
smbclient -L //192.168.1.10 -U smbuser

# Monter
apt install -y cifs-utils
mount -t cifs //192.168.1.10/share /mnt/samba -o username=smbuser
```

---

## Différences Rocky vs Debian

| Aspect | Rocky 9 | Debian 12 |
|--------|---------|-----------|
| Service | `smb` | `smbd` |
| SELinux/AppArmor | SELinux | AppArmor |
| Groupe par défaut | `smbgroup` | `sambashare` |

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
