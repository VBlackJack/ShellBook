---
tags:
  - tutos
  - storage
  - iscsi
  - san
  - debian
---

# iSCSI Target sur Debian 12

Configuration d'un serveur **iSCSI Target** sur Debian 12.

| Composant | Version |
|-----------|---------|
| Debian | 12 Bookworm |
| targetcli-fb | 2.1+ |

**Durée estimée :** 25 minutes

---

## 1. Installation (Target/Serveur)

```bash
apt update
apt install -y targetcli-fb

systemctl enable --now rtslib-fb-targetctl
```

---

## 2. Préparer le stockage

```bash
# Fichier image
mkdir -p /var/iscsi
dd if=/dev/zero of=/var/iscsi/disk1.img bs=1M count=10240

# Ou LVM
lvcreate -L 50G -n lv_disk1 vg_data
```

---

## 3. Configuration avec targetcli

```bash
targetcli

# Backstore
/> backstores/fileio create disk1 /var/iscsi/disk1.img
# ou
/> backstores/block create disk1 /dev/vg_data/lv_disk1

# Target
/> iscsi/ create iqn.2024-01.com.example:storage.target1

# LUN
/> iscsi/iqn.2024-01.com.example:storage.target1/tpg1/luns create /backstores/fileio/disk1

# ACL
/> iscsi/iqn.2024-01.com.example:storage.target1/tpg1/acls create iqn.2024-01.com.example:client1

# Portail
/> iscsi/iqn.2024-01.com.example:storage.target1/tpg1/portals create 0.0.0.0 3260

# Sauvegarder
/> saveconfig
/> exit
```

---

## 4. Authentification CHAP

```bash
targetcli

/> iscsi/iqn.2024-01.com.example:storage.target1/tpg1/acls/iqn.2024-01.com.example:client1 set auth userid=user1
/> iscsi/iqn.2024-01.com.example:storage.target1/tpg1/acls/iqn.2024-01.com.example:client1 set auth password=secretpassword

/> saveconfig
/> exit
```

---

## 5. Firewall

```bash
ufw allow 3260/tcp
ufw reload
```

---

## 6. Client iSCSI (Initiator)

```bash
apt install -y open-iscsi

# IQN
vim /etc/iscsi/initiatorname.iscsi
```

```
InitiatorName=iqn.2024-01.com.example:client1
```

```bash
# CHAP (si activé)
vim /etc/iscsi/iscsid.conf
```

```ini
node.session.auth.authmethod = CHAP
node.session.auth.username = user1
node.session.auth.password = secretpassword
```

```bash
systemctl restart iscsid open-iscsi

# Découvrir
iscsiadm -m discovery -t sendtargets -p 192.168.1.10

# Connecter
iscsiadm -m node -T iqn.2024-01.com.example:storage.target1 -p 192.168.1.10 --login

# Vérifier
lsblk
```

---

## 7. Monter

```bash
mkfs.ext4 /dev/sdb
mkdir /mnt/iscsi
mount /dev/sdb /mnt/iscsi

echo "/dev/sdb /mnt/iscsi ext4 _netdev 0 0" >> /etc/fstab
```

---

## Comparatif Rocky vs Debian

| Aspect | Rocky 9 | Debian 12 |
|--------|---------|-----------|
| Package | targetcli | targetcli-fb |
| Service | target | rtslib-fb-targetctl |
| Client | iscsi-initiator-utils | open-iscsi |

---

## Vérification

```bash
targetcli ls
iscsiadm -m session
lsblk
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
