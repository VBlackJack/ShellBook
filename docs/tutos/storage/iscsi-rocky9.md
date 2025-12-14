---
tags:
  - tutos
  - storage
  - iscsi
  - san
  - rocky
---

# iSCSI Target sur Rocky Linux 9

Configuration d'un serveur **iSCSI Target** pour le stockage bloc.

| Composant | Version |
|-----------|---------|
| Rocky Linux | 9.x |
| targetcli | 2.1+ |

**Durée estimée :** 30 minutes

---

## Concepts iSCSI

| Terme | Description |
|-------|-------------|
| **Target** | Serveur de stockage |
| **Initiator** | Client qui se connecte |
| **LUN** | Logical Unit Number (disque virtuel) |
| **IQN** | iSCSI Qualified Name (identifiant unique) |
| **Portal** | Point d'accès réseau (IP:port) |

```
┌─────────────┐     iSCSI (TCP 3260)    ┌─────────────┐
│  Initiator  │◄───────────────────────►│   Target    │
│   Client    │                         │   Serveur   │
│             │                         │             │
│  /dev/sdb   │                         │  LUN (LVM)  │
└─────────────┘                         └─────────────┘
```

---

## 1. Installation (Target/Serveur)

```bash
dnf install -y targetcli

systemctl enable --now target
```

---

## 2. Préparer le stockage

### Option A : Fichier image

```bash
mkdir -p /var/iscsi
dd if=/dev/zero of=/var/iscsi/disk1.img bs=1M count=10240  # 10GB
```

### Option B : Volume LVM (recommandé)

```bash
# Créer un VG dédié
pvcreate /dev/sdb
vgcreate vg_iscsi /dev/sdb

# Créer un LV
lvcreate -L 50G -n lv_disk1 vg_iscsi
```

### Option C : Partition

```bash
# Utiliser une partition dédiée
# /dev/sdb1
```

---

## 3. Configuration avec targetcli

```bash
targetcli
```

### Créer le backstore

```bash
# Pour un fichier
/> backstores/fileio create disk1 /var/iscsi/disk1.img

# Pour un LVM
/> backstores/block create disk1 /dev/vg_iscsi/lv_disk1

# Pour une partition
/> backstores/block create disk1 /dev/sdb1
```

### Créer le target iSCSI

```bash
/> iscsi/ create iqn.2024-01.com.example:storage.target1
```

### Créer le LUN

```bash
/> iscsi/iqn.2024-01.com.example:storage.target1/tpg1/luns create /backstores/block/disk1
```

### Configurer l'ACL (autorisation)

```bash
# Autoriser un initiator spécifique
/> iscsi/iqn.2024-01.com.example:storage.target1/tpg1/acls create iqn.2024-01.com.example:client1

# Ou désactiver l'authentification (non recommandé)
/> iscsi/iqn.2024-01.com.example:storage.target1/tpg1 set attribute authentication=0
/> iscsi/iqn.2024-01.com.example:storage.target1/tpg1 set attribute generate_node_acls=1
```

### Configurer le portail

```bash
# Par défaut, écoute sur toutes les interfaces
/> iscsi/iqn.2024-01.com.example:storage.target1/tpg1/portals create 0.0.0.0 3260

# Ou IP spécifique
/> iscsi/iqn.2024-01.com.example:storage.target1/tpg1/portals create 192.168.1.10 3260
```

### Sauvegarder et quitter

```bash
/> saveconfig
/> exit
```

---

## 4. Authentification CHAP

```bash
targetcli

# Définir les credentials
/> iscsi/iqn.2024-01.com.example:storage.target1/tpg1/acls/iqn.2024-01.com.example:client1 set auth userid=user1
/> iscsi/iqn.2024-01.com.example:storage.target1/tpg1/acls/iqn.2024-01.com.example:client1 set auth password=secretpassword

# Authentification mutuelle (optionnel)
/> iscsi/iqn.2024-01.com.example:storage.target1/tpg1/acls/iqn.2024-01.com.example:client1 set auth mutual_userid=target1
/> iscsi/iqn.2024-01.com.example:storage.target1/tpg1/acls/iqn.2024-01.com.example:client1 set auth mutual_password=targetsecret

/> saveconfig
/> exit
```

---

## 5. Firewall

```bash
firewall-cmd --permanent --add-port=3260/tcp
firewall-cmd --reload
```

---

## 6. SELinux

```bash
# Si utilisation de fichiers hors /var/target
semanage fcontext -a -t iscsi_var_lib_t "/var/iscsi(/.*)?"
restorecon -Rv /var/iscsi
```

---

## 7. Vérifier la configuration

```bash
targetcli ls

# Exemple de sortie
o- / ......................................... [...]
  o- backstores ............................. [...]
  | o- block ................. [Storage Objects: 1]
  | | o- disk1 .... [/dev/vg_iscsi/lv_disk1 (50.0GiB)]
  o- iscsi ................................... [...]
  | o- iqn.2024-01.com.example:storage.target1 [...]
  |   o- tpg1 ......................... [enabled]
  |     o- acls ................................ [...]
  |     | o- iqn.2024-01.com.example:client1 [...]
  |     o- luns ................................ [...]
  |     | o- lun0 ............... [block/disk1]
  |     o- portals ............................. [...]
  |       o- 0.0.0.0:3260 .............. [OK]
```

---

## 8. Client iSCSI (Initiator)

### Installation

```bash
dnf install -y iscsi-initiator-utils
```

### Configurer l'IQN du client

```bash
vim /etc/iscsi/initiatorname.iscsi
```

```
InitiatorName=iqn.2024-01.com.example:client1
```

### Authentification CHAP (si configuré)

```bash
vim /etc/iscsi/iscsid.conf
```

```ini
node.session.auth.authmethod = CHAP
node.session.auth.username = user1
node.session.auth.password = secretpassword

# Mutual CHAP
node.session.auth.username_in = target1
node.session.auth.password_in = targetsecret
```

### Découvrir les targets

```bash
systemctl enable --now iscsid

iscsiadm -m discovery -t sendtargets -p 192.168.1.10
```

### Se connecter

```bash
iscsiadm -m node -T iqn.2024-01.com.example:storage.target1 -p 192.168.1.10 --login
```

### Vérifier

```bash
iscsiadm -m session

# Nouveau disque
lsblk
fdisk -l /dev/sdb
```

### Formater et monter

```bash
mkfs.xfs /dev/sdb
mkdir /mnt/iscsi
mount /dev/sdb /mnt/iscsi

# fstab
echo "/dev/sdb /mnt/iscsi xfs _netdev 0 0" >> /etc/fstab
```

### Déconnexion

```bash
umount /mnt/iscsi
iscsiadm -m node -T iqn.2024-01.com.example:storage.target1 -p 192.168.1.10 --logout
```

---

## 9. Multipath (haute dispo)

```bash
dnf install -y device-mapper-multipath

mpathconf --enable
systemctl enable --now multipathd

# Vérifier
multipath -ll
```

---

## Dépannage

```bash
# Status
systemctl status target
targetcli ls

# Logs
journalctl -u target -f

# Sessions actives
targetcli /iscsi/iqn.2024-01.com.example:storage.target1/tpg1 sessions detail

# Client
iscsiadm -m session -P 3
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
