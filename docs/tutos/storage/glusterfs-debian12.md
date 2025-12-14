---
tags:
  - tutos
  - storage
  - glusterfs
  - distributed
  - debian
---

# GlusterFS sur Debian 12

Configuration de **GlusterFS** sur Debian 12 Bookworm.

| Composant | Version |
|-----------|---------|
| Debian | 12 Bookworm |
| GlusterFS | 10+ |

**Durée estimée :** 35 minutes

---

## 1. Prérequis

```bash
# Sur tous les nœuds
cat >> /etc/hosts << 'EOF'
192.168.1.11 gluster01
192.168.1.12 gluster02
192.168.1.13 gluster03
EOF
```

---

## 2. Installation

```bash
apt update
apt install -y glusterfs-server

glusterfs --version
```

---

## 3. Préparer le stockage

```bash
mkfs.xfs -i size=512 /dev/sdb1
mkdir -p /data/brick1
echo '/dev/sdb1 /data/brick1 xfs defaults 0 0' >> /etc/fstab
mount -a

mkdir -p /data/brick1/gv0
```

---

## 4. Démarrer

```bash
systemctl enable --now glusterd
systemctl status glusterd
```

---

## 5. Firewall

```bash
ufw allow 24007/tcp
ufw allow 24008/tcp
ufw allow 49152:49251/tcp
ufw reload
```

---

## 6. Créer le cluster

```bash
# Depuis gluster01
gluster peer probe gluster02
gluster peer probe gluster03

gluster peer status
```

---

## 7. Créer un volume répliqué

```bash
gluster volume create gv0 replica 3 \
    gluster01:/data/brick1/gv0 \
    gluster02:/data/brick1/gv0 \
    gluster03:/data/brick1/gv0

gluster volume start gv0
gluster volume info gv0
```

---

## 8. Client

```bash
apt install -y glusterfs-client

mkdir -p /mnt/gluster
mount -t glusterfs gluster01:/gv0 /mnt/gluster

# fstab
echo 'gluster01:/gv0 /mnt/gluster glusterfs defaults,_netdev,backup-volfile-servers=gluster02:gluster03 0 0' >> /etc/fstab
```

---

## 9. Options

```bash
# Performance
gluster volume set gv0 performance.cache-size 256MB

# Accès
gluster volume set gv0 auth.allow 192.168.1.*

# Quotas
gluster volume quota gv0 enable
gluster volume quota gv0 limit-usage / 100GB
```

---

## 10. Maintenance

```bash
# Heal
gluster volume heal gv0
gluster volume heal gv0 info

# Snapshots
gluster snapshot create snap1 gv0
gluster snapshot list gv0
```

---

## Comparatif Rocky vs Debian

| Aspect | Rocky 9 | Debian 12 |
|--------|---------|-----------|
| Package | centos-release-gluster10 | glusterfs-server |
| Client | glusterfs-fuse | glusterfs-client |
| Firewall | firewalld | ufw |

---

## Commandes

```bash
gluster peer status              # Status cluster
gluster volume list              # Lister volumes
gluster volume info gv0          # Info volume
gluster volume status gv0        # Status volume
gluster volume heal gv0 info     # Status heal
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
