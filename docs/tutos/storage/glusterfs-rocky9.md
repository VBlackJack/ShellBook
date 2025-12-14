---
tags:
  - tutos
  - storage
  - glusterfs
  - distributed
  - rocky
---

# GlusterFS sur Rocky Linux 9

Configuration de **GlusterFS** pour le stockage distribué.

| Composant | Version |
|-----------|---------|
| Rocky Linux | 9.x |
| GlusterFS | 10+ |

**Durée estimée :** 40 minutes

---

## Types de volumes

| Type | Description | Min. serveurs |
|------|-------------|---------------|
| **Distributed** | Données réparties | 2+ |
| **Replicated** | Données dupliquées | 2+ |
| **Dispersed** | Erasure coding | 3+ |
| **Distributed-Replicated** | Combo | 4+ |

---

## Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  Node 1     │     │  Node 2     │     │  Node 3     │
│  gluster01  │◄───►│  gluster02  │◄───►│  gluster03  │
│             │     │             │     │             │
│  /data/brick│     │  /data/brick│     │  /data/brick│
└─────────────┘     └─────────────┘     └─────────────┘
       │                   │                   │
       └───────────────────┼───────────────────┘
                          │
                   ┌──────▼──────┐
                   │   Client    │
                   │ /mnt/gluster│
                   └─────────────┘
```

---

## 1. Prérequis

### Sur tous les nœuds

```bash
# Hostname
hostnamectl set-hostname gluster01  # 02, 03 sur les autres

# /etc/hosts
cat >> /etc/hosts << 'EOF'
192.168.1.11 gluster01
192.168.1.12 gluster02
192.168.1.13 gluster03
EOF

# Désactiver SELinux temporairement (ou configurer)
setenforce 0
sed -i 's/SELINUX=enforcing/SELINUX=permissive/' /etc/selinux/config
```

---

## 2. Installation

```bash
# Activer le repo CentOS Stream pour GlusterFS
dnf install -y centos-release-gluster10

# Installer
dnf install -y glusterfs-server

# Version
glusterfs --version
```

---

## 3. Préparer le stockage

```bash
# Partitionner le disque dédié
fdisk /dev/sdb
# Créer partition Linux (type 83)

# Formater en XFS
mkfs.xfs -i size=512 /dev/sdb1

# Monter
mkdir -p /data/brick1
echo '/dev/sdb1 /data/brick1 xfs defaults 0 0' >> /etc/fstab
mount -a

# Créer le répertoire brick
mkdir -p /data/brick1/gv0
```

---

## 4. Démarrer GlusterFS

```bash
systemctl enable --now glusterd
systemctl status glusterd
```

---

## 5. Firewall

```bash
firewall-cmd --permanent --add-service=glusterfs
firewall-cmd --reload

# Ou ports spécifiques
firewall-cmd --permanent --add-port=24007-24008/tcp
firewall-cmd --permanent --add-port=49152-49251/tcp
firewall-cmd --reload
```

---

## 6. Créer le cluster (Trusted Pool)

### Depuis gluster01

```bash
# Ajouter les peers
gluster peer probe gluster02
gluster peer probe gluster03

# Vérifier
gluster peer status
```

---

## 7. Créer les volumes

### Volume répliqué (mirror)

```bash
gluster volume create gv0 replica 3 \
    gluster01:/data/brick1/gv0 \
    gluster02:/data/brick1/gv0 \
    gluster03:/data/brick1/gv0

# Démarrer
gluster volume start gv0

# Info
gluster volume info gv0
```

### Volume distribué

```bash
gluster volume create gv-dist \
    gluster01:/data/brick1/gv-dist \
    gluster02:/data/brick1/gv-dist \
    gluster03:/data/brick1/gv-dist

gluster volume start gv-dist
```

### Volume distribué-répliqué (4 nœuds)

```bash
gluster volume create gv-distrep replica 2 \
    gluster01:/data/brick1/gv-distrep \
    gluster02:/data/brick1/gv-distrep \
    gluster03:/data/brick1/gv-distrep \
    gluster04:/data/brick1/gv-distrep
```

---

## 8. Monter côté client

### Installation client

```bash
dnf install -y glusterfs-fuse
```

### Montage

```bash
mkdir -p /mnt/gluster

# Montage direct
mount -t glusterfs gluster01:/gv0 /mnt/gluster

# Ou avec backup
mount -t glusterfs gluster01,gluster02:/gv0 /mnt/gluster
```

### fstab

```bash
echo 'gluster01:/gv0 /mnt/gluster glusterfs defaults,_netdev,backup-volfile-servers=gluster02:gluster03 0 0' >> /etc/fstab
```

### NFS (alternative)

```bash
# Activer NFS sur le volume
gluster volume set gv0 nfs.disable off

# Monter via NFS
mount -t nfs gluster01:/gv0 /mnt/gluster
```

---

## 9. Options de volume

### Performance

```bash
# Cache
gluster volume set gv0 performance.cache-size 256MB
gluster volume set gv0 performance.io-thread-count 32

# Readdir-ahead
gluster volume set gv0 performance.readdir-ahead on
```

### Sécurité

```bash
# Restreindre l'accès
gluster volume set gv0 auth.allow 192.168.1.*

# Refuser
gluster volume set gv0 auth.reject 192.168.1.100
```

### Quotas

```bash
gluster volume quota gv0 enable
gluster volume quota gv0 limit-usage / 100GB
gluster volume quota gv0 list
```

---

## 10. Gestion

### Status

```bash
gluster peer status
gluster volume status gv0
gluster volume info gv0
```

### Ajouter un brick

```bash
# Préparation sur le nouveau nœud
gluster peer probe gluster04

# Ajouter (pour replica, multiple de replica count)
gluster volume add-brick gv0 replica 4 gluster04:/data/brick1/gv0
```

### Supprimer un brick

```bash
gluster volume remove-brick gv0 replica 2 gluster03:/data/brick1/gv0 start
gluster volume remove-brick gv0 replica 2 gluster03:/data/brick1/gv0 status
gluster volume remove-brick gv0 replica 2 gluster03:/data/brick1/gv0 commit
```

### Heal (réparation)

```bash
# Lancer le heal
gluster volume heal gv0

# Status
gluster volume heal gv0 info
gluster volume heal gv0 info healed
gluster volume heal gv0 info heal-failed
```

---

## 11. Snapshots

```bash
# Créer
gluster snapshot create snap1 gv0

# Lister
gluster snapshot list gv0

# Restaurer
gluster snapshot restore snap1

# Supprimer
gluster snapshot delete snap1
```

---

## 12. Monitoring

```bash
# Status détaillé
gluster volume status gv0 detail

# Profiling
gluster volume profile gv0 start
gluster volume profile gv0 info
gluster volume profile gv0 stop

# Top operations
gluster volume top gv0 read-perf
gluster volume top gv0 write-perf
```

---

## Commandes utiles

```bash
# Cluster
gluster peer status
gluster peer probe <node>
gluster peer detach <node>

# Volumes
gluster volume list
gluster volume info [vol]
gluster volume status [vol]
gluster volume start/stop <vol>

# Maintenance
gluster volume heal <vol>
gluster volume rebalance <vol> start
```

---

## Dépannage

```bash
# Logs
tail -f /var/log/glusterfs/glusterd.log
tail -f /var/log/glusterfs/bricks/*

# Connectivité
gluster peer status

# Heal status
gluster volume heal gv0 info

# Split-brain
gluster volume heal gv0 info split-brain
```

| Problème | Solution |
|----------|----------|
| Peer rejected | Vérifier /etc/hosts, firewall |
| Split-brain | `gluster volume heal gv0 split-brain` |
| Volume offline | `gluster volume start gv0 force` |

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
