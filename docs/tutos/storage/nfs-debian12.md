---
tags:
  - tutos
  - nfs
  - storage
  - debian
---

# Serveur NFS sur Debian 12

Configuration d'un serveur **NFS** (Network File System) v4.

| Composant | Version |
|-----------|---------|
| Debian | 12 Bookworm |
| NFS | v4.2 |

**Durée estimée :** 20 minutes

---

## 1. Installation

```bash
apt update
apt install -y nfs-kernel-server nfs-common
```

---

## 2. Configuration du Firewall

```bash
# Avec UFW
ufw allow from 192.168.1.0/24 to any port nfs
ufw allow from 192.168.1.0/24 to any port 111

# Vérifier
ufw status
```

---

## 3. Créer les répertoires

```bash
mkdir -p /srv/nfs/share
mkdir -p /srv/nfs/homes

chown -R nobody:nogroup /srv/nfs/share
chmod 755 /srv/nfs/share
```

---

## 4. Configuration des exports

```bash
cat > /etc/exports << 'EOF'
/srv/nfs/share    192.168.1.0/24(rw,sync,no_subtree_check,no_root_squash)
/srv/nfs/homes    192.168.1.50(rw,sync,no_subtree_check)
EOF
```

---

## 5. Démarrer le service

```bash
# Appliquer les exports
exportfs -arv

# Redémarrer
systemctl restart nfs-kernel-server
systemctl enable nfs-kernel-server

# Vérifier
systemctl status nfs-kernel-server
exportfs -s
```

---

## 6. Client Debian

```bash
# Installation
apt install -y nfs-common

# Montage
mkdir -p /mnt/nfs/share
mount -t nfs4 192.168.1.10:/srv/nfs/share /mnt/nfs/share

# Permanent (fstab)
echo "192.168.1.10:/srv/nfs/share /mnt/nfs/share nfs4 defaults,_netdev 0 0" >> /etc/fstab
```

---

## Différences Rocky vs Debian

| Aspect | Rocky 9 | Debian 12 |
|--------|---------|-----------|
| Paquet serveur | `nfs-utils` | `nfs-kernel-server` |
| Service | `nfs-server` | `nfs-kernel-server` |
| User nobody | `nobody:nobody` | `nobody:nogroup` |
| SELinux/AppArmor | SELinux | AppArmor |

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
