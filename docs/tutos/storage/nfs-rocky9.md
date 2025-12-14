---
tags:
  - tutos
  - nfs
  - storage
  - rocky-linux
---

# Serveur NFS sur Rocky Linux 9

Configuration d'un serveur **NFS** (Network File System) v4.

| Composant | Version |
|-----------|---------|
| Rocky Linux | 9.x |
| NFS | v4.2 |

**Durée estimée :** 20 minutes

---

## 1. Installation

```bash
# Installer les paquets NFS
dnf install -y nfs-utils

# Vérifier
rpm -q nfs-utils
```

---

## 2. Configuration du Firewall

```bash
# Autoriser NFS
firewall-cmd --permanent --add-service=nfs
firewall-cmd --permanent --add-service=mountd
firewall-cmd --permanent --add-service=rpc-bind

# Recharger
firewall-cmd --reload
```

---

## 3. Créer les répertoires à partager

```bash
# Répertoire de partage
mkdir -p /srv/nfs/share
mkdir -p /srv/nfs/homes

# Permissions
chown -R nobody:nobody /srv/nfs/share
chmod 755 /srv/nfs/share

# Pour les homes (permissions différentes)
chmod 755 /srv/nfs/homes
```

---

## 4. Configuration des exports

### Fichier /etc/exports

```bash
cat > /etc/exports << 'EOF'
# Partage accessible à tout le réseau 192.168.1.0/24
/srv/nfs/share    192.168.1.0/24(rw,sync,no_subtree_check,no_root_squash)

# Partage lecture seule
/srv/nfs/readonly 192.168.1.0/24(ro,sync,no_subtree_check)

# Partage pour un hôte spécifique
/srv/nfs/homes    192.168.1.50(rw,sync,no_subtree_check,no_root_squash)
EOF
```

### Options principales

| Option | Description |
|--------|-------------|
| `rw` | Lecture/écriture |
| `ro` | Lecture seule |
| `sync` | Écriture synchrone (sécurisé) |
| `no_subtree_check` | Désactive la vérification de sous-arbre |
| `no_root_squash` | Root client = root serveur |
| `root_squash` | Root client = nobody (défaut) |
| `all_squash` | Tous les users = nobody |

---

## 5. Démarrer les services

```bash
# Activer et démarrer
systemctl enable --now nfs-server rpcbind

# Vérifier
systemctl status nfs-server

# Exporter les partages
exportfs -arv

# Lister les exports
exportfs -s
```

---

## 6. Configuration client

### Installation client

```bash
# Sur le client Rocky/RHEL
dnf install -y nfs-utils
```

### Montage manuel

```bash
# Créer le point de montage
mkdir -p /mnt/nfs/share

# Monter le partage
mount -t nfs4 192.168.1.10:/srv/nfs/share /mnt/nfs/share

# Vérifier
df -h /mnt/nfs/share
```

### Montage permanent (fstab)

```bash
# Ajouter dans /etc/fstab
echo "192.168.1.10:/srv/nfs/share /mnt/nfs/share nfs4 defaults,_netdev 0 0" >> /etc/fstab

# Tester
mount -a
```

### Montage avec autofs

```bash
# Installer autofs
dnf install -y autofs

# Configurer /etc/auto.master
echo "/mnt/nfs /etc/auto.nfs --timeout=300" >> /etc/auto.master

# Créer /etc/auto.nfs
echo "share -fstype=nfs4,rw 192.168.1.10:/srv/nfs/share" > /etc/auto.nfs

# Démarrer autofs
systemctl enable --now autofs
```

---

## 7. Commandes utiles

```bash
# Voir les exports actifs
showmount -e localhost

# Voir les clients connectés
showmount -a

# Recharger les exports
exportfs -r

# Statistiques NFS
nfsstat -s  # Serveur
nfsstat -c  # Client

# Debug montage
mount -v -t nfs4 192.168.1.10:/srv/nfs/share /mnt/test
```

---

## 8. SELinux

```bash
# Autoriser NFS à exporter des répertoires home
setsebool -P nfs_export_all_rw 1
setsebool -P nfs_export_all_ro 1

# Contexte pour les répertoires partagés
semanage fcontext -a -t nfs_t "/srv/nfs(/.*)?"
restorecon -Rv /srv/nfs
```

---

## Dépannage

### Client ne peut pas monter

```bash
# Vérifier que le serveur exporte
showmount -e 192.168.1.10

# Vérifier le firewall serveur
firewall-cmd --list-services

# Test de connectivité
rpcinfo -p 192.168.1.10
```

### Permission denied

```bash
# Vérifier les permissions du répertoire
ls -la /srv/nfs/

# Vérifier les options d'export
cat /etc/exports

# Vérifier SELinux
ausearch -m avc -ts recent
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
