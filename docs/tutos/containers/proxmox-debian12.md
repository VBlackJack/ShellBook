---
tags:
  - tutos
  - containers
  - proxmox
  - virtualization
  - kvm
  - lxc
  - debian
---

# Proxmox VE sur Debian 12

Installation de **Proxmox VE** sur Debian 12 Bookworm - plateforme de virtualisation.

| Composant | Version |
|-----------|---------|
| Debian | 12 Bookworm |
| Proxmox VE | 8.x |

**Durée estimée :** 30 minutes

---

## Fonctionnalités

| Fonction | Description |
|----------|-------------|
| **KVM** | VMs complètes |
| **LXC** | Conteneurs légers |
| **Cluster** | Haute disponibilité |
| **Storage** | ZFS, Ceph, NFS... |
| **Backup** | Intégré avec PBS |
| **Web UI** | Interface complète |

---

## Prérequis

- Debian 12 fraîchement installé
- CPU avec virtualisation (VT-x/AMD-V)
- 4 GB RAM minimum (8+ recommandé)
- 32 GB disque minimum

---

## 1. Configuration hostname

```bash
# Le hostname doit être un FQDN
hostnamectl set-hostname pve.example.com

# Configurer /etc/hosts
cat > /etc/hosts << 'EOF'
127.0.0.1       localhost
192.168.1.100   pve.example.com pve

# IPv6
::1             localhost ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters
EOF
```

Vérifier :
```bash
hostname --ip-address
# Doit retourner l'IP (pas 127.0.0.1)
```

---

## 2. Ajouter le repository Proxmox

```bash
# Clé GPG
wget https://enterprise.proxmox.com/debian/proxmox-release-bookworm.gpg -O /etc/apt/trusted.gpg.d/proxmox-release-bookworm.gpg

# Repository (version gratuite no-subscription)
echo "deb http://download.proxmox.com/debian/pve bookworm pve-no-subscription" > /etc/apt/sources.list.d/pve-install-repo.list

apt update
apt full-upgrade -y
```

---

## 3. Installer Proxmox VE

```bash
apt install -y proxmox-ve postfix open-iscsi chrony
```

Choisir "Local only" pour Postfix si demandé.

---

## 4. Supprimer le kernel Debian (optionnel)

```bash
apt remove linux-image-amd64 'linux-image-6.1*'
update-grub
```

---

## 5. Redémarrer

```bash
reboot
```

---

## 6. Accès Web

- URL: `https://IP:8006`
- User: `root`
- Password: mot de passe root Debian
- Realm: `PAM`

---

## 7. Supprimer le message subscription

```bash
# Optionnel - supprimer le popup
sed -Ezi.bak "s/(Ext.Msg.show\(\{\s+title: gettext\('No valid subscription')/void\(\{ \/\/\1/g" /usr/share/javascript/proxmox-widget-toolkit/proxmoxlib.js

systemctl restart pveproxy.service
```

---

## 8. Configuration réseau

### Bridge pour VMs

```bash
# Vérifier le bridge créé
cat /etc/network/interfaces
```

Configuration typique :
```
auto lo
iface lo inet loopback

auto enp0s3
iface enp0s3 inet manual

auto vmbr0
iface vmbr0 inet static
    address 192.168.1.100/24
    gateway 192.168.1.1
    bridge-ports enp0s3
    bridge-stp off
    bridge-fd 0
```

### Appliquer

```bash
ifreload -a
```

---

## 9. Storage

### Local storage

Déjà configuré :
- `local` : ISO, templates
- `local-lvm` : VM disks

### Ajouter du storage NFS

Datacenter → Storage → Add → NFS

### Ajouter du storage ZFS

```bash
# Si disques disponibles
zpool create tank /dev/sdb /dev/sdc
```

Datacenter → Storage → Add → ZFS

---

## 10. Créer une VM

### Via Web UI

1. Créer VM → Nom, ID
2. OS → ISO image
3. System → SCSI controller: VirtIO SCSI
4. Disks → Size
5. CPU → Cores
6. Memory → RAM
7. Network → Bridge: vmbr0, Model: VirtIO

### Via CLI

```bash
# Créer VM
qm create 100 --name debian-vm --memory 2048 --cores 2 --net0 virtio,bridge=vmbr0

# Ajouter disque
qm set 100 --scsi0 local-lvm:32

# Ajouter ISO
qm set 100 --ide2 local:iso/debian-12.iso,media=cdrom

# Boot order
qm set 100 --boot order=ide2;scsi0

# Démarrer
qm start 100
```

---

## 11. Créer un conteneur LXC

### Télécharger un template

```bash
pveam update
pveam available | grep debian
pveam download local debian-12-standard_12.0-1_amd64.tar.zst
```

### Créer le conteneur

```bash
pct create 200 local:vztmpl/debian-12-standard_12.0-1_amd64.tar.zst \
    --hostname ct-debian \
    --memory 1024 \
    --cores 2 \
    --net0 name=eth0,bridge=vmbr0,ip=dhcp \
    --storage local-lvm \
    --rootfs local-lvm:8 \
    --password

pct start 200
```

---

## 12. Cloud-Init

### Créer un template cloud-init

```bash
# Télécharger image cloud
wget https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-generic-amd64.qcow2

# Créer VM
qm create 9000 --name debian-cloud --memory 2048 --cores 2 --net0 virtio,bridge=vmbr0

# Importer le disque
qm importdisk 9000 debian-12-generic-amd64.qcow2 local-lvm

# Attacher le disque
qm set 9000 --scsihw virtio-scsi-pci --scsi0 local-lvm:vm-9000-disk-0

# Cloud-Init drive
qm set 9000 --ide2 local-lvm:cloudinit

# Boot
qm set 9000 --boot c --bootdisk scsi0

# Serial console
qm set 9000 --serial0 socket --vga serial0

# Convertir en template
qm template 9000
```

### Cloner depuis le template

```bash
qm clone 9000 101 --name vm-from-template --full
qm set 101 --ciuser admin --cipassword password --ipconfig0 ip=dhcp
qm start 101
```

---

## 13. Backup

### Backup manuel

```bash
# VM
vzdump 100 --storage local --mode snapshot

# Conteneur
vzdump 200 --storage local --mode stop
```

### Backup automatique

Datacenter → Backup → Add

---

## 14. Cluster (multi-nœuds)

### Sur le premier nœud

```bash
pvecm create mycluster
```

### Sur les autres nœuds

```bash
pvecm add 192.168.1.100
```

### Vérifier

```bash
pvecm status
pvecm nodes
```

---

## 15. Haute Disponibilité

### Prérequis

- Minimum 3 nœuds
- Storage partagé (Ceph, NFS, iSCSI)
- Quorum device ou 3+ nœuds

### Activer HA sur une VM

Datacenter → HA → Add → VM ID

---

## 16. Firewall

### Activer le firewall

Datacenter → Firewall → Options → Enable

### Règles

```bash
# Via CLI
pve-firewall compile
```

---

## Commandes utiles

```bash
# VMs
qm list
qm start 100
qm stop 100
qm shutdown 100
qm status 100
qm config 100

# Conteneurs
pct list
pct start 200
pct stop 200
pct enter 200

# Cluster
pvecm status
pvecm nodes

# Storage
pvesm status

# Backup
vzdump 100 --mode snapshot
qmrestore /var/lib/vz/dump/vzdump-qemu-100.vma 101

# Logs
journalctl -u pveproxy
journalctl -u pvedaemon
```

---

## Dépannage

```bash
# Réparer subscription warning
rm /etc/apt/sources.list.d/pve-enterprise.list

# Vérifier services
systemctl status pve-cluster
systemctl status pvedaemon
systemctl status pveproxy

# Réseau
cat /etc/network/interfaces
ip addr
brctl show

# Logs
tail -f /var/log/pveproxy/access.log
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
