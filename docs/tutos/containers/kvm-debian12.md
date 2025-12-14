---
tags:
  - tutos
  - virtualization
  - kvm
  - libvirt
  - debian
---

# KVM/QEMU sur Debian 12

Installation et configuration de **KVM** sur Debian 12 Bookworm.

| Composant | Version |
|-----------|---------|
| Debian | 12 Bookworm |
| QEMU-KVM | 7.x |
| Libvirt | 9.x |

**Durée estimée :** 40 minutes

---

## Prérequis

```bash
# Vérifier le support CPU
grep -E '(vmx|svm)' /proc/cpuinfo

# Vérifier le module
lsmod | grep kvm
```

---

## 1. Installation

```bash
apt update
apt install -y qemu-kvm libvirt-daemon-system libvirt-clients \
    virtinst virt-viewer bridge-utils

# Outils supplémentaires
apt install -y libguestfs-tools virt-top
```

### Ajouter l'utilisateur au groupe

```bash
usermod -aG libvirt $USER
usermod -aG kvm $USER

# Se reconnecter ou
newgrp libvirt
```

### Démarrer les services

```bash
systemctl enable --now libvirtd
systemctl status libvirtd

virsh version
```

---

## 2. Réseau

### Réseau NAT par défaut

```bash
virsh net-list --all
virsh net-start default
virsh net-autostart default
```

### Bridge réseau

```bash
vim /etc/network/interfaces
```

```
auto br0
iface br0 inet static
    address 192.168.1.10
    netmask 255.255.255.0
    gateway 192.168.1.1
    bridge_ports eth0
    bridge_stp off
    bridge_fd 0
```

```bash
systemctl restart networking
```

### Ou avec NetworkManager

```bash
nmcli connection add type bridge con-name br0 ifname br0
nmcli connection add type ethernet slave-type bridge con-name br0-port ifname eth0 master br0
nmcli connection modify br0 ipv4.addresses "192.168.1.10/24"
nmcli connection modify br0 ipv4.gateway "192.168.1.1"
nmcli connection modify br0 ipv4.method manual
nmcli connection up br0
```

---

## 3. Stockage

```bash
# Pool par défaut
virsh pool-list --all
virsh pool-start default
virsh pool-autostart default

# Créer un pool personnalisé
mkdir -p /data/vms

virsh pool-define-as data dir --target /data/vms
virsh pool-build data
virsh pool-start data
virsh pool-autostart data
```

---

## 4. Créer une VM

### Télécharger une ISO

```bash
cd /var/lib/libvirt/images
wget https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/debian-12.0.0-amd64-netinst.iso
```

### Installation

```bash
virt-install \
  --name debian12-vm \
  --ram 2048 \
  --vcpus 2 \
  --disk path=/var/lib/libvirt/images/debian12-vm.qcow2,size=20 \
  --os-variant debian12 \
  --network network=default \
  --graphics vnc,listen=0.0.0.0 \
  --cdrom /var/lib/libvirt/images/debian-12.0.0-amd64-netinst.iso
```

### Import

```bash
virt-install \
  --name imported-vm \
  --ram 2048 \
  --vcpus 2 \
  --disk path=/var/lib/libvirt/images/existing.qcow2 \
  --os-variant debian12 \
  --network network=default \
  --import
```

### Cloud-init

```bash
# Télécharger image cloud
wget https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-generic-amd64.qcow2

# Créer le disque
cp debian-12-generic-amd64.qcow2 /var/lib/libvirt/images/cloud-vm.qcow2
qemu-img resize /var/lib/libvirt/images/cloud-vm.qcow2 20G

# Cloud-init
cat > /tmp/cloud-init.cfg << 'EOF'
#cloud-config
hostname: cloud-vm
users:
  - name: admin
    sudo: ALL=(ALL) NOPASSWD:ALL
    ssh_authorized_keys:
      - ssh-rsa AAAA...
EOF

cloud-localds /var/lib/libvirt/images/cloud-init.iso /tmp/cloud-init.cfg

virt-install \
  --name cloud-vm \
  --ram 2048 \
  --vcpus 2 \
  --disk path=/var/lib/libvirt/images/cloud-vm.qcow2 \
  --disk path=/var/lib/libvirt/images/cloud-init.iso,device=cdrom \
  --os-variant debian12 \
  --network network=default \
  --import
```

---

## 5. Gestion des VMs

```bash
# Lister
virsh list --all

# Démarrer / Arrêter
virsh start debian12-vm
virsh shutdown debian12-vm
virsh destroy debian12-vm
virsh reboot debian12-vm

# Autostart
virsh autostart debian12-vm

# Console
virt-viewer debian12-vm
virsh console debian12-vm

# Supprimer
virsh undefine --remove-all-storage debian12-vm
```

---

## 6. Snapshots

```bash
# Créer
virsh snapshot-create-as debian12-vm snap1 "Before update"

# Lister
virsh snapshot-list debian12-vm

# Restaurer
virsh snapshot-revert debian12-vm snap1

# Supprimer
virsh snapshot-delete debian12-vm snap1
```

---

## 7. Clonage

```bash
virt-clone \
  --original debian12-vm \
  --name debian12-clone \
  --file /var/lib/libvirt/images/debian12-clone.qcow2
```

---

## 8. Modifier une VM

```bash
# RAM
virsh setmaxmem debian12-vm 4G --config
virsh setmem debian12-vm 4G --config

# vCPUs
virsh setvcpus debian12-vm 4 --config --maximum
virsh setvcpus debian12-vm 4 --config

# Ajouter disque
qemu-img create -f qcow2 /var/lib/libvirt/images/data.qcow2 50G
virsh attach-disk debian12-vm /var/lib/libvirt/images/data.qcow2 vdb --persistent

# Ajouter réseau
virsh attach-interface debian12-vm network default --model virtio --persistent
```

---

## 9. Templates

```bash
# Préparer le template
virt-sysprep -d debian12-template

# Déployer
cp /var/lib/libvirt/images/debian12-template.qcow2 /var/lib/libvirt/images/new-vm.qcow2

virt-install \
  --name new-vm \
  --ram 2048 \
  --vcpus 2 \
  --disk path=/var/lib/libvirt/images/new-vm.qcow2 \
  --os-variant debian12 \
  --network network=default \
  --import
```

---

## 10. Monitoring

```bash
virt-top
virsh domstats debian12-vm
virsh cpu-stats debian12-vm
virsh domblkstat debian12-vm vda
```

---

## 11. Firewall

```bash
ufw allow 5900:5910/tcp  # VNC
ufw reload
```

---

## Comparatif Rocky vs Debian

| Aspect | Rocky 9 | Debian 12 |
|--------|---------|-----------|
| Packages | @virtualization-host | qemu-kvm libvirt-* |
| Groupe | libvirt | libvirt |
| Réseau | nmcli | interfaces ou nmcli |
| Firewall | firewalld | ufw |
| SELinux | Oui | Non (AppArmor) |

---

## Vérification

```bash
virsh version
virt-host-validate
virsh list --all
virsh net-list --all
virsh pool-list --all
```

---

## Dépannage

```bash
# Logs
journalctl -u libvirtd -f
cat /var/log/libvirt/qemu/*.log

# Permissions
ls -la /var/lib/libvirt/images/

# AppArmor
aa-status
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
