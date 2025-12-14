---
tags:
  - tutos
  - virtualization
  - kvm
  - libvirt
  - rocky
---

# KVM/QEMU sur Rocky Linux 9

Installation et configuration de **KVM** pour la virtualisation sur Rocky Linux 9.

| Composant | Version |
|-----------|---------|
| Rocky Linux | 9.x |
| QEMU-KVM | 7.x |
| Libvirt | 9.x |

**Durée estimée :** 45 minutes

---

## Prérequis

### Vérifier le support CPU

```bash
# Vérifier les extensions de virtualisation
grep -E '(vmx|svm)' /proc/cpuinfo

# vmx = Intel VT-x
# svm = AMD-V

# Vérifier le module KVM
lsmod | grep kvm
```

---

## 1. Installation

```bash
# Packages de virtualisation
dnf install -y @virtualization-host-environment

# Ou installation minimale
dnf install -y qemu-kvm libvirt virt-install virt-viewer

# Outils supplémentaires
dnf install -y libguestfs-tools virt-top bridge-utils
```

### Démarrer les services

```bash
systemctl enable --now libvirtd
systemctl status libvirtd

# Vérifier
virsh version
```

---

## 2. Configuration réseau

### Bridge réseau

```bash
# Créer un bridge
nmcli connection add type bridge con-name br0 ifname br0
nmcli connection add type ethernet slave-type bridge con-name br0-port1 ifname eth0 master br0

# Configurer IP
nmcli connection modify br0 ipv4.addresses "192.168.1.10/24"
nmcli connection modify br0 ipv4.gateway "192.168.1.1"
nmcli connection modify br0 ipv4.dns "192.168.1.1"
nmcli connection modify br0 ipv4.method manual

# Activer
nmcli connection up br0
```

### Réseau NAT par défaut

```bash
# Le réseau 'default' est créé automatiquement
virsh net-list --all
virsh net-start default
virsh net-autostart default
```

### Créer un réseau isolé

```bash
cat > /tmp/isolated-net.xml << 'EOF'
<network>
  <name>isolated</name>
  <bridge name="virbr1"/>
  <ip address="10.10.10.1" netmask="255.255.255.0">
    <dhcp>
      <range start="10.10.10.10" end="10.10.10.100"/>
    </dhcp>
  </ip>
</network>
EOF

virsh net-define /tmp/isolated-net.xml
virsh net-start isolated
virsh net-autostart isolated
```

---

## 3. Stockage

### Pool par défaut

```bash
# Le pool 'default' utilise /var/lib/libvirt/images
virsh pool-list --all
virsh pool-start default
virsh pool-autostart default
```

### Créer un pool personnalisé

```bash
mkdir -p /data/vms

cat > /tmp/data-pool.xml << 'EOF'
<pool type="dir">
  <name>data</name>
  <target>
    <path>/data/vms</path>
  </target>
</pool>
EOF

virsh pool-define /tmp/data-pool.xml
virsh pool-build data
virsh pool-start data
virsh pool-autostart data
```

---

## 4. Créer une VM

### Télécharger une ISO

```bash
cd /var/lib/libvirt/images
wget https://download.rockylinux.org/pub/rocky/9/isos/x86_64/Rocky-9-latest-x86_64-minimal.iso
```

### Installation interactive

```bash
virt-install \
  --name rocky9-vm \
  --ram 2048 \
  --vcpus 2 \
  --disk path=/var/lib/libvirt/images/rocky9-vm.qcow2,size=20 \
  --os-variant rocky9 \
  --network network=default \
  --graphics vnc,listen=0.0.0.0 \
  --cdrom /var/lib/libvirt/images/Rocky-9-latest-x86_64-minimal.iso
```

### Installation automatisée (kickstart)

```bash
virt-install \
  --name rocky9-auto \
  --ram 2048 \
  --vcpus 2 \
  --disk path=/var/lib/libvirt/images/rocky9-auto.qcow2,size=20 \
  --os-variant rocky9 \
  --network network=default \
  --graphics none \
  --console pty,target_type=serial \
  --location /var/lib/libvirt/images/Rocky-9-latest-x86_64-minimal.iso \
  --extra-args "console=ttyS0,115200n8 inst.ks=http://kickstart.example.com/rocky9.ks"
```

### Import depuis qcow2 existant

```bash
virt-install \
  --name imported-vm \
  --ram 2048 \
  --vcpus 2 \
  --disk path=/var/lib/libvirt/images/existing.qcow2 \
  --os-variant rocky9 \
  --network network=default \
  --graphics vnc \
  --import
```

---

## 5. Gestion des VMs

### Commandes de base

```bash
# Lister les VMs
virsh list --all

# Démarrer / Arrêter
virsh start rocky9-vm
virsh shutdown rocky9-vm
virsh destroy rocky9-vm  # Force stop
virsh reboot rocky9-vm

# Autostart
virsh autostart rocky9-vm
virsh autostart --disable rocky9-vm

# Supprimer
virsh undefine rocky9-vm
virsh undefine --remove-all-storage rocky9-vm
```

### Console

```bash
# Console graphique
virt-viewer rocky9-vm

# Console série
virsh console rocky9-vm

# VNC
virsh vncdisplay rocky9-vm
```

### Informations

```bash
# Détails VM
virsh dominfo rocky9-vm

# Configuration XML
virsh dumpxml rocky9-vm

# Adresse IP
virsh domifaddr rocky9-vm
```

---

## 6. Snapshots

```bash
# Créer un snapshot
virsh snapshot-create-as rocky9-vm snap1 "Before update"

# Lister
virsh snapshot-list rocky9-vm

# Restaurer
virsh snapshot-revert rocky9-vm snap1

# Supprimer
virsh snapshot-delete rocky9-vm snap1
```

---

## 7. Clonage

```bash
# Cloner une VM (doit être arrêtée)
virt-clone \
  --original rocky9-vm \
  --name rocky9-clone \
  --file /var/lib/libvirt/images/rocky9-clone.qcow2
```

---

## 8. Modifier une VM

### Ajouter de la RAM

```bash
virsh setmaxmem rocky9-vm 4G --config
virsh setmem rocky9-vm 4G --config
```

### Ajouter des vCPUs

```bash
virsh setvcpus rocky9-vm 4 --config --maximum
virsh setvcpus rocky9-vm 4 --config
```

### Ajouter un disque

```bash
# Créer le disque
qemu-img create -f qcow2 /var/lib/libvirt/images/data-disk.qcow2 50G

# Attacher
virsh attach-disk rocky9-vm /var/lib/libvirt/images/data-disk.qcow2 vdb --persistent
```

### Ajouter une interface réseau

```bash
virsh attach-interface rocky9-vm network default --model virtio --persistent
```

---

## 9. Templates

### Préparer une image template

```bash
# Installer la VM, puis :
virt-sysprep -d rocky9-template

# Ou manuellement dans la VM :
# - Supprimer /etc/ssh/ssh_host_*
# - Supprimer /etc/machine-id
# - Nettoyer les logs
```

### Déployer depuis template

```bash
# Copier le disque
cp /var/lib/libvirt/images/rocky9-template.qcow2 /var/lib/libvirt/images/new-vm.qcow2

# Créer la VM
virt-install \
  --name new-vm \
  --ram 2048 \
  --vcpus 2 \
  --disk path=/var/lib/libvirt/images/new-vm.qcow2 \
  --os-variant rocky9 \
  --network network=default \
  --import
```

---

## 10. Migration

### Migration à froid

```bash
# Exporter la config
virsh dumpxml rocky9-vm > rocky9-vm.xml

# Copier le disque
rsync -av /var/lib/libvirt/images/rocky9-vm.qcow2 target-host:/var/lib/libvirt/images/

# Sur le serveur cible
virsh define rocky9-vm.xml
```

### Migration live

```bash
# Prérequis : stockage partagé (NFS, iSCSI)
virsh migrate --live rocky9-vm qemu+ssh://target-host/system
```

---

## 11. Monitoring

```bash
# Stats
virt-top

# Ressources
virsh domstats rocky9-vm

# CPU
virsh cpu-stats rocky9-vm

# I/O
virsh domblkstat rocky9-vm vda
virsh domifstat rocky9-vm vnet0
```

---

## 12. Firewall

```bash
firewall-cmd --permanent --add-port=5900-5910/tcp  # VNC
firewall-cmd --reload
```

---

## Vérification

```bash
virsh version
virsh list --all
virsh net-list --all
virsh pool-list --all
virt-host-validate
```

---

## Dépannage

```bash
# Logs libvirt
journalctl -u libvirtd -f

# Logs VM
cat /var/log/libvirt/qemu/rocky9-vm.log

# Vérifier config
virsh validate rocky9-vm.xml

# Problèmes de permissions
ls -la /var/lib/libvirt/images/
```

| Problème | Solution |
|----------|----------|
| Cannot access storage | Vérifier permissions, SELinux |
| Network not starting | `virsh net-start default` |
| VM won't start | Vérifier logs, ressources |

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
