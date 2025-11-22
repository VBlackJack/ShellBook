---
tags:
  - kvm
  - qemu
  - libvirt
  - virtualization
---

# KVM & Libvirt Virtualization

Virtualisation native Linux avec KVM et gestion via Libvirt.

---

## Architecture KVM

### Les Briques de la Virtualisation

```
┌─────────────────────────────────────────────────────────────┐
│                    Applications                              │
├─────────────────────────────────────────────────────────────┤
│                  virt-manager (GUI)                          │
│                     virsh (CLI)                              │
├─────────────────────────────────────────────────────────────┤
│                      Libvirt                                 │
│            (API de gestion unifiée)                          │
├─────────────────────────────────────────────────────────────┤
│                       QEMU                                   │
│          (Émulation matérielle)                              │
├─────────────────────────────────────────────────────────────┤
│                        KVM                                   │
│              (Module Kernel)                                 │
├─────────────────────────────────────────────────────────────┤
│                   Linux Kernel                               │
├─────────────────────────────────────────────────────────────┤
│              CPU (Intel VT-x / AMD-V)                        │
└─────────────────────────────────────────────────────────────┘
```

| Composant | Rôle | Type |
|-----------|------|------|
| **KVM** | Module kernel qui transforme Linux en hyperviseur Type 1 | Kernel module |
| **QEMU** | Émule le matériel virtuel (disques, cartes réseau, USB) | Userspace |
| **Libvirt** | API et démon de gestion unifié | Service/API |
| **virsh** | CLI pour piloter Libvirt | Outil |
| **virt-manager** | Interface graphique | GUI |

### Hyperviseur Type 1 vs Type 2

| Type | Description | Exemples |
|------|-------------|----------|
| **Type 1** (Bare-metal) | Directement sur le hardware | KVM, VMware ESXi, Hyper-V |
| **Type 2** (Hosted) | Sur un OS hôte | VirtualBox, VMware Workstation |

KVM est un **Type 1** car le module s'intègre directement dans le kernel Linux.

---

## Installation & Validation

### Vérification CPU

```bash
# Vérifier le support de virtualisation hardware
egrep -c '(vmx|svm)' /proc/cpuinfo

# vmx = Intel VT-x
# svm = AMD-V
# Résultat > 0 = OK
```

!!! warning "Résultat = 0 ?"
    - Vérifier que la virtualisation est activée dans le BIOS/UEFI
    - Sur une VM imbriquée, activer "Nested Virtualization"

### Installation des Paquets

```bash
# Debian/Ubuntu
sudo apt install qemu-kvm libvirt-daemon-system libvirt-clients bridge-utils virtinst

# RHEL/CentOS
sudo dnf install qemu-kvm libvirt virt-install bridge-utils

# Ajouter l'utilisateur au groupe libvirt
sudo usermod -aG libvirt $USER
sudo usermod -aG kvm $USER

# Relogin pour appliquer les groupes
newgrp libvirt
```

| Paquet | Description |
|--------|-------------|
| `qemu-kvm` | QEMU avec support KVM |
| `libvirt-daemon-system` | Démon Libvirt |
| `libvirt-clients` | Outils CLI (virsh) |
| `bridge-utils` | Gestion des bridges réseau |
| `virtinst` | virt-install pour créer des VMs |

### Validation

```bash
# Démarrer et activer libvirtd
sudo systemctl enable --now libvirtd

# Vérifier que KVM est chargé
lsmod | grep kvm
# kvm_intel (ou kvm_amd)
# kvm

# Vérifier libvirt
virsh list --all

# Output (vide au début):
#  Id   Name   State
# ----------------------

# Vérifier la connexion
virsh uri
# qemu:///system
```

---

## Virsh Cheatsheet

### Créer une VM (virt-install)

```bash
# Création avec ISO
virt-install \
    --name ubuntu-server \
    --ram 2048 \
    --vcpus 2 \
    --disk path=/var/lib/libvirt/images/ubuntu.qcow2,size=20 \
    --os-variant ubuntu22.04 \
    --network network=default \
    --graphics vnc \
    --cdrom /path/to/ubuntu-22.04.iso

# Création depuis image cloud (cloud-init)
virt-install \
    --name vm1 \
    --ram 2048 \
    --vcpus 2 \
    --import \
    --disk /var/lib/libvirt/images/vm1.qcow2 \
    --os-variant ubuntu22.04 \
    --network network=default \
    --noautoconsole

# Lister les OS variants disponibles
osinfo-query os | grep ubuntu
```

### Gestion du Cycle de Vie

```bash
# Lister toutes les VMs
virsh list --all

# Démarrer une VM
virsh start vm1

# Arrêt propre (ACPI - comme appuyer sur le bouton power)
virsh shutdown vm1

# Arrêt forcé (comme débrancher la prise)
virsh destroy vm1

# Redémarrer
virsh reboot vm1

# Suspendre / Reprendre
virsh suspend vm1
virsh resume vm1

# Autostart au boot de l'hôte
virsh autostart vm1
virsh autostart --disable vm1
```

| Commande | Action | Équivalent physique |
|----------|--------|---------------------|
| `shutdown` | Arrêt ACPI propre | Appuyer sur le bouton power |
| `destroy` | Arrêt immédiat | Débrancher la prise |
| `reboot` | Redémarrage ACPI | Ctrl+Alt+Del |

### Informations et Console

```bash
# Infos détaillées
virsh dominfo vm1

# Configuration XML
virsh dumpxml vm1

# Statistiques CPU/Mémoire
virsh domstats vm1

# Console série (Ctrl+] pour quitter)
virsh console vm1

# Adresse IP (si qemu-guest-agent installé)
virsh domifaddr vm1
```

### Snapshots

```bash
# Créer un snapshot
virsh snapshot-create-as vm1 snap1 "Before upgrade"

# Lister les snapshots
virsh snapshot-list vm1

# Infos sur un snapshot
virsh snapshot-info vm1 snap1

# Revenir à un snapshot
virsh snapshot-revert vm1 snap1

# Supprimer un snapshot
virsh snapshot-delete vm1 snap1
```

!!! tip "Snapshots et format de disque"
    Les snapshots nécessitent le format **qcow2**. Les disques raw ne supportent pas les snapshots internes.

### Modification à Chaud

```bash
# Ajouter de la RAM (si maxMemory configuré)
virsh setmem vm1 4G --live

# Ajouter un vCPU (si maxVcpus configuré)
virsh setvcpus vm1 4 --live

# Attacher un disque
virsh attach-disk vm1 /path/to/disk.qcow2 vdb --live

# Détacher un disque
virsh detach-disk vm1 vdb --live
```

### Supprimer une VM

```bash
# Arrêter si nécessaire
virsh destroy vm1

# Supprimer la définition
virsh undefine vm1

# Supprimer avec les volumes associés
virsh undefine vm1 --remove-all-storage

# Supprimer avec snapshots
virsh undefine vm1 --snapshots-metadata
```

---

## Réseau & Stockage

### Modes Réseau

#### Default NAT (Par défaut)

```
┌─────────────────────────────────────────────────────────────┐
│                       Internet                               │
└─────────────────────────────────────────────────────────────┘
                              │
                    ┌─────────┴─────────┐
                    │   Hôte Linux      │
                    │   (192.168.1.10)  │
                    └─────────┬─────────┘
                              │ NAT (virbr0)
                    ┌─────────┴─────────┐
                    │  192.168.122.0/24 │
            ┌───────┴───────┬───────────┴───────┐
            │               │                   │
         ┌──┴──┐         ┌──┴──┐            ┌──┴──┐
         │ VM1 │         │ VM2 │            │ VM3 │
         │.101 │         │.102 │            │.103 │
         └─────┘         └─────┘            └─────┘
```

- VMs accèdent à Internet via NAT
- VMs non accessibles directement depuis l'extérieur
- Idéal pour le développement

```bash
# Voir les réseaux
virsh net-list --all

# Détails du réseau default
virsh net-info default
virsh net-dumpxml default
```

#### Bridge Public

```
┌─────────────────────────────────────────────────────────────┐
│                       Internet                               │
└─────────────────────────────────────────────────────────────┘
                              │
                    ┌─────────┴─────────┐
                    │      Switch       │
                    │  192.168.1.0/24   │
                    └─────────┬─────────┘
                              │ br0
            ┌─────────────────┼─────────────────┐
            │                 │                 │
         ┌──┴──┐           ┌──┴──┐          ┌──┴──┐
         │Hôte │           │ VM1 │          │ VM2 │
         │ .10 │           │ .20 │          │ .21 │
         └─────┘           └─────┘          └─────┘
```

- VMs ont une IP sur le réseau physique
- VMs accessibles directement
- Idéal pour la production

```bash
# Créer un bridge (Netplan)
# /etc/netplan/00-bridge.yaml
network:
  version: 2
  ethernets:
    eth0:
      dhcp4: false
  bridges:
    br0:
      interfaces: [eth0]
      dhcp4: true
      # ou addresses: [192.168.1.10/24]
```

### Stockage

#### Formats de Disque

| Format | Avantages | Inconvénients | Usage |
|--------|-----------|---------------|-------|
| **qcow2** | Snapshots, thin provisioning, compression | Légèrement plus lent | Recommandé |
| **raw** | Performances maximales | Taille fixe, pas de snapshot | I/O intensif |

```bash
# Créer un disque qcow2
qemu-img create -f qcow2 disk.qcow2 20G

# Créer un disque raw
qemu-img create -f raw disk.raw 20G

# Convertir raw → qcow2
qemu-img convert -f raw -O qcow2 disk.raw disk.qcow2

# Infos sur un disque
qemu-img info disk.qcow2

# Redimensionner
qemu-img resize disk.qcow2 +10G
```

#### Pools de Stockage

```bash
# Lister les pools
virsh pool-list --all

# Pool par défaut
ls /var/lib/libvirt/images/

# Lister les volumes d'un pool
virsh vol-list default

# Créer un volume
virsh vol-create-as default newdisk.qcow2 20G --format qcow2
```

---

## Référence Rapide

```bash
# === INSTALLATION ===
sudo apt install qemu-kvm libvirt-daemon-system libvirt-clients virtinst
sudo usermod -aG libvirt,kvm $USER

# === VÉRIFICATION ===
egrep -c '(vmx|svm)' /proc/cpuinfo    # Support CPU
virsh list --all                       # Liste VMs

# === CYCLE DE VIE ===
virsh start vm1                        # Démarrer
virsh shutdown vm1                     # Arrêt propre
virsh destroy vm1                      # Arrêt forcé
virsh reboot vm1                       # Redémarrer

# === SNAPSHOTS ===
virsh snapshot-create-as vm1 snap1 "Description"
virsh snapshot-list vm1
virsh snapshot-revert vm1 snap1

# === INFO ===
virsh dominfo vm1                      # Infos
virsh console vm1                      # Console (Ctrl+] quit)

# === RÉSEAU ===
virsh net-list --all                   # Réseaux

# === STOCKAGE ===
qemu-img create -f qcow2 disk.qcow2 20G
qemu-img info disk.qcow2
```
