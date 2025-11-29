---
tags:
  - windows
  - hyper-v
  - virtualization
  - infrastructure
---

# Hyper-V

Guide de virtualisation avec Microsoft Hyper-V : installation, configuration des VMs, networking et haute disponibilité.

## Installation

```powershell
# Installer Hyper-V (Windows Server)
Install-WindowsFeature -Name Hyper-V -IncludeManagementTools -Restart

# Installer Hyper-V (Windows 10/11)
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All

# Vérifier l'installation
Get-WindowsFeature Hyper-V*
```

---

## Gestion des VMs

### Créer une VM

```powershell
# Créer une VM Generation 2
New-VM -Name "SRV-WEB-01" `
    -Generation 2 `
    -MemoryStartupBytes 4GB `
    -NewVHDPath "D:\Hyper-V\VHDs\SRV-WEB-01.vhdx" `
    -NewVHDSizeBytes 100GB `
    -SwitchName "vSwitch-LAN"

# Configurer la VM
Set-VM -Name "SRV-WEB-01" `
    -ProcessorCount 4 `
    -DynamicMemory `
    -MemoryMinimumBytes 2GB `
    -MemoryMaximumBytes 8GB

# Monter l'ISO d'installation
Add-VMDvdDrive -VMName "SRV-WEB-01" -Path "D:\ISO\WindowsServer2022.iso"

# Configurer le boot order (DVD first)
$dvd = Get-VMDvdDrive -VMName "SRV-WEB-01"
Set-VMFirmware -VMName "SRV-WEB-01" -FirstBootDevice $dvd

# Démarrer la VM
Start-VM -Name "SRV-WEB-01"
```

### Gestion Quotidienne

```powershell
# Lister les VMs
Get-VM | Select-Object Name, State, CPUUsage, MemoryAssigned

# Démarrer/Arrêter
Start-VM -Name "SRV-WEB-01"
Stop-VM -Name "SRV-WEB-01" -Force
Restart-VM -Name "SRV-WEB-01"

# Sauvegarder l'état
Save-VM -Name "SRV-WEB-01"

# Snapshot (Checkpoint)
Checkpoint-VM -Name "SRV-WEB-01" -SnapshotName "Before-Update"

# Restaurer un snapshot
Restore-VMSnapshot -VMName "SRV-WEB-01" -Name "Before-Update"

# Supprimer un snapshot
Remove-VMSnapshot -VMName "SRV-WEB-01" -Name "Before-Update"

# Exporter une VM
Export-VM -Name "SRV-WEB-01" -Path "D:\Exports"

# Supprimer une VM
Remove-VM -Name "OldVM" -Force
Remove-Item "D:\Hyper-V\VHDs\OldVM.vhdx"
```

---

## Networking

### Virtual Switches

```powershell
# Créer un switch externe (accès réseau)
New-VMSwitch -Name "vSwitch-External" `
    -NetAdapterName "Ethernet" `
    -AllowManagementOS $true

# Créer un switch interne (host + VMs)
New-VMSwitch -Name "vSwitch-Internal" -SwitchType Internal

# Créer un switch privé (VMs uniquement)
New-VMSwitch -Name "vSwitch-Private" -SwitchType Private

# Lister les switches
Get-VMSwitch

# Connecter une VM au switch
Connect-VMNetworkAdapter -VMName "SRV-WEB-01" -SwitchName "vSwitch-External"

# Ajouter une carte réseau
Add-VMNetworkAdapter -VMName "SRV-WEB-01" -SwitchName "vSwitch-Internal" -Name "Internal-NIC"
```

### VLAN et QoS

```powershell
# Configurer un VLAN
Set-VMNetworkAdapterVlan -VMName "SRV-WEB-01" `
    -Access `
    -VlanId 100

# Activer le VLAN trunking
Set-VMNetworkAdapterVlan -VMName "SRV-WEB-01" -Trunk -AllowedVlanIdList "100,200,300" -NativeVlanId 1

# Configurer QoS (bande passante)
Set-VMNetworkAdapter -VMName "SRV-WEB-01" `
    -MinimumBandwidthAbsolute 100MB `
    -MaximumBandwidth 1GB
```

---

## Stockage

### Disques Virtuels

```powershell
# Créer un disque dynamique
New-VHD -Path "D:\Hyper-V\VHDs\Data.vhdx" `
    -SizeBytes 500GB `
    -Dynamic

# Créer un disque fixe (meilleures perfs)
New-VHD -Path "D:\Hyper-V\VHDs\Data-Fixed.vhdx" `
    -SizeBytes 500GB `
    -Fixed

# Créer un disque différentiel
New-VHD -Path "D:\Hyper-V\VHDs\Child.vhdx" `
    -ParentPath "D:\Hyper-V\VHDs\Parent.vhdx" `
    -Differencing

# Attacher un disque à une VM
Add-VMHardDiskDrive -VMName "SRV-WEB-01" -Path "D:\Hyper-V\VHDs\Data.vhdx"

# Redimensionner un disque
Resize-VHD -Path "D:\Hyper-V\VHDs\Data.vhdx" -SizeBytes 1TB

# Convertir VHD en VHDX
Convert-VHD -Path "D:\Old.vhd" -DestinationPath "D:\New.vhdx" -VHDType Dynamic
```

### Pass-Through Disk

```powershell
# Identifier le disque physique
Get-Disk | Where-Object { $_.OperationalStatus -eq "Offline" }

# Attacher en pass-through
Add-VMHardDiskDrive -VMName "SRV-SQL-01" -DiskNumber 2
```

---

## Haute Disponibilité

### Live Migration

```powershell
# Activer Live Migration
Enable-VMMigration

# Configurer les réseaux de migration
Set-VMMigrationNetwork -Subnet "10.10.100.0/24" -Priority 1

# Configurer l'authentification
Set-VMHost -VirtualMachineMigrationAuthenticationType Kerberos

# Migrer une VM
Move-VM -Name "SRV-WEB-01" -DestinationHost "HV-NODE-02"

# Migration du stockage uniquement
Move-VMStorage -VMName "SRV-WEB-01" -DestinationStoragePath "D:\Hyper-V\NewStorage"
```

### Réplication Hyper-V

```powershell
# Activer le serveur réplica
Set-VMReplicationServer -ReplicationEnabled $true `
    -AllowedAuthenticationType Kerberos `
    -ReplicationAllowedFromAnyServer $false

# Configurer la réplication pour une VM
Enable-VMReplication -VMName "SRV-WEB-01" `
    -ReplicaServerName "HV-DR-01.corp.local" `
    -ReplicaServerPort 443 `
    -AuthenticationType Kerberos `
    -ReplicationFrequencySec 300

# Démarrer la réplication initiale
Start-VMInitialReplication -VMName "SRV-WEB-01"

# Failover planifié
Start-VMFailover -VMName "SRV-WEB-01" -Prepare
# Sur le serveur réplica :
Start-VMFailover -VMName "SRV-WEB-01"
```

---

## Monitoring

```powershell
# Statistiques des VMs
Get-VM | Select-Object Name, State, CPUUsage, @{N='MemoryGB';E={$_.MemoryAssigned/1GB}}

# Métriques détaillées
Enable-VMResourceMetering -VMName "SRV-WEB-01"
Measure-VM -VMName "SRV-WEB-01"

# Événements Hyper-V
Get-WinEvent -LogName "Microsoft-Windows-Hyper-V-*" -MaxEvents 50

# Vérifier la santé
Get-VMIntegrationService -VMName "SRV-WEB-01"
```

---

## Bonnes Pratiques

```yaml
Checklist Hyper-V:
  Configuration:
    - [ ] Generation 2 pour nouvelles VMs
    - [ ] Mémoire dynamique activée
    - [ ] Integration Services à jour

  Stockage:
    - [ ] VHDX (pas VHD)
    - [ ] Disques sur volume dédié
    - [ ] Pas de snapshots en production long-terme

  Réseau:
    - [ ] Switches dédiés par usage
    - [ ] VLANs configurés
    - [ ] NIC Teaming sur l'host

  HA:
    - [ ] Réplication ou Failover Cluster
    - [ ] Live Migration testé
    - [ ] Backup régulier des VMs
```

---

**Voir aussi :**

- [Disk Management](disk-management.md) - Stockage
- [Cluster](failover-cluster.md) - Haute disponibilité
- [PowerShell Remoting](powershell-remoting.md) - Gestion à distance
