---
tags:
  - tutos
  - storage
  - nfs
  - samba
  - fileserver
---

# Tutoriels Stockage

## Partage de fichiers

| Tutoriel | OS | Service | Status |
|----------|-----|---------|--------|
| [NFS Server](nfs-rocky9.md) | Rocky 9 | NFS v4 | Disponible |
| [NFS Server](nfs-debian12.md) | Debian 12 | NFS v4 | Disponible |
| [Samba](samba-rocky9.md) | Rocky 9 | Samba 4 | Disponible |
| [Samba](samba-debian12.md) | Debian 12 | Samba 4 | Disponible |
| [File Server + DFS](fileserver-windows2022.md) | Windows 2022 | SMB 3.1 | Disponible |

## Stockage bloc

| Tutoriel | OS | Service | Status |
|----------|-----|---------|--------|
| iSCSI Target | Rocky 9 | targetcli | Planifié |
| iSCSI Target | Debian 12 | tgt | Planifié |
| iSCSI Target | Windows 2022 | iSCSI Target Server | Planifié |

## Stockage distribué

| Tutoriel | OS | Service | Status |
|----------|-----|---------|--------|
| GlusterFS | Rocky 9 | GlusterFS | Planifié |
| MinIO (S3) | Rocky 9 | MinIO | Planifié |

## Comparatif

| Critère | NFS | SMB/Samba | iSCSI |
|---------|-----|-----------|-------|
| Type | Fichiers | Fichiers | Bloc |
| Clients | Linux/Unix | Windows/Linux | Tous |
| Performance | Excellente | Bonne | Excellente |
| Cas d'usage | Serveurs Linux | Mixte | VMs, BDD |
