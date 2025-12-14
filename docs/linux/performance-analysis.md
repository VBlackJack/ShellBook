---
tags:
  - load-average
  - ram
  - iostat
  - vmstat
  - sysstat
---

# Load Average & Performance Analysis

Diagnostic et analyse des performances système Linux.

---

## Comprendre le Load Average

### Définition

!!! warning "Le Load Average n'est PAS un pourcentage CPU"
    Le Load Average représente le **nombre moyen de processus** :

    - En cours d'exécution sur le CPU
    - En attente du CPU
    - En attente d'I/O disque (état "D" - uninterruptible sleep)

```bash
$ uptime
 14:30:05 up 45 days, load average: 2.50, 1.80, 1.20
                                    │     │     │
                                    │     │     └── Moyenne 15 min
                                    │     └──────── Moyenne 5 min
                                    └────────────── Moyenne 1 min
```

### Règle du Pouce

```text
Load Average < Nombre de Coeurs = OK
Load Average > Nombre de Coeurs = Saturation
```

| Coeurs | Load OK | Load Attention | Load Critique |
|--------|---------|----------------|---------------|
| 1 | < 1.0 | 1.0 - 2.0 | > 2.0 |
| 4 | < 4.0 | 4.0 - 8.0 | > 8.0 |
| 8 | < 8.0 | 8.0 - 16.0 | > 16.0 |
| 16 | < 16.0 | 16.0 - 32.0 | > 32.0 |

```bash
# Nombre de coeurs
nproc
# ou
grep -c processor /proc/cpuinfo

# Load actuel
uptime
w
cat /proc/loadavg
```

### Interpréter les Tendances

```text
Load: 8.00, 4.00, 2.00
      ↑     ↑     ↑
      1min  5min  15min

→ Charge EN AUGMENTATION (problème récent, en cours)

Load: 2.00, 4.00, 8.00
→ Charge EN DIMINUTION (problème passé, en résolution)

Load: 8.00, 8.00, 8.00
→ Charge STABLE élevée (problème persistant)
```

---

## Mémoire & OOM Killer

### Lecture de free -h

```bash
$ free -h
              total        used        free      shared  buff/cache   available
Mem:           15Gi       8.5Gi       512Mi       256Mi       6.5Gi       6.2Gi
Swap:          4.0Gi       100Mi       3.9Gi
```

| Colonne | Description |
|---------|-------------|
| **total** | RAM physique totale |
| **used** | RAM utilisée par les applications |
| **free** | RAM réellement libre (inutilisée) |
| **shared** | Mémoire partagée (tmpfs, etc.) |
| **buff/cache** | Cache disque en RAM (libérable) |
| **available** | RAM disponible pour nouvelles apps |

!!! tip "Buff/Cache : Ne pas paniquer"
    Linux utilise la RAM "libre" comme cache disque pour accélérer les I/O.

    **Ce cache est automatiquement libéré** quand une application a besoin de mémoire.

    ```text
    Mémoire réellement disponible = free + buff/cache ≈ available
    ```

### OOM Killer (Out of Memory)

Quand la RAM physique + Swap sont épuisées, le kernel **tue des processus** pour survivre.

```text
┌─────────────────────────────────────────────────────────────┐
│                     RAM PHYSIQUE                             │
│  ████████████████████████████████████████████████ 100%      │
├─────────────────────────────────────────────────────────────┤
│                        SWAP                                  │
│  ████████████████████████████████████████████████ 100%      │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   💀 OOM KILLER ACTIVÉ → Tue le processus le plus gourmand  │
│                          (souvent MySQL, PostgreSQL, Java)   │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

#### Détecter un OOM Kill

```bash
# Dans dmesg
dmesg | grep -i "killed process"
dmesg | grep -i "out of memory"

# Dans les logs
grep -i "killed process" /var/log/kern.log
grep -i "oom" /var/log/syslog

# Exemple de message
# Out of memory: Killed process 1234 (mysqld) total-vm:2048000kB
```

#### Prévenir l'OOM

```bash
# Surveiller la mémoire
watch -n 1 free -h

# Identifier les gros consommateurs
ps aux --sort=-%mem | head -10

# Ajuster le swap si nécessaire
# Voir docs/linux/filesystem-and-storage.md
```

---

## I/O Disk Bottlenecks

### Le Coupable Souvent Ignoré

!!! danger "Symptôme : Tout est lent, mais CPU et RAM semblent OK"
    Le disque est souvent le goulet d'étranglement invisible :

    - Load Average élevé avec CPU idle
    - Applications figées
    - Bases de données lentes

### iostat : L'Outil de Diagnostic

```bash
# Installation
sudo apt install sysstat

# Utilisation (rafraîchissement chaque seconde)
iostat -xz 1
```

```text
Device   r/s   w/s  rkB/s  wkB/s  await  %util
sda      5.0  150.0   20.0 15000.0  45.0   98.5  ← PROBLÈME
nvme0n1  2.0   10.0   80.0   500.0   0.5    5.0  ← OK
```

### Métriques Clés

| Métrique | Description | Seuil d'alerte |
|----------|-------------|----------------|
| **%util** | Pourcentage d'utilisation du disque | > 80% = saturation |
| **await** | Latence moyenne (ms) | > 20ms (HDD), > 5ms (SSD) |
| **r/s, w/s** | Lectures/écritures par seconde | Dépend du workload |
| **rkB/s, wkB/s** | Débit en KB/s | Comparer au max théorique |

### Identifier le Processus Coupable

```bash
# iotop : Top pour les I/O disque
sudo apt install iotop
sudo iotop -o    # -o = only processes doing I/O

# Ou via pidstat
pidstat -d 1     # I/O par processus chaque seconde
```

### Exemple de Diagnostic

```bash
# Étape 1 : Load élevé ?
$ uptime
load average: 12.00, 10.00, 8.00   # Élevé pour 4 coeurs

# Étape 2 : CPU idle malgré le load ?
$ mpstat 1
%idle: 85%   # CPU en attente → I/O probable

# Étape 3 : Disque saturé ?
$ iostat -xz 1
sda  %util: 99%  await: 150ms   # Disque HDD saturé

# Étape 4 : Quel processus ?
$ sudo iotop -o
mysqld: 95% DISK WRITE   # Coupable identifié
```

---

## Synthèse des Outils

### Vue d'Ensemble

| Ressource | Outil Rapide | Outil Détaillé | Installation |
|-----------|--------------|----------------|--------------|
| **CPU** | `top`, `htop` | `mpstat`, `pidstat` | `sysstat` |
| **RAM** | `free -h` | `vmstat`, `smem` | `sysstat`, `smem` |
| **Disk I/O** | `iostat` | `iotop`, `pidstat -d` | `sysstat`, `iotop` |
| **Network** | `iftop` | `nload`, `nethogs` | `iftop`, `nload` |
| **Global** | `htop` | `glances`, `nmon` | `glances`, `nmon` |

### Commandes de Premier Réflexe

```bash
# Vue globale rapide
htop                      # CPU, RAM, processus
glances                   # Tout en un

# CPU
mpstat 1                  # Utilisation par coeur
pidstat 1                 # CPU par processus

# RAM
free -h                   # Vue globale
vmstat 1                  # Détails (si, so = swap in/out)
ps aux --sort=-%mem | head

# Disk
iostat -xz 1              # Saturation disque
iotop -o                  # I/O par processus
df -h                     # Espace disque

# Network
iftop                     # Bande passante par connexion
nload                     # Graphique bande passante
ss -tulpn                 # Ports en écoute
```

### vmstat : Vue Synthétique

```bash
$ vmstat 1
procs -----------memory---------- ---swap-- -----io---- -system-- ------cpu-----
 r  b   swpd   free   buff  cache   si   so    bi    bo   in   cs us sy id wa st
 2  0      0 512000 128000 6000000    0    0    50  1000  500 1000 15  5 75  5  0
 │  │                                │    │                          │  │  │  │
 │  │                                │    │                          │  │  │  └─ wa: I/O wait
 │  │                                │    │                          │  │  └──── id: idle
 │  │                                │    │                          │  └─────── sy: system
 │  │                                │    └──────────────────────────└────────── us: user
 │  │                                └─ si/so: swap in/out (> 0 = problème RAM)
 │  └─ b: processus bloqués sur I/O
 └──── r: processus en attente CPU
```

| Colonne | Signification | Alerte si |
|---------|---------------|-----------|
| `r` | Runnable processes | > nb coeurs |
| `b` | Blocked (I/O wait) | > 0 constant |
| `si/so` | Swap in/out | > 0 |
| `wa` | I/O wait % | > 20% |
| `id` | Idle % | < 10% |

---

## Référence Rapide

```bash
# === LOAD ===
uptime                    # Load average
nproc                     # Nombre de coeurs
# Règle : Load < nproc = OK

# === RAM ===
free -h                   # Vue globale
ps aux --sort=-%mem | head  # Top consommateurs
dmesg | grep -i killed    # OOM kills

# === DISK I/O ===
iostat -xz 1              # %util, await
iotop -o                  # Par processus
# %util > 80% = saturation

# === CPU ===
htop                      # Interactif
mpstat 1                  # Par coeur

# === GLOBAL ===
vmstat 1                  # Synthèse
glances                   # Dashboard complet
```

---

## Voir aussi

- [Débogage Système & Logs](debugging.md)
- [Kernel Debugging & Troubleshooting](kernel-debugging.md)
