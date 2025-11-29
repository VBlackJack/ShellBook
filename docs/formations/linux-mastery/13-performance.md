---
tags:
  - formation
  - linux
  - performance
  - troubleshooting
  - debugging
---

# Module 13 : Performance & Troubleshooting

## Objectifs du Module

À l'issue de ce module, vous serez capable de :

- Analyser les performances CPU, mémoire et I/O
- Diagnostiquer les problèmes système
- Utiliser les outils de profiling (strace, perf)
- Optimiser les performances système

**Durée :** 8 heures

**Niveau :** Ingénierie

---

## 1. Analyse CPU

### Load Average

```bash
# Afficher le load
uptime
# 14:30:00 up 5 days, load average: 0.52, 0.58, 0.59
#                                    1min  5min  15min

# Règle : load < nombre de CPU = OK
nproc
# 4

# Si load > 4 sur une machine 4 cores = surcharge
```

### top / htop

```bash
# top - raccourcis
# P : trier par CPU
# M : trier par mémoire
# k : kill un processus
# 1 : afficher tous les cores
# q : quitter

# htop (plus lisible)
sudo dnf install htop
htop
```

### mpstat - Statistiques CPU

```bash
sudo dnf install sysstat

# Toutes les secondes, 5 fois
mpstat 1 5

# Par CPU
mpstat -P ALL 1 5
```

### Processus Gourmands

```bash
# Top 10 CPU
ps aux --sort=-%cpu | head -11

# Top 10 mémoire
ps aux --sort=-%mem | head -11

# Arborescence avec ressources
ps auxf
pstree -p
```

---

## 2. Analyse Mémoire

### free

```bash
free -h
#               total   used   free   shared  buff/cache  available
# Mem:          7.7Gi   2.1Gi  3.2Gi  256Mi   2.4Gi       5.1Gi
# Swap:         2.0Gi   0B     2.0Gi

# available = mémoire réellement disponible (free + buff/cache récupérable)
```

### vmstat

```bash
vmstat 1 5
# procs -----------memory---------- ---swap-- -----io---- -system-- ------cpu-----
#  r  b   swpd   free   buff  cache   si   so    bi    bo   in   cs us sy id wa st
#  1  0      0 3342176 234560 2512640  0    0     5    10  100  200  2  1 97  0  0
```

| Colonne | Description |
|---------|-------------|
| `r` | Processus en attente CPU |
| `b` | Processus bloqués (I/O) |
| `si/so` | Swap in/out (doit être ~0) |
| `us` | CPU user |
| `sy` | CPU system |
| `id` | CPU idle |
| `wa` | CPU wait I/O |

### OOM Killer

```bash
# Voir les événements OOM
dmesg | grep -i "out of memory"
journalctl -k | grep -i oom

# Score OOM d'un processus
cat /proc/$(pgrep nginx)/oom_score

# Protéger un processus
echo -1000 > /proc/$(pgrep critical-app)/oom_score_adj
```

---

## 3. Analyse I/O

### iostat

```bash
iostat -xz 1 5
# Device  r/s     w/s    rkB/s   wkB/s  await  %util
# sda     5.00   10.00   50.00  100.00   2.50  15.00

# await > 10ms = lenteur I/O
# %util > 80% = disque saturé
```

### iotop

```bash
sudo dnf install iotop
sudo iotop

# Par processus
sudo iotop -o    # Seulement les processus actifs
```

### Analyse des Fichiers Ouverts

```bash
# Fichiers ouverts par un processus
lsof -p $(pgrep nginx)

# Qui utilise un fichier
lsof /var/log/messages

# Fichiers réseau
lsof -i :80
lsof -i -P -n
```

---

## 4. Outils de Profiling

### strace - Tracer les Appels Système

```bash
# Tracer un processus
strace -p 1234

# Lancer avec trace
strace ./mon_programme

# Options utiles
strace -f ./script.sh           # Suivre les forks
strace -e open,read,write ./app # Filtrer
strace -c ./app                 # Statistiques
strace -T ./app                 # Temps par appel
strace -o trace.log ./app       # Vers fichier
```

### ltrace - Tracer les Appels de Bibliothèque

```bash
ltrace ./mon_programme
ltrace -e malloc+free ./app
```

### perf - Profiling Avancé

```bash
# Installation
sudo dnf install perf

# Statistiques globales
perf stat ./mon_programme

# Enregistrer un profil
perf record -g ./mon_programme
perf report

# Profiler un processus existant
perf record -p $(pgrep nginx) -g -- sleep 30
perf report
```

---

## 5. Troubleshooting Réseau

### Diagnostic Rapide

```bash
# Connectivité
ping -c 4 8.8.8.8
ping -c 4 google.com

# DNS
nslookup google.com
dig google.com +short

# Routes
ip route
tracepath google.com

# Ports
ss -tuln
ss -tulnp | grep :80
```

### tcpdump

```bash
# Capturer sur une interface
sudo tcpdump -i eth0

# Filtrer par port
sudo tcpdump -i eth0 port 80

# Filtrer par hôte
sudo tcpdump -i eth0 host 192.168.1.100

# Sauvegarder
sudo tcpdump -i eth0 -w capture.pcap

# Lire
tcpdump -r capture.pcap
```

### Analyse des Connexions

```bash
# Connexions établies
ss -tn state established

# Connexions par état
ss -s

# Sockets TIME_WAIT (trop = problème)
ss -tn state time-wait | wc -l
```

---

## 6. Logs et Journaux

### journalctl

```bash
# Erreurs récentes
journalctl -p err -b

# Service spécifique
journalctl -u nginx --since "1 hour ago"

# Kernel messages
journalctl -k

# Temps réel
journalctl -f

# Boot précédent
journalctl -b -1
```

### dmesg

```bash
# Messages kernel
dmesg
dmesg -T          # Avec timestamps lisibles
dmesg --level=err # Seulement erreurs
dmesg -w          # Temps réel
```

### Logs Système

```bash
# Fichiers importants
/var/log/messages     # RHEL - général
/var/log/syslog       # Ubuntu - général
/var/log/secure       # RHEL - auth
/var/log/auth.log     # Ubuntu - auth
/var/log/audit/       # Audit
```

---

## 7. Optimisation Système

### Paramètres Kernel (sysctl)

```bash
# Voir tous les paramètres
sysctl -a

# Paramètres réseau
sysctl -w net.core.somaxconn=65535
sysctl -w net.ipv4.tcp_max_syn_backlog=65535

# Persistant
cat << 'EOF' >> /etc/sysctl.d/99-tuning.conf
net.core.somaxconn = 65535
vm.swappiness = 10
vm.dirty_ratio = 20
EOF
sysctl --system
```

### Limites Utilisateur

```bash
# /etc/security/limits.conf
*    soft    nofile    65535
*    hard    nofile    65535
*    soft    nproc     65535

# Vérifier
ulimit -a
ulimit -n    # Fichiers ouverts
```

---

## 8. Exercice Pratique

!!! example "Exercice : Diagnostic d'un Système Lent"

    Simuler et diagnostiquer :

    1. Identifier un processus consommant trop de CPU
    2. Analyser l'utilisation mémoire
    3. Vérifier les I/O disque
    4. Tracer les appels système d'un processus
    5. Analyser les logs pour trouver des erreurs

    **Durée estimée :** 30 minutes

---

## Points Clés à Retenir

| Problème | Outils |
|----------|--------|
| CPU élevé | `top`, `htop`, `mpstat`, `perf` |
| Mémoire | `free`, `vmstat`, `oom` logs |
| I/O lent | `iostat`, `iotop`, `lsof` |
| Réseau | `ss`, `tcpdump`, `tracepath` |
| Profiling | `strace`, `ltrace`, `perf` |

---

[:octicons-arrow-right-24: Module 14 : Scripting Avancé](14-scripting-avance.md)

---

**Retour au :** [Programme de la Formation](index.md)
