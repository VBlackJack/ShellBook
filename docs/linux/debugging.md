# Débogage Système & Logs

Commandes essentielles pour dépanner les systèmes Linux.

---

## Logs Systemd (journalctl)

### Voir les Logs d'un Service

```bash
# Logs pour un service spécifique
journalctl -u nginx
journalctl -u ssh

# Suivre les logs en temps réel
journalctl -u nginx -f

# Les 100 dernières lignes
journalctl -u nginx -n 100
```

### Filtrage par Temps

```bash
# Depuis 1 heure
journalctl --since "1 hour ago"

# Depuis un moment spécifique
journalctl --since "2024-01-15 10:00:00"

# Plage temporelle
journalctl --since "2024-01-15" --until "2024-01-16"

# Depuis le dernier démarrage
journalctl -b

# Démarrage précédent
journalctl -b -1
```

### Filtrer par Priorité

```bash
# Erreurs uniquement
journalctl -p err

# Erreurs et avertissements
journalctl -p warning

# Niveaux de priorité : emerg, alert, crit, err, warning, notice, info, debug
```

| Option | Description |
|--------|-------------|
| `-u <service>` | Filtrer par unité systemd |
| `-f` | Suivre (comme tail -f) |
| `-n <N>` | Afficher les N dernières lignes |
| `-p <level>` | Filtrer par priorité |
| `-b` | Démarrage actuel uniquement |
| `--since` | Filtre de temps de début |
| `--no-pager` | Sortie sans pagination |

---

## Inspection de Fichiers & Ports (lsof)

### Trouver le Processus Utilisant un Port

```bash
# Qui utilise le port 80 ?
lsof -i :80

# Qui utilise le port 443 ? (TCP uniquement)
lsof -i TCP:443

# Toutes les connexions réseau
lsof -i

# Tous les ports en écoute
lsof -i -P -n | grep LISTEN
```

### Trouver les Fichiers Ouverts

```bash
# Fichiers ouverts par un utilisateur
lsof -u root
lsof -u www-data

# Fichiers ouverts par un processus
lsof -p 1234

# Qui a ce fichier ouvert ?
lsof /var/log/syslog

# Fichiers dans un répertoire
lsof +D /var/log/
```

!!! tip "Alternative : ss + fuser"
    ```bash
    # Trouver le processus sur un port
    ss -tulpn | grep :80

    # Tuer le processus utilisant un fichier
    fuser -k /var/lock/lockfile
    ```

---

## Messages du Noyau (dmesg)

```bash
# Timestamps lisibles
dmesg -T

# Suivre les messages du noyau
dmesg -w

# Filtrer par niveau
dmesg --level=err,warn

# Filtrer par facility
dmesg -f kern

# Effacer le ring buffer (nécessite root)
dmesg -c
```

### Cas d'Usage Courants

```bash
# Problèmes de périphérique USB
dmesg -T | grep -i usb

# Erreurs de disque
dmesg -T | grep -iE "(sda|nvme|error|fail)"

# Problèmes de mémoire
dmesg -T | grep -iE "(oom|memory|killed)"
```

---

## L'Option Nucléaire (strace)

!!! danger "Impact sur les Performances"
    `strace` ralentit significativement les processus tracés.
    **Ne jamais utiliser sur des systèmes de production à forte charge** sans comprendre l'impact.
    Considérez `perf` ou les outils `eBPF` pour le débogage en production.

### Usage de Base

```bash
# Tracer un processus en cours
strace -p <PID>

# Tracer une commande
strace ls -la

# Tracer avec timestamps
strace -t -p <PID>

# Tracer uniquement des syscalls spécifiques
strace -e open,read,write -p <PID>

# Résumé des syscalls
strace -c ls -la
```

### Exemples Pratiques

```bash
# Pourquoi ce processus est-il bloqué ?
strace -p $(pgrep -f "stuck_process")

# Quels fichiers sont accédés ?
strace -e openat -p <PID>

# Activité réseau
strace -e network -p <PID>

# Sauvegarder la sortie dans un fichier
strace -o /tmp/trace.log -p <PID>
```

!!! tip "Alternatives pour la Production"
    - `ltrace` - Traçage des appels de bibliothèque
    - `perf trace` - Overhead plus faible
    - `bpftrace` - Basé sur eBPF, impact minimal
