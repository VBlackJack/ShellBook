---
tags:
  - logrotate
  - rsyslog
  - var-log
  - troubleshooting
---

# Logs Rotation & Management

Gestion et rotation des logs système sous Linux.

---

## Anatomie de /var/log

### Fichiers Standards (Debian/Ubuntu)

| Fichier | Contenu | Criticité |
|---------|---------|-----------|
| `auth.log` | Authentification SSH, sudo, PAM | **Critique** - Sécurité |
| `syslog` | Messages système généraux (fourre-tout) | Haute |
| `kern.log` | Messages kernel (drivers, hardware) | Haute |
| `dmesg` | Buffer kernel au boot | Moyenne |
| `dpkg.log` | Installations/suppressions paquets | Moyenne |
| `apt/history.log` | Historique APT | Moyenne |
| `boot.log` | Messages de démarrage | Moyenne |
| `cron.log` | Exécutions cron | Moyenne |
| `mail.log` | Serveur mail (Postfix, etc.) | Variable |
| `nginx/access.log` | Requêtes HTTP Nginx | Variable |
| `nginx/error.log` | Erreurs Nginx | Haute |
| `mysql/error.log` | Erreurs MySQL/MariaDB | Haute |

### Logs Critiques pour la Sécurité

```bash
# Tentatives de connexion SSH
grep "Failed password" /var/log/auth.log

# Connexions SSH réussies
grep "Accepted" /var/log/auth.log

# Commandes sudo
grep "sudo:" /var/log/auth.log

# Erreurs kernel (hardware)
grep -i "error\|fail" /var/log/kern.log
```

### Structure Typique

```text
/var/log/
├── auth.log              # Auth actuel
├── auth.log.1            # Rotation précédente
├── auth.log.2.gz         # Compressé
├── syslog
├── kern.log
├── dmesg
├── apt/
│   ├── history.log
│   └── term.log
├── nginx/
│   ├── access.log
│   └── error.log
└── journal/              # Systemd journald
```

---

## Logrotate (Le Gardien de l'Espace Disque)

### Concept

Logrotate gère automatiquement le cycle de vie des logs :

```text
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  app.log    │ ──► │  app.log.1  │ ──► │ app.log.2.gz│ ──► │  Supprimé   │
│  (actif)    │     │  (hier)     │     │ (compressé) │     │  (rotate 7) │
└─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘
     Rotation           Rotation           Rotation           Rétention
```

| Action | Description |
|--------|-------------|
| **Rotation** | Renomme le fichier actuel (app.log → app.log.1) |
| **Compression** | Compresse les anciens fichiers (.gz) |
| **Rétention** | Supprime les fichiers au-delà de N rotations |

### Configuration

#### Fichier Principal

```bash
# /etc/logrotate.conf

# Rotation hebdomadaire par défaut
weekly

# Garder 4 rotations
rotate 4

# Créer un nouveau fichier après rotation
create

# Compresser les anciens logs
compress

# Inclure les configs spécifiques
include /etc/logrotate.d
```

#### Dossier des Règles

```bash
/etc/logrotate.d/
├── apt
├── dpkg
├── nginx
├── mysql-server
├── rsyslog
└── myapp          # Vos règles custom
```

### Exemple Complet Commenté

```nginx
# /etc/logrotate.d/myapp

/var/log/myapp/*.log {
    # Fréquence de rotation
    daily                   # daily, weekly, monthly, yearly

    # Nombre de fichiers à conserver
    rotate 7                # Garde 7 jours de logs

    # Compression
    compress                # Compresse les anciens fichiers
    delaycompress           # Ne compresse pas le .1 (permet tail -f)

    # Gestion des fichiers manquants/vides
    missingok               # Pas d'erreur si fichier absent
    notifempty              # Ne pas tourner si fichier vide

    # Permissions du nouveau fichier
    create 0640 www-data www-data

    # Rotation par taille (alternative à daily)
    # size 100M             # Tourne si > 100MB
    # maxsize 500M          # Force rotation si > 500MB

    # Script post-rotation
    postrotate
        # Recharger l'app pour qu'elle écrive dans le nouveau fichier
        systemctl reload myapp >/dev/null 2>&1 || true
    endscript

    # Ou pour Nginx
    # postrotate
    #     [ -f /var/run/nginx.pid ] && kill -USR1 $(cat /var/run/nginx.pid)
    # endscript
}
```

### Options Courantes

| Option | Description |
|--------|-------------|
| `daily/weekly/monthly` | Fréquence de rotation |
| `rotate N` | Nombre de fichiers à garder |
| `compress` | Compresse avec gzip |
| `delaycompress` | Compresse à la rotation suivante |
| `missingok` | Ignore si fichier absent |
| `notifempty` | Ne tourne pas si vide |
| `create MODE USER GROUP` | Permissions nouveau fichier |
| `copytruncate` | Copie puis vide (apps sans reload) |
| `size N` | Tourne si taille > N |
| `maxsize N` | Force rotation si > N |
| `dateext` | Suffixe date au lieu de numéro |
| `sharedscripts` | postrotate une seule fois pour tous les fichiers |

### Commandes de Survie

```bash
# Tester la configuration (dry run - ne fait rien)
sudo logrotate -d /etc/logrotate.d/myapp

# Forcer la rotation immédiate
sudo logrotate -f /etc/logrotate.d/myapp

# Verbose (voir ce qui se passe)
sudo logrotate -v /etc/logrotate.conf

# Exécution manuelle complète
sudo logrotate -f /etc/logrotate.conf

# Vérifier le statut (dernières rotations)
cat /var/lib/logrotate/status
```

### Dépannage Logrotate

```bash
# Logrotate ne tourne pas ?

# 1. Vérifier la syntaxe
sudo logrotate -d /etc/logrotate.d/myapp

# 2. Vérifier les permissions
ls -la /var/log/myapp/

# 3. Vérifier le status file
cat /var/lib/logrotate/status | grep myapp

# 4. Forcer une rotation
sudo logrotate -f -v /etc/logrotate.d/myapp

# 5. Vérifier cron
cat /etc/cron.daily/logrotate
```

---

## Consultation Efficace

### Suivre les Logs en Temps Réel

```bash
# tail -f : Suivre un fichier (Ctrl+C pour quitter)
tail -f /var/log/syslog

# Suivre plusieurs fichiers
tail -f /var/log/nginx/*.log

# less +F : Suivre AVEC navigation possible
less +F /var/log/syslog
# Ctrl+C pour arrêter le suivi et naviguer
# Shift+F pour reprendre le suivi

# Avec filtrage (uniquement les erreurs)
tail -f /var/log/syslog | grep --line-buffered "error"
```

### Recherche Rapide

```bash
# Chercher dans un fichier
grep "error" /var/log/syslog
grep -i "error" /var/log/syslog     # Case insensitive

# Chercher récursivement dans tous les logs
grep -r "error" /var/log/

# Avec contexte (3 lignes avant/après)
grep -B3 -A3 "error" /var/log/syslog

# Compter les occurrences
grep -c "Failed password" /var/log/auth.log

# Chercher dans les fichiers compressés
zgrep "error" /var/log/syslog.2.gz

# Chercher dans TOUS les syslog (actuels et archivés)
zgrep "error" /var/log/syslog*
```

### Filtrer par Date/Heure

```bash
# Logs d'aujourd'hui (format Jan 15)
grep "$(date '+%b %e')" /var/log/syslog

# Logs d'une heure spécifique
grep "Jan 15 14:" /var/log/syslog

# Avec journalctl (plus précis)
journalctl --since "2024-01-15 14:00" --until "2024-01-15 15:00"
journalctl --since "1 hour ago"
journalctl --since today
```

### Journalctl (Systemd)

```bash
# Logs d'un service
journalctl -u nginx
journalctl -u nginx --since today

# Suivre en temps réel
journalctl -f
journalctl -fu nginx              # Service spécifique

# Logs kernel
journalctl -k

# Logs de boot actuel
journalctl -b

# Boot précédent
journalctl -b -1

# Par priorité (0=emerg à 7=debug)
journalctl -p err                 # Erreurs et plus grave
journalctl -p warning

# Espace utilisé
journalctl --disk-usage

# Nettoyer les vieux logs
sudo journalctl --vacuum-time=7d  # Garde 7 jours
sudo journalctl --vacuum-size=500M
```

---

## Référence Rapide

```bash
# === FICHIERS CLÉS ===
/var/log/auth.log          # SSH, sudo
/var/log/syslog            # Système général
/var/log/kern.log          # Kernel

# === LOGROTATE ===
/etc/logrotate.conf        # Config principale
/etc/logrotate.d/          # Configs spécifiques

sudo logrotate -d /etc/logrotate.d/myapp   # Test (dry run)
sudo logrotate -f /etc/logrotate.d/myapp   # Forcer

# === CONSULTATION ===
tail -f /var/log/syslog              # Suivre
less +F /var/log/syslog              # Suivre + naviguer
grep -r "error" /var/log/            # Chercher
zgrep "error" /var/log/syslog*.gz    # Dans compressés

# === JOURNALCTL ===
journalctl -fu nginx                 # Suivre service
journalctl --since "1 hour ago"      # Par temps
journalctl -p err                    # Par priorité
```
