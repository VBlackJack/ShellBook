---
tags:
  - formation
  - linux
  - cron
  - automation
  - systemd-timers
---

# Module 10 : Automatisation & Planification

## Objectifs du Module

À l'issue de ce module, vous serez capable de :

- Planifier des tâches avec cron
- Utiliser systemd timers comme alternative moderne
- Créer des scripts de maintenance automatisés
- Gérer les logs et la rotation

**Durée :** 8 heures

**Niveau :** Administration

---

## 1. Cron

### Syntaxe Crontab

```text
┌───────────── minute (0-59)
│ ┌───────────── heure (0-23)
│ │ ┌───────────── jour du mois (1-31)
│ │ │ ┌───────────── mois (1-12)
│ │ │ │ ┌───────────── jour de la semaine (0-6, 0=dimanche)
│ │ │ │ │
* * * * * commande
```

### Valeurs Spéciales

| Symbole | Signification |
|---------|---------------|
| `*` | Toutes les valeurs |
| `*/5` | Toutes les 5 unités |
| `1,15` | Aux valeurs 1 et 15 |
| `1-5` | De 1 à 5 |

### Exemples

```bash
# Toutes les 5 minutes
*/5 * * * * /script.sh

# Tous les jours à 2h30
30 2 * * * /backup.sh

# Lundi à 8h
0 8 * * 1 /report.sh

# Premier du mois à minuit
0 0 1 * * /monthly.sh

# Dimanche à 3h
0 3 * * 0 /cleanup.sh
```

### Gestion des Crontabs

```bash
# Éditer
crontab -e

# Lister
crontab -l

# Supprimer
crontab -r

# Éditer pour un autre utilisateur (root)
sudo crontab -u alice -e

# Fichiers système
/etc/crontab           # Crontab système
/etc/cron.d/           # Fragments
/etc/cron.daily/       # Scripts quotidiens
/etc/cron.weekly/      # Scripts hebdomadaires
/etc/cron.monthly/     # Scripts mensuels
```

### Bonnes Pratiques

```bash
# Rediriger les sorties
*/5 * * * * /script.sh >> /var/log/script.log 2>&1

# Variable d'environnement
SHELL=/bin/bash
PATH=/usr/local/bin:/usr/bin:/bin
MAILTO=admin@example.com

0 2 * * * /backup.sh

# Lock pour éviter les exécutions parallèles
*/5 * * * * flock -n /tmp/script.lock /script.sh
```

---

## 2. Systemd Timers

### Avantages sur Cron

- Logs centralisés (journald)
- Dépendances entre unités
- Gestion fine des ressources
- Calcul du temps manqué

### Créer un Timer

```bash
# Service (/etc/systemd/system/backup.service)
[Unit]
Description=Daily Backup

[Service]
Type=oneshot
ExecStart=/opt/scripts/backup.sh
```

```bash
# Timer (/etc/systemd/system/backup.timer)
[Unit]
Description=Run backup daily

[Timer]
OnCalendar=*-*-* 02:00:00
Persistent=true

[Install]
WantedBy=timers.target
```

```bash
# Activer
sudo systemctl daemon-reload
sudo systemctl enable --now backup.timer

# Vérifier
systemctl list-timers
journalctl -u backup.service
```

### Syntaxe OnCalendar

```bash
OnCalendar=daily              # Tous les jours à minuit
OnCalendar=weekly             # Chaque lundi à minuit
OnCalendar=*-*-* 02:30:00     # Tous les jours à 2h30
OnCalendar=Mon *-*-* 08:00:00 # Lundis à 8h
OnCalendar=*-*-01 00:00:00    # Premier du mois
```

---

## 3. Scripts de Maintenance

### Exemple : Nettoyage de Logs

```bash
#!/bin/bash
# /opt/scripts/cleanup-logs.sh

set -euo pipefail

LOG_DIR="/var/log"
DAYS=30
LOG_FILE="/var/log/cleanup.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_FILE"
}

log "Début du nettoyage"

# Supprimer les vieux logs
find "$LOG_DIR" -name "*.log" -type f -mtime +$DAYS -delete
find "$LOG_DIR" -name "*.gz" -type f -mtime +$DAYS -delete

# Vider les gros fichiers sans les supprimer
for file in "$LOG_DIR"/*.log; do
    if [[ -f "$file" ]] && [[ $(stat -c%s "$file") -gt 100000000 ]]; then
        log "Truncating: $file"
        : > "$file"
    fi
done

log "Nettoyage terminé"
```

### Exemple : Backup avec Rotation

```bash
#!/bin/bash
# /opt/scripts/backup.sh

set -euo pipefail

SOURCE="/var/www"
DEST="/backup"
DATE=$(date +%Y%m%d)
KEEP_DAYS=7

# Créer le backup
tar -czf "${DEST}/backup_${DATE}.tar.gz" "$SOURCE"

# Rotation
find "$DEST" -name "backup_*.tar.gz" -mtime +$KEEP_DAYS -delete

echo "Backup completed: backup_${DATE}.tar.gz"
```

---

## 4. Logrotate

### Configuration

```bash
# /etc/logrotate.d/myapp
/var/log/myapp/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0640 appuser appgroup
    postrotate
        systemctl reload myapp
    endscript
}
```

### Options Courantes

| Option | Description |
|--------|-------------|
| `daily/weekly/monthly` | Fréquence |
| `rotate 7` | Garder 7 versions |
| `compress` | Compresser les anciens |
| `delaycompress` | Compresser à la rotation suivante |
| `missingok` | Pas d'erreur si fichier absent |
| `notifempty` | Ne pas tourner si vide |
| `copytruncate` | Copier puis tronquer |

```bash
# Tester
sudo logrotate -d /etc/logrotate.d/myapp

# Forcer
sudo logrotate -f /etc/logrotate.d/myapp
```

---

## 5. Exercice Pratique

!!! example "Exercice : Automatisation Complète"

    1. Créer un script de monitoring qui enregistre l'usage CPU/RAM toutes les 5 minutes
    2. Configurer un cron pour l'exécuter
    3. Convertir en systemd timer
    4. Configurer logrotate pour les logs générés

    **Durée estimée :** 35 minutes

---

## 6. Solution

??? quote "Solution"

    ```bash
    # 1. Script de monitoring
    sudo tee /opt/scripts/monitor.sh << 'EOF'
    #!/bin/bash
    DATE=$(date '+%Y-%m-%d %H:%M:%S')
    CPU=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}')
    MEM=$(free -m | awk '/Mem:/ {printf "%.1f", $3/$2*100}')
    echo "$DATE CPU:${CPU}% MEM:${MEM}%" >> /var/log/monitor.log
    EOF
    sudo chmod +x /opt/scripts/monitor.sh

    # 2. Cron
    echo "*/5 * * * * /opt/scripts/monitor.sh" | sudo crontab -

    # 3. Systemd timer
    sudo tee /etc/systemd/system/monitor.service << 'EOF'
    [Unit]
    Description=System Monitor
    [Service]
    Type=oneshot
    ExecStart=/opt/scripts/monitor.sh
    EOF

    sudo tee /etc/systemd/system/monitor.timer << 'EOF'
    [Unit]
    Description=Run monitor every 5 minutes
    [Timer]
    OnBootSec=1min
    OnUnitActiveSec=5min
    [Install]
    WantedBy=timers.target
    EOF

    sudo systemctl daemon-reload
    sudo systemctl enable --now monitor.timer

    # 4. Logrotate
    sudo tee /etc/logrotate.d/monitor << 'EOF'
    /var/log/monitor.log {
        daily
        rotate 7
        compress
        missingok
        notifempty
    }
    EOF
    ```

---

## Félicitations !

Vous avez terminé le **Niveau 2 - Administration Système** !

Vous maîtrisez maintenant :

- La gestion des paquets (APT/DNF)
- Les processus et services (systemd)
- Le stockage et LVM
- La configuration réseau
- L'automatisation des tâches

**Prochaine étape :** Le Niveau 3 - Ingénierie Système !

[:octicons-arrow-right-24: Module 11 : Sécurité & Hardening](11-securite.md)

---

**Retour au :** [Programme de la Formation](index.md)

---

## Navigation

| | |
|:---|---:|
| [← Module 9 : Réseau Fondamental](09-reseau.md) | [Module 11 : Sécurité & Hardening →](11-securite.md) |

[Retour au Programme](index.md){ .md-button }
