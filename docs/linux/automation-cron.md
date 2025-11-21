# Cron & Systemd Timers

`#cron` `#systemd` `#automation` `#scheduling`

Planification de tâches sous Linux : méthode classique et moderne.

---

## Cron (Le Standard)

### Syntaxe de la Crontab

```
┌───────────── minute (0 - 59)
│ ┌───────────── hour (0 - 23)
│ │ ┌───────────── day of month (1 - 31)
│ │ │ ┌───────────── month (1 - 12)
│ │ │ │ ┌───────────── day of week (0 - 6) (Sunday = 0)
│ │ │ │ │
* * * * * command
```

| Champ | Valeurs | Caractères spéciaux |
|-------|---------|---------------------|
| Minute | 0-59 | `*` `,` `-` `/` |
| Hour | 0-23 | `*` `,` `-` `/` |
| Day of Month | 1-31 | `*` `,` `-` `/` |
| Month | 1-12 | `*` `,` `-` `/` |
| Day of Week | 0-6 | `*` `,` `-` `/` |

### Exemples Courants

| Expression | Description |
|------------|-------------|
| `* * * * *` | Chaque minute |
| `0 * * * *` | Chaque heure |
| `0 0 * * *` | Chaque jour à minuit |
| `0 0 * * 0` | Chaque dimanche à minuit |
| `0 0 1 * *` | Premier du mois à minuit |
| `*/15 * * * *` | Toutes les 15 minutes |
| `0 9-17 * * 1-5` | 9h-17h, lundi-vendredi |
| `0 0 1,15 * *` | 1er et 15 du mois |

### Crontab User vs Système

| Type | Commande/Fichier | Utilisateur |
|------|------------------|-------------|
| User | `crontab -e` | Utilisateur courant |
| User | `crontab -e -u john` | Utilisateur spécifique (root) |
| Système | `/etc/crontab` | Spécifié dans la ligne |
| Système | `/etc/cron.d/*` | Spécifié dans la ligne |

```bash
# Crontab utilisateur
crontab -e                    # Éditer
crontab -l                    # Lister
crontab -r                    # Supprimer

# Format /etc/crontab et /etc/cron.d/* (avec USER)
# Min Hour Dom Mon Dow USER Command
0 0 * * * root /usr/local/bin/backup.sh
```

### Répertoires Prédéfinis

```bash
/etc/cron.hourly/    # Scripts exécutés chaque heure
/etc/cron.daily/     # Scripts exécutés chaque jour
/etc/cron.weekly/    # Scripts exécutés chaque semaine
/etc/cron.monthly/   # Scripts exécutés chaque mois
```

### Astuces de Pro

#### Redirection des Logs

```bash
# Capturer stdout ET stderr
* * * * * /opt/scripts/backup.sh >> /var/log/backup.log 2>&1

# Avec timestamp
* * * * * /opt/scripts/backup.sh 2>&1 | while read line; do echo "$(date '+\%Y-\%m-\%d \%H:\%M:\%S') $line"; done >> /var/log/backup.log
```

#### Éviter le Spam Mail

```bash
# En tête de crontab : désactiver les mails
MAILTO=""

# Ou rediriger vers /dev/null
* * * * * /opt/scripts/task.sh > /dev/null 2>&1
```

#### Variables d'Environnement

```bash
# Définir le PATH (cron a un PATH minimal)
PATH=/usr/local/bin:/usr/bin:/bin

# Définir le shell
SHELL=/bin/bash

# Exemple complet
SHELL=/bin/bash
PATH=/usr/local/bin:/usr/bin:/bin
MAILTO=""

0 0 * * * /opt/scripts/backup.sh >> /var/log/backup.log 2>&1
```

---

## Systemd Timers (L'Alternative Moderne)

### Pourquoi Remplacer Cron ?

| Aspect | Cron | Systemd Timer |
|--------|------|---------------|
| Logs | Syslog, difficile à filtrer | Journald natif |
| Précision | Minute | Seconde |
| Dépendances | Aucune | Services systemd |
| Rattrapage | Non | `Persistent=true` |
| Monitoring | `crontab -l` | `systemctl list-timers` |
| Ressources | Aucun contrôle | Cgroups, limits |

### Structure : 2 Fichiers Requis

Un timer systemd nécessite **deux fichiers** :

1. **`.service`** : Définit la tâche à exécuter
2. **`.timer`** : Définit quand l'exécuter

```
/etc/systemd/system/
├── backup.service    # Quoi faire
└── backup.timer      # Quand le faire
```

### Exemple Concret : Backup Quotidien

#### backup.service

```ini
# /etc/systemd/system/backup.service
[Unit]
Description=Daily Backup Script
After=network.target

[Service]
Type=oneshot
ExecStart=/opt/scripts/backup.sh
User=root
StandardOutput=journal
StandardError=journal
```

#### backup.timer

```ini
# /etc/systemd/system/backup.timer
[Unit]
Description=Run backup daily

[Timer]
OnCalendar=daily
# Ou plus précis : OnCalendar=*-*-* 02:00:00
Persistent=true
RandomizedDelaySec=300

[Install]
WantedBy=timers.target
```

### Syntaxe OnCalendar

| Expression | Description |
|------------|-------------|
| `minutely` | Chaque minute |
| `hourly` | Chaque heure |
| `daily` | Chaque jour à 00:00 |
| `weekly` | Chaque lundi à 00:00 |
| `monthly` | Premier du mois à 00:00 |
| `*-*-* 02:00:00` | Chaque jour à 02:00 |
| `Mon *-*-* 09:00:00` | Chaque lundi à 09:00 |
| `*-*-01 00:00:00` | Premier du mois |
| `*:0/15` | Toutes les 15 minutes |

```bash
# Valider une expression
systemd-analyze calendar "Mon *-*-* 09:00:00"

# Output:
#   Original form: Mon *-*-* 09:00:00
#      Next elapse: Mon 2024-01-15 09:00:00 CET
```

### Activer et Gérer

```bash
# Recharger systemd
sudo systemctl daemon-reload

# Activer le timer (pas le service !)
sudo systemctl enable backup.timer
sudo systemctl start backup.timer

# Vérifier
sudo systemctl status backup.timer

# Lister tous les timers
systemctl list-timers --all

# Exécuter manuellement le service
sudo systemctl start backup.service

# Voir les logs
journalctl -u backup.service
journalctl -u backup.service --since today
```

### Options Timer Utiles

```ini
[Timer]
# Exécution calendaire
OnCalendar=*-*-* 02:00:00

# Délai aléatoire (évite les pics)
RandomizedDelaySec=1h

# Rattraper les exécutions manquées
Persistent=true

# Exécution au boot + intervalle
OnBootSec=5min
OnUnitActiveSec=1h
```

---

## Sécurité (SecNumCloud)

### Restreindre l'Accès à Cron

!!! danger "Contrôle d'Accès Cron"
    Par défaut, tous les utilisateurs peuvent créer des crontabs.
    En environnement sécurisé, restreindre via allow/deny.

#### Logique des Fichiers

| Fichier | Existe | Comportement |
|---------|--------|--------------|
| `/etc/cron.allow` | Oui | Seuls les users listés peuvent utiliser cron |
| `/etc/cron.deny` | Oui | Users listés ne peuvent PAS utiliser cron |
| Aucun | - | Tous les users peuvent utiliser cron |

**Priorité :** `cron.allow` est vérifié en premier. S'il existe, `cron.deny` est ignoré.

#### Configuration Recommandée

```bash
# Créer la whitelist (seul root peut utiliser cron)
echo "root" | sudo tee /etc/cron.allow

# Ajouter un utilisateur autorisé
echo "deploy" | sudo tee -a /etc/cron.allow

# Vérifier
cat /etc/cron.allow

# Supprimer cron.deny si présent
sudo rm -f /etc/cron.deny
```

### Audit des Crontabs

```bash
# Lister toutes les crontabs utilisateur
for user in $(cut -f1 -d: /etc/passwd); do
    crontab -l -u $user 2>/dev/null && echo "=== $user ==="
done

# Vérifier les fichiers /etc/cron.d/
ls -la /etc/cron.d/

# Vérifier les répertoires cron.*
ls -la /etc/cron.{hourly,daily,weekly,monthly}/
```

---

## Quick Reference

```bash
# === CRON ===
crontab -e                    # Éditer crontab user
crontab -l                    # Lister
crontab -r                    # Supprimer

# Syntaxe : Min Hour Dom Mon Dow Command
0 2 * * * /opt/scripts/backup.sh >> /var/log/backup.log 2>&1

# === SYSTEMD TIMERS ===
systemctl list-timers         # Lister les timers
systemctl enable backup.timer # Activer
systemctl start backup.timer  # Démarrer
journalctl -u backup.service  # Logs

# Valider expression
systemd-analyze calendar "daily"

# === SÉCURITÉ ===
echo "root" > /etc/cron.allow # Whitelist
```
