---
tags:
  - systemd
  - systemctl
  - journalctl
  - cheatsheet
  - linux
  - services
---

# Systemd Cheatsheet

Guide de référence complet pour systemd: gestion des services, journaux, units, et timers.

---

## 1. systemctl - Gestion des Services

### Commandes de Base

| Action | Commande | Description |
|--------|----------|-------------|
| **Start** | `systemctl start <service>` | Démarrer un service |
| **Stop** | `systemctl stop <service>` | Arrêter un service |
| **Restart** | `systemctl restart <service>` | Redémarrer un service |
| **Reload** | `systemctl reload <service>` | Recharger la configuration (sans redémarrage) |
| **Status** | `systemctl status <service>` | Voir le statut détaillé |
| **Enable** | `systemctl enable <service>` | Activer au démarrage |
| **Disable** | `systemctl disable <service>` | Désactiver au démarrage |
| **Is-active** | `systemctl is-active <service>` | Vérifier si actif |
| **Is-enabled** | `systemctl is-enabled <service>` | Vérifier si activé au boot |
| **Is-failed** | `systemctl is-failed <service>` | Vérifier si en échec |

```bash
# Gérer nginx
systemctl start nginx
systemctl stop nginx
systemctl restart nginx
systemctl reload nginx  # Recharge config sans couper les connexions

# Activer au démarrage
systemctl enable nginx
systemctl enable --now nginx  # Enable + start en une commande

# Désactiver au démarrage
systemctl disable nginx
systemctl disable --now nginx  # Disable + stop

# Voir le statut
systemctl status nginx
systemctl status nginx -l  # Sans troncature
systemctl status nginx -n 50  # 50 dernières lignes de log

# Vérifications rapides
systemctl is-active nginx    # Retourne: active/inactive
systemctl is-enabled nginx   # Retourne: enabled/disabled
systemctl is-failed nginx    # Retourne: active/failed
```

### Listing des Services

```bash
# Lister tous les services
systemctl list-units --type=service
systemctl list-units --type=service --all  # Incluant inactifs

# Lister seulement les services actifs
systemctl list-units --type=service --state=running

# Lister les services en échec
systemctl list-units --type=service --state=failed
systemctl --failed

# Lister les services activés
systemctl list-unit-files --type=service --state=enabled

# Format simplifié
systemctl list-units --type=service --no-pager
systemctl list-units --type=service -o json

# Filtrer par nom
systemctl list-units 'nginx*'
systemctl list-units '*docker*'
```

### Dépendances & Relations

```bash
# Voir les dépendances d'un service
systemctl list-dependencies nginx
systemctl list-dependencies nginx --all  # Récursif

# Voir ce qui dépend d'un service
systemctl list-dependencies nginx --reverse

# Arbre de dépendances
systemctl list-dependencies --all --after nginx
systemctl list-dependencies --all --before nginx

# Voir les propriétés d'un service
systemctl show nginx
systemctl show nginx -p MainPID,LoadState,ActiveState

# Fichier unit d'un service
systemctl cat nginx
```

---

## 2. Gestion Avancée des Services

### Contrôle des Services

```bash
# Redémarrer seulement si déjà actif
systemctl try-restart nginx

# Recharger ou redémarrer (selon disponibilité)
systemctl reload-or-restart nginx

# Kill processus d'un service
systemctl kill nginx
systemctl kill -s SIGKILL nginx  # Force kill

# Masquer un service (empêche le démarrage)
systemctl mask nginx
systemctl unmask nginx

# Isoler un target (comme changer de runlevel)
systemctl isolate multi-user.target
```

### Reset & Troubleshooting

```bash
# Reset l'état "failed" d'un service
systemctl reset-failed nginx
systemctl reset-failed  # Reset tous

# Recharger la configuration systemd
systemctl daemon-reload

# Re-exécuter les générateurs
systemctl daemon-reexec

# Voir les logs d'erreur d'un service
systemctl status nginx -l
journalctl -u nginx -n 50 --no-pager
```

---

## 3. journalctl - Logs Systemd

### Commandes de Base

| Action | Commande | Description |
|--------|----------|-------------|
| **Tout voir** | `journalctl` | Tous les logs |
| **Service** | `journalctl -u <service>` | Logs d'un service |
| **Follow** | `journalctl -f` | Suivre en temps réel |
| **Dernières N lignes** | `journalctl -n <N>` | N dernières entrées |
| **Depuis X temps** | `journalctl --since "1h ago"` | Depuis 1 heure |
| **Priorité** | `journalctl -p err` | Seulement erreurs |
| **Boot actuel** | `journalctl -b` | Logs du boot actuel |
| **Kernel** | `journalctl -k` | Logs kernel |
| **Format** | `journalctl -o json` | Format JSON |

```bash
# Voir tous les logs
journalctl

# Logs d'un service
journalctl -u nginx
journalctl -u nginx.service

# Suivre en temps réel (follow)
journalctl -f
journalctl -u nginx -f

# Dernières N lignes
journalctl -n 100
journalctl -u nginx -n 50

# Combine follow + tail
journalctl -u nginx -f -n 20
```

### Filtres Temporels

```bash
# Depuis X temps
journalctl --since "1 hour ago"
journalctl --since "2 days ago"
journalctl --since "30 minutes ago"
journalctl --since yesterday
journalctl --since today

# Jusqu'à X temps
journalctl --until "2024-01-01 00:00:00"

# Période spécifique
journalctl --since "2024-01-01" --until "2024-01-31"
journalctl --since "2024-01-15 10:00" --until "2024-01-15 12:00"

# Combiné avec service
journalctl -u nginx --since "1 hour ago"
```

### Filtres par Priorité

```bash
# Priorités (de 0 à 7):
# 0: emerg   - Système inutilisable
# 1: alert   - Action immédiate requise
# 2: crit    - Conditions critiques
# 3: err     - Erreurs
# 4: warning - Avertissements
# 5: notice  - Normal mais significatif
# 6: info    - Informations
# 7: debug   - Debug

# Seulement erreurs et plus critique
journalctl -p err
journalctl -p 3

# Warnings et plus
journalctl -p warning
journalctl -p 4

# Seulement un niveau
journalctl -p err --no-pager
```

### Filtres par Boot

```bash
# Lister les boots
journalctl --list-boots

# Boot actuel
journalctl -b
journalctl -b 0

# Boot précédent
journalctl -b -1

# Boot spécifique
journalctl -b <boot-id>

# Combiner avec service
journalctl -u nginx -b 0
```

### Filtres Avancés

```bash
# Logs du kernel
journalctl -k
journalctl -k -b  # Kernel du boot actuel

# Par PID
journalctl _PID=1234

# Par UID
journalctl _UID=1000

# Par exécutable
journalctl /usr/bin/nginx

# Par unité systemd
journalctl -u nginx -u mysql  # Plusieurs services

# Reverse (du plus récent au plus ancien)
journalctl -r

# Pas de pager (tout afficher)
journalctl --no-pager

# Sans couleur
journalctl --no-pager --no-full
```

### Formats de Sortie

```bash
# Format court (défaut)
journalctl -u nginx -n 10

# Format JSON
journalctl -u nginx -n 10 -o json

# Format JSON-pretty
journalctl -u nginx -n 10 -o json-pretty

# Format export (binaire)
journalctl -u nginx -o export > nginx.journal

# Format cat (seulement les messages)
journalctl -u nginx -o cat

# Format verbose (tous les champs)
journalctl -u nginx -n 5 -o verbose

# Format avec-hostname
journalctl -o short-full
journalctl -o short-iso  # Timestamps ISO 8601
```

### Gestion de l'Espace

```bash
# Voir l'espace utilisé
journalctl --disk-usage

# Nettoyer les logs (garder seulement X)
journalctl --vacuum-time=7d     # Garder 7 jours
journalctl --vacuum-size=500M   # Garder 500 MB max
journalctl --vacuum-files=10    # Garder 10 fichiers max

# Rotation manuelle
journalctl --rotate

# Vérifier les logs
journalctl --verify
```

---

## 4. Unit Files

### Types de Units

| Type | Extension | Description |
|------|-----------|-------------|
| **service** | `.service` | Services et daemons |
| **socket** | `.socket` | Sockets IPC ou réseau |
| **target** | `.target` | Groupes de units (runlevels) |
| **timer** | `.timer` | Timers (cron-like) |
| **mount** | `.mount` | Points de montage |
| **automount** | `.automount` | Montage automatique |
| **device** | `.device` | Périphériques |
| **path** | `.path` | Surveillance de fichiers |
| **slice** | `.slice` | Gestion des ressources |
| **scope** | `.scope` | Processus externes |

### Localisation des Unit Files

```bash
# Chemins des unit files (par ordre de priorité):
# 1. /etc/systemd/system/          (Admin, priorité max)
# 2. /run/systemd/system/          (Runtime)
# 3. /lib/systemd/system/          (Paquets installés)
# 4. /usr/lib/systemd/system/      (Distribution)

# Voir le fichier d'un service
systemctl cat nginx

# Éditer un service (crée un override)
systemctl edit nginx

# Éditer le fichier complet
systemctl edit --full nginx

# Recharger après modification
systemctl daemon-reload
```

### Exemple de Service Unit

```ini
# /etc/systemd/system/myapp.service
[Unit]
Description=My Application
Documentation=https://example.com/docs
After=network.target
Wants=mysql.service
Requires=redis.service

[Service]
Type=simple
User=myapp
Group=myapp
WorkingDirectory=/opt/myapp

# Commandes
ExecStartPre=/opt/myapp/scripts/pre-start.sh
ExecStart=/opt/myapp/bin/myapp --config /etc/myapp/config.yml
ExecReload=/bin/kill -HUP $MAINPID
ExecStop=/opt/myapp/scripts/stop.sh
ExecStopPost=/opt/myapp/scripts/cleanup.sh

# Restart policy
Restart=on-failure
RestartSec=5s
StartLimitBurst=5
StartLimitIntervalSec=60s

# Ressources
MemoryLimit=512M
CPUQuota=50%

# Logs
StandardOutput=journal
StandardError=journal
SyslogIdentifier=myapp

# Security
PrivateTmp=yes
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/myapp /var/log/myapp

[Install]
WantedBy=multi-user.target
```

### Types de Service

```ini
# Type=simple (défaut)
# Le processus spécifié dans ExecStart est le processus principal
[Service]
Type=simple
ExecStart=/usr/bin/myapp

# Type=forking
# Le processus fork et le parent se termine
[Service]
Type=forking
PIDFile=/var/run/myapp.pid
ExecStart=/usr/bin/myapp --daemon

# Type=oneshot
# Pour les scripts qui se terminent (pas de daemon)
[Service]
Type=oneshot
ExecStart=/usr/bin/backup.sh
RemainAfterExit=yes

# Type=notify
# Le service notifie systemd quand il est prêt
[Service]
Type=notify
ExecStart=/usr/bin/myapp

# Type=dbus
# Le service acquiert un nom D-Bus
[Service]
Type=dbus
BusName=com.example.myapp
ExecStart=/usr/bin/myapp

# Type=idle
# Attend que les autres services soient démarrés
[Service]
Type=idle
ExecStart=/usr/bin/myapp
```

### Restart Policies

```ini
[Service]
# Ne jamais redémarrer
Restart=no

# Toujours redémarrer (sauf stop/disable)
Restart=always

# Redémarrer sur erreur ou timeout
Restart=on-failure

# Redémarrer sauf si exit 0
Restart=on-abnormal

# Redémarrer si crash
Restart=on-abort

# Redémarrer si watchdog timeout
Restart=on-watchdog

# Options de restart
RestartSec=5s              # Attendre 5s avant restart
StartLimitBurst=5          # Max 5 restarts
StartLimitIntervalSec=60s  # Dans une fenêtre de 60s
```

---

## 5. Timers (Alternative à Cron)

### Créer un Timer

```ini
# /etc/systemd/system/backup.timer
[Unit]
Description=Daily backup timer
Requires=backup.service

[Timer]
# Déclenchement
OnCalendar=daily
OnCalendar=*-*-* 02:00:00  # Tous les jours à 2h
#OnCalendar=Mon *-*-* 00:00:00  # Tous les lundis
#OnCalendar=*-*-01 00:00:00     # Le 1er de chaque mois

# Ou par intervalle
#OnBootSec=15min     # 15 min après le boot
#OnUnitActiveSec=1d  # 1 jour après dernière exécution

# Options
Persistent=true  # Rattraper les exécutions manquées
AccuracySec=1h   # Précision (économie d'énergie)

[Install]
WantedBy=timers.target
```

```ini
# /etc/systemd/system/backup.service
[Unit]
Description=Backup service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/backup.sh
User=backup
Group=backup
```

### Gestion des Timers

```bash
# Activer un timer
systemctl enable backup.timer
systemctl start backup.timer

# Lister les timers
systemctl list-timers
systemctl list-timers --all

# Status d'un timer
systemctl status backup.timer

# Voir quand un timer va se déclencher
systemctl list-timers backup.timer

# Logs d'un timer
journalctl -u backup.timer
journalctl -u backup.service

# Tester le service manuellement
systemctl start backup.service
```

### Exemples de Calendrier

```ini
# Syntaxe OnCalendar
# Format: DOW YYYY-MM-DD HH:MM:SS

# Toutes les heures
OnCalendar=hourly
OnCalendar=*-*-* *:00:00

# Tous les jours à 3h30
OnCalendar=daily
OnCalendar=*-*-* 03:30:00

# Toutes les semaines (dimanche 00:00)
OnCalendar=weekly
OnCalendar=Sun *-*-* 00:00:00

# Tous les mois (1er à 00:00)
OnCalendar=monthly
OnCalendar=*-*-01 00:00:00

# Tous les lundis à 9h
OnCalendar=Mon *-*-* 09:00:00

# Du lundi au vendredi à 8h et 18h
OnCalendar=Mon..Fri *-*-* 08,18:00:00

# Toutes les 15 minutes
OnCalendar=*:0/15

# Exemples complexes
OnCalendar=Mon,Tue,Wed,Thu,Fri *-*-* 09:00:00  # Semaine à 9h
OnCalendar=*-*-* 09:00:00,12:00:00,18:00:00    # 3x par jour
OnCalendar=*-01,04,07,10-01 00:00:00            # Trimestriel

# Vérifier une expression
systemd-analyze calendar "Mon *-*-* 09:00:00"
systemd-analyze calendar weekly
```

---

## 6. Targets (Runlevels)

### Targets Courants

| Target | Équivalent Runlevel | Description |
|--------|-------------------|-------------|
| `poweroff.target` | 0 | Éteindre |
| `rescue.target` | 1 | Mode rescue (single user) |
| `multi-user.target` | 3 | Multi-utilisateur (sans GUI) |
| `graphical.target` | 5 | Multi-utilisateur avec GUI |
| `reboot.target` | 6 | Redémarrer |

```bash
# Voir le target actuel
systemctl get-default

# Changer le target par défaut
systemctl set-default multi-user.target
systemctl set-default graphical.target

# Isoler un target (équivalent à changer de runlevel)
systemctl isolate multi-user.target
systemctl isolate graphical.target

# Lister les targets
systemctl list-units --type=target

# Éteindre/Redémarrer
systemctl poweroff
systemctl reboot
systemctl suspend
systemctl hibernate
systemctl hybrid-sleep
```

---

## 7. Analyse & Debug

### systemd-analyze

```bash
# Temps de boot
systemd-analyze

# Temps par service
systemd-analyze blame

# Chaîne critique (chemin le plus long)
systemd-analyze critical-chain

# Graphe de démarrage (DOT format)
systemd-analyze dot | dot -Tsvg > boot.svg

# Graphe d'un service spécifique
systemd-analyze dot nginx | dot -Tpng > nginx.png

# Vérifier la syntaxe d'un unit file
systemd-analyze verify /etc/systemd/system/myapp.service

# Analyser une expression calendar
systemd-analyze calendar "Mon *-*-* 09:00:00"

# Voir la configuration systemd
systemd-analyze cat-config systemd/system.conf

# Dump de la configuration
systemd-analyze dump
```

### Debugging

```bash
# Verbose status
systemctl status nginx -l --no-pager

# Voir les logs d'erreur
journalctl -u nginx -p err -n 50

# Debug d'un service qui ne démarre pas
systemctl status myapp -l
journalctl -u myapp -xe

# Vérifier les dépendances
systemctl list-dependencies myapp --all

# Voir pourquoi un service a échoué
systemctl status myapp
journalctl -u myapp --since "5 minutes ago"

# Tracer l'exécution d'un service
systemd-run --unit=test --setenv=SYSTEMD_LOG_LEVEL=debug /usr/bin/myapp

# Voir les propriétés
systemctl show myapp

# Vérifier le fichier unit
systemctl cat myapp
systemd-analyze verify /etc/systemd/system/myapp.service
```

---

## 8. Gestion des Ressources (cgroups)

### Limites de Ressources

```ini
# Dans le unit file [Service]

# CPU
CPUQuota=50%           # 50% d'un core
CPUShares=1024         # Poids relatif (défaut: 1024)
CPUAffinity=0,1        # Cores 0 et 1

# Mémoire
MemoryLimit=512M       # Limite mémoire (deprecated, utiliser MemoryMax)
MemoryMax=512M         # Limite mémoire stricte
MemoryHigh=400M        # Seuil avant throttling
MemorySwapMax=1G       # Limite swap

# IO
IOWeight=100           # Poids IO (10-1000, défaut: 100)
IOReadBandwidthMax=/dev/sda 10M   # Limite lecture
IOWriteBandwidthMax=/dev/sda 5M   # Limite écriture

# Tasks/Processus
TasksMax=100           # Max 100 processus/threads

# Fichiers
LimitNOFILE=65536      # Max file descriptors
```

### Slices (Groupement)

```bash
# Voir les slices
systemctl -t slice

# Slices par défaut:
# - system.slice     (services système)
# - user.slice       (sessions utilisateur)
# - machine.slice    (VMs/containers)

# Créer une slice personnalisée
# /etc/systemd/system/app.slice
[Unit]
Description=Application slice

[Slice]
MemoryMax=2G
CPUQuota=200%

# Utiliser la slice dans un service
[Service]
Slice=app.slice
```

---

## 9. Sécurité & Isolation

### Options de Sécurité

```ini
# Dans [Service]

# Utilisateur/Groupe
User=myapp
Group=myapp
DynamicUser=yes        # Créer user temporaire

# Filesystem
PrivateTmp=yes         # /tmp isolé
ProtectSystem=strict   # Filesystem en lecture seule
ProtectHome=yes        # /home inaccessible
ReadOnlyPaths=/etc /usr
ReadWritePaths=/var/lib/myapp
InaccessiblePaths=/root

# Réseau
PrivateNetwork=yes     # Réseau isolé
RestrictAddressFamilies=AF_INET AF_INET6  # Seulement IPv4/IPv6

# Capabilities
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes    # Pas de setuid

# Namespaces
PrivateDevices=yes     # /dev isolé
PrivateUsers=yes       # User namespace
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes

# Syscalls
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources

# Ressources
RestrictRealtime=yes
LockPersonality=yes
RestrictSUIDSGID=yes
```

### Sandbox Complet

```ini
[Service]
# Isolation maximale
Type=simple
User=nobody
Group=nogroup
DynamicUser=yes

# Filesystem
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ReadOnlyPaths=/

# Réseau
PrivateNetwork=yes

# Capabilities
NoNewPrivileges=yes
CapabilityBoundingSet=

# Syscalls
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources
SystemCallErrorNumber=EPERM

# Autres
RestrictRealtime=yes
RestrictAddressFamilies=AF_UNIX
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictNamespaces=yes
```

---

## 10. Tips & Commandes Utiles

### Raccourcis Pratiques

```bash
# Reboot
systemctl reboot
reboot

# Poweroff
systemctl poweroff
poweroff

# Suspend
systemctl suspend

# Hibernate
systemctl hibernate

# Liste compacte des services
systemctl list-units --type=service --no-pager | grep running

# Services en erreur
systemctl --failed

# Reset tous les services en erreur
systemctl reset-failed

# Voir les logs boot actuel
journalctl -b

# Logs depuis le dernier boot
journalctl -b -1

# Suivre tous les logs
journalctl -f

# Logs d'un user spécifique
journalctl _UID=1000
```

### Alias Utiles

```bash
# Ajouter dans ~/.bashrc ou ~/.zshrc

alias sc='systemctl'
alias scs='systemctl status'
alias scr='systemctl restart'
alias sce='systemctl enable'
alias scd='systemctl disable'
alias jc='journalctl'
alias jcf='journalctl -f'
alias jcu='journalctl -u'
alias scf='systemctl --failed'
alias scdr='systemctl daemon-reload'
```

### One-liners

```bash
# Lister les services les plus lents au boot
systemd-analyze blame | head -20

# Trouver les services qui ont crashé
systemctl list-units --state=failed

# Redémarrer tous les services en échec
systemctl reset-failed
for service in $(systemctl list-units --failed --no-legend | awk '{print $1}'); do
  systemctl restart "$service"
done

# Taille des logs par service
journalctl --disk-usage
for service in $(systemctl list-units --type=service --no-legend | awk '{print $1}'); do
  echo "$service: $(journalctl -u $service --disk-usage 2>/dev/null | grep -oP '\d+\.\d+[KMGT]')"
done | sort -hrk2

# Export logs JSON
journalctl -u nginx -o json-pretty --since today > nginx-logs.json
```

---

## Ressources Complémentaires

- **Documentation officielle**: https://www.freedesktop.org/wiki/Software/systemd/
- **systemd for Administrators**: https://www.freedesktop.org/wiki/Software/systemd/
- **ArchWiki systemd**: https://wiki.archlinux.org/title/Systemd
- **Red Hat systemd Guide**: https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html/configuring_basic_system_settings/assembly_working-with-systemd-unit-files_configuring-basic-system-settings

!!! tip "Aller Plus Loin"
    - Explorez **systemd-nspawn** pour les containers
    - Utilisez **systemd.resource-control** pour la gestion fine des ressources
    - Apprenez **systemd socket activation** pour l'optimisation
    - Maîtrisez **systemd-tmpfiles** pour la gestion des fichiers temporaires
