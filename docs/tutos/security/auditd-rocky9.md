---
tags:
  - tutos
  - security
  - audit
  - compliance
  - rocky
---

# Auditd sur Rocky Linux 9

Configuration du système d'audit Linux pour la conformité et la sécurité.

| Composant | Version |
|-----------|---------|
| Rocky Linux | 9.x |
| auditd | 3.0+ |

**Durée estimée :** 35 minutes

---

## Concepts

| Terme | Description |
|-------|-------------|
| **auditd** | Démon d'audit |
| **auditctl** | Contrôle en temps réel |
| **ausearch** | Recherche dans les logs |
| **aureport** | Rapports d'audit |
| **Rule** | Règle de surveillance |

---

## 1. Installation

```bash
dnf install -y audit audit-libs

# Version
auditctl -v
```

---

## 2. Configuration principale

```bash
vim /etc/audit/auditd.conf
```

```ini
# Fichier de log
log_file = /var/log/audit/audit.log
log_format = ENRICHED

# Taille max du fichier (Mo)
max_log_file = 50
num_logs = 10
max_log_file_action = ROTATE

# Comportement si disque plein
space_left = 75
space_left_action = SYSLOG
admin_space_left = 50
admin_space_left_action = SUSPEND
disk_full_action = SUSPEND
disk_error_action = SUSPEND

# Buffer
buffer_size = 8192
flush = INCREMENTAL_ASYNC
freq = 50

# Network (optionnel)
# tcp_listen_port = 60
# tcp_max_per_addr = 1
```

---

## 3. Démarrer

```bash
systemctl enable --now auditd

# Statut
auditctl -s
```

---

## 4. Règles d'audit

### Types de règles

| Type | Description |
|------|-------------|
| `-w` | Watch (fichier/répertoire) |
| `-a` | System call |
| `-k` | Key (tag) |

### Fichier de règles

```bash
vim /etc/audit/rules.d/audit.rules
```

### Règles recommandées (CIS)

```bash
cat > /etc/audit/rules.d/cis.rules << 'EOF'
# Supprimer les règles existantes
-D

# Buffer
-b 8192

# Échec de l'audit = shutdown
-f 1

# ===== FICHIERS SENSIBLES =====

# Fichiers d'authentification
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# Sudoers
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

# SSH
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /root/.ssh/ -p wa -k root_ssh

# Cron
-w /etc/crontab -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /etc/cron.daily/ -p wa -k cron
-w /etc/cron.hourly/ -p wa -k cron
-w /etc/cron.monthly/ -p wa -k cron
-w /etc/cron.weekly/ -p wa -k cron
-w /var/spool/cron/ -p wa -k cron

# Réseau
-w /etc/hosts -p wa -k hosts
-w /etc/sysconfig/network -p wa -k network
-w /etc/sysconfig/network-scripts/ -p wa -k network

# Logs
-w /var/log/lastlog -p wa -k logins
-w /var/log/faillock/ -p wa -k logins

# ===== COMMANDES PRIVILEGIÉES =====

# Modification date/heure
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change

# Modification utilisateurs/groupes
-a always,exit -F arch=b64 -S setuid -S setgid -S setreuid -S setregid -k perm_mod
-a always,exit -F arch=b32 -S setuid -S setgid -S setreuid -S setregid -k perm_mod

# Mount
-a always,exit -F arch=b64 -S mount -k mounts
-a always,exit -F arch=b32 -S mount -k mounts

# Suppression de fichiers
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -k delete

# Modules kernel
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules

# ===== BINAIRES PRIVILÉGIÉS =====

-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

# ===== ACCÈS FICHIERS =====

# Accès non autorisé
-a always,exit -F arch=b64 -S open -S openat -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S open -S openat -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access

# ===== SESSIONS =====

-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session

# ===== VERROUILLER LA CONFIG =====
# Décommenter pour empêcher les modifications
# -e 2
EOF
```

### Charger les règles

```bash
augenrules --load
auditctl -l
```

---

## 5. Règles spécifiques

### Surveiller un répertoire

```bash
auditctl -w /etc/nginx/ -p wa -k nginx_config
```

### Surveiller un syscall

```bash
# Exécutions
auditctl -a always,exit -F arch=b64 -S execve -k commands
```

### Surveiller un utilisateur

```bash
auditctl -a always,exit -F arch=b64 -F auid=1001 -k user_1001
```

### Supprimer une règle

```bash
auditctl -d -w /etc/passwd -p wa -k identity
```

---

## 6. Recherche et rapports

### ausearch

```bash
# Par clé
ausearch -k identity

# Par utilisateur
ausearch -ua 1000

# Par date
ausearch --start today

# Par fichier
ausearch -f /etc/passwd

# Format interprété
ausearch -i -k sudoers

# Derniers événements
ausearch -ts recent
```

### aureport

```bash
# Résumé global
aureport

# Authentifications
aureport -au

# Exécutions
aureport -x

# Fichiers modifiés
aureport -f

# Échecs
aureport --failed

# Par clé
aureport -k

# Utilisateurs
aureport -u

# Événements par jour
aureport --summary
```

---

## 7. Analyse des logs

### Format des logs

```
type=SYSCALL msg=audit(1702656000.123:456): arch=c000003e syscall=2 success=yes exit=3
a0=7ffd12345678 items=1 ppid=1234 pid=5678 auid=1000 uid=0 gid=0 euid=0 suid=0
fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm="vim" exe="/usr/bin/vim"
key="identity"
```

### Champs importants

| Champ | Description |
|-------|-------------|
| `auid` | Audit UID (original) |
| `uid` | UID effectif |
| `exe` | Exécutable |
| `key` | Tag de la règle |
| `success` | Succès/échec |

---

## 8. Centralisation (rsyslog)

```bash
vim /etc/audit/plugins.d/syslog.conf
```

```ini
active = yes
direction = out
path = /sbin/audisp-syslog
type = always
args = LOG_INFO
format = string
```

```bash
systemctl restart auditd
```

---

## 9. Audit des conteneurs

```bash
# Podman/Docker
-a always,exit -F arch=b64 -S clone -F a0&0x7C020000 -k container_create
-w /etc/containers/ -p wa -k container_config
-w /var/lib/containers/ -p wa -k container_data
```

---

## 10. Bonnes pratiques

### Performance

```bash
# Vérifier le buffer
auditctl -s | grep lost

# Si pertes, augmenter
auditctl -b 32768
```

### Rotation des logs

```bash
# Rotation manuelle
service auditd rotate
```

### Exclure le bruit

```bash
# Exclure les lectures
-a never,exit -F arch=b64 -S read

# Exclure un utilisateur système
-a never,exit -F auid=systemd-network
```

---

## Commandes utiles

```bash
# Status
auditctl -s

# Lister règles
auditctl -l

# Charger règles
augenrules --load

# Rechercher
ausearch -k <key>

# Rapport
aureport

# Test règle
auditctl -w /tmp/test -p wa -k test
touch /tmp/test
ausearch -k test
```

---

## Dépannage

```bash
# Logs auditd
journalctl -u auditd

# Événements perdus
auditctl -s | grep lost

# Tester les règles
auditctl -l

# Syntaxe
augenrules --check
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
