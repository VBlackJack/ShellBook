---
tags:
  - tutos
  - security
  - audit
  - compliance
  - debian
---

# Auditd sur Debian 12

Configuration du système d'audit sur Debian 12 Bookworm.

| Composant | Version |
|-----------|---------|
| Debian | 12 Bookworm |
| auditd | 3.0+ |

**Durée estimée :** 30 minutes

---

## 1. Installation

```bash
apt update
apt install -y auditd audispd-plugins

auditctl -v
```

---

## 2. Configuration

```bash
vim /etc/audit/auditd.conf
```

```ini
log_file = /var/log/audit/audit.log
log_format = ENRICHED
max_log_file = 50
num_logs = 10
max_log_file_action = ROTATE
space_left_action = SYSLOG
admin_space_left_action = SUSPEND
disk_full_action = SUSPEND
```

---

## 3. Démarrer

```bash
systemctl enable --now auditd
auditctl -s
```

---

## 4. Règles d'audit

```bash
cat > /etc/audit/rules.d/audit.rules << 'EOF'
-D
-b 8192
-f 1

# Fichiers sensibles
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

# SSH
-w /etc/ssh/sshd_config -p wa -k sshd

# Cron
-w /etc/crontab -p wa -k cron
-w /etc/cron.d/ -p wa -k cron

# Temps
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-w /etc/localtime -p wa -k time-change

# Modules
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules

# Commandes privilégiées
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

# Sessions
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session
EOF
```

```bash
augenrules --load
auditctl -l
```

---

## 5. Recherche

```bash
# Par clé
ausearch -k identity

# Par fichier
ausearch -f /etc/passwd

# Format lisible
ausearch -i -k sudoers

# Aujourd'hui
ausearch --start today
```

---

## 6. Rapports

```bash
aureport              # Résumé
aureport -au          # Authentifications
aureport -x           # Exécutions
aureport -f           # Fichiers
aureport --failed     # Échecs
```

---

## 7. Centralisation syslog

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

## Comparatif Rocky vs Debian

| Aspect | Rocky 9 | Debian 12 |
|--------|---------|-----------|
| Package | audit | auditd |
| Plugins | audit-plugins | audispd-plugins |
| Config | /etc/audit/ | /etc/audit/ |

---

## Commandes

```bash
auditctl -s        # Status
auditctl -l        # Lister règles
augenrules --load  # Charger règles
ausearch -k <key>  # Rechercher
aureport           # Rapport
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
