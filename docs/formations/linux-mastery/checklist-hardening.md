---
tags:
  - formation
  - linux
  - securite
  - hardening
  - checklist
---

# Checklist Hardening Linux

Checklist complète pour sécuriser un serveur Linux en production.

---

## 1. Installation et Partitionnement

### Partitions Séparées

- [ ] `/` - Système racine
- [ ] `/boot` - Fichiers de boot (500 MB - 1 GB)
- [ ] `/home` - Données utilisateurs
- [ ] `/var` - Logs et données variables
- [ ] `/var/log` - Logs (séparé si possible)
- [ ] `/tmp` - Fichiers temporaires
- [ ] `/var/tmp` - Temporaires persistants
- [ ] `swap` - Espace d'échange

### Options de Montage Sécurisées

```bash
# /etc/fstab - Options recommandées
/dev/mapper/vg-home  /home     ext4  defaults,nodev,nosuid           0 2
/dev/mapper/vg-tmp   /tmp      ext4  defaults,nodev,nosuid,noexec    0 2
/dev/mapper/vg-var   /var      ext4  defaults,nodev,nosuid           0 2
tmpfs                /dev/shm  tmpfs defaults,nodev,nosuid,noexec    0 0
```

| Option | Description |
|--------|-------------|
| `nodev` | Pas de fichiers device |
| `nosuid` | Ignorer SUID/SGID |
| `noexec` | Pas d'exécution |

---

## 2. Mises à Jour

### Système à Jour

- [ ] Tous les paquets mis à jour
- [ ] Mises à jour de sécurité automatiques configurées
- [ ] Kernel à jour

```bash
# RHEL/Rocky
sudo dnf update -y
sudo dnf install dnf-automatic
sudo systemctl enable --now dnf-automatic.timer

# Ubuntu
sudo apt update && sudo apt upgrade -y
sudo apt install unattended-upgrades
sudo dpkg-reconfigure unattended-upgrades
```

---

## 3. Comptes Utilisateurs

### Politique de Mots de Passe

- [ ] Longueur minimale : 12 caractères
- [ ] Complexité requise
- [ ] Expiration configurée
- [ ] Historique des mots de passe

```bash
# /etc/security/pwquality.conf
minlen = 12
minclass = 3
maxrepeat = 3
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1

# /etc/login.defs
PASS_MAX_DAYS   90
PASS_MIN_DAYS   7
PASS_WARN_AGE   14
```

### Comptes

- [ ] Root désactivé pour login direct
- [ ] Comptes inutilisés supprimés/désactivés
- [ ] Shells appropriés (`/sbin/nologin` pour services)
- [ ] UID 0 uniquement pour root

```bash
# Vérifier les comptes avec UID 0
awk -F: '($3 == 0) {print}' /etc/passwd

# Verrouiller un compte
sudo usermod -L username
sudo passwd -l username

# Shell nologin pour service
sudo usermod -s /sbin/nologin serviceuser
```

### Sudo

- [ ] Utilisateurs autorisés uniquement
- [ ] Logs sudo activés
- [ ] Timeout configuré
- [ ] Pas de NOPASSWD sauf nécessité absolue

```bash
# /etc/sudoers.d/hardening
Defaults    logfile="/var/log/sudo.log"
Defaults    log_input, log_output
Defaults    timestamp_timeout=5
Defaults    passwd_tries=3
```

---

## 4. SSH

### Configuration sshd_config

- [ ] Port changé (optionnel mais recommandé)
- [ ] PermitRootLogin no
- [ ] PasswordAuthentication no
- [ ] Authentification par clé uniquement
- [ ] Protocole 2 uniquement
- [ ] AllowUsers/AllowGroups configuré
- [ ] MaxAuthTries limité

```bash
# /etc/ssh/sshd_config
Port 2222
Protocol 2
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
MaxAuthTries 3
MaxSessions 2
ClientAliveInterval 300
ClientAliveCountMax 2
AllowUsers admin deploy
X11Forwarding no
PermitEmptyPasswords no
HostbasedAuthentication no
IgnoreRhosts yes
LoginGraceTime 60
Banner /etc/issue.net

# Algorithmes modernes
KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
```

### Clés SSH

- [ ] Clés Ed25519 ou RSA 4096 bits
- [ ] Passphrase sur les clés
- [ ] Permissions correctes sur ~/.ssh

```bash
# Générer clé sécurisée
ssh-keygen -t ed25519 -C "user@host"

# Permissions
chmod 700 ~/.ssh
chmod 600 ~/.ssh/id_ed25519
chmod 644 ~/.ssh/id_ed25519.pub
chmod 600 ~/.ssh/authorized_keys
```

---

## 5. Firewall

### Configuration

- [ ] Firewall activé (firewalld ou ufw)
- [ ] Politique par défaut : DROP
- [ ] Seuls les ports nécessaires ouverts
- [ ] Règles spécifiques par source IP si possible

```bash
# firewalld (RHEL/Rocky)
sudo firewall-cmd --set-default-zone=drop
sudo firewall-cmd --add-service=ssh --permanent
sudo firewall-cmd --add-rich-rule='rule family="ipv4" source address="10.0.0.0/8" port port="22" protocol="tcp" accept' --permanent
sudo firewall-cmd --reload

# ufw (Ubuntu)
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow from 10.0.0.0/8 to any port 22
sudo ufw enable
```

### Fail2ban

- [ ] Installé et configuré
- [ ] Protection SSH activée
- [ ] Temps de ban approprié

```bash
# /etc/fail2ban/jail.local
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 3

[sshd]
enabled = true
port = 2222
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
```

---

## 6. SELinux / AppArmor

### SELinux (RHEL/Rocky)

- [ ] Mode Enforcing
- [ ] Booleans configurés
- [ ] Contextes corrects

```bash
# Vérifier
getenforce
sestatus

# Activer
sudo setenforce 1
# /etc/selinux/config → SELINUX=enforcing

# Booleans courants
sudo setsebool -P httpd_can_network_connect on
sudo setsebool -P httpd_can_network_connect_db on
```

### AppArmor (Ubuntu)

- [ ] Activé
- [ ] Profils en mode enforce

```bash
sudo aa-status
sudo aa-enforce /etc/apparmor.d/*
```

---

## 7. Services

### Minimisation

- [ ] Services inutiles désactivés
- [ ] Ports d'écoute vérifiés

```bash
# Lister les services actifs
systemctl list-units --type=service --state=running

# Services à désactiver (si non utilisés)
sudo systemctl disable --now cups
sudo systemctl disable --now avahi-daemon
sudo systemctl disable --now bluetooth
sudo systemctl disable --now rpcbind

# Vérifier les ports ouverts
ss -tuln
```

---

## 8. Permissions Fichiers

### Fichiers Critiques

- [ ] /etc/passwd : 644
- [ ] /etc/shadow : 000 ou 600
- [ ] /etc/group : 644
- [ ] /etc/gshadow : 000 ou 600
- [ ] /etc/ssh/sshd_config : 600
- [ ] Clés SSH privées : 600

```bash
chmod 644 /etc/passwd
chmod 600 /etc/shadow
chmod 644 /etc/group
chmod 600 /etc/gshadow
chmod 600 /etc/ssh/sshd_config
```

### SUID/SGID

- [ ] Fichiers SUID/SGID audités
- [ ] Fichiers world-writable audités

```bash
# Trouver les SUID
find / -perm -4000 -type f 2>/dev/null

# Trouver les SGID
find / -perm -2000 -type f 2>/dev/null

# Trouver les world-writable
find / -type f -perm -0002 2>/dev/null
find / -type d -perm -0002 2>/dev/null
```

---

## 9. Paramètres Kernel (sysctl)

```bash
# /etc/sysctl.d/99-hardening.conf

# Réseau
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_syncookies = 1

# IPv6 (si non utilisé)
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1

# Kernel
kernel.randomize_va_space = 2
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 1
fs.suid_dumpable = 0

# Appliquer
sudo sysctl --system
```

---

## 10. Audit et Logging

### Auditd

- [ ] Installé et activé
- [ ] Règles configurées pour fichiers critiques

```bash
# /etc/audit/rules.d/hardening.rules

# Fichiers d'authentification
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

# SSH
-w /etc/ssh/sshd_config -p wa -k sshd

# Commandes privilégiées
-a always,exit -F path=/usr/bin/sudo -F perm=x -F apts auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

# Modules kernel
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
```

### Logging

- [ ] rsyslog ou journald configuré
- [ ] Logs envoyés vers serveur central (optionnel)
- [ ] Rotation des logs configurée

```bash
# Vérifier journald
journalctl --disk-usage

# /etc/systemd/journald.conf
[Journal]
Storage=persistent
Compress=yes
SystemMaxUse=500M
MaxFileSec=1month
```

---

## 11. Bannières

- [ ] Bannière de connexion configurée
- [ ] Avertissement légal

```bash
# /etc/issue.net (SSH)
# /etc/issue (console)
******************************************************************
*                    AUTHORIZED ACCESS ONLY                       *
*                                                                  *
* This system is for authorized users only. All activities are    *
* logged and monitored. Unauthorized access is prohibited.         *
******************************************************************

# Activer dans sshd_config
Banner /etc/issue.net
```

---

## 12. Désactiver les Fonctionnalités Inutiles

```bash
# Core dumps
echo "* hard core 0" >> /etc/security/limits.conf
echo "fs.suid_dumpable = 0" >> /etc/sysctl.d/99-hardening.conf

# USB storage (si non nécessaire)
echo "install usb-storage /bin/false" >> /etc/modprobe.d/disable-usb.conf
echo "blacklist usb-storage" >> /etc/modprobe.d/disable-usb.conf

# Protocoles réseau inutiles
echo "install dccp /bin/false" >> /etc/modprobe.d/disable-protocols.conf
echo "install sctp /bin/false" >> /etc/modprobe.d/disable-protocols.conf
echo "install rds /bin/false" >> /etc/modprobe.d/disable-protocols.conf
echo "install tipc /bin/false" >> /etc/modprobe.d/disable-protocols.conf
```

---

## 13. Backup et Recovery

- [ ] Stratégie de backup documentée
- [ ] Backups testés régulièrement
- [ ] Plan de disaster recovery

```bash
# Backup de configuration
tar -czvf /backup/etc-$(date +%Y%m%d).tar.gz /etc

# Liste des paquets installés
rpm -qa > /backup/packages-$(date +%Y%m%d).txt  # RHEL
dpkg --get-selections > /backup/packages-$(date +%Y%m%d).txt  # Ubuntu
```

---

## 14. Scan de Sécurité

### OpenSCAP

```bash
# Installation
sudo dnf install openscap-scanner scap-security-guide

# Scan CIS
sudo oscap xccdf eval \
    --profile xccdf_org.ssgproject.content_profile_cis \
    --results scan-results.xml \
    --report scan-report.html \
    /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml
```

### Lynis

```bash
# Installation
sudo dnf install lynis

# Audit
sudo lynis audit system
```

---

## 15. Vérification Finale

```bash
#!/bin/bash
# Script de vérification basique

echo "=== Vérification Hardening ==="

echo -n "SELinux/AppArmor: "
if command -v getenforce &>/dev/null; then
    getenforce
elif command -v aa-status &>/dev/null; then
    aa-status --enabled && echo "Enabled"
fi

echo -n "Firewall: "
systemctl is-active firewalld 2>/dev/null || systemctl is-active ufw 2>/dev/null

echo -n "SSH Root Login: "
grep "^PermitRootLogin" /etc/ssh/sshd_config

echo -n "SSH Password Auth: "
grep "^PasswordAuthentication" /etc/ssh/sshd_config

echo -n "Fail2ban: "
systemctl is-active fail2ban

echo -n "Auditd: "
systemctl is-active auditd

echo -n "Kernel Hardening: "
sysctl kernel.randomize_va_space

echo "=== Ports ouverts ==="
ss -tuln

echo "=== Mises à jour disponibles ==="
dnf check-update 2>/dev/null | head -5 || apt list --upgradable 2>/dev/null | head -5
```

---

## Ressources

- **CIS Benchmarks** : [cisecurity.org](https://www.cisecurity.org/cis-benchmarks)
- **NIST** : [nist.gov](https://www.nist.gov/)
- **ANSSI** : [ssi.gouv.fr](https://www.ssi.gouv.fr/)
- **OpenSCAP** : [open-scap.org](https://www.open-scap.org/)

---

**Retour au :** [Programme de la Formation](index.md)
