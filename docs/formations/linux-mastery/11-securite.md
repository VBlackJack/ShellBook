---
tags:
  - formation
  - linux
  - security
  - hardening
  - ssh
  - firewall
  - selinux
---

# Module 11 : Sécurité & Hardening

## Objectifs du Module

À l'issue de ce module, vous serez capable de :

- Sécuriser SSH et les accès distants
- Configurer sudo et les privilèges
- Mettre en place un firewall (firewalld/ufw)
- Comprendre et configurer SELinux/AppArmor
- Auditer et durcir un système

**Durée :** 10 heures

**Niveau :** Ingénierie

---

## 1. Sécurisation SSH

### Configuration Sécurisée

```bash
# /etc/ssh/sshd_config
Port 2222                          # Changer le port par défaut
PermitRootLogin no                 # Interdire root
PasswordAuthentication no          # Clés uniquement
PubkeyAuthentication yes
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
AllowUsers alice bob               # Whitelist
Protocol 2

# Algorithmes modernes
KexAlgorithms curve25519-sha256@libssh.org
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com
```

```bash
# Appliquer
sudo sshd -t                       # Tester la config
sudo systemctl restart sshd
```

### Clés SSH

```bash
# Générer une clé Ed25519 (recommandé)
ssh-keygen -t ed25519 -C "alice@example.com"

# Copier sur le serveur
ssh-copy-id -i ~/.ssh/id_ed25519.pub user@server

# Permissions
chmod 700 ~/.ssh
chmod 600 ~/.ssh/id_ed25519
chmod 644 ~/.ssh/id_ed25519.pub
chmod 600 ~/.ssh/authorized_keys
```

### Fail2ban

```bash
# Installation
sudo apt install fail2ban    # Debian/Ubuntu
sudo dnf install fail2ban    # RHEL/Rocky

# Configuration
sudo tee /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 3

[sshd]
enabled = true
port = 2222
filter = sshd
logpath = /var/log/auth.log
EOF

sudo systemctl enable --now fail2ban
sudo fail2ban-client status sshd
```

---

## 2. Gestion des Privilèges (sudo)

### Configuration Sécurisée

```bash
# /etc/sudoers.d/admins
# Toujours éditer avec visudo !

# Groupe admins avec tous les droits
%admins ALL=(ALL:ALL) ALL

# Commandes spécifiques sans mot de passe
%developers ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart nginx
%developers ALL=(ALL) NOPASSWD: /usr/bin/docker *

# Logging amélioré
Defaults logfile="/var/log/sudo.log"
Defaults log_input, log_output
Defaults timestamp_timeout=5
```

```bash
sudo visudo -f /etc/sudoers.d/admins
sudo visudo -c  # Vérifier la syntaxe
```

### Principe du Moindre Privilège

```bash
# Créer un utilisateur applicatif sans shell
sudo useradd -r -s /usr/sbin/nologin appuser

# Permissions minimales
sudo chown -R appuser:appuser /opt/myapp
sudo chmod 750 /opt/myapp
```

---

## 3. Firewall

### Firewalld (RHEL/Rocky)

```bash
# Statut
sudo firewall-cmd --state
sudo firewall-cmd --list-all

# Zones
sudo firewall-cmd --get-zones
sudo firewall-cmd --get-default-zone
sudo firewall-cmd --set-default-zone=public

# Ouvrir un port
sudo firewall-cmd --add-port=8080/tcp --permanent
sudo firewall-cmd --add-service=https --permanent
sudo firewall-cmd --reload

# Rich rules
sudo firewall-cmd --add-rich-rule='rule family="ipv4" source address="192.168.1.0/24" port port="22" protocol="tcp" accept' --permanent
```

### UFW (Ubuntu)

```bash
# Activer
sudo ufw enable
sudo ufw status verbose

# Règles
sudo ufw allow ssh
sudo ufw allow 443/tcp
sudo ufw allow from 192.168.1.0/24 to any port 22

# Deny
sudo ufw deny 23/tcp

# Logging
sudo ufw logging on
```

---

## 4. SELinux (RHEL/Rocky)

### Modes

| Mode | Description |
|------|-------------|
| **Enforcing** | Applique les politiques |
| **Permissive** | Log sans bloquer |
| **Disabled** | Désactivé |

```bash
# Statut
getenforce
sestatus

# Changer temporairement
sudo setenforce 0    # Permissive
sudo setenforce 1    # Enforcing

# Permanent (/etc/selinux/config)
SELINUX=enforcing
```

### Contextes

```bash
# Voir les contextes
ls -Z /var/www/html
ps auxZ | grep nginx

# Restaurer les contextes
sudo restorecon -Rv /var/www/html

# Changer le contexte
sudo chcon -t httpd_sys_content_t /var/www/html/index.html

# Définir un contexte permanent
sudo semanage fcontext -a -t httpd_sys_content_t "/opt/myapp(/.*)?"
sudo restorecon -Rv /opt/myapp
```

### Troubleshooting

```bash
# Voir les denials
sudo ausearch -m avc -ts recent
sudo sealert -a /var/log/audit/audit.log

# Booleans
getsebool -a | grep httpd
sudo setsebool -P httpd_can_network_connect on
```

---

## 5. AppArmor (Ubuntu)

```bash
# Statut
sudo aa-status

# Modes
sudo aa-enforce /etc/apparmor.d/usr.sbin.nginx    # Enforce
sudo aa-complain /etc/apparmor.d/usr.sbin.nginx   # Complain

# Désactiver un profil
sudo aa-disable /etc/apparmor.d/usr.sbin.nginx

# Logs
sudo journalctl -k | grep apparmor
```

---

## 6. Audit Système

### Auditd

```bash
# Installation
sudo dnf install audit

# Règles
sudo auditctl -w /etc/passwd -p wa -k passwd_changes
sudo auditctl -w /etc/shadow -p wa -k shadow_changes
sudo auditctl -w /var/log/sudo.log -p wa -k sudo_log

# Fichier de règles persistant
# /etc/audit/rules.d/custom.rules
-w /etc/passwd -p wa -k passwd_changes
-w /etc/shadow -p wa -k shadow_changes

# Recherche
sudo ausearch -k passwd_changes
sudo aureport --summary
```

### OpenSCAP

```bash
# Installation
sudo dnf install openscap-scanner scap-security-guide

# Scan
sudo oscap xccdf eval \
    --profile xccdf_org.ssgproject.content_profile_cis \
    --results scan-results.xml \
    --report scan-report.html \
    /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml
```

---

## 7. Checklist Hardening

```bash
# Désactiver les services inutiles
sudo systemctl disable --now rpcbind
sudo systemctl disable --now avahi-daemon

# Permissions fichiers sensibles
sudo chmod 600 /etc/shadow
sudo chmod 600 /etc/gshadow
sudo chmod 644 /etc/passwd
sudo chmod 644 /etc/group

# Bannière de connexion
echo "Authorized users only. All activity is logged." | sudo tee /etc/issue.net
# Dans sshd_config: Banner /etc/issue.net

# Désactiver core dumps
echo "* hard core 0" | sudo tee -a /etc/security/limits.conf

# Sysctl hardening
cat << 'EOF' | sudo tee /etc/sysctl.d/99-hardening.conf
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
kernel.randomize_va_space = 2
EOF
sudo sysctl --system
```

---

## 8. Exercice Pratique

!!! example "Exercice : Hardening Complet"

    1. Sécuriser SSH (port custom, clés uniquement, no root)
    2. Configurer fail2ban
    3. Configurer le firewall (SSH + HTTP/HTTPS uniquement)
    4. Activer SELinux en mode enforcing
    5. Configurer des règles d'audit pour /etc/passwd et /etc/shadow
    6. Exécuter un scan OpenSCAP

    **Durée estimée :** 45 minutes

---

## Points Clés à Retenir

| Composant | Outils |
|-----------|--------|
| SSH | `sshd_config`, clés Ed25519, fail2ban |
| Privilèges | `sudo`, `/etc/sudoers.d/` |
| Firewall | `firewall-cmd` (RHEL), `ufw` (Ubuntu) |
| MAC | SELinux (RHEL), AppArmor (Ubuntu) |
| Audit | `auditd`, `ausearch`, OpenSCAP |

---

[:octicons-arrow-right-24: Module 12 : Services Réseau](12-services-reseau.md)

---

**Retour au :** [Programme de la Formation](index.md)

---

## Navigation

| | |
|:---|---:|
| [← Module 10 : Automatisation & Planific...](10-automatisation.md) | [Module 12 : Services Réseau →](12-services-reseau.md) |

[Retour au Programme](index.md){ .md-button }
