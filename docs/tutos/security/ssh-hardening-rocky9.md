---
tags:
  - tutos
  - security
  - ssh
  - hardening
  - rocky
---

# SSH Hardening sur Rocky Linux 9

Sécurisation du serveur **OpenSSH** sur Rocky Linux 9.

| Composant | Version |
|-----------|---------|
| Rocky Linux | 9.x |
| OpenSSH | 8.7+ |

**Durée estimée :** 20 minutes

---

## 1. Configuration de base sécurisée

```bash
# Backup
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

vim /etc/ssh/sshd_config
```

```ini
# Port (changer si possible)
Port 22
# Port 2222

# Protocole (SSH2 uniquement, par défaut)
Protocol 2

# Écoute
AddressFamily inet
ListenAddress 0.0.0.0

# Authentification
PermitRootLogin no
MaxAuthTries 3
MaxSessions 5
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no

# Désactiver les méthodes non utilisées
KerberosAuthentication no
GSSAPIAuthentication no
HostbasedAuthentication no

# Timeouts
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2

# Sécurité
StrictModes yes
IgnoreRhosts yes
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
PermitTunnel no
Banner /etc/ssh/banner

# Logging
SyslogFacility AUTH
LogLevel VERBOSE

# Subsystems
Subsystem sftp /usr/libexec/openssh/sftp-server -f AUTH -l INFO
```

---

## 2. Restreindre les utilisateurs

```ini
# Autoriser uniquement certains utilisateurs
AllowUsers admin deploy

# Ou par groupe
AllowGroups ssh-users wheel

# Refuser des utilisateurs
DenyUsers guest test

# Refuser des groupes
DenyGroups noSSH
```

Créer le groupe SSH :

```bash
groupadd ssh-users
usermod -aG ssh-users admin
```

---

## 3. Algorithmes cryptographiques modernes

```ini
# Ciphers (AES-GCM, ChaCha20)
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr

# MACs
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256

# Key Exchange
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group18-sha512,diffie-hellman-group16-sha512

# Host Key Algorithms
HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256
```

---

## 4. Clés d'hôte

```bash
# Supprimer les anciennes clés DSA/ECDSA si non nécessaires
rm /etc/ssh/ssh_host_dsa_key*
rm /etc/ssh/ssh_host_ecdsa_key*

# Régénérer les clés RSA et Ed25519
ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N ""
ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""

# Permissions
chmod 600 /etc/ssh/ssh_host_*_key
chmod 644 /etc/ssh/ssh_host_*_key.pub
```

Dans sshd_config :

```ini
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key
```

---

## 5. Authentification par clé SSH

### Sur le client

```bash
# Générer une clé Ed25519 (recommandé)
ssh-keygen -t ed25519 -C "user@workstation"

# Ou RSA 4096
ssh-keygen -t rsa -b 4096 -C "user@workstation"

# Copier la clé sur le serveur
ssh-copy-id -i ~/.ssh/id_ed25519.pub user@server
```

### Vérifier sur le serveur

```bash
cat ~/.ssh/authorized_keys
chmod 700 ~/.ssh
chmod 600 ~/.ssh/authorized_keys
```

---

## 6. Bannière de connexion

```bash
cat > /etc/ssh/banner << 'EOF'
*******************************************************************
*                   AUTHORIZED ACCESS ONLY                        *
*                                                                 *
* This system is for authorized users only. All activities are   *
* monitored and recorded. Unauthorized access is prohibited and  *
* will be prosecuted to the fullest extent of the law.           *
*******************************************************************
EOF
```

---

## 7. Fail2ban pour SSH

```bash
dnf install -y epel-release
dnf install -y fail2ban

cat > /etc/fail2ban/jail.local << 'EOF'
[sshd]
enabled = true
port = ssh
filter = sshd
backend = systemd
maxretry = 3
bantime = 3600
findtime = 600
EOF

systemctl enable --now fail2ban
fail2ban-client status sshd
```

---

## 8. Two-Factor Authentication (2FA)

```bash
dnf install -y google-authenticator

# Configurer pour un utilisateur
su - admin
google-authenticator
# Répondre aux questions (recommandé: y,y,n,y,y)
```

Dans sshd_config :

```ini
ChallengeResponseAuthentication yes
AuthenticationMethods publickey,keyboard-interactive
```

```bash
vim /etc/pam.d/sshd
```

Ajouter en haut :

```
auth required pam_google_authenticator.so
```

---

## 9. Port Knocking (optionnel)

```bash
dnf install -y knock-server

vim /etc/knockd.conf
```

```ini
[options]
    logfile = /var/log/knockd.log

[openSSH]
    sequence = 7000,8000,9000
    seq_timeout = 5
    command = /usr/bin/firewall-cmd --add-rich-rule='rule family="ipv4" source address="%IP%" port protocol="tcp" port="22" accept'
    tcpflags = syn

[closeSSH]
    sequence = 9000,8000,7000
    seq_timeout = 5
    command = /usr/bin/firewall-cmd --remove-rich-rule='rule family="ipv4" source address="%IP%" port protocol="tcp" port="22" accept'
    tcpflags = syn
```

---

## 10. Firewall

```bash
# Limiter les connexions SSH
firewall-cmd --permanent --add-rich-rule='rule service name="ssh" limit value="5/m" accept'
firewall-cmd --reload

# Ou autoriser uniquement certaines IPs
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="192.168.1.0/24" service name="ssh" accept'
firewall-cmd --permanent --remove-service=ssh
firewall-cmd --reload
```

---

## 11. SELinux

```bash
# Si port SSH non standard
semanage port -a -t ssh_port_t -p tcp 2222

# Vérifier
semanage port -l | grep ssh
```

---

## 12. Appliquer les changements

```bash
# Vérifier la syntaxe
sshd -t

# Redémarrer
systemctl restart sshd

# Tester AVANT de fermer la session actuelle
# Ouvrir une nouvelle connexion pour vérifier
```

---

## Vérification

```bash
# Configuration active
sshd -T | grep -E "permitrootlogin|passwordauthentication|pubkeyauth"

# Connexions actives
ss -tnp | grep :22
who

# Logs
journalctl -u sshd -f
```

---

## Checklist de sécurité

- [ ] PermitRootLogin no
- [ ] PasswordAuthentication no
- [ ] Clés SSH Ed25519/RSA 4096
- [ ] AllowUsers/AllowGroups configuré
- [ ] Fail2ban actif
- [ ] Algorithmes cryptographiques modernes
- [ ] LoginGraceTime réduit
- [ ] MaxAuthTries limité
- [ ] Bannière configurée
- [ ] Logging VERBOSE

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
