---
tags:
  - tutos
  - security
  - ssh
  - hardening
  - debian
---

# SSH Hardening sur Debian 12

Sécurisation du serveur **OpenSSH** sur Debian 12.

| Composant | Version |
|-----------|---------|
| Debian | 12 Bookworm |
| OpenSSH | 9.2+ |

**Durée estimée :** 20 minutes

---

## 1. Configuration sécurisée

```bash
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
vim /etc/ssh/sshd_config
```

```ini
# Port
Port 22

# Authentification
PermitRootLogin no
MaxAuthTries 3
MaxSessions 5
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
KbdInteractiveAuthentication no

# Désactiver
KerberosAuthentication no
GSSAPIAuthentication no
HostbasedAuthentication no
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
PermitTunnel no

# Timeouts
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2

# Sécurité
StrictModes yes
IgnoreRhosts yes
Banner /etc/ssh/banner

# Logging
SyslogFacility AUTH
LogLevel VERBOSE

# SFTP
Subsystem sftp /usr/lib/openssh/sftp-server -f AUTH -l INFO
```

---

## 2. Restreindre les utilisateurs

```ini
AllowUsers admin deploy
# ou
AllowGroups ssh-users
```

```bash
groupadd ssh-users
usermod -aG ssh-users admin
```

---

## 3. Algorithmes cryptographiques

```ini
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com

MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com

KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group18-sha512,diffie-hellman-group16-sha512

HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256
```

---

## 4. Clés d'hôte

```bash
rm /etc/ssh/ssh_host_dsa_key* 2>/dev/null
rm /etc/ssh/ssh_host_ecdsa_key* 2>/dev/null

ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""
ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N ""

chmod 600 /etc/ssh/ssh_host_*_key
```

```ini
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key
```

---

## 5. Authentification par clé

```bash
# Client
ssh-keygen -t ed25519 -C "user@workstation"
ssh-copy-id -i ~/.ssh/id_ed25519.pub user@server

# Serveur
chmod 700 ~/.ssh
chmod 600 ~/.ssh/authorized_keys
```

---

## 6. Bannière

```bash
cat > /etc/ssh/banner << 'EOF'
*******************************************************************
*                   AUTHORIZED ACCESS ONLY                        *
* All activities are monitored and recorded.                      *
*******************************************************************
EOF
```

---

## 7. Fail2ban

```bash
apt install -y fail2ban

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
```

---

## 8. 2FA avec Google Authenticator

```bash
apt install -y libpam-google-authenticator

su - admin
google-authenticator
```

```bash
vim /etc/pam.d/sshd
```

Ajouter :
```
auth required pam_google_authenticator.so
```

```ini
# Dans sshd_config
KbdInteractiveAuthentication yes
AuthenticationMethods publickey,keyboard-interactive
```

---

## 9. Firewall UFW

```bash
ufw limit ssh
ufw reload

# Ou IPs spécifiques
ufw allow from 192.168.1.0/24 to any port 22
ufw delete allow ssh
```

---

## 10. Appliquer

```bash
sshd -t
systemctl restart sshd

# Tester dans une nouvelle session avant de fermer
```

---

## Comparatif Rocky vs Debian

| Aspect | Rocky 9 | Debian 12 |
|--------|---------|-----------|
| OpenSSH | 8.7 | 9.2 |
| SFTP path | /usr/libexec/openssh/ | /usr/lib/openssh/ |
| SELinux | Oui | Non (AppArmor) |
| Firewall | firewalld | ufw |

---

## Checklist

- [ ] PermitRootLogin no
- [ ] PasswordAuthentication no
- [ ] Clés Ed25519/RSA 4096
- [ ] AllowUsers/AllowGroups
- [ ] Fail2ban
- [ ] Algorithmes modernes
- [ ] Logging VERBOSE

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
