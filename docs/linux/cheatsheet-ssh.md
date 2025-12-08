---
tags:
  - ssh
  - tunnels
  - cheatsheet
  - security
  - network
  - remote
---

# SSH Cheatsheet

Guide de référence complet pour SSH: configuration, gestion des clés, tunnels (local, remote, dynamic), et jump hosts.

---

## 1. Connexion SSH de Base

### Syntaxe de Base

```bash
# Connexion simple
ssh user@hostname
ssh user@192.168.1.100

# Connexion avec port spécifique
ssh -p 2222 user@hostname

# Connexion avec clé spécifique
ssh -i ~/.ssh/id_rsa_custom user@hostname

# Exécuter une commande à distance
ssh user@hostname 'ls -la /var/log'
ssh user@hostname 'uptime'

# Commande avec sortie locale
ssh user@hostname 'cat /etc/hosts' > local-hosts.txt

# Commande interactive
ssh -t user@hostname 'sudo systemctl status nginx'

# Mode verbose (debug)
ssh -v user@hostname    # Verbose
ssh -vv user@hostname   # Plus verbose
ssh -vvv user@hostname  # Très verbose
```

### Options Courantes

| Option | Description |
|--------|-------------|
| `-p <port>` | Port SSH (défaut: 22) |
| `-i <keyfile>` | Fichier de clé privée |
| `-l <user>` | Nom d'utilisateur |
| `-v`, `-vv`, `-vvv` | Verbosité (debug) |
| `-4` | Forcer IPv4 |
| `-6` | Forcer IPv6 |
| `-A` | Agent forwarding |
| `-X` | X11 forwarding |
| `-C` | Compression |
| `-N` | Pas de commande (tunnels) |
| `-f` | Background (après auth) |
| `-T` | Pas de pseudo-terminal |
| `-t` | Forcer pseudo-terminal |
| `-q` | Mode silencieux |

```bash
# Combinaisons utiles
ssh -A user@bastion  # Forward SSH agent
ssh -X user@server   # Forward X11 (GUI)
ssh -C user@server   # Avec compression
ssh -Nf -L 8080:localhost:80 user@server  # Tunnel en background
```

---

## 2. Gestion des Clés SSH

### Générer des Clés

```bash
# Générer une clé RSA 4096 bits (recommandé)
ssh-keygen -t rsa -b 4096 -C "email@example.com"

# Générer une clé Ed25519 (moderne, plus sécurisée)
ssh-keygen -t ed25519 -C "email@example.com"

# Générer avec nom de fichier spécifique
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519_github -C "github@example.com"

# Générer sans passphrase (automatisation, CI/CD)
ssh-keygen -t ed25519 -N "" -f ~/.ssh/id_ed25519_deploy

# Changer la passphrase d'une clé existante
ssh-keygen -p -f ~/.ssh/id_rsa

# Voir la fingerprint d'une clé
ssh-keygen -lf ~/.ssh/id_rsa.pub
ssh-keygen -lf ~/.ssh/id_rsa.pub -E md5  # Format MD5

# Voir la fingerprint en art ASCII
ssh-keygen -lvf ~/.ssh/id_rsa.pub
```

### Types de Clés

| Type | Sécurité | Taille | Recommandation |
|------|----------|--------|----------------|
| **RSA** | Bonne | 2048-4096 bits | Standard, compatible |
| **Ed25519** | Excellente | 256 bits | Moderne, recommandée |
| **ECDSA** | Bonne | 256-521 bits | Bonne alternative |
| **DSA** | Faible | 1024 bits | Obsolète, éviter |

### Copier une Clé Publique

```bash
# Méthode recommandée (ssh-copy-id)
ssh-copy-id user@hostname
ssh-copy-id -i ~/.ssh/id_ed25519.pub user@hostname

# Avec port spécifique
ssh-copy-id -p 2222 user@hostname

# Méthode manuelle (si ssh-copy-id non disponible)
cat ~/.ssh/id_rsa.pub | ssh user@hostname 'mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys'

# Définir les bonnes permissions
ssh user@hostname 'chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys'

# One-liner complet
cat ~/.ssh/id_rsa.pub | ssh user@hostname 'mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys'
```

### Agent SSH

```bash
# Démarrer l'agent SSH
eval "$(ssh-agent -s)"

# Ajouter une clé à l'agent
ssh-add ~/.ssh/id_rsa
ssh-add ~/.ssh/id_ed25519

# Ajouter avec durée de vie (1 heure)
ssh-add -t 3600 ~/.ssh/id_rsa

# Lister les clés dans l'agent
ssh-add -l
ssh-add -L  # Avec clés publiques complètes

# Supprimer toutes les clés de l'agent
ssh-add -D

# Supprimer une clé spécifique
ssh-add -d ~/.ssh/id_rsa

# Tester l'authentification
ssh -T git@github.com
```

### Permissions des Fichiers SSH

```bash
# Permissions correctes (important pour la sécurité!)
chmod 700 ~/.ssh                      # Dossier .ssh
chmod 600 ~/.ssh/id_rsa               # Clé privée
chmod 644 ~/.ssh/id_rsa.pub           # Clé publique
chmod 600 ~/.ssh/authorized_keys      # Clés autorisées
chmod 600 ~/.ssh/config               # Fichier config
chmod 600 ~/.ssh/known_hosts          # Hosts connus

# Script pour fixer les permissions
#!/bin/bash
chmod 700 ~/.ssh
chmod 600 ~/.ssh/id_*
chmod 644 ~/.ssh/*.pub
chmod 600 ~/.ssh/authorized_keys
chmod 600 ~/.ssh/config
chmod 600 ~/.ssh/known_hosts
```

---

## 3. Configuration SSH (~/.ssh/config)

### Structure de Base

```bash
# ~/.ssh/config

# Configuration globale
Host *
    ServerAliveInterval 60
    ServerAliveCountMax 3
    Compression yes
    ControlMaster auto
    ControlPath ~/.ssh/sockets/%r@%h-%p
    ControlPersist 600

# Hôte spécifique
Host myserver
    HostName 192.168.1.100
    User admin
    Port 2222
    IdentityFile ~/.ssh/id_ed25519_myserver

# Serveur de production
Host prod
    HostName prod.example.com
    User deploy
    IdentityFile ~/.ssh/id_rsa_prod
    ForwardAgent yes

# Bastion/Jump host
Host bastion
    HostName bastion.example.com
    User bastion-user
    Port 22

# Serveurs derrière le bastion
Host server-*.internal
    ProxyJump bastion
    User admin

# GitHub
Host github.com
    User git
    IdentityFile ~/.ssh/id_ed25519_github
    IdentitiesOnly yes

# GitLab
Host gitlab.com
    User git
    IdentityFile ~/.ssh/id_ed25519_gitlab
    IdentitiesOnly yes
```

### Options de Configuration Importantes

| Option | Description | Exemple |
|--------|-------------|---------|
| `Host` | Pattern de host | `Host myserver` |
| `HostName` | Vrai hostname/IP | `HostName 192.168.1.100` |
| `User` | Utilisateur SSH | `User admin` |
| `Port` | Port SSH | `Port 2222` |
| `IdentityFile` | Clé privée | `IdentityFile ~/.ssh/id_rsa` |
| `IdentitiesOnly` | Utiliser seulement la clé spécifiée | `IdentitiesOnly yes` |
| `ProxyJump` | Jump host | `ProxyJump bastion` |
| `ProxyCommand` | Commande proxy | `ProxyCommand ssh bastion nc %h %p` |
| `ForwardAgent` | Forward SSH agent | `ForwardAgent yes` |
| `LocalForward` | Port forwarding local | `LocalForward 8080 localhost:80` |
| `RemoteForward` | Port forwarding remote | `RemoteForward 9000 localhost:3000` |
| `DynamicForward` | SOCKS proxy | `DynamicForward 1080` |
| `Compression` | Activer compression | `Compression yes` |
| `ServerAliveInterval` | Keepalive interval | `ServerAliveInterval 60` |
| `ControlMaster` | Multiplexing | `ControlMaster auto` |
| `ControlPath` | Socket multiplexing | `ControlPath ~/.ssh/cm-%r@%h:%p` |
| `ControlPersist` | Durée connexion | `ControlPersist 10m` |

### Exemples Avancés

```bash
# Multi-hop avec ProxyJump
Host final-server
    HostName 10.0.2.100
    User app
    ProxyJump bastion,gateway

# Wildcard avec différentes clés
Host *.prod.example.com
    User deploy
    IdentityFile ~/.ssh/id_rsa_prod
    StrictHostKeyChecking yes

Host *.dev.example.com
    User developer
    IdentityFile ~/.ssh/id_rsa_dev
    StrictHostKeyChecking no

# Tunnel SOCKS permanent
Host socks-proxy
    HostName proxy.example.com
    User proxyuser
    DynamicForward 1080
    ExitOnForwardFailure yes

# Port forwarding permanent
Host db-tunnel
    HostName db-server.internal
    User dbuser
    LocalForward 5432 localhost:5432
    ExitOnForwardFailure yes

# Match conditions (SSH 7.0+)
Match Host *.internal User admin
    IdentityFile ~/.ssh/id_rsa_admin
    ForwardAgent yes

Match Host * Exec "[ $(date +%H) -ge 9 -a $(date +%H) -le 17 ]"
    # Configuration pendant les heures de bureau
    ControlMaster auto
```

---

## 4. Tunnels SSH (Port Forwarding)

### Tunnel Local (Local Forward)

**Concept**: Rediriger un port local vers un port sur le serveur distant.

```
[Vous] → [Port Local] → [SSH Tunnel] → [Serveur SSH] → [Port Distant]
```

```bash
# Syntaxe de base
ssh -L [local_port]:[destination_host]:[destination_port] user@ssh-server

# Exemples pratiques

# Accéder à un service web distant (port 80) via le port local 8080
ssh -L 8080:localhost:80 user@webserver
# Ensuite: http://localhost:8080

# Accéder à une base de données distante
ssh -L 3306:localhost:3306 user@dbserver
# Ensuite: mysql -h 127.0.0.1 -P 3306

# Accéder à un service sur un autre serveur via le SSH server
ssh -L 5432:db-internal:5432 user@bastion
# Le bastion forward vers db-internal:5432

# Multiples tunnels
ssh -L 8080:localhost:80 -L 3306:localhost:3306 user@server

# Tunnel en arrière-plan
ssh -fNL 8080:localhost:80 user@server
# -f: background
# -N: pas de commande (seulement tunnel)

# Tunnel avec bind address spécifique
ssh -L 192.168.1.100:8080:localhost:80 user@server
# Accessible depuis 192.168.1.100:8080 (pas seulement localhost)

# Tunnel accessible depuis le réseau (ATTENTION: risque sécurité)
ssh -L 0.0.0.0:8080:localhost:80 user@server
# Accessible depuis toutes les interfaces
```

### Tunnel Remote (Remote Forward)

**Concept**: Rediriger un port du serveur distant vers un port local.

```
[Serveur SSH] → [Port Distant] → [SSH Tunnel] → [Vous] → [Port Local]
```

```bash
# Syntaxe de base
ssh -R [remote_port]:[local_host]:[local_port] user@ssh-server

# Exemples pratiques

# Exposer votre serveur web local (port 3000) au serveur distant (port 8080)
ssh -R 8080:localhost:3000 user@server
# Sur le serveur: curl http://localhost:8080

# Exposer un service local au serveur distant
ssh -R 9000:localhost:9000 user@server

# Permettre au serveur de bind sur toutes les interfaces
# (nécessite GatewayPorts yes dans sshd_config du serveur)
ssh -R 0.0.0.0:8080:localhost:3000 user@server

# Tunnel remote en arrière-plan
ssh -fNR 8080:localhost:3000 user@server

# Exposer un service sur un autre serveur
ssh -R 8080:internal-server:80 user@public-server
# Le serveur public peut accéder à internal-server:80 via localhost:8080
```

### Tunnel Dynamic (SOCKS Proxy)

**Concept**: Créer un proxy SOCKS pour router tout le trafic via SSH.

```bash
# Syntaxe de base
ssh -D [local_port] user@ssh-server

# Exemples pratiques

# Créer un proxy SOCKS sur le port 1080
ssh -D 1080 user@server

# En arrière-plan
ssh -fND 1080 user@server

# Utiliser avec curl
curl --socks5 localhost:1080 https://example.com

# Utiliser avec Firefox
# Preferences → Network → Settings → Manual proxy
# SOCKS Host: localhost, Port: 1080, SOCKS v5

# Utiliser avec Git
git config --global http.proxy socks5://localhost:1080
git config --global https.proxy socks5://localhost:1080

# Utiliser avec tout le système (via proxychains)
# /etc/proxychains.conf:
# socks5 127.0.0.1 1080
proxychains curl https://example.com
proxychains firefox

# Tunnel SOCKS avec keepalive
ssh -D 1080 -o ServerAliveInterval=60 -o ServerAliveCountMax=3 user@server
```

### Tunnels Combinés

```bash
# Local + Remote + Dynamic en même temps
ssh -L 8080:localhost:80 \
    -R 9000:localhost:3000 \
    -D 1080 \
    user@server

# Configuration permanente dans ~/.ssh/config
Host tunnel-server
    HostName server.example.com
    User tunneluser
    LocalForward 8080 localhost:80
    RemoteForward 9000 localhost:3000
    DynamicForward 1080
    ExitOnForwardFailure yes

# Ensuite: ssh tunnel-server
```

### AutoSSH - Tunnels Persistants

```bash
# Installer autossh
sudo apt install autossh  # Debian/Ubuntu
sudo yum install autossh  # RHEL/CentOS

# Tunnel persistant avec autossh
autossh -M 0 -fN -L 8080:localhost:80 user@server

# Options autossh
# -M 0: Désactive le monitoring port (utilise ServerAlive à la place)
# -f: Background
# -N: Pas de shell

# Tunnel SOCKS persistant
autossh -M 0 -fN -D 1080 \
    -o ServerAliveInterval=60 \
    -o ServerAliveCountMax=3 \
    -o ExitOnForwardFailure=yes \
    user@server

# Service systemd pour autossh
# /etc/systemd/system/ssh-tunnel.service
[Unit]
Description=AutoSSH tunnel
After=network.target

[Service]
Type=simple
User=myuser
ExecStart=/usr/bin/autossh -M 0 -N \
    -o "ServerAliveInterval=60" \
    -o "ServerAliveCountMax=3" \
    -o "ExitOnForwardFailure=yes" \
    -L 8080:localhost:80 \
    user@server
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target

# Activer le service
sudo systemctl enable ssh-tunnel
sudo systemctl start ssh-tunnel
```

---

## 5. Jump Hosts / Bastion

### ProxyJump (SSH 7.3+)

```bash
# Syntaxe de base
ssh -J jump-host target-host
ssh -J user1@jump:port user2@target

# Exemples

# Via un bastion
ssh -J bastion.example.com server.internal

# Via un bastion avec utilisateur différent
ssh -J admin@bastion deploy@server.internal

# Multiple jump hosts (chaîne)
ssh -J bastion1,bastion2,bastion3 final-server

# Avec port spécifique
ssh -J user@bastion:2222 user@target

# Configuration dans ~/.ssh/config
Host internal-*
    ProxyJump bastion.example.com

Host bastion.example.com
    User bastion-user
    IdentityFile ~/.ssh/id_rsa_bastion

# Ensuite simplement:
ssh internal-server1
ssh internal-server2
```

### ProxyCommand (Méthode Legacy)

```bash
# Via netcat (nc)
ssh -o ProxyCommand="ssh bastion nc %h %p" target-server

# Via netcat avec timeout
ssh -o ProxyCommand="ssh bastion nc -w 10 %h %p" target-server

# Configuration dans ~/.ssh/config
Host internal-*.company.com
    ProxyCommand ssh bastion.company.com nc %h %p

# Avec socat
Host internal-*
    ProxyCommand ssh bastion socat - TCP:%h:%p

# Multi-hop avec ProxyCommand
Host jump1
    HostName bastion1.example.com

Host jump2
    HostName bastion2.internal
    ProxyCommand ssh jump1 nc %h %p

Host final
    HostName server.internal
    ProxyCommand ssh jump2 nc %h %p
```

### SCP via Jump Host

```bash
# Avec ProxyJump
scp -J bastion file.txt target:/path/

# Avec ProxyCommand
scp -o ProxyCommand="ssh bastion nc %h %p" file.txt target:/path/

# Si configuré dans ~/.ssh/config
scp file.txt internal-server:/path/

# Copier depuis un serveur distant via bastion
scp -J bastion target:/remote/file.txt ./local/
```

### SSHFS via Jump Host

```bash
# Monter un système de fichiers distant via bastion
sshfs -o ProxyCommand="ssh bastion nc %h %p" \
    target:/remote/path /local/mount

# Avec ProxyJump
sshfs -o ProxyJump=bastion \
    target:/remote/path /local/mount

# Démonter
fusermount -u /local/mount
```

---

## 6. Sécurité SSH

### Configuration Serveur (/etc/ssh/sshd_config)

```bash
# Fichier: /etc/ssh/sshd_config

# Port non standard (obscurité, pas sécurité!)
Port 2222

# Protocole SSH version 2 uniquement
Protocol 2

# Désactiver root login
PermitRootLogin no

# Désactiver authentification par mot de passe
PasswordAuthentication no
PubkeyAuthentication yes

# Désactiver authentification par challenge-response
ChallengeResponseAuthentication no

# Désactiver PAM si pas nécessaire
UsePAM no

# Autoriser seulement certains utilisateurs
AllowUsers deploy admin
AllowGroups ssh-users

# Bloquer certains utilisateurs
DenyUsers guest test

# Timeout de connexion
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2

# Nombre max de tentatives d'authentification
MaxAuthTries 3
MaxSessions 10

# Désactiver X11 forwarding (si pas nécessaire)
X11Forwarding no

# Désactiver TCP forwarding (si pas nécessaire)
AllowTcpForwarding no
AllowStreamLocalForwarding no
GatewayPorts no

# Désactiver Agent forwarding
AllowAgentForwarding no

# Chroot SFTP pour certains utilisateurs
Match User sftpuser
    ChrootDirectory /home/sftpuser
    ForceCommand internal-sftp
    AllowTcpForwarding no
    X11Forwarding no

# Banner de sécurité
Banner /etc/ssh/banner.txt

# Logging
SyslogFacility AUTH
LogLevel VERBOSE

# Algorithmes de chiffrement forts uniquement
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256
HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256

# Redémarrer SSH après modification
sudo systemctl restart sshd
```

### Fail2Ban - Protection Brute Force

```bash
# Installer Fail2Ban
sudo apt install fail2ban  # Debian/Ubuntu
sudo yum install fail2ban  # RHEL/CentOS

# Configuration: /etc/fail2ban/jail.local
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
port = 22,2222
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600

# Démarrer Fail2Ban
sudo systemctl enable fail2ban
sudo systemctl start fail2ban

# Voir les bans actifs
sudo fail2ban-client status sshd

# Débanner une IP
sudo fail2ban-client set sshd unbanip 192.168.1.100
```

### SSH Hardening Checklist

```bash
# 1. Désactiver root login
PermitRootLogin no

# 2. Utiliser seulement clés SSH
PasswordAuthentication no
PubkeyAuthentication yes

# 3. Port non standard
Port 2222

# 4. Limiter les utilisateurs
AllowUsers deploy admin

# 5. Fail2Ban activé
sudo systemctl status fail2ban

# 6. Firewall configuré
sudo ufw allow 2222/tcp
sudo ufw enable

# 7. SSH v2 uniquement
Protocol 2

# 8. Timeouts configurés
ClientAliveInterval 300
ClientAliveCountMax 2

# 9. Algorithmes forts seulement
# (Voir section précédente)

# 10. Monitoring des logs
sudo journalctl -u sshd -f
```

### Test de Sécurité SSH

```bash
# Tester les algorithmes supportés
ssh -Q cipher
ssh -Q mac
ssh -Q kex
ssh -Q key

# Scanner avec ssh-audit
git clone https://github.com/jtesta/ssh-audit.git
cd ssh-audit
python ssh-audit.py server.example.com

# Nmap scan SSH
nmap -p 22 --script ssh2-enum-algos server.example.com
nmap -p 22 --script ssh-hostkey server.example.com
```

---

## 7. Transfert de Fichiers

### SCP (Secure Copy)

```bash
# Copier fichier local → distant
scp file.txt user@server:/path/to/destination/

# Copier fichier distant → local
scp user@server:/path/to/file.txt ./local/

# Copier dossier (récursif)
scp -r /local/folder user@server:/remote/folder/

# Avec port spécifique
scp -P 2222 file.txt user@server:/path/

# Préserver permissions et timestamps
scp -p file.txt user@server:/path/

# Avec compression
scp -C large-file.tar.gz user@server:/path/

# Avec limitation de bande passante (KB/s)
scp -l 1000 file.txt user@server:/path/

# Copier entre deux serveurs distants
scp user1@server1:/path/file.txt user2@server2:/path/

# Mode verbeux
scp -v file.txt user@server:/path/

# Copier plusieurs fichiers
scp file1.txt file2.txt user@server:/path/
scp *.txt user@server:/path/
```

### SFTP (SSH File Transfer Protocol)

```bash
# Connexion SFTP interactive
sftp user@server

# Commandes SFTP courantes:
sftp> ls                    # Lister fichiers distants
sftp> lls                   # Lister fichiers locaux
sftp> pwd                   # Dossier distant
sftp> lpwd                  # Dossier local
sftp> cd /path              # Changer dossier distant
sftp> lcd /path             # Changer dossier local
sftp> get file.txt          # Télécharger fichier
sftp> get -r folder/        # Télécharger dossier
sftp> put file.txt          # Upload fichier
sftp> put -r folder/        # Upload dossier
sftp> mkdir newdir          # Créer dossier distant
sftp> rm file.txt           # Supprimer fichier distant
sftp> rmdir folder          # Supprimer dossier distant
sftp> rename old new        # Renommer distant
sftp> !ls                   # Commande locale
sftp> exit                  # Quitter

# SFTP avec port spécifique
sftp -P 2222 user@server

# Batch mode (non-interactif)
sftp -b commands.txt user@server

# commands.txt:
# cd /remote/path
# get file.txt
# put local.txt
# exit

# One-liner
echo "get /remote/file.txt" | sftp user@server
```

### rsync via SSH

```bash
# Synchroniser dossier local → distant
rsync -avz /local/folder/ user@server:/remote/folder/

# Options courantes:
# -a: archive (permissions, timestamps, récursif)
# -v: verbose
# -z: compression
# -P: progress + partial (reprendre)
# -h: human-readable
# --delete: supprimer fichiers supprimés de la source

# Synchroniser distant → local
rsync -avz user@server:/remote/folder/ /local/folder/

# Dry-run (simulation)
rsync -avzn /local/ user@server:/remote/

# Avec port SSH spécifique
rsync -avz -e "ssh -p 2222" /local/ user@server:/remote/

# Exclure fichiers
rsync -avz --exclude='*.log' --exclude='node_modules' /local/ user@server:/remote/

# Supprimer les fichiers supprimés de la source
rsync -avz --delete /local/ user@server:/remote/

# Limiter bande passante (KB/s)
rsync -avz --bwlimit=1000 /local/ user@server:/remote/

# Progress détaillé
rsync -avzP /local/ user@server:/remote/

# Via jump host
rsync -avz -e "ssh -J bastion" /local/ target:/remote/
```

---

## 8. Multiplexing SSH

### Configuration ControlMaster

```bash
# ~/.ssh/config
Host *
    ControlMaster auto
    ControlPath ~/.ssh/sockets/%r@%h-%p
    ControlPersist 600

# Créer le dossier sockets
mkdir -p ~/.ssh/sockets
```

### Utilisation

```bash
# Première connexion (master)
ssh user@server

# Connexions suivantes (réutilisent la connexion)
ssh user@server  # Instantané!
scp file.txt user@server:/path/  # Utilise la connexion existante

# Voir les connexions actives
ls ~/.ssh/sockets/

# Fermer une connexion master
ssh -O exit user@server

# Vérifier le status
ssh -O check user@server

# Stopper le master
ssh -O stop user@server

# Commandes de contrôle:
# -O check: Vérifier si master actif
# -O exit: Fermer master (après dernière session)
# -O stop: Fermer master immédiatement
# -O forward: Forward port
# -O cancel: Annuler forward
```

---

## 9. Tips & Tricks

### Raccourcis Pratiques

```bash
# Rouvrir la dernière connexion
ssh !!

# Se reconnecter jusqu'à succès
while ! ssh user@server; do sleep 1; done

# Connexion avec keepalive agressif
ssh -o ServerAliveInterval=5 -o ServerAliveCountMax=3 user@server

# Désactiver strict host key checking (DEV SEULEMENT!)
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null user@server

# Forcer mot de passe (ignorer clés)
ssh -o PubkeyAuthentication=no user@server

# SSH avec timeout de connexion
ssh -o ConnectTimeout=10 user@server

# Exécuter commande locale avec output distant
ssh user@server 'bash -s' < local-script.sh

# Port knock avant SSH
for port in 7000 8000 9000; do nc -z server $port; done && ssh user@server
```

### Escape Sequences

```bash
# Dans une session SSH, taper:
~.    # Déconnexion immédiate
~^Z   # Suspend SSH (fg pour revenir)
~#    # Liste des forwards
~&    # Background SSH
~?    # Aide escape sequences
~C    # Ouvrir ligne de commande SSH
~R    # Request rekeying
```

### SSH Command Line

```bash
# Dans une session SSH, taper ~C pour ouvrir la ligne de commande
ssh> help
ssh> -L 8080:localhost:80    # Ajouter tunnel local
ssh> -R 9000:localhost:3000  # Ajouter tunnel remote
ssh> -D 1080                 # Ajouter SOCKS proxy
ssh> -KL 8080:localhost:80   # Supprimer tunnel
```

### Alias Utiles

```bash
# Ajouter dans ~/.bashrc ou ~/.zshrc

# Connexions fréquentes
alias prod='ssh production-server'
alias dev='ssh development-server'
alias bastion='ssh jump-host'

# Tunnels
alias tunnel-db='ssh -fNL 5432:localhost:5432 db-server'
alias socks-proxy='ssh -fND 1080 proxy-server'

# SCP rapide
alias scpp='scp -C -o compression_level=9'

# rsync avec progress
alias rssh='rsync -avzP --stats'
```

### One-liners Avancés

```bash
# Copier clé SSH vers plusieurs serveurs
for server in server1 server2 server3; do
    ssh-copy-id user@$server
done

# Exécuter commande sur plusieurs serveurs
for server in server{1..10}; do
    ssh user@$server 'uptime'
done

# Synchroniser vers plusieurs serveurs
for server in web{1..5}; do
    rsync -avz /local/app/ user@$server:/remote/app/
done

# Backup distant automatique
rsync -avz --delete -e "ssh -p 2222" \
    user@server:/data/ \
    /backup/$(date +%Y%m%d)/

# Tunnel reverse pour webhook local
ssh -R 8080:localhost:3000 user@public-server
# Ensuite configurer webhook: http://public-server:8080

# Mount distant via SSHFS
mkdir ~/remote-mount
sshfs user@server:/remote/path ~/remote-mount
# Démonter: fusermount -u ~/remote-mount
```

---

## 10. Troubleshooting

### Debug SSH

```bash
# Mode verbose
ssh -v user@server      # Verbose
ssh -vv user@server     # Plus verbose
ssh -vvv user@server    # Maximum verbose

# Tester la connexion
ssh -T user@server

# Voir la configuration effective
ssh -G user@server

# Tester une clé spécifique
ssh -i ~/.ssh/id_rsa -v user@server

# Vérifier les permissions
ls -la ~/.ssh/
# .ssh/ doit être 700
# id_rsa doit être 600
# authorized_keys doit être 600
```

### Problèmes Courants

```bash
# "Permission denied (publickey)"
# 1. Vérifier que la clé publique est sur le serveur
ssh user@server 'cat ~/.ssh/authorized_keys'

# 2. Vérifier les permissions
ssh user@server 'ls -la ~/.ssh/'

# 3. Vérifier les logs serveur
ssh user@server 'sudo tail /var/log/auth.log'

# "Connection refused"
# Vérifier que SSH est actif
ssh user@server 'sudo systemctl status sshd'

# Vérifier le port
nmap -p 22 server

# "Host key verification failed"
# Supprimer l'ancienne clé
ssh-keygen -R server
ssh-keygen -R 192.168.1.100

# "Too many authentication failures"
# Limiter les clés essayées
ssh -o IdentitiesOnly=yes -i ~/.ssh/specific_key user@server

# Timeout de connexion
# Augmenter le timeout
ssh -o ConnectTimeout=30 user@server

# Connection timed out (firewall?)
# Tester avec telnet
telnet server 22
```

### Logs SSH

```bash
# Logs client (avec -v)
ssh -vvv user@server 2>&1 | tee ssh-debug.log

# Logs serveur
sudo tail -f /var/log/auth.log        # Debian/Ubuntu
sudo tail -f /var/log/secure          # RHEL/CentOS
sudo journalctl -u sshd -f            # systemd

# Voir les tentatives de connexion
sudo grep "Failed password" /var/log/auth.log
sudo grep "Accepted publickey" /var/log/auth.log

# Voir les connexions actives
who
w
last
```

---

## Ressources Complémentaires

- **OpenSSH Documentation**: https://www.openssh.com/manual.html
- **SSH Security Best Practices**: https://infosec.mozilla.org/guidelines/openssh
- **SSH Tunneling Guide**: https://www.ssh.com/academy/ssh/tunneling
- **SSH Hardening**: https://www.sshaudit.com/hardening_guides.html

!!! tip "Aller Plus Loin"
    - Configurez **2FA avec Google Authenticator** pour SSH
    - Explorez **Teleport** ou **Boundary** pour la gestion SSH centralisée
    - Utilisez **Ansible** avec SSH pour l'automatisation
    - Apprenez **Mosh** (mobile shell) pour des connexions instables
