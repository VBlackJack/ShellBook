---
tags:
  - ssh
  - security
  - fail2ban
  - hardening
---

# SSH Hardening & Fail2Ban

Sécurisation du service SSH et protection contre les attaques par bruteforce.

---

## Hardening sshd_config

### Directives Essentielles

| Directive | Valeur Recommandée | Description |
|-----------|-------------------|-------------|
| `PermitRootLogin` | `no` | Interdit la connexion root directe |
| `PasswordAuthentication` | `no` | Force l'authentification par clé |
| `PubkeyAuthentication` | `yes` | Active l'auth par clé publique |
| `AllowUsers` | `user1 user2` | Liste blanche d'utilisateurs |
| `AllowGroups` | `sshusers` | Liste blanche de groupes |
| `Port` | `2222` | Port non standard (security through obscurity) |
| `Protocol` | `2` | SSH v2 uniquement |
| `MaxAuthTries` | `3` | Tentatives max avant déconnexion |
| `LoginGraceTime` | `30` | Timeout connexion (secondes) |
| `PermitEmptyPasswords` | `no` | Interdit mots de passe vides |
| `X11Forwarding` | `no` | Désactive le forwarding X11 |
| `AllowTcpForwarding` | `no` | Désactive le port forwarding |
| `ClientAliveInterval` | `300` | Keepalive toutes les 5 min |
| `ClientAliveCountMax` | `2` | Déconnexion après 2 keepalives sans réponse |

### Configuration Recommandée

```bash
# /etc/ssh/sshd_config

# Protocole et Port
Port 2222
Protocol 2

# Authentification
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
PermitEmptyPasswords no
MaxAuthTries 3
LoginGraceTime 30

# Restrictions utilisateurs
AllowUsers deploy admin
# ou AllowGroups sshusers

# Sécurité réseau
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no

# Keepalive
ClientAliveInterval 300
ClientAliveCountMax 2

# Bannière légale
Banner /etc/issue.net

# Algorithmes sécurisés (modern)
KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group16-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
```

### Appliquer les Changements

```bash
# Vérifier la syntaxe
sudo sshd -t

# Redémarrer le service
sudo systemctl restart sshd

# Vérifier le status
sudo systemctl status sshd
```

!!! danger "SecNumCloud : Ne pas se verrouiller dehors"
    Avant de désactiver `PasswordAuthentication` :

    1. Vérifier que votre clé SSH est bien configurée
    2. Garder une session ouverte pendant les tests
    3. Avoir un accès console de secours (KVM, IPMI)

---

## Fail2Ban

### Installation

=== "RHEL/Rocky"

    ```bash
    sudo dnf install epel-release -y
    sudo dnf install fail2ban

    # Démarrer et activer
    sudo systemctl enable --now fail2ban
    ```

=== "Debian/Ubuntu"

    ```bash
    sudo apt install fail2ban

    # Démarrer et activer
    sudo systemctl enable --now fail2ban
    ```

### Configuration jail.local

```bash
# /etc/fail2ban/jail.local
# Ne jamais modifier jail.conf directement !

[DEFAULT]
# Durée du ban (10 minutes)
bantime = 10m

# Fenêtre de détection
findtime = 10m

# Tentatives avant ban
maxretry = 5

# Email de notification
destemail = admin@example.com
sender = fail2ban@example.com

# Action par défaut
action = %(action_mwl)s

# IPs à ne jamais bannir
ignoreip = 127.0.0.1/8 ::1 192.168.1.0/24

[sshd]
enabled = true
port = 2222
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 1h
```

### Commandes Utiles

```bash
# Status global
sudo fail2ban-client status

# Status d'une jail
sudo fail2ban-client status sshd

# Bannir manuellement
sudo fail2ban-client set sshd banip 1.2.3.4

# Débannir
sudo fail2ban-client set sshd unbanip 1.2.3.4

# Voir les IPs bannies
sudo fail2ban-client get sshd banned

# Recharger la config
sudo fail2ban-client reload
```

### Ban Progressif

```bash
# /etc/fail2ban/jail.local

[sshd]
enabled = true
port = 2222
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 1h

# Récidivistes
[recidive]
enabled = true
filter = recidive
logpath = /var/log/fail2ban.log
bantime = 1w
findtime = 1d
maxretry = 3
```

---

## Banner & MotD

### Intérêt Légal

!!! warning "Pourquoi une bannière d'avertissement ?"
    Une bannière légale avant connexion :

    - **Prévient** que le système est privé et surveillé
    - **Dissuade** les attaquants (valeur légale limitée)
    - **Protège juridiquement** en cas de poursuites
    - **Obligatoire** dans certains référentiels (SecNumCloud, PCI-DSS)

### /etc/issue.net (Pré-connexion)

```bash
# /etc/issue.net
**************************************************************************
*                           ATTENTION                                     *
*  Ce système est réservé aux utilisateurs autorisés.                    *
*  Toute tentative d'accès non autorisé est interdite et sera            *
*  poursuivie conformément à la législation en vigueur.                  *
*                                                                         *
*  Les connexions sont journalisées et surveillées.                      *
**************************************************************************
```

### /etc/motd (Post-connexion)

```bash
# /etc/motd
==========================================================================
  Serveur de production - Environnement SecNumCloud

  Toutes les actions sont enregistrées.
  Contact: admin@example.com
==========================================================================
```

### Activer la Bannière

```bash
# Dans /etc/ssh/sshd_config
Banner /etc/issue.net

# Redémarrer SSH
sudo systemctl restart sshd
```

---

## Référence Rapide

```bash
# SSH Hardening
sudo nano /etc/ssh/sshd_config
sudo sshd -t                    # Vérifier syntaxe
sudo systemctl restart sshd

# Fail2Ban
sudo apt install fail2ban
sudo nano /etc/fail2ban/jail.local
sudo fail2ban-client status sshd
sudo fail2ban-client set sshd unbanip IP

# Bannière
sudo nano /etc/issue.net        # Pré-connexion
sudo nano /etc/motd             # Post-connexion
```
