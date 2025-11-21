# Firewalling with UFW

`#ufw` `#firewall` `#security` `#iptables`

Gestion simplifiée du pare-feu Linux avec UFW (Uncomplicated Firewall).

---

## Pourquoi UFW ?

### Wrapper pour netfilter/iptables

UFW est une interface simplifiée au-dessus de netfilter/iptables :

```
┌─────────────────────────────────────────────────────────┐
│                     Applications                         │
├─────────────────────────────────────────────────────────┤
│                        UFW                               │
│              (Interface simplifiée)                      │
├─────────────────────────────────────────────────────────┤
│                     iptables                             │
│              (Outil de configuration)                    │
├─────────────────────────────────────────────────────────┤
│                     netfilter                            │
│              (Framework kernel)                          │
└─────────────────────────────────────────────────────────┘
```

| Aspect | iptables | UFW |
|--------|----------|-----|
| Syntaxe | Complexe | Simple |
| Courbe d'apprentissage | Élevée | Faible |
| Flexibilité | Totale | Suffisante pour 90% des cas |
| Cas d'usage | Routeurs, NAT avancé | Serveurs applicatifs |

### Politique par Défaut

!!! tip "Standard de Sécurité : Deny by Default"
    La politique recommandée :

    - **Deny Incoming** : Bloquer tout le trafic entrant par défaut
    - **Allow Outgoing** : Autoriser tout le trafic sortant

    Principe : N'ouvrir que ce qui est strictement nécessaire.

```bash
# Configurer la politique par défaut
sudo ufw default deny incoming
sudo ufw default allow outgoing
```

---

## Commandes Essentielles

### Workflow de Base

!!! danger "CRITIQUE : Autoriser SSH AVANT d'activer"
    Si vous activez UFW sans autoriser SSH, vous perdez l'accès à votre serveur !

    ```bash
    # TOUJOURS faire ceci EN PREMIER
    sudo ufw allow ssh
    # ou explicitement
    sudo ufw allow 22/tcp
    ```

### Activer / Désactiver

```bash
# Activer le firewall
sudo ufw enable

# Désactiver (garde les règles)
sudo ufw disable

# Reset complet (supprime toutes les règles)
sudo ufw reset
```

### Voir l'État

```bash
# État simple
sudo ufw status

# État détaillé avec politique par défaut
sudo ufw status verbose

# Règles numérotées (pour suppression)
sudo ufw status numbered
```

### Règles Simples

```bash
# Autoriser un port TCP
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Autoriser un port UDP
sudo ufw allow 53/udp

# Autoriser TCP et UDP
sudo ufw allow 53

# Autoriser une plage de ports
sudo ufw allow 6000:6007/tcp

# Autoriser depuis une IP spécifique
sudo ufw allow from 192.168.1.100

# Autoriser un sous-réseau
sudo ufw allow from 192.168.1.0/24

# Autoriser une IP vers un port spécifique
sudo ufw allow from 192.168.1.100 to any port 22

# Refuser explicitement
sudo ufw deny from 10.0.0.0/8
```

### Supprimer des Règles

```bash
# Méthode 1 : Par la règle exacte
sudo ufw delete allow 80/tcp

# Méthode 2 : Par numéro
sudo ufw status numbered
# Output:
# [1] 22/tcp    ALLOW IN    Anywhere
# [2] 80/tcp   ALLOW IN    Anywhere

sudo ufw delete 2
```

### Règles Avancées

```bash
# Autoriser une interface spécifique
sudo ufw allow in on eth0 to any port 80

# Limiter les connexions (anti-bruteforce)
sudo ufw limit ssh

# Règle avec commentaire
sudo ufw allow 80/tcp comment 'HTTP Web Server'
```

---

## Application Profiles

UFW supporte des profils d'application prédéfinis.

### Lister les Applications

```bash
sudo ufw app list

# Output:
# Available applications:
#   Nginx Full
#   Nginx HTTP
#   Nginx HTTPS
#   OpenSSH
#   Apache
#   Apache Full
#   Apache Secure
```

### Utiliser un Profil

```bash
# Autoriser par nom d'application
sudo ufw allow 'Nginx Full'
sudo ufw allow 'OpenSSH'

# Voir les détails d'un profil
sudo ufw app info 'Nginx Full'

# Output:
# Profile: Nginx Full
# Title: Web Server (Nginx, HTTP + HTTPS)
# Description: Small, but very powerful and efficient web server
# Ports:
#   80,443/tcp
```

### Créer un Profil Custom

```bash
# /etc/ufw/applications.d/myapp
[MyApp]
title=My Custom Application
description=Custom app on port 8080
ports=8080/tcp
```

```bash
# Recharger et utiliser
sudo ufw app update MyApp
sudo ufw allow 'MyApp'
```

---

## Logging

### Activer les Logs

```bash
# Activer le logging
sudo ufw logging on

# Niveaux de log
sudo ufw logging low      # Bloqués uniquement
sudo ufw logging medium   # + Invalid packets
sudo ufw logging high     # + Tout le trafic
sudo ufw logging full     # Debug complet

# Désactiver
sudo ufw logging off
```

### Lire les Logs

```bash
# Fichier de log principal
sudo tail -f /var/log/ufw.log

# Via dmesg (kernel)
sudo dmesg | grep UFW

# Via journalctl
sudo journalctl | grep UFW
```

### Exemple de Log

```
Jan 15 10:30:45 server kernel: [UFW BLOCK] IN=eth0 OUT= MAC=...
SRC=1.2.3.4 DST=192.168.1.10 LEN=40 TOS=0x00 PROTO=TCP SPT=54321
DPT=22 WINDOW=1024 RES=0x00 SYN URGP=0
```

| Champ | Description |
|-------|-------------|
| `UFW BLOCK` | Action (BLOCK, ALLOW, AUDIT) |
| `IN=eth0` | Interface d'entrée |
| `SRC=1.2.3.4` | IP source |
| `DST=192.168.1.10` | IP destination |
| `DPT=22` | Port destination |
| `PROTO=TCP` | Protocole |

---

## Quick Reference

```bash
# Installation
sudo apt install ufw

# TOUJOURS autoriser SSH d'abord !
sudo ufw allow ssh

# Politique par défaut
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Activer
sudo ufw enable

# État
sudo ufw status verbose
sudo ufw status numbered

# Règles
sudo ufw allow 80/tcp
sudo ufw allow from 192.168.1.0/24
sudo ufw delete allow 80/tcp

# Applications
sudo ufw app list
sudo ufw allow 'Nginx Full'

# Logging
sudo ufw logging on
tail -f /var/log/ufw.log
```
