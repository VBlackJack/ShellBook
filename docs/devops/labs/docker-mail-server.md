---
tags:
  - docker
  - mail
  - postfix
  - dovecot
  - lab
---

# Lab : Construire un Serveur Mail avec Docker

Objectif : Comprendre l'architecture d'un système de messagerie en le construisant brique par brique avec Docker Compose.

Ce lab est basé sur les travaux de Thomas Boutry.

## Niveau 1 : Le Relais SMTP Simple

Nous allons commencer par un conteneur unique capable d'envoyer des emails.

### 1. Architecture
*   **Service** : Postfix
*   **Port** : 25 (SMTP)
*   **Rôle** : Accepter les mails et les relayer (ou les stocker localement).

### 2. Configuration (`docker-compose.yml`)

```yaml
version: '3'
services:
  smtp:
    build: .
    ports:
      - "2525:25" # On mappe le 25 interne sur le 2525 hôte pour éviter les conflits
    environment:
      - MY_DOMAIN=example.com
```

### 3. Le Dockerfile

```dockerfile
FROM debian:stable-slim

# Installation de Postfix et Supervisor (pour garder le conteneur en vie)
RUN apt-get update && apt-get install -y \
    postfix \
    supervisor \
    rsyslog \
    && rm -rf /var/lib/apt/lists/*

# Configuration Postfix basique
COPY conf/postfix-main.cf /etc/postfix/main.cf
COPY conf/supervisor.conf /etc/supervisor/conf.d/supervisord.conf

# Exposition du port SMTP
EXPOSE 25

# Démarrage
CMD ["/usr/bin/supervisord"]
```

## Niveau 2 : Séparation SMTP & IMAP

Une vraie architecture sépare la **réception** (SMTP) de la **relève** (IMAP).

### 1. Architecture
*   **Conteneur SMTP (Postfix)** : Reçoit les mails et les écrit dans un volume partagé.
*   **Conteneur IMAP (Dovecot)** : Lit les mails dans le volume partagé pour les servir aux clients (Outlook, Thunderbird).
*   **Volume** : `vmail_data` partagé entre les deux.

### 2. Configuration (`docker-compose.yml`)

```yaml
version: '3'
services:
  smtp:
    image: my-postfix
    volumes:
      - vmail_data:/var/mail
    networks:
      - mailnet

  imap:
    image: my-dovecot
    ports:
      - "143:143"
    volumes:
      - vmail_data:/var/mail
    networks:
      - mailnet

volumes:
  vmail_data:

networks:
  mailnet:
```

### 3. Test de fonctionnement

1.  **Envoyer un mail (SMTP)** :
    ```bash
telnet localhost 25
HELO client
MAIL FROM: <test@example.com>
RCPT TO: <user1@example.com>
DATA
Subject: Test Docker
Ceci est un test.
.
QUIT
```

2.  **Lire le mail (IMAP)** :
    ```bash
telnet localhost 143
a1 LOGIN user1 password
a2 SELECT INBOX
a3 FETCH 1 BODY[]
a4 LOGOUT
```

## Niveau 3 : L'Architecture Complète (ISP Style)

Pour gérer des milliers d'utilisateurs, on ne crée pas des comptes Linux locaux (`/etc/passwd`). On utilise une base de données.

*   **MySQL/MariaDB** : Stocke les utilisateurs, mots de passe et domaines.
*   **PostfixAdmin** : Interface Web pour créer les comptes.
*   **Postfix/Dovecot** : Configurés pour s'authentifier via SQL.

### Challenge
Essayez d'intégrer **Rspamd** (Anti-spam) à cette architecture.
C'est le standard moderne pour filtrer les mails avant qu'ils n'arrivent à Dovecot.

```