---
tags:
  - formation
  - docker
  - containers
  - fundamentals
---

# Module 1 : Fondamentaux Docker

## Objectifs du Module

- Comprendre la conteneurisation
- Installer Docker
- Maîtriser les commandes de base
- Gérer le cycle de vie des containers

**Durée :** 2 heures

---

## 1. Containers vs VMs

```
CONTAINERS vs MACHINES VIRTUELLES
═════════════════════════════════

VM                              CONTAINER
──                              ─────────

┌─────────────────────┐        ┌─────────────────────┐
│       App A         │        │       App A         │
├─────────────────────┤        ├─────────────────────┤
│   Guest OS (GB)     │        │    Bins/Libs        │
├─────────────────────┤        ├─────────────────────┤
│       App B         │        │       App B         │
├─────────────────────┤        ├─────────────────────┤
│   Guest OS (GB)     │        │    Bins/Libs        │
├─────────────────────┤        ├─────────────────────┤
│     Hypervisor      │        │   Container Engine  │
├─────────────────────┤        ├─────────────────────┤
│      Host OS        │        │      Host OS        │
├─────────────────────┤        ├─────────────────────┤
│    Infrastructure   │        │    Infrastructure   │
└─────────────────────┘        └─────────────────────┘

Startup: Minutes               Startup: Secondes
Size: GB                       Size: MB
Isolation: Forte               Isolation: Processus
```

---

## 2. Installation

### 2.1 Linux (Ubuntu/Debian)

```bash
# Supprimer anciennes versions
sudo apt-get remove docker docker-engine docker.io containerd runc

# Prérequis
sudo apt-get update
sudo apt-get install -y \
    ca-certificates \
    curl \
    gnupg \
    lsb-release

# Ajouter la clé GPG
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg

# Ajouter le repository
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Installer Docker
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Ajouter l'utilisateur au groupe docker
sudo usermod -aG docker $USER

# Vérifier
docker version
docker info
```

### 2.2 Windows/Mac

```bash
# Docker Desktop
# Télécharger depuis https://www.docker.com/products/docker-desktop

# Vérifier
docker version
```

---

## 3. Commandes de Base

### 3.1 Images

```bash
# Lister les images
docker images
docker image ls

# Télécharger une image
docker pull nginx
docker pull nginx:1.25-alpine

# Rechercher une image
docker search nginx

# Supprimer une image
docker rmi nginx
docker image rm nginx

# Inspecter une image
docker image inspect nginx

# Historique des layers
docker history nginx
```

### 3.2 Containers

```bash
# Lancer un container
docker run nginx

# En arrière-plan
docker run -d nginx

# Avec un nom
docker run -d --name webserver nginx

# Avec mapping de port
docker run -d -p 8080:80 nginx

# Avec variable d'environnement
docker run -d -e MYSQL_ROOT_PASSWORD=secret mysql

# Mode interactif
docker run -it ubuntu /bin/bash

# Auto-remove à l'arrêt
docker run --rm nginx

# Lister les containers
docker ps          # Running
docker ps -a       # Tous

# Arrêter un container
docker stop webserver

# Démarrer un container
docker start webserver

# Redémarrer
docker restart webserver

# Supprimer
docker rm webserver
docker rm -f webserver  # Force (même si running)

# Supprimer tous les containers arrêtés
docker container prune
```

### 3.3 Interaction avec les Containers

```bash
# Logs
docker logs webserver
docker logs -f webserver  # Follow
docker logs --tail 100 webserver

# Exec dans un container
docker exec -it webserver /bin/bash
docker exec webserver ls /etc/nginx

# Copier des fichiers
docker cp file.txt webserver:/path/
docker cp webserver:/path/file.txt ./

# Stats
docker stats
docker top webserver

# Inspecter
docker inspect webserver
docker inspect webserver --format '{{.NetworkSettings.IPAddress}}'
```

---

## 4. Cycle de Vie

```
CYCLE DE VIE D'UN CONTAINER
═══════════════════════════

         docker create
              │
              ▼
┌─────────────────────────┐
│        CREATED          │
└───────────┬─────────────┘
            │ docker start
            ▼
┌─────────────────────────┐
│        RUNNING          │◄────────────┐
└───────────┬─────────────┘             │
            │                           │
     ┌──────┴──────┐                    │
     │             │                    │
docker stop   docker pause              │
     │             │                    │
     ▼             ▼                    │
┌─────────┐  ┌─────────────┐            │
│ EXITED  │  │   PAUSED    │            │
└────┬────┘  └──────┬──────┘            │
     │              │                   │
docker start    docker unpause          │
     │              │                   │
     └──────────────┴───────────────────┘

docker rm
     │
     ▼
┌─────────────────────────┐
│        DELETED          │
└─────────────────────────┘
```

---

## 5. Exercice Pratique

### Tâches

1. Installer Docker
2. Lancer un container nginx avec port mapping
3. Vérifier les logs
4. Accéder au container en bash
5. Arrêter et supprimer

### Solution

```bash
# 1. Vérifier l'installation
docker version

# 2. Lancer nginx
docker run -d --name web -p 8080:80 nginx

# 3. Vérifier
curl http://localhost:8080
docker logs web

# 4. Accéder
docker exec -it web /bin/bash

# 5. Cleanup
docker stop web
docker rm web
```

---

## Quiz

1. **Quelle commande pour voir les containers en cours ?**
   - [ ] A. docker containers
   - [ ] B. docker ps
   - [ ] C. docker list

2. **Comment mapper le port 80 du container vers 8080 de l'host ?**
   - [ ] A. -p 80:8080
   - [ ] B. -p 8080:80
   - [ ] C. --port 8080=80

**Réponses :** 1-B, 2-B

---

**Suivant :** [Module 2 - Images](02-module.md)
