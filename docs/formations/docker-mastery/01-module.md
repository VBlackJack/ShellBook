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

## 5. Exercice : À Vous de Jouer

!!! example "Mise en Pratique"
    **Objectif** : Maîtriser le cycle de vie complet d'un container Docker

    **Contexte** : Vous devez déployer un serveur web nginx, le configurer, surveiller son état et effectuer des opérations de maintenance de base.

    **Tâches à réaliser** :

    1. Vérifier que Docker est correctement installé sur votre système
    2. Lancer un container nginx en mode détaché avec le nom "webserver" et mapper le port 8080 de l'hôte vers le port 80 du container
    3. Vérifier que le serveur répond et consulter les logs d'accès
    4. Se connecter au container en mode interactif et explorer la structure des fichiers nginx
    5. Copier le fichier de configuration nginx depuis le container vers votre machine locale
    6. Arrêter proprement le container, le supprimer, puis nettoyer les ressources non utilisées

    **Critères de validation** :

    - [ ] Le container est accessible via http://localhost:8080
    - [ ] Les logs affichent les requêtes HTTP effectuées
    - [ ] Vous avez pu accéder au shell du container
    - [ ] Le fichier nginx.conf a été récupéré localement
    - [ ] Aucun container ou image orphelin ne subsiste après le nettoyage

??? quote "Solution"
    Voici les commandes pour accomplir cet exercice :

    ```bash
    # 1. Vérifier l'installation Docker
    docker version
    docker info

    # 2. Lancer le container nginx
    docker run -d --name webserver -p 8080:80 nginx

    # Vérifier que le container est en cours d'exécution
    docker ps

    # 3. Tester l'accès et voir les logs
    curl http://localhost:8080
    docker logs webserver
    docker logs -f webserver  # Mode follow (Ctrl+C pour quitter)

    # 4. Accéder au container en bash
    docker exec -it webserver /bin/bash
    # Une fois dans le container :
    ls -la /etc/nginx/
    cat /etc/nginx/nginx.conf
    exit

    # 5. Copier le fichier de configuration
    docker cp webserver:/etc/nginx/nginx.conf ./nginx.conf
    cat nginx.conf

    # 6. Cleanup complet
    docker stop webserver
    docker rm webserver
    docker container prune -f
    docker image prune -f

    # Vérifier le nettoyage
    docker ps -a
    ```

    **Points clés** :

    - `-d` : mode détaché (background)
    - `-p 8080:80` : port host:container
    - `docker exec -it` : mode interactif avec TTY
    - `docker cp` : copier des fichiers entre host et container
    - `prune` : nettoyer les ressources non utilisées

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
