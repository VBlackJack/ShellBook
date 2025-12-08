---
tags:
  - docker
  - containers
  - cheatsheet
  - devops
---

# Docker Cheatsheet

Guide de référence complet pour Docker: images, containers, networks, volumes et Docker Compose.

---

## 1. Images

### Gestion des Images

| Action | Commande | Description |
|--------|----------|-------------|
| **Lister images** | `docker images` ou `docker image ls` | Afficher toutes les images locales |
| **Pull image** | `docker pull <image>:<tag>` | Télécharger une image du registry |
| **Build image** | `docker build -t <nom>:<tag> .` | Construire une image depuis un Dockerfile |
| **Tag image** | `docker tag <image> <nouveau-nom>:<tag>` | Renommer/créer un alias d'image |
| **Push image** | `docker push <image>:<tag>` | Envoyer une image vers un registry |
| **Remove image** | `docker rmi <image>` | Supprimer une image |
| **Inspecter image** | `docker inspect <image>` | Détails complets de l'image |
| **Historique** | `docker history <image>` | Voir les layers de l'image |

```bash
# Télécharger une image
docker pull nginx:latest
docker pull ubuntu:22.04
docker pull postgres:15-alpine

# Build une image avec tag
docker build -t myapp:v1.0 .
docker build -t myapp:latest -f Dockerfile.prod .

# Build avec arguments
docker build --build-arg VERSION=1.0 -t myapp:v1.0 .

# Build sans cache
docker build --no-cache -t myapp:latest .

# Tag et push vers un registry
docker tag myapp:v1.0 registry.example.com/myapp:v1.0
docker push registry.example.com/myapp:v1.0

# Sauvegarder une image dans un fichier
docker save nginx:latest > nginx.tar
docker save -o nginx.tar nginx:latest

# Charger une image depuis un fichier
docker load < nginx.tar
docker load -i nginx.tar
```

### Recherche & Registry

```bash
# Rechercher une image sur Docker Hub
docker search nginx
docker search postgres --limit 5

# Se connecter à un registry
docker login
docker login registry.example.com -u username

# Se déconnecter
docker logout
docker logout registry.example.com

# Voir les tags disponibles (nécessite curl)
curl -s https://registry.hub.docker.com/v2/repositories/library/nginx/tags | jq '.results[].name'
```

---

## 2. Containers

### Cycle de Vie des Containers

| Action | Commande | Description |
|--------|----------|-------------|
| **Run** | `docker run <image>` | Créer et démarrer un container |
| **Run détaché** | `docker run -d <image>` | Démarrer en arrière-plan |
| **Run interactif** | `docker run -it <image> /bin/bash` | Mode interactif avec shell |
| **Run temporaire** | `docker run --rm <image>` | Auto-suppression après arrêt |
| **Start** | `docker start <container>` | Démarrer un container arrêté |
| **Stop** | `docker stop <container>` | Arrêter proprement (SIGTERM) |
| **Kill** | `docker kill <container>` | Arrêter brutalement (SIGKILL) |
| **Restart** | `docker restart <container>` | Redémarrer un container |
| **Pause** | `docker pause <container>` | Suspendre les processus |
| **Unpause** | `docker unpause <container>` | Reprendre les processus |
| **Remove** | `docker rm <container>` | Supprimer un container arrêté |
| **Force remove** | `docker rm -f <container>` | Supprimer même si en cours |

```bash
# Lancer un container simple
docker run nginx

# Lancer en arrière-plan avec nom
docker run -d --name web nginx

# Lancer avec port mapping
docker run -d -p 8080:80 --name web nginx

# Lancer avec variables d'environnement
docker run -d -e MYSQL_ROOT_PASSWORD=secret -e MYSQL_DATABASE=mydb mysql:8

# Lancer avec volume
docker run -d -v /host/path:/container/path nginx

# Lancer avec limite de ressources
docker run -d --memory="512m" --cpus="1.5" nginx

# Lancer avec restart policy
docker run -d --restart=always --name web nginx

# Container temporaire pour tester
docker run --rm -it alpine sh

# Exécuter une commande sans créer de container persistant
docker run --rm ubuntu:22.04 cat /etc/os-release
```

### Listing & Inspection

```bash
# Lister les containers actifs
docker ps
docker container ls

# Lister tous les containers (actifs + arrêtés)
docker ps -a
docker container ls -a

# Lister seulement les IDs
docker ps -q
docker ps -aq

# Format personnalisé
docker ps --format "table {{.ID}}\t{{.Names}}\t{{.Status}}"

# Voir les containers avec leur taille
docker ps -s

# Filtrer les containers
docker ps -f "status=running"
docker ps -f "name=web"
docker ps -f "ancestor=nginx"

# Inspecter un container
docker inspect <container>
docker inspect <container> | jq '.[0].NetworkSettings.IPAddress'

# Statistiques en temps réel
docker stats
docker stats --no-stream

# Processus dans un container
docker top <container>
```

---

## 3. Logs & Debugging

### Logs

| Action | Commande |
|--------|----------|
| **Voir logs** | `docker logs <container>` |
| **Follow logs** | `docker logs -f <container>` |
| **Dernières N lignes** | `docker logs --tail 100 <container>` |
| **Logs depuis X temps** | `docker logs --since 1h <container>` |
| **Logs avec timestamps** | `docker logs -t <container>` |

```bash
# Voir les logs
docker logs web

# Suivre les logs en temps réel
docker logs -f web

# Dernières 100 lignes
docker logs --tail 100 web

# Logs depuis 1 heure
docker logs --since 1h web
docker logs --since 2024-01-01T10:00:00 web

# Logs avec timestamps
docker logs -t web

# Combiner plusieurs options
docker logs -f --tail 50 --since 10m web
```

### Exec & Attach

```bash
# Ouvrir un shell dans un container actif
docker exec -it web bash
docker exec -it web sh  # Si bash n'est pas disponible

# Exécuter une commande
docker exec web ls -la /var/www/html
docker exec web ps aux
docker exec web env

# Exécuter en tant qu'utilisateur spécifique
docker exec -u root web whoami

# Attacher à un container actif (voir stdout/stderr)
docker attach web

# Copier des fichiers depuis/vers un container
docker cp web:/var/log/nginx/access.log ./access.log
docker cp config.yaml web:/etc/app/config.yaml
```

### Debugging

```bash
# Voir les changements du filesystem
docker diff <container>

# Événements Docker
docker events
docker events --filter "type=container"
docker events --since 1h

# Voir les ports mappés
docker port <container>

# Informations détaillées
docker inspect <container>

# Voir les processus du container
docker top <container>

# Export filesystem d'un container
docker export <container> > container-backup.tar

# Import d'un container depuis un tarball
docker import container-backup.tar myimage:backup
```

---

## 4. Networks

### Gestion des Réseaux

| Action | Commande |
|--------|----------|
| **Lister networks** | `docker network ls` |
| **Créer network** | `docker network create <nom>` |
| **Inspecter network** | `docker network inspect <nom>` |
| **Connecter container** | `docker network connect <network> <container>` |
| **Déconnecter** | `docker network disconnect <network> <container>` |
| **Supprimer network** | `docker network rm <nom>` |
| **Cleanup networks** | `docker network prune` |

```bash
# Lister les réseaux
docker network ls

# Créer un network bridge
docker network create mynetwork
docker network create --driver bridge mynetwork

# Créer un network avec subnet spécifique
docker network create --subnet=172.20.0.0/16 mynetwork

# Inspecter un network
docker network inspect bridge
docker network inspect mynetwork

# Lancer un container sur un network
docker run -d --name web --network mynetwork nginx
docker run -d --name db --network mynetwork mysql:8

# Connecter un container existant à un network
docker network connect mynetwork web

# Déconnecter un container
docker network disconnect mynetwork web

# Supprimer un network
docker network rm mynetwork

# Nettoyer les networks non utilisés
docker network prune -f
```

### Types de Networks

```bash
# Bridge (défaut): Réseau isolé sur l'hôte
docker network create --driver bridge app-network

# Host: Partage le réseau de l'hôte
docker run -d --network host nginx

# None: Pas de réseau
docker run -d --network none alpine

# Overlay: Communication entre hôtes Docker Swarm
docker network create --driver overlay my-overlay-net
```

### Communication Entre Containers

```bash
# Créer un réseau pour l'application
docker network create webapp

# Lancer une base de données
docker run -d \
  --name postgres \
  --network webapp \
  -e POSTGRES_PASSWORD=secret \
  postgres:15

# Lancer l'application (peut accéder à postgres via son nom)
docker run -d \
  --name app \
  --network webapp \
  -e DATABASE_HOST=postgres \
  myapp:latest

# Test de connectivité
docker exec app ping postgres
docker exec app nslookup postgres
```

---

## 5. Volumes & Storage

### Gestion des Volumes

| Action | Commande |
|--------|----------|
| **Lister volumes** | `docker volume ls` |
| **Créer volume** | `docker volume create <nom>` |
| **Inspecter volume** | `docker volume inspect <nom>` |
| **Supprimer volume** | `docker volume rm <nom>` |
| **Cleanup volumes** | `docker volume prune` |

```bash
# Créer un volume
docker volume create mydata

# Lister les volumes
docker volume ls

# Inspecter un volume
docker volume inspect mydata

# Utiliser un volume avec un container
docker run -d -v mydata:/var/lib/mysql --name db mysql:8

# Bind mount (lier un dossier de l'hôte)
docker run -d -v /host/path:/container/path nginx
docker run -d -v $(pwd):/app node:18

# Bind mount en lecture seule
docker run -d -v /host/path:/container/path:ro nginx

# Volume temporaire (tmpfs)
docker run -d --tmpfs /tmp:size=100m nginx

# Supprimer un volume
docker volume rm mydata

# Nettoyer les volumes non utilisés
docker volume prune -f
```

### Types de Montage

```bash
# 1. Named Volume (géré par Docker, recommandé pour la persistance)
docker run -d -v mysql-data:/var/lib/mysql mysql:8

# 2. Bind Mount (lier un dossier de l'hôte)
docker run -d -v /home/user/data:/data nginx

# 3. tmpfs Mount (en mémoire, non persistant)
docker run -d --tmpfs /cache:rw,size=100m nginx

# Format moderne (--mount, plus verbeux mais plus clair)
docker run -d \
  --mount type=volume,source=mysql-data,target=/var/lib/mysql \
  mysql:8

docker run -d \
  --mount type=bind,source=/host/path,target=/app \
  nginx
```

---

## 6. Docker Compose

### Commandes de Base

| Action | Commande | Description |
|--------|----------|-------------|
| **Start** | `docker compose up` | Démarrer les services |
| **Start détaché** | `docker compose up -d` | Démarrer en arrière-plan |
| **Stop** | `docker compose stop` | Arrêter les services |
| **Down** | `docker compose down` | Arrêter et supprimer |
| **Down + volumes** | `docker compose down -v` | Supprimer aussi les volumes |
| **Logs** | `docker compose logs` | Voir les logs |
| **Follow logs** | `docker compose logs -f` | Suivre les logs |
| **Liste services** | `docker compose ps` | Lister les containers |
| **Build** | `docker compose build` | Build les images |
| **Pull** | `docker compose pull` | Pull les images |
| **Exec** | `docker compose exec <service> <cmd>` | Exécuter une commande |
| **Restart** | `docker compose restart` | Redémarrer les services |

```bash
# Démarrer les services
docker compose up
docker compose up -d  # Détaché

# Démarrer des services spécifiques
docker compose up web db

# Build et start
docker compose up --build

# Voir les logs
docker compose logs
docker compose logs -f  # Follow
docker compose logs -f web  # Logs d'un service

# Lister les containers
docker compose ps
docker compose ps -a

# Exécuter une commande
docker compose exec web bash
docker compose exec db psql -U postgres

# Stopper les services
docker compose stop
docker compose stop web  # Un service spécifique

# Redémarrer
docker compose restart
docker compose restart web

# Arrêter et supprimer tout
docker compose down
docker compose down -v  # Avec les volumes
docker compose down --rmi all  # Avec les images

# Scaler un service
docker compose up -d --scale web=3

# Voir la config finale (après merge des fichiers)
docker compose config

# Valider le fichier compose
docker compose config --quiet
```

### Exemple docker-compose.yml

```yaml
version: '3.8'

services:
  # Service web (Nginx)
  web:
    image: nginx:latest
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./html:/usr/share/nginx/html:ro
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
    depends_on:
      - app
    networks:
      - frontend
    restart: unless-stopped

  # Service application (Node.js)
  app:
    build:
      context: ./app
      dockerfile: Dockerfile
      args:
        NODE_ENV: production
    environment:
      - DATABASE_HOST=db
      - DATABASE_PORT=5432
      - DATABASE_NAME=myapp
      - DATABASE_USER=postgres
      - DATABASE_PASSWORD=secret
    volumes:
      - ./app:/usr/src/app
      - /usr/src/app/node_modules  # Volume anonyme pour node_modules
    depends_on:
      - db
      - redis
    networks:
      - frontend
      - backend
    restart: unless-stopped

  # Service base de données (PostgreSQL)
  db:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: myapp
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: secret
    volumes:
      - postgres-data:/var/lib/postgresql/data
      - ./init.sql:/docker-entrypoint-initdb.d/init.sql
    networks:
      - backend
    restart: unless-stopped
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 10s
      timeout: 5s
      retries: 5

  # Service cache (Redis)
  redis:
    image: redis:7-alpine
    volumes:
      - redis-data:/data
    networks:
      - backend
    restart: unless-stopped
    command: redis-server --appendonly yes

volumes:
  postgres-data:
  redis-data:

networks:
  frontend:
  backend:
```

### Commandes Avancées

```bash
# Utiliser plusieurs fichiers compose (override)
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d

# Variables d'environnement depuis un fichier
docker compose --env-file .env.production up -d

# Forcer la recréation des containers
docker compose up -d --force-recreate

# Recréer seulement si changements
docker compose up -d --no-recreate

# Build sans cache
docker compose build --no-cache

# Pull les dernières images
docker compose pull

# Voir les images utilisées
docker compose images

# Voir les volumes
docker compose volume ls

# Top des processus
docker compose top

# Événements en temps réel
docker compose events

# Pause/Unpause
docker compose pause
docker compose unpause
```

---

## 7. Cleanup & Maintenance

### Nettoyage des Ressources

```bash
# Supprimer tous les containers arrêtés
docker container prune
docker container prune -f  # Sans confirmation

# Supprimer toutes les images non utilisées
docker image prune
docker image prune -a  # Incluant les images non taguées

# Supprimer tous les volumes non utilisés
docker volume prune
docker volume prune -f

# Supprimer tous les networks non utilisés
docker network prune
docker network prune -f

# Nettoyage complet (ATTENTION!)
docker system prune
docker system prune -a  # Inclut toutes les images
docker system prune -a --volumes  # Inclut aussi les volumes

# Voir l'espace disque utilisé
docker system df
docker system df -v  # Détaillé
```

### Gestion de l'Espace

```bash
# Voir l'utilisation du disque
docker system df

# Exemple de sortie:
# TYPE            TOTAL     ACTIVE    SIZE      RECLAIMABLE
# Images          15        5         2.5GB     1.2GB (48%)
# Containers      10        3         500MB     300MB (60%)
# Local Volumes   8         2         1GB       800MB (80%)
# Build Cache     20        0         3GB       3GB (100%)

# Supprimer les images non utilisées depuis X jours
docker image prune -a --filter "until=720h"  # 30 jours

# Supprimer containers arrêtés depuis X temps
docker container prune --filter "until=24h"

# Voir les layers d'une image
docker history nginx:latest

# Cleanup build cache
docker builder prune
docker builder prune -a -f  # Tout supprimer
```

---

## 8. Build & Dockerfile

### Commandes de Build

```bash
# Build basique
docker build -t myapp:latest .

# Build avec un Dockerfile spécifique
docker build -f Dockerfile.prod -t myapp:prod .

# Build avec arguments
docker build --build-arg VERSION=1.0 --build-arg ENV=prod -t myapp:v1 .

# Build sans cache
docker build --no-cache -t myapp:latest .

# Build avec target (multi-stage)
docker build --target production -t myapp:prod .

# Build avec secret (BuildKit)
docker build --secret id=mysecret,src=./secret.txt -t myapp .

# Build pour une plateforme spécifique
docker build --platform linux/amd64 -t myapp:amd64 .
docker buildx build --platform linux/amd64,linux/arm64 -t myapp:multi .

# Voir le build cache
docker builder ls
```

### Exemple Dockerfile Multi-stage

```dockerfile
# Stage 1: Build
FROM node:18-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
RUN npm run build

# Stage 2: Production
FROM node:18-alpine AS production
WORKDIR /app

# Créer un utilisateur non-root
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001

# Copier seulement le nécessaire depuis le builder
COPY --from=builder --chown=nodejs:nodejs /app/dist ./dist
COPY --from=builder --chown=nodejs:nodejs /app/node_modules ./node_modules
COPY --from=builder --chown=nodejs:nodejs /app/package*.json ./

USER nodejs

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node healthcheck.js

CMD ["node", "dist/index.js"]
```

### Best Practices Dockerfile

```dockerfile
# 1. Utiliser des images de base officielles et spécifiques
FROM node:18.17-alpine3.18

# 2. Définir le working directory
WORKDIR /app

# 3. Copier package.json en premier (cache layer)
COPY package*.json ./

# 4. Installer les dépendances
RUN npm ci --only=production && \
    npm cache clean --force

# 5. Copier le code source
COPY . .

# 6. Utiliser un utilisateur non-root
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser

# 7. Exposer le port
EXPOSE 3000

# 8. Health check
HEALTHCHECK CMD curl --fail http://localhost:3000/health || exit 1

# 9. CMD avec format exec (recommandé)
CMD ["node", "server.js"]
```

---

## 9. Registry & Distribution

### Docker Hub

```bash
# Login
docker login
docker login -u username -p password

# Tag pour Docker Hub
docker tag myapp:latest username/myapp:latest
docker tag myapp:latest username/myapp:v1.0

# Push vers Docker Hub
docker push username/myapp:latest
docker push username/myapp:v1.0

# Logout
docker logout
```

### Registry Privé

```bash
# Lancer un registry local
docker run -d -p 5000:5000 --name registry registry:2

# Tag pour registry privé
docker tag myapp:latest localhost:5000/myapp:latest
docker tag myapp:latest registry.example.com/myapp:latest

# Push vers registry privé
docker push localhost:5000/myapp:latest
docker push registry.example.com/myapp:latest

# Pull depuis registry privé
docker pull localhost:5000/myapp:latest

# Login vers registry privé
docker login registry.example.com -u username
```

---

## 10. Security & Best Practices

### Sécurité

```bash
# Scanner une image pour les vulnérabilités (avec Docker Scout)
docker scout cves nginx:latest
docker scout cves myapp:latest

# Scan avec Trivy
trivy image nginx:latest
trivy image --severity HIGH,CRITICAL myapp:latest

# Voir les capabilities d'un container
docker inspect <container> | jq '.[0].HostConfig.CapAdd'

# Limiter les ressources
docker run -d \
  --memory="512m" \
  --memory-swap="1g" \
  --cpus="1.5" \
  --pids-limit=100 \
  nginx

# Lancer en mode read-only
docker run -d --read-only --tmpfs /tmp nginx

# Utiliser user namespace remapping
# Dans /etc/docker/daemon.json:
# {
#   "userns-remap": "default"
# }

# Ne pas lancer en root
docker run -d --user 1000:1000 nginx
```

### Best Practices

```bash
# 1. Toujours utiliser des tags spécifiques (pas :latest)
docker pull nginx:1.25.3-alpine

# 2. Minimiser les layers (combiner les RUN)
# MAUVAIS:
# RUN apt-get update
# RUN apt-get install -y curl
# RUN apt-get install -y vim

# BON:
# RUN apt-get update && apt-get install -y \
#     curl \
#     vim \
#     && rm -rf /var/lib/apt/lists/*

# 3. Utiliser .dockerignore
cat > .dockerignore << EOF
node_modules
.git
.env
*.log
EOF

# 4. Ne pas stocker de secrets dans les images
# Utiliser docker secrets ou variables d'environnement au runtime

# 5. Limiter les privilèges
docker run -d --cap-drop=ALL --cap-add=NET_BIND_SERVICE nginx

# 6. Utiliser health checks
docker run -d \
  --health-cmd="curl -f http://localhost/ || exit 1" \
  --health-interval=30s \
  --health-timeout=3s \
  --health-retries=3 \
  nginx
```

---

## 11. Tips & Aliases

### Aliases Utiles

```bash
# Ajouter dans ~/.bashrc ou ~/.zshrc

# Docker shortcuts
alias d='docker'
alias dc='docker compose'
alias dps='docker ps'
alias dpsa='docker ps -a'
alias di='docker images'
alias dex='docker exec -it'
alias dlogs='docker logs -f'

# Cleanup aliases
alias dclean='docker system prune -af'
alias dcleanv='docker system prune -af --volumes'
alias drmi='docker rmi $(docker images -q)'
alias drm='docker rm $(docker ps -aq)'

# Quick run
alias drun='docker run --rm -it'
alias drunb='docker run --rm -it busybox'
alias druna='docker run --rm -it alpine sh'

# Stats
alias dstats='docker stats --no-stream'
alias dsystem='docker system df'
```

### One-liners Utiles

```bash
# Stopper tous les containers
docker stop $(docker ps -q)

# Supprimer tous les containers
docker rm $(docker ps -aq)

# Supprimer toutes les images
docker rmi $(docker images -q)

# Supprimer images dangling
docker rmi $(docker images -f "dangling=true" -q)

# Logs de tous les containers
docker ps -q | xargs -L 1 docker logs

# Obtenir l'IP d'un container
docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' <container>

# Voir les ports mappés
docker inspect -f '{{range $p, $conf := .NetworkSettings.Ports}}{{$p}} -> {{(index $conf 0).HostPort}}{{end}}' <container>

# Exec bash dans tous les containers actifs
docker ps -q | xargs -I {} docker exec -it {} bash

# Copier un fichier vers tous les containers d'une image
docker ps -q --filter ancestor=nginx | xargs -I {} docker cp config.yaml {}:/etc/nginx/
```

---

## Ressources Complémentaires

- **Documentation officielle**: https://docs.docker.com/
- **Docker Hub**: https://hub.docker.com/
- **Dockerfile best practices**: https://docs.docker.com/develop/develop-images/dockerfile_best-practices/
- **Docker Compose spec**: https://docs.docker.com/compose/compose-file/
- **Awesome Docker**: https://github.com/veggiemonk/awesome-docker

!!! tip "Aller Plus Loin"
    - Explorez **Docker Swarm** pour l'orchestration native
    - Apprenez **Kubernetes** pour l'orchestration avancée
    - Utilisez **Hadolint** pour linter vos Dockerfiles
    - Intégrez **Trivy** ou **Snyk** pour la sécurité des images
