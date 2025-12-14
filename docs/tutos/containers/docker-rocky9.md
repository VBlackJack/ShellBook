---
tags:
  - tutos
  - containers
  - docker
  - rocky
---

# Docker CE sur Rocky Linux 9

Installation de **Docker Community Edition** sur Rocky Linux 9.

| Composant | Version |
|-----------|---------|
| Rocky Linux | 9.x |
| Docker CE | 24.x |
| Docker Compose | 2.x |

**Durée estimée :** 20 minutes

---

## 1. Prérequis

```bash
# Supprimer les anciennes versions
dnf remove -y docker docker-client docker-client-latest \
    docker-common docker-latest docker-latest-logrotate \
    docker-logrotate docker-engine podman runc
```

---

## 2. Installation

### Ajouter le dépôt Docker

```bash
dnf install -y dnf-plugins-core
dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
```

### Installer Docker

```bash
dnf install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Vérifier
docker --version
docker compose version
```

### Démarrer le service

```bash
systemctl enable --now docker
systemctl status docker
```

---

## 3. Post-installation

### Utiliser Docker sans sudo

```bash
# Ajouter l'utilisateur au groupe docker
usermod -aG docker $USER

# Appliquer (se reconnecter ou)
newgrp docker

# Tester
docker run hello-world
```

### Configurer le daemon

```bash
mkdir -p /etc/docker

cat > /etc/docker/daemon.json << 'EOF'
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "storage-driver": "overlay2",
  "live-restore": true
}
EOF

systemctl restart docker
```

---

## 4. Commandes essentielles

### Images

```bash
# Télécharger
docker pull nginx:alpine
docker pull python:3.11

# Lister
docker images

# Supprimer
docker rmi nginx:alpine
```

### Conteneurs

```bash
# Lancer
docker run -d --name web -p 8080:80 nginx:alpine

# Lister
docker ps
docker ps -a

# Logs
docker logs -f web

# Exec
docker exec -it web sh

# Stop/Start/Remove
docker stop web
docker start web
docker rm -f web
```

### Volumes

```bash
# Créer
docker volume create mydata

# Utiliser
docker run -d --name db \
    -v mydata:/var/lib/mysql \
    -e MYSQL_ROOT_PASSWORD=secret \
    mysql:8

# Bind mount
docker run -d --name web \
    -v $(pwd)/html:/usr/share/nginx/html:ro \
    -p 80:80 \
    nginx:alpine
```

### Réseaux

```bash
# Créer
docker network create mynet

# Utiliser
docker run -d --name web --network mynet nginx
docker run -d --name app --network mynet myapp

# Inspecter
docker network inspect mynet
```

---

## 5. Docker Compose

### Fichier compose.yml

```yaml
version: "3.8"

services:
  web:
    image: nginx:alpine
    ports:
      - "80:80"
    volumes:
      - ./www:/usr/share/nginx/html:ro
    depends_on:
      - api
    restart: unless-stopped

  api:
    build: ./api
    environment:
      - DATABASE_URL=mysql://user:pass@db/app
    depends_on:
      - db
    restart: unless-stopped

  db:
    image: mysql:8
    environment:
      MYSQL_ROOT_PASSWORD: rootpass
      MYSQL_USER: user
      MYSQL_PASSWORD: pass
      MYSQL_DATABASE: app
    volumes:
      - db-data:/var/lib/mysql
    restart: unless-stopped

volumes:
  db-data:

networks:
  default:
    name: myapp-network
```

### Commandes Compose

```bash
# Lancer
docker compose up -d

# Logs
docker compose logs -f

# Status
docker compose ps

# Arrêter
docker compose down

# Arrêter et supprimer volumes
docker compose down -v
```

---

## 6. Build d'images

### Dockerfile

```dockerfile
FROM python:3.11-alpine

WORKDIR /app

# Dépendances système
RUN apk add --no-cache gcc musl-dev

# Dépendances Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Code application
COPY . .

# Utilisateur non-root
RUN adduser -D appuser
USER appuser

EXPOSE 5000

CMD ["python", "app.py"]
```

### Build

```bash
docker build -t myapp:1.0 .
docker build -t myapp:latest --no-cache .

# Multi-stage
docker build --target production -t myapp:prod .
```

---

## 7. Registry

### Docker Hub

```bash
docker login

docker tag myapp:1.0 username/myapp:1.0
docker push username/myapp:1.0
```

### Registry privé

```bash
# Lancer un registry local
docker run -d --name registry \
    -p 5000:5000 \
    -v registry:/var/lib/registry \
    --restart always \
    registry:2

# Pousser
docker tag myapp:1.0 localhost:5000/myapp:1.0
docker push localhost:5000/myapp:1.0
```

---

## 8. Firewall

```bash
# Docker gère iptables automatiquement
# Pour exposer un port spécifique
firewall-cmd --permanent --add-port=8080/tcp
firewall-cmd --reload

# Ou désactiver la gestion par Docker
# Dans /etc/docker/daemon.json: "iptables": false
```

---

## 9. SELinux

```bash
# Docker fonctionne avec SELinux
# Pour les volumes, utiliser :z ou :Z
docker run -v /data:/data:z nginx  # Shared
docker run -v /data:/data:Z nginx  # Private

# Vérifier
getenforce
ls -Z /data
```

---

## 10. Monitoring

```bash
# Stats en temps réel
docker stats

# Événements
docker events

# Espace disque
docker system df
```

---

## 11. Nettoyage

```bash
# Conteneurs arrêtés
docker container prune

# Images non utilisées
docker image prune -a

# Volumes orphelins
docker volume prune

# Tout nettoyer
docker system prune -a --volumes

# Attention : supprime TOUT
```

---

## 12. Sécurité

### Limiter les ressources

```bash
docker run -d --name app \
    --memory="512m" \
    --cpus="1.0" \
    --pids-limit=100 \
    myapp:latest
```

### Utilisateur non-root

```dockerfile
# Dans Dockerfile
RUN adduser -D appuser
USER appuser
```

### Read-only filesystem

```bash
docker run --read-only --tmpfs /tmp myapp
```

---

## Vérification

```bash
# Version
docker --version
docker compose version

# Info système
docker info

# Test
docker run --rm hello-world
```

---

## Dépannage

```bash
# Logs Docker
journalctl -u docker -f

# Logs conteneur
docker logs container_name

# Inspecter
docker inspect container_name

# Reset
systemctl restart docker
```

| Problème | Solution |
|----------|----------|
| Permission denied | `usermod -aG docker $USER` + reconnexion |
| Port already in use | `docker ps -a` puis `docker rm -f` |
| No space left | `docker system prune -a` |

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
