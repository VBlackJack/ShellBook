---
tags:
  - tutos
  - containers
  - docker
  - debian
---

# Docker CE sur Debian 12

Installation de **Docker Community Edition** sur Debian 12 Bookworm.

| Composant | Version |
|-----------|---------|
| Debian | 12 Bookworm |
| Docker CE | 24.x |
| Docker Compose | 2.x |

**Durée estimée :** 20 minutes

---

## 1. Prérequis

```bash
# Supprimer anciennes versions
apt remove -y docker docker-engine docker.io containerd runc

# Dépendances
apt update
apt install -y ca-certificates curl gnupg
```

---

## 2. Installation

### Ajouter le dépôt Docker

```bash
# Clé GPG
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg

# Dépôt
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  tee /etc/apt/sources.list.d/docker.list > /dev/null
```

### Installer Docker

```bash
apt update
apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

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
usermod -aG docker $USER
newgrp docker

# Tester
docker run hello-world
```

### Configuration daemon

```bash
cat > /etc/docker/daemon.json << 'EOF'
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "storage-driver": "overlay2",
  "live-restore": true,
  "default-address-pools": [
    {"base": "172.17.0.0/16", "size": 24}
  ]
}
EOF

systemctl restart docker
```

---

## 4. Commandes de base

### Images

```bash
docker pull nginx:alpine
docker images
docker rmi nginx:alpine
```

### Conteneurs

```bash
# Lancer
docker run -d --name web -p 8080:80 nginx:alpine

# Gérer
docker ps
docker logs -f web
docker exec -it web sh
docker stop web
docker rm web
```

### Volumes

```bash
docker volume create appdata
docker run -d -v appdata:/data myapp
docker run -d -v $(pwd)/html:/var/www:ro nginx
```

### Réseaux

```bash
docker network create mynet
docker run -d --network mynet --name web nginx
docker run -d --network mynet --name app myapp
```

---

## 5. Docker Compose

```yaml
# compose.yml
version: "3.8"

services:
  frontend:
    image: nginx:alpine
    ports:
      - "80:80"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./www:/usr/share/nginx/html:ro
    depends_on:
      - backend
    restart: unless-stopped

  backend:
    build:
      context: ./backend
      dockerfile: Dockerfile
    environment:
      - DB_HOST=database
      - DB_NAME=app
    depends_on:
      database:
        condition: service_healthy
    restart: unless-stopped

  database:
    image: postgres:15
    environment:
      POSTGRES_DB: app
      POSTGRES_USER: user
      POSTGRES_PASSWORD: secret
    volumes:
      - pgdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U user -d app"]
      interval: 10s
      timeout: 5s
      retries: 5
    restart: unless-stopped

volumes:
  pgdata:
```

```bash
docker compose up -d
docker compose logs -f
docker compose ps
docker compose down
```

---

## 6. Build d'images

### Dockerfile multi-stage

```dockerfile
# Build stage
FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

# Production stage
FROM nginx:alpine AS production
COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/nginx.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
```

```bash
docker build -t myapp:1.0 .
docker build --target builder -t myapp:dev .
```

---

## 7. Registry

```bash
# Docker Hub
docker login
docker tag myapp:1.0 user/myapp:1.0
docker push user/myapp:1.0

# Registry local
docker run -d -p 5000:5000 --restart always registry:2
docker tag myapp:1.0 localhost:5000/myapp:1.0
docker push localhost:5000/myapp:1.0
```

---

## 8. Firewall UFW

```bash
# Docker modifie iptables directement
# UFW peut être contourné par défaut

# Pour forcer UFW
cat >> /etc/ufw/after.rules << 'EOF'
*filter
:DOCKER-USER - [0:0]
-A DOCKER-USER -j RETURN
COMMIT
EOF

ufw reload
```

---

## 9. Healthchecks

```yaml
# Dans compose.yml
services:
  web:
    image: nginx
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost/"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
```

```bash
docker inspect --format='{{.State.Health.Status}}' web
```

---

## 10. Ressources et limites

```bash
# Limiter mémoire et CPU
docker run -d \
    --memory="256m" \
    --memory-swap="512m" \
    --cpus="0.5" \
    --pids-limit=50 \
    myapp

# Dans compose.yml
services:
  app:
    image: myapp
    deploy:
      resources:
        limits:
          cpus: '0.5'
          memory: 256M
        reservations:
          cpus: '0.25'
          memory: 128M
```

---

## 11. Logs

```bash
# Voir les logs
docker logs container_name
docker logs -f --tail 100 container_name

# Driver de log
docker run -d \
    --log-driver=json-file \
    --log-opt max-size=10m \
    --log-opt max-file=3 \
    myapp
```

---

## 12. Nettoyage

```bash
# Conteneurs arrêtés
docker container prune -f

# Images orphelines
docker image prune -a -f

# Volumes non utilisés
docker volume prune -f

# Tout (attention!)
docker system prune -a --volumes -f

# Vérifier l'espace
docker system df
```

---

## 13. Backup

```bash
# Exporter un conteneur
docker export container_name > backup.tar

# Sauvegarder une image
docker save myapp:1.0 > myapp.tar

# Restaurer
docker load < myapp.tar

# Backup volume
docker run --rm \
    -v myvolume:/data \
    -v $(pwd):/backup \
    alpine tar czf /backup/volume-backup.tar.gz /data
```

---

## Comparatif Rocky vs Debian

| Aspect | Rocky 9 | Debian 12 |
|--------|---------|-----------|
| Dépôt | centos | debian |
| SELinux | Oui | Non (AppArmor) |
| Firewall | firewalld | ufw/iptables |
| Volumes | :z/:Z | Standard |

---

## Vérification

```bash
docker --version
docker compose version
docker info
docker run --rm hello-world
```

---

## Dépannage

```bash
journalctl -u docker -f
docker logs container_name
docker inspect container_name
docker events
```

| Problème | Solution |
|----------|----------|
| Permission denied | `usermod -aG docker $USER` |
| Port in use | `docker ps -a` + `docker rm -f` |
| Disk full | `docker system prune -a` |
| Network issue | `docker network prune` |

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
