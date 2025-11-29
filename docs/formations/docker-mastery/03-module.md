---
tags:
  - formation
  - docker
  - compose
  - orchestration
---

# Module 3 : Docker Compose

## Objectifs du Module

- Maîtriser la syntaxe Docker Compose
- Orchestrer des applications multi-containers
- Gérer les environnements
- Configurer networks et volumes

**Durée :** 3 heures

---

## 1. Introduction

```yaml
# docker-compose.yml - Structure de base
version: '3.8'  # Optionnel depuis Compose v2

services:
  web:
    image: nginx:alpine
    ports:
      - "80:80"

  api:
    build: ./api
    environment:
      - DATABASE_URL=postgres://db:5432
    depends_on:
      - db

  db:
    image: postgres:15
    volumes:
      - db_data:/var/lib/postgresql/data

volumes:
  db_data:
```

---

## 2. Services

### 2.1 Configuration Complète

```yaml
services:
  api:
    # Build depuis Dockerfile
    build:
      context: ./api
      dockerfile: Dockerfile
      args:
        - VERSION=1.0
      target: production

    # Ou image existante
    image: myregistry/api:latest

    # Container settings
    container_name: myapp-api
    hostname: api
    restart: unless-stopped

    # Ports
    ports:
      - "8080:8080"           # host:container
      - "127.0.0.1:9090:9090" # localhost only

    # Environnement
    environment:
      - NODE_ENV=production
      - DATABASE_URL=${DATABASE_URL}
    env_file:
      - .env
      - .env.local

    # Volumes
    volumes:
      - ./src:/app/src:ro     # Bind mount (dev)
      - node_modules:/app/node_modules
      - /app/dist             # Anonymous volume

    # Réseau
    networks:
      - frontend
      - backend

    # Dépendances
    depends_on:
      db:
        condition: service_healthy
      redis:
        condition: service_started

    # Health check
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

    # Resources
    deploy:
      resources:
        limits:
          cpus: '0.5'
          memory: 512M
        reservations:
          cpus: '0.25'
          memory: 256M

    # Commande
    command: ["npm", "start"]
    entrypoint: ["/entrypoint.sh"]
```

### 2.2 Depends On avec Conditions

```yaml
services:
  api:
    depends_on:
      db:
        condition: service_healthy
      redis:
        condition: service_started
      migration:
        condition: service_completed_successfully

  db:
    image: postgres:15
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 5s
      timeout: 5s
      retries: 5

  migration:
    image: myapp/migration
    command: ["migrate", "up"]
```

---

## 3. Networks et Volumes

### 3.1 Networks

```yaml
services:
  frontend:
    networks:
      - public

  api:
    networks:
      - public
      - private

  db:
    networks:
      - private

networks:
  public:
    driver: bridge
  private:
    driver: bridge
    internal: true  # Pas d'accès externe
```

### 3.2 Volumes

```yaml
services:
  db:
    volumes:
      # Named volume
      - db_data:/var/lib/postgresql/data
      # Bind mount
      - ./init.sql:/docker-entrypoint-initdb.d/init.sql:ro
      # tmpfs
      - type: tmpfs
        target: /tmp

volumes:
  db_data:
    driver: local
    driver_opts:
      type: none
      o: bind
      device: /path/on/host
```

---

## 4. Variables et Environnement

### 4.1 Fichier .env

```bash
# .env
COMPOSE_PROJECT_NAME=myapp
POSTGRES_VERSION=15
DATABASE_PASSWORD=secret
```

```yaml
# docker-compose.yml
services:
  db:
    image: postgres:${POSTGRES_VERSION:-14}
    environment:
      POSTGRES_PASSWORD: ${DATABASE_PASSWORD}
```

### 4.2 Profiles

```yaml
services:
  api:
    # Toujours démarré

  debug:
    image: busybox
    profiles:
      - debug

  test:
    image: myapp/test
    profiles:
      - test
```

```bash
# Démarrer avec profile
docker compose --profile debug up
docker compose --profile test run test
```

---

## 5. Commandes

```bash
# Démarrer
docker compose up
docker compose up -d
docker compose up --build

# Arrêter
docker compose down
docker compose down -v  # + volumes
docker compose down --rmi all  # + images

# Logs
docker compose logs
docker compose logs -f api

# Exec
docker compose exec api sh

# Scale
docker compose up -d --scale api=3

# Config validation
docker compose config

# Build
docker compose build
docker compose build --no-cache
```

---

## 6. Exemple Complet

```yaml
# docker-compose.yml
version: '3.8'

services:
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
    depends_on:
      - api
    networks:
      - frontend

  api:
    build:
      context: ./api
      target: production
    environment:
      - DATABASE_URL=postgres://postgres:${DB_PASSWORD}@db:5432/myapp
      - REDIS_URL=redis://redis:6379
    depends_on:
      db:
        condition: service_healthy
      redis:
        condition: service_started
    networks:
      - frontend
      - backend
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  db:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: myapp
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes:
      - db_data:/var/lib/postgresql/data
      - ./init.sql:/docker-entrypoint-initdb.d/init.sql:ro
    networks:
      - backend
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 5s
      timeout: 5s
      retries: 5

  redis:
    image: redis:7-alpine
    volumes:
      - redis_data:/data
    networks:
      - backend

networks:
  frontend:
  backend:
    internal: true

volumes:
  db_data:
  redis_data:
```

---

## Quiz

1. **Comment démarrer en arrière-plan ?**
   - [ ] A. docker compose up -b
   - [ ] B. docker compose up -d
   - [ ] C. docker compose start

2. **Quelle condition attend que le service soit healthy ?**
   - [ ] A. service_started
   - [ ] B. service_ready
   - [ ] C. service_healthy

**Réponses :** 1-B, 2-C

---

**Précédent :** [Module 2 - Images](02-module.md)

**Suivant :** [Module 4 - Networking](04-module.md)
