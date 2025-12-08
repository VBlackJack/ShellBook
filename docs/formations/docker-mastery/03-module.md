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

## Exercice : À Vous de Jouer

!!! example "Mise en Pratique"
    **Objectif** : Orchestrer une application complète multi-containers avec Docker Compose

    **Contexte** : Vous devez déployer une stack applicative complète comprenant un frontend nginx, une API Node.js, une base de données PostgreSQL et un cache Redis. L'architecture doit respecter les principes de séparation des réseaux et de persistance des données.

    **Tâches à réaliser** :

    1. Créer une structure de projet avec les dossiers appropriés (frontend/, api/)
    2. Écrire un fichier `docker-compose.yml` définissant les 4 services (nginx, api, postgres, redis)
    3. Configurer deux réseaux : `frontend` (public) et `backend` (privé/internal)
    4. Ajouter des volumes nommés pour la persistance de PostgreSQL et Redis
    5. Configurer les dépendances avec healthchecks pour garantir l'ordre de démarrage
    6. Créer un fichier `.env` pour les variables sensibles
    7. Démarrer la stack complète et vérifier la communication entre services

    **Critères de validation** :

    - [ ] Tous les services démarrent sans erreur dans le bon ordre
    - [ ] Le frontend nginx ne peut pas accéder directement à la base de données
    - [ ] L'API peut communiquer avec postgres et redis
    - [ ] Les données persistent après un `docker compose down` et `up`
    - [ ] Les healthchecks fonctionnent correctement
    - [ ] Les logs montrent que les dépendances sont respectées

??? quote "Solution"
    **Étape 1 : Structure du projet**

    ```bash
    mkdir -p myapp/{frontend,api}
    cd myapp
    ```

    **Étape 2 : Fichier .env**

    ```bash
    # .env
    COMPOSE_PROJECT_NAME=myapp
    POSTGRES_VERSION=15
    POSTGRES_PASSWORD=mysecretpassword
    POSTGRES_DB=appdb
    POSTGRES_USER=appuser
    REDIS_VERSION=7-alpine
    NODE_ENV=production
    ```

    **Étape 3 : docker-compose.yml**

    ```yaml
    # docker-compose.yml
    version: '3.8'

    services:
      # Frontend - Nginx
      frontend:
        image: nginx:alpine
        container_name: myapp-frontend
        ports:
          - "80:80"
        volumes:
          - ./frontend/nginx.conf:/etc/nginx/nginx.conf:ro
        depends_on:
          api:
            condition: service_healthy
        networks:
          - frontend
        restart: unless-stopped

      # API - Node.js
      api:
        image: node:20-alpine
        container_name: myapp-api
        working_dir: /app
        volumes:
          - ./api:/app
        environment:
          - NODE_ENV=${NODE_ENV}
          - DATABASE_URL=postgres://${POSTGRES_USER}:${POSTGRES_PASSWORD}@db:5432/${POSTGRES_DB}
          - REDIS_URL=redis://redis:6379
        command: ["node", "server.js"]
        depends_on:
          db:
            condition: service_healthy
          redis:
            condition: service_started
        networks:
          - frontend
          - backend
        healthcheck:
          test: ["CMD", "wget", "--no-verbose", "--tries=1", "--spider", "http://localhost:3000/health"]
          interval: 30s
          timeout: 10s
          retries: 3
          start_period: 40s
        restart: unless-stopped

      # Base de données - PostgreSQL
      db:
        image: postgres:${POSTGRES_VERSION:-15}-alpine
        container_name: myapp-db
        environment:
          POSTGRES_USER: ${POSTGRES_USER}
          POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
          POSTGRES_DB: ${POSTGRES_DB}
        volumes:
          - postgres_data:/var/lib/postgresql/data
          - ./api/init.sql:/docker-entrypoint-initdb.d/init.sql:ro
        networks:
          - backend
        healthcheck:
          test: ["CMD-SHELL", "pg_isready -U ${POSTGRES_USER}"]
          interval: 5s
          timeout: 5s
          retries: 5
        restart: unless-stopped

      # Cache - Redis
      redis:
        image: redis:${REDIS_VERSION:-7-alpine}
        container_name: myapp-redis
        command: redis-server --appendonly yes
        volumes:
          - redis_data:/data
        networks:
          - backend
        restart: unless-stopped

    networks:
      frontend:
        driver: bridge
      backend:
        driver: bridge
        internal: true  # Pas d'accès internet direct

    volumes:
      postgres_data:
        driver: local
      redis_data:
        driver: local
    ```

    **Étape 4 : Configuration nginx**

    ```nginx
    # frontend/nginx.conf
    events {
        worker_connections 1024;
    }

    http {
        upstream api {
            server api:3000;
        }

        server {
            listen 80;

            location / {
                proxy_pass http://api;
                proxy_set_header Host $host;
                proxy_set_header X-Real-IP $remote_addr;
            }
        }
    }
    ```

    **Étape 5 : API simple (exemple)**

    ```javascript
    // api/server.js
    const http = require('http');

    const server = http.createServer((req, res) => {
        if (req.url === '/health') {
            res.writeHead(200);
            res.end(JSON.stringify({ status: 'healthy' }));
        } else {
            res.writeHead(200);
            res.end(JSON.stringify({
                message: 'Hello from API!',
                database: process.env.DATABASE_URL ? 'configured' : 'not configured',
                redis: process.env.REDIS_URL ? 'configured' : 'not configured'
            }));
        }
    });

    server.listen(3000, () => {
        console.log('API listening on port 3000');
    });
    ```

    ```sql
    -- api/init.sql
    CREATE TABLE IF NOT EXISTS health_check (
        id SERIAL PRIMARY KEY,
        checked_at TIMESTAMP DEFAULT NOW()
    );
    ```

    **Étape 6 : Démarrage et tests**

    ```bash
    # Valider la configuration
    docker compose config

    # Démarrer tous les services
    docker compose up -d

    # Voir les logs
    docker compose logs -f

    # Vérifier l'état des services
    docker compose ps

    # Tester l'application
    curl http://localhost

    # Vérifier les réseaux
    docker network ls
    docker network inspect myapp_backend

    # Tester la persistance
    docker compose exec db psql -U appuser -d appdb -c "SELECT * FROM health_check;"

    # Arrêter sans supprimer les volumes
    docker compose down

    # Redémarrer
    docker compose up -d
    # Les données doivent être conservées

    # Cleanup complet (avec volumes)
    docker compose down -v
    ```

    **Points clés** :

    - Deux réseaux séparent frontend et backend pour la sécurité
    - `internal: true` empêche le réseau backend d'accéder à internet
    - Healthchecks garantissent que les services sont prêts avant démarrage des dépendants
    - Volumes nommés assurent la persistance des données
    - `.env` centralise la configuration
    - `depends_on` avec conditions assure l'ordre de démarrage correct

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

---

## Navigation

| | |
|:---|---:|
| [← Module 2 : Images et Dockerfile](02-module.md) | [Module 4 : Networking →](04-module.md) |

[Retour au Programme](index.md){ .md-button }
