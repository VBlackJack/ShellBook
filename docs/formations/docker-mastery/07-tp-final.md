---
tags:
  - formation
  - docker
  - tp
---

# TP Final : Application Production-Ready

## Objectifs

- Créer une stack Docker complète
- Appliquer les bonnes pratiques
- Préparer pour la CI/CD

**Durée :** 1 heure

---

## Scénario

Déployer une application web avec :
- Frontend (React/Nginx)
- API (Node.js)
- Base de données (PostgreSQL)
- Cache (Redis)

---

## Architecture

```text
┌─────────────────────────────────────────────────────────┐
│                      Docker Host                         │
│                                                          │
│  ┌──────────┐   ┌──────────┐   ┌──────────┐            │
│  │  Nginx   │──▶│   API    │──▶│ Postgres │            │
│  │  :80     │   │  :3000   │   │  :5432   │            │
│  └──────────┘   └────┬─────┘   └──────────┘            │
│                      │                                   │
│                      ▼                                   │
│                 ┌──────────┐                            │
│                 │  Redis   │                            │
│                 │  :6379   │                            │
│                 └──────────┘                            │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

---

## Solution

### docker-compose.yml

```yaml
version: '3.8'

services:
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./frontend/build:/usr/share/nginx/html:ro
    depends_on:
      - api
    networks:
      - frontend
    restart: unless-stopped

  api:
    build:
      context: ./api
      target: production
    environment:
      - NODE_ENV=production
      - DATABASE_URL=postgres://app:${DB_PASSWORD}@db:5432/myapp
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
      test: ["CMD", "wget", "-q", "--spider", "http://localhost:3000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
    restart: unless-stopped
    read_only: true
    tmpfs:
      - /tmp
    security_opt:
      - no-new-privileges:true

  db:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: myapp
      POSTGRES_USER: app
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes:
      - db_data:/var/lib/postgresql/data
      - ./init.sql:/docker-entrypoint-initdb.d/init.sql:ro
    networks:
      - backend
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U app -d myapp"]
      interval: 5s
      timeout: 5s
      retries: 5
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    command: redis-server --appendonly yes
    volumes:
      - redis_data:/data
    networks:
      - backend
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 3
    restart: unless-stopped

networks:
  frontend:
  backend:
    internal: true

volumes:
  db_data:
  redis_data:
```

### Dockerfile API (Multi-stage)

```dockerfile
# api/Dockerfile
FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:20-alpine AS production
RUN addgroup -S app && adduser -S app -G app
WORKDIR /app
COPY --from=builder --chown=app:app /app/dist ./dist
COPY --from=builder --chown=app:app /app/node_modules ./node_modules
COPY --chown=app:app package.json ./
USER app
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=3s \
  CMD wget -q --spider http://localhost:3000/health || exit 1
CMD ["node", "dist/index.js"]
```

### .env

```bash
DB_PASSWORD=S3cur3P@ssw0rd!
```

---

## Commandes

```bash
# Démarrer
docker compose up -d

# Vérifier
docker compose ps
docker compose logs -f

# Tester
curl http://localhost/api/health

# Cleanup
docker compose down -v
```

---

## Checklist

- [ ] Multi-stage build
- [ ] User non-root
- [ ] Health checks
- [ ] Networks isolés
- [ ] Volumes persistants
- [ ] Security options
- [ ] Environment variables

---

**Précédent :** [Module 6 - Sécurité](06-module.md)

**Retour au programme :** [Index](index.md)

---

## Navigation

| | |
|:---|---:|
| [← Module 6 : Sécurité Docker](06-module.md) | [Programme →](index.md) |

[Retour au Programme](index.md){ .md-button }
