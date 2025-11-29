---
tags:
  - formation
  - docker
  - dockerfile
  - images
---

# Module 2 : Images et Dockerfile

## Objectifs du Module

- Comprendre l'anatomie des images
- Écrire des Dockerfiles optimisés
- Maîtriser les multi-stage builds
- Optimiser la taille des images

**Durée :** 3 heures

---

## 1. Anatomie d'une Image

```
LAYERS D'UNE IMAGE
══════════════════

┌─────────────────────────────────┐
│  Layer 5: COPY app.py          │  ← Votre code (change souvent)
├─────────────────────────────────┤
│  Layer 4: RUN pip install      │  ← Dépendances
├─────────────────────────────────┤
│  Layer 3: WORKDIR /app         │
├─────────────────────────────────┤
│  Layer 2: RUN apt-get update   │  ← OS packages
├─────────────────────────────────┤
│  Layer 1: FROM python:3.11     │  ← Image de base
└─────────────────────────────────┘

Chaque instruction crée un layer
Layers sont cachés et réutilisés
Ordre important pour l'optimisation du cache
```

---

## 2. Dockerfile de Base

### 2.1 Instructions Principales

```dockerfile
# Dockerfile

# Image de base
FROM python:3.11-slim

# Métadonnées
LABEL maintainer="dev@example.com"
LABEL version="1.0"

# Variables d'environnement
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    APP_HOME=/app

# Répertoire de travail
WORKDIR $APP_HOME

# Copier les fichiers
COPY requirements.txt .

# Exécuter des commandes
RUN pip install --no-cache-dir -r requirements.txt

# Copier le reste (après les deps pour le cache)
COPY . .

# Exposer un port (documentation)
EXPOSE 8000

# Utilisateur non-root
RUN useradd -m appuser
USER appuser

# Commande par défaut
CMD ["python", "app.py"]

# Ou avec ENTRYPOINT
ENTRYPOINT ["python"]
CMD ["app.py"]
```

### 2.2 CMD vs ENTRYPOINT

```dockerfile
# CMD - Peut être remplacé au runtime
CMD ["python", "app.py"]
# docker run myapp python other.py  → Remplace CMD

# ENTRYPOINT - Toujours exécuté
ENTRYPOINT ["python"]
CMD ["app.py"]
# docker run myapp other.py  → Exécute python other.py

# Forme shell vs exec
CMD python app.py        # Shell form (PID != 1)
CMD ["python", "app.py"] # Exec form (PID = 1, recommandé)
```

---

## 3. Bonnes Pratiques

### 3.1 Optimisation du Cache

```dockerfile
# ❌ Mauvais - Invalide le cache à chaque changement de code
COPY . .
RUN pip install -r requirements.txt

# ✅ Bon - Dépendances d'abord, code ensuite
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
```

### 3.2 Réduire les Layers

```dockerfile
# ❌ Mauvais - 3 layers
RUN apt-get update
RUN apt-get install -y curl
RUN rm -rf /var/lib/apt/lists/*

# ✅ Bon - 1 layer
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*
```

### 3.3 Images Légères

```dockerfile
# Image de base légère
FROM python:3.11-slim    # ~150MB vs ~900MB pour full
FROM python:3.11-alpine  # ~50MB (attention: musl libc)
FROM gcr.io/distroless/python3  # Minimal, pas de shell
```

---

## 4. Multi-Stage Builds

### 4.1 Concept

```dockerfile
# Build stage
FROM golang:1.21 AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o myapp

# Production stage
FROM gcr.io/distroless/static
COPY --from=builder /app/myapp /
EXPOSE 8080
CMD ["/myapp"]
```

### 4.2 Exemple Python

```dockerfile
# Builder
FROM python:3.11-slim AS builder
WORKDIR /app
RUN pip install --user pipenv
COPY Pipfile Pipfile.lock ./
RUN pipenv install --system --deploy

# Production
FROM python:3.11-slim
WORKDIR /app
COPY --from=builder /root/.local /root/.local
COPY . .
ENV PATH=/root/.local/bin:$PATH
CMD ["python", "app.py"]
```

### 4.3 Exemple Node.js

```dockerfile
# Build
FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

# Production
FROM node:20-alpine
WORKDIR /app
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
EXPOSE 3000
CMD ["node", "dist/index.js"]
```

---

## 5. Build et Push

```bash
# Build
docker build -t myapp .
docker build -t myapp:v1.0 .
docker build -f Dockerfile.prod -t myapp:prod .

# Avec arguments de build
docker build --build-arg VERSION=1.0 -t myapp .

# Push vers registry
docker login
docker tag myapp:v1.0 myregistry/myapp:v1.0
docker push myregistry/myapp:v1.0

# Multi-architecture
docker buildx build --platform linux/amd64,linux/arm64 -t myapp:multi .
```

---

## 6. .dockerignore

```
# .dockerignore
.git
.gitignore
.env
*.md
!README.md
Dockerfile*
docker-compose*.yml
__pycache__
*.pyc
node_modules
.npm
*.log
.coverage
tests/
docs/
```

---

## 7. Exercice Pratique

### Tâches

1. Créer un Dockerfile pour une app Python
2. Optimiser avec multi-stage build
3. Build et tester
4. Comparer les tailles

### Solution

```dockerfile
# Dockerfile
FROM python:3.11-slim AS builder
WORKDIR /app
COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

FROM python:3.11-slim
WORKDIR /app
COPY --from=builder /root/.local /root/.local
ENV PATH=/root/.local/bin:$PATH
COPY app.py .
RUN useradd -m appuser && chown -R appuser /app
USER appuser
EXPOSE 5000
CMD ["python", "app.py"]
```

```bash
# Build et compare
docker build -t myapp:v1 .
docker images myapp
```

---

## Quiz

1. **Quelle instruction définit la commande par défaut ?**
   - [ ] A. RUN
   - [ ] B. CMD
   - [ ] C. EXEC

2. **Quel avantage du multi-stage build ?**
   - [ ] A. Plus rapide à build
   - [ ] B. Image finale plus petite
   - [ ] C. Meilleure sécurité uniquement

**Réponses :** 1-B, 2-B

---

**Précédent :** [Module 1 - Fondamentaux](01-module.md)

**Suivant :** [Module 3 - Docker Compose](03-module.md)
