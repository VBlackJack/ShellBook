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

## 7. Exercice : À Vous de Jouer

!!! example "Mise en Pratique"
    **Objectif** : Créer une image Docker optimisée pour une application web Python en utilisant les bonnes pratiques

    **Contexte** : Vous développez une API Flask simple. Vous devez créer un Dockerfile optimisé qui minimise la taille de l'image finale, utilise le cache intelligemment et respecte les principes de sécurité.

    **Tâches à réaliser** :

    1. Créer une application Flask minimaliste (`app.py`) et son fichier de dépendances (`requirements.txt`)
    2. Écrire un premier Dockerfile simple (single-stage) et noter la taille de l'image résultante
    3. Optimiser le Dockerfile avec un multi-stage build pour réduire la taille
    4. Ajouter les bonnes pratiques : utilisateur non-root, layers optimisés, .dockerignore
    5. Builder les deux versions et comparer les tailles d'images
    6. Tester que l'application fonctionne correctement dans les deux cas

    **Critères de validation** :

    - [ ] L'application répond sur http://localhost:5000
    - [ ] La version multi-stage est significativement plus petite (au moins 30% de réduction)
    - [ ] Le container s'exécute avec un utilisateur non-root
    - [ ] Le fichier .dockerignore exclut les fichiers inutiles
    - [ ] Le cache Docker est correctement utilisé (rebuilds rapides quand seul le code change)

??? quote "Solution"
    **Étape 1 : Créer l'application**

    ```python
    # app.py
    from flask import Flask, jsonify
    import os

    app = Flask(__name__)

    @app.route('/')
    def hello():
        return jsonify({"message": "Hello from Docker!", "version": "1.0"})

    @app.route('/health')
    def health():
        return jsonify({"status": "healthy"})

    if __name__ == '__main__':
        app.run(host='0.0.0.0', port=5000)
    ```

    ```text
    # requirements.txt
    flask==3.0.0
    gunicorn==21.2.0
    ```

    **Étape 2 : Dockerfile simple (version 1)**

    ```dockerfile
    # Dockerfile.simple
    FROM python:3.11
    WORKDIR /app
    COPY . .
    RUN pip install -r requirements.txt
    EXPOSE 5000
    CMD ["python", "app.py"]
    ```

    ```bash
    # Build et vérifier la taille
    docker build -f Dockerfile.simple -t myapp:simple .
    docker images myapp:simple
    # Taille: ~1GB
    ```

    **Étape 3 : Dockerfile optimisé (multi-stage)**

    ```dockerfile
    # Dockerfile
    # Stage 1: Builder
    FROM python:3.11-slim AS builder
    WORKDIR /app

    # Copier uniquement les dépendances d'abord (cache)
    COPY requirements.txt .
    RUN pip install --user --no-cache-dir -r requirements.txt

    # Stage 2: Production
    FROM python:3.11-slim
    WORKDIR /app

    # Créer utilisateur non-root
    RUN useradd -m -u 1000 appuser && \
        chown -R appuser:appuser /app

    # Copier les dépendances depuis le builder
    COPY --from=builder /root/.local /home/appuser/.local

    # Copier le code application
    COPY --chown=appuser:appuser app.py .

    # Configurer l'environnement
    ENV PATH=/home/appuser/.local/bin:$PATH \
        PYTHONUNBUFFERED=1 \
        PYTHONDONTWRITEBYTECODE=1

    # Utiliser l'utilisateur non-root
    USER appuser

    EXPOSE 5000

    # Utiliser gunicorn en production
    CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "app:app"]
    ```

    **Étape 4 : Créer .dockerignore**

    ```
    # .dockerignore
    .git
    .gitignore
    __pycache__
    *.pyc
    *.pyo
    *.pyd
    .Python
    *.so
    .env
    venv/
    *.md
    !README.md
    Dockerfile*
    .dockerignore
    ```

    **Étape 5 : Build et comparaison**

    ```bash
    # Build version optimisée
    docker build -t myapp:optimized .

    # Comparer les tailles
    docker images | grep myapp
    # simple: ~1GB
    # optimized: ~150-200MB

    # Tester
    docker run -d -p 5000:5000 --name myapp myapp:optimized
    curl http://localhost:5000
    curl http://localhost:5000/health

    # Vérifier l'utilisateur
    docker exec myapp whoami
    # Devrait afficher: appuser

    # Cleanup
    docker stop myapp && docker rm myapp
    ```

    **Points clés** :

    - Multi-stage build réduit la taille en excluant les outils de build
    - Image `python:3.11-slim` au lieu de `python:3.11` (900MB → 150MB)
    - `pip install --user` installe dans le répertoire utilisateur
    - `--no-cache-dir` évite de stocker le cache pip
    - Ordre des COPY optimise le cache Docker
    - Utilisateur non-root améliore la sécurité
    - .dockerignore réduit le contexte de build

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

---

## Navigation

| | |
|:---|---:|
| [← Module 1 : Fondamentaux Docker](01-module.md) | [Module 3 : Docker Compose →](03-module.md) |

[Retour au Programme](index.md){ .md-button }
