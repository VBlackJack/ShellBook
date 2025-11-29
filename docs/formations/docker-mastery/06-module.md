---
tags:
  - formation
  - docker
  - security
---

# Module 6 : Sécurité Docker

## Objectifs du Module

- Exécuter des containers en non-root
- Gérer les capabilities Linux
- Scanner les images pour vulnérabilités
- Gérer les secrets

**Durée :** 2 heures

---

## 1. User Non-Root

```dockerfile
# Dockerfile
FROM node:20-alpine

# Créer un utilisateur
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

WORKDIR /app
COPY --chown=appuser:appgroup . .

# Utiliser l'utilisateur non-root
USER appuser

CMD ["node", "app.js"]
```

```bash
# Ou au runtime
docker run --user 1000:1000 nginx
docker run --user nobody nginx
```

---

## 2. Capabilities

```bash
# Supprimer toutes les capabilities
docker run --cap-drop=ALL nginx

# Ajouter seulement ce qui est nécessaire
docker run --cap-drop=ALL --cap-add=NET_BIND_SERVICE nginx

# Lister les capabilities par défaut
docker run --rm alpine cat /proc/self/status | grep Cap
```

---

## 3. Read-Only et Security Options

```bash
# Filesystem read-only
docker run --read-only nginx

# Avec tmpfs pour /tmp
docker run --read-only --tmpfs /tmp:rw,noexec,nosuid nginx

# No new privileges
docker run --security-opt=no-new-privileges nginx

# Seccomp profile
docker run --security-opt seccomp=profile.json nginx
```

---

## 4. Scanning d'Images

```bash
# Docker Scout (intégré)
docker scout cves nginx:latest
docker scout quickview nginx:latest

# Trivy (recommandé)
trivy image nginx:latest
trivy image --severity HIGH,CRITICAL myapp:v1

# Grype
grype nginx:latest
```

---

## 5. Secrets

```yaml
# docker-compose.yml
services:
  api:
    image: myapi
    secrets:
      - db_password
      - api_key
    environment:
      DB_PASSWORD_FILE: /run/secrets/db_password

secrets:
  db_password:
    file: ./secrets/db_password.txt
  api_key:
    external: true  # Créé avec docker secret create
```

```bash
# Créer un secret (Swarm mode)
echo "mysecret" | docker secret create db_password -

# Lister
docker secret ls
```

---

## 6. Bonnes Pratiques

```dockerfile
# Dockerfile sécurisé
FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production

FROM node:20-alpine
# User non-root
RUN addgroup -S app && adduser -S app -G app

WORKDIR /app
COPY --from=builder --chown=app:app /app/node_modules ./node_modules
COPY --chown=app:app . .

USER app
EXPOSE 3000

# Healthcheck
HEALTHCHECK --interval=30s --timeout=3s \
  CMD wget --no-verbose --tries=1 --spider http://localhost:3000/health || exit 1

CMD ["node", "app.js"]
```

```yaml
# docker-compose.yml sécurisé
services:
  api:
    image: myapi
    read_only: true
    tmpfs:
      - /tmp
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
    user: "1000:1000"
```

---

## Quiz

1. **Comment supprimer toutes les capabilities ?**
   - [ ] A. --cap-remove=ALL
   - [ ] B. --cap-drop=ALL
   - [ ] C. --no-capabilities

**Réponse :** B

---

**Précédent :** [Module 5 - Volumes](05-module.md)

**Suivant :** [TP Final](07-tp-final.md)
