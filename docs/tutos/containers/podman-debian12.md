---
tags:
  - tutos
  - containers
  - podman
  - rootless
  - debian
---

# Podman sur Debian 12

Installation et utilisation de **Podman** sur Debian 12 Bookworm.

| Composant | Version |
|-----------|---------|
| Debian | 12 Bookworm |
| Podman | 4.x |

**Durée estimée :** 25 minutes

---

## 1. Installation

```bash
apt update
apt install -y podman podman-compose

# Vérifier
podman --version
podman info
```

### Alias Docker (optionnel)

```bash
apt install -y podman-docker
# Crée automatiquement l'alias docker → podman
```

---

## 2. Configuration Rootless

```bash
# Vérifier subuid/subgid
cat /etc/subuid
cat /etc/subgid

# Si absent pour votre utilisateur
sudo usermod --add-subuids 100000-165535 --add-subgids 100000-165535 $USER

# Appliquer
podman system migrate
```

---

## 3. Commandes essentielles

### Images

```bash
# Rechercher
podman search nginx

# Télécharger
podman pull docker.io/nginx:alpine
podman pull docker.io/python:3.11

# Lister
podman images

# Supprimer
podman rmi nginx:alpine
```

### Conteneurs

```bash
# Lancer
podman run -d --name web -p 8080:80 nginx:alpine

# Lister
podman ps
podman ps -a

# Logs
podman logs -f web

# Exec
podman exec -it web sh

# Stop/Start/Remove
podman stop web
podman start web
podman rm -f web
```

---

## 4. Volumes et Bind Mounts

```bash
# Volume nommé
podman volume create appdata
podman run -d --name db \
    -v appdata:/var/lib/mysql \
    -e MYSQL_ROOT_PASSWORD=secret \
    mariadb:10

# Bind mount
podman run -d --name web \
    -v $(pwd)/html:/usr/share/nginx/html:ro \
    -p 8080:80 \
    nginx:alpine

# Lister volumes
podman volume ls

# Inspecter
podman volume inspect appdata
```

---

## 5. Réseaux

```bash
# Créer
podman network create mynet

# Utiliser
podman run -d --name frontend --network mynet nginx
podman run -d --name backend --network mynet python:alpine sleep infinity

# Communication entre conteneurs
podman exec backend ping frontend

# Lister / Supprimer
podman network ls
podman network rm mynet
```

---

## 6. Pods

```bash
# Créer un pod
podman pod create --name webapp -p 8080:80 -p 5432:5432

# Ajouter conteneurs
podman run -d --pod webapp --name web nginx:alpine
podman run -d --pod webapp --name db \
    -e POSTGRES_PASSWORD=secret \
    postgres:15

# Lister
podman pod ls
podman pod ps webapp

# Gérer
podman pod stop webapp
podman pod start webapp
podman pod rm webapp
```

---

## 7. Build d'images

```bash
mkdir myapp && cd myapp

cat > Containerfile << 'EOF'
FROM docker.io/node:20-alpine

WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .

EXPOSE 3000
CMD ["node", "server.js"]
EOF

# Build
podman build -t myapp:1.0 .

# Multi-arch
podman build --platform linux/amd64,linux/arm64 -t myapp:1.0 .
```

---

## 8. Podman Compose

```bash
cat > compose.yml << 'EOF'
version: "3"
services:
  web:
    image: nginx:alpine
    ports:
      - "80:80"
    volumes:
      - ./www:/usr/share/nginx/html:ro
    depends_on:
      - api

  api:
    build: ./api
    environment:
      DATABASE_URL: postgres://user:pass@db/app
    depends_on:
      - db

  db:
    image: postgres:15
    environment:
      POSTGRES_USER: user
      POSTGRES_PASSWORD: pass
      POSTGRES_DB: app
    volumes:
      - pgdata:/var/lib/postgresql/data

volumes:
  pgdata:
EOF

# Lancer
podman-compose up -d

# Logs
podman-compose logs -f

# Arrêter
podman-compose down
```

---

## 9. Systemd Integration

### Générer service utilisateur

```bash
# Conteneur existant
podman run -d --name web -p 8080:80 nginx:alpine

# Générer le service
mkdir -p ~/.config/systemd/user
podman generate systemd --new --name web > ~/.config/systemd/user/container-web.service

# Activer
systemctl --user daemon-reload
systemctl --user enable --now container-web

# Linger pour persistance
sudo loginctl enable-linger $USER
```

### Quadlet (moderne)

```bash
mkdir -p ~/.config/containers/systemd

cat > ~/.config/containers/systemd/web.container << 'EOF'
[Container]
Image=docker.io/nginx:alpine
PublishPort=8080:80
Volume=%h/www:/usr/share/nginx/html:ro

[Service]
Restart=always

[Install]
WantedBy=default.target
EOF

systemctl --user daemon-reload
systemctl --user start web
```

---

## 10. Registry

### Login

```bash
podman login docker.io
podman login ghcr.io
podman login quay.io
```

### Push

```bash
podman tag myapp:1.0 docker.io/user/myapp:1.0
podman push docker.io/user/myapp:1.0
```

### Registry local

```bash
podman run -d --name registry \
    -p 5000:5000 \
    -v registry:/var/lib/registry \
    registry:2

podman push localhost:5000/myapp:1.0 --tls-verify=false
```

---

## 11. Import/Export

```bash
# Exporter un conteneur
podman export web > web-backup.tar

# Importer comme image
podman import web-backup.tar mybackup:latest

# Sauvegarder une image
podman save -o nginx.tar nginx:alpine

# Charger une image
podman load -i nginx.tar
```

---

## 12. Healthcheck

```bash
podman run -d --name web \
    --health-cmd "curl -f http://localhost/ || exit 1" \
    --health-interval 30s \
    --health-retries 3 \
    --health-timeout 10s \
    -p 8080:80 \
    nginx:alpine

# Vérifier
podman healthcheck run web
podman inspect web --format '{{.State.Health.Status}}'
```

---

## 13. Nettoyage

```bash
# Conteneurs arrêtés
podman container prune

# Images inutilisées
podman image prune -a

# Volumes orphelins
podman volume prune

# Tout
podman system prune -a --volumes

# Espace utilisé
podman system df
```

---

## Comparatif Rocky vs Debian

| Aspect | Rocky 9 | Debian 12 |
|--------|---------|-----------|
| Version Podman | 4.x | 4.x |
| Installation | Natif | Natif |
| SELinux | Oui (:z/:Z) | AppArmor |
| Compose | podman-compose | podman-compose |
| Quadlet | Oui | Oui |

---

## Vérification

```bash
podman --version
podman info --format '{{.Host.OS}}'

# Test
podman run --rm alpine echo "Hello from Podman!"

# Rootless
podman run --rm alpine id
```

---

## Dépannage

```bash
# Logs
podman logs container_name

# Événements
podman events

# Reset complet
podman system reset

# Debug
podman --log-level debug run alpine
```

| Problème | Solution |
|----------|----------|
| ERRO[0000] cannot find mappings | `podman system migrate` |
| Permission denied | Vérifier subuid/subgid |
| Network unreachable | `podman network reload --all` |

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
