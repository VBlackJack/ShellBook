---
tags:
  - tutos
  - containers
  - podman
  - rootless
  - rocky
---

# Podman sur Rocky Linux 9

Installation et utilisation de **Podman** pour la conteneurisation sans daemon ni root.

| Composant | Version |
|-----------|---------|
| Rocky Linux | 9.x |
| Podman | 4.x |

**Durée estimée :** 30 minutes

---

## Pourquoi Podman ?

| Critère | Podman | Docker |
|---------|--------|--------|
| Daemon | Non | Oui (dockerd) |
| Root requis | Non (rootless) | Oui par défaut |
| Compatibilité | CLI Docker | - |
| Systemd | Natif | Add-on |
| Pods | Natif (K8s style) | Non |
| Sécurité | SELinux intégré | Limité |

---

## 1. Installation

```bash
# Podman est inclus dans Rocky 9
dnf install -y podman podman-docker

# Vérifier
podman --version
podman info
```

### Alias Docker (optionnel)

```bash
# podman-docker crée l'alias automatiquement
docker --version  # Affiche podman

# Ou manuellement
echo 'alias docker=podman' >> ~/.bashrc
```

---

## 2. Mode Rootless (recommandé)

### Configurer l'utilisateur

```bash
# Vérifier les subuid/subgid
grep $USER /etc/subuid
grep $USER /etc/subgid

# Si absent, ajouter
echo "$USER:100000:65536" | sudo tee -a /etc/subuid
echo "$USER:100000:65536" | sudo tee -a /etc/subgid
```

### Utilisation rootless

```bash
# En tant qu'utilisateur normal (pas root)
podman run hello-world
podman ps -a
```

---

## 3. Commandes de base

### Images

```bash
# Rechercher une image
podman search nginx

# Télécharger
podman pull docker.io/nginx:alpine
podman pull quay.io/podman/hello

# Lister les images
podman images

# Supprimer
podman rmi nginx:alpine
```

### Conteneurs

```bash
# Lancer un conteneur
podman run -d --name web -p 8080:80 nginx:alpine

# Lister
podman ps
podman ps -a

# Logs
podman logs web
podman logs -f web

# Exécuter une commande
podman exec -it web sh

# Arrêter / Démarrer
podman stop web
podman start web

# Supprimer
podman rm web
podman rm -f web
```

### Informations

```bash
# Inspecter
podman inspect web

# Stats
podman stats

# Top (processus)
podman top web
```

---

## 4. Volumes

```bash
# Créer un volume
podman volume create mydata

# Lister
podman volume ls

# Utiliser
podman run -d --name db \
    -v mydata:/var/lib/mysql \
    -e MYSQL_ROOT_PASSWORD=secret \
    mariadb:10

# Bind mount (dossier local)
podman run -d --name web \
    -v /srv/www:/usr/share/nginx/html:ro \
    -p 8080:80 \
    nginx:alpine

# Inspecter
podman volume inspect mydata

# Supprimer
podman volume rm mydata
```

---

## 5. Réseaux

```bash
# Créer un réseau
podman network create mynet

# Lister
podman network ls

# Utiliser
podman run -d --name web --network mynet nginx:alpine
podman run -d --name app --network mynet myapp:latest

# Inspecter
podman network inspect mynet

# Supprimer
podman network rm mynet
```

---

## 6. Pods (style Kubernetes)

```bash
# Créer un pod
podman pod create --name mypod -p 8080:80

# Ajouter des conteneurs au pod
podman run -d --pod mypod --name web nginx:alpine
podman run -d --pod mypod --name app myapp:latest

# Les conteneurs partagent le réseau
# localhost:80 dans app atteint nginx

# Lister les pods
podman pod ls

# Inspecter
podman pod inspect mypod

# Arrêter/Démarrer
podman pod stop mypod
podman pod start mypod

# Supprimer
podman pod rm mypod
```

---

## 7. Construire des images

### Containerfile (Dockerfile)

```bash
mkdir myapp && cd myapp

cat > Containerfile << 'EOF'
FROM docker.io/python:3.11-alpine

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000
CMD ["python", "app.py"]
EOF
```

### Build

```bash
# Construire
podman build -t myapp:1.0 .

# Avec tag
podman build -t myregistry.com/myapp:latest .

# Multi-stage
podman build --target production -t myapp:prod .
```

---

## 8. Registry

### Login

```bash
# Docker Hub
podman login docker.io

# Quay.io
podman login quay.io

# Registry privé
podman login myregistry.example.com
```

### Push

```bash
podman tag myapp:1.0 docker.io/myuser/myapp:1.0
podman push docker.io/myuser/myapp:1.0
```

### Registry local

```bash
# Lancer un registry local
podman run -d --name registry \
    -p 5000:5000 \
    -v registry-data:/var/lib/registry \
    registry:2

# Pousser vers le registry local
podman tag myapp:1.0 localhost:5000/myapp:1.0
podman push localhost:5000/myapp:1.0 --tls-verify=false
```

---

## 9. Systemd integration

### Générer un service systemd

```bash
# Créer et démarrer le conteneur
podman run -d --name web -p 8080:80 nginx:alpine

# Générer le fichier service
podman generate systemd --new --name web > ~/.config/systemd/user/container-web.service

# Activer
systemctl --user daemon-reload
systemctl --user enable --now container-web

# Vérifier
systemctl --user status container-web
```

### Pour un pod

```bash
podman generate systemd --new --name mypod --files
# Génère plusieurs fichiers .service
```

### Linger (rootless persistant)

```bash
# Permettre aux services utilisateur de tourner sans session
sudo loginctl enable-linger $USER
```

---

## 10. Podman Compose

### Installer

```bash
dnf install -y podman-compose
# ou
pip3 install podman-compose
```

### Utiliser

```bash
cat > docker-compose.yml << 'EOF'
version: "3"
services:
  web:
    image: nginx:alpine
    ports:
      - "8080:80"
    volumes:
      - ./html:/usr/share/nginx/html:ro

  db:
    image: mariadb:10
    environment:
      MYSQL_ROOT_PASSWORD: secret
      MYSQL_DATABASE: app
    volumes:
      - db-data:/var/lib/mysql

volumes:
  db-data:
EOF

# Lancer
podman-compose up -d

# Arrêter
podman-compose down
```

---

## 11. Quadlet (systemd natif)

Rocky 9.2+ supporte Quadlet pour déclarer des conteneurs via systemd :

```bash
mkdir -p ~/.config/containers/systemd/

cat > ~/.config/containers/systemd/nginx.container << 'EOF'
[Container]
Image=docker.io/nginx:alpine
PublishPort=8080:80
Volume=/srv/www:/usr/share/nginx/html:ro

[Service]
Restart=always

[Install]
WantedBy=default.target
EOF

systemctl --user daemon-reload
systemctl --user start nginx
```

---

## 12. SELinux

```bash
# Podman gère SELinux automatiquement avec :z ou :Z
podman run -v /data:/data:z nginx  # Shared label
podman run -v /data:/data:Z nginx  # Private label

# Vérifier les contextes
ls -Z /data
```

---

## 13. Nettoyage

```bash
# Supprimer conteneurs arrêtés
podman container prune

# Supprimer images non utilisées
podman image prune

# Supprimer volumes non utilisés
podman volume prune

# Tout nettoyer
podman system prune -a
```

---

## Vérification

```bash
# Version
podman --version
podman info

# Lancer un test
podman run --rm hello-world
podman run --rm -it alpine sh -c "echo Hello from Podman"

# Conteneurs actifs
podman ps
```

---

## Dépannage

| Problème | Solution |
|----------|----------|
| Permission denied | Vérifier subuid/subgid |
| Image not found | Préfixer avec docker.io/ ou quay.io/ |
| Port already in use | `podman ps -a` et supprimer le conteneur |
| SELinux denial | Utiliser `:z` ou `:Z` pour les volumes |

```bash
# Logs système
journalctl --user -u container-web

# Reset podman
podman system reset
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
