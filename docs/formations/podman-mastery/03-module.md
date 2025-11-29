---
tags:
  - formation
  - podman
  - buildah
  - images
---

# Module 3 : Buildah & Construction d'Images

## Objectifs du Module

- Comprendre Buildah et ses avantages
- Construire des images sans Dockerfile
- Maîtriser les multi-stage builds
- Optimiser les images avec UBI

**Durée :** 3 heures

---

## 1. Buildah vs Dockerfile

```
APPROCHES DE CONSTRUCTION
═════════════════════════════════════════════════════════

DOCKERFILE (déclaratif)           BUILDAH (impératif)
────────────────────────          ─────────────────────
FROM ubi9/ubi-minimal             ctr=$(buildah from ubi-minimal)
RUN dnf install -y nginx          buildah run $ctr dnf install -y nginx
COPY app/ /app                    buildah copy $ctr app/ /app
EXPOSE 80                         buildah config --port 80 $ctr
CMD ["nginx", "-g", "..."]        buildah config --cmd "nginx" $ctr
                                  buildah commit $ctr myimage

Avantages Buildah:
✓ Pas de daemon requis
✓ Scripting shell natif
✓ Intégration CI/CD facilitée
✓ Construction rootless
✓ Contrôle granulaire
```

### Installation

```bash
# Buildah est inclus dans container-tools
sudo dnf install -y buildah

# Vérifier
buildah --version
```

---

## 2. Construction avec Dockerfile

Buildah supporte nativement les Dockerfiles :

```bash
# Construire depuis un Dockerfile
buildah build -t myapp:v1 .

# Équivalent à
podman build -t myapp:v1 .

# Options utiles
buildah build \
  --tag myapp:v1 \
  --tag myapp:latest \
  --file Containerfile \
  --build-arg VERSION=1.0 \
  --layers \
  --squash \
  .
```

### Dockerfile Optimisé pour UBI

```dockerfile
# Containerfile
FROM registry.access.redhat.com/ubi9/ubi-minimal

# Metadata
LABEL maintainer="team@company.com" \
      version="1.0" \
      description="Application web"

# Installation en une seule couche
RUN microdnf install -y \
      nginx \
      && microdnf clean all \
      && rm -rf /var/cache/yum

# Configuration
COPY nginx.conf /etc/nginx/nginx.conf
COPY --chown=1001:0 app/ /usr/share/nginx/html/

# User non-root
USER 1001

EXPOSE 8080

CMD ["nginx", "-g", "daemon off;"]
```

---

## 3. Construction Scriptée avec Buildah

```bash
#!/bin/bash
# build-app.sh - Construction avec Buildah

set -e

# Variables
IMAGE_NAME="myapp"
IMAGE_TAG="v1"
REGISTRY="registry.lab.local:5000"

# Créer un conteneur de travail
container=$(buildah from registry.access.redhat.com/ubi9/ubi-minimal)

# Installer les dépendances
buildah run $container -- microdnf install -y nginx
buildah run $container -- microdnf clean all

# Copier les fichiers
buildah copy $container ./app/ /usr/share/nginx/html/
buildah copy $container ./nginx.conf /etc/nginx/nginx.conf

# Configuration
buildah config --port 8080 $container
buildah config --user 1001 $container
buildah config --cmd '["nginx", "-g", "daemon off;"]' $container
buildah config --label maintainer="team@company.com" $container
buildah config --env APP_ENV=production $container

# Commit l'image
buildah commit $container ${IMAGE_NAME}:${IMAGE_TAG}

# Tag pour le registry
buildah tag ${IMAGE_NAME}:${IMAGE_TAG} ${REGISTRY}/${IMAGE_NAME}:${IMAGE_TAG}

# Cleanup
buildah rm $container

echo "Image ${IMAGE_NAME}:${IMAGE_TAG} créée avec succès"
```

### Commandes Buildah Essentielles

```bash
# Conteneur de travail
buildah from <image>              # Créer depuis une image
buildah from scratch              # Image vide

# Manipulation
buildah run <container> -- <cmd>  # Exécuter une commande
buildah copy <container> <src> <dst>  # Copier des fichiers
buildah add <container> <src> <dst>   # Copier + extraction archives

# Configuration
buildah config --cmd <cmd> <container>
buildah config --entrypoint <cmd> <container>
buildah config --env KEY=value <container>
buildah config --port <port> <container>
buildah config --user <user> <container>
buildah config --workingdir <dir> <container>
buildah config --label key=value <container>

# Finalisation
buildah commit <container> <image>
buildah tag <image> <newtag>

# Nettoyage
buildah rm <container>
buildah rmi <image>
buildah containers  # Lister les conteneurs de build
```

---

## 4. Multi-Stage Builds

```dockerfile
# Containerfile.multistage

# === Stage 1: Build ===
FROM registry.access.redhat.com/ubi9/ubi AS builder

RUN dnf install -y golang make

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o app .

# === Stage 2: Runtime ===
FROM registry.access.redhat.com/ubi9/ubi-micro

# Copier uniquement le binaire
COPY --from=builder /src/app /app

USER 1001
ENTRYPOINT ["/app"]
```

### Multi-Stage avec Buildah Script

```bash
#!/bin/bash
# multi-stage-build.sh

set -e

# Stage 1: Build
echo "=== Stage 1: Build ==="
builder=$(buildah from registry.access.redhat.com/ubi9/ubi)

buildah run $builder -- dnf install -y golang make
buildah copy $builder . /src
buildah config --workingdir /src $builder
buildah run $builder -- go mod download
buildah run $builder -- go build -o /app .

# Monter le filesystem pour extraire le binaire
mnt=$(buildah mount $builder)
cp ${mnt}/app ./app-binary
buildah unmount $builder

# Stage 2: Runtime
echo "=== Stage 2: Runtime ==="
runtime=$(buildah from registry.access.redhat.com/ubi9/ubi-micro)

buildah copy $runtime ./app-binary /app
buildah config --entrypoint '["/app"]' $runtime
buildah config --user 1001 $runtime

buildah commit $runtime myapp:v1

# Cleanup
buildah rm $builder $runtime
rm ./app-binary

echo "Image myapp:v1 créée (multi-stage)"
```

---

## 5. Images UBI Optimisées

### Comparaison des Images de Base

```bash
# Télécharger les images UBI
podman pull registry.access.redhat.com/ubi9/ubi
podman pull registry.access.redhat.com/ubi9/ubi-minimal
podman pull registry.access.redhat.com/ubi9/ubi-micro

# Comparer les tailles
podman images | grep ubi9
# ubi         ~215MB  (dnf, systemd, full)
# ubi-minimal ~95MB   (microdnf, no systemd)
# ubi-micro   ~25MB   (no package manager)
```

### Choisir la Bonne Image

```
ARBRE DE DÉCISION UBI
═════════════════════════════════════════════════════════

Besoin d'installer des packages au runtime ?
│
├── OUI → Besoin de systemd ?
│         │
│         ├── OUI → ubi9/ubi
│         │
│         └── NON → ubi9/ubi-minimal (microdnf)
│
└── NON → Application statique/binaire ?
          │
          ├── OUI → ubi9/ubi-micro (ou scratch)
          │
          └── NON → ubi9/ubi-minimal
```

### Exemple : Application Go Minimale

```dockerfile
# Containerfile.go-micro

# Build stage
FROM registry.access.redhat.com/ubi9/go-toolset AS builder
WORKDIR /app
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o server .

# Runtime stage - ubi-micro (25MB!)
FROM registry.access.redhat.com/ubi9/ubi-micro
COPY --from=builder /app/server /server
USER 1001
ENTRYPOINT ["/server"]
```

---

## 6. Optimisation des Couches

### Avant (Non Optimisé)

```dockerfile
# Mauvais : plusieurs couches, cache inefficace
FROM ubi9/ubi-minimal
RUN microdnf install -y nginx
RUN microdnf install -y curl
RUN microdnf clean all
COPY file1.txt /app/
COPY file2.txt /app/
COPY file3.txt /app/
```

### Après (Optimisé)

```dockerfile
# Bon : couches minimisées, cache optimisé
FROM ubi9/ubi-minimal

# Une seule couche pour les packages
RUN microdnf install -y nginx curl \
    && microdnf clean all \
    && rm -rf /var/cache/yum

# Une seule couche pour les fichiers
COPY app/ /app/
```

### Squash des Couches

```bash
# Fusionner toutes les couches en une seule
buildah build --squash -t myapp:squashed .

# Comparer
podman images myapp
# myapp:v1       150MB (10 layers)
# myapp:squashed 145MB (1 layer)
```

---

## 7. Exercice Pratique

### Objectif

Construire une application Python avec Buildah en multi-stage.

### Fichiers de l'Application

```python
# app.py
from flask import Flask
app = Flask(__name__)

@app.route('/')
def hello():
    return "Hello from Buildah!"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
```

```
# requirements.txt
flask==3.0.0
gunicorn==21.2.0
```

### Construction

```bash
#!/bin/bash
# build-python-app.sh

set -e

# Stage 1: Build avec dépendances
echo "=== Building dependencies ==="
builder=$(buildah from registry.access.redhat.com/ubi9/python-311)

buildah copy $builder requirements.txt /tmp/
buildah run $builder -- pip install --user -r /tmp/requirements.txt

# Stage 2: Runtime minimal
echo "=== Creating runtime image ==="
runtime=$(buildah from registry.access.redhat.com/ubi9/python-311-minimal)

# Copier les packages installés
mnt_builder=$(buildah mount $builder)
buildah copy $runtime ${mnt_builder}/opt/app-root/src/.local /opt/app-root/src/.local
buildah unmount $builder

# Copier l'application
buildah copy $runtime app.py /opt/app-root/src/
buildah config --workingdir /opt/app-root/src $runtime
buildah config --port 8080 $runtime
buildah config --user 1001 $runtime
buildah config --cmd '["gunicorn", "-b", "0.0.0.0:8080", "app:app"]' $runtime

# Commit
buildah commit $runtime python-app:v1

# Cleanup
buildah rm $builder $runtime

echo "=== Testing ==="
podman run -d --name test -p 8080:8080 python-app:v1
sleep 3
curl http://localhost:8080
podman stop test && podman rm test

echo "Image python-app:v1 ready!"
```

---

## Quiz

1. **Quelle commande crée un conteneur de travail Buildah ?**
   - [ ] A. buildah create
   - [ ] B. buildah from
   - [ ] C. buildah init

**Réponse :** B

2. **Quelle image UBI utiliser pour un binaire Go statique ?**
   - [ ] A. ubi9/ubi
   - [ ] B. ubi9/ubi-minimal
   - [ ] C. ubi9/ubi-micro

**Réponse :** C - ubi-micro est la plus légère pour les binaires statiques

3. **Comment fusionner toutes les couches d'une image ?**
   - [ ] A. --flatten
   - [ ] B. --squash
   - [ ] C. --merge

**Réponse :** B

---

**Précédent :** [Module 2 - Rootless](02-module.md)

**Suivant :** [Module 4 - Skopeo & Registries](04-module.md)
