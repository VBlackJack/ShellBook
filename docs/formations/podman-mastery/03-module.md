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

```text
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

```text
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

## Exercice : À Vous de Jouer

!!! example "Mise en Pratique"
    **Objectif** : Construire une application Python Flask avec Buildah en utilisant un build multi-stage pour optimiser la taille de l'image

    **Contexte** : Vous devez créer une image conteneur pour une application web Python Flask. Pour minimiser la taille de l'image finale, vous utiliserez une approche multi-stage : un conteneur pour installer les dépendances, et un conteneur minimal pour l'exécution. L'image finale utilisera Gunicorn comme serveur WSGI.

    **Tâches à réaliser** :

    1. Créer une application Flask simple avec ses dépendances
    2. Écrire un script Buildah pour un build multi-stage
    3. Stage 1 : Installer les dépendances Python dans une image complète
    4. Stage 2 : Créer une image runtime minimale avec seulement l'application
    5. Configurer l'image avec le bon utilisateur, port et commande
    6. Tester l'image construite
    7. Comparer la taille avec une approche simple (non multi-stage)

    **Critères de validation** :

    - [ ] L'application Flask démarre correctement
    - [ ] Le serveur web répond sur le port 8080
    - [ ] L'image utilise un utilisateur non-root (1001)
    - [ ] L'image finale est basée sur ubi9/python-311-minimal
    - [ ] L'application est accessible via curl

??? quote "Solution"
    Voici la solution complète avec build multi-stage :

    **1. Créer l'application Flask**

    ```python
    # app.py
    from flask import Flask
    import os
    import socket

    app = Flask(__name__)

    @app.route('/')
    def hello():
        return f"""
        <h1>Hello from Buildah!</h1>
        <p>Hostname: {socket.gethostname()}</p>
        <p>Python version: {os.sys.version}</p>
        <p>Built with multi-stage Buildah</p>
        """

    @app.route('/health')
    def health():
        return {'status': 'ok'}, 200

    if __name__ == '__main__':
        app.run(host='0.0.0.0', port=8080)
    ```

    ```txt
    # requirements.txt
    flask==3.0.0
    gunicorn==21.2.0
    ```

    **2. Script Buildah multi-stage**

    ```bash
    #!/bin/bash
    # build-python-app.sh

    set -e

    echo "=== Buildah Multi-Stage Build ==="

    # Stage 1: Build - Installation des dépendances
    echo "Stage 1: Building dependencies..."
    builder=$(buildah from registry.access.redhat.com/ubi9/python-311)

    # Copier requirements et installer
    buildah copy $builder requirements.txt /tmp/requirements.txt
    buildah run $builder -- pip install --user --no-cache-dir -r /tmp/requirements.txt

    # Stage 2: Runtime - Image minimale
    echo "Stage 2: Creating runtime image..."
    runtime=$(buildah from registry.access.redhat.com/ubi9/python-311-minimal)

    # Extraire les packages installés du builder
    mnt_builder=$(buildah mount $builder)
    buildah copy $runtime ${mnt_builder}/opt/app-root/src/.local /opt/app-root/src/.local
    buildah unmount $builder

    # Copier l'application
    buildah copy $runtime app.py /opt/app-root/src/app.py
    buildah config --workingdir /opt/app-root/src $runtime

    # Configuration du conteneur
    buildah config --port 8080 $runtime
    buildah config --user 1001 $runtime
    buildah config --env PATH=/opt/app-root/src/.local/bin:$PATH $runtime
    buildah config --cmd '["gunicorn", "-b", "0.0.0.0:8080", "-w", "2", "app:app"]' $runtime

    # Metadata
    buildah config --label maintainer="devops@company.com" $runtime
    buildah config --label version="1.0" $runtime
    buildah config --label description="Flask app built with Buildah" $runtime

    # Commit l'image
    buildah commit --rm $runtime localhost/python-app:v1

    # Cleanup du builder
    buildah rm $builder

    # Afficher les informations
    echo "=== Image Info ==="
    podman images localhost/python-app:v1

    echo "=== Testing ==="
    podman run -d --name flask-test -p 8080:8080 localhost/python-app:v1
    echo "Waiting for app to start..."
    sleep 4

    # Tester l'application
    echo "Testing endpoints..."
    curl -s http://localhost:8080/ | head -5
    curl -s http://localhost:8080/health

    # Cleanup
    podman stop flask-test
    podman rm flask-test

    echo ""
    echo "✓ Image python-app:v1 built and tested successfully!"
    echo "  Run with: podman run -d -p 8080:8080 localhost/python-app:v1"
    ```

    **3. Exécuter le build**

    ```bash
    # Créer le répertoire de travail
    mkdir -p ~/podman-lab/buildah-python
    cd ~/podman-lab/buildah-python

    # Créer les fichiers (app.py et requirements.txt)
    # ... (copier le contenu ci-dessus)

    # Rendre le script exécutable et lancer
    chmod +x build-python-app.sh
    ./build-python-app.sh
    ```

    **4. Comparaison : Build simple vs Multi-stage**

    ```bash
    # Build simple (pour comparaison)
    cat > Containerfile.simple << 'EOF'
    FROM registry.access.redhat.com/ubi9/python-311
    COPY requirements.txt /tmp/
    RUN pip install --no-cache-dir -r /tmp/requirements.txt
    COPY app.py /opt/app-root/src/
    WORKDIR /opt/app-root/src
    USER 1001
    EXPOSE 8080
    CMD ["gunicorn", "-b", "0.0.0.0:8080", "app:app"]
    EOF

    buildah build -t localhost/python-app:simple -f Containerfile.simple .

    # Comparer les tailles
    podman images | grep python-app
    # python-app:v1     (minimal) ~180MB
    # python-app:simple (full)    ~350MB
    ```

    !!! success "Avantages du Multi-Stage"
        - **Taille réduite** : ~50% plus petite (minimal vs full)
        - **Surface d'attaque** : Moins de packages, moins de vulnérabilités
        - **Performance** : Image plus légère = déploiement plus rapide
        - **Sécurité** : Pas d'outils de build dans l'image de production

    !!! tip "Bonnes pratiques Buildah"
        - Toujours utiliser `--rm` avec `buildah commit` pour nettoyer
        - Monter/démonter proprement les filesystems avec `buildah mount/unmount`
        - Utiliser des images de base officielles et maintenues (UBI)
        - Définir un utilisateur non-root avec `--user`
        - Ajouter des labels pour la traçabilité

    !!! note "Alternatives"
        Cette même application peut être construite avec :
        - **Dockerfile** : `podman build` ou `buildah build`
        - **Buildah script** : Plus de contrôle, intégration CI/CD
        - **Buildah + Containerfile** : Meilleur des deux mondes

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

---

## Navigation

| | |
|:---|---:|
| [← Module 2 : Conteneurs Rootless](02-module.md) | [Module 4 : Skopeo & Gestion des Regis... →](04-module.md) |

[Retour au Programme](index.md){ .md-button }
