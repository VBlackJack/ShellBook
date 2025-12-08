---
tags:
  - formation
  - podman
  - skopeo
  - registry
---

# Module 4 : Skopeo & Gestion des Registries

## Objectifs du Module

- Inspecter les images distantes sans les télécharger
- Copier des images entre registries
- Gérer les signatures et la vérification
- Configurer des registries privés

**Durée :** 2 heures

---

## 1. Introduction à Skopeo

```
SKOPEO - GESTION DES IMAGES
═════════════════════════════════════════════════════════

Cas d'usage :
┌─────────────────────────────────────────────────────┐
│                                                      │
│  Inspecter    Copier       Supprimer    Synchroniser│
│  ─────────    ──────       ─────────    ────────────│
│                                                      │
│  Registry A ──────────────► Registry B              │
│      │                          │                   │
│      │         Skopeo           │                   │
│      │                          │                   │
│      ▼                          ▼                   │
│  [manifest]                 [manifest]              │
│  [layers]                   [layers]                │
│  [config]                   [config]                │
│                                                      │
└─────────────────────────────────────────────────────┘

Avantages vs podman pull/push :
✓ Pas de stockage local requis
✓ Copie directe entre registries
✓ Inspection sans téléchargement
✓ Support multi-format (OCI, Docker v2)
```

### Installation

```bash
# Skopeo est inclus dans container-tools
sudo dnf install -y skopeo

# Vérifier
skopeo --version
```

---

## 2. Inspection d'Images

### Inspecter une Image Distante

```bash
# Inspecter sans télécharger
skopeo inspect docker://docker.io/library/nginx:alpine

# Format JSON (exploitable avec jq)
skopeo inspect docker://nginx:alpine | jq '.Labels'

# Informations clés
skopeo inspect docker://nginx:alpine | jq '{
  created: .Created,
  architecture: .Architecture,
  os: .Os,
  layers: .Layers | length,
  labels: .Labels
}'
```

### Comparer des Images

```bash
# Voir les digests
skopeo inspect docker://nginx:1.25 --format '{{.Digest}}'
skopeo inspect docker://nginx:latest --format '{{.Digest}}'

# Lister les tags disponibles
skopeo list-tags docker://docker.io/library/nginx
skopeo list-tags docker://registry.access.redhat.com/ubi9/ubi-minimal
```

### Inspecter le Manifest Raw

```bash
# Manifest complet
skopeo inspect --raw docker://nginx:alpine | jq .

# Voir les couches (layers)
skopeo inspect --raw docker://nginx:alpine | jq '.layers[] | {digest, size}'
```

---

## 3. Copie d'Images

### Entre Registries

```bash
# Copier de Docker Hub vers un registry privé
skopeo copy \
  docker://docker.io/library/nginx:alpine \
  docker://registry.lab.local:5000/nginx:alpine

# Copier avec authentification
skopeo copy \
  --src-creds user:password \
  --dest-creds admin:secret \
  docker://source.registry.io/app:v1 \
  docker://dest.registry.io/app:v1
```

### Vers/Depuis le Stockage Local

```bash
# Vers un répertoire local (format OCI)
skopeo copy docker://nginx:alpine oci:./nginx-local:alpine

# Vers une archive tar
skopeo copy docker://nginx:alpine docker-archive:./nginx.tar:nginx:alpine

# Depuis une archive vers un registry
skopeo copy docker-archive:./nginx.tar docker://registry.lab.local:5000/nginx:alpine

# Depuis un répertoire OCI
skopeo copy oci:./nginx-local:alpine docker://registry.lab.local:5000/nginx:alpine
```

### Formats Supportés

```
FORMATS DE TRANSPORT SKOPEO
═══════════════════════════

docker://          Registry Docker/OCI (défaut)
docker-archive:    Archive tar (format Docker)
oci:               Répertoire OCI
oci-archive:       Archive tar OCI
dir:               Répertoire simple
containers-storage: Stockage Podman local

Exemples :
  docker://registry.io/image:tag
  docker-archive:/path/to/archive.tar
  oci:/path/to/dir:tag
  dir:/path/to/dir
  containers-storage:localhost/myimage:tag
```

---

## 4. Synchronisation et Mirroring

### Script de Mirroring

```bash
#!/bin/bash
# mirror-images.sh - Synchroniser des images vers un registry privé

DEST_REGISTRY="registry.lab.local:5000"

# Liste des images à synchroniser
IMAGES=(
  "docker.io/library/nginx:alpine"
  "docker.io/library/redis:7-alpine"
  "docker.io/library/postgres:15-alpine"
  "registry.access.redhat.com/ubi9/ubi-minimal:latest"
)

for image in "${IMAGES[@]}"; do
  # Extraire le nom de l'image sans le registry
  image_name=$(echo $image | sed 's|.*/||')

  echo "Mirroring $image -> $DEST_REGISTRY/$image_name"

  skopeo copy \
    --dest-tls-verify=false \
    docker://$image \
    docker://$DEST_REGISTRY/$image_name
done

echo "Mirroring complete!"
```

### Synchronisation avec skopeo sync

```bash
# Créer un fichier de configuration
cat > sync.yaml << 'EOF'
docker.io:
  images:
    nginx:
      - "alpine"
      - "1.25"
    redis:
      - "7-alpine"
registry.access.redhat.com:
  images:
    ubi9/ubi-minimal:
      - "latest"
      - "9.3"
EOF

# Synchroniser vers un registry
skopeo sync \
  --src yaml \
  --dest docker \
  sync.yaml \
  registry.lab.local:5000

# Synchroniser vers un répertoire (air-gap)
skopeo sync \
  --src yaml \
  --dest dir \
  sync.yaml \
  ./offline-images/
```

---

## 5. Registries Privés

### Configuration sans TLS (Lab)

```toml
# /etc/containers/registries.conf.d/lab.conf
[[registry]]
location = "registry.lab.local:5000"
insecure = true
```

### Déployer un Registry avec Podman

```bash
# Registry simple
podman run -d \
  --name registry \
  -p 5000:5000 \
  -v registry-data:/var/lib/registry \
  docker.io/library/registry:2

# Tester
curl http://localhost:5000/v2/_catalog

# Push une image
podman tag nginx:alpine localhost:5000/nginx:alpine
podman push localhost:5000/nginx:alpine

# Via Skopeo
skopeo copy \
  --dest-tls-verify=false \
  docker://docker.io/library/redis:alpine \
  docker://localhost:5000/redis:alpine
```

### Registry avec Authentification

```bash
# Créer les credentials
mkdir -p ~/registry/auth
podman run --rm \
  --entrypoint htpasswd \
  docker.io/library/httpd:2 \
  -Bbn admin secret123 > ~/registry/auth/htpasswd

# Lancer avec auth
podman run -d \
  --name registry-auth \
  -p 5001:5000 \
  -v ~/registry/auth:/auth:Z \
  -v registry-auth-data:/var/lib/registry \
  -e REGISTRY_AUTH=htpasswd \
  -e REGISTRY_AUTH_HTPASSWD_REALM="Registry Realm" \
  -e REGISTRY_AUTH_HTPASSWD_PATH=/auth/htpasswd \
  docker.io/library/registry:2

# Login
podman login localhost:5001
# Username: admin
# Password: secret123

# Push
podman push localhost:5001/myimage:v1
```

---

## 6. Signatures et Vérification

### Configurer la Politique de Signature

```bash
# Fichier de politique
cat /etc/containers/policy.json
```

```json
{
  "default": [{"type": "insecureAcceptAnything"}],
  "transports": {
    "docker": {
      "registry.access.redhat.com": [
        {
          "type": "signedBy",
          "keyType": "GPGKeys",
          "keyPath": "/etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release"
        }
      ],
      "registry.lab.local:5000": [
        {"type": "insecureAcceptAnything"}
      ]
    }
  }
}
```

### Signer une Image avec GPG

```bash
# Générer une clé GPG (si nécessaire)
gpg --full-generate-key

# Configurer Podman pour signer
cat > ~/.config/containers/registries.d/default.yaml << 'EOF'
default-docker:
  sigstore: file:///var/lib/containers/sigstore
docker:
  registry.lab.local:5000:
    sigstore: http://registry.lab.local:5000/signatures
EOF

# Pousser avec signature
podman push --sign-by your@email.com localhost:5000/myapp:v1
```

---

## Exercice : À Vous de Jouer

!!! example "Mise en Pratique"
    **Objectif** : Mettre en place un registry privé local et créer un workflow de mirroring d'images avec validation d'intégrité

    **Contexte** : Vous travaillez dans un environnement d'entreprise où vous devez synchroniser des images Docker Hub vers un registry privé interne. Vous devez également préparer des images pour un déploiement air-gap (sans connexion internet). Skopeo vous permettra d'inspecter, copier et valider les images sans les télécharger localement.

    **Tâches à réaliser** :

    1. Déployer un registry Docker local avec Podman
    2. Configurer Podman pour accepter le registry insecure
    3. Inspecter des images distantes avec Skopeo sans les télécharger
    4. Copier plusieurs images de Docker Hub vers le registry local
    5. Vérifier l'intégrité des images copiées en comparant les digests
    6. Lister le catalogue du registry
    7. Exporter des images au format OCI pour un déploiement air-gap
    8. Nettoyer l'environnement

    **Critères de validation** :

    - [ ] Le registry local est accessible sur localhost:5000
    - [ ] Les images sont copiées avec succès vers le registry local
    - [ ] Les digests source et destination sont identiques
    - [ ] Le catalogue du registry affiche les images copiées
    - [ ] Les images sont exportées au format OCI

??? quote "Solution"
    Voici la solution complète pour le mirroring avec Skopeo :

    ```bash
    # 1. Démarrer un registry Docker local
    echo "=== Starting local registry ==="
    podman run -d \
      --name lab-registry \
      -p 5000:5000 \
      -v lab-registry:/var/lib/registry \
      --restart=always \
      docker.io/library/registry:2

    # Attendre que le registry démarre
    sleep 3
    curl -s http://localhost:5000/v2/ | jq .

    # 2. Configurer Podman pour accepter le registry insecure
    echo "=== Configuring insecure registry ==="
    sudo tee /etc/containers/registries.conf.d/lab.conf << 'EOF'
    [[registry]]
    location = "localhost:5000"
    insecure = true
    EOF

    # Vérifier la configuration
    grep -A2 "localhost:5000" /etc/containers/registries.conf.d/lab.conf

    # 3. Inspecter les images sources SANS les télécharger
    echo "=== Inspecting remote images with Skopeo ==="

    # Nginx - informations complètes
    skopeo inspect docker://docker.io/library/nginx:alpine | jq '{
      name: .Name,
      created: .Created,
      architecture: .Architecture,
      os: .Os,
      size: .Size,
      layers: .Layers | length,
      digest: .Digest
    }'

    # Redis - tags disponibles
    skopeo list-tags docker://docker.io/library/redis | jq '.Tags | .[] | select(startswith("7-alpine"))'

    # PostgreSQL - manifest brut
    skopeo inspect --raw docker://docker.io/library/postgres:15-alpine | jq '.schemaVersion'

    # 4. Copier plusieurs images vers le registry local
    echo "=== Mirroring images to local registry ==="

    IMAGES=(
      "nginx:alpine"
      "redis:7-alpine"
      "postgres:15-alpine"
    )

    for img in "${IMAGES[@]}"; do
      echo "Copying $img..."
      skopeo copy \
        --dest-tls-verify=false \
        docker://docker.io/library/$img \
        docker://localhost:5000/$img
    done

    # 5. Vérifier le catalogue du registry
    echo "=== Registry catalog ==="
    curl -s http://localhost:5000/v2/_catalog | jq .

    # Lister les tags de nginx
    curl -s http://localhost:5000/v2/nginx/tags/list | jq .

    # 6. Valider l'intégrité des images (comparer les digests)
    echo "=== Verifying image integrity ==="

    for img in "${IMAGES[@]}"; do
      echo "Checking $img..."
      SOURCE_DIGEST=$(skopeo inspect docker://docker.io/library/$img --format '{{.Digest}}')
      LOCAL_DIGEST=$(skopeo inspect --tls-verify=false docker://localhost:5000/$img --format '{{.Digest}}')

      if [ "$SOURCE_DIGEST" == "$LOCAL_DIGEST" ]; then
        echo "  ✓ Digests match: $SOURCE_DIGEST"
      else
        echo "  ✗ Digest mismatch!"
        echo "    Source: $SOURCE_DIGEST"
        echo "    Local:  $LOCAL_DIGEST"
      fi
    done

    # 7. Exporter pour déploiement air-gap
    echo "=== Exporting images for air-gap deployment ==="
    mkdir -p ~/podman-lab/air-gap-images

    # Export au format OCI
    skopeo copy \
      --src-tls-verify=false \
      docker://localhost:5000/nginx:alpine \
      oci:~/podman-lab/air-gap-images/nginx:alpine

    # Export au format docker-archive
    skopeo copy \
      --src-tls-verify=false \
      docker://localhost:5000/redis:7-alpine \
      docker-archive:~/podman-lab/air-gap-images/redis-7-alpine.tar:redis:7-alpine

    # Vérifier les exports
    ls -lh ~/podman-lab/air-gap-images/
    du -sh ~/podman-lab/air-gap-images/*

    # 8. Tester le chargement depuis l'export
    echo "=== Testing air-gap import ==="

    # Import depuis OCI
    skopeo copy \
      oci:~/podman-lab/air-gap-images/nginx:alpine \
      containers-storage:localhost/nginx-airgap:latest

    # Vérifier que l'image est chargée
    podman images localhost/nginx-airgap

    # 9. Synchronisation avancée (bonus)
    echo "=== Advanced: Sync multiple images ==="

    # Créer un fichier de configuration pour skopeo sync
    cat > ~/podman-lab/sync-config.yaml << 'EOF'
    docker.io:
      images:
        nginx:
          - "alpine"
          - "1.25-alpine"
        redis:
          - "7-alpine"
    EOF

    # Synchroniser vers un répertoire
    skopeo sync \
      --src yaml \
      --dest dir \
      ~/podman-lab/sync-config.yaml \
      ~/podman-lab/synced-images/

    ls -R ~/podman-lab/synced-images/

    # 10. Cleanup
    echo "=== Cleanup ==="
    podman stop lab-registry
    podman rm lab-registry
    podman volume rm lab-registry
    podman rmi localhost/nginx-airgap
    rm -rf ~/podman-lab/air-gap-images
    rm -rf ~/podman-lab/synced-images
    rm ~/podman-lab/sync-config.yaml
    sudo rm /etc/containers/registries.conf.d/lab.conf

    echo "✓ Exercise completed successfully!"
    ```

    !!! success "Avantages de Skopeo"
        - **Pas de stockage local** : Copie directe registry-à-registry
        - **Inspection sans pull** : Économise bande passante et espace disque
        - **Multi-format** : OCI, Docker, tar archives
        - **Validation d'intégrité** : Vérification des digests automatique

    !!! tip "Cas d'usage en production"
        **Registry mirroring** :
        ```bash
        # Automatiser avec cron/systemd timer
        */30 * * * * /usr/local/bin/mirror-critical-images.sh
        ```

        **Air-gap deployment** :
        ```bash
        # Sur la machine connectée
        skopeo sync --src yaml --dest dir sync.yaml /media/usb/images/

        # Sur la machine air-gap
        skopeo sync --src dir --dest docker /media/usb/images/ registry.local:5000
        ```

        **Vérification de sécurité** :
        ```bash
        # Vérifier les vulnérabilités avant mirroring
        skopeo inspect docker://image:tag | jq .Labels
        ```

    !!! note "Formats de transport"
        - `docker://` : Registry Docker/OCI (standard)
        - `oci:` : Répertoire au format OCI Layout
        - `docker-archive:` : Archive tar Docker
        - `dir:` : Répertoire simple (debug)
        - `containers-storage:` : Storage Podman local

---

## Quiz

1. **Comment inspecter une image sans la télécharger ?**
   - [ ] A. podman inspect
   - [ ] B. skopeo inspect docker://
   - [ ] C. buildah inspect

**Réponse :** B

2. **Quel format utiliser pour un export air-gap ?**
   - [ ] A. docker://
   - [ ] B. containers-storage:
   - [ ] C. oci: ou docker-archive:

**Réponse :** C

3. **Comment lister les tags d'une image distante ?**
   - [ ] A. skopeo tags
   - [ ] B. skopeo list-tags docker://
   - [ ] C. skopeo inspect --tags

**Réponse :** B

---

**Précédent :** [Module 3 - Buildah](03-module.md)

**Suivant :** [Module 5 - Pods](05-module.md)

---

## Navigation

| | |
|:---|---:|
| [← Module 3 : Buildah & Construction d'I...](03-module.md) | [Module 5 : Pods & Multi-Conteneurs →](05-module.md) |

[Retour au Programme](index.md){ .md-button }
