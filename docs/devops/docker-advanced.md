# Astuces & Hacks Docker Pro

`#docker` `#productivity` `#security`

Fonctionnalités avancées de Docker qui vous feront gagner des heures de travail.

---

## Astuce 1: Scaffolding Instantané (`docker init`)

Arrêtez d'écrire des Dockerfiles from scratch. Laissez Docker les générer pour vous.

```bash
cd mon-projet
docker init
```

**Ce que ça fait:**

- Détecte le langage de votre projet (Python, Node, Go, Rust, etc.)
- Génère un `Dockerfile` optimisé avec les bonnes pratiques
- Crée un `compose.yaml` pour le développement local
- Ajoute un fichier `.dockerignore`

**Exemple de sortie:**

```
? What application platform does your project use? Python
? What version of Python? 3.11
? What port does your server listen on? 8000

✔ Created Dockerfile
✔ Created compose.yaml
✔ Created .dockerignore
```

!!! tip "Fonctionne avec les projets existants"
    Exécuter `docker init` dans n'importe quel répertoire de projet existant. Il analyse votre code et génère les configs appropriées.

---

## Astuce 2: Hot Reloading (`docker compose watch`)

Remplacer les montages de volumes complexes par une synchronisation de fichiers native pour le développement.

```bash
docker compose watch
```

**Configuration compose.yaml:**

```yaml
services:
  web:
    build: .
    ports:
      - "3000:3000"
    develop:
      watch:
        # Synchroniser les fichiers sans rebuild
        - action: sync
          path: ./src
          target: /app/src

        # Synchroniser et redémarrer le container
        - action: sync+restart
          path: ./config
          target: /app/config

        # Rebuild lors de changements de dépendances
        - action: rebuild
          path: ./package.json
```

**Actions expliquées:**

| Action | Comportement |
|--------|----------|
| `sync` | Copier les fichiers vers le container (hot reload) |
| `sync+restart` | Copier les fichiers et redémarrer le container |
| `rebuild` | Déclencher un rebuild complet de l'image |

!!! warning "Remplace les bind mounts"
    `docker compose watch` est plus propre que les montages de volumes pour le développement:

    - Pas de problèmes de permissions
    - Meilleures performances sur macOS/Windows
    - Synchronisation sélective (ignorer node_modules)

---

## Astuce 3: Déboguer Distroless (`docker debug`)

**Problème:** Votre container de production n'a pas de shell, pas de bash, pas d'outils. Comment déboguer?

```bash
# Ça échoue sur les images distroless/minimales
docker exec -it mon-container /bin/sh
# Error: executable file not found
```

**Solution:** Docker Debug attache un toolkit de débogage.

```bash
docker debug <container_id>
```

**Ce que vous obtenez:**

- Accès shell complet (même sur distroless)
- vim, curl, wget, netcat pré-installés
- Outils d'inspection de processus
- Utilitaires de débogage réseau

```bash
# Déboguer un container en cours d'exécution
docker debug mon-api-container

# Déboguer avec une image spécifique comme toolkit
docker debug --shell bash mon-container

# Déboguer un container arrêté
docker debug --platform linux/amd64 mon-container
```

!!! info "Comment ça marche"
    Docker Debug crée un container sidecar qui partage les namespaces du container cible (PID, réseau, filesystem) sans modifier l'image originale.

---

## Astuce 4: Scan de Sécurité (`docker scout`)

Scan CVE intégré et recommandations de remédiation.

### Aperçu Rapide des Vulnérabilités

```bash
# Scanner l'image du répertoire actuel
docker scout quickview

# Scanner une image spécifique
docker scout quickview nginx:latest

# Exemple de sortie:
#   Target     │ nginx:latest
#   Digest     │ sha256:abc123...
#   Base Image │ debian:bookworm-slim
#
#   Vulnerabilities
#     Critical: 2
#     High:     5
#     Medium:   12
```

### Obtenir les Recommandations de Correctifs

```bash
# Obtenir les recommandations de mise à jour
docker scout recommendations nginx:latest

# Exemple de sortie:
#   Recommended fixes:
#   ✓ Update base image from debian:bookworm-slim to debian:bookworm-slim@sha256:...
#     Fixes: CVE-2024-1234 (Critical), CVE-2024-5678 (High)
```

### Comparer les Images

```bash
# Comparer deux versions d'image
docker scout compare nginx:1.24 nginx:1.25

# Voir ce qui a changé (nouvelles CVE, CVE corrigées)
```

!!! danger "Intégration CI/CD"
    Ajouter Scout à votre pipeline pour faire échouer les builds sur des CVE critiques:

    ```yaml
    - name: Scan for vulnerabilities
      run: |
        docker scout cves --exit-code --only-severity critical,high
    ```

---

## Astuce 5: Applications GUI dans les Containers (Forwarding X11)

Exécuter des applications graphiques (navigateurs, IDEs, jeux) dans des containers.

### Configuration Linux

```bash
# Autoriser les connexions X11
xhost +local:docker

# Exécuter Firefox dans un container
docker run -it --rm \
  -e DISPLAY=$DISPLAY \
  -v /tmp/.X11-unix:/tmp/.X11-unix \
  --network host \
  jess/firefox
```

### Configuration macOS (XQuartz)

```bash
# 1. Installer XQuartz
brew install --cask xquartz

# 2. Activer les connexions réseau dans les préférences XQuartz
# XQuartz → Preferences → Security → "Allow connections from network clients"

# 3. Redémarrer et autoriser les connexions
xhost +localhost

# 4. Exécuter avec DISPLAY pointant vers l'hôte
docker run -it --rm \
  -e DISPLAY=host.docker.internal:0 \
  jess/firefox
```

### Configuration Windows (VcXsrv)

```powershell
# 1. Installer VcXsrv
# 2. Lancer XLaunch avec "Disable access control" coché

# 3. Exécuter le container
docker run -it --rm `
  -e DISPLAY=host.docker.internal:0 `
  jess/firefox
```

!!! tip "Containers GUI Populaires"
    - `jess/firefox` - Navigateur Firefox
    - `linuxserver/firefox` - Firefox avec VNC
    - `linuxserver/chromium` - Navigateur Chromium
    - `kasmweb/*` - Isolation de navigateur (entreprise)

---

## Astuce 6: Vitesse Multi-Arch (`docker build --builder cloud`)

**Problème:** Builder des images x86/amd64 sur Apple Silicon (ARM) est très lent à cause de l'émulation QEMU.

```bash
# C'est LENT sur Mac M1/M2 (émulation)
docker build --platform linux/amd64 -t myapp .
```

**Solution:** Délocaliser les builds vers Docker Build Cloud.

```bash
# Créer un cloud builder
docker buildx create --driver cloud myorg/mybuilder

# Builder en utilisant le cloud (vitesse native pour toutes les architectures)
docker build --builder cloud-myorg-mybuilder \
  --platform linux/amd64,linux/arm64 \
  -t myapp:latest .
```

### Avantages

| Build Local (Émulé) | Build Cloud (Natif) |
|------------------------|----------------------|
| 10-20 minutes | 1-2 minutes |
| CPU à 100% | CPU local inactif |
| Une arch à la fois | Multi-arch parallèle |

### Configuration

```bash
# Se connecter à Docker Hub
docker login

# Créer un cloud builder (nécessite un abonnement Docker)
docker buildx create --driver cloud <org>/<builder-name>

# L'utiliser
docker buildx use cloud-<org>-<builder-name>
```

!!! info "Free Tier Disponible"
    Docker Build Cloud a un tier gratuit avec des minutes de build limitées. Parfait pour des builds multi-arch occasionnels.

---

## Bonus: Référence Rapide

```bash
# Nettoyer tout (récupérer de l'espace disque)
docker system prune -a --volumes

# Voir l'utilisation des ressources en temps réel
docker stats

# Copier des fichiers depuis un container
docker cp container:/path/file ./local/

# Exporter le filesystem d'un container
docker export container > container.tar

# Inspecter les couches d'une image
docker history --no-trunc myimage

# Exécuter une commande ponctuelle dans un nouveau container
docker run --rm -it alpine sh
```
