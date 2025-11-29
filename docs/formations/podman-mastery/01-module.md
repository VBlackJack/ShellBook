---
tags:
  - formation
  - podman
  - containers
  - architecture
---

# Module 1 : Fondamentaux & Architecture

## Objectifs du Module

- Comprendre les différences Docker vs Podman
- Maîtriser l'architecture daemonless
- Installer et configurer Podman
- Exécuter vos premiers conteneurs

**Durée :** 2 heures

---

## 1. Docker vs Podman

```
ARCHITECTURE COMPARÉE
═════════════════════════════════════════════════════════

DOCKER                          PODMAN
──────                          ──────

┌─────────┐                    ┌─────────┐
│ docker  │                    │ podman  │
│   CLI   │                    │   CLI   │
└────┬────┘                    └────┬────┘
     │                              │
     │ socket                       │ direct
     ▼                              ▼
┌─────────┐                    ┌─────────┐
│ dockerd │ ◄── daemon         │ conmon  │ ◄── par conteneur
│ (root)  │     permanent      │         │     fork/exec
└────┬────┘                    └────┬────┘
     │                              │
     ▼                              ▼
┌─────────┐                    ┌─────────┐
│  runc   │                    │  crun   │
└─────────┘                    └─────────┘

Points clés :
• Docker : daemon central, single point of failure
• Podman : fork/exec, pas de daemon, rootless natif
```

### Avantages Podman

| Aspect | Docker | Podman |
|--------|--------|--------|
| Daemon | Oui (dockerd) | Non (daemonless) |
| Root requis | Par défaut | Rootless natif |
| Sécurité | Socket root | Fork/exec user |
| Systemd | Via wrapper | Intégration native |
| Pods | Non | Oui (comme K8s) |
| Compatibility | Standard | 100% OCI + Docker CLI |

---

## 2. Installation sur RHEL/Rocky

```bash
# RHEL 9 / Rocky Linux 9
sudo dnf install -y podman buildah skopeo

# Outils complémentaires
sudo dnf install -y podman-compose  # Alternative à docker-compose
sudo dnf install -y container-tools # Meta-package

# Vérification
podman --version
podman info
```

### Configuration Système

```bash
# Activer le linger pour les conteneurs rootless au boot
sudo loginctl enable-linger $USER

# Vérifier
loginctl show-user $USER | grep Linger
# Linger=yes
```

---

## 3. Configuration des Registries

```bash
# Fichier de configuration
cat /etc/containers/registries.conf
```

```toml
# /etc/containers/registries.conf

# Registries par défaut pour les noms courts
unqualified-search-registries = ["registry.redhat.io", "registry.access.redhat.com", "docker.io"]

# Miroirs (optionnel)
[[registry]]
location = "docker.io"
  [[registry.mirror]]
  location = "mirror.gcr.io"

# Registry privé sans TLS (lab)
[[registry]]
location = "registry.lab.local:5000"
insecure = true
```

### Configuration Utilisateur

```bash
# Configuration personnelle
mkdir -p ~/.config/containers

# Copier et personnaliser
cp /etc/containers/registries.conf ~/.config/containers/

# Authentification
podman login registry.redhat.io
podman login docker.io
# Credentials stockés dans ~/.local/share/containers/auth.json
```

---

## 4. Commandes de Base

```bash
# Alias compatible Docker
alias docker=podman

# Rechercher une image
podman search nginx
podman search --list-tags docker.io/library/nginx

# Télécharger une image
podman pull nginx:alpine
podman pull registry.access.redhat.com/ubi9/ubi-minimal

# Lister les images
podman images

# Exécuter un conteneur
podman run -d --name web -p 8080:80 nginx:alpine

# Lister les conteneurs
podman ps
podman ps -a

# Logs
podman logs web
podman logs -f web

# Exécuter une commande
podman exec -it web sh

# Arrêter et supprimer
podman stop web
podman rm web

# Nettoyage
podman system prune -af
```

---

## 5. Images UBI (Universal Base Image)

Red Hat fournit des images de base gratuites et supportées :

```bash
# UBI 9 - Image complète
podman pull registry.access.redhat.com/ubi9/ubi

# UBI 9 Minimal - Image légère
podman pull registry.access.redhat.com/ubi9/ubi-minimal

# UBI 9 Micro - Image ultra-légère (distroless-like)
podman pull registry.access.redhat.com/ubi9/ubi-micro

# Comparaison des tailles
podman images | grep ubi
# ubi         ~210MB
# ubi-minimal ~95MB
# ubi-micro   ~25MB
```

### Pourquoi UBI ?

```
AVANTAGES UBI
═════════════
✓ Gratuites (même sans subscription)
✓ Supportées par Red Hat
✓ Mises à jour sécurité régulières
✓ Certifiées pour production
✓ Compatible RHEL (même packages)
✓ Disponibles sur tous les registries
```

---

## 6. Informations Système

```bash
# Informations complètes
podman info

# Points importants
podman info | grep -A5 "store"
# graphRoot: /var/lib/containers/storage (root)
# graphRoot: ~/.local/share/containers/storage (rootless)

# Version et features
podman version

# Vérifier le mode rootless
podman info | grep rootless
# rootless: true
```

---

## 7. Exercice Pratique

### Objectif

Déployer un serveur web Nginx avec du contenu personnalisé.

### Étapes

```bash
# 1. Créer un répertoire de travail
mkdir -p ~/podman-lab/web
cd ~/podman-lab/web

# 2. Créer une page HTML
cat > index.html << 'EOF'
<!DOCTYPE html>
<html>
<head><title>Podman Lab</title></head>
<body>
<h1>Hello from Podman!</h1>
<p>Running rootless on $(hostname)</p>
</body>
</html>
EOF

# 3. Lancer le conteneur avec un volume
podman run -d \
  --name webserver \
  -p 8080:80 \
  -v ./index.html:/usr/share/nginx/html/index.html:ro,Z \
  nginx:alpine

# 4. Tester
curl http://localhost:8080

# 5. Inspecter
podman inspect webserver | jq '.[0].NetworkSettings'

# 6. Voir les logs
podman logs webserver

# 7. Cleanup
podman stop webserver && podman rm webserver
```

!!! note "Option :Z"
    L'option `:Z` sur les volumes applique le contexte SELinux approprié. Essentiel sur RHEL/Rocky.

---

## Quiz

1. **Quelle est la différence principale entre Docker et Podman ?**
   - [ ] A. Podman est plus rapide
   - [ ] B. Podman n'a pas de daemon
   - [ ] C. Podman ne supporte pas les volumes

**Réponse :** B - Podman utilise une architecture fork/exec sans daemon central.

2. **Quel fichier configure les registries par défaut ?**
   - [ ] A. /etc/podman/config.json
   - [ ] B. /etc/containers/registries.conf
   - [ ] C. ~/.podman/registries.yaml

**Réponse :** B

3. **Quelle image UBI est la plus légère ?**
   - [ ] A. ubi9/ubi
   - [ ] B. ubi9/ubi-minimal
   - [ ] C. ubi9/ubi-micro

**Réponse :** C - ubi-micro (~25MB)

---

**Suivant :** [Module 2 - Conteneurs Rootless](02-module.md)
