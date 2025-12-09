---
tags:
  - formation
  - podman
  - systemd
  - quadlet
---

# Module 6 : Intégration Systemd

## Objectifs du Module

- Générer des unités systemd pour les conteneurs
- Maîtriser Quadlet pour les conteneurs déclaratifs
- Configurer l'auto-update des images
- Gérer les logs avec journald

**Durée :** 2 heures

---

## 1. Conteneurs et Systemd

```text
INTÉGRATION SYSTEMD
═════════════════════════════════════════════════════════

Pourquoi systemd ?
──────────────────
✓ Démarrage automatique au boot
✓ Gestion des dépendances
✓ Restart automatique
✓ Logs centralisés (journald)
✓ Monitoring intégré
✓ Rootless supporté

Méthodes d'intégration :
────────────────────────
1. podman generate systemd (legacy)
2. Quadlet (moderne, recommandé)
```

---

## 2. Génération d'Unités Systemd

### Méthode Classique

```bash
# Créer un conteneur
podman run -d --name nginx -p 8080:80 nginx:alpine

# Générer l'unité systemd
podman generate systemd --name nginx > nginx.service

# Voir le contenu
cat nginx.service
```

### Unité Générée

```ini
# nginx.service (généré)
[Unit]
Description=Podman container-nginx.service
Documentation=man:podman-generate-systemd(1)
Wants=network-online.target
After=network-online.target
RequiresMountsFor=%t/containers

[Service]
Environment=PODMAN_SYSTEMD_UNIT=%n
Restart=on-failure
TimeoutStopSec=70
ExecStart=/usr/bin/podman start nginx
ExecStop=/usr/bin/podman stop -t 10 nginx
ExecStopPost=/usr/bin/podman stop -t 10 nginx
PIDFile=%t/containers/nginx.pid
Type=forking

[Install]
WantedBy=default.target
```

### Installation Rootless

```bash
# Créer le répertoire utilisateur
mkdir -p ~/.config/systemd/user/

# Générer et installer
podman generate systemd --name nginx --files --new
mv container-nginx.service ~/.config/systemd/user/

# Activer
systemctl --user daemon-reload
systemctl --user enable --now container-nginx.service

# Vérifier
systemctl --user status container-nginx.service

# Important : activer le linger pour le boot
sudo loginctl enable-linger $USER
```

### Installation Rootful

```bash
# En tant que root
sudo podman run -d --name nginx -p 80:80 nginx:alpine
sudo podman generate systemd --name nginx --files --new
sudo mv container-nginx.service /etc/systemd/system/

# Activer
sudo systemctl daemon-reload
sudo systemctl enable --now container-nginx.service
```

---

## 3. Quadlet (Moderne)

### Introduction

Quadlet est la méthode moderne et déclarative pour gérer les conteneurs avec systemd.

```text
QUADLET - CONTENEURS DÉCLARATIFS
════════════════════════════════

Fichiers supportés :
────────────────────
.container   → Conteneur simple
.pod         → Pod multi-conteneurs
.volume      → Volume nommé
.network     → Réseau
.kube        → Manifest Kubernetes

Emplacement :
─────────────
Rootless : ~/.config/containers/systemd/
Rootful  : /etc/containers/systemd/
```

### Conteneur Simple

```ini
# ~/.config/containers/systemd/nginx.container

[Unit]
Description=Nginx Web Server

[Container]
Image=docker.io/library/nginx:alpine
PublishPort=8080:80
Volume=nginx-html:/usr/share/nginx/html:Z

# Options de sécurité
ReadOnly=true
NoNewPrivileges=true

[Service]
Restart=always
TimeoutStartSec=30

[Install]
WantedBy=default.target
```

### Activer un Quadlet

```bash
# Recharger les unités
systemctl --user daemon-reload

# Lister les unités générées
systemctl --user list-unit-files | grep nginx

# Démarrer
systemctl --user start nginx.service

# Activer au boot
systemctl --user enable nginx.service

# Logs
journalctl --user -u nginx.service -f
```

---

## 4. Exemples Quadlet Avancés

### Application avec Base de Données

```ini
# ~/.config/containers/systemd/app-network.network
[Network]
Subnet=10.89.0.0/24
Gateway=10.89.0.1
```

```ini
# ~/.config/containers/systemd/postgres.container
[Unit]
Description=PostgreSQL Database
After=app-network.service

[Container]
Image=docker.io/library/postgres:15-alpine
Network=app-network.network
Volume=postgres-data:/var/lib/postgresql/data:Z
Environment=POSTGRES_USER=app
Environment=POSTGRES_PASSWORD=secret
Environment=POSTGRES_DB=myapp
HealthCmd=pg_isready -U app
HealthInterval=10s

[Service]
Restart=always

[Install]
WantedBy=default.target
```

```ini
# ~/.config/containers/systemd/api.container
[Unit]
Description=API Server
After=postgres.service
Requires=postgres.service

[Container]
Image=myregistry/api:latest
Network=app-network.network
PublishPort=8080:8080
Environment=DATABASE_URL=postgres://app:secret@postgres:5432/myapp
HealthCmd=curl -f http://localhost:8080/health
HealthInterval=30s

# Auto-update
AutoUpdate=registry

[Service]
Restart=always

[Install]
WantedBy=default.target
```

### Volume Dédié

```ini
# ~/.config/containers/systemd/postgres-data.volume
[Volume]
# Options du volume
Driver=local
```

### Pod avec Quadlet

```ini
# ~/.config/containers/systemd/webapp.pod
[Unit]
Description=Web Application Pod

[Pod]
PublishPort=80:80
PublishPort=443:443
Network=app-network.network
```

```ini
# ~/.config/containers/systemd/webapp-nginx.container
[Unit]
Description=Nginx in webapp pod

[Container]
Image=nginx:alpine
Pod=webapp.pod
Volume=./nginx.conf:/etc/nginx/nginx.conf:ro,Z

[Install]
WantedBy=default.target
```

---

## 5. Auto-Update des Images

### Configuration

```ini
# Dans le fichier .container
[Container]
Image=docker.io/library/nginx:latest
AutoUpdate=registry
```

### Activer l'Auto-Update

```bash
# Timer systemd pour les mises à jour
systemctl --user enable --now podman-auto-update.timer

# Vérifier le timer
systemctl --user list-timers podman-auto-update.timer

# Déclencher manuellement
podman auto-update

# Voir les conteneurs éligibles
podman auto-update --dry-run
```

### Stratégies d'Auto-Update

```text
AUTO-UPDATE STRATEGIES
══════════════════════

registry (recommandé)
─────────────────────
- Vérifie le registry pour une nouvelle image
- Pull et restart si digest différent

local
─────
- Utilise l'image locale si mise à jour
- Pour les builds locaux

Rollback automatique :
──────────────────────
Si le healthcheck échoue après update,
Podman restaure l'ancienne image
```

---

## 6. Logs et Monitoring

### Configuration Journald

```ini
# Dans le fichier .container
[Container]
LogDriver=journald
```

### Consulter les Logs

```bash
# Logs d'un service
journalctl --user -u nginx.service

# Suivre les logs
journalctl --user -u nginx.service -f

# Logs depuis un timestamp
journalctl --user -u nginx.service --since "1 hour ago"

# Logs JSON (pour parsing)
journalctl --user -u nginx.service -o json

# Filtrer par priorité
journalctl --user -u nginx.service -p err
```

### Monitoring avec Systemd

```bash
# Status détaillé
systemctl --user status nginx.service

# Ressources utilisées
systemctl --user show nginx.service --property=MemoryCurrent,CPUUsageNSec

# Events systemd
journalctl --user -u nginx.service -o cat | grep -E "(Started|Stopped|Failed)"
```

---

## Exercice : À Vous de Jouer

!!! example "Mise en Pratique"
    **Objectif** : Déployer une stack applicative complète avec Quadlet pour une gestion déclarative et une intégration native avec systemd

    **Contexte** : Vous devez mettre en place une application web en production avec une approche moderne et déclarative. L'application comprend un frontend Nginx, une API backend, et une base de données PostgreSQL. Tous les services doivent démarrer automatiquement au boot, se redémarrer en cas de crash, et être gérés par systemd. Vous utiliserez Quadlet pour définir l'infrastructure de manière déclarative.

    **Tâches à réaliser** :

    1. Créer un réseau dédié pour l'application avec Quadlet
    2. Définir un volume persistant pour PostgreSQL
    3. Déployer PostgreSQL avec health checks
    4. Déployer l'API avec dépendances sur PostgreSQL
    5. Déployer Nginx en frontend avec auto-update activé
    6. Configurer les dépendances entre services
    7. Activer tous les services au boot
    8. Tester le fonctionnement et consulter les logs journald
    9. Vérifier l'auto-update
    10. Nettoyer l'environnement

    **Critères de validation** :

    - [ ] Les fichiers Quadlet sont dans ~/.config/containers/systemd/
    - [ ] Les services systemd sont générés automatiquement
    - [ ] PostgreSQL démarre avant l'API (dépendances respectées)
    - [ ] Les services redémarrent automatiquement en cas d'échec
    - [ ] Les logs sont disponibles via journalctl
    - [ ] Les services sont activés au boot

??? quote "Solution"
    Voici la solution complète pour déployer une stack avec Quadlet :

    **1. Créer la structure Quadlet**

    ```bash
    # Créer le répertoire Quadlet
    mkdir -p ~/.config/containers/systemd/
    cd ~/.config/containers/systemd/

    # Vérifier le support Quadlet
    ls -la ~/.config/containers/systemd/
    ```

    **2. Définir le réseau dédié**

    ```bash
    cat > ~/.config/containers/systemd/myapp-network.network << 'EOF'
    # Réseau isolé pour l'application
    [Network]
    # Subnet IPv4 dédié
    Subnet=10.90.0.0/24
    Gateway=10.90.0.1

    # Labels pour identification
    Label=app=myapp
    Label=env=production

    [Install]
    WantedBy=default.target
    EOF
    ```

    **3. Créer le volume PostgreSQL**

    ```bash
    cat > ~/.config/containers/systemd/postgres-data.volume << 'EOF'
    # Volume persistant pour PostgreSQL
    [Volume]
    # Driver par défaut (local)
    Driver=local

    # Labels
    Label=app=myapp
    Label=component=database

    [Install]
    WantedBy=default.target
    EOF
    ```

    **4. Déployer PostgreSQL avec health checks**

    ```bash
    cat > ~/.config/containers/systemd/postgres.container << 'EOF'
    [Unit]
    Description=PostgreSQL Database for MyApp
    Documentation=https://www.postgresql.org/docs/
    After=myapp-network.service
    Requires=myapp-network.service

    [Container]
    # Image officielle PostgreSQL
    Image=docker.io/library/postgres:15-alpine

    # Réseau dédié
    Network=myapp-network.network

    # Volume persistant
    Volume=postgres-data.volume:/var/lib/postgresql/data:Z

    # Configuration PostgreSQL
    Environment=POSTGRES_USER=myapp
    Environment=POSTGRES_PASSWORD=SecureP@ssw0rd123
    Environment=POSTGRES_DB=myapp
    Environment=POSTGRES_INITDB_ARGS=--encoding=UTF8 --locale=en_US.UTF-8

    # Health check
    HealthCmd=pg_isready -U myapp -d myapp
    HealthInterval=10s
    HealthTimeout=5s
    HealthRetries=3
    HealthStartPeriod=30s

    # Sécurité
    NoNewPrivileges=true
    ReadOnlyTmpfs=true

    # Labels
    Label=app=myapp
    Label=component=database
    Label=version=15

    [Service]
    Restart=always
    RestartSec=10
    TimeoutStartSec=120

    [Install]
    WantedBy=default.target
    EOF
    ```

    **5. Déployer l'API backend**

    ```bash
    cat > ~/.config/containers/systemd/api.container << 'EOF'
    [Unit]
    Description=API Backend Server
    After=postgres.service
    Requires=postgres.service
    BindsTo=postgres.service

    [Container]
    # API de test (httpbin)
    Image=docker.io/kennethreitz/httpbin:latest

    # Réseau commun avec PostgreSQL
    Network=myapp-network.network

    # Variables d'environnement
    Environment=DATABASE_URL=postgres://myapp:SecureP@ssw0rd123@10.90.0.2:5432/myapp
    Environment=API_ENV=production
    Environment=LOG_LEVEL=info

    # Health check
    HealthCmd=curl -f http://localhost:8080/health || exit 1
    HealthInterval=30s
    HealthTimeout=10s

    # Sécurité
    NoNewPrivileges=true

    # Labels
    Label=app=myapp
    Label=component=api

    [Service]
    Restart=always
    RestartSec=5

    [Install]
    WantedBy=default.target
    EOF
    ```

    **6. Déployer Nginx frontend**

    ```bash
    cat > ~/.config/containers/systemd/nginx.container << 'EOF'
    [Unit]
    Description=Nginx Frontend Reverse Proxy
    After=api.service
    Wants=api.service

    [Container]
    # Nginx Alpine
    Image=docker.io/library/nginx:alpine

    # Réseau et port exposé
    Network=myapp-network.network
    PublishPort=8080:80

    # Auto-update activé
    AutoUpdate=registry

    # Sécurité
    NoNewPrivileges=true
    ReadOnly=true
    Tmpfs=/var/cache/nginx
    Tmpfs=/var/run

    # Labels
    Label=app=myapp
    Label=component=frontend
    Label=io.containers.autoupdate=registry

    [Service]
    Restart=always
    RestartSec=5
    TimeoutStartSec=60

    [Install]
    WantedBy=default.target
    EOF
    ```

    **7. Activer et démarrer les services**

    ```bash
    # Recharger systemd pour découvrir les nouveaux fichiers Quadlet
    echo "=== Reloading systemd ==="
    systemctl --user daemon-reload

    # Lister les unités générées par Quadlet
    echo "=== Generated Units ==="
    systemctl --user list-unit-files | grep -E "(postgres|api|nginx|myapp)"

    # Vérifier les fichiers de service générés
    ls -la ~/.config/systemd/user/

    # Démarrer les services (les dépendances démarreront automatiquement)
    echo "=== Starting Services ==="
    systemctl --user start nginx.service

    # Attendre le démarrage complet
    sleep 10

    # Vérifier le statut de chaque service
    echo "=== Services Status ==="
    systemctl --user status postgres.service --no-pager -l
    systemctl --user status api.service --no-pager -l
    systemctl --user status nginx.service --no-pager -l
    systemctl --user status myapp-network.service --no-pager -l

    # Activer au boot
    echo "=== Enabling Services at Boot ==="
    systemctl --user enable postgres.service
    systemctl --user enable api.service
    systemctl --user enable nginx.service
    systemctl --user enable myapp-network.service

    # Vérifier que le linger est activé
    loginctl show-user $USER | grep Linger
    # Si "Linger=no", activer avec:
    # sudo loginctl enable-linger $USER
    ```

    **8. Vérifier et tester**

    ```bash
    # Lister les conteneurs actifs
    echo "=== Running Containers ==="
    podman ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

    # Vérifier le réseau
    echo "=== Network Info ==="
    podman network inspect systemd-myapp-network | jq '.[0].containers'

    # Tester l'application
    echo "=== Testing Application ==="
    curl -s http://localhost:8080 | head -20

    # Tester les health checks
    echo "=== Health Checks ==="
    podman healthcheck run systemd-postgres
    # Devrait retourner "healthy"

    # Vérifier les volumes
    echo "=== Volumes ==="
    podman volume ls
    podman volume inspect systemd-postgres-data | jq '.[0].Mountpoint'
    ```

    **9. Consulter les logs avec journalctl**

    ```bash
    # Logs PostgreSQL
    echo "=== PostgreSQL Logs ==="
    journalctl --user -u postgres.service -n 50 --no-pager

    # Logs de l'API
    journalctl --user -u api.service -n 30 --no-pager

    # Logs Nginx
    journalctl --user -u nginx.service -n 20 --no-pager

    # Suivre les logs en temps réel
    journalctl --user -u postgres.service -f
    # Ctrl+C pour arrêter

    # Logs depuis une date
    journalctl --user -u nginx.service --since "10 minutes ago"

    # Logs avec niveau de priorité
    journalctl --user -u postgres.service -p err
    ```

    **10. Tester l'auto-update**

    ```bash
    # Vérifier la configuration auto-update
    echo "=== Auto-Update Status ==="
    podman auto-update --dry-run

    # Activer le timer auto-update
    systemctl --user enable --now podman-auto-update.timer

    # Vérifier le timer
    systemctl --user list-timers --all | grep podman-auto-update

    # Forcer une vérification manuelle
    systemctl --user start podman-auto-update.service
    journalctl --user -u podman-auto-update.service -n 20
    ```

    **11. Test de résilience**

    ```bash
    # Tuer un conteneur pour tester le restart
    echo "=== Testing Auto-Restart ==="
    podman kill systemd-nginx

    # Observer le redémarrage
    watch -n 1 "systemctl --user status nginx.service | grep Active"

    # Vérifier les restart count
    systemctl --user show nginx.service -p NRestarts
    ```

    **12. Cleanup**

    ```bash
    # Arrêter tous les services
    echo "=== Stopping Services ==="
    systemctl --user stop nginx.service
    systemctl --user stop api.service
    systemctl --user stop postgres.service
    systemctl --user stop myapp-network.service

    # Désactiver les services
    systemctl --user disable nginx.service
    systemctl --user disable api.service
    systemctl --user disable postgres.service
    systemctl --user disable myapp-network.service

    # Supprimer les fichiers Quadlet
    rm ~/.config/containers/systemd/postgres.container
    rm ~/.config/containers/systemd/api.container
    rm ~/.config/containers/systemd/nginx.container
    rm ~/.config/containers/systemd/myapp-network.network
    rm ~/.config/containers/systemd/postgres-data.volume

    # Recharger systemd
    systemctl --user daemon-reload

    # Nettoyer les volumes et réseaux
    podman volume rm systemd-postgres-data
    podman network rm systemd-myapp-network

    echo "✓ Cleanup completed!"
    ```

    !!! success "Avantages de Quadlet"
        - **Déclaratif** : Infrastructure as Code avec des fichiers simples
        - **Intégration systemd** : Gestion native, logs journald, dépendances
        - **Rootless friendly** : Fonctionne parfaitement en mode utilisateur
        - **Auto-update** : Mises à jour automatiques des images
        - **Production ready** : Restart automatique, health checks, monitoring

    !!! tip "Bonnes pratiques Quadlet"
        **Organisation des fichiers** :
        ```text
        ~/.config/containers/systemd/
        ├── app-network.network
        ├── app-data.volume
        ├── database.container
        ├── api.container
        └── frontend.container
        ```

        **Gestion des secrets** :
        ```bash
        # Utiliser des secrets Podman
        podman secret create db_password /path/to/secret
        ```

        **Monitoring** :
        ```bash
        # Créer des alertes systemd
        systemctl --user edit postgres.service
        # Ajouter [Unit] OnFailure=notify-failure@%n.service
        ```

    !!! note "Différences avec docker-compose"
        | Feature | docker-compose | Quadlet |
        |---------|---------------|---------|
        | Format | YAML | INI (systemd) |
        | Daemon | Oui (dockerd) | Non (systemd) |
        | Logs | docker logs | journalctl |
        | Auto-restart | Dans le YAML | systemd natif |
        | Boot | Extra config | systemd enable |
        | Rootless | Limité | Natif |

    !!! warning "Points d'attention"
        - Les chemins de fichiers dans Quadlet doivent être absolus
        - Le reload systemd est nécessaire après chaque modification
        - Les volumes et réseaux sont préfixés par "systemd-"
        - Le linger doit être activé pour les services rootless au boot

---

## Quiz

1. **Où placer les fichiers Quadlet en mode rootless ?**
   - [ ] A. /etc/systemd/user/
   - [ ] B. ~/.config/containers/systemd/
   - [ ] C. ~/.local/share/podman/

**Réponse :** B

2. **Quelle commande recharge les unités Quadlet ?**
   - [ ] A. podman reload
   - [ ] B. systemctl --user daemon-reload
   - [ ] C. quadlet reload

**Réponse :** B

3. **Quelle option active les mises à jour automatiques ?**
   - [ ] A. Update=auto
   - [ ] B. AutoUpdate=registry
   - [ ] C. AutoPull=true

**Réponse :** B

---

**Précédent :** [Module 5 - Pods](05-module.md)

**Suivant :** [Module 7 - TP Final](07-tp-final.md)

---

## Navigation

| | |
|:---|---:|
| [← Module 5 : Pods & Multi-Conteneurs](05-module.md) | [TP Final : Stack Production Rootless →](07-tp-final.md) |

[Retour au Programme](index.md){ .md-button }
