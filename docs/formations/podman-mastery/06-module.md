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

```
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

```
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

```
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

## 7. Exercice Pratique

### Objectif

Déployer une stack complète avec Quadlet : nginx + API + PostgreSQL.

### Fichiers à Créer

```bash
# Créer le répertoire
mkdir -p ~/.config/containers/systemd/

# 1. Network
cat > ~/.config/containers/systemd/myapp-network.network << 'EOF'
[Network]
Subnet=10.90.0.0/24
EOF

# 2. Volume PostgreSQL
cat > ~/.config/containers/systemd/postgres-data.volume << 'EOF'
[Volume]
EOF

# 3. PostgreSQL
cat > ~/.config/containers/systemd/postgres.container << 'EOF'
[Unit]
Description=PostgreSQL for MyApp

[Container]
Image=docker.io/library/postgres:15-alpine
Network=myapp-network.network
Volume=postgres-data.volume:/var/lib/postgresql/data:Z
Environment=POSTGRES_USER=myapp
Environment=POSTGRES_PASSWORD=secret123
Environment=POSTGRES_DB=myapp
HealthCmd=pg_isready -U myapp -d myapp
HealthInterval=10s
HealthStartPeriod=30s

[Service]
Restart=always

[Install]
WantedBy=default.target
EOF

# 4. API (httpbin comme exemple)
cat > ~/.config/containers/systemd/api.container << 'EOF'
[Unit]
Description=API Server
After=postgres.service
Requires=postgres.service

[Container]
Image=docker.io/kennethreitz/httpbin:latest
Network=myapp-network.network
Environment=DATABASE_URL=postgres://myapp:secret123@postgres:5432/myapp

[Service]
Restart=always

[Install]
WantedBy=default.target
EOF

# 5. Nginx (frontend)
cat > ~/.config/containers/systemd/nginx.container << 'EOF'
[Unit]
Description=Nginx Frontend
After=api.service

[Container]
Image=docker.io/library/nginx:alpine
Network=myapp-network.network
PublishPort=8080:80
AutoUpdate=registry

[Service]
Restart=always

[Install]
WantedBy=default.target
EOF
```

### Déployer et Tester

```bash
# Recharger systemd
systemctl --user daemon-reload

# Voir les unités générées
systemctl --user list-unit-files | grep -E "(postgres|api|nginx|myapp)"

# Démarrer la stack (dans l'ordre grâce aux dépendances)
systemctl --user start nginx.service

# Vérifier le status
echo "=== Services Status ==="
systemctl --user status postgres.service --no-pager
systemctl --user status api.service --no-pager
systemctl --user status nginx.service --no-pager

# Vérifier les conteneurs
echo "=== Containers ==="
podman ps

# Tester
echo "=== Testing ==="
curl -s http://localhost:8080 | head -20

# Logs
echo "=== Logs ==="
journalctl --user -u postgres.service --since "5 min ago" --no-pager | tail -10

# Activer au boot
systemctl --user enable postgres.service api.service nginx.service

# Test auto-update
podman auto-update --dry-run

# Cleanup
systemctl --user stop nginx.service api.service postgres.service
systemctl --user disable nginx.service api.service postgres.service
rm ~/.config/containers/systemd/{postgres,api,nginx}.container
rm ~/.config/containers/systemd/{myapp-network.network,postgres-data.volume}
systemctl --user daemon-reload
podman volume rm systemd-postgres-data
```

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
