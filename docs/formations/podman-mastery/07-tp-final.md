---
tags:
  - formation
  - podman
  - tp
  - production
---

# TP Final : Stack Production Rootless

## Objectifs

- Déployer une application 3-tiers complète
- Appliquer toutes les bonnes pratiques
- Utiliser Quadlet pour la gestion systemd
- Implémenter l'auto-update et le monitoring

**Durée :** 2 heures

---

## Scénario

Vous devez déployer une application web de production comprenant :

- **Frontend** : Nginx servant une SPA
- **API** : Application Python Flask
- **Base de données** : PostgreSQL
- **Cache** : Redis

Le tout doit être :
- Rootless (sécurité)
- Géré par systemd (Quadlet)
- Auto-update activé
- Logs centralisés (journald)

---

## Architecture

```text
ARCHITECTURE DE LA STACK
═════════════════════════════════════════════════════════

                    ┌─────────────────────────────────────┐
                    │         Host (RHEL 9)               │
                    │                                     │
     Port 8080 ────►│  ┌─────────┐                       │
                    │  │  Nginx  │ (frontend)            │
                    │  │  :80    │                       │
                    │  └────┬────┘                       │
                    │       │                            │
                    │       ▼                            │
                    │  ┌─────────┐    ┌─────────┐       │
                    │  │   API   │───►│  Redis  │       │
                    │  │  :5000  │    │  :6379  │       │
                    │  └────┬────┘    └─────────┘       │
                    │       │                            │
                    │       ▼                            │
                    │  ┌─────────┐                       │
                    │  │Postgres │                       │
                    │  │  :5432  │                       │
                    │  └─────────┘                       │
                    │                                     │
                    │  Network: prod-network (10.91.0.0) │
                    └─────────────────────────────────────┘

Flux :
1. User → Nginx (8080) → Static files
2. Nginx → API (5000) → Business logic
3. API → Redis (6379) → Cache
4. API → Postgres (5432) → Data
```

---

## Étape 1 : Préparation

```bash
# Créer la structure
mkdir -p ~/production-stack/{app,nginx,data}
cd ~/production-stack

# Vérifier les prérequis
echo "=== Checking prerequisites ==="
podman --version
buildah --version
systemctl --user status

# Activer linger
sudo loginctl enable-linger $USER
```

---

## Étape 2 : Application Flask

### Code de l'API

```python
# app/app.py
import os
import redis
import psycopg2
from flask import Flask, jsonify
from datetime import datetime

app = Flask(__name__)

# Configuration
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379')
DATABASE_URL = os.getenv('DATABASE_URL', 'postgresql://app:secret@localhost:5432/app')

def get_redis():
    return redis.from_url(REDIS_URL)

def get_db():
    return psycopg2.connect(DATABASE_URL)

@app.route('/health')
def health():
    status = {'api': 'ok', 'timestamp': datetime.now().isoformat()}

    # Check Redis
    try:
        r = get_redis()
        r.ping()
        status['redis'] = 'ok'
    except Exception as e:
        status['redis'] = f'error: {str(e)}'

    # Check PostgreSQL
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute('SELECT 1')
        conn.close()
        status['postgres'] = 'ok'
    except Exception as e:
        status['postgres'] = f'error: {str(e)}'

    return jsonify(status)

@app.route('/api/visits')
def visits():
    r = get_redis()
    count = r.incr('visits')
    return jsonify({'visits': count})

@app.route('/')
def index():
    return jsonify({'message': 'API Production Stack', 'version': '1.0'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
```

```text
# app/requirements.txt
flask==3.0.0
gunicorn==21.2.0
redis==5.0.1
psycopg2-binary==2.9.9
```

### Containerfile API

```dockerfile
# app/Containerfile
FROM registry.access.redhat.com/ubi9/python-311 AS builder
WORKDIR /app
COPY requirements.txt .
RUN pip install --user -r requirements.txt

FROM registry.access.redhat.com/ubi9/python-311-minimal
WORKDIR /app
COPY --from=builder /opt/app-root/src/.local /opt/app-root/src/.local
COPY app.py .

USER 1001
EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=3s \
  CMD curl -f http://localhost:5000/health || exit 1

CMD ["gunicorn", "-b", "0.0.0.0:5000", "-w", "2", "app:app"]
```

### Construire l'Image

```bash
cd ~/production-stack/app
buildah build -t localhost/prod-api:v1 -f Containerfile .
```

---

## Étape 3 : Configuration Nginx

```nginx
# nginx/nginx.conf
worker_processes auto;
error_log /dev/stderr;
pid /tmp/nginx.pid;

events {
    worker_connections 1024;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    access_log /dev/stdout;

    # Temp paths pour rootless
    client_body_temp_path /tmp/client_body;
    proxy_temp_path /tmp/proxy;
    fastcgi_temp_path /tmp/fastcgi;
    uwsgi_temp_path /tmp/uwsgi;
    scgi_temp_path /tmp/scgi;

    server {
        listen 8080;
        server_name _;

        # Frontend static
        location / {
            root /usr/share/nginx/html;
            index index.html;
            try_files $uri $uri/ /index.html;
        }

        # API proxy
        location /api/ {
            proxy_pass http://api:5000/;
            proxy_http_version 1.1;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }

        # Health endpoint
        location /health {
            proxy_pass http://api:5000/health;
        }
    }
}
```

```html
<!-- nginx/html/index.html -->
<!DOCTYPE html>
<html>
<head>
    <title>Production Stack</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #1a1a2e; color: #eee; }
        .container { max-width: 600px; margin: 0 auto; }
        h1 { color: #00d9ff; }
        .status { padding: 20px; background: #16213e; border-radius: 8px; margin: 20px 0; }
        .ok { color: #00ff88; }
        .error { color: #ff4444; }
        button { padding: 10px 20px; background: #00d9ff; border: none; border-radius: 4px; cursor: pointer; }
        #visits { font-size: 2em; color: #00d9ff; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚀 Production Stack</h1>
        <div class="status" id="health">Loading health status...</div>
        <div class="status">
            <h3>Visit Counter</h3>
            <p>Total visits: <span id="visits">-</span></p>
            <button onclick="incrementVisits()">Count Visit</button>
        </div>
    </div>
    <script>
        async function checkHealth() {
            try {
                const res = await fetch('/health');
                const data = await res.json();
                let html = '<h3>Health Status</h3>';
                for (const [key, value] of Object.entries(data)) {
                    const cls = value === 'ok' ? 'ok' : (typeof value === 'string' && value.includes('error') ? 'error' : '');
                    html += `<p>${key}: <span class="${cls}">${value}</span></p>`;
                }
                document.getElementById('health').innerHTML = html;
            } catch (e) {
                document.getElementById('health').innerHTML = '<p class="error">Failed to fetch health</p>';
            }
        }

        async function incrementVisits() {
            try {
                const res = await fetch('/api/visits');
                const data = await res.json();
                document.getElementById('visits').textContent = data.visits;
            } catch (e) {
                console.error(e);
            }
        }

        checkHealth();
        setInterval(checkHealth, 10000);
    </script>
</body>
</html>
```

---

## Étape 4 : Fichiers Quadlet

```bash
# Créer le répertoire Quadlet
mkdir -p ~/.config/containers/systemd/
cd ~/.config/containers/systemd/
```

### Network

```ini
# prod-network.network
[Network]
Subnet=10.91.0.0/24
Gateway=10.91.0.1
Label=app=production
```

### Volumes

```ini
# postgres-data.volume
[Volume]
Label=app=production
Label=component=database
```

```ini
# redis-data.volume
[Volume]
Label=app=production
Label=component=cache
```

### PostgreSQL

```ini
# postgres.container
[Unit]
Description=PostgreSQL Database (Production)

[Container]
Image=docker.io/library/postgres:15-alpine
ContainerName=postgres
Network=prod-network.network
Volume=postgres-data.volume:/var/lib/postgresql/data:Z

Environment=POSTGRES_USER=app
Environment=POSTGRES_PASSWORD=SecureP@ss2024!
Environment=POSTGRES_DB=app

HealthCmd=pg_isready -U app -d app
HealthInterval=10s
HealthTimeout=5s
HealthStartPeriod=30s
HealthRetries=3

Label=app=production
Label=component=database

[Service]
Restart=always
TimeoutStartSec=60

[Install]
WantedBy=default.target
```

### Redis

```ini
# redis.container
[Unit]
Description=Redis Cache (Production)

[Container]
Image=docker.io/library/redis:7-alpine
ContainerName=redis
Network=prod-network.network
Volume=redis-data.volume:/data:Z

Exec=redis-server --appendonly yes

HealthCmd=redis-cli ping
HealthInterval=10s
HealthTimeout=3s

Label=app=production
Label=component=cache

[Service]
Restart=always

[Install]
WantedBy=default.target
```

### API

```ini
# api.container
[Unit]
Description=Flask API (Production)
After=postgres.service redis.service
Requires=postgres.service redis.service

[Container]
Image=localhost/prod-api:v1
ContainerName=api
Network=prod-network.network

Environment=DATABASE_URL=postgresql://app:SecureP@ss2024!@postgres:5432/app
Environment=REDIS_URL=redis://redis:6379

HealthCmd=curl -f http://localhost:5000/health || exit 1
HealthInterval=30s
HealthTimeout=5s
HealthStartPeriod=10s

# Sécurité
ReadOnly=true
NoNewPrivileges=true

Label=app=production
Label=component=api

[Service]
Restart=always

[Install]
WantedBy=default.target
```

### Nginx

```ini
# nginx.container
[Unit]
Description=Nginx Frontend (Production)
After=api.service

[Container]
Image=docker.io/library/nginx:alpine
ContainerName=nginx
Network=prod-network.network
PublishPort=8080:8080

Volume=%h/production-stack/nginx/nginx.conf:/etc/nginx/nginx.conf:ro,Z
Volume=%h/production-stack/nginx/html:/usr/share/nginx/html:ro,Z

HealthCmd=curl -f http://localhost:8080/ || exit 1
HealthInterval=30s

# Sécurité
ReadOnly=true
NoNewPrivileges=true

# Auto-update
AutoUpdate=registry

Label=app=production
Label=component=frontend

[Service]
Restart=always

[Install]
WantedBy=default.target
```

---

## Étape 5 : Déploiement

```bash
# Recharger systemd
systemctl --user daemon-reload

# Voir les unités générées
systemctl --user list-unit-files | grep -E "(postgres|redis|api|nginx|prod)"

# Démarrer la stack (nginx démarre tout grâce aux dépendances)
systemctl --user start nginx.service

# Vérifier le status
echo "=== Stack Status ==="
systemctl --user status postgres.service redis.service api.service nginx.service --no-pager

# Voir les conteneurs
echo "=== Containers ==="
podman ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

# Tester
echo "=== Testing ==="
sleep 5  # Attendre que tout soit prêt
curl -s http://localhost:8080/health | jq .
curl -s http://localhost:8080/api/visits | jq .
```

---

## Étape 6 : Monitoring et Logs

```bash
# Logs temps réel de toute la stack
journalctl --user -u postgres.service -u redis.service -u api.service -u nginx.service -f

# Logs d'un service spécifique
journalctl --user -u api.service --since "10 min ago"

# Stats des conteneurs
podman stats --no-stream

# Inspecter le réseau
podman network inspect systemd-prod-network

# Vérifier les volumes
podman volume ls --filter label=app=production
```

---

## Étape 7 : Activer au Boot

```bash
# Activer tous les services
systemctl --user enable postgres.service redis.service api.service nginx.service

# Vérifier le linger
loginctl show-user $USER | grep Linger
# Doit afficher: Linger=yes

# Reboot test
sudo reboot

# Après reboot, vérifier
systemctl --user status nginx.service
curl http://localhost:8080/health
```

---

## Étape 8 : Auto-Update

```bash
# Activer le timer d'auto-update
systemctl --user enable --now podman-auto-update.timer

# Vérifier les conteneurs éligibles
podman auto-update --dry-run

# Voir le planning
systemctl --user list-timers podman-auto-update.timer
```

---

## Checklist de Validation

```text
VALIDATION PRODUCTION
═════════════════════

Infrastructure :
  [ ] Tous les conteneurs running
  [ ] Réseau prod-network créé
  [ ] Volumes persistants créés
  [ ] Healthchecks passent

Sécurité :
  [ ] Mode rootless actif
  [ ] ReadOnly sur nginx et api
  [ ] NoNewPrivileges activé
  [ ] Pas de ports < 1024

Systemd :
  [ ] Services enabled au boot
  [ ] Linger activé
  [ ] Auto-update configuré
  [ ] Restart=always

Monitoring :
  [ ] Logs dans journald
  [ ] Health endpoint fonctionnel
  [ ] Stats accessibles
```

---

## Solution de Troubleshooting

```bash
# Si un service ne démarre pas
systemctl --user status <service> --no-pager -l
journalctl --user -u <service> --no-pager -n 50

# Reset complet
systemctl --user stop nginx.service api.service redis.service postgres.service
podman rm -f nginx api redis postgres
podman volume rm systemd-postgres-data systemd-redis-data
systemctl --user daemon-reload
systemctl --user start nginx.service

# Vérifier les permissions SELinux
ls -laZ ~/production-stack/nginx/
# Si problème : restorecon -Rv ~/production-stack/

# Tester manuellement un conteneur
podman run --rm -it --network systemd-prod-network localhost/prod-api:v1 sh
```

---

## Cleanup

```bash
# Arrêter et désactiver
systemctl --user stop nginx.service api.service redis.service postgres.service
systemctl --user disable nginx.service api.service redis.service postgres.service

# Supprimer les fichiers Quadlet
rm ~/.config/containers/systemd/{nginx,api,redis,postgres}.container
rm ~/.config/containers/systemd/{postgres-data,redis-data}.volume
rm ~/.config/containers/systemd/prod-network.network

# Recharger
systemctl --user daemon-reload

# Supprimer les volumes
podman volume rm systemd-postgres-data systemd-redis-data

# Supprimer l'image API
podman rmi localhost/prod-api:v1

# Nettoyer
rm -rf ~/production-stack
```

---

**Précédent :** [Module 6 - Intégration Systemd](06-module.md)

**Retour au programme :** [Index](index.md)

---

## Navigation

| | |
|:---|---:|
| [← Module 6 : Intégration Systemd](06-module.md) | [Programme →](index.md) |

[Retour au Programme](index.md){ .md-button }
