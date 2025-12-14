---
tags:
  - tutos
  - containers
  - traefik
  - reverse-proxy
  - rocky
---

# Traefik sur Rocky Linux 9

Installation de **Traefik** comme reverse proxy et load balancer.

| Composant | Version |
|-----------|---------|
| Rocky Linux | 9.x |
| Traefik | 3.x |
| Docker | 24+ |

**Durée estimée :** 30 minutes

---

## Avantages Traefik

| Caractéristique | Description |
|-----------------|-------------|
| **Auto-discovery** | Détection automatique des conteneurs |
| **Let's Encrypt** | Certificats automatiques |
| **Dashboard** | Interface de monitoring |
| **Middlewares** | Auth, rate-limit, headers... |

---

## 1. Installation Docker

```bash
dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
dnf install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
systemctl enable --now docker
```

---

## 2. Structure projet

```bash
mkdir -p /opt/traefik/{config,certs}
cd /opt/traefik
```

---

## 3. Configuration statique

```bash
cat > /opt/traefik/traefik.yml << 'EOF'
# API et Dashboard
api:
  dashboard: true
  insecure: true  # Désactiver en prod

# Entrypoints
entryPoints:
  web:
    address: ":80"
    http:
      redirections:
        entryPoint:
          to: websecure
          scheme: https
  websecure:
    address: ":443"

# Providers
providers:
  docker:
    endpoint: "unix:///var/run/docker.sock"
    exposedByDefault: false
  file:
    directory: /etc/traefik/config
    watch: true

# Certificats Let's Encrypt
certificatesResolvers:
  letsencrypt:
    acme:
      email: admin@example.com
      storage: /etc/traefik/certs/acme.json
      httpChallenge:
        entryPoint: web

# Logging
log:
  level: INFO

accessLog:
  filePath: /var/log/traefik/access.log
EOF
```

---

## 4. Docker Compose

```bash
cat > /opt/traefik/docker-compose.yml << 'EOF'
version: '3.8'

services:
  traefik:
    image: traefik:v3.0
    container_name: traefik
    restart: unless-stopped
    security_opt:
      - no-new-privileges:true
    ports:
      - "80:80"
      - "443:443"
      - "8080:8080"  # Dashboard
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./traefik.yml:/etc/traefik/traefik.yml:ro
      - ./config:/etc/traefik/config:ro
      - ./certs:/etc/traefik/certs
      - /var/log/traefik:/var/log/traefik
    networks:
      - traefik-net
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.dashboard.rule=Host(`traefik.example.com`)"
      - "traefik.http.routers.dashboard.service=api@internal"
      - "traefik.http.routers.dashboard.entrypoints=websecure"
      - "traefik.http.routers.dashboard.tls.certresolver=letsencrypt"

networks:
  traefik-net:
    external: true
EOF
```

---

## 5. Créer le réseau

```bash
docker network create traefik-net
```

---

## 6. Initialiser acme.json

```bash
touch /opt/traefik/certs/acme.json
chmod 600 /opt/traefik/certs/acme.json
mkdir -p /var/log/traefik
```

---

## 7. Démarrer Traefik

```bash
cd /opt/traefik
docker compose up -d
```

---

## 8. Firewall

```bash
firewall-cmd --permanent --add-service=http
firewall-cmd --permanent --add-service=https
firewall-cmd --permanent --add-port=8080/tcp
firewall-cmd --reload
```

---

## 9. Exemple : Application avec labels

```yaml
# /opt/myapp/docker-compose.yml
version: '3.8'

services:
  webapp:
    image: nginx:alpine
    container_name: webapp
    restart: unless-stopped
    networks:
      - traefik-net
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.webapp.rule=Host(`app.example.com`)"
      - "traefik.http.routers.webapp.entrypoints=websecure"
      - "traefik.http.routers.webapp.tls.certresolver=letsencrypt"
      - "traefik.http.services.webapp.loadbalancer.server.port=80"

networks:
  traefik-net:
    external: true
```

---

## 10. Middlewares

### Basic Auth

```yaml
labels:
  - "traefik.http.middlewares.auth.basicauth.users=admin:$$apr1$$..."
  - "traefik.http.routers.webapp.middlewares=auth"
```

Générer le hash :
```bash
htpasswd -nb admin password
```

### Rate Limiting

```yaml
labels:
  - "traefik.http.middlewares.ratelimit.ratelimit.average=100"
  - "traefik.http.middlewares.ratelimit.ratelimit.burst=50"
  - "traefik.http.routers.webapp.middlewares=ratelimit"
```

### Headers sécurité

```yaml
labels:
  - "traefik.http.middlewares.secure-headers.headers.stsSeconds=31536000"
  - "traefik.http.middlewares.secure-headers.headers.stsIncludeSubdomains=true"
  - "traefik.http.middlewares.secure-headers.headers.contentTypeNosniff=true"
  - "traefik.http.routers.webapp.middlewares=secure-headers"
```

---

## 11. Configuration fichier (services externes)

```bash
cat > /opt/traefik/config/services.yml << 'EOF'
http:
  routers:
    external-service:
      rule: "Host(`external.example.com`)"
      service: external-svc
      entryPoints:
        - websecure
      tls:
        certResolver: letsencrypt

  services:
    external-svc:
      loadBalancer:
        servers:
          - url: "http://192.168.1.50:8080"
          - url: "http://192.168.1.51:8080"
        healthCheck:
          path: /health
          interval: 10s
EOF
```

---

## 12. TCP/UDP (non-HTTP)

```yaml
# traefik.yml
entryPoints:
  mysql:
    address: ":3306"

tcp:
  routers:
    mysql-router:
      rule: "HostSNI(`*`)"
      service: mysql-svc
      entryPoints:
        - mysql

  services:
    mysql-svc:
      loadBalancer:
        servers:
          - address: "192.168.1.60:3306"
```

---

## 13. Dashboard sécurisé

```yaml
# Middleware auth pour dashboard
- "traefik.http.middlewares.dashboard-auth.basicauth.users=admin:$$apr1$$..."
- "traefik.http.routers.dashboard.middlewares=dashboard-auth"
```

---

## Commandes utiles

```bash
# Logs
docker logs -f traefik

# Recharger config
docker compose restart traefik

# Vérifier certificats
cat /opt/traefik/certs/acme.json | jq

# API
curl http://localhost:8080/api/rawdata
```

---

## Dépannage

```bash
# Logs détaillés
# Dans traefik.yml: log.level: DEBUG

# Vérifier les routers
curl http://localhost:8080/api/http/routers

# Vérifier les services
curl http://localhost:8080/api/http/services
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
