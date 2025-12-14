---
tags:
  - tutos
  - containers
  - traefik
  - reverse-proxy
  - debian
---

# Traefik sur Debian 12

Installation de **Traefik** sur Debian 12 Bookworm.

| Composant | Version |
|-----------|---------|
| Debian | 12 Bookworm |
| Traefik | 3.x |
| Docker | 24+ |

**Durée estimée :** 25 minutes

---

## 1. Docker

```bash
apt update
apt install -y ca-certificates curl gnupg
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" > /etc/apt/sources.list.d/docker.list
apt update
apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
```

---

## 2. Structure

```bash
mkdir -p /opt/traefik/{config,certs}
cd /opt/traefik
```

---

## 3. Configuration

```bash
cat > /opt/traefik/traefik.yml << 'EOF'
api:
  dashboard: true

entryPoints:
  web:
    address: ":80"
    http:
      redirections:
        entryPoint:
          to: websecure
  websecure:
    address: ":443"

providers:
  docker:
    exposedByDefault: false
  file:
    directory: /etc/traefik/config

certificatesResolvers:
  letsencrypt:
    acme:
      email: admin@example.com
      storage: /etc/traefik/certs/acme.json
      httpChallenge:
        entryPoint: web
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
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
      - "8080:8080"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./traefik.yml:/etc/traefik/traefik.yml:ro
      - ./config:/etc/traefik/config:ro
      - ./certs:/etc/traefik/certs
    networks:
      - traefik-net

networks:
  traefik-net:
    external: true
EOF
```

---

## 5. Démarrer

```bash
docker network create traefik-net
touch /opt/traefik/certs/acme.json
chmod 600 /opt/traefik/certs/acme.json
cd /opt/traefik
docker compose up -d
```

---

## 6. Firewall

```bash
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 8080/tcp
ufw reload
```

---

## 7. Exemple application

```yaml
version: '3.8'

services:
  app:
    image: nginx:alpine
    networks:
      - traefik-net
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.app.rule=Host(`app.example.com`)"
      - "traefik.http.routers.app.entrypoints=websecure"
      - "traefik.http.routers.app.tls.certresolver=letsencrypt"

networks:
  traefik-net:
    external: true
```

---

## Comparatif Rocky vs Debian

| Aspect | Rocky 9 | Debian 12 |
|--------|---------|-----------|
| Docker repo | centos | debian |
| Firewall | firewalld | ufw |
| Config | Identique | Identique |

---

## Commandes

```bash
docker logs -f traefik
docker compose restart traefik
curl http://localhost:8080/api/http/routers
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
