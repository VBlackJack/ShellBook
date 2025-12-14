---
tags:
  - tutos
  - monitoring
  - uptime-kuma
  - status-page
  - alerting
  - rocky
---

# Uptime Kuma sur Rocky Linux 9

Installation de **Uptime Kuma** - monitoring de disponibilité avec page de status.

| Composant | Version |
|-----------|---------|
| Rocky Linux | 9.x |
| Uptime Kuma | 1.23+ |
| Node.js | 18+ |

**Durée estimée :** 15 minutes

---

## Fonctionnalités

| Fonction | Description |
|----------|-------------|
| **HTTP(S)** | Monitoring sites web |
| **TCP/UDP** | Ports et services |
| **Ping** | Disponibilité réseau |
| **DNS** | Résolution DNS |
| **Status Page** | Page publique |
| **Notifications** | 90+ intégrations |

---

## Méthode 1 : Docker (recommandé)

### Installation Docker

```bash
dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
dnf install -y docker-ce docker-ce-cli containerd.io
systemctl enable --now docker
```

### Déployer Uptime Kuma

```bash
docker volume create uptime-kuma

docker run -d \
  --name uptime-kuma \
  --restart=always \
  -p 3001:3001 \
  -v uptime-kuma:/app/data \
  louislam/uptime-kuma:latest
```

---

## Méthode 2 : Installation native

### Node.js 18

```bash
dnf module enable nodejs:18 -y
dnf install -y nodejs git
```

### Installer Uptime Kuma

```bash
useradd -r -s /sbin/nologin uptimekuma
mkdir -p /opt/uptime-kuma
cd /opt/uptime-kuma

git clone https://github.com/louislam/uptime-kuma.git .
npm run setup

chown -R uptimekuma:uptimekuma /opt/uptime-kuma
```

### Service systemd

```bash
cat > /etc/systemd/system/uptime-kuma.service << 'EOF'
[Unit]
Description=Uptime Kuma
After=network.target

[Service]
Type=simple
User=uptimekuma
WorkingDirectory=/opt/uptime-kuma
ExecStart=/usr/bin/node server/server.js
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now uptime-kuma
```

---

## 3. Firewall

```bash
firewall-cmd --permanent --add-port=3001/tcp
firewall-cmd --reload
```

---

## 4. Premier accès

1. Ouvrir `http://IP:3001`
2. Créer le compte admin
3. Commencer à ajouter des monitors

---

## 5. Types de monitors

### HTTP(S)

- URL à surveiller
- Code de retour attendu (200)
- Mot-clé dans la réponse
- Certificat SSL

### TCP Port

- Host et port
- Timeout

### Ping

- Hostname ou IP

### DNS

- Hostname à résoudre
- Type d'enregistrement (A, AAAA, MX...)
- Serveur DNS

### Docker Container

```bash
# Monter le socket Docker
docker run -d \
  --name uptime-kuma \
  -p 3001:3001 \
  -v uptime-kuma:/app/data \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  louislam/uptime-kuma:latest
```

---

## 6. Notifications

### Configurer une notification

1. Settings → Notifications → Setup Notification
2. Choisir le type

### Types disponibles

| Service | Configuration |
|---------|---------------|
| **Email** | SMTP settings |
| **Slack** | Webhook URL |
| **Discord** | Webhook URL |
| **Telegram** | Bot token + Chat ID |
| **Teams** | Webhook URL |
| **Pushover** | User key + App token |
| **Webhook** | URL personnalisée |

### Exemple Slack

1. Créer un Slack Webhook
2. Notification Type: Slack
3. Webhook URL: `https://hooks.slack.com/services/XXX/YYY/ZZZ`

### Exemple Telegram

```bash
# Obtenir le bot token de @BotFather
# Obtenir le chat ID via @userinfobot
```

---

## 7. Status Page

### Créer une page de status

1. Status Pages → New Status Page
2. Slug: `status`
3. Title: "Service Status"
4. Ajouter les monitors
5. Publier

Accès: `http://IP:3001/status/slug`

### Personnalisation

- Logo personnalisé
- Couleurs
- Domaine personnalisé (via reverse proxy)

---

## 8. Groupes de monitors

1. Ajouter un monitor
2. Créer/sélectionner un groupe
3. Organiser la hiérarchie

---

## 9. Maintenance

### Planifier une maintenance

1. Maintenance → Schedule Maintenance
2. Titre et description
3. Date/heure début et fin
4. Sélectionner les monitors affectés

---

## 10. Docker Compose

```yaml
# /opt/uptime-kuma/docker-compose.yml
version: '3.8'

services:
  uptime-kuma:
    image: louislam/uptime-kuma:latest
    container_name: uptime-kuma
    restart: always
    ports:
      - "3001:3001"
    volumes:
      - uptime-kuma:/app/data
      - /var/run/docker.sock:/var/run/docker.sock:ro
    environment:
      - TZ=Europe/Paris

volumes:
  uptime-kuma:
```

```bash
docker compose up -d
```

---

## 11. Reverse Proxy Nginx

```bash
cat > /etc/nginx/conf.d/uptime-kuma.conf << 'EOF'
server {
    listen 80;
    server_name status.example.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name status.example.com;

    ssl_certificate /etc/letsencrypt/live/status.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/status.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:3001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
EOF

systemctl reload nginx
```

---

## 12. Backup

### Exporter les données

Settings → Backup → Export

### Backup Docker volume

```bash
docker stop uptime-kuma
docker run --rm \
  -v uptime-kuma:/data \
  -v $(pwd):/backup \
  alpine tar czf /backup/uptime-kuma-backup.tar.gz -C /data .
docker start uptime-kuma
```

---

## 13. API

### Obtenir le token API

Settings → API Keys → Add API Key

### Exemples

```bash
# Liste des monitors
curl -H "Authorization: Bearer TOKEN" http://localhost:3001/api/monitors

# Status d'un monitor
curl -H "Authorization: Bearer TOKEN" http://localhost:3001/api/monitor/1

# Heartbeats
curl -H "Authorization: Bearer TOKEN" http://localhost:3001/api/monitor/1/beats
```

---

## Commandes utiles

```bash
# Docker logs
docker logs -f uptime-kuma

# Restart
docker restart uptime-kuma

# Update
docker pull louislam/uptime-kuma:latest
docker stop uptime-kuma
docker rm uptime-kuma
# Relancer le run

# Native - logs
journalctl -u uptime-kuma -f
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
