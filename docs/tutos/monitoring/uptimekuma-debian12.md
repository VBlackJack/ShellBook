---
tags:
  - tutos
  - monitoring
  - uptime-kuma
  - status-page
  - alerting
  - debian
---

# Uptime Kuma sur Debian 12

Installation de **Uptime Kuma** sur Debian 12 Bookworm.

| Composant | Version |
|-----------|---------|
| Debian | 12 Bookworm |
| Uptime Kuma | 1.23+ |

**Durée estimée :** 10 minutes

---

## Méthode 1 : Docker (recommandé)

```bash
# Docker
apt update
apt install -y ca-certificates curl gnupg
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" > /etc/apt/sources.list.d/docker.list
apt update
apt install -y docker-ce docker-ce-cli containerd.io

# Uptime Kuma
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

```bash
apt install -y nodejs npm git

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

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now uptime-kuma
```

---

## 3. Firewall

```bash
ufw allow 3001/tcp
ufw reload
```

---

## 4. Accès

1. `http://IP:3001`
2. Créer admin
3. Ajouter monitors

---

## 5. Docker Compose

```yaml
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
    environment:
      - TZ=Europe/Paris

volumes:
  uptime-kuma:
```

---

## 6. Notifications

Types supportés :
- Email (SMTP)
- Slack / Discord / Teams
- Telegram
- Pushover
- Webhook

---

## 7. Status Page

1. Status Pages → New
2. Ajouter monitors
3. Publier

---

## Comparatif Rocky vs Debian

| Aspect | Rocky 9 | Debian 12 |
|--------|---------|-----------|
| Node.js | Module 18 | Package nodejs |
| Docker | centos repo | debian repo |
| Firewall | firewalld | ufw |

---

## Commandes

```bash
# Docker
docker logs -f uptime-kuma
docker restart uptime-kuma

# Update
docker pull louislam/uptime-kuma:latest
docker stop uptime-kuma && docker rm uptime-kuma
# Relancer

# Native
journalctl -u uptime-kuma -f
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
