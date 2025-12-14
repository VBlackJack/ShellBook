---
tags:
  - tutos
  - containers
  - portainer
  - docker
  - management
  - debian
---

# Portainer sur Debian 12

Installation de **Portainer** sur Debian 12 Bookworm.

| Composant | Version |
|-----------|---------|
| Debian | 12 Bookworm |
| Portainer CE | 2.19+ |
| Docker | 24+ |

**Durée estimée :** 10 minutes

---

## 1. Prérequis Docker

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

## 2. Installation

```bash
docker volume create portainer_data

docker run -d \
  -p 8000:8000 \
  -p 9443:9443 \
  --name portainer \
  --restart=always \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v portainer_data:/data \
  portainer/portainer-ce:latest
```

---

## 3. Firewall

```bash
ufw allow 9443/tcp
ufw allow 8000/tcp
ufw reload
```

---

## 4. Accès

1. Ouvrir `https://IP:9443`
2. Créer admin
3. Get Started

---

## 5. Docker Compose

```yaml
# /opt/portainer/docker-compose.yml
version: '3.8'

services:
  portainer:
    image: portainer/portainer-ce:latest
    container_name: portainer
    restart: always
    ports:
      - "8000:8000"
      - "9443:9443"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - portainer_data:/data

volumes:
  portainer_data:
```

```bash
docker compose up -d
```

---

## 6. Agent distant

Sur le serveur distant :

```bash
docker run -d \
  -p 9001:9001 \
  --name portainer_agent \
  --restart=always \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v /var/lib/docker/volumes:/var/lib/docker/volumes \
  portainer/agent:latest
```

---

## 7. Stacks

Créer une stack via l'interface :

```yaml
version: '3.8'

services:
  app:
    image: nginx:alpine
    ports:
      - "8080:80"
```

---

## 8. Backup

```bash
docker stop portainer
docker run --rm \
  -v portainer_data:/data \
  -v $(pwd):/backup \
  alpine tar czf /backup/portainer-backup.tar.gz -C /data .
docker start portainer
```

---

## Comparatif Rocky vs Debian

| Aspect | Rocky 9 | Debian 12 |
|--------|---------|-----------|
| Docker repo | centos | debian |
| Firewall | firewalld | ufw |
| Installation | Identique | Identique |

---

## Commandes

```bash
# Logs
docker logs -f portainer

# Mettre à jour
docker stop portainer && docker rm portainer
docker pull portainer/portainer-ce:latest
# Relancer le run

# Status
docker ps | grep portainer
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
