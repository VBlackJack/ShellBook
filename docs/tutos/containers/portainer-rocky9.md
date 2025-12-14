---
tags:
  - tutos
  - containers
  - portainer
  - docker
  - management
  - rocky
---

# Portainer sur Rocky Linux 9

Installation de **Portainer** - interface de gestion Docker/Kubernetes.

| Composant | Version |
|-----------|---------|
| Rocky Linux | 9.x |
| Portainer CE | 2.19+ |
| Docker | 24+ |

**Durée estimée :** 15 minutes

---

## Fonctionnalités

| Fonction | Description |
|----------|-------------|
| **Containers** | Gestion graphique |
| **Stacks** | Docker Compose |
| **Images** | Pull, build, manage |
| **Networks** | Configuration réseau |
| **Volumes** | Gestion stockage |
| **Users** | RBAC intégré |

---

## 1. Prérequis Docker

```bash
dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
dnf install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
systemctl enable --now docker
```

---

## 2. Installation Portainer

### Volume pour persistance

```bash
docker volume create portainer_data
```

### Déployer Portainer CE

```bash
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
firewall-cmd --permanent --add-port=9443/tcp
firewall-cmd --permanent --add-port=8000/tcp  # Edge agents
firewall-cmd --reload
```

---

## 4. Premier accès

1. Ouvrir `https://IP:9443`
2. Créer l'utilisateur admin
3. Sélectionner "Get Started" pour le local Docker

---

## 5. Docker Compose alternative

```bash
mkdir -p /opt/portainer
cd /opt/portainer

cat > docker-compose.yml << 'EOF'
version: '3.8'

services:
  portainer:
    image: portainer/portainer-ce:latest
    container_name: portainer
    restart: always
    security_opt:
      - no-new-privileges:true
    ports:
      - "8000:8000"
      - "9443:9443"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - portainer_data:/data

volumes:
  portainer_data:
EOF

docker compose up -d
```

---

## 6. Ajouter des environnements

### Agent Portainer (sur autre host)

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

Dans Portainer :
1. Environments → Add environment
2. Docker Standalone → Agent
3. URL: `IP:9001`

### Edge Agent (sans port exposé)

```bash
# Obtenir la commande depuis Portainer UI
# Environments → Add environment → Docker Standalone → Edge Agent
```

---

## 7. Stacks (Docker Compose)

### Créer une stack

1. Stacks → Add stack
2. Name: `nginx-demo`
3. Web editor:

```yaml
version: '3.8'

services:
  web:
    image: nginx:alpine
    ports:
      - "8080:80"
    volumes:
      - web_data:/usr/share/nginx/html

volumes:
  web_data:
```

4. Deploy the stack

---

## 8. Templates

### App Templates

1. Settings → App Templates
2. URL: `https://raw.githubusercontent.com/portainer/templates/master/templates-2.0.json`

### Custom Templates

1. Custom Templates → Add Custom Template
2. Définir le docker-compose.yml
3. Variables d'environnement si nécessaires

---

## 9. Registries privés

### Ajouter un registry

1. Registries → Add registry
2. Custom registry
3. URL: `registry.example.com`
4. Credentials si nécessaires

### GitLab Registry

1. Registries → Add registry
2. GitLab
3. URL: `registry.gitlab.com`
4. Username: token name
5. Password: access token

---

## 10. RBAC et Users

### Créer un utilisateur

1. Users → Add user
2. Username/Password
3. Administrator ou User

### Teams et accès

1. Teams → Add team
2. Ajouter des membres
3. Environments → Manage access
4. Attribuer accès aux teams

---

## 11. Backup

### Backup des données

```bash
# Arrêter Portainer
docker stop portainer

# Backup volume
docker run --rm \
  -v portainer_data:/data \
  -v $(pwd):/backup \
  alpine tar czf /backup/portainer-backup.tar.gz -C /data .

# Redémarrer
docker start portainer
```

### Restore

```bash
docker stop portainer
docker run --rm \
  -v portainer_data:/data \
  -v $(pwd):/backup \
  alpine sh -c "rm -rf /data/* && tar xzf /backup/portainer-backup.tar.gz -C /data"
docker start portainer
```

---

## 12. SSL avec certificat personnalisé

```bash
docker run -d \
  -p 9443:9443 \
  --name portainer \
  --restart=always \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v portainer_data:/data \
  -v /path/to/certs:/certs \
  portainer/portainer-ce:latest \
  --sslcert /certs/cert.pem \
  --sslkey /certs/key.pem
```

---

## 13. Reverse Proxy Nginx

```bash
cat > /etc/nginx/conf.d/portainer.conf << 'EOF'
server {
    listen 80;
    server_name portainer.example.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name portainer.example.com;

    ssl_certificate /etc/letsencrypt/live/portainer.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/portainer.example.com/privkey.pem;

    location / {
        proxy_pass https://127.0.0.1:9443;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WebSocket
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
EOF

systemctl reload nginx
```

---

## 14. Portainer avec Kubernetes

### Helm

```bash
helm repo add portainer https://portainer.github.io/k8s/
helm repo update

helm install portainer portainer/portainer \
  --namespace portainer --create-namespace \
  --set service.type=LoadBalancer
```

### Manifest direct

```bash
kubectl apply -n portainer -f https://downloads.portainer.io/ce2-19/portainer.yaml
```

---

## Commandes utiles

```bash
# Logs
docker logs -f portainer

# Redémarrer
docker restart portainer

# Mettre à jour
docker stop portainer
docker rm portainer
docker pull portainer/portainer-ce:latest
# Relancer avec la même commande run

# Version
docker exec portainer /portainer --version
```

---

## Dépannage

```bash
# Reset admin password
docker exec -it portainer /portainer --admin-password-file /tmp/reset

# Vérifier socket Docker
ls -la /var/run/docker.sock

# Permissions
chmod 666 /var/run/docker.sock
# Ou ajouter l'utilisateur au groupe docker
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
