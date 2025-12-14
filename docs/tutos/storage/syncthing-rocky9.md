---
tags:
  - tutos
  - storage
  - syncthing
  - sync
  - p2p
  - rocky
---

# Syncthing sur Rocky Linux 9

Installation de **Syncthing** - synchronisation de fichiers décentralisée.

| Composant | Version |
|-----------|---------|
| Rocky Linux | 9.x |
| Syncthing | Latest |

**Durée estimée :** 15 minutes

---

## Caractéristiques

| Fonction | Description |
|----------|-------------|
| **P2P** | Pas de serveur central |
| **Chiffré** | TLS de bout en bout |
| **Cross-platform** | Linux, Windows, macOS, Android |
| **Versioning** | Historique des fichiers |
| **Open Source** | Gratuit et auditable |

---

## 1. Installation

### Via repository

```bash
cat > /etc/yum.repos.d/syncthing.repo << 'EOF'
[syncthing]
name=Syncthing
baseurl=https://yum.syncthing.net/rpm/$basearch/
gpgcheck=1
gpgkey=https://yum.syncthing.net/rpm/gpg.key
enabled=1
EOF

dnf install -y syncthing
```

### Via binaire

```bash
cd /tmp
wget https://github.com/syncthing/syncthing/releases/download/v1.27.2/syncthing-linux-amd64-v1.27.2.tar.gz
tar -xzf syncthing-linux-amd64-v1.27.2.tar.gz
mv syncthing-linux-amd64-v1.27.2/syncthing /usr/local/bin/
chmod +x /usr/local/bin/syncthing
```

---

## 2. Créer un utilisateur dédié

```bash
useradd -m -s /bin/bash syncthing
```

---

## 3. Service systemd

```bash
cat > /etc/systemd/system/syncthing@.service << 'EOF'
[Unit]
Description=Syncthing - Open Source Continuous File Synchronization for %i
Documentation=man:syncthing(1)
After=network.target

[Service]
User=%i
ExecStart=/usr/local/bin/syncthing serve --no-browser --no-restart --logflags=0
Restart=on-failure
RestartSec=10
SuccessExitStatus=3 4
RestartForceExitStatus=3 4

# Hardening
ProtectSystem=full
PrivateTmp=true
SystemCallArchitectures=native
MemoryDenyWriteExecute=true
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now syncthing@syncthing
```

---

## 4. Firewall

```bash
firewall-cmd --permanent --add-port=8384/tcp   # Web UI
firewall-cmd --permanent --add-port=22000/tcp  # Sync protocol
firewall-cmd --permanent --add-port=22000/udp  # QUIC
firewall-cmd --permanent --add-port=21027/udp  # Discovery
firewall-cmd --reload
```

---

## 5. Accès distant à l'interface Web

Par défaut, l'interface est accessible uniquement en local.

### Modifier la configuration

```bash
systemctl stop syncthing@syncthing

# Éditer config.xml
vim /home/syncthing/.config/syncthing/config.xml
```

Modifier la ligne :
```xml
<gui enabled="true" tls="false" debugging="false">
    <address>0.0.0.0:8384</address>
```

```bash
systemctl start syncthing@syncthing
```

---

## 6. Accès Web

- URL: `http://IP:8384`
- Définir un mot de passe : Actions → Settings → GUI

---

## 7. Ajouter un dossier à synchroniser

### Via Web UI

1. Add Folder
2. Folder Path: `/home/syncthing/sync`
3. Folder ID: `default`
4. Share with devices: (sélectionner les appareils)
5. Save

### Via CLI

```bash
syncthing cli config folders add --id "mydata" --path "/data/sync" --label "My Data"
```

---

## 8. Connecter des appareils

### Obtenir l'ID de l'appareil

```bash
syncthing cli show system | grep myID
```

Ou via Web UI : Actions → Show ID

### Ajouter un appareil distant

1. Add Remote Device
2. Device ID: (ID de l'appareil distant)
3. Device Name: (nom descriptif)
4. Introducer: Non
5. Auto Accept: selon besoin
6. Save

---

## 9. Versioning

### Types disponibles

| Type | Description |
|------|-------------|
| **Simple** | Garde N versions |
| **Staggered** | Versions par période |
| **Trashcan** | Poubelle |
| **External** | Script personnalisé |

### Configuration

Edit Folder → File Versioning

```yaml
# Staggered (recommandé)
cleanInterval: 3600
maxAge: 2592000  # 30 jours
```

---

## 10. Ignorer des fichiers

Créer `.stignore` dans le dossier synchronisé :

```
# Patterns
*.tmp
*.log
.DS_Store
Thumbs.db

# Dossiers
node_modules
.git
__pycache__

# Regex
(?d).git
```

---

## 11. Configuration avancée

### Priorité de sync

Edit Folder → Advanced → Order

- `random` : Aléatoire
- `alphabetic` : Par nom
- `smallestFirst` : Plus petits d'abord
- `largestFirst` : Plus grands d'abord
- `newestFirst` : Plus récents d'abord
- `oldestFirst` : Plus anciens d'abord

### Limitations bande passante

Actions → Settings → Connections

```
Incoming Rate Limit: 10000 (KiB/s)
Outgoing Rate Limit: 5000 (KiB/s)
```

---

## 12. Syncthing en tant que service système

Pour exécuter sans utilisateur connecté :

```bash
# Service système global
systemctl enable --now syncthing@root

# Ou pour un utilisateur spécifique au démarrage
loginctl enable-linger syncthing
```

---

## 13. Reverse Proxy Nginx

```bash
cat > /etc/nginx/conf.d/syncthing.conf << 'EOF'
server {
    listen 80;
    server_name sync.example.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name sync.example.com;

    ssl_certificate /etc/letsencrypt/live/sync.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/sync.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8384;
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

## 14. Docker

```bash
docker run -d \
  --name syncthing \
  --hostname syncthing-server \
  -p 8384:8384 \
  -p 22000:22000/tcp \
  -p 22000:22000/udp \
  -p 21027:21027/udp \
  -v syncthing_config:/var/syncthing/config \
  -v /data/sync:/var/syncthing/Sync \
  -e PUID=1000 \
  -e PGID=1000 \
  syncthing/syncthing:latest
```

---

## 15. Monitoring

### API REST

```bash
# Status
curl -H "X-API-Key: YOUR_API_KEY" http://localhost:8384/rest/system/status

# Connexions
curl -H "X-API-Key: YOUR_API_KEY" http://localhost:8384/rest/system/connections

# Dossiers
curl -H "X-API-Key: YOUR_API_KEY" http://localhost:8384/rest/config/folders
```

### Prometheus metrics

Activer dans Settings → Usage Reporting

Endpoint : `http://localhost:8384/metrics`

---

## Commandes CLI

```bash
# Status
syncthing cli show system

# Pause un dossier
syncthing cli operations pause --folder mydata

# Resume
syncthing cli operations resume --folder mydata

# Lister les dossiers
syncthing cli config folders list

# Lister les appareils
syncthing cli config devices list

# Logs
journalctl -u syncthing@syncthing -f
```

---

## Dépannage

```bash
# Logs
journalctl -u syncthing@syncthing -f
tail -f /home/syncthing/.config/syncthing/syncthing.log

# Conflits
find /path/to/folder -name "*.sync-conflict-*"

# Reset database
syncthing cli operations shutdown
rm -rf /home/syncthing/.config/syncthing/index-*
systemctl start syncthing@syncthing
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
