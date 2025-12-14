---
tags:
  - tutos
  - storage
  - syncthing
  - sync
  - p2p
  - debian
---

# Syncthing sur Debian 12

Installation de **Syncthing** sur Debian 12 Bookworm.

| Composant | Version |
|-----------|---------|
| Debian | 12 Bookworm |
| Syncthing | Latest |

**Durée estimée :** 10 minutes

---

## 1. Installation

```bash
apt update
apt install -y syncthing
```

Ou via repository officiel :

```bash
curl -L -o /etc/apt/keyrings/syncthing-archive-keyring.gpg https://syncthing.net/release-key.gpg
echo "deb [signed-by=/etc/apt/keyrings/syncthing-archive-keyring.gpg] https://apt.syncthing.net/ syncthing stable" > /etc/apt/sources.list.d/syncthing.list
apt update
apt install -y syncthing
```

---

## 2. Service utilisateur

```bash
useradd -m -s /bin/bash syncthing
systemctl enable --now syncthing@syncthing
```

---

## 3. Firewall

```bash
ufw allow 8384/tcp   # Web UI
ufw allow 22000/tcp  # Sync
ufw allow 22000/udp  # QUIC
ufw allow 21027/udp  # Discovery
ufw reload
```

---

## 4. Accès distant

```bash
systemctl stop syncthing@syncthing

# Modifier config.xml
vim /home/syncthing/.config/syncthing/config.xml
```

```xml
<address>0.0.0.0:8384</address>
```

```bash
systemctl start syncthing@syncthing
```

---

## 5. Accès Web

- URL: `http://IP:8384`
- Définir mot de passe dans Settings → GUI

---

## 6. Ajouter un dossier

1. Add Folder
2. Path: `/home/syncthing/sync`
3. Share with: (appareils connectés)
4. Save

---

## 7. Connecter un appareil

1. Obtenir Device ID : Actions → Show ID
2. Sur l'autre appareil : Add Remote Device
3. Entrer l'ID
4. Accepter la connexion

---

## 8. Ignorer des fichiers

Créer `.stignore` :

```
*.tmp
*.log
node_modules
.git
```

---

## 9. Docker

```bash
docker run -d \
  --name syncthing \
  -p 8384:8384 \
  -p 22000:22000/tcp \
  -p 22000:22000/udp \
  -v syncthing_config:/var/syncthing/config \
  -v /data/sync:/var/syncthing/Sync \
  syncthing/syncthing:latest
```

---

## Comparatif Rocky vs Debian

| Aspect | Rocky 9 | Debian 12 |
|--------|---------|-----------|
| Package | yum repo | apt repo |
| Firewall | firewalld | ufw |
| Service | Identique | Identique |

---

## Commandes

```bash
# Status
systemctl status syncthing@syncthing

# Logs
journalctl -u syncthing@syncthing -f

# CLI
syncthing cli show system
syncthing cli config folders list
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
