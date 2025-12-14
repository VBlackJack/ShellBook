---
tags:
  - tutos
  - network
  - pihole
  - dns
  - adblock
  - debian
---

# Pi-hole sur Debian 12

Installation de **Pi-hole** sur Debian 12 Bookworm.

| Composant | Version |
|-----------|---------|
| Debian | 12 Bookworm |
| Pi-hole | 5.x |

**Durée estimée :** 15 minutes

---

## 1. Prérequis

### Désactiver systemd-resolved

```bash
systemctl stop systemd-resolved
systemctl disable systemd-resolved
rm /etc/resolv.conf
echo "nameserver 8.8.8.8" > /etc/resolv.conf
```

### IP statique

```bash
cat > /etc/network/interfaces.d/eth0 << 'EOF'
auto eth0
iface eth0 inet static
    address 192.168.1.10
    netmask 255.255.255.0
    gateway 192.168.1.1
EOF

systemctl restart networking
```

---

## 2. Installation

```bash
curl -sSL https://install.pi-hole.net | bash
```

Suivre l'assistant d'installation.

---

## 3. Mot de passe admin

```bash
pihole -a -p
```

---

## 4. Firewall

```bash
ufw allow 53/tcp
ufw allow 53/udp
ufw allow 80/tcp
ufw reload
```

---

## 5. Accès

- URL: `http://IP/admin`
- Password: défini à l'étape 3

---

## 6. Listes de blocage

### Ajouter via web

Group Management → Adlists

```
https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt
```

### Mettre à jour

```bash
pihole -g
```

---

## 7. DNS over HTTPS

```bash
# Installer cloudflared
wget https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb
dpkg -i cloudflared-linux-amd64.deb

useradd -r -s /sbin/nologin cloudflared

mkdir -p /etc/cloudflared
cat > /etc/cloudflared/config.yml << 'EOF'
proxy-dns: true
proxy-dns-port: 5053
proxy-dns-upstream:
  - https://1.1.1.1/dns-query
  - https://1.0.0.1/dns-query
EOF

# Service
cat > /etc/systemd/system/cloudflared.service << 'EOF'
[Unit]
Description=cloudflared DNS over HTTPS proxy
After=network.target

[Service]
User=cloudflared
ExecStart=/usr/bin/cloudflared --config /etc/cloudflared/config.yml
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now cloudflared
```

Configurer Pi-hole → Settings → DNS → `127.0.0.1#5053`

---

## 8. Docker alternative

```bash
docker run -d \
  --name pihole \
  --restart=unless-stopped \
  -p 53:53/tcp -p 53:53/udp \
  -p 80:80 \
  -e TZ='Europe/Paris' \
  -e WEBPASSWORD='secure_password' \
  -v pihole_data:/etc/pihole \
  -v dnsmasq_data:/etc/dnsmasq.d \
  pihole/pihole:latest
```

---

## 9. Whitelist / Blacklist

```bash
# Whitelist
pihole -w example.com

# Blacklist
pihole -b ads.example.com

# Supprimer
pihole -w -d example.com
```

---

## Comparatif Rocky vs Debian

| Aspect | Rocky 9 | Debian 12 |
|--------|---------|-----------|
| resolved | systemd-resolved | systemd-resolved |
| Firewall | firewalld | ufw |
| cloudflared | .rpm | .deb |

---

## Commandes

```bash
# Status
pihole status

# Activer/Désactiver
pihole enable
pihole disable 5m

# Mettre à jour
pihole -up

# Logs
pihole -t

# Gravity
pihole -g
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
