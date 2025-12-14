---
tags:
  - tutos
  - network
  - pihole
  - dns
  - adblock
  - rocky
---

# Pi-hole sur Rocky Linux 9

Installation de **Pi-hole** - DNS sinkhole pour bloquer publicités et trackers.

| Composant | Version |
|-----------|---------|
| Rocky Linux | 9.x |
| Pi-hole | 5.x |

**Durée estimée :** 20 minutes

---

## Fonctionnalités

| Fonction | Description |
|----------|-------------|
| **DNS** | Serveur DNS local |
| **Adblock** | Blocage publicités |
| **Privacy** | Blocage trackers |
| **Dashboard** | Interface web |
| **DHCP** | Serveur DHCP optionnel |

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
# Vérifier l'IP statique
nmcli con show
nmcli con mod "System eth0" ipv4.addresses "192.168.1.10/24"
nmcli con mod "System eth0" ipv4.gateway "192.168.1.1"
nmcli con mod "System eth0" ipv4.method manual
nmcli con up "System eth0"
```

---

## 2. Installation Pi-hole

### Script automatisé

```bash
curl -sSL https://install.pi-hole.net | bash
```

Ou en mode non-interactif :

```bash
cat > /tmp/pihole-setup.conf << 'EOF'
PIHOLE_INTERFACE=eth0
PIHOLE_DNS_1=8.8.8.8
PIHOLE_DNS_2=8.8.4.4
QUERY_LOGGING=true
INSTALL_WEB_SERVER=true
INSTALL_WEB_INTERFACE=true
LIGHTTPD_ENABLED=true
CACHE_SIZE=10000
DNS_FQDN_REQUIRED=true
DNS_BOGUS_PRIV=true
WEBPASSWORD=
EOF

curl -sSL https://install.pi-hole.net | bash /dev/stdin --unattended
```

---

## 3. Définir le mot de passe admin

```bash
pihole -a -p
```

---

## 4. Firewall

```bash
firewall-cmd --permanent --add-service=dns
firewall-cmd --permanent --add-port=80/tcp    # Web interface
firewall-cmd --permanent --add-port=53/udp    # DNS
firewall-cmd --permanent --add-port=53/tcp    # DNS
firewall-cmd --reload
```

---

## 5. Accès

- Interface : `http://IP/admin`
- Login : mot de passe défini à l'étape 3

---

## 6. Configurer les clients

### DHCP - Modifier le DNS

Sur votre routeur/DHCP, définir le DNS vers l'IP Pi-hole.

### Client individuel

```bash
# Linux - /etc/resolv.conf
nameserver 192.168.1.10

# Windows
# Propriétés adaptateur → IPv4 → DNS: 192.168.1.10
```

---

## 7. Listes de blocage

### Ajouter des adlists

1. Group Management → Adlists
2. Ajouter l'URL de la liste
3. Tools → Update Gravity

Listes recommandées :

```
https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt
https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt
```

### Mettre à jour Gravity

```bash
pihole -g
```

---

## 8. Whitelist / Blacklist

### Via CLI

```bash
# Whitelist
pihole -w example.com
pihole -w sub.example.com

# Blacklist
pihole -b ads.example.com

# Retirer
pihole -w -d example.com
pihole -b -d ads.example.com
```

### Via Web

- Domains → Whitelist / Blacklist

---

## 9. DNS over HTTPS (DoH)

### Installer cloudflared

```bash
wget https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.rpm
rpm -i cloudflared-linux-amd64.rpm

useradd -r -s /sbin/nologin cloudflared

cat > /etc/cloudflared/config.yml << 'EOF'
proxy-dns: true
proxy-dns-port: 5053
proxy-dns-upstream:
  - https://1.1.1.1/dns-query
  - https://1.0.0.1/dns-query
EOF

chown cloudflared:cloudflared /etc/cloudflared/config.yml
```

### Service systemd

```bash
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

### Configurer Pi-hole

1. Settings → DNS
2. Upstream DNS: `127.0.0.1#5053`
3. Décocher les autres upstream

---

## 10. DHCP intégré

### Activer le DHCP

1. Settings → DHCP
2. DHCP server enabled
3. Range: `192.168.1.100` - `192.168.1.200`
4. Router: `192.168.1.1`

**Important** : Désactiver le DHCP sur votre routeur !

---

## 11. Local DNS Records

### Ajouter des enregistrements

1. Local DNS → DNS Records
2. Domain: `server.local`
3. IP: `192.168.1.50`

Ou via fichier :

```bash
echo "192.168.1.50 server.local" >> /etc/pihole/custom.list
pihole restartdns
```

---

## 12. Groupes et clients

### Groupes

1. Group Management → Groups
2. Créer des groupes (ex: "Kids", "Work")

### Assigner clients

1. Group Management → Clients
2. Ajouter le client par IP ou MAC
3. Assigner au groupe

### Adlists par groupe

1. Group Management → Adlists
2. Assigner les listes aux groupes

---

## 13. Installation Docker

Alternative avec Docker :

```bash
docker volume create pihole_data
docker volume create dnsmasq_data

docker run -d \
  --name pihole \
  --restart=unless-stopped \
  -p 53:53/tcp -p 53:53/udp \
  -p 80:80 \
  -e TZ='Europe/Paris' \
  -e WEBPASSWORD='secure_password' \
  -v pihole_data:/etc/pihole \
  -v dnsmasq_data:/etc/dnsmasq.d \
  --dns=127.0.0.1 --dns=8.8.8.8 \
  pihole/pihole:latest
```

---

## 14. Backup

```bash
# Teleporter backup (via web)
# Settings → Teleporter → Export

# CLI
pihole -a -t

# Fichiers importants
/etc/pihole/
/etc/dnsmasq.d/
```

---

## Commandes utiles

```bash
# Status
pihole status

# Activer/Désactiver
pihole enable
pihole disable        # Permanent
pihole disable 5m     # 5 minutes

# Mettre à jour
pihole -up

# Gravity
pihole -g

# Logs temps réel
pihole -t

# Stats
pihole -c

# Flush logs
pihole flush
```

---

## Dépannage

```bash
# Réparer
pihole -r

# Logs
cat /var/log/pihole.log
cat /var/log/pihole-FTL.log

# DNS test
dig @127.0.0.1 google.com

# Vérifier les services
systemctl status pihole-FTL
systemctl status lighttpd
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
