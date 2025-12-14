---
tags:
  - tutos
  - vpn
  - wireguard
  - network
  - rocky
---

# WireGuard VPN sur Rocky Linux 9

Installation et configuration de **WireGuard** sur Rocky Linux 9.

| Composant | Version |
|-----------|---------|
| Rocky Linux | 9.x |
| WireGuard | Kernel intégré |

**Durée estimée :** 30 minutes

---

## Avantages de WireGuard

| Critère | WireGuard | OpenVPN |
|---------|-----------|---------|
| Performance | Excellente | Bonne |
| Complexité | Simple | Complexe |
| Code | ~4000 lignes | ~100000 lignes |
| Cryptographie | Moderne (ChaCha20) | Configurable |
| Audit | Facile | Difficile |

---

## Architecture

```
┌─────────────────┐          ┌─────────────────┐
│  Client VPN     │          │  Serveur VPN    │
│  10.0.0.2/32    │◄────────►│  10.0.0.1/32    │
│  wg0            │  :51820  │  wg0            │
└─────────────────┘          └─────────────────┘
                                     │
                             ┌───────▼───────┐
                             │  LAN interne  │
                             │ 192.168.1.0/24│
                             └───────────────┘
```

---

## 1. Installation

```bash
# WireGuard est dans le kernel Linux 5.6+
dnf install -y wireguard-tools

# Vérifier
modprobe wireguard
lsmod | grep wireguard
```

---

## 2. Configuration Serveur

### Générer les clés

```bash
cd /etc/wireguard
umask 077

# Clé privée serveur
wg genkey | tee server_private.key | wg pubkey > server_public.key

# Afficher pour utilisation
cat server_private.key
cat server_public.key
```

### Configuration serveur

```bash
vim /etc/wireguard/wg0.conf
```

```ini
[Interface]
# Adresse VPN du serveur
Address = 10.0.0.1/24

# Port d'écoute
ListenPort = 51820

# Clé privée du serveur
PrivateKey = <CONTENU_DE_server_private.key>

# NAT pour accès Internet via VPN
PostUp = firewall-cmd --add-masquerade
PostUp = firewall-cmd --add-port=51820/udp
PostDown = firewall-cmd --remove-masquerade
PostDown = firewall-cmd --remove-port=51820/udp

# OU avec iptables
# PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
# PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

# Clients (ajoutés après)
[Peer]
# Client 1
PublicKey = <CLE_PUBLIQUE_CLIENT1>
AllowedIPs = 10.0.0.2/32

[Peer]
# Client 2
PublicKey = <CLE_PUBLIQUE_CLIENT2>
AllowedIPs = 10.0.0.3/32
```

### Activer le forwarding IP

```bash
echo 'net.ipv4.ip_forward = 1' >> /etc/sysctl.d/99-wireguard.conf
sysctl -p /etc/sysctl.d/99-wireguard.conf
```

### Démarrer WireGuard

```bash
systemctl enable --now wg-quick@wg0
systemctl status wg-quick@wg0

# Vérifier
wg show
ip a show wg0
```

---

## 3. Configuration Client (Linux)

### Générer les clés client

```bash
cd /etc/wireguard
umask 077
wg genkey | tee client_private.key | wg pubkey > client_public.key
```

### Configuration client

```bash
vim /etc/wireguard/wg0.conf
```

```ini
[Interface]
# Adresse VPN du client
Address = 10.0.0.2/32

# Clé privée du client
PrivateKey = <CONTENU_DE_client_private.key>

# DNS via VPN (optionnel)
DNS = 10.0.0.1

[Peer]
# Serveur VPN
PublicKey = <CLE_PUBLIQUE_SERVEUR>

# Endpoint (IP publique du serveur)
Endpoint = vpn.example.com:51820

# Tout le trafic via VPN
AllowedIPs = 0.0.0.0/0

# Ou uniquement le réseau VPN + LAN distant
# AllowedIPs = 10.0.0.0/24, 192.168.1.0/24

# Keepalive (important si client derrière NAT)
PersistentKeepalive = 25
```

### Connecter

```bash
wg-quick up wg0
wg show

# Tester
ping 10.0.0.1
```

---

## 4. Client Windows

1. Télécharger WireGuard : https://www.wireguard.com/install/
2. Créer un nouveau tunnel
3. Coller la configuration :

```ini
[Interface]
PrivateKey = <CLE_PRIVEE_CLIENT>
Address = 10.0.0.3/32
DNS = 10.0.0.1

[Peer]
PublicKey = <CLE_PUBLIQUE_SERVEUR>
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
```

4. Activer le tunnel

---

## 5. Client Mobile (Android/iOS)

1. Installer l'app WireGuard
2. Scanner un QR code ou importer la config

### Générer un QR code

```bash
dnf install -y qrencode

qrencode -t ansiutf8 < /etc/wireguard/client.conf
```

---

## 6. Script d'ajout de client

```bash
#!/bin/bash
# add-wg-client.sh

CLIENT_NAME=$1
CLIENT_IP=$2

if [ -z "$CLIENT_NAME" ] || [ -z "$CLIENT_IP" ]; then
    echo "Usage: $0 <client_name> <client_ip>"
    echo "Example: $0 laptop 10.0.0.5"
    exit 1
fi

cd /etc/wireguard

# Générer les clés
wg genkey | tee ${CLIENT_NAME}_private.key | wg pubkey > ${CLIENT_NAME}_public.key
CLIENT_PRIVATE=$(cat ${CLIENT_NAME}_private.key)
CLIENT_PUBLIC=$(cat ${CLIENT_NAME}_public.key)
SERVER_PUBLIC=$(cat server_public.key)

# Créer la config client
cat > ${CLIENT_NAME}.conf << EOF
[Interface]
PrivateKey = $CLIENT_PRIVATE
Address = ${CLIENT_IP}/32
DNS = 10.0.0.1

[Peer]
PublicKey = $SERVER_PUBLIC
Endpoint = $(curl -s ifconfig.me):51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF

# Ajouter le peer au serveur
cat >> wg0.conf << EOF

[Peer]
# $CLIENT_NAME
PublicKey = $CLIENT_PUBLIC
AllowedIPs = ${CLIENT_IP}/32
EOF

# Recharger
wg syncconf wg0 <(wg-quick strip wg0)

echo "Configuration client créée: ${CLIENT_NAME}.conf"
qrencode -t ansiutf8 < ${CLIENT_NAME}.conf
```

---

## 7. Commandes de gestion

```bash
# Status
wg show
wg show wg0

# Activer/Désactiver
wg-quick up wg0
wg-quick down wg0

# Recharger sans déconnecter
wg syncconf wg0 <(wg-quick strip wg0)

# Ajouter un peer à chaud
wg set wg0 peer <PUBLIC_KEY> allowed-ips 10.0.0.5/32

# Supprimer un peer
wg set wg0 peer <PUBLIC_KEY> remove
```

---

## 8. Firewall

```bash
# Port WireGuard
firewall-cmd --permanent --add-port=51820/udp

# NAT/Masquerade
firewall-cmd --permanent --add-masquerade

# Forward
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="10.0.0.0/24" masquerade'

firewall-cmd --reload
```

---

## 9. Accès au LAN interne

Pour permettre aux clients VPN d'accéder au LAN :

```ini
# Sur le serveur, dans PostUp
PostUp = iptables -A FORWARD -i wg0 -o eth0 -j ACCEPT
PostUp = iptables -A FORWARD -i eth0 -o wg0 -m state --state RELATED,ESTABLISHED -j ACCEPT

# Sur le client, dans AllowedIPs
AllowedIPs = 10.0.0.0/24, 192.168.1.0/24
```

---

## Vérification

```bash
# Interface
ip a show wg0

# Connexions
wg show

# Ping
ping 10.0.0.2

# Trafic
wg show wg0 transfer
```

---

## Dépannage

| Problème | Solution |
|----------|----------|
| Handshake failed | Vérifier clés, endpoint, port |
| No route | Vérifier AllowedIPs |
| Pas d'Internet | Vérifier NAT, ip_forward |

```bash
# Debug
journalctl -u wg-quick@wg0 -f
dmesg | grep wireguard
tcpdump -i eth0 port 51820
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
