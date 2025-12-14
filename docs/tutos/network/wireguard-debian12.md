---
tags:
  - tutos
  - vpn
  - wireguard
  - network
  - debian
---

# WireGuard VPN sur Debian 12

Installation de **WireGuard** sur Debian 12 Bookworm.

| Composant | Version |
|-----------|---------|
| Debian | 12 Bookworm |
| WireGuard | Kernel intégré |

**Durée estimée :** 25 minutes

---

## 1. Installation

```bash
apt update
apt install -y wireguard wireguard-tools qrencode

modprobe wireguard
```

---

## 2. Configuration Serveur

### Générer les clés

```bash
cd /etc/wireguard
umask 077
wg genkey | tee server_private.key | wg pubkey > server_public.key
```

### Configuration

```bash
vim /etc/wireguard/wg0.conf
```

```ini
[Interface]
Address = 10.0.0.1/24
ListenPort = 51820
PrivateKey = <CONTENU_server_private.key>

# NAT
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

[Peer]
# Client 1
PublicKey = <CLE_PUBLIQUE_CLIENT>
AllowedIPs = 10.0.0.2/32
```

### Activer IP forwarding

```bash
echo 'net.ipv4.ip_forward = 1' >> /etc/sysctl.d/99-wireguard.conf
sysctl -p /etc/sysctl.d/99-wireguard.conf
```

### Démarrer

```bash
systemctl enable --now wg-quick@wg0
wg show
```

---

## 3. Configuration Client

```bash
cd /etc/wireguard
wg genkey | tee client_private.key | wg pubkey > client_public.key
```

```ini
# /etc/wireguard/wg0.conf
[Interface]
PrivateKey = <CLE_PRIVEE_CLIENT>
Address = 10.0.0.2/32
DNS = 10.0.0.1

[Peer]
PublicKey = <CLE_PUBLIQUE_SERVEUR>
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
```

```bash
wg-quick up wg0
ping 10.0.0.1
```

---

## 4. Firewall UFW

```bash
ufw allow 51820/udp
ufw reload

# Autoriser forwarding
vim /etc/default/ufw
# DEFAULT_FORWARD_POLICY="ACCEPT"

# NAT
vim /etc/ufw/before.rules
# Ajouter avant *filter:
*nat
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -s 10.0.0.0/24 -o eth0 -j MASQUERADE
COMMIT

ufw reload
```

---

## 5. QR Code pour mobile

```bash
qrencode -t ansiutf8 < /etc/wireguard/client.conf
```

---

## 6. Commandes

```bash
wg show
wg-quick up wg0
wg-quick down wg0
wg syncconf wg0 <(wg-quick strip wg0)
```

---

## Comparatif Rocky vs Debian

| Aspect | Rocky 9 | Debian 12 |
|--------|---------|-----------|
| Firewall | firewalld | ufw/iptables |
| NAT config | firewall-cmd | iptables |
| Package | wireguard-tools | wireguard |

---

## Dépannage

```bash
journalctl -u wg-quick@wg0 -f
wg show
ip route
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
