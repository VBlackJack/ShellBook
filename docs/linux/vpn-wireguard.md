---
tags:
  - vpn
  - wireguard
  - security
  - network
---

# WireGuard VPN

VPN moderne, rapide et sécurisé sous Linux.

![WireGuard VPN Architecture](../assets/diagrams/wireguard-vpn-architecture.jpeg)

---

## Pourquoi WireGuard ?

### Comparatif Éclair

| Aspect | WireGuard | OpenVPN | IPSec |
|--------|-----------|---------|-------|
| **Lignes de code** | ~4,000 | ~100,000+ | ~400,000+ |
| **Audit sécurité** | Facile | Complexe | Très complexe |
| **Cryptographie** | Moderne (ChaCha20, Curve25519) | Configurable (risque) | Variable |
| **Handshake** | 1-RTT | Multi-RTT | Multi-RTT |
| **Intégration kernel** | Native (Linux 5.6+) | Userspace | Kernel |
| **Configuration** | Simple | Complexe | Très complexe |

### Avantages Clés

```text
┌─────────────────────────────────────────────────────────────┐
│                    WIREGUARD                                 │
├─────────────────────────────────────────────────────────────┤
│  ✓ Minimaliste     - Code auditable facilement              │
│  ✓ Rapide          - Handshake en 1 round-trip              │
│  ✓ Silencieux      - Ne répond pas aux paquets non auth     │
│  ✓ Roaming         - Gère le changement d'IP client         │
│  ✓ Kernel-native   - Performances maximales                 │
└─────────────────────────────────────────────────────────────┘
```

!!! tip "Silencieux par défaut"
    WireGuard ne répond **jamais** aux paquets non authentifiés. Un scan de port ne détecte rien. C'est un "stealth VPN".

---

## Installation & Clés

### Installation

=== "RHEL/Rocky"

    ```bash
    sudo dnf install wireguard-tools

    # Vérifier le module kernel
    lsmod | grep wireguard
    ```

=== "Debian/Ubuntu"

    ```bash
    sudo apt install wireguard wireguard-tools

    # Vérifier le module kernel
    lsmod | grep wireguard
    ```

### Génération des Clés

```bash
# Créer le répertoire (permissions restrictives)
sudo mkdir -p /etc/wireguard
cd /etc/wireguard
umask 077

# Générer la paire de clés
wg genkey | tee privatekey | wg pubkey > publickey

# Ou en une ligne avec affichage
wg genkey | tee privatekey | wg pubkey | tee publickey

# Vérifier
cat privatekey
cat publickey

# Permissions (CRITIQUE)
chmod 600 privatekey
```

!!! danger "Protéger la clé privée"
    La clé privée ne doit **jamais** quitter le serveur.

    - `chmod 600 privatekey`
    - Ne jamais la transmettre par email ou chat

### Concept : Crypto Routing

WireGuard associe une **clé publique** à une **IP autorisée** :

```text
┌─────────────────────────────────────────────────────────────┐
│                     CRYPTO ROUTING                           │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   PublicKey: abc123...  →  AllowedIPs: 10.10.0.2/32         │
│   PublicKey: def456...  →  AllowedIPs: 10.10.0.3/32         │
│   PublicKey: ghi789...  →  AllowedIPs: 10.10.0.4/32         │
│                                                              │
│   Seule la clé "abc123" peut envoyer des paquets            │
│   avec l'IP source 10.10.0.2                                │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Configuration Serveur

### Fichier wg0.conf

```ini
# /etc/wireguard/wg0.conf

[Interface]
# IP du serveur dans le tunnel VPN
Address = 10.10.0.1/24

# Clé privée du serveur
PrivateKey = <SERVER_PRIVATE_KEY>

# Port d'écoute UDP
ListenPort = 51820

# Commandes post-up/down (optionnel - pour NAT)
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

# DNS pour les clients (optionnel)
# DNS = 1.1.1.1, 8.8.8.8

[Peer]
# Client 1 : Laptop
PublicKey = <CLIENT1_PUBLIC_KEY>
AllowedIPs = 10.10.0.2/32

[Peer]
# Client 2 : Mobile
PublicKey = <CLIENT2_PUBLIC_KEY>
AllowedIPs = 10.10.0.3/32

[Peer]
# Client 3 : Site distant (sous-réseau entier)
PublicKey = <SITE_PUBLIC_KEY>
AllowedIPs = 10.10.0.4/32, 192.168.100.0/24
```

### Configuration Client

```ini
# /etc/wireguard/wg0.conf (côté client)

[Interface]
# IP du client dans le tunnel
Address = 10.10.0.2/24

# Clé privée du client
PrivateKey = <CLIENT_PRIVATE_KEY>

# DNS à utiliser via le VPN
DNS = 1.1.1.1

[Peer]
# Serveur VPN
PublicKey = <SERVER_PUBLIC_KEY>

# IP publique du serveur
Endpoint = vpn.example.com:51820

# IPs à router via le VPN
# 0.0.0.0/0 = Tout le trafic (full tunnel)
# 10.10.0.0/24 = Seulement le réseau VPN (split tunnel)
AllowedIPs = 0.0.0.0/0

# Keepalive (utile derrière NAT)
PersistentKeepalive = 25
```

### AllowedIPs Expliqué

| Valeur | Effet |
|--------|-------|
| `10.10.0.2/32` | Seulement cette IP (Peer) |
| `10.10.0.0/24` | Tout le réseau VPN |
| `0.0.0.0/0` | Tout le trafic (full tunnel) |
| `192.168.0.0/16, 10.0.0.0/8` | Réseaux privés seulement |

### Activation

```bash
# Démarrer l'interface
sudo wg-quick up wg0

# Arrêter
sudo wg-quick down wg0

# Activer au boot
sudo systemctl enable wg-quick@wg0

# Status
sudo wg show

# Output:
# interface: wg0
#   public key: <SERVER_PUBLIC_KEY>
#   private key: (hidden)
#   listening port: 51820
#
# peer: <CLIENT_PUBLIC_KEY>
#   endpoint: 1.2.3.4:54321
#   allowed ips: 10.10.0.2/32
#   latest handshake: 42 seconds ago
#   transfer: 1.23 MiB received, 4.56 MiB sent
```

### Gestion des Peers (à chaud)

```bash
# Ajouter un peer sans redémarrer
sudo wg set wg0 peer <PUBLIC_KEY> allowed-ips 10.10.0.5/32

# Supprimer un peer
sudo wg set wg0 peer <PUBLIC_KEY> remove

# Voir la config actuelle
sudo wg showconf wg0
```

---

## Sécurité & Réseau

### Firewall (UFW)

```bash
# Autoriser le port WireGuard
sudo ufw allow 51820/udp

# Si le serveur est une passerelle, autoriser le forwarding
sudo ufw route allow in on wg0 out on eth0
```

### Firewall (iptables)

```bash
# Autoriser WireGuard
sudo iptables -A INPUT -p udp --dport 51820 -j ACCEPT

# Autoriser le forwarding depuis wg0
sudo iptables -A FORWARD -i wg0 -j ACCEPT
sudo iptables -A FORWARD -o wg0 -j ACCEPT

# NAT (si le VPN sert de passerelle Internet)
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
```

### IP Forwarding

```bash
# Vérifier l'état actuel
cat /proc/sys/net/ipv4/ip_forward
# 0 = désactivé, 1 = activé

# Activer temporairement
sudo sysctl -w net.ipv4.ip_forward=1

# Activer définitivement
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# IPv6 aussi (si nécessaire)
echo "net.ipv6.conf.all.forwarding=1" | sudo tee -a /etc/sysctl.conf
```

!!! warning "IP Forwarding nécessaire si :"
    - Le VPN sert de passerelle vers Internet (full tunnel)
    - Le VPN connecte plusieurs sites (site-to-site)
    - Les clients doivent atteindre d'autres réseaux via le VPN

### Génération de Config Client (QR Code)

```bash
# Installer qrencode
sudo apt install qrencode

# Créer config client
cat > /etc/wireguard/clients/client1.conf << EOF
[Interface]
Address = 10.10.0.2/24
PrivateKey = <CLIENT_PRIVATE_KEY>
DNS = 1.1.1.1

[Peer]
PublicKey = <SERVER_PUBLIC_KEY>
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF

# Générer QR code (pour mobile)
qrencode -t ansiutf8 < /etc/wireguard/clients/client1.conf
```

---

## Référence Rapide

```bash
# === INSTALLATION ===
sudo apt install wireguard wireguard-tools

# === CLÉS ===
wg genkey | tee privatekey | wg pubkey > publickey
chmod 600 privatekey

# === GESTION ===
sudo wg-quick up wg0              # Démarrer
sudo wg-quick down wg0            # Arrêter
sudo systemctl enable wg-quick@wg0  # Autostart

# === STATUS ===
sudo wg show                      # État détaillé
sudo wg show wg0 latest-handshakes  # Derniers handshakes

# === PEERS À CHAUD ===
sudo wg set wg0 peer <PUBKEY> allowed-ips 10.10.0.5/32
sudo wg set wg0 peer <PUBKEY> remove

# === SÉCURITÉ ===
sudo ufw allow 51820/udp
sudo sysctl -w net.ipv4.ip_forward=1

# === QR CODE ===
qrencode -t ansiutf8 < client.conf
```
