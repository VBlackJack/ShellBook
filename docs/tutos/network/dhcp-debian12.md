---
tags:
  - tutos
  - dhcp
  - debian
  - network
---

# Serveur DHCP sur Debian 12

Configuration d'un serveur **DHCP** avec ISC DHCP Server sur Debian 12 Bookworm.

| Composant | Version |
|-----------|---------|
| Debian | 12 Bookworm |
| ISC DHCP | 4.4 |

**Durée estimée :** 25 minutes

**Prérequis :**

- Debian 12 installé
- Accès root ou sudo
- IP statique configurée sur le serveur

---

## 1. Installation

```bash
# Mettre à jour
apt update

# Installer le serveur DHCP
apt install -y isc-dhcp-server

# Vérifier l'installation
dpkg -l | grep isc-dhcp-server
```

---

## 2. Configuration du Firewall (UFW)

```bash
# Installer UFW si nécessaire
apt install -y ufw

# Autoriser DHCP
ufw allow 67/udp
ufw allow 68/udp

# Si pas encore activé
ufw allow ssh
ufw enable

# Vérifier
ufw status
```

---

## 3. Définir l'interface d'écoute

### Fichier /etc/default/isc-dhcp-server

```bash
# Configurer l'interface
cat > /etc/default/isc-dhcp-server << 'EOF'
# Interface(s) sur laquelle le DHCP écoute
INTERFACESv4="eth0"
INTERFACESv6=""
EOF
```

!!! warning "Adapter l'interface"
    Remplacez `eth0` par le nom de votre interface réseau (`ip link show`).

---

## 4. Configuration principale

### Fichier /etc/dhcp/dhcpd.conf

```bash
# Sauvegarder
cp /etc/dhcp/dhcpd.conf /etc/dhcp/dhcpd.conf.bak

# Créer la configuration
cat > /etc/dhcp/dhcpd.conf << 'EOF'
#
# DHCP Server Configuration - Debian 12
#

# Paramètres globaux
authoritative;
default-lease-time 3600;        # 1 heure
max-lease-time 86400;           # 24 heures

# Options globales
option domain-name "example.lan";
option domain-name-servers 192.168.1.10, 8.8.8.8;
option ntp-servers 192.168.1.10;

# Subnet principal
subnet 192.168.1.0 netmask 255.255.255.0 {
    # Plage d'adresses dynamiques
    range 192.168.1.100 192.168.1.200;

    # Passerelle par défaut
    option routers 192.168.1.1;

    # Serveur DNS
    option domain-name-servers 192.168.1.10;

    # Broadcast
    option broadcast-address 192.168.1.255;

    # Durée du bail
    default-lease-time 3600;
    max-lease-time 7200;
}

# Réservations statiques (par adresse MAC)
host srv-web {
    hardware ethernet 00:11:22:33:44:55;
    fixed-address 192.168.1.20;
    option host-name "srv-web";
}

host srv-db {
    hardware ethernet 00:11:22:33:44:56;
    fixed-address 192.168.1.21;
    option host-name "srv-db";
}
EOF
```

---

## 5. Vérification et démarrage

### Vérifier la syntaxe

```bash
# Tester la configuration
dhcpd -t -cf /etc/dhcp/dhcpd.conf
```

### Démarrer le service

```bash
# Activer et démarrer
systemctl enable isc-dhcp-server
systemctl start isc-dhcp-server

# Vérifier le statut
systemctl status isc-dhcp-server

# Vérifier l'écoute
ss -ulnp | grep :67
```

---

## 6. Tests et monitoring

### Logs

```bash
# Logs en temps réel
journalctl -u isc-dhcp-server -f

# Ou via syslog
tail -f /var/log/syslog | grep dhcpd
```

### Baux actifs

```bash
# Fichier des baux
cat /var/lib/dhcp/dhcpd.leases

# Afficher les baux actifs
dhcp-lease-list

# Ou manuellement
grep -E "^lease|hardware|client-hostname" /var/lib/dhcp/dhcpd.leases
```

### Test depuis un client

```bash
# Libérer et renouveler
dhclient -r ens18
dhclient ens18

# Vérifier
ip addr show ens18
cat /etc/resolv.conf
```

---

## 7. Différences Rocky 9 vs Debian 12

| Aspect | Rocky 9 | Debian 12 |
|--------|---------|-----------|
| Paquet | `dhcp-server` | `isc-dhcp-server` |
| Service | `dhcpd` | `isc-dhcp-server` |
| Config interface | `/etc/sysconfig/dhcpd` | `/etc/default/isc-dhcp-server` |
| Fichier leases | `/var/lib/dhcpd/dhcpd.leases` | `/var/lib/dhcp/dhcpd.leases` |

---

## 8. Options avancées

### Classes de clients

```bash
# Ajouter dans dhcpd.conf
class "pc-windows" {
    match if substring (option vendor-class-identifier, 0, 4) = "MSFT";
}

class "pc-linux" {
    match if substring (option vendor-class-identifier, 0, 5) = "Linux";
}

# Pools par classe
subnet 192.168.1.0 netmask 255.255.255.0 {
    pool {
        allow members of "pc-windows";
        range 192.168.1.100 192.168.1.150;
    }
    pool {
        allow members of "pc-linux";
        range 192.168.1.151 192.168.1.200;
    }
    option routers 192.168.1.1;
}
```

### Mise à jour DNS dynamique

```bash
# Intégration avec BIND
ddns-updates on;
ddns-update-style interim;
update-static-leases on;

key "dhcp-key" {
    algorithm hmac-sha256;
    secret "votre-cle-secrete-base64";
};

zone example.lan. {
    primary 192.168.1.10;
    key "dhcp-key";
}

zone 1.168.192.in-addr.arpa. {
    primary 192.168.1.10;
    key "dhcp-key";
}
```

---

## Dépannage

### Service ne démarre pas

```bash
# Vérifier les logs
journalctl -u isc-dhcp-server -n 50

# Vérifier la syntaxe
dhcpd -t -cf /etc/dhcp/dhcpd.conf

# Vérifier l'interface configurée existe
ip link show
cat /etc/default/isc-dhcp-server
```

### Erreur "No subnet declaration"

L'interface doit avoir une IP dans un subnet déclaré :

```bash
# Vérifier l'IP de l'interface
ip addr show eth0

# L'IP doit correspondre à un subnet dans dhcpd.conf
# Si l'interface a 192.168.1.10, le subnet 192.168.1.0/24 doit exister
```

### Clients ne reçoivent pas d'adresse

```bash
# Capturer le trafic DHCP
tcpdump -i eth0 port 67 or port 68 -n -v

# Vérifier le firewall
ufw status

# Tester côté client
dhclient -v eth0
```

---

## Pour aller plus loin

- [DNS Bind Debian 12](dns-bind-debian12.md)
- [DNS + DHCP avec DDNS](dns-dhcp-ddns.md)
- [Kea DHCP (remplaçant ISC)](kea-dhcp-debian12.md)

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale - Debian 12 + ISC DHCP 4.4 |
