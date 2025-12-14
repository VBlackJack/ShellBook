---
tags:
  - tutos
  - dhcp
  - rocky-linux
  - network
---

# Serveur DHCP sur Rocky Linux 9

Configuration d'un serveur **DHCP** avec ISC DHCP Server.

| Composant | Version |
|-----------|---------|
| Rocky Linux | 9.x |
| ISC DHCP | 4.4 |

**Durée estimée :** 25 minutes

**Prérequis :**

- Rocky Linux 9 installé
- Accès root ou sudo
- IP statique configurée sur le serveur
- Plage d'adresses à distribuer définie

---

## 1. Installation

```bash
# Installer le serveur DHCP
dnf install -y dhcp-server

# Vérifier l'installation
rpm -q dhcp-server
```

---

## 2. Configuration du Firewall

```bash
# Autoriser le service DHCP
firewall-cmd --permanent --add-service=dhcp

# Recharger
firewall-cmd --reload

# Vérifier
firewall-cmd --list-services
```

---

## 3. Configuration principale

### Fichier /etc/dhcp/dhcpd.conf

```bash
# Sauvegarder le fichier exemple
cp /etc/dhcp/dhcpd.conf /etc/dhcp/dhcpd.conf.bak

# Créer la configuration
cat > /etc/dhcp/dhcpd.conf << 'EOF'
#
# DHCP Server Configuration - Rocky Linux 9
#

# Paramètres globaux
authoritative;
default-lease-time 3600;        # 1 heure
max-lease-time 86400;           # 24 heures
log-facility local7;

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

# Second subnet (optionnel)
# subnet 192.168.2.0 netmask 255.255.255.0 {
#     range 192.168.2.100 192.168.2.200;
#     option routers 192.168.2.1;
#     option domain-name-servers 192.168.1.10;
# }
EOF
```

---

## 4. Définir l'interface d'écoute

```bash
# Éditer le fichier de service
cat > /etc/sysconfig/dhcpd << 'EOF'
# Interface sur laquelle le DHCP écoute
DHCPDARGS="eth0"
EOF
```

!!! warning "Adapter l'interface"
    Remplacez `eth0` par le nom de votre interface réseau (`ip link show`).

---

## 5. Vérification et démarrage

### Vérifier la syntaxe

```bash
# Tester la configuration
dhcpd -t -cf /etc/dhcp/dhcpd.conf
```

**Résultat attendu :** Pas d'erreur affichée.

### Démarrer le service

```bash
# Activer et démarrer
systemctl enable --now dhcpd

# Vérifier le statut
systemctl status dhcpd

# Vérifier l'écoute sur le port 67
ss -ulnp | grep :67
```

---

## 6. Tests

### Voir les logs

```bash
# Logs DHCP en temps réel
journalctl -u dhcpd -f

# Ou via syslog
tail -f /var/log/messages | grep dhcpd
```

### Vérifier les baux actifs

```bash
# Fichier des baux
cat /var/lib/dhcpd/dhcpd.leases

# Voir les baux actifs formatés
grep -E "^lease|hardware|client-hostname" /var/lib/dhcpd/dhcpd.leases
```

### Depuis un client Linux

```bash
# Demander une adresse (libérer puis renouveler)
dhclient -r eth0
dhclient eth0

# Vérifier l'adresse obtenue
ip addr show eth0
```

---

## 7. Réservations DHCP

### Ajouter une réservation

1. Obtenir l'adresse MAC du client :
```bash
ip link show eth0
# ou
cat /sys/class/net/eth0/address
```

2. Ajouter dans `/etc/dhcp/dhcpd.conf` :
```
host nouveau-client {
    hardware ethernet aa:bb:cc:dd:ee:ff;
    fixed-address 192.168.1.50;
    option host-name "nouveau-client";
}
```

3. Recharger :
```bash
systemctl restart dhcpd
```

---

## 8. Options DHCP courantes

```bash
# Options disponibles dans la configuration

# DNS
option domain-name-servers 192.168.1.10, 8.8.8.8;

# Nom de domaine
option domain-name "example.lan";

# Passerelle
option routers 192.168.1.1;

# NTP
option ntp-servers 192.168.1.10;

# WINS (pour Windows)
option netbios-name-servers 192.168.1.10;

# Boot PXE
next-server 192.168.1.10;
filename "pxelinux.0";

# MTU
option interface-mtu 1500;

# Serveur TFTP
option tftp-server-name "192.168.1.10";
```

---

## 9. DHCP Failover (Haute disponibilité)

### Serveur primaire

```bash
# Ajouter dans /etc/dhcp/dhcpd.conf
failover peer "dhcp-failover" {
    primary;
    address 192.168.1.10;
    port 647;
    peer address 192.168.1.11;
    peer port 647;
    max-response-delay 30;
    max-unacked-updates 10;
    load balance max seconds 3;
    mclt 1800;
    split 128;
}

# Modifier le subnet
subnet 192.168.1.0 netmask 255.255.255.0 {
    pool {
        failover peer "dhcp-failover";
        range 192.168.1.100 192.168.1.200;
    }
    option routers 192.168.1.1;
}
```

### Serveur secondaire

```bash
failover peer "dhcp-failover" {
    secondary;
    address 192.168.1.11;
    port 647;
    peer address 192.168.1.10;
    peer port 647;
    max-response-delay 30;
    max-unacked-updates 10;
    load balance max seconds 3;
}
```

---

## 10. Configuration SELinux

```bash
# Vérifier le contexte
ls -lZ /etc/dhcp/dhcpd.conf

# Si problème, restaurer le contexte
restorecon -Rv /etc/dhcp/

# Autoriser DHCP à écrire les leases
setsebool -P dhcpd_disable_trans 0
```

---

## Dépannage

### Le service ne démarre pas

```bash
# Vérifier les logs
journalctl -u dhcpd -n 50

# Tester la configuration
dhcpd -t -cf /etc/dhcp/dhcpd.conf

# Vérifier l'interface
ip addr show
```

### Aucun bail distribué

```bash
# Vérifier que le port 67 est ouvert
firewall-cmd --list-services

# Vérifier l'interface dans /etc/sysconfig/dhcpd
cat /etc/sysconfig/dhcpd

# Capturer le trafic DHCP
tcpdump -i eth0 port 67 or port 68 -n
```

### Client ne reçoit pas d'adresse

```bash
# Côté client, tester en mode verbose
dhclient -v eth0

# Vérifier les logs serveur
tail -f /var/log/messages | grep dhcpd
```

---

## Pour aller plus loin

- [DNS Bind Rocky 9](dns-bind-rocky9.md)
- [DNS + DHCP intégration](dns-dhcp-integration.md)
- [PXE Boot avec DHCP](pxe-boot-rocky9.md)

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale - Rocky 9 + ISC DHCP 4.4 |
