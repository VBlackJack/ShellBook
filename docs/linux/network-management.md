---
tags:
  - netplan
  - interfaces
  - dns
  - systemd-resolved
---

# Network Configuration & DNS

Configuration réseau persistante sur Debian et Ubuntu.

---

## Configuration Persistante : Le Duel

### Vue d'Ensemble

| Distribution | Méthode | Fichier(s) | Commande |
|--------------|---------|------------|----------|
| Debian | ifupdown | `/etc/network/interfaces` | `systemctl restart networking` |
| Ubuntu 18.04+ | Netplan | `/etc/netplan/*.yaml` | `netplan apply` |
| RHEL/CentOS | NetworkManager | `/etc/NetworkManager/` | `nmcli` |

---

### Debian : /etc/network/interfaces

**Fichier :** `/etc/network/interfaces`

#### IP Statique

```bash
# /etc/network/interfaces

# Loopback
auto lo
iface lo inet loopback

# Interface principale - IP Statique
auto eth0
iface eth0 inet static
    address 192.168.1.100
    netmask 255.255.255.0
    gateway 192.168.1.1
    dns-nameservers 8.8.8.8 8.8.4.4
    dns-search example.com
```

#### DHCP

```bash
# /etc/network/interfaces

auto lo
iface lo inet loopback

# Interface principale - DHCP
auto eth0
iface eth0 inet dhcp
```

#### Appliquer les Changements

```bash
# Méthode 1 : Redémarrer le service
sudo systemctl restart networking

# Méthode 2 : Interface spécifique
sudo ifdown eth0 && sudo ifup eth0

# Vérifier
ip addr show eth0
```

---

### Ubuntu : Netplan

**Fichier :** `/etc/netplan/00-installer-config.yaml` (ou autre `.yaml`)

!!! warning "Indentation YAML Critique"
    Netplan utilise YAML. **2 espaces** d'indentation, **pas de tabulations**.
    Une erreur d'indentation = configuration non appliquée.

#### IP Statique

```yaml
# /etc/netplan/00-installer-config.yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    eth0:
      addresses:
        - 192.168.1.100/24
      routes:
        - to: default
          via: 192.168.1.1
      nameservers:
        addresses:
          - 8.8.8.8
          - 8.8.4.4
        search:
          - example.com
```

#### DHCP

```yaml
# /etc/netplan/00-installer-config.yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    eth0:
      dhcp4: true
```

#### Multiples Interfaces

```yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    eth0:
      dhcp4: true
    eth1:
      addresses:
        - 10.0.0.10/24
      routes:
        - to: 10.0.0.0/8
          via: 10.0.0.1
```

#### Appliquer les Changements

```bash
# Vérifier la syntaxe (ne modifie rien)
sudo netplan generate

# Tester sans appliquer définitivement (rollback auto après 120s)
sudo netplan try

# Appliquer définitivement
sudo netplan apply

# Debug
sudo netplan --debug apply
```

---

### Commandes Immédiates (Non Persistantes)

```bash
# Ajouter une IP (temporaire, perdu au reboot)
sudo ip addr add 192.168.1.200/24 dev eth0

# Supprimer une IP
sudo ip addr del 192.168.1.200/24 dev eth0

# Activer/Désactiver une interface
sudo ip link set eth0 up
sudo ip link set eth0 down

# Ajouter une route
sudo ip route add 10.0.0.0/8 via 192.168.1.1

# Voir la configuration
ip addr
ip route
ip link
```

---

## Gestion du DNS

### Le Piège /etc/resolv.conf

!!! danger "Ne pas modifier directement"
    Sur les systèmes modernes, `/etc/resolv.conf` est **généré automatiquement** par :

    - `systemd-resolved` (Ubuntu)
    - `NetworkManager`
    - `dhclient`
    - `resolvconf`

    Vos modifications seront **écrasées** au prochain reboot ou renouvellement DHCP.

```bash
# Vérifier si c'est un lien symbolique
ls -la /etc/resolv.conf

# Output typique Ubuntu:
# lrwxrwxrwx 1 root root 39 /etc/resolv.conf -> ../run/systemd/resolve/stub-resolv.conf
```

---

### Systemd-resolved (Méthode Moderne)

Ubuntu et distributions modernes utilisent `systemd-resolved`.

#### Vérifier le Status

```bash
# Status complet
resolvectl status

# Output:
# Global
#        Protocols: +LLMNR +mDNS -DNSOverTLS DNSSEC=no/unsupported
# resolv.conf mode: stub
#
# Link 2 (eth0)
#     Current Scopes: DNS LLMNR/IPv4 LLMNR/IPv6
#          Protocols: +DefaultRoute +LLMNR -mDNS -DNSOverTLS
# Current DNS Server: 8.8.8.8
#        DNS Servers: 8.8.8.8 8.8.4.4
```

#### Tester la Résolution DNS

```bash
# Résolution via systemd-resolved
resolvectl query google.com

# Avec détails
resolvectl query --type=A google.com
resolvectl query --type=MX google.com

# Classique (aussi fonctionnel)
dig google.com
nslookup google.com
host google.com
```

#### Configurer les DNS Manuellement

**Méthode 1 : Via Netplan (recommandé)**

```yaml
# /etc/netplan/00-installer-config.yaml
network:
  version: 2
  ethernets:
    eth0:
      dhcp4: true
      nameservers:
        addresses:
          - 1.1.1.1
          - 8.8.8.8
```

**Méthode 2 : Via resolved.conf**

```bash
# /etc/systemd/resolved.conf
[Resolve]
DNS=1.1.1.1 8.8.8.8
FallbackDNS=9.9.9.9
Domains=~.
DNSSEC=allow-downgrade
DNSOverTLS=opportunistic

# Appliquer
sudo systemctl restart systemd-resolved
```

#### Vider le Cache DNS

```bash
# Systemd-resolved
sudo resolvectl flush-caches

# Vérifier les stats du cache
resolvectl statistics
```

---

### /etc/hosts : DNS Local

Le fichier `/etc/hosts` est consulté **avant** le DNS. Idéal pour :

- Résolution locale rapide
- Bloquer des domaines (rediriger vers 127.0.0.1)
- Tests sans modifier le DNS

```bash
# /etc/hosts

127.0.0.1       localhost
127.0.1.1       myserver.example.com myserver

# Serveurs internes
192.168.1.10    db.internal db
192.168.1.20    web.internal web
192.168.1.30    cache.internal cache

# Bloquer un domaine
127.0.0.1       ads.example.com
127.0.0.1       tracking.example.com

# IPv6
::1             localhost ip6-localhost ip6-loopback
```

!!! tip "Ordre de Résolution"
    L'ordre est défini dans `/etc/nsswitch.conf` :

    ```
    hosts: files dns
    ```

    `files` = `/etc/hosts` consulté en premier.

---

## Hostname & Identification

### Voir le Hostname Actuel

```bash
# Méthode moderne
hostnamectl

# Output:
#  Static hostname: myserver
#        Icon name: computer-vm
#          Chassis: vm
#       Machine ID: abc123...
#          Boot ID: def456...
#   Virtualization: kvm
# Operating System: Ubuntu 22.04.3 LTS
#           Kernel: Linux 5.15.0-91-generic
#     Architecture: x86-64

# Méthode classique
hostname
cat /etc/hostname
```

### Changer le Hostname

```bash
# Méthode moderne (recommandée)
sudo hostnamectl set-hostname new-server-name

# Vérifier
hostnamectl
```

### Mettre à Jour /etc/hosts

!!! warning "Impact sur sudo et services"
    Après changement du hostname, **mettre à jour `/etc/hosts`** est crucial.

    Sans cela :

    - `sudo` devient lent (timeout de résolution)
    - Certains services démarrent mal
    - Logs contiennent des warnings

```bash
# /etc/hosts - APRÈS changement de hostname

127.0.0.1       localhost
127.0.1.1       new-server-name.example.com new-server-name

# Le reste...
```

**Procédure Complète :**

```bash
# 1. Changer le hostname
sudo hostnamectl set-hostname webserver01

# 2. Mettre à jour /etc/hosts
sudo sed -i 's/old-hostname/webserver01/g' /etc/hosts

# Ou éditer manuellement
sudo nano /etc/hosts

# 3. Vérifier
hostname
ping $(hostname)
sudo echo "test"   # Doit être instantané
```

---

## Diagnostic Réseau

### Commandes Essentielles

```bash
# Configuration IP
ip addr                    # Toutes les interfaces
ip addr show eth0          # Interface spécifique
ip -br addr                # Format court

# Routes
ip route                   # Table de routage
ip route get 8.8.8.8       # Quelle route pour cette IP ?

# Connexions actives
ss -tulpn                  # Ports en écoute
ss -t state established    # Connexions établies

# DNS
resolvectl status          # Status DNS
resolvectl query domain    # Test résolution
cat /etc/resolv.conf       # Serveurs DNS actifs

# Connectivité
ping -c 4 8.8.8.8          # Test ICMP
traceroute google.com      # Trace route
mtr google.com             # Traceroute interactif
```

### Tester la Connectivité par Couche

```bash
# 1. Interface up ?
ip link show eth0

# 2. IP assignée ?
ip addr show eth0

# 3. Gateway accessible ?
ping -c 2 $(ip route | grep default | awk '{print $3}')

# 4. DNS fonctionne ?
resolvectl query google.com

# 5. Internet accessible ?
ping -c 2 8.8.8.8
curl -I https://google.com
```

---

## Référence Rapide

```bash
# Debian
sudo nano /etc/network/interfaces
sudo systemctl restart networking

# Ubuntu (Netplan)
sudo nano /etc/netplan/00-installer-config.yaml
sudo netplan apply

# IP temporaire
sudo ip addr add 192.168.1.100/24 dev eth0
sudo ip link set eth0 up

# DNS
resolvectl status
resolvectl query domain
sudo resolvectl flush-caches

# Hostname
sudo hostnamectl set-hostname new-name
# + Mettre à jour /etc/hosts !

# Diagnostic
ip addr
ip route
ss -tulpn
ping -c 4 8.8.8.8
```
