---
tags:
  - tutos
  - dns
  - bind
  - debian
  - network
---

# Serveur DNS Bind sur Debian 12

Configuration d'un serveur DNS autoritaire avec **BIND 9** sur Debian 12 Bookworm.

| Composant | Version |
|-----------|---------|
| Debian | 12 Bookworm |
| BIND | 9.18 |

**Durée estimée :** 40 minutes

**Prérequis :**

- Debian 12 installé
- Accès root ou sudo
- IP statique configurée
- Nom de domaine à gérer (ex: `example.lan`)

---

## 1. Installation de BIND

```bash
# Mettre à jour les paquets
apt update

# Installer BIND9 et les utilitaires
apt install -y bind9 bind9utils bind9-dnsutils

# Vérifier la version
named -v
```

---

## 2. Configuration du Firewall (UFW)

```bash
# Installer UFW si nécessaire
apt install -y ufw

# Autoriser SSH
ufw allow ssh

# Autoriser DNS
ufw allow 53/tcp
ufw allow 53/udp

# Activer UFW
ufw enable

# Vérifier
ufw status
```

---

## 3. Structure des fichiers Debian

Debian organise BIND différemment de RHEL :

```
/etc/bind/
├── named.conf              # Configuration principale (inclut les autres)
├── named.conf.options      # Options globales
├── named.conf.local        # Zones locales (à éditer)
├── named.conf.default-zones # Zones par défaut
├── db.local                # Zone localhost
├── db.127                  # Zone reverse localhost
└── zones/                  # Nos zones personnalisées (à créer)
```

---

## 4. Configuration des options

### Fichier /etc/bind/named.conf.options

```bash
# Sauvegarder
cp /etc/bind/named.conf.options /etc/bind/named.conf.options.bak

# Éditer
cat > /etc/bind/named.conf.options << 'EOF'
// ACL pour les réseaux autorisés
acl "trusted" {
    localhost;
    localnets;
    192.168.1.0/24;    // Adapter à votre réseau
};

options {
    directory "/var/cache/bind";

    // Écouter sur toutes les interfaces
    listen-on { any; };
    listen-on-v6 { any; };

    // Autoriser les requêtes
    allow-query { trusted; };
    allow-recursion { trusted; };
    allow-transfer { none; };

    // Forwarders (DNS upstream)
    forwarders {
        8.8.8.8;
        8.8.4.4;
    };

    // Sécurité
    recursion yes;
    dnssec-validation auto;

    // Cacher la version
    version "not disclosed";

    // Logging des requêtes
    querylog yes;
};
EOF
```

---

## 5. Configurer le logging

```bash
cat >> /etc/bind/named.conf << 'EOF'

// Logging personnalisé
logging {
    channel bind_log {
        file "/var/log/bind/bind.log" versions 3 size 5m;
        severity info;
        print-time yes;
        print-severity yes;
        print-category yes;
    };
    channel query_log {
        file "/var/log/bind/query.log" versions 3 size 10m;
        severity info;
        print-time yes;
    };
    category default { bind_log; };
    category queries { query_log; };
};
EOF

# Créer le répertoire de logs
mkdir -p /var/log/bind
chown bind:bind /var/log/bind
```

---

## 6. Définir les zones locales

### Fichier /etc/bind/named.conf.local

```bash
cat > /etc/bind/named.conf.local << 'EOF'
//
// Zones locales - Debian 12
//

// Zone forward - example.lan
zone "example.lan" {
    type master;
    file "/etc/bind/zones/db.example.lan";
    allow-update { none; };
};

// Zone reverse - 192.168.1.x
zone "1.168.192.in-addr.arpa" {
    type master;
    file "/etc/bind/zones/db.192.168.1";
    allow-update { none; };
};
EOF

# Créer le répertoire des zones
mkdir -p /etc/bind/zones
```

---

## 7. Créer la zone forward

```bash
cat > /etc/bind/zones/db.example.lan << 'EOF'
$TTL 86400
@   IN  SOA     ns1.example.lan. admin.example.lan. (
        2024120101  ; Serial (YYYYMMDDNN)
        3600        ; Refresh (1 heure)
        1800        ; Retry (30 min)
        604800      ; Expire (1 semaine)
        86400       ; Minimum TTL (1 jour)
)

; Serveurs de noms
@       IN  NS      ns1.example.lan.

; Enregistrements A (IPv4)
ns1     IN  A       192.168.1.10
dns     IN  CNAME   ns1

; Serveurs
srv-web     IN  A       192.168.1.20
srv-db      IN  A       192.168.1.21
srv-mail    IN  A       192.168.1.22

; Alias (CNAME)
www         IN  CNAME   srv-web
mysql       IN  CNAME   srv-db
mail        IN  CNAME   srv-mail

; Enregistrement MX (Mail)
@           IN  MX  10  srv-mail.example.lan.
EOF
```

---

## 8. Créer la zone reverse

```bash
cat > /etc/bind/zones/db.192.168.1 << 'EOF'
$TTL 86400
@   IN  SOA     ns1.example.lan. admin.example.lan. (
        2024120101  ; Serial
        3600        ; Refresh
        1800        ; Retry
        604800      ; Expire
        86400       ; Minimum TTL
)

; Serveurs de noms
@       IN  NS      ns1.example.lan.

; Enregistrements PTR (Reverse)
10      IN  PTR     ns1.example.lan.
20      IN  PTR     srv-web.example.lan.
21      IN  PTR     srv-db.example.lan.
22      IN  PTR     srv-mail.example.lan.
EOF
```

---

## 9. Permissions et vérification

### Appliquer les permissions

```bash
# Propriétaire bind
chown -R bind:bind /etc/bind/zones

# Permissions
chmod 640 /etc/bind/zones/*
```

### Vérifier la configuration

```bash
# Vérifier la syntaxe globale
named-checkconf

# Vérifier la zone forward
named-checkzone example.lan /etc/bind/zones/db.example.lan

# Vérifier la zone reverse
named-checkzone 1.168.192.in-addr.arpa /etc/bind/zones/db.192.168.1
```

**Résultat attendu :** `OK` pour chaque vérification.

---

## 10. Démarrer le service

```bash
# Redémarrer BIND9
systemctl restart bind9

# Activer au démarrage
systemctl enable bind9

# Vérifier le statut
systemctl status bind9

# Vérifier l'écoute sur le port 53
ss -ulnp | grep :53
ss -tlnp | grep :53
```

---

## 11. Tests DNS

### Depuis le serveur

```bash
# Test résolution forward
dig @localhost srv-web.example.lan

# Test résolution reverse
dig @localhost -x 192.168.1.20

# Test CNAME
dig @localhost www.example.lan

# Test MX
dig @localhost example.lan MX

# Requête courte
dig @localhost +short srv-web.example.lan

# Test avec nslookup
nslookup srv-web.example.lan localhost
```

### Configurer un client Debian

```bash
# Via /etc/resolv.conf (temporaire)
echo "nameserver 192.168.1.10" > /etc/resolv.conf

# Via NetworkManager (permanent)
nmcli con mod "Wired connection 1" ipv4.dns "192.168.1.10"
nmcli con up "Wired connection 1"

# Ou via /etc/network/interfaces
# dns-nameservers 192.168.1.10
```

---

## 12. Commandes de gestion

```bash
# Recharger la configuration
systemctl reload bind9

# Ou via rndc
rndc reload

# Recharger une zone spécifique
rndc reload example.lan

# Vider le cache
rndc flush

# Statistiques
rndc stats
cat /var/cache/bind/named.stats

# Logs en temps réel
tail -f /var/log/bind/query.log
```

---

## 13. Rotation des logs

```bash
cat > /etc/logrotate.d/bind << 'EOF'
/var/log/bind/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0640 bind bind
    postrotate
        /usr/sbin/rndc reopen
    endscript
}
EOF
```

---

## Différences Rocky 9 vs Debian 12

| Aspect | Rocky 9 | Debian 12 |
|--------|---------|-----------|
| Paquet | `bind` | `bind9` |
| Service | `named` | `bind9` |
| Utilisateur | `named` | `bind` |
| Config principale | `/etc/named.conf` | `/etc/bind/named.conf` |
| Répertoire zones | `/var/named/zones` | `/etc/bind/zones` |
| Cache | `/var/named` | `/var/cache/bind` |
| SELinux/AppArmor | SELinux | AppArmor |

---

## Dépannage

### BIND ne démarre pas

```bash
# Vérifier les logs
journalctl -u bind9 -n 50

# Vérifier la syntaxe
named-checkconf

# Mode debug
named -g -d 3
```

### AppArmor bloque BIND

```bash
# Vérifier le profil AppArmor
aa-status | grep named

# Si blocage, ajouter les chemins nécessaires
# /etc/apparmor.d/local/usr.sbin.named
```

### Résolution échoue depuis l'extérieur

```bash
# Vérifier le firewall
ufw status verbose

# Vérifier que BIND écoute sur toutes les interfaces
ss -ulnp | grep :53
# Doit afficher 0.0.0.0:53, pas 127.0.0.1:53
```

---

## Pour aller plus loin

- [DNS Bind Rocky 9](dns-bind-rocky9.md)
- [DHCP Server Debian 12](dhcp-debian12.md)
- [DNS + DHCP intégration](dns-dhcp-integration.md)

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale - Debian 12 + BIND 9.18 |
