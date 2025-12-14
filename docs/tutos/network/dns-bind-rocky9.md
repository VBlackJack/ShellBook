---
tags:
  - tutos
  - dns
  - bind
  - rocky-linux
  - network
---

# Serveur DNS Bind sur Rocky Linux 9

Configuration d'un serveur DNS autoritaire avec **BIND 9** (Berkeley Internet Name Domain).

| Composant | Version |
|-----------|---------|
| Rocky Linux | 9.x |
| BIND | 9.16 |

**Durée estimée :** 45 minutes

**Prérequis :**

- Rocky Linux 9 installé
- Accès root ou sudo
- IP statique configurée
- Nom de domaine à gérer (ex: `example.lan`)

---

## 1. Installation de BIND

```bash
# Installer BIND et les utilitaires
dnf install -y bind bind-utils

# Vérifier la version
named -v
```

---

## 2. Configuration du Firewall

```bash
# Autoriser le service DNS
firewall-cmd --permanent --add-service=dns

# Recharger
firewall-cmd --reload

# Vérifier
firewall-cmd --list-services
```

---

## 3. Configuration principale

### Fichier /etc/named.conf

```bash
# Sauvegarder la configuration originale
cp /etc/named.conf /etc/named.conf.bak

# Éditer la configuration
cat > /etc/named.conf << 'EOF'
//
// BIND Configuration - Rocky Linux 9
//

// ACL pour les réseaux autorisés
acl "trusted" {
    localhost;
    localnets;
    192.168.1.0/24;    // Adapter à votre réseau
};

options {
    listen-on port 53 { any; };
    listen-on-v6 port 53 { any; };

    directory       "/var/named";
    dump-file       "/var/named/data/cache_dump.db";
    statistics-file "/var/named/data/named_stats.txt";
    memstatistics-file "/var/named/data/named_mem_stats.txt";

    // Autoriser les requêtes depuis les réseaux de confiance
    allow-query     { trusted; };
    allow-recursion { trusted; };

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

    // Logging
    querylog yes;
};

// Logging
logging {
    channel default_log {
        file "/var/named/log/named.log" versions 3 size 5m;
        severity info;
        print-time yes;
        print-severity yes;
        print-category yes;
    };
    category default { default_log; };
    category queries { default_log; };
};

// Zone racine
zone "." IN {
    type hint;
    file "named.ca";
};

// Zones localhost
include "/etc/named.rfc1912.zones";
include "/etc/named.root.key";

// Zones personnalisées
include "/etc/named/zones.conf";
EOF

# Créer le répertoire de logs
mkdir -p /var/named/log
chown named:named /var/named/log
```

---

## 4. Définir les zones

### Fichier des zones

```bash
cat > /etc/named/zones.conf << 'EOF'
// Zone forward - example.lan
zone "example.lan" IN {
    type master;
    file "zones/db.example.lan";
    allow-update { none; };
};

// Zone reverse - 192.168.1.x
zone "1.168.192.in-addr.arpa" IN {
    type master;
    file "zones/db.192.168.1";
    allow-update { none; };
};
EOF

# Créer le répertoire des zones
mkdir -p /var/named/zones
```

---

## 5. Créer la zone forward

```bash
cat > /var/named/zones/db.example.lan << 'EOF'
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

## 6. Créer la zone reverse

```bash
cat > /var/named/zones/db.192.168.1 << 'EOF'
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

## 7. Permissions et vérification

### Appliquer les permissions

```bash
# Propriétaire named
chown -R named:named /var/named/zones

# Permissions
chmod 640 /var/named/zones/*
```

### Vérifier la configuration

```bash
# Vérifier la syntaxe de named.conf
named-checkconf /etc/named.conf

# Vérifier la zone forward
named-checkzone example.lan /var/named/zones/db.example.lan

# Vérifier la zone reverse
named-checkzone 1.168.192.in-addr.arpa /var/named/zones/db.192.168.1
```

**Résultat attendu :** `OK` pour chaque zone.

---

## 8. Démarrer le service

```bash
# Activer et démarrer BIND
systemctl enable --now named

# Vérifier le statut
systemctl status named

# Vérifier l'écoute sur le port 53
ss -ulnp | grep :53
ss -tlnp | grep :53
```

---

## 9. Tests DNS

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
```

### Depuis un client

```bash
# Configurer le client pour utiliser ce DNS
# /etc/resolv.conf ou via NetworkManager
nmcli con mod "Wired connection 1" ipv4.dns "192.168.1.10"
nmcli con up "Wired connection 1"

# Tester
nslookup srv-web.example.lan
ping srv-web.example.lan
```

---

## 10. Configuration SELinux

```bash
# Vérifier le contexte SELinux
ls -lZ /var/named/zones/

# Si nécessaire, restaurer le contexte
restorecon -Rv /var/named/

# Autoriser BIND à écrire (pour les zones dynamiques)
setsebool -P named_write_master_zones 1
```

---

## 11. Ajouter des enregistrements

### Procédure pour ajouter un hôte

1. Éditer le fichier de zone forward :
```bash
vim /var/named/zones/db.example.lan
```

2. Ajouter l'enregistrement :
```
nouveau-srv  IN  A  192.168.1.30
```

3. **Incrémenter le Serial** (obligatoire !)
```
2024120101  →  2024120102
```

4. Ajouter l'enregistrement reverse :
```bash
vim /var/named/zones/db.192.168.1
# Ajouter :
30      IN  PTR     nouveau-srv.example.lan.
```

5. Vérifier et recharger :
```bash
named-checkzone example.lan /var/named/zones/db.example.lan
systemctl reload named
```

---

## 12. Commandes utiles

```bash
# Recharger la configuration
systemctl reload named

# Recharger une zone spécifique
rndc reload example.lan

# Vider le cache
rndc flush

# Statistiques
rndc stats
cat /var/named/data/named_stats.txt

# Logs en temps réel
tail -f /var/named/log/named.log

# Debug des requêtes
rndc querylog on   # Activer
rndc querylog off  # Désactiver
```

---

## 13. Configuration DNS secondaire (optionnel)

### Sur le serveur primaire (master)

Modifier la zone dans `/etc/named/zones.conf` :
```
zone "example.lan" IN {
    type master;
    file "zones/db.example.lan";
    allow-transfer { 192.168.1.11; };  // IP du serveur secondaire
    also-notify { 192.168.1.11; };
};
```

### Sur le serveur secondaire (slave)

```bash
# /etc/named/zones.conf sur le secondaire
zone "example.lan" IN {
    type slave;
    file "slaves/db.example.lan";
    masters { 192.168.1.10; };  // IP du master
};
```

---

## Dépannage

### BIND ne démarre pas

```bash
# Vérifier les logs
journalctl -u named -n 50

# Vérifier la syntaxe
named-checkconf -z

# Mode debug
named -g -d 3
```

### Résolution échoue

```bash
# Vérifier que le port 53 est ouvert
firewall-cmd --list-all

# Vérifier SELinux
ausearch -m avc -ts recent

# Test direct
dig @127.0.0.1 example.lan
```

### Zone non chargée

```bash
# Vérifier les permissions
ls -la /var/named/zones/

# Vérifier le contexte SELinux
ls -lZ /var/named/zones/

# Forcer le rechargement
rndc reconfig
```

---

## Pour aller plus loin

- [DNS Bind Debian 12](dns-bind-debian12.md)
- [DHCP Server Rocky 9](dhcp-rocky9.md)
- [DNS + DHCP intégration](dns-dhcp-integration.md)

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale - Rocky 9 + BIND 9.16 |
