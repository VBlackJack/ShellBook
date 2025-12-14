---
tags:
  - tutos
  - firewall
  - firewalld
  - security
  - rocky-linux
---

# Firewalld sur Rocky Linux 9

Configuration du firewall **firewalld** avec zones et services.

| Composant | Version |
|-----------|---------|
| Rocky Linux | 9.x |
| Firewalld | 1.x |

**Durée estimée :** 20 minutes

---

## 1. Vérifier l'installation

```bash
# Firewalld est installé par défaut
systemctl status firewalld

# Si non installé
dnf install -y firewalld
systemctl enable --now firewalld
```

---

## 2. Concepts de base

### Zones

| Zone | Description |
|------|-------------|
| `drop` | Tout est rejeté silencieusement |
| `block` | Tout est rejeté avec message ICMP |
| `public` | Réseau public non fiable (défaut) |
| `external` | NAT/masquerading activé |
| `dmz` | Zone démilitarisée |
| `work` | Réseau de travail |
| `home` | Réseau domestique |
| `internal` | Réseau interne |
| `trusted` | Tout est accepté |

---

## 3. Commandes de base

```bash
# État du firewall
firewall-cmd --state

# Zone par défaut
firewall-cmd --get-default-zone

# Zones actives
firewall-cmd --get-active-zones

# Lister la configuration
firewall-cmd --list-all

# Recharger
firewall-cmd --reload
```

---

## 4. Gérer les services

```bash
# Lister les services disponibles
firewall-cmd --get-services

# Ajouter un service (temporaire)
firewall-cmd --add-service=http

# Ajouter un service (permanent)
firewall-cmd --permanent --add-service=http
firewall-cmd --permanent --add-service=https

# Supprimer un service
firewall-cmd --permanent --remove-service=cockpit

# Appliquer les changements permanents
firewall-cmd --reload

# Vérifier
firewall-cmd --list-services
```

---

## 5. Gérer les ports

```bash
# Ajouter un port
firewall-cmd --permanent --add-port=8080/tcp
firewall-cmd --permanent --add-port=8443/tcp

# Plage de ports
firewall-cmd --permanent --add-port=3000-3100/tcp

# Port UDP
firewall-cmd --permanent --add-port=161/udp

# Supprimer
firewall-cmd --permanent --remove-port=8080/tcp

# Lister les ports
firewall-cmd --list-ports
```

---

## 6. Règles riches (rich rules)

```bash
# Autoriser une IP spécifique
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="192.168.1.100" accept'

# Autoriser un réseau pour un service
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="192.168.1.0/24" service name="ssh" accept'

# Bloquer une IP
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="10.0.0.50" reject'

# Limiter le rate (protection DDoS)
firewall-cmd --permanent --add-rich-rule='rule service name="ssh" limit value="10/m" accept'

# Logging
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="192.168.1.0/24" service name="ssh" log prefix="SSH-ACCESS: " level="info" accept'

# Lister les rich rules
firewall-cmd --list-rich-rules

firewall-cmd --reload
```

---

## 7. Zones et interfaces

```bash
# Assigner une interface à une zone
firewall-cmd --permanent --zone=internal --change-interface=eth1

# Définir la zone par défaut
firewall-cmd --set-default-zone=public

# Lister les interfaces d'une zone
firewall-cmd --zone=public --list-interfaces

# Configuration par zone
firewall-cmd --zone=internal --list-all
```

---

## 8. Masquerading et forwarding

```bash
# Activer le masquerading (NAT)
firewall-cmd --permanent --zone=external --add-masquerade

# Port forwarding
firewall-cmd --permanent --add-forward-port=port=80:proto=tcp:toport=8080

# Forwarding vers une autre machine
firewall-cmd --permanent --add-forward-port=port=80:proto=tcp:toaddr=192.168.1.100:toport=80

# Activer le forwarding IP
echo 'net.ipv4.ip_forward = 1' >> /etc/sysctl.conf
sysctl -p
```

---

## 9. Direct rules (iptables)

```bash
# Ajouter une règle iptables directe
firewall-cmd --permanent --direct --add-rule ipv4 filter INPUT 0 -p tcp --dport 9999 -j ACCEPT

# Lister les règles directes
firewall-cmd --direct --get-all-rules
```

---

## 10. Configuration d'un serveur type

### Serveur Web

```bash
firewall-cmd --permanent --add-service=http
firewall-cmd --permanent --add-service=https
firewall-cmd --reload
```

### Serveur de base de données

```bash
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="192.168.1.0/24" port port="3306" protocol="tcp" accept'
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="192.168.1.0/24" port port="5432" protocol="tcp" accept'
firewall-cmd --reload
```

### Serveur complet

```bash
# Services standards
firewall-cmd --permanent --add-service=ssh
firewall-cmd --permanent --add-service=http
firewall-cmd --permanent --add-service=https
firewall-cmd --permanent --add-service=dns
firewall-cmd --permanent --add-service=ntp

# Limiter SSH
firewall-cmd --permanent --add-rich-rule='rule service name="ssh" limit value="5/m" accept'

# Recharger
firewall-cmd --reload
firewall-cmd --list-all
```

---

## 11. Créer un service personnalisé

```bash
# Créer le fichier de service
cat > /etc/firewalld/services/myapp.xml << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<service>
  <short>MyApp</short>
  <description>Mon application personnalisée</description>
  <port protocol="tcp" port="9000"/>
  <port protocol="tcp" port="9001"/>
</service>
EOF

# Recharger et utiliser
firewall-cmd --reload
firewall-cmd --permanent --add-service=myapp
firewall-cmd --reload
```

---

## 12. Sauvegarde et restauration

```bash
# Sauvegarder
cp -r /etc/firewalld /backup/firewalld-$(date +%Y%m%d)

# Ou exporter
firewall-cmd --list-all > /backup/firewall-rules.txt

# Runtime vers permanent
firewall-cmd --runtime-to-permanent
```

---

## Dépannage

```bash
# Logs firewalld
journalctl -u firewalld -f

# Mode debug
firewall-cmd --set-log-denied=all
# Voir les rejets dans: journalctl -k | grep REJECT

# Désactiver temporairement
systemctl stop firewalld
# ⚠️ Attention en production!

# Reset complet
firewall-cmd --complete-reload
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
