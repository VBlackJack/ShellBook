---
tags:
  - tutos
  - ntp
  - chrony
  - time
  - rocky
---

# Chrony NTP sur Rocky Linux 9

Configuration de **Chrony** pour la synchronisation temps sur Rocky Linux 9.

| Composant | Version |
|-----------|---------|
| Rocky Linux | 9.x |
| Chrony | 4.x |

**Durée estimée :** 15 minutes

---

## Pourquoi la synchronisation temps ?

- Logs cohérents entre serveurs
- Authentification Kerberos/AD
- Certificats SSL (validité)
- Réplication bases de données
- Clusters (Kubernetes, Galera...)

---

## 1. Installation

```bash
# Chrony est installé par défaut sur Rocky 9
dnf install -y chrony

systemctl enable --now chronyd
systemctl status chronyd
```

---

## 2. Configuration client NTP

### Utiliser les serveurs publics

```bash
vim /etc/chrony.conf
```

```ini
# Serveurs NTP publics (pool.ntp.org)
pool 2.rocky.pool.ntp.org iburst

# Ou serveurs spécifiques
# server ntp1.example.com iburst
# server ntp2.example.com iburst

# Fichier drift
driftfile /var/lib/chrony/drift

# Autoriser les grandes corrections au démarrage
makestep 1.0 3

# Activer RTC sync
rtcsync

# Logs
logdir /var/log/chrony
```

```bash
systemctl restart chronyd
```

---

## 3. Configuration serveur NTP

Pour servir l'heure aux clients du réseau :

```bash
vim /etc/chrony.conf
```

```ini
# Sources externes
pool 2.rocky.pool.ntp.org iburst

# Servir l'heure au réseau local
allow 192.168.1.0/24
allow 10.0.0.0/8

# Mode serveur local (si perte connexion Internet)
local stratum 10

driftfile /var/lib/chrony/drift
makestep 1.0 3
rtcsync
logdir /var/log/chrony
```

### Firewall

```bash
firewall-cmd --permanent --add-service=ntp
firewall-cmd --reload
```

---

## 4. Commandes de gestion

### Status

```bash
# Sources NTP
chronyc sources

# Détails des sources
chronyc sources -v

# Tracking (état sync)
chronyc tracking

# Activité
chronyc activity
```

### Forcer la synchronisation

```bash
# Sync immédiate
chronyc makestep

# Burst de requêtes
chronyc burst 4/4
```

### Clients connectés (mode serveur)

```bash
chronyc clients
```

---

## 5. Vérification

```bash
# État du service
systemctl status chronyd

# Sources synchronisées
chronyc sources

# ^ = serveur sélectionné
# * = source actuelle
# + = source candidate
# - = source non utilisée
# ? = source en test

# Offset et précision
chronyc tracking | grep -E "Stratum|System time|Last offset"

# Date système
timedatectl
```

---

## 6. Configuration avancée

### Authentification NTP (NTS)

```ini
# Dans /etc/chrony.conf
server time.cloudflare.com iburst nts
server nts.sth1.ntp.se iburst nts

# Répertoire pour cookies NTS
ntsdumpdir /var/lib/chrony
```

### Serveur NTP interne avec GPS (stratum 1)

```ini
# Référence GPS
refclock SHM 0 refid GPS precision 1e-1 offset 0.9999
refclock SHM 1 refid PPS precision 1e-9

# Servir comme stratum 1
local stratum 1
```

---

## 7. Logs et debug

```bash
# Activer les logs détaillés
vim /etc/chrony.conf
```

```ini
log tracking measurements statistics
logdir /var/log/chrony
```

```bash
systemctl restart chronyd

# Voir les logs
cat /var/log/chrony/tracking.log
cat /var/log/chrony/measurements.log
```

---

## 8. Intégration systemd-timesyncd

Rocky 9 utilise Chrony par défaut, pas timesyncd. Vérifier :

```bash
# Chrony doit être actif
systemctl status chronyd

# timesyncd doit être inactif
systemctl status systemd-timesyncd
```

---

## Dépannage

| Problème | Solution |
|----------|----------|
| No sources | Vérifier réseau, DNS, firewall |
| Large offset | `chronyc makestep` |
| Stratum 16 | Pas de source valide |

```bash
# Debug
chronyc sources -v
chronyc tracking
journalctl -u chronyd -f

# Tester connectivité NTP
chronyd -Q 'server pool.ntp.org iburst'
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
