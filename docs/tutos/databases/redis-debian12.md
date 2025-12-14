---
tags:
  - tutos
  - databases
  - redis
  - cache
  - debian
---

# Redis sur Debian 12

Installation de **Redis** sur Debian 12 Bookworm.

| Composant | Version |
|-----------|---------|
| Debian | 12 Bookworm |
| Redis | 7.0+ |

**Durée estimée :** 20 minutes

---

## 1. Installation

```bash
apt update
apt install -y redis-server

# Version
redis-server --version
```

---

## 2. Configuration

```bash
cp /etc/redis/redis.conf /etc/redis/redis.conf.bak
vim /etc/redis/redis.conf
```

```ini
# Écoute
bind 0.0.0.0
port 6379

# Sécurité
requirepass VotreMotDePasseSecurise

# Logging
loglevel notice
logfile /var/log/redis/redis-server.log

# Persistance
save 900 1
save 300 10
save 60 10000

appendonly yes
appendfsync everysec

# Mémoire
maxmemory 2gb
maxmemory-policy allkeys-lru

# Timeouts
timeout 300
tcp-keepalive 300
```

---

## 3. Démarrer

```bash
systemctl enable --now redis-server
systemctl status redis-server
```

---

## 4. Test

```bash
redis-cli -a VotreMotDePasseSecurise PING
# PONG

redis-cli -a VotreMotDePasseSecurise SET test "Hello"
redis-cli -a VotreMotDePasseSecurise GET test
```

---

## 5. Firewall

```bash
ufw allow 6379/tcp
ufw reload
```

---

## 6. Sécurisation

```ini
# Renommer commandes dangereuses
rename-command FLUSHDB ""
rename-command FLUSHALL ""
rename-command DEBUG ""
```

---

## 7. Réplication

### Master (aucun changement)

### Replica

```ini
replicaof 192.168.1.10 6379
masterauth VotreMotDePasseSecurise
```

```bash
systemctl restart redis-server

# Vérifier
redis-cli INFO replication
```

---

## 8. Sentinel

```bash
cat > /etc/redis/sentinel.conf << 'EOF'
port 26379
daemonize yes
logfile /var/log/redis/sentinel.log

sentinel monitor mymaster 192.168.1.10 6379 2
sentinel auth-pass mymaster VotreMotDePasseSecurise
sentinel down-after-milliseconds mymaster 5000
sentinel failover-timeout mymaster 60000
EOF

redis-sentinel /etc/redis/sentinel.conf
```

---

## 9. PHP Integration

```bash
apt install -y php-redis
systemctl restart php-fpm
```

```ini
; Sessions PHP via Redis
session.save_handler = redis
session.save_path = "tcp://127.0.0.1:6379?auth=VotreMotDePasseSecurise"
```

---

## Comparatif Rocky vs Debian

| Aspect | Rocky 9 | Debian 12 |
|--------|---------|-----------|
| Package | redis | redis-server |
| Service | redis | redis-server |
| Config | /etc/redis/redis.conf | /etc/redis/redis.conf |
| Version | 6.2 (7.x via Remi) | 7.0 |

---

## Commandes

```bash
redis-cli INFO                  # Infos
redis-cli KEYS "*"              # Lister clés
redis-cli GET key               # Lire
redis-cli SET key value 3600    # Écrire avec TTL
redis-cli DEL key               # Supprimer
redis-cli BGSAVE                # Sauvegarder
redis-cli MONITOR               # Debug temps réel
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
