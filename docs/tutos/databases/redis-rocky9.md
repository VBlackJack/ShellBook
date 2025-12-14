---
tags:
  - tutos
  - databases
  - redis
  - cache
  - rocky
---

# Redis sur Rocky Linux 9

Installation et configuration de **Redis** comme cache et broker de messages.

| Composant | Version |
|-----------|---------|
| Rocky Linux | 9.x |
| Redis | 6.2+ / 7.x |

**Durée estimée :** 25 minutes

---

## Cas d'utilisation

| Usage | Description |
|-------|-------------|
| **Cache** | Sessions PHP, objets, pages |
| **Broker** | File de messages, pub/sub |
| **Base** | Stockage clé-valeur |
| **Compteurs** | Rate limiting, statistiques |

---

## 1. Installation

### Depuis les repos AppStream

```bash
dnf install -y redis

# Version
redis-server --version
```

### Depuis Remi (version récente)

```bash
dnf install -y https://rpms.remirepo.net/enterprise/remi-release-9.rpm
dnf module reset redis
dnf module enable redis:remi-7.2
dnf install -y redis
```

---

## 2. Configuration de base

```bash
cp /etc/redis/redis.conf /etc/redis/redis.conf.bak
vim /etc/redis/redis.conf
```

```ini
# Écouter sur toutes les interfaces (ou 127.0.0.1 pour local)
bind 0.0.0.0

# Port
port 6379

# Mot de passe
requirepass VotreMotDePasseSecurise

# Mode démon
daemonize no

# Fichier PID
pidfile /var/run/redis/redis.pid

# Logging
loglevel notice
logfile /var/log/redis/redis.log

# Bases de données
databases 16

# Persistance RDB
save 900 1
save 300 10
save 60 10000

# Fichier RDB
dbfilename dump.rdb
dir /var/lib/redis

# Mémoire max (50% de la RAM)
maxmemory 2gb
maxmemory-policy allkeys-lru

# Timeout connexion
timeout 300

# TCP keepalive
tcp-keepalive 300
```

---

## 3. Persistance

### RDB (snapshot)

```ini
# Sauvegarde si X modifications en Y secondes
save 900 1      # 1 modif en 15 min
save 300 10     # 10 modifs en 5 min
save 60 10000   # 10000 modifs en 1 min

rdbcompression yes
rdbchecksum yes
dbfilename dump.rdb
```

### AOF (Append Only File)

```ini
appendonly yes
appendfilename "appendonly.aof"
appendfsync everysec

# Réécriture automatique
auto-aof-rewrite-percentage 100
auto-aof-rewrite-min-size 64mb
```

### Hybride (recommandé)

```ini
aof-use-rdb-preamble yes
```

---

## 4. Démarrer Redis

```bash
systemctl enable --now redis
systemctl status redis
```

### Tester la connexion

```bash
redis-cli

# Avec authentification
redis-cli -a VotreMotDePasseSecurise

# Commandes de test
127.0.0.1:6379> AUTH VotreMotDePasseSecurise
127.0.0.1:6379> PING
PONG
127.0.0.1:6379> SET test "Hello Redis"
OK
127.0.0.1:6379> GET test
"Hello Redis"
127.0.0.1:6379> INFO
```

---

## 5. Firewall et SELinux

```bash
# Firewall
firewall-cmd --permanent --add-port=6379/tcp
firewall-cmd --reload

# SELinux (si accès réseau)
setsebool -P redis_enable_remote_connections on
```

---

## 6. Sécurisation

### Renommer les commandes dangereuses

```ini
# Dans redis.conf
rename-command FLUSHDB ""
rename-command FLUSHALL ""
rename-command DEBUG ""
rename-command CONFIG "CONFIG_b840fc02d524045429941cc15f59e41cb7be6c52"
```

### TLS (Redis 6+)

```bash
# Générer certificats
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/redis/redis.key \
    -out /etc/redis/redis.crt \
    -subj "/CN=redis.example.com"

chmod 600 /etc/redis/redis.key
chown redis:redis /etc/redis/redis.*
```

```ini
# redis.conf
tls-port 6380
port 0
tls-cert-file /etc/redis/redis.crt
tls-key-file /etc/redis/redis.key
tls-ca-cert-file /etc/redis/redis.crt
```

---

## 7. Redis Sentinel (haute disponibilité)

### Architecture

```
        ┌──────────────┐
        │  Sentinel 1  │
        └──────┬───────┘
               │
┌──────────────┼──────────────┐
│              │              │
▼              ▼              ▼
┌────────┐  ┌────────┐  ┌────────┐
│ Master │  │Replica1│  │Replica2│
└────────┘  └────────┘  └────────┘
```

### Configuration Replica

```ini
# Sur les réplicas
replicaof 192.168.1.10 6379
masterauth VotreMotDePasseSecurise
```

### Configuration Sentinel

```bash
cat > /etc/redis/sentinel.conf << 'EOF'
port 26379
daemonize yes
pidfile /var/run/redis/redis-sentinel.pid
logfile /var/log/redis/sentinel.log

sentinel monitor mymaster 192.168.1.10 6379 2
sentinel auth-pass mymaster VotreMotDePasseSecurise
sentinel down-after-milliseconds mymaster 5000
sentinel failover-timeout mymaster 60000
sentinel parallel-syncs mymaster 1
EOF

redis-sentinel /etc/redis/sentinel.conf
```

---

## 8. Redis Cluster (scalabilité)

```bash
# Créer 6 instances (3 masters, 3 replicas)
redis-cli --cluster create \
    192.168.1.10:6379 \
    192.168.1.11:6379 \
    192.168.1.12:6379 \
    192.168.1.10:6380 \
    192.168.1.11:6380 \
    192.168.1.12:6380 \
    --cluster-replicas 1 \
    -a VotreMotDePasseSecurise
```

---

## 9. Monitoring

### Commandes INFO

```bash
redis-cli INFO memory
redis-cli INFO replication
redis-cli INFO stats
redis-cli INFO clients
```

### Redis CLI monitor

```bash
redis-cli MONITOR
```

### Métriques clés

```bash
# Mémoire utilisée
redis-cli INFO memory | grep used_memory_human

# Connexions
redis-cli INFO clients | grep connected_clients

# Hits/Misses cache
redis-cli INFO stats | grep keyspace
```

---

## 10. Intégration applications

### PHP (php-redis)

```bash
dnf install -y php-redis
systemctl restart php-fpm
```

```php
<?php
$redis = new Redis();
$redis->connect('127.0.0.1', 6379);
$redis->auth('VotreMotDePasseSecurise');

// Cache
$redis->set('key', 'value', 3600);
echo $redis->get('key');

// Sessions PHP
// Dans php.ini:
// session.save_handler = redis
// session.save_path = "tcp://127.0.0.1:6379?auth=password"
```

### Python

```python
import redis

r = redis.Redis(
    host='localhost',
    port=6379,
    password='VotreMotDePasseSecurise',
    decode_responses=True
)

r.set('foo', 'bar')
print(r.get('foo'))
```

---

## Commandes utiles

```bash
# Info complète
redis-cli INFO

# Statistiques mémoire
redis-cli MEMORY STATS

# Liste des clés
redis-cli KEYS "*"

# Supprimer une clé
redis-cli DEL key

# TTL d'une clé
redis-cli TTL key

# Flush base courante
redis-cli FLUSHDB

# Sauvegarde manuelle
redis-cli BGSAVE

# Dernière sauvegarde
redis-cli LASTSAVE
```

---

## Dépannage

```bash
# Logs
tail -f /var/log/redis/redis.log

# Status
systemctl status redis

# Test connexion
redis-cli PING

# Latence
redis-cli --latency

# Mémoire
redis-cli INFO memory
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
