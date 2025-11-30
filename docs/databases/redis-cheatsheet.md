---
tags:
  - redis
  - cheatsheet
  - cache
  - nosql
---

# Redis Survival Guide

Commandes essentielles pour survivre en production Redis.

---

## Connexion

```bash
# Connexion locale
redis-cli

# Avec mot de passe
redis-cli -a password

# Connexion distante
redis-cli -h host -p 6379 -a password

# Sélectionner une base (0-15)
redis-cli -n 1

# Exécuter une commande
redis-cli PING

# Mode interactif avec auth
redis-cli
> AUTH password
```

---

## Commandes de Base

| Commande | Description |
|----------|-------------|
| `PING` | Test connexion (PONG) |
| `INFO` | Infos serveur |
| `INFO memory` | Infos mémoire |
| `INFO replication` | Infos réplication |
| `DBSIZE` | Nombre de clés |
| `SELECT n` | Changer de base (0-15) |
| `FLUSHDB` | Vider la base courante |
| `FLUSHALL` | Vider toutes les bases |
| `KEYS *` | Lister les clés (ATTENTION prod!) |
| `SCAN 0` | Parcourir les clés (safe) |

---

## Types de Données

### Strings

```bash
# Set / Get
SET key "value"
GET key

# Avec expiration
SET session:123 "data" EX 3600    # 1 heure
SETEX session:123 3600 "data"     # Équivalent

# Incrémenter
SET counter 0
INCR counter          # 1
INCRBY counter 10     # 11
DECR counter          # 10

# Vérifier existence
EXISTS key            # 1 ou 0

# TTL
TTL key               # Secondes restantes
PERSIST key           # Supprimer le TTL

# Supprimer
DEL key
DEL key1 key2 key3
```

### Hashes

```bash
# Set champs
HSET user:1 name "John" email "john@test.com" age 30

# Get un champ
HGET user:1 name

# Get tous les champs
HGETALL user:1

# Incrémenter un champ
HINCRBY user:1 age 1

# Existe ?
HEXISTS user:1 email

# Supprimer un champ
HDEL user:1 email
```

### Lists

```bash
# Ajouter
LPUSH queue "item1"      # Début
RPUSH queue "item2"      # Fin

# Récupérer et supprimer
LPOP queue               # Premier
RPOP queue               # Dernier
BLPOP queue 30           # Blocking (attendre 30s)

# Voir les éléments
LRANGE queue 0 -1        # Tous
LLEN queue               # Longueur
```

### Sets

```bash
# Ajouter
SADD tags "redis" "database" "cache"

# Membres
SMEMBERS tags

# Est membre ?
SISMEMBER tags "redis"   # 1 ou 0

# Opérations
SINTER set1 set2         # Intersection
SUNION set1 set2         # Union
SDIFF set1 set2          # Différence

# Supprimer
SREM tags "cache"
```

### Sorted Sets

```bash
# Ajouter avec score
ZADD leaderboard 100 "player1" 250 "player2"

# Top N
ZREVRANGE leaderboard 0 2 WITHSCORES

# Rang d'un membre
ZREVRANK leaderboard "player2"

# Incrémenter score
ZINCRBY leaderboard 50 "player1"

# Compter par score
ZCOUNT leaderboard 100 200
```

---

## Pub/Sub

```bash
# Terminal 1 : S'abonner
SUBSCRIBE channel

# Terminal 2 : Publier
PUBLISH channel "message"

# Pattern matching
PSUBSCRIBE news:*
```

---

## Expiration & TTL

```bash
# Définir expiration
EXPIRE key 3600          # En secondes
PEXPIRE key 3600000      # En millisecondes
EXPIREAT key 1735689600  # Timestamp Unix

# Voir TTL
TTL key                  # -1 = pas d'expiration, -2 = n'existe pas
PTTL key                 # En millisecondes

# Supprimer expiration
PERSIST key
```

---

## Transactions

```bash
# Transaction basique
MULTI
SET key1 "value1"
SET key2 "value2"
INCR counter
EXEC

# Annuler
MULTI
SET key "value"
DISCARD

# Watch (optimistic locking)
WATCH key
MULTI
SET key "newvalue"
EXEC                     # Échoue si key a changé
```

---

## Scripting Lua

```bash
# Script inline
EVAL "return redis.call('GET', KEYS[1])" 1 mykey

# Incrémenter si existe
EVAL "if redis.call('EXISTS', KEYS[1]) == 1 then return redis.call('INCR', KEYS[1]) else return nil end" 1 counter
```

---

## Monitoring

```bash
# Infos complètes
INFO

# Mémoire
INFO memory
# used_memory_human: 1.5G
# maxmemory_human: 4G

# Clients connectés
INFO clients
CLIENT LIST

# Statistiques
INFO stats

# Commandes par seconde
INFO stats | grep instantaneous_ops_per_sec

# Slow log
SLOWLOG GET 10
SLOWLOG LEN
SLOWLOG RESET

# Monitor en temps réel (ATTENTION perf!)
MONITOR
```

---

## Réplication

```bash
# Info réplication
INFO replication

# Sur le replica
REPLICAOF host 6379
REPLICAOF NO ONE        # Promouvoir en master

# Statut
INFO replication
# role:master ou role:slave
# connected_slaves:2
```

---

## Sentinel

```bash
# Connexion Sentinel
redis-cli -p 26379

# Info masters
SENTINEL masters

# Info replicas
SENTINEL slaves mymaster

# Adresse du master actuel
SENTINEL get-master-addr-by-name mymaster

# Forcer failover
SENTINEL failover mymaster
```

---

## Cluster

```bash
# Info cluster
CLUSTER INFO

# Nœuds
CLUSTER NODES

# Slots
CLUSTER SLOTS

# Connexion cluster mode
redis-cli -c -h host -p 6379
```

---

## Backup

```bash
# Déclencher un snapshot RDB
BGSAVE

# Dernier save réussi
LASTSAVE

# Réécrire AOF
BGREWRITEAOF

# Copier le dump
cp /var/lib/redis/dump.rdb /backup/redis_$(date +%Y%m%d).rdb
```

---

## Configuration

```bash
# Voir un paramètre
CONFIG GET maxmemory
CONFIG GET *            # Tous

# Modifier (runtime)
CONFIG SET maxmemory 2gb
CONFIG SET maxmemory-policy allkeys-lru

# Sauver la config
CONFIG REWRITE
```

---

## Sécurité

```bash
# Authentification
AUTH password

# Changer le mot de passe (runtime)
CONFIG SET requirepass newpassword

# Renommer commandes dangereuses (dans redis.conf)
# rename-command FLUSHALL ""
# rename-command CONFIG ""

# ACL (Redis 6+)
ACL LIST
ACL SETUSER myuser on >password ~* +@all
```

---

## Troubleshooting Express

| Problème | Commande |
|----------|----------|
| Redis down | `redis-cli PING` |
| Mémoire pleine | `INFO memory`, `CONFIG GET maxmemory-policy` |
| Connexions | `INFO clients`, `CLIENT LIST` |
| Slow queries | `SLOWLOG GET 10` |
| Réplication lag | `INFO replication` |
| Keys bloquantes | `SCAN 0 MATCH pattern* COUNT 100` |
| Évictions | `INFO stats` (evicted_keys) |

### Calcul Hit Ratio

```bash
redis-cli INFO stats | grep -E "keyspace_hits|keyspace_misses"
# hit_ratio = hits / (hits + misses) * 100
# Devrait être > 90%
```

### Mémoire par Type

```bash
redis-cli --bigkeys
# Trouve les plus grosses clés par type
```

### Analyse Mémoire

```bash
redis-cli MEMORY DOCTOR
redis-cli MEMORY STATS
redis-cli MEMORY USAGE mykey
```

---

## Patterns Courants

### Cache avec TTL

```bash
SET cache:user:123 "{...}" EX 3600
GET cache:user:123
```

### Rate Limiting

```bash
# Incrémenter et expirer
INCR rate:user:123
EXPIRE rate:user:123 60

# Vérifier
GET rate:user:123    # Si > 100, bloquer
```

### Session Store

```bash
HSET session:abc123 user_id 1 expires 1735689600
EXPIRE session:abc123 3600
HGETALL session:abc123
```

### Queue (FIFO)

```bash
RPUSH queue:jobs '{"task": "send_email"}'
BLPOP queue:jobs 30     # Worker attend 30s
```

---

## Voir Aussi

- [Redis Guide Complet](redis.md)
- [Haute Disponibilité](high-availability.md)
