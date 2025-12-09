---
tags:
  - mongodb
  - nosql
  - document
  - database
  - replication
---

# MongoDB

Guide d'administration MongoDB : installation, configuration, requêtes et réplication.

---

## Concepts Clés

```mermaid
flowchart LR
    subgraph "Structure MongoDB"
        DB[(Database)] --> C1[Collection 1]
        DB --> C2[Collection 2]
        C1 --> D1[Document JSON]
        C1 --> D2[Document JSON]
        C2 --> D3[Document JSON]
    end
```

| Concept SQL | Équivalent MongoDB |
|-------------|-------------------|
| Database | Database |
| Table | Collection |
| Row | Document (JSON/BSON) |
| Column | Field |
| Primary Key | `_id` (automatique) |
| JOIN | `$lookup` / Embedding |

---

## Installation

=== "RHEL/Rocky 9"

    ```bash
    # Ajouter le repo MongoDB 7.0
    cat << 'EOF' | sudo tee /etc/yum.repos.d/mongodb-org-7.0.repo
    [mongodb-org-7.0]
    name=MongoDB Repository
    baseurl=https://repo.mongodb.org/yum/redhat/9/mongodb-org/7.0/x86_64/
    gpgcheck=1
    enabled=1
    gpgkey=https://pgp.mongodb.com/server-7.0.asc
    EOF

    # Installer MongoDB
    sudo dnf install -y mongodb-org

    # Démarrer et activer
    sudo systemctl enable --now mongod

    # Vérifier
    mongosh --eval "db.runCommand({ping: 1})"
    ```

=== "Debian/Ubuntu"

    ```bash
    # Importer la clé GPG
    curl -fsSL https://pgp.mongodb.com/server-7.0.asc | \
        sudo gpg -o /usr/share/keyrings/mongodb-server-7.0.gpg --dearmor

    # Ajouter le repo (Ubuntu 22.04)
    echo "deb [ signed-by=/usr/share/keyrings/mongodb-server-7.0.gpg ] https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/7.0 multiverse" | \
        sudo tee /etc/apt/sources.list.d/mongodb-org-7.0.list

    # Installer
    sudo apt update
    sudo apt install -y mongodb-org

    # Démarrer
    sudo systemctl enable --now mongod
    ```

=== "Docker"

    ```bash
    # Lancement avec authentification
    docker run -d \
      --name mongodb \
      -e MONGO_INITDB_ROOT_USERNAME=admin \
      -e MONGO_INITDB_ROOT_PASSWORD=secretpassword \
      -v mongodb_data:/data/db \
      -p 27017:27017 \
      mongo:7

    # Connexion
    docker exec -it mongodb mongosh -u admin -p secretpassword
    ```

---

## Configuration

### Fichier de Configuration

```yaml
# /etc/mongod.conf

# Stockage
storage:
  dbPath: /var/lib/mongo
  journal:
    enabled: true
  wiredTiger:
    engineConfig:
      cacheSizeGB: 2  # 50% RAM - 1GB, ajuster selon serveur

# Logs
systemLog:
  destination: file
  logAppend: true
  path: /var/log/mongodb/mongod.log
  logRotate: reopen

# Réseau
net:
  port: 27017
  bindIp: 127.0.0.1  # localhost uniquement
  # bindIp: 0.0.0.0  # Toutes les interfaces (avec auth!)
  maxIncomingConnections: 1000

# Sécurité
security:
  authorization: enabled  # ACTIVER EN PRODUCTION

# Processus
processManagement:
  timeZoneInfo: /usr/share/zoneinfo
  fork: true
  pidFilePath: /var/run/mongodb/mongod.pid

# Réplication (si replica set)
# replication:
#   replSetName: rs0
```

### Activer l'Authentification

```bash
# 1. Connexion sans auth (première fois)
mongosh

# 2. Créer l'admin
use admin
db.createUser({
  user: "admin",
  pwd: "strong_admin_password",
  roles: [ { role: "userAdminAnyDatabase", db: "admin" }, "readWriteAnyDatabase" ]
})

# 3. Activer l'auth dans mongod.conf
# security:
#   authorization: enabled

# 4. Redémarrer MongoDB
sudo systemctl restart mongod

# 5. Connexion avec auth
mongosh -u admin -p strong_admin_password --authenticationDatabase admin
```

---

## Gestion des Utilisateurs

### Créer des Utilisateurs

```javascript
// Connexion admin
use admin

// Créer un utilisateur pour une base spécifique
use myapp_db
db.createUser({
  user: "myapp_user",
  pwd: "user_password",
  roles: [
    { role: "readWrite", db: "myapp_db" }
  ]
})

// Utilisateur lecture seule
db.createUser({
  user: "readonly_user",
  pwd: "readonly_password",
  roles: [
    { role: "read", db: "myapp_db" }
  ]
})

// Utilisateur avec accès à plusieurs bases
use admin
db.createUser({
  user: "multi_db_user",
  pwd: "password",
  roles: [
    { role: "readWrite", db: "app1_db" },
    { role: "read", db: "app2_db" }
  ]
})
```

### Rôles Principaux

| Rôle | Description |
|------|-------------|
| `read` | Lecture seule |
| `readWrite` | Lecture et écriture |
| `dbAdmin` | Administration de la base (index, stats) |
| `dbOwner` | Tous les droits sur la base |
| `userAdmin` | Gestion des utilisateurs |
| `clusterAdmin` | Administration du cluster |
| `root` | Superadmin (tout) |

### Audit des Utilisateurs

```javascript
// Lister tous les utilisateurs
use admin
db.getUsers()

// Voir les rôles d'un utilisateur
db.getUser("myapp_user")

// Modifier les rôles
db.updateUser("myapp_user", {
  roles: [
    { role: "readWrite", db: "myapp_db" },
    { role: "read", db: "logs_db" }
  ]
})

// Supprimer un utilisateur
db.dropUser("old_user")
```

---

## Opérations CRUD

### Create (Insert)

```javascript
use myapp_db

// Insérer un document
db.users.insertOne({
  name: "John Doe",
  email: "john@example.com",
  age: 30,
  roles: ["user", "admin"],
  created_at: new Date()
})

// Insérer plusieurs documents
db.users.insertMany([
  { name: "Jane Doe", email: "jane@example.com", age: 28 },
  { name: "Bob Smith", email: "bob@example.com", age: 35 }
])
```

### Read (Find)

```javascript
// Tous les documents
db.users.find()

// Avec filtre
db.users.find({ age: { $gte: 30 } })

// Un seul document
db.users.findOne({ email: "john@example.com" })

// Projection (champs spécifiques)
db.users.find({}, { name: 1, email: 1, _id: 0 })

// Tri et limite
db.users.find().sort({ age: -1 }).limit(10)

// Comptage
db.users.countDocuments({ age: { $gte: 30 } })
```

### Opérateurs de Requête

```javascript
// Comparaison
db.users.find({ age: { $eq: 30 } })   // Égal
db.users.find({ age: { $ne: 30 } })   // Différent
db.users.find({ age: { $gt: 25 } })   // Plus grand
db.users.find({ age: { $gte: 25 } })  // Plus grand ou égal
db.users.find({ age: { $lt: 40 } })   // Plus petit
db.users.find({ age: { $lte: 40 } })  // Plus petit ou égal
db.users.find({ age: { $in: [25, 30, 35] } })  // Dans la liste

// Logiques
db.users.find({ $and: [{ age: { $gte: 25 } }, { age: { $lte: 35 } }] })
db.users.find({ $or: [{ age: 25 }, { age: 30 }] })
db.users.find({ age: { $not: { $gt: 30 } } })

// Tableaux
db.users.find({ roles: "admin" })           // Contient "admin"
db.users.find({ roles: { $all: ["user", "admin"] } })  // Contient tous
db.users.find({ roles: { $size: 2 } })      // Taille exacte

// Existence
db.users.find({ phone: { $exists: true } })

// Regex
db.users.find({ name: { $regex: /^John/i } })
```

### Update

```javascript
// Mettre à jour un document
db.users.updateOne(
  { email: "john@example.com" },
  { $set: { age: 31, updated_at: new Date() } }
)

// Mettre à jour plusieurs documents
db.users.updateMany(
  { age: { $lt: 30 } },
  { $set: { category: "young" } }
)

// Incrémenter
db.users.updateOne(
  { email: "john@example.com" },
  { $inc: { login_count: 1 } }
)

// Ajouter à un tableau
db.users.updateOne(
  { email: "john@example.com" },
  { $push: { roles: "moderator" } }
)

// Retirer d'un tableau
db.users.updateOne(
  { email: "john@example.com" },
  { $pull: { roles: "admin" } }
)

// Upsert (insert si n'existe pas)
db.users.updateOne(
  { email: "new@example.com" },
  { $set: { name: "New User", age: 25 } },
  { upsert: true }
)
```

### Delete

```javascript
// Supprimer un document
db.users.deleteOne({ email: "john@example.com" })

// Supprimer plusieurs documents
db.users.deleteMany({ age: { $lt: 18 } })

// Supprimer tous les documents
db.users.deleteMany({})

// Supprimer la collection
db.users.drop()
```

---

## Index

### Création d'Index

```javascript
// Index simple
db.users.createIndex({ email: 1 })  // 1 = ASC, -1 = DESC

// Index unique
db.users.createIndex({ email: 1 }, { unique: true })

// Index composé
db.users.createIndex({ last_name: 1, first_name: 1 })

// Index TTL (expiration automatique)
db.sessions.createIndex(
  { created_at: 1 },
  { expireAfterSeconds: 3600 }  // Expire après 1 heure
)

// Index texte (full-text search)
db.articles.createIndex({ title: "text", content: "text" })

// Index partiel
db.users.createIndex(
  { email: 1 },
  { partialFilterExpression: { status: "active" } }
)
```

### Gestion des Index

```javascript
// Lister les index
db.users.getIndexes()

// Statistiques d'utilisation
db.users.aggregate([{ $indexStats: {} }])

// Supprimer un index
db.users.dropIndex("email_1")

// Supprimer tous les index (sauf _id)
db.users.dropIndexes()

// Analyser une requête
db.users.find({ email: "john@example.com" }).explain("executionStats")
```

---

## Aggregation Framework

### Pipeline Basique

```javascript
db.orders.aggregate([
  // Stage 1: Filtrer
  { $match: { status: "completed" } },

  // Stage 2: Grouper
  { $group: {
    _id: "$customer_id",
    total_spent: { $sum: "$amount" },
    order_count: { $sum: 1 },
    avg_order: { $avg: "$amount" }
  }},

  // Stage 3: Trier
  { $sort: { total_spent: -1 } },

  // Stage 4: Limiter
  { $limit: 10 }
])
```

### Opérateurs d'Aggregation

```javascript
// $lookup (équivalent JOIN)
db.orders.aggregate([
  { $lookup: {
    from: "customers",
    localField: "customer_id",
    foreignField: "_id",
    as: "customer_info"
  }},
  { $unwind: "$customer_info" }
])

// $project (projection)
db.users.aggregate([
  { $project: {
    full_name: { $concat: ["$first_name", " ", "$last_name"] },
    email: 1,
    year_of_birth: { $subtract: [{ $year: new Date() }, "$age"] }
  }}
])

// $bucket (histogramme)
db.users.aggregate([
  { $bucket: {
    groupBy: "$age",
    boundaries: [0, 18, 30, 50, 100],
    default: "Other",
    output: { count: { $sum: 1 } }
  }}
])

// $facet (multi-pipelines)
db.products.aggregate([
  { $facet: {
    by_category: [
      { $group: { _id: "$category", count: { $sum: 1 } } }
    ],
    price_stats: [
      { $group: {
        _id: null,
        avg_price: { $avg: "$price" },
        max_price: { $max: "$price" }
      }}
    ]
  }}
])
```

---

## Réplication (Replica Set)

### Architecture

![MongoDB Replica Set Architecture](../assets/diagrams/mongodb-replica-set-architecture.jpeg)

```text
┌─────────────────────────────────────────────────────────┐
│                     Replica Set                          │
│                                                          │
│   ┌─────────┐     ┌─────────┐     ┌─────────┐          │
│   │ PRIMARY │────▶│SECONDARY│────▶│SECONDARY│          │
│   │  (R/W)  │     │  (Read) │     │  (Read) │          │
│   └─────────┘     └─────────┘     └─────────┘          │
│        │               │               │                │
│        └───────────────┴───────────────┘                │
│                   Oplog Sync                            │
└─────────────────────────────────────────────────────────┘
```

### Configuration Replica Set

```yaml
# /etc/mongod.conf sur CHAQUE nœud
replication:
  replSetName: rs0

net:
  bindIp: 0.0.0.0
  port: 27017

security:
  authorization: enabled
  keyFile: /etc/mongodb/keyfile  # Authentification interne
```

```bash
# Générer le keyfile (sur un nœud, puis copier)
openssl rand -base64 756 > /etc/mongodb/keyfile
chmod 400 /etc/mongodb/keyfile
chown mongod:mongod /etc/mongodb/keyfile
```

### Initialiser le Replica Set

```javascript
// Sur le PRIMARY
mongosh

// Initialiser
rs.initiate({
  _id: "rs0",
  members: [
    { _id: 0, host: "mongo1.example.com:27017", priority: 2 },
    { _id: 1, host: "mongo2.example.com:27017", priority: 1 },
    { _id: 2, host: "mongo3.example.com:27017", priority: 1 }
  ]
})

// Vérifier le statut
rs.status()

// Voir la configuration
rs.conf()

// Ajouter un membre
rs.add("mongo4.example.com:27017")

// Ajouter un arbiter (vote sans données)
rs.addArb("arbiter.example.com:27017")
```

### Monitoring Réplication

```javascript
// Statut détaillé
rs.status()

// Lag de réplication
rs.printSecondaryReplicationInfo()

// Oplog info
rs.printReplicationInfo()

// Forcer une élection (si PRIMARY down)
rs.stepDown()
```

---

## Sauvegarde et Restauration

### mongodump / mongorestore

```bash
# Sauvegarder toutes les bases
mongodump --uri="mongodb://admin:password@localhost:27017" \
  --out=/backup/mongodb/$(date +%Y%m%d)

# Sauvegarder une base spécifique
mongodump --uri="mongodb://admin:password@localhost:27017/myapp_db" \
  --out=/backup/mongodb/myapp_$(date +%Y%m%d)

# Avec compression
mongodump --uri="mongodb://admin:password@localhost:27017" \
  --gzip --archive=/backup/mongodb/full_$(date +%Y%m%d).gz

# Restaurer
mongorestore --uri="mongodb://admin:password@localhost:27017" \
  /backup/mongodb/20241130/

# Restaurer une base spécifique
mongorestore --uri="mongodb://admin:password@localhost:27017" \
  --nsInclude="myapp_db.*" \
  /backup/mongodb/20241130/

# Restaurer depuis archive compressée
mongorestore --uri="mongodb://admin:password@localhost:27017" \
  --gzip --archive=/backup/mongodb/full_20241130.gz
```

### Script de Backup

```bash
#!/bin/bash
# /opt/scripts/mongo_backup.sh

BACKUP_DIR="/backup/mongodb"
RETENTION_DAYS=7
DATE=$(date +%Y%m%d_%H%M%S)
MONGO_URI="mongodb://backup_user:password@localhost:27017"

mkdir -p "$BACKUP_DIR"

echo "Starting MongoDB backup..."
mongodump --uri="$MONGO_URI" \
  --gzip \
  --archive="$BACKUP_DIR/full_$DATE.gz"

if [ $? -eq 0 ]; then
    echo "✓ Backup completed: full_$DATE.gz"
    # Nettoyage
    find "$BACKUP_DIR" -name "*.gz" -mtime +$RETENTION_DAYS -delete
else
    echo "✗ Backup failed"
    exit 1
fi
```

---

## Monitoring

### Commandes de Diagnostic

```javascript
// Statut du serveur
db.serverStatus()

// Statistiques de la base
db.stats()

// Statistiques d'une collection
db.users.stats()

// Opérations en cours
db.currentOp()

// Tuer une opération
db.killOp(<opId>)

// Profiler (requêtes lentes)
db.setProfilingLevel(1, { slowms: 100 })  // Log requêtes > 100ms
db.system.profile.find().sort({ ts: -1 }).limit(10)
```

### Métriques Importantes

```javascript
// Connexions
db.serverStatus().connections

// Mémoire
db.serverStatus().mem
db.serverStatus().wiredTiger.cache

// Opérations
db.serverStatus().opcounters

// Réplication lag
rs.printSecondaryReplicationInfo()
```

### Logs

```bash
# Voir les logs
tail -f /var/log/mongodb/mongod.log

# Rotation des logs
mongosh --eval "db.adminCommand({ logRotate: 1 })"

# Changer le niveau de log
mongosh --eval "db.setLogLevel(1, 'query')"  # 0-5
```

---

## Sécurité

### Checklist

- [ ] Authentification activée (`security.authorization: enabled`)
- [ ] Bind IP restreint (pas 0.0.0.0 sans auth)
- [ ] Utilisateurs avec privilèges minimaux
- [ ] KeyFile pour replica set
- [ ] TLS/SSL pour les connexions distantes
- [ ] Firewall (port 27017)
- [ ] Audit logging activé (Enterprise)

### Configuration TLS

```yaml
# /etc/mongod.conf
net:
  tls:
    mode: requireTLS
    certificateKeyFile: /etc/mongodb/server.pem
    CAFile: /etc/mongodb/ca.pem
```

```bash
# Connexion TLS
mongosh --tls \
  --tlsCAFile /etc/mongodb/ca.pem \
  --tlsCertificateKeyFile /etc/mongodb/client.pem \
  "mongodb://localhost:27017"
```

---

## Voir Aussi

- [PostgreSQL](postgresql.md) - Base relationnelle
- [Redis](redis.md) - Cache et sessions
- [Haute Disponibilité](high-availability.md) - Architectures HA
- [Concepts BDD](../concepts/databases.md) - Types de bases de données
