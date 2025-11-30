---
tags:
  - mongodb
  - cheatsheet
  - nosql
---

# MongoDB Survival Guide

Commandes essentielles pour survivre en production MongoDB.

---

## Connexion

```bash
# Connexion locale
mongosh

# Connexion avec auth
mongosh -u admin -p password --authenticationDatabase admin

# Connexion distante
mongosh "mongodb://user:password@host:27017/dbname"

# Connexion replica set
mongosh "mongodb://host1:27017,host2:27017,host3:27017/dbname?replicaSet=rs0"

# Exécuter une commande
mongosh --eval "db.serverStatus()"
```

---

## Commandes Shell

| Commande | Description |
|----------|-------------|
| `show dbs` | Lister les bases |
| `use dbname` | Sélectionner une base |
| `show collections` | Lister les collections |
| `db.stats()` | Stats de la base |
| `db.coll.stats()` | Stats d'une collection |
| `db.coll.getIndexes()` | Index d'une collection |
| `db.getUsers()` | Lister les users |
| `db.currentOp()` | Opérations en cours |
| `db.serverStatus()` | Statut serveur |
| `exit` | Quitter |

---

## CRUD Rapide

### Create

```javascript
// Insérer un document
db.users.insertOne({ name: "John", age: 30 })

// Insérer plusieurs
db.users.insertMany([
  { name: "Jane", age: 25 },
  { name: "Bob", age: 35 }
])
```

### Read

```javascript
// Tous les documents
db.users.find()

// Avec filtre
db.users.find({ age: { $gte: 30 } })

// Un seul
db.users.findOne({ name: "John" })

// Projection
db.users.find({}, { name: 1, _id: 0 })

// Tri + limite
db.users.find().sort({ age: -1 }).limit(5)

// Count
db.users.countDocuments({ age: { $gte: 30 } })
```

### Update

```javascript
// Modifier un document
db.users.updateOne(
  { name: "John" },
  { $set: { age: 31 } }
)

// Modifier plusieurs
db.users.updateMany(
  { age: { $lt: 30 } },
  { $set: { category: "young" } }
)

// Incrémenter
db.users.updateOne({ name: "John" }, { $inc: { age: 1 } })

// Ajouter à un array
db.users.updateOne({ name: "John" }, { $push: { tags: "vip" } })

// Upsert
db.users.updateOne({ name: "New" }, { $set: { age: 20 } }, { upsert: true })
```

### Delete

```javascript
// Supprimer un
db.users.deleteOne({ name: "John" })

// Supprimer plusieurs
db.users.deleteMany({ age: { $lt: 18 } })

// Supprimer tous
db.users.deleteMany({})

// Drop collection
db.users.drop()
```

---

## Opérateurs de Requête

| Opérateur | Exemple | Description |
|-----------|---------|-------------|
| `$eq` | `{ age: { $eq: 30 } }` | Égal |
| `$ne` | `{ age: { $ne: 30 } }` | Différent |
| `$gt` | `{ age: { $gt: 25 } }` | Plus grand |
| `$gte` | `{ age: { $gte: 25 } }` | Plus grand ou égal |
| `$lt` | `{ age: { $lt: 40 } }` | Plus petit |
| `$lte` | `{ age: { $lte: 40 } }` | Plus petit ou égal |
| `$in` | `{ age: { $in: [25, 30] } }` | Dans la liste |
| `$nin` | `{ age: { $nin: [25, 30] } }` | Pas dans la liste |
| `$and` | `{ $and: [{...}, {...}] }` | ET logique |
| `$or` | `{ $or: [{...}, {...}] }` | OU logique |
| `$exists` | `{ phone: { $exists: true } }` | Champ existe |
| `$regex` | `{ name: { $regex: /^J/i } }` | Expression régulière |

---

## Index

```javascript
// Créer un index
db.users.createIndex({ email: 1 })

// Index unique
db.users.createIndex({ email: 1 }, { unique: true })

// Index composé
db.users.createIndex({ lastName: 1, firstName: 1 })

// Index TTL (expiration auto)
db.sessions.createIndex({ createdAt: 1 }, { expireAfterSeconds: 3600 })

// Index text
db.articles.createIndex({ title: "text", content: "text" })

// Lister les index
db.users.getIndexes()

// Supprimer un index
db.users.dropIndex("email_1")

// Analyser une requête
db.users.find({ email: "test@test.com" }).explain("executionStats")
```

---

## Aggregation

```javascript
// Pipeline simple
db.orders.aggregate([
  { $match: { status: "completed" } },
  { $group: { _id: "$customerId", total: { $sum: "$amount" } } },
  { $sort: { total: -1 } },
  { $limit: 10 }
])

// Lookup (JOIN)
db.orders.aggregate([
  { $lookup: {
      from: "customers",
      localField: "customerId",
      foreignField: "_id",
      as: "customer"
  }},
  { $unwind: "$customer" }
])

// Count par groupe
db.users.aggregate([
  { $group: { _id: "$country", count: { $sum: 1 } } }
])
```

---

## Utilisateurs

```javascript
// Créer un admin
use admin
db.createUser({
  user: "admin",
  pwd: "password",
  roles: ["userAdminAnyDatabase", "readWriteAnyDatabase"]
})

// Créer un user pour une base
use mydb
db.createUser({
  user: "myuser",
  pwd: "password",
  roles: [{ role: "readWrite", db: "mydb" }]
})

// User read-only
db.createUser({
  user: "readonly",
  pwd: "password",
  roles: [{ role: "read", db: "mydb" }]
})

// Lister les users
db.getUsers()

// Supprimer un user
db.dropUser("myuser")
```

---

## Backup & Restore

```bash
# Dump une base
mongodump --db mydb --out /backup/

# Dump avec auth
mongodump -u admin -p password --authenticationDatabase admin --db mydb --out /backup/

# Dump compressé
mongodump --db mydb --gzip --archive=/backup/mydb.gz

# Restore
mongorestore --db mydb /backup/mydb/

# Restore depuis archive
mongorestore --gzip --archive=/backup/mydb.gz

# Dump une collection
mongodump --db mydb --collection users --out /backup/
```

---

## Replica Set

```javascript
// Statut du replica set
rs.status()

// Configuration
rs.conf()

// Ajouter un membre
rs.add("host:27017")

// Ajouter un arbiter
rs.addArb("arbiter:27017")

// Retirer un membre
rs.remove("host:27017")

// Forcer une élection
rs.stepDown()

// Info réplication
rs.printReplicationInfo()
rs.printSecondaryReplicationInfo()
```

---

## Monitoring

```javascript
// Statut serveur
db.serverStatus()

// Opérations en cours
db.currentOp()

// Opérations lentes
db.currentOp({ "secs_running": { $gte: 5 } })

// Tuer une opération
db.killOp(opId)

// Profiler (slow queries)
db.setProfilingLevel(1, { slowms: 100 })
db.system.profile.find().sort({ ts: -1 }).limit(5)

// Stats mémoire
db.serverStatus().mem
db.serverStatus().wiredTiger.cache
```

---

## Requêtes Utiles

### Taille des Collections

```javascript
db.getCollectionNames().forEach(function(c) {
    var stats = db.getCollection(c).stats();
    print(c + ": " + Math.round(stats.size / 1024 / 1024) + " MB");
});
```

### Documents par Collection

```javascript
db.getCollectionNames().forEach(function(c) {
    print(c + ": " + db.getCollection(c).countDocuments());
});
```

### Connexions Actives

```javascript
db.serverStatus().connections
```

---

## Troubleshooting Express

| Problème | Commande |
|----------|----------|
| Serveur down | `db.runCommand({ ping: 1 })` |
| Opération bloquée | `db.currentOp()` puis `db.killOp(opId)` |
| Replica lag | `rs.printSecondaryReplicationInfo()` |
| Mémoire | `db.serverStatus().mem` |
| Slow queries | `db.setProfilingLevel(1); db.system.profile.find()` |
| Index missing | `db.coll.find({...}).explain("executionStats")` |
| Connexions | `db.serverStatus().connections` |

---

## Voir Aussi

- [MongoDB Guide Complet](mongodb.md)
- [Haute Disponibilité](high-availability.md)
