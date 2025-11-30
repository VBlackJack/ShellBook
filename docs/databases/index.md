# Bases de Données

Administration, optimisation et haute disponibilité des bases de données.

## Sections

| Section | Description |
|---------|-------------|
| 🐘 **PostgreSQL** | Installation, configuration, tuning et backup |
| 🐬 **MariaDB/MySQL** | Administration et réplication |
| 🍃 **MongoDB** | Documents JSON, aggregation, replica sets |
| 🔴 **Redis** | Cache, sessions et pub/sub |
| 🔄 **Haute Disponibilité** | Patroni, Galera, failover automatique |
| 📊 **Concepts** | Types de BDD, choix d'architecture |

## Guide de Décision Rapide

```mermaid
flowchart TD
    A[Quel besoin ?] --> B{ACID requis ?}
    B -->|Oui| C{Volume ?}
    B -->|Non| D{Type de données ?}

    C -->|< 1TB| E[PostgreSQL]
    C -->|> 1TB| F[PostgreSQL + Partitioning]

    D -->|Key-Value| G[Redis]
    D -->|Documents JSON| H[MongoDB]
    D -->|Time Series| I[InfluxDB/Prometheus]
    D -->|Logs/Analytics| J[ClickHouse/Elasticsearch]
```

| Cas d'usage | Base recommandée | Justification |
|-------------|------------------|---------------|
| Transactions financières | PostgreSQL | ACID, fiabilité |
| Cache applicatif | Redis | Latence < 1ms |
| Sessions utilisateurs | Redis | TTL natif, rapide |
| Logs centralisés | Elasticsearch | Full-text search |
| Métriques/Monitoring | Prometheus | Time series optimisé |
| E-commerce | PostgreSQL + Redis | ACID + cache |
