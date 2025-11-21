# The 7 Database Types

`#sql` `#nosql` `#architecture` `#redis`

A practical guide to choosing the right database for your use case.

---

!!! tip "Quick Decision Guide"
    - **Need ACID/Money?** → Relational (PostgreSQL, MySQL)
    - **Need Speed/Cache?** → Key-Value (Redis, Memcached)
    - **Need Flexibility/JSON?** → Document (MongoDB, CouchDB)
    - **Need Analytics/Logs?** → Columnar (ClickHouse, BigQuery)
    - **Need Metrics/IoT?** → Time Series (Prometheus, InfluxDB)
    - **Need Relationships?** → Graph (Neo4j, DGraph)
    - **Need AI/Embeddings?** → Vector (Pinecone, Milvus)

---

## 1. Relational (SQL)

**Concept:** Structured data in tables with rows and columns, enforcing relationships via foreign keys.

**Best For:**

- Financial transactions (ACID compliance)
- User accounts & authentication
- E-commerce orders
- Any data requiring strong consistency

**Pros:**

- ACID guarantees (Atomicity, Consistency, Isolation, Durability)
- Mature ecosystem, SQL is universal
- Complex queries with JOINs
- Strong data integrity

**Cons:**

- Vertical scaling is expensive
- Schema changes can be painful
- Not ideal for unstructured data

**Tools:** PostgreSQL, MySQL, MariaDB, SQL Server, Oracle

---

## 2. Document Store

**Concept:** Stores data as flexible JSON/BSON documents. No fixed schema required.

**Best For:**

- User profiles with varying fields
- Content management systems
- Product catalogs
- Rapid prototyping

**Pros:**

- Schema flexibility (add fields anytime)
- Horizontal scaling built-in
- Natural fit for JSON APIs
- Good developer experience

**Cons:**

- No JOINs (denormalization required)
- Weaker consistency guarantees
- Can lead to data duplication

**Tools:** MongoDB, CouchDB, Amazon DocumentDB, Firestore

---

## 3. Key-Value Store

**Concept:** Simple key-to-value mapping. Think of it as a giant distributed hash map.

**Best For:**

- Session storage
- Caching layer
- Real-time leaderboards
- Rate limiting
- Feature flags

**Pros:**

- Extremely fast (sub-millisecond)
- Simple API (GET, SET, DELETE)
- Horizontal scaling
- Perfect for ephemeral data

**Cons:**

- No complex queries
- Limited data modeling
- Usually in-memory (data loss risk)

**Tools:** Redis, Memcached, Amazon ElastiCache, etcd

!!! warning "Redis as Sidecar"
    Redis is typically used as a **caching layer** alongside a primary database, not as the sole data store.

    ```
    Client → Redis (cache hit?) → PostgreSQL (if miss)
    ```

---

## 4. Columnar (Wide-Column)

**Concept:** Data stored by columns instead of rows. Optimized for analytical queries on large datasets.

**Best For:**

- Analytics dashboards
- Log aggregation
- Business intelligence
- Data warehousing
- OLAP workloads

**Pros:**

- Blazing fast aggregations (SUM, AVG, COUNT)
- Excellent compression (similar values together)
- Handles petabytes of data
- Parallel query execution

**Cons:**

- Slow for single-row lookups
- Not for transactional workloads
- Complex setup

**Tools:** ClickHouse, Apache Cassandra, Google BigQuery, Amazon Redshift, Apache HBase

---

## 5. Time Series

**Concept:** Optimized for time-stamped data points. Built-in downsampling and retention policies.

**Best For:**

- Infrastructure metrics (CPU, memory, disk)
- IoT sensor data
- Financial tick data
- Application performance monitoring
- Log timestamps

**Pros:**

- Extreme compression (delta encoding)
- Built-in retention policies
- Optimized for time-range queries
- Native downsampling

**Cons:**

- Limited query flexibility
- Not for general-purpose storage
- Specialized use case

**Tools:** Prometheus, InfluxDB, TimescaleDB, VictoriaMetrics, QuestDB

!!! info "Compression Magic"
    Time series DBs use **delta encoding**: instead of storing `[100, 101, 102, 103]`, they store `[100, +1, +1, +1]`.

    Result: 10-100x compression vs SQL for metrics data.

---

## 6. Graph

**Concept:** Data as nodes (entities) and edges (relationships). Query by traversing connections.

**Best For:**

- Social networks (friends-of-friends)
- Recommendation engines
- Fraud detection
- Knowledge graphs
- Network topology

**Pros:**

- Fast relationship traversal
- Natural for connected data
- Flexible schema
- Powerful pattern matching

**Cons:**

- Steep learning curve (Cypher, Gremlin)
- Not for tabular data
- Scaling can be challenging

**Tools:** Neo4j, Amazon Neptune, ArangoDB, DGraph, TigerGraph

---

## 7. Vector

**Concept:** Stores high-dimensional vectors (embeddings) for similarity search. The AI/ML database.

**Best For:**

- Semantic search
- LLM context retrieval (RAG)
- Image similarity
- Recommendation systems
- Anomaly detection

**Pros:**

- Approximate nearest neighbor search
- Essential for AI applications
- Handles millions of vectors
- Integrates with embedding models

**Cons:**

- New technology (less mature)
- Requires understanding of embeddings
- Index building can be slow

**Tools:** Pinecone, Milvus, Weaviate, Qdrant, Chroma, pgvector

!!! tip "Vector DBs & LLMs"
    Vector databases are the backbone of **RAG (Retrieval-Augmented Generation)**.

    ```
    User Query → Embed → Vector Search → Context → LLM → Response
    ```

---

## Comparison Table

| Type | Data Structure | Scalability | Query Language | Typical Use Case |
|------|----------------|-------------|----------------|------------------|
| **Relational** | Tables (rows/cols) | Vertical | SQL | Transactions, ACID |
| **Document** | JSON documents | Horizontal | JSON queries | Flexible schemas |
| **Key-Value** | Key → Value | Horizontal | GET/SET | Caching, sessions |
| **Columnar** | Column families | Horizontal | SQL-like | Analytics, OLAP |
| **Time Series** | Timestamp → Value | Horizontal | PromQL, InfluxQL | Metrics, IoT |
| **Graph** | Nodes + Edges | Varies | Cypher, Gremlin | Relationships |
| **Vector** | Embeddings | Horizontal | Similarity search | AI/ML, search |

---

## Pro Tips

!!! example "Multi-Database Architecture"
    Modern systems often combine multiple database types:

    ```
    PostgreSQL  → Source of truth (users, orders)
         ↓
    Redis       → Cache layer (sessions, hot data)
         ↓
    ClickHouse  → Analytics (dashboards, reports)
         ↓
    Pinecone    → AI search (semantic queries)
    ```

!!! warning "Don't Over-Engineer"
    Start with PostgreSQL. It handles JSON (document), has extensions for time series (TimescaleDB), and even vector search (pgvector).

    Add specialized databases only when PostgreSQL becomes a bottleneck.
