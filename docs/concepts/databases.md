# Les 7 Types de Bases de Données

`#sql` `#nosql` `#architecture` `#redis`

Un guide pratique pour choisir la bonne base de données selon votre cas d'usage.

---

!!! tip "Guide de Décision Rapide"
    - **Besoin ACID/Argent ?** → Relationnelle (PostgreSQL, MySQL)
    - **Besoin Vitesse/Cache ?** → Key-Value (Redis, Memcached)
    - **Besoin Flexibilité/JSON ?** → Document (MongoDB, CouchDB)
    - **Besoin Analytics/Logs ?** → Columnar (ClickHouse, BigQuery)
    - **Besoin Metrics/IoT ?** → Time Series (Prometheus, InfluxDB)
    - **Besoin Relations ?** → Graph (Neo4j, DGraph)
    - **Besoin AI/Embeddings ?** → Vector (Pinecone, Milvus)

---

## 1. Relationnelle (SQL)

**Concept :** Données structurées en tables avec lignes et colonnes, appliquant des relations via des clés étrangères.

**Idéale Pour :**

- Transactions financières (conformité ACID)
- Comptes utilisateurs & authentification
- Commandes e-commerce
- Toute donnée nécessitant une forte cohérence

**Avantages :**

- Garanties ACID (Atomicity, Consistency, Isolation, Durability)
- Écosystème mature, SQL est universel
- Requêtes complexes avec JOINs
- Forte intégrité des données

**Inconvénients :**

- Mise à l'échelle verticale coûteuse
- Changements de schéma peuvent être douloureux
- Pas idéale pour données non structurées

**Outils :** PostgreSQL, MySQL, MariaDB, SQL Server, Oracle

---

## 2. Document Store

**Concept :** Stocke les données sous forme de documents JSON/BSON flexibles. Pas de schéma fixe requis.

**Idéal Pour :**

- Profils utilisateurs avec champs variables
- Systèmes de gestion de contenu
- Catalogues produits
- Prototypage rapide

**Avantages :**

- Flexibilité du schéma (ajouter des champs à tout moment)
- Mise à l'échelle horizontale intégrée
- Adaptation naturelle aux APIs JSON
- Bonne expérience développeur

**Inconvénients :**

- Pas de JOINs (dénormalisation requise)
- Garanties de cohérence plus faibles
- Peut conduire à la duplication de données

**Outils :** MongoDB, CouchDB, Amazon DocumentDB, Firestore

---

## 3. Key-Value Store

**Concept :** Simple mapping clé-vers-valeur. Pensez-y comme une gigantesque hash map distribuée.

**Idéal Pour :**

- Stockage de sessions
- Couche de cache
- Tableaux de classement en temps réel
- Rate limiting
- Feature flags

**Avantages :**

- Extrêmement rapide (sous-milliseconde)
- API simple (GET, SET, DELETE)
- Mise à l'échelle horizontale
- Parfait pour données éphémères

**Inconvénients :**

- Pas de requêtes complexes
- Modélisation de données limitée
- Généralement en mémoire (risque de perte de données)

**Outils :** Redis, Memcached, Amazon ElastiCache, etcd

!!! warning "Redis en Sidecar"
    Redis est typiquement utilisé comme **couche de cache** à côté d'une base de données primaire, pas comme seul stockage de données.

    ```
    Client → Redis (cache hit ?) → PostgreSQL (si miss)
    ```

---

## 4. Columnar (Wide-Column)

**Concept :** Données stockées par colonnes au lieu de lignes. Optimisé pour les requêtes analytiques sur de grands ensembles de données.

**Idéal Pour :**

- Tableaux de bord analytiques
- Agrégation de logs
- Business intelligence
- Data warehousing
- Workloads OLAP

**Avantages :**

- Agrégations ultra-rapides (SUM, AVG, COUNT)
- Excellente compression (valeurs similaires ensemble)
- Gère des pétaoctets de données
- Exécution de requêtes parallèle

**Inconvénients :**

- Lent pour recherches de lignes individuelles
- Pas pour workloads transactionnels
- Configuration complexe

**Outils :** ClickHouse, Apache Cassandra, Google BigQuery, Amazon Redshift, Apache HBase

---

## 5. Time Series

**Concept :** Optimisé pour les points de données horodatés. Politiques de downsampling et de rétention intégrées.

**Idéal Pour :**

- Métriques d'infrastructure (CPU, mémoire, disque)
- Données de capteurs IoT
- Données tick financières
- Monitoring de performance applicative
- Timestamps de logs

**Avantages :**

- Compression extrême (delta encoding)
- Politiques de rétention intégrées
- Optimisé pour requêtes par plage de temps
- Downsampling natif

**Inconvénients :**

- Flexibilité de requête limitée
- Pas pour stockage général
- Cas d'usage spécialisé

**Outils :** Prometheus, InfluxDB, TimescaleDB, VictoriaMetrics, QuestDB

!!! info "Magie de la Compression"
    Les BDs time series utilisent **delta encoding** : au lieu de stocker `[100, 101, 102, 103]`, elles stockent `[100, +1, +1, +1]`.

    Résultat : compression 10-100x vs SQL pour les données de métriques.

---

## 6. Graph

**Concept :** Données sous forme de nœuds (entités) et arêtes (relations). Requête par traversée de connexions.

**Idéal Pour :**

- Réseaux sociaux (amis d'amis)
- Moteurs de recommandation
- Détection de fraude
- Graphes de connaissance
- Topologie réseau

**Avantages :**

- Traversée rapide de relations
- Naturel pour données connectées
- Schéma flexible
- Pattern matching puissant

**Inconvénients :**

- Courbe d'apprentissage raide (Cypher, Gremlin)
- Pas pour données tabulaires
- Mise à l'échelle peut être difficile

**Outils :** Neo4j, Amazon Neptune, ArangoDB, DGraph, TigerGraph

---

## 7. Vector

**Concept :** Stocke des vecteurs haute dimension (embeddings) pour recherche de similarité. La base de données AI/ML.

**Idéal Pour :**

- Recherche sémantique
- Récupération de contexte LLM (RAG)
- Similarité d'images
- Systèmes de recommandation
- Détection d'anomalies

**Avantages :**

- Recherche de voisins les plus proches approximatifs
- Essentiel pour applications AI
- Gère des millions de vecteurs
- Intégration avec modèles d'embeddings

**Inconvénients :**

- Technologie nouvelle (moins mature)
- Nécessite compréhension des embeddings
- Construction d'index peut être lente

**Outils :** Pinecone, Milvus, Weaviate, Qdrant, Chroma, pgvector

!!! tip "BDs Vector & LLMs"
    Les bases de données vectorielles sont la colonne vertébrale du **RAG (Retrieval-Augmented Generation)**.

    ```
    Requête Utilisateur → Embed → Vector Search → Contexte → LLM → Réponse
    ```

---

## Tableau Comparatif

| Type | Structure de Données | Scalabilité | Langage de Requête | Cas d'Usage Typique |
|------|----------------|-------------|----------------|------------------|
| **Relationnelle** | Tables (lignes/cols) | Verticale | SQL | Transactions, ACID |
| **Document** | Documents JSON | Horizontale | Requêtes JSON | Schémas flexibles |
| **Key-Value** | Clé → Valeur | Horizontale | GET/SET | Cache, sessions |
| **Columnar** | Familles de colonnes | Horizontale | SQL-like | Analytics, OLAP |
| **Time Series** | Timestamp → Valeur | Horizontale | PromQL, InfluxQL | Metrics, IoT |
| **Graph** | Nœuds + Arêtes | Variable | Cypher, Gremlin | Relations |
| **Vector** | Embeddings | Horizontale | Recherche similarité | AI/ML, recherche |

---

## Astuces de Pro

!!! example "Architecture Multi-Database"
    Les systèmes modernes combinent souvent plusieurs types de bases de données :

    ```
    PostgreSQL  → Source de vérité (utilisateurs, commandes)
         ↓
    Redis       → Couche de cache (sessions, données chaudes)
         ↓
    ClickHouse  → Analytics (tableaux de bord, rapports)
         ↓
    Pinecone    → Recherche AI (requêtes sémantiques)
    ```

!!! warning "Ne Sur-ingéniérez Pas"
    Commencez par PostgreSQL. Il gère le JSON (document), a des extensions pour time series (TimescaleDB), et même la recherche vectorielle (pgvector).

    Ajoutez des bases de données spécialisées seulement quand PostgreSQL devient un goulot d'étranglement.
