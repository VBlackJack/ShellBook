---
tags:
  - scripts
  - bash
  - postgresql
  - database
  - maintenance
---

# pg-bloat-check.sh

Outil d'estimation du bloat (fragmentation) des tables et index PostgreSQL pour déterminer si un VACUUM est nécessaire.

---

## Informations

| Propriété | Valeur |
|-----------|--------|
| **Langage** | Bash + SQL |
| **Catégorie** | Base de données / Maintenance |
| **Niveau** | :material-star::material-star::material-star: Avancé |
| **Dépendances** | psql (client PostgreSQL) |

---

## Description

Ce script analyse les statistiques internes de PostgreSQL pour estimer le "bloat" (espace gaspillé par les tuples morts) dans les tables et index. Cette information est cruciale pour planifier les opérations de maintenance VACUUM.

**Fonctionnalités :**

- Estimation du bloat des tables basée sur `pg_class` et `pg_statistic`
- Estimation du bloat des index
- Rapport formaté avec taille du bloat et pourcentage
- Filtrage par base de données et schéma
- Seuil configurable pour n'afficher que les tables problématiques

---

## Prérequis

```bash
# Client PostgreSQL installé
psql --version

# Accès à la base de données avec privilèges de lecture sur les catalogues système
# L'utilisateur doit avoir accès à pg_class, pg_statistic, pg_namespace
```

---

## Comprendre le Bloat PostgreSQL

!!! info "Qu'est-ce que le Bloat ?"
    PostgreSQL utilise **MVCC** (Multi-Version Concurrency Control) pour gérer les transactions concurrentes. Lorsqu'une ligne est mise à jour ou supprimée, l'ancienne version n'est pas immédiatement supprimée mais marquée comme "morte" (dead tuple).

    Ces dead tuples s'accumulent et créent du **bloat** :

    - **Espace disque gaspillé** : Les fichiers de données grossissent inutilement
    - **Performances dégradées** : Les scans doivent parcourir plus de pages
    - **Index inefficaces** : Les index pointent vers des tuples morts

!!! warning "VACUUM FULL - Attention en Production"
    **Ne jamais exécuter `VACUUM FULL` sur une base de production active !**

    - `VACUUM FULL` prend un **verrou exclusif** sur la table (ACCESS EXCLUSIVE LOCK)
    - La table est **complètement inaccessible** pendant l'opération
    - Sur une grosse table, cela peut prendre **plusieurs heures**

    **Alternatives recommandées :**

    - `VACUUM` standard (sans FULL) - non bloquant
    - `pg_repack` - réorganisation sans verrou exclusif
    - `REINDEX CONCURRENTLY` (PostgreSQL 12+) pour les index

---

## Script

```bash
#!/bin/bash
#===============================================================================
# Script Name: pg-bloat-check.sh
# Description: Estimate table and index bloat in PostgreSQL
# Author: ShellBook
# Date: 2024-01-15
# Version: 1.0
#===============================================================================

set -euo pipefail
IFS=$'\n\t'

# Variables
readonly SCRIPT_NAME=$(basename "$0")

# Colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m'
readonly BOLD='\033[1m'

# Default values
DB_HOST="${PGHOST:-localhost}"
DB_PORT="${PGPORT:-5432}"
DB_NAME="${PGDATABASE:-postgres}"
DB_USER="${PGUSER:-postgres}"
DB_SCHEMA="public"
BLOAT_THRESHOLD=10
CHECK_TABLES=true
CHECK_INDEXES=true

# Functions
log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1" >&2; }

usage() {
    cat << EOF
${CYAN}Usage:${NC} $SCRIPT_NAME [OPTIONS]

Estimate table and index bloat in PostgreSQL to determine VACUUM needs.

${CYAN}Options:${NC}
    -h, --help              Affiche cette aide
    -H, --host HOST         Hôte PostgreSQL (défaut: localhost)
    -p, --port PORT         Port PostgreSQL (défaut: 5432)
    -d, --database DB       Base de données (défaut: postgres)
    -U, --user USER         Utilisateur PostgreSQL (défaut: postgres)
    -s, --schema SCHEMA     Schéma à analyser (défaut: public)
    -t, --threshold PCT     Seuil de bloat minimum à afficher (défaut: 10%)
    --tables-only           Analyser uniquement les tables
    --indexes-only          Analyser uniquement les index

${CYAN}Variables d'environnement:${NC}
    PGHOST, PGPORT, PGDATABASE, PGUSER, PGPASSWORD

${CYAN}Exemples:${NC}
    $SCRIPT_NAME -d myapp -U admin
    $SCRIPT_NAME -H db.example.com -d production -t 20
    $SCRIPT_NAME --tables-only -s myschema

${CYAN}Note:${NC}
    Ce script fournit une ESTIMATION du bloat basée sur les statistiques.
    Pour des résultats précis, exécutez ANALYZE sur les tables concernées.

EOF
}

# Check psql availability
check_psql() {
    if ! command -v psql &> /dev/null; then
        log_error "psql n'est pas installé ou n'est pas dans le PATH"
        exit 1
    fi
}

# Test database connection
test_connection() {
    log_info "Test de connexion à ${DB_HOST}:${DB_PORT}/${DB_NAME}..."

    if ! psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "SELECT 1" &> /dev/null; then
        log_error "Impossible de se connecter à la base de données"
        log_error "Vérifiez les paramètres de connexion et PGPASSWORD"
        exit 1
    fi

    log_info "Connexion établie"
}

# Query for table bloat estimation
# Based on the famous bloat estimation query from PostgreSQL wiki
get_table_bloat_query() {
    cat << 'EOSQL'
WITH constants AS (
    SELECT current_setting('block_size')::numeric AS bs,
           23 AS hdr,
           8 AS ma
),
no_stats AS (
    SELECT table_schema, table_name,
           n_live_tup::numeric AS est_rows,
           pg_table_size(quote_ident(table_schema) || '.' || quote_ident(table_name))::numeric AS table_size
    FROM information_schema.tables
    JOIN pg_stat_user_tables AS psut
        ON table_schema = psut.schemaname AND table_name = psut.relname
    WHERE table_schema = :schema
),
null_headers AS (
    SELECT
        ns.nspname AS table_schema,
        tbl.relname AS table_name,
        hdr + 1 + (
            SUM(CASE WHEN att.attnotnull THEN 0 ELSE 1 END) / 8
        ) AS nullhdr,
        SUM((1 - att.attnotnull::int) * att.atttypmod) AS nullhdr2
    FROM pg_attribute AS att
    JOIN pg_class AS tbl ON att.attrelid = tbl.oid
    JOIN pg_namespace AS ns ON ns.oid = tbl.relnamespace
    CROSS JOIN constants
    WHERE att.attnum > 0
        AND tbl.relkind = 'r'
        AND ns.nspname = :schema
    GROUP BY 1, 2, hdr
),
table_estimates AS (
    SELECT
        schemaname AS table_schema,
        relname AS table_name,
        bs * tblpages AS real_size,
        (tblpages - est_tblpages) * bs AS extra_size,
        CASE
            WHEN tblpages > 0 AND tblpages - est_tblpages > 0
            THEN 100 * (tblpages - est_tblpages) / tblpages
            ELSE 0
        END AS extra_pct,
        fillfactor,
        (tblpages - est_tblpages_ff) * bs AS bloat_size,
        CASE
            WHEN tblpages > 0 AND tblpages - est_tblpages_ff > 0
            THEN 100 * (tblpages - est_tblpages_ff) / tblpages
            ELSE 0
        END AS bloat_pct
    FROM (
        SELECT
            schemaname,
            relname,
            bs,
            reltuples::numeric AS est_rows,
            relpages::numeric AS tblpages,
            COALESCE(fillfactor, 100) AS fillfactor,
            CEIL(reltuples / (
                (bs - page_hdr) /
                NULLIF(tpl_size, 0)
            )) AS est_tblpages,
            CEIL(reltuples / (
                (bs - page_hdr) * COALESCE(fillfactor, 100) / 100 /
                NULLIF(tpl_size, 0)
            )) AS est_tblpages_ff
        FROM (
            SELECT
                c.relname,
                n.nspname AS schemaname,
                c.reltuples,
                c.relpages,
                bs,
                CEIL(
                    (c.reltuples * (
                        (datahdr + ma -
                            CASE WHEN datahdr % ma = 0 THEN ma ELSE datahdr % ma END
                        ) + nullhdr + 4
                    )) / (bs - 20)
                ) AS est_raw,
                24 + CEIL(c.reltuples / ((bs - page_hdr) / NULLIF(tpl_size, 0))) * 4 AS page_hdr,
                (
                    SELECT (
                        (1 - null_frac) * avg_width +
                        null_frac * 0
                    ) AS datalen
                    FROM pg_stats
                    WHERE schemaname = n.nspname
                        AND tablename = c.relname
                    LIMIT 1
                ) + 23 AS tpl_size,
                23 AS datahdr,
                COALESCE(
                    (SELECT (
                        SELECT max(avg_width)
                        FROM pg_stats
                        WHERE schemaname = n.nspname
                            AND tablename = c.relname
                    )), 0
                ) AS maxfracsum,
                (SELECT reloptions FROM pg_class WHERE oid = c.oid) AS relopts,
                (
                    SELECT (regexp_matches(
                        array_to_string(reloptions, ','),
                        'fillfactor=([0-9]+)'
                    ))[1]::int
                    FROM pg_class
                    WHERE oid = c.oid
                ) AS fillfactor
            FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            CROSS JOIN constants
            LEFT JOIN null_headers nh ON nh.table_schema = n.nspname AND nh.table_name = c.relname
            WHERE c.relkind = 'r'
                AND n.nspname = :schema
        ) AS s
        WHERE est_raw IS NOT NULL
    ) AS s2
)
SELECT
    table_schema AS "Schema",
    table_name AS "Table",
    pg_size_pretty(real_size::bigint) AS "Size",
    pg_size_pretty(bloat_size::bigint) AS "Bloat",
    ROUND(bloat_pct::numeric, 1) AS "Bloat %"
FROM table_estimates
WHERE bloat_pct >= :threshold
ORDER BY bloat_size DESC
LIMIT 50;
EOSQL
}

# Query for index bloat estimation
get_index_bloat_query() {
    cat << 'EOSQL'
WITH btree_index_atts AS (
    SELECT
        nspname AS schema_name,
        indexclass.relname AS index_name,
        indexclass.reltuples,
        indexclass.relpages,
        indrelid,
        indexrelid,
        indexclass.relam,
        tableclass.relname AS table_name,
        (
            regexp_split_to_table(
                indkey::text, ' '
            )
        )::smallint AS attnum,
        indexrelid AS index_oid
    FROM pg_index
    JOIN pg_class AS indexclass ON pg_index.indexrelid = indexclass.oid
    JOIN pg_class AS tableclass ON pg_index.indrelid = tableclass.oid
    JOIN pg_namespace ON pg_namespace.oid = indexclass.relnamespace
    JOIN pg_am ON indexclass.relam = pg_am.oid
    WHERE pg_am.amname = 'btree'
        AND indexclass.relpages > 0
        AND nspname = :schema
),
index_item_sizes AS (
    SELECT
        ind_atts.schema_name,
        ind_atts.table_name,
        ind_atts.index_name,
        ind_atts.reltuples,
        ind_atts.relpages,
        ind_atts.indrelid,
        ind_atts.indexrelid,
        current_setting('block_size')::numeric AS bs,
        8 AS maxalign,
        24 AS pagehdr,
        CASE
            WHEN max(COALESCE(pg_stats.null_frac, 0)) = 0 THEN 2
            ELSE 6
        END AS index_tuple_hdr,
        SUM((1 - COALESCE(pg_stats.null_frac, 0)) * COALESCE(pg_stats.avg_width, 1024)) AS nulldatawidth
    FROM btree_index_atts AS ind_atts
    JOIN pg_attribute ON pg_attribute.attrelid = ind_atts.indrelid
        AND pg_attribute.attnum = ind_atts.attnum
    JOIN pg_stats ON pg_stats.schemaname = ind_atts.schema_name
        AND pg_stats.tablename = ind_atts.table_name
        AND pg_stats.attname = pg_attribute.attname
    WHERE pg_attribute.attnum > 0
    GROUP BY 1, 2, 3, 4, 5, 6, 7, 8, 9
),
index_aligned_est AS (
    SELECT
        schema_name,
        table_name,
        index_name,
        bs,
        reltuples,
        relpages,
        COALESCE(
            CEIL(
                reltuples * (6 + maxalign -
                    CASE
                        WHEN (index_tuple_hdr + nulldatawidth) % maxalign = 0 THEN maxalign
                        ELSE (index_tuple_hdr + nulldatawidth) % maxalign
                    END +
                    nulldatawidth
                )::numeric / (bs - pagehdr)::numeric +
                1
            ),
            0
        ) AS expected_pages
    FROM index_item_sizes
),
index_bloat AS (
    SELECT
        schema_name AS "Schema",
        table_name AS "Table",
        index_name AS "Index",
        bs * relpages AS real_size,
        bs * expected_pages AS expected_size,
        bs * (relpages - expected_pages) AS bloat_size,
        CASE
            WHEN relpages > 0
            THEN 100 * (relpages - expected_pages)::numeric / relpages
            ELSE 0
        END AS bloat_pct
    FROM index_aligned_est
)
SELECT
    "Schema",
    "Table",
    "Index",
    pg_size_pretty(real_size::bigint) AS "Size",
    pg_size_pretty(bloat_size::bigint) AS "Bloat",
    ROUND(bloat_pct::numeric, 1) AS "Bloat %"
FROM index_bloat
WHERE bloat_pct >= :threshold
    AND bloat_size > 0
ORDER BY bloat_size DESC
LIMIT 50;
EOSQL
}

# Run table bloat analysis
analyze_table_bloat() {
    echo -e "\n${BOLD}${CYAN}=== BLOAT DES TABLES ===${NC}\n"

    local query
    query=$(get_table_bloat_query)

    psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" \
        --set=schema="'$DB_SCHEMA'" \
        --set=threshold="$BLOAT_THRESHOLD" \
        -c "$query" 2>/dev/null || {
            log_warn "Impossible d'estimer le bloat des tables (statistiques manquantes ?)"
            log_info "Exécutez ANALYZE sur le schéma $DB_SCHEMA"
        }
}

# Run index bloat analysis
analyze_index_bloat() {
    echo -e "\n${BOLD}${CYAN}=== BLOAT DES INDEX ===${NC}\n"

    local query
    query=$(get_index_bloat_query)

    psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" \
        --set=schema="'$DB_SCHEMA'" \
        --set=threshold="$BLOAT_THRESHOLD" \
        -c "$query" 2>/dev/null || {
            log_warn "Impossible d'estimer le bloat des index (statistiques manquantes ?)"
        }
}

# Show database info
show_db_info() {
    echo -e "${BOLD}${CYAN}=== ANALYSE DU BLOAT POSTGRESQL ===${NC}"
    echo -e "Base: ${BOLD}$DB_NAME${NC} | Schéma: ${BOLD}$DB_SCHEMA${NC} | Seuil: ${BOLD}${BLOAT_THRESHOLD}%${NC}"
    echo -e "Hôte: $DB_HOST:$DB_PORT | Utilisateur: $DB_USER"
    echo ""

    # Get database size
    local db_size
    db_size=$(psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" \
        -t -c "SELECT pg_size_pretty(pg_database_size('$DB_NAME'))" 2>/dev/null | tr -d ' ')

    echo -e "Taille de la base: ${BOLD}$db_size${NC}"
}

# Show recommendations
show_recommendations() {
    echo -e "\n${BOLD}${CYAN}=== RECOMMANDATIONS ===${NC}\n"
    cat << EOF
${YELLOW}Tables avec bloat élevé (>30%) :${NC}
  → Exécuter: VACUUM ANALYZE <table>;
  → Pour récupérer l'espace: VACUUM FULL <table>; (ATTENTION: verrou exclusif)
  → Alternative sans blocage: pg_repack -t <table>

${YELLOW}Index avec bloat élevé (>30%) :${NC}
  → PostgreSQL 12+: REINDEX INDEX CONCURRENTLY <index>;
  → Versions antérieures: pg_repack -i <index>

${YELLOW}Maintenance préventive :${NC}
  → Vérifier autovacuum: SELECT * FROM pg_stat_user_tables WHERE n_dead_tup > 1000;
  → Ajuster les seuils autovacuum si nécessaire

EOF
}

# Parse arguments
main() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                usage
                exit 0
                ;;
            -H|--host)
                DB_HOST="$2"
                shift 2
                ;;
            -p|--port)
                DB_PORT="$2"
                shift 2
                ;;
            -d|--database)
                DB_NAME="$2"
                shift 2
                ;;
            -U|--user)
                DB_USER="$2"
                shift 2
                ;;
            -s|--schema)
                DB_SCHEMA="$2"
                shift 2
                ;;
            -t|--threshold)
                BLOAT_THRESHOLD="$2"
                shift 2
                ;;
            --tables-only)
                CHECK_INDEXES=false
                shift
                ;;
            --indexes-only)
                CHECK_TABLES=false
                shift
                ;;
            *)
                log_error "Option inconnue: $1"
                usage
                exit 1
                ;;
        esac
    done

    # Check dependencies
    check_psql

    # Test connection
    test_connection

    # Show database info
    show_db_info

    # Run analysis
    if [[ "$CHECK_TABLES" == "true" ]]; then
        analyze_table_bloat
    fi

    if [[ "$CHECK_INDEXES" == "true" ]]; then
        analyze_index_bloat
    fi

    # Show recommendations
    show_recommendations
}

# Execute
main "$@"
```

---

## Utilisation

### Analyse Basique

```bash
# Analyser la base par défaut (postgres)
./pg-bloat-check.sh

# Analyser une base spécifique
./pg-bloat-check.sh -d myapp

# Avec authentification
PGPASSWORD=secret ./pg-bloat-check.sh -H db.example.com -d production -U admin
```

### Filtrage et Options

```bash
# Afficher uniquement les tables avec >20% de bloat
./pg-bloat-check.sh -d myapp -t 20

# Analyser un schéma spécifique
./pg-bloat-check.sh -d myapp -s inventory

# Tables uniquement
./pg-bloat-check.sh -d myapp --tables-only

# Index uniquement
./pg-bloat-check.sh -d myapp --indexes-only
```

---

## Exemple de Sortie

```
=== ANALYSE DU BLOAT POSTGRESQL ===
Base: myapp | Schéma: public | Seuil: 10%
Hôte: localhost:5432 | Utilisateur: postgres

Taille de la base: 2.5 GB

=== BLOAT DES TABLES ===

 Schema |    Table     |  Size   |  Bloat  | Bloat %
--------+--------------+---------+---------+---------
 public | orders       | 850 MB  | 212 MB  |    25.0
 public | order_items  | 420 MB  | 84 MB   |    20.0
 public | sessions     | 150 MB  | 45 MB   |    30.0
 public | audit_logs   | 1.2 GB  | 180 MB  |    15.0

=== BLOAT DES INDEX ===

 Schema |    Table     |        Index         |  Size  | Bloat  | Bloat %
--------+--------------+----------------------+--------+--------+---------
 public | orders       | orders_created_idx   | 120 MB | 36 MB  |    30.0
 public | sessions     | sessions_user_idx    | 45 MB  | 18 MB  |    40.0

=== RECOMMANDATIONS ===

Tables avec bloat élevé (>30%) :
  → Exécuter: VACUUM ANALYZE <table>;
  → Pour récupérer l'espace: VACUUM FULL <table>; (ATTENTION: verrou exclusif)
  → Alternative sans blocage: pg_repack -t <table>
```

---

## Options

| Option | Description |
|--------|-------------|
| `-h`, `--help` | Affiche l'aide |
| `-H`, `--host HOST` | Hôte PostgreSQL (défaut: localhost) |
| `-p`, `--port PORT` | Port PostgreSQL (défaut: 5432) |
| `-d`, `--database DB` | Base de données à analyser |
| `-U`, `--user USER` | Utilisateur PostgreSQL |
| `-s`, `--schema SCHEMA` | Schéma à analyser (défaut: public) |
| `-t`, `--threshold PCT` | Seuil minimum de bloat à afficher (défaut: 10%) |
| `--tables-only` | Analyser uniquement les tables |
| `--indexes-only` | Analyser uniquement les index |

---

!!! danger "VACUUM FULL en Production"
    **VACUUM FULL** réécrit entièrement la table et prend un **verrou exclusif (ACCESS EXCLUSIVE LOCK)**.

    Pendant l'opération :

    - Aucune lecture ni écriture possible sur la table
    - Les requêtes sont bloquées ou timeout
    - Durée : proportionnelle à la taille de la table

    **Utilisez plutôt :**

    ```bash
    # pg_repack - réorganisation sans blocage
    pg_repack -d myapp -t orders

    # VACUUM standard (non bloquant)
    VACUUM ANALYZE orders;
    ```

!!! tip "Statistiques Précises"
    Pour des estimations fiables, assurez-vous que les statistiques sont à jour :

    ```sql
    -- Analyser une table
    ANALYZE orders;

    -- Analyser tout le schéma
    ANALYZE VERBOSE;

    -- Vérifier l'âge des statistiques
    SELECT schemaname, relname, last_analyze, last_autoanalyze
    FROM pg_stat_user_tables
    ORDER BY last_analyze NULLS FIRST;
    ```

---

## Voir Aussi

- [check-postgresql.sh](check-postgresql.md) - Vérification santé PostgreSQL
- [mysql-security-audit.sh](mysql-security-audit.md) - Audit sécurité MySQL
- [Scripts Python - Redis Key Auditor](../python/redis_key_auditor.md)
