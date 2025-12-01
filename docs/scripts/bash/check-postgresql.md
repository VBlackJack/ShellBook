---
tags:
  - scripts
  - bash
  - postgresql
  - database
  - linux
---

# check-postgresql.sh

:material-star::material-star: **Niveau : Intermédiaire**

Vérification complète d'un serveur PostgreSQL.

---

## Description

Ce script vérifie l'état d'un serveur PostgreSQL :
- Service et connectivité
- Bases de données et taille
- Connections actives
- Réplication streaming
- Vacuum et bloat
- Statistiques I/O
- Verrous et requêtes longues

---

## Script

```bash
#!/bin/bash
#===============================================================================
# check-postgresql.sh - Vérification santé serveur PostgreSQL
#===============================================================================
# Usage: ./check-postgresql.sh [-h host] [-p port] [-U user] [-d database]
#===============================================================================

set -o pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
GRAY='\033[0;90m'
NC='\033[0m'

# Parameters par défaut
PG_HOST="localhost"
PG_PORT="5432"
PG_USER="postgres"
PG_DB="postgres"

# Seuils
CONN_WARNING_PCT=70
CONN_CRITICAL_PCT=90
LONG_QUERY_SECONDS=300

# Counters
TOTAL=0
PASSED=0
WARNINGS=0
FAILED=0

#===============================================================================
# Functions
#===============================================================================
usage() {
    cat << EOF
Usage: $0 [options]

Options:
    -h HOST      Server PostgreSQL (default: localhost)
    -p PORT      Port PostgreSQL (default: 5432)
    -U USER      Utilisateur (default: postgres)
    -d DATABASE  Base de données (default: postgres)
    --help       Afficher cette aide
EOF
    exit 0
}

check_result() {
    local name="$1"
    local status="$2"
    local message="$3"

    ((TOTAL++))

    case $status in
        pass)
            echo -e "${GREEN}[OK]  ${NC} $name${GRAY} - $message${NC}"
            ((PASSED++))
            ;;
        warn)
            echo -e "${YELLOW}[WARN]${NC} $name${GRAY} - $message${NC}"
            ((WARNINGS++))
            ;;
        fail)
            echo -e "${RED}[FAIL]${NC} $name${GRAY} - $message${NC}"
            ((FAILED++))
            ;;
        info)
            echo -e "${CYAN}[INFO]${NC} $name${GRAY} - $message${NC}"
            ;;
    esac
}

pg_query() {
    local query="$1"
    psql -h "$PG_HOST" -p "$PG_PORT" -U "$PG_USER" -d "$PG_DB" \
        -t -A -c "$query" 2>/dev/null
}

pg_query_csv() {
    local query="$1"
    psql -h "$PG_HOST" -p "$PG_PORT" -U "$PG_USER" -d "$PG_DB" \
        -t -A -F'|' -c "$query" 2>/dev/null
}

#===============================================================================
# Parse arguments
#===============================================================================
while [[ $# -gt 0 ]]; do
    case $1 in
        -h) PG_HOST="$2"; shift 2 ;;
        -p) PG_PORT="$2"; shift 2 ;;
        -U) PG_USER="$2"; shift 2 ;;
        -d) PG_DB="$2"; shift 2 ;;
        --help) usage ;;
        *) echo "Unknown option: $1"; usage ;;
    esac
done

#===============================================================================
# Main
#===============================================================================
echo ""
echo -e "${CYAN}=================================================================${NC}"
echo -e "${GREEN}  POSTGRESQL HEALTH CHECK${NC}"
echo -e "${CYAN}=================================================================${NC}"
echo "  Host: $PG_HOST:$PG_PORT"
echo "  User: $PG_USER"
echo "  Date: $(date '+%Y-%m-%d %H:%M:%S')"
echo -e "${CYAN}-----------------------------------------------------------------${NC}"

# ═══════════════════════════════════════════════════════════════════
# CHECK 1: Service PostgreSQL
# ═══════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[Service PostgreSQL]${NC}"

if systemctl is-active --quiet postgresql 2>/dev/null; then
    check_result "Service postgresql" "pass" "Running"
elif systemctl is-active --quiet postgresql-* 2>/dev/null; then
    check_result "Service postgresql" "pass" "Running"
elif pgrep -x postgres > /dev/null || pgrep -x postmaster > /dev/null; then
    check_result "Process postgres" "pass" "Running"
else
    check_result "Service PostgreSQL" "fail" "Not running"
fi

# ═══════════════════════════════════════════════════════════════════
# CHECK 2: Connectivité
# ═══════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[Connectivité]${NC}"

# Test port
if nc -z -w 3 "$PG_HOST" "$PG_PORT" 2>/dev/null; then
    check_result "Port $PG_PORT" "pass" "Open"
else
    check_result "Port $PG_PORT" "fail" "Closed"
    echo -e "\n${RED}[FATAL] Cannot connect to PostgreSQL. Aborting.${NC}"
    exit 2
fi

# Test connexion
version=$(pg_query "SELECT version()" | head -1)
if [[ -n "$version" ]]; then
    check_result "PostgreSQL Connection" "pass" "Connected"
    pg_version=$(echo "$version" | grep -oP 'PostgreSQL \K[0-9.]+')
    echo -e "       ${GRAY}Version: $pg_version${NC}"
else
    check_result "PostgreSQL Connection" "fail" "Authentication failed"
    echo -e "\n${RED}[FATAL] Cannot authenticate. Check pg_hba.conf.${NC}"
    exit 2
fi

# ═══════════════════════════════════════════════════════════════════
# CHECK 3: État général
# ═══════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[État Général]${NC}"

# Uptime
start_time=$(pg_query "SELECT pg_postmaster_start_time()")
if [[ -n "$start_time" ]]; then
    uptime=$(pg_query "SELECT now() - pg_postmaster_start_time()")
    check_result "Uptime" "pass" "$uptime"
fi

# Mode recovery
in_recovery=$(pg_query "SELECT pg_is_in_recovery()")
if [[ "$in_recovery" == "t" ]]; then
    check_result "Server Role" "info" "Standby (replica)"
else
    check_result "Server Role" "info" "Primary"
fi

# ═══════════════════════════════════════════════════════════════════
# CHECK 4: Connections
# ═══════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[Connections]${NC}"

max_connections=$(pg_query "SHOW max_connections")
current_connections=$(pg_query "SELECT count(*) FROM pg_stat_activity")
superuser_reserved=$(pg_query "SHOW superuser_reserved_connections")

available=$((max_connections - superuser_reserved))
conn_pct=$((current_connections * 100 / available))

echo -e "       ${GRAY}Current: $current_connections / $available (max: $max_connections)${NC}"

if [[ $conn_pct -ge $CONN_CRITICAL_PCT ]]; then
    check_result "Connection Usage" "fail" "${conn_pct}%"
elif [[ $conn_pct -ge $CONN_WARNING_PCT ]]; then
    check_result "Connection Usage" "warn" "${conn_pct}%"
else
    check_result "Connection Usage" "pass" "${conn_pct}%"
fi

# Connections par état
echo -e "       ${GRAY}By state:${NC}"
pg_query_csv "SELECT state, count(*) FROM pg_stat_activity GROUP BY state ORDER BY count DESC" | while IFS='|' read state count; do
    echo -e "       ${GRAY}  - ${state:-idle}: $count${NC}"
done

# ═══════════════════════════════════════════════════════════════════
# CHECK 5: Bases de données
# ═══════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[Bases de Données]${NC}"

db_count=$(pg_query "SELECT count(*) FROM pg_database WHERE NOT datistemplate")
check_result "User Databases" "info" "$db_count"

# Taille totale
total_size=$(pg_query "SELECT pg_size_pretty(sum(pg_database_size(datname))) FROM pg_database")
echo -e "       ${GRAY}Total size: $total_size${NC}"

# Top 5 bases
echo -e "       ${GRAY}Largest databases:${NC}"
pg_query_csv "SELECT datname, pg_size_pretty(pg_database_size(datname)) FROM pg_database WHERE NOT datistemplate ORDER BY pg_database_size(datname) DESC LIMIT 5" | while IFS='|' read db size; do
    echo -e "       ${GRAY}  - $db: $size${NC}"
done

# ═══════════════════════════════════════════════════════════════════
# CHECK 6: Réplication
# ═══════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[Réplication]${NC}"

if [[ "$in_recovery" == "f" ]]; then
    # Primary - vérifier les replicas
    replica_count=$(pg_query "SELECT count(*) FROM pg_stat_replication")

    if [[ $replica_count -gt 0 ]]; then
        check_result "Streaming Replicas" "pass" "$replica_count connected"

        pg_query_csv "SELECT client_addr, state, sent_lsn, write_lsn, replay_lsn FROM pg_stat_replication" | while IFS='|' read addr state sent write replay; do
            lag=$(pg_query "SELECT pg_wal_lsn_diff('$sent', '$replay')")
            lag_mb=$((lag / 1024 / 1024))
            echo -e "       ${GRAY}  - $addr: $state (lag: ${lag_mb}MB)${NC}"
        done
    else
        check_result "Replication" "info" "No replicas connected"
    fi
else
    # Standby - vérifier le lag
    receive_lsn=$(pg_query "SELECT pg_last_wal_receive_lsn()")
    replay_lsn=$(pg_query "SELECT pg_last_wal_replay_lsn()")

    if [[ -n "$receive_lsn" ]] && [[ -n "$replay_lsn" ]]; then
        lag=$(pg_query "SELECT pg_wal_lsn_diff('$receive_lsn', '$replay_lsn')")
        lag_mb=$((lag / 1024 / 1024))

        if [[ $lag_mb -gt 100 ]]; then
            check_result "Replication Lag" "warn" "${lag_mb}MB behind"
        else
            check_result "Replication Lag" "pass" "${lag_mb}MB"
        fi
    fi
fi

# ═══════════════════════════════════════════════════════════════════
# CHECK 7: Vacuum et Autovacuum
# ═══════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[Vacuum & Maintenance]${NC}"

# Autovacuum activé
autovacuum=$(pg_query "SHOW autovacuum")
if [[ "$autovacuum" == "on" ]]; then
    check_result "Autovacuum" "pass" "Enabled"
else
    check_result "Autovacuum" "warn" "Disabled"
fi

# Tables nécessitant vacuum
tables_need_vacuum=$(pg_query "SELECT count(*) FROM pg_stat_user_tables WHERE n_dead_tup > 10000 AND (last_autovacuum IS NULL OR last_autovacuum < now() - interval '7 days')")
if [[ $tables_need_vacuum -gt 0 ]]; then
    check_result "Tables needing vacuum" "warn" "$tables_need_vacuum table(s)"
else
    check_result "Tables needing vacuum" "pass" "None"
fi

# Oldest transaction ID
oldest_xid=$(pg_query "SELECT age(datfrozenxid) FROM pg_database ORDER BY age(datfrozenxid) DESC LIMIT 1")
xid_warning=$((2000000000 - oldest_xid))
if [[ $xid_warning -lt 100000000 ]]; then
    check_result "Transaction ID Age" "warn" "$oldest_xid (vacuum freeze needed)"
else
    check_result "Transaction ID Age" "pass" "$oldest_xid"
fi

# ═══════════════════════════════════════════════════════════════════
# CHECK 8: Statistiques I/O
# ═══════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[Performance I/O]${NC}"

# Cache hit ratio
hit_ratio=$(pg_query "SELECT ROUND(100.0 * sum(blks_hit) / nullif(sum(blks_hit) + sum(blks_read), 0), 2) FROM pg_stat_database")
if [[ -n "$hit_ratio" ]]; then
    if (( $(echo "$hit_ratio < 90" | bc -l 2>/dev/null || echo 0) )); then
        check_result "Cache Hit Ratio" "warn" "${hit_ratio}%"
    else
        check_result "Cache Hit Ratio" "pass" "${hit_ratio}%"
    fi
fi

# Index hit ratio
idx_hit_ratio=$(pg_query "SELECT ROUND(100.0 * sum(idx_blks_hit) / nullif(sum(idx_blks_hit) + sum(idx_blks_read), 0), 2) FROM pg_statio_user_indexes")
[[ -n "$idx_hit_ratio" ]] && echo -e "       ${GRAY}Index hit ratio: ${idx_hit_ratio}%${NC}"

# Checkpoints
checkpoints=$(pg_query "SELECT checkpoints_req, checkpoints_timed FROM pg_stat_bgwriter" | tr '|' ' ')
echo -e "       ${GRAY}Checkpoints: $checkpoints (req|timed)${NC}"

# ═══════════════════════════════════════════════════════════════════
# CHECK 9: Requêtes longues et verrous
# ═══════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[Requêtes & Verrous]${NC}"

# Requêtes longues
long_queries=$(pg_query "SELECT count(*) FROM pg_stat_activity WHERE state = 'active' AND now() - query_start > interval '$LONG_QUERY_SECONDS seconds' AND query NOT LIKE 'autovacuum%'")
if [[ $long_queries -gt 0 ]]; then
    check_result "Long running queries (>${LONG_QUERY_SECONDS}s)" "warn" "$long_queries"
else
    check_result "Long running queries" "pass" "None"
fi

# Verrous en attente
waiting_locks=$(pg_query "SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock'")
if [[ $waiting_locks -gt 5 ]]; then
    check_result "Waiting on locks" "warn" "$waiting_locks session(s)"
elif [[ $waiting_locks -gt 0 ]]; then
    check_result "Waiting on locks" "info" "$waiting_locks session(s)"
else
    check_result "Waiting on locks" "pass" "None"
fi

# Deadlocks
deadlocks=$(pg_query "SELECT deadlocks FROM pg_stat_database WHERE datname = current_database()")
if [[ $deadlocks -gt 0 ]]; then
    check_result "Deadlocks" "warn" "$deadlocks total"
else
    check_result "Deadlocks" "pass" "None"
fi

# ═══════════════════════════════════════════════════════════════════
# CHECK 10: WAL et Archivage
# ═══════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[WAL & Archivage]${NC}"

# Taille WAL
wal_size=$(pg_query "SELECT pg_size_pretty(sum(size)) FROM pg_ls_waldir()" 2>/dev/null)
[[ -n "$wal_size" ]] && check_result "WAL Size" "info" "$wal_size"

# Archivage
archive_mode=$(pg_query "SHOW archive_mode")
if [[ "$archive_mode" == "on" ]]; then
    # Check les WAL en attente
    pending_wal=$(pg_query "SELECT count(*) FROM pg_stat_archiver WHERE last_failed_time > last_archived_time" 2>/dev/null)
    if [[ "$pending_wal" == "1" ]]; then
        check_result "WAL Archiving" "warn" "Archive errors detected"
    else
        check_result "WAL Archiving" "pass" "Enabled and working"
    fi
else
    check_result "WAL Archiving" "info" "Disabled"
fi

# ═══════════════════════════════════════════════════════════════════
# RÉSUMÉ
# ═══════════════════════════════════════════════════════════════════
echo ""
echo -e "${CYAN}=================================================================${NC}"
echo -e "${GREEN}  RÉSUMÉ${NC}"
echo -e "${CYAN}=================================================================${NC}"

echo "  Checks: $TOTAL total"
echo -e "    - ${GREEN}Passed: $PASSED${NC}"
echo -e "    - ${YELLOW}Warnings: $WARNINGS${NC}"
echo -e "    - ${RED}Failed: $FAILED${NC}"

echo ""
if [[ $FAILED -gt 0 ]]; then
    echo -e "  ${RED}POSTGRESQL STATUS: CRITICAL${NC}"
    exit 2
elif [[ $WARNINGS -gt 0 ]]; then
    echo -e "  ${YELLOW}POSTGRESQL STATUS: DEGRADED${NC}"
    exit 1
else
    echo -e "  ${GREEN}POSTGRESQL STATUS: HEALTHY${NC}"
    exit 0
fi
```

---

## Usage

```bash
# Server local
./check-postgresql.sh

# Server distant
./check-postgresql.sh -h pg.domain.local -U admin -d mydb

# Port personnalisé
./check-postgresql.sh -h pg.domain.local -p 5433
```

---

## Exemple de Sortie

```text
=================================================================
  POSTGRESQL HEALTH CHECK
=================================================================
  Host: localhost:5432
  User: postgres
  Date: 2025-12-01 16:02:38
-----------------------------------------------------------------

[Service PostgreSQL]
[OK]   Service postgresql - Running

[Connectivité]
[OK]   Port 5432 - Open
[OK]   PostgreSQL Connection - Connected
       Version: 16.1

[État Général]
[OK]   Uptime - 32 days 08:45:12
[INFO] Server Role - Primary

[Connections]
       Current: 45 / 97 (max: 100)
[OK]   Connection Usage - 46%
       By state:
         - active: 8
         - idle: 35
         - idle in transaction: 2

[Bases de Données]
[INFO] User Databases - 6
       Total size: 156 GB
       Largest databases:
         - production: 98 GB
         - analytics: 42 GB
         - staging: 12 GB
         - development: 3584 MB
         - test: 512 MB

[Réplication]
[OK]   Streaming Replicas - 2 connected
         - 192.168.1.51: streaming (lag: 0MB)
         - 192.168.1.52: streaming (lag: 2MB)

[Vacuum & Maintenance]
[OK]   Autovacuum - Enabled
[WARN] Tables needing vacuum - 3 table(s)
[OK]   Transaction ID Age - 124567892

[Performance I/O]
[OK]   Cache Hit Ratio - 99.42%
       Index hit ratio: 99.87%
       Checkpoints: 156 1247 (req|timed)

[Requêtes & Verrous]
[OK]   Long running queries - None
[INFO] Waiting on locks - 1 session(s)
[OK]   Deadlocks - None

[WAL & Archivage]
[INFO] WAL Size - 2.1 GB
[OK]   WAL Archiving - Enabled and working

=================================================================
  RÉSUMÉ
=================================================================
  Checks: 18 total
    - Passed: 14
    - Warnings: 1
    - Failed: 0

  POSTGRESQL STATUS: DEGRADED
```

---

## Voir Aussi

- [check-mysql.sh](check-mysql.md)
- [check-ldap.sh](check-ldap.md)
