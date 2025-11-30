---
tags:
  - scripts
  - bash
  - mysql
  - mariadb
  - database
  - linux
---

# check-mysql.sh

:material-star::material-star: **Niveau : Intermédiaire**

Vérification complète d'un serveur MySQL/MariaDB.

---

## Description

Ce script vérifie l'état d'un serveur MySQL/MariaDB :
- Service et connectivité
- État des bases de données
- Réplication master/slave
- Connections actives et threads
- Disk space et taille des tables
- Variables critiques
- Slow queries

---

## Script

```bash
#!/bin/bash
#===============================================================================
# check-mysql.sh - Vérification santé serveur MySQL/MariaDB
#===============================================================================
# Usage: ./check-mysql.sh [-h host] [-P port] [-u user] [-p password]
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
MYSQL_HOST="localhost"
MYSQL_PORT="3306"
MYSQL_USER="root"
MYSQL_PASS=""
MYSQL_SOCKET=""

# Seuils
CONN_WARNING_PCT=70
CONN_CRITICAL_PCT=90
SLOW_QUERY_THRESHOLD=100

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
    -h HOST      Server MySQL (default: localhost)
    -P PORT      Port MySQL (default: 3306)
    -u USER      Utilisateur (default: root)
    -p PASSWORD  Mot de passe
    -S SOCKET    Socket Unix
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

mysql_query() {
    local query="$1"
    local opts="-h $MYSQL_HOST -P $MYSQL_PORT -u $MYSQL_USER"
    [[ -n "$MYSQL_PASS" ]] && opts="$opts -p$MYSQL_PASS"
    [[ -n "$MYSQL_SOCKET" ]] && opts="$opts -S $MYSQL_SOCKET"

    mysql $opts -N -e "$query" 2>/dev/null
}

mysql_value() {
    local query="$1"
    mysql_query "$query" | head -1 | awk '{print $NF}'
}

#===============================================================================
# Parse arguments
#===============================================================================
while [[ $# -gt 0 ]]; do
    case $1 in
        -h) MYSQL_HOST="$2"; shift 2 ;;
        -P) MYSQL_PORT="$2"; shift 2 ;;
        -u) MYSQL_USER="$2"; shift 2 ;;
        -p) MYSQL_PASS="$2"; shift 2 ;;
        -S) MYSQL_SOCKET="$2"; shift 2 ;;
        --help) usage ;;
        *) echo "Unknown option: $1"; usage ;;
    esac
done

#===============================================================================
# Main
#===============================================================================
echo ""
echo -e "${CYAN}=================================================================${NC}"
echo -e "${GREEN}  MYSQL/MARIADB HEALTH CHECK${NC}"
echo -e "${CYAN}=================================================================${NC}"
echo "  Host: $MYSQL_HOST:$MYSQL_PORT"
echo "  User: $MYSQL_USER"
echo "  Date: $(date '+%Y-%m-%d %H:%M:%S')"
echo -e "${CYAN}-----------------------------------------------------------------${NC}"

# ═══════════════════════════════════════════════════════════════════
# CHECK 1: Service MySQL
# ═══════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[Service MySQL]${NC}"

if systemctl is-active --quiet mysql 2>/dev/null; then
    check_result "Service mysql" "pass" "Running"
elif systemctl is-active --quiet mariadb 2>/dev/null; then
    check_result "Service mariadb" "pass" "Running"
elif systemctl is-active --quiet mysqld 2>/dev/null; then
    check_result "Service mysqld" "pass" "Running"
elif pgrep -x mysqld > /dev/null || pgrep -x mariadbd > /dev/null; then
    check_result "Process MySQL" "pass" "Running"
else
    check_result "Service MySQL" "fail" "Not running"
fi

# ═══════════════════════════════════════════════════════════════════
# CHECK 2: Connectivité
# ═══════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[Connectivité]${NC}"

# Test port
if nc -z -w 3 "$MYSQL_HOST" "$MYSQL_PORT" 2>/dev/null; then
    check_result "Port $MYSQL_PORT" "pass" "Open"
else
    check_result "Port $MYSQL_PORT" "fail" "Closed"
    echo -e "\n${RED}[FATAL] Cannot connect to MySQL. Aborting.${NC}"
    exit 2
fi

# Test connexion MySQL
version=$(mysql_value "SELECT VERSION()")
if [[ -n "$version" ]]; then
    check_result "MySQL Connection" "pass" "Connected"
    echo -e "       ${GRAY}Version: $version${NC}"
else
    check_result "MySQL Connection" "fail" "Authentication failed"
    echo -e "\n${RED}[FATAL] Cannot authenticate. Aborting.${NC}"
    exit 2
fi

# ═══════════════════════════════════════════════════════════════════
# CHECK 3: Uptime et état général
# ═══════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[État Général]${NC}"

uptime_seconds=$(mysql_value "SHOW GLOBAL STATUS LIKE 'Uptime'" | awk '{print $2}')
if [[ -n "$uptime_seconds" ]]; then
    uptime_days=$((uptime_seconds / 86400))
    uptime_hours=$(( (uptime_seconds % 86400) / 3600 ))

    if [[ $uptime_seconds -lt 3600 ]]; then
        check_result "Uptime" "warn" "${uptime_seconds}s (recently restarted)"
    else
        check_result "Uptime" "pass" "${uptime_days}d ${uptime_hours}h"
    fi
fi

# Questions (total queries)
questions=$(mysql_value "SHOW GLOBAL STATUS LIKE 'Questions'" | awk '{print $2}')
qps=$((questions / uptime_seconds))
echo -e "       ${GRAY}Total queries: $questions (${qps}/sec avg)${NC}"

# ═══════════════════════════════════════════════════════════════════
# CHECK 4: Connections
# ═══════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[Connections]${NC}"

max_connections=$(mysql_value "SHOW VARIABLES LIKE 'max_connections'" | awk '{print $2}')
current_connections=$(mysql_value "SHOW GLOBAL STATUS LIKE 'Threads_connected'" | awk '{print $2}')
max_used=$(mysql_value "SHOW GLOBAL STATUS LIKE 'Max_used_connections'" | awk '{print $2}')

conn_pct=$((current_connections * 100 / max_connections))

echo -e "       ${GRAY}Current: $current_connections / $max_connections${NC}"
echo -e "       ${GRAY}Max used: $max_used${NC}"

if [[ $conn_pct -ge $CONN_CRITICAL_PCT ]]; then
    check_result "Connection Usage" "fail" "${conn_pct}% (critical)"
elif [[ $conn_pct -ge $CONN_WARNING_PCT ]]; then
    check_result "Connection Usage" "warn" "${conn_pct}%"
else
    check_result "Connection Usage" "pass" "${conn_pct}%"
fi

# Connections refusées
aborted_connects=$(mysql_value "SHOW GLOBAL STATUS LIKE 'Aborted_connects'" | awk '{print $2}')
if [[ $aborted_connects -gt 100 ]]; then
    check_result "Aborted Connections" "warn" "$aborted_connects"
else
    check_result "Aborted Connections" "info" "$aborted_connects"
fi

# ═══════════════════════════════════════════════════════════════════
# CHECK 5: Bases de données
# ═══════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[Bases de Données]${NC}"

db_count=$(mysql_query "SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME NOT IN ('information_schema', 'performance_schema', 'mysql', 'sys')")
check_result "User Databases" "info" "$db_count"

# Taille totale
total_size=$(mysql_query "SELECT ROUND(SUM(data_length + index_length) / 1024 / 1024 / 1024, 2) AS 'Size (GB)' FROM information_schema.TABLES" | head -1)
echo -e "       ${GRAY}Total size: ${total_size:-0} GB${NC}"

# Top 5 bases par taille
echo -e "       ${GRAY}Largest databases:${NC}"
mysql_query "SELECT table_schema, ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) AS 'Size (MB)' FROM information_schema.TABLES GROUP BY table_schema ORDER BY SUM(data_length + index_length) DESC LIMIT 5" | while read db size; do
    echo -e "       ${GRAY}  - $db: ${size}MB${NC}"
done

# ═══════════════════════════════════════════════════════════════════
# CHECK 6: Réplication
# ═══════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[Réplication]${NC}"

# Check slave status
slave_status=$(mysql_query "SHOW SLAVE STATUS\G" 2>/dev/null)

if [[ -n "$slave_status" ]]; then
    slave_io=$(echo "$slave_status" | grep "Slave_IO_Running:" | awk '{print $2}')
    slave_sql=$(echo "$slave_status" | grep "Slave_SQL_Running:" | awk '{print $2}')
    seconds_behind=$(echo "$slave_status" | grep "Seconds_Behind_Master:" | awk '{print $2}')
    last_error=$(echo "$slave_status" | grep "Last_Error:" | cut -d: -f2-)

    if [[ "$slave_io" == "Yes" ]] && [[ "$slave_sql" == "Yes" ]]; then
        if [[ "$seconds_behind" == "NULL" ]] || [[ -z "$seconds_behind" ]]; then
            check_result "Replication" "warn" "Status unknown"
        elif [[ $seconds_behind -gt 300 ]]; then
            check_result "Replication" "warn" "${seconds_behind}s behind master"
        else
            check_result "Replication" "pass" "${seconds_behind}s behind"
        fi
    else
        check_result "Replication" "fail" "IO=$slave_io SQL=$slave_sql"
        [[ -n "$last_error" ]] && echo -e "       ${RED}Error: $last_error${NC}"
    fi
else
    # Check master status
    master_status=$(mysql_query "SHOW MASTER STATUS" 2>/dev/null)
    if [[ -n "$master_status" ]]; then
        binlog_file=$(echo "$master_status" | awk '{print $1}')
        binlog_pos=$(echo "$master_status" | awk '{print $2}')
        check_result "Replication" "info" "Master (File: $binlog_file, Pos: $binlog_pos)"
    else
        check_result "Replication" "info" "Not configured"
    fi
fi

# ═══════════════════════════════════════════════════════════════════
# CHECK 7: InnoDB Status
# ═══════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[InnoDB]${NC}"

# Buffer pool
buffer_pool_size=$(mysql_value "SHOW VARIABLES LIKE 'innodb_buffer_pool_size'" | awk '{print $2}')
buffer_pool_gb=$(echo "scale=2; $buffer_pool_size / 1024 / 1024 / 1024" | bc 2>/dev/null || echo "N/A")
check_result "Buffer Pool Size" "info" "${buffer_pool_gb}GB"

# Buffer pool hit ratio
reads=$(mysql_value "SHOW GLOBAL STATUS LIKE 'Innodb_buffer_pool_reads'" | awk '{print $2}')
read_requests=$(mysql_value "SHOW GLOBAL STATUS LIKE 'Innodb_buffer_pool_read_requests'" | awk '{print $2}')

if [[ $read_requests -gt 0 ]]; then
    hit_ratio=$(echo "scale=2; (1 - $reads / $read_requests) * 100" | bc 2>/dev/null)
    if [[ -n "$hit_ratio" ]]; then
        if (( $(echo "$hit_ratio < 95" | bc -l 2>/dev/null || echo 0) )); then
            check_result "Buffer Pool Hit Ratio" "warn" "${hit_ratio}%"
        else
            check_result "Buffer Pool Hit Ratio" "pass" "${hit_ratio}%"
        fi
    fi
fi

# Pending I/O
pending_reads=$(mysql_value "SHOW GLOBAL STATUS LIKE 'Innodb_data_pending_reads'" | awk '{print $2}')
pending_writes=$(mysql_value "SHOW GLOBAL STATUS LIKE 'Innodb_data_pending_writes'" | awk '{print $2}')
echo -e "       ${GRAY}Pending I/O: reads=$pending_reads writes=$pending_writes${NC}"

# ═══════════════════════════════════════════════════════════════════
# CHECK 8: Slow Queries
# ═══════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[Slow Queries]${NC}"

slow_queries=$(mysql_value "SHOW GLOBAL STATUS LIKE 'Slow_queries'" | awk '{print $2}')
slow_query_log=$(mysql_value "SHOW VARIABLES LIKE 'slow_query_log'" | awk '{print $2}')
long_query_time=$(mysql_value "SHOW VARIABLES LIKE 'long_query_time'" | awk '{print $2}')

echo -e "       ${GRAY}Long query time: ${long_query_time}s${NC}"

if [[ "$slow_query_log" == "ON" ]]; then
    check_result "Slow Query Log" "pass" "Enabled"
else
    check_result "Slow Query Log" "warn" "Disabled"
fi

if [[ $slow_queries -gt $SLOW_QUERY_THRESHOLD ]]; then
    check_result "Slow Queries" "warn" "$slow_queries total"
else
    check_result "Slow Queries" "info" "$slow_queries total"
fi

# ═══════════════════════════════════════════════════════════════════
# CHECK 9: Tables nécessitant maintenance
# ═══════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[Maintenance]${NC}"

# Tables fragmentées
fragmented=$(mysql_query "SELECT COUNT(*) FROM information_schema.TABLES WHERE DATA_FREE > 100*1024*1024 AND ENGINE='InnoDB'" | head -1)
if [[ $fragmented -gt 0 ]]; then
    check_result "Fragmented Tables" "warn" "$fragmented table(s) > 100MB free space"
else
    check_result "Fragmented Tables" "pass" "None significant"
fi

# Tables sans primary key
no_pk=$(mysql_query "SELECT COUNT(*) FROM information_schema.TABLES t LEFT JOIN information_schema.TABLE_CONSTRAINTS tc ON t.TABLE_SCHEMA = tc.TABLE_SCHEMA AND t.TABLE_NAME = tc.TABLE_NAME AND tc.CONSTRAINT_TYPE = 'PRIMARY KEY' WHERE t.TABLE_SCHEMA NOT IN ('information_schema', 'mysql', 'performance_schema', 'sys') AND t.TABLE_TYPE = 'BASE TABLE' AND tc.CONSTRAINT_NAME IS NULL" | head -1)
if [[ $no_pk -gt 0 ]]; then
    check_result "Tables without PK" "warn" "$no_pk table(s)"
else
    check_result "Tables without PK" "pass" "All tables have PK"
fi

# ═══════════════════════════════════════════════════════════════════
# CHECK 10: Sécurité basique
# ═══════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[Sécurité]${NC}"

# Utilisateurs sans mot de passe
no_password=$(mysql_query "SELECT COUNT(*) FROM mysql.user WHERE authentication_string = '' OR authentication_string IS NULL" 2>/dev/null | head -1)
if [[ -n "$no_password" ]] && [[ $no_password -gt 0 ]]; then
    check_result "Users without password" "warn" "$no_password user(s)"
else
    check_result "Users without password" "pass" "None"
fi

# Root accessible depuis n'importe où
root_anywhere=$(mysql_query "SELECT COUNT(*) FROM mysql.user WHERE User='root' AND Host='%'" 2>/dev/null | head -1)
if [[ "$root_anywhere" == "1" ]]; then
    check_result "Root remote access" "warn" "Enabled from any host"
else
    check_result "Root remote access" "pass" "Restricted"
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
    echo -e "  ${RED}MYSQL STATUS: CRITICAL${NC}"
    exit 2
elif [[ $WARNINGS -gt 0 ]]; then
    echo -e "  ${YELLOW}MYSQL STATUS: DEGRADED${NC}"
    exit 1
else
    echo -e "  ${GREEN}MYSQL STATUS: HEALTHY${NC}"
    exit 0
fi
```

---

## Usage

```bash
# Server local (root sans mot de passe)
./check-mysql.sh

# Server distant avec authentification
./check-mysql.sh -h mysql.domain.local -u admin -p 'password'

# Via socket Unix
./check-mysql.sh -S /var/run/mysqld/mysqld.sock -u root
```

---

## Voir Aussi

- [check-postgresql.sh](check-postgresql.md)
- [check-ldap.sh](check-ldap.md)
