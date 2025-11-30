---
tags:
  - scripts
  - bash
  - nginx
  - web
  - linux
---

# check-nginx.sh

:material-star::material-star: **Niveau : Intermédiaire**

Vérification complète d'un serveur Nginx.

---

## Description

Ce script vérifie l'état d'un serveur Nginx :
- Service et processus workers
- Configuration syntaxique
- Sites actifs et SSL
- Certificats et expiration
- Logs et erreurs récentes
- Statistiques (si stub_status activé)

---

## Script

```bash
#!/bin/bash
#===============================================================================
# check-nginx.sh - Vérification santé serveur Nginx
#===============================================================================
# Usage: ./check-nginx.sh [-c config_path] [-s status_url]
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
NGINX_CONF="/etc/nginx/nginx.conf"
SITES_DIR="/etc/nginx/sites-enabled"
STATUS_URL=""
CERT_WARNING_DAYS=30

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
    -c CONFIG    Chemin nginx.conf (default: /etc/nginx/nginx.conf)
    -s URL       URL stub_status pour statistiques
    -d DAYS      Jours avant alerte expiration SSL (default: 30)
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

check_ssl_cert() {
    local domain="$1"
    local port="${2:-443}"

    cert_info=$(echo | timeout 5 openssl s_client -servername "$domain" \
        -connect "$domain:$port" 2>/dev/null | \
        openssl x509 -noout -dates -subject 2>/dev/null)

    if [[ -n "$cert_info" ]]; then
        not_after=$(echo "$cert_info" | grep "notAfter" | cut -d= -f2)
        subject=$(echo "$cert_info" | grep "subject" | sed 's/subject=//')

        if [[ -n "$not_after" ]]; then
            expiry_epoch=$(date -d "$not_after" +%s 2>/dev/null)
            now_epoch=$(date +%s)
            days_left=$(( (expiry_epoch - now_epoch) / 86400 ))

            echo "$days_left|$subject"
        fi
    fi
}

#===============================================================================
# Parse arguments
#===============================================================================
while [[ $# -gt 0 ]]; do
    case $1 in
        -c) NGINX_CONF="$2"; shift 2 ;;
        -s) STATUS_URL="$2"; shift 2 ;;
        -d) CERT_WARNING_DAYS="$2"; shift 2 ;;
        --help) usage ;;
        *) echo "Unknown option: $1"; usage ;;
    esac
done

#===============================================================================
# Main
#===============================================================================
echo ""
echo -e "${CYAN}=================================================================${NC}"
echo -e "${GREEN}  NGINX HEALTH CHECK${NC}"
echo -e "${CYAN}=================================================================${NC}"
echo "  Date: $(date '+%Y-%m-%d %H:%M:%S')"
echo -e "${CYAN}-----------------------------------------------------------------${NC}"

# ═══════════════════════════════════════════════════════════════════
# CHECK 1: Service Nginx
# ═══════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[Service Nginx]${NC}"

if systemctl is-active --quiet nginx 2>/dev/null; then
    check_result "Service nginx" "pass" "Running"
elif pgrep -x nginx > /dev/null; then
    check_result "Process nginx" "pass" "Running"
else
    check_result "Service nginx" "fail" "Not running"
fi

# Version
nginx_version=$(nginx -v 2>&1 | grep -oP 'nginx/\K[0-9.]+')
if [[ -n "$nginx_version" ]]; then
    echo -e "       ${GRAY}Version: $nginx_version${NC}"
fi

# ═══════════════════════════════════════════════════════════════════
# CHECK 2: Processus Workers
# ═══════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[Processus]${NC}"

master_pid=$(pgrep -x nginx | head -1)
worker_count=$(pgrep -x nginx | wc -l)
worker_count=$((worker_count - 1))  # Exclure le master

if [[ $worker_count -gt 0 ]]; then
    check_result "Worker processes" "pass" "$worker_count worker(s)"
else
    check_result "Worker processes" "warn" "No workers running"
fi

# CPU et mémoire des workers
if [[ $worker_count -gt 0 ]]; then
    total_mem=$(ps -C nginx -o rss= | awk '{sum+=$1} END {print sum/1024}')
    echo -e "       ${GRAY}Total memory: ${total_mem}MB${NC}"
fi

# Configured workers
conf_workers=$(grep -E "^\s*worker_processes" "$NGINX_CONF" 2>/dev/null | awk '{print $2}' | tr -d ';')
echo -e "       ${GRAY}Configured: $conf_workers worker(s)${NC}"

# ═══════════════════════════════════════════════════════════════════
# CHECK 3: Configuration
# ═══════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[Configuration]${NC}"

# Test syntaxe
config_test=$(nginx -t 2>&1)
if echo "$config_test" | grep -q "syntax is ok"; then
    check_result "Configuration syntax" "pass" "Valid"
else
    check_result "Configuration syntax" "fail" "Invalid"
    echo -e "       ${RED}$config_test${NC}"
fi

# Ficyesterday de config principal
if [[ -f "$NGINX_CONF" ]]; then
    check_result "Main config" "pass" "$NGINX_CONF"
else
    check_result "Main config" "fail" "Not found: $NGINX_CONF"
fi

# ═══════════════════════════════════════════════════════════════════
# CHECK 4: Sites actifs
# ═══════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[Sites Actives]${NC}"

if [[ -d "$SITES_DIR" ]]; then
    site_count=$(ls -1 "$SITES_DIR" 2>/dev/null | wc -l)
    check_result "Enabled sites" "info" "$site_count site(s)"

    # Lister les sites et leurs ports
    for site in "$SITES_DIR"/*; do
        if [[ -f "$site" ]]; then
            site_name=$(basename "$site")
            listen_ports=$(grep -E "^\s*listen" "$site" 2>/dev/null | \
                awk '{print $2}' | tr -d ';' | sort -u | tr '\n' ' ')
            server_names=$(grep -E "^\s*server_name" "$site" 2>/dev/null | \
                head -1 | awk '{$1=""; print $0}' | tr -d ';' | xargs)

            echo -e "       ${GRAY}$site_name: ${server_names:-_} (ports: ${listen_ports:-?})${NC}"
        fi
    done
else
    # Configuration incluse directement
    server_blocks=$(grep -c "server {" "$NGINX_CONF" 2>/dev/null)
    check_result "Server blocks" "info" "$server_blocks"
fi

# ═══════════════════════════════════════════════════════════════════
# CHECK 5: Ports d'écoute
# ═══════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[Ports d'écoute]${NC}"

# Port 80
if ss -tlnp 2>/dev/null | grep -q ":80 "; then
    check_result "Port 80 (HTTP)" "pass" "Listening"
else
    check_result "Port 80 (HTTP)" "info" "Not listening"
fi

# Port 443
if ss -tlnp 2>/dev/null | grep -q ":443 "; then
    check_result "Port 443 (HTTPS)" "pass" "Listening"
else
    check_result "Port 443 (HTTPS)" "info" "Not listening"
fi

# Autres ports nginx
other_ports=$(ss -tlnp 2>/dev/null | grep nginx | grep -v -E ":(80|443) " | \
    awk '{print $4}' | rev | cut -d: -f1 | rev | sort -u | tr '\n' ' ')
[[ -n "$other_ports" ]] && echo -e "       ${GRAY}Other ports: $other_ports${NC}"

# ═══════════════════════════════════════════════════════════════════
# CHECK 6: Certificats SSL
# ═══════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[Certificats SSL]${NC}"

# Trouver les certificats configurés
ssl_certs=$(grep -rh "ssl_certificate\s" /etc/nginx/ 2>/dev/null | \
    grep -v "ssl_certificate_key" | awk '{print $2}' | tr -d ';' | sort -u)

if [[ -n "$ssl_certs" ]]; then
    while read -r cert_path; do
        if [[ -f "$cert_path" ]]; then
            cert_info=$(openssl x509 -in "$cert_path" -noout -dates -subject 2>/dev/null)
            not_after=$(echo "$cert_info" | grep "notAfter" | cut -d= -f2)
            subject=$(echo "$cert_info" | grep "subject" | sed 's/.*CN\s*=\s*//' | cut -d',' -f1)

            if [[ -n "$not_after" ]]; then
                expiry_epoch=$(date -d "$not_after" +%s 2>/dev/null)
                now_epoch=$(date +%s)
                days_left=$(( (expiry_epoch - now_epoch) / 86400 ))

                if [[ $days_left -lt 0 ]]; then
                    check_result "Cert $subject" "fail" "EXPIRED"
                elif [[ $days_left -lt $CERT_WARNING_DAYS ]]; then
                    check_result "Cert $subject" "warn" "Expires in $days_left days"
                else
                    check_result "Cert $subject" "pass" "Valid ($days_left days)"
                fi
            fi
        else
            check_result "Certificate" "warn" "File not found: $cert_path"
        fi
    done <<< "$ssl_certs"
else
    check_result "SSL Certificates" "info" "None configured"
fi

# ═══════════════════════════════════════════════════════════════════
# CHECK 7: Logs
# ═══════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[Logs]${NC}"

# Error log
error_log=$(grep -E "^\s*error_log" "$NGINX_CONF" 2>/dev/null | head -1 | awk '{print $2}' | tr -d ';')
error_log="${error_log:-/var/log/nginx/error.log}"

if [[ -f "$error_log" ]]; then
    log_size=$(du -h "$error_log" 2>/dev/null | awk '{print $1}')
    check_result "Error log" "info" "$error_log ($log_size)"

    # Erreurs récentes (last heure)
    recent_errors=$(awk -v date="$(date -d '1 hour ago' '+%Y/%m/%d %H')" \
        '$0 ~ date {count++} END {print count+0}' "$error_log" 2>/dev/null)

    if [[ $recent_errors -gt 100 ]]; then
        check_result "Recent errors (1h)" "warn" "$recent_errors"
    else
        check_result "Recent errors (1h)" "pass" "$recent_errors"
    fi

    # Types d'erreurs
    echo -e "       ${GRAY}Last 5 unique errors:${NC}"
    tail -100 "$error_log" 2>/dev/null | \
        grep -oP '\[error\].*' | cut -d',' -f1 | sort | uniq -c | \
        sort -rn | head -5 | while read count error; do
            echo -e "       ${GRAY}  $count: ${error:0:60}...${NC}"
        done
else
    check_result "Error log" "warn" "Not found: $error_log"
fi

# Access log
access_log=$(grep -E "^\s*access_log" "$NGINX_CONF" 2>/dev/null | head -1 | awk '{print $2}' | tr -d ';')
access_log="${access_log:-/var/log/nginx/access.log}"

if [[ -f "$access_log" ]]; then
    log_size=$(du -h "$access_log" 2>/dev/null | awk '{print $1}')
    check_result "Access log" "info" "$access_log ($log_size)"

    # Requêtes par minute (last minute)
    rpm=$(tail -1000 "$access_log" 2>/dev/null | \
        awk -v min="$(date -d '1 minute ago' '+%d/%b/%Y:%H:%M')" \
        '$0 ~ min {count++} END {print count+0}')
    echo -e "       ${GRAY}Requests last minute: $rpm${NC}"
fi

# ═══════════════════════════════════════════════════════════════════
# CHECK 8: Stub Status (si configuré)
# ═══════════════════════════════════════════════════════════════════
if [[ -n "$STATUS_URL" ]]; then
    echo -e "\n${CYAN}[Statistiques]${NC}"

    status_output=$(curl -s "$STATUS_URL" 2>/dev/null)

    if [[ -n "$status_output" ]]; then
        active=$(echo "$status_output" | grep "Active" | awk '{print $3}')
        accepts=$(echo "$status_output" | sed -n '3p' | awk '{print $1}')
        handled=$(echo "$status_output" | sed -n '3p' | awk '{print $2}')
        requests=$(echo "$status_output" | sed -n '3p' | awk '{print $3}')
        reading=$(echo "$status_output" | grep "Reading" | awk '{print $2}')
        writing=$(echo "$status_output" | grep "Writing" | awk '{print $4}')
        waiting=$(echo "$status_output" | grep "Waiting" | awk '{print $6}')

        check_result "Active connections" "info" "$active"
        echo -e "       ${GRAY}Accepts: $accepts | Handled: $handled | Requests: $requests${NC}"
        echo -e "       ${GRAY}Reading: $reading | Writing: $writing | Waiting: $waiting${NC}"

        # Check les connexions dropping
        dropped=$((accepts - handled))
        if [[ $dropped -gt 0 ]]; then
            check_result "Dropped connections" "warn" "$dropped"
        fi
    else
        check_result "Stub status" "warn" "Could not fetch: $STATUS_URL"
    fi
fi

# ═══════════════════════════════════════════════════════════════════
# CHECK 9: Sécurité basique
# ═══════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[Sécurité]${NC}"

# Server tokens
if grep -rq "server_tokens off" /etc/nginx/ 2>/dev/null; then
    check_result "Server tokens" "pass" "Hidden"
else
    check_result "Server tokens" "warn" "Visible (server_tokens on)"
fi

# SSL protocols
ssl_protocols=$(grep -rh "ssl_protocols" /etc/nginx/ 2>/dev/null | head -1)
if echo "$ssl_protocols" | grep -qE "TLSv1\s|TLSv1\.0|SSLv"; then
    check_result "SSL Protocols" "warn" "Legacy protocols enabled"
else
    check_result "SSL Protocols" "pass" "Modern protocols only"
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
    echo -e "  ${RED}NGINX STATUS: CRITICAL${NC}"
    exit 2
elif [[ $WARNINGS -gt 0 ]]; then
    echo -e "  ${YELLOW}NGINX STATUS: DEGRADED${NC}"
    exit 1
else
    echo -e "  ${GREEN}NGINX STATUS: HEALTHY${NC}"
    exit 0
fi
```

---

## Usage

```bash
# Vérification basique
./check-nginx.sh

# Avec stub_status
./check-nginx.sh -s http://localhost/nginx_status

# Config personnalisée
./check-nginx.sh -c /opt/nginx/nginx.conf
```

---

## Configuration stub_status

Pour activer les statistiques, ajoutez dans votre configuration :

```nginx
server {
    listen 127.0.0.1:8080;
    location /nginx_status {
        stub_status on;
        allow 127.0.0.1;
        deny all;
    }
}
```

---

## Voir Aussi

- [ssl-csr-wizard.sh](ssl-csr-wizard.md) - Génération CSR SSL
- [health-check.sh](health-check.md) - Vérification santé services
