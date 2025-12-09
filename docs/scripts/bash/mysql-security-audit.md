---
tags:
  - scripts
  - bash
  - mysql
  - mariadb
  - security
  - audit
---

# mysql-security-audit.sh

Outil d'audit de sécurité rapide pour MySQL/MariaDB avec rapport colorisé PASS/FAIL.

---

## Informations

| Propriété | Valeur |
|-----------|--------|
| **Langage** | Bash |
| **Catégorie** | Base de données / Sécurité |
| **Niveau** | :material-star::material-star: Intermédiaire |
| **Dépendances** | mysql client |

---

## Description

Ce script effectue un audit de sécurité rapide d'une instance MySQL ou MariaDB en vérifiant les failles de configuration les plus courantes. Il produit un rapport colorisé indiquant clairement les tests succeededs (PASS) et faileds (FAIL).

**Vérifications effectuées :**

1. **Mots de passe vides** : Utilisateurs sans authentification
2. **Root accessible à distance** : `root@'%'` est un risque critique
3. **Utilisateurs anonymes** : Comptes sans nom (legacy)
4. **Privilèges excessifs** : Utilisateurs avec `GRANT ALL PRIVILEGES`
5. **Bases de données de test** : Présence de `test` database
6. **Plugin d'authentification** : Vérification des méthodes sécurisées

---

## Prérequis

```bash
# Client MySQL installé
mysql --version

# Accès administrateur à l'instance MySQL
# L'utilisateur doit pouvoir lire mysql.user et information_schema
```

---

## Cas d'Usage

- **Audit de sécurité périodique** : Vérification automatisée des configurations de sécurité MySQL avec rapport détaillé
- **Conformité réglementaire** : Documentation et validation des paramètres de sécurité pour audits
- **Durcissement post-installation** : Identification rapide des failles de sécurité après installation MySQL
- **Validation avant production** : Test de sécurité complet avant mise en production d'un serveur de base de données

---

## Script

```bash
#!/bin/bash
#===============================================================================
# Script Name: mysql-security-audit.sh
# Description: Rapid security assessment of MySQL/MariaDB instance
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

# Default connection parameters
DB_HOST="${MYSQL_HOST:-localhost}"
DB_PORT="${MYSQL_TCP_PORT:-3306}"
DB_USER="${MYSQL_USER:-root}"
DB_SOCKET=""

# Counters
PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0

# Functions
log_pass() {
    echo -e "  ${GREEN}[PASS]${NC} $1"
    ((PASS_COUNT++))
}

log_fail() {
    echo -e "  ${RED}[FAIL]${NC} $1"
    ((FAIL_COUNT++))
}

log_warn() {
    echo -e "  ${YELLOW}[WARN]${NC} $1"
    ((WARN_COUNT++))
}

log_info() {
    echo -e "  ${BLUE}[INFO]${NC} $1"
}

usage() {
    cat << EOF
${CYAN}Usage:${NC} $SCRIPT_NAME [OPTIONS]

Perform a rapid security audit of a MySQL/MariaDB instance.

${CYAN}Options:${NC}
    -h, --help          Show this help
    -H, --host HOST     Hôte MySQL (default: localhost)
    -P, --port PORT     Port MySQL (default: 3306)
    -u, --user USER     Utilisateur MySQL (default: root)
    -p, --password      Demander le mot de passe
    -S, --socket PATH   Chemin du socket Unix

${CYAN}Variables d'environnement:${NC}
    MYSQL_HOST, MYSQL_TCP_PORT, MYSQL_USER, MYSQL_PWD

${CYAN}Examples:${NC}
    $SCRIPT_NAME
    $SCRIPT_NAME -H db.example.com -u admin -p
    $SCRIPT_NAME -S /var/run/mysqld/mysqld.sock

${CYAN}Vérifications effectuées:${NC}
    1. Utilisateurs avec mots de passe vides
    2. Root accessible depuis '%' (remote)
    3. Existence d'utilisateurs anonymes
    4. Utilisateurs avec GRANT ALL PRIVILEGES
    5. Présence de la base 'test'
    6. Plugins d'authentification non sécurisés

EOF
}

# Build MySQL command with connection parameters
mysql_cmd() {
    local cmd="mysql -N -B"

    if [[ -n "$DB_SOCKET" ]]; then
        cmd="$cmd -S $DB_SOCKET"
    else
        cmd="$cmd -h $DB_HOST -P $DB_PORT"
    fi

    cmd="$cmd -u $DB_USER"

    echo "$cmd"
}

# Test database connection
test_connection() {
    echo -e "\n${BOLD}${CYAN}=== TEST DE CONNEXION ===${NC}\n"

    local cmd
    cmd=$(mysql_cmd)

    if ! $cmd -e "SELECT 1" &> /dev/null; then
        echo -e "${RED}Impossible de se connecter à MySQL${NC}"
        echo "Vérifiez les paramètres de connexion et le mot de passe (MYSQL_PWD)"
        exit 1
    fi

    # Get server version
    local version
    version=$($cmd -e "SELECT VERSION()")
    log_info "Connecté à MySQL/MariaDB: $version"

    # Check if MariaDB or MySQL
    if [[ "$version" == *"MariaDB"* ]]; then
        log_info "Type: MariaDB"
    else
        log_info "Type: MySQL"
    fi
}

# Check 1: Users with empty passwords
check_empty_passwords() {
    echo -e "\n${BOLD}${CYAN}=== VÉRIFICATION 1: Mots de passe vides ===${NC}\n"

    local cmd
    cmd=$(mysql_cmd)

    # Query differs between MySQL 5.7+/8.0 and older versions
    local query="
        SELECT User, Host
        FROM mysql.user
        WHERE (authentication_string = '' OR authentication_string IS NULL)
        AND plugin NOT IN ('auth_socket', 'unix_socket', 'auth_pam')
        AND User != ''
    "

    local result
    result=$($cmd -e "$query" 2>/dev/null || echo "QUERY_ERROR")

    if [[ "$result" == "QUERY_ERROR" ]]; then
        # Fallback for older MySQL versions
        query="
            SELECT User, Host
            FROM mysql.user
            WHERE (Password = '' OR Password IS NULL)
            AND User != ''
        "
        result=$($cmd -e "$query" 2>/dev/null || echo "")
    fi

    if [[ -z "$result" ]]; then
        log_pass "Aucun utilisateur avec mot de passe vide"
    else
        log_fail "Utilisateurs avec mot de passe vide détectés:"
        echo "$result" | while read -r user host; do
            echo -e "       ${RED}→ '$user'@'$host'${NC}"
        done
        echo -e "\n       ${YELLOW}Recommandation: ALTER USER 'user'@'host' IDENTIFIED BY 'strong_password';${NC}"
    fi
}

# Check 2: Root accessible from remote hosts
check_remote_root() {
    echo -e "\n${BOLD}${CYAN}=== VÉRIFICATION 2: Root accessible à distance ===${NC}\n"

    local cmd
    cmd=$(mysql_cmd)

    local query="
        SELECT User, Host
        FROM mysql.user
        WHERE User = 'root'
        AND Host NOT IN ('localhost', '127.0.0.1', '::1')
    "

    local result
    result=$($cmd -e "$query" 2>/dev/null)

    if [[ -z "$result" ]]; then
        log_pass "Root n'est pas accessible à distance"
    else
        log_fail "Root est accessible depuis des hôtes distants:"
        echo "$result" | while read -r user host; do
            echo -e "       ${RED}→ '$user'@'$host'${NC}"
        done

        # Special warning for root@'%'
        if echo "$result" | grep -q "%"; then
            echo -e "\n       ${RED}⚠️  CRITIQUE: root@'%' permet l'accès depuis n'importe quelle IP!${NC}"
        fi

        echo -e "\n       ${YELLOW}Recommandation: DROP USER 'root'@'%'; ou restreindre à une IP spécifique${NC}"
    fi
}

# Check 3: Anonymous users
check_anonymous_users() {
    echo -e "\n${BOLD}${CYAN}=== VÉRIFICATION 3: Utilisateurs anonymes ===${NC}\n"

    local cmd
    cmd=$(mysql_cmd)

    local query="
        SELECT User, Host
        FROM mysql.user
        WHERE User = ''
    "

    local result
    result=$($cmd -e "$query" 2>/dev/null)

    if [[ -z "$result" ]]; then
        log_pass "Aucun utilisateur anonyme"
    else
        log_fail "Utilisateurs anonymes détectés:"
        echo "$result" | while read -r user host; do
            echo -e "       ${RED}→ ''@'$host'${NC}"
        done
        echo -e "\n       ${YELLOW}Recommandation: DROP USER ''@'localhost'; DROP USER ''@'hostname';${NC}"
    fi
}

# Check 4: Users with GRANT ALL PRIVILEGES
check_grant_all() {
    echo -e "\n${BOLD}${CYAN}=== VÉRIFICATION 4: Utilisateurs avec GRANT ALL ===${NC}\n"

    local cmd
    cmd=$(mysql_cmd)

    # Check for users with all privileges on *.*
    local query="
        SELECT DISTINCT User, Host
        FROM mysql.user
        WHERE (
            Select_priv = 'Y' AND Insert_priv = 'Y' AND Update_priv = 'Y'
            AND Delete_priv = 'Y' AND Create_priv = 'Y' AND Drop_priv = 'Y'
            AND Reload_priv = 'Y' AND Shutdown_priv = 'Y' AND Process_priv = 'Y'
            AND File_priv = 'Y' AND Grant_priv = 'Y' AND References_priv = 'Y'
            AND Index_priv = 'Y' AND Alter_priv = 'Y' AND Super_priv = 'Y'
        )
        AND User NOT IN ('root', 'mysql.sys', 'mysql.session', 'mysql.infoschema', 'mariadb.sys')
    "

    local result
    result=$($cmd -e "$query" 2>/dev/null)

    if [[ -z "$result" ]]; then
        log_pass "Aucun utilisateur non-root avec tous les privilèges"
    else
        log_warn "Utilisateurs avec GRANT ALL PRIVILEGES (hors root):"
        echo "$result" | while read -r user host; do
            echo -e "       ${YELLOW}→ '$user'@'$host'${NC}"
        done
        echo -e "\n       ${YELLOW}Recommandation: Appliquer le principe du moindre privilège${NC}"
        echo -e "       ${YELLOW}REVOKE ALL PRIVILEGES ON *.* FROM 'user'@'host';${NC}"
        echo -e "       ${YELLOW}GRANT SELECT, INSERT, UPDATE ON mydb.* TO 'user'@'host';${NC}"
    fi
}

# Check 5: Test database exists
check_test_database() {
    echo -e "\n${BOLD}${CYAN}=== VÉRIFICATION 5: Base de données 'test' ===${NC}\n"

    local cmd
    cmd=$(mysql_cmd)

    local query="SHOW DATABASES LIKE 'test'"

    local result
    result=$($cmd -e "$query" 2>/dev/null)

    if [[ -z "$result" ]]; then
        log_pass "La base de données 'test' does not exist"
    else
        log_warn "La base de données 'test' existe"
        echo -e "       ${YELLOW}Cette base est accessible par défaut à tous les utilisateurs${NC}"
        echo -e "\n       ${YELLOW}Recommandation: DROP DATABASE test;${NC}"
    fi
}

# Check 6: Authentication plugins
check_auth_plugins() {
    echo -e "\n${BOLD}${CYAN}=== VÉRIFICATION 6: Plugins d'authentification ===${NC}\n"

    local cmd
    cmd=$(mysql_cmd)

    local query="
        SELECT User, Host, plugin
        FROM mysql.user
        WHERE plugin IN ('mysql_old_password', 'mysql_native_password')
        AND User != ''
        ORDER BY plugin, User
    "

    local result
    result=$($cmd -e "$query" 2>/dev/null || echo "")

    # Check for old password plugin
    if echo "$result" | grep -q "mysql_old_password"; then
        log_fail "Utilisateurs avec mysql_old_password (obsolète et non sécurisé):"
        echo "$result" | grep "mysql_old_password" | while read -r user host plugin; do
            echo -e "       ${RED}→ '$user'@'$host' ($plugin)${NC}"
        done
    fi

    # Check for native password (warning for MySQL 8+)
    local version
    version=$($cmd -e "SELECT @@version" 2>/dev/null)

    if [[ "$version" == 8.* ]]; then
        local native_count
        native_count=$(echo "$result" | grep -c "mysql_native_password" || echo "0")

        if [[ "$native_count" -gt 0 ]]; then
            log_warn "Utilisateurs avec mysql_native_password (MySQL 8+ recommande caching_sha2_password):"
            echo "$result" | grep "mysql_native_password" | head -5 | while read -r user host plugin; do
                echo -e "       ${YELLOW}→ '$user'@'$host'${NC}"
            done
            if [[ "$native_count" -gt 5 ]]; then
                echo -e "       ${YELLOW}... et $((native_count - 5)) autres${NC}"
            fi
        else
            log_pass "Tous les utilisateurs utilisent des plugins d'authentification sécurisés"
        fi
    else
        log_pass "Plugin mysql_native_password approprié pour cette version"
    fi
}

# Check 7: Validate_password plugin
check_password_policy() {
    echo -e "\n${BOLD}${CYAN}=== VÉRIFICATION 7: Politique de mots de passe ===${NC}\n"

    local cmd
    cmd=$(mysql_cmd)

    # Check if validate_password is installed
    local result
    result=$($cmd -e "SHOW VARIABLES LIKE 'validate_password%'" 2>/dev/null || echo "")

    if [[ -z "$result" ]]; then
        log_warn "Le plugin validate_password n'est pas installé"
        echo -e "       ${YELLOW}Ce plugin renforce la politique de mots de passe${NC}"
        echo -e "\n       ${YELLOW}Installation: INSTALL COMPONENT 'file://component_validate_password';${NC}"
    else
        log_pass "Plugin validate_password actif"

        # Show current policy
        local policy
        policy=$($cmd -e "SHOW VARIABLES LIKE 'validate_password.policy'" 2>/dev/null | awk '{print $2}')
        if [[ -n "$policy" ]]; then
            log_info "Politique actuelle: $policy"
        fi
    fi
}

# Check 8: SSL/TLS Configuration
check_ssl_config() {
    echo -e "\n${BOLD}${CYAN}=== VÉRIFICATION 8: Configuration SSL/TLS ===${NC}\n"

    local cmd
    cmd=$(mysql_cmd)

    local ssl_status
    ssl_status=$($cmd -e "SHOW VARIABLES LIKE 'have_ssl'" 2>/dev/null | awk '{print $2}')

    if [[ "$ssl_status" == "YES" ]]; then
        log_pass "SSL/TLS est disponible"

        # Check if SSL is required for any users
        local ssl_required
        ssl_required=$($cmd -e "SELECT User, Host, ssl_type FROM mysql.user WHERE ssl_type != ''" 2>/dev/null)

        if [[ -n "$ssl_required" ]]; then
            log_info "Utilisateurs avec exigence SSL:"
            echo "$ssl_required" | while read -r user host ssl_type; do
                echo -e "       → '$user'@'$host' ($ssl_type)"
            done
        else
            log_warn "Aucun utilisateur n'exige SSL pour la connexion"
            echo -e "       ${YELLOW}Recommandation: ALTER USER 'user'@'host' REQUIRE SSL;${NC}"
        fi
    else
        log_warn "SSL/TLS n'est pas activé"
        echo -e "       ${YELLOW}Les connexions ne sont pas chiffrées${NC}"
    fi
}

# Print summary
print_summary() {
    echo -e "\n${BOLD}${CYAN}================================================================${NC}"
    echo -e "${BOLD}${CYAN}                    RÉSUMÉ DE L'AUDIT${NC}"
    echo -e "${BOLD}${CYAN}================================================================${NC}\n"

    echo -e "  ${GREEN}PASS:${NC} $PASS_COUNT"
    echo -e "  ${RED}FAIL:${NC} $FAIL_COUNT"
    echo -e "  ${YELLOW}WARN:${NC} $WARN_COUNT"

    echo -e "\n${BOLD}Score de sécurité:${NC}"

    local total=$((PASS_COUNT + FAIL_COUNT + WARN_COUNT))
    if [[ $total -gt 0 ]]; then
        local score=$((PASS_COUNT * 100 / total))

        if [[ $FAIL_COUNT -eq 0 && $WARN_COUNT -eq 0 ]]; then
            echo -e "  ${GREEN}██████████ 100% - Excellent!${NC}"
        elif [[ $FAIL_COUNT -eq 0 ]]; then
            echo -e "  ${YELLOW}████████░░ ${score}% - Bon, quelques améliorations possibles${NC}"
        elif [[ $FAIL_COUNT -le 2 ]]; then
            echo -e "  ${YELLOW}██████░░░░ ${score}% - Attention requise${NC}"
        else
            echo -e "  ${RED}████░░░░░░ ${score}% - Actions urgentes nécessaires!${NC}"
        fi
    fi

    if [[ $FAIL_COUNT -gt 0 ]]; then
        echo -e "\n${RED}⚠️  Des problèmes de sécurité critiques ont été détectés.${NC}"
        echo -e "${RED}   Veuillez les corriger dès que possible.${NC}"
    fi

    echo -e "\n${BOLD}${CYAN}================================================================${NC}\n"
}

# Parse arguments
main() {
    local ask_password=false

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
            -P|--port)
                DB_PORT="$2"
                shift 2
                ;;
            -u|--user)
                DB_USER="$2"
                shift 2
                ;;
            -p|--password)
                ask_password=true
                shift
                ;;
            -S|--socket)
                DB_SOCKET="$2"
                shift 2
                ;;
            *)
                echo -e "${RED}Unknown option: $1${NC}"
                usage
                exit 1
                ;;
        esac
    done

    # Ask for password if requested
    if [[ "$ask_password" == "true" ]]; then
        echo -n "Mot de passe MySQL: "
        read -rs MYSQL_PWD
        export MYSQL_PWD
        echo ""
    fi

    # Header
    echo -e "\n${BOLD}${CYAN}================================================================${NC}"
    echo -e "${BOLD}${CYAN}           AUDIT DE SÉCURITÉ MySQL/MariaDB${NC}"
    echo -e "${BOLD}${CYAN}================================================================${NC}"
    echo -e "Hôte: ${BOLD}$DB_HOST:$DB_PORT${NC} | Utilisateur: ${BOLD}$DB_USER${NC}"

    # Run checks
    test_connection
    check_empty_passwords
    check_remote_root
    check_anonymous_users
    check_grant_all
    check_test_database
    check_auth_plugins
    check_password_policy
    check_ssl_config

    # Print summary
    print_summary

    # Exit code based on failures
    if [[ $FAIL_COUNT -gt 0 ]]; then
        exit 1
    fi

    exit 0
}

# Execute
main "$@"
```

---

## Usage

### Audit Basique

```bash
# Audit local avec root
./mysql-security-audit.sh

# Avec demande de mot de passe
./mysql-security-audit.sh -p

# Via socket Unix
./mysql-security-audit.sh -S /var/run/mysqld/mysqld.sock
```

### Audit Distant

```bash
# Instance distante
./mysql-security-audit.sh -H db.example.com -u admin -p

# Port personnalisé
./mysql-security-audit.sh -H db.example.com -P 3307 -u admin -p

# Avec variable d'environnement
MYSQL_PWD=secret ./mysql-security-audit.sh -H db.example.com -u admin
```

---

## Exemple de Sortie

```sql
================================================================
           AUDIT DE SÉCURITÉ MySQL/MariaDB
================================================================
Hôte: localhost:3306 | Utilisateur: root

=== TEST DE CONNEXION ===

  [INFO] Connecté à MySQL/MariaDB: 8.0.35
  [INFO] Type: MySQL

=== VÉRIFICATION 1: Mots de passe vides ===

  [PASS] Aucun utilisateur avec mot de passe vide

=== VÉRIFICATION 2: Root accessible à distance ===

  [FAIL] Root est accessible depuis des hôtes distants:
       → 'root'@'%'

       ⚠️  CRITIQUE: root@'%' permet l'accès depuis n'importe quelle IP!

       Recommandation: DROP USER 'root'@'%'; ou restreindre à une IP spécifique

=== VÉRIFICATION 3: Utilisateurs anonymes ===

  [PASS] Aucun utilisateur anonyme

=== VÉRIFICATION 4: Utilisateurs avec GRANT ALL ===

  [WARN] Utilisateurs avec GRANT ALL PRIVILEGES (hors root):
       → 'backup_user'@'localhost'

       Recommandation: Appliquer le principe du moindre privilège

=== VÉRIFICATION 5: Base de données 'test' ===

  [WARN] La base de données 'test' existe
       Cette base est accessible par défaut à tous les utilisateurs

       Recommandation: DROP DATABASE test;

=== VÉRIFICATION 6: Plugins d'authentification ===

  [PASS] Tous les utilisateurs utilisent des plugins d'authentification sécurisés

=== VÉRIFICATION 7: Politique de mots de passe ===

  [PASS] Plugin validate_password actif
  [INFO] Politique actuelle: MEDIUM

=== VÉRIFICATION 8: Configuration SSL/TLS ===

  [PASS] SSL/TLS est disponible
  [WARN] Aucun utilisateur n'exige SSL pour la connexion
       Recommandation: ALTER USER 'user'@'host' REQUIRE SSL;

================================================================
                    RÉSUMÉ DE L'AUDIT
================================================================

  PASS: 5
  FAIL: 1
  WARN: 3

Score de sécurité:
  ██████░░░░ 55% - Attention requise

⚠️  Des problèmes de sécurité critiques ont été détectés.
   Veuillez les corriger dès que possible.

================================================================
```

---

## Vérifications Effectuées

| # | Vérification | Sévérité | Description |
|---|--------------|----------|-------------|
| 1 | Mots de passe vides | **CRITIQUE** | Utilisateurs sans authentification |
| 2 | Root à distance | **CRITIQUE** | `root@'%'` accessible depuis tout IP |
| 3 | Utilisateurs anonymes | **HAUTE** | Comptes sans nom (legacy) |
| 4 | GRANT ALL | **MOYENNE** | Privilèges excessifs |
| 5 | Base test | **BASSE** | Base accessible par tous |
| 6 | Auth plugins | **MOYENNE** | Méthodes obsolètes |
| 7 | Password policy | **MOYENNE** | Politique de complexité |
| 8 | SSL/TLS | **HAUTE** | Chiffrement des connexions |

---

## Options

| Option | Description |
|--------|-------------|
| `-h`, `--help` | Affiche l'aide |
| `-H`, `--host HOST` | Hôte MySQL (default: localhost) |
| `-P`, `--port PORT` | Port MySQL (default: 3306) |
| `-u`, `--user USER` | Utilisateur MySQL (default: root) |
| `-p`, `--password` | Demander le mot de passe interactivement |
| `-S`, `--socket PATH` | Chemin du socket Unix |

---

!!! danger "Actions Immédiates"
    Si l'audit révèle des **FAIL**, corrigez immédiatement :

    ```sql
    -- Supprimer root@'%'
    DROP USER 'root'@'%';

    -- Supprimer utilisateurs anonymes
    DROP USER ''@'localhost';
    DROP USER ''@'%';

    -- Définir un mot de passe
    ALTER USER 'user'@'host' IDENTIFIED BY 'StrongP@ssw0rd!';

    -- Supprimer base test
    DROP DATABASE test;
    ```

!!! tip "Hardening MySQL"
    Après l'audit, exécutez également :

    ```bash
    # Script officiel de sécurisation
    mysql_secure_installation
    ```

    Ce script interactif configure :

    - Mot de passe root
    - Suppression utilisateurs anonymes
    - Désactivation accès root distant
    - Suppression base test

---

## Voir Aussi

- [check-mysql.sh](check-mysql.md) - Vérification santé MySQL
- [pg-bloat-check.sh](pg-bloat-check.md) - Analyse bloat PostgreSQL
- [redis_key_auditor.py](../python/redis_key_auditor.md) - Audit clés Redis
