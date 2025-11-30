---
tags:
  - scripts
  - bash
  - ssl
  - tls
  - security
  - certificates
---

# ssl-csr-wizard.sh

Assistant de génération de clé privée et CSR (Certificate Signing Request) avec support des SANs (Subject Alternative Names).

---

## Informations

| Propriété | Valeur |
|-----------|--------|
| **Langage** | Bash |
| **Catégorie** | Sécurité / Certificats |
| **Niveau** | :material-star::material-star: Intermédiaire |
| **Dépendances** | OpenSSL |

---

## Description

Ce script simplifie la génération de clés privées RSA/ECDSA et de CSR (Certificate Signing Request) pour l'obtention de certificats SSL/TLS. Il gère automatiquement la configuration OpenSSL pour inclure les **Subject Alternative Names (SANs)**, essentiels pour les certificats modernes.

**Fonctionnalités :**

- **Support des SANs** : Ajoute plusieurs domaines/sous-domaines au certificat
- **Choix de l'algorithme** : RSA (2048/4096) ou ECDSA (prime256v1)
- **Configuration automatique** : Génère le ficyesterday OpenSSL temporaire
- **Vérification** : Affiche le contenu du CSR pour validation
- **Mode interactif** : Assistant pas-à-pas

---

## Prérequis

```bash
# OpenSSL doit être installé
openssl version

# Check que openssl peut générer des clés
openssl genrsa -out /dev/null 2048 2>/dev/null && echo "OK"
```

---

## Pourquoi les SANs sont Importants

!!! warning "Certificats sans SAN"
    Depuis 2017, les navigateurs (Chrome, Firefox) **ignorent le Common Name (CN)** et
    exigent que les domaines soient listés dans les SANs.

    Un certificat sans SAN affichera une erreur :

    ```
    NET::ERR_CERT_COMMON_NAME_INVALID
    ```

Les SANs permettent d'inclure :

- Plusieurs domaines : `example.com`, `example.org`
- Sous-domaines : `www.example.com`, `api.example.com`
- Wildcard : `*.example.com`
- Adresses IP : `192.168.1.1`

---

## Script

```bash
#!/bin/bash
#===============================================================================
# Script Name: ssl-csr-wizard.sh
# Description: Generate private key and CSR with SANs support
# Author: ShellBook
# Date: 2024-01-15
# Version: 1.0
#===============================================================================

set -euo pipefail
IFS=$'\n\t'

# Variables
readonly SCRIPT_NAME=$(basename "$0")
readonly TEMP_DIR=$(mktemp -d)

# Colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m'
readonly BOLD='\033[1m'

# Default values
DOMAIN=""
OUTPUT_DIR="."
KEY_TYPE="rsa"
KEY_SIZE="2048"
COUNTRY="FR"
STATE=""
CITY=""
ORG=""
OU=""
EMAIL=""
SANS=()
INTERACTIVE=false

# Functions
log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1" >&2; }

cleanup() {
    # Remove temporary files
    rm -rf "$TEMP_DIR"
}

trap cleanup EXIT

usage() {
    cat << EOF
${CYAN}Usage:${NC} $SCRIPT_NAME [OPTIONS] -d <domain>

Generate a private key and CSR (Certificate Signing Request) with SANs support.

${CYAN}Options:${NC}
    -h, --help              Show this help
    -d, --domain DOMAIN     Domaine principal (Common Name)
    -o, --output DIR        Répertoire de sortie (default: .)
    -s, --san DOMAIN        Subject Alternative Name (répétable)
    -k, --key-type TYPE     Type de clé: rsa, ecdsa (default: rsa)
    -b, --bits SIZE         Taille de clé RSA: 2048, 4096 (default: 2048)
    -i, --interactive       Mode interactif
    -c, --country CODE      Code pays (default: FR)
    --state STATE           État/Région
    --city CITY             Ville
    --org ORG               Organisation
    --ou OU                 Unité organisationnelle
    --email EMAIL           Email de contact

${CYAN}Examples:${NC}
    # CSR simple
    $SCRIPT_NAME -d example.com

    # Avec SANs multiples
    $SCRIPT_NAME -d example.com -s www.example.com -s api.example.com

    # Clé ECDSA
    $SCRIPT_NAME -d example.com -k ecdsa

    # Mode interactif complet
    $SCRIPT_NAME -i -d example.com

    # RSA 4096 bits
    $SCRIPT_NAME -d example.com -b 4096 -o /etc/ssl/private

${CYAN}Ficyesterdays générés:${NC}
    <domain>.key    Clé privée (GARDER SECRÈTE!)
    <domain>.csr    Certificate Signing Request

EOF
}

# Check OpenSSL availability
check_openssl() {
    if ! command -v openssl &> /dev/null; then
        log_error "OpenSSL n'est pas installé"
        exit 1
    fi
}

# Validate domain format
validate_domain() {
    local domain="$1"

    # Basic domain validation regex
    if [[ ! "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$ ]] && \
       [[ ! "$domain" =~ ^\*\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$ ]]; then
        log_error "Format de domaine invalide: $domain"
        return 1
    fi
    return 0
}

# Interactive mode to collect information
interactive_mode() {
    echo -e "\n${BOLD}${CYAN}=== SSL CSR WIZARD ===${NC}\n"

    # Domain
    if [[ -z "$DOMAIN" ]]; then
        read -rp "Domaine principal (Common Name): " DOMAIN
        if [[ -z "$DOMAIN" ]]; then
            log_error "Le domaine est requis"
            exit 1
        fi
    fi
    validate_domain "$DOMAIN"

    # SANs
    echo -e "\n${CYAN}Subject Alternative Names (SANs)${NC}"
    echo "Le domaine principal sera automatiquement inclus."
    echo "Entrez les domaines/sous-domaines additionnels (vide pour terminer):"

    while true; do
        read -rp "  SAN: " san
        if [[ -z "$san" ]]; then
            break
        fi
        if validate_domain "$san"; then
            SANS+=("$san")
        fi
    done

    # Key type
    echo -e "\n${CYAN}Type de clé:${NC}"
    echo "  1. RSA 2048 bits (compatible, recommandé)"
    echo "  2. RSA 4096 bits (plus sécurisé, plus lent)"
    echo "  3. ECDSA prime256v1 (moderne, rapide)"
    read -rp "Choix [1]: " key_choice

    case "$key_choice" in
        2)
            KEY_TYPE="rsa"
            KEY_SIZE="4096"
            ;;
        3)
            KEY_TYPE="ecdsa"
            ;;
        *)
            KEY_TYPE="rsa"
            KEY_SIZE="2048"
            ;;
    esac

    # Organization info
    echo -e "\n${CYAN}Informations organisation (optionnel):${NC}"
    read -rp "Pays (code 2 lettres) [FR]: " input
    COUNTRY="${input:-FR}"

    read -rp "État/Région: " STATE
    read -rp "Ville: " CITY
    read -rp "Organisation: " ORG
    read -rp "Unité (département): " OU
    read -rp "Email: " EMAIL

    # Output directory
    read -rp "Répertoire de sortie [.]: " input
    OUTPUT_DIR="${input:-.}"
}

# Generate OpenSSL configuration file with SANs
generate_openssl_config() {
    local config_file="$TEMP_DIR/openssl.cnf"

    cat > "$config_file" << EOF
[req]
default_bits = ${KEY_SIZE}
prompt = no
default_md = sha256
req_extensions = req_ext
distinguished_name = dn

[dn]
CN = ${DOMAIN}
EOF

    # Add optional fields
    [[ -n "$COUNTRY" ]] && echo "C = ${COUNTRY}" >> "$config_file"
    [[ -n "$STATE" ]] && echo "ST = ${STATE}" >> "$config_file"
    [[ -n "$CITY" ]] && echo "L = ${CITY}" >> "$config_file"
    [[ -n "$ORG" ]] && echo "O = ${ORG}" >> "$config_file"
    [[ -n "$OU" ]] && echo "OU = ${OU}" >> "$config_file"
    [[ -n "$EMAIL" ]] && echo "emailAddress = ${EMAIL}" >> "$config_file"

    # Add SAN extension
    cat >> "$config_file" << EOF

[req_ext]
subjectAltName = @alt_names

[alt_names]
EOF

    # Add domain as first SAN
    local san_index=1
    echo "DNS.${san_index} = ${DOMAIN}" >> "$config_file"
    ((san_index++))

    # Add additional SANs
    for san in "${SANS[@]}"; do
        echo "DNS.${san_index} = ${san}" >> "$config_file"
        ((san_index++))
    done

    echo "$config_file"
}

# Generate private key
generate_key() {
    local key_file="$1"

    log_info "Génération de la clé privée ($KEY_TYPE)..."

    if [[ "$KEY_TYPE" == "ecdsa" ]]; then
        openssl ecparam -genkey -name prime256v1 -out "$key_file" 2>/dev/null
    else
        openssl genrsa -out "$key_file" "$KEY_SIZE" 2>/dev/null
    fi

    # Set restrictive permissions
    chmod 600 "$key_file"

    log_info "Clé privée générée: $key_file"
}

# Generate CSR
generate_csr() {
    local key_file="$1"
    local csr_file="$2"
    local config_file="$3"

    log_info "Génération du CSR..."

    openssl req -new -key "$key_file" -out "$csr_file" -config "$config_file" 2>/dev/null

    log_info "CSR généré: $csr_file"
}

# Verify and display CSR
verify_csr() {
    local csr_file="$1"

    echo -e "\n${BOLD}${CYAN}=== VÉRIFICATION DU CSR ===${NC}\n"

    # Display CSR details
    echo -e "${CYAN}Subject:${NC}"
    openssl req -in "$csr_file" -noout -subject | sed 's/^subject=/  /'

    echo -e "\n${CYAN}Subject Alternative Names:${NC}"
    openssl req -in "$csr_file" -noout -text 2>/dev/null | \
        grep -A1 "Subject Alternative Name" | \
        tail -1 | \
        tr ',' '\n' | \
        sed 's/^[[:space:]]*/  /'

    echo -e "\n${CYAN}Signature Algorithm:${NC}"
    openssl req -in "$csr_file" -noout -text 2>/dev/null | \
        grep "Signature Algorithm" | head -1 | \
        sed 's/^[[:space:]]*/  /'

    echo -e "\n${CYAN}Public Key:${NC}"
    openssl req -in "$csr_file" -noout -text 2>/dev/null | \
        grep "Public Key Algorithm" | \
        sed 's/^[[:space:]]*/  /'
}

# Display summary and next steps
display_summary() {
    local key_file="$1"
    local csr_file="$2"

    echo -e "\n${BOLD}${GREEN}=== GÉNÉRATION TERMINÉE ===${NC}\n"

    echo -e "${CYAN}Ficyesterdays créés:${NC}"
    echo -e "  ${GREEN}✓${NC} Clé privée: $key_file"
    echo -e "  ${GREEN}✓${NC} CSR:        $csr_file"

    echo -e "\n${CYAN}Prochaines étapes:${NC}"
    echo "  1. Soumettez le CSR à votre autorité de certification (CA)"
    echo "  2. Conservez la clé privée en lieu sûr"
    echo "  3. Une fois le certificat reçu, configurez votre serveur"

    echo -e "\n${CYAN}Afficher le contenu du CSR:${NC}"
    echo "  cat $csr_file"

    echo -e "\n${CYAN}Vérifier le CSR:${NC}"
    echo "  openssl req -in $csr_file -noout -text"

    echo -e "\n${RED}⚠️  IMPORTANT:${NC}"
    echo "  La clé privée ($key_file) doit rester CONFIDENTIELLE."
    echo "  Ne la partagez JAMAIS et ne la commitez pas dans Git!"
}

# Parse arguments
main() {
    # Check for help first
    for arg in "$@"; do
        if [[ "$arg" == "-h" || "$arg" == "--help" ]]; then
            usage
            exit 0
        fi
    done

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -d|--domain)
                DOMAIN="$2"
                shift 2
                ;;
            -o|--output)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            -s|--san)
                SANS+=("$2")
                shift 2
                ;;
            -k|--key-type)
                KEY_TYPE="$2"
                shift 2
                ;;
            -b|--bits)
                KEY_SIZE="$2"
                shift 2
                ;;
            -i|--interactive)
                INTERACTIVE=true
                shift
                ;;
            -c|--country)
                COUNTRY="$2"
                shift 2
                ;;
            --state)
                STATE="$2"
                shift 2
                ;;
            --city)
                CITY="$2"
                shift 2
                ;;
            --org)
                ORG="$2"
                shift 2
                ;;
            --ou)
                OU="$2"
                shift 2
                ;;
            --email)
                EMAIL="$2"
                shift 2
                ;;
            *)
                log_error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done

    # Check OpenSSL
    check_openssl

    # Interactive mode
    if [[ "$INTERACTIVE" == "true" ]] || [[ -z "$DOMAIN" ]]; then
        interactive_mode
    fi

    # Validate domain
    if [[ -z "$DOMAIN" ]]; then
        log_error "Le domaine (-d) est requis"
        usage
        exit 1
    fi

    validate_domain "$DOMAIN"

    # Create output directory
    mkdir -p "$OUTPUT_DIR"

    # Sanitize domain for filename
    local safe_domain
    safe_domain=$(echo "$DOMAIN" | tr '*' '_')

    # File paths
    local key_file="$OUTPUT_DIR/${safe_domain}.key"
    local csr_file="$OUTPUT_DIR/${safe_domain}.csr"

    # Check if files exist
    if [[ -f "$key_file" ]] || [[ -f "$csr_file" ]]; then
        log_warn "Des ficyesterdays existent déjà:"
        [[ -f "$key_file" ]] && echo "  - $key_file"
        [[ -f "$csr_file" ]] && echo "  - $csr_file"
        read -rp "Écraser? [o/N]: " overwrite
        if [[ "$overwrite" != "o" && "$overwrite" != "O" ]]; then
            log_info "Abandon"
            exit 0
        fi
    fi

    # Generate OpenSSL config
    local config_file
    config_file=$(generate_openssl_config)

    # Generate key
    generate_key "$key_file"

    # Generate CSR
    generate_csr "$key_file" "$csr_file" "$config_file"

    # Verify CSR
    verify_csr "$csr_file"

    # Display summary
    display_summary "$key_file" "$csr_file"
}

# Execute
main "$@"
```

---

## Usage

### Mode Simple

```bash
# CSR pour un seul domaine
./ssl-csr-wizard.sh -d example.com

# Avec répertoire de sortie
./ssl-csr-wizard.sh -d example.com -o /etc/ssl/private
```

### Avec SANs (Subject Alternative Names)

```bash
# Plusieurs sous-domaines
./ssl-csr-wizard.sh -d example.com \
    -s www.example.com \
    -s api.example.com \
    -s admin.example.com

# Wildcard + domaines spécifiques
./ssl-csr-wizard.sh -d example.com \
    -s "*.example.com" \
    -s example.org
```

### Options Avancées

```bash
# Clé RSA 4096 bits
./ssl-csr-wizard.sh -d example.com -b 4096

# Clé ECDSA (recommandé pour performances)
./ssl-csr-wizard.sh -d example.com -k ecdsa

# Informations organisation complètes
./ssl-csr-wizard.sh -d example.com \
    -c FR \
    --state "Île-de-France" \
    --city "Paris" \
    --org "Ma Société" \
    --ou "IT" \
    --email "ssl@example.com"
```

### Mode Interactif

```bash
# Assistant complet
./ssl-csr-wizard.sh -i

# Ou simplement sans arguments
./ssl-csr-wizard.sh
```

---

## Exemple de Session Interactive

```
=== SSL CSR WIZARD ===

Domaine principal (Common Name): example.com

Subject Alternative Names (SANs)
Le domaine principal sera automatiquement inclus.
Entrez les domaines/sous-domaines additionnels (vide pour terminer):
  SAN: www.example.com
  SAN: api.example.com
  SAN:

Type de clé:
  1. RSA 2048 bits (compatible, recommandé)
  2. RSA 4096 bits (plus sécurisé, plus lent)
  3. ECDSA prime256v1 (moderne, rapide)
Choix [1]: 1

Informations organisation (optionnel):
Pays (code 2 lettres) [FR]: FR
État/Région: Île-de-France
Ville: Paris
Organisation: Ma Société
Unité (département): IT
Email: admin@example.com

[INFO] Génération de la clé privée (rsa)...
[INFO] Clé privée générée: ./example.com.key
[INFO] Génération du CSR...
[INFO] CSR généré: ./example.com.csr

=== VÉRIFICATION DU CSR ===

Subject:
  CN = example.com, C = FR, ST = Île-de-France, L = Paris, O = Ma Société

Subject Alternative Names:
  DNS:example.com
  DNS:www.example.com
  DNS:api.example.com

=== GÉNÉRATION TERMINÉE ===

Ficyesterdays créés:
  ✓ Clé privée: ./example.com.key
  ✓ CSR:        ./example.com.csr
```

---

## Options

| Option | Description |
|--------|-------------|
| `-d`, `--domain DOMAIN` | Domaine principal (Common Name) |
| `-o`, `--output DIR` | Répertoire de sortie (default: .) |
| `-s`, `--san DOMAIN` | SAN additionnel (répétable) |
| `-k`, `--key-type TYPE` | Type de clé: rsa, ecdsa |
| `-b`, `--bits SIZE` | Taille clé RSA: 2048, 4096 |
| `-i`, `--interactive` | Mode interactif |
| `-c`, `--country CODE` | Code pays (default: FR) |
| `--state STATE` | État/Région |
| `--city CITY` | Ville |
| `--org ORG` | Organisation |
| `--ou OU` | Unité organisationnelle |
| `--email EMAIL` | Email de contact |

---

!!! danger "Protégez votre Clé Privée"
    La clé privée (`.key`) est **CONFIDENTIELLE**. Ne jamais :

    - La partager par email
    - La commiter dans Git
    - La stocker sur un serveur public

    Permissions recommandées :
    ```bash
    chmod 600 example.com.key
    chown root:root example.com.key
    ```

!!! tip "Validation du CSR"
    Avant de soumettre le CSR à votre CA, vérifiez son contenu :

    ```bash
    # Display les détails
    openssl req -in example.com.csr -noout -text

    # Check les SANs
    openssl req -in example.com.csr -noout -text | grep -A1 "Subject Alternative Name"
    ```

---

## Voir Aussi

- [cert_checker.py](../python/cert_checker.md) - Vérification certificats SSL/TLS
- [systemd_generator.py](../python/systemd_generator.md) - Générateur service Systemd
- [logrotate-builder.sh](logrotate-builder.md) - Générateur config logrotate
