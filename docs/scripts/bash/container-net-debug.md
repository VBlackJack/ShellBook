---
tags:
  - scripts
  - bash
  - docker
  - networking
  - debug
---

# container-net-debug.sh

Outil de debug réseau pour conteneurs Docker utilisant le pattern sidecar avec nicolaka/netshoot.

---

## Informations

| Propriété | Valeur |
|-----------|--------|
| **Langage** | Bash |
| **Catégorie** | DevOps / Conteneurs / Network |
| **Niveau** | :material-star::material-star: Intermédiaire |
| **Dépendances** | Docker, nicolaka/netshoot |

---

## Description

Ce script lance un conteneur de debug réseau attaché à l'espace réseau d'un conteneur cible. Il utilise l'image `nicolaka/netshoot` qui contient tous les outils réseau nécessaires (tcpdump, netstat, curl, dig, nmap, etc.).

**Fonctionnalités :**

- Attache un shell interactif au namespace réseau du conteneur cible
- Fournit tous les outils réseau standards (tcpdump, netstat, ss, curl, dig...)
- Mode non-interactif pour exécuter une commande unique
- Liste les outils disponibles
- Supporte Docker et Podman

---

## Prérequis

```bash
# Docker doit être installé et en cours d'exécution
docker info

# L'image netshoot sera téléchargée automatiquement si absente
docker pull nicolaka/netshoot
```

---

## Script

```bash
#!/bin/bash
#===============================================================================
# Script Name: container-net-debug.sh
# Description: Network debugging for containers using netshoot sidecar pattern
# Author: ShellBook
# Date: 2024-01-15
# Version: 1.0
#===============================================================================

set -euo pipefail
IFS=$'\n\t'

# Variables
readonly SCRIPT_NAME=$(basename "$0")
readonly NETSHOOT_IMAGE="nicolaka/netshoot"

# Colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m'

# Functions
log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1" >&2; }
log_debug() { echo -e "${BLUE}[DEBUG]${NC} $1"; }

usage() {
    cat << EOF
${CYAN}Usage:${NC} $SCRIPT_NAME [OPTIONS] <container_name_or_id>

Attach a network debugging container to the target container's network namespace.

${CYAN}Options:${NC}
    -h, --help          Show this help
    -c, --command CMD   Exécute une commande et quitte (mode non-interactif)
    -l, --list-tools    Liste les outils disponibles dans netshoot
    -p, --podman        Utilise Podman au lieu de Docker
    -v, --verbose       Verbose mode

${CYAN}Examples:${NC}
    # Shell interactif dans le namespace réseau du conteneur
    $SCRIPT_NAME my_container

    # Exécuter tcpdump sur le conteneur cible
    $SCRIPT_NAME -c "tcpdump -i any -n port 80" my_container

    # Check la connectivité DNS
    $SCRIPT_NAME -c "dig google.com" my_container

    # Lister les connexions actives
    $SCRIPT_NAME -c "ss -tunapl" my_container

    # Scanner les ports ouverts du localhost (du point de vue du conteneur)
    $SCRIPT_NAME -c "nmap -sT localhost" my_container

${CYAN}Outils disponibles dans netshoot:${NC}
    Network: tcpdump, netstat, ss, nmap, iperf3, mtr, traceroute
    DNS: dig, nslookup, host
    HTTP: curl, wget, httpie
    Utils: jq, vim, bash, zsh

${CYAN}Note:${NC}
    Ce script utilise l'image nicolaka/netshoot qui sera téléchargée
    automatiquement si elle does not exist localement.

EOF
}

# List available tools in netshoot
list_tools() {
    echo -e "${CYAN}=== Outils disponibles dans nicolaka/netshoot ===${NC}\n"

    cat << EOF
${GREEN}Analyse Network:${NC}
  tcpdump       - Capture de paquets
  wireshark     - Analyse de protocoles (CLI: tshark)
  nmap          - Scanner de ports
  netstat       - Statistiques réseau
  ss            - Socket statistics (moderne)
  iptables      - Règles firewall
  nftables      - Nouveau framework firewall

${GREEN}Connectivité:${NC}
  ping          - Test ICMP
  traceroute    - Trace des routes
  mtr           - Traceroute amélioré
  iperf3        - Test de bande passante
  netcat (nc)   - Outil réseau polyvalent
  socat         - Relay de sockets

${GREEN}DNS:${NC}
  dig           - Requêtes DNS détaillées
  nslookup      - Résolution DNS simple
  host          - Lookup DNS
  drill         - Alternative à dig

${GREEN}HTTP/API:${NC}
  curl          - Transfert de données
  wget          - Téléchargement
  httpie (http) - Client HTTP moderne
  ab            - Apache Benchmark

${GREEN}Certificats SSL:${NC}
  openssl       - Toolkit SSL/TLS

${GREEN}Utilitaires:${NC}
  jq            - CPU JSON
  yq            - CPU YAML
  vim/nano      - Éditeurs
  bash/zsh      - Shells

EOF
}

# Check if container runtime is available
check_runtime() {
    local runtime="$1"

    if ! command -v "$runtime" &> /dev/null; then
        log_error "$runtime n'est pas installé"
        return 1
    fi

    if ! $runtime info &> /dev/null; then
        log_error "Le daemon $runtime n'est pas accessible"
        return 1
    fi

    return 0
}

# Check if target container exists and is running
check_container() {
    local runtime="$1"
    local container="$2"

    # Check if container exists
    if ! $runtime inspect "$container" &> /dev/null; then
        log_error "Le conteneur '$container' does not exist"
        return 1
    fi

    # Check if container is running
    local state
    state=$($runtime inspect -f '{{.State.Running}}' "$container" 2>/dev/null || \
            $runtime inspect -f '{{.State.Status}}' "$container" 2>/dev/null)

    if [[ "$state" != "true" && "$state" != "running" ]]; then
        log_error "Le conteneur '$container' n'est pas en cours d'exécution"
        log_info "État actuel: $state"
        return 1
    fi

    return 0
}

# Pull netshoot image if not present
ensure_image() {
    local runtime="$1"

    if ! $runtime image inspect "$NETSHOOT_IMAGE" &> /dev/null; then
        log_info "Téléchargement de l'image $NETSHOOT_IMAGE..."
        if ! $runtime pull "$NETSHOOT_IMAGE"; then
            log_error "Impossible de télécharger l'image $NETSHOOT_IMAGE"
            return 1
        fi
    fi

    return 0
}

# Run debug container
run_debug_container() {
    local runtime="$1"
    local container="$2"
    local command="$3"
    local verbose="$4"

    # Build run command
    local run_args=(
        "--rm"
        "--net=container:$container"
        "--name=netshoot-debug-$$"
    )

    # Add interactive and tty if no command specified
    if [[ -z "$command" ]]; then
        run_args+=("-it")
    fi

    # Add privileged for full network access
    run_args+=("--privileged")

    if [[ "$verbose" == "true" ]]; then
        log_debug "Commande: $runtime run ${run_args[*]} $NETSHOOT_IMAGE $command"
    fi

    echo -e "${CYAN}=== Attaché au namespace réseau de: $container ===${NC}"
    echo -e "${CYAN}=== Utilisez 'exit' pour quitter ===${NC}\n"

    if [[ -n "$command" ]]; then
        # Non-interactive mode: run command and exit
        $runtime run "${run_args[@]}" "$NETSHOOT_IMAGE" sh -c "$command"
    else
        # Interactive mode: start shell
        $runtime run "${run_args[@]}" "$NETSHOOT_IMAGE"
    fi
}

# Parse arguments
main() {
    local container=""
    local command=""
    local runtime="docker"
    local verbose="false"
    local show_tools="false"

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                usage
                exit 0
                ;;
            -c|--command)
                if [[ -z "${2:-}" ]]; then
                    log_error "L'option --command nécessite un argument"
                    exit 1
                fi
                command="$2"
                shift 2
                ;;
            -l|--list-tools)
                show_tools="true"
                shift
                ;;
            -p|--podman)
                runtime="podman"
                shift
                ;;
            -v|--verbose)
                verbose="true"
                shift
                ;;
            -*)
                log_error "Unknown option: $1"
                usage
                exit 1
                ;;
            *)
                container="$1"
                shift
                ;;
        esac
    done

    # Show tools and exit if requested
    if [[ "$show_tools" == "true" ]]; then
        list_tools
        exit 0
    fi

    # Validate container argument
    if [[ -z "$container" ]]; then
        log_error "Le nom ou ID du conteneur est requis"
        echo ""
        usage
        exit 1
    fi

    # Check runtime
    if ! check_runtime "$runtime"; then
        exit 1
    fi

    # Check target container
    if ! check_container "$runtime" "$container"; then
        exit 1
    fi

    # Ensure netshoot image is available
    if ! ensure_image "$runtime"; then
        exit 1
    fi

    # Run debug container
    run_debug_container "$runtime" "$container" "$command" "$verbose"
}

# Trap to cleanup on exit
cleanup() {
    # Remove any leftover debug container
    docker rm -f "netshoot-debug-$$" 2>/dev/null || true
}

trap cleanup EXIT

# Execute
main "$@"
```

---

## Usage

### Mode Interactif

```bash
# Ouvrir un shell dans le namespace réseau du conteneur
./container-net-debug.sh my_webapp

# Avec Podman
./container-net-debug.sh --podman my_webapp
```

### Mode Commande Unique

```bash
# Capturer le trafic HTTP
./container-net-debug.sh -c "tcpdump -i any -n port 80 -c 10" my_webapp

# Check la résolution DNS
./container-net-debug.sh -c "dig api.example.com" my_webapp

# Lister les connexions établies
./container-net-debug.sh -c "ss -tunapl" my_webapp

# Tester la connectivité vers un service
./container-net-debug.sh -c "curl -v http://backend:8080/health" my_webapp
```

---

## Cas d'Usage

### Debug Problème de Connectivité

```bash
# Check si le conteneur peut résoudre le DNS
./container-net-debug.sh -c "dig backend-service" my_app

# Tester la connectivité TCP
./container-net-debug.sh -c "nc -zv backend-service 5432" my_app

# Tracer la route vers un service externe
./container-net-debug.sh -c "mtr --report google.com" my_app
```

### Analyse du Trafic Network

```bash
# Capturer tout le trafic
./container-net-debug.sh -c "tcpdump -i any -w /tmp/capture.pcap" my_app

# Filtrer par port
./container-net-debug.sh -c "tcpdump -i any -n port 443" my_app

# Analyser les requêtes HTTP
./container-net-debug.sh -c "tcpdump -i any -A -s0 'tcp port 80'" my_app
```

### Vérification des Ports et Services

```bash
# Lister les ports en écoute
./container-net-debug.sh -c "ss -tlnp" my_app

# Scanner les ports ouverts localement
./container-net-debug.sh -c "nmap -sT localhost" my_app

# Check les règles iptables
./container-net-debug.sh -c "iptables -L -n" my_app
```

### Test de Performance Network

```bash
# Test de bande passante (nécessite iperf3 server)
./container-net-debug.sh -c "iperf3 -c iperf-server" my_app

# Latence vers un service
./container-net-debug.sh -c "ping -c 5 database" my_app
```

---

## Exemple de Session Interactive

```bash
$ ./container-net-debug.sh my_webapp
=== Attaché au namespace réseau de: my_webapp ===
=== Utilisez 'exit' pour quitter ===

                    dP            dP                           dP
                    88            88                           88
88d888b. .d8888b. d8888P .d8888b. 88d888b. .d8888b. .d8888b. d8888P
88'  `88 88ooood8   88   Y8ooooo. 88'  `88 88'  `88 88'  `88   88
88    88 88.  ...   88         88 88    88 88.  .88 88.  .88   88
dP    dP `88888P'   dP   `88888P' dP    dP `88888P' `88888P'   dP

Welcome to Netshoot! (github.com/nicolaka/netshoot)
Version: 0.11

 my_webapp  ~  ss -tunapl
Netid  State   Recv-Q  Send-Q  Local Address:Port  Peer Address:Port
tcp    LISTEN  0       128     0.0.0.0:80          0.0.0.0:*
tcp    ESTAB   0       0       172.17.0.5:80       172.17.0.1:45678

 my_webapp  ~  curl -s localhost/health
{"status":"healthy","uptime":"2h45m"}

 my_webapp  ~  dig backend +short
172.17.0.10

 my_webapp  ~  exit
```

---

## Options

| Option | Description |
|--------|-------------|
| `-h`, `--help` | Affiche l'aide |
| `-c CMD`, `--command CMD` | Exécute une commande et quitte |
| `-l`, `--list-tools` | Liste tous les outils disponibles |
| `-p`, `--podman` | Utilise Podman au lieu de Docker |
| `-v`, `--verbose` | Verbose mode |

---

!!! warning "Privilèges Requis"
    Le conteneur de debug s'exécute en mode `--privileged` pour avoir accès complet
    au namespace réseau. Ceci est nécessaire pour des outils comme `tcpdump` ou `iptables`.

!!! tip "Alias Pratique"
    Ajoutez un alias dans votre `.bashrc` :
    ```bash
    alias netdebug='container-net-debug.sh'

    # Usage : netdebug my_container
    ```

!!! info "Image nicolaka/netshoot"
    L'image `nicolaka/netshoot` est une image Docker populaire contenant plus de
    30 outils réseau. Elle est automatiquement téléchargée si absente.

    Taille : ~180 MB

    GitHub : [github.com/nicolaka/netshoot](https://github.com/nicolaka/netshoot)

---

## Voir Aussi

- [docker_cleaner_pro.py](../python/docker_cleaner_pro.md) - Nettoyage Docker avancé
- [k8s-pod-inspector.sh](k8s-pod-inspector.md) - Diagnostic pods Kubernetes
- [check-connectivity.sh](check-connectivity.md) - Test de connectivité réseau
