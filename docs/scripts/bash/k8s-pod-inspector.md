---
tags:
  - scripts
  - bash
  - kubernetes
  - k8s
  - troubleshooting
  - devops
---

# k8s-pod-inspector.sh

:material-star::material-star: **Niveau : Intermédiaire**

Génération d'un rapport de diagnostic rapide pour un pod en erreur.

---

## Description

Ce script collecte automatiquement toutes les informations de diagnostic nécessaires pour analyser un pod Kubernetes défaillant :

- **Description complète** du pod (état, conditions, événements)
- **Logs actuels** et **logs précédents** (en cas de crash)
- **Événements récents** liés au pod
- **État des containers** (ready, restarts, exit codes)

Le rapport est formaté de manière claire avec des sections distinctes, prêt à être partagé ou archivé.

---

## Prérequis

```bash
# kubectl installé et configuré
kubectl version --client

# Contexte Kubernetes actif
kubectl config current-context

# Droits de lecture sur le namespace cible
kubectl auth can-i get pods -n <namespace>
```

!!! warning "Configuration du contexte kubectl"
    Ce script utilise le contexte kubectl actif. Assurez-vous d'être connecté au bon cluster avant l'exécution :

    ```bash
    # Lister les contextes disponibles
    kubectl config get-contexts

    # Changer de contexte
    kubectl config use-context <context-name>

    # Vérifier le contexte actuel
    kubectl config current-context
    ```

---

## Script

```bash
#!/bin/bash
#===============================================================================
# k8s-pod-inspector.sh - Kubernetes Pod Diagnostic Report Generator
#===============================================================================
# Author: ShellBook
# Version: 1.0
# Description: Generate comprehensive diagnostic report for failing pods
#===============================================================================

set -o pipefail

# Colors for terminal output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly CYAN='\033[0;36m'
readonly BLUE='\033[0;34m'
readonly GRAY='\033[0;90m'
readonly BOLD='\033[1m'
readonly NC='\033[0m'

# Default values
NAMESPACE=""
POD_NAME=""
OUTPUT_FILE=""
TAIL_LINES=100
INCLUDE_PREVIOUS=true
VERBOSE=false

#===============================================================================
# Functions
#===============================================================================

usage() {
    cat << EOF
Usage: $(basename "$0") -n <namespace> -p <pod_name> [OPTIONS]

Generate a diagnostic report for a Kubernetes pod.

Required:
    -n, --namespace NAME    Kubernetes namespace
    -p, --pod NAME          Pod name (supports partial match)

Optional:
    -o, --output FILE       Save report to file (default: stdout)
    -l, --lines NUM         Number of log lines to fetch (default: 100)
    --no-previous           Skip previous container logs
    -v, --verbose           Include additional debug info
    -h, --help              Show this help message

Examples:
    $(basename "$0") -n production -p api-server-7d8f9
    $(basename "$0") -n staging -p worker --output report.txt
    $(basename "$0") -n default -p nginx -l 500 --verbose
EOF
    exit 0
}

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1" >&2; }

print_section() {
    local title="$1"
    local width=70

    echo ""
    echo "$(printf '═%.0s' $(seq 1 $width))"
    echo "  ${title}"
    echo "$(printf '═%.0s' $(seq 1 $width))"
    echo ""
}

print_subsection() {
    local title="$1"
    echo ""
    echo "─── ${title} ───"
    echo ""
}

check_prerequisites() {
    # Check kubectl is installed
    if ! command -v kubectl &> /dev/null; then
        log_error "kubectl is not installed or not in PATH"
        exit 1
    fi

    # Check cluster connectivity
    if ! kubectl cluster-info &> /dev/null; then
        log_error "Cannot connect to Kubernetes cluster"
        log_error "Please check your kubeconfig and context"
        exit 1
    fi

    # Check namespace exists
    if ! kubectl get namespace "$NAMESPACE" &> /dev/null; then
        log_error "Namespace '$NAMESPACE' does not exist"
        exit 1
    fi
}

find_pod() {
    local search="$1"
    local pods

    # Try exact match first
    if kubectl get pod -n "$NAMESPACE" "$search" &> /dev/null; then
        echo "$search"
        return 0
    fi

    # Try partial match
    pods=$(kubectl get pods -n "$NAMESPACE" --no-headers -o custom-columns=":metadata.name" | grep -i "$search" || true)

    if [[ -z "$pods" ]]; then
        return 1
    fi

    # Count matches
    local count
    count=$(echo "$pods" | wc -l)

    if [[ $count -eq 1 ]]; then
        echo "$pods"
        return 0
    else
        log_error "Multiple pods match '$search':"
        echo "$pods" | while read -r pod; do
            echo "  - $pod"
        done
        return 1
    fi
}

get_pod_status_summary() {
    local pod="$1"

    # Get pod phase and conditions
    kubectl get pod -n "$NAMESPACE" "$pod" -o jsonpath='{
        "Phase: "}{.status.phase}{"
        "}{range .status.conditions[*]}{"Condition: "}{.type}{" = "}{.status}{" ("}{.reason}{")"}{"\n"}{end}
    ' 2>/dev/null || echo "Unable to retrieve pod status"
}

get_container_statuses() {
    local pod="$1"

    kubectl get pod -n "$NAMESPACE" "$pod" -o jsonpath='{range .status.containerStatuses[*]}{
        "Container: "}{.name}{"\n"}{
        "  Ready: "}{.ready}{"\n"}{
        "  Restarts: "}{.restartCount}{"\n"}{
        "  State: "}{range .state.*}{@}{end}{"\n"}{
        "---\n"}{end}' 2>/dev/null || echo "Unable to retrieve container statuses"
}

get_init_container_statuses() {
    local pod="$1"

    local init_status
    init_status=$(kubectl get pod -n "$NAMESPACE" "$pod" -o jsonpath='{.status.initContainerStatuses}' 2>/dev/null)

    if [[ -n "$init_status" ]] && [[ "$init_status" != "null" ]]; then
        kubectl get pod -n "$NAMESPACE" "$pod" -o jsonpath='{range .status.initContainerStatuses[*]}{
            "Init Container: "}{.name}{"\n"}{
            "  Ready: "}{.ready}{"\n"}{
            "  State: "}{range .state.*}{@}{end}{"\n"}{
            "---\n"}{end}' 2>/dev/null
    else
        echo "No init containers"
    fi
}

get_pod_events() {
    local pod="$1"

    kubectl get events -n "$NAMESPACE" \
        --field-selector "involvedObject.name=$pod" \
        --sort-by='.lastTimestamp' \
        -o custom-columns='TIMESTAMP:.lastTimestamp,TYPE:.type,REASON:.reason,MESSAGE:.message' \
        2>/dev/null || echo "Unable to retrieve events"
}

get_container_logs() {
    local pod="$1"
    local container="$2"
    local previous="${3:-false}"

    local opts="--tail=$TAIL_LINES"
    [[ "$previous" == "true" ]] && opts="$opts --previous"

    if [[ -n "$container" ]]; then
        kubectl logs -n "$NAMESPACE" "$pod" -c "$container" $opts 2>&1
    else
        kubectl logs -n "$NAMESPACE" "$pod" $opts 2>&1
    fi
}

get_resource_usage() {
    local pod="$1"

    if kubectl top pod -n "$NAMESPACE" "$pod" &> /dev/null; then
        kubectl top pod -n "$NAMESPACE" "$pod" 2>/dev/null
    else
        echo "Metrics not available (metrics-server may not be installed)"
    fi
}

generate_report() {
    local pod="$1"

    # Header
    echo "╔══════════════════════════════════════════════════════════════════════╗"
    echo "║           KUBERNETES POD DIAGNOSTIC REPORT                           ║"
    echo "╚══════════════════════════════════════════════════════════════════════╝"
    echo ""
    echo "Generated: $(date '+%Y-%m-%d %H:%M:%S %Z')"
    echo "Cluster:   $(kubectl config current-context 2>/dev/null || echo 'unknown')"
    echo "Namespace: $NAMESPACE"
    echo "Pod:       $pod"

    # Pod Overview
    print_section "POD OVERVIEW"

    print_subsection "Basic Information"
    kubectl get pod -n "$NAMESPACE" "$pod" -o wide 2>/dev/null

    print_subsection "Status Summary"
    get_pod_status_summary "$pod"

    print_subsection "Resource Usage"
    get_resource_usage "$pod"

    # Container Statuses
    print_section "CONTAINER STATUSES"

    print_subsection "Init Containers"
    get_init_container_statuses "$pod"

    print_subsection "Main Containers"
    get_container_statuses "$pod"

    # Pod Description
    print_section "POD DESCRIPTION"
    kubectl describe pod -n "$NAMESPACE" "$pod" 2>/dev/null

    # Events
    print_section "RELATED EVENTS"
    get_pod_events "$pod"

    # Container Logs
    print_section "CONTAINER LOGS"

    # Get list of containers
    local containers
    containers=$(kubectl get pod -n "$NAMESPACE" "$pod" -o jsonpath='{.spec.containers[*].name}' 2>/dev/null)

    for container in $containers; do
        print_subsection "Logs: $container (current)"
        get_container_logs "$pod" "$container" "false"

        # Get previous logs if container has restarted
        if [[ "$INCLUDE_PREVIOUS" == "true" ]]; then
            local restarts
            restarts=$(kubectl get pod -n "$NAMESPACE" "$pod" \
                -o jsonpath="{.status.containerStatuses[?(@.name==\"$container\")].restartCount}" 2>/dev/null)

            if [[ -n "$restarts" ]] && [[ "$restarts" -gt 0 ]]; then
                print_subsection "Logs: $container (previous - crashed)"
                get_container_logs "$pod" "$container" "true"
            fi
        fi
    done

    # Verbose extras
    if [[ "$VERBOSE" == "true" ]]; then
        print_section "VERBOSE INFORMATION"

        print_subsection "Full Pod YAML"
        kubectl get pod -n "$NAMESPACE" "$pod" -o yaml 2>/dev/null

        print_subsection "Related ReplicaSet/Deployment"
        local owner
        owner=$(kubectl get pod -n "$NAMESPACE" "$pod" -o jsonpath='{.metadata.ownerReferences[0].name}' 2>/dev/null)
        if [[ -n "$owner" ]]; then
            kubectl describe replicaset -n "$NAMESPACE" "$owner" 2>/dev/null || \
            kubectl describe deployment -n "$NAMESPACE" "$owner" 2>/dev/null || \
            echo "Owner resource not found or not accessible"
        fi
    fi

    # Footer
    echo ""
    echo "═══════════════════════════════════════════════════════════════════════"
    echo "  END OF DIAGNOSTIC REPORT"
    echo "═══════════════════════════════════════════════════════════════════════"
}

#===============================================================================
# Parse arguments
#===============================================================================

while [[ $# -gt 0 ]]; do
    case $1 in
        -n|--namespace)
            NAMESPACE="$2"
            shift 2
            ;;
        -p|--pod)
            POD_NAME="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        -l|--lines)
            TAIL_LINES="$2"
            shift 2
            ;;
        --no-previous)
            INCLUDE_PREVIOUS=false
            shift
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            log_error "Unknown option: $1"
            echo "Use --help for usage information."
            exit 1
            ;;
    esac
done

#===============================================================================
# Main
#===============================================================================

# Validate required arguments
if [[ -z "$NAMESPACE" ]]; then
    log_error "Namespace is required (-n, --namespace)"
    exit 1
fi

if [[ -z "$POD_NAME" ]]; then
    log_error "Pod name is required (-p, --pod)"
    exit 1
fi

# Check prerequisites
check_prerequisites

# Find the pod (supports partial matching)
log_info "Searching for pod '$POD_NAME' in namespace '$NAMESPACE'..."
ACTUAL_POD=$(find_pod "$POD_NAME")

if [[ -z "$ACTUAL_POD" ]]; then
    log_error "Pod '$POD_NAME' not found in namespace '$NAMESPACE'"
    exit 1
fi

if [[ "$ACTUAL_POD" != "$POD_NAME" ]]; then
    log_info "Found matching pod: $ACTUAL_POD"
fi

# Generate report
log_info "Generating diagnostic report..."

if [[ -n "$OUTPUT_FILE" ]]; then
    generate_report "$ACTUAL_POD" > "$OUTPUT_FILE"
    log_info "Report saved to: $OUTPUT_FILE"
else
    generate_report "$ACTUAL_POD"
fi

log_info "Diagnostic complete."
```

---

## Utilisation

### Diagnostic basique

```bash
# Pod dans un namespace spécifique
./k8s-pod-inspector.sh -n production -p api-server-7d8f9abc-xyz

# Avec correspondance partielle du nom
./k8s-pod-inspector.sh -n staging -p worker
# Trouvera automatiquement "worker-deployment-7d8f9-abc12"
```

### Export vers fichier

```bash
# Sauvegarder le rapport
./k8s-pod-inspector.sh -n production -p api-server -o diagnostic.txt

# Avec timestamp dans le nom
./k8s-pod-inspector.sh -n prod -p nginx -o "report-$(date +%Y%m%d-%H%M%S).txt"
```

### Options avancées

```bash
# Plus de lignes de logs
./k8s-pod-inspector.sh -n default -p myapp -l 500

# Sans les logs des containers précédents
./k8s-pod-inspector.sh -n default -p myapp --no-previous

# Mode verbeux (inclut le YAML complet et les ReplicaSets)
./k8s-pod-inspector.sh -n production -p api -v --output full-report.txt
```

---

## Sortie exemple

```
╔══════════════════════════════════════════════════════════════════════╗
║           KUBERNETES POD DIAGNOSTIC REPORT                           ║
╚══════════════════════════════════════════════════════════════════════╝

Generated: 2024-11-30 15:45:22 UTC
Cluster:   production-cluster
Namespace: production
Pod:       api-server-7d8f9abc-xyz

══════════════════════════════════════════════════════════════════════
  POD OVERVIEW
══════════════════════════════════════════════════════════════════════

─── Basic Information ───

NAME                      READY   STATUS             RESTARTS   AGE   IP           NODE
api-server-7d8f9abc-xyz   0/1     CrashLoopBackOff   5          10m   10.0.2.15    node-1

─── Status Summary ───

Phase: Running
Condition: Initialized = True ()
Condition: Ready = False (ContainersNotReady)
Condition: ContainersReady = False (ContainersNotReady)
Condition: PodScheduled = True ()

─── Container Statuses ───

Container: api-server
  Ready: false
  Restarts: 5
  State: waiting reason:CrashLoopBackOff

══════════════════════════════════════════════════════════════════════
  RELATED EVENTS
══════════════════════════════════════════════════════════════════════

TIMESTAMP              TYPE      REASON     MESSAGE
2024-11-30T15:40:22Z   Normal    Pulled     Container image pulled
2024-11-30T15:40:23Z   Normal    Created    Created container api-server
2024-11-30T15:40:24Z   Normal    Started    Started container api-server
2024-11-30T15:40:30Z   Warning   BackOff    Back-off restarting failed container

══════════════════════════════════════════════════════════════════════
  CONTAINER LOGS
══════════════════════════════════════════════════════════════════════

─── Logs: api-server (previous - crashed) ───

2024-11-30 15:40:25 ERROR Database connection failed
2024-11-30 15:40:25 ERROR Unable to connect to postgres:5432
2024-11-30 15:40:25 FATAL Exiting due to configuration error

═══════════════════════════════════════════════════════════════════════
  END OF DIAGNOSTIC REPORT
═══════════════════════════════════════════════════════════════════════
```

---

## Intégration CI/CD

### Diagnostic automatique sur échec de déploiement

```bash
#!/bin/bash
# post-deploy-check.sh

NAMESPACE="$1"
DEPLOYMENT="$2"

# Wait for rollout
if ! kubectl rollout status deployment/$DEPLOYMENT -n $NAMESPACE --timeout=300s; then
    echo "Deployment failed! Generating diagnostic..."

    # Find failed pods
    FAILED_POD=$(kubectl get pods -n $NAMESPACE -l app=$DEPLOYMENT \
        --field-selector=status.phase!=Running -o jsonpath='{.items[0].metadata.name}')

    if [[ -n "$FAILED_POD" ]]; then
        ./k8s-pod-inspector.sh -n $NAMESPACE -p $FAILED_POD -o "failed-deploy-$(date +%s).txt"
    fi

    exit 1
fi
```

---

!!! tip "Astuce : Alias kubectl"
    Créez un alias pour un accès rapide :

    ```bash
    # Dans ~/.bashrc ou ~/.zshrc
    alias kdiag='/path/to/k8s-pod-inspector.sh'

    # Utilisation
    kdiag -n prod -p api-server
    ```

---

## Voir Aussi

- [container-net-debug.sh](container-net-debug.md) - Debug réseau des containers
- [kubernetes_health.py](../python/kubernetes_health.md) - Vérification santé cluster
