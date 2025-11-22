# Kubectl Survival Kit

`#kubectl` `#debug` `#pods` `#cheatsheet`

Commandes essentielles pour le troubleshooting Kubernetes au quotidien.

---

## Configuration & Contextes

### Gérer les Clusters

```bash
# Voir la config actuelle
kubectl config view

# Lister les contextes disponibles
kubectl config get-contexts

# Contexte actuel
kubectl config current-context

# Changer de contexte
kubectl config use-context production-cluster

# Changer le namespace par défaut d'un contexte
kubectl config set-context --current --namespace=myapp
```

### Must Have : kubectx & kubens

```bash
# Installation
# macOS
brew install kubectx

# Linux
sudo apt install kubectx

# Ou via krew (plugin manager)
kubectl krew install ctx ns
```

```bash
# kubectx : Changer de cluster rapidement
kubectx                      # Liste les contextes
kubectx production           # Switch vers "production"
kubectx -                    # Revenir au contexte précédent

# kubens : Changer de namespace rapidement
kubens                       # Liste les namespaces
kubens kube-system           # Switch vers kube-system
kubens -                     # Revenir au namespace précédent
```

### Alias Vitaux (~/.bashrc ou ~/.zshrc)

```bash
# Alias de base
alias k='kubectl'
alias kgp='kubectl get pods'
alias kgs='kubectl get svc'
alias kgd='kubectl get deployments'
alias kgn='kubectl get nodes'
alias kga='kubectl get all'

# Avec namespace
alias kgpa='kubectl get pods -A'           # All namespaces
alias kgpw='kubectl get pods -o wide'      # Plus de détails

# Describe et logs
alias kdp='kubectl describe pod'
alias kl='kubectl logs -f'

# Apply et delete
alias ka='kubectl apply -f'
alias kd='kubectl delete -f'

# Contexte et namespace
alias kctx='kubectl config current-context'
alias kns='kubectl config view --minify --output "jsonpath={..namespace}"'
```

### Autocomplétion

```bash
# Bash
source <(kubectl completion bash)
echo 'source <(kubectl completion bash)' >> ~/.bashrc

# Zsh
source <(kubectl completion zsh)
echo 'source <(kubectl completion zsh)' >> ~/.zshrc

# Autocomplétion pour l'alias k
complete -o default -F __start_kubectl k
```

---

## Pod Lifecycle Management

### Créer Rapidement (Mode Impératif)

```bash
# Créer un pod simple
kubectl run nginx --image=nginx

# Pod one-shot (ne redémarre pas)
kubectl run debug --image=busybox --restart=Never -- sleep 3600

# Pod interactif (supprimé à la sortie)
kubectl run -it debug --image=busybox --rm --restart=Never -- /bin/sh

# Avec des variables d'environnement
kubectl run myapp --image=myapp:v1 --env="DB_HOST=postgres" --env="DB_PORT=5432"

# Avec des limites de ressources
kubectl run nginx --image=nginx --requests='cpu=100m,memory=256Mi' --limits='cpu=200m,memory=512Mi'
```

### Générer du YAML (Sans Créer)

```bash
# Générer le YAML d'un pod
kubectl run nginx --image=nginx --dry-run=client -o yaml > nginx-pod.yaml

# Générer le YAML d'un deployment
kubectl create deployment nginx --image=nginx --dry-run=client -o yaml > nginx-deploy.yaml

# Générer le YAML d'un service
kubectl expose deployment nginx --port=80 --dry-run=client -o yaml > nginx-svc.yaml

# Générer un job
kubectl create job myjob --image=busybox --dry-run=client -o yaml -- echo "Hello"

# Générer un cronjob
kubectl create cronjob mycron --image=busybox --schedule="*/5 * * * *" --dry-run=client -o yaml -- echo "Hello"
```

!!! tip "Astuce CKA/CKAD"
    `--dry-run=client -o yaml` est votre meilleur ami pour les examens. Générez le squelette puis éditez.

### Supprimer des Ressources

```bash
# Suppression normale
kubectl delete pod nginx

# Suppression avec timeout
kubectl delete pod nginx --timeout=30s

# Forcer la suppression (pod bloqué en Terminating)
kubectl delete pod nginx --grace-period=0 --force

# Supprimer tous les pods d'un namespace
kubectl delete pods --all -n myapp

# Supprimer par label
kubectl delete pods -l app=nginx
```

### Mise à Jour

```bash
# Mettre à jour l'image d'un deployment
kubectl set image deployment/myapp myapp=myapp:v2

# Rollback
kubectl rollout undo deployment/myapp

# Voir l'historique des révisions
kubectl rollout history deployment/myapp

# Rollback vers une révision spécifique
kubectl rollout undo deployment/myapp --to-revision=2

# Status du rollout
kubectl rollout status deployment/myapp

# Restart (force le re-pull de l'image)
kubectl rollout restart deployment/myapp
```

---

## Inspection & Debug

### Logs

```bash
# Logs d'un pod
kubectl logs mypod

# Suivre les logs en temps réel
kubectl logs -f mypod

# Dernières 100 lignes
kubectl logs --tail=100 mypod

# Logs depuis 1 heure
kubectl logs --since=1h mypod

# Logs d'un container spécifique (pod multi-containers)
kubectl logs mypod -c sidecar-container

# Logs de tous les containers du pod
kubectl logs mypod --all-containers=true

# Logs d'un pod précédent (crash)
kubectl logs mypod --previous

# Logs par label (tous les pods d'une app)
kubectl logs -l app=nginx --all-containers=true
```

### Shell Interactif

```bash
# Bash dans un pod
kubectl exec -it mypod -- /bin/bash

# Si bash n'existe pas (images minimalistes)
kubectl exec -it mypod -- /bin/sh

# Container spécifique
kubectl exec -it mypod -c mycontainer -- /bin/bash

# Commande unique (non interactif)
kubectl exec mypod -- cat /etc/config/app.conf
kubectl exec mypod -- env
kubectl exec mypod -- ps aux

# Debug avec image ephemeral container (K8s 1.23+)
kubectl debug -it mypod --image=busybox --target=mycontainer
```

### Copier des Fichiers

```bash
# Pod → Local
kubectl cp mypod:/var/log/app.log ./app.log
kubectl cp mypod:/etc/config/ ./config-backup/

# Local → Pod
kubectl cp ./config.yaml mypod:/app/config.yaml

# Avec namespace
kubectl cp myns/mypod:/path/file ./file

# Container spécifique
kubectl cp mypod:/path/file ./file -c mycontainer
```

### Port-Forward

```bash
# Forward un port vers un pod
kubectl port-forward pod/mypod 8080:80

# Forward vers un service
kubectl port-forward svc/postgres 5432:5432

# Forward vers un deployment
kubectl port-forward deployment/myapp 8080:80

# Écouter sur toutes les interfaces (accès réseau)
kubectl port-forward --address 0.0.0.0 svc/myapp 8080:80

# Background
kubectl port-forward svc/postgres 5432:5432 &
```

### Describe (Le Debugger)

```bash
# Describe un pod (EVENTS = clé du debug)
kubectl describe pod mypod

# Les events sont en bas - cherchez :
# - Failed to pull image
# - Insufficient cpu/memory
# - Back-off restarting failed container
# - FailedScheduling

# Describe autres ressources
kubectl describe node worker-1
kubectl describe svc myservice
kubectl describe deployment myapp
kubectl describe pvc my-volume
```

---

## Nodes & Ressources

### Métriques (Nécessite Metrics Server)

```bash
# Ressources des nodes
kubectl top nodes

# Output:
# NAME       CPU(cores)   CPU%   MEMORY(bytes)   MEMORY%
# worker-1   250m         12%    2048Mi          52%
# worker-2   180m         9%     1536Mi          39%

# Ressources des pods
kubectl top pods
kubectl top pods -A                    # Tous les namespaces
kubectl top pods --sort-by=memory      # Trier par RAM
kubectl top pods --sort-by=cpu         # Trier par CPU

# Pod spécifique avec containers
kubectl top pod mypod --containers
```

### État des Nodes

```bash
# Lister les nodes
kubectl get nodes
kubectl get nodes -o wide              # Plus de détails

# Conditions d'un node
kubectl describe node worker-1 | grep -A5 Conditions

# Pourquoi un node est NotReady ?
kubectl describe node worker-1 | grep -A10 "Conditions:"

# Taints d'un node
kubectl describe node worker-1 | grep Taints

# Pods sur un node spécifique
kubectl get pods -A --field-selector spec.nodeName=worker-1
```

### Diagnostiquer un Pod "Pending"

```bash
# Describe = la réponse est dans les Events
kubectl describe pod mypod

# Causes communes :
# - Insufficient cpu/memory → Pas assez de ressources
# - No nodes available → Aucun node ne matche les contraintes
# - PersistentVolumeClaim not bound → PVC en attente
# - ImagePullBackOff → Image introuvable

# Vérifier les ressources disponibles sur les nodes
kubectl describe nodes | grep -A5 "Allocated resources"
```

### Pod non-Running : Checklist

| État | Commande | Cause probable |
|------|----------|----------------|
| **Pending** | `describe pod` | Ressources, nodeSelector, PVC |
| **ImagePullBackOff** | `describe pod` | Image introuvable, auth registry |
| **CrashLoopBackOff** | `logs --previous` | App crash au démarrage |
| **Error** | `logs` | Erreur applicative |
| **Terminating** | `delete --force` | Finalizers, preStop hook |

```bash
# Debug rapide : tout en une commande
kubectl get pod mypod -o yaml | grep -A20 "status:"
```

---

## Référence Rapide

```bash
# === CONTEXTE ===
kubectl config get-contexts
kubectl config use-context prod
kubectx / kubens                # Outils recommandés

# === PODS ===
kubectl run nginx --image=nginx --dry-run=client -o yaml
kubectl delete pod x --grace-period=0 --force

# === DEBUG ===
kubectl logs -f mypod
kubectl logs mypod -c container --previous
kubectl exec -it mypod -- /bin/sh
kubectl describe pod mypod      # EVENTS !
kubectl port-forward svc/db 5432:5432

# === COPIE ===
kubectl cp mypod:/path/file ./file

# === RESSOURCES ===
kubectl top nodes
kubectl top pods --sort-by=memory

# === ROLLOUT ===
kubectl set image deploy/app app=app:v2
kubectl rollout undo deploy/app
kubectl rollout restart deploy/app
```
