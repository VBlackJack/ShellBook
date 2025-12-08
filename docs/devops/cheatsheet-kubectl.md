---
tags:
  - kubernetes
  - kubectl
  - cheatsheet
  - k8s
  - containers
---

# Kubectl Cheatsheet

Guide de référence rapide pour les commandes kubectl essentielles au quotidien.

---

## 1. Configuration & Contextes

### Gestion des Contextes

| Action | Commande | Description |
|--------|----------|-------------|
| **Lister contextes** | `kubectl config get-contexts` | Afficher tous les contextes disponibles |
| **Contexte actuel** | `kubectl config current-context` | Afficher le contexte en cours |
| **Changer contexte** | `kubectl config use-context <nom>` | Basculer vers un contexte |
| **Définir namespace** | `kubectl config set-context --current --namespace=<ns>` | Définir le namespace par défaut |
| **Voir config** | `kubectl config view` | Afficher la configuration kubeconfig |

```bash
# Créer un alias pour un contexte
kubectl config set-context dev --cluster=minikube --user=minikube --namespace=dev

# Basculer rapidement entre contextes
kubectl config use-context production
kubectl config use-context staging

# Voir quel namespace est actif
kubectl config view --minify | grep namespace:
```

!!! tip "Alias Recommandé"
    ```bash
    alias k='kubectl'
    alias kx='kubectl config use-context'
    alias kns='kubectl config set-context --current --namespace'
    ```

### Gestion des Namespaces

| Action | Commande |
|--------|----------|
| **Lister namespaces** | `kubectl get namespaces` ou `kubectl get ns` |
| **Créer namespace** | `kubectl create namespace <nom>` |
| **Supprimer namespace** | `kubectl delete namespace <nom>` |
| **Tout voir dans un NS** | `kubectl get all -n <namespace>` |

```bash
# Créer plusieurs namespaces
kubectl create ns dev
kubectl create ns staging
kubectl create ns production

# Travailler temporairement dans un namespace
kubectl get pods -n kube-system
kubectl get svc -n production

# Définir le namespace par défaut pour la session
kns production  # Avec l'alias défini plus haut
```

---

## 2. Pods

### Opérations de Base

| Action | Commande | Description |
|--------|----------|-------------|
| **Lister pods** | `kubectl get pods` | Tous les pods du namespace actuel |
| **Tous les namespaces** | `kubectl get pods -A` ou `--all-namespaces` | Pods de tous les namespaces |
| **Détails d'un pod** | `kubectl describe pod <nom>` | Informations détaillées |
| **Format large** | `kubectl get pods -o wide` | Afficher IP, Node, etc. |
| **Watch** | `kubectl get pods -w` | Surveiller les changements en temps réel |
| **Créer pod** | `kubectl run <nom> --image=<image>` | Créer un pod simple |
| **Supprimer pod** | `kubectl delete pod <nom>` | Supprimer un pod |
| **Force delete** | `kubectl delete pod <nom> --grace-period=0 --force` | Suppression forcée |

```bash
# Lancer un pod nginx temporaire
kubectl run nginx --image=nginx:latest --port=80

# Pod avec variables d'environnement
kubectl run myapp --image=myapp:v1 --env="ENV=production" --env="DEBUG=false"

# Pod temporaire pour debug (supprimé après exit)
kubectl run debug --rm -it --image=busybox -- sh

# Obtenir les pods avec leur consommation (nécessite metrics-server)
kubectl top pods
kubectl top pods --all-namespaces
```

### Sélecteurs & Filtres

```bash
# Filtrer par label
kubectl get pods -l app=nginx
kubectl get pods -l app=nginx,env=production
kubectl get pods -l 'env in (dev,staging)'

# Filtrer par statut
kubectl get pods --field-selector=status.phase=Running
kubectl get pods --field-selector=status.phase!=Running

# Trier par création
kubectl get pods --sort-by=.metadata.creationTimestamp

# Trier par restarts
kubectl get pods --sort-by='.status.containerStatuses[0].restartCount'
```

---

## 3. Deployments, ReplicaSets & StatefulSets

### Deployments

| Action | Commande |
|--------|----------|
| **Lister** | `kubectl get deployments` ou `kubectl get deploy` |
| **Créer** | `kubectl create deployment <nom> --image=<image>` |
| **Scaler** | `kubectl scale deployment <nom> --replicas=5` |
| **Autoscale** | `kubectl autoscale deployment <nom> --min=2 --max=10 --cpu-percent=80` |
| **Update image** | `kubectl set image deployment/<nom> <container>=<image>:<tag>` |
| **Rollout status** | `kubectl rollout status deployment/<nom>` |
| **Rollout history** | `kubectl rollout history deployment/<nom>` |
| **Rollback** | `kubectl rollout undo deployment/<nom>` |
| **Rollback version** | `kubectl rollout undo deployment/<nom> --to-revision=2` |
| **Pause rollout** | `kubectl rollout pause deployment/<nom>` |
| **Resume rollout** | `kubectl rollout resume deployment/<nom>` |

```bash
# Créer un deployment avec 3 replicas
kubectl create deployment webapp --image=nginx:1.21 --replicas=3

# Mettre à jour l'image (déclenchement d'un rolling update)
kubectl set image deployment/webapp nginx=nginx:1.22

# Surveiller le déploiement
kubectl rollout status deployment/webapp

# Voir l'historique des déploiements
kubectl rollout history deployment/webapp

# Rollback au déploiement précédent
kubectl rollout undo deployment/webapp

# Rollback à une version spécifique
kubectl rollout history deployment/webapp  # Voir les révisions
kubectl rollout undo deployment/webapp --to-revision=3
```

!!! warning "Rolling Updates"
    Par défaut, Kubernetes effectue un rolling update (mise à jour progressive).
    Configuration dans le deployment:
    ```yaml
    spec:
      replicas: 3
      strategy:
        type: RollingUpdate
        rollingUpdate:
          maxSurge: 1        # Max 1 pod supplémentaire pendant l'update
          maxUnavailable: 0  # Aucun pod indisponible (zero downtime)
    ```

### ReplicaSets & StatefulSets

```bash
# Lister ReplicaSets
kubectl get replicasets
kubectl get rs

# Lister StatefulSets
kubectl get statefulsets
kubectl get sts

# Scaler un StatefulSet
kubectl scale statefulset/mysql --replicas=3

# Supprimer un StatefulSet sans supprimer les pods
kubectl delete statefulset mysql --cascade=false
```

---

## 4. Services & Networking

### Services

| Action | Commande |
|--------|----------|
| **Lister services** | `kubectl get services` ou `kubectl get svc` |
| **Créer service** | `kubectl expose deployment <nom> --port=80 --type=ClusterIP` |
| **Service NodePort** | `kubectl expose deployment <nom> --port=80 --type=NodePort` |
| **Service LoadBalancer** | `kubectl expose deployment <nom> --port=80 --type=LoadBalancer` |
| **Détails service** | `kubectl describe svc <nom>` |
| **Endpoints** | `kubectl get endpoints <service>` |

```bash
# Exposer un deployment en ClusterIP (interne uniquement)
kubectl expose deployment webapp --port=80 --target-port=8080 --name=webapp-svc

# Exposer en NodePort (accessible via IP du node)
kubectl expose deployment webapp --port=80 --type=NodePort --name=webapp-nodeport

# Exposer en LoadBalancer (cloud provider)
kubectl expose deployment webapp --port=80 --type=LoadBalancer --name=webapp-lb

# Voir les endpoints d'un service
kubectl get endpoints webapp-svc

# Tester un service depuis un pod temporaire
kubectl run curl --image=curlimages/curl -i --rm --restart=Never -- curl http://webapp-svc
```

### Ingress

```bash
# Lister les Ingress
kubectl get ingress
kubectl get ing

# Décrire un Ingress
kubectl describe ingress myapp-ingress

# Créer un Ingress (nécessite un fichier YAML)
kubectl apply -f ingress.yaml
```

### Network Policies

```bash
# Lister les Network Policies
kubectl get networkpolicies
kubectl get netpol

# Décrire une Network Policy
kubectl describe networkpolicy deny-all
```

---

## 5. Logs & Debugging

### Logs

| Action | Commande |
|--------|----------|
| **Logs d'un pod** | `kubectl logs <pod>` |
| **Logs container spécifique** | `kubectl logs <pod> -c <container>` |
| **Follow logs** | `kubectl logs -f <pod>` |
| **Logs précédent** | `kubectl logs <pod> --previous` |
| **Dernières N lignes** | `kubectl logs <pod> --tail=100` |
| **Logs depuis X temps** | `kubectl logs <pod> --since=1h` |
| **Tous les pods d'un label** | `kubectl logs -l app=nginx --all-containers=true` |

```bash
# Logs en temps réel
kubectl logs -f webapp-7d8f9c5b6-xkq2m

# Logs du container précédent (après crash)
kubectl logs webapp-7d8f9c5b6-xkq2m --previous

# Logs multiples pods (par label)
kubectl logs -f -l app=webapp --all-containers=true

# Logs depuis les 30 dernières minutes
kubectl logs webapp-7d8f9c5b6-xkq2m --since=30m

# Logs avec timestamps
kubectl logs webapp-7d8f9c5b6-xkq2m --timestamps

# Exporter les logs dans un fichier
kubectl logs webapp-7d8f9c5b6-xkq2m > /tmp/webapp.log
```

### Debugging & Exec

| Action | Commande |
|--------|----------|
| **Shell dans un pod** | `kubectl exec -it <pod> -- /bin/bash` |
| **Exec dans container** | `kubectl exec -it <pod> -c <container> -- /bin/sh` |
| **Commande unique** | `kubectl exec <pod> -- ls -la /app` |
| **Port forward** | `kubectl port-forward <pod> 8080:80` |
| **Port forward service** | `kubectl port-forward svc/<service> 8080:80` |
| **Copy vers pod** | `kubectl cp /local/file <pod>:/remote/path` |
| **Copy depuis pod** | `kubectl cp <pod>:/remote/file /local/path` |

```bash
# Ouvrir un shell dans un pod
kubectl exec -it webapp-7d8f9c5b6-xkq2m -- /bin/bash

# Exécuter une commande sans entrer dans le pod
kubectl exec webapp-7d8f9c5b6-xkq2m -- env
kubectl exec webapp-7d8f9c5b6-xkq2m -- cat /etc/nginx/nginx.conf

# Port forwarding (accès local au pod)
kubectl port-forward webapp-7d8f9c5b6-xkq2m 8080:80
# Ensuite: curl http://localhost:8080

# Port forwarding vers un service
kubectl port-forward svc/webapp-svc 8080:80

# Copier un fichier vers un pod
kubectl cp config.yaml webapp-7d8f9c5b6-xkq2m:/etc/app/config.yaml

# Copier depuis un pod
kubectl cp webapp-7d8f9c5b6-xkq2m:/var/log/app.log ./app.log
```

### Debugging Avancé

```bash
# Voir les événements du cluster
kubectl get events --sort-by=.metadata.creationTimestamp
kubectl get events --field-selector type=Warning

# Événements d'un namespace
kubectl get events -n kube-system

# Debug d'un pod qui ne démarre pas
kubectl describe pod <pod>
kubectl logs <pod> --previous

# Créer un pod de debug avec image spécifique
kubectl debug <pod> -it --image=busybox --share-processes --copy-to=debug-pod

# Voir l'utilisation des ressources
kubectl top nodes
kubectl top pods
kubectl top pods --containers
```

---

## 6. ConfigMaps & Secrets

### ConfigMaps

| Action | Commande |
|--------|----------|
| **Lister** | `kubectl get configmaps` ou `kubectl get cm` |
| **Créer depuis literal** | `kubectl create configmap <nom> --from-literal=key=value` |
| **Créer depuis fichier** | `kubectl create configmap <nom> --from-file=config.yaml` |
| **Créer depuis dossier** | `kubectl create configmap <nom> --from-file=/path/to/dir/` |
| **Voir contenu** | `kubectl describe configmap <nom>` |
| **Voir en YAML** | `kubectl get configmap <nom> -o yaml` |

```bash
# Créer un ConfigMap avec des paires clé-valeur
kubectl create configmap app-config \
  --from-literal=database_host=mysql.example.com \
  --from-literal=database_port=3306 \
  --from-literal=log_level=info

# Créer depuis un fichier
kubectl create configmap nginx-config --from-file=nginx.conf

# Créer depuis plusieurs fichiers
kubectl create configmap app-configs --from-file=./config/

# Voir le contenu
kubectl get configmap app-config -o yaml

# Utiliser dans un pod (exemple)
# spec:
#   containers:
#   - name: app
#     envFrom:
#     - configMapRef:
#         name: app-config
```

### Secrets

| Action | Commande |
|--------|----------|
| **Lister** | `kubectl get secrets` |
| **Créer generic** | `kubectl create secret generic <nom> --from-literal=key=value` |
| **Créer TLS** | `kubectl create secret tls <nom> --cert=cert.crt --key=cert.key` |
| **Créer docker-registry** | `kubectl create secret docker-registry <nom> --docker-server=<server> --docker-username=<user> --docker-password=<pass>` |
| **Voir secret** | `kubectl get secret <nom> -o yaml` |
| **Décoder secret** | `kubectl get secret <nom> -o jsonpath='{.data.password}' \| base64 -d` |

```bash
# Créer un secret pour DB credentials
kubectl create secret generic db-credentials \
  --from-literal=username=admin \
  --from-literal=password='MyS3cr3tP@ss'

# Créer un secret TLS
kubectl create secret tls webapp-tls \
  --cert=webapp.crt \
  --key=webapp.key

# Secret pour pull depuis un registry privé
kubectl create secret docker-registry regcred \
  --docker-server=registry.example.com \
  --docker-username=myuser \
  --docker-password=mypassword \
  --docker-email=myemail@example.com

# Voir un secret (encodé en base64)
kubectl get secret db-credentials -o yaml

# Décoder un secret
kubectl get secret db-credentials -o jsonpath='{.data.password}' | base64 -d
echo ""  # Ajouter un retour à la ligne

# Créer un secret depuis un fichier
kubectl create secret generic ssh-key --from-file=id_rsa=~/.ssh/id_rsa
```

!!! danger "Attention Sécurité"
    Les secrets Kubernetes sont encodés en base64, **PAS chiffrés**.
    - Utilisez RBAC pour limiter l'accès
    - Considérez des solutions comme **Sealed Secrets** ou **External Secrets Operator**
    - Activez le chiffrement au repos (encryption at rest)

---

## 7. Volumes & Persistent Storage

### PersistentVolumes & PersistentVolumeClaims

```bash
# Lister PersistentVolumes
kubectl get persistentvolumes
kubectl get pv

# Lister PersistentVolumeClaims
kubectl get persistentvolumeclaims
kubectl get pvc

# Décrire un PVC
kubectl describe pvc mysql-pvc

# Voir l'utilisation du stockage
kubectl get pvc -o custom-columns=NAME:.metadata.name,SIZE:.spec.resources.requests.storage,USED:.status.capacity.storage

# Supprimer un PVC (attention: supprime les données si reclaim policy = Delete)
kubectl delete pvc mysql-pvc
```

### StorageClasses

```bash
# Lister les StorageClasses
kubectl get storageclass
kubectl get sc

# Voir les détails
kubectl describe sc standard

# Définir une StorageClass par défaut
kubectl patch storageclass standard -p '{"metadata": {"annotations":{"storageclass.kubernetes.io/is-default-class":"true"}}}'
```

---

## 8. Commandes Utilitaires

### Manipulation YAML & JSON

```bash
# Obtenir la définition YAML d'une ressource
kubectl get pod webapp-7d8f9c5b6-xkq2m -o yaml

# Format JSON
kubectl get pod webapp-7d8f9c5b6-xkq2m -o json

# Extraire un champ spécifique (jsonpath)
kubectl get pods -o jsonpath='{.items[*].metadata.name}'
kubectl get pods -o jsonpath='{.items[*].status.podIP}'

# Format custom-columns
kubectl get pods -o custom-columns=NAME:.metadata.name,STATUS:.status.phase,IP:.status.podIP

# Export pour sauvegarde/migration
kubectl get deployment webapp -o yaml --export > webapp-deployment.yaml

# Dry-run: Voir le YAML sans créer la ressource
kubectl create deployment test --image=nginx --dry-run=client -o yaml
kubectl run test --image=nginx --dry-run=client -o yaml > pod.yaml
```

### Apply, Create, Replace

```bash
# Apply: Créer ou mettre à jour (recommandé)
kubectl apply -f deployment.yaml

# Create: Créer uniquement (erreur si existe)
kubectl create -f deployment.yaml

# Replace: Remplacer (erreur si n'existe pas)
kubectl replace -f deployment.yaml

# Delete: Supprimer
kubectl delete -f deployment.yaml

# Apply un dossier entier
kubectl apply -f ./manifests/

# Apply depuis une URL
kubectl apply -f https://raw.githubusercontent.com/example/repo/main/deploy.yaml
```

### Labels & Annotations

```bash
# Ajouter un label
kubectl label pod webapp-7d8f9c5b6-xkq2m env=production

# Modifier un label existant
kubectl label pod webapp-7d8f9c5b6-xkq2m env=staging --overwrite

# Supprimer un label
kubectl label pod webapp-7d8f9c5b6-xkq2m env-

# Ajouter une annotation
kubectl annotate pod webapp-7d8f9c5b6-xkq2m description="Main web application"

# Lister avec labels
kubectl get pods --show-labels
kubectl get pods -L app,env
```

---

## 9. Gestion des Ressources

### Quotas & Limits

```bash
# Lister ResourceQuotas
kubectl get resourcequotas
kubectl get quota

# Lister LimitRanges
kubectl get limitranges
kubectl get limits

# Voir l'utilisation des ressources d'un namespace
kubectl describe namespace production
kubectl top pods -n production
kubectl top nodes
```

### Patch & Edit

```bash
# Edit: Ouvrir la ressource dans un éditeur
kubectl edit deployment webapp

# Patch: Modifier partiellement (JSON)
kubectl patch deployment webapp -p '{"spec":{"replicas":5}}'

# Patch stratégique (merge)
kubectl patch deployment webapp --type='json' -p='[{"op": "replace", "path": "/spec/replicas", "value":3}]'

# Patch avec un fichier
kubectl patch deployment webapp --patch-file=patch.yaml
```

---

## 10. Maintenance & Administration

### Nodes

```bash
# Lister les nodes
kubectl get nodes
kubectl get nodes -o wide

# Détails d'un node
kubectl describe node <node-name>

# Marquer un node comme non schedulable (drain)
kubectl cordon <node-name>

# Évacuer les pods d'un node (maintenance)
kubectl drain <node-name> --ignore-daemonsets --delete-emptydir-data

# Remettre un node en service
kubectl uncordon <node-name>

# Voir les pods sur un node
kubectl get pods --all-namespaces -o wide --field-selector spec.nodeName=<node-name>

# Taint un node (empêcher scheduling)
kubectl taint nodes <node-name> key=value:NoSchedule

# Retirer un taint
kubectl taint nodes <node-name> key:NoSchedule-
```

### Backup & Restore

```bash
# Backup de toutes les ressources d'un namespace
kubectl get all -n production -o yaml > backup-production.yaml

# Backup spécifique
kubectl get deployment,service,configmap,secret -n production -o yaml > backup.yaml

# Restore
kubectl apply -f backup-production.yaml

# Backup avec Velero (outil dédié)
velero backup create production-backup --include-namespaces production
velero restore create --from-backup production-backup
```

---

## 11. Tips & Tricks

### Productivité

```bash
# Complétion bash (à ajouter dans ~/.bashrc)
source <(kubectl completion bash)
echo "source <(kubectl completion bash)" >> ~/.bashrc

# Alias kubectl -> k
alias k=kubectl
complete -o default -F __start_kubectl k

# Fonction pour changer rapidement de namespace
kns() {
  kubectl config set-context --current --namespace=$1
}

# Fonction pour changer de contexte
kx() {
  kubectl config use-context $1
}
```

### Commandes Combinées

```bash
# Supprimer tous les pods Failed
kubectl delete pods --field-selector status.phase=Failed -A

# Supprimer tous les pods Evicted
kubectl get pods -A | grep Evicted | awk '{print $2, "-n", $1}' | xargs kubectl delete pod

# Redémarrer tous les pods d'un deployment
kubectl rollout restart deployment webapp

# Obtenir les images de tous les pods
kubectl get pods -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.containers[*].image}{"\n"}{end}'

# Compter les pods par node
kubectl get pods -A -o wide | awk '{print $8}' | sort | uniq -c

# Voir tous les pods qui ne sont pas Running
kubectl get pods -A --field-selector=status.phase!=Running
```

### Debug Shortcuts

```bash
# Pod de debug temporaire (auto-supprimé)
kubectl run debug-pod --rm -it --image=nicolaka/netshoot -- bash

# Tester la résolution DNS
kubectl run dnsutils --rm -it --image=gcr.io/kubernetes-e2e-test-images/dnsutils:1.3 -- nslookup kubernetes.default

# Curl depuis un pod temporaire
kubectl run curl --rm -it --image=curlimages/curl -- sh

# Voir les API resources disponibles
kubectl api-resources
kubectl api-resources --namespaced=true
kubectl api-resources --namespaced=false

# Expliquer une ressource
kubectl explain pod
kubectl explain pod.spec
kubectl explain pod.spec.containers
```

---

## 12. Formats de Sortie

| Format | Commande | Usage |
|--------|----------|-------|
| **Large** | `-o wide` | Plus de colonnes (IP, Node, etc.) |
| **YAML** | `-o yaml` | Format YAML complet |
| **JSON** | `-o json` | Format JSON complet |
| **Name** | `-o name` | Seulement le nom (type/name) |
| **JSONPath** | `-o jsonpath='...'` | Extraire des champs spécifiques |
| **Custom Columns** | `-o custom-columns=...` | Colonnes personnalisées |
| **Go Template** | `-o go-template='...'` | Template Go |

```bash
# Exemples pratiques
kubectl get pods -o wide
kubectl get pods -o yaml
kubectl get pods -o json | jq '.items[0].metadata.name'
kubectl get pods -o name
kubectl get pods -o jsonpath='{.items[*].metadata.name}'
kubectl get pods -o custom-columns=NAME:.metadata.name,STATUS:.status.phase
```

---

## Ressources Complémentaires

- **Documentation officielle**: https://kubernetes.io/docs/reference/kubectl/
- **Kubectl Cheat Sheet officiel**: https://kubernetes.io/docs/reference/kubectl/cheatsheet/
- **k9s** (TUI pour Kubernetes): https://k9scli.io/
- **Lens** (IDE Kubernetes): https://k8slens.dev/
- **kubectx/kubens**: https://github.com/ahmetb/kubectx

!!! tip "Aller Plus Loin"
    - Installez **k9s** pour une interface TUI interactive
    - Utilisez **kubectx** et **kubens** pour changer rapidement de contexte/namespace
    - Explorez **Helm** pour le packaging d'applications Kubernetes
    - Apprenez **Kustomize** pour la gestion de configurations multiples
