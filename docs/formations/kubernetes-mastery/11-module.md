---
tags:
  - formation
  - kubernetes
  - troubleshooting
  - debugging
  - operations
---

# Module 11 : Opérations et Troubleshooting

## Objectifs du Module

- Maîtriser kubectl avancé
- Debugger efficacement les pods
- Analyser les logs et événements
- Sauvegarder et restaurer avec Velero

**Durée :** 2 heures

---

## 1. kubectl Avancé

### 1.1 Commandes Essentielles

```bash
# Informations rapides
kubectl get pods -o wide
kubectl get pods -o yaml
kubectl get pods -o json | jq '.items[].metadata.name'

# Champs personnalisés
kubectl get pods -o custom-columns=NAME:.metadata.name,STATUS:.status.phase,NODE:.spec.nodeName

# Tri et filtrage
kubectl get pods --sort-by=.metadata.creationTimestamp
kubectl get pods --field-selector=status.phase=Running
kubectl get pods -l app=nginx,env=prod

# Tous les namespaces
kubectl get pods -A
kubectl get all -A

# Watch
kubectl get pods -w
```

### 1.2 JSONPath et JQ

```bash
# JSONPath
kubectl get pods -o jsonpath='{.items[*].metadata.name}'
kubectl get pods -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.status.phase}{"\n"}{end}'

# Extraire une valeur
kubectl get secret my-secret -o jsonpath='{.data.password}' | base64 -d

# Avec jq
kubectl get pods -o json | jq '.items[] | {name: .metadata.name, status: .status.phase}'
```

### 1.3 Contextes et Config

```bash
# Voir le contexte actuel
kubectl config current-context

# Lister les contextes
kubectl config get-contexts

# Changer de contexte
kubectl config use-context production

# Définir le namespace par défaut
kubectl config set-context --current --namespace=production

# Voir la config complète
kubectl config view
```

---

## 2. Debugging des Pods

### 2.1 États des Pods

```
ÉTATS DES PODS
══════════════

Pending       │ Pod accepté mais pas encore schedulé
              │ → Vérifier: resources, nodeSelector, taints

Running       │ Au moins un container en cours d'exécution

Succeeded     │ Tous les containers terminés avec succès (Jobs)

Failed        │ Au moins un container terminé en erreur

Unknown       │ État du pod indéterminé (problème de communication node)


RAISONS COURANTES DE PENDING
────────────────────────────
Insufficient cpu/memory
No nodes match nodeSelector
Node had taint that pod didn't tolerate
PersistentVolumeClaim not bound


RAISONS COURANTES DE CRASHLOOPBACKOFF
─────────────────────────────────────
Application crash au démarrage
Configuration invalide
Dépendances non disponibles
Probe échouée
```

### 2.2 Commandes de Debug

```bash
# Describe - informations détaillées
kubectl describe pod <pod-name>

# Événements récents
kubectl get events --sort-by=.metadata.creationTimestamp
kubectl get events --field-selector involvedObject.name=<pod-name>

# Logs
kubectl logs <pod-name>
kubectl logs <pod-name> -c <container>
kubectl logs <pod-name> --previous
kubectl logs <pod-name> --tail=100
kubectl logs <pod-name> --since=1h

# Logs de tous les pods d'un deployment
kubectl logs -l app=nginx --all-containers

# Exec dans un container
kubectl exec -it <pod-name> -- /bin/sh
kubectl exec -it <pod-name> -c <container> -- /bin/sh

# Copier des fichiers
kubectl cp <pod-name>:/path/to/file ./local-file
kubectl cp ./local-file <pod-name>:/path/to/file
```

### 2.3 Debug avec Ephemeral Containers

```bash
# Ajouter un container debug à un pod en cours
kubectl debug -it <pod-name> --image=busybox --target=<container>

# Créer une copie du pod avec un shell
kubectl debug <pod-name> -it --copy-to=debug-pod --container=debug --image=busybox

# Debug un node
kubectl debug node/<node-name> -it --image=ubuntu
```

### 2.4 Diagnostic Réseau

```bash
# Pod de test réseau
kubectl run nettest --rm -it --image=nicolaka/netshoot -- /bin/bash

# Dans le pod:
# DNS
nslookup kubernetes.default
nslookup <service-name>.<namespace>.svc.cluster.local

# Connectivité
ping <pod-ip>
curl http://<service-name>:<port>
nc -zv <host> <port>

# Trace
traceroute <host>

# Vérifier les endpoints
kubectl get endpoints <service-name>
```

---

## 3. Analyse des Événements et Logs

### 3.1 Événements Kubernetes

```bash
# Tous les événements
kubectl get events -A --sort-by=.lastTimestamp

# Événements d'un namespace
kubectl get events -n production

# Filtrer par type
kubectl get events --field-selector type=Warning

# Événements d'une ressource
kubectl get events --field-selector involvedObject.kind=Pod,involvedObject.name=myapp-xxx
```

### 3.2 Logs Centralisés

```bash
# Stern - logs multi-pods
# Installation: https://github.com/stern/stern
stern app-name
stern -n production "api-.*"
stern --all-namespaces ".*"

# Avec labels
stern -l app=nginx

# Avec timestamp
stern myapp --timestamps

# k9s - UI terminal
# Installation: https://k9scli.io/
k9s
```

### 3.3 Audit Logs

```yaml
# Configurer l'audit logging (kube-apiserver)
# /etc/kubernetes/audit-policy.yaml
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  - level: Metadata
    resources:
      - group: ""
        resources: ["secrets", "configmaps"]
  - level: RequestResponse
    resources:
      - group: ""
        resources: ["pods"]
    verbs: ["create", "delete"]
```

---

## 4. Backup et Restore avec Velero

### 4.1 Installation

```bash
# Installer Velero CLI
wget https://github.com/vmware-tanzu/velero/releases/download/v1.12.0/velero-v1.12.0-linux-amd64.tar.gz
tar xvf velero-v1.12.0-linux-amd64.tar.gz
sudo mv velero-v1.12.0-linux-amd64/velero /usr/local/bin/

# Installer sur le cluster (exemple AWS S3)
velero install \
  --provider aws \
  --plugins velero/velero-plugin-for-aws:v1.8.0 \
  --bucket velero-backups \
  --backup-location-config region=eu-west-1 \
  --snapshot-location-config region=eu-west-1 \
  --secret-file ./credentials-velero

# Vérifier
kubectl get all -n velero
velero backup-location get
```

### 4.2 Backup

```bash
# Backup complet du cluster
velero backup create full-backup

# Backup d'un namespace
velero backup create ns-backup --include-namespaces production

# Backup avec labels
velero backup create app-backup --selector app=myapp

# Backup excluant des ressources
velero backup create backup --exclude-resources secrets

# Backup planifié
velero schedule create daily-backup --schedule="0 2 * * *"

# Vérifier les backups
velero backup get
velero backup describe <backup-name>
velero backup logs <backup-name>
```

### 4.3 Restore

```bash
# Restore complet
velero restore create --from-backup full-backup

# Restore d'un namespace spécifique
velero restore create --from-backup full-backup --include-namespaces production

# Restore vers un autre namespace
velero restore create --from-backup ns-backup --namespace-mappings production:production-restore

# Vérifier
velero restore get
velero restore describe <restore-name>
```

---

## 5. Checklist Troubleshooting

```
CHECKLIST TROUBLESHOOTING
═════════════════════════

POD NE DÉMARRE PAS
──────────────────
□ kubectl describe pod <pod>  → Events
□ kubectl get events
□ Vérifier les resources (CPU/Memory)
□ Vérifier les nodeSelector/affinity
□ Vérifier les PVC (Pending?)
□ Vérifier les images (ImagePullBackOff?)
□ Vérifier les secrets/configmaps

POD CRASHE
──────────
□ kubectl logs <pod> --previous
□ kubectl describe pod <pod>
□ Vérifier les probes
□ kubectl exec pour investiguer
□ Vérifier la config (env, volumes)

SERVICE NE RÉPOND PAS
─────────────────────
□ kubectl get endpoints <svc>
□ Vérifier les labels selector
□ Test depuis un pod: curl <svc>:<port>
□ Vérifier les ports (targetPort)
□ kubectl describe svc <svc>

RÉSEAU
──────
□ kubectl run test --rm -it --image=busybox
□ nslookup <service>
□ Vérifier NetworkPolicies
□ Vérifier CNI pods (kube-system)
```

---

## 6. Exercice Pratique

### Tâches

1. Débugger un pod en CrashLoopBackOff
2. Investiguer un service qui ne répond pas
3. Créer un backup Velero
4. Restaurer un namespace

### Scénarios

```bash
# Créer un pod problématique
kubectl run broken --image=nginx --command -- /bin/sh -c "exit 1"

# Investiguer
kubectl describe pod broken
kubectl logs broken --previous

# Créer un service mal configuré
kubectl expose deployment nginx --port=8080  # Mauvais port
kubectl get endpoints nginx  # Vide?
```

---

## Quiz

1. **Quelle commande pour voir les logs d'un container précédent ?**
   - [ ] A. kubectl logs --previous
   - [ ] B. kubectl logs --old
   - [ ] C. kubectl logs --crashed

2. **Quel outil pour les backups Kubernetes ?**
   - [ ] A. etcdctl
   - [ ] B. Velero
   - [ ] C. kubectl backup

**Réponses :** 1-A, 2-B

---

**Précédent :** [Module 10 - GitOps](10-module.md)

**Suivant :** [TP Final](12-tp-final.md)
