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

## 6. Exercice : À Vous de Jouer

!!! example "Mise en Pratique"
    **Objectif** : Résoudre différents problèmes courants dans un cluster Kubernetes et mettre en place une stratégie de backup

    **Contexte** : Vous êtes l'ingénieur DevOps de garde et vous recevez plusieurs alertes concernant une application critique en production. Vous devez identifier et résoudre rapidement les problèmes suivants : un pod qui ne démarre pas, un service inaccessible, des problèmes de réseau, et vous devez également configurer une solution de backup pour éviter les pertes de données.

    **Tâches à réaliser** :

    1. Débugger un pod en état CrashLoopBackOff
    2. Résoudre un problème de Service qui ne route pas le trafic
    3. Diagnostiquer et corriger un problème de résolution DNS
    4. Investiguer un pod bloqué en état Pending
    5. Installer Velero et créer un backup complet
    6. Simuler une perte de données et restaurer depuis le backup

    **Critères de validation** :

    - [ ] Tous les pods sont en état Running et Ready
    - [ ] Les services routent correctement le trafic
    - [ ] La résolution DNS fonctionne
    - [ ] Velero est opérationnel avec des backups planifiés
    - [ ] La restauration depuis backup fonctionne

??? quote "Solution"
    **Préparation : Créer les Scénarios de Problèmes**

    ```bash
    # Créer un namespace de test
    kubectl create namespace troubleshooting
    kubectl config set-context --current --namespace=troubleshooting
    ```

    **Scénario 1 : Pod en CrashLoopBackOff**

    ```yaml
    # broken-app.yaml
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: broken-app
    spec:
      replicas: 1
      selector:
        matchLabels:
          app: broken-app
      template:
        metadata:
          labels:
            app: broken-app
        spec:
          containers:
            - name: app
              image: busybox
              command:
                - /bin/sh
                - -c
                - |
                  echo "Starting application..."
                  echo "Connecting to database at $DB_HOST..."
                  # Simule une erreur car DB_HOST n'existe pas
                  if [ -z "$DB_HOST" ]; then
                    echo "ERROR: DB_HOST not set!"
                    exit 1
                  fi
                  sleep 3600
              env:
                - name: API_KEY
                  valueFrom:
                    secretKeyRef:
                      name: api-credentials
                      key: api-key  # Ce secret n'existe pas!
    ```

    ```bash
    kubectl apply -f broken-app.yaml

    # Observer le problème
    kubectl get pods -w
    # Le pod va crasher en boucle
    ```

    **Résolution du Scénario 1**

    ```bash
    # Étape 1 : Identifier le problème
    kubectl get pods
    # NAME                          READY   STATUS             RESTARTS   AGE
    # broken-app-xxx                0/1     CrashLoopBackOff   5          3m

    # Étape 2 : Voir les événements
    kubectl describe pod -l app=broken-app

    # Rechercher dans les Events:
    # Warning  Failed     pod/broken-app-xxx  Error: secret "api-credentials" not found

    # Étape 3 : Créer le secret manquant
    kubectl create secret generic api-credentials \
      --from-literal=api-key=secret123

    # Étape 4 : Vérifier les logs pour voir s'il y a d'autres problèmes
    kubectl logs -l app=broken-app
    # ERROR: DB_HOST not set!

    # Étape 5 : Corriger le Deployment
    kubectl set env deployment/broken-app DB_HOST=postgres.database.svc.cluster.local

    # Étape 6 : Vérifier que le pod démarre
    kubectl get pods -l app=broken-app -w
    # Le pod devrait maintenant être Running

    # Étape 7 : Vérifier les logs
    kubectl logs -l app=broken-app
    # Starting application...
    # Connecting to database at postgres.database.svc.cluster.local...
    ```

    **Scénario 2 : Service qui ne Route Pas**

    ```yaml
    # web-app.yaml
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: web-app
    spec:
      replicas: 3
      selector:
        matchLabels:
          app: web-app
          version: v1
      template:
        metadata:
          labels:
            app: web-app
            version: v1
        spec:
          containers:
            - name: nginx
              image: nginx:alpine
              ports:
                - containerPort: 80
                  name: http
    ---
    apiVersion: v1
    kind: Service
    metadata:
      name: web-app-svc
    spec:
      selector:
        app: web-app
        version: v2  # ERREUR: Mauvais selector!
      ports:
        - port: 80
          targetPort: 8080  # ERREUR: Mauvais port!
          name: http
      type: ClusterIP
    ```

    ```bash
    kubectl apply -f web-app.yaml

    # Tester le service
    kubectl run test --rm -it --image=curlimages/curl -- curl http://web-app-svc
    # Timeout ou erreur de connexion
    ```

    **Résolution du Scénario 2**

    ```bash
    # Étape 1 : Vérifier les endpoints
    kubectl get endpoints web-app-svc
    # NAME          ENDPOINTS   AGE
    # web-app-svc   <none>      2m

    # Pas d'endpoints = le selector ne matche aucun pod!

    # Étape 2 : Comparer les labels
    kubectl get pods -l app=web-app --show-labels
    # Les pods ont: app=web-app,version=v1

    kubectl get svc web-app-svc -o yaml | grep -A2 selector
    # selector:
    #   app: web-app
    #   version: v2  # Problème ici!

    # Étape 3 : Corriger le selector
    kubectl patch service web-app-svc -p '{"spec":{"selector":{"app":"web-app","version":"v1"}}}'

    # Étape 4 : Vérifier les endpoints
    kubectl get endpoints web-app-svc
    # NAME          ENDPOINTS                          AGE
    # web-app-svc   10.244.0.5:80,10.244.0.6:80,...    3m

    # Étape 5 : Vérifier le port
    kubectl get svc web-app-svc
    # PORT(S)   80:xxxxx/TCP
    # TARGET PORT  8080  # Problème: nginx écoute sur 80, pas 8080!

    # Étape 6 : Corriger le targetPort
    kubectl patch service web-app-svc -p '{"spec":{"ports":[{"port":80,"targetPort":80,"name":"http"}]}}'

    # Étape 7 : Tester à nouveau
    kubectl run test --rm -it --image=curlimages/curl -- curl -v http://web-app-svc
    # HTTP/1.1 200 OK
    # Succès!

    # Étape 8 : Validation complète
    kubectl run debug --rm -it --image=nicolaka/netshoot -- /bin/bash
    # Dans le pod:
    curl http://web-app-svc
    nslookup web-app-svc
    nslookup web-app-svc.troubleshooting.svc.cluster.local
    ```

    **Scénario 3 : Problème DNS**

    ```yaml
    # dns-test.yaml
    apiVersion: v1
    kind: Pod
    metadata:
      name: dns-test
    spec:
      containers:
        - name: test
          image: busybox
          command:
            - sleep
            - "3600"
      dnsPolicy: None  # ERREUR: DNS désactivé!
      dnsConfig:
        nameservers:
          - 1.1.1.1  # Mauvais DNS pour Kubernetes
    ```

    ```bash
    kubectl apply -f dns-test.yaml

    # Tester la résolution DNS
    kubectl exec dns-test -- nslookup kubernetes.default
    # Échec de résolution
    ```

    **Résolution du Scénario 3**

    ```bash
    # Étape 1 : Identifier le problème
    kubectl exec dns-test -- cat /etc/resolv.conf
    # nameserver 1.1.1.1  # Pas le DNS Kubernetes!

    # Étape 2 : Vérifier la config DNS normale
    kubectl run test-normal --rm -it --image=busybox -- cat /etc/resolv.conf
    # nameserver 10.96.0.10  # IP du service kube-dns
    # search troubleshooting.svc.cluster.local svc.cluster.local cluster.local

    # Étape 3 : Corriger le pod
    kubectl delete pod dns-test

    cat <<EOF | kubectl apply -f -
    apiVersion: v1
    kind: Pod
    metadata:
      name: dns-test-fixed
    spec:
      containers:
        - name: test
          image: busybox
          command:
            - sleep
            - "3600"
      # dnsPolicy: ClusterFirst  # Valeur par défaut
    EOF

    # Étape 4 : Vérifier
    kubectl exec dns-test-fixed -- nslookup kubernetes.default
    # Succès!

    kubectl exec dns-test-fixed -- nslookup web-app-svc
    # Résolution correcte

    # Étape 5 : Vérifier CoreDNS
    kubectl get pods -n kube-system -l k8s-app=kube-dns
    kubectl logs -n kube-system -l k8s-app=kube-dns --tail=50
    ```

    **Scénario 4 : Pod Pending**

    ```yaml
    # resource-hungry.yaml
    apiVersion: v1
    kind: Pod
    metadata:
      name: resource-hungry
    spec:
      containers:
        - name: app
          image: nginx
          resources:
            requests:
              memory: "64Gi"  # ERREUR: Trop de mémoire!
              cpu: "32"       # ERREUR: Trop de CPU!
      nodeSelector:
        disktype: ssd  # ERREUR: Ce label n'existe probablement pas!
    ```

    ```bash
    kubectl apply -f resource-hungry.yaml

    # Le pod reste Pending
    kubectl get pods resource-hungry
    ```

    **Résolution du Scénario 4**

    ```bash
    # Étape 1 : Identifier pourquoi le pod est Pending
    kubectl describe pod resource-hungry

    # Events:
    # Warning  FailedScheduling  pod/resource-hungry  0/3 nodes are available:
    # 3 Insufficient memory, 3 Insufficient cpu, 3 node(s) didn't match Pod's node affinity/selector

    # Étape 2 : Vérifier les ressources disponibles
    kubectl describe nodes | grep -A5 "Allocated resources"

    # Étape 3 : Vérifier les node labels
    kubectl get nodes --show-labels | grep disktype
    # Aucun node avec ce label

    # Étape 4 : Corriger le pod
    kubectl delete pod resource-hungry

    cat <<EOF | kubectl apply -f -
    apiVersion: v1
    kind: Pod
    metadata:
      name: resource-hungry-fixed
    spec:
      containers:
        - name: app
          image: nginx
          resources:
            requests:
              memory: "128Mi"  # Raisonnable
              cpu: "100m"      # Raisonnable
            limits:
              memory: "256Mi"
              cpu: "200m"
      # nodeSelector retiré ou corrigé
    EOF

    # Étape 5 : Vérifier
    kubectl get pod resource-hungry-fixed -w
    # Running après quelques secondes
    ```

    **Scénario 5 : Installer Velero**

    ```bash
    # Étape 1 : Installer Velero CLI
    wget https://github.com/vmware-tanzu/velero/releases/download/v1.12.0/velero-v1.12.0-linux-amd64.tar.gz
    tar xvf velero-v1.12.0-linux-amd64.tar.gz
    sudo mv velero-v1.12.0-linux-amd64/velero /usr/local/bin/
    velero version --client-only

    # Étape 2 : Préparer MinIO pour le stockage (simulation AWS S3)
    cat <<EOF | kubectl apply -f -
    apiVersion: v1
    kind: Namespace
    metadata:
      name: minio
    ---
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: minio
      namespace: minio
    spec:
      selector:
        matchLabels:
          app: minio
      template:
        metadata:
          labels:
            app: minio
        spec:
          containers:
            - name: minio
              image: minio/minio:latest
              args:
                - server
                - /data
              env:
                - name: MINIO_ROOT_USER
                  value: "minio"
                - name: MINIO_ROOT_PASSWORD
                  value: "minio123"
              ports:
                - containerPort: 9000
              volumeMounts:
                - name: data
                  mountPath: /data
          volumes:
            - name: data
              emptyDir: {}
    ---
    apiVersion: v1
    kind: Service
    metadata:
      name: minio
      namespace: minio
    spec:
      selector:
        app: minio
      ports:
        - port: 9000
          targetPort: 9000
      type: ClusterIP
    EOF

    # Attendre que MinIO soit prêt
    kubectl wait --for=condition=Ready pod -l app=minio -n minio --timeout=120s

    # Créer le bucket (depuis un pod client)
    kubectl run minio-client --rm -it --image=minio/mc -- /bin/sh
    # Dans le pod:
    mc alias set myminio http://minio.minio.svc.cluster.local:9000 minio minio123
    mc mb myminio/velero
    mc ls myminio
    exit

    # Étape 3 : Créer les credentials Velero
    cat <<EOF > /tmp/credentials-velero
    [default]
    aws_access_key_id = minio
    aws_secret_access_key = minio123
    EOF

    # Étape 4 : Installer Velero
    velero install \
      --provider aws \
      --plugins velero/velero-plugin-for-aws:v1.8.0 \
      --bucket velero \
      --secret-file /tmp/credentials-velero \
      --use-volume-snapshots=false \
      --backup-location-config region=minio,s3ForcePathStyle="true",s3Url=http://minio.minio.svc.cluster.local:9000

    # Étape 5 : Vérifier l'installation
    kubectl get all -n velero
    velero version

    # Vérifier la backup location
    velero backup-location get
    ```

    **Scénario 6 : Backup et Restore**

    ```bash
    # Étape 1 : Créer des données à sauvegarder
    kubectl create namespace production-app

    cat <<EOF | kubectl apply -f -
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: critical-app
      namespace: production-app
    spec:
      replicas: 3
      selector:
        matchLabels:
          app: critical-app
      template:
        metadata:
          labels:
            app: critical-app
        spec:
          containers:
            - name: nginx
              image: nginx:alpine
              volumeMounts:
                - name: data
                  mountPath: /usr/share/nginx/html
          initContainers:
            - name: init-data
              image: busybox
              command:
                - sh
                - -c
                - echo "Critical Production Data - $(date)" > /data/index.html
              volumeMounts:
                - name: data
                  mountPath: /data
          volumes:
            - name: data
              emptyDir: {}
    ---
    apiVersion: v1
    kind: Service
    metadata:
      name: critical-app
      namespace: production-app
    spec:
      selector:
        app: critical-app
      ports:
        - port: 80
      type: ClusterIP
    ---
    apiVersion: v1
    kind: ConfigMap
    metadata:
      name: critical-config
      namespace: production-app
    data:
      database_url: "postgres://prod-db:5432/app"
      feature_flags: "v2_api=true,new_ui=true"
    EOF

    # Vérifier que l'app fonctionne
    kubectl get all -n production-app
    kubectl run test --rm -it --image=curlimages/curl -n production-app -- \
      curl http://critical-app

    # Étape 2 : Créer un backup
    velero backup create production-backup \
      --include-namespaces production-app \
      --wait

    # Vérifier le backup
    velero backup describe production-backup
    velero backup logs production-backup

    # Étape 3 : Créer un backup planifié (quotidien à 2h du matin)
    velero schedule create daily-backup \
      --schedule="0 2 * * *" \
      --include-namespaces production-app

    # Vérifier les schedules
    velero schedule get

    # Étape 4 : Simuler une catastrophe (perte de données)
    kubectl delete namespace production-app --wait=true

    # Vérifier que tout est supprimé
    kubectl get all -n production-app
    # Error from server (NotFound): No resources found

    # Étape 5 : Restaurer depuis le backup
    velero restore create --from-backup production-backup --wait

    # Vérifier la restauration
    velero restore get
    velero restore describe production-backup-20231201120000
    velero restore logs production-backup-20231201120000

    # Étape 6 : Vérifier que tout est restauré
    kubectl get all -n production-app
    kubectl get configmap -n production-app

    # Tester l'application restaurée
    kubectl run test --rm -it --image=curlimages/curl -n production-app -- \
      curl http://critical-app
    # Devrait afficher: Critical Production Data - ...

    # Étape 7 : Backup sélectif par label
    velero backup create app-backup \
      --selector app=critical-app \
      --include-namespaces production-app

    # Étape 8 : Exclure certaines ressources
    velero backup create backup-no-secrets \
      --include-namespaces production-app \
      --exclude-resources secrets
    ```

    **Validation Complète**

    ```bash
    # 1. Vérifier tous les pods
    kubectl get pods --all-namespaces | grep -v Running
    # Ne devrait montrer que les pods Completed

    # 2. Vérifier les services
    kubectl get svc -n troubleshooting
    kubectl get endpoints -n troubleshooting

    # 3. Test de connectivité réseau
    kubectl run nettest --rm -it --image=nicolaka/netshoot -n troubleshooting -- /bin/bash
    # Dans le pod:
    nslookup kubernetes.default
    nslookup web-app-svc.troubleshooting.svc.cluster.local
    curl http://web-app-svc.troubleshooting.svc.cluster.local
    exit

    # 4. Vérifier Velero
    velero backup get
    velero schedule get
    velero backup-location get

    # 5. Vérifier l'application restaurée
    kubectl get all -n production-app

    # 6. Résumé final
    echo "=== État Final du Cluster ==="
    kubectl get pods --all-namespaces | grep -v Running | grep -v Completed
    kubectl get nodes
    kubectl top nodes
    velero backup get
    ```

    **Checklist de Troubleshooting Appliquée**

    ```bash
    # Pour chaque problème résolu :

    # ✓ CrashLoopBackOff
    #   → Vérifié les logs (kubectl logs --previous)
    #   → Vérifié les events (kubectl describe)
    #   → Créé les secrets manquants
    #   → Ajouté les variables d'environnement

    # ✓ Service ne répond pas
    #   → Vérifié les endpoints (kubectl get endpoints)
    #   → Corrigé les selectors
    #   → Corrigé les ports (containerPort vs targetPort)

    # ✓ Problème DNS
    #   → Vérifié /etc/resolv.conf
    #   → Corrigé dnsPolicy
    #   → Vérifié CoreDNS

    # ✓ Pod Pending
    #   → Vérifié les events (FailedScheduling)
    #   → Ajusté les resources requests
    #   → Corrigé les nodeSelector

    # ✓ Backup/Restore
    #   → Installé Velero
    #   → Créé des backups manuels et planifiés
    #   → Testé la restauration

    echo "✓ Tous les problèmes ont été résolus avec succès!"
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

---

## Navigation

| | |
|:---|---:|
| [← Module 10 : GitOps et CI/CD](10-module.md) | [TP Final : Plateforme Production →](12-tp-final.md) |

[Retour au Programme](index.md){ .md-button }
