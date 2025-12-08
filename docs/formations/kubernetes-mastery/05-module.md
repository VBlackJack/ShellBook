---
tags:
  - formation
  - kubernetes
  - storage
  - persistentvolume
  - pvc
---

# Module 5 : Stockage

## Objectifs du Module

- Comprendre les types de volumes Kubernetes
- Configurer PersistentVolumes et PersistentVolumeClaims
- Implémenter le Dynamic Provisioning
- Utiliser les StorageClasses

**Durée :** 3 heures

---

## 1. Types de Volumes

### 1.1 Vue d'Ensemble

![Types de Volumes Kubernetes](../../assets/diagrams/k8s-volume-types.jpeg)

### 1.2 emptyDir

```yaml
# emptyDir - Volume éphémère partagé entre containers
apiVersion: v1
kind: Pod
metadata:
  name: shared-volume
spec:
  containers:
    - name: writer
      image: busybox
      command: ['sh', '-c', 'echo "Hello" > /data/message && sleep 3600']
      volumeMounts:
        - name: shared-data
          mountPath: /data

    - name: reader
      image: busybox
      command: ['sh', '-c', 'cat /data/message && sleep 3600']
      volumeMounts:
        - name: shared-data
          mountPath: /data

  volumes:
    - name: shared-data
      emptyDir: {}
      # Options
      # emptyDir:
      #   medium: Memory  # tmpfs en RAM
      #   sizeLimit: 100Mi
```

### 1.3 hostPath

```yaml
# hostPath - Attention: non recommandé en production
apiVersion: v1
kind: Pod
metadata:
  name: hostpath-pod
spec:
  containers:
    - name: app
      image: nginx
      volumeMounts:
        - name: host-logs
          mountPath: /var/log/nginx
  volumes:
    - name: host-logs
      hostPath:
        path: /var/log/nginx
        type: DirectoryOrCreate
        # Types: Directory, DirectoryOrCreate, File, FileOrCreate, Socket, CharDevice, BlockDevice
```

---

## 2. PersistentVolumes et PersistentVolumeClaims

### 2.1 Architecture

![Architecture PV/PVC Kubernetes](../../assets/diagrams/k8s-pv-pvc-architecture.jpeg)

### 2.2 PersistentVolume

```yaml
# pv.yaml
apiVersion: v1
kind: PersistentVolume
metadata:
  name: pv-nfs-data
  labels:
    type: nfs
spec:
  capacity:
    storage: 100Gi
  volumeMode: Filesystem  # ou Block
  accessModes:
    - ReadWriteMany  # RWX - plusieurs pods en lecture/écriture
    # - ReadWriteOnce  # RWO - un seul node
    # - ReadOnlyMany   # ROX - plusieurs pods en lecture seule
    # - ReadWriteOncePod  # RWOP - un seul pod (K8s 1.22+)
  persistentVolumeReclaimPolicy: Retain
    # Retain  - Conservation après suppression du PVC
    # Delete  - Suppression automatique
    # Recycle - Deprecated
  storageClassName: nfs-storage
  mountOptions:
    - hard
    - nfsvers=4.1
  nfs:
    server: nfs-server.example.com
    path: /exports/data

---
# PV avec hostPath (dev/test)
apiVersion: v1
kind: PersistentVolume
metadata:
  name: pv-local
spec:
  capacity:
    storage: 10Gi
  accessModes:
    - ReadWriteOnce
  persistentVolumeReclaimPolicy: Delete
  storageClassName: local-storage
  hostPath:
    path: /mnt/data
```

### 2.3 PersistentVolumeClaim

```yaml
# pvc.yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: data-pvc
spec:
  accessModes:
    - ReadWriteOnce
  storageClassName: nfs-storage
  resources:
    requests:
      storage: 50Gi
  selector:  # Optionnel: sélectionner un PV spécifique
    matchLabels:
      type: nfs
```

### 2.4 Utilisation dans un Pod

```yaml
# pod-with-pvc.yaml
apiVersion: v1
kind: Pod
metadata:
  name: app-with-storage
spec:
  containers:
    - name: app
      image: nginx
      volumeMounts:
        - name: data-volume
          mountPath: /usr/share/nginx/html
  volumes:
    - name: data-volume
      persistentVolumeClaim:
        claimName: data-pvc
```

---

## 3. StorageClasses et Dynamic Provisioning

### 3.1 Concept

```
DYNAMIC PROVISIONING
════════════════════

Sans Dynamic Provisioning:
  Admin crée PV → User crée PVC → Binding manuel

Avec Dynamic Provisioning:
  User crée PVC avec StorageClass → PV créé automatiquement

┌─────────────────────────────────────────────────────────────┐
│                     StorageClass                             │
│                                                              │
│   provisioner: kubernetes.io/aws-ebs                        │
│   parameters:                                                │
│     type: gp3                                                │
│     iopsPerGB: "10"                                         │
│                                                              │
└───────────────────────────┬─────────────────────────────────┘
                            │
                            │ PVC demande cette StorageClass
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                         PVC                                  │
│   storageClassName: aws-gp3                                 │
│   storage: 100Gi                                            │
└───────────────────────────┬─────────────────────────────────┘
                            │
                            │ Provisioner crée automatiquement
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                          PV                                  │
│   (Créé automatiquement par le provisioner)                 │
│   AWS EBS Volume gp3 de 100Gi                               │
└─────────────────────────────────────────────────────────────┘
```

### 3.2 StorageClass

```yaml
# storageclass.yaml
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: fast-ssd
  annotations:
    storageclass.kubernetes.io/is-default-class: "true"
provisioner: kubernetes.io/aws-ebs  # ou csi driver
parameters:
  type: gp3
  iopsPerGB: "50"
  encrypted: "true"
reclaimPolicy: Delete
allowVolumeExpansion: true
volumeBindingMode: WaitForFirstConsumer
  # Immediate - bind dès la création du PVC
  # WaitForFirstConsumer - bind quand un pod utilise le PVC

---
# StorageClass pour NFS (avec provisioner externe)
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: nfs-client
provisioner: nfs-subdir-external-provisioner
parameters:
  archiveOnDelete: "false"
  pathPattern: "${.PVC.namespace}-${.PVC.name}"
```

### 3.3 PVC avec StorageClass

```yaml
# pvc-dynamic.yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: dynamic-pvc
spec:
  accessModes:
    - ReadWriteOnce
  storageClassName: fast-ssd  # Référence la StorageClass
  resources:
    requests:
      storage: 100Gi
```

---

## 4. CSI Drivers

### 4.1 Architecture CSI

```
CSI - Container Storage Interface
═════════════════════════════════

┌─────────────────────────────────────────────────────────────┐
│                      KUBERNETES                              │
│                                                              │
│   ┌──────────────────┐  ┌──────────────────┐               │
│   │ CSI Controller   │  │ CSI Node Plugin  │               │
│   │ (Deployment)     │  │ (DaemonSet)      │               │
│   └────────┬─────────┘  └────────┬─────────┘               │
│            │                     │                          │
│            │    gRPC calls       │                          │
│            └──────────┬──────────┘                          │
│                       │                                     │
│                       ▼                                     │
│   ┌─────────────────────────────────────────────────────┐  │
│   │                  CSI Driver                          │  │
│   │                                                      │  │
│   │   aws-ebs-csi-driver                                │  │
│   │   gcp-pd-csi-driver                                 │  │
│   │   azure-disk-csi-driver                             │  │
│   │   csi-driver-nfs                                    │  │
│   │   longhorn                                          │  │
│   │   rook-ceph                                         │  │
│   │                                                      │  │
│   └─────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### 4.2 Installation AWS EBS CSI Driver

```bash
# Installation avec Helm
helm repo add aws-ebs-csi-driver https://kubernetes-sigs.github.io/aws-ebs-csi-driver
helm install aws-ebs-csi-driver aws-ebs-csi-driver/aws-ebs-csi-driver \
  --namespace kube-system \
  --set controller.serviceAccount.create=true \
  --set controller.serviceAccount.name=ebs-csi-controller-sa

# StorageClass pour EBS
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: ebs-sc
provisioner: ebs.csi.aws.com
volumeBindingMode: WaitForFirstConsumer
parameters:
  type: gp3
  encrypted: "true"
```

---

## Exercice : À Vous de Jouer

!!! example "Mise en Pratique"
    **Objectif** : Configurer un stockage persistant pour une base de données MySQL

    **Contexte** : Vous devez déployer une base de données MySQL dans Kubernetes avec un stockage persistant. Les données doivent survivre aux redémarrages des pods et être stockées de manière fiable.

    **Tâches à réaliser** :

    1. Créer une StorageClass pour le provisionnement de volumes
    2. Créer un PersistentVolume (PV) de 10Gi
    3. Déployer un StatefulSet MySQL qui utilise un PVC automatique
    4. Insérer des données dans MySQL et vérifier leur persistance
    5. Supprimer le pod et vérifier que les données sont toujours présentes

    **Critères de validation** :

    - [ ] La StorageClass est créée et disponible
    - [ ] Le PV est créé avec la capacité demandée
    - [ ] Le StatefulSet crée automatiquement un PVC
    - [ ] Les données survivent à la suppression du pod
    - [ ] Le PVC reste en status "Bound"

??? quote "Solution"
    **Étape 1 : Créer la StorageClass et le PV**

    ```yaml
    # storage.yaml
    apiVersion: storage.k8s.io/v1
    kind: StorageClass
    metadata:
      name: local-storage
    provisioner: kubernetes.io/no-provisioner
    volumeBindingMode: WaitForFirstConsumer
    reclaimPolicy: Retain

    ---
    apiVersion: v1
    kind: PersistentVolume
    metadata:
      name: mysql-pv
    spec:
      capacity:
        storage: 10Gi
      accessModes:
        - ReadWriteOnce
      persistentVolumeReclaimPolicy: Retain
      storageClassName: local-storage
      hostPath:
        path: /mnt/data/mysql
        type: DirectoryOrCreate
    ```

    ```bash
    kubectl apply -f storage.yaml
    kubectl get storageclass
    kubectl get pv
    ```

    **Étape 2 : Créer le Service Headless pour MySQL**

    ```yaml
    # mysql-service.yaml
    apiVersion: v1
    kind: Service
    metadata:
      name: mysql
      labels:
        app: mysql
    spec:
      clusterIP: None
      selector:
        app: mysql
      ports:
        - name: mysql
          port: 3306
    ```

    ```bash
    kubectl apply -f mysql-service.yaml
    ```

    **Étape 3 : Déployer le StatefulSet MySQL**

    ```yaml
    # mysql-statefulset.yaml
    apiVersion: apps/v1
    kind: StatefulSet
    metadata:
      name: mysql
    spec:
      serviceName: mysql
      replicas: 1
      selector:
        matchLabels:
          app: mysql
      template:
        metadata:
          labels:
            app: mysql
        spec:
          containers:
            - name: mysql
              image: mysql:8.0
              ports:
                - containerPort: 3306
                  name: mysql
              env:
                - name: MYSQL_ROOT_PASSWORD
                  value: "rootpassword"
                - name: MYSQL_DATABASE
                  value: "testdb"
              volumeMounts:
                - name: data
                  mountPath: /var/lib/mysql
              resources:
                requests:
                  cpu: 250m
                  memory: 512Mi
                limits:
                  cpu: 1
                  memory: 1Gi
              livenessProbe:
                exec:
                  command:
                    - mysqladmin
                    - ping
                    - -h
                    - localhost
                initialDelaySeconds: 30
                periodSeconds: 10
              readinessProbe:
                exec:
                  command:
                    - mysql
                    - -h
                    - localhost
                    - -e
                    - "SELECT 1"
                initialDelaySeconds: 10
                periodSeconds: 5
      volumeClaimTemplates:
        - metadata:
            name: data
          spec:
            accessModes:
              - ReadWriteOnce
            storageClassName: local-storage
            resources:
              requests:
                storage: 5Gi
    ```

    ```bash
    kubectl apply -f mysql-statefulset.yaml

    # Attendre que le pod soit prêt
    kubectl wait --for=condition=Ready pod/mysql-0 --timeout=120s

    # Vérifier le PVC créé automatiquement
    kubectl get pvc
    kubectl get pv
    ```

    **Étape 4 : Insérer des données**

    ```bash
    # Accéder au pod MySQL
    kubectl exec -it mysql-0 -- mysql -uroot -prootpassword testdb

    # Dans MySQL, exécuter :
    # CREATE TABLE users (id INT PRIMARY KEY, name VARCHAR(50));
    # INSERT INTO users VALUES (1, 'Alice'), (2, 'Bob');
    # SELECT * FROM users;
    # EXIT;

    # Ou via une seule commande
    kubectl exec -it mysql-0 -- mysql -uroot -prootpassword testdb -e "
    CREATE TABLE IF NOT EXISTS users (id INT PRIMARY KEY, name VARCHAR(50));
    INSERT INTO users VALUES (1, 'Alice'), (2, 'Bob');
    SELECT * FROM users;
    "
    ```

    **Étape 5 : Tester la persistance**

    ```bash
    # Supprimer le pod (pas le StatefulSet!)
    kubectl delete pod mysql-0

    # Le StatefulSet va recréer le pod automatiquement
    kubectl wait --for=condition=Ready pod/mysql-0 --timeout=120s

    # Vérifier que les données sont toujours présentes
    kubectl exec -it mysql-0 -- mysql -uroot -prootpassword testdb -e "SELECT * FROM users;"

    # Les données devraient être intactes !
    ```

    **Étape 6 : Vérifications supplémentaires**

    ```bash
    # Vérifier le StatefulSet
    kubectl describe statefulset mysql

    # Vérifier le PVC
    kubectl get pvc data-mysql-0 -o yaml

    # Vérifier le binding PV <-> PVC
    kubectl get pv mysql-pv -o yaml | grep -A5 claimRef

    # Voir les événements
    kubectl get events --sort-by='.lastTimestamp' | grep mysql
    ```

    **Test avancé : Scaling**

    ```bash
    # Scaler à 2 replicas (chaque pod aura son propre PVC)
    kubectl scale statefulset mysql --replicas=2

    # Observer la création du deuxième PVC
    kubectl get pvc -w

    # Note: Vous auriez besoin d'un deuxième PV pour que le deuxième pod démarre
    ```

    **Nettoyage** :

    ```bash
    # Supprimer le StatefulSet
    kubectl delete statefulset mysql

    # Les PVC ne sont PAS supprimés automatiquement (protection des données)
    kubectl get pvc

    # Supprimer manuellement si nécessaire
    kubectl delete pvc data-mysql-0

    # Supprimer le PV
    kubectl delete pv mysql-pv

    # Supprimer la StorageClass
    kubectl delete storageclass local-storage
    ```

---

## Quiz

1. **Quel accessMode permet plusieurs pods en écriture ?**
   - [ ] A. ReadWriteOnce
   - [ ] B. ReadWriteMany
   - [ ] C. ReadOnlyMany

2. **Que fait le reclaimPolicy "Retain" ?**
   - [ ] A. Supprime le PV
   - [ ] B. Conserve le PV après suppression du PVC
   - [ ] C. Recycle le volume

3. **Qu'est-ce que le Dynamic Provisioning ?**
   - [ ] A. Création manuelle de PV
   - [ ] B. Création automatique de PV via StorageClass
   - [ ] C. Augmentation automatique de la taille

**Réponses :** 1-B, 2-B, 3-B

---

**Précédent :** [Module 4 - Networking](04-module.md)

**Suivant :** [Module 6 - Sécurité](06-module.md)

---

## Navigation

| | |
|:---|---:|
| [← Module 4 : Networking](04-module.md) | [Module 6 : Sécurité et RBAC →](06-module.md) |

[Retour au Programme](index.md){ .md-button }
