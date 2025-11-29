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

```
TYPES DE VOLUMES KUBERNETES
═══════════════════════════

ÉPHÉMÈRES                      PERSISTANTS
───────────                    ───────────
emptyDir                       PersistentVolume (PV)
configMap                      PersistentVolumeClaim (PVC)
secret                         CSI Drivers
downwardAPI

SPÉCIFIQUES
───────────
hostPath     │ Chemin sur le node (dev/test uniquement)
nfs          │ Montage NFS
iscsi        │ iSCSI
awsEBS       │ AWS Elastic Block Store
gcePD        │ Google Persistent Disk
azureDisk    │ Azure Disk
```

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

```
PV / PVC ARCHITECTURE
═════════════════════

┌─────────────────────────────────────────────────────────────┐
│                         ADMIN                                │
│                                                              │
│   Crée les PersistentVolumes                                │
│   ┌──────────────────────────────────────────────────────┐  │
│   │                 PersistentVolume                      │  │
│   │                                                       │  │
│   │   capacity: 100Gi                                     │  │
│   │   accessModes: ReadWriteOnce                         │  │
│   │   persistentVolumeReclaimPolicy: Retain              │  │
│   │   storageClassName: fast-ssd                         │  │
│   │   nfs:                                                │  │
│   │     server: nfs-server.local                         │  │
│   │     path: /exports/data                              │  │
│   └──────────────────────────────────────────────────────┘  │
│                            │                                 │
│                            │ Binding                         │
│                            ▼                                 │
│   ┌──────────────────────────────────────────────────────┐  │
│   │              PersistentVolumeClaim                    │  │
│   │                                                       │  │
│   │   resources.requests.storage: 50Gi                   │  │
│   │   accessModes: ReadWriteOnce                         │  │
│   │   storageClassName: fast-ssd                         │  │
│   └──────────────────────────────────────────────────────┘  │
│                            │                                 │
│                            │ Used by                         │
│                            ▼                                 │
│   ┌──────────────────────────────────────────────────────┐  │
│   │                       POD                             │  │
│   │                                                       │  │
│   │   volumes:                                            │  │
│   │     - name: data                                      │  │
│   │       persistentVolumeClaim:                          │  │
│   │         claimName: my-pvc                             │  │
│   └──────────────────────────────────────────────────────┘  │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

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

## 5. Exercice Pratique

### Tâches

1. Créer une StorageClass
2. Créer un PVC utilisant cette StorageClass
3. Déployer un StatefulSet avec stockage persistant
4. Vérifier la persistance des données

### Solution

```yaml
# StorageClass + PVC + StatefulSet
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: local-storage
provisioner: kubernetes.io/no-provisioner
volumeBindingMode: WaitForFirstConsumer

---
apiVersion: v1
kind: PersistentVolume
metadata:
  name: local-pv
spec:
  capacity:
    storage: 10Gi
  accessModes:
    - ReadWriteOnce
  storageClassName: local-storage
  hostPath:
    path: /mnt/data

---
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
          env:
            - name: MYSQL_ROOT_PASSWORD
              value: password
          volumeMounts:
            - name: data
              mountPath: /var/lib/mysql
  volumeClaimTemplates:
    - metadata:
        name: data
      spec:
        accessModes: ["ReadWriteOnce"]
        storageClassName: local-storage
        resources:
          requests:
            storage: 5Gi
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
