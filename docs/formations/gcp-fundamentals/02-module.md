---
tags:
  - formation
  - gcp
  - compute-engine
  - vm
  - instance-groups
  - autoscaling
---

# Module 2 : Compute Engine - VMs dans le Cloud

## Objectifs du Module

À la fin de ce module, vous serez capable de :

- :fontawesome-solid-server: Créer des VMs avec différents machine types
- :fontawesome-solid-hard-drive: Gérer les disques (Persistent Disks, snapshots)
- :material-file-document: Utiliser startup scripts et metadata
- :fontawesome-solid-copy: Créer des Instance Templates réutilisables
- :material-trending-up: Configurer des Managed Instance Groups avec autoscaling

---

## 1. Concepts Fondamentaux

### Qu'est-ce que Compute Engine ?

Compute Engine est le service **IaaS** (Infrastructure as a Service) de GCP pour les machines virtuelles :

- VMs Linux ou Windows
- Machines customs ou prédéfinies
- Facturation à la seconde (minimum 1 minute)
- SLA 99.99% pour les instances individuelles

### Régions et Zones

```mermaid
graph TD
    subgraph "Europe (EU)"
        subgraph "europe-west1 (Belgium)"
            A[zone-a]
            B[zone-b]
            C[zone-c]
        end
        subgraph "europe-west9 (Paris)"
            D[zone-a]
            E[zone-b]
            F[zone-c]
        end
    end

    style A fill:#4285F4,color:#fff
    style B fill:#34A853,color:#fff
    style C fill:#FBBC04,color:#000
```

| Concept | Description | Exemple |
|---------|-------------|---------|
| **Region** | Zone géographique (data centers proches) | `europe-west1` (Belgique) |
| **Zone** | Data center individuel dans une région | `europe-west1-b` |

!!! tip "Choix de région"
    - **Latence** : Choisir proche des utilisateurs
    - **Prix** : Varie selon les régions (~10-20%)
    - **Services** : Certains services pas disponibles partout
    - **Conformité** : RGPD → préférer régions EU

---

## 2. Machine Types

### Familles de machines

| Famille | Usage | vCPU | Mémoire |
|---------|-------|------|---------|
| **E2** | Usage général, économique | 2-32 | 0.5-128 GB |
| **N2/N2D** | Usage général, balanced | 2-128 | 0.5-864 GB |
| **C2/C2D** | Compute-intensive | 4-112 | 8-896 GB |
| **M2/M3** | Memory-intensive | 12-416 | 340 GB-12 TB |
| **A2** | GPU (ML/AI) | 12-96 | 85-1360 GB |
| **T2D** | Scale-out workloads (AMD) | 1-60 | 1-240 GB |

### Nomenclature

```
e2-standard-4
│    │       │
│    │       └── 4 vCPUs
│    └────────── standard (ratio mémoire/CPU équilibré)
└─────────────── E2 (famille)

Variations:
- standard : 4 GB/vCPU
- highmem  : 8 GB/vCPU
- highcpu  : 0.9 GB/vCPU
```

### Lister les machine types disponibles

```bash
# Tous les types dans une zone
gcloud compute machine-types list --zones=europe-west1-b

# Filtrer par famille
gcloud compute machine-types list --zones=europe-west1-b \
    --filter="name~^e2"

# Détails d'un type
gcloud compute machine-types describe e2-standard-4 \
    --zone=europe-west1-b
```

### Custom Machine Types

```bash
# Machine custom : 6 vCPU, 24 GB RAM
gcloud compute instances create my-custom-vm \
    --custom-cpu=6 \
    --custom-memory=24GB \
    --zone=europe-west1-b
```

---

## 3. Images

### Images publiques

```bash
# Lister les familles d'images
gcloud compute images list --no-standard-images

# Images Debian/Ubuntu
gcloud compute images list --filter="family~debian OR family~ubuntu"

# Images RHEL/Rocky
gcloud compute images list --filter="family~rhel OR family~rocky"

# Images Windows
gcloud compute images list --filter="family~windows"
```

### Images courantes

| OS | Image Family | Project |
|----|--------------|---------|
| Debian 12 | `debian-12` | `debian-cloud` |
| Ubuntu 22.04 LTS | `ubuntu-2204-lts` | `ubuntu-os-cloud` |
| Rocky Linux 9 | `rocky-linux-9` | `rocky-linux-cloud` |
| RHEL 9 | `rhel-9` | `rhel-cloud` |
| Windows Server 2022 | `windows-2022` | `windows-cloud` |

### Images custom

```bash
# Créer une image depuis un disque
gcloud compute images create my-golden-image \
    --source-disk=my-configured-vm \
    --source-disk-zone=europe-west1-b \
    --family=my-app-images \
    --description="Image with app v1.2.3 preinstalled"

# Utiliser l'image
gcloud compute instances create new-vm \
    --image=my-golden-image
```

---

## 4. Créer des Instances

### Via gcloud CLI

```bash
# Instance basique
gcloud compute instances create my-vm \
    --zone=europe-west1-b \
    --machine-type=e2-medium \
    --image-family=debian-12 \
    --image-project=debian-cloud

# Instance avec options
gcloud compute instances create web-server \
    --zone=europe-west1-b \
    --machine-type=e2-standard-2 \
    --image-family=ubuntu-2204-lts \
    --image-project=ubuntu-os-cloud \
    --boot-disk-size=50GB \
    --boot-disk-type=pd-ssd \
    --tags=http-server,https-server \
    --metadata=enable-oslogin=true
```

### Startup Scripts

Les startup scripts s'exécutent au premier démarrage :

```bash
# Script inline
gcloud compute instances create web-server \
    --zone=europe-west1-b \
    --machine-type=e2-small \
    --image-family=debian-12 \
    --image-project=debian-cloud \
    --metadata=startup-script='#!/bin/bash
apt-get update
apt-get install -y nginx
systemctl enable nginx
systemctl start nginx
echo "Hello from $(hostname)" > /var/www/html/index.html'

# Script depuis un fichier
gcloud compute instances create web-server \
    --zone=europe-west1-b \
    --metadata-from-file=startup-script=startup.sh

# Script depuis Cloud Storage
gcloud compute instances create web-server \
    --zone=europe-west1-b \
    --metadata=startup-script-url=gs://my-bucket/startup.sh
```

### Metadata

```bash
# Ajouter des metadata custom
gcloud compute instances create app-server \
    --zone=europe-west1-b \
    --metadata=environment=production,version=1.2.3

# Récupérer metadata depuis la VM
curl -H "Metadata-Flavor: Google" \
    http://metadata.google.internal/computeMetadata/v1/instance/attributes/environment

# Metadata du projet (disponible sur toutes les VMs)
gcloud compute project-info add-metadata \
    --metadata=db-host=10.0.1.5
```

---

## 5. Accès SSH

### Via gcloud (recommandé)

```bash
# SSH simple
gcloud compute ssh my-vm --zone=europe-west1-b

# SSH avec commande
gcloud compute ssh my-vm --zone=europe-west1-b --command="uptime"

# SSH avec tunnel de port
gcloud compute ssh my-vm --zone=europe-west1-b \
    --ssh-flag="-L 8080:localhost:80"

# SCP pour transférer des fichiers
gcloud compute scp ./local-file.txt my-vm:~/remote-file.txt \
    --zone=europe-west1-b
```

### OS Login (best practice)

OS Login utilise les comptes Google pour l'authentification SSH :

```bash
# Activer OS Login au niveau projet
gcloud compute project-info add-metadata \
    --metadata=enable-oslogin=TRUE

# Ou au niveau instance
gcloud compute instances add-metadata my-vm \
    --metadata=enable-oslogin=TRUE \
    --zone=europe-west1-b

# Donner l'accès SSH à un utilisateur
gcloud projects add-iam-policy-binding PROJECT_ID \
    --member="user:alice@example.com" \
    --role="roles/compute.osLogin"

# Pour accès sudo
gcloud projects add-iam-policy-binding PROJECT_ID \
    --member="user:alice@example.com" \
    --role="roles/compute.osAdminLogin"
```

---

## 6. Disques

### Types de disques

| Type | Code | IOPS | Throughput | Usage |
|------|------|------|------------|-------|
| **Standard** | `pd-standard` | 0.75/GB | 12 MB/s | Archives, backups |
| **Balanced** | `pd-balanced` | 6/GB | 28 MB/s | Usage général |
| **SSD** | `pd-ssd` | 30/GB | 48 MB/s | Databases, OLTP |
| **Extreme** | `pd-extreme` | Configurable | 1.2 GB/s | SAP HANA, Oracle |
| **Local SSD** | `local-ssd` | 900K | 9.4 GB/s | Cache, temp data |

!!! warning "Local SSD"
    Les Local SSDs sont **éphémères** : les données sont perdues si la VM s'arrête ou est préemptée.

### Gérer les disques

```bash
# Créer un disque
gcloud compute disks create data-disk \
    --zone=europe-west1-b \
    --size=100GB \
    --type=pd-ssd

# Attacher à une VM (nécessite redémarrage ou attachment à chaud)
gcloud compute instances attach-disk my-vm \
    --disk=data-disk \
    --zone=europe-west1-b

# Détacher
gcloud compute instances detach-disk my-vm \
    --disk=data-disk \
    --zone=europe-west1-b

# Redimensionner (online, sans downtime)
gcloud compute disks resize data-disk \
    --size=200GB \
    --zone=europe-west1-b
```

### Monter un disque dans la VM

```bash
# SSH dans la VM
gcloud compute ssh my-vm --zone=europe-west1-b

# Identifier le disque
lsblk
# sda      8:0    0   10G  0 disk
# └─sda1   8:1    0   10G  0 part /
# sdb      8:16   0  100G  0 disk  <- nouveau disque

# Formater (première utilisation)
sudo mkfs.ext4 -F /dev/sdb

# Monter
sudo mkdir -p /mnt/data
sudo mount /dev/sdb /mnt/data

# Montage permanent (fstab)
echo "UUID=$(sudo blkid -s UUID -o value /dev/sdb) /mnt/data ext4 defaults 0 2" | sudo tee -a /etc/fstab
```

### Snapshots

```bash
# Créer un snapshot
gcloud compute disks snapshot my-vm \
    --zone=europe-west1-b \
    --snapshot-names=my-vm-snapshot-$(date +%Y%m%d)

# Lister les snapshots
gcloud compute snapshots list

# Créer un disque depuis un snapshot
gcloud compute disks create restored-disk \
    --source-snapshot=my-vm-snapshot-20240115 \
    --zone=europe-west1-b

# Snapshot schedule (automatique)
gcloud compute resource-policies create snapshot-schedule daily-backup \
    --region=europe-west1 \
    --max-retention-days=7 \
    --start-time=02:00 \
    --daily-schedule

# Appliquer au disque
gcloud compute disks add-resource-policies my-vm \
    --resource-policies=daily-backup \
    --zone=europe-west1-b
```

---

## 7. Instance Templates

### Créer un template

```bash
# Template basique
gcloud compute instance-templates create web-template \
    --machine-type=e2-small \
    --image-family=debian-12 \
    --image-project=debian-cloud \
    --boot-disk-size=20GB \
    --boot-disk-type=pd-balanced \
    --tags=http-server \
    --metadata=startup-script='#!/bin/bash
apt-get update && apt-get install -y nginx'

# Lister les templates
gcloud compute instance-templates list

# Créer une VM depuis un template
gcloud compute instances create web-1 \
    --source-instance-template=web-template \
    --zone=europe-west1-b
```

### Templates avec Service Account

```bash
gcloud compute instance-templates create app-template \
    --machine-type=e2-medium \
    --image-family=ubuntu-2204-lts \
    --image-project=ubuntu-os-cloud \
    --service-account=my-app-sa@PROJECT_ID.iam.gserviceaccount.com \
    --scopes=cloud-platform \
    --metadata=enable-oslogin=TRUE
```

---

## 8. Managed Instance Groups (MIG)

### Créer un MIG

```bash
# MIG zonal
gcloud compute instance-groups managed create web-mig \
    --template=web-template \
    --size=3 \
    --zone=europe-west1-b

# MIG régional (multi-zone HA)
gcloud compute instance-groups managed create web-mig-regional \
    --template=web-template \
    --size=3 \
    --region=europe-west1 \
    --zones=europe-west1-b,europe-west1-c,europe-west1-d
```

### Health Checks

```bash
# Créer un health check HTTP
gcloud compute health-checks create http web-health-check \
    --port=80 \
    --request-path=/health \
    --check-interval=10s \
    --timeout=5s \
    --healthy-threshold=2 \
    --unhealthy-threshold=3

# Appliquer au MIG
gcloud compute instance-groups managed set-autohealing web-mig \
    --health-check=web-health-check \
    --initial-delay=120 \
    --zone=europe-west1-b
```

### Autoscaling

```bash
# Autoscaling basé sur CPU
gcloud compute instance-groups managed set-autoscaling web-mig \
    --zone=europe-west1-b \
    --min-num-replicas=2 \
    --max-num-replicas=10 \
    --target-cpu-utilization=0.6 \
    --cool-down-period=60

# Autoscaling basé sur Load Balancing
gcloud compute instance-groups managed set-autoscaling web-mig \
    --zone=europe-west1-b \
    --min-num-replicas=2 \
    --max-num-replicas=10 \
    --target-load-balancing-utilization=0.8
```

```mermaid
graph LR
    A[Load Balancer] --> B[MIG]
    B --> C[VM 1]
    B --> D[VM 2]
    B --> E[VM 3]
    B --> F[... VM N]

    G[Health Check] --> C
    G --> D
    G --> E

    H[Autoscaler] --> B
    H -.->|CPU > 60%| I[Scale Up]
    H -.->|CPU < 30%| J[Scale Down]

    style A fill:#4285F4,color:#fff
    style B fill:#34A853,color:#fff
    style H fill:#FBBC04,color:#000
```

### Rolling Updates

```bash
# Créer un nouveau template
gcloud compute instance-templates create web-template-v2 \
    --machine-type=e2-small \
    --image-family=debian-12 \
    --image-project=debian-cloud \
    --metadata=startup-script='#!/bin/bash
apt-get update && apt-get install -y nginx
echo "Version 2.0" > /var/www/html/version.txt'

# Rolling update (mise à jour progressive)
gcloud compute instance-groups managed rolling-action start-update web-mig \
    --version=template=web-template-v2 \
    --zone=europe-west1-b \
    --max-surge=1 \
    --max-unavailable=0

# Vérifier le status
gcloud compute instance-groups managed list-instances web-mig \
    --zone=europe-west1-b
```

---

## 9. Preemptible & Spot VMs

### VMs préemptibles (économies jusqu'à 80%)

```bash
# Créer une VM préemptible
gcloud compute instances create batch-worker \
    --zone=europe-west1-b \
    --machine-type=e2-standard-4 \
    --preemptible \
    --maintenance-policy=TERMINATE \
    --no-restart-on-failure

# Spot VMs (évolution des preemptibles)
gcloud compute instances create spot-worker \
    --zone=europe-west1-b \
    --machine-type=e2-standard-4 \
    --provisioning-model=SPOT \
    --instance-termination-action=STOP
```

!!! warning "Limitations"
    - Durée max : 24h (arrêt automatique)
    - Peut être préempté à tout moment (préavis 30s)
    - Pas de SLA de disponibilité
    - Pas de live migration

**Cas d'usage** : Batch processing, CI/CD runners, rendering, ML training

### Arbre de décision : Choisir le bon type de VM

```mermaid
flowchart TD
    A[Nouvelle VM] --> B{Workload type?}
    B -->|General purpose| C{Budget?}
    C -->|Économique| D[E2]
    C -->|Performance| E[N2/N2D]
    B -->|Compute intensive| F[C2/C2D]
    B -->|Memory intensive| G{Size?}
    G -->|< 1TB RAM| H[N2-highmem]
    G -->|> 1TB RAM| I[M2/M3]
    B -->|ML/AI| J[A2 + GPU]
    B -->|Batch/Interruptible| K{Duration?}
    K -->|< 24h| L[Spot VM<br/>-60-91%]
    K -->|Long running| M[Standard VM]

    style D fill:#34A853,color:#fff
    style L fill:#FBBC04,color:#000
    style J fill:#4285F4,color:#fff
```

### Architecture MIG avec Load Balancer

```mermaid
graph TB
    subgraph "Internet"
        Users((Users))
    end

    subgraph "Global"
        GLB[Global HTTP(S)<br/>Load Balancer]
    end

    subgraph "europe-west1"
        subgraph "MIG EU"
            EU1[VM eu-1]
            EU2[VM eu-2]
            EU3[VM eu-3]
        end
        HC_EU[Health Check]
        AS_EU[Autoscaler<br/>CPU: 60%]
    end

    subgraph "us-central1"
        subgraph "MIG US"
            US1[VM us-1]
            US2[VM us-2]
        end
        HC_US[Health Check]
        AS_US[Autoscaler<br/>CPU: 60%]
    end

    Users --> GLB
    GLB -->|EU users| EU1
    GLB -->|EU users| EU2
    GLB -->|EU users| EU3
    GLB -->|US users| US1
    GLB -->|US users| US2

    HC_EU --> EU1
    HC_EU --> EU2
    HC_EU --> EU3
    HC_US --> US1
    HC_US --> US2

    AS_EU -.-> EU1
    AS_US -.-> US1

    style GLB fill:#4285F4,color:#fff
    style AS_EU fill:#FBBC04,color:#000
    style AS_US fill:#FBBC04,color:#000
```

---

## 10. Exercices Pratiques

### Exercice 1 : Déployer un serveur web

!!! example "Exercice"
    1. Créez une VM `web-server` avec :
        - Machine type : `e2-small`
        - Image : `debian-12`
        - Disque : 20 GB SSD
        - Tag : `http-server`
    2. Utilisez un startup script pour installer nginx
    3. Vérifiez que nginx fonctionne

??? quote "Solution"
    ```bash
    # Créer la VM
    gcloud compute instances create web-server \
        --zone=europe-west1-b \
        --machine-type=e2-small \
        --image-family=debian-12 \
        --image-project=debian-cloud \
        --boot-disk-size=20GB \
        --boot-disk-type=pd-ssd \
        --tags=http-server \
        --metadata=startup-script='#!/bin/bash
    apt-get update
    apt-get install -y nginx
    systemctl enable nginx
    systemctl start nginx
    echo "Hello from $(hostname)" > /var/www/html/index.html'

    # Créer une règle firewall (si pas déjà existante)
    gcloud compute firewall-rules create allow-http \
        --direction=INGRESS \
        --priority=1000 \
        --network=default \
        --action=ALLOW \
        --rules=tcp:80 \
        --target-tags=http-server

    # Obtenir l'IP externe
    gcloud compute instances describe web-server \
        --zone=europe-west1-b \
        --format="get(networkInterfaces[0].accessConfigs[0].natIP)"

    # Tester
    curl http://EXTERNAL_IP
    ```

### Exercice 2 : MIG avec autoscaling

!!! example "Exercice"
    1. Créez un Instance Template `stress-template` basé sur Debian
    2. Créez un MIG `stress-mig` avec 1 instance
    3. Configurez l'autoscaling (min: 1, max: 5, CPU: 50%)
    4. Générez de la charge CPU et observez le scale-up

??? quote "Solution"
    ```bash
    # Template avec stress tool
    gcloud compute instance-templates create stress-template \
        --machine-type=e2-small \
        --image-family=debian-12 \
        --image-project=debian-cloud \
        --metadata=startup-script='#!/bin/bash
    apt-get update && apt-get install -y stress-ng'

    # MIG
    gcloud compute instance-groups managed create stress-mig \
        --template=stress-template \
        --size=1 \
        --zone=europe-west1-b

    # Autoscaling
    gcloud compute instance-groups managed set-autoscaling stress-mig \
        --zone=europe-west1-b \
        --min-num-replicas=1 \
        --max-num-replicas=5 \
        --target-cpu-utilization=0.5 \
        --cool-down-period=60

    # Identifier l'instance et y accéder
    gcloud compute instance-groups managed list-instances stress-mig \
        --zone=europe-west1-b

    # SSH et générer de la charge
    gcloud compute ssh stress-mig-xxxx --zone=europe-west1-b
    stress-ng --cpu 2 --timeout 300s

    # Observer le scale-up (dans un autre terminal)
    watch -n5 "gcloud compute instance-groups managed list-instances stress-mig --zone=europe-west1-b"
    ```

### Exercice 3 : Snapshot et restauration

!!! example "Exercice"
    1. Créez un snapshot du disque de `web-server`
    2. Créez un nouveau disque depuis ce snapshot
    3. Créez une nouvelle VM utilisant ce disque

??? quote "Solution"
    ```bash
    # Créer le snapshot
    gcloud compute disks snapshot web-server \
        --zone=europe-west1-b \
        --snapshot-names=web-server-snap

    # Créer un disque depuis le snapshot
    gcloud compute disks create web-server-restored \
        --source-snapshot=web-server-snap \
        --zone=europe-west1-b

    # Créer une VM avec ce disque
    gcloud compute instances create web-server-clone \
        --zone=europe-west1-b \
        --machine-type=e2-small \
        --disk=name=web-server-restored,boot=yes

    # Vérifier
    gcloud compute ssh web-server-clone --zone=europe-west1-b \
        --command="cat /var/www/html/index.html"
    ```

### Exercice 4 : Blue-Green Deployment avec MIG

!!! example "Exercice"
    Simulez un déploiement Blue-Green :

    1. Créez deux templates : `blue-template` (v1) et `green-template` (v2)
    2. Créez un MIG avec `blue-template`
    3. Effectuez un rolling update vers `green-template`
    4. Vérifiez que le rollback fonctionne

??? quote "Solution"
    ```bash
    # Template Blue (v1)
    gcloud compute instance-templates create blue-template \
        --machine-type=e2-micro \
        --image-family=debian-12 \
        --image-project=debian-cloud \
        --metadata=startup-script='#!/bin/bash
    apt-get update && apt-get install -y nginx
    echo "<h1>Version BLUE (v1)</h1>" > /var/www/html/index.html
    systemctl start nginx'

    # Template Green (v2)
    gcloud compute instance-templates create green-template \
        --machine-type=e2-micro \
        --image-family=debian-12 \
        --image-project=debian-cloud \
        --metadata=startup-script='#!/bin/bash
    apt-get update && apt-get install -y nginx
    echo "<h1>Version GREEN (v2)</h1>" > /var/www/html/index.html
    systemctl start nginx'

    # MIG avec Blue
    gcloud compute instance-groups managed create deploy-mig \
        --template=blue-template \
        --size=3 \
        --zone=europe-west1-b

    # Attendre que les instances soient prêtes
    gcloud compute instance-groups managed wait-until --stable deploy-mig \
        --zone=europe-west1-b

    # Rolling update vers Green (canary: 1 instance d'abord)
    gcloud compute instance-groups managed rolling-action start-update deploy-mig \
        --version=template=green-template \
        --zone=europe-west1-b \
        --max-surge=1 \
        --max-unavailable=0

    # Observer le déploiement
    watch -n2 "gcloud compute instance-groups managed list-instances deploy-mig --zone=europe-west1-b"

    # Rollback si problème
    gcloud compute instance-groups managed rolling-action start-update deploy-mig \
        --version=template=blue-template \
        --zone=europe-west1-b
    ```

### Exercice 5 : Optimisation des coûts

!!! example "Exercice"
    Analysez et optimisez les coûts d'un environnement :

    1. Listez toutes les VMs avec leur type et leur statut
    2. Identifiez les VMs qui pourraient être des Spot VMs
    3. Calculez les économies potentielles
    4. Créez un script de rightsizing

??? quote "Solution"
    ```bash
    # Lister toutes les VMs avec détails
    gcloud compute instances list \
        --format="table(name,zone,machineType.basename(),status,scheduling.preemptible)"

    # Identifier les VMs sous-utilisées (nécessite monitoring)
    # Via Console : Monitoring > Dashboards > VM Instances
    # Chercher CPU < 10% sur 7 jours

    # Script de rightsizing
    cat > rightsizing.sh << 'EOF'
    #!/bin/bash
    # Analyse des recommendations de rightsizing

    PROJECT_ID=$(gcloud config get-value project)

    echo "=== VMs actuelles ==="
    gcloud compute instances list --format="table(name,machineType.basename(),zone)"

    echo ""
    echo "=== Recommendations ==="
    # Via Recommender API
    gcloud recommender recommendations list \
        --project=$PROJECT_ID \
        --location=europe-west1-b \
        --recommender=google.compute.instance.MachineTypeRecommender \
        --format="table(content.overview.resourceName,content.overview.recommendedMachineType.name)"

    echo ""
    echo "=== Économies Spot potentielles ==="
    echo "VMs batch/dev qui pourraient être Spot :"
    gcloud compute instances list \
        --filter="name~batch OR name~dev OR name~test" \
        --format="table(name,machineType.basename())"

    echo ""
    echo "Économie estimée avec Spot : 60-91% sur ces VMs"
    EOF

    chmod +x rightsizing.sh
    ./rightsizing.sh
    ```

---

## 11. Nettoyage

```bash
# Supprimer les ressources créées
gcloud compute instances delete web-server web-server-clone \
    --zone=europe-west1-b --quiet

gcloud compute instance-groups managed delete stress-mig \
    --zone=europe-west1-b --quiet

gcloud compute instance-templates delete web-template stress-template --quiet

gcloud compute disks delete data-disk web-server-restored \
    --zone=europe-west1-b --quiet

gcloud compute snapshots delete web-server-snap --quiet

gcloud compute firewall-rules delete allow-http --quiet
```

---

## Résumé du Module

| Concept | Points clés |
|---------|-------------|
| **Machine Types** | E2 (économique), N2 (balanced), C2 (compute), M2 (memory) |
| **Images** | Publiques (Debian, Ubuntu, RHEL) ou custom |
| **Startup Scripts** | Automatiser la configuration au boot |
| **Disques** | pd-standard, pd-balanced, pd-ssd, local-ssd |
| **Snapshots** | Backup incrémental, restauration rapide |
| **Templates** | Configuration réutilisable pour VMs identiques |
| **MIG** | Autoscaling, health checks, rolling updates |
| **Spot/Preemptible** | -80% de coût, pour workloads interruptibles |

---

**[← Retour au Module 1](01-module.md)** | **[Continuer vers le Module 3 : Networking →](03-module.md)**

---

**Retour au :** [Programme de la Formation](index.md) | [Catalogue des Formations](../index.md)
