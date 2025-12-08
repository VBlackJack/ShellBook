---
tags:
  - formation
  - aws
  - s3
  - rds
  - storage
  - cloud
---

# Module 4 : Storage & Databases

## Objectifs du Module

À la fin de ce module, vous serez capable de :

- :fontawesome-solid-bucket: Créer et gérer des buckets S3 avec politiques de sécurité
- :fontawesome-solid-hard-drive: Configurer les différents types de stockage EBS
- :fontawesome-solid-database: Déployer des bases de données RDS et Aurora
- :fontawesome-solid-clock-rotate-left: Implémenter des stratégies de backup et lifecycle
- :fontawesome-solid-shield-halved: Sécuriser les données avec encryption et IAM

## Prérequis

- Module 3 complété (VPC)
- Compréhension des concepts de stockage
- Notions de bases de données relationnelles

---

## 1. Amazon S3 - Object Storage

### 1.1 Concepts Fondamentaux

```mermaid
graph TB
    subgraph "S3 Structure"
        BUCKET["🪣 Bucket<br/>my-app-bucket"]

        subgraph "Objects"
            OBJ1["📄 index.html"]
            OBJ2["📁 images/logo.png"]
            OBJ3["📁 data/report.csv"]
        end

        BUCKET --> OBJ1
        BUCKET --> OBJ2
        BUCKET --> OBJ3
    end

    subgraph "Storage Classes"
        STD["Standard<br/>Frequently accessed"]
        IA["Standard-IA<br/>Infrequent access"]
        GLA["Glacier<br/>Archive"]
        DEEP["Glacier Deep<br/>Long-term archive"]
    end

    OBJ1 --> STD
    OBJ2 --> IA
    OBJ3 --> GLA

    style BUCKET fill:#569a31,color:#fff
    style STD fill:#ff9900,color:#000
```

### 1.2 Classes de Stockage

| Classe | Use Case | Durabilité | Disponibilité | Prix (GB/mois) |
|--------|----------|------------|---------------|----------------|
| **Standard** | Données fréquemment accédées | 99.999999999% | 99.99% | $0.023 |
| **Standard-IA** | Données moins fréquentes | 99.999999999% | 99.9% | $0.0125 |
| **One Zone-IA** | Données recréables | 99.999999999% | 99.5% | $0.01 |
| **Glacier Instant** | Archive accès immédiat | 99.999999999% | 99.9% | $0.004 |
| **Glacier Flexible** | Archive 1-12h retrieval | 99.999999999% | 99.99% | $0.0036 |
| **Glacier Deep** | Archive 12-48h retrieval | 99.999999999% | 99.99% | $0.00099 |

### 1.3 Créer et Gérer des Buckets

```bash
# Créer un bucket (nom globalement unique)
aws s3 mb s3://my-company-app-prod-$(date +%s) --region eu-west-1

# Ou via l'API
aws s3api create-bucket \
    --bucket my-company-app-prod-123456 \
    --region eu-west-1 \
    --create-bucket-configuration LocationConstraint=eu-west-1

# Activer le versioning
aws s3api put-bucket-versioning \
    --bucket my-company-app-prod-123456 \
    --versioning-configuration Status=Enabled

# Bloquer l'accès public (best practice)
aws s3api put-public-access-block \
    --bucket my-company-app-prod-123456 \
    --public-access-block-configuration '{
        "BlockPublicAcls": true,
        "IgnorePublicAcls": true,
        "BlockPublicPolicy": true,
        "RestrictPublicBuckets": true
    }'

# Lister les buckets
aws s3 ls

# Lister le contenu d'un bucket
aws s3 ls s3://my-company-app-prod-123456/ --recursive --human-readable
```

### 1.4 Upload et Download

```bash
# Upload un fichier
aws s3 cp local-file.txt s3://my-bucket/path/file.txt

# Upload avec storage class
aws s3 cp large-archive.zip s3://my-bucket/archives/ --storage-class GLACIER

# Upload un répertoire entier
aws s3 sync ./local-folder/ s3://my-bucket/folder/ --exclude "*.tmp"

# Download
aws s3 cp s3://my-bucket/file.txt ./local-file.txt

# Sync bidirectionnel
aws s3 sync s3://my-bucket/folder/ ./local-folder/ --delete

# Copie entre buckets
aws s3 sync s3://source-bucket/ s3://dest-bucket/ --source-region eu-west-1 --region us-east-1

# Presigned URL (accès temporaire)
aws s3 presign s3://my-bucket/private-file.pdf --expires-in 3600
```

### 1.5 Bucket Policies

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowCloudFrontAccess",
            "Effect": "Allow",
            "Principal": {
                "Service": "cloudfront.amazonaws.com"
            },
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::my-bucket/*",
            "Condition": {
                "StringEquals": {
                    "AWS:SourceArn": "arn:aws:cloudfront::123456789012:distribution/EXAMPLE"
                }
            }
        },
        {
            "Sid": "DenyUnencryptedUploads",
            "Effect": "Deny",
            "Principal": "*",
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::my-bucket/*",
            "Condition": {
                "StringNotEquals": {
                    "s3:x-amz-server-side-encryption": "aws:kms"
                }
            }
        },
        {
            "Sid": "EnforceTLS",
            "Effect": "Deny",
            "Principal": "*",
            "Action": "s3:*",
            "Resource": [
                "arn:aws:s3:::my-bucket",
                "arn:aws:s3:::my-bucket/*"
            ],
            "Condition": {
                "Bool": {
                    "aws:SecureTransport": "false"
                }
            }
        }
    ]
}
```

```bash
# Appliquer la policy
aws s3api put-bucket-policy \
    --bucket my-bucket \
    --policy file://bucket-policy.json
```

### 1.6 Lifecycle Policies

```bash
# Créer une lifecycle policy
cat > lifecycle.json << 'EOF'
{
    "Rules": [
        {
            "ID": "MoveToIAAfter30Days",
            "Status": "Enabled",
            "Filter": {
                "Prefix": "logs/"
            },
            "Transitions": [
                {
                    "Days": 30,
                    "StorageClass": "STANDARD_IA"
                },
                {
                    "Days": 90,
                    "StorageClass": "GLACIER"
                },
                {
                    "Days": 365,
                    "StorageClass": "DEEP_ARCHIVE"
                }
            ],
            "Expiration": {
                "Days": 730
            }
        },
        {
            "ID": "DeleteOldVersions",
            "Status": "Enabled",
            "Filter": {},
            "NoncurrentVersionExpiration": {
                "NoncurrentDays": 30
            },
            "AbortIncompleteMultipartUpload": {
                "DaysAfterInitiation": 7
            }
        }
    ]
}
EOF

aws s3api put-bucket-lifecycle-configuration \
    --bucket my-bucket \
    --lifecycle-configuration file://lifecycle.json
```

### 1.7 S3 Encryption

```bash
# Activer l'encryption par défaut (SSE-S3)
aws s3api put-bucket-encryption \
    --bucket my-bucket \
    --server-side-encryption-configuration '{
        "Rules": [
            {
                "ApplyServerSideEncryptionByDefault": {
                    "SSEAlgorithm": "AES256"
                },
                "BucketKeyEnabled": true
            }
        ]
    }'

# Encryption avec KMS
aws s3api put-bucket-encryption \
    --bucket my-bucket \
    --server-side-encryption-configuration '{
        "Rules": [
            {
                "ApplyServerSideEncryptionByDefault": {
                    "SSEAlgorithm": "aws:kms",
                    "KMSMasterKeyID": "arn:aws:kms:eu-west-1:123456789012:key/xxx"
                },
                "BucketKeyEnabled": true
            }
        ]
    }'
```

---

## 2. Amazon EBS - Block Storage

### 2.1 Types de Volumes (Rappel)

```mermaid
graph LR
    subgraph "SSD-backed"
        GP3["gp3<br/>General Purpose<br/>3,000-16,000 IOPS"]
        IO2["io2<br/>Provisioned IOPS<br/>Up to 64,000 IOPS"]
    end

    subgraph "HDD-backed"
        ST1["st1<br/>Throughput Optimized<br/>500 MB/s"]
        SC1["sc1<br/>Cold HDD<br/>250 MB/s"]
    end

    GP3 -->|"Boot volumes<br/>Databases<br/>Dev/Test"| USE_GP3["✅"]
    IO2 -->|"Critical databases<br/>I/O intensive"| USE_IO2["✅"]
    ST1 -->|"Big data<br/>Log processing"| USE_ST1["✅"]
    SC1 -->|"Infrequent access<br/>Archives"| USE_SC1["✅"]

    style GP3 fill:#ff9900,color:#000
    style IO2 fill:#1a73e8,color:#fff
```

### 2.2 Opérations Avancées

```bash
# Créer un volume gp3 avec IOPS et throughput personnalisés
aws ec2 create-volume \
    --availability-zone eu-west-1a \
    --size 500 \
    --volume-type gp3 \
    --iops 10000 \
    --throughput 500 \
    --encrypted \
    --kms-key-id alias/ebs-key \
    --tag-specifications 'ResourceType=volume,Tags=[{Key=Name,Value=data-volume}]'

# Modifier un volume existant (online resize)
aws ec2 modify-volume \
    --volume-id vol-0123456789abcdef0 \
    --size 1000 \
    --iops 16000 \
    --throughput 1000

# Vérifier l'état de la modification
aws ec2 describe-volumes-modifications \
    --volume-ids vol-0123456789abcdef0

# Sur l'instance : étendre le filesystem
# XFS
sudo xfs_growfs /data
# ext4
sudo resize2fs /dev/xvdf
```

### 2.3 Snapshots Multi-Volume

```bash
# Créer des snapshots cohérents multi-volume
aws ec2 create-snapshots \
    --instance-specification InstanceId=i-0123456789abcdef0 \
    --description "Consistent backup $(date +%Y-%m-%d)" \
    --copy-tags-from-source volume

# Data Lifecycle Manager pour automatisation
aws dlm create-lifecycle-policy \
    --description "Daily EBS snapshots" \
    --state ENABLED \
    --execution-role-arn arn:aws:iam::123456789012:role/AWSDataLifecycleManagerDefaultRole \
    --policy-details '{
        "PolicyType": "EBS_SNAPSHOT_MANAGEMENT",
        "ResourceTypes": ["VOLUME"],
        "TargetTags": [{"Key": "Backup", "Value": "daily"}],
        "Schedules": [{
            "Name": "DailySnapshots",
            "CreateRule": {
                "Interval": 24,
                "IntervalUnit": "HOURS",
                "Times": ["03:00"]
            },
            "RetainRule": {
                "Count": 7
            },
            "CopyTags": true
        }]
    }'
```

---

## 3. Amazon EFS - Elastic File System

### 3.1 Création et Montage

```bash
# Créer un filesystem EFS
EFS_ID=$(aws efs create-file-system \
    --performance-mode generalPurpose \
    --throughput-mode bursting \
    --encrypted \
    --kms-key-id alias/efs-key \
    --tags Key=Name,Value=shared-data \
    --query 'FileSystemId' --output text)

# Créer un mount target dans chaque AZ
for SUBNET in subnet-aaaaa subnet-bbbbb; do
    aws efs create-mount-target \
        --file-system-id $EFS_ID \
        --subnet-id $SUBNET \
        --security-groups sg-efs-mount
done

# Sur les instances EC2 :
# Installer le client
sudo yum install -y amazon-efs-utils

# Monter avec le helper (TLS activé)
sudo mount -t efs -o tls $EFS_ID:/ /mnt/efs

# Ou dans fstab
echo "$EFS_ID:/ /mnt/efs efs _netdev,tls 0 0" | sudo tee -a /etc/fstab
```

### 3.2 Access Points

```bash
# Créer un Access Point pour une application
aws efs create-access-point \
    --file-system-id $EFS_ID \
    --posix-user Uid=1000,Gid=1000 \
    --root-directory "Path=/app-data,CreationInfo={OwnerUid=1000,OwnerGid=1000,Permissions=755}" \
    --tags Key=Name,Value=app-access-point

# Monter via Access Point
sudo mount -t efs -o tls,accesspoint=fsap-0123456789abcdef0 $EFS_ID:/ /mnt/app-data
```

---

## 4. Amazon RDS

### 4.1 Architecture Multi-AZ

```mermaid
graph TB
    subgraph "Region: eu-west-1"
        subgraph "AZ-A"
            PRIMARY["🗄️ RDS Primary<br/>db.r6g.large<br/>Read/Write"]
            EBS_P["💾 EBS Volume<br/>gp3 500GB"]
        end

        subgraph "AZ-B"
            STANDBY["🗄️ RDS Standby<br/>Synchronous Replication<br/>Automatic Failover"]
            EBS_S["💾 EBS Volume<br/>gp3 500GB"]
        end

        subgraph "AZ-C (Optional)"
            REPLICA["📖 Read Replica<br/>Async Replication<br/>Read-only"]
        end
    end

    APP["💻 Application"] --> PRIMARY
    APP -.->|Read traffic| REPLICA
    PRIMARY --> EBS_P
    STANDBY --> EBS_S
    PRIMARY <-->|Sync| STANDBY

    style PRIMARY fill:#ff9900,color:#000
    style STANDBY fill:#34a853,color:#fff
    style REPLICA fill:#1a73e8,color:#fff
```

### 4.2 Créer une Instance RDS

```bash
# Créer un subnet group
aws rds create-db-subnet-group \
    --db-subnet-group-name prod-db-subnets \
    --db-subnet-group-description "Production database subnets" \
    --subnet-ids subnet-db-a subnet-db-b subnet-db-c

# Créer un parameter group personnalisé
aws rds create-db-parameter-group \
    --db-parameter-group-name prod-postgres-params \
    --db-parameter-group-family postgres15 \
    --description "Production PostgreSQL parameters"

# Modifier les paramètres
aws rds modify-db-parameter-group \
    --db-parameter-group-name prod-postgres-params \
    --parameters '[
        {"ParameterName": "shared_buffers", "ParameterValue": "{DBInstanceClassMemory/4}", "ApplyMethod": "pending-reboot"},
        {"ParameterName": "max_connections", "ParameterValue": "200", "ApplyMethod": "pending-reboot"},
        {"ParameterName": "log_statement", "ParameterValue": "ddl", "ApplyMethod": "immediate"}
    ]'

# Créer l'instance RDS
aws rds create-db-instance \
    --db-instance-identifier prod-postgres \
    --db-instance-class db.r6g.large \
    --engine postgres \
    --engine-version 15.4 \
    --master-username admin \
    --master-user-password "SecurePassword123!" \
    --allocated-storage 100 \
    --storage-type gp3 \
    --storage-throughput 125 \
    --iops 3000 \
    --multi-az \
    --db-subnet-group-name prod-db-subnets \
    --vpc-security-group-ids sg-database \
    --db-parameter-group-name prod-postgres-params \
    --backup-retention-period 7 \
    --preferred-backup-window "03:00-04:00" \
    --preferred-maintenance-window "sun:04:00-sun:05:00" \
    --storage-encrypted \
    --kms-key-id alias/rds-key \
    --enable-performance-insights \
    --performance-insights-retention-period 7 \
    --deletion-protection \
    --tags Key=Environment,Value=production

# Attendre que l'instance soit disponible
aws rds wait db-instance-available --db-instance-identifier prod-postgres
```

### 4.3 Read Replicas

```bash
# Créer un read replica (même région)
aws rds create-db-instance-read-replica \
    --db-instance-identifier prod-postgres-replica-1 \
    --source-db-instance-identifier prod-postgres \
    --db-instance-class db.r6g.large \
    --availability-zone eu-west-1c

# Créer un read replica cross-region (DR)
aws rds create-db-instance-read-replica \
    --db-instance-identifier prod-postgres-replica-dr \
    --source-db-instance-identifier arn:aws:rds:eu-west-1:123456789012:db:prod-postgres \
    --db-instance-class db.r6g.large \
    --region us-east-1 \
    --kms-key-id alias/rds-key-us

# Promouvoir un replica en standalone (pour DR)
aws rds promote-read-replica \
    --db-instance-identifier prod-postgres-replica-dr \
    --region us-east-1
```

### 4.4 Snapshots et Restore

```bash
# Créer un snapshot manuel
aws rds create-db-snapshot \
    --db-instance-identifier prod-postgres \
    --db-snapshot-identifier prod-postgres-$(date +%Y%m%d)

# Copier un snapshot vers une autre région
aws rds copy-db-snapshot \
    --source-db-snapshot-identifier arn:aws:rds:eu-west-1:123456789012:snapshot:prod-postgres-20240101 \
    --target-db-snapshot-identifier prod-postgres-dr-copy \
    --kms-key-id alias/rds-key-us \
    --region us-east-1

# Restaurer depuis un snapshot
aws rds restore-db-instance-from-db-snapshot \
    --db-instance-identifier prod-postgres-restored \
    --db-snapshot-identifier prod-postgres-20240101 \
    --db-instance-class db.r6g.large \
    --db-subnet-group-name prod-db-subnets \
    --vpc-security-group-ids sg-database

# Point-in-time recovery
aws rds restore-db-instance-to-point-in-time \
    --source-db-instance-identifier prod-postgres \
    --target-db-instance-identifier prod-postgres-pitr \
    --restore-time "2024-01-15T10:30:00Z" \
    --db-instance-class db.r6g.large \
    --db-subnet-group-name prod-db-subnets
```

---

## 5. Amazon Aurora

### 5.1 Architecture Aurora

```mermaid
graph TB
    subgraph "Aurora Cluster"
        WRITER["✏️ Writer Instance<br/>Primary endpoint"]
        READER1["📖 Reader 1"]
        READER2["📖 Reader 2"]

        CLUSTER_EP["🔗 Cluster Endpoint<br/>Write operations"]
        READER_EP["🔗 Reader Endpoint<br/>Read operations"]
    end

    subgraph "Shared Storage Layer"
        STORAGE["💾 Aurora Storage<br/>6 copies across 3 AZs<br/>Auto-scaling up to 128TB"]
    end

    APP["💻 Application"]

    APP -->|Writes| CLUSTER_EP
    APP -->|Reads| READER_EP

    CLUSTER_EP --> WRITER
    READER_EP --> READER1
    READER_EP --> READER2

    WRITER --> STORAGE
    READER1 --> STORAGE
    READER2 --> STORAGE

    style WRITER fill:#ff9900,color:#000
    style STORAGE fill:#34a853,color:#fff
```

### 5.2 Créer un Cluster Aurora

```bash
# Créer le cluster Aurora
aws rds create-db-cluster \
    --db-cluster-identifier prod-aurora-cluster \
    --engine aurora-postgresql \
    --engine-version 15.4 \
    --master-username admin \
    --master-user-password "SecurePassword123!" \
    --db-subnet-group-name prod-db-subnets \
    --vpc-security-group-ids sg-database \
    --storage-encrypted \
    --kms-key-id alias/aurora-key \
    --backup-retention-period 7 \
    --preferred-backup-window "03:00-04:00" \
    --preferred-maintenance-window "sun:04:00-sun:05:00" \
    --enable-cloudwatch-logs-exports '["postgresql"]' \
    --deletion-protection \
    --tags Key=Environment,Value=production

# Créer l'instance writer
aws rds create-db-instance \
    --db-instance-identifier prod-aurora-writer \
    --db-cluster-identifier prod-aurora-cluster \
    --db-instance-class db.r6g.large \
    --engine aurora-postgresql

# Créer les instances reader
for i in 1 2; do
    aws rds create-db-instance \
        --db-instance-identifier prod-aurora-reader-$i \
        --db-cluster-identifier prod-aurora-cluster \
        --db-instance-class db.r6g.large \
        --engine aurora-postgresql
done

# Récupérer les endpoints
aws rds describe-db-clusters \
    --db-cluster-identifier prod-aurora-cluster \
    --query 'DBClusters[0].[Endpoint,ReaderEndpoint]'
```

### 5.3 Aurora Serverless v2

```bash
# Créer un cluster Aurora Serverless v2
aws rds create-db-cluster \
    --db-cluster-identifier prod-aurora-serverless \
    --engine aurora-postgresql \
    --engine-version 15.4 \
    --master-username admin \
    --master-user-password "SecurePassword123!" \
    --db-subnet-group-name prod-db-subnets \
    --vpc-security-group-ids sg-database \
    --serverless-v2-scaling-configuration MinCapacity=0.5,MaxCapacity=16 \
    --storage-encrypted

# Créer une instance serverless
aws rds create-db-instance \
    --db-instance-identifier prod-aurora-serverless-1 \
    --db-cluster-identifier prod-aurora-serverless \
    --db-instance-class db.serverless \
    --engine aurora-postgresql
```

### 5.4 Aurora Global Database

```bash
# Créer un global database (pour DR cross-region)
aws rds create-global-cluster \
    --global-cluster-identifier prod-global-aurora \
    --source-db-cluster-identifier arn:aws:rds:eu-west-1:123456789012:cluster:prod-aurora-cluster

# Ajouter une région secondaire
aws rds create-db-cluster \
    --db-cluster-identifier prod-aurora-us-cluster \
    --engine aurora-postgresql \
    --engine-version 15.4 \
    --global-cluster-identifier prod-global-aurora \
    --db-subnet-group-name prod-db-subnets-us \
    --region us-east-1

# Failover vers la région secondaire
aws rds failover-global-cluster \
    --global-cluster-identifier prod-global-aurora \
    --target-db-cluster-identifier arn:aws:rds:us-east-1:123456789012:cluster:prod-aurora-us-cluster
```

---

## 6. DynamoDB - NoSQL

### 6.1 Concepts Clés

```mermaid
graph LR
    subgraph "DynamoDB Table"
        TABLE["📊 Table: Orders"]
        PK["🔑 Partition Key: OrderId"]
        SK["🔑 Sort Key: Timestamp"]
    end

    subgraph "Capacity Modes"
        PROV["📈 Provisioned<br/>RCU/WCU définies"]
        OD["🔄 On-Demand<br/>Auto-scale"]
    end

    subgraph "Features"
        GSI["📇 Global Secondary Index"]
        LSI["📇 Local Secondary Index"]
        STREAMS["📡 DynamoDB Streams"]
        TTL["⏰ Time to Live"]
    end

    TABLE --> PK
    TABLE --> SK
    TABLE --> GSI
    TABLE --> STREAMS

    style TABLE fill:#2d72d9,color:#fff
```

### 6.2 Créer et Gérer une Table

```bash
# Créer une table avec On-Demand capacity
aws dynamodb create-table \
    --table-name Orders \
    --attribute-definitions \
        AttributeName=OrderId,AttributeType=S \
        AttributeName=CustomerId,AttributeType=S \
        AttributeName=OrderDate,AttributeType=S \
    --key-schema \
        AttributeName=OrderId,KeyType=HASH \
    --global-secondary-indexes '[
        {
            "IndexName": "CustomerOrders",
            "KeySchema": [
                {"AttributeName": "CustomerId", "KeyType": "HASH"},
                {"AttributeName": "OrderDate", "KeyType": "RANGE"}
            ],
            "Projection": {"ProjectionType": "ALL"}
        }
    ]' \
    --billing-mode PAY_PER_REQUEST \
    --tags Key=Environment,Value=production

# Activer Point-in-time recovery
aws dynamodb update-continuous-backups \
    --table-name Orders \
    --point-in-time-recovery-specification PointInTimeRecoveryEnabled=true

# Activer DynamoDB Streams
aws dynamodb update-table \
    --table-name Orders \
    --stream-specification StreamEnabled=true,StreamViewType=NEW_AND_OLD_IMAGES

# Activer TTL
aws dynamodb update-time-to-live \
    --table-name Orders \
    --time-to-live-specification Enabled=true,AttributeName=ExpirationTime
```

### 6.3 CRUD Operations

```bash
# Put Item
aws dynamodb put-item \
    --table-name Orders \
    --item '{
        "OrderId": {"S": "ORD-001"},
        "CustomerId": {"S": "CUST-123"},
        "OrderDate": {"S": "2024-01-15"},
        "Amount": {"N": "150.00"},
        "Status": {"S": "PENDING"}
    }'

# Get Item
aws dynamodb get-item \
    --table-name Orders \
    --key '{"OrderId": {"S": "ORD-001"}}'

# Query (avec index)
aws dynamodb query \
    --table-name Orders \
    --index-name CustomerOrders \
    --key-condition-expression "CustomerId = :cid AND OrderDate BETWEEN :start AND :end" \
    --expression-attribute-values '{
        ":cid": {"S": "CUST-123"},
        ":start": {"S": "2024-01-01"},
        ":end": {"S": "2024-01-31"}
    }'

# Update Item
aws dynamodb update-item \
    --table-name Orders \
    --key '{"OrderId": {"S": "ORD-001"}}' \
    --update-expression "SET #s = :status, UpdatedAt = :now" \
    --expression-attribute-names '{"#s": "Status"}' \
    --expression-attribute-values '{
        ":status": {"S": "COMPLETED"},
        ":now": {"S": "2024-01-15T14:30:00Z"}
    }'

# Delete Item
aws dynamodb delete-item \
    --table-name Orders \
    --key '{"OrderId": {"S": "ORD-001"}}'
```

---

## Exercice : À Vous de Jouer

!!! example "Mise en Pratique"
    **Objectif** : Déployer une architecture de stockage complète, scalable et hautement disponible

    **Contexte** : Vous devez concevoir et déployer l'infrastructure de stockage pour une application SaaS multi-tenant. L'application nécessite du stockage objet pour les médias utilisateurs, du stockage fichier partagé pour les workers de traitement, des volumes EBS performants pour les bases de données, et une instance RDS PostgreSQL Multi-AZ pour les données transactionnelles. L'architecture doit être optimisée pour les coûts avec des policies de lifecycle appropriées et des backups automatisés.

    **Tâches à réaliser** :

    1. Créer un bucket S3 avec versioning, encryption, et lifecycle policy (Standard → IA après 30j → Glacier après 90j)
    2. Configurer S3 Replication vers un bucket de backup dans une autre région
    3. Créer 2 volumes EBS gp3 (100GB chacun) avec snapshots automatiques via DLM
    4. Déployer un système de fichiers EFS avec lifecycle management (IA après 30 jours)
    5. Créer une instance RDS PostgreSQL 14 Multi-AZ avec Read Replica
    6. Configurer les automated backups RDS avec fenêtre de maintenance
    7. Activer Performance Insights et Enhanced Monitoring sur RDS
    8. Créer un FSx for Lustre pour workloads HPC (optionnel si budget disponible)

    **Critères de validation** :

    - [ ] Le bucket S3 est chiffré, versionné avec lifecycle policy active
    - [ ] La réplication S3 fonctionne vers la région secondaire
    - [ ] Les volumes EBS sont chiffrés avec des snapshots quotidiens automatiques (rétention 7 jours)
    - [ ] EFS est accessible depuis plusieurs AZs avec encryption au repos et en transit
    - [ ] RDS est Multi-AZ avec au moins un Read Replica fonctionnel
    - [ ] Les backups RDS sont configurés avec rétention de 7 jours minimum
    - [ ] Performance Insights montre les métriques de la base de données
    - [ ] Tous les services de stockage utilisent le chiffrement
    - [ ] Une estimation des coûts mensuels est documentée

??? quote "Solution"

    **Étape 1 : Création du bucket S3 avec lifecycle et réplication**

    ```bash
    #!/bin/bash
    # Script: deploy-storage-architecture.sh
    # Description: Déploiement complet de l'architecture de stockage

    set -e

    # Variables
    PRIMARY_REGION="eu-west-1"
    BACKUP_REGION="eu-west-3"
    BUCKET_NAME="saas-app-media-$(date +%s)"
    BACKUP_BUCKET="saas-app-backup-$(date +%s)"
    VPC_ID="vpc-xxx"  # À remplacer

    echo "=== Configuration S3 Primary Bucket ==="

    # Créer le bucket principal
    aws s3api create-bucket \
        --bucket $BUCKET_NAME \
        --region $PRIMARY_REGION \
        --create-bucket-configuration LocationConstraint=$PRIMARY_REGION

    # Activer versioning (requis pour replication)
    aws s3api put-bucket-versioning \
        --bucket $BUCKET_NAME \
        --versioning-configuration Status=Enabled

    # Encryption SSE-S3
    aws s3api put-bucket-encryption \
        --bucket $BUCKET_NAME \
        --server-side-encryption-configuration '{
            "Rules": [{
                "ApplyServerSideEncryptionByDefault": {
                    "SSEAlgorithm": "AES256"
                },
                "BucketKeyEnabled": true
            }]
        }'

    # Bloquer l'accès public
    aws s3api put-public-access-block \
        --bucket $BUCKET_NAME \
        --public-access-block-configuration \
            BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

    # Lifecycle policy
    cat > s3-lifecycle.json << 'EOF'
    {
        "Rules": [
            {
                "ID": "OptimizeStorage",
                "Status": "Enabled",
                "Filter": {"Prefix": ""},
                "Transitions": [
                    {
                        "Days": 30,
                        "StorageClass": "STANDARD_IA"
                    },
                    {
                        "Days": 90,
                        "StorageClass": "GLACIER_IR"
                    },
                    {
                        "Days": 365,
                        "StorageClass": "DEEP_ARCHIVE"
                    }
                ],
                "NoncurrentVersionTransitions": [
                    {
                        "NoncurrentDays": 30,
                        "StorageClass": "GLACIER_IR"
                    }
                ],
                "NoncurrentVersionExpiration": {
                    "NoncurrentDays": 90
                },
                "AbortIncompleteMultipartUpload": {
                    "DaysAfterInitiation": 7
                }
            },
            {
                "ID": "CleanupOldThumbnails",
                "Status": "Enabled",
                "Filter": {"Prefix": "thumbnails/"},
                "Expiration": {"Days": 90}
            }
        ]
    }
    EOF

    aws s3api put-bucket-lifecycle-configuration \
        --bucket $BUCKET_NAME \
        --lifecycle-configuration file://s3-lifecycle.json

    echo "✅ Bucket S3 principal configuré : $BUCKET_NAME"
    ```

    **Étape 2 : Configuration S3 Replication**

    ```bash
    echo "=== Configuration S3 Replication ==="

    # Créer le bucket de backup dans la région secondaire
    aws s3api create-bucket \
        --bucket $BACKUP_BUCKET \
        --region $BACKUP_REGION \
        --create-bucket-configuration LocationConstraint=$BACKUP_REGION

    aws s3api put-bucket-versioning \
        --bucket $BACKUP_BUCKET \
        --versioning-configuration Status=Enabled

    # Créer le rôle IAM pour replication
    cat > replication-trust-policy.json << 'EOF'
    {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "s3.amazonaws.com"},
            "Action": "sts:AssumeRole"
        }]
    }
    EOF

    REPLICATION_ROLE=$(aws iam create-role \
        --role-name S3ReplicationRole \
        --assume-role-policy-document file://replication-trust-policy.json \
        --query 'Role.Arn' --output text)

    # Policy de replication
    ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

    cat > replication-policy.json << EOF
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "s3:GetReplicationConfiguration",
                    "s3:ListBucket"
                ],
                "Resource": "arn:aws:s3:::$BUCKET_NAME"
            },
            {
                "Effect": "Allow",
                "Action": [
                    "s3:GetObjectVersionForReplication",
                    "s3:GetObjectVersionAcl"
                ],
                "Resource": "arn:aws:s3:::$BUCKET_NAME/*"
            },
            {
                "Effect": "Allow",
                "Action": [
                    "s3:ReplicateObject",
                    "s3:ReplicateDelete"
                ],
                "Resource": "arn:aws:s3:::$BACKUP_BUCKET/*"
            }
        ]
    }
    EOF

    aws iam put-role-policy \
        --role-name S3ReplicationRole \
        --policy-name S3ReplicationPolicy \
        --policy-document file://replication-policy.json

    # Attendre la propagation du rôle
    sleep 10

    # Configurer la replication
    cat > replication-config.json << EOF
    {
        "Role": "$REPLICATION_ROLE",
        "Rules": [{
            "ID": "ReplicateAll",
            "Priority": 1,
            "Filter": {},
            "Status": "Enabled",
            "Destination": {
                "Bucket": "arn:aws:s3:::$BACKUP_BUCKET",
                "ReplicationTime": {
                    "Status": "Enabled",
                    "Time": {"Minutes": 15}
                },
                "Metrics": {
                    "Status": "Enabled",
                    "EventThreshold": {"Minutes": 15}
                }
            },
            "DeleteMarkerReplication": {"Status": "Enabled"}
        }]
    }
    EOF

    aws s3api put-bucket-replication \
        --bucket $BUCKET_NAME \
        --replication-configuration file://replication-config.json

    echo "✅ Réplication S3 configurée vers $BACKUP_REGION"
    ```

    **Étape 3 : Volumes EBS avec snapshots automatiques**

    ```bash
    echo "=== Création volumes EBS avec DLM ==="

    # Créer 2 volumes EBS gp3
    for i in 1 2; do
        VOLUME_ID=$(aws ec2 create-volume \
            --availability-zone ${PRIMARY_REGION}a \
            --size 100 \
            --volume-type gp3 \
            --iops 3000 \
            --throughput 125 \
            --encrypted \
            --tag-specifications "ResourceType=volume,Tags=[{Key=Name,Value=app-data-vol${i}},{Key=Backup,Value=daily},{Key=Environment,Value=production}]" \
            --query 'VolumeId' --output text)

        echo "✅ Volume EBS créé : $VOLUME_ID"
    done

    # Créer le rôle IAM pour DLM
    cat > dlm-trust-policy.json << 'EOF'
    {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "dlm.amazonaws.com"},
            "Action": "sts:AssumeRole"
        }]
    }
    EOF

    DLM_ROLE=$(aws iam create-role \
        --role-name AWSDataLifecycleManagerRole \
        --assume-role-policy-document file://dlm-trust-policy.json \
        --query 'Role.Arn' --output text)

    aws iam attach-role-policy \
        --role-name AWSDataLifecycleManagerRole \
        --policy-arn arn:aws:iam::aws:policy/service-role/AWSDataLifecycleManagerServiceRole

    # Attendre la propagation
    sleep 10

    # Créer la policy DLM
    aws dlm create-lifecycle-policy \
        --description "Daily EBS snapshots - 7 days retention" \
        --state ENABLED \
        --execution-role-arn $DLM_ROLE \
        --policy-details '{
            "PolicyType": "EBS_SNAPSHOT_MANAGEMENT",
            "ResourceTypes": ["VOLUME"],
            "TargetTags": [{"Key": "Backup", "Value": "daily"}],
            "Schedules": [{
                "Name": "DailySnapshots",
                "CreateRule": {
                    "Interval": 24,
                    "IntervalUnit": "HOURS",
                    "Times": ["03:00"]
                },
                "RetainRule": {
                    "Count": 7
                },
                "TagsToAdd": [
                    {"Key": "SnapshotType", "Value": "automated"},
                    {"Key": "CreatedBy", "Value": "DLM"}
                ],
                "CopyTags": true
            }]
        }'

    echo "✅ DLM Policy créée pour snapshots quotidiens"
    ```

    **Étape 4 : Système de fichiers EFS**

    ```bash
    echo "=== Déploiement EFS ==="

    # Security Group EFS
    EFS_SG=$(aws ec2 create-security-group \
        --group-name efs-mount-targets-sg \
        --description "Security group for EFS mount targets" \
        --vpc-id $VPC_ID \
        --query 'GroupId' --output text)

    aws ec2 authorize-security-group-ingress \
        --group-id $EFS_SG \
        --protocol tcp \
        --port 2049 \
        --cidr 10.0.0.0/16

    # Créer le filesystem EFS
    EFS_ID=$(aws efs create-file-system \
        --performance-mode generalPurpose \
        --throughput-mode bursting \
        --encrypted \
        --lifecycle-policies '[{"TransitionToIA":"AFTER_30_DAYS"},{"TransitionToPrimaryStorageClass":"AFTER_1_ACCESS"}]' \
        --tags Key=Name,Value=shared-app-storage Key=Environment,Value=production \
        --query 'FileSystemId' --output text)

    echo "⏳ Attente de la disponibilité du filesystem EFS..."
    aws efs describe-file-systems --file-system-id $EFS_ID --query 'FileSystems[0].LifeCycleState'

    # Récupérer les subnets privés
    SUBNETS=$(aws ec2 describe-subnets \
        --filters "Name=vpc-id,Values=$VPC_ID" "Name=tag:Tier,Values=private" \
        --query 'Subnets[0:2].SubnetId' --output text)

    # Créer les mount targets
    for SUBNET in $SUBNETS; do
        aws efs create-mount-target \
            --file-system-id $EFS_ID \
            --subnet-id $SUBNET \
            --security-groups $EFS_SG
        echo "✅ Mount target créé dans subnet $SUBNET"
    done

    echo "✅ EFS créé : $EFS_ID"
    echo "   DNS: ${EFS_ID}.efs.${PRIMARY_REGION}.amazonaws.com"
    ```

    **Étape 5-7 : Instance RDS PostgreSQL Multi-AZ**

    ```bash
    echo "=== Déploiement RDS PostgreSQL Multi-AZ ==="

    # DB Subnet Group
    DB_SUBNETS=$(aws ec2 describe-subnets \
        --filters "Name=vpc-id,Values=$VPC_ID" "Name=tag:Tier,Values=database" \
        --query 'Subnets[].SubnetId' --output text)

    aws rds create-db-subnet-group \
        --db-subnet-group-name saas-db-subnet-group \
        --db-subnet-group-description "Subnet group for SaaS database" \
        --subnet-ids $DB_SUBNETS

    # Security Group RDS
    RDS_SG=$(aws ec2 create-security-group \
        --group-name rds-postgres-sg \
        --description "Security group for RDS PostgreSQL" \
        --vpc-id $VPC_ID \
        --query 'GroupId' --output text)

    aws ec2 authorize-security-group-ingress \
        --group-id $RDS_SG \
        --protocol tcp \
        --port 5432 \
        --source-group $APP_SG  # Security group des instances applicatives

    # Créer l'instance RDS principale (Multi-AZ)
    aws rds create-db-instance \
        --db-instance-identifier saas-app-db \
        --db-instance-class db.r6g.large \
        --engine postgres \
        --engine-version 14.9 \
        --master-username dbadmin \
        --master-user-password 'ChangeMeP@ssw0rd!' \
        --allocated-storage 100 \
        --storage-type gp3 \
        --iops 3000 \
        --storage-encrypted \
        --multi-az \
        --db-subnet-group-name saas-db-subnet-group \
        --vpc-security-group-ids $RDS_SG \
        --backup-retention-period 7 \
        --preferred-backup-window "03:00-04:00" \
        --preferred-maintenance-window "mon:04:00-mon:05:00" \
        --enable-cloudwatch-logs-exports '["postgresql","upgrade"]' \
        --enable-performance-insights \
        --performance-insights-retention-period 7 \
        --monitoring-interval 60 \
        --monitoring-role-arn arn:aws:iam::${ACCOUNT_ID}:role/rds-monitoring-role \
        --deletion-protection \
        --copy-tags-to-snapshot \
        --tags Key=Name,Value=saas-app-db Key=Environment,Value=production

    echo "⏳ Attente de la disponibilité de l'instance RDS (environ 10-15 minutes)..."
    aws rds wait db-instance-available --db-instance-identifier saas-app-db

    echo "✅ Instance RDS créée : saas-app-db"

    # Créer le Read Replica
    aws rds create-db-instance-read-replica \
        --db-instance-identifier saas-app-db-replica \
        --source-db-instance-identifier saas-app-db \
        --db-instance-class db.r6g.large \
        --publicly-accessible false \
        --enable-performance-insights \
        --performance-insights-retention-period 7 \
        --monitoring-interval 60 \
        --monitoring-role-arn arn:aws:iam::${ACCOUNT_ID}:role/rds-monitoring-role \
        --tags Key=Name,Value=saas-app-db-replica Key=Role,Value=read-replica

    echo "⏳ Création du Read Replica en cours..."
    aws rds wait db-instance-available --db-instance-identifier saas-app-db-replica

    echo "✅ Read Replica créé : saas-app-db-replica"

    # Récupérer les endpoints
    PRIMARY_ENDPOINT=$(aws rds describe-db-instances \
        --db-instance-identifier saas-app-db \
        --query 'DBInstances[0].Endpoint.Address' --output text)

    REPLICA_ENDPOINT=$(aws rds describe-db-instances \
        --db-instance-identifier saas-app-db-replica \
        --query 'DBInstances[0].Endpoint.Address' --output text)

    echo ""
    echo "📊 Endpoints RDS:"
    echo "   Primary: $PRIMARY_ENDPOINT:5432"
    echo "   Replica: $REPLICA_ENDPOINT:5432"
    ```

    **Vérification et tests :**

    ```bash
    echo ""
    echo "===========================================  ======"
    echo "✅ Déploiement Storage Architecture Terminé"
    echo "=================================================="
    echo ""
    echo "S3 Primary Bucket: $BUCKET_NAME"
    echo "S3 Backup Bucket: $BACKUP_BUCKET (région: $BACKUP_REGION)"
    echo "EFS FileSystem: $EFS_ID"
    echo "RDS Primary: saas-app-db"
    echo "RDS Replica: saas-app-db-replica"
    echo ""
    echo "=== Tests à effectuer ==="
    echo ""
    echo "1. Test S3 Replication:"
    echo "   aws s3 cp test.txt s3://$BUCKET_NAME/"
    echo "   aws s3 ls s3://$BACKUP_BUCKET/ --region $BACKUP_REGION"
    echo ""
    echo "2. Test EFS Mount (depuis une EC2):"
    echo "   sudo mount -t nfs4 -o nfsvers=4.1 ${EFS_ID}.efs.${PRIMARY_REGION}.amazonaws.com:/ /mnt/efs"
    echo "   df -h /mnt/efs"
    echo ""
    echo "3. Test connexion RDS:"
    echo "   psql -h $PRIMARY_ENDPOINT -U dbadmin -d postgres"
    echo ""
    echo "4. Vérifier les métriques Performance Insights dans la console RDS"
    echo ""
    echo "=== Estimation des coûts mensuels (eu-west-1) ==="
    echo "S3 Standard (100GB): ~2.30 USD"
    echo "S3 Replication: ~2.00 USD"
    echo "EBS gp3 (200GB total): ~16.00 USD"
    echo "EFS (50GB utilisé): ~15.00 USD"
    echo "RDS db.r6g.large Multi-AZ: ~420.00 USD"
    echo "RDS Read Replica: ~210.00 USD"
    echo "Backups & Snapshots: ~10.00 USD"
    echo "-------------------------------------------"
    echo "TOTAL ESTIMÉ: ~675 USD/mois"
    echo ""
    echo "💡 Optimisations possibles:"
    echo "   - Utiliser Reserved Instances pour RDS (-40%)"
    echo "   - Activer S3 Intelligent-Tiering"
    echo "   - Réduire Performance Insights retention"
    echo "=================================================="
    ```

---

## 8. Résumé

| Service | Use Case | Commande clé |
|---------|----------|--------------|
| **S3** | Object storage, backups, static files | `aws s3 cp` / `aws s3 sync` |
| **EBS** | Block storage for EC2 | `aws ec2 create-volume` |
| **EFS** | Shared file storage | `aws efs create-file-system` |
| **RDS** | Managed relational databases | `aws rds create-db-instance` |
| **Aurora** | High-performance MySQL/PostgreSQL | `aws rds create-db-cluster` |
| **DynamoDB** | NoSQL, serverless | `aws dynamodb create-table` |

---

## Navigation

| Précédent | Suivant |
|-----------|---------|
| [← Module 3 : VPC & Networking](03-module.md) | [Module 5 : EKS & Containers →](05-module.md) |

---

## Navigation

| | |
|:---|---:|
| [← Module 3 : VPC & Networking](03-module.md) | [Module 5 : EKS & Containers →](05-module.md) |

[Retour au Programme](index.md){ .md-button }
