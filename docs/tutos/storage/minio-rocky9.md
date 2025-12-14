---
tags:
  - tutos
  - storage
  - minio
  - s3
  - object-storage
  - rocky
---

# MinIO sur Rocky Linux 9

Installation de **MinIO** pour le stockage objet S3-compatible.

| Composant | Version |
|-----------|---------|
| Rocky Linux | 9.x |
| MinIO | Latest |

**Durée estimée :** 25 minutes

---

## Cas d'utilisation

| Usage | Description |
|-------|-------------|
| **Backup** | Stockage backups S3 |
| **Media** | Fichiers statiques |
| **Data Lake** | Big Data, ML |
| **Registry** | Container registry backend |

---

## 1. Installation

### Télécharger le binaire

```bash
wget https://dl.min.io/server/minio/release/linux-amd64/minio
chmod +x minio
mv minio /usr/local/bin/
```

### Client mc

```bash
wget https://dl.min.io/client/mc/release/linux-amd64/mc
chmod +x mc
mv mc /usr/local/bin/
```

---

## 2. Configuration

### Utilisateur et répertoires

```bash
useradd -r -s /sbin/nologin minio-user

mkdir -p /data/minio
chown -R minio-user:minio-user /data/minio
```

### Fichier d'environnement

```bash
cat > /etc/default/minio << 'EOF'
# Credentials
MINIO_ROOT_USER=minioadmin
MINIO_ROOT_PASSWORD=minioadmin123

# Volumes
MINIO_VOLUMES="/data/minio"

# Console
MINIO_OPTS="--console-address :9001"

# Region
MINIO_REGION=eu-west-1
EOF

chmod 600 /etc/default/minio
```

---

## 3. Service systemd

```bash
cat > /etc/systemd/system/minio.service << 'EOF'
[Unit]
Description=MinIO Object Storage
Documentation=https://docs.min.io
After=network-online.target
Wants=network-online.target

[Service]
User=minio-user
Group=minio-user
EnvironmentFile=/etc/default/minio
ExecStart=/usr/local/bin/minio server $MINIO_VOLUMES $MINIO_OPTS
Restart=always
RestartSec=10
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now minio
```

---

## 4. Firewall

```bash
firewall-cmd --permanent --add-port=9000/tcp  # API
firewall-cmd --permanent --add-port=9001/tcp  # Console
firewall-cmd --reload
```

---

## 5. Accès

### Console Web

- URL : `http://IP:9001`
- Login : `minioadmin` / `minioadmin123`

### API S3

- Endpoint : `http://IP:9000`

---

## 6. Configuration Client (mc)

```bash
mc alias set myminio http://localhost:9000 minioadmin minioadmin123

# Vérifier
mc admin info myminio
```

---

## 7. Gestion des buckets

```bash
# Créer un bucket
mc mb myminio/mybucket

# Lister les buckets
mc ls myminio

# Upload
mc cp myfile.txt myminio/mybucket/

# Download
mc cp myminio/mybucket/myfile.txt ./

# Sync
mc mirror ./localdir myminio/mybucket/
```

---

## 8. Gestion des utilisateurs

```bash
# Créer un utilisateur
mc admin user add myminio newuser newuserpassword

# Lister
mc admin user list myminio

# Attacher une policy
mc admin policy attach myminio readwrite --user=newuser
```

### Policies intégrées

| Policy | Description |
|--------|-------------|
| `readonly` | Lecture seule |
| `writeonly` | Écriture seule |
| `readwrite` | Lecture/écriture |
| `diagnostics` | Diagnostics |

---

## 9. Policies personnalisées

```bash
cat > /tmp/custom-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject"
      ],
      "Resource": [
        "arn:aws:s3:::mybucket/*"
      ]
    }
  ]
}
EOF

mc admin policy create myminio mybucket-policy /tmp/custom-policy.json
mc admin policy attach myminio mybucket-policy --user=newuser
```

---

## 10. TLS/HTTPS

### Générer les certificats

```bash
mkdir -p /data/minio/certs

# Auto-signé
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /data/minio/certs/private.key \
    -out /data/minio/certs/public.crt \
    -subj "/CN=minio.example.com"

chown -R minio-user:minio-user /data/minio/certs
```

### Configurer MinIO

```bash
# Les certificats doivent être dans ~/.minio/certs ou MINIO_VOLUMES/certs
# MinIO détecte automatiquement les certificats
```

---

## 11. Mode distribué (cluster)

```bash
# Sur chaque nœud
cat > /etc/default/minio << 'EOF'
MINIO_ROOT_USER=minioadmin
MINIO_ROOT_PASSWORD=minioadmin123
MINIO_VOLUMES="http://minio{1...4}.example.com:9000/data/minio"
MINIO_OPTS="--console-address :9001"
EOF
```

---

## 12. Bucket versioning

```bash
# Activer le versioning
mc version enable myminio/mybucket

# Lister les versions
mc ls --versions myminio/mybucket/

# Restaurer une version
mc cp --version-id=VERSION_ID myminio/mybucket/file.txt ./
```

---

## 13. Lifecycle policies

```bash
cat > /tmp/lifecycle.json << 'EOF'
{
  "Rules": [
    {
      "ID": "expire-old",
      "Status": "Enabled",
      "Expiration": {
        "Days": 30
      }
    }
  ]
}
EOF

mc ilm import myminio/mybucket < /tmp/lifecycle.json
```

---

## 14. Notifications (Webhooks)

```bash
# Configurer une notification webhook
mc admin config set myminio notify_webhook:mywebhook \
    endpoint="http://myapp.example.com/webhook" \
    auth_token="secret"

mc event add myminio/mybucket arn:minio:sqs::mywebhook:webhook \
    --event put,delete
```

---

## 15. Intégration applications

### AWS CLI

```bash
aws configure
# Access Key: minioadmin
# Secret Key: minioadmin123
# Region: eu-west-1

aws --endpoint-url http://localhost:9000 s3 ls
aws --endpoint-url http://localhost:9000 s3 cp file.txt s3://mybucket/
```

### Python (boto3)

```python
import boto3

s3 = boto3.client('s3',
    endpoint_url='http://localhost:9000',
    aws_access_key_id='minioadmin',
    aws_secret_access_key='minioadmin123'
)

s3.upload_file('file.txt', 'mybucket', 'file.txt')
```

---

## Commandes mc utiles

```bash
mc ls myminio/                    # Lister buckets
mc mb myminio/newbucket           # Créer bucket
mc rb myminio/oldbucket           # Supprimer bucket
mc cp file myminio/bucket/        # Upload
mc cat myminio/bucket/file        # Afficher contenu
mc rm myminio/bucket/file         # Supprimer
mc mirror src myminio/bucket/     # Sync
mc admin info myminio             # Info serveur
mc admin user list myminio        # Lister users
```

---

## Dépannage

```bash
# Logs
journalctl -u minio -f

# Status
mc admin info myminio

# Health check
curl http://localhost:9000/minio/health/live
curl http://localhost:9000/minio/health/ready
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
