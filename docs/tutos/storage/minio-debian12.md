---
tags:
  - tutos
  - storage
  - minio
  - s3
  - object-storage
  - debian
---

# MinIO sur Debian 12

Installation de **MinIO** sur Debian 12 Bookworm.

| Composant | Version |
|-----------|---------|
| Debian | 12 Bookworm |
| MinIO | Latest |

**Durée estimée :** 20 minutes

---

## 1. Installation

```bash
wget https://dl.min.io/server/minio/release/linux-amd64/minio
chmod +x minio
mv minio /usr/local/bin/

wget https://dl.min.io/client/mc/release/linux-amd64/mc
chmod +x mc
mv mc /usr/local/bin/
```

---

## 2. Configuration

```bash
useradd -r -s /sbin/nologin minio-user
mkdir -p /data/minio
chown -R minio-user:minio-user /data/minio
```

```bash
cat > /etc/default/minio << 'EOF'
MINIO_ROOT_USER=minioadmin
MINIO_ROOT_PASSWORD=minioadmin123
MINIO_VOLUMES="/data/minio"
MINIO_OPTS="--console-address :9001"
EOF

chmod 600 /etc/default/minio
```

---

## 3. Service systemd

```bash
cat > /etc/systemd/system/minio.service << 'EOF'
[Unit]
Description=MinIO
After=network-online.target

[Service]
User=minio-user
Group=minio-user
EnvironmentFile=/etc/default/minio
ExecStart=/usr/local/bin/minio server $MINIO_VOLUMES $MINIO_OPTS
Restart=always
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
ufw allow 9000/tcp
ufw allow 9001/tcp
ufw reload
```

---

## 5. Accès

- Console : `http://IP:9001`
- API S3 : `http://IP:9000`
- Login : `minioadmin` / `minioadmin123`

---

## 6. Client mc

```bash
mc alias set myminio http://localhost:9000 minioadmin minioadmin123
mc admin info myminio
```

---

## 7. Gestion buckets

```bash
mc mb myminio/mybucket
mc cp file.txt myminio/mybucket/
mc ls myminio/mybucket/
mc mirror ./localdir myminio/mybucket/
```

---

## 8. Utilisateurs

```bash
mc admin user add myminio user1 password123
mc admin policy attach myminio readwrite --user=user1
```

---

## Comparatif Rocky vs Debian

| Aspect | Rocky 9 | Debian 12 |
|--------|---------|-----------|
| Installation | Identique | Identique |
| Firewall | firewalld | ufw |
| SELinux | Oui | Non |

---

## Commandes

```bash
mc ls myminio/                     # Lister
mc mb myminio/bucket               # Créer bucket
mc cp file myminio/bucket/         # Upload
mc admin info myminio              # Status
mc admin user list myminio         # Users
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
