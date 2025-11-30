---
tags:
  - python
  - aws
  - boto3
  - cloud
---

# Cloud & AWS (Boto3)

Automatisation AWS avec Python et Boto3.

---

## Installation et Configuration

```bash
pip install boto3
```

### Configuration AWS CLI

```bash
# Configurer les credentials
aws configure
# AWS Access Key ID: AKIAXXXXXXXX
# AWS Secret Access Key: xxxxxxxxxxxx
# Default region: eu-west-1
# Default output format: json

# Ou via variables d'environnement
export AWS_ACCESS_KEY_ID="AKIAXXXXXXXX"
export AWS_SECRET_ACCESS_KEY="xxxxxxxxxxxx"
export AWS_DEFAULT_REGION="eu-west-1"
```

### Fichiers de Configuration

```ini
# ~/.aws/credentials
[default]
aws_access_key_id = AKIAXXXXXXXX
aws_secret_access_key = xxxxxxxxxxxx

[prod]
aws_access_key_id = AKIAYYYYYYYY
aws_secret_access_key = yyyyyyyyyyyy

# ~/.aws/config
[default]
region = eu-west-1
output = json

[profile prod]
region = eu-west-1
```

---

## Concepts Boto3

```python
import boto3

# Session (gère les credentials)
session = boto3.Session(profile_name='prod')

# Client (bas niveau, 1:1 avec l'API AWS)
ec2_client = boto3.client('ec2')

# Resource (haut niveau, orienté objet)
ec2_resource = boto3.resource('ec2')

# Avec profil spécifique
s3 = boto3.client('s3', profile_name='prod')

# Avec région spécifique
ec2 = boto3.client('ec2', region_name='us-east-1')
```

---

## EC2

### Lister les Instances

```python
import boto3

ec2 = boto3.client('ec2')

# Toutes les instances
response = ec2.describe_instances()

for reservation in response['Reservations']:
    for instance in reservation['Instances']:
        instance_id = instance['InstanceId']
        state = instance['State']['Name']
        instance_type = instance['InstanceType']

        # Récupérer le tag Name
        name = "N/A"
        for tag in instance.get('Tags', []):
            if tag['Key'] == 'Name':
                name = tag['Value']
                break

        print(f"{instance_id} | {name} | {state} | {instance_type}")

# Avec filtres
response = ec2.describe_instances(
    Filters=[
        {'Name': 'instance-state-name', 'Values': ['running']},
        {'Name': 'tag:Environment', 'Values': ['production']}
    ]
)
```

### Gérer les Instances

```python
import boto3

ec2 = boto3.client('ec2')

# Démarrer
ec2.start_instances(InstanceIds=['i-1234567890abcdef0'])

# Arrêter
ec2.stop_instances(InstanceIds=['i-1234567890abcdef0'])

# Redémarrer
ec2.reboot_instances(InstanceIds=['i-1234567890abcdef0'])

# Terminer (supprimer)
ec2.terminate_instances(InstanceIds=['i-1234567890abcdef0'])
```

### Créer une Instance

```python
import boto3

ec2 = boto3.resource('ec2')

instances = ec2.create_instances(
    ImageId='ami-0abcdef1234567890',
    InstanceType='t3.micro',
    KeyName='my-key-pair',
    MinCount=1,
    MaxCount=1,
    SecurityGroupIds=['sg-0123456789abcdef0'],
    SubnetId='subnet-0123456789abcdef0',
    TagSpecifications=[
        {
            'ResourceType': 'instance',
            'Tags': [
                {'Key': 'Name', 'Value': 'web-server-01'},
                {'Key': 'Environment', 'Value': 'production'}
            ]
        }
    ]
)

instance = instances[0]
print(f"Created instance: {instance.id}")

# Attendre que l'instance soit running
instance.wait_until_running()
instance.reload()
print(f"Public IP: {instance.public_ip_address}")
```

---

## S3

### Opérations de Base

```python
import boto3

s3 = boto3.client('s3')

# Lister les buckets
response = s3.list_buckets()
for bucket in response['Buckets']:
    print(bucket['Name'])

# Lister les objets d'un bucket
response = s3.list_objects_v2(Bucket='my-bucket', Prefix='logs/')
for obj in response.get('Contents', []):
    print(f"{obj['Key']} - {obj['Size']} bytes")

# Upload un fichier
s3.upload_file('/local/file.txt', 'my-bucket', 'remote/file.txt')

# Download un fichier
s3.download_file('my-bucket', 'remote/file.txt', '/local/file.txt')

# Upload depuis la mémoire
s3.put_object(
    Bucket='my-bucket',
    Key='data/config.json',
    Body='{"key": "value"}',
    ContentType='application/json'
)

# Lire un objet
response = s3.get_object(Bucket='my-bucket', Key='data/config.json')
content = response['Body'].read().decode('utf-8')

# Supprimer
s3.delete_object(Bucket='my-bucket', Key='old-file.txt')
```

### Presigned URLs

```python
import boto3

s3 = boto3.client('s3')

# URL de téléchargement temporaire (1 heure)
url = s3.generate_presigned_url(
    'get_object',
    Params={'Bucket': 'my-bucket', 'Key': 'private/file.pdf'},
    ExpiresIn=3600
)
print(url)

# URL d'upload temporaire
url = s3.generate_presigned_url(
    'put_object',
    Params={'Bucket': 'my-bucket', 'Key': 'uploads/new-file.txt'},
    ExpiresIn=3600
)
```

---

## IAM

```python
import boto3

iam = boto3.client('iam')

# Lister les utilisateurs
response = iam.list_users()
for user in response['Users']:
    print(f"{user['UserName']} - Created: {user['CreateDate']}")

# Lister les rôles
response = iam.list_roles()
for role in response['Roles']:
    print(role['RoleName'])

# Créer un utilisateur
iam.create_user(UserName='new-user')

# Attacher une policy
iam.attach_user_policy(
    UserName='new-user',
    PolicyArn='arn:aws:iam::aws:policy/ReadOnlyAccess'
)

# Créer des access keys
response = iam.create_access_key(UserName='new-user')
print(f"Access Key: {response['AccessKey']['AccessKeyId']}")
print(f"Secret Key: {response['AccessKey']['SecretAccessKey']}")
```

---

## RDS

```python
import boto3

rds = boto3.client('rds')

# Lister les instances RDS
response = rds.describe_db_instances()
for db in response['DBInstances']:
    print(f"{db['DBInstanceIdentifier']} | {db['DBInstanceStatus']} | {db['Engine']}")

# Créer un snapshot
rds.create_db_snapshot(
    DBSnapshotIdentifier='my-snapshot-2024',
    DBInstanceIdentifier='my-database'
)

# Redémarrer
rds.reboot_db_instance(DBInstanceIdentifier='my-database')
```

---

## Lambda

```python
import boto3
import json

lambda_client = boto3.client('lambda')

# Invoquer une fonction
response = lambda_client.invoke(
    FunctionName='my-function',
    InvocationType='RequestResponse',  # ou 'Event' pour async
    Payload=json.dumps({'key': 'value'})
)

result = json.loads(response['Payload'].read())
print(result)

# Lister les fonctions
response = lambda_client.list_functions()
for func in response['Functions']:
    print(f"{func['FunctionName']} - {func['Runtime']}")
```

---

## Secrets Manager

```python
import boto3
import json

secrets = boto3.client('secretsmanager')

# Récupérer un secret
response = secrets.get_secret_value(SecretId='my-app/database')
secret_data = json.loads(response['SecretString'])
db_password = secret_data['password']

# Créer/Mettre à jour un secret
secrets.put_secret_value(
    SecretId='my-app/api-key',
    SecretString=json.dumps({'api_key': 'new-key-value'})
)
```

---

## SSM Parameter Store

```python
import boto3

ssm = boto3.client('ssm')

# Récupérer un paramètre
response = ssm.get_parameter(
    Name='/myapp/database/host',
    WithDecryption=True  # Pour les SecureString
)
value = response['Parameter']['Value']

# Récupérer plusieurs paramètres
response = ssm.get_parameters_by_path(
    Path='/myapp/',
    Recursive=True,
    WithDecryption=True
)
for param in response['Parameters']:
    print(f"{param['Name']} = {param['Value']}")

# Créer/Mettre à jour
ssm.put_parameter(
    Name='/myapp/database/host',
    Value='db.example.com',
    Type='String',  # ou 'SecureString'
    Overwrite=True
)
```

---

## CloudWatch

### Métriques

```python
import boto3
from datetime import datetime, timedelta

cloudwatch = boto3.client('cloudwatch')

# Récupérer des métriques
response = cloudwatch.get_metric_statistics(
    Namespace='AWS/EC2',
    MetricName='CPUUtilization',
    Dimensions=[
        {'Name': 'InstanceId', 'Value': 'i-1234567890abcdef0'}
    ],
    StartTime=datetime.utcnow() - timedelta(hours=1),
    EndTime=datetime.utcnow(),
    Period=300,
    Statistics=['Average', 'Maximum']
)

for datapoint in response['Datapoints']:
    print(f"{datapoint['Timestamp']}: Avg={datapoint['Average']:.2f}%")
```

### Alarmes

```python
import boto3

cloudwatch = boto3.client('cloudwatch')

# Créer une alarme
cloudwatch.put_metric_alarm(
    AlarmName='HighCPUUtilization',
    MetricName='CPUUtilization',
    Namespace='AWS/EC2',
    Dimensions=[
        {'Name': 'InstanceId', 'Value': 'i-1234567890abcdef0'}
    ],
    Statistic='Average',
    Period=300,
    EvaluationPeriods=2,
    Threshold=80,
    ComparisonOperator='GreaterThanThreshold',
    AlarmActions=['arn:aws:sns:eu-west-1:123456789:alerts']
)
```

---

## Classe Wrapper AWS

```python
import boto3
from typing import List, Dict, Optional


class AWSManager:
    """Gestionnaire AWS centralisé."""

    def __init__(self, profile: str = None, region: str = None):
        session_kwargs = {}
        if profile:
            session_kwargs['profile_name'] = profile
        if region:
            session_kwargs['region_name'] = region

        self.session = boto3.Session(**session_kwargs)

    def get_running_instances(self) -> List[Dict]:
        """Liste les instances EC2 running."""
        ec2 = self.session.client('ec2')
        response = ec2.describe_instances(
            Filters=[{'Name': 'instance-state-name', 'Values': ['running']}]
        )

        instances = []
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                name = next(
                    (t['Value'] for t in instance.get('Tags', []) if t['Key'] == 'Name'),
                    'N/A'
                )
                instances.append({
                    'id': instance['InstanceId'],
                    'name': name,
                    'type': instance['InstanceType'],
                    'private_ip': instance.get('PrivateIpAddress'),
                    'public_ip': instance.get('PublicIpAddress')
                })

        return instances

    def get_secret(self, secret_name: str) -> Dict:
        """Récupère un secret depuis Secrets Manager."""
        import json
        secrets = self.session.client('secretsmanager')
        response = secrets.get_secret_value(SecretId=secret_name)
        return json.loads(response['SecretString'])

    def upload_to_s3(self, local_path: str, bucket: str, key: str):
        """Upload un fichier vers S3."""
        s3 = self.session.client('s3')
        s3.upload_file(local_path, bucket, key)


# Utilisation
aws = AWSManager(profile='prod', region='eu-west-1')
instances = aws.get_running_instances()
for inst in instances:
    print(f"{inst['name']}: {inst['private_ip']}")

db_creds = aws.get_secret('myapp/database')
```

---

## Gestion des Erreurs

```python
import boto3
from botocore.exceptions import ClientError, BotoCoreError

s3 = boto3.client('s3')

try:
    s3.download_file('my-bucket', 'file.txt', '/local/file.txt')
except ClientError as e:
    error_code = e.response['Error']['Code']
    if error_code == '404':
        print("File not found")
    elif error_code == 'AccessDenied':
        print("Access denied")
    else:
        print(f"AWS Error: {e}")
except BotoCoreError as e:
    print(f"Boto Core Error: {e}")
```

---

## Voir Aussi

- [Fondamentaux](fundamentals.md) - Bases Python
- [API & Réseau](api-network.md) - Requests, HTTP
- [HashiCorp Vault](../security/hashicorp-vault.md) - Gestion des secrets
