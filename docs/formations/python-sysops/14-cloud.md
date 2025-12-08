---
tags:
  - formation
  - python
  - cloud
  - aws
  - boto3
  - infrastructure
---

# Module 14 - Cloud & AWS avec Python

Automatiser l'infrastructure cloud avec Python et boto3.

---

## Objectifs du Module

- Utiliser boto3 pour AWS
- Gérer EC2, S3, et autres services
- Automatiser l'infrastructure
- Implémenter des patterns cloud

---

## 1. Introduction à boto3

### Installation

```bash
pip install boto3
```

### Configuration

```python
import boto3

# Configuration par défaut (~/.aws/credentials)
# [default]
# aws_access_key_id = YOUR_KEY
# aws_secret_access_key = YOUR_SECRET
# region = eu-west-1

# Client explicite
client = boto3.client(
    "ec2",
    aws_access_key_id="YOUR_KEY",
    aws_secret_access_key="YOUR_SECRET",
    region_name="eu-west-1"
)

# Avec profil nommé
session = boto3.Session(profile_name="production")
client = session.client("ec2")

# Variables d'environnement
# AWS_ACCESS_KEY_ID
# AWS_SECRET_ACCESS_KEY
# AWS_DEFAULT_REGION
```

### Client vs Resource

```python
import boto3

# Client (bas niveau) - Retourne des dictionnaires
ec2_client = boto3.client("ec2")
response = ec2_client.describe_instances()
instances = response["Reservations"][0]["Instances"]

# Resource (haut niveau) - Retourne des objets
ec2_resource = boto3.resource("ec2")
for instance in ec2_resource.instances.all():
    print(instance.id, instance.state["Name"])
```

---

## 2. Amazon EC2

### Lister les Instances

```python
import boto3

ec2 = boto3.resource("ec2")

def list_instances(filters=None):
    """Liste les instances EC2."""
    instances = []

    for instance in ec2.instances.filter(Filters=filters or []):
        instances.append({
            "id": instance.id,
            "type": instance.instance_type,
            "state": instance.state["Name"],
            "public_ip": instance.public_ip_address,
            "private_ip": instance.private_ip_address,
            "name": get_tag(instance.tags, "Name"),
            "launch_time": instance.launch_time
        })

    return instances

def get_tag(tags, key):
    """Récupère la valeur d'un tag."""
    if tags:
        for tag in tags:
            if tag["Key"] == key:
                return tag["Value"]
    return None

# Filtrer par tag
running = list_instances([
    {"Name": "instance-state-name", "Values": ["running"]},
    {"Name": "tag:Environment", "Values": ["production"]}
])
```

### Gérer les Instances

```python
import boto3

ec2 = boto3.resource("ec2")
ec2_client = boto3.client("ec2")

def start_instance(instance_id):
    """Démarre une instance."""
    instance = ec2.Instance(instance_id)
    instance.start()
    instance.wait_until_running()
    print(f"Instance {instance_id} running")

def stop_instance(instance_id):
    """Arrête une instance."""
    instance = ec2.Instance(instance_id)
    instance.stop()
    instance.wait_until_stopped()
    print(f"Instance {instance_id} stopped")

def terminate_instance(instance_id):
    """Termine une instance."""
    instance = ec2.Instance(instance_id)
    instance.terminate()
    instance.wait_until_terminated()
    print(f"Instance {instance_id} terminated")

def reboot_instance(instance_id):
    """Redémarre une instance."""
    ec2_client.reboot_instances(InstanceIds=[instance_id])

# Actions sur plusieurs instances
def stop_all_dev_instances():
    """Arrête toutes les instances de dev."""
    instances = ec2.instances.filter(
        Filters=[
            {"Name": "tag:Environment", "Values": ["development"]},
            {"Name": "instance-state-name", "Values": ["running"]}
        ]
    )

    ids = [i.id for i in instances]
    if ids:
        ec2.instances.filter(InstanceIds=ids).stop()
        print(f"Stopped: {ids}")
```

### Créer une Instance

```python
import boto3

ec2 = boto3.resource("ec2")

def create_instance(
    name,
    instance_type="t3.micro",
    ami_id="ami-0123456789",
    key_name="my-key",
    security_groups=None,
    subnet_id=None,
    user_data=None
):
    """Crée une nouvelle instance EC2."""

    instances = ec2.create_instances(
        ImageId=ami_id,
        InstanceType=instance_type,
        KeyName=key_name,
        MinCount=1,
        MaxCount=1,
        SecurityGroupIds=security_groups or [],
        SubnetId=subnet_id,
        UserData=user_data or "",
        TagSpecifications=[
            {
                "ResourceType": "instance",
                "Tags": [
                    {"Key": "Name", "Value": name},
                    {"Key": "Environment", "Value": "development"},
                    {"Key": "ManagedBy", "Value": "Python"}
                ]
            }
        ]
    )

    instance = instances[0]
    instance.wait_until_running()
    instance.reload()

    return {
        "id": instance.id,
        "public_ip": instance.public_ip_address,
        "private_ip": instance.private_ip_address
    }

# Exemple avec user data
user_data = """#!/bin/bash
yum update -y
yum install -y nginx
systemctl start nginx
systemctl enable nginx
"""

instance = create_instance(
    name="web-server",
    instance_type="t3.small",
    user_data=user_data
)
```

---

## 3. Amazon S3

### Opérations de Base

```python
import boto3
from botocore.exceptions import ClientError

s3 = boto3.client("s3")
s3_resource = boto3.resource("s3")

def list_buckets():
    """Liste tous les buckets."""
    response = s3.list_buckets()
    return [b["Name"] for b in response["Buckets"]]

def create_bucket(name, region="eu-west-1"):
    """Crée un bucket."""
    try:
        s3.create_bucket(
            Bucket=name,
            CreateBucketConfiguration={"LocationConstraint": region}
        )
        return True
    except ClientError as e:
        print(f"Erreur: {e}")
        return False

def delete_bucket(name, force=False):
    """Supprime un bucket."""
    bucket = s3_resource.Bucket(name)

    if force:
        # Supprimer tous les objets d'abord
        bucket.objects.all().delete()
        bucket.object_versions.all().delete()

    bucket.delete()
```

### Upload et Download

```python
import boto3
from pathlib import Path

s3 = boto3.client("s3")

def upload_file(local_path, bucket, s3_key, metadata=None):
    """Upload un fichier vers S3."""
    extra_args = {}
    if metadata:
        extra_args["Metadata"] = metadata

    s3.upload_file(
        str(local_path),
        bucket,
        s3_key,
        ExtraArgs=extra_args
    )
    print(f"Uploaded: s3://{bucket}/{s3_key}")

def download_file(bucket, s3_key, local_path):
    """Download un fichier depuis S3."""
    Path(local_path).parent.mkdir(parents=True, exist_ok=True)
    s3.download_file(bucket, s3_key, str(local_path))
    print(f"Downloaded: {local_path}")

def upload_directory(local_dir, bucket, prefix=""):
    """Upload un répertoire complet."""
    local_path = Path(local_dir)

    for file_path in local_path.rglob("*"):
        if file_path.is_file():
            relative = file_path.relative_to(local_path)
            s3_key = f"{prefix}/{relative}" if prefix else str(relative)
            upload_file(file_path, bucket, s3_key)

# Avec callback de progression
def upload_with_progress(local_path, bucket, s3_key):
    """Upload avec barre de progression."""
    from rich.progress import Progress

    file_size = Path(local_path).stat().st_size

    with Progress() as progress:
        task = progress.add_task("Uploading...", total=file_size)

        def callback(bytes_transferred):
            progress.update(task, completed=bytes_transferred)

        s3.upload_file(
            str(local_path),
            bucket,
            s3_key,
            Callback=callback
        )
```

### Gestion des Objets

```python
import boto3
from datetime import datetime, timedelta

s3 = boto3.client("s3")

def list_objects(bucket, prefix=""):
    """Liste les objets d'un bucket."""
    paginator = s3.get_paginator("list_objects_v2")

    objects = []
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        for obj in page.get("Contents", []):
            objects.append({
                "key": obj["Key"],
                "size": obj["Size"],
                "modified": obj["LastModified"]
            })

    return objects

def delete_objects(bucket, keys):
    """Supprime plusieurs objets."""
    objects = [{"Key": k} for k in keys]
    s3.delete_objects(
        Bucket=bucket,
        Delete={"Objects": objects}
    )

def generate_presigned_url(bucket, key, expiration=3600):
    """Génère une URL signée temporaire."""
    url = s3.generate_presigned_url(
        "get_object",
        Params={"Bucket": bucket, "Key": key},
        ExpiresIn=expiration
    )
    return url

def copy_object(source_bucket, source_key, dest_bucket, dest_key):
    """Copie un objet entre buckets."""
    s3.copy_object(
        CopySource={"Bucket": source_bucket, "Key": source_key},
        Bucket=dest_bucket,
        Key=dest_key
    )
```

---

## 4. Autres Services AWS

### Systems Manager (SSM)

```python
import boto3

ssm = boto3.client("ssm")

def get_parameter(name, decrypt=True):
    """Récupère un paramètre SSM."""
    response = ssm.get_parameter(
        Name=name,
        WithDecryption=decrypt
    )
    return response["Parameter"]["Value"]

def put_parameter(name, value, param_type="SecureString"):
    """Stocke un paramètre SSM."""
    ssm.put_parameter(
        Name=name,
        Value=value,
        Type=param_type,
        Overwrite=True
    )

def run_command(instance_ids, commands):
    """Exécute des commandes via SSM."""
    response = ssm.send_command(
        InstanceIds=instance_ids,
        DocumentName="AWS-RunShellScript",
        Parameters={"commands": commands}
    )
    return response["Command"]["CommandId"]

def get_command_output(command_id, instance_id):
    """Récupère la sortie d'une commande."""
    import time

    while True:
        response = ssm.get_command_invocation(
            CommandId=command_id,
            InstanceId=instance_id
        )
        status = response["Status"]

        if status in ["Success", "Failed", "Cancelled"]:
            return {
                "status": status,
                "stdout": response.get("StandardOutputContent", ""),
                "stderr": response.get("StandardErrorContent", "")
            }

        time.sleep(2)
```

### Secrets Manager

```python
import boto3
import json

secrets = boto3.client("secretsmanager")

def get_secret(secret_name):
    """Récupère un secret."""
    response = secrets.get_secret_value(SecretId=secret_name)

    if "SecretString" in response:
        return json.loads(response["SecretString"])
    return response["SecretBinary"]

def create_secret(name, value):
    """Crée un nouveau secret."""
    secrets.create_secret(
        Name=name,
        SecretString=json.dumps(value) if isinstance(value, dict) else value
    )

def update_secret(name, value):
    """Met à jour un secret."""
    secrets.put_secret_value(
        SecretId=name,
        SecretString=json.dumps(value) if isinstance(value, dict) else value
    )

# Utilisation
db_creds = get_secret("production/database")
print(db_creds["username"])
print(db_creds["password"])
```

### CloudWatch

```python
import boto3
from datetime import datetime, timedelta

cloudwatch = boto3.client("cloudwatch")
logs = boto3.client("logs")

def get_metric(namespace, metric_name, dimensions, period=300, hours=1):
    """Récupère des métriques CloudWatch."""
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(hours=hours)

    response = cloudwatch.get_metric_statistics(
        Namespace=namespace,
        MetricName=metric_name,
        Dimensions=dimensions,
        StartTime=start_time,
        EndTime=end_time,
        Period=period,
        Statistics=["Average", "Maximum", "Minimum"]
    )

    return response["Datapoints"]

def get_ec2_cpu(instance_id, hours=1):
    """Récupère le CPU d'une instance EC2."""
    return get_metric(
        namespace="AWS/EC2",
        metric_name="CPUUtilization",
        dimensions=[{"Name": "InstanceId", "Value": instance_id}],
        hours=hours
    )

def put_custom_metric(namespace, metric_name, value, unit="Count"):
    """Publie une métrique personnalisée."""
    cloudwatch.put_metric_data(
        Namespace=namespace,
        MetricData=[
            {
                "MetricName": metric_name,
                "Value": value,
                "Unit": unit,
                "Timestamp": datetime.utcnow()
            }
        ]
    )

def get_log_events(log_group, log_stream, limit=100):
    """Récupère les événements d'un log."""
    response = logs.get_log_events(
        logGroupName=log_group,
        logStreamName=log_stream,
        limit=limit
    )
    return response["events"]
```

### Lambda

```python
import boto3
import json
import zipfile
from io import BytesIO

lambda_client = boto3.client("lambda")

def invoke_lambda(function_name, payload):
    """Invoque une fonction Lambda."""
    response = lambda_client.invoke(
        FunctionName=function_name,
        InvocationType="RequestResponse",
        Payload=json.dumps(payload)
    )

    return json.loads(response["Payload"].read())

def invoke_async(function_name, payload):
    """Invoque une Lambda de manière asynchrone."""
    lambda_client.invoke(
        FunctionName=function_name,
        InvocationType="Event",
        Payload=json.dumps(payload)
    )

def update_lambda_code(function_name, code_path):
    """Met à jour le code d'une Lambda."""
    # Créer un ZIP en mémoire
    zip_buffer = BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.write(code_path, "lambda_function.py")

    lambda_client.update_function_code(
        FunctionName=function_name,
        ZipFile=zip_buffer.getvalue()
    )
```

---

## 5. Infrastructure as Code

### Gestionnaire d'Infrastructure

```python
import boto3
from dataclasses import dataclass, field
from typing import List, Dict
import yaml

@dataclass
class InfraConfig:
    name: str
    environment: str
    vpc_cidr: str = "10.0.0.0/16"
    instance_type: str = "t3.micro"
    instance_count: int = 1
    tags: Dict[str, str] = field(default_factory=dict)

class InfraManager:
    """Gestionnaire d'infrastructure AWS."""

    def __init__(self, config: InfraConfig):
        self.config = config
        self.ec2 = boto3.resource("ec2")
        self.ec2_client = boto3.client("ec2")

    def create_vpc(self):
        """Crée un VPC."""
        vpc = self.ec2.create_vpc(CidrBlock=self.config.vpc_cidr)
        vpc.create_tags(Tags=[
            {"Key": "Name", "Value": f"{self.config.name}-vpc"},
            {"Key": "Environment", "Value": self.config.environment}
        ])
        vpc.wait_until_available()
        return vpc

    def create_subnet(self, vpc_id, cidr, az):
        """Crée un subnet."""
        subnet = self.ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=cidr,
            AvailabilityZone=az
        )
        subnet.create_tags(Tags=[
            {"Key": "Name", "Value": f"{self.config.name}-subnet"}
        ])
        return subnet

    def create_security_group(self, vpc_id, rules):
        """Crée un security group."""
        sg = self.ec2.create_security_group(
            GroupName=f"{self.config.name}-sg",
            Description=f"Security group for {self.config.name}",
            VpcId=vpc_id
        )

        for rule in rules:
            sg.authorize_ingress(
                IpProtocol=rule.get("protocol", "tcp"),
                FromPort=rule["port"],
                ToPort=rule["port"],
                CidrIp=rule.get("cidr", "0.0.0.0/0")
            )

        return sg

    def deploy(self):
        """Déploie l'infrastructure complète."""
        print(f"Deploying {self.config.name}...")

        # Créer VPC
        vpc = self.create_vpc()
        print(f"Created VPC: {vpc.id}")

        # Créer subnet
        subnet = self.create_subnet(
            vpc.id,
            "10.0.1.0/24",
            "eu-west-1a"
        )
        print(f"Created Subnet: {subnet.id}")

        # Créer security group
        sg = self.create_security_group(vpc.id, [
            {"port": 22},
            {"port": 80},
            {"port": 443}
        ])
        print(f"Created SG: {sg.id}")

        return {
            "vpc_id": vpc.id,
            "subnet_id": subnet.id,
            "security_group_id": sg.id
        }

# Utilisation
config = InfraConfig(
    name="myapp",
    environment="production",
    instance_type="t3.small",
    instance_count=2
)

manager = InfraManager(config)
resources = manager.deploy()
```

### Cleanup Automatique

```python
import boto3
from datetime import datetime, timedelta

def cleanup_old_resources(days=7, dry_run=True):
    """Nettoie les ressources anciennes."""
    ec2 = boto3.resource("ec2")
    cutoff = datetime.now(tz=timezone.utc) - timedelta(days=days)

    # Snapshots anciens
    snapshots = ec2.snapshots.filter(OwnerIds=["self"])
    for snap in snapshots:
        if snap.start_time < cutoff:
            print(f"Would delete snapshot: {snap.id}")
            if not dry_run:
                snap.delete()

    # AMIs anciennes
    client = boto3.client("ec2")
    images = client.describe_images(Owners=["self"])
    for img in images["Images"]:
        created = datetime.fromisoformat(img["CreationDate"].replace("Z", "+00:00"))
        if created < cutoff:
            print(f"Would deregister AMI: {img['ImageId']}")
            if not dry_run:
                client.deregister_image(ImageId=img["ImageId"])

    # Volumes non attachés
    volumes = ec2.volumes.filter(
        Filters=[{"Name": "status", "Values": ["available"]}]
    )
    for vol in volumes:
        print(f"Would delete unattached volume: {vol.id}")
        if not dry_run:
            vol.delete()
```

---

## 6. Patterns Cloud

### Cost Explorer

```python
import boto3
from datetime import datetime, timedelta

ce = boto3.client("ce")

def get_monthly_costs(months=3):
    """Récupère les coûts mensuels."""
    end = datetime.now().replace(day=1)
    start = end - timedelta(days=months * 30)

    response = ce.get_cost_and_usage(
        TimePeriod={
            "Start": start.strftime("%Y-%m-%d"),
            "End": end.strftime("%Y-%m-%d")
        },
        Granularity="MONTHLY",
        Metrics=["UnblendedCost"],
        GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}]
    )

    costs = []
    for result in response["ResultsByTime"]:
        period = result["TimePeriod"]["Start"]
        for group in result["Groups"]:
            costs.append({
                "period": period,
                "service": group["Keys"][0],
                "cost": float(group["Metrics"]["UnblendedCost"]["Amount"])
            })

    return costs
```

### Auto Scaling Manager

```python
import boto3

autoscaling = boto3.client("autoscaling")

def scale_up(asg_name, count=1):
    """Augmente la capacité."""
    response = autoscaling.describe_auto_scaling_groups(
        AutoScalingGroupNames=[asg_name]
    )

    current = response["AutoScalingGroups"][0]["DesiredCapacity"]
    new_capacity = current + count

    autoscaling.set_desired_capacity(
        AutoScalingGroupName=asg_name,
        DesiredCapacity=new_capacity
    )

    return new_capacity

def scale_down(asg_name, count=1):
    """Réduit la capacité."""
    response = autoscaling.describe_auto_scaling_groups(
        AutoScalingGroupNames=[asg_name]
    )

    current = response["AutoScalingGroups"][0]["DesiredCapacity"]
    new_capacity = max(1, current - count)

    autoscaling.set_desired_capacity(
        AutoScalingGroupName=asg_name,
        DesiredCapacity=new_capacity
    )

    return new_capacity
```

---

## Exercices Pratiques

### Exercice 1 : Backup S3 Automatique

```python
# Créer un script qui :
# - Scanne les instances EC2 avec un tag "Backup=true"
# - Crée des snapshots EBS
# - Les upload vers S3
# - Nettoie les anciens backups
```

### Exercice 2 : Monitoring Dashboard

```python
# Créer un script qui :
# - Collecte les métriques de toutes les instances
# - Génère un rapport HTML
# - L'envoie par email via SES
```

### Exercice 3 : Infrastructure Scheduler

```python
# Créer un outil qui :
# - Démarre les instances de dev à 8h
# - Les arrête à 20h
# - Gère les week-ends
# - Supporte les exceptions
```

---

## Points Clés à Retenir

!!! success "Bonnes Pratiques"
    - Utiliser des rôles IAM plutôt que des clés
    - Implémenter des retry avec backoff
    - Taguer toutes les ressources
    - Utiliser des régions multiples pour la résilience

!!! warning "Sécurité"
    - Ne jamais commiter les credentials
    - Utiliser Secrets Manager pour les secrets
    - Appliquer le principe du moindre privilège
    - Chiffrer les données sensibles

---

## Voir Aussi

- [Module 13 - Outils CLI](13-cli.md)
- [Module 15 - Tests & Qualité](15-tests.md)
- [Cheatsheet Bibliothèques](cheatsheet-libs.md)

---

## Navigation

| | |
|:---|---:|
| [← Module 13 - Création d'Outils CLI](13-cli.md) | [Module 15 - Tests & Qualité du Code →](15-tests.md) |

[Retour au Programme](index.md){ .md-button }
