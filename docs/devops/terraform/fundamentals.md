# Terraform: Infrastructure as Code

`#terraform` `#iac` `#hcl` `#aws` `#state`

Définir, provisionner et gérer l'infrastructure cloud de manière déclarative.

---

## Pourquoi Terraform ?

### Le Problème : Configuration Manuelle

**Scénario classique :**

```
Dev  : "J'ai besoin d'un serveur web avec une BDD"
Ops  : *Clique 47 fois dans la console AWS*
Ops  : "C'est fait, note bien l'IP : 54.123.45.67"
Dev  : "Peux-tu recréer la même chose en staging ?"
Ops  : "Euh... je ne me souviens plus de toutes les config..."
```

**Problèmes :**
- Non reproductible (Configuration Drift)
- Pas de versioning (impossible de rollback)
- Erreurs humaines (oubli de firewall, mauvais subnet...)
- Pas de collaboration (qui a modifié quoi ?)

### La Solution : Infrastructure as Code

```mermaid
flowchart LR
    A[Write HCL Code] -->|1. terraform plan| B[Execution Plan]
    B -->|2. Review Changes| C{Approve?}
    C -->|Yes| D[terraform apply]
    C -->|No| A
    D -->|3. API Calls| E[Cloud Provider]
    E -->|4. Resources Created| F[terraform.tfstate]
    F -->|5. Track State| D
```

**Workflow déclaratif :**
1. **Write** : Vous décrivez l'infrastructure souhaitée (HCL)
2. **Plan** : Terraform calcule les changements nécessaires
3. **Apply** : Terraform crée/modifie/supprime les ressources
4. **State** : Terraform garde une trace de l'infrastructure réelle

!!! success "Bénéfices"
    - **Reproductible** : Le même code produit toujours la même infra
    - **Versionné** : Git devient la source de vérité
    - **Collaboratif** : Code Review sur l'infrastructure
    - **Multi-cloud** : AWS, Azure, GCP avec la même syntaxe
    - **Rollback** : `git revert` = infrastructure rollback

---

## Section 1 : Concepts & HCL

### Le Langage HCL (HashiCorp Configuration Language)

**HCL = JSON lisible par un humain**

```hcl
# Syntaxe de base
<BLOCK_TYPE> "<BLOCK_LABEL>" "<BLOCK_NAME>" {
  argument = "value"
  nested_block {
    key = "value"
  }
}
```

### Les 5 Blocs Essentiels

#### 1. Provider : Connexion au Cloud

```hcl
# Spécifie le fournisseur cloud
provider "aws" {
  region = "eu-west-1"

  # Best Practice : Ne jamais mettre les credentials en dur !
  # Utiliser AWS_ACCESS_KEY_ID et AWS_SECRET_ACCESS_KEY
}

# Toujours fixer la version (production requirement)
terraform {
  required_version = ">= 1.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"  # Autorise 5.x mais pas 6.0
    }
  }
}
```

#### 2. Resource : Créer une Infrastructure

```hcl
# Créer une instance EC2
resource "aws_instance" "web_server" {
  ami           = "ami-0c55b159cbfafe1f0"  # Ubuntu 22.04
  instance_type = "t3.micro"

  tags = {
    Name        = "WebServer"
    Environment = "Production"
    ManagedBy   = "Terraform"
  }

  # Meta-argument : Créer 3 instances
  count = 3
}

# Référencer une ressource : <TYPE>.<NAME>.<ATTRIBUTE>
output "instance_id" {
  value = aws_instance.web_server[0].id
}
```

#### 3. Data Source : Lire une Infrastructure Existante

```hcl
# Récupérer l'AMI Ubuntu la plus récente
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"]  # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }
}

# Utiliser la data source
resource "aws_instance" "web" {
  ami = data.aws_ami.ubuntu.id  # Toujours l'AMI la plus récente
  instance_type = "t3.micro"
}
```

#### 4. Variable : Paramétrer le Code

```hcl
# Définition dans variables.tf
variable "instance_type" {
  description = "Type d'instance EC2"
  type        = string
  default     = "t3.micro"

  validation {
    condition     = contains(["t3.micro", "t3.small"], var.instance_type)
    error_message = "Seuls t3.micro et t3.small sont autorisés en dev."
  }
}

variable "environment" {
  type = string
}

# Utilisation dans main.tf
resource "aws_instance" "app" {
  instance_type = var.instance_type

  tags = {
    Environment = var.environment
  }
}
```

**Ordre de priorité des valeurs :**
1. CLI : `terraform apply -var="environment=prod"`
2. Fichier : `terraform.tfvars` ou `*.auto.tfvars`
3. Variable d'environnement : `TF_VAR_environment=prod`
4. Valeur par défaut dans `variables.tf`

```hcl
# terraform.tfvars (à ne JAMAIS commiter si secrets)
environment   = "production"
instance_type = "t3.small"
```

#### 5. Output : Exposer des Informations

```hcl
# Afficher l'IP publique après apply
output "instance_public_ip" {
  description = "IP publique du serveur web"
  value       = aws_instance.web_server.public_ip
  sensitive   = false
}

# Masquer les secrets
output "db_password" {
  value     = aws_db_instance.main.password
  sensitive = true  # Ne s'affiche pas dans les logs
}
```

### Exemple Complet : Provisionner un Fichier Local

```hcl
# main.tf (exemple simple sans cloud)
terraform {
  required_version = ">= 1.0"
}

# Créer un fichier local
resource "local_file" "example" {
  filename = "${path.module}/generated.txt"
  content  = "Infrastructure provisioned at ${timestamp()}"
}

output "file_path" {
  value = local_file.example.filename
}
```

**Exécution :**
```bash
$ terraform init
$ terraform apply -auto-approve
local_file.example: Creating...
local_file.example: Creation complete after 0s

Outputs:
file_path = "./generated.txt"
```

---

## Section 2 : Le Cycle de Vie (CLI)

### Workflow Standard

```mermaid
flowchart TD
    A[terraform init] --> B[terraform fmt]
    B --> C[terraform validate]
    C --> D[terraform plan -out=tfplan]
    D --> E{Plan OK?}
    E -->|Yes| F[terraform apply tfplan]
    E -->|No| G[Fix Code]
    G --> B
    F --> H[terraform output]
    H --> I[Infrastructure Ready]
```

### 1. `terraform init` : Initialisation

**Première commande à exécuter dans un nouveau projet.**

```bash
$ terraform init

Initializing the backend...
Initializing provider plugins...
- Finding hashicorp/aws versions matching "~> 5.0"...
- Installing hashicorp/aws v5.31.0...

Terraform has been successfully initialized!
```

**Ce qui se passe :**
- Télécharge les providers dans `.terraform/`
- Initialise le backend (local ou S3)
- Crée le fichier `.terraform.lock.hcl` (équivalent de `package-lock.json`)

!!! tip "À Réexécuter Quand"
    - Nouveau provider ajouté
    - Changement de backend (local → S3)
    - Clonage du repo Git (`git clone` → `terraform init`)

### 2. `terraform fmt` & `validate` : Linting

**Indispensable en équipe : formater le code.**

```bash
# Formater automatiquement tous les fichiers .tf
$ terraform fmt -recursive

# Vérifier la syntaxe HCL
$ terraform validate
Success! The configuration is valid.
```

**Intégration CI/CD :**
```yaml
# .github/workflows/terraform.yml
- name: Terraform Format Check
  run: terraform fmt -check -recursive
  # Échoue si le code n'est pas formaté
```

### 3. `terraform plan` : Prévisualisation (Sécurité)

**Règle d'Or : Toujours sauvegarder le plan avant apply.**

```bash
# Générer le plan d'exécution
$ terraform plan -out=tfplan

Terraform will perform the following actions:

  # aws_instance.web_server will be created
  + resource "aws_instance" "web_server" {
      + ami                    = "ami-0c55b159cbfafe1f0"
      + instance_type          = "t3.micro"
      + public_ip              = (known after apply)
    }

Plan: 1 to add, 0 to change, 0 to destroy.

Saved the plan to: tfplan
```

**Symboles du plan :**
- `+` : Ressource à créer
- `-` : Ressource à détruire
- `~` : Ressource à modifier (in-place)
- `-/+` : Ressource à remplacer (destroy + create)
- `<=` : Data source à lire

!!! warning "Plan ≠ Garantie"
    Le plan peut devenir invalide si :
    - Quelqu'un modifie l'infra manuellement (Console AWS)
    - Une autre instance Terraform applique des changements
    - → Toujours utiliser le **State Locking** (cf. Section 3)

### 4. `terraform apply` : Application Stricte

**Appliquer exactement le plan validé.**

```bash
# ❌ Mauvaise Pratique : Apply sans plan sauvegardé
$ terraform apply

# ✅ Bonne Pratique : Apply avec plan
$ terraform apply "tfplan"

aws_instance.web_server: Creating...
aws_instance.web_server: Creation complete after 42s [id=i-0abc123def456]

Apply complete! Resources: 1 added, 0 changed, 0 destroyed.
```

**Pourquoi sauvegarder le plan ?**
```
1. DevOps exécute `terraform plan -out=tfplan`
2. Lead Architect review le plan
3. 3 heures plus tard, quelqu'un lance `terraform apply`
   → Sans tfplan, Terraform recalcule le plan (peut différer !)
   → Avec tfplan, applique EXACTEMENT ce qui a été validé
```

### 5. Autres Commandes Essentielles

```bash
# Lister toutes les ressources gérées
$ terraform state list
aws_instance.web_server
aws_security_group.allow_http

# Afficher les détails d'une ressource
$ terraform state show aws_instance.web_server

# Afficher les outputs
$ terraform output
instance_public_ip = "54.123.45.67"

# Détruire toute l'infrastructure (DANGER)
$ terraform destroy
Plan: 0 to add, 0 to change, 5 to destroy.
Do you really want to destroy all resources? yes
```

---

## Section 3 : State Management (Critique)

### Le Fichier `terraform.tfstate`

**State = Source de vérité de Terraform**

```json
{
  "version": 4,
  "terraform_version": "1.6.0",
  "resources": [
    {
      "type": "aws_instance",
      "name": "web_server",
      "provider": "provider[\"registry.terraform.io/hashicorp/aws\"]",
      "instances": [
        {
          "attributes": {
            "id": "i-0abc123def456",
            "public_ip": "54.123.45.67",
            "private_key": "-----BEGIN RSA PRIVATE KEY-----\n..."
          }
        }
      ]
    }
  ]
}
```

!!! danger "SECRETS EN CLAIR"
    Le fichier `terraform.tfstate` contient :

    - Mots de passe de bases de données
    - Clés privées SSH
    - API tokens
    - Tous les attributs sensibles

    **Ne JAMAIS commiter `terraform.tfstate` dans Git !**

### Règle d'Or : Remote Backend

**Problème du state local :**

| Scénario | Problème |
|----------|----------|
| **Équipe** | Alice et Bob ont chacun leur `tfstate` local → Incohérences |
| **CI/CD** | Pipeline GitHub Actions ne peut pas accéder au fichier local |
| **Concurrence** | Deux `terraform apply` simultanés → Corruption du state |
| **Secrets** | State en clair sur le disque dur |

**Solution : Remote Backend avec S3 + DynamoDB**

```hcl
# backend.tf
terraform {
  backend "s3" {
    # Stockage du state
    bucket = "my-company-terraform-state"
    key    = "production/infrastructure.tfstate"
    region = "eu-west-1"

    # Chiffrement au repos
    encrypt = true

    # State Locking (empêche les apply simultanés)
    dynamodb_table = "terraform-state-lock"

    # Optionnel : Versionning pour rollback
    # → Activer le versioning sur le bucket S3
  }
}
```

**Prérequis AWS :**

```bash
# 1. Créer le bucket S3
aws s3api create-bucket \
  --bucket my-company-terraform-state \
  --region eu-west-1 \
  --create-bucket-configuration LocationConstraint=eu-west-1

# 2. Activer le versioning (rollback en cas d'erreur)
aws s3api put-bucket-versioning \
  --bucket my-company-terraform-state \
  --versioning-configuration Status=Enabled

# 3. Activer le chiffrement
aws s3api put-bucket-encryption \
  --bucket my-company-terraform-state \
  --server-side-encryption-configuration '{
    "Rules": [{
      "ApplyServerSideEncryptionByDefault": {
        "SSEAlgorithm": "AES256"
      }
    }]
  }'

# 4. Créer la table DynamoDB pour le locking
aws dynamodb create-table \
  --table-name terraform-state-lock \
  --attribute-definitions AttributeName=LockID,AttributeType=S \
  --key-schema AttributeName=LockID,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST \
  --region eu-west-1
```

**Migration du state local vers S3 :**

```bash
# 1. Ajouter le bloc backend dans backend.tf
# 2. Réinitialiser
$ terraform init -migrate-state

Initializing the backend...
Do you want to copy existing state to the new backend? yes

Successfully configured the backend "s3"!
```

### State Locking : Éviter les Conflits

**Sans Locking :**
```
┌─────────────┐         ┌─────────────┐
│  Alice      │         │    Bob      │
│ terraform   │         │ terraform   │
│   apply     │         │   apply     │
└──────┬──────┘         └──────┬──────┘
       │                       │
       ├───────┐       ┌───────┤
       │       ▼       ▼       │
       │   ┌─────────────┐     │
       │   │    State    │     │
       │   │  CORRUPTION │     │
       └───┴─────────────┴─────┘
```

**Avec DynamoDB Locking :**
```
Alice: terraform apply
  → Acquire Lock ✅
  → Apply changes
  → Release Lock

Bob: terraform apply (pendant qu'Alice travaille)
  → Wait for Lock...
  → Lock acquired after Alice
  → Apply changes
```

**Forcer le unlock (en cas de blocage) :**
```bash
# Si un apply a crashé et laissé le lock
$ terraform force-unlock <LOCK_ID>
```

---

## Section 4 : Modularité & Variables

### Variables : Paramétrer le Code

#### Types de Variables

```hcl
# variables.tf
variable "instance_type" {
  description = "Type d'instance EC2"
  type        = string
  default     = "t3.micro"
}

variable "enable_monitoring" {
  type    = bool
  default = true
}

variable "allowed_ports" {
  type    = list(number)
  default = [80, 443, 22]
}

variable "tags" {
  type = map(string)
  default = {
    Environment = "dev"
    Team        = "platform"
  }
}

variable "database_config" {
  type = object({
    engine         = string
    engine_version = string
    instance_class = string
  })
  default = {
    engine         = "postgres"
    engine_version = "15.4"
    instance_class = "db.t3.micro"
  }
}
```

#### Fichiers de Variables

```hcl
# terraform.tfvars (chargé automatiquement)
instance_type = "t3.small"
environment   = "production"

# dev.tfvars (chargé avec -var-file)
instance_type = "t3.micro"
environment   = "development"
```

**Utilisation :**
```bash
$ terraform apply -var-file="dev.tfvars"
```

#### Variables d'Environnement

```bash
# Préfixe TF_VAR_
export TF_VAR_instance_type="t3.large"
export TF_VAR_environment="staging"

$ terraform apply
# Utilise automatiquement les variables d'environnement
```

### Modules : Réutiliser le Code

**Problème : Tout dans `main.tf`**

```hcl
# main.tf (800 lignes 😱)
resource "aws_vpc" "main" { ... }
resource "aws_subnet" "public_1" { ... }
resource "aws_subnet" "public_2" { ... }
resource "aws_security_group" "web" { ... }
resource "aws_instance" "web_1" { ... }
resource "aws_instance" "web_2" { ... }
resource "aws_lb" "main" { ... }
resource "aws_db_instance" "postgres" { ... }
# ... 50 autres ressources
```

**Solution : Modules**

```
.
├── main.tf
├── variables.tf
├── outputs.tf
└── modules/
    ├── vpc/
    │   ├── main.tf
    │   ├── variables.tf
    │   └── outputs.tf
    ├── ec2/
    │   ├── main.tf
    │   ├── variables.tf
    │   └── outputs.tf
    └── rds/
        ├── main.tf
        ├── variables.tf
        └── outputs.tf
```

#### Créer un Module

```hcl
# modules/ec2/main.tf
resource "aws_instance" "this" {
  ami           = var.ami
  instance_type = var.instance_type

  tags = merge(
    var.tags,
    {
      Name = var.name
    }
  )
}

# modules/ec2/variables.tf
variable "name" {
  type = string
}

variable "ami" {
  type = string
}

variable "instance_type" {
  type = string
}

variable "tags" {
  type    = map(string)
  default = {}
}

# modules/ec2/outputs.tf
output "instance_id" {
  value = aws_instance.this.id
}

output "public_ip" {
  value = aws_instance.this.public_ip
}
```

#### Utiliser un Module

```hcl
# main.tf
module "web_server" {
  source = "./modules/ec2"

  name          = "WebServer"
  ami           = data.aws_ami.ubuntu.id
  instance_type = "t3.micro"

  tags = {
    Environment = "production"
    Team        = "platform"
  }
}

module "app_server" {
  source = "./modules/ec2"

  name          = "AppServer"
  ami           = data.aws_ami.ubuntu.id
  instance_type = "t3.small"

  tags = {
    Environment = "production"
    Team        = "backend"
  }
}

# Utiliser les outputs du module
output "web_ip" {
  value = module.web_server.public_ip
}
```

#### Modules Publics (Terraform Registry)

```hcl
# Utiliser le module VPC officiel AWS
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.1.2"

  name = "my-vpc"
  cidr = "10.0.0.0/16"

  azs             = ["eu-west-1a", "eu-west-1b"]
  private_subnets = ["10.0.1.0/24", "10.0.2.0/24"]
  public_subnets  = ["10.0.101.0/24", "10.0.102.0/24"]

  enable_nat_gateway = true
  enable_vpn_gateway = false

  tags = {
    Terraform   = "true"
    Environment = "production"
  }
}
```

---

## Section 5 : Bonnes Pratiques (SecNumCloud)

### 1. Sécrets : Ne Jamais en Dur

!!! danger "❌ NE JAMAIS FAIRE"
    ```hcl
    provider "aws" {
      access_key = "AKIAIOSFODNN7EXAMPLE"  # ❌ DANGER
      secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    }

    resource "aws_db_instance" "main" {
      password = "SuperSecretPassword123"  # ❌ DANGER
    }
    ```

#### Solution 1 : Variables d'Environnement

```bash
# ~/.bashrc ou CI/CD secrets
export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
export AWS_SECRET_ACCESS_KEY="wJalrXUt..."

# Terraform utilise automatiquement ces variables
$ terraform apply
```

#### Solution 2 : Terraform Variables

```hcl
# variables.tf
variable "db_password" {
  description = "Database master password"
  type        = string
  sensitive   = true
  # Pas de valeur par défaut pour forcer la saisie
}

# main.tf
resource "aws_db_instance" "main" {
  password = var.db_password
}
```

**Utilisation :**
```bash
# Prompt interactif
$ terraform apply
var.db_password
  Enter a value: ********

# Ou via variable d'environnement
$ export TF_VAR_db_password="SecurePassword"
$ terraform apply
```

#### Solution 3 : HashiCorp Vault

```hcl
# Récupérer un secret depuis Vault
data "vault_generic_secret" "db_password" {
  path = "secret/database/production"
}

resource "aws_db_instance" "main" {
  password = data.vault_generic_secret.db_password.data["password"]
}
```

#### Solution 4 : AWS Secrets Manager

```hcl
# Créer un secret aléatoire
resource "random_password" "db_password" {
  length  = 32
  special = true
}

# Stocker dans AWS Secrets Manager
resource "aws_secretsmanager_secret" "db_password" {
  name = "production-db-password"
}

resource "aws_secretsmanager_secret_version" "db_password" {
  secret_id     = aws_secretsmanager_secret.db_password.id
  secret_string = random_password.db_password.result
}

# Utiliser le secret
resource "aws_db_instance" "main" {
  password = random_password.db_password.result
}
```

### 2. Version Pinning : Éviter les Surprises

**Problème sans version fixe :**
```
Dev  : "Mon code fonctionne en local"
CI/CD: "terraform apply échoue !"
Cause: Nouveau provider AWS 6.0 avec breaking changes
```

**Solution : Toujours fixer les versions**

```hcl
# versions.tf
terraform {
  # Version de Terraform
  required_version = ">= 1.6.0, < 2.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.31"  # 5.31.x autorisé, pas 5.32 ou 6.0
    }

    random = {
      source  = "hashicorp/random"
      version = "= 3.6.0"  # Version exacte
    }
  }
}
```

**Opérateurs de version :**
- `= 5.31.0` : Version exacte uniquement
- `>= 5.0` : 5.0 ou supérieur
- `~> 5.31` : 5.31.x (patch autorisé, pas minor)
- `>= 5.0, < 6.0` : Plage de versions

### 3. `.gitignore` : Fichiers à Exclure

```gitignore
# .gitignore pour projet Terraform

# State files (CONTIENNENT DES SECRETS)
*.tfstate
*.tfstate.*
*.tfstate.backup

# Crash logs
crash.log
crash.*.log

# Variables locales (peuvent contenir des secrets)
*.tfvars
*.tfvars.json
!example.tfvars  # Sauf les fichiers d'exemple

# Override files (personnalisations locales)
override.tf
override.tf.json
*_override.tf
*_override.tf.json

# CLI configuration files
.terraformrc
terraform.rc

# Répertoires générés
.terraform/
.terraform.lock.hcl  # Debatable : certains le committent pour reproducibilité

# Plans générés
*.tfplan
tfplan

# IDE
.idea/
.vscode/
*.swp
*.swo
```

### 4. Structure de Projet Standard

```
terraform-infrastructure/
├── environments/
│   ├── dev/
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   ├── terraform.tfvars  # Git-ignored
│   │   ├── backend.tf
│   │   └── outputs.tf
│   ├── staging/
│   │   └── ...
│   └── production/
│       └── ...
├── modules/
│   ├── vpc/
│   ├── ec2/
│   ├── rds/
│   └── s3/
├── .gitignore
├── README.md
└── versions.tf
```

### 5. Commentaires & Documentation

```hcl
# Utiliser des commentaires pour expliquer le "pourquoi"
resource "aws_security_group" "web" {
  name        = "web-server-sg"
  description = "Allow HTTP/HTTPS from CloudFlare IPs only"

  # CloudFlare IP ranges (updated 2024-01)
  # Source: https://www.cloudflare.com/ips/
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["173.245.48.0/20", "103.21.244.0/22"]
    description = "HTTPS from CloudFlare"
  }
}
```

### 6. Checklist Pré-Production

- [ ] **State** : Remote backend S3 configuré
- [ ] **Locking** : DynamoDB table créée
- [ ] **Secrets** : Aucun secret en dur dans le code
- [ ] **Versions** : `required_version` et `required_providers` définis
- [ ] **Gitignore** : `*.tfstate`, `*.tfvars` exclus
- [ ] **Tagging** : Toutes les ressources ont des tags (Environment, ManagedBy, Team)
- [ ] **Validation** : `terraform fmt` + `terraform validate` passent
- [ ] **Plan Review** : Le plan a été reviewé par un Senior
- [ ] **Backup** : Versioning activé sur le bucket S3 du state

---

## Référence Rapide

### Commandes Essentielles

```bash
# Installation & Initialisation
terraform version                    # Vérifier la version installée
terraform init                       # Initialiser le projet
terraform init -upgrade              # Mettre à jour les providers

# Développement
terraform fmt -recursive             # Formater le code
terraform validate                   # Valider la syntaxe HCL
terraform console                    # Console interactive (tester des expressions)

# Planning & Application
terraform plan                       # Prévisualiser les changements
terraform plan -out=tfplan           # Sauvegarder le plan
terraform apply "tfplan"             # Appliquer le plan sauvegardé
terraform apply -auto-approve        # Apply sans confirmation (CI/CD uniquement)

# Gestion du State
terraform state list                 # Lister toutes les ressources
terraform state show <RESOURCE>      # Afficher les détails d'une ressource
terraform state mv <SRC> <DEST>      # Renommer une ressource dans le state
terraform state rm <RESOURCE>        # Retirer une ressource du state (ne la détruit pas)
terraform state pull                 # Télécharger le state distant

# Outputs
terraform output                     # Afficher tous les outputs
terraform output <NAME>              # Afficher un output spécifique
terraform output -json               # Format JSON (pour scripts)

# Destruction
terraform destroy                    # Détruire toute l'infrastructure
terraform destroy -target=<RESOURCE> # Détruire une ressource spécifique

# Troubleshooting
terraform show                       # Afficher le state actuel
terraform graph | dot -Tpng > graph.png  # Générer un graphe de dépendances
terraform refresh                    # Mettre à jour le state (lecture seule)
TF_LOG=DEBUG terraform apply         # Activer les logs debug
```

### Meta-Arguments des Resources

```hcl
resource "aws_instance" "web" {
  # ... configuration ...

  # Créer N instances
  count = 3
  # Référence : aws_instance.web[0].id

  # OU créer des instances avec des noms
  for_each = toset(["web1", "web2", "web3"])
  # Référence : aws_instance.web["web1"].id

  # Dépendances explicites
  depends_on = [aws_security_group.allow_http]

  # Cycle de vie
  lifecycle {
    create_before_destroy = true     # Créer avant détruire (zero-downtime)
    prevent_destroy       = true     # Bloquer la destruction (protection)
    ignore_changes        = [tags]   # Ignorer les changements sur tags
  }

  # Provisionner après création (à éviter, préférer cloud-init)
  provisioner "local-exec" {
    command = "echo ${self.private_ip} >> private_ips.txt"
  }
}
```

### Functions Utiles

```hcl
# Strings
format("instance-%03d", count.index)  # → "instance-001"
join(", ", var.allowed_ips)           # → "10.0.0.1, 10.0.0.2"
split(",", "a,b,c")                   # → ["a", "b", "c"]

# Collections
length(var.subnets)                   # Nombre d'éléments
element(var.subnets, 0)               # Premier élément
concat(list1, list2)                  # Fusionner des listes
merge(map1, map2)                     # Fusionner des maps

# Fichiers
file("${path.module}/script.sh")      # Lire un fichier
templatefile("user-data.tpl", {       # Template avec variables
  hostname = var.hostname
})

# Conditionnels
var.env == "prod" ? "t3.large" : "t3.micro"  # Ternaire
```

### Ressources AWS Courantes

```hcl
# VPC & Networking
resource "aws_vpc" "main" { ... }
resource "aws_subnet" "public" { ... }
resource "aws_internet_gateway" "igw" { ... }
resource "aws_route_table" "public" { ... }
resource "aws_security_group" "allow_http" { ... }

# Compute
resource "aws_instance" "web" { ... }
resource "aws_launch_template" "app" { ... }
resource "aws_autoscaling_group" "app" { ... }

# Load Balancing
resource "aws_lb" "main" { ... }
resource "aws_lb_target_group" "app" { ... }
resource "aws_lb_listener" "https" { ... }

# Storage
resource "aws_s3_bucket" "data" { ... }
resource "aws_ebs_volume" "data" { ... }

# Database
resource "aws_db_instance" "postgres" { ... }
resource "aws_elasticache_cluster" "redis" { ... }

# IAM
resource "aws_iam_role" "app" { ... }
resource "aws_iam_policy" "app" { ... }
resource "aws_iam_role_policy_attachment" "app" { ... }
```

### Troubleshooting Courant

| Erreur | Cause | Solution |
|--------|-------|----------|
| `Error: No configuration files` | Pas de fichiers `.tf` dans le répertoire | Vérifier le `pwd` |
| `Error: Provider registry.terraform.io/hashicorp/aws not found` | `terraform init` pas exécuté | Lancer `terraform init` |
| `Error: Error acquiring the state lock` | Autre apply en cours ou crashé | `terraform force-unlock <LOCK_ID>` |
| `Error: Error loading state: AccessDenied` | Permissions S3 insuffisantes | Vérifier IAM policies |
| `Error: creating EC2 Instance: UnauthorizedOperation` | Credentials AWS invalides | Vérifier `AWS_ACCESS_KEY_ID` |
| `Error: Cycle` | Dépendances circulaires | Revoir les `depends_on` |

---

## Ressources

**Documentation Officielle :**
- [Terraform Registry](https://registry.terraform.io/)
- [AWS Provider](https://registry.terraform.io/providers/hashicorp/aws/latest/docs)
- [Best Practices](https://www.terraform-best-practices.com/)

**Formations :**
- [Xavki - Terraform sur YouTube](https://www.youtube.com/c/xavki)
- [HashiCorp Learn](https://learn.hashicorp.com/terraform)

**Outils Complémentaires :**
- `terraform-docs` : Générer la doc automatiquement
- `tflint` : Linter pour détecter les erreurs
- `checkov` : Scanner de sécurité
- `infracost` : Estimer les coûts AWS avant apply

---

**Next Steps :**
- [Terraform Workspaces](https://developer.hashicorp.com/terraform/language/state/workspaces) : Gérer plusieurs environnements (dev/staging/prod)
- [Terraform Cloud](https://cloud.hashicorp.com/products/terraform) : Remote execution & collaboration
- [Terragrunt](https://terragrunt.gruntwork.io/) : DRY Terraform (éviter la duplication de code)
