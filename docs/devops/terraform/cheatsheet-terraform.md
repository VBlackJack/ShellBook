---
title: "Terraform Cheatsheet"
description: "Essential Terraform commands, state management, and best practices"
tags: ["terraform", "iac", "devops", "cheatsheet"]
---

# Terraform Cheatsheet

## Core Commands

| Command | Description | Options |
|---------|-------------|---------|
| `terraform init` | Initialize working directory | `-upgrade` (update providers) |
| `terraform plan` | Preview changes | `-out=plan.tfplan` (save plan) |
| `terraform apply` | Apply changes | `-auto-approve` (skip confirmation) |
| `terraform destroy` | Destroy infrastructure | `-target=resource` (specific resource) |
| `terraform validate` | Validate configuration | |
| `terraform fmt` | Format code | `-recursive` (all subdirs) |
| `terraform output` | Show output values | `-json` (JSON format) |

## State Management

### State Commands

```bash
# List resources in state
terraform state list

# Show detailed resource state
terraform state show aws_instance.example

# Move resource in state
terraform state mv aws_instance.old aws_instance.new

# Remove resource from state (doesn't destroy)
terraform state rm aws_instance.example

# Pull current state
terraform state pull > terraform.tfstate

# Push state (dangerous!)
terraform state push terraform.tfstate

# Replace provider in state
terraform state replace-provider registry.terraform.io/hashicorp/aws registry.acme.corp/acme/aws
```

### Remote State Configuration

```hcl
terraform {
  backend "s3" {
    bucket         = "my-terraform-state"
    key            = "prod/terraform.tfstate"
    region         = "eu-west-1"
    encrypt        = true
    dynamodb_table = "terraform-locks"
  }
}
```

### State Locking

```bash
# Force unlock (use with caution)
terraform force-unlock <LOCK_ID>

# Import existing resource
terraform import aws_instance.example i-1234567890abcdef0
```

## Variables

### Variable Definition

```hcl
# variables.tf
variable "region" {
  description = "AWS region"
  type        = string
  default     = "eu-west-1"
}

variable "instance_count" {
  description = "Number of instances"
  type        = number
  default     = 2
  validation {
    condition     = var.instance_count > 0 && var.instance_count <= 10
    error_message = "Instance count must be between 1 and 10"
  }
}

variable "tags" {
  description = "Resource tags"
  type        = map(string)
  default = {
    Environment = "dev"
    Project     = "example"
  }
}

variable "availability_zones" {
  description = "List of AZs"
  type        = list(string)
  default     = ["eu-west-1a", "eu-west-1b"]
}

variable "instance_config" {
  description = "Instance configuration"
  type = object({
    instance_type = string
    ami           = string
    disk_size     = number
  })
}
```

### Variable Assignment

```bash
# Command line
terraform apply -var="region=us-east-1" -var="instance_count=3"

# Variable file
terraform apply -var-file="prod.tfvars"

# Environment variable
export TF_VAR_region="us-east-1"
terraform apply
```

### terraform.tfvars

```hcl
region         = "eu-west-1"
instance_count = 5
tags = {
  Environment = "production"
  CostCenter  = "engineering"
}
```

## Outputs

```hcl
# outputs.tf
output "instance_ip" {
  description = "Public IP of instance"
  value       = aws_instance.example.public_ip
}

output "instance_ids" {
  description = "List of instance IDs"
  value       = aws_instance.example[*].id
}

output "db_connection_string" {
  description = "Database connection string"
  value       = "postgresql://${aws_db_instance.db.endpoint}"
  sensitive   = true
}

output "vpc_config" {
  description = "VPC configuration"
  value = {
    vpc_id     = aws_vpc.main.id
    cidr_block = aws_vpc.main.cidr_block
    subnets    = aws_subnet.private[*].id
  }
}
```

```bash
# Query outputs
terraform output
terraform output instance_ip
terraform output -json > outputs.json
```

## Modules

### Module Structure

```
modules/
└── webserver/
    ├── main.tf
    ├── variables.tf
    ├── outputs.tf
    └── README.md
```

### Using Modules

```hcl
# Local module
module "webserver" {
  source = "./modules/webserver"

  instance_type = "t3.micro"
  subnet_id     = aws_subnet.public.id
  tags          = var.common_tags
}

# Remote module (Terraform Registry)
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"

  name = "my-vpc"
  cidr = "10.0.0.0/16"

  azs             = ["eu-west-1a", "eu-west-1b"]
  private_subnets = ["10.0.1.0/24", "10.0.2.0/24"]
  public_subnets  = ["10.0.101.0/24", "10.0.102.0/24"]
}

# Git module
module "consul" {
  source = "git::https://github.com/hashicorp/consul.git//terraform/aws?ref=v1.0.0"
}

# Access module outputs
resource "aws_instance" "web" {
  subnet_id = module.vpc.public_subnets[0]
}
```

### Module Commands

```bash
# Initialize modules
terraform get

# Update modules
terraform get -update

# Show module tree
terraform providers
```

## Workspaces

```bash
# List workspaces
terraform workspace list

# Create workspace
terraform workspace new dev

# Switch workspace
terraform workspace select prod

# Show current workspace
terraform workspace show

# Delete workspace
terraform workspace delete dev
```

### Using Workspaces in Code

```hcl
resource "aws_instance" "example" {
  instance_type = terraform.workspace == "prod" ? "t3.large" : "t3.micro"

  tags = {
    Environment = terraform.workspace
  }
}
```

## Data Sources

```hcl
# Query existing resources
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-*"]
  }
}

data "aws_vpc" "default" {
  default = true
}

# Use data source
resource "aws_instance" "web" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = "t3.micro"
  subnet_id     = data.aws_vpc.default.id
}
```

## Provisioners

```hcl
resource "aws_instance" "web" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.micro"

  # File provisioner
  provisioner "file" {
    source      = "script.sh"
    destination = "/tmp/script.sh"

    connection {
      type        = "ssh"
      user        = "ubuntu"
      private_key = file("~/.ssh/id_rsa")
      host        = self.public_ip
    }
  }

  # Remote-exec provisioner
  provisioner "remote-exec" {
    inline = [
      "chmod +x /tmp/script.sh",
      "/tmp/script.sh",
    ]
  }

  # Local-exec provisioner
  provisioner "local-exec" {
    command = "echo ${self.public_ip} >> inventory.txt"
  }

  # Destroy-time provisioner
  provisioner "local-exec" {
    when    = destroy
    command = "echo 'Instance destroyed' >> log.txt"
  }
}
```

## Meta-Arguments

### count

```hcl
resource "aws_instance" "server" {
  count         = 3
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.micro"

  tags = {
    Name = "server-${count.index}"
  }
}

# Reference
resource "aws_eip" "ip" {
  count    = 3
  instance = aws_instance.server[count.index].id
}
```

### for_each

```hcl
variable "users" {
  type = map(object({
    role = string
  }))
  default = {
    "alice" = { role = "admin" }
    "bob"   = { role = "developer" }
  }
}

resource "aws_iam_user" "users" {
  for_each = var.users
  name     = each.key

  tags = {
    Role = each.value.role
  }
}

# With set
resource "aws_subnet" "private" {
  for_each = toset(["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"])

  vpc_id     = aws_vpc.main.id
  cidr_block = each.key
}
```

### depends_on

```hcl
resource "aws_instance" "web" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.micro"

  depends_on = [
    aws_security_group.web,
    aws_subnet.public
  ]
}
```

### lifecycle

```hcl
resource "aws_instance" "web" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.micro"

  lifecycle {
    create_before_destroy = true
    prevent_destroy       = true
    ignore_changes        = [tags]
  }
}
```

## Functions

### Common Functions

```hcl
# String functions
upper("hello")                    # "HELLO"
lower("HELLO")                    # "hello"
title("hello world")              # "Hello World"
trimspace("  hello  ")            # "hello"
format("Hello, %s!", "World")     # "Hello, World!"
join(",", ["a", "b", "c"])        # "a,b,c"
split(",", "a,b,c")               # ["a", "b", "c"]
replace("hello", "l", "r")        # "herro"

# Collection functions
length([1, 2, 3])                 # 3
concat([1, 2], [3, 4])            # [1, 2, 3, 4]
merge({a=1}, {b=2})               # {a=1, b=2}
lookup({a=1, b=2}, "a", "default") # 1
contains(["a", "b"], "a")         # true
distinct([1, 2, 2, 3])            # [1, 2, 3]
flatten([[1, 2], [3, 4]])         # [1, 2, 3, 4]

# Numeric functions
min(1, 2, 3)                      # 1
max(1, 2, 3)                      # 3
abs(-5)                           # 5
ceil(4.3)                         # 5
floor(4.8)                        # 4

# Type conversion
tostring(42)
tonumber("42")
tolist(["a", "b"])
toset(["a", "b", "b"])
tomap({a = "1", b = "2"})

# File functions
file("path/to/file")
fileexists("path/to/file")
filebase64("path/to/file")
templatefile("template.tpl", {name = "World"})

# Date/Time
timestamp()                       # "2025-12-08T10:30:00Z"
formatdate("DD MMM YYYY", timestamp())

# Crypto functions
md5("hello")
sha256("hello")
base64encode("hello")
base64decode("aGVsbG8=")
```

### Dynamic Blocks

```hcl
variable "ingress_rules" {
  type = list(object({
    port        = number
    protocol    = string
    cidr_blocks = list(string)
  }))
}

resource "aws_security_group" "web" {
  name = "web-sg"

  dynamic "ingress" {
    for_each = var.ingress_rules
    content {
      from_port   = ingress.value.port
      to_port     = ingress.value.port
      protocol    = ingress.value.protocol
      cidr_blocks = ingress.value.cidr_blocks
    }
  }
}
```

## Terraform Console

```bash
# Interactive console
terraform console

# Test expressions
> var.region
"eu-west-1"

> aws_instance.web.public_ip
"54.123.45.67"

> [for s in aws_subnet.private : s.id]
["subnet-123", "subnet-456"]
```

## Import Resources

```bash
# Import AWS instance
terraform import aws_instance.example i-1234567890abcdef0

# Import AWS S3 bucket
terraform import aws_s3_bucket.bucket my-bucket-name

# Import module resource
terraform import module.vpc.aws_vpc.main vpc-12345678
```

## Tips & Best Practices

### Directory Structure

```
project/
├── main.tf              # Primary resources
├── variables.tf         # Variable definitions
├── outputs.tf           # Output definitions
├── versions.tf          # Terraform and provider versions
├── backend.tf           # Backend configuration
├── terraform.tfvars     # Variable values
├── dev.tfvars           # Dev environment
├── prod.tfvars          # Prod environment
└── modules/
    └── custom-module/
```

### Version Constraints

```hcl
terraform {
  required_version = ">= 1.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}
```

### Common Patterns

```hcl
# Conditional resources
resource "aws_instance" "web" {
  count = var.create_instance ? 1 : 0
  # ...
}

# Conditional values
resource "aws_instance" "web" {
  instance_type = var.environment == "prod" ? "t3.large" : "t3.micro"
}

# For expressions
locals {
  instance_ips = [for i in aws_instance.web : i.private_ip]

  upper_tags = {
    for k, v in var.tags : k => upper(v)
  }

  filtered = [for s in var.servers : s if s.enabled]
}
```

### Debugging

```bash
# Enable debug logging
export TF_LOG=DEBUG
export TF_LOG_PATH=terraform.log

# Log levels: TRACE, DEBUG, INFO, WARN, ERROR
export TF_LOG=TRACE

# Disable logging
unset TF_LOG
```

### Common Errors & Fixes

```bash
# Error: state lock
# Fix: Force unlock (use carefully)
terraform force-unlock <LOCK_ID>

# Error: Provider version conflict
# Fix: Upgrade providers
terraform init -upgrade

# Error: Resource already exists
# Fix: Import existing resource
terraform import <resource_type>.<name> <id>

# Error: Invalid configuration
# Fix: Validate and format
terraform validate
terraform fmt -recursive
```

### Performance

```bash
# Parallel operations (default: 10)
terraform apply -parallelism=20

# Target specific resources
terraform apply -target=aws_instance.web

# Refresh only
terraform refresh
terraform apply -refresh-only
```

### Security

```bash
# Scan for security issues
tfsec .

# Validate policies
terraform fmt -check
terraform validate

# Don't commit these files:
# .terraform/
# *.tfstate
# *.tfstate.backup
# .terraform.lock.hcl (commit this in teams)
# *.tfvars (if contains secrets)
```

### Useful Aliases

```bash
alias tf='terraform'
alias tfi='terraform init'
alias tfp='terraform plan'
alias tfa='terraform apply'
alias tfd='terraform destroy'
alias tfo='terraform output'
alias tfs='terraform state list'
alias tfv='terraform validate'
alias tff='terraform fmt -recursive'
```

## Resources

- [Terraform Documentation](https://www.terraform.io/docs)
- [Terraform Registry](https://registry.terraform.io/)
- [Best Practices](https://www.terraform-best-practices.com/)
- [Style Guide](https://www.terraform.io/docs/language/syntax/style.html)
