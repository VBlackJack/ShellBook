---
tags:
  - tools
  - terraform
  - iac
  - cloud
---

# Terraform Module Generator

Generateur de modules Terraform pour les principaux providers cloud.

<div id="terraform-app">
  <div class="terraform-container">
    <div class="terraform-section">
      <h3>Configuration</h3>

      <div class="form-group">
        <label>Provider</label>
        <select id="provider" onchange="generate()">
          <option value="aws" selected>AWS</option>
          <option value="gcp">Google Cloud</option>
          <option value="azure">Azure</option>
          <option value="kubernetes">Kubernetes</option>
        </select>
      </div>

      <div class="form-group">
        <label>Type de ressource</label>
        <select id="resourceType" onchange="generate()">
          <option value="ec2">EC2 Instance (AWS)</option>
          <option value="s3">S3 Bucket (AWS)</option>
          <option value="rds">RDS Database (AWS)</option>
          <option value="vpc">VPC (AWS)</option>
          <option value="alb">Load Balancer (AWS)</option>
          <option value="ecs">ECS Service (AWS)</option>
        </select>
      </div>

      <div id="ec2Options">
        <div class="form-group">
          <label>Instance type</label>
          <select id="instanceType" onchange="generate()">
            <option value="t3.micro">t3.micro (Free tier)</option>
            <option value="t3.small">t3.small</option>
            <option value="t3.medium" selected>t3.medium</option>
            <option value="t3.large">t3.large</option>
            <option value="m5.large">m5.large</option>
            <option value="m5.xlarge">m5.xlarge</option>
          </select>
        </div>

        <div class="form-group">
          <label>AMI (laisser vide pour latest Amazon Linux 2)</label>
          <input type="text" id="ami" value="" placeholder="ami-xxxxxxxxx" oninput="generate()">
        </div>

        <div class="form-group">
          <label>Nombre d'instances</label>
          <input type="number" id="instanceCount" value="1" min="1" max="100" oninput="generate()">
        </div>

        <div class="form-group">
          <label>
            <input type="checkbox" id="publicIp" onchange="generate()" checked>
            IP publique
          </label>
        </div>

        <div class="form-group">
          <label>Key pair name</label>
          <input type="text" id="keyName" value="my-key" oninput="generate()">
        </div>
      </div>

      <div id="s3Options" style="display:none">
        <div class="form-group">
          <label>Nom du bucket</label>
          <input type="text" id="bucketName" value="my-bucket" oninput="generate()">
        </div>

        <div class="form-group">
          <label>
            <input type="checkbox" id="versioning" onchange="generate()">
            Activer versioning
          </label>
        </div>

        <div class="form-group">
          <label>
            <input type="checkbox" id="encryption" onchange="generate()" checked>
            Chiffrement SSE-S3
          </label>
        </div>
      </div>

      <div id="rdsOptions" style="display:none">
        <div class="form-group">
          <label>Engine</label>
          <select id="dbEngine" onchange="generate()">
            <option value="mysql">MySQL</option>
            <option value="postgres" selected>PostgreSQL</option>
            <option value="mariadb">MariaDB</option>
          </select>
        </div>

        <div class="form-group">
          <label>Instance class</label>
          <select id="dbClass" onchange="generate()">
            <option value="db.t3.micro">db.t3.micro</option>
            <option value="db.t3.small" selected>db.t3.small</option>
            <option value="db.t3.medium">db.t3.medium</option>
            <option value="db.r5.large">db.r5.large</option>
          </select>
        </div>

        <div class="form-group">
          <label>Storage (GB)</label>
          <input type="number" id="dbStorage" value="20" min="20" max="16384" oninput="generate()">
        </div>

        <div class="form-group">
          <label>
            <input type="checkbox" id="multiAz" onchange="generate()">
            Multi-AZ
          </label>
        </div>
      </div>

      <h4>Options generales</h4>

      <div class="form-group">
        <label>Region</label>
        <input type="text" id="region" value="eu-west-1" oninput="generate()">
      </div>

      <div class="form-group">
        <label>Environment tag</label>
        <input type="text" id="environment" value="production" oninput="generate()">
      </div>

      <div class="form-group">
        <label>Project tag</label>
        <input type="text" id="project" value="myproject" oninput="generate()">
      </div>

      <div class="form-group">
        <label>
          <input type="checkbox" id="addOutputs" onchange="generate()" checked>
          Ajouter outputs
        </label>
      </div>

      <div class="form-group">
        <label>
          <input type="checkbox" id="addVariables" onchange="generate()" checked>
          Generer variables.tf
        </label>
      </div>
    </div>

    <div class="terraform-section">
      <h3>Configuration generee</h3>

      <div class="output-tabs">
        <button class="output-tab active" onclick="switchOutput('main')">main.tf</button>
        <button class="output-tab" onclick="switchOutput('variables')">variables.tf</button>
        <button class="output-tab" onclick="switchOutput('outputs')">outputs.tf</button>
      </div>

      <pre id="mainOutput"># main.tf</pre>
      <pre id="variablesOutput" style="display:none"># variables.tf</pre>
      <pre id="outputsOutput" style="display:none"># outputs.tf</pre>
      <button onclick="copyConfig()">Copier</button>
    </div>
  </div>

  <div class="presets-section">
    <h3>Architectures types</h3>
    <div class="presets-grid">
      <div class="preset-card" onclick="loadPreset('webserver')">
        <h4>Web Server</h4>
        <p>EC2 + Security Group</p>
      </div>
      <div class="preset-card" onclick="loadPreset('staticsite')">
        <h4>Static Site</h4>
        <p>S3 + CloudFront</p>
      </div>
      <div class="preset-card" onclick="loadPreset('database')">
        <h4>Database</h4>
        <p>RDS PostgreSQL</p>
      </div>
      <div class="preset-card" onclick="loadPreset('vpc')">
        <h4>VPC</h4>
        <p>Network complet</p>
      </div>
      <div class="preset-card" onclick="loadPreset('ecs')">
        <h4>ECS Fargate</h4>
        <p>Container service</p>
      </div>
      <div class="preset-card" onclick="loadPreset('k8s')">
        <h4>EKS Cluster</h4>
        <p>Kubernetes AWS</p>
      </div>
    </div>
  </div>
</div>

<style>
.terraform-container {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 20px;
}

@media (max-width: 900px) {
  .terraform-container { grid-template-columns: 1fr; }
}

.terraform-section, .presets-section {
  background: var(--md-code-bg-color);
  padding: 20px;
  border-radius: 8px;
  margin-bottom: 20px;
}

.form-group {
  margin-bottom: 15px;
}

.form-group label {
  display: block;
  font-size: 0.85em;
  margin-bottom: 5px;
  color: var(--md-default-fg-color--light);
}

.form-group h4 {
  margin: 20px 0 10px 0;
  padding-top: 15px;
  border-top: 1px solid var(--md-default-fg-color--lightest);
}

.form-group select,
.form-group input[type="text"],
.form-group input[type="number"] {
  width: 100%;
  padding: 10px;
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  background: var(--md-default-bg-color);
  color: var(--md-default-fg-color);
  font-family: monospace;
}

.form-group input[type="checkbox"] { margin-right: 8px; }

.output-tabs {
  display: flex;
  gap: 5px;
  margin-bottom: 10px;
}

.output-tab {
  padding: 6px 12px;
  border: 1px solid var(--md-default-fg-color--lightest);
  background: transparent;
  border-radius: 4px;
  cursor: pointer;
  color: var(--md-default-fg-color);
  font-size: 0.85em;
}

.output-tab.active {
  background: var(--md-primary-fg-color);
  color: white;
}

#mainOutput, #variablesOutput, #outputsOutput {
  background: #1e1e1e;
  color: #d4d4d4;
  padding: 15px;
  border-radius: 4px;
  font-size: 0.85em;
  overflow-x: auto;
  white-space: pre-wrap;
  min-height: 350px;
}

.terraform-section button {
  margin-top: 10px;
  margin-right: 10px;
  padding: 8px 16px;
  background: var(--md-primary-fg-color);
  color: white;
  border: none;
  border-radius: 4px;
  cursor: pointer;
}

.presets-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
  gap: 12px;
}

.preset-card {
  background: var(--md-default-bg-color);
  padding: 15px;
  border-radius: 6px;
  cursor: pointer;
  transition: transform 0.2s;
}

.preset-card:hover { transform: scale(1.02); }
.preset-card h4 { margin: 0 0 5px 0; font-size: 0.95em; }
.preset-card p { margin: 0; font-size: 0.8em; color: var(--md-default-fg-color--light); }
</style>

<script>
let currentOutput = 'main';

function switchOutput(type) {
  currentOutput = type;
  document.querySelectorAll('.output-tab').forEach(btn => btn.classList.remove('active'));
  event.target.classList.add('active');

  document.getElementById('mainOutput').style.display = type === 'main' ? 'block' : 'none';
  document.getElementById('variablesOutput').style.display = type === 'variables' ? 'block' : 'none';
  document.getElementById('outputsOutput').style.display = type === 'outputs' ? 'block' : 'none';
}

function generate() {
  const provider = document.getElementById('provider').value;
  const resourceType = document.getElementById('resourceType').value;
  const region = document.getElementById('region').value;
  const environment = document.getElementById('environment').value;
  const project = document.getElementById('project').value;
  const addOutputs = document.getElementById('addOutputs').checked;
  const addVariables = document.getElementById('addVariables').checked;

  // Visibility
  document.getElementById('ec2Options').style.display = resourceType === 'ec2' ? 'block' : 'none';
  document.getElementById('s3Options').style.display = resourceType === 's3' ? 'block' : 'none';
  document.getElementById('rdsOptions').style.display = resourceType === 'rds' ? 'block' : 'none';

  let main = `# main.tf
# Generated by ShellBook Terraform Generator

terraform {
  required_version = ">= 1.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}

locals {
  common_tags = {
    Environment = var.environment
    Project     = var.project
    ManagedBy   = "Terraform"
  }
}

`;

  let variables = `# variables.tf

variable "region" {
  description = "AWS region"
  type        = string
  default     = "${region}"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "${environment}"
}

variable "project" {
  description = "Project name"
  type        = string
  default     = "${project}"
}

`;

  let outputs = `# outputs.tf

`;

  // EC2
  if (resourceType === 'ec2') {
    const instanceType = document.getElementById('instanceType').value;
    const ami = document.getElementById('ami').value;
    const instanceCount = document.getElementById('instanceCount').value;
    const publicIp = document.getElementById('publicIp').checked;
    const keyName = document.getElementById('keyName').value;

    if (!ami) {
      main += `# Get latest Amazon Linux 2 AMI
data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }
}

`;
    }

    main += `# Security Group
resource "aws_security_group" "instance" {
  name_prefix = "\${var.project}-"
  description = "Security group for EC2 instance"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "SSH"
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTP"
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, {
    Name = "\${var.project}-sg"
  })
}

# EC2 Instance
resource "aws_instance" "main" {
  count = ${instanceCount}

  ami           = ${ami ? `"${ami}"` : 'data.aws_ami.amazon_linux.id'}
  instance_type = var.instance_type

  key_name                    = var.key_name
  vpc_security_group_ids      = [aws_security_group.instance.id]
  associate_public_ip_address = ${publicIp}

  root_block_device {
    volume_size = 20
    volume_type = "gp3"
    encrypted   = true
  }

  tags = merge(local.common_tags, {
    Name = "\${var.project}-\${count.index + 1}"
  })
}
`;

    variables += `
variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "${instanceType}"
}

variable "key_name" {
  description = "SSH key pair name"
  type        = string
  default     = "${keyName}"
}
`;

    outputs += `output "instance_ids" {
  description = "EC2 instance IDs"
  value       = aws_instance.main[*].id
}

output "public_ips" {
  description = "Public IP addresses"
  value       = aws_instance.main[*].public_ip
}

output "security_group_id" {
  description = "Security group ID"
  value       = aws_security_group.instance.id
}
`;
  }

  // S3
  if (resourceType === 's3') {
    const bucketName = document.getElementById('bucketName').value;
    const versioning = document.getElementById('versioning').checked;
    const encryption = document.getElementById('encryption').checked;

    main += `# S3 Bucket
resource "aws_s3_bucket" "main" {
  bucket = var.bucket_name

  tags = merge(local.common_tags, {
    Name = var.bucket_name
  })
}

resource "aws_s3_bucket_public_access_block" "main" {
  bucket = aws_s3_bucket.main.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
`;

    if (versioning) {
      main += `
resource "aws_s3_bucket_versioning" "main" {
  bucket = aws_s3_bucket.main.id
  versioning_configuration {
    status = "Enabled"
  }
}
`;
    }

    if (encryption) {
      main += `
resource "aws_s3_bucket_server_side_encryption_configuration" "main" {
  bucket = aws_s3_bucket.main.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}
`;
    }

    variables += `
variable "bucket_name" {
  description = "S3 bucket name"
  type        = string
  default     = "${bucketName}"
}
`;

    outputs += `output "bucket_id" {
  description = "S3 bucket ID"
  value       = aws_s3_bucket.main.id
}

output "bucket_arn" {
  description = "S3 bucket ARN"
  value       = aws_s3_bucket.main.arn
}
`;
  }

  // RDS
  if (resourceType === 'rds') {
    const dbEngine = document.getElementById('dbEngine').value;
    const dbClass = document.getElementById('dbClass').value;
    const dbStorage = document.getElementById('dbStorage').value;
    const multiAz = document.getElementById('multiAz').checked;

    main += `# RDS Security Group
resource "aws_security_group" "rds" {
  name_prefix = "\${var.project}-rds-"
  description = "Security group for RDS"

  ingress {
    from_port   = ${dbEngine === 'mysql' || dbEngine === 'mariadb' ? '3306' : '5432'}
    to_port     = ${dbEngine === 'mysql' || dbEngine === 'mariadb' ? '3306' : '5432'}
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
    description = "${dbEngine === 'mysql' || dbEngine === 'mariadb' ? 'MySQL' : 'PostgreSQL'}"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, {
    Name = "\${var.project}-rds-sg"
  })
}

# RDS Instance
resource "aws_db_instance" "main" {
  identifier = "\${var.project}-db"

  engine         = "${dbEngine}"
  engine_version = "${dbEngine === 'postgres' ? '15' : '8.0'}"
  instance_class = var.db_instance_class

  allocated_storage     = var.db_storage
  max_allocated_storage = var.db_storage * 2
  storage_type          = "gp3"
  storage_encrypted     = true

  db_name  = var.db_name
  username = var.db_username
  password = var.db_password

  vpc_security_group_ids = [aws_security_group.rds.id]

  multi_az               = ${multiAz}
  publicly_accessible    = false
  skip_final_snapshot    = true
  deletion_protection    = var.environment == "production" ? true : false

  backup_retention_period = 7
  backup_window          = "03:00-04:00"
  maintenance_window     = "Mon:04:00-Mon:05:00"

  tags = merge(local.common_tags, {
    Name = "\${var.project}-db"
  })
}
`;

    variables += `
variable "db_instance_class" {
  description = "RDS instance class"
  type        = string
  default     = "${dbClass}"
}

variable "db_storage" {
  description = "RDS storage in GB"
  type        = number
  default     = ${dbStorage}
}

variable "db_name" {
  description = "Database name"
  type        = string
  default     = "mydb"
}

variable "db_username" {
  description = "Database master username"
  type        = string
  default     = "admin"
  sensitive   = true
}

variable "db_password" {
  description = "Database master password"
  type        = string
  sensitive   = true
}
`;

    outputs += `output "rds_endpoint" {
  description = "RDS endpoint"
  value       = aws_db_instance.main.endpoint
}

output "rds_port" {
  description = "RDS port"
  value       = aws_db_instance.main.port
}
`;
  }

  document.getElementById('mainOutput').textContent = main;
  document.getElementById('variablesOutput').textContent = variables;
  document.getElementById('outputsOutput').textContent = outputs;
}

function loadPreset(name) {
  switch(name) {
    case 'webserver':
      document.getElementById('resourceType').value = 'ec2';
      document.getElementById('instanceType').value = 't3.small';
      document.getElementById('instanceCount').value = '1';
      break;
    case 'staticsite':
      document.getElementById('resourceType').value = 's3';
      document.getElementById('versioning').checked = true;
      break;
    case 'database':
      document.getElementById('resourceType').value = 'rds';
      document.getElementById('dbEngine').value = 'postgres';
      document.getElementById('multiAz').checked = false;
      break;
    case 'vpc':
      document.getElementById('resourceType').value = 'vpc';
      break;
    case 'ecs':
      document.getElementById('resourceType').value = 'ecs';
      break;
    case 'k8s':
      document.getElementById('resourceType').value = 'ec2';
      document.getElementById('instanceType').value = 't3.medium';
      document.getElementById('instanceCount').value = '3';
      break;
  }
  generate();
}

function copyConfig() {
  let content;
  switch(currentOutput) {
    case 'main':
      content = document.getElementById('mainOutput').textContent;
      break;
    case 'variables':
      content = document.getElementById('variablesOutput').textContent;
      break;
    case 'outputs':
      content = document.getElementById('outputsOutput').textContent;
      break;
  }
  navigator.clipboard.writeText(content).then(() => {
    event.target.textContent = 'Copie!';
    setTimeout(() => event.target.textContent = 'Copier', 1500);
  });
}

generate();
</script>

---

## Commandes utiles

```bash
# Initialiser
terraform init

# Valider
terraform validate

# Plan
terraform plan -out=tfplan

# Appliquer
terraform apply tfplan

# Detruire
terraform destroy
```

---

## Voir aussi

- [Ansible Playbook Generator](ansible-generator.md)
- [AWS EC2 Lookup](ec2-lookup.md)
