# Napkin.ai - Tous les Diagrammes Restants

> Scan complet du 08/12/2024
> Total estimé : ~45 diagrammes Mermaid/ASCII à convertir

---

## PRIORITÉ HAUTE - Architecture Complexe

### 1. Patroni PostgreSQL HA Architecture
**Fichier:** `docs/databases/high-availability.md:67-128`
```
Create a hand-drawn style technical diagram showing Patroni PostgreSQL High Availability architecture.

Layout (top to bottom):
- Top: "Application Layer" box
- Middle-top: "HAProxy Load Balancer" (green box)
- Middle: 3 PostgreSQL nodes in a row:
  - Node 1: "PostgreSQL + Patroni" (blue, labeled "Leader")
  - Node 2: "PostgreSQL + Patroni" (gray, labeled "Replica")
  - Node 3: "PostgreSQL + Patroni" (gray, labeled "Replica")
- Arrows showing "Streaming Replication" between Leader and Replicas
- Bottom: "Etcd Cluster" (3 orange nodes) with "Raft Consensus" label

Connections:
- Application → HAProxy (read/write traffic)
- HAProxy → All PostgreSQL nodes
- All Patroni → Etcd (leader election, config)

Style: Clean technical diagram, color-coded components, directional arrows
```

### 2. DMZ Security Architecture
**Fichier:** `docs/network/fundamentals.md:208-283`
```
Create a hand-drawn style network security diagram showing DMZ architecture.

Layout (left to right):
- Left: Cloud icon labeled "Internet" (red zone - "Non-Fiable")
- First firewall: "External Firewall" (wall icon)
- Middle zone: "DMZ" (orange zone - "Semi-Fiable") containing:
  - Web Server icon
  - Mail Server icon
  - DNS Server icon
- Second firewall: "Internal Firewall" (wall icon)
- Right: "LAN" (green zone - "Fiable") containing:
  - Database icon
  - Active Directory icon
  - File Server icon

Arrows showing traffic flow with rules:
- Internet → DMZ: HTTP/HTTPS, SMTP, DNS
- DMZ → LAN: Limited, specific ports only
- LAN → DMZ: Application queries

Color coding: Red (untrusted), Orange (semi-trusted), Green (trusted)
```

### 3. Star Schema Data Warehouse
**Fichier:** `docs/databases/bi-concepts.md:146-196`
```
Create a hand-drawn style data warehouse star schema diagram.

Center: Large table "FACT_VENTES" (blue) containing:
- id_vente (PK)
- id_date (FK)
- id_produit (FK)
- id_client (FK)
- id_magasin (FK)
- quantite
- montant
- cout

4 Dimension tables around it (gray boxes):
- Top-left: "DIM_DATE" (id_date, jour, mois, trimestre, annee, jour_semaine)
- Top-right: "DIM_PRODUIT" (id_produit, nom, categorie, sous_categorie, marque, prix_unitaire)
- Bottom-left: "DIM_CLIENT" (id_client, nom, prenom, email, segment, ville, pays)
- Bottom-right: "DIM_MAGASIN" (id_magasin, nom, adresse, ville, region, type)

Lines connecting each dimension to the fact table (FK relationships)
Label: "Star Schema - Modèle en Étoile"
```

### 4. Modern Data Stack Architecture
**Fichier:** `docs/databases/bi-concepts.md:308-333`
```
Create a hand-drawn style modern data stack architecture diagram.

Vertical stack (bottom to top):

Layer 1 (Bottom) - "DATA SOURCES":
- Icons: Database, API, Files, SaaS apps
- Examples: PostgreSQL, REST APIs, CSV, Salesforce

Layer 2 - "INGESTION":
- Tools: Fivetran, Airbyte, Stitch
- Arrow pointing up

Layer 3 - "STORAGE (Data Lake/Warehouse)":
- Tools: Snowflake, BigQuery, Databricks, Redshift
- Large container icon

Layer 4 - "TRANSFORMATION (ELT)":
- Tool: dbt (Data Build Tool)
- Label: "SQL as Code"
- Git icon for version control

Layer 5 (Top) - "VISUALIZATION":
- Tools: Power BI, Tableau, Metabase, Superset, Looker
- Dashboard icons

Side panel: "ORCHESTRATION" (Airflow, Dagster) connecting all layers
```

---

## PRIORITÉ HAUTE - Cloud Fundamentals

### 5. Cloud Evolution Timeline
**Fichier:** `docs/formations/cloud-fundamentals/01-module.md:87-110`
```
Create a hand-drawn style timeline diagram showing cloud computing evolution.

Horizontal timeline with milestones:

1960s: "Mainframes" - Large computer icon, "Time-sharing"
1990s: "Internet" - Globe icon, "Web hosting"
2000s: "Virtualisation" - VM icon, "VMware, Xen"
2006: "AWS Launch" - Orange cloud, "EC2, S3"
2008: "Google App Engine" - Blue cloud, "PaaS"
2010: "Azure Launch" - Blue cloud, "Microsoft Cloud"
2010s: "Cloud Native" - Container icon, "Docker, Kubernetes"
2020s: "Multi-Cloud & Edge" - Multiple clouds, "Hybrid strategies"

Style: Timeline with icons at each milestone, brief labels, arrow showing progression
```

### 6. Cloud Deployment Models
**Fichier:** `docs/formations/cloud-fundamentals/01-module.md:153-193`
```
Create a hand-drawn style diagram showing 4 cloud deployment models.

4 quadrants layout:

Top-Left - "PUBLIC CLOUD":
- Multiple tenants icon
- Shared infrastructure
- Examples: AWS, Azure, GCP
- Benefits: Scalable, Pay-as-you-go

Top-Right - "PRIVATE CLOUD":
- Single building/company icon
- Dedicated infrastructure
- Examples: VMware, OpenStack
- Benefits: Control, Security

Bottom-Left - "HYBRID CLOUD":
- Connected public + private clouds
- Bridge/connection icon
- Use case: Burst to cloud
- Benefits: Flexibility

Bottom-Right - "MULTI-CLOUD":
- Multiple public cloud icons
- AWS + Azure + GCP logos
- Use case: Avoid vendor lock-in
- Benefits: Best of breed

Center: Connecting lines showing relationships
```

### 7. Cloud Market Share Pie Chart
**Fichier:** `docs/formations/cloud-fundamentals/01-module.md:201-218`
```
Create a hand-drawn style pie chart showing cloud market share 2024.

Pie chart with segments:
- AWS: 31% (Orange)
- Azure: 25% (Blue)
- Google Cloud: 11% (Red/Yellow/Green/Blue)
- Alibaba: 4% (Orange)
- Others: 29% (Gray)

Title: "Cloud Market Share 2024"
Legend on the side with company logos
Total market value annotation: "$600B+"
```

---

## PRIORITÉ MOYENNE - Terraform

### 8. Terraform Core Architecture
**Fichier:** `docs/formations/terraform-aci/01-module.md:90-123`
```
Create a hand-drawn style Terraform architecture diagram.

Center: "Terraform Core" (purple hexagon)

Connected to 3 provider boxes:
- Left: "ACI Provider" → Cisco APIC icon
- Top: "AWS Provider" → AWS cloud icon
- Right: "Azure Provider" → Azure cloud icon

Below Terraform Core:
- "State File" (terraform.tfstate) - Database icon
- Arrow to "Real Infrastructure"

Flow arrows showing:
1. HCL Code → Terraform Core
2. Terraform Core → Providers
3. Providers → Infrastructure APIs
4. State ↔ Terraform Core (bidirectional)

Label: "Terraform - Infrastructure as Code"
```

### 9. Terraform State Management
**Fichier:** `docs/formations/terraform-aci/01-module.md:296-349`
```
Create a hand-drawn style diagram comparing Terraform state backends.

Two sections side by side:

LEFT - "Local State" (Red border - Problems):
- Single laptop icon
- terraform.tfstate file
- Problems listed:
  - No collaboration
  - No locking
  - Risk of loss
  - Secrets in plain text

RIGHT - "Remote State" (Green border - Benefits):
- Cloud storage icon (S3, Azure Blob, GCS)
- Multiple users icons
- Benefits listed:
  - Team collaboration
  - State locking
  - Versioning
  - Encryption at rest

Arrow from left to right: "Migration recommended"
```

---

## PRIORITÉ MOYENNE - AWS

### 10. EC2 Architecture Overview
**Fichier:** `docs/formations/aws-fundamentals/02-module.md:36-62`
```
Create a hand-drawn style AWS EC2 architecture diagram.

Layout:
- Outer box: "AWS Region" (e.g., eu-west-1)
- Inside: 2 "Availability Zones" boxes

Per AZ:
- EC2 Instance icon with:
  - AMI label (Amazon Machine Image)
  - Instance Type (e.g., t3.medium)
- Attached EBS Volume icon
- Security Group (firewall icon)

Connections:
- Internet Gateway at top
- VPC surrounding AZs
- Subnet per AZ

Labels: Region, AZ, VPC, Subnet, EC2, EBS, Security Group
```

### 11. EC2 Instance Selection Flowchart
**Fichier:** `docs/formations/aws-fundamentals/02-module.md:105-131`
```
Create a hand-drawn style decision flowchart for EC2 instance selection.

Start: "What's your workload?"

Decision branches:

Branch 1: "General Purpose?"
- Yes → "T3/M6i" (Web servers, small DBs)

Branch 2: "Compute Intensive?"
- Yes → "C6i/C7g" (HPC, batch processing)

Branch 3: "Memory Intensive?"
- Yes → "R6i/X2idn" (In-memory DBs, caching)

Branch 4: "Storage Intensive?"
- Yes → "I3/D3" (Data warehousing, distributed FS)

Branch 5: "GPU/ML Workloads?"
- Yes → "P4d/G5" (Machine learning, graphics)

Each endpoint shows instance family with use case icons
```

### 12. Auto Scaling Architecture
**Fichier:** `docs/formations/aws-fundamentals/02-module.md:476-500`
```
Create a hand-drawn style AWS Auto Scaling architecture diagram.

Components:
- Top: "Application Load Balancer" (ALB)
- Middle: "Auto Scaling Group" containing:
  - 3 EC2 instances (expandable visualization)
  - Min: 2, Max: 10, Desired: 3 labels
- Side: "Launch Template" connected to ASG

Triggers shown:
- CloudWatch alarm icon → "CPU > 70% = Scale Out"
- CloudWatch alarm icon → "CPU < 30% = Scale In"

Arrows:
- Users → ALB → EC2 instances
- CloudWatch → ASG (scaling decisions)

Multi-AZ visualization with instances spread across 2+ AZs
```

### 13. VPC Architecture with Subnets
**Fichier:** `docs/formations/aws-fundamentals/03-module.md`
```
Create a hand-drawn style AWS VPC architecture diagram.

Outer box: "VPC 10.0.0.0/16"

Inside - 2 Availability Zones side by side:

AZ-1:
- Public Subnet (10.0.1.0/24) - Green
  - NAT Gateway
  - Bastion Host
- Private Subnet (10.0.2.0/24) - Blue
  - Application servers

AZ-2:
- Public Subnet (10.0.3.0/24) - Green
  - NAT Gateway
- Private Subnet (10.0.4.0/24) - Blue
  - Database (RDS)

Top: Internet Gateway connected to public subnets
Arrows showing traffic flow:
- Internet → IGW → Public subnets
- Public → NAT → Private (outbound only)

Route tables shown for public (0.0.0.0/0 → IGW) and private (0.0.0.0/0 → NAT)
```

---

## PRIORITÉ MOYENNE - Kubernetes

### 14. Controller Manager Reconciliation Loop
**Fichier:** `docs/formations/kubernetes-mastery/01-module.md:117-124`
```
Create a hand-drawn style diagram showing Kubernetes controller reconciliation loop.

Circular flow diagram:

3 main steps in a cycle:

1. "OBSERVE" (Eye icon)
   - "Watch current state"
   - "Get from API Server"

2. "COMPARE" (Balance scale icon)
   - "Current vs Desired"
   - "Detect drift"

3. "ACT" (Gear/wrench icon)
   - "Reconcile"
   - "Create/Update/Delete resources"

Arrows connecting: Observe → Compare → Act → Observe (loop)

Center label: "Reconciliation Loop"
Side note: "Runs continuously every ~10 seconds"
```

### 15. Kubernetes Service Types
**Fichier:** `docs/formations/kubernetes-mastery/03-module.md` (if exists)
```
Create a hand-drawn style diagram showing Kubernetes service types.

4 service types comparison:

1. "ClusterIP" (Default):
   - Internal cluster icon
   - Pod → Service → Pod
   - "Internal only"

2. "NodePort":
   - Node with open port
   - External → Node:30000 → Service → Pod
   - "Range: 30000-32767"

3. "LoadBalancer":
   - Cloud LB icon
   - External → Cloud LB → Service → Pod
   - "Cloud provider integration"

4. "ExternalName":
   - DNS icon
   - Service → External DNS
   - "CNAME record"

Each type shows traffic flow with arrows
```

---

## PRIORITÉ MOYENNE - Azure

### 16. Azure Resource Hierarchy
**Fichier:** `docs/formations/azure-fundamentals/01-module.md`
```
Create a hand-drawn style Azure resource hierarchy diagram.

Tree structure (top to bottom):

Level 1: "Azure AD Tenant" (top, purple)
  │
Level 2: "Management Groups" (can be nested)
  │
Level 3: "Subscriptions" (billing boundary)
  ├── Subscription: Production
  └── Subscription: Development
      │
Level 4: "Resource Groups" (logical containers)
  ├── RG: Networking
  └── RG: Application
      │
Level 5: "Resources" (actual services)
  ├── VM
  ├── Storage Account
  └── SQL Database

Annotations:
- RBAC can be applied at each level
- Policies inherit downward
- Tags for organization
```

### 17. Azure Virtual Network Architecture
**Fichier:** `docs/formations/azure-fundamentals/03-module.md`
```
Create a hand-drawn style Azure VNet architecture diagram.

Components:
- Outer: "Virtual Network (VNet)" - 10.0.0.0/16
- 2 Subnets inside:
  - "Frontend Subnet" 10.0.1.0/24 (public-facing)
  - "Backend Subnet" 10.0.2.0/24 (private)

Resources:
- Frontend: Application Gateway, VMs with Public IPs
- Backend: VMs (no public IP), Azure SQL

Security:
- NSG (Network Security Group) on each subnet
- Rules shown: Allow 443 inbound, Deny all default

Connectivity:
- VNet Peering to another VNet (dotted line)
- ExpressRoute to On-premises (dedicated line)
- VPN Gateway option
```

---

## PRIORITÉ MOYENNE - GCP

### 18. GCP Project Hierarchy
**Fichier:** `docs/formations/gcp-fundamentals/01-module.md`
```
Create a hand-drawn style GCP resource hierarchy diagram.

Tree structure:

Level 1: "Organization" (domain-level, optional)
  │
Level 2: "Folders" (can be nested, for departments)
  ├── Folder: Engineering
  │   ├── Folder: Frontend
  │   └── Folder: Backend
  └── Folder: Finance
      │
Level 3: "Projects" (fundamental unit)
  ├── Project: prod-app-123
  └── Project: dev-app-456
      │
Level 4: "Resources"
  ├── Compute Engine VM
  ├── Cloud Storage Bucket
  └── BigQuery Dataset

Side notes:
- IAM policies at each level
- Billing linked to projects
- Labels for cost tracking
```

### 19. GCP VPC Network Model
**Fichier:** `docs/formations/gcp-fundamentals/03-module.md`
```
Create a hand-drawn style GCP VPC diagram showing global VPC model.

Key concept: "GCP VPC is GLOBAL"

Diagram:
- Large "VPC Network" spanning multiple regions
- Region 1 (us-central1):
  - Subnet A: 10.0.1.0/24
  - VM instances
- Region 2 (europe-west1):
  - Subnet B: 10.0.2.0/24
  - VM instances
- Region 3 (asia-east1):
  - Subnet C: 10.0.3.0/24
  - VM instances

Connections:
- Internal traffic between regions (automatic, no peering needed)
- Google's global fiber network visualization

Comparison note: "Unlike AWS/Azure where VPC is regional"
```

---

## PRIORITÉ BASSE - Autres

### 20. GitOps Push vs Pull Model
**Fichier:** `docs/devops/gitops-argocd.md:37-54`
```
Create a hand-drawn style diagram comparing GitOps push vs pull deployment models.

Two sections:

LEFT - "PUSH Model (Traditional CI/CD)":
- Developer → Git Repository → CI Pipeline → PUSH → Kubernetes
- Problems:
  - CI needs cluster credentials
  - Security risk
  - No drift detection

RIGHT - "PULL Model (GitOps with ArgoCD)":
- Developer → Git Repository ← PULL ← ArgoCD → Kubernetes
- Benefits:
  - ArgoCD runs inside cluster
  - No external credentials
  - Continuous reconciliation
  - Drift detection & auto-heal

ArgoCD logo in the center
Arrows clearly showing direction of deployment
```

### 21-25. Infrastructure as Code Workflow (Multiple files)
```
Create a hand-drawn style Infrastructure as Code workflow diagram.

Flow (left to right):

1. "CODE" (Developer laptop)
   - Write HCL/YAML/JSON
   - IDE with syntax highlighting

2. "VERSION CONTROL" (Git icon)
   - Commit & Push
   - Pull Request review

3. "CI/CD PIPELINE" (Pipeline icon)
   - Terraform plan
   - Policy checks (OPA, Sentinel)
   - Approval gates

4. "INFRASTRUCTURE" (Cloud icons)
   - Apply changes
   - Resources created/modified

Feedback loop:
- State file updated
- Drift detection
- Notifications

Benefits listed: Reproducible, Auditable, Collaborative
```

---

## Formations Cloud - Diagrammes Spécifiques par Module

### AWS Fundamentals (Modules 1-10)

| Module | Diagramme | Priorité |
|--------|-----------|----------|
| 01 | IAM Policy Evaluation Flow | Haute |
| 02 | EC2 Placement Groups | Moyenne |
| 03 | VPC Endpoints (Gateway vs Interface) | Haute |
| 04 | S3 Storage Classes Lifecycle | Moyenne |
| 05 | RDS Multi-AZ vs Read Replicas | Haute |
| 06 | Lambda Event Sources | Moyenne |
| 07 | CloudFront Distribution | Moyenne |
| 08 | Route 53 Routing Policies | Moyenne |
| 09 | ECS vs EKS Comparison | Haute |
| 10 | Well-Architected Framework Pillars | Basse |

### Azure Fundamentals (Modules 1-10)

| Module | Diagramme | Priorité |
|--------|-----------|----------|
| 01 | Azure Global Infrastructure | Moyenne |
| 02 | Compute Options Comparison | Haute |
| 03 | Networking Components | Haute |
| 04 | Storage Account Types | Moyenne |
| 05 | Azure SQL Options | Moyenne |
| 06 | Identity (AAD/Entra ID) | Haute |
| 07 | Monitoring Stack | Moyenne |
| 08 | DevOps Integration | Basse |
| 09 | Security Center | Moyenne |
| 10 | Cost Management | Basse |

### GCP Fundamentals (Modules 1-10)

| Module | Diagramme | Priorité |
|--------|-----------|----------|
| 01 | GCP Services Overview | Moyenne |
| 02 | Compute Options | Haute |
| 03 | Networking (Global VPC) | Haute |
| 04 | Storage Options | Moyenne |
| 05 | BigQuery Architecture | Haute |
| 06 | IAM & Security | Haute |
| 07 | Operations Suite | Moyenne |
| 08 | CI/CD with Cloud Build | Basse |
| 09 | Kubernetes (GKE) | Haute |
| 10 | Data & AI Services | Moyenne |

---

## Récapitulatif

| Catégorie | Nombre | Priorité |
|-----------|--------|----------|
| Architecture Complexe | 4 | Haute |
| Cloud Fundamentals | 3 | Haute |
| Terraform | 2 | Moyenne |
| AWS Specifiques | 4 | Moyenne-Haute |
| Kubernetes | 2 | Moyenne |
| Azure Specifiques | 2 | Moyenne |
| GCP Specifiques | 2 | Moyenne |
| DevOps/GitOps | 2 | Basse |
| Cloud Modules (30) | ~30 | Variable |

**Total estimé : ~45-50 diagrammes**

---

## Notes pour Génération

1. **Style Napkin.ai** : Hand-drawn, sketch-like, professional
2. **Couleurs** : Utiliser les couleurs des providers (AWS orange, Azure blue, GCP multicolor)
3. **Résolution** : Générer en haute qualité pour le web
4. **Format** : JPEG, nommage cohérent (kebab-case)
5. **Taille** : Optimiser pour affichage markdown (~800-1200px largeur)
