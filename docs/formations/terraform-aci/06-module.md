---
tags:
  - formation
  - terraform
  - aci
  - modules
  - patterns
  - best-practices
---

# Module 6 : Patterns & Modules Terraform

## Objectifs du Module

À la fin de ce module, vous serez capable de :

- :fontawesome-solid-folder-tree: Organiser un projet Terraform ACI
- :fontawesome-solid-cubes: Créer des modules réutilisables
- :fontawesome-solid-sliders: Utiliser variables, locals et outputs efficacement
- :fontawesome-solid-copy: Exploiter for_each et count pour le DRY
- :fontawesome-solid-layer-group: Gérer les workspaces pour multi-environnements
- :fontawesome-solid-database: Configurer un backend remote pour le state

**Durée estimée : 3 heures**

---

## Organisation d'un Projet

### Structure Recommandée

```
aci-infrastructure/
├── environments/
│   ├── dev/
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   ├── terraform.tfvars
│   │   └── backend.tf
│   ├── staging/
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   ├── terraform.tfvars
│   │   └── backend.tf
│   └── prod/
│       ├── main.tf
│       ├── variables.tf
│       ├── terraform.tfvars
│       └── backend.tf
├── modules/
│   ├── tenant/
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   └── outputs.tf
│   ├── epg/
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   └── outputs.tf
│   └── contract/
│       ├── main.tf
│       ├── variables.tf
│       └── outputs.tf
├── shared/
│   └── filters.tf
└── README.md
```

### Convention de Nommage

| Élément | Convention | Exemple |
|---------|------------|---------|
| **Fichiers** | lowercase, tirets | `bridge-domain.tf` |
| **Ressources** | snake_case | `aci_tenant.prod_main` |
| **Variables** | snake_case | `tenant_name` |
| **Modules** | lowercase, tirets | `modules/aci-tenant` |
| **Outputs** | snake_case | `tenant_dn` |

---

## Variables et Locals

### Variables Typées

```hcl
# variables.tf

variable "tenant_name" {
  description = "Nom du Tenant ACI"
  type        = string

  validation {
    condition     = can(regex("^[a-zA-Z][a-zA-Z0-9_-]{0,63}$", var.tenant_name))
    error_message = "Le nom du Tenant doit commencer par une lettre et contenir max 64 caractères."
  }
}

variable "environment" {
  description = "Environnement (dev, staging, prod)"
  type        = string

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "L'environnement doit être: dev, staging ou prod."
  }
}

variable "vrfs" {
  description = "Liste des VRFs à créer"
  type = list(object({
    name        = string
    description = string
    enforced    = optional(bool, true)
  }))
  default = []
}

variable "epgs" {
  description = "Configuration des EPGs"
  type = map(object({
    name        = string
    bd_name     = string
    description = optional(string, "")
    contracts = object({
      consumed = optional(list(string), [])
      provided = optional(list(string), [])
    })
  }))
}
```

### Locals pour Calculs

```hcl
# locals.tf

locals {
  # Préfixe basé sur l'environnement
  prefix = "${var.tenant_name}-${var.environment}"

  # Tags communs
  common_tags = {
    Environment = var.environment
    ManagedBy   = "terraform"
    Project     = var.tenant_name
  }

  # Annotation standard
  annotation = "orchestrator:terraform,env:${var.environment}"

  # Calcul dynamique des subnets
  subnet_configs = {
    for name, epg in var.epgs : name => {
      subnet   = cidrsubnet(var.base_cidr, 8, index(keys(var.epgs), name))
      gateway  = cidrhost(cidrsubnet(var.base_cidr, 8, index(keys(var.epgs), name)), 1)
    }
  }

  # Liste plate de tous les contracts
  all_contracts = distinct(flatten([
    for epg in var.epgs : concat(
      epg.contracts.consumed,
      epg.contracts.provided
    )
  ]))
}
```

### Fichier tfvars

```hcl
# terraform.tfvars

tenant_name = "Worldline-Payment"
environment = "prod"

vrfs = [
  {
    name        = "Production"
    description = "VRF Production PCI-DSS"
    enforced    = true
  },
  {
    name        = "Management"
    description = "VRF Management réseau"
    enforced    = true
  }
]

epgs = {
  frontend = {
    name        = "Frontend"
    bd_name     = "BD-Web"
    description = "Serveurs web frontend"
    contracts = {
      consumed = ["web-to-app"]
      provided = ["inet-to-web"]
    }
  }
  api = {
    name        = "API"
    bd_name     = "BD-App"
    description = "API backend"
    contracts = {
      consumed = ["app-to-db"]
      provided = ["web-to-app"]
    }
  }
  database = {
    name        = "Database"
    bd_name     = "BD-Data"
    description = "PostgreSQL servers"
    contracts = {
      consumed = []
      provided = ["app-to-db"]
    }
  }
}
```

---

## For_each et Count

### For_each avec Map

```hcl
# Créer plusieurs EPGs à partir d'une map
resource "aci_application_epg" "epgs" {
  for_each = var.epgs

  application_profile_dn = aci_application_profile.main.id
  name                   = each.value.name
  description            = each.value.description
  relation_fv_rs_bd      = aci_bridge_domain.bds[each.value.bd_name].id
  annotation             = local.annotation
}

# Créer les Bridge Domains correspondants
resource "aci_bridge_domain" "bds" {
  for_each = toset([for epg in var.epgs : epg.bd_name])

  tenant_dn          = aci_tenant.main.id
  name               = each.value
  relation_fv_rs_ctx = aci_vrf.production.id
  annotation         = local.annotation
}
```

### For_each avec Nested Loops

```hcl
# Créer les associations EPG → Contract Consumer
locals {
  epg_contract_consumers = flatten([
    for epg_key, epg in var.epgs : [
      for contract in epg.contracts.consumed : {
        epg_key      = epg_key
        contract_name = contract
      }
    ]
  ])
}

resource "aci_epg_to_contract" "consumers" {
  for_each = {
    for item in local.epg_contract_consumers :
    "${item.epg_key}-${item.contract_name}" => item
  }

  application_epg_dn = aci_application_epg.epgs[each.value.epg_key].id
  contract_dn        = aci_contract.contracts[each.value.contract_name].id
  contract_type      = "consumer"
}
```

### Count pour Ressources Conditionnelles

```hcl
# Créer un L3Out seulement en production
resource "aci_l3_outside" "internet" {
  count = var.environment == "prod" ? 1 : 0

  tenant_dn = aci_tenant.main.id
  name      = "L3Out-Internet"
  # ...
}

# Référencer avec count
resource "aci_external_network_instance_profile" "external" {
  count = var.environment == "prod" ? 1 : 0

  l3_outside_dn = aci_l3_outside.internet[0].id
  name          = "External-Internet"
}
```

---

## Création de Modules

### Module : Tenant Complet

```hcl
# modules/tenant/variables.tf

variable "name" {
  description = "Nom du Tenant"
  type        = string
}

variable "description" {
  description = "Description du Tenant"
  type        = string
  default     = ""
}

variable "vrfs" {
  description = "VRFs à créer dans le Tenant"
  type = list(object({
    name        = string
    description = optional(string, "")
    enforced    = optional(bool, true)
  }))
  default = []
}

variable "annotation" {
  description = "Annotation pour traçabilité"
  type        = string
  default     = "orchestrator:terraform"
}
```

```hcl
# modules/tenant/main.tf

resource "aci_tenant" "this" {
  name        = var.name
  description = var.description
  annotation  = var.annotation
}

resource "aci_vrf" "vrfs" {
  for_each = { for vrf in var.vrfs : vrf.name => vrf }

  tenant_dn   = aci_tenant.this.id
  name        = each.value.name
  description = each.value.description
  pc_enf_pref = each.value.enforced ? "enforced" : "unenforced"
  annotation  = var.annotation
}
```

```hcl
# modules/tenant/outputs.tf

output "tenant_dn" {
  description = "DN du Tenant créé"
  value       = aci_tenant.this.id
}

output "tenant_name" {
  description = "Nom du Tenant"
  value       = aci_tenant.this.name
}

output "vrf_dns" {
  description = "Map des DNs des VRFs"
  value       = { for k, v in aci_vrf.vrfs : k => v.id }
}
```

### Module : EPG avec Contracts

```hcl
# modules/epg/variables.tf

variable "tenant_dn" {
  description = "DN du Tenant parent"
  type        = string
}

variable "application_profile_dn" {
  description = "DN de l'Application Profile"
  type        = string
}

variable "name" {
  description = "Nom de l'EPG"
  type        = string
}

variable "bridge_domain_dn" {
  description = "DN du Bridge Domain"
  type        = string
}

variable "vmm_domain_dn" {
  description = "DN du VMM Domain (optionnel)"
  type        = string
  default     = null
}

variable "contracts_consumed" {
  description = "Liste des DNs de Contracts consommés"
  type        = list(string)
  default     = []
}

variable "contracts_provided" {
  description = "Liste des DNs de Contracts fournis"
  type        = list(string)
  default     = []
}
```

```hcl
# modules/epg/main.tf

resource "aci_application_epg" "this" {
  application_profile_dn = var.application_profile_dn
  name                   = var.name
  relation_fv_rs_bd      = var.bridge_domain_dn
  annotation             = "orchestrator:terraform"
}

# Association VMM Domain si fourni
resource "aci_epg_to_domain" "vmm" {
  count = var.vmm_domain_dn != null ? 1 : 0

  application_epg_dn = aci_application_epg.this.id
  tdn                = var.vmm_domain_dn
  instr_imedcy       = "immediate"
  res_imedcy         = "immediate"
}

# Contracts consommés
resource "aci_epg_to_contract" "consumed" {
  for_each = toset(var.contracts_consumed)

  application_epg_dn = aci_application_epg.this.id
  contract_dn        = each.value
  contract_type      = "consumer"
}

# Contracts fournis
resource "aci_epg_to_contract" "provided" {
  for_each = toset(var.contracts_provided)

  application_epg_dn = aci_application_epg.this.id
  contract_dn        = each.value
  contract_type      = "provider"
}
```

```hcl
# modules/epg/outputs.tf

output "epg_dn" {
  description = "DN de l'EPG créé"
  value       = aci_application_epg.this.id
}

output "epg_name" {
  description = "Nom de l'EPG"
  value       = aci_application_epg.this.name
}
```

### Utiliser les Modules

```hcl
# environments/prod/main.tf

module "tenant" {
  source = "../../modules/tenant"

  name        = "Production"
  description = "Tenant de production"

  vrfs = [
    {
      name        = "Prod-VRF"
      description = "VRF principale"
      enforced    = true
    }
  ]
}

module "frontend_epg" {
  source = "../../modules/epg"

  tenant_dn              = module.tenant.tenant_dn
  application_profile_dn = aci_application_profile.main.id
  name                   = "Frontend"
  bridge_domain_dn       = aci_bridge_domain.web.id
  vmm_domain_dn          = data.aci_vmm_domain.vcenter.id

  contracts_consumed = [aci_contract.web_to_app.id]
  contracts_provided = [aci_contract.inet_to_web.id]
}

module "backend_epg" {
  source = "../../modules/epg"

  tenant_dn              = module.tenant.tenant_dn
  application_profile_dn = aci_application_profile.main.id
  name                   = "Backend"
  bridge_domain_dn       = aci_bridge_domain.app.id
  vmm_domain_dn          = data.aci_vmm_domain.vcenter.id

  contracts_consumed = [aci_contract.app_to_db.id]
  contracts_provided = [aci_contract.web_to_app.id]
}
```

---

## Workspaces

### Gérer Multi-Environnements

```bash
# Créer des workspaces
terraform workspace new dev
terraform workspace new staging
terraform workspace new prod

# Lister les workspaces
terraform workspace list
  default
* dev
  staging
  prod

# Changer de workspace
terraform workspace select prod
```

### Variables par Workspace

```hcl
# variables.tf

locals {
  # Configuration par environnement
  env_config = {
    dev = {
      tenant_prefix     = "Dev"
      vrf_enforced      = false
      create_l3out      = false
      subnet_base       = "10.10.0.0/16"
    }
    staging = {
      tenant_prefix     = "Staging"
      vrf_enforced      = true
      create_l3out      = false
      subnet_base       = "10.20.0.0/16"
    }
    prod = {
      tenant_prefix     = "Prod"
      vrf_enforced      = true
      create_l3out      = true
      subnet_base       = "10.30.0.0/16"
    }
  }

  # Configuration courante basée sur le workspace
  current_config = local.env_config[terraform.workspace]
}

# Utilisation
resource "aci_tenant" "main" {
  name = "${local.current_config.tenant_prefix}-${var.project_name}"
}

resource "aci_vrf" "main" {
  tenant_dn   = aci_tenant.main.id
  name        = "Main-VRF"
  pc_enf_pref = local.current_config.vrf_enforced ? "enforced" : "unenforced"
}
```

---

## Backend Remote

### Configuration S3 + DynamoDB (AWS)

```hcl
# backend.tf

terraform {
  backend "s3" {
    bucket         = "worldline-terraform-state"
    key            = "aci/production/terraform.tfstate"
    region         = "eu-west-1"
    encrypt        = true
    dynamodb_table = "terraform-locks"
  }
}
```

### Configuration Azure Blob

```hcl
# backend.tf

terraform {
  backend "azurerm" {
    resource_group_name  = "rg-terraform-state"
    storage_account_name = "wlterraformstate"
    container_name       = "tfstate"
    key                  = "aci/prod.terraform.tfstate"
  }
}
```

### Configuration GitLab CI avec HTTP Backend

```hcl
# backend.tf

terraform {
  backend "http" {
    address        = "https://gitlab.example.com/api/v4/projects/123/terraform/state/aci-prod"
    lock_address   = "https://gitlab.example.com/api/v4/projects/123/terraform/state/aci-prod/lock"
    unlock_address = "https://gitlab.example.com/api/v4/projects/123/terraform/state/aci-prod/lock"
    lock_method    = "POST"
    unlock_method  = "DELETE"
    retry_wait_min = 5
  }
}
```

---

## Patterns Avancés

### Pattern : Application Stack

Créer une application complète avec un seul module :

```hcl
# modules/application-stack/variables.tf

variable "tenant_dn" {
  type = string
}

variable "name" {
  description = "Nom de l'application"
  type        = string
}

variable "tiers" {
  description = "Tiers de l'application"
  type = map(object({
    subnet      = string
    ports       = list(number)
    depends_on  = optional(list(string), [])
  }))
}
```

```hcl
# modules/application-stack/main.tf

# Application Profile
resource "aci_application_profile" "this" {
  tenant_dn   = var.tenant_dn
  name        = var.name
  annotation  = "orchestrator:terraform"
}

# Bridge Domains pour chaque tier
resource "aci_bridge_domain" "tiers" {
  for_each = var.tiers

  tenant_dn          = var.tenant_dn
  name               = "BD-${var.name}-${each.key}"
  relation_fv_rs_ctx = var.vrf_dn
}

# Subnets
resource "aci_subnet" "tiers" {
  for_each = var.tiers

  parent_dn = aci_bridge_domain.tiers[each.key].id
  ip        = each.value.subnet
  scope     = ["public"]
}

# EPGs
resource "aci_application_epg" "tiers" {
  for_each = var.tiers

  application_profile_dn = aci_application_profile.this.id
  name                   = each.key
  relation_fv_rs_bd      = aci_bridge_domain.tiers[each.key].id
}

# Filters dynamiques
resource "aci_filter" "tiers" {
  for_each = var.tiers

  tenant_dn = var.tenant_dn
  name      = "filter-${var.name}-${each.key}"
}

resource "aci_filter_entry" "ports" {
  for_each = {
    for item in flatten([
      for tier_name, tier in var.tiers : [
        for port in tier.ports : {
          tier = tier_name
          port = port
        }
      ]
    ]) : "${item.tier}-${item.port}" => item
  }

  filter_dn   = aci_filter.tiers[each.value.tier].id
  name        = "port-${each.value.port}"
  ether_t     = "ipv4"
  prot        = "tcp"
  d_from_port = tostring(each.value.port)
  d_to_port   = tostring(each.value.port)
  stateful    = "yes"
}

# Contracts basés sur les dépendances
resource "aci_contract" "tier_contracts" {
  for_each = {
    for item in flatten([
      for tier_name, tier in var.tiers : [
        for dep in tier.depends_on : {
          consumer = tier_name
          provider = dep
        }
      ]
    ]) : "${item.consumer}-to-${item.provider}" => item
  }

  tenant_dn = var.tenant_dn
  name      = "${each.value.consumer}-to-${each.value.provider}"
  scope     = "context"
}
```

**Utilisation :**

```hcl
module "ecommerce" {
  source = "./modules/application-stack"

  tenant_dn = aci_tenant.prod.id
  vrf_dn    = aci_vrf.main.id
  name      = "E-Commerce"

  tiers = {
    frontend = {
      subnet = "10.1.1.1/24"
      ports  = [443]
    }
    api = {
      subnet     = "10.1.2.1/24"
      ports      = [8080, 8443]
      depends_on = ["frontend"]
    }
    database = {
      subnet     = "10.1.3.1/24"
      ports      = [5432]
      depends_on = ["api"]
    }
  }
}
```

### Pattern : Environment Factory

```hcl
# modules/environment/main.tf

# Ce module crée un environnement complet
# avec isolation tenant, VRF, et contracts standards

variable "name" {
  type = string
}

variable "cidr" {
  type = string
}

variable "apps" {
  type = map(object({
    tiers = list(string)
  }))
}

# Tenant isolé pour l'environnement
resource "aci_tenant" "env" {
  name       = "Env-${var.name}"
  annotation = "env:${var.name},orchestrator:terraform"
}

# VRF dédié
resource "aci_vrf" "env" {
  tenant_dn   = aci_tenant.env.id
  name        = "${var.name}-VRF"
  pc_enf_pref = "enforced"
}

# Contracts standards (DNS, NTP, etc.)
module "standard_contracts" {
  source = "../standard-contracts"

  tenant_dn = aci_tenant.env.id
}

# Applications
module "apps" {
  source   = "../application-stack"
  for_each = var.apps

  tenant_dn = aci_tenant.env.id
  vrf_dn    = aci_vrf.env.id
  name      = each.key
  # ...
}
```

---

## Exercice Pratique

!!! example "Lab 6.1 : Créer un Module EPG Réutilisable"

    **Objectif** : Créer un module `epg-with-contracts` réutilisable.

    **Spécifications :**

    1. Le module doit créer :
        - Un EPG
        - Ses associations Contract (consumer/provider)
        - Son association VMM Domain (optionnelle)

    2. Variables requises :
        - `name` (string)
        - `application_profile_dn` (string)
        - `bridge_domain_dn` (string)
        - `vmm_domain_dn` (string, optional)
        - `contracts` (object avec consumed/provided lists)

    3. Outputs :
        - `epg_dn`
        - `epg_name`

    **Structure :**

    ```
    lab6/
    ├── modules/
    │   └── epg-with-contracts/
    │       ├── main.tf
    │       ├── variables.tf
    │       └── outputs.tf
    └── main.tf
    ```

??? quote "Solution Lab 6.1"

    ```hcl
    # lab6/modules/epg-with-contracts/variables.tf

    variable "name" {
      description = "Nom de l'EPG"
      type        = string

      validation {
        condition     = length(var.name) > 0 && length(var.name) <= 64
        error_message = "Le nom doit faire entre 1 et 64 caractères."
      }
    }

    variable "application_profile_dn" {
      description = "DN de l'Application Profile parent"
      type        = string
    }

    variable "bridge_domain_dn" {
      description = "DN du Bridge Domain"
      type        = string
    }

    variable "description" {
      description = "Description de l'EPG"
      type        = string
      default     = ""
    }

    variable "vmm_domain_dn" {
      description = "DN du VMM Domain (VMware)"
      type        = string
      default     = null
    }

    variable "contracts" {
      description = "Contracts à associer"
      type = object({
        consumed = optional(list(string), [])
        provided = optional(list(string), [])
      })
      default = {
        consumed = []
        provided = []
      }
    }

    variable "annotation" {
      description = "Annotation pour traçabilité"
      type        = string
      default     = "orchestrator:terraform"
    }
    ```

    ```hcl
    # lab6/modules/epg-with-contracts/main.tf

    resource "aci_application_epg" "this" {
      application_profile_dn = var.application_profile_dn
      name                   = var.name
      description            = var.description
      relation_fv_rs_bd      = var.bridge_domain_dn
      annotation             = var.annotation
    }

    # Association VMM Domain
    resource "aci_epg_to_domain" "vmm" {
      count = var.vmm_domain_dn != null ? 1 : 0

      application_epg_dn    = aci_application_epg.this.id
      tdn                   = var.vmm_domain_dn
      vmm_allow_promiscuous = "reject"
      vmm_forged_transmits  = "reject"
      vmm_mac_changes       = "reject"
      instr_imedcy          = "immediate"
      res_imedcy            = "immediate"
    }

    # Contracts consommés
    resource "aci_epg_to_contract" "consumed" {
      for_each = toset(var.contracts.consumed)

      application_epg_dn = aci_application_epg.this.id
      contract_dn        = each.value
      contract_type      = "consumer"
    }

    # Contracts fournis
    resource "aci_epg_to_contract" "provided" {
      for_each = toset(var.contracts.provided)

      application_epg_dn = aci_application_epg.this.id
      contract_dn        = each.value
      contract_type      = "provider"
    }
    ```

    ```hcl
    # lab6/modules/epg-with-contracts/outputs.tf

    output "epg_dn" {
      description = "Distinguished Name de l'EPG"
      value       = aci_application_epg.this.id
    }

    output "epg_name" {
      description = "Nom de l'EPG"
      value       = aci_application_epg.this.name
    }

    output "contracts_consumed" {
      description = "Nombre de contracts consommés"
      value       = length(var.contracts.consumed)
    }

    output "contracts_provided" {
      description = "Nombre de contracts fournis"
      value       = length(var.contracts.provided)
    }
    ```

    ```hcl
    # lab6/main.tf

    terraform {
      required_providers {
        aci = {
          source  = "CiscoDevNet/aci"
          version = "~> 2.13"
        }
      }
    }

    provider "aci" {
      username = var.apic_username
      password = var.apic_password
      url      = var.apic_url
      insecure = true
    }

    # Structure de base
    resource "aci_tenant" "lab" {
      name = "Lab-Modules"
    }

    resource "aci_vrf" "main" {
      tenant_dn   = aci_tenant.lab.id
      name        = "Main-VRF"
      pc_enf_pref = "enforced"
    }

    resource "aci_bridge_domain" "web" {
      tenant_dn          = aci_tenant.lab.id
      name               = "BD-Web"
      relation_fv_rs_ctx = aci_vrf.main.id
    }

    resource "aci_application_profile" "app" {
      tenant_dn = aci_tenant.lab.id
      name      = "MyApp"
    }

    # Contracts
    resource "aci_contract" "web" {
      tenant_dn = aci_tenant.lab.id
      name      = "Web-Contract"
      scope     = "context"
    }

    # Utilisation du module
    module "frontend_epg" {
      source = "./modules/epg-with-contracts"

      name                   = "Frontend"
      application_profile_dn = aci_application_profile.app.id
      bridge_domain_dn       = aci_bridge_domain.web.id
      description            = "Web frontend servers"

      contracts = {
        consumed = []
        provided = [aci_contract.web.id]
      }
    }

    # Output
    output "frontend_dn" {
      value = module.frontend_epg.epg_dn
    }
    ```

---

## Points Clés à Retenir

!!! abstract "Résumé du Module 6"

    ### Organisation Projet

    ```
    project/
    ├── environments/     # Configs par environnement
    ├── modules/          # Modules réutilisables
    └── shared/           # Ressources partagées
    ```

    ### Variables Best Practices

    - Toujours typer les variables
    - Utiliser `validation` blocks
    - Valeurs par défaut sensées
    - `sensitive = true` pour secrets

    ### For_each vs Count

    | Critère | for_each | count |
    |---------|----------|-------|
    | Clé | String/Map | Index numérique |
    | Suppression | Propre | Cascade |
    | Recommandé | Maps/Sets | Conditionnel |

    ### Modules

    - Un module = une responsabilité
    - Variables explicites
    - Outputs utiles
    - Documentation intégrée

    ### Workspaces

    - Isolation par environnement
    - Même code, configs différentes
    - State séparé par workspace

    ### Backend Remote

    - **Obligatoire** en équipe
    - Locking pour éviter conflits
    - Encryption du state

---

## Navigation

| Précédent | Suivant |
|-----------|---------|
| [← Module 5 : Provider ACI](05-module.md) | [Module 7 : Flux Nord-Sud (L3Out) →](07-module.md) |
