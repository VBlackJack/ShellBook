---
tags:
  - formation
  - windows-server
  - iac
  - dsc
  - ansible
  - terraform
---

# Module 19 : Infrastructure as Code

## Objectifs du Module

Ce module couvre l'Infrastructure as Code pour Windows :

- Maîtriser PowerShell DSC (Desired State Configuration)
- Automatiser Windows avec Ansible
- Provisionner avec Terraform sur Azure
- Intégrer dans des pipelines CI/CD
- Appliquer les bonnes pratiques IaC

**Durée :** 9 heures

**Niveau :** Expert

---

## 1. PowerShell DSC

### 1.1 Concepts de Base

```powershell
# DSC = Desired State Configuration
# Déclare l'état souhaité, DSC l'applique

# Composants:
# - Configuration: Script décrivant l'état souhaité
# - Resources: Modules qui implémentent les changements
# - LCM (Local Configuration Manager): Moteur d'exécution

# Modes:
# - Push: Appliqué manuellement
# - Pull: Serveur DSC distribue les configurations
```

### 1.2 Écrire une Configuration

```powershell
# Configuration de base
Configuration WebServerConfig {
    Import-DscResource -ModuleName PSDesiredStateConfiguration

    Node "WEB01" {
        # Installer IIS
        WindowsFeature IIS {
            Ensure = "Present"
            Name   = "Web-Server"
        }

        # Installer ASP.NET
        WindowsFeature ASP {
            Ensure    = "Present"
            Name      = "Web-Asp-Net45"
            DependsOn = "[WindowsFeature]IIS"
        }

        # Démarrer le service W3SVC
        Service W3SVC {
            Name        = "W3SVC"
            State       = "Running"
            StartupType = "Automatic"
            DependsOn   = "[WindowsFeature]IIS"
        }

        # Créer un répertoire
        File WebContent {
            Ensure          = "Present"
            Type            = "Directory"
            DestinationPath = "C:\inetpub\wwwroot\mysite"
        }
    }
}

# Générer le MOF
WebServerConfig -OutputPath "C:\DSC\WebServerConfig"

# Appliquer (Push)
Start-DscConfiguration -Path "C:\DSC\WebServerConfig" -Wait -Verbose

# Vérifier l'état
Test-DscConfiguration
Get-DscConfiguration
```

### 1.3 Resources DSC Personnalisées

```powershell
# Installer des resources de la Gallery
Install-Module -Name xWebAdministration
Install-Module -Name ComputerManagementDsc

# Configuration avec resource externe
Configuration IISWebsite {
    Import-DscResource -ModuleName xWebAdministration

    Node "WEB01" {
        xWebsite DefaultSite {
            Ensure       = "Present"
            Name         = "Default Web Site"
            State        = "Stopped"
            PhysicalPath = "C:\inetpub\wwwroot"
        }

        xWebsite MySite {
            Ensure       = "Present"
            Name         = "MySite"
            State        = "Started"
            PhysicalPath = "C:\inetpub\wwwroot\mysite"
            BindingInfo  = @(
                MSFT_xWebBindingInformation {
                    Protocol  = "HTTP"
                    Port      = 80
                    HostName  = "mysite.corp.local"
                }
            )
        }
    }
}
```

---

## 2. Ansible pour Windows

### 2.1 Configuration

```yaml
# ansible.cfg
[defaults]
inventory = inventory.yml
host_key_checking = False

# inventory.yml
all:
  children:
    windows:
      hosts:
        win-web01:
          ansible_host: 192.168.1.20
        win-web02:
          ansible_host: 192.168.1.21
      vars:
        ansible_user: Administrator
        ansible_password: "{{ vault_windows_password }}"
        ansible_connection: winrm
        ansible_winrm_transport: ntlm
        ansible_winrm_server_cert_validation: ignore
        ansible_port: 5986
```

### 2.2 Playbooks Windows

```yaml
# install-iis.yml
---
- name: Configure Windows Web Servers
  hosts: windows
  tasks:
    - name: Install IIS
      win_feature:
        name: Web-Server
        state: present
        include_management_tools: yes

    - name: Install ASP.NET
      win_feature:
        name: Web-Asp-Net45
        state: present

    - name: Start W3SVC
      win_service:
        name: W3SVC
        state: started
        start_mode: auto

    - name: Create website directory
      win_file:
        path: C:\inetpub\wwwroot\mysite
        state: directory

    - name: Deploy website content
      win_copy:
        src: ./website/
        dest: C:\inetpub\wwwroot\mysite\

    - name: Configure firewall
      win_firewall_rule:
        name: HTTP-In
        localport: 80
        protocol: tcp
        direction: in
        action: allow
        state: present
```

### 2.3 Exécution

```bash
# Configurer WinRM sur les serveurs Windows
# Sur chaque serveur:
winrm quickconfig
winrm set winrm/config/service/auth '@{Basic="true"}'
winrm set winrm/config/service '@{AllowUnencrypted="true"}'

# Exécuter le playbook
ansible-playbook -i inventory.yml install-iis.yml

# Avec variables chiffrées
ansible-playbook -i inventory.yml install-iis.yml --ask-vault-pass
```

---

## 3. Terraform pour Azure

### 3.1 Configuration de Base

```hcl
# main.tf
terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
  }
}

provider "azurerm" {
  features {}
}

# Resource Group
resource "azurerm_resource_group" "main" {
  name     = "rg-windows-prod"
  location = "West Europe"
}

# Virtual Network
resource "azurerm_virtual_network" "main" {
  name                = "vnet-prod"
  address_space       = ["10.0.0.0/16"]
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
}

# Subnet
resource "azurerm_subnet" "servers" {
  name                 = "snet-servers"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.0.1.0/24"]
}
```

### 3.2 Windows VM

```hcl
# windows-vm.tf
resource "azurerm_network_interface" "web" {
  name                = "nic-web01"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.servers.id
    private_ip_address_allocation = "Dynamic"
  }
}

resource "azurerm_windows_virtual_machine" "web" {
  name                = "vm-web01"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  size                = "Standard_B2s"
  admin_username      = "adminuser"
  admin_password      = var.admin_password

  network_interface_ids = [
    azurerm_network_interface.web.id,
  ]

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "MicrosoftWindowsServer"
    offer     = "WindowsServer"
    sku       = "2022-datacenter-azure-edition"
    version   = "latest"
  }
}

# Extension pour DSC
resource "azurerm_virtual_machine_extension" "dsc" {
  name                 = "dsc-config"
  virtual_machine_id   = azurerm_windows_virtual_machine.web.id
  publisher            = "Microsoft.Powershell"
  type                 = "DSC"
  type_handler_version = "2.77"

  settings = <<SETTINGS
    {
      "configuration": {
        "url": "https://mystorageaccount.blob.core.windows.net/dsc/WebServerConfig.zip",
        "script": "WebServerConfig.ps1",
        "function": "WebServerConfig"
      }
    }
SETTINGS
}
```

### 3.3 Exécution

```bash
# Initialiser
terraform init

# Planifier
terraform plan -var="admin_password=P@ssw0rd123!"

# Appliquer
terraform apply -var="admin_password=P@ssw0rd123!" -auto-approve

# Détruire
terraform destroy
```

---

## 4. CI/CD avec GitHub Actions

```yaml
# .github/workflows/deploy.yml
name: Deploy Windows Infrastructure

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  terraform:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v2

      - name: Azure Login
        uses: azure/login@v1
        with:
          creds: ${{ secrets.AZURE_CREDENTIALS }}

      - name: Terraform Init
        run: terraform init

      - name: Terraform Plan
        run: terraform plan -out=tfplan
        env:
          TF_VAR_admin_password: ${{ secrets.VM_PASSWORD }}

      - name: Terraform Apply
        if: github.ref == 'refs/heads/main'
        run: terraform apply -auto-approve tfplan

  ansible:
    needs: terraform
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    steps:
      - uses: actions/checkout@v3

      - name: Run Ansible Playbook
        uses: dawidd6/action-ansible-playbook@v2
        with:
          playbook: install-iis.yml
          inventory: |
            [windows]
            ${{ needs.terraform.outputs.vm_ip }}
          options: |
            --extra-vars "ansible_password=${{ secrets.VM_PASSWORD }}"
```

---

## 5. Exercice Pratique

### Déploiement Complet IaC

```powershell
# 1. Configuration DSC locale
Configuration ServerHardening {
    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName SecurityPolicyDsc

    Node localhost {
        # Désactiver SMBv1
        WindowsOptionalFeature SMB1 {
            Name   = "SMB1Protocol"
            Ensure = "Disable"
        }

        # Configurer Windows Firewall
        Service MpsSvc {
            Name        = "MpsSvc"
            State       = "Running"
            StartupType = "Automatic"
        }

        # Désactiver les services inutiles
        Service RemoteRegistry {
            Name        = "RemoteRegistry"
            State       = "Stopped"
            StartupType = "Disabled"
        }
    }
}

# Générer et appliquer
ServerHardening
Start-DscConfiguration -Path .\ServerHardening -Wait -Verbose
```

---

## Exercice : À Vous de Jouer

!!! example "Mise en Pratique"
    **Objectif** : Déployer une infrastructure Windows complète en utilisant Terraform pour le provisioning, PowerShell DSC pour la configuration, et un pipeline GitHub Actions pour l'automatisation

    **Contexte** : Votre entreprise souhaite adopter une approche Infrastructure as Code (IaC) complète. Vous devez provisionner deux machines virtuelles Windows dans Azure avec Terraform, appliquer une configuration DSC pour installer IIS et sécuriser les serveurs, puis automatiser l'ensemble du processus avec un pipeline CI/CD GitHub Actions qui valide, déploie et teste l'infrastructure.

    **Tâches à réaliser** :

    1. Créer un projet Terraform avec des modules réutilisables pour déployer un Resource Group, un Virtual Network avec deux subnets (web et db), un Network Security Group, et deux VMs Windows Server 2022 (WEB01 et WEB02)
    2. Écrire une configuration PowerShell DSC nommée `WebServerConfig` qui installe IIS, ASP.NET, configure le firewall Windows, désactive SMBv1, et déploie un site web simple avec une page HTML affichant le hostname
    3. Intégrer la configuration DSC dans le déploiement Terraform en utilisant l'extension `Microsoft.Powershell.DSC` sur les VMs, avec un script d'initialisation (custom script extension)
    4. Créer des variables Terraform pour rendre le déploiement paramétrable (nom du Resource Group, région Azure, taille des VMs, mot de passe admin) et gérer les secrets avec Azure Key Vault ou GitHub Secrets
    5. Implémenter un workflow GitHub Actions avec trois jobs : `validate` (terraform fmt, validate), `plan` (terraform plan avec artifact), et `apply` (terraform apply uniquement sur la branche main), incluant la gestion des états Terraform dans un Storage Account Azure
    6. Tester le pipeline en créant une Pull Request avec une modification, vérifier que le plan s'exécute automatiquement, merger vers main, et valider que l'infrastructure est déployée et fonctionnelle (site IIS accessible)

    **Critères de validation** :

    - [ ] `terraform plan` s'exécute sans erreurs et montre la création de toutes les ressources attendues (RG, VNet, NSG, 2 VMs, disques, NICs)
    - [ ] Les VMs sont déployées avec succès : `az vm list` montre WEB01 et WEB02 avec le statut "Succeeded"
    - [ ] La configuration DSC est appliquée : vérifier que `Get-WindowsFeature Web-Server` montre "Installed" sur les VMs
    - [ ] Les sites IIS répondent sur les IPs publiques : `Invoke-WebRequest` retourne le code 200 avec le hostname affiché
    - [ ] Le pipeline GitHub Actions s'exécute avec succès : tous les jobs (validate, plan, apply) sont verts
    - [ ] L'état Terraform est stocké dans Azure Blob Storage et verrouillé pendant les opérations
    - [ ] Les modifications apportées via Pull Request déclenchent automatiquement un `terraform plan` visible dans les commentaires

??? quote "Solution"
    **Étape 1 : Structure du projet Terraform**

    ```powershell
    # Créer la structure du projet
    New-Item -Path "C:\TerraformIaC" -ItemType Directory -Force
    Set-Location "C:\TerraformIaC"

    # Structure recommandée
    @"
    terraform-infrastructure/
    ├── main.tf
    ├── variables.tf
    ├── outputs.tf
    ├── terraform.tfvars
    ├── backend.tf
    ├── modules/
    │   ├── network/
    │   │   ├── main.tf
    │   │   ├── variables.tf
    │   │   └── outputs.tf
    │   └── vm-windows/
    │       ├── main.tf
    │       ├── variables.tf
    │       └── outputs.tf
    ├── dsc/
    │   └── WebServerConfig.ps1
    └── .github/
        └── workflows/
            └── terraform.yml
    "@ | Out-File "structure.txt"

    # Créer les répertoires
    "modules/network", "modules/vm-windows", "dsc", ".github/workflows" | ForEach-Object {
        New-Item -Path $_ -ItemType Directory -Force
    }
    ```

    **Créer `backend.tf`** :

    ```hcl
    terraform {
      backend "azurerm" {
        resource_group_name  = "rg-terraform-state"
        storage_account_name = "sttfstate001"  # Doit être unique
        container_name       = "tfstate"
        key                  = "infrastructure.tfstate"
      }
    }
    ```

    **Créer `variables.tf`** :

    ```hcl
    variable "resource_group_name" {
      description = "Nom du Resource Group"
      type        = string
      default     = "rg-infrastructure-prod"
    }

    variable "location" {
      description = "Région Azure"
      type        = string
      default     = "westeurope"
    }

    variable "admin_username" {
      description = "Nom d'utilisateur administrateur"
      type        = string
      default     = "azureadmin"
    }

    variable "admin_password" {
      description = "Mot de passe administrateur"
      type        = string
      sensitive   = true
    }

    variable "vm_size" {
      description = "Taille des VMs"
      type        = string
      default     = "Standard_B2s"
    }

    variable "vm_count" {
      description = "Nombre de VMs web"
      type        = number
      default     = 2
    }

    variable "tags" {
      description = "Tags à appliquer aux ressources"
      type        = map(string)
      default = {
        Environment = "Production"
        ManagedBy   = "Terraform"
        Project     = "IaC-Demo"
      }
    }
    ```

    **Créer `main.tf`** :

    ```hcl
    terraform {
      required_version = ">= 1.0"
      required_providers {
        azurerm = {
          source  = "hashicorp/azurerm"
          version = "~> 3.0"
        }
      }
    }

    provider "azurerm" {
      features {}
    }

    # Resource Group
    resource "azurerm_resource_group" "main" {
      name     = var.resource_group_name
      location = var.location
      tags     = var.tags
    }

    # Network Module
    module "network" {
      source = "./modules/network"

      resource_group_name = azurerm_resource_group.main.name
      location            = azurerm_resource_group.main.location
      vnet_address_space  = ["10.0.0.0/16"]
      subnet_web_prefix   = "10.0.1.0/24"
      subnet_db_prefix    = "10.0.2.0/24"
      tags                = var.tags
    }

    # Windows VMs Module
    module "web_vms" {
      source = "./modules/vm-windows"
      count  = var.vm_count

      vm_name             = "WEB0${count.index + 1}"
      resource_group_name = azurerm_resource_group.main.name
      location            = azurerm_resource_group.main.location
      subnet_id           = module.network.subnet_web_id
      vm_size             = var.vm_size
      admin_username      = var.admin_username
      admin_password      = var.admin_password
      tags                = var.tags
    }

    # Storage Account pour DSC
    resource "azurerm_storage_account" "dsc" {
      name                     = "stdsc${random_string.storage_suffix.result}"
      resource_group_name      = azurerm_resource_group.main.name
      location                 = azurerm_resource_group.main.location
      account_tier             = "Standard"
      account_replication_type = "LRS"
      tags                     = var.tags
    }

    resource "random_string" "storage_suffix" {
      length  = 8
      special = false
      upper   = false
    }

    resource "azurerm_storage_container" "dsc" {
      name                  = "dsc-configs"
      storage_account_name  = azurerm_storage_account.dsc.name
      container_access_type = "private"
    }
    ```

    **Module Network : `modules/network/main.tf`** :

    ```hcl
    variable "resource_group_name" { type = string }
    variable "location" { type = string }
    variable "vnet_address_space" { type = list(string) }
    variable "subnet_web_prefix" { type = string }
    variable "subnet_db_prefix" { type = string }
    variable "tags" { type = map(string) }

    resource "azurerm_virtual_network" "main" {
      name                = "vnet-prod"
      address_space       = var.vnet_address_space
      location            = var.location
      resource_group_name = var.resource_group_name
      tags                = var.tags
    }

    resource "azurerm_subnet" "web" {
      name                 = "snet-web"
      resource_group_name  = var.resource_group_name
      virtual_network_name = azurerm_virtual_network.main.name
      address_prefixes     = [var.subnet_web_prefix]
    }

    resource "azurerm_subnet" "db" {
      name                 = "snet-db"
      resource_group_name  = var.resource_group_name
      virtual_network_name = azurerm_virtual_network.main.name
      address_prefixes     = [var.subnet_db_prefix]
    }

    resource "azurerm_network_security_group" "web" {
      name                = "nsg-web"
      location            = var.location
      resource_group_name = var.resource_group_name
      tags                = var.tags

      security_rule {
        name                       = "AllowHTTP"
        priority                   = 100
        direction                  = "Inbound"
        access                     = "Allow"
        protocol                   = "Tcp"
        source_port_range          = "*"
        destination_port_range     = "80"
        source_address_prefix      = "*"
        destination_address_prefix = "*"
      }

      security_rule {
        name                       = "AllowRDP"
        priority                   = 200
        direction                  = "Inbound"
        access                     = "Allow"
        protocol                   = "Tcp"
        source_port_range          = "*"
        destination_port_range     = "3389"
        source_address_prefix      = "*"
        destination_address_prefix = "*"
      }
    }

    resource "azurerm_subnet_network_security_group_association" "web" {
      subnet_id                 = azurerm_subnet.web.id
      network_security_group_id = azurerm_network_security_group.web.id
    }

    output "vnet_id" { value = azurerm_virtual_network.main.id }
    output "subnet_web_id" { value = azurerm_subnet.web.id }
    output "subnet_db_id" { value = azurerm_subnet.db.id }
    ```

    **Module VM Windows : `modules/vm-windows/main.tf`** :

    ```hcl
    variable "vm_name" { type = string }
    variable "resource_group_name" { type = string }
    variable "location" { type = string }
    variable "subnet_id" { type = string }
    variable "vm_size" { type = string }
    variable "admin_username" { type = string }
    variable "admin_password" { type = string; sensitive = true }
    variable "tags" { type = map(string) }

    resource "azurerm_public_ip" "vm" {
      name                = "pip-${var.vm_name}"
      location            = var.location
      resource_group_name = var.resource_group_name
      allocation_method   = "Static"
      sku                 = "Standard"
      tags                = var.tags
    }

    resource "azurerm_network_interface" "vm" {
      name                = "nic-${var.vm_name}"
      location            = var.location
      resource_group_name = var.resource_group_name
      tags                = var.tags

      ip_configuration {
        name                          = "internal"
        subnet_id                     = var.subnet_id
        private_ip_address_allocation = "Dynamic"
        public_ip_address_id          = azurerm_public_ip.vm.id
      }
    }

    resource "azurerm_windows_virtual_machine" "vm" {
      name                = var.vm_name
      resource_group_name = var.resource_group_name
      location            = var.location
      size                = var.vm_size
      admin_username      = var.admin_username
      admin_password      = var.admin_password
      tags                = var.tags

      network_interface_ids = [azurerm_network_interface.vm.id]

      os_disk {
        caching              = "ReadWrite"
        storage_account_type = "Premium_LRS"
      }

      source_image_reference {
        publisher = "MicrosoftWindowsServer"
        offer     = "WindowsServer"
        sku       = "2022-datacenter-azure-edition"
        version   = "latest"
      }
    }

    output "vm_id" { value = azurerm_windows_virtual_machine.vm.id }
    output "public_ip" { value = azurerm_public_ip.vm.ip_address }
    output "private_ip" { value = azurerm_network_interface.vm.private_ip_address }
    ```

    **Créer `outputs.tf`** :

    ```hcl
    output "resource_group_name" {
      value = azurerm_resource_group.main.name
    }

    output "web_vms_public_ips" {
      value = [for vm in module.web_vms : vm.public_ip]
    }

    output "web_vms_private_ips" {
      value = [for vm in module.web_vms : vm.private_ip]
    }
    ```

    **Étape 2 : Configuration PowerShell DSC**

    Créer `dsc/WebServerConfig.ps1` :

    ```powershell
    Configuration WebServerConfig {
        Import-DscResource -ModuleName PSDesiredStateConfiguration

        Node localhost {
            # Installer IIS
            WindowsFeature IIS {
                Ensure = "Present"
                Name   = "Web-Server"
            }

            # Installer ASP.NET
            WindowsFeature ASPNET {
                Ensure    = "Present"
                Name      = "Web-Asp-Net45"
                DependsOn = "[WindowsFeature]IIS"
            }

            # Installer les outils de gestion IIS
            WindowsFeature IISManagement {
                Ensure    = "Present"
                Name      = "Web-Mgmt-Console"
                DependsOn = "[WindowsFeature]IIS"
            }

            # Désactiver SMBv1 (sécurité)
            WindowsOptionalFeature SMB1 {
                Ensure = "Disable"
                Name   = "SMB1Protocol"
            }

            # Configurer le service Windows Firewall
            Service Firewall {
                Name        = "MpsSvc"
                State       = "Running"
                StartupType = "Automatic"
            }

            # Service W3SVC
            Service W3SVC {
                Name        = "W3SVC"
                State       = "Running"
                StartupType = "Automatic"
                DependsOn   = "[WindowsFeature]IIS"
            }

            # Créer le répertoire du site
            File WebsiteContent {
                Ensure          = "Present"
                Type            = "Directory"
                DestinationPath = "C:\inetpub\wwwroot\mysite"
                DependsOn       = "[WindowsFeature]IIS"
            }

            # Créer la page HTML
            File IndexHTML {
                Ensure          = "Present"
                Type            = "File"
                DestinationPath = "C:\inetpub\wwwroot\mysite\index.html"
                Contents        = @"
<!DOCTYPE html>
<html>
<head>
    <title>IaC Demo - Windows Server</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        .container {
            text-align: center;
            background: rgba(255,255,255,0.1);
            padding: 40px;
            border-radius: 15px;
            backdrop-filter: blur(10px);
        }
        h1 { font-size: 48px; margin-bottom: 20px; }
        .info { font-size: 24px; margin: 10px 0; }
        .badge {
            display: inline-block;
            background: #4CAF50;
            padding: 10px 20px;
            border-radius: 20px;
            margin: 10px;
        }
    </style>
</head>
<body>
    <div class='container'>
        <h1>Infrastructure as Code</h1>
        <p class='info'>Serveur: <strong>$env:COMPUTERNAME</strong></p>
        <p class='info'>IP: <strong>$(Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.InterfaceAlias -notlike '*Loopback*'} | Select-Object -First 1 -ExpandProperty IPAddress)</strong></p>
        <div>
            <span class='badge'>Terraform</span>
            <span class='badge'>PowerShell DSC</span>
            <span class='badge'>GitHub Actions</span>
        </div>
        <p style='margin-top: 30px; font-size: 18px;'>Déployé automatiquement via IaC</p>
    </div>
</body>
</html>
"@
                DependsOn       = "[File]WebsiteContent"
            }

            # Configurer le firewall pour HTTP
            Script ConfigureFirewall {
                GetScript  = { @{ Result = "" } }
                TestScript = {
                    $rule = Get-NetFirewallRule -DisplayName "Allow HTTP" -ErrorAction SilentlyContinue
                    return ($null -ne $rule)
                }
                SetScript  = {
                    New-NetFirewallRule -DisplayName "Allow HTTP" `
                        -Direction Inbound `
                        -Protocol TCP `
                        -LocalPort 80 `
                        -Action Allow
                }
                DependsOn  = "[Service]Firewall"
            }
        }
    }

    # Générer le MOF
    WebServerConfig -OutputPath "C:\DSC"

    # Créer l'archive pour Azure
    Compress-Archive -Path "C:\DSC\*" -DestinationPath "C:\DSC\WebServerConfig.zip" -Force
    ```

    **Compiler la configuration DSC** :

    ```powershell
    # Exécuter la configuration DSC
    Set-Location "C:\TerraformIaC"

    # Installer les modules nécessaires
    Install-Module -Name PSDesiredStateConfiguration -Force

    # Compiler
    . .\dsc\WebServerConfig.ps1

    # Le fichier WebServerConfig.zip sera uploadé vers Azure Storage
    ```

    **Étape 3 : Intégration DSC dans Terraform**

    Ajouter à `main.tf` :

    ```hcl
    # Upload de la configuration DSC vers Storage Account
    resource "azurerm_storage_blob" "dsc_config" {
      name                   = "WebServerConfig.zip"
      storage_account_name   = azurerm_storage_account.dsc.name
      storage_container_name = azurerm_storage_container.dsc.name
      type                   = "Block"
      source                 = "${path.module}/dsc/WebServerConfig.zip"
    }

    # Extension DSC pour les VMs
    resource "azurerm_virtual_machine_extension" "dsc" {
      count = var.vm_count

      name                 = "DSC"
      virtual_machine_id   = module.web_vms[count.index].vm_id
      publisher            = "Microsoft.Powershell"
      type                 = "DSC"
      type_handler_version = "2.77"

      settings = jsonencode({
        configuration = {
          url      = azurerm_storage_blob.dsc_config.url
          script   = "WebServerConfig.ps1"
          function = "WebServerConfig"
        }
      })

      depends_on = [module.web_vms]
    }
    ```

    **Étape 4 : Variables et secrets**

    Créer `terraform.tfvars` (à NE PAS committer) :

    ```hcl
    resource_group_name = "rg-infrastructure-prod"
    location            = "westeurope"
    admin_username      = "azureadmin"
    admin_password      = "P@ssw0rd123!ComplexPassword"
    vm_size             = "Standard_B2s"
    vm_count            = 2
    ```

    Créer `.gitignore` :

    ```
    # Terraform
    .terraform/
    *.tfstate
    *.tfstate.backup
    .terraform.lock.hcl
    terraform.tfvars
    *.tfvars

    # DSC
    dsc/*.mof
    dsc/*.zip

    # Secrets
    *.secret
    ```

    **Étape 5 : Pipeline GitHub Actions**

    Créer `.github/workflows/terraform.yml` :

    ```yaml
    name: 'Terraform Infrastructure'

    on:
      push:
        branches: [ main ]
        paths:
          - '**.tf'
          - '.github/workflows/terraform.yml'
      pull_request:
        branches: [ main ]
        paths:
          - '**.tf'

    env:
      ARM_CLIENT_ID: ${{ secrets.AZURE_CLIENT_ID }}
      ARM_CLIENT_SECRET: ${{ secrets.AZURE_CLIENT_SECRET }}
      ARM_SUBSCRIPTION_ID: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
      ARM_TENANT_ID: ${{ secrets.AZURE_TENANT_ID }}

    jobs:
      validate:
        name: 'Validate Terraform'
        runs-on: ubuntu-latest
        steps:
          - name: Checkout
            uses: actions/checkout@v3

          - name: Setup Terraform
            uses: hashicorp/setup-terraform@v2
            with:
              terraform_version: 1.5.0

          - name: Terraform Format Check
            run: terraform fmt -check -recursive

          - name: Terraform Init
            run: terraform init -backend=false

          - name: Terraform Validate
            run: terraform validate

      plan:
        name: 'Terraform Plan'
        needs: validate
        runs-on: ubuntu-latest
        steps:
          - name: Checkout
            uses: actions/checkout@v3

          - name: Setup Terraform
            uses: hashicorp/setup-terraform@v2

          - name: Azure Login
            uses: azure/login@v1
            with:
              creds: ${{ secrets.AZURE_CREDENTIALS }}

          - name: Terraform Init
            run: terraform init

          - name: Terraform Plan
            id: plan
            run: |
              terraform plan \
                -var="admin_password=${{ secrets.VM_ADMIN_PASSWORD }}" \
                -out=tfplan \
                -no-color
            continue-on-error: true

          - name: Upload Plan
            uses: actions/upload-artifact@v3
            with:
              name: tfplan
              path: tfplan

          - name: Comment PR
            if: github.event_name == 'pull_request'
            uses: actions/github-script@v6
            with:
              github-token: ${{ secrets.GITHUB_TOKEN }}
              script: |
                const output = `#### Terraform Plan 📖
                \`\`\`
                ${{ steps.plan.outputs.stdout }}
                \`\`\`
                *Pushed by: @${{ github.actor }}, Action: \`${{ github.event_name }}\`*`;

                github.rest.issues.createComment({
                  issue_number: context.issue.number,
                  owner: context.repo.owner,
                  repo: context.repo.repo,
                  body: output
                })

      apply:
        name: 'Terraform Apply'
        needs: plan
        if: github.ref == 'refs/heads/main' && github.event_name == 'push'
        runs-on: ubuntu-latest
        environment: production
        steps:
          - name: Checkout
            uses: actions/checkout@v3

          - name: Setup Terraform
            uses: hashicorp/setup-terraform@v2

          - name: Azure Login
            uses: azure/login@v1
            with:
              creds: ${{ secrets.AZURE_CREDENTIALS }}

          - name: Terraform Init
            run: terraform init

          - name: Download Plan
            uses: actions/download-artifact@v3
            with:
              name: tfplan

          - name: Terraform Apply
            run: terraform apply -auto-approve tfplan

          - name: Get Outputs
            id: outputs
            run: |
              echo "web_ips=$(terraform output -json web_vms_public_ips)" >> $GITHUB_OUTPUT

          - name: Test Deployment
            run: |
              IPS=$(echo '${{ steps.outputs.outputs.web_ips }}' | jq -r '.[]')
              for IP in $IPS; do
                echo "Testing http://$IP"
                curl -f http://$IP || exit 1
              done
    ```

    **Configuration des secrets GitHub** :

    ```powershell
    # Créer un Service Principal Azure
    az ad sp create-for-rbac --name "github-actions-terraform" `
        --role Contributor `
        --scopes /subscriptions/<SUBSCRIPTION_ID> `
        --sdk-auth

    # Ajouter dans GitHub → Settings → Secrets and variables → Actions :
    # - AZURE_CLIENT_ID
    # - AZURE_CLIENT_SECRET
    # - AZURE_SUBSCRIPTION_ID
    # - AZURE_TENANT_ID
    # - AZURE_CREDENTIALS (JSON complet du SP)
    # - VM_ADMIN_PASSWORD
    ```

    **Étape 6 : Déploiement et tests**

    ```powershell
    # Initialiser Git
    git init
    git add .
    git commit -m "Initial commit: Terraform IaC infrastructure"

    # Créer le repo sur GitHub et push
    gh repo create terraform-infrastructure --private
    git remote add origin https://github.com/YOUR_USERNAME/terraform-infrastructure.git
    git branch -M main
    git push -u origin main

    # Créer le backend Terraform State dans Azure
    $RESOURCE_GROUP_NAME="rg-terraform-state"
    $STORAGE_ACCOUNT_NAME="sttfstate$(Get-Random -Minimum 100 -Maximum 999)"
    $CONTAINER_NAME="tfstate"

    # Créer les ressources
    az group create --name $RESOURCE_GROUP_NAME --location westeurope

    az storage account create `
        --resource-group $RESOURCE_GROUP_NAME `
        --name $STORAGE_ACCOUNT_NAME `
        --sku Standard_LRS `
        --encryption-services blob

    az storage container create `
        --name $CONTAINER_NAME `
        --account-name $STORAGE_ACCOUNT_NAME

    # Activer le verrouillage d'état
    az storage account blob-service-properties update `
        --account-name $STORAGE_ACCOUNT_NAME `
        --enable-versioning true

    # Mettre à jour backend.tf avec les vraies valeurs
    # Puis committer

    # Test local
    terraform init
    terraform fmt -recursive
    terraform validate
    terraform plan -var="admin_password=P@ssw0rd123!Complex"

    # Si OK, créer une Pull Request
    git checkout -b feature/add-load-balancer
    # ... faire des modifications ...
    git add .
    git commit -m "feat: Add load balancer configuration"
    git push origin feature/add-load-balancer

    # Créer la PR sur GitHub
    gh pr create --title "Add load balancer" --body "Adds Azure Load Balancer for web VMs"

    # Le workflow s'exécute automatiquement et poste le plan dans la PR

    # Après review, merger vers main
    gh pr merge --merge

    # Le workflow applique automatiquement les changements

    # Vérifier le déploiement
    terraform output web_vms_public_ips

    # Tester les sites
    $ips = terraform output -json web_vms_public_ips | ConvertFrom-Json

    foreach ($ip in $ips) {
        Write-Host "Testing http://$ip" -ForegroundColor Cyan
        $response = Invoke-WebRequest -Uri "http://$ip" -UseBasicParsing
        if ($response.StatusCode -eq 200) {
            Write-Host "✓ $ip is responding" -ForegroundColor Green
            Write-Host $response.Content.Substring(0, 200)
        } else {
            Write-Host "✗ $ip failed" -ForegroundColor Red
        }
    }
    ```

    **Monitoring et validation continue** :

    ```powershell
    # Script de validation post-déploiement
    # Validate-Infrastructure.ps1

    param(
        [string]$ResourceGroup = "rg-infrastructure-prod"
    )

    Write-Host "=== VALIDATION INFRASTRUCTURE ===" -ForegroundColor Cyan

    # 1. Vérifier les VMs
    $vms = az vm list --resource-group $ResourceGroup | ConvertFrom-Json

    Write-Host "`n VMs déployées : $($vms.Count)" -ForegroundColor Yellow
    foreach ($vm in $vms) {
        $vmStatus = az vm get-instance-view --name $vm.name --resource-group $ResourceGroup |
            ConvertFrom-Json

        $powerState = $vmStatus.instanceView.statuses |
            Where-Object { $_.code -like "PowerState/*" } |
            Select-Object -ExpandProperty displayStatus

        Write-Host "  - $($vm.name): $powerState" -ForegroundColor $(
            if ($powerState -eq "VM running") { "Green" } else { "Red" }
        )
    }

    # 2. Tester les endpoints HTTP
    Write-Host "`n Test des endpoints HTTP :" -ForegroundColor Yellow

    $publicIps = az network public-ip list --resource-group $ResourceGroup |
        ConvertFrom-Json

    foreach ($pip in $publicIps) {
        $ip = $pip.ipAddress
        try {
            $response = Invoke-WebRequest -Uri "http://$ip" -TimeoutSec 5 -UseBasicParsing
            Write-Host "  - http://$ip : OK (Status: $($response.StatusCode))" -ForegroundColor Green
        }
        catch {
            Write-Host "  - http://$ip : FAILED" -ForegroundColor Red
        }
    }

    # 3. Vérifier la configuration DSC
    Write-Host "`n État DSC :" -ForegroundColor Yellow

    foreach ($vm in $vms) {
        $dscStatus = az vm extension show `
            --name "DSC" `
            --vm-name $vm.name `
            --resource-group $ResourceGroup |
            ConvertFrom-Json

        Write-Host "  - $($vm.name): $($dscStatus.provisioningState)" -ForegroundColor $(
            if ($dscStatus.provisioningState -eq "Succeeded") { "Green" } else { "Red" }
        )
    }

    Write-Host "`n=== FIN VALIDATION ===" -ForegroundColor Cyan
    ```

---

## Quiz

1. **Quel mode DSC nécessite un serveur central ?**
   - [ ] A. Push
   - [ ] B. Pull
   - [ ] C. Les deux

2. **Quelle connexion utilise Ansible pour Windows ?**
   - [ ] A. SSH
   - [ ] B. WinRM
   - [ ] C. RDP

**Réponses :** 1-B, 2-B

---

**Précédent :** [Module 18 : Hybrid Cloud](18-hybrid-cloud.md)

**Suivant :** [Module 20 : Projet Final Expert](20-projet-final.md)

---

## Navigation

| | |
|:---|---:|
| [← Module 18 : Hybrid Cloud](18-hybrid-cloud.md) | [Module 20 : Projet Final Expert →](20-projet-final.md) |

[Retour au Programme](index.md){ .md-button }
