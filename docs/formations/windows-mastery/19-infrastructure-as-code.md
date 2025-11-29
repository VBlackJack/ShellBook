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
