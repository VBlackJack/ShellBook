---
tags:
  - formation
  - security
  - windows
  - hacking
  - lab
  - vagrant
  - automation
---

# Lab Automatisé - Vagrantfile Complet

Ce guide fournit un Vagrantfile complet pour déployer automatiquement un environnement Active Directory vulnérable pour la formation.

---

## Prérequis

### Matériel

| Composant | Minimum | Recommandé |
|-----------|---------|------------|
| RAM | 16 Go | 32 Go |
| CPU | 4 cores | 8+ cores |
| Stockage | 150 Go SSD | 300 Go NVMe |

### Logiciels

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install -y virtualbox virtualbox-ext-pack

# Installation Vagrant
wget https://releases.hashicorp.com/vagrant/2.4.1/vagrant_2.4.1-1_amd64.deb
sudo dpkg -i vagrant_2.4.1-1_amd64.deb

# Plugins requis
vagrant plugin install vagrant-reload
vagrant plugin install vagrant-vbguest
```

### Boxes Vagrant

```bash
# Télécharger les boxes Windows (peut prendre du temps)
vagrant box add gusztavvargadr/windows-server-2019-standard
vagrant box add gusztavvargadr/windows-10
vagrant box add kalilinux/rolling
```

---

## Architecture du Lab

```
┌─────────────────────────────────────────────────────────────────┐
│                    Réseau : 192.168.56.0/24                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐       │
│  │  DC01    │  │  SRV01   │  │  WS01    │  │  KALI    │       │
│  │ .10      │  │  .20     │  │  .50     │  │  .100    │       │
│  │ DC+DNS   │  │ ADCS+FS  │  │ Client   │  │ Attacker │       │
│  │ 4Go RAM  │  │ 2Go RAM  │  │ 2Go RAM  │  │ 4Go RAM  │       │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘       │
│       │                                                        │
│       │ Parent Trust                                           │
│       ▼                                                        │
│  ┌──────────┐  ┌──────────┐                                   │
│  │  DC02    │  │  DEV01   │                                   │
│  │  .11     │  │  .30     │                                   │
│  │ Child DC │  │ Dev Srv  │                                   │
│  │ 4Go RAM  │  │ 2Go RAM  │                                   │
│  └──────────┘  └──────────┘                                   │
│                                                                 │
│            YOURCOMPANY-DEV.LOCAL (Child Domain)                │
└─────────────────────────────────────────────────────────────────┘
```

---

## Vagrantfile Complet

Créez un fichier `Vagrantfile` dans un nouveau répertoire :

```ruby
# -*- mode: ruby -*-
# vi: set ft=ruby :

# ============================================================
# Windows Hacking Mastery - Vulnerable AD Lab
# ============================================================
# Ce Vagrantfile déploie un environnement AD vulnérable complet
# pour la formation au pentest Windows/Active Directory.
#
# Usage:
#   vagrant up           # Déploie tout le lab (~60-90 min)
#   vagrant up dc01      # Déploie uniquement DC01
#   vagrant status       # Vérifie l'état des VMs
#   vagrant halt         # Arrête toutes les VMs
#   vagrant destroy -f   # Supprime tout le lab
# ============================================================

# Configuration globale
DOMAIN_NAME = "yourcompany.local"
DOMAIN_NETBIOS = "YOURCOMPANY"
CHILD_DOMAIN = "dev.yourcompany.local"
CHILD_NETBIOS = "DEV"
SAFE_MODE_PASS = "P@ssw0rd123!"
ADMIN_PASS = "P@ssw0rd123!"

# Réseau
NETWORK_PREFIX = "192.168.56"

Vagrant.configure("2") do |config|

  # ============================================================
  # DC01 - Domain Controller Principal
  # ============================================================
  config.vm.define "dc01", primary: true do |dc01|
    dc01.vm.box = "gusztavvargadr/windows-server-2019-standard"
    dc01.vm.hostname = "DC01"
    dc01.vm.network "private_network", ip: "#{NETWORK_PREFIX}.10"

    dc01.vm.provider "virtualbox" do |vb|
      vb.name = "WHM-DC01"
      vb.memory = 4096
      vb.cpus = 2
      vb.gui = false
    end

    dc01.vm.communicator = "winrm"
    dc01.winrm.username = "vagrant"
    dc01.winrm.password = "vagrant"
    dc01.vm.boot_timeout = 600

    # Provisioning - Installation AD DS
    dc01.vm.provision "shell", inline: <<-SHELL
      # Désactiver le firewall pour le lab
      Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False

      # Installation du rôle AD DS
      Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
    SHELL

    # Reboot après installation du rôle
    dc01.vm.provision :reload

    # Promotion en Domain Controller
    dc01.vm.provision "shell", inline: <<-SHELL
      $SafePass = ConvertTo-SecureString '#{SAFE_MODE_PASS}' -AsPlainText -Force

      # Vérifier si déjà promu
      $domain = Get-WmiObject Win32_ComputerSystem | Select-Object -ExpandProperty Domain
      if ($domain -ne "#{DOMAIN_NAME}") {
        Install-ADDSForest `
          -DomainName "#{DOMAIN_NAME}" `
          -DomainNetBIOSName "#{DOMAIN_NETBIOS}" `
          -SafeModeAdministratorPassword $SafePass `
          -InstallDns:$true `
          -NoRebootOnCompletion:$false `
          -Force:$true
      }
    SHELL

    # Reboot après promotion
    dc01.vm.provision :reload

    # Configuration des vulnérabilités
    dc01.vm.provision "shell", path: "scripts/configure-vulns.ps1"
  end

  # ============================================================
  # DC02 - Domain Controller Enfant (DEV)
  # ============================================================
  config.vm.define "dc02" do |dc02|
    dc02.vm.box = "gusztavvargadr/windows-server-2019-standard"
    dc02.vm.hostname = "DC02"
    dc02.vm.network "private_network", ip: "#{NETWORK_PREFIX}.11"

    dc02.vm.provider "virtualbox" do |vb|
      vb.name = "WHM-DC02"
      vb.memory = 4096
      vb.cpus = 2
      vb.gui = false
    end

    dc02.vm.communicator = "winrm"
    dc02.winrm.username = "vagrant"
    dc02.winrm.password = "vagrant"
    dc02.vm.boot_timeout = 600

    # Attendre que DC01 soit prêt
    dc02.vm.provision "shell", inline: <<-SHELL
      # Configurer DNS vers DC01
      $adapter = Get-NetAdapter | Where-Object {$_.Status -eq "Up"} | Select-Object -First 1
      Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses "#{NETWORK_PREFIX}.10"

      # Désactiver le firewall
      Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False

      # Installation du rôle AD DS
      Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
    SHELL

    dc02.vm.provision :reload

    # Promotion en DC enfant
    dc02.vm.provision "shell", inline: <<-SHELL
      $SafePass = ConvertTo-SecureString '#{SAFE_MODE_PASS}' -AsPlainText -Force
      $Cred = New-Object PSCredential("#{DOMAIN_NETBIOS}\\Administrator", $SafePass)

      # Attendre que le domaine parent soit disponible
      $maxRetries = 30
      $retry = 0
      while ($retry -lt $maxRetries) {
        try {
          $null = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain(
            (New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain", "#{DOMAIN_NAME}"))
          )
          Write-Host "[+] Parent domain is available"
          break
        } catch {
          Write-Host "[*] Waiting for parent domain... ($retry/$maxRetries)"
          Start-Sleep -Seconds 30
          $retry++
        }
      }

      # Créer le domaine enfant
      $domain = Get-WmiObject Win32_ComputerSystem | Select-Object -ExpandProperty Domain
      if ($domain -ne "#{CHILD_DOMAIN}") {
        Install-ADDSDomain `
          -NewDomainName "dev" `
          -ParentDomainName "#{DOMAIN_NAME}" `
          -DomainType "ChildDomain" `
          -SafeModeAdministratorPassword $SafePass `
          -Credential $Cred `
          -InstallDns:$true `
          -NoRebootOnCompletion:$false `
          -Force:$true
      }
    SHELL

    dc02.vm.provision :reload
  end

  # ============================================================
  # SRV01 - Serveur ADCS + File Server
  # ============================================================
  config.vm.define "srv01" do |srv01|
    srv01.vm.box = "gusztavvargadr/windows-server-2019-standard"
    srv01.vm.hostname = "SRV01"
    srv01.vm.network "private_network", ip: "#{NETWORK_PREFIX}.20"

    srv01.vm.provider "virtualbox" do |vb|
      vb.name = "WHM-SRV01"
      vb.memory = 2048
      vb.cpus = 2
      vb.gui = false
    end

    srv01.vm.communicator = "winrm"
    srv01.winrm.username = "vagrant"
    srv01.winrm.password = "vagrant"
    srv01.vm.boot_timeout = 600

    srv01.vm.provision "shell", inline: <<-SHELL
      # Configurer DNS vers DC01
      $adapter = Get-NetAdapter | Where-Object {$_.Status -eq "Up"} | Select-Object -First 1
      Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses "#{NETWORK_PREFIX}.10"

      # Désactiver le firewall
      Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
    SHELL

    srv01.vm.provision :reload

    # Joindre le domaine
    srv01.vm.provision "shell", inline: <<-SHELL
      $Pass = ConvertTo-SecureString '#{ADMIN_PASS}' -AsPlainText -Force
      $Cred = New-Object PSCredential("#{DOMAIN_NETBIOS}\\Administrator", $Pass)

      # Attendre le DC
      $maxRetries = 20
      $retry = 0
      while ($retry -lt $maxRetries) {
        if (Test-Connection -ComputerName "#{NETWORK_PREFIX}.10" -Count 1 -Quiet) {
          try {
            Add-Computer -DomainName "#{DOMAIN_NAME}" -Credential $Cred -Force -Restart
            break
          } catch {
            Write-Host "[*] Waiting to join domain... ($retry/$maxRetries)"
            Start-Sleep -Seconds 30
            $retry++
          }
        }
      }
    SHELL

    srv01.vm.provision :reload

    # Installer ADCS avec vulnérabilités
    srv01.vm.provision "shell", path: "scripts/install-adcs.ps1"
  end

  # ============================================================
  # WS01 - Workstation Windows 10
  # ============================================================
  config.vm.define "ws01" do |ws01|
    ws01.vm.box = "gusztavvargadr/windows-10"
    ws01.vm.hostname = "WS01"
    ws01.vm.network "private_network", ip: "#{NETWORK_PREFIX}.50"

    ws01.vm.provider "virtualbox" do |vb|
      vb.name = "WHM-WS01"
      vb.memory = 2048
      vb.cpus = 2
      vb.gui = true  # GUI pour workstation
    end

    ws01.vm.communicator = "winrm"
    ws01.winrm.username = "vagrant"
    ws01.winrm.password = "vagrant"
    ws01.vm.boot_timeout = 600

    ws01.vm.provision "shell", inline: <<-SHELL
      # Configurer DNS
      $adapter = Get-NetAdapter | Where-Object {$_.Status -eq "Up"} | Select-Object -First 1
      Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses "#{NETWORK_PREFIX}.10"

      # Désactiver firewall et Defender (pour le lab uniquement!)
      Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
      Set-MpPreference -DisableRealtimeMonitoring $true
    SHELL

    ws01.vm.provision :reload

    # Joindre le domaine
    ws01.vm.provision "shell", inline: <<-SHELL
      $Pass = ConvertTo-SecureString '#{ADMIN_PASS}' -AsPlainText -Force
      $Cred = New-Object PSCredential("#{DOMAIN_NETBIOS}\\Administrator", $Pass)

      $maxRetries = 20
      $retry = 0
      while ($retry -lt $maxRetries) {
        try {
          Add-Computer -DomainName "#{DOMAIN_NAME}" -Credential $Cred -Force -Restart
          break
        } catch {
          Start-Sleep -Seconds 30
          $retry++
        }
      }
    SHELL

    ws01.vm.provision :reload
  end

  # ============================================================
  # KALI - Machine d'attaque
  # ============================================================
  config.vm.define "kali" do |kali|
    kali.vm.box = "kalilinux/rolling"
    kali.vm.hostname = "kali"
    kali.vm.network "private_network", ip: "#{NETWORK_PREFIX}.100"

    kali.vm.provider "virtualbox" do |vb|
      vb.name = "WHM-KALI"
      vb.memory = 4096
      vb.cpus = 2
      vb.gui = true
    end

    kali.vm.provision "shell", inline: <<-SHELL
      # Mise à jour
      apt-get update

      # Installer les outils essentiels
      apt-get install -y \
        bloodhound \
        neo4j \
        crackmapexec \
        evil-winrm \
        responder \
        feroxbuster

      # Installer Impacket via pipx
      apt-get install -y pipx
      pipx install impacket
      pipx ensurepath

      # Kerbrute
      wget -q https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64 -O /usr/local/bin/kerbrute
      chmod +x /usr/local/bin/kerbrute

      # Certipy
      pipx install certipy-ad

      # Configurer /etc/hosts
      echo "#{NETWORK_PREFIX}.10 dc01.#{DOMAIN_NAME} dc01" >> /etc/hosts
      echo "#{NETWORK_PREFIX}.11 dc02.#{CHILD_DOMAIN} dc02" >> /etc/hosts
      echo "#{NETWORK_PREFIX}.20 srv01.#{DOMAIN_NAME} srv01" >> /etc/hosts

      echo "[+] Kali setup complete!"
    SHELL
  end

end
```

---

## Scripts de Provisioning

### scripts/configure-vulns.ps1

Créez le dossier `scripts/` et le fichier suivant :

```powershell
# ============================================================
# Configuration des vulnérabilités AD
# Exécuté sur DC01 après promotion
# ============================================================

Import-Module ActiveDirectory
$Domain = "yourcompany.local"

Write-Host "`n[*] Configuration des vulnérabilités AD..." -ForegroundColor Cyan

# ============================================================
# 1. Utilisateurs avec mots de passe faibles
# ============================================================
Write-Host "`n[+] Création des utilisateurs vulnérables..." -ForegroundColor Green

$Users = @(
    @{
        Name = "svc_backup"
        Password = "Backup123!"
        SPN = "MSSQLSvc/srv01.yourcompany.local:1433"
        Description = "Service account for SQL backups"
        Group = "Domain Users"
    },
    @{
        Name = "svc_web"
        Password = "Summer2024"
        SPN = "HTTP/srv01.yourcompany.local"
        Description = "IIS Service Account"
        Group = "Domain Users"
    },
    @{
        Name = "svc_admin"
        Password = "ServiceAdmin1"
        SPN = "cifs/srv01.yourcompany.local"
        Description = "Admin service account"
        Group = "Domain Admins"  # Vulnérabilité : service account DA !
    },
    @{
        Name = "j.smith"
        Password = "Welcome1"
        Description = "John Smith - IT Support"
        Group = "IT_Support"
    },
    @{
        Name = "a.johnson"
        Password = "Password123"
        Description = "Alice Johnson - HR"
        Group = "HR_Users"
    },
    @{
        Name = "b.wilson"
        Password = "Company2024!"
        Description = "Bob Wilson - Finance"
        Group = "Finance_Users"
    },
    @{
        Name = "admin.local"
        Password = "Admin123"
        Description = "Local admin account"
        Group = "IT_Admins"
    },
    @{
        Name = "helpdesk"
        Password = "Help2024!"
        Description = "Helpdesk shared account"
        Group = "IT_Support"
    }
)

# Créer les OUs
$OUs = @("IT", "HR", "Finance", "Services", "Admins")
foreach ($OU in $OUs) {
    try {
        New-ADOrganizationalUnit -Name $OU -Path "DC=yourcompany,DC=local" -ErrorAction SilentlyContinue
    } catch {}
}

# Créer les groupes
$Groups = @("IT_Support", "IT_Admins", "HR_Users", "Finance_Users")
foreach ($Group in $Groups) {
    try {
        New-ADGroup -Name $Group -GroupScope Global -GroupCategory Security -ErrorAction SilentlyContinue
    } catch {}
}

# Créer les utilisateurs
foreach ($User in $Users) {
    try {
        $SecurePass = ConvertTo-SecureString $User.Password -AsPlainText -Force

        New-ADUser -Name $User.Name `
                   -SamAccountName $User.Name `
                   -UserPrincipalName "$($User.Name)@$Domain" `
                   -AccountPassword $SecurePass `
                   -Enabled $true `
                   -PasswordNeverExpires $true `
                   -Description $User.Description `
                   -ErrorAction Stop

        # Ajouter au groupe
        if ($User.Group -eq "Domain Admins") {
            Add-ADGroupMember -Identity "Domain Admins" -Members $User.Name
        } elseif ($User.Group) {
            try {
                Add-ADGroupMember -Identity $User.Group -Members $User.Name -ErrorAction SilentlyContinue
            } catch {}
        }

        # Configurer SPN si défini
        if ($User.SPN) {
            Set-ADUser -Identity $User.Name -ServicePrincipalNames @{Add=$User.SPN}
            Write-Host "    [Kerberoastable] $($User.Name) - SPN: $($User.SPN)" -ForegroundColor Yellow
        }

        Write-Host "    Created: $($User.Name)" -ForegroundColor White
    } catch {
        Write-Host "    [!] Error creating $($User.Name): $_" -ForegroundColor Red
    }
}

# ============================================================
# 2. AS-REP Roastable Users
# ============================================================
Write-Host "`n[+] Configuration AS-REP Roasting..." -ForegroundColor Green

$ASREPUsers = @("j.smith", "helpdesk")
foreach ($User in $ASREPUsers) {
    try {
        Set-ADAccountControl -Identity $User -DoesNotRequirePreAuth $true
        Write-Host "    [AS-REP Roastable] $User" -ForegroundColor Yellow
    } catch {}
}

# ============================================================
# 3. Unconstrained Delegation
# ============================================================
Write-Host "`n[+] Configuration Unconstrained Delegation..." -ForegroundColor Green

# Sera appliqué sur SRV01 après qu'il rejoint le domaine
# Pour l'instant, préparer le script

# ============================================================
# 4. DCSync Rights (Vulnérabilité ACL)
# ============================================================
Write-Host "`n[+] Configuration DCSync rights pour IT_Admins..." -ForegroundColor Green

try {
    $RootDSE = Get-ADRootDSE
    $DomainDN = $RootDSE.defaultNamingContext
    $ACL = Get-Acl "AD:\$DomainDN"
    $SID = (Get-ADGroup "IT_Admins").SID

    # DS-Replication-Get-Changes
    $ACE1 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $SID, "ExtendedRight", "Allow",
        [GUID]"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
    )

    # DS-Replication-Get-Changes-All
    $ACE2 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $SID, "ExtendedRight", "Allow",
        [GUID]"1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
    )

    $ACL.AddAccessRule($ACE1)
    $ACL.AddAccessRule($ACE2)
    Set-Acl "AD:\$DomainDN" $ACL

    Write-Host "    [DCSync] IT_Admins group has replication rights" -ForegroundColor Yellow
} catch {
    Write-Host "    [!] Error setting DCSync rights: $_" -ForegroundColor Red
}

# ============================================================
# 5. GenericAll sur Domain Admins (pour b.wilson)
# ============================================================
Write-Host "`n[+] Configuration ACL abuse (GenericAll)..." -ForegroundColor Green

try {
    $DAGroup = Get-ADGroup "Domain Admins"
    $User = Get-ADUser "b.wilson"

    $ACL = Get-Acl "AD:\$($DAGroup.DistinguishedName)"
    $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $User.SID, "GenericAll", "Allow"
    )
    $ACL.AddAccessRule($ACE)
    Set-Acl "AD:\$($DAGroup.DistinguishedName)" $ACL

    Write-Host "    [GenericAll] b.wilson has GenericAll on Domain Admins" -ForegroundColor Yellow
} catch {
    Write-Host "    [!] Error: $_" -ForegroundColor Red
}

# ============================================================
# 6. Désactiver SMB Signing (pour relay attacks)
# ============================================================
Write-Host "`n[+] Désactivation SMB Signing (relay attacks)..." -ForegroundColor Green

try {
    Set-SmbServerConfiguration -RequireSecuritySignature $false -EnableSecuritySignature $false -Force
    Write-Host "    [SMB Relay] SMB signing disabled" -ForegroundColor Yellow
} catch {}

# ============================================================
# 7. LLMNR/NBT-NS (activés par défaut sur Windows)
# ============================================================
Write-Host "`n[+] LLMNR et NBT-NS sont activés par défaut" -ForegroundColor Green
Write-Host "    [LLMNR Poisoning] Vulnerable to Responder attacks" -ForegroundColor Yellow

# ============================================================
# 8. Partages réseau avec permissions faibles
# ============================================================
Write-Host "`n[+] Création de partages vulnérables..." -ForegroundColor Green

try {
    New-Item -ItemType Directory -Path "C:\Shares\Public" -Force | Out-Null
    New-Item -ItemType Directory -Path "C:\Shares\IT" -Force | Out-Null
    New-Item -ItemType Directory -Path "C:\Shares\Scripts" -Force | Out-Null

    # Partage public (Everyone)
    New-SmbShare -Name "Public" -Path "C:\Shares\Public" -FullAccess "Everyone" -ErrorAction SilentlyContinue

    # Partage IT avec scripts
    New-SmbShare -Name "IT" -Path "C:\Shares\IT" -FullAccess "IT_Support","IT_Admins" -ErrorAction SilentlyContinue

    # Partage Scripts lisible par tous (pour découverte de creds)
    New-SmbShare -Name "Scripts" -Path "C:\Shares\Scripts" -ReadAccess "Domain Users" -ErrorAction SilentlyContinue

    # Créer un script avec credentials en clair (vulnérabilité courante)
    $ScriptContent = @"
# Deployment Script - DO NOT SHARE
`$server = "srv01.yourcompany.local"
`$username = "svc_deploy"
`$password = "Deploy2024!"

# Connect to remote server
net use \\`$server\C$ /user:`$username `$password
"@
    Set-Content -Path "C:\Shares\Scripts\deploy.ps1" -Value $ScriptContent

    Write-Host "    [Shares] Created vulnerable shares with exposed credentials" -ForegroundColor Yellow
} catch {
    Write-Host "    [!] Error creating shares: $_" -ForegroundColor Red
}

# ============================================================
# 9. Password Policy faible
# ============================================================
Write-Host "`n[+] Configuration Password Policy faible..." -ForegroundColor Green

try {
    Set-ADDefaultDomainPasswordPolicy -Identity $Domain `
        -MinPasswordLength 6 `
        -PasswordHistoryCount 0 `
        -ComplexityEnabled $false `
        -MinPasswordAge 0 `
        -MaxPasswordAge 0 `
        -LockoutThreshold 0  # Pas de lockout = password spray possible

    Write-Host "    [Password Policy] Weak policy configured (min 6 chars, no complexity, no lockout)" -ForegroundColor Yellow
} catch {
    Write-Host "    [!] Error: $_" -ForegroundColor Red
}

# ============================================================
# Résumé des vulnérabilités
# ============================================================
Write-Host "`n" + "="*60 -ForegroundColor Cyan
Write-Host "VULNÉRABILITÉS CONFIGURÉES" -ForegroundColor Cyan
Write-Host "="*60 -ForegroundColor Cyan
Write-Host @"

[Kerberoasting]
  - svc_backup (Backup123!)
  - svc_web (Summer2024)
  - svc_admin (ServiceAdmin1) - DOMAIN ADMIN!

[AS-REP Roasting]
  - j.smith (Welcome1)
  - helpdesk (Help2024!)

[Password Spray Targets]
  - a.johnson (Password123)
  - b.wilson (Company2024!)

[Privilege Escalation]
  - IT_Admins group has DCSync rights
  - b.wilson has GenericAll on Domain Admins

[Network Attacks]
  - SMB Signing disabled (relay attacks)
  - LLMNR/NBT-NS enabled (poisoning)

[Information Disclosure]
  - \\DC01\Scripts\deploy.ps1 contains cleartext credentials
  - Weak password policy (no lockout)

"@ -ForegroundColor White

Write-Host "[*] Vulnerable AD configuration complete!" -ForegroundColor Green
```

### scripts/install-adcs.ps1

```powershell
# ============================================================
# Installation ADCS avec vulnérabilités ESC
# Exécuté sur SRV01 après jonction au domaine
# ============================================================

Write-Host "`n[*] Installation ADCS avec vulnérabilités ESC..." -ForegroundColor Cyan

# Attendre que le serveur soit bien dans le domaine
Start-Sleep -Seconds 30

# ============================================================
# 1. Installation du rôle ADCS
# ============================================================
Write-Host "`n[+] Installation du rôle AD Certificate Services..." -ForegroundColor Green

Install-WindowsFeature -Name AD-Certificate -IncludeManagementTools
Install-WindowsFeature -Name ADCS-Cert-Authority -IncludeManagementTools
Install-WindowsFeature -Name ADCS-Web-Enrollment -IncludeManagementTools

# ============================================================
# 2. Configuration de l'autorité de certification
# ============================================================
Write-Host "`n[+] Configuration de l'autorité de certification..." -ForegroundColor Green

try {
    Install-AdcsCertificationAuthority `
        -CAType EnterpriseRootCA `
        -CACommonName "YOURCOMPANY-CA" `
        -KeyLength 2048 `
        -HashAlgorithmName SHA256 `
        -ValidityPeriod Years `
        -ValidityPeriodUnits 10 `
        -Force

    Write-Host "    CA installed: YOURCOMPANY-CA" -ForegroundColor White
} catch {
    Write-Host "    [!] CA may already be installed: $_" -ForegroundColor Yellow
}

# ============================================================
# 3. Installation Web Enrollment (pour ESC8)
# ============================================================
Write-Host "`n[+] Installation Web Enrollment (ESC8 vulnerability)..." -ForegroundColor Green

try {
    Install-AdcsWebEnrollment -Force
    Write-Host "    [ESC8] Web Enrollment enabled at /certsrv" -ForegroundColor Yellow
} catch {
    Write-Host "    [!] Web Enrollment: $_" -ForegroundColor Yellow
}

# ============================================================
# 4. Création de templates vulnérables
# ============================================================
Write-Host "`n[+] Création de templates de certificats vulnérables..." -ForegroundColor Green

# Note : La création de templates via PowerShell est complexe.
# Utiliser certtmpl.msc manuellement ou DVAD pour des templates préconfigurés.

# Pour ESC1 : Template avec Client Authentication + SAN modifiable
# Pour ESC4 : Template avec Authenticated Users ayant Write permissions

Write-Host @"

[!] IMPORTANT: Templates vulnérables à créer manuellement :

1. Ouvrir certtmpl.msc sur le serveur
2. Dupliquer le template "User"
3. Configurer les vulnérabilités :

   [ESC1 - SAN Injection]
   - Security : Domain Users = Enroll
   - Subject Name : "Supply in the request" (au lieu de "build from AD")
   - Application Policies : Client Authentication

   [ESC4 - Template ACL]
   - Security : Authenticated Users = Write

4. Publier les templates via certsrv.msc

"@ -ForegroundColor Yellow

# ============================================================
# 5. Activer NTLM sur l'enrollment (pour ESC8 relay)
# ============================================================
Write-Host "`n[+] Configuration IIS pour NTLM relay (ESC8)..." -ForegroundColor Green

try {
    # Désactiver Extended Protection (permet le relay)
    Import-Module WebAdministration
    Set-WebConfigurationProperty -Filter "/system.webServer/security/authentication/windowsAuthentication" `
        -Name "extendedProtection.tokenChecking" `
        -Value "None" `
        -PSPath "IIS:\Sites\Default Web Site\CertSrv"

    Write-Host "    [ESC8] Extended Protection disabled - vulnerable to NTLM relay" -ForegroundColor Yellow
} catch {
    Write-Host "    [!] IIS config: $_" -ForegroundColor Yellow
}

# ============================================================
# Résumé ADCS
# ============================================================
Write-Host "`n" + "="*60 -ForegroundColor Cyan
Write-Host "ADCS VULNERABILITIES" -ForegroundColor Cyan
Write-Host "="*60 -ForegroundColor Cyan
Write-Host @"

[ESC8 - NTLM Relay to Web Enrollment]
  URL: http://srv01.yourcompany.local/certsrv/
  Attack: certipy relay + PetitPotam/PrinterBug

[ESC1/ESC4]
  Require manual template configuration (see instructions above)
  Or use DVAD for pre-configured vulnerable templates

[Enumeration]
  certipy find -u user@yourcompany.local -p 'pass' -dc-ip 192.168.56.10

"@ -ForegroundColor White

Write-Host "[*] ADCS installation complete!" -ForegroundColor Green
```

---

## Déploiement

### Déploiement complet

```bash
# Créer la structure
mkdir -p ad-lab/scripts
cd ad-lab

# Copier le Vagrantfile et les scripts (depuis cette page)
# Puis lancer le déploiement

vagrant up

# Le déploiement prend 60-90 minutes
# Les VMs démarrent dans l'ordre : dc01 -> dc02 -> srv01 -> ws01 -> kali
```

### Déploiement partiel

```bash
# Déployer uniquement certaines machines
vagrant up dc01          # Domain Controller principal uniquement
vagrant up dc01 kali     # DC + machine d'attaque
vagrant up dc01 srv01 kali  # Lab minimal pour ADCS
```

### Commandes utiles

```bash
# État des VMs
vagrant status

# Se connecter à une VM
vagrant ssh kali            # Linux
vagrant rdp ws01            # Windows (si RDP configuré)
vagrant winrm dc01 -c "hostname"  # Commande WinRM

# Redémarrer une VM
vagrant reload srv01

# Reprovisioner (réappliquer les scripts)
vagrant provision dc01

# Arrêter le lab
vagrant halt

# Supprimer tout
vagrant destroy -f
```

---

## Vérification du Lab

### Depuis Kali

```bash
# Vérifier la connectivité
ping 192.168.56.10

# Énumérer le domaine
crackmapexec smb 192.168.56.10
crackmapexec smb 192.168.56.10 -u 'j.smith' -p 'Welcome1' --shares

# Collecter BloodHound
bloodhound-python -d yourcompany.local -u j.smith -p 'Welcome1' -dc 192.168.56.10 -c All

# Tester Kerberoasting
GetUserSPNs.py yourcompany.local/j.smith:'Welcome1' -dc-ip 192.168.56.10 -request

# Tester AS-REP Roasting
GetNPUsers.py yourcompany.local/ -usersfile users.txt -dc-ip 192.168.56.10
```

### Checklist de validation

- [ ] DC01 répond sur 192.168.56.10
- [ ] DNS résout `dc01.yourcompany.local`
- [ ] Authentification fonctionne avec les credentials de test
- [ ] BloodHound collecte les données
- [ ] Utilisateurs Kerberoastable détectés (svc_backup, svc_web, svc_admin)
- [ ] Utilisateurs AS-REP Roastable détectés (j.smith, helpdesk)
- [ ] Partages accessibles et scripts visibles
- [ ] ADCS accessible sur SRV01 (si déployé)

---

## Troubleshooting

### Problèmes courants

| Problème | Solution |
|----------|----------|
| VM ne démarre pas | Vérifier RAM disponible, désactiver Hyper-V |
| Timeout WinRM | Augmenter `boot_timeout`, vérifier le firewall |
| Échec jonction domaine | Vérifier DNS, attendre que DC01 soit prêt |
| Box non trouvée | `vagrant box add <box-name>` |
| Erreur provision | `vagrant provision <vm>` pour réessayer |

### Logs

```bash
# Logs Vagrant
vagrant up --debug > vagrant.log 2>&1

# Logs Windows (après connexion)
Get-EventLog -LogName System -Newest 50
Get-EventLog -LogName Application -Newest 50
```

### Reset complet

```bash
vagrant destroy -f
vagrant box update
rm -rf .vagrant/
vagrant up
```

---

## Personnalisation

### Modifier les credentials

Éditez les variables au début du Vagrantfile :

```ruby
DOMAIN_NAME = "yourcompany.local"  # Changez le nom de domaine
ADMIN_PASS = "VotreMotDePasse!"    # Changez le mot de passe admin
```

### Ajouter des VMs

Copiez un bloc de définition et modifiez :

```ruby
config.vm.define "srv02" do |srv02|
  srv02.vm.box = "gusztavvargadr/windows-server-2019-standard"
  srv02.vm.hostname = "SRV02"
  srv02.vm.network "private_network", ip: "#{NETWORK_PREFIX}.21"
  # ...
end
```

### Réduire les ressources

Pour les machines limitées en RAM :

```ruby
vb.memory = 2048  # Réduire à 2Go par VM Windows
vb.cpus = 1       # Un seul CPU
```

---

## Alternatives

| Projet | Description |
|--------|-------------|
| [DVAD](https://github.com/WazeHell/vulnerable-AD) | Damn Vulnerable AD - Lab préconfigur é|
| [GOAD](https://github.com/Orange-Cyberdefense/GOAD) | Game of Active Directory - Multi-forests |
| [DetectionLab](https://github.com/clong/DetectionLab) | Lab avec SIEM intégré |
| [PurpleCloud](https://github.com/iknowjason/PurpleCloud) | Lab cloud (Azure/AWS) |

---

[Retour au Module 01](01-module.md){ .md-button }
[Retour au Programme](index.md){ .md-button .md-button--primary }
