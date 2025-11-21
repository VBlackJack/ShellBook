# Ansible for Windows: WinRM & Automation

`#ansible` `#windows` `#winrm` `#powershell` `#active-directory`

Piloter Windows sans agent SSH : Configuration WinRM et modules natifs.

---

## Le Défi de la Connexion : WinRM, pas SSH

### Pourquoi WinRM ?

**Sur Linux :** Ansible utilise SSH (protocole standard, omniprésent).

**Sur Windows :** SSH n'est pas le standard natif. Windows utilise **WinRM** (Windows Remote Management).

```
┌──────────────────┐            WinRM (5985/5986)           ┌──────────────────┐
│ Ansible Control  │ ──────────────────────────────────────► │  Windows Host    │
│    (Linux)       │            HTTP/HTTPS                   │   (WinRM enabled)│
└──────────────────┘                                         └──────────────────┘
```

| Aspect | SSH (Linux) | WinRM (Windows) |
|--------|-------------|-----------------|
| **Port** | 22 | 5985 (HTTP), 5986 (HTTPS) |
| **Transport** | SSH | HTTP/HTTPS |
| **Authentification** | Clés SSH, mot de passe | NTLM, Kerberos, CredSSP, Certificate |
| **Setup** | Natif | Nécessite configuration |

!!! danger "Prérequis : PowerShell Remoting Activé"
    WinRM n'est **pas activé par défaut** sur Windows. Il faut le configurer manuellement.

---

## Setup WinRM : Script de Configuration

### Script PowerShell Standard Ansible

**Fichier :** `ConfigureRemotingForAnsible.ps1`

Ce script officiel d'Ansible configure WinRM pour la gestion à distance.

```powershell
# ConfigureRemotingForAnsible.ps1
# Source: https://github.com/ansible/ansible/blob/devel/examples/scripts/ConfigureRemotingForAnsible.ps1

# Télécharger et exécuter le script officiel
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$url = "https://raw.githubusercontent.com/ansible/ansible/devel/examples/scripts/ConfigureRemotingForAnsible.ps1"
$file = "$env:temp\ConfigureRemotingForAnsible.ps1"
(New-Object -TypeName System.Net.WebClient).DownloadFile($url, $file)
powershell.exe -ExecutionPolicy ByPass -File $file
```

**Ou manuellement :**

```powershell
# Exécuter en tant qu'Administrateur

# Activer PowerShell Remoting
Enable-PSRemoting -Force

# Configurer WinRM
winrm quickconfig -quiet

# Autoriser l'authentification Basic (NTLM)
Set-Item -Path WSMan:\localhost\Service\Auth\Basic -Value $true

# Autoriser les connexions non chiffrées (LAB ONLY !)
Set-Item -Path WSMan:\localhost\Service\AllowUnencrypted -Value $true

# Créer un listener HTTP
New-NetFirewallRule -DisplayName "WinRM HTTP" `
    -Direction Inbound `
    -LocalPort 5985 `
    -Protocol TCP `
    -Action Allow

# Vérifier la configuration
winrm get winrm/config

# Tester localement
Test-WSMan -ComputerName localhost
```

!!! warning "Sécurité : Production vs Lab"
    **Pour un LAB :** Le script ci-dessus fonctionne (HTTP non chiffré).

    **Pour la PRODUCTION :**
    - ✅ Utilisez **HTTPS** (port 5986) avec un certificat valide
    - ✅ Utilisez **Kerberos** (Active Directory)
    - ✅ Désactivez `AllowUnencrypted`
    - ✅ Activez `CertificateThumbprintAuthentication` si possible

**Configuration HTTPS (Production) :**

```powershell
# Générer un certificat self-signed (ou utiliser un CA)
$cert = New-SelfSignedCertificate -DnsName "winhost.example.com" `
    -CertStoreLocation Cert:\LocalMachine\My `
    -NotAfter (Get-Date).AddYears(5)

# Créer un listener HTTPS
New-Item -Path WSMan:\localhost\Listener `
    -Transport HTTPS `
    -Address * `
    -CertificateThumbPrint $cert.Thumbprint -Force

# Firewall pour HTTPS
New-NetFirewallRule -DisplayName "WinRM HTTPS" `
    -Direction Inbound `
    -LocalPort 5986 `
    -Protocol TCP `
    -Action Allow
```

---

## Configuration Inventaire Ansible

### Variables Obligatoires (Côté Linux)

**Fichier :** `inventory/windows_hosts.yml`

```yaml
---
all:
  children:
    windows:
      hosts:
        win01.example.com:
          ansible_host: 192.168.1.100
        win02.example.com:
          ansible_host: 192.168.1.101

      vars:
        # === CONNEXION ===
        ansible_connection: winrm        # Utiliser WinRM au lieu de SSH

        # === AUTHENTIFICATION ===
        ansible_user: Administrator      # Ou utilisateur local/domaine
        ansible_password: "{{ vault_win_password }}"  # Utiliser Ansible Vault !

        # === TRANSPORT ===
        ansible_winrm_transport: ntlm    # Options : ntlm, kerberos, credssp, certificate

        # Port WinRM
        ansible_port: 5985               # HTTP (lab)
        # ansible_port: 5986             # HTTPS (production)

        # === VALIDATION CERTIFICAT ===
        ansible_winrm_server_cert_validation: ignore  # LAB ONLY !
        # ansible_winrm_server_cert_validation: validate  # Production

        # === TIMEOUT ===
        ansible_winrm_connection_timeout: 60
        ansible_winrm_operation_timeout: 60
        ansible_winrm_read_timeout: 70
```

### Configuration pour Active Directory (Kerberos)

**Prérequis :** Installer `pywinrm[kerberos]` sur le contrôleur Ansible.

```bash
# Sur le contrôleur Linux
pip install "pywinrm[kerberos]"

# Installer krb5
sudo apt install krb5-user  # Debian/Ubuntu
sudo yum install krb5-workstation  # RHEL/CentOS
```

**Fichier :** `/etc/krb5.conf`

```ini
[libdefaults]
    default_realm = EXAMPLE.COM
    dns_lookup_realm = false
    dns_lookup_kdc = true

[realms]
    EXAMPLE.COM = {
        kdc = dc01.example.com
        admin_server = dc01.example.com
    }

[domain_realm]
    .example.com = EXAMPLE.COM
    example.com = EXAMPLE.COM
```

**Inventaire avec Kerberos :**

```yaml
---
all:
  children:
    windows_domain:
      hosts:
        win-server.example.com:

      vars:
        ansible_connection: winrm
        ansible_user: Administrator@EXAMPLE.COM  # Format UPN
        ansible_password: "{{ vault_ad_password }}"
        ansible_winrm_transport: kerberos       # Kerberos (AD)
        ansible_port: 5986                       # HTTPS obligatoire
        ansible_winrm_server_cert_validation: validate
```

### Tester la Connexion

```bash
# Ping Windows depuis Ansible
ansible windows -i inventory/windows_hosts.yml -m win_ping

# Output attendu :
# win01.example.com | SUCCESS => {
#     "changed": false,
#     "ping": "pong"
# }

# Test avec variable (gather_facts)
ansible windows -i inventory/windows_hosts.yml -m setup

# Test avec commande PowerShell
ansible windows -i inventory/windows_hosts.yml \
    -m win_shell -a "Get-ComputerInfo | Select-Object CsName, OsName"
```

---

## Les Modules `win_` Indispensables

!!! warning "Ne PAS utiliser les modules Linux !"
    - ❌ `file` → ✅ `win_file`
    - ❌ `copy` → ✅ `win_copy`
    - ❌ `shell` → ✅ `win_shell`
    - ❌ `service` → ✅ `win_service`
    - ❌ `apt` / `yum` → ✅ `win_package` / `win_chocolatey`

### `win_feature` : Gérer les Rôles Windows

**Installer IIS (Web Server) :**

```yaml
---
- name: Install IIS Web Server
  hosts: windows
  tasks:
    - name: Install IIS feature
      ansible.windows.win_feature:
        name: Web-Server
        state: present
        include_management_tools: yes
      register: iis_install

    - name: Reboot if required
      ansible.windows.win_reboot:
        msg: "Reboot initiated by Ansible for IIS installation"
      when: iis_install.reboot_required
```

**Installer Remote Server Administration Tools (RSAT) :**

```yaml
---
- name: Install RSAT tools
  hosts: windows
  tasks:
    - name: Install RSAT AD DS tools
      ansible.windows.win_feature:
        name:
          - RSAT-AD-Tools
          - RSAT-AD-PowerShell
          - RSAT-ADDS
        state: present
        include_management_tools: yes
```

**Lister les features disponibles :**

```yaml
---
- name: List all Windows features
  hosts: windows
  tasks:
    - name: Get all features
      ansible.windows.win_shell: Get-WindowsFeature | Where-Object {$_.InstallState -eq "Available"}
      register: features

    - name: Display features
      ansible.builtin.debug:
        var: features.stdout_lines
```

### `win_service` : Gérer les Services

```yaml
---
- name: Manage Windows services
  hosts: windows
  tasks:
    # Démarrer un service
    - name: Ensure W3SVC (IIS) is running
      ansible.windows.win_service:
        name: W3SVC
        state: started
        start_mode: auto

    # Arrêter un service
    - name: Stop Windows Update service
      ansible.windows.win_service:
        name: wuauserv
        state: stopped
        start_mode: disabled

    # Redémarrer un service
    - name: Restart DNS Client
      ansible.windows.win_service:
        name: Dnscache
        state: restarted

    # Vérifier l'état d'un service
    - name: Check service status
      ansible.windows.win_service_info:
        name: W3SVC
      register: service_info

    - name: Display service info
      ansible.builtin.debug:
        msg: "Service {{ service_info.services[0].display_name }} is {{ service_info.services[0].state }}"
```

### `win_package` : Installer des Logiciels

```yaml
---
- name: Install software via MSI
  hosts: windows
  tasks:
    # Installer depuis un MSI local
    - name: Install 7-Zip
      ansible.windows.win_package:
        path: C:\Temp\7z-x64.msi
        state: present
        arguments: /quiet /norestart

    # Installer depuis une URL
    - name: Install Notepad++
      ansible.windows.win_package:
        path: https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v8.5.4/npp.8.5.4.Installer.x64.exe
        product_id: Notepad++
        arguments: /S
        state: present

    # Désinstaller
    - name: Uninstall software
      ansible.windows.win_package:
        product_id: '{GUID-OF-PRODUCT}'
        state: absent
```

### `win_chocolatey` : Package Manager pour Windows

!!! tip "Chocolatey : Le APT de Windows"
    Chocolatey est un package manager pour Windows. **Beaucoup plus simple que MSI !**

**Installer Chocolatey d'abord :**

```yaml
---
- name: Setup Chocolatey
  hosts: windows
  tasks:
    - name: Install Chocolatey
      ansible.windows.win_chocolatey:
        name: chocolatey
        state: present
```

**Installer des packages :**

```yaml
---
- name: Install packages with Chocolatey
  hosts: windows
  tasks:
    - name: Install common tools
      ansible.windows.win_chocolatey:
        name:
          - git
          - vscode
          - googlechrome
          - 7zip
          - python
        state: present

    - name: Install specific version
      ansible.windows.win_chocolatey:
        name: nodejs
        version: 18.17.1
        state: present

    - name: Upgrade all packages
      ansible.windows.win_chocolatey:
        name: all
        state: latest
```

### `win_file` / `win_copy` : Gestion de Fichiers

```yaml
---
- name: File management
  hosts: windows
  tasks:
    # Créer un dossier
    - name: Create directory
      ansible.windows.win_file:
        path: C:\MyApp\Config
        state: directory

    # Copier un fichier depuis le contrôleur
    - name: Copy configuration file
      ansible.windows.win_copy:
        src: files/config.ini
        dest: C:\MyApp\Config\config.ini

    # Copier un dossier complet
    - name: Copy entire directory
      ansible.windows.win_copy:
        src: files/webapp/
        dest: C:\inetpub\wwwroot\
        remote_src: no

    # Supprimer un fichier
    - name: Delete file
      ansible.windows.win_file:
        path: C:\Temp\old_file.txt
        state: absent

    # Créer un lien symbolique
    - name: Create symlink
      ansible.windows.win_file:
        src: C:\MyApp\Data
        dest: C:\Data
        state: link
```

---

## PowerShell & Ansible

### `win_shell` vs `win_command`

| Module | Usage | Quand l'utiliser |
|--------|-------|------------------|
| `win_command` | Exécute une commande (pas de shell) | Binaires directs (exe, cmd) |
| `win_shell` | Exécute via PowerShell | Scripts PS, pipes, variables |

```yaml
---
- name: Command vs Shell
  hosts: windows
  tasks:
    # win_command : Simple, pas de shell
    - name: Run executable
      ansible.windows.win_command: ipconfig /all
      register: ipconfig

    # win_shell : PowerShell complet
    - name: Run PowerShell command
      ansible.windows.win_shell: |
        Get-Process | Where-Object {$_.CPU -gt 100} | Select-Object Name, CPU
      register: high_cpu_processes

    - name: Display results
      ansible.builtin.debug:
        var: high_cpu_processes.stdout_lines
```

### Exécuter un Script PowerShell Complexe

**Scénario :** Créer un utilisateur Active Directory avec Ansible.

```yaml
---
- name: Create AD User
  hosts: domain_controller
  tasks:
    - name: Create AD user with PowerShell
      ansible.windows.win_shell: |
        Import-Module ActiveDirectory

        $username = "{{ ad_username }}"
        $password = ConvertTo-SecureString "{{ ad_password }}" -AsPlainText -Force
        $ou = "OU=Users,OU=IT,DC=example,DC=com"

        # Vérifier si l'utilisateur existe
        $user = Get-ADUser -Filter "SamAccountName -eq '$username'" -ErrorAction SilentlyContinue

        if (-not $user) {
            New-ADUser -Name $username `
                -GivenName "{{ first_name }}" `
                -Surname "{{ last_name }}" `
                -SamAccountName $username `
                -UserPrincipalName "$username@example.com" `
                -Path $ou `
                -AccountPassword $password `
                -Enabled $true `
                -ChangePasswordAtLogon $false `
                -PasswordNeverExpires $true

            Write-Output "User $username created successfully"
        } else {
            Write-Output "User $username already exists"
        }
      register: ad_user_creation

    - name: Display result
      ansible.builtin.debug:
        var: ad_user_creation.stdout_lines
```

**Avec un fichier de script externe :**

```yaml
---
- name: Run external PowerShell script
  hosts: windows
  tasks:
    - name: Copy PowerShell script
      ansible.windows.win_copy:
        src: scripts/CreateADUser.ps1
        dest: C:\Temp\CreateADUser.ps1

    - name: Execute script
      ansible.windows.win_shell: |
        C:\Temp\CreateADUser.ps1 -Username "{{ username }}" -Password "{{ password }}"
      register: script_output

    - name: Show output
      ansible.builtin.debug:
        var: script_output.stdout
```

---

## Cas d'Usage "Production"

### Scénario 1 : Déployer IIS avec Page Custom

**Playbook complet :**

```yaml
---
- name: Deploy IIS Web Server with custom page
  hosts: webservers
  vars:
    website_name: "MyWebsite"
    website_path: "C:\\inetpub\\wwwroot\\{{ website_name }}"
    website_port: 80
  tasks:
    # Étape 1 : Installer IIS
    - name: Install IIS features
      ansible.windows.win_feature:
        name:
          - Web-Server
          - Web-Mgmt-Console
          - Web-Static-Content
          - Web-Default-Doc
        state: present
        include_management_tools: yes
      register: iis_install

    # Étape 2 : Reboot si nécessaire
    - name: Reboot after IIS installation
      ansible.windows.win_reboot:
        msg: "Reboot for IIS"
      when: iis_install.reboot_required

    # Étape 3 : Créer le dossier du site
    - name: Create website directory
      ansible.windows.win_file:
        path: "{{ website_path }}"
        state: directory

    # Étape 4 : Déployer le contenu
    - name: Copy index.html
      ansible.windows.win_copy:
        content: |
          <!DOCTYPE html>
          <html>
          <head>
              <title>{{ website_name }}</title>
          </head>
          <body>
              <h1>Welcome to {{ website_name }}</h1>
              <p>Deployed by Ansible on {{ ansible_date_time.iso8601 }}</p>
          </body>
          </html>
        dest: "{{ website_path }}\\index.html"

    # Étape 5 : Créer le site IIS
    - name: Create IIS website
      community.windows.win_iis_website:
        name: "{{ website_name }}"
        state: started
        physical_path: "{{ website_path }}"
        port: "{{ website_port }}"

    # Étape 6 : Configurer le firewall
    - name: Allow HTTP traffic
      community.windows.win_firewall_rule:
        name: "Allow HTTP"
        localport: "{{ website_port }}"
        action: allow
        direction: in
        protocol: tcp
        state: present
        enabled: yes

    # Étape 7 : Vérifier le service
    - name: Ensure IIS service is running
      ansible.windows.win_service:
        name: W3SVC
        state: started
        start_mode: auto

    # Étape 8 : Test HTTP
    - name: Test website
      ansible.windows.win_uri:
        url: "http://localhost:{{ website_port }}"
        return_content: yes
      register: website_test

    - name: Display website content
      ansible.builtin.debug:
        msg: "Website is accessible: {{ website_test.status_code }}"
```

### Scénario 2 : Joindre une Machine au Domaine AD

**Crucial pour l'entreprise !**

```yaml
---
- name: Join Windows server to Active Directory domain
  hosts: new_servers
  vars:
    domain_name: "example.com"
    domain_admin_user: "Administrator@{{ domain_name }}"
    domain_admin_password: "{{ vault_domain_admin_password }}"
    domain_ou: "OU=Servers,OU=IT,DC=example,DC=com"
  tasks:
    # Étape 1 : Configurer DNS
    - name: Set DNS server to domain controller
      ansible.windows.win_dns_client:
        adapter_names: '*'
        dns_servers:
          - 192.168.1.10   # IP du DC

    # Étape 2 : Joindre le domaine
    - name: Join domain
      ansible.windows.win_domain_membership:
        dns_domain_name: "{{ domain_name }}"
        domain_admin_user: "{{ domain_admin_user }}"
        domain_admin_password: "{{ domain_admin_password }}"
        domain_ou_path: "{{ domain_ou }}"
        state: domain
      register: domain_join

    # Étape 3 : Reboot (obligatoire)
    - name: Reboot after domain join
      ansible.windows.win_reboot:
        msg: "Reboot for domain join"
        pre_reboot_delay: 15
      when: domain_join.reboot_required

    # Étape 4 : Vérifier l'appartenance au domaine
    - name: Verify domain membership
      ansible.windows.win_shell: |
        (Get-WmiObject -Class Win32_ComputerSystem).Domain
      register: domain_check

    - name: Display domain
      ansible.builtin.debug:
        msg: "Server is now member of: {{ domain_check.stdout | trim }}"
```

### Scénario 3 : Windows Updates (Le Cauchemar Géré)

```yaml
---
- name: Manage Windows Updates
  hosts: windows
  tasks:
    # Rechercher les mises à jour
    - name: Search for Windows updates
      ansible.windows.win_updates:
        category_names:
          - SecurityUpdates
          - CriticalUpdates
        state: searched
      register: updates_available

    - name: Display updates count
      ansible.builtin.debug:
        msg: "{{ updates_available.found_update_count }} updates available"

    # Installer les mises à jour critiques
    - name: Install critical updates
      ansible.windows.win_updates:
        category_names:
          - SecurityUpdates
          - CriticalUpdates
        reboot: yes
        reboot_timeout: 3600
      register: updates_result

    - name: Display updates installed
      ansible.builtin.debug:
        msg: "{{ updates_result.installed_update_count }} updates installed"

    # Installer TOUTES les mises à jour (attention !)
    - name: Install all updates (use with caution)
      ansible.windows.win_updates:
        category_names:
          - '*'
        state: installed
        reboot: yes
      when: install_all_updates | default(false)

    # Blacklist certaines mises à jour
    - name: Install updates except blacklisted
      ansible.windows.win_updates:
        category_names:
          - SecurityUpdates
        reject_list:
          - KB4056892  # Exemple de KB problématique
        reboot: yes
```

---

## Quick Reference

### Comparaison Linux vs Windows

| Opération | Linux (Module) | Windows (Module) |
|-----------|----------------|------------------|
| **Installer package** | `apt`, `yum` | `win_chocolatey`, `win_package` |
| **Gérer service** | `service`, `systemd` | `win_service` |
| **Copier fichier** | `copy` | `win_copy` |
| **Créer dossier** | `file` | `win_file` |
| **Exécuter commande** | `shell`, `command` | `win_shell`, `win_command` |
| **Reboot** | `reboot` | `win_reboot` |
| **Mises à jour** | `apt upgrade`, `yum update` | `win_updates` |
| **Utilisateurs** | `user` | `win_user` |
| **Groupes** | `group` | `win_group` |
| **Firewall** | `ufw`, `firewalld` | `win_firewall_rule` |
| **Cron / Tasks** | `cron` | `win_scheduled_task` |

### Modules Windows Essentiels

| Module | Usage |
|--------|-------|
| `win_ping` | Tester la connexion |
| `win_feature` | Gérer les rôles/features Windows |
| `win_service` | Gérer les services |
| `win_package` | Installer/désinstaller software |
| `win_chocolatey` | Package manager Chocolatey |
| `win_copy` | Copier des fichiers |
| `win_file` | Gérer fichiers/dossiers |
| `win_shell` | Exécuter PowerShell |
| `win_command` | Exécuter une commande |
| `win_reboot` | Redémarrer |
| `win_updates` | Gérer Windows Updates |
| `win_user` | Gérer utilisateurs locaux |
| `win_domain_membership` | Joindre/quitter domaine AD |
| `win_iis_website` | Gérer sites IIS |
| `win_firewall_rule` | Gérer règles firewall |
| `win_scheduled_task` | Gérer tâches planifiées |

### Collections Windows

```bash
# Installer les collections Windows
ansible-galaxy collection install ansible.windows
ansible-galaxy collection install community.windows

# Vérifier
ansible-galaxy collection list | grep windows
```

---

## Ressources Complémentaires

- **Ansible Windows Docs** : https://docs.ansible.com/ansible/latest/os_guide/windows.html
- **WinRM Setup Script** : https://github.com/ansible/ansible/blob/devel/examples/scripts/ConfigureRemotingForAnsible.ps1
- **PyWinRM Documentation** : https://github.com/diyan/pywinrm
- **Chocolatey Packages** : https://community.chocolatey.org/packages

---

!!! tip "Intégration avec les autres guides"
    **Combinez avec :**

    - [PowerShell Foundations](powershell-foundations.md) - Maîtriser PowerShell pour les scripts complexes
    - [Active Directory](active-directory.md) - Gérer AD avec PowerShell (peut être piloté par Ansible)
    - [Windows Security](windows-security.md) - Hardening Windows avec Ansible
    - [Ansible Advanced Patterns](../devops/ansible/advanced-patterns.md) - block/rescue, serial, performance

!!! example "Parcours Recommandé"
    **Nouveau sur Ansible Windows ?**

    1. Configurer WinRM sur une VM de test
    2. Tester `win_ping` depuis Ansible
    3. Installer IIS avec `win_feature`
    4. Déployer un site web simple
    5. Joindre au domaine AD
    6. Gérer Windows Updates

    **Projet réel :** Déployer une ferme IIS (3+ serveurs) avec load balancer, Active Directory, et monitoring.
