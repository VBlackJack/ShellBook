---
tags:
  - chocolatey
  - ansible
  - gpo
  - intune
  - automation
  - deployment
---

# Module 4 : Déploiement de Masse - Industrialisation

## Introduction

> **"Don't run choco manually on 500 machines."**

Vous avez maintenant :

- ✅ Un client Chocolatey configuré (Module 1)
- ✅ Des packages personnalisés (`corpapp.nupkg`) (Module 2)
- ✅ Un repository privé (`http://repo.corp.local/chocolatey`) (Module 3)

**Mais un problème subsiste :**

**Comment déployer `corpapp` sur 500 workstations sans se connecter en RDP sur chacune ?**

| Approche Manuelle | Problème |
|-------------------|----------|
| **RDP + choco install** | ❌ Ne passe pas à l'échelle (500 connexions = 3 jours) |
| **Script PS distribué** | ❌ Pas d'audit (qui a installé quoi, quand ?) |
| **GPO Startup Script** | ❌ Lent, pas idempotent, logs difficiles |

**La solution : Configuration Management**

Le **Configuration Management (CM)** consiste à décrire l'**état désiré** d'un système et laisser un outil l'appliquer automatiquement.

**Exemple d'état désiré :**

```yaml
- Chocolatey installé
- Source chocolatey.org désactivée
- Source repo.corp.local configurée (priorité 0)
- Package corpapp installé (version 1.0.0)
- Package adobereader supprimé
- Package googlechrome installé (dernière version)
```

**Outils de Configuration Management pour Windows :**

| Outil | Paradigme | Langage | Agent | Complexité |
|-------|-----------|---------|-------|------------|
| **Ansible** | Agentless (SSH/WinRM) | YAML | ❌ Non requis | ⭐⭐ Moyen |
| **PowerShell DSC** | Desired State Configuration | PowerShell | ✅ LCM (Local Configuration Manager) | ⭐⭐⭐ Complexe |
| **Intune / Endpoint Manager** | Cloud MDM | PowerShell/Scripts | ✅ Intune Agent | ⭐ Facile |
| **SCCM / ConfigMgr** | Enterprise Systems Management | GUI + PowerShell | ✅ SCCM Client | ⭐⭐⭐⭐ Très complexe |
| **GPO (Group Policy)** | Active Directory | GUI + Scripts | ❌ Non (natif AD) | ⭐ Facile (mais limité) |

**Dans ce module, nous allons nous concentrer sur :**

- ✅ **Ansible** (le plus populaire, agentless, cross-platform)
- ✅ **Intune** (moderne, cloud-first, Microsoft 365)
- ✅ **GPO** (rapide à mettre en place pour PME avec AD)

Vous allez apprendre à :

- ✅ Comprendre l'**idempotence** (principe clé du CM)
- ✅ Déployer Chocolatey avec **Ansible** (`win_chocolatey`, `win_chocolatey_source`)
- ✅ Créer un playbook de **migration de logiciel** (Adobe Reader → Foxit Reader)
- ✅ Packager des commandes Chocolatey pour **Intune**
- ✅ Utiliser **GPO** pour déployer des packages au démarrage

---

## Concept : Configuration Management vs Scripting

### Scripting Impératif (Approche Traditionnelle)

**Script PowerShell classique :**

```powershell
# deploy-corpapp.ps1
choco install corpapp -y
```

**Problème :** Si vous exécutez ce script **2 fois**, que se passe-t-il ?

```
1ère exécution : corpapp 1.0.0 installé ✅
2ème exécution : "corpapp 1.0.0 is already installed" ⚠️ (mais pas d'erreur)
3ème exécution : Idem
```

**Résultat :** Pas d'erreur, mais **aucune garantie** que le système est dans l'état désiré.

---

### Configuration Management (Approche Déclarative)

**Playbook Ansible :**

```yaml
- name: Ensure corpapp is installed
  win_chocolatey:
    name: corpapp
    state: present
```

**Résultat :**

```
1ère exécution : corpapp 1.0.0 installé ✅ (changed)
2ème exécution : corpapp déjà présent ✅ (ok)
3ème exécution : corpapp déjà présent ✅ (ok)
```

**Différence clé : Idempotence.**

---

### Idempotence

**Définition :**

> Une opération est **idempotente** si elle peut être exécutée **plusieurs fois** sans changer le résultat après la première application réussie.

**Exemple mathématique :**

| Opération | Idempotente ? |
|-----------|---------------|
| `x = 5` | ✅ Oui (toujours `x = 5`) |
| `x = x + 1` | ❌ Non (change à chaque fois) |

**Dans le contexte Chocolatey :**

| Commande | Idempotente ? | Explication |
|----------|---------------|-------------|
| `choco install app` | ✅ Oui | Si déjà installé, pas de changement |
| `choco upgrade app` | ⚠️ Partiellement | Met à jour si nouvelle version disponible |
| `choco uninstall app` | ✅ Oui | Si déjà absent, pas d'erreur |
| `PowerShell "Download-File"` | ❌ Non | Télécharge à chaque fois |

**Pourquoi c'est important ?**

- ✅ **Convergence** : Le système converge vers l'état désiré, peu importe l'état initial
- ✅ **Sécurité** : Relancer un playbook 10 fois ne casse rien
- ✅ **Audit** : Si `changed = 0`, le système était déjà conforme

---

### Comparaison des Méthodes de Déploiement

| Critère | GPO | Ansible | Intune | SCCM |
|---------|-----|---------|--------|------|
| **Complexité Setup** | ⭐ Facile | ⭐⭐ Moyen | ⭐ Facile | ⭐⭐⭐⭐ Complexe |
| **Prérequis** | Active Directory | Python + WinRM | Microsoft 365 E3+ | Infrastructure lourde |
| **Agent requis** | ❌ Non | ❌ Non (WinRM) | ✅ Oui (Intune Agent) | ✅ Oui (SCCM Client) |
| **Idempotence native** | ❌ Non | ✅ Oui | ⚠️ Scripts manuels | ✅ Oui |
| **Cross-platform** | ❌ Windows uniquement | ✅ Linux/macOS/Windows | ⚠️ Windows/macOS/Android | ❌ Principalement Windows |
| **Vitesse d'exécution** | 🐢 Lent (GPO Refresh 90 min) | ⚡ Rapide (push immédiat) | ⚡ Rapide (cloud) | ⚡ Rapide |
| **Logs centralisés** | ❌ Difficile | ✅ Oui (stdout) | ✅ Oui (portail Intune) | ✅ Oui (console SCCM) |
| **Rollback** | ❌ Manuel | ✅ Oui (version control) | ⚠️ Scripts manuels | ✅ Oui |
| **Coût** | 🆓 Gratuit (inclus AD) | 🆓 Gratuit (OSS) | 💰 Payant (M365 E3) | 💰💰 Très cher |
| **Cas d'usage** | PME < 200 postes | DevOps, multi-OS | Cloud-first, mobile | Grande entreprise legacy |

**Recommandations :**

| Taille entreprise | Contexte | Outil recommandé |
|-------------------|----------|------------------|
| **< 100 postes** | PME avec AD | **GPO** (simplicité) |
| **100-500 postes** | Infra hybride On-Prem/Cloud | **Ansible** (flexibilité) |
| **> 500 postes** | Cloud-first Microsoft 365 | **Intune** (moderne) |
| **> 1000 postes** | Infrastructure legacy complexe | **SCCM** (si déjà en place) |

---

## Pratique : Ansible - Le Module `win_chocolatey`

### Prérequis

#### 1. Control Node (Linux/macOS)

**Installer Ansible :**

=== "RHEL/Rocky"

    ```bash
    sudo dnf install ansible -y

    # Vérifier
    ansible --version
    ```

=== "Debian/Ubuntu"

    ```bash
    sudo apt update
    sudo apt install -y ansible

    # Vérifier
    ansible --version
    ```

=== "macOS"

    ```bash
    brew install ansible

    # Vérifier
    ansible --version
    ```

#### 2. Windows Hosts (Machines cibles)

**Activer WinRM :**

```powershell
# Sur chaque Windows cible
Enable-PSRemoting -Force

# Configurer WinRM pour HTTP (dev/test uniquement)
winrm set winrm/config/service '@{AllowUnencrypted="true"}'
winrm set winrm/config/service/auth '@{Basic="true"}'

# Ouvrir le firewall
Enable-NetFirewallRule -Name "WINRM-HTTP-In-TCP"

# Vérifier
Test-WSMan -ComputerName localhost
```

**⚠️ En production : utiliser HTTPS avec certificats.**

#### 3. Inventaire Ansible

**Fichier : `inventory.ini`**

```ini
[windows]
win-client-01.corp.local
win-client-02.corp.local

[windows:vars]
ansible_user=administrator
ansible_password=P@ssw0rd123
ansible_connection=winrm
ansible_winrm_transport=basic
ansible_winrm_server_cert_validation=ignore
```

**⚠️ En production : utiliser Ansible Vault pour chiffrer les credentials.**

**Tester la connectivité :**

```bash
ansible windows -i inventory.ini -m win_ping
```

**Sortie attendue :**

```json
win-client-01.corp.local | SUCCESS => {
    "changed": false,
    "ping": "pong"
}
```

---

### Le Module `win_chocolatey`

**Documentation :** [ansible.windows.win_chocolatey](https://docs.ansible.com/ansible/latest/collections/chocolatey/chocolatey/win_chocolatey_module.html)

**Paramètres clés :**

| Paramètre | Type | Description | Exemple |
|-----------|------|-------------|---------|
| `name` | string | Nom du package | `firefox`, `git`, `corpapp` |
| `state` | string | État désiré | `present`, `absent`, `latest` |
| `version` | string | Version spécifique (optionnel) | `115.0.0`, `1.0.0` |
| `source` | string | URL du repository | `http://repo.corp.local/chocolatey` |
| `install_args` | string | Arguments d'installation | `/S /VERYSILENT` |
| `package_params` | string | Paramètres package | `/NoDesktopIcon /NoStartMenu` |
| `timeout` | int | Timeout (secondes) | `3600` |
| `force` | bool | Forcer la réinstallation | `true` / `false` |

---

### Exemples de Tâches

#### 1. Installer un Package

```yaml
- name: Install Firefox
  win_chocolatey:
    name: firefox
    state: present
```

**Résultat :**

- Si Firefox n'est **pas installé** : Installation ✅ (`changed: true`)
- Si Firefox est **déjà installé** : Rien ✅ (`changed: false`)

---

#### 2. Installer une Version Spécifique

```yaml
- name: Install Firefox 115.0
  win_chocolatey:
    name: firefox
    version: 115.0
    state: present
```

**Résultat :** Installe **exactement** Firefox 115.0, même si 120.0 est disponible.

---

#### 3. Mettre à Jour un Package

```yaml
- name: Upgrade Google Chrome
  win_chocolatey:
    name: googlechrome
    state: latest
```

**Résultat :**

- Si Chrome 119 est installé et 120 disponible : Update vers 120 ✅
- Si Chrome 120 déjà installé : Rien ✅

---

#### 4. Désinstaller un Package

```yaml
- name: Remove Adobe Reader
  win_chocolatey:
    name: adobereader
    state: absent
```

**Résultat :**

- Si Adobe Reader est installé : Désinstallation ✅
- Si déjà absent : Rien ✅

---

#### 5. Installer depuis un Repo Privé

```yaml
- name: Install corpapp from internal repo
  win_chocolatey:
    name: corpapp
    version: 1.0.0
    source: http://repo.corp.local/chocolatey
    state: present
```

---

#### 6. Installer avec des Arguments

```yaml
- name: Install 7zip without desktop icon
  win_chocolatey:
    name: 7zip
    package_params: /NoDesktopIcon
    state: present
```

---

### Le Module `win_chocolatey_source`

**Objectif :** Configurer les sources Chocolatey (ajouter/désactiver repos).

**Paramètres :**

| Paramètre | Description | Exemple |
|-----------|-------------|---------|
| `name` | Nom de la source | `internal-repo`, `chocolatey` |
| `source` | URL du repository | `http://repo.corp.local/chocolatey` |
| `state` | État | `present`, `absent`, `disabled` |
| `priority` | Priorité (0 = plus haute) | `0`, `10` |

**Exemples :**

#### 1. Ajouter un Repo Privé

```yaml
- name: Add internal Chocolatey repository
  win_chocolatey_source:
    name: internal-repo
    source: http://repo.corp.local/chocolatey
    priority: 0
    state: present
```

#### 2. Désactiver chocolatey.org

```yaml
- name: Disable public Chocolatey repository
  win_chocolatey_source:
    name: chocolatey
    state: disabled
```

---

### Le Module `win_chocolatey_config`

**Objectif :** Modifier la configuration Chocolatey (`choco config`).

**Exemple :**

```yaml
- name: Set cache location
  win_chocolatey_config:
    name: cacheLocation
    value: C:\ProgramData\ChocolateyCache
    state: present
```

**Configurations courantes :**

| Config | Description | Valeur |
|--------|-------------|--------|
| `cacheLocation` | Répertoire de cache | `C:\ProgramData\ChocolateyCache` |
| `commandExecutionTimeoutSeconds` | Timeout installations | `3600` |
| `proxy` | Proxy HTTP | `http://proxy.corp.local:8080` |
| `proxyUser` | User proxy | `DOMAIN\user` |

---

### Le Module `win_chocolatey_feature`

**Objectif :** Activer/désactiver des fonctionnalités Chocolatey.

**Exemple :**

```yaml
- name: Enable checksumFiles feature
  win_chocolatey_feature:
    name: checksumFiles
    state: enabled
```

**Features courantes :**

| Feature | Description |
|---------|-------------|
| `checksumFiles` | Vérifier les checksums |
| `allowGlobalConfirmation` | Toujours `-y` par défaut |
| `failOnStandardError` | Échouer si stderr non vide |

---

## Pratique : Playbook Complet

### Exemple : Bootstrap Chocolatey

**Fichier : `bootstrap-chocolatey.yml`**

```yaml
---
- name: Bootstrap Chocolatey on Windows Hosts
  hosts: windows
  gather_facts: no

  tasks:
    - name: Check if Chocolatey is installed
      win_command: choco --version
      register: choco_installed
      failed_when: false
      changed_when: false

    - name: Install Chocolatey
      win_shell: |
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
      when: choco_installed.rc != 0

    - name: Add internal Chocolatey repository
      win_chocolatey_source:
        name: internal-repo
        source: http://repo.corp.local/chocolatey
        priority: 0
        state: present

    - name: Disable public Chocolatey repository
      win_chocolatey_source:
        name: chocolatey
        state: disabled

    - name: Install core packages
      win_chocolatey:
        name: "{{ item }}"
        state: present
      loop:
        - git
        - vscode
        - 7zip
        - googlechrome
```

**Exécution :**

```bash
ansible-playbook -i inventory.ini bootstrap-chocolatey.yml
```

**Sortie attendue :**

```
PLAY [Bootstrap Chocolatey on Windows Hosts] ***************

TASK [Check if Chocolatey is installed] ********************
ok: [win-client-01.corp.local]

TASK [Install Chocolatey] ***********************************
changed: [win-client-01.corp.local]

TASK [Add internal Chocolatey repository] *******************
changed: [win-client-01.corp.local]

TASK [Disable public Chocolatey repository] ****************
changed: [win-client-01.corp.local]

TASK [Install core packages] ********************************
changed: [win-client-01.corp.local] => (item=git)
changed: [win-client-01.corp.local] => (item=vscode)
ok: [win-client-01.corp.local] => (item=7zip)
ok: [win-client-01.corp.local] => (item=googlechrome)

PLAY RECAP **************************************************
win-client-01.corp.local : ok=5  changed=4  unreachable=0  failed=0
```

---

## Pratique : Intune / Endpoint Manager

### Vue d'Ensemble

**Microsoft Intune** est une plateforme **MDM/MAM** (Mobile Device Management / Mobile Application Management) cloud qui permet de gérer les appareils et applications.

**Avantages :**

- ✅ **Cloud-first** : Pas de serveur On-Prem requis
- ✅ **Moderne** : Intégration Microsoft 365, Azure AD
- ✅ **Multi-plateforme** : Windows, macOS, iOS, Android

**Inconvénients :**

- ❌ **Coût** : Nécessite Microsoft 365 E3 ou supérieur
- ❌ **Dépendance Cloud** : Requiert Internet
- ❌ **Moins flexible** qu'Ansible (pas de scripting avancé natif)

---

### Déployer Chocolatey avec Intune

#### Méthode 1 : Script PowerShell (.ps1)

**1. Créer le script d'installation**

**Fichier : `install-corpapp.ps1`**

```powershell
#Requires -RunAsAdministrator
# install-corpapp.ps1

# Vérifier si Chocolatey est installé
if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
    # Installer Chocolatey
    Set-ExecutionPolicy Bypass -Scope Process -Force
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
    iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
}

# Configurer le repository interne
choco source add --name="internal-repo" --source="http://repo.corp.local/chocolatey" --priority=0
choco source disable --name="chocolatey"

# Installer corpapp
choco install corpapp -y --no-progress

# Code de sortie
exit 0
```

**2. Uploader dans Intune**

- Aller dans **Endpoint Manager** → **Devices** → **Scripts**
- Cliquer **Add** → **Windows 10 and later**
- Uploader `install-corpapp.ps1`
- **Run this script using the logged on credentials** : `No` (exécuter en SYSTEM)
- **Assign** : Assigner à un groupe Azure AD (ex: `All-Workstations`)

**3. Forcer la synchronisation**

Sur un client Windows :

```powershell
# Forcer une synchronisation Intune
Get-ScheduledTask | Where-Object {$_.TaskName -eq 'PushLaunch'} | Start-ScheduledTask
```

**Résultat :** Le script s'exécute dans les 15 minutes.

---

#### Méthode 2 : Win32 App (.intunewin)

**1. Créer le script d'installation**

**Fichier : `install.ps1`**

```powershell
choco install corpapp -y --source http://repo.corp.local/chocolatey
exit 0
```

**Fichier : `uninstall.ps1`**

```powershell
choco uninstall corpapp -y
exit 0
```

**2. Packager avec IntuneWinAppUtil**

Télécharger l'outil : [Microsoft-Win32-Content-Prep-Tool](https://github.com/Microsoft/Microsoft-Win32-Content-Prep-Tool)

```powershell
.\IntuneWinAppUtil.exe `
  -c C:\Source\corpapp `
  -s install.ps1 `
  -o C:\Output

# Génère : corpapp.intunewin
```

**3. Uploader dans Intune**

- **Endpoint Manager** → **Apps** → **All apps** → **Add**
- App type : **Windows app (Win32)**
- Upload `corpapp.intunewin`
- **Install command** : `powershell.exe -ExecutionPolicy Bypass -File install.ps1`
- **Uninstall command** : `powershell.exe -ExecutionPolicy Bypass -File uninstall.ps1`
- **Detection rule** : Registry ou File (ex: `C:\Program Files\CorpApp\CorpApp.exe`)
- **Assign** à un groupe

**Résultat :** Déploiement trackable avec statut dans le portail Intune.

---

## Pratique : GPO (Group Policy Objects)

### Vue d'Ensemble

**GPO** est la méthode **legacy** de déploiement de logiciels dans Active Directory.

**Avantages :**

- ✅ **Gratuit** (inclus dans Windows Server)
- ✅ **Rapide à mettre en place** (GUI)
- ✅ **Pas d'agent** requis

**Inconvénients :**

- ❌ **Lent** (GPO Refresh toutes les 90 minutes)
- ❌ **Pas idempotent** (scripts s'exécutent à chaque démarrage)
- ❌ **Logs difficiles** à centraliser
- ❌ **Limité** (pas de rollback, pas de versioning)

---

### Déployer Chocolatey avec GPO

#### Étape 1 : Créer le Script PowerShell

**Fichier : `install-packages.ps1`**

```powershell
# install-packages.ps1
# GPO Startup Script pour installer des packages Chocolatey

# Vérifier si Chocolatey est installé
if (-not (Test-Path "C:\ProgramData\chocolatey\choco.exe")) {
    # Installer Chocolatey
    Set-ExecutionPolicy Bypass -Scope Process -Force
    [System.Net.ServicePointManager]::SecurityProtocol = 3072
    iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
}

# Installer les packages
& C:\ProgramData\chocolatey\choco.exe install git -y --no-progress
& C:\ProgramData\chocolatey\choco.exe install vscode -y --no-progress
& C:\ProgramData\chocolatey\choco.exe install googlechrome -y --no-progress
```

**Copier le script dans SYSVOL :**

```powershell
Copy-Item install-packages.ps1 -Destination "\\corp.local\SYSVOL\corp.local\scripts\"
```

---

#### Étape 2 : Créer une GPO

**1. Ouvrir la console GPMC :**

```powershell
gpmc.msc
```

**2. Créer une nouvelle GPO :**

- Right-click sur l'OU cible → **Create a GPO in this domain, and Link it here**
- Nom : `Deploy Chocolatey Packages`

**3. Éditer la GPO :**

- **Computer Configuration** → **Policies** → **Windows Settings** → **Scripts (Startup/Shutdown)**
- Double-click **Startup**
- **Add** → **Script Name** : `\\corp.local\SYSVOL\corp.local\scripts\install-packages.ps1`
- **PowerShell Scripts** (onglet) → **Add** → Parcourir le script

**4. Forcer la politique :**

```powershell
gpupdate /force
```

**5. Tester :**

Redémarrer un client Windows. Au démarrage, le script s'exécute.

---

### Limites de GPO

**Problème d'idempotence :**

Si le script s'exécute à **chaque démarrage**, `choco install git` vérifiera à chaque fois si Git est installé.

**Solution :** Ajouter une vérification manuelle :

```powershell
# Vérifier si Git est installé
if (-not (Test-Path "C:\Program Files\Git\bin\git.exe")) {
    choco install git -y
}
```

**Problème de logs :**

Les logs GPO sont dispersés dans `Event Viewer` → **Windows Logs** → **System**.

**Solution :** Logger manuellement :

```powershell
$LogFile = "C:\ProgramData\ChocolateyGPO.log"
"$(Get-Date) - Starting GPO Chocolatey deployment" | Out-File $LogFile -Append
```

---

## Bonnes Pratiques

### 1. ✅ Utiliser Ansible Vault pour les Credentials

**Créer un fichier chiffré :**

```bash
ansible-vault create secrets.yml
```

**Contenu :**

```yaml
ansible_user: administrator
ansible_password: P@ssw0rd123
```

**Utiliser dans l'inventaire :**

```ini
[windows:vars]
ansible_connection=winrm
ansible_winrm_transport=basic
```

**Exécuter avec le vault :**

```bash
ansible-playbook -i inventory.ini playbook.yml --ask-vault-pass
```

---

### 2. ✅ Tester sur un Groupe Pilote

**Inventaire avec groupes :**

```ini
[pilot]
win-pilot-01.corp.local

[production]
win-prod-01.corp.local
win-prod-02.corp.local
win-prod-03.corp.local
```

**Déployer d'abord sur Pilot :**

```bash
ansible-playbook -i inventory.ini playbook.yml --limit pilot
```

**Si OK, déployer sur Production :**

```bash
ansible-playbook -i inventory.ini playbook.yml --limit production
```

---

### 3. ✅ Utiliser des Tags pour Exécution Partielle

**Playbook avec tags :**

```yaml
- name: Deploy Chocolatey
  hosts: windows
  tasks:
    - name: Install Chocolatey
      win_shell: |
        iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
      tags:
        - bootstrap

    - name: Install packages
      win_chocolatey:
        name: git
        state: present
      tags:
        - packages
```

**Exécuter uniquement les packages :**

```bash
ansible-playbook playbook.yml --tags packages
```

---

### 4. ✅ Versionner les Playbooks dans Git

**Structure recommandée :**

```
chocolatey-ansible/
├── inventory/
│   ├── production.ini
│   ├── staging.ini
│   └── development.ini
├── playbooks/
│   ├── bootstrap-chocolatey.yml
│   ├── deploy-corpapp.yml
│   └── migrate-pdf.yml
├── roles/
│   └── chocolatey/
│       ├── tasks/
│       │   └── main.yml
│       └── defaults/
│           └── main.yml
├── group_vars/
│   └── windows.yml
└── ansible.cfg
```

**Committer :**

```bash
git add .
git commit -m "feat: Add playbook for PDF migration"
git push origin main
```

---

### 5. ✅ Monitorer avec Ansible Tower / AWX

**Ansible Tower** (commercial) et **AWX** (OSS) fournissent :

- ✅ **UI Web** pour lancer les playbooks
- ✅ **RBAC** (Role-Based Access Control)
- ✅ **Logs centralisés** et dashboards
- ✅ **Scheduling** (exécution planifiée)
- ✅ **API REST** pour intégration CI/CD

**Alternative gratuite :** **Semaphore UI** (interface web pour Ansible).

---

## Exercice : La Migration PDF

### Contexte

Vous êtes SysOps dans **DocCorp** (infrastructure 300 workstations Windows 10).

**Directive de la Direction :** Migrer tous les postes de **Adobe Reader** (payant) vers **Foxit Reader** (gratuit) pour réduire les coûts.

**Contraintes :**

- ✅ Désinstaller Adobe Reader proprement
- ✅ Installer Foxit Reader depuis le repository interne
- ✅ Mettre à jour Google Chrome (sécurité)
- ✅ Configurer le repository interne comme source prioritaire
- ✅ Désactiver chocolatey.org

**Environnement :**

- **Repository interne :** `http://repo.doccorp.local/chocolatey`
- **Packages disponibles :** `foxitreader`, `googlechrome`
- **Ansible Control Node :** `ansible.doccorp.local` (Linux)
- **Inventaire :** 300 workstations dans le groupe `[windows]`

---

### Mission

Créer un playbook Ansible `migrate_pdf.yml` qui :

1. **Bootstrap** : S'assurer que Chocolatey est installé
2. **Configuration** : Ajouter le repository interne et désactiver chocolatey.org
3. **Désinstallation** : Supprimer Adobe Reader
4. **Installation** : Installer Foxit Reader
5. **Mise à jour** : Mettre à jour Google Chrome vers la dernière version
6. **Vérification** : Vérifier que Foxit Reader est installé

---

### Prérequis

- Ansible installé sur le Control Node
- WinRM configuré sur les 300 workstations
- Inventaire `inventory.ini` avec groupe `[windows]`

---

### Étapes

#### 1. Créer l'Inventaire

**Fichier : `inventory.ini`**

```ini
[windows]
win-workstation-[001:300].doccorp.local

[windows:vars]
ansible_user=administrator
ansible_password=P@ssw0rd123
ansible_connection=winrm
ansible_winrm_transport=basic
ansible_winrm_server_cert_validation=ignore
```

**Note :** `win-workstation-[001:300]` génère 300 hosts (001 à 300).

#### 2. Créer le Playbook

**Fichier : `migrate_pdf.yml`**

(Voir la solution ci-dessous)

#### 3. Exécuter

```bash
ansible-playbook -i inventory.ini migrate_pdf.yml
```

---

### Solution

??? quote "**Solution : Playbook `migrate_pdf.yml`**"

    **Fichier : `migrate_pdf.yml`**

    ```yaml
    ---
    - name: Migrate from Adobe Reader to Foxit Reader
      hosts: windows
      gather_facts: yes

      vars:
        internal_repo_url: "http://repo.doccorp.local/chocolatey"
        internal_repo_name: "internal-repo"
        packages_to_install:
          - name: foxitreader
            version: null  # Dernière version
          - name: googlechrome
            state: latest  # Mettre à jour vers la dernière version
        packages_to_remove:
          - adobereader

      tasks:
        # ========================================
        # STEP 1 : BOOTSTRAP CHOCOLATEY
        # ========================================
        - name: Check if Chocolatey is installed
          win_command: choco --version
          register: choco_check
          failed_when: false
          changed_when: false

        - name: Install Chocolatey if not present
          win_shell: |
            Set-ExecutionPolicy Bypass -Scope Process -Force
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
            iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
          when: choco_check.rc != 0
          register: choco_install
          changed_when: choco_install.rc == 0

        - name: Verify Chocolatey installation
          win_command: choco --version
          register: choco_verify
          failed_when: choco_verify.rc != 0
          changed_when: false

        # ========================================
        # STEP 2 : CONFIGURATION SOURCES
        # ========================================
        - name: Add internal Chocolatey repository
          win_chocolatey_source:
            name: "{{ internal_repo_name }}"
            source: "{{ internal_repo_url }}"
            priority: 0
            state: present

        - name: Disable public Chocolatey repository
          win_chocolatey_source:
            name: chocolatey
            state: disabled

        - name: List configured sources (for verification)
          win_command: choco source list
          register: sources_list
          changed_when: false

        - name: Display configured sources
          debug:
            var: sources_list.stdout_lines

        # ========================================
        # STEP 3 : DÉSINSTALLATION ADOBE READER
        # ========================================
        - name: Check if Adobe Reader is installed
          win_command: choco list --local-only adobereader
          register: adobe_check
          failed_when: false
          changed_when: false

        - name: Remove Adobe Reader
          win_chocolatey:
            name: "{{ item }}"
            state: absent
          loop: "{{ packages_to_remove }}"
          when: "'adobereader' in adobe_check.stdout"

        # ========================================
        # STEP 4 : INSTALLATION FOXIT READER
        # ========================================
        - name: Install Foxit Reader
          win_chocolatey:
            name: foxitreader
            source: "{{ internal_repo_url }}"
            state: present

        # ========================================
        # STEP 5 : MISE À JOUR GOOGLE CHROME
        # ========================================
        - name: Update Google Chrome to latest version
          win_chocolatey:
            name: googlechrome
            source: "{{ internal_repo_url }}"
            state: latest

        # ========================================
        # STEP 6 : VÉRIFICATION
        # ========================================
        - name: Verify Foxit Reader installation
          win_command: choco list --local-only foxitreader
          register: foxit_verify
          failed_when: "'foxitreader' not in foxit_verify.stdout"
          changed_when: false

        - name: Display installed packages
          win_command: choco list --local-only
          register: installed_packages
          changed_when: false

        - name: Show final package list
          debug:
            msg: "{{ installed_packages.stdout_lines }}"

        # ========================================
        # STEP 7 : RAPPORT FINAL
        # ========================================
        - name: Generate migration report
          win_shell: |
            $Report = @"
            ========================================
            MIGRATION PDF REPORT
            ========================================
            Hostname: $(hostname)
            Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

            PACKAGES REMOVED:
            - Adobe Reader

            PACKAGES INSTALLED:
            - Foxit Reader

            PACKAGES UPDATED:
            - Google Chrome

            SOURCES CONFIGURED:
            - internal-repo: {{ internal_repo_url }} (Priority 0)
            - chocolatey: DISABLED

            ========================================
            "@

            $Report | Out-File "C:\ProgramData\ChocolateyMigrationReport.txt" -Force
            Write-Output $Report
          register: report
          changed_when: false

        - name: Display migration report
          debug:
            var: report.stdout_lines
    ```

    ---

    **Fichier : `ansible.cfg` (optionnel, recommandé)**

    ```ini
    [defaults]
    inventory = inventory.ini
    host_key_checking = False
    retry_files_enabled = False
    log_path = ./ansible.log

    [privilege_escalation]
    become = False
    ```

    ---

    **Exécution avec logging :**

    ```bash
    # Exécuter le playbook
    ansible-playbook migrate_pdf.yml

    # Vérifier les logs
    cat ansible.log
    ```

    ---

    **Sortie attendue :**

    ```
    PLAY [Migrate from Adobe Reader to Foxit Reader] ***************

    TASK [Gathering Facts] ******************************************
    ok: [win-workstation-001.doccorp.local]
    ok: [win-workstation-002.doccorp.local]
    ...

    TASK [Check if Chocolatey is installed] ************************
    ok: [win-workstation-001.doccorp.local]

    TASK [Install Chocolatey if not present] ***********************
    skipping: [win-workstation-001.doccorp.local]

    TASK [Verify Chocolatey installation] **************************
    ok: [win-workstation-001.doccorp.local]

    TASK [Add internal Chocolatey repository] **********************
    changed: [win-workstation-001.doccorp.local]

    TASK [Disable public Chocolatey repository] ********************
    changed: [win-workstation-001.doccorp.local]

    TASK [List configured sources (for verification)] **************
    ok: [win-workstation-001.doccorp.local]

    TASK [Display configured sources] *******************************
    ok: [win-workstation-001.doccorp.local] => {
        "sources_list.stdout_lines": [
            "internal-repo - http://repo.doccorp.local/chocolatey | Priority 0",
            "chocolatey - https://community.chocolatey.org/api/v2/ [Disabled]"
        ]
    }

    TASK [Check if Adobe Reader is installed] **********************
    ok: [win-workstation-001.doccorp.local]

    TASK [Remove Adobe Reader] **************************************
    changed: [win-workstation-001.doccorp.local] => (item=adobereader)

    TASK [Install Foxit Reader] *************************************
    changed: [win-workstation-001.doccorp.local]

    TASK [Update Google Chrome to latest version] ******************
    changed: [win-workstation-001.doccorp.local]

    TASK [Verify Foxit Reader installation] ************************
    ok: [win-workstation-001.doccorp.local]

    TASK [Display installed packages] *******************************
    ok: [win-workstation-001.doccorp.local]

    TASK [Show final package list] **********************************
    ok: [win-workstation-001.doccorp.local] => {
        "msg": [
            "Chocolatey v2.2.2",
            "foxitreader 2024.1.0",
            "googlechrome 120.0.6099.130",
            "git 2.43.0",
            "3 packages installed."
        ]
    }

    TASK [Generate migration report] ********************************
    ok: [win-workstation-001.doccorp.local]

    TASK [Display migration report] *********************************
    ok: [win-workstation-001.doccorp.local] => {
        "report.stdout_lines": [
            "========================================",
            "MIGRATION PDF REPORT",
            "========================================",
            "Hostname: WIN-WORKSTATION-001",
            "Date: 2025-01-22 15:30:00",
            "",
            "PACKAGES REMOVED:",
            "- Adobe Reader",
            "",
            "PACKAGES INSTALLED:",
            "- Foxit Reader",
            "",
            "PACKAGES UPDATED:",
            "- Google Chrome",
            "",
            "SOURCES CONFIGURED:",
            "- internal-repo: http://repo.doccorp.local/chocolatey (Priority 0)",
            "- chocolatey: DISABLED",
            "",
            "========================================"
        ]
    }

    PLAY RECAP ******************************************************
    win-workstation-001.doccorp.local : ok=16  changed=5  unreachable=0  failed=0
    win-workstation-002.doccorp.local : ok=16  changed=5  unreachable=0  failed=0
    ...
    win-workstation-300.doccorp.local : ok=16  changed=5  unreachable=0  failed=0
    ```

    ---

    **Résumé du Playbook :**

    | Étape | Tâches | Changed ? |
    |-------|--------|-----------|
    | **Bootstrap** | Vérifier/installer Chocolatey | ⚠️ Si absent |
    | **Configuration** | Ajouter repo interne, désactiver chocolatey.org | ✅ Oui |
    | **Désinstallation** | Supprimer Adobe Reader | ✅ Si présent |
    | **Installation** | Installer Foxit Reader | ✅ Oui |
    | **Update** | Mettre à jour Google Chrome | ✅ Si nouvelle version |
    | **Vérification** | Vérifier installation Foxit | ❌ Non (check) |
    | **Rapport** | Générer rapport texte | ❌ Non (write file) |

    **Total changed : 5 tâches** (sur 300 workstations = 1500 changements)

    **Temps d'exécution estimé :** 10-15 minutes (avec 20 forks parallèles).

    ---

    **Optimisation avec `ansible.cfg` :**

    ```ini
    [defaults]
    forks = 20  # Exécuter 20 hosts en parallèle
    timeout = 600  # Timeout 10 minutes par task
    ```

---

## Points Clés à Retenir

### ✅ Configuration Management

- **Idempotence** : Exécuter N fois = même résultat
- **Déclaratif** : Décrire l'état désiré, pas les étapes
- **Outils** : Ansible (agentless), Intune (cloud), GPO (legacy)

### ✅ Ansible - win_chocolatey

- **Module principal** : `win_chocolatey` (name, state, version, source)
- **Configuration** : `win_chocolatey_source`, `win_chocolatey_config`
- **Prérequis** : WinRM activé sur Windows

### ✅ Déploiement

- **Ansible** : Flexible, cross-platform, gratuit
- **Intune** : Moderne, cloud, payant
- **GPO** : Simple, AD-based, limité

### ✅ Bonnes Pratiques

- ✅ Ansible Vault pour credentials
- ✅ Tester sur groupe pilote
- ✅ Utiliser tags pour exécution partielle
- ✅ Versionner dans Git
- ✅ Monitorer avec Tower/AWX

---

## Prochaines Étapes

**Vous avez maintenant une chaîne complète Chocolatey industrielle :**

1. ✅ **Client** : Installation et CLI (Module 1)
2. ✅ **Packaging** : Créer des `.nupkg` (Module 2)
3. ✅ **Repository** : Serveur privé Chocolatey Server (Module 3)
4. ✅ **Déploiement** : Ansible/Intune/GPO (Module 4)

**Prochaines améliorations possibles :**

- 🚀 **CI/CD** : Automatiser le packaging avec GitLab CI/Azure DevOps
- 🔐 **Sécurité** : Scanner les packages avec Trivy/Checkmarx
- 📊 **Monitoring** : Dashboard Grafana pour suivre les installations
- 🧪 **Testing** : Pester tests pour valider les playbooks

**Vous êtes capable de gérer 1000+ workstations Windows avec Chocolatey !** 🍫

---

**Ressources :**

- [Ansible - win_chocolatey](https://docs.ansible.com/ansible/latest/collections/chocolatey/chocolatey/win_chocolatey_module.html)
- [Microsoft Intune Documentation](https://learn.microsoft.com/en-us/mem/intune/)
- [Chocolatey Deployment](https://docs.chocolatey.org/en-us/guides/organizations/organizational-deployment-guide)

---

## Navigation

| | |
|:---|---:|
| [← Module 3 : Serveur Privé - L'Usine Lo...](03-module.md) | [Module 5 : TP Final - La Chocolatey F... →](05-tp-final.md) |

[Retour au Programme](index.md){ .md-button }
