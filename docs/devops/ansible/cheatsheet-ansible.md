---
tags:
  - ansible
  - automation
  - cheatsheet
  - devops
  - iac
---

# Ansible Cheatsheet

Guide de référence rapide pour Ansible: ad-hoc commands, playbooks, variables, et modules courants.

---

## 1. Ad-hoc Commands

### Syntaxe de Base

```bash
ansible <hosts> -m <module> -a "<arguments>"
```

| Option | Description |
|--------|-------------|
| `-i <inventory>` | Fichier d'inventaire |
| `-m <module>` | Module à utiliser |
| `-a "<args>"` | Arguments du module |
| `-b` ou `--become` | Exécuter avec sudo |
| `-K` ou `--ask-become-pass` | Demander le mot de passe sudo |
| `-u <user>` | Utilisateur SSH |
| `-k` ou `--ask-pass` | Demander le mot de passe SSH |
| `--limit <host>` | Limiter à un sous-ensemble d'hôtes |
| `-f <forks>` | Parallélisme (défaut: 5) |
| `-v`, `-vv`, `-vvv` | Verbosité (debug) |

### Commandes Courantes

```bash
# Ping tous les hosts
ansible all -m ping

# Ping un groupe spécifique
ansible webservers -m ping

# Exécuter une commande
ansible all -m command -a "uptime"
ansible all -a "df -h"  # -m command est le défaut

# Exécuter avec sudo
ansible all -b -m command -a "systemctl status nginx"

# Shell (permet pipes, redirections)
ansible all -m shell -a "ps aux | grep nginx"

# Copier un fichier
ansible webservers -m copy -a "src=/tmp/file.txt dest=/tmp/file.txt"

# Installer un paquet (apt)
ansible ubuntu-servers -b -m apt -a "name=nginx state=present"

# Installer un paquet (yum/dnf)
ansible rhel-servers -b -m yum -a "name=nginx state=present"

# Redémarrer un service
ansible all -b -m systemd -a "name=nginx state=restarted"

# Créer un utilisateur
ansible all -b -m user -a "name=john state=present"

# Gather facts (informations système)
ansible all -m setup

# Gather facts filtré
ansible all -m setup -a "filter=ansible_distribution*"
```

### Exemples Pratiques

```bash
# Vérifier l'espace disque
ansible all -a "df -h"

# Mettre à jour tous les paquets (Ubuntu)
ansible ubuntu -b -m apt -a "upgrade=dist update_cache=yes"

# Mettre à jour tous les paquets (RHEL)
ansible rhel -b -m yum -a "name=* state=latest"

# Créer un dossier
ansible all -m file -a "path=/opt/app state=directory mode=0755"

# Télécharger un fichier
ansible all -m get_url -a "url=https://example.com/file.tar.gz dest=/tmp/"

# Exécuter un script
ansible all -m script -a "/path/to/script.sh"

# Vérifier la connectivité
ansible all -m ping -i inventory.ini

# Limiter à un seul host
ansible all -m ping --limit web01

# Utiliser une clé SSH spécifique
ansible all -m ping --private-key=~/.ssh/id_rsa_custom
```

---

## 2. Inventaire (Inventory)

### Format INI

```ini
# inventory.ini

# Hôtes individuels
web01 ansible_host=192.168.1.10
web02 ansible_host=192.168.1.11

# Groupe de hosts
[webservers]
web01
web02
web03 ansible_host=192.168.1.12

[databases]
db01 ansible_host=192.168.1.20 ansible_port=2222
db02 ansible_host=192.168.1.21

# Groupe de groupes
[production:children]
webservers
databases

# Variables de groupe
[webservers:vars]
ansible_user=deploy
ansible_become=yes
http_port=80

[databases:vars]
ansible_user=dbadmin
mysql_port=3306

# Variables globales
[all:vars]
ansible_python_interpreter=/usr/bin/python3
```

### Format YAML

```yaml
# inventory.yml
all:
  children:
    webservers:
      hosts:
        web01:
          ansible_host: 192.168.1.10
        web02:
          ansible_host: 192.168.1.11
      vars:
        ansible_user: deploy
        http_port: 80

    databases:
      hosts:
        db01:
          ansible_host: 192.168.1.20
          ansible_port: 2222
        db02:
          ansible_host: 192.168.1.21
      vars:
        mysql_port: 3306

    production:
      children:
        webservers:
        databases:

  vars:
    ansible_python_interpreter: /usr/bin/python3
```

### Variables d'Inventaire Communes

| Variable | Description |
|----------|-------------|
| `ansible_host` | Adresse IP ou hostname |
| `ansible_port` | Port SSH (défaut: 22) |
| `ansible_user` | Utilisateur SSH |
| `ansible_password` | Mot de passe SSH (non recommandé) |
| `ansible_ssh_private_key_file` | Clé SSH privée |
| `ansible_become` | Utiliser sudo (true/false) |
| `ansible_become_user` | Utilisateur pour sudo (défaut: root) |
| `ansible_become_password` | Mot de passe sudo |
| `ansible_python_interpreter` | Chemin vers Python |
| `ansible_connection` | Type de connexion (ssh, local, etc.) |

### Commandes d'Inventaire

```bash
# Lister tous les hosts
ansible all --list-hosts

# Lister un groupe spécifique
ansible webservers --list-hosts

# Voir les groupes
ansible all --list-hosts -i inventory.ini

# Voir les variables d'un host
ansible web01 -m debug -a "var=hostvars[inventory_hostname]"

# Graphe de l'inventaire
ansible-inventory --graph

# Export en JSON
ansible-inventory --list -i inventory.ini
```

---

## 3. Playbooks

### Structure de Base

```yaml
---
# playbook.yml
- name: Configure web servers
  hosts: webservers
  become: yes
  vars:
    http_port: 80
    max_clients: 200

  tasks:
    - name: Install nginx
      ansible.builtin.apt:
        name: nginx
        state: present
        update_cache: yes

    - name: Copy nginx config
      ansible.builtin.template:
        src: nginx.conf.j2
        dest: /etc/nginx/nginx.conf
      notify: restart nginx

    - name: Ensure nginx is running
      ansible.builtin.systemd:
        name: nginx
        state: started
        enabled: yes

  handlers:
    - name: restart nginx
      ansible.builtin.systemd:
        name: nginx
        state: restarted
```

### Exécution de Playbooks

```bash
# Exécuter un playbook
ansible-playbook playbook.yml

# Avec inventaire spécifique
ansible-playbook -i inventory.ini playbook.yml

# Limiter à certains hosts
ansible-playbook playbook.yml --limit web01,web02

# Vérifier la syntaxe
ansible-playbook playbook.yml --syntax-check

# Dry-run (simulation)
ansible-playbook playbook.yml --check

# Voir les différences
ansible-playbook playbook.yml --check --diff

# Mode verbeux
ansible-playbook playbook.yml -v
ansible-playbook playbook.yml -vvv  # Très verbeux

# Démarrer à partir d'une tâche
ansible-playbook playbook.yml --start-at-task="Install nginx"

# Exécuter seulement certains tags
ansible-playbook playbook.yml --tags "configuration,deployment"

# Exclure certains tags
ansible-playbook playbook.yml --skip-tags "testing"

# Lister les tâches
ansible-playbook playbook.yml --list-tasks

# Lister les hosts concernés
ansible-playbook playbook.yml --list-hosts

# Lister les tags
ansible-playbook playbook.yml --list-tags
```

### Sections d'un Playbook

```yaml
---
- name: Playbook complet
  hosts: all
  become: yes                # Utiliser sudo
  gather_facts: yes          # Collecter les facts (défaut)
  serial: 1                  # Exécuter sur 1 host à la fois
  max_fail_percentage: 0     # Tolérance aux erreurs

  vars:
    # Variables du playbook
    app_name: myapp
    app_version: "1.0"

  vars_files:
    # Fichiers de variables externes
    - vars/common.yml
    - vars/{{ environment }}.yml

  pre_tasks:
    # Tâches avant les rôles
    - name: Update apt cache
      ansible.builtin.apt:
        update_cache: yes

  roles:
    # Rôles à appliquer
    - common
    - webserver
    - { role: database, db_name: "mydb" }

  tasks:
    # Tâches principales
    - name: Install application
      ansible.builtin.copy:
        src: app.tar.gz
        dest: /opt/

  post_tasks:
    # Tâches après les rôles
    - name: Send notification
      ansible.builtin.debug:
        msg: "Deployment completed"

  handlers:
    # Handlers (déclenchés par notify)
    - name: restart service
      ansible.builtin.systemd:
        name: myapp
        state: restarted
```

---

## 4. Variables

### Déclaration de Variables

```yaml
# Dans un playbook
vars:
  http_port: 80
  max_clients: 200
  server_name: "webserver01"

# Dans un fichier externe
vars_files:
  - vars/common.yml
  - vars/production.yml

# Dans l'inventaire
[webservers:vars]
http_port=80

# Prompt à l'exécution
vars_prompt:
  - name: username
    prompt: "Enter username"
    private: no

  - name: password
    prompt: "Enter password"
    private: yes
```

### Priorité des Variables

Ordre de priorité (du plus faible au plus fort):

1. Defaults de rôle (`role/defaults/main.yml`)
2. Variables d'inventaire
3. Variables de groupe (`group_vars/`)
4. Variables d'hôte (`host_vars/`)
5. Variables de playbook
6. Variables de rôle (`role/vars/main.yml`)
7. Block vars
8. Task vars
9. Extra vars (`-e` ou `--extra-vars`)

```bash
# Extra vars (priorité maximale)
ansible-playbook playbook.yml -e "http_port=8080 env=production"
ansible-playbook playbook.yml -e "@vars/override.yml"
```

### Utilisation de Variables

```yaml
tasks:
  - name: Install package
    ansible.builtin.apt:
      name: "{{ package_name }}"
      state: present

  - name: Create directory
    ansible.builtin.file:
      path: "/opt/{{ app_name }}/{{ app_version }}"
      state: directory

  - name: Use default value
    ansible.builtin.debug:
      msg: "Port is {{ http_port | default(80) }}"

  - name: Conditional variable
    ansible.builtin.debug:
      msg: "{{ 'Production' if env == 'prod' else 'Development' }}"
```

### Facts (Variables Système)

```yaml
# Facts automatiques
tasks:
  - name: Show OS distribution
    ansible.builtin.debug:
      msg: "{{ ansible_distribution }} {{ ansible_distribution_version }}"

  - name: Show IP address
    ansible.builtin.debug:
      msg: "{{ ansible_default_ipv4.address }}"

  - name: Show hostname
    ansible.builtin.debug:
      msg: "{{ ansible_hostname }}"

  # Créer un fact personnalisé
  - name: Set custom fact
    ansible.builtin.set_fact:
      custom_var: "computed_value"

  # Utiliser register
  - name: Check if file exists
    ansible.builtin.stat:
      path: /etc/nginx/nginx.conf
    register: nginx_config

  - name: Use registered variable
    ansible.builtin.debug:
      msg: "Config exists: {{ nginx_config.stat.exists }}"
```

### Facts Courants

| Fact | Description |
|------|-------------|
| `ansible_hostname` | Nom d'hôte court |
| `ansible_fqdn` | FQDN complet |
| `ansible_default_ipv4.address` | Adresse IPv4 principale |
| `ansible_all_ipv4_addresses` | Toutes les adresses IPv4 |
| `ansible_distribution` | Distribution (Ubuntu, CentOS, etc.) |
| `ansible_distribution_version` | Version de la distribution |
| `ansible_os_family` | Famille OS (Debian, RedHat, etc.) |
| `ansible_architecture` | Architecture (x86_64, arm64, etc.) |
| `ansible_processor_cores` | Nombre de cores CPU |
| `ansible_memtotal_mb` | Mémoire totale en MB |
| `ansible_mounts` | Points de montage |
| `ansible_date_time.iso8601` | Date/heure ISO 8601 |

```bash
# Voir tous les facts d'un host
ansible web01 -m setup

# Filtrer les facts
ansible web01 -m setup -a "filter=ansible_distribution*"
ansible web01 -m setup -a "filter=ansible_*_ipv4"
```

---

## 5. Conditions & Boucles

### Conditions (when)

```yaml
tasks:
  # Condition simple
  - name: Install nginx on Debian
    ansible.builtin.apt:
      name: nginx
      state: present
    when: ansible_os_family == "Debian"

  # Condition multiple (AND)
  - name: Task for production Ubuntu
    ansible.builtin.debug:
      msg: "Production Ubuntu server"
    when:
      - ansible_distribution == "Ubuntu"
      - environment == "production"

  # Condition OR
  - name: Task for RedHat or CentOS
    ansible.builtin.debug:
      msg: "RedHat-based system"
    when: ansible_distribution == "RedHat" or ansible_distribution == "CentOS"

  # Condition sur variable définie
  - name: Task if variable is defined
    ansible.builtin.debug:
      msg: "Variable is set"
    when: my_var is defined

  # Condition sur variable non définie
  - name: Task if variable is not defined
    ansible.builtin.debug:
      msg: "Variable is not set"
    when: my_var is not defined

  # Condition sur register
  - name: Check service status
    ansible.builtin.systemd:
      name: nginx
      state: started
    register: service_result

  - name: Alert if service failed
    ansible.builtin.debug:
      msg: "Service failed to start"
    when: service_result.failed

  # Condition sur stdout
  - name: Get uptime
    ansible.builtin.command: uptime
    register: uptime_result

  - name: Check if uptime > 100 days
    ansible.builtin.debug:
      msg: "Server needs reboot"
    when: "'100 days' in uptime_result.stdout"
```

### Boucles (loop)

```yaml
tasks:
  # Boucle simple
  - name: Create multiple users
    ansible.builtin.user:
      name: "{{ item }}"
      state: present
    loop:
      - alice
      - bob
      - charlie

  # Boucle avec dictionnaires
  - name: Create users with details
    ansible.builtin.user:
      name: "{{ item.name }}"
      uid: "{{ item.uid }}"
      groups: "{{ item.groups }}"
    loop:
      - { name: "alice", uid: 1001, groups: "admin" }
      - { name: "bob", uid: 1002, groups: "users" }
      - { name: "charlie", uid: 1003, groups: "developers" }

  # Boucle sur une variable
  - name: Install packages
    ansible.builtin.apt:
      name: "{{ item }}"
      state: present
    loop: "{{ packages }}"

  # Boucle avec range
  - name: Create directories
    ansible.builtin.file:
      path: "/opt/dir{{ item }}"
      state: directory
    loop: "{{ range(1, 6) | list }}"  # 1 à 5

  # Boucle avec fichiers
  - name: Copy config files
    ansible.builtin.copy:
      src: "{{ item }}"
      dest: "/etc/app/"
    with_fileglob:
      - /path/to/configs/*.conf

  # Boucle imbriquée
  - name: Create user directories
    ansible.builtin.file:
      path: "/home/{{ item.0 }}/{{ item.1 }}"
      state: directory
    loop: "{{ users | product(directories) | list }}"
    vars:
      users: ['alice', 'bob']
      directories: ['downloads', 'documents']

  # Loop avec condition
  - name: Install packages conditionally
    ansible.builtin.apt:
      name: "{{ item }}"
      state: present
    loop:
      - nginx
      - mysql-server
      - redis
    when: item != "mysql-server" or install_mysql
```

---

## 6. Modules Courants

### Gestion des Fichiers

```yaml
# file: Créer/modifier fichiers et dossiers
- name: Create directory
  ansible.builtin.file:
    path: /opt/app
    state: directory
    mode: '0755'
    owner: www-data
    group: www-data

- name: Create symlink
  ansible.builtin.file:
    src: /opt/app/current
    dest: /opt/app/releases/v1.0
    state: link

- name: Delete file
  ansible.builtin.file:
    path: /tmp/old_file
    state: absent

# copy: Copier des fichiers
- name: Copy file
  ansible.builtin.copy:
    src: files/config.yml
    dest: /etc/app/config.yml
    owner: root
    group: root
    mode: '0644'
    backup: yes

# template: Copier avec templating Jinja2
- name: Deploy template
  ansible.builtin.template:
    src: templates/nginx.conf.j2
    dest: /etc/nginx/nginx.conf
    owner: root
    mode: '0644'
  notify: restart nginx

# lineinfile: Modifier une ligne
- name: Ensure line in file
  ansible.builtin.lineinfile:
    path: /etc/hosts
    line: "192.168.1.100 server.example.com"
    state: present

- name: Replace line
  ansible.builtin.lineinfile:
    path: /etc/ssh/sshd_config
    regexp: '^PermitRootLogin'
    line: 'PermitRootLogin no'

# blockinfile: Modifier un bloc
- name: Add block to file
  ansible.builtin.blockinfile:
    path: /etc/nginx/nginx.conf
    block: |
      server {
        listen 80;
        server_name example.com;
      }
    marker: "# {mark} ANSIBLE MANAGED BLOCK"
```

### Gestion des Paquets

```yaml
# apt (Debian/Ubuntu)
- name: Install package
  ansible.builtin.apt:
    name: nginx
    state: present
    update_cache: yes

- name: Install multiple packages
  ansible.builtin.apt:
    name:
      - nginx
      - mysql-server
      - redis-server
    state: present

- name: Upgrade all packages
  ansible.builtin.apt:
    upgrade: dist
    update_cache: yes

# yum/dnf (RedHat/CentOS)
- name: Install package
  ansible.builtin.yum:
    name: nginx
    state: present

# package (générique)
- name: Install package (OS-agnostic)
  ansible.builtin.package:
    name: nginx
    state: present

# pip (Python packages)
- name: Install Python package
  ansible.builtin.pip:
    name: flask
    version: '2.0.1'
    state: present
```

### Gestion des Services

```yaml
# systemd
- name: Start service
  ansible.builtin.systemd:
    name: nginx
    state: started
    enabled: yes

- name: Restart service
  ansible.builtin.systemd:
    name: nginx
    state: restarted

- name: Reload service
  ansible.builtin.systemd:
    name: nginx
    state: reloaded

- name: Stop and disable service
  ansible.builtin.systemd:
    name: nginx
    state: stopped
    enabled: no

# service (générique)
- name: Manage service
  ansible.builtin.service:
    name: nginx
    state: started
    enabled: yes
```

### Commandes Shell

```yaml
# command: Commandes simples (sans shell)
- name: Run command
  ansible.builtin.command: /usr/bin/make install
  args:
    chdir: /opt/app
    creates: /opt/app/installed.txt  # Skip si le fichier existe

# shell: Commandes avec shell (pipes, redirections)
- name: Run shell command
  ansible.builtin.shell: |
    ps aux | grep nginx | wc -l
  register: nginx_processes

- name: Use shell with pipes
  ansible.builtin.shell: cat /etc/hosts | grep localhost
  changed_when: false  # Ne compte pas comme changement

# script: Exécuter un script local
- name: Run local script on remote
  ansible.builtin.script: scripts/deploy.sh
  args:
    creates: /opt/app/deployed

# raw: SSH brut (sans Python)
- name: Bootstrap Python
  ansible.builtin.raw: apt-get install -y python3
```

### Gestion des Utilisateurs

```yaml
# user: Gérer les utilisateurs
- name: Create user
  ansible.builtin.user:
    name: deploy
    uid: 1001
    groups: sudo,docker
    shell: /bin/bash
    home: /home/deploy
    create_home: yes
    state: present

- name: Add SSH key
  ansible.posix.authorized_key:
    user: deploy
    key: "{{ lookup('file', '~/.ssh/id_rsa.pub') }}"
    state: present

# group: Gérer les groupes
- name: Create group
  ansible.builtin.group:
    name: developers
    gid: 2000
    state: present
```

### Réseau

```yaml
# uri: Requêtes HTTP
- name: Check API health
  ansible.builtin.uri:
    url: https://api.example.com/health
    method: GET
    status_code: 200
  register: api_check

- name: POST to API
  ansible.builtin.uri:
    url: https://api.example.com/deploy
    method: POST
    body_format: json
    body:
      version: "1.0"
      env: "production"
    headers:
      Authorization: "Bearer {{ api_token }}"

# get_url: Télécharger un fichier
- name: Download file
  ansible.builtin.get_url:
    url: https://example.com/app.tar.gz
    dest: /tmp/app.tar.gz
    mode: '0644'
    checksum: sha256:abc123...
```

---

## 7. Handlers

### Déclaration et Utilisation

```yaml
---
- name: Configure web server
  hosts: webservers
  tasks:
    - name: Copy nginx config
      ansible.builtin.template:
        src: nginx.conf.j2
        dest: /etc/nginx/nginx.conf
      notify:
        - restart nginx
        - reload nginx

    - name: Update certificate
      ansible.builtin.copy:
        src: cert.pem
        dest: /etc/ssl/cert.pem
      notify: restart nginx

  handlers:
    # Les handlers ne s'exécutent qu'une fois à la fin
    # même s'ils sont notifiés plusieurs fois
    - name: restart nginx
      ansible.builtin.systemd:
        name: nginx
        state: restarted

    - name: reload nginx
      ansible.builtin.systemd:
        name: nginx
        state: reloaded

    # Handler qui écoute plusieurs noms
    - name: reload web services
      listen: "reload services"
      ansible.builtin.systemd:
        name: "{{ item }}"
        state: reloaded
      loop:
        - nginx
        - php-fpm
```

### Forcer l'Exécution des Handlers

```yaml
tasks:
  - name: Flush handlers immediately
    ansible.builtin.meta: flush_handlers

  - name: Continue with other tasks
    ansible.builtin.debug:
      msg: "Handlers executed before this"
```

---

## 8. Roles

### Structure d'un Rôle

```text
roles/
  webserver/
    tasks/
      main.yml          # Tâches principales
    handlers/
      main.yml          # Handlers
    templates/
      nginx.conf.j2     # Templates Jinja2
    files/
      index.html        # Fichiers statiques
    vars/
      main.yml          # Variables du rôle
    defaults/
      main.yml          # Variables par défaut
    meta/
      main.yml          # Métadonnées et dépendances
```

### Utilisation dans un Playbook

```yaml
---
- name: Configure servers
  hosts: webservers
  roles:
    # Rôle simple
    - common
    - webserver

    # Rôle avec variables
    - role: database
      vars:
        db_name: myapp
        db_user: appuser

    # Rôle conditionnel
    - role: monitoring
      when: enable_monitoring
```

### Créer un Rôle

```bash
# Créer la structure
ansible-galaxy init webserver

# Résultat:
# webserver/
#   defaults/
#   files/
#   handlers/
#   meta/
#   tasks/
#   templates/
#   tests/
#   vars/
```

### Ansible Galaxy

```bash
# Installer un rôle depuis Galaxy
ansible-galaxy install geerlingguy.nginx

# Installer depuis requirements.yml
ansible-galaxy install -r requirements.yml

# requirements.yml:
# ---
# - name: geerlingguy.nginx
#   version: "3.1.0"
# - src: https://github.com/user/role.git
#   version: master
#   name: custom-role

# Lister les rôles installés
ansible-galaxy list

# Supprimer un rôle
ansible-galaxy remove geerlingguy.nginx
```

---

## 9. Ansible Vault (Secrets)

### Chiffrement de Fichiers

```bash
# Créer un fichier chiffré
ansible-vault create secrets.yml

# Éditer un fichier chiffré
ansible-vault edit secrets.yml

# Chiffrer un fichier existant
ansible-vault encrypt vars/production.yml

# Déchiffrer un fichier
ansible-vault decrypt vars/production.yml

# Voir un fichier chiffré
ansible-vault view secrets.yml

# Rekey (changer le mot de passe)
ansible-vault rekey secrets.yml
```

### Utilisation dans les Playbooks

```bash
# Exécuter avec vault password
ansible-playbook playbook.yml --ask-vault-pass

# Avec fichier de mot de passe
ansible-playbook playbook.yml --vault-password-file ~/.vault_pass

# Avec script de mot de passe
ansible-playbook playbook.yml --vault-password-file vault-pass.sh

# Plusieurs vault IDs
ansible-playbook playbook.yml --vault-id dev@prompt --vault-id prod@~/.vault_prod
```

### Exemple de Fichier Vault

```yaml
# secrets.yml (chiffré)
---
db_password: "S3cr3tP@ssw0rd"
api_key: "abc123xyz789"
ssl_key: |
  -----BEGIN PRIVATE KEY-----
  MIIEvQIBADANBgkqhkiG9w0...
  -----END PRIVATE KEY-----
```

```yaml
# Utilisation dans un playbook
---
- name: Deploy application
  hosts: webservers
  vars_files:
    - secrets.yml  # Fichier chiffré
  tasks:
    - name: Configure database
      ansible.builtin.template:
        src: db.conf.j2
        dest: /etc/app/db.conf
      # Le template peut utiliser {{ db_password }}
```

---

## 10. Configuration (ansible.cfg)

### Fichier de Configuration

```ini
# ansible.cfg (racine du projet ou ~/.ansible.cfg)

[defaults]
# Inventaire par défaut
inventory = ./inventory/hosts.ini

# Rôles path
roles_path = ./roles:/usr/share/ansible/roles

# Parallélisme
forks = 10

# Retry files (désactiver)
retry_files_enabled = False

# Logs
log_path = ./ansible.log

# Gather facts (désactiver par défaut pour performance)
gathering = explicit

# Verbosité
#verbosity = 1

# Callback plugins
stdout_callback = yaml
#stdout_callback = json

# SSH options
[ssh_connection]
# Pipelining (performance)
pipelining = True

# SSH multiplexing
ssh_args = -o ControlMaster=auto -o ControlPersist=60s

# Timeout
timeout = 30

# [privilege_escalation]
# become = True
# become_method = sudo
# become_user = root
# become_ask_pass = False
```

### Ordre de Recherche

Ansible cherche `ansible.cfg` dans cet ordre:

1. `ANSIBLE_CONFIG` (variable d'environnement)
2. `./ansible.cfg` (répertoire courant)
3. `~/.ansible.cfg` (home de l'utilisateur)
4. `/etc/ansible/ansible.cfg` (système)

---

## 11. Tips & Best Practices

### Organisation des Projets

```text
ansible-project/
  ansible.cfg              # Configuration
  inventory/
    production/
      hosts.ini            # Inventaire production
      group_vars/
        all.yml
        webservers.yml
      host_vars/
        web01.yml
    staging/
      hosts.ini
      group_vars/

  playbooks/
    deploy.yml
    update.yml

  roles/
    common/
    webserver/
    database/

  group_vars/             # Variables globales
    all.yml

  host_vars/

  files/                  # Fichiers statiques
  templates/              # Templates Jinja2

  requirements.yml        # Rôles Galaxy

  .gitignore
  README.md
```

### Commandes Utiles

```bash
# Vérifier la syntaxe d'un playbook
ansible-playbook playbook.yml --syntax-check

# Lister les tâches
ansible-playbook playbook.yml --list-tasks

# Lister les hosts
ansible-playbook playbook.yml --list-hosts

# Dry-run avec diff
ansible-playbook playbook.yml --check --diff

# Démarrer à partir d'une tâche
ansible-playbook playbook.yml --start-at-task="Install nginx"

# Step-by-step (confirmer chaque tâche)
ansible-playbook playbook.yml --step

# Voir les variables d'un host
ansible -m debug -a "var=hostvars[inventory_hostname]" web01

# Vérifier la connectivité
ansible all -m ping -i inventory.ini

# Version d'Ansible
ansible --version
```

### Alias Pratiques

```bash
# Ajouter dans ~/.bashrc ou ~/.zshrc
alias ap='ansible-playbook'
alias apc='ansible-playbook --check'
alias apcd='ansible-playbook --check --diff'
alias ai='ansible-inventory'
alias ag='ansible-galaxy'
alias av='ansible-vault'
```

---

## Ressources Complémentaires

- **Documentation officielle**: https://docs.ansible.com/
- **Ansible Galaxy**: https://galaxy.ansible.com/
- **Ansible Collections**: https://docs.ansible.com/ansible/latest/collections/
- **Best Practices**: https://docs.ansible.com/ansible/latest/user_guide/playbooks_best_practices.html
- **Awesome Ansible**: https://github.com/ansible/awesome-ansible

!!! tip "Aller Plus Loin"
    - Explorez **Ansible Collections** pour des modules additionnels
    - Utilisez **Ansible Tower / AWX** pour une interface web
    - Apprenez **Molecule** pour tester vos rôles
    - Intégrez Ansible dans vos pipelines CI/CD
