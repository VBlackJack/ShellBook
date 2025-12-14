---
tags:
  - tutos
  - network
  - ansible
  - automation
  - devops
  - rocky
---

# Ansible sur Rocky Linux 9

Installation et configuration d'**Ansible** pour l'automatisation IT.

| Composant | Version |
|-----------|---------|
| Rocky Linux | 9.x |
| Ansible | 2.14+ |

**Durée estimée :** 35 minutes

---

## Concepts

| Terme | Description |
|-------|-------------|
| **Control Node** | Machine avec Ansible |
| **Managed Node** | Machines cibles |
| **Inventory** | Liste des hôtes |
| **Playbook** | Fichier YAML de tâches |
| **Role** | Collection réutilisable |
| **Module** | Unité de travail |

---

## Architecture

```
┌─────────────────────┐
│   Control Node      │
│   (Ansible)         │
│                     │
│  ┌───────────────┐  │
│  │  Playbooks    │  │
│  │  Inventory    │  │
│  │  Roles        │  │
│  └───────────────┘  │
└──────────┬──────────┘
           │ SSH
           │
     ┌─────┴─────┐
     │           │
     ▼           ▼
┌─────────┐  ┌─────────┐
│ Web 01  │  │ DB 01   │
└─────────┘  └─────────┘
```

---

## 1. Installation

### Via pip (recommandé)

```bash
dnf install -y python3 python3-pip
pip3 install ansible

# Version
ansible --version
```

### Via EPEL

```bash
dnf install -y epel-release
dnf install -y ansible-core

ansible --version
```

---

## 2. Configuration SSH

```bash
# Générer une clé SSH
ssh-keygen -t ed25519 -f ~/.ssh/ansible_key -N ""

# Copier sur les cibles
ssh-copy-id -i ~/.ssh/ansible_key.pub user@target1
ssh-copy-id -i ~/.ssh/ansible_key.pub user@target2
```

---

## 3. Structure de projet

```bash
mkdir -p ~/ansible-project/{inventory,playbooks,roles,group_vars,host_vars}
cd ~/ansible-project
```

```
ansible-project/
├── ansible.cfg
├── inventory/
│   ├── production
│   └── staging
├── playbooks/
│   ├── site.yml
│   ├── webservers.yml
│   └── databases.yml
├── roles/
│   ├── common/
│   ├── nginx/
│   └── mariadb/
├── group_vars/
│   ├── all.yml
│   └── webservers.yml
└── host_vars/
    └── web01.yml
```

---

## 4. Configuration Ansible

```bash
cat > ansible.cfg << 'EOF'
[defaults]
inventory = inventory/production
remote_user = ansible
private_key_file = ~/.ssh/ansible_key
host_key_checking = False
retry_files_enabled = False
forks = 10

[privilege_escalation]
become = True
become_method = sudo
become_user = root
become_ask_pass = False
EOF
```

---

## 5. Inventory

### Format INI

```ini
# inventory/production
[webservers]
web01 ansible_host=192.168.1.10
web02 ansible_host=192.168.1.11

[databases]
db01 ansible_host=192.168.1.20

[loadbalancers]
lb01 ansible_host=192.168.1.5

[production:children]
webservers
databases
loadbalancers

[all:vars]
ansible_python_interpreter=/usr/bin/python3
```

### Format YAML

```yaml
# inventory/production.yml
all:
  children:
    webservers:
      hosts:
        web01:
          ansible_host: 192.168.1.10
        web02:
          ansible_host: 192.168.1.11
    databases:
      hosts:
        db01:
          ansible_host: 192.168.1.20
  vars:
    ansible_python_interpreter: /usr/bin/python3
```

---

## 6. Commandes Ad-Hoc

```bash
# Ping tous les hôtes
ansible all -m ping

# Info système
ansible all -m setup

# Exécuter une commande
ansible webservers -m command -a "uptime"

# Shell
ansible all -m shell -a "df -h"

# Copier un fichier
ansible all -m copy -a "src=/etc/hosts dest=/tmp/hosts"

# Installer un package
ansible webservers -m dnf -a "name=nginx state=present"

# Service
ansible webservers -m service -a "name=nginx state=started enabled=yes"

# Utilisateur
ansible all -m user -a "name=deploy state=present"
```

---

## 7. Playbook de base

```yaml
# playbooks/site.yml
---
- name: Configuration des serveurs web
  hosts: webservers
  become: yes
  vars:
    nginx_port: 80

  tasks:
    - name: Installer Nginx
      dnf:
        name: nginx
        state: present

    - name: Configurer Nginx
      template:
        src: templates/nginx.conf.j2
        dest: /etc/nginx/nginx.conf
        backup: yes
      notify: Restart Nginx

    - name: Démarrer Nginx
      service:
        name: nginx
        state: started
        enabled: yes

    - name: Ouvrir le firewall
      firewalld:
        port: "{{ nginx_port }}/tcp"
        permanent: yes
        state: enabled
        immediate: yes

  handlers:
    - name: Restart Nginx
      service:
        name: nginx
        state: restarted
```

### Exécuter

```bash
ansible-playbook playbooks/site.yml

# Dry-run
ansible-playbook playbooks/site.yml --check

# Verbose
ansible-playbook playbooks/site.yml -v

# Limiter aux hôtes
ansible-playbook playbooks/site.yml --limit web01
```

---

## 8. Variables

### group_vars

```yaml
# group_vars/webservers.yml
---
nginx_port: 80
nginx_worker_processes: auto
nginx_worker_connections: 1024
```

### host_vars

```yaml
# host_vars/web01.yml
---
nginx_server_name: web01.example.com
```

### Dans le playbook

```yaml
vars:
  http_port: 80

vars_files:
  - vars/secrets.yml
```

---

## 9. Templates Jinja2

```jinja2
# templates/nginx.conf.j2
worker_processes {{ nginx_worker_processes }};

events {
    worker_connections {{ nginx_worker_connections }};
}

http {
    server {
        listen {{ nginx_port }};
        server_name {{ nginx_server_name | default('localhost') }};

        location / {
            root /var/www/html;
            index index.html;
        }
    }
}
```

---

## 10. Rôles

### Créer un rôle

```bash
ansible-galaxy init roles/nginx
```

### Structure

```
roles/nginx/
├── defaults/
│   └── main.yml
├── files/
├── handlers/
│   └── main.yml
├── meta/
│   └── main.yml
├── tasks/
│   └── main.yml
├── templates/
└── vars/
    └── main.yml
```

### tasks/main.yml

```yaml
---
- name: Install Nginx
  dnf:
    name: nginx
    state: present

- name: Configure Nginx
  template:
    src: nginx.conf.j2
    dest: /etc/nginx/nginx.conf
  notify: restart nginx

- name: Start Nginx
  service:
    name: nginx
    state: started
    enabled: yes
```

### handlers/main.yml

```yaml
---
- name: restart nginx
  service:
    name: nginx
    state: restarted
```

### Utiliser le rôle

```yaml
# playbooks/webservers.yml
---
- hosts: webservers
  become: yes
  roles:
    - common
    - nginx
```

---

## 11. Ansible Vault

```bash
# Créer un fichier chiffré
ansible-vault create vars/secrets.yml

# Éditer
ansible-vault edit vars/secrets.yml

# Chiffrer un fichier existant
ansible-vault encrypt vars/passwords.yml

# Déchiffrer
ansible-vault decrypt vars/passwords.yml

# Voir le contenu
ansible-vault view vars/secrets.yml

# Exécuter avec vault
ansible-playbook site.yml --ask-vault-pass
ansible-playbook site.yml --vault-password-file ~/.vault_pass
```

### Contenu chiffré

```yaml
# vars/secrets.yml
---
db_password: "SuperSecret123!"
api_key: "abc123xyz"
```

---

## 12. Conditions et boucles

### Conditions

```yaml
- name: Install package (RedHat)
  dnf:
    name: httpd
    state: present
  when: ansible_os_family == "RedHat"

- name: Install package (Debian)
  apt:
    name: apache2
    state: present
  when: ansible_os_family == "Debian"
```

### Boucles

```yaml
- name: Créer des utilisateurs
  user:
    name: "{{ item.name }}"
    groups: "{{ item.groups }}"
    state: present
  loop:
    - { name: 'user1', groups: 'wheel' }
    - { name: 'user2', groups: 'users' }

- name: Installer plusieurs packages
  dnf:
    name: "{{ item }}"
    state: present
  loop:
    - nginx
    - php-fpm
    - mariadb-server
```

---

## 13. Ansible Galaxy

```bash
# Chercher
ansible-galaxy search nginx

# Installer
ansible-galaxy install geerlingguy.nginx

# Requirements file
cat > requirements.yml << 'EOF'
---
roles:
  - name: geerlingguy.nginx
  - name: geerlingguy.mysql

collections:
  - name: community.general
EOF

ansible-galaxy install -r requirements.yml
```

---

## Commandes utiles

```bash
# Test de syntaxe
ansible-playbook playbook.yml --syntax-check

# Liste des tâches
ansible-playbook playbook.yml --list-tasks

# Liste des hôtes
ansible-playbook playbook.yml --list-hosts

# Tags
ansible-playbook playbook.yml --tags "config,deploy"
ansible-playbook playbook.yml --skip-tags "test"

# Facts d'un hôte
ansible hostname -m setup

# Documentation module
ansible-doc dnf
ansible-doc -l | grep user
```

---

## Dépannage

```bash
# Verbose
ansible-playbook -vvv playbook.yml

# Debug module
- name: Debug variable
  debug:
    var: my_variable

- name: Debug message
  debug:
    msg: "La valeur est {{ my_var }}"

# Step by step
ansible-playbook playbook.yml --step

# Start at task
ansible-playbook playbook.yml --start-at-task="Install Nginx"
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
