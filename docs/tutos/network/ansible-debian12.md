---
tags:
  - tutos
  - network
  - ansible
  - automation
  - devops
  - debian
---

# Ansible sur Debian 12

Installation d'**Ansible** sur Debian 12 Bookworm.

| Composant | Version |
|-----------|---------|
| Debian | 12 Bookworm |
| Ansible | 2.14+ |

**Durée estimée :** 30 minutes

---

## 1. Installation

### Via pip (recommandé)

```bash
apt update
apt install -y python3 python3-pip python3-venv

python3 -m pip install --user ansible

# Version
ansible --version
```

### Via apt

```bash
apt install -y ansible

ansible --version
```

---

## 2. Configuration SSH

```bash
ssh-keygen -t ed25519 -f ~/.ssh/ansible_key -N ""
ssh-copy-id -i ~/.ssh/ansible_key.pub user@target
```

---

## 3. Structure projet

```bash
mkdir -p ~/ansible/{inventory,playbooks,roles,group_vars}
cd ~/ansible
```

---

## 4. Configuration

```bash
cat > ansible.cfg << 'EOF'
[defaults]
inventory = inventory/hosts
remote_user = ansible
private_key_file = ~/.ssh/ansible_key
host_key_checking = False

[privilege_escalation]
become = True
become_method = sudo
EOF
```

---

## 5. Inventory

```ini
# inventory/hosts
[webservers]
web01 ansible_host=192.168.1.10
web02 ansible_host=192.168.1.11

[databases]
db01 ansible_host=192.168.1.20

[all:vars]
ansible_python_interpreter=/usr/bin/python3
```

---

## 6. Commandes Ad-Hoc

```bash
ansible all -m ping
ansible webservers -m apt -a "name=nginx state=present"
ansible all -m shell -a "uptime"
```

---

## 7. Playbook

```yaml
# playbooks/webservers.yml
---
- name: Configure web servers
  hosts: webservers
  become: yes

  tasks:
    - name: Install Nginx
      apt:
        name: nginx
        state: present
        update_cache: yes

    - name: Start Nginx
      service:
        name: nginx
        state: started
        enabled: yes

    - name: Configure firewall
      ufw:
        rule: allow
        port: '80'
        proto: tcp
```

```bash
ansible-playbook playbooks/webservers.yml
```

---

## 8. Variables

```yaml
# group_vars/webservers.yml
---
nginx_port: 80
nginx_worker_processes: auto
```

---

## 9. Rôles

```bash
ansible-galaxy init roles/nginx
```

```yaml
# roles/nginx/tasks/main.yml
---
- name: Install Nginx
  apt:
    name: nginx
    state: present

- name: Start Nginx
  service:
    name: nginx
    state: started
    enabled: yes
```

```yaml
# playbooks/site.yml
---
- hosts: webservers
  become: yes
  roles:
    - nginx
```

---

## 10. Vault

```bash
ansible-vault create vars/secrets.yml
ansible-playbook site.yml --ask-vault-pass
```

---

## Comparatif Rocky vs Debian

| Aspect | Rocky 9 | Debian 12 |
|--------|---------|-----------|
| Package manager | dnf | apt |
| Firewall | firewalld | ufw |
| Module packages | dnf | apt |
| Installation | EPEL/pip | apt/pip |

---

## Modules Debian

```yaml
# Packages
- apt:
    name: nginx
    state: present
    update_cache: yes

# UFW
- ufw:
    rule: allow
    port: '443'
    proto: tcp

# Services
- service:
    name: nginx
    state: started
```

---

## Commandes

```bash
ansible all -m ping                          # Test
ansible-playbook playbook.yml                # Exécuter
ansible-playbook playbook.yml --check        # Dry-run
ansible-playbook playbook.yml -v             # Verbose
ansible-doc apt                              # Documentation
ansible-galaxy install geerlingguy.nginx     # Installer rôle
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
