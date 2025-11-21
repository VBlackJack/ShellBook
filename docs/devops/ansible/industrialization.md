# Industrializing Ansible: Roles & Vault

`#ansible` `#security` `#jinja2` `#roles`

Scale your automation with proper structure and security.

---

## Roles (The Structure)

!!! tip "Don't put everything in one file"
    A 500-line playbook is unmaintainable. Roles provide reusable, modular organization.

### Create a Role

```bash
# Generate standard role structure
ansible-galaxy init my_role

# Or with custom path
ansible-galaxy init roles/nginx
```

### Role Directory Structure

```
roles/
└── nginx/
    ├── defaults/
    │   └── main.yml      # Default variables (lowest priority)
    ├── files/
    │   └── nginx.conf    # Static files to copy
    ├── handlers/
    │   └── main.yml      # Handlers (restart, reload)
    ├── meta/
    │   └── main.yml      # Role metadata, dependencies
    ├── tasks/
    │   └── main.yml      # Main task list (entry point)
    ├── templates/
    │   └── site.conf.j2  # Jinja2 templates
    ├── vars/
    │   └── main.yml      # Role variables (high priority)
    └── README.md
```

| Directory | Purpose |
|-----------|---------|
| `tasks/` | Main logic (required) |
| `handlers/` | Triggered actions (restart services) |
| `templates/` | Jinja2 files (.j2) |
| `files/` | Static files to copy |
| `vars/` | Role variables (high priority) |
| `defaults/` | Default values (low priority, overridable) |
| `meta/` | Dependencies, metadata |

### Using Roles

```yaml
# site.yml
---
- name: Configure webservers
  hosts: webservers
  become: yes

  roles:
    - common           # roles/common/
    - nginx            # roles/nginx/
    - { role: app, app_port: 8080 }  # With variables
```

### Role with Tags and Conditions

```yaml
roles:
  - role: nginx
    tags: webserver
    when: "'webservers' in group_names"

  - role: postgresql
    tags: database
    vars:
      pg_version: 15
```

### Example Role: nginx

**roles/nginx/tasks/main.yml:**

```yaml
---
- name: Install nginx
  apt:
    name: nginx
    state: present
    update_cache: yes
  tags: install

- name: Deploy configuration
  template:
    src: nginx.conf.j2
    dest: /etc/nginx/nginx.conf
  notify: Reload nginx
  tags: config

- name: Ensure nginx is running
  service:
    name: nginx
    state: started
    enabled: yes
```

**roles/nginx/handlers/main.yml:**

```yaml
---
- name: Reload nginx
  service:
    name: nginx
    state: reloaded

- name: Restart nginx
  service:
    name: nginx
    state: restarted
```

**roles/nginx/defaults/main.yml:**

```yaml
---
nginx_worker_processes: auto
nginx_worker_connections: 1024
nginx_port: 80
```

---

## Jinja2 Templates (Flexibility)

Generate dynamic configuration files with variables, loops, and conditions.

### Basic Syntax

| Syntax | Purpose | Example |
|--------|---------|---------|
| `{{ var }}` | Print variable | `{{ nginx_port }}` |
| `{% ... %}` | Logic (if, for) | `{% if enabled %}` |
| `{# ... #}` | Comment | `{# This is ignored #}` |
| `{{ var \| filter }}` | Apply filter | `{{ name \| upper }}` |

### Variables

```jinja
# Basic variable
server_name {{ ansible_hostname }};
listen {{ nginx_port | default(80) }};

# Accessing nested data
{{ user.name }}
{{ servers[0].ip }}

# Facts
{{ ansible_default_ipv4.address }}
{{ ansible_memtotal_mb }}
```

### Conditions

```jinja
{% if env == 'production' %}
worker_processes {{ ansible_processor_vcpus }};
{% else %}
worker_processes 1;
{% endif %}

{# Inline condition #}
debug = {{ 'true' if debug_mode else 'false' }}

{# Check if variable is defined #}
{% if custom_config is defined %}
include {{ custom_config }};
{% endif %}
```

### Loops

```jinja
# Simple loop
{% for server in upstream_servers %}
server {{ server }};
{% endfor %}

# Loop with index
{% for user in users %}
# User {{ loop.index }}: {{ user.name }}
{% endfor %}

# Loop with condition
{% for vhost in vhosts if vhost.enabled %}
include /etc/nginx/sites-enabled/{{ vhost.name }}.conf;
{% endfor %}

# Dictionary loop
{% for key, value in settings.items() %}
{{ key }} = {{ value }};
{% endfor %}
```

### Filters

```jinja
# String manipulation
{{ name | lower }}
{{ name | upper }}
{{ name | capitalize }}
{{ path | basename }}
{{ path | dirname }}

# Default values
{{ port | default(8080) }}
{{ config | default('none', true) }}  # Also for empty strings

# Lists
{{ servers | join(', ') }}
{{ items | length }}
{{ items | first }}
{{ items | last }}
{{ items | unique }}
{{ items | sort }}

# JSON/YAML
{{ data | to_json }}
{{ data | to_yaml }}
{{ data | to_nice_json(indent=2) }}

# Math
{{ value | int }}
{{ price | float }}
{{ values | sum }}
{{ values | max }}
```

### Complete Template Example

**templates/nginx.conf.j2:**

```jinja
# {{ ansible_managed }}
# Generated on {{ ansible_date_time.iso8601 }}

user www-data;
worker_processes {{ nginx_worker_processes | default('auto') }};
pid /run/nginx.pid;

events {
    worker_connections {{ nginx_worker_connections | default(1024) }};
}

http {
    sendfile on;
    tcp_nopush on;

{% if nginx_gzip_enabled | default(true) %}
    gzip on;
    gzip_types text/plain text/css application/json;
{% endif %}

{% for vhost in nginx_vhosts %}
    server {
        listen {{ vhost.port | default(80) }};
        server_name {{ vhost.server_name }};
        root {{ vhost.root }};

{% if vhost.ssl | default(false) %}
        ssl_certificate {{ vhost.ssl_cert }};
        ssl_certificate_key {{ vhost.ssl_key }};
{% endif %}
    }
{% endfor %}
}
```

---

## Ansible Vault (Security)

!!! danger "NEVER commit cleartext passwords to Git"
    Use Ansible Vault to encrypt sensitive data: passwords, API keys, certificates.

### Create Encrypted File

```bash
# Create new encrypted file
ansible-vault create secrets.yml

# Encrypt existing file
ansible-vault encrypt secrets.yml

# Decrypt file
ansible-vault decrypt secrets.yml
```

### Edit & View

```bash
# Edit encrypted file (decrypts in memory)
ansible-vault edit secrets.yml

# View contents without editing
ansible-vault view secrets.yml

# Change password
ansible-vault rekey secrets.yml
```

### Encrypted File Structure

```yaml
# secrets.yml (before encryption)
---
db_password: SuperSecret123!
api_key: sk-1234567890abcdef
ssl_private_key: |
  -----BEGIN PRIVATE KEY-----
  MIIEvgIBADANBgkqhkiG9w0BAQE...
  -----END PRIVATE KEY-----
```

After encryption, file contains:

```
$ANSIBLE_VAULT;1.1;AES256
3832666538653...encrypted data...
```

### Running with Vault

```bash
# Prompt for password
ansible-playbook site.yml --ask-vault-pass

# Password from file
ansible-playbook site.yml --vault-password-file ~/.vault_pass

# Multiple vault passwords
ansible-playbook site.yml --vault-id dev@~/.vault_dev --vault-id prod@~/.vault_prod
```

### Using Encrypted Variables

```yaml
# playbook.yml
---
- hosts: databases
  become: yes
  vars_files:
    - vars/main.yml
    - vars/secrets.yml      # Encrypted file

  tasks:
    - name: Configure database
      template:
        src: db.conf.j2
        dest: /etc/myapp/db.conf
      vars:
        password: "{{ db_password }}"  # From secrets.yml
```

### Encrypt Single Variable

```bash
# Encrypt a string
ansible-vault encrypt_string 'SuperSecret123!' --name 'db_password'

# Output (paste into vars file):
db_password: !vault |
  $ANSIBLE_VAULT;1.1;AES256
  6138653033326...
```

---

## Best Practices

### Project Layout

```
ansible-project/
├── ansible.cfg              # Local config
├── inventory/
│   ├── production/
│   │   ├── hosts            # Production servers
│   │   └── group_vars/
│   │       └── all.yml
│   └── staging/
│       ├── hosts
│       └── group_vars/
│           └── all.yml
├── group_vars/
│   ├── all.yml              # Variables for all hosts
│   ├── webservers.yml
│   └── databases.yml
├── host_vars/
│   └── special-server.yml
├── roles/
│   ├── common/
│   ├── nginx/
│   ├── postgresql/
│   └── app/
├── playbooks/
│   ├── site.yml             # Master playbook
│   ├── webservers.yml
│   └── databases.yml
├── files/                   # Global static files
├── templates/               # Global templates
└── requirements.yml         # Role dependencies
```

### Optimized ansible.cfg

```ini
[defaults]
inventory = ./inventory/production
roles_path = ./roles
remote_user = deploy
private_key_file = ~/.ssh/ansible_key

# Performance
forks = 10                    # Parallel hosts (default: 5)
gathering = smart             # Cache facts
fact_caching = jsonfile
fact_caching_connection = /tmp/ansible_facts
fact_caching_timeout = 86400  # 24 hours

# Output
stdout_callback = yaml        # Readable output
display_skipped_hosts = False

# Security
host_key_checking = False     # For automation (less secure)
vault_password_file = ~/.vault_pass

[ssh_connection]
pipelining = True             # Faster execution
control_path = /tmp/ansible-%%h-%%r
ssh_args = -o ControlMaster=auto -o ControlPersist=60s

[privilege_escalation]
become = True
become_method = sudo
become_ask_pass = False
```

### Performance Tips

| Setting | Impact |
|---------|--------|
| `forks = 10` | Run on 10 hosts in parallel |
| `pipelining = True` | Reduce SSH operations |
| `gathering = smart` | Don't re-gather facts |
| `strategy: free` | Don't wait for slowest host |

```yaml
# In playbook for async tasks
- name: Long running task
  command: /usr/bin/long_task
  async: 3600        # Max runtime
  poll: 0            # Fire and forget
  register: task_result

- name: Check task status
  async_status:
    jid: "{{ task_result.ansible_job_id }}"
  register: job_result
  until: job_result.finished
  retries: 60
  delay: 10
```

---

## Quick Reference

```bash
# Roles
ansible-galaxy init roles/myrole
ansible-galaxy install -r requirements.yml

# Vault
ansible-vault create secrets.yml
ansible-vault edit secrets.yml
ansible-vault encrypt_string 'secret' --name 'var_name'
ansible-playbook site.yml --ask-vault-pass

# Run with options
ansible-playbook site.yml -i inventory/prod --limit webservers
ansible-playbook site.yml --tags "config,deploy" --skip-tags "debug"
ansible-playbook site.yml --check --diff
```
