---
tags:
  - ansible
  - security
  - jinja2
  - roles
---

# Industrialiser Ansible : Roles & Vault

Faire passer votre automatisation à l'échelle avec une structure et une sécurité appropriées.

---

## Roles (La Structure)

!!! tip "Ne mettez pas tout dans un seul fichier"
    Un playbook de 500 lignes est impossible à maintenir. Les roles fournissent une organisation modulaire et réutilisable.

### Créer un Role

```bash
# Générer la structure standard d'un role
ansible-galaxy init my_role

# Ou avec un chemin personnalisé
ansible-galaxy init roles/nginx
```

### Structure de Répertoire d'un Role

```
roles/
└── nginx/
    ├── defaults/
    │   └── main.yml      # Variables par défaut (priorité la plus basse)
    ├── files/
    │   └── nginx.conf    # Fichiers statiques à copier
    ├── handlers/
    │   └── main.yml      # Handlers (restart, reload)
    ├── meta/
    │   └── main.yml      # Métadonnées du role, dépendances
    ├── tasks/
    │   └── main.yml      # Liste principale des tasks (point d'entrée)
    ├── templates/
    │   └── site.conf.j2  # Templates Jinja2
    ├── vars/
    │   └── main.yml      # Variables du role (priorité haute)
    └── README.md
```

| Répertoire | Objectif |
|-----------|---------|
| `tasks/` | Logique principale (requis) |
| `handlers/` | Actions déclenchées (redémarrer les services) |
| `templates/` | Fichiers Jinja2 (.j2) |
| `files/` | Fichiers statiques à copier |
| `vars/` | Variables du role (priorité haute) |
| `defaults/` | Valeurs par défaut (priorité basse, surchargeable) |
| `meta/` | Dépendances, métadonnées |

### Utiliser les Roles

```yaml
# site.yml
---
- name: Configure webservers
  hosts: webservers
  become: yes

  roles:
    - common           # roles/common/
    - nginx            # roles/nginx/
    - { role: app, app_port: 8080 }  # Avec des variables
```

### Role avec Tags et Conditions

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

### Exemple de Role : nginx

**roles/nginx/tasks/main.yml :**

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

**roles/nginx/handlers/main.yml :**

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

**roles/nginx/defaults/main.yml :**

```yaml
---
nginx_worker_processes: auto
nginx_worker_connections: 1024
nginx_port: 80
```

---

## Templates Jinja2 (Flexibilité)

Générer des fichiers de configuration dynamiques avec variables, boucles et conditions.

### Syntaxe de Base

| Syntaxe | Objectif | Exemple |
|--------|---------|---------|
| `{{ var }}` | Afficher une variable | `{{ nginx_port }}` |
| `{% ... %}` | Logique (if, for) | `{% if enabled %}` |
| `{# ... #}` | Commentaire | `{# Ceci est ignoré #}` |
| `{{ var \| filter }}` | Appliquer un filtre | `{{ name \| upper }}` |

### Variables

```jinja
# Variable basique
server_name {{ ansible_hostname }};
listen {{ nginx_port | default(80) }};

# Accès aux données imbriquées
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

{# Condition inline #}
debug = {{ 'true' if debug_mode else 'false' }}

{# Vérifier si une variable est définie #}
{% if custom_config is defined %}
include {{ custom_config }};
{% endif %}
```

### Boucles

```jinja
# Boucle simple
{% for server in upstream_servers %}
server {{ server }};
{% endfor %}

# Boucle avec index
{% for user in users %}
# User {{ loop.index }}: {{ user.name }}
{% endfor %}

# Boucle avec condition
{% for vhost in vhosts if vhost.enabled %}
include /etc/nginx/sites-enabled/{{ vhost.name }}.conf;
{% endfor %}

# Boucle sur un dictionnaire
{% for key, value in settings.items() %}
{{ key }} = {{ value }};
{% endfor %}
```

### Filtres

```jinja
# Manipulation de chaînes
{{ name | lower }}
{{ name | upper }}
{{ name | capitalize }}
{{ path | basename }}
{{ path | dirname }}

# Valeurs par défaut
{{ port | default(8080) }}
{{ config | default('none', true) }}  # Aussi pour les chaînes vides

# Listes
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

# Mathématiques
{{ value | int }}
{{ price | float }}
{{ values | sum }}
{{ values | max }}
```

### Exemple de Template Complet

**templates/nginx.conf.j2 :**

```jinja
# {{ ansible_managed }}
# Généré le {{ ansible_date_time.iso8601 }}

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

## Ansible Vault (Sécurité)

!!! danger "NE commitez JAMAIS de mots de passe en clair dans Git"
    Utilisez Ansible Vault pour chiffrer les données sensibles : mots de passe, clés API, certificats.

### Créer un Fichier Chiffré

```bash
# Créer un nouveau fichier chiffré
ansible-vault create secrets.yml

# Chiffrer un fichier existant
ansible-vault encrypt secrets.yml

# Déchiffrer un fichier
ansible-vault decrypt secrets.yml
```

### Éditer & Visualiser

```bash
# Éditer un fichier chiffré (déchiffre en mémoire)
ansible-vault edit secrets.yml

# Voir le contenu sans éditer
ansible-vault view secrets.yml

# Changer le mot de passe
ansible-vault rekey secrets.yml
```

### Structure du Fichier Chiffré

```yaml
# secrets.yml (avant chiffrement)
---
db_password: SuperSecret123!
api_key: sk-1234567890abcdef
ssl_private_key: |
  -----BEGIN PRIVATE KEY-----
  MIIEvgIBADANBgkqhkiG9w0BAQE...
  -----END PRIVATE KEY-----
```

Après chiffrement, le fichier contient :

```
$ANSIBLE_VAULT;1.1;AES256
3832666538653...données chiffrées...
```

### Exécution avec Vault

```bash
# Demander le mot de passe
ansible-playbook site.yml --ask-vault-pass

# Mot de passe depuis un fichier
ansible-playbook site.yml --vault-password-file ~/.vault_pass

# Plusieurs mots de passe vault
ansible-playbook site.yml --vault-id dev@~/.vault_dev --vault-id prod@~/.vault_prod
```

### Utiliser les Variables Chiffrées

```yaml
# playbook.yml
---
- hosts: databases
  become: yes
  vars_files:
    - vars/main.yml
    - vars/secrets.yml      # Fichier chiffré

  tasks:
    - name: Configure database
      template:
        src: db.conf.j2
        dest: /etc/myapp/db.conf
      vars:
        password: "{{ db_password }}"  # Depuis secrets.yml
```

### Chiffrer une Variable Unique

```bash
# Chiffrer une chaîne
ansible-vault encrypt_string 'SuperSecret123!' --name 'db_password'

# Sortie (à coller dans le fichier vars) :
db_password: !vault |
  $ANSIBLE_VAULT;1.1;AES256
  6138653033326...
```

---

## Bonnes Pratiques

### Structure de Projet

```
ansible-project/
├── ansible.cfg              # Config locale
├── inventory/
│   ├── production/
│   │   ├── hosts            # Serveurs de production
│   │   └── group_vars/
│   │       └── all.yml
│   └── staging/
│       ├── hosts
│       └── group_vars/
│           └── all.yml
├── group_vars/
│   ├── all.yml              # Variables pour tous les hôtes
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
│   ├── site.yml             # Playbook maître
│   ├── webservers.yml
│   └── databases.yml
├── files/                   # Fichiers statiques globaux
├── templates/               # Templates globaux
└── requirements.yml         # Dépendances de roles
```

### ansible.cfg Optimisé

```ini
[defaults]
inventory = ./inventory/production
roles_path = ./roles
remote_user = deploy
private_key_file = ~/.ssh/ansible_key

# Performance
forks = 10                    # Hôtes parallèles (défaut : 5)
gathering = smart             # Mettre en cache les facts
fact_caching = jsonfile
fact_caching_connection = /tmp/ansible_facts
fact_caching_timeout = 86400  # 24 heures

# Sortie
stdout_callback = yaml        # Sortie lisible
display_skipped_hosts = False

# Sécurité
host_key_checking = False     # Pour l'automation (moins sécurisé)
vault_password_file = ~/.vault_pass

[ssh_connection]
pipelining = True             # Exécution plus rapide
control_path = /tmp/ansible-%%h-%%r
ssh_args = -o ControlMaster=auto -o ControlPersist=60s

[privilege_escalation]
become = True
become_method = sudo
become_ask_pass = False
```

### Astuces de Performance

| Paramètre | Impact |
|---------|--------|
| `forks = 10` | Exécuter sur 10 hôtes en parallèle |
| `pipelining = True` | Réduire les opérations SSH |
| `gathering = smart` | Ne pas re-collecter les facts |
| `strategy: free` | Ne pas attendre l'hôte le plus lent |

```yaml
# Dans le playbook pour les tasks asynchrones
- name: Long running task
  command: /usr/bin/long_task
  async: 3600        # Durée max d'exécution
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

## Référence Rapide

```bash
# Roles
ansible-galaxy init roles/myrole
ansible-galaxy install -r requirements.yml

# Vault
ansible-vault create secrets.yml
ansible-vault edit secrets.yml
ansible-vault encrypt_string 'secret' --name 'var_name'
ansible-playbook site.yml --ask-vault-pass

# Exécuter avec options
ansible-playbook site.yml -i inventory/prod --limit webservers
ansible-playbook site.yml --tags "config,deploy" --skip-tags "debug"
ansible-playbook site.yml --check --diff
```
