---
tags:
  - formation
  - ansible
  - roles
  - templates
  - jinja2
  - ansible-galaxy
  - industrialization
  - devops
---

# Module 3 : Roles & Templates - L'Industrialisation

## Objectif du Module

Maîtriser l'organisation du code Ansible en rôles réutilisables, créer des configurations dynamiques avec les templates Jinja2, et industrialiser votre infrastructure as code pour gérer des centaines de serveurs avec efficacité.

**Durée :** 3 heures

## Introduction : Le Problème du Monolithe

### Don't Repeat Yourself (DRY)

> **"Don't Repeat Yourself (DRY)."**
> — Andy Hunt & Dave Thomas, The Pragmatic Programmer

**Le problème des playbooks monolithiques :**

Vous avez appris à écrire des playbooks au Module 2. Parfait pour débuter. Mais imaginez cette situation :

```yaml
# site.yml - 500 lignes, TOUT dans un fichier
---
- name: Configuration complète
  hosts: all
  become: yes

  tasks:
    # Nginx (50 lignes)
    - name: Installer Nginx
      apt: name=nginx state=present
    - name: Copier config Nginx
      copy: src=nginx.conf dest=/etc/nginx/
    - name: Démarrer Nginx
      service: name=nginx state=started
    # ... 47 autres tâches Nginx

    # PostgreSQL (60 lignes)
    - name: Installer PostgreSQL
      apt: name=postgresql state=present
    - name: Configurer pg_hba.conf
      copy: src=pg_hba.conf dest=/etc/postgresql/
    # ... 58 autres tâches PostgreSQL

    # Monitoring (40 lignes)
    - name: Installer Prometheus
      apt: name=prometheus state=present
    # ... 38 autres tâches Prometheus

    # Backup (35 lignes)
    # Logs (30 lignes)
    # SSL (45 lignes)
    # Users (25 lignes)
    # Firewall (40 lignes)
    # ... Total : 500+ lignes
```

**Problèmes à l'échelle :**

1. ❌ **Lisibilité** : Impossible de trouver rapidement une tâche (500 lignes)
2. ❌ **Réutilisabilité** : Nginx configuré ici = copier-coller pour un autre projet
3. ❌ **Maintenance** : Modifier Nginx = chercher dans 500 lignes
4. ❌ **Collaboration** : 5 personnes qui modifient le même fichier = conflits Git
5. ❌ **Tests** : Impossible de tester "juste Nginx" isolément
6. ❌ **Duplication** : Config similaire pour dev/staging/prod = copier-coller

### La Solution : Roles & Templates

**Architecture en Rôles :**

```text
ansible-project/
├── site.yml                    # 20 lignes (orchestration)
├── roles/
│   ├── nginx/                  # Rôle autonome
│   │   ├── tasks/main.yml      # Tâches Nginx
│   │   ├── handlers/main.yml   # Handlers Nginx
│   │   ├── templates/nginx.conf.j2  # Config dynamique
│   │   └── vars/main.yml       # Variables Nginx
│   ├── postgresql/             # Rôle autonome
│   │   └── tasks/main.yml
│   ├── monitoring/             # Rôle autonome
│   └── common/                 # Rôle partagé
└── group_vars/
    ├── web.yml                 # Variables groupe web
    └── db.yml                  # Variables groupe db
```

**Playbook principal simplifié :**

```yaml
# site.yml - 20 lignes !
---
- name: Serveurs Web
  hosts: web
  roles:
    - common
    - nginx

- name: Serveurs DB
  hosts: db
  roles:
    - common
    - postgresql
    - monitoring
```

**Avantages :**

- ✅ **Lisibilité** : 1 rôle = 1 fonction (Nginx, PostgreSQL, etc.)
- ✅ **Réutilisabilité** : Rôle Nginx utilisable dans 10 projets
- ✅ **Maintenance** : Modifier Nginx = `roles/nginx/tasks/main.yml`
- ✅ **Collaboration** : 1 personne = 1 rôle (pas de conflit Git)
- ✅ **Tests** : `ansible-playbook test-nginx.yml` (test isolé)
- ✅ **Environnements** : Mêmes rôles, variables différentes (dev/prod)

### Statistiques de l'Industrie

**Migration Playbooks Monolithiques → Rôles :**

| **Métrique** | **Monolithique** | **Rôles** | **Gain** |
|--------------|-----------------|----------|----------|
| Lignes playbook principal | 500+ | 20-50 | -90% |
| Temps de maintenance (modifier 1 service) | 15 min (chercher) | 2 min (direct) | -87% |
| Réutilisation code entre projets | 0% (copier-coller) | 80% (import role) | +80% |
| Conflits Git (5 devs) | 12/mois | 1/mois | -92% |
| Temps onboarding nouveau dev | 2 jours (comprendre monolithe) | 4 heures (1 rôle à la fois) | -75% |

**ROI des rôles :** Amortissement dès le 2ème projet.

---

## Concept : Les Rôles Ansible

### Qu'est-ce qu'un Rôle ?

**Définition :** Un rôle est une **unité réutilisable d'automatisation** contenant tout le nécessaire pour gérer un composant (Nginx, PostgreSQL, utilisateurs, etc.).

**Analogie :** Si un playbook est une "recette de cuisine", un rôle est un "ingrédient pré-préparé" (comme acheter de la pâte feuilletée au lieu de la faire soi-même).

### Structure Standard d'un Rôle

**Arborescence complète d'un rôle :**

```text
roles/nginx/
├── tasks/
│   └── main.yml         # Tâches principales (OBLIGATOIRE)
├── handlers/
│   └── main.yml         # Handlers (restart Nginx, etc.)
├── templates/
│   └── nginx.conf.j2    # Templates Jinja2
├── files/
│   └── index.html       # Fichiers statiques
├── vars/
│   └── main.yml         # Variables du rôle (priorité haute)
├── defaults/
│   └── main.yml         # Variables par défaut (priorité basse)
├── meta/
│   └── main.yml         # Métadonnées (dépendances, Galaxy)
└── README.md            # Documentation du rôle
```

**Hiérarchie de priorité des variables :**

1. **`vars/main.yml`** : Priorité HAUTE (difficile à surcharger)
2. **`defaults/main.yml`** : Priorité BASSE (facile à surcharger)

**Règle d'or :** Utiliser `defaults/` pour variables personnalisables, `vars/` pour constantes.

#### Explication de Chaque Répertoire

##### 1. `tasks/main.yml` (OBLIGATOIRE)

**Contient les tâches du rôle.**

```yaml
# roles/nginx/tasks/main.yml
---
- name: Installer Nginx
  apt:
    name: nginx
    state: present
    update_cache: yes

- name: Copier configuration Nginx
  template:
    src: nginx.conf.j2
    dest: /etc/nginx/nginx.conf
  notify: Restart Nginx

- name: Démarrer Nginx
  service:
    name: nginx
    state: started
    enabled: yes
```

##### 2. `handlers/main.yml`

**Handlers déclenchés par `notify`.**

```yaml
# roles/nginx/handlers/main.yml
---
- name: Restart Nginx
  service:
    name: nginx
    state: restarted

- name: Reload Nginx
  service:
    name: nginx
    state: reloaded
```

##### 3. `templates/` (Templates Jinja2)

**Fichiers de configuration dynamiques** (voir section Jinja2).

```jinja2
# roles/nginx/templates/nginx.conf.j2
server {
    listen {{ nginx_port }};
    server_name {{ server_name }};
    root {{ document_root }};
}
```

##### 4. `files/`

**Fichiers statiques copiés tels quels** (HTML, scripts, certificats).

```yaml
# Dans tasks/main.yml
- name: Copier fichier statique
  copy:
    src: index.html    # Cherche dans roles/nginx/files/index.html
    dest: /var/www/html/
```

##### 5. `vars/main.yml`

**Variables du rôle (priorité haute).**

```yaml
# roles/nginx/vars/main.yml
---
nginx_user: www-data
nginx_worker_processes: 4
```

**Utilisation :** Constantes du rôle, difficiles à surcharger.

##### 6. `defaults/main.yml`

**Variables par défaut (priorité basse).**

```yaml
# roles/nginx/defaults/main.yml
---
nginx_port: 80
server_name: localhost
document_root: /var/www/html
```

**Utilisation :** Variables personnalisables par l'utilisateur du rôle.

**Exemple de surcharge :**

```yaml
# playbook.yml
- hosts: web
  roles:
    - role: nginx
      vars:
        nginx_port: 8080    # Surcharge la valeur par défaut (80)
```

##### 7. `meta/main.yml`

**Métadonnées du rôle.**

```yaml
# roles/nginx/meta/main.yml
---
galaxy_info:
  author: VotreNom
  description: Installation et configuration de Nginx
  license: MIT
  min_ansible_version: 2.9
  platforms:
    - name: Ubuntu
      versions:
        - focal
        - jammy

dependencies:
  - role: common    # Ce rôle dépend du rôle "common"
```

**`dependencies:`** : Rôles exécutés **avant** ce rôle.

---

### Ansible Galaxy - L'Initialisation de Rôles

**Ansible Galaxy** est un hub communautaire de rôles pré-faits (comme Docker Hub pour les conteneurs).

#### Créer un Rôle avec `ansible-galaxy init`

**Commande :**

```bash
# Créer la structure complète d'un rôle
ansible-galaxy init roles/nginx
```

**Sortie :**

```text
- Role roles/nginx was created successfully
```

**Structure générée automatiquement :**

```text
roles/nginx/
├── README.md
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
├── tests/
│   ├── inventory
│   └── test.yml
└── vars/
    └── main.yml
```

**Tous les fichiers sont créés avec des commentaires explicatifs.**

#### Utiliser un Rôle depuis Galaxy

**Rechercher des rôles :**

```bash
# Rechercher sur https://galaxy.ansible.com
ansible-galaxy search nginx

# Installer un rôle depuis Galaxy
ansible-galaxy install geerlingguy.nginx
```

**Le rôle sera installé dans** : `~/.ansible/roles/geerlingguy.nginx`

**Utilisation dans un playbook :**

```yaml
- hosts: web
  roles:
    - geerlingguy.nginx
```

**Spécifier la version :**

```bash
ansible-galaxy install geerlingguy.nginx,3.1.4
```

**Fichier `requirements.yml` (recommandé) :**

```yaml
# requirements.yml
---
- name: geerlingguy.nginx
  version: 3.1.4

- name: geerlingguy.postgresql
  version: 3.4.2
```

**Installation :**

```bash
ansible-galaxy install -r requirements.yml
```

---

## Concept : Templates Jinja2

### Qu'est-ce que Jinja2 ?

**Jinja2** est un moteur de templates Python utilisé par Ansible pour générer des fichiers de configuration dynamiques.

**Analogie :** Si `copy` copie un fichier **statique**, `template` génère un fichier **dynamique** à partir de variables.

**Exemple :**

**Template `nginx.conf.j2` :**

```jinja2
server {
    listen {{ nginx_port }};
    server_name {{ server_name }};
}
```

**Variables :**

```yaml
nginx_port: 8080
server_name: example.com
```

**Fichier généré `/etc/nginx/nginx.conf` :**

```nginx
server {
    listen 8080;
    server_name example.com;
}
```

---

### Syntaxe Jinja2

#### 1. Variables : `{{ variable }}`

**Insérer une variable :**

```jinja2
# Template
Mon serveur : {{ ansible_hostname }}
Port : {{ nginx_port }}
```

**Variables Ansible automatiques :**

- `{{ ansible_hostname }}` : Nom du serveur
- `{{ ansible_default_ipv4.address }}` : IP du serveur
- `{{ ansible_distribution }}` : Distribution (Ubuntu, CentOS, etc.)
- `{{ ansible_processor_cores }}` : Nombre de cœurs CPU

**Exemple complet :**

```jinja2
# roles/nginx/templates/nginx.conf.j2
user {{ nginx_user }};
worker_processes {{ ansible_processor_cores }};

server {
    listen {{ nginx_port }};
    server_name {{ server_name }};

    location / {
        root {{ document_root }};
    }
}
```

---

#### 2. Conditions : `{% if %}`

**Syntaxe :**

```jinja2
{% if condition %}
    # Code si condition vraie
{% elif autre_condition %}
    # Code si autre condition vraie
{% else %}
    # Code sinon
{% endif %}
```

**Exemple - SSL Conditionnel :**

```jinja2
server {
    listen {{ nginx_port }};
    server_name {{ server_name }};

    {% if ssl_enabled %}
    # Configuration SSL
    listen 443 ssl;
    ssl_certificate {{ ssl_cert_path }};
    ssl_certificate_key {{ ssl_key_path }};
    {% endif %}

    location / {
        root {{ document_root }};
    }
}
```

**Variables :**

```yaml
# Avec SSL
ssl_enabled: true
ssl_cert_path: /etc/ssl/certs/server.crt
ssl_key_path: /etc/ssl/private/server.key

# Sans SSL
ssl_enabled: false
```

**Tests conditionnels courants :**

```jinja2
{% if variable is defined %}
{% if variable is not defined %}
{% if my_list | length > 0 %}
{% if ansible_distribution == "Ubuntu" %}
{% if nginx_port == 80 or nginx_port == 443 %}
```

---

#### 3. Boucles : `{% for %}`

**Syntaxe :**

```jinja2
{% for item in liste %}
    # Code répété pour chaque élément
{% endfor %}
```

**Exemple - Backends Multiples :**

```jinja2
# Template upstream Nginx
upstream backend {
    {% for host in groups['backend'] %}
    server {{ hostvars[host]['ansible_default_ipv4']['address'] }}:8080;
    {% endfor %}
}
```

**Inventory :**

```ini
[backend]
backend1 ansible_host=192.168.1.10
backend2 ansible_host=192.168.1.11
backend3 ansible_host=192.168.1.12
```

**Fichier généré :**

```text
upstream backend {
    server 192.168.1.10:8080;
    server 192.168.1.11:8080;
    server 192.168.1.12:8080;
}
```

**Exemple - Boucle sur Liste de Ports :**

```jinja2
# Ouvrir plusieurs ports dans le firewall
{% for port in allowed_ports %}
ufw allow {{ port }}/tcp
{% endfor %}
```

**Variables :**

```yaml
allowed_ports:
  - 80
  - 443
  - 8080
```

**Généré :**

```text
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 8080/tcp
```

---

#### 4. Filtres Jinja2

**Les filtres transforment des variables.**

**Syntaxe :** `{{ variable | filtre }}`

**Filtres courants :**

```jinja2
# Majuscules
{{ server_name | upper }}           # EXAMPLE.COM

# Minuscules
{{ server_name | lower }}           # example.com

# Valeur par défaut si variable non définie
{{ my_var | default('valeur_par_defaut') }}

# Longueur d'une liste
{{ my_list | length }}

# Joindre une liste
{{ ['a', 'b', 'c'] | join(',') }}   # a,b,c

# Trier
{{ my_list | sort }}

# Unique (supprimer doublons)
{{ my_list | unique }}
```

**Exemple combiné :**

```jinja2
# Générer liste de serveurs en majuscules
{% for host in groups['web'] | sort %}
SERVER={{ host | upper }}
{% endfor %}
```

---

#### 5. Commentaires Jinja2

**Syntaxe :**

```jinja2
{# Ceci est un commentaire Jinja2 #}
{# Il ne sera PAS dans le fichier généré #}

# Ceci est un commentaire dans le fichier généré
```

---

### Utiliser un Template dans un Playbook

**Module `template` :**

```yaml
- name: Générer configuration Nginx
  template:
    src: nginx.conf.j2        # Template source
    dest: /etc/nginx/nginx.conf  # Fichier généré
    owner: root
    group: root
    mode: '0644'
  notify: Reload Nginx
```

**Où cherche Ansible le template ?**

1. **Dans un rôle** : `roles/nginx/templates/nginx.conf.j2`
2. **Dans le playbook** : `templates/nginx.conf.j2` (à côté du playbook)

---

## Pratique : Refactoring Nginx en Rôle

### Objectif

Transformer le playbook Nginx du Module 2 en un **rôle réutilisable** avec un **template Jinja2** pour rendre le port dynamique.

**Avant (Module 2) :**

```yaml
# install_nginx.yml - Tout dans un fichier
---
- name: Installer Nginx
  hosts: web
  become: yes

  tasks:
    - name: Installer Nginx
      apt: name=nginx state=present

    - name: Copier config
      copy: src=nginx.conf dest=/etc/nginx/nginx.conf

    - name: Démarrer Nginx
      service: name=nginx state=started
```

**Après (Module 3) :**

```yaml
# site.yml - Simple et réutilisable
---
- name: Serveurs Web
  hosts: web
  roles:
    - nginx
```

### Étape 1 : Créer la Structure du Rôle

```bash
# Créer le rôle nginx
ansible-galaxy init roles/nginx
```

### Étape 2 : Définir les Variables par Défaut

**Fichier `roles/nginx/defaults/main.yml` :**

```yaml
---
# Port d'écoute Nginx
nginx_port: 80

# Nom du serveur
server_name: localhost

# Racine des documents
document_root: /var/www/html

# Utilisateur Nginx
nginx_user: www-data

# Nombre de worker processes
nginx_worker_processes: auto
```

### Étape 3 : Créer le Template Jinja2

**Fichier `roles/nginx/templates/nginx.conf.j2` :**

```jinja2
# Configuration Nginx générée par Ansible
# Rôle: nginx
# Date: {{ ansible_date_time.iso8601 }}

user {{ nginx_user }};
worker_processes {{ nginx_worker_processes }};
pid /run/nginx.pid;

events {
    worker_connections 768;
}

http {
    # Configuration HTTP de base
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;

    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    # Logs
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;

    # Serveur par défaut
    server {
        listen {{ nginx_port }};
        server_name {{ server_name }};

        root {{ document_root }};
        index index.html index.htm;

        location / {
            try_files $uri $uri/ =404;
        }

        # Informations serveur (debug)
        location /server-info {
            return 200 "Serveur: {{ ansible_hostname }}\nIP: {{ ansible_default_ipv4.address }}\nPort: {{ nginx_port }}\n";
            add_header Content-Type text/plain;
        }
    }
}
```

### Étape 4 : Créer les Tâches

**Fichier `roles/nginx/tasks/main.yml` :**

```yaml
---
- name: Installer Nginx
  apt:
    name: nginx
    state: present
    update_cache: yes
  tags:
    - nginx
    - install

- name: Générer configuration Nginx depuis template
  template:
    src: nginx.conf.j2
    dest: /etc/nginx/nginx.conf
    owner: root
    group: root
    mode: '0644'
    backup: yes    # Créer une backup avant modification
  notify: Reload Nginx
  tags:
    - nginx
    - config

- name: Créer le répertoire document_root
  file:
    path: "{{ document_root }}"
    state: directory
    owner: "{{ nginx_user }}"
    group: "{{ nginx_user }}"
    mode: '0755'
  tags:
    - nginx

- name: Copier page index.html personnalisée
  template:
    src: index.html.j2
    dest: "{{ document_root }}/index.html"
    owner: "{{ nginx_user }}"
    group: "{{ nginx_user }}"
    mode: '0644'
  tags:
    - nginx
    - deploy

- name: S'assurer que Nginx est démarré et activé
  service:
    name: nginx
    state: started
    enabled: yes
  tags:
    - nginx
    - service
```

### Étape 5 : Créer les Handlers

**Fichier `roles/nginx/handlers/main.yml` :**

```yaml
---
- name: Reload Nginx
  service:
    name: nginx
    state: reloaded

- name: Restart Nginx
  service:
    name: nginx
    state: restarted
```

### Étape 6 : Créer le Template HTML

**Fichier `roles/nginx/templates/index.html.j2` :**

```html
<!DOCTYPE html>
<html>
<head>
    <title>Nginx - {{ ansible_hostname }}</title>
    <style>
        body {
            font-family: Arial, sans-serif;
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
            padding: 50px;
            border-radius: 20px;
            backdrop-filter: blur(10px);
        }
        h1 { font-size: 3em; margin: 0; }
        p { font-size: 1.5em; margin-top: 20px; }
        .info {
            background: rgba(0,0,0,0.3);
            padding: 20px;
            border-radius: 10px;
            margin-top: 30px;
        }
        .info p { font-size: 1em; margin: 5px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚀 Nginx Déployé par Ansible</h1>
        <p>Rôle: nginx (Module 3)</p>

        <div class="info">
            <p><strong>Serveur:</strong> {{ ansible_hostname }}</p>
            <p><strong>IP:</strong> {{ ansible_default_ipv4.address }}</p>
            <p><strong>Port:</strong> {{ nginx_port }}</p>
            <p><strong>Distribution:</strong> {{ ansible_distribution }} {{ ansible_distribution_version }}</p>
        </div>
    </div>
</body>
</html>
```

### Étape 7 : Créer le Playbook Principal

**Fichier `site.yml` :**

```yaml
---
- name: Configuration serveurs web
  hosts: web
  become: yes

  roles:
    - role: nginx
      vars:
        nginx_port: 8080           # Surcharge port (défaut: 80)
        server_name: web.example.com
```

### Étape 8 : Exécuter le Playbook

```bash
# Vérifier syntaxe
ansible-playbook --syntax-check site.yml

# Dry-run
ansible-playbook --check site.yml

# Exécution
ansible-playbook site.yml
```

**Sortie attendue :**

```text
PLAY [Configuration serveurs web] *****************************************

TASK [nginx : Installer Nginx] ********************************************
ok: [web1]

TASK [nginx : Générer configuration Nginx depuis template] ***************
changed: [web1]

TASK [nginx : Créer le répertoire document_root] *************************
ok: [web1]

TASK [nginx : Copier page index.html personnalisée] **********************
changed: [web1]

TASK [nginx : S'assurer que Nginx est démarré et activé] *****************
ok: [web1]

RUNNING HANDLER [nginx : Reload Nginx] ************************************
changed: [web1]

PLAY RECAP ****************************************************************
web1                       : ok=6    changed=3    unreachable=0    failed=0
```

### Étape 9 : Vérifier le Résultat

**Ouvrir un navigateur :**

```text
http://localhost:8080/
```

**Vous verrez la page HTML avec les informations dynamiques :**
- Serveur: web1
- IP: 192.168.1.10
- Port: 8080
- Distribution: Ubuntu 22.04

**Vérifier la configuration générée :**

```bash
ansible web -m command -a "cat /etc/nginx/nginx.conf | grep 'listen'"
```

**Sortie :**

```text
web1 | CHANGED | rc=0 >>
        listen 8080;
```

**Le port est dynamique !** ✅

---

## Exercice : Le Rôle Common

### Scénario

**Problématique :** Chaque serveur de votre infrastructure (web, db, monitoring) a besoin d'une **configuration de base identique** :

- Packages essentiels : `vim`, `curl`, `htop`
- Timezone : `Europe/Paris`
- Configuration locale : `fr_FR.UTF-8`

**Actuellement :** Vous dupliquez ces tâches dans chaque playbook → **Violation du principe DRY**.

**Solution :** Créer un rôle `common` appliqué à **tous** les serveurs.

### Mission

Créer un rôle `common` qui :

1. **Installe les packages de base** : `vim`, `curl`, `htop`
2. **Configure le timezone** : `Europe/Paris`
3. **Est appliqué à tous les serveurs** via `site.yml`

### Étapes

#### Étape 1 : Créer le Rôle

```bash
ansible-galaxy init roles/common
```

#### Étape 2 : Définir les Variables

**Fichier `roles/common/defaults/main.yml` :**

Créez une liste de packages par défaut et le timezone.

**Indice :**

```yaml
common_packages:
  - vim
  - curl
  - htop

timezone: Europe/Paris
```

#### Étape 3 : Créer les Tâches

**Fichier `roles/common/tasks/main.yml` :**

Ajoutez 2 tâches :

1. **Installer les packages** (module `apt`)
2. **Configurer le timezone** (module `timezone`)

**Indice module timezone :**

```yaml
- name: Configurer le timezone
  timezone:
    name: "{{ timezone }}"
```

#### Étape 4 : Créer le Playbook

**Fichier `site.yml` :**

Appliquez le rôle `common` à **tous** les serveurs.

```yaml
---
- name: Configuration de base (tous serveurs)
  hosts: all
  become: yes

  roles:
    - common
```

#### Étape 5 : Tester

```bash
# Syntaxe
ansible-playbook --syntax-check site.yml

# Dry-run
ansible-playbook --check site.yml

# Exécution
ansible-playbook site.yml
```

#### Étape 6 : Validation

**Vérifier que les packages sont installés :**

```bash
ansible all -m command -a "which vim"
ansible all -m command -a "which htop"
```

**Vérifier le timezone :**

```bash
ansible all -m command -a "timedatectl | grep 'Time zone'"
```

**Sortie attendue :**

```text
web1 | CHANGED | rc=0 >>
       Time zone: Europe/Paris (CET, +0100)
```

---

## Solution

??? quote "Solution Complète - Rôle Common"

    ### Structure du Rôle

    ```text
    roles/common/
    ├── defaults/
    │   └── main.yml
    ├── tasks/
    │   └── main.yml
    ├── handlers/
    │   └── main.yml
    └── meta/
        └── main.yml
    ```

    ---

    ### Fichier `roles/common/defaults/main.yml`

    ```yaml
    ---
    # Liste des packages de base à installer
    common_packages:
      - vim
      - curl
      - htop
      - git
      - wget
      - net-tools

    # Timezone à configurer
    timezone: Europe/Paris

    # Locale à configurer
    locale: fr_FR.UTF-8
    ```

    ---

    ### Fichier `roles/common/tasks/main.yml`

    ```yaml
    ---
    - name: Mettre à jour le cache APT
      apt:
        update_cache: yes
        cache_valid_time: 3600
      tags:
        - common
        - packages

    - name: Installer les packages de base
      apt:
        name: "{{ common_packages }}"
        state: present
      tags:
        - common
        - packages

    - name: Configurer le timezone
      timezone:
        name: "{{ timezone }}"
      notify: Display Timezone Info
      tags:
        - common
        - timezone

    - name: Configurer la locale
      locale_gen:
        name: "{{ locale }}"
        state: present
      tags:
        - common
        - locale

    - name: Définir la locale par défaut
      command: update-locale LANG={{ locale }}
      changed_when: false
      tags:
        - common
        - locale

    - name: Créer le répertoire /opt/scripts (si nécessaire)
      file:
        path: /opt/scripts
        state: directory
        owner: root
        group: root
        mode: '0755'
      tags:
        - common
        - filesystem
    ```

    ---

    ### Fichier `roles/common/handlers/main.yml`

    ```yaml
    ---
    - name: Display Timezone Info
      debug:
        msg: "Timezone configuré : {{ timezone }}"
    ```

    ---

    ### Fichier `roles/common/meta/main.yml`

    ```yaml
    ---
    galaxy_info:
      author: VotreNom
      description: Configuration de base pour tous les serveurs
      company: VotreEntreprise
      license: MIT
      min_ansible_version: 2.9

      platforms:
        - name: Ubuntu
          versions:
            - focal
            - jammy
        - name: Debian
          versions:
            - buster
            - bullseye

      galaxy_tags:
        - common
        - base
        - system

    dependencies: []
    ```

    ---

    ### Fichier `site.yml` (Playbook Principal)

    ```yaml
    ---
    - name: Configuration de base (tous serveurs)
      hosts: all
      become: yes

      roles:
        - common

    - name: Serveurs Web
      hosts: web
      become: yes

      roles:
        - role: common
          tags: [common]
        - role: nginx
          vars:
            nginx_port: 8080
          tags: [nginx]

    - name: Serveurs DB
      hosts: db
      become: yes

      roles:
        - common
    ```

    ---

    ### Exécution

    **1. Vérifier la syntaxe**

    ```bash
    ansible-playbook --syntax-check site.yml
    ```

    ---

    **2. Dry-run**

    ```bash
    ansible-playbook --check site.yml
    ```

    **Sortie attendue :**

    ```text
    PLAY [Configuration de base (tous serveurs)] ******************************

    TASK [common : Mettre à jour le cache APT] ********************************
    ok: [web1]
    ok: [web2]
    ok: [database]

    TASK [common : Installer les packages de base] ****************************
    changed: [web1]
    changed: [web2]
    changed: [database]

    TASK [common : Configurer le timezone] ************************************
    changed: [web1]
    changed: [web2]
    changed: [database]

    TASK [common : Configurer la locale] **************************************
    changed: [web1]
    changed: [web2]
    changed: [database]

    TASK [common : Définir la locale par défaut] ******************************
    ok: [web1]
    ok: [web2]
    ok: [database]

    TASK [common : Créer le répertoire /opt/scripts] **************************
    changed: [web1]
    changed: [web2]
    changed: [database]

    RUNNING HANDLER [common : Display Timezone Info] **************************
    ok: [web1] => {
        "msg": "Timezone configuré : Europe/Paris"
    }

    PLAY RECAP ****************************************************************
    web1                       : ok=7    changed=4    unreachable=0    failed=0
    web2                       : ok=7    changed=4    unreachable=0    failed=0
    database                   : ok=7    changed=4    unreachable=0    failed=0
    ```

    ---

    **3. Exécution réelle**

    ```bash
    ansible-playbook site.yml
    ```

    ---

    **4. Exécution sélective (tags)**

    ```bash
    # Uniquement les packages
    ansible-playbook site.yml --tags packages

    # Uniquement le timezone
    ansible-playbook site.yml --tags timezone

    # Tout le rôle common
    ansible-playbook site.yml --tags common
    ```

    ---

    ### Validations Post-Exécution

    **Vérifier que Vim est installé :**

    ```bash
    ansible all -m command -a "which vim"
    ```

    **Sortie :**

    ```text
    web1 | CHANGED | rc=0 >>
    /usr/bin/vim

    web2 | CHANGED | rc=0 >>
    /usr/bin/vim

    database | CHANGED | rc=0 >>
    /usr/bin/vim
    ```

    ---

    **Vérifier que htop est installé :**

    ```bash
    ansible all -m command -a "htop --version"
    ```

    ---

    **Vérifier le timezone :**

    ```bash
    ansible all -m command -a "timedatectl | grep 'Time zone'"
    ```

    **Sortie :**

    ```text
    web1 | CHANGED | rc=0 >>
           Time zone: Europe/Paris (CET, +0100)

    web2 | CHANGED | rc=0 >>
           Time zone: Europe/Paris (CET, +0100)

    database | CHANGED | rc=0 >>
           Time zone: Europe/Paris (CET, +0100)
    ```

    ---

    **Vérifier la locale :**

    ```bash
    ansible all -m command -a "locale | grep LANG"
    ```

    **Sortie :**

    ```text
    web1 | CHANGED | rc=0 >>
    LANG=fr_FR.UTF-8
    ```

    ---

    **Vérifier le répertoire /opt/scripts :**

    ```bash
    ansible all -m command -a "ls -ld /opt/scripts"
    ```

    **Sortie :**

    ```text
    web1 | CHANGED | rc=0 >>
    drwxr-xr-x 2 root root 4096 Nov 22 16:30 /opt/scripts
    ```

    ---

    ### Variante : Surcharge de Variables

    **Si vous voulez des packages différents pour certains serveurs :**

    **Fichier `group_vars/db.yml` :**

    ```yaml
    ---
    common_packages:
      - vim
      - curl
      - htop
      - postgresql-client    # Package supplémentaire pour DB
      - pg_top               # Monitoring PostgreSQL
    ```

    **Ansible utilisera automatiquement ces packages pour le groupe `db`.**

    ---

    ### Bonus : Rôle Common Avancé

    **Ajouter d'autres tâches utiles :**

    ```yaml
    # roles/common/tasks/main.yml
    ---
    # ... (tâches existantes)

    - name: Désactiver les mises à jour automatiques (optionnel)
      apt:
        name: unattended-upgrades
        state: absent
      tags:
        - common
        - security

    - name: Configurer les limites système (ulimit)
      pam_limits:
        domain: '*'
        limit_type: soft
        limit_item: nofile
        value: '65536'
      tags:
        - common
        - limits

    - name: Créer un utilisateur de déploiement
      user:
        name: deploy
        state: present
        shell: /bin/bash
        create_home: yes
        groups: sudo
        append: yes
      tags:
        - common
        - users

    - name: Copier clé SSH publique pour deploy
      authorized_key:
        user: deploy
        state: present
        key: "{{ lookup('file', '~/.ssh/id_rsa.pub') }}"
      tags:
        - common
        - ssh
    ```

## Conclusion du Module

### Ce que Vous Avez Appris

✅ **Structure des rôles** : 8 répertoires (tasks, handlers, templates, files, vars, defaults, meta, README)

✅ **Ansible Galaxy** : Créer (`ansible-galaxy init`), rechercher, installer des rôles

✅ **Templates Jinja2** : Variables `{{ }}`, conditions `{% if %}`, boucles `{% for %}`, filtres

✅ **Refactoring** : Transformer un playbook monolithique en rôle réutilisable

✅ **Rôle common** : Configuration de base partagée entre tous les serveurs

✅ **Organisation** : Séparer code (rôles) et données (group_vars, host_vars)

### Commandes Clés à Retenir

```bash
# Créer un rôle
ansible-galaxy init roles/myrole

# Rechercher des rôles
ansible-galaxy search nginx

# Installer un rôle depuis Galaxy
ansible-galaxy install geerlingguy.nginx

# Installer depuis requirements.yml
ansible-galaxy install -r requirements.yml

# Lister les rôles installés
ansible-galaxy list

# Supprimer un rôle
ansible-galaxy remove geerlingguy.nginx
```

### Organisation Recommandée d'un Projet

```text
ansible-project/
├── ansible.cfg              # Configuration Ansible
├── inventory/
│   ├── production.ini       # Inventory production
│   └── staging.ini          # Inventory staging
├── group_vars/
│   ├── all.yml              # Variables pour tous
│   ├── web.yml              # Variables groupe web
│   └── db.yml               # Variables groupe db
├── host_vars/
│   ├── web1.yml             # Variables serveur web1
│   └── db1.yml              # Variables serveur db1
├── roles/
│   ├── common/              # Rôle de base
│   ├── nginx/               # Rôle Nginx
│   ├── postgresql/          # Rôle PostgreSQL
│   └── monitoring/          # Rôle monitoring
├── playbooks/
│   ├── site.yml             # Playbook principal
│   ├── web.yml              # Playbook serveurs web
│   └── db.yml               # Playbook serveurs DB
├── requirements.yml         # Rôles Galaxy à installer
└── README.md                # Documentation projet
```

### Best Practices

**1. Un rôle = Une fonction**

```text
✅ BON :
roles/nginx/         # Uniquement Nginx
roles/postgresql/    # Uniquement PostgreSQL

❌ MAUVAIS :
roles/webserver/     # Nginx + PostgreSQL + Redis (trop large)
```

**2. Variables dans `defaults/` (personnalisables)**

```yaml
# roles/nginx/defaults/main.yml
nginx_port: 80        # Facile à surcharger
nginx_user: www-data  # Facile à surcharger
```

**3. Documenter les variables dans README.md**

```markdown
# Rôle Nginx

## Variables

- `nginx_port` (défaut: 80) : Port d'écoute
- `server_name` (défaut: localhost) : Nom du serveur
```

**4. Utiliser des tags**

```yaml
tasks:
  - name: Installer Nginx
    apt: name=nginx
    tags: [nginx, install]

  - name: Configurer Nginx
    template: ...
    tags: [nginx, config]
```

**5. Tester les rôles isolément**

```bash
# Tester uniquement le rôle nginx
ansible-playbook playbooks/nginx-test.yml
```

### Différence Playbook vs Rôle

| **Aspect** | **Playbook** | **Rôle** |
|------------|-------------|----------|
| **Portée** | Orchestration globale | Fonction spécifique |
| **Réutilisabilité** | ⚠️ Limitée (copier-coller) | ✅ Totale (import) |
| **Organisation** | ⚠️ Fichier unique (peut devenir gros) | ✅ Structure en répertoires |
| **Variables** | Dans le playbook | `defaults/`, `vars/` |
| **Templates** | `templates/` à côté du playbook | `roles/myrole/templates/` |
| **Partage** | ⚠️ Difficile | ✅ Ansible Galaxy |
| **Tests** | ⚠️ Tester tout le playbook | ✅ Tester un rôle isolé |

### Hiérarchie de Priorité des Variables

**De la PLUS BASSE à la PLUS HAUTE priorité :**

1. `role defaults` (`roles/myrole/defaults/main.yml`)
2. `inventory file` (`inventory.ini`)
3. `inventory group_vars` (`group_vars/web.yml`)
4. `inventory host_vars` (`host_vars/web1.yml`)
5. `playbook group_vars` (`group_vars/web.yml` dans le playbook)
6. `playbook host_vars` (`host_vars/web1.yml` dans le playbook)
7. `host facts` (variables Ansible automatiques)
8. `play vars`
9. `role vars` (`roles/myrole/vars/main.yml`)
10. `block vars`
11. `task vars`
12. `extra vars` (`-e "var=value"` en ligne de commande) ← **PRIORITÉ MAX**

**Exemple :**

```yaml
# defaults/main.yml
nginx_port: 80

# group_vars/web.yml
nginx_port: 8080    # Surcharge defaults

# Ligne de commande
ansible-playbook site.yml -e "nginx_port=9000"  # Surcharge tout
```

**Résultat :** `nginx_port = 9000`

### Prochaines Étapes

**Module 4 (à venir) : Sécurité & Secrets**

- Ansible Vault (chiffrement des variables sensibles)
- Gestion des credentials (SSH, API keys, passwords)
- Intégration HashiCorp Vault
- Best practices sécurité

**Module 5 (à venir) : Testing & CI/CD**

- Molecule (tests automatisés de rôles)
- Ansible Lint (validation syntaxe et best practices)
- Intégration GitLab CI / GitHub Actions
- Pipeline complet : Lint → Test → Deploy

### Ressources Complémentaires

**Documentation officielle :**

- [Ansible Roles](https://docs.ansible.com/ansible/latest/user_guide/playbooks_reuse_roles.html)
- [Jinja2 Templates](https://docs.ansible.com/ansible/latest/user_guide/playbooks_templating.html)
- [Ansible Galaxy](https://galaxy.ansible.com/)
- [Best Practices](https://docs.ansible.com/ansible/latest/user_guide/playbooks_best_practices.html)

**Rôles Galaxy recommandés :**

- `geerlingguy.nginx` : Nginx complet et bien documenté
- `geerlingguy.postgresql` : PostgreSQL avec réplication
- `geerlingguy.docker` : Installation Docker
- `geerlingguy.security` : Hardening Linux de base

**Bonnes pratiques :**

- Toujours documenter vos rôles (README.md avec exemples)
- Utiliser `ansible-galaxy init` pour structure cohérente
- Tester vos rôles sur Molecule avant publication
- Versionner vos rôles dans Git (tags sémantiques)
- Publier vos rôles réutilisables sur Galaxy

---

**Félicitations ! Vous maîtrisez l'industrialisation Ansible avec les rôles et templates, et pouvez gérer des infrastructures à grande échelle avec du code réutilisable et maintenable.** 🎉

**Prochaine étape : Module 4 - Sécurité & Secrets pour protéger vos credentials et configurations sensibles !**

---

## Navigation

| | |
|:---|---:|
| [← Module 2 : Playbooks - L'Art de l'Aut...](02-module.md) | [Module 4 : Sécurité & Secrets - Ansib... →](04-module.md) |

[Retour au Programme](index.md){ .md-button }
