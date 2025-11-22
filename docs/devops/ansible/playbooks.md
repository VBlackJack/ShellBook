---
tags:
  - yaml
  - automation
  - modules
---

# Maîtriser les Playbooks

Des commandes ad-hoc à l'automatisation répétable.

---

## Anatomie d'un Playbook

Un playbook est un fichier YAML décrivant l'état souhaité de vos systèmes.

```yaml
---
# playbook.yml

- name: Configure webservers        # Nom du play (descriptif)
  hosts: webservers                 # Groupe cible depuis l'inventory
  become: yes                       # Utiliser sudo
  gather_facts: yes                 # Collecter les infos système

  vars:                             # Variables pour ce play
    app_port: 8080
    app_user: www-data

  tasks:                            # Liste d'actions
    - name: Install nginx           # Nom de la task (affiché dans la sortie)
      apt:                          # Module à utiliser
        name: nginx                 # Arguments du module
        state: present
        update_cache: yes

    - name: Start nginx service
      service:
        name: nginx
        state: started
        enabled: yes

  handlers:                         # Déclenché par notify
    - name: Restart nginx
      service:
        name: nginx
        state: restarted
```

### Éléments Clés

| Élément | Objectif |
|---------|---------|
| `name` | Description lisible par l'humain |
| `hosts` | Serveurs cibles (depuis l'inventory) |
| `become` | Élever les privilèges (sudo) |
| `gather_facts` | Collecter les infos système (vars ansible_*) |
| `vars` | Définir les variables |
| `tasks` | Liste d'actions à effectuer |
| `handlers` | Actions déclenchées par les changements |

### Exécuter un Playbook

```bash
# Exécution basique
ansible-playbook playbook.yml -i inventory/hosts

# Dry run (mode check)
ansible-playbook playbook.yml --check --diff

# Limiter à des hôtes spécifiques
ansible-playbook playbook.yml --limit web1.example.com

# Avec des variables supplémentaires
ansible-playbook playbook.yml -e "app_port=9000"

# Sortie verbeuse
ansible-playbook playbook.yml -v    # ou -vv, -vvv
```

---

## Aide-Mémoire des Modules Essentiels

=== "Système"

    ### service (Gérer les services)

    ```yaml
    - name: Start and enable nginx
      service:
        name: nginx
        state: started      # started, stopped, restarted, reloaded
        enabled: yes        # Démarrer au boot

    - name: Restart service
      service:
        name: nginx
        state: restarted
    ```

    ### systemd (Plus de contrôle)

    ```yaml
    - name: Reload systemd daemon
      systemd:
        daemon_reload: yes

    - name: Enable and start service
      systemd:
        name: myapp
        state: started
        enabled: yes
    ```

    ### user (Gérer les utilisateurs)

    ```yaml
    - name: Create deploy user
      user:
        name: deploy
        shell: /bin/bash
        groups: sudo,docker
        append: yes              # Ne pas retirer des autres groupes
        create_home: yes
        state: present

    - name: Add SSH key for user
      authorized_key:
        user: deploy
        key: "{{ lookup('file', '~/.ssh/id_ed25519.pub') }}"
    ```

    ### group (Gérer les groupes)

    ```yaml
    - name: Create app group
      group:
        name: appgroup
        gid: 1500
        state: present
    ```

=== "Fichiers"

    ### copy (Fichiers statiques)

    ```yaml
    - name: Copy config file
      copy:
        src: files/nginx.conf      # Source locale
        dest: /etc/nginx/nginx.conf
        owner: root
        group: root
        mode: '0644'
        backup: yes                # Garder une sauvegarde de l'original

    - name: Copy content directly
      copy:
        content: |
          server {
            listen 80;
            root /var/www/html;
          }
        dest: /etc/nginx/sites-available/default
    ```

    ### template (Fichiers dynamiques avec Jinja2)

    ```yaml
    - name: Deploy config from template
      template:
        src: templates/app.conf.j2
        dest: /etc/app/app.conf
        owner: root
        mode: '0640'
      notify: Restart app
    ```

    **Fichier template (app.conf.j2) :**
    ```jinja
    # Géré par Ansible
    server_name={{ ansible_hostname }}
    listen_port={{ app_port | default(8080) }}
    workers={{ ansible_processor_vcpus * 2 }}
    environment={{ env }}
    ```

    ### file (Permissions, répertoires, liens symboliques)

    ```yaml
    - name: Create directory
      file:
        path: /var/www/myapp
        state: directory
        owner: www-data
        group: www-data
        mode: '0755'

    - name: Create symlink
      file:
        src: /etc/nginx/sites-available/myapp
        dest: /etc/nginx/sites-enabled/myapp
        state: link

    - name: Set file permissions
      file:
        path: /etc/ssl/private/key.pem
        mode: '0600'
        owner: root

    - name: Delete file
      file:
        path: /tmp/junk
        state: absent
    ```

    ### lineinfile (Éditer une seule ligne)

    ```yaml
    - name: Ensure line in file
      lineinfile:
        path: /etc/ssh/sshd_config
        regexp: '^PermitRootLogin'
        line: 'PermitRootLogin no'
        backup: yes
      notify: Restart SSH
    ```

=== "Paquets"

    ### apt (Debian/Ubuntu)

    ```yaml
    - name: Update cache and install packages
      apt:
        name:
          - nginx
          - python3
          - git
        state: present
        update_cache: yes
        cache_valid_time: 3600    # Ne pas mettre à jour si < 1h

    - name: Remove package
      apt:
        name: apache2
        state: absent
        purge: yes                # Supprimer aussi les fichiers de config

    - name: Upgrade all packages
      apt:
        upgrade: dist
        update_cache: yes
    ```

    ### yum/dnf (RHEL/CentOS)

    ```yaml
    - name: Install packages
      yum:
        name:
          - nginx
          - python3
        state: present

    - name: Install from URL
      yum:
        name: https://example.com/package.rpm
        state: present
    ```

    ### package (Générique - auto-détection)

    ```yaml
    - name: Install package (any distro)
      package:
        name: git
        state: present
    ```

---

## Handlers (La "Magie")

Les handlers s'exécutent **uniquement quand notifiés** par une task qui a fait des changements.

**Problème :** Vous ne voulez pas redémarrer Nginx à chaque exécution du playbook—uniquement quand la config change.

**Solution :** Les handlers !

```yaml
---
- name: Configure webserver
  hosts: webservers
  become: yes

  tasks:
    - name: Copy nginx config
      copy:
        src: nginx.conf
        dest: /etc/nginx/nginx.conf
      notify: Restart nginx          # Déclencher le handler si changé

    - name: Copy site config
      template:
        src: site.conf.j2
        dest: /etc/nginx/sites-available/mysite
      notify:                        # Peut notifier plusieurs handlers
        - Reload nginx
        - Clear cache

  handlers:
    - name: Restart nginx
      service:
        name: nginx
        state: restarted

    - name: Reload nginx
      service:
        name: nginx
        state: reloaded

    - name: Clear cache
      file:
        path: /var/cache/nginx
        state: absent
```

### Comportement des Handlers

| Scénario | Le handler s'exécute ? |
|----------|---------------|
| La task a changé quelque chose | ✅ Oui (à la fin du play) |
| La task n'a fait aucun changement | ❌ Non |
| Plusieurs tasks notifient le même handler | ✅ Une fois (dédupliqué) |
| Le playbook échoue avant la fin | ❌ Non (sauf `--force-handlers`) |

```bash
# Forcer les handlers même en cas d'échec
ansible-playbook playbook.yml --force-handlers
```

!!! tip "Les handlers s'exécutent à la fin"
    Les handlers sont mis en file d'attente et s'exécutent **à la fin du play**, pas immédiatement.

    Pour exécuter immédiatement, utilisez `meta: flush_handlers` :

    ```yaml
    - name: Copy config
      copy: ...
      notify: Restart app

    - name: Flush handlers now
      meta: flush_handlers

    - name: Check app is running
      uri:
        url: http://localhost:8080/health
    ```

---

## Exemple Concret

Playbook complet : Installer Nginx, déployer une page personnalisée, s'assurer qu'il tourne.

```yaml
---
# deploy_nginx.yml

- name: Deploy Nginx webserver
  hosts: webservers
  become: yes

  vars:
    site_title: "Welcome to ShellBook"
    nginx_port: 80

  tasks:
    # ============== Installation ==============
    - name: Install Nginx
      apt:
        name: nginx
        state: present
        update_cache: yes
      tags: install

    # ============== Configuration ==============
    - name: Create web root directory
      file:
        path: /var/www/mysite
        state: directory
        owner: www-data
        group: www-data
        mode: '0755'

    - name: Deploy index.html
      template:
        src: templates/index.html.j2
        dest: /var/www/mysite/index.html
        owner: www-data
        mode: '0644'
      tags: content

    - name: Deploy Nginx site config
      template:
        src: templates/nginx-site.conf.j2
        dest: /etc/nginx/sites-available/mysite
      notify: Reload nginx
      tags: config

    - name: Enable site
      file:
        src: /etc/nginx/sites-available/mysite
        dest: /etc/nginx/sites-enabled/mysite
        state: link
      notify: Reload nginx

    - name: Remove default site
      file:
        path: /etc/nginx/sites-enabled/default
        state: absent
      notify: Reload nginx

    # ============== Service ==============
    - name: Ensure Nginx is running
      service:
        name: nginx
        state: started
        enabled: yes
      tags: service

  handlers:
    - name: Reload nginx
      service:
        name: nginx
        state: reloaded
```

**templates/index.html.j2 :**

```html
<!DOCTYPE html>
<html>
<head>
    <title>{{ site_title }}</title>
</head>
<body>
    <h1>{{ site_title }}</h1>
    <p>Déployé par Ansible sur {{ ansible_hostname }}</p>
    <p>IP du serveur : {{ ansible_default_ipv4.address }}</p>
    <p>Date : {{ ansible_date_time.iso8601 }}</p>
</body>
</html>
```

**templates/nginx-site.conf.j2 :**

```nginx
server {
    listen {{ nginx_port }};
    server_name {{ ansible_fqdn }} {{ ansible_hostname }};

    root /var/www/mysite;
    index index.html;

    location / {
        try_files $uri $uri/ =404;
    }
}
```

### Exécution

```bash
# Déploiement complet
ansible-playbook deploy_nginx.yml

# Mettre à jour uniquement le contenu
ansible-playbook deploy_nginx.yml --tags content

# Mode check d'abord
ansible-playbook deploy_nginx.yml --check --diff
```

---

## Référence Rapide des Modules

| Tâche | Module | Arguments Clés |
|------|--------|---------------|
| Installer un paquet | `apt` / `yum` | `name`, `state` |
| Gérer un service | `service` | `name`, `state`, `enabled` |
| Copier un fichier | `copy` | `src`, `dest`, `mode` |
| Template | `template` | `src`, `dest` |
| Créer un répertoire | `file` | `path`, `state=directory` |
| Éditer une ligne | `lineinfile` | `path`, `regexp`, `line` |
| Exécuter une commande | `shell` / `command` | `cmd` |
| Télécharger un fichier | `get_url` | `url`, `dest` |
| Cloner avec Git | `git` | `repo`, `dest`, `version` |
| Gérer un utilisateur | `user` | `name`, `groups`, `state` |
