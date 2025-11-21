# Mastering Playbooks

`#yaml` `#automation` `#modules`

From ad-hoc commands to repeatable automation.

---

## Anatomy of a Playbook

A playbook is a YAML file describing the desired state of your systems.

```yaml
---
# playbook.yml

- name: Configure webservers        # Play name (descriptive)
  hosts: webservers                 # Target group from inventory
  become: yes                       # Use sudo
  gather_facts: yes                 # Collect system info

  vars:                             # Variables for this play
    app_port: 8080
    app_user: www-data

  tasks:                            # List of actions
    - name: Install nginx           # Task name (shows in output)
      apt:                          # Module to use
        name: nginx                 # Module arguments
        state: present
        update_cache: yes

    - name: Start nginx service
      service:
        name: nginx
        state: started
        enabled: yes

  handlers:                         # Triggered by notify
    - name: Restart nginx
      service:
        name: nginx
        state: restarted
```

### Key Elements

| Element | Purpose |
|---------|---------|
| `name` | Human-readable description |
| `hosts` | Target servers (from inventory) |
| `become` | Escalate privileges (sudo) |
| `gather_facts` | Collect system info (ansible_* vars) |
| `vars` | Define variables |
| `tasks` | List of actions to perform |
| `handlers` | Actions triggered by changes |

### Running a Playbook

```bash
# Basic run
ansible-playbook playbook.yml -i inventory/hosts

# Dry run (check mode)
ansible-playbook playbook.yml --check --diff

# Limit to specific hosts
ansible-playbook playbook.yml --limit web1.example.com

# With extra variables
ansible-playbook playbook.yml -e "app_port=9000"

# Verbose output
ansible-playbook playbook.yml -v    # or -vv, -vvv
```

---

## Essential Modules Cheatsheet

=== "System"

    ### service (Manage services)

    ```yaml
    - name: Start and enable nginx
      service:
        name: nginx
        state: started      # started, stopped, restarted, reloaded
        enabled: yes        # Start on boot

    - name: Restart service
      service:
        name: nginx
        state: restarted
    ```

    ### systemd (More control)

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

    ### user (Manage users)

    ```yaml
    - name: Create deploy user
      user:
        name: deploy
        shell: /bin/bash
        groups: sudo,docker
        append: yes              # Don't remove from other groups
        create_home: yes
        state: present

    - name: Add SSH key for user
      authorized_key:
        user: deploy
        key: "{{ lookup('file', '~/.ssh/id_ed25519.pub') }}"
    ```

    ### group (Manage groups)

    ```yaml
    - name: Create app group
      group:
        name: appgroup
        gid: 1500
        state: present
    ```

=== "Files"

    ### copy (Static files)

    ```yaml
    - name: Copy config file
      copy:
        src: files/nginx.conf      # Local source
        dest: /etc/nginx/nginx.conf
        owner: root
        group: root
        mode: '0644'
        backup: yes                # Keep backup of original

    - name: Copy content directly
      copy:
        content: |
          server {
            listen 80;
            root /var/www/html;
          }
        dest: /etc/nginx/sites-available/default
    ```

    ### template (Dynamic files with Jinja2)

    ```yaml
    - name: Deploy config from template
      template:
        src: templates/app.conf.j2
        dest: /etc/app/app.conf
        owner: root
        mode: '0640'
      notify: Restart app
    ```

    **Template file (app.conf.j2):**
    ```jinja
    # Managed by Ansible
    server_name={{ ansible_hostname }}
    listen_port={{ app_port | default(8080) }}
    workers={{ ansible_processor_vcpus * 2 }}
    environment={{ env }}
    ```

    ### file (Permissions, directories, symlinks)

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

    ### lineinfile (Edit single line)

    ```yaml
    - name: Ensure line in file
      lineinfile:
        path: /etc/ssh/sshd_config
        regexp: '^PermitRootLogin'
        line: 'PermitRootLogin no'
        backup: yes
      notify: Restart SSH
    ```

=== "Packages"

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
        cache_valid_time: 3600    # Don't update if < 1 hour old

    - name: Remove package
      apt:
        name: apache2
        state: absent
        purge: yes                # Remove config files too

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

    ### package (Generic - auto-detects)

    ```yaml
    - name: Install package (any distro)
      package:
        name: git
        state: present
    ```

---

## Handlers (The "Magic")

Handlers run **only when notified** by a task that made changes.

**Problem:** You don't want to restart Nginx on every playbook run—only when config changes.

**Solution:** Handlers!

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
      notify: Restart nginx          # Trigger handler if changed

    - name: Copy site config
      template:
        src: site.conf.j2
        dest: /etc/nginx/sites-available/mysite
      notify:                        # Can notify multiple handlers
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

### Handler Behavior

| Scenario | Handler Runs? |
|----------|---------------|
| Task changed something | ✅ Yes (at end of play) |
| Task made no changes | ❌ No |
| Multiple tasks notify same handler | ✅ Once (deduplicated) |
| Playbook fails before end | ❌ No (unless `--force-handlers`) |

```bash
# Force handlers even on failure
ansible-playbook playbook.yml --force-handlers
```

!!! tip "Handlers Run at End"
    Handlers are queued and run **at the end of the play**, not immediately.

    To run immediately, use `meta: flush_handlers`:

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

## Real-World Example

Complete playbook: Install Nginx, deploy custom page, ensure running.

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
    # ============== Install ==============
    - name: Install Nginx
      apt:
        name: nginx
        state: present
        update_cache: yes
      tags: install

    # ============== Configure ==============
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

**templates/index.html.j2:**

```html
<!DOCTYPE html>
<html>
<head>
    <title>{{ site_title }}</title>
</head>
<body>
    <h1>{{ site_title }}</h1>
    <p>Deployed by Ansible on {{ ansible_hostname }}</p>
    <p>Server IP: {{ ansible_default_ipv4.address }}</p>
    <p>Date: {{ ansible_date_time.iso8601 }}</p>
</body>
</html>
```

**templates/nginx-site.conf.j2:**

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

### Run It

```bash
# Full deployment
ansible-playbook deploy_nginx.yml

# Only update content
ansible-playbook deploy_nginx.yml --tags content

# Check mode first
ansible-playbook deploy_nginx.yml --check --diff
```

---

## Module Quick Reference

| Task | Module | Key Arguments |
|------|--------|---------------|
| Install package | `apt` / `yum` | `name`, `state` |
| Manage service | `service` | `name`, `state`, `enabled` |
| Copy file | `copy` | `src`, `dest`, `mode` |
| Template | `template` | `src`, `dest` |
| Create dir | `file` | `path`, `state=directory` |
| Edit line | `lineinfile` | `path`, `regexp`, `line` |
| Run command | `shell` / `command` | `cmd` |
| Download file | `get_url` | `url`, `dest` |
| Git clone | `git` | `repo`, `dest`, `version` |
| Manage user | `user` | `name`, `groups`, `state` |
