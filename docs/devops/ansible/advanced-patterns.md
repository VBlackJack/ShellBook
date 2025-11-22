# Ansible Advanced Patterns & Optimization

`#ansible` `#performance` `#logic` `#strategies` `#jinja2`

Passer de l'exécution de tâches simples à l'orchestration intelligente et optimisée.

---

## Maîtriser la Logique (Control Flow)

### `register` : Capturer et Réutiliser

**Concept :** Enregistrer le résultat d'une tâche pour l'utiliser dans les conditions suivantes.

```yaml
---
- name: Conditional execution based on file existence
  hosts: webservers
  tasks:
    # Étape 1 : Vérifier si un fichier existe
    - name: Check if maintenance mode is enabled
      ansible.builtin.stat:
        path: /var/www/html/.maintenance
      register: maintenance_file

    # Étape 2 : Afficher le résultat (debug)
    - name: Show stat result
      ansible.builtin.debug:
        var: maintenance_file

    # Étape 3 : Agir selon l'existence du fichier
    - name: Skip deployment if maintenance mode
      ansible.builtin.fail:
        msg: "Maintenance mode is active. Aborting deployment."
      when: maintenance_file.stat.exists

    - name: Deploy application
      ansible.builtin.copy:
        src: app.tar.gz
        dest: /var/www/html/
      when: not maintenance_file.stat.exists
```

**Variables utiles dans `register` :**

| Module | Variable clé | Description |
|--------|--------------|-------------|
| `stat` | `.stat.exists` | Fichier existe ? |
| `command` / `shell` | `.stdout` | Sortie standard |
| `command` / `shell` | `.rc` | Code retour (0 = succès) |
| `service` | `.changed` | État modifié ? |
| `apt` / `yum` | `.changed` | Paquet installé/mis à jour ? |

### `set_fact` : Variables Dynamiques

**Concept :** Créer des variables calculées à la volée (pendant l'exécution).

```yaml
---
- name: Dynamic variable creation
  hosts: all
  vars:
    environment: production
  tasks:
    # Créer une variable selon l'environnement
    - name: Set database host based on environment
      ansible.builtin.set_fact:
        db_host: "{{ 'db-prod.example.com' if environment == 'production' else 'db-dev.example.com' }}"

    - name: Display computed variable
      ansible.builtin.debug:
        msg: "Database host: {{ db_host }}"

    # Construire une URL complexe
    - name: Build monitoring URL
      ansible.builtin.set_fact:
        monitoring_url: "https://{{ inventory_hostname }}.monitoring.local:{{ monitoring_port | default(9090) }}/metrics"

    - name: Use the computed URL
      ansible.builtin.uri:
        url: "{{ monitoring_url }}"
        method: GET
      register: metrics_check
```

**Cas d'Usage :**
- Calculer des valeurs basées sur l'inventory ou les facts
- Construire des chaînes complexes (URLs, chemins)
- Simplifier les templates Jinja2 lourds

### Block / Rescue / Always : Gestion des Erreurs

**Concept :** Try/Catch/Finally version Ansible. Indispensable pour la robustesse en production.

```yaml
---
- name: Error handling with block/rescue/always
  hosts: webservers
  tasks:
    - name: Deploy application with rollback capability
      block:
        # === TENTATIVE (Try) ===
        - name: Stop application
          ansible.builtin.systemd:
            name: myapp
            state: stopped

        - name: Backup current version
          ansible.builtin.copy:
            src: /opt/app/
            dest: /opt/app.backup/
            remote_src: yes

        - name: Deploy new version
          ansible.builtin.unarchive:
            src: myapp-v2.0.tar.gz
            dest: /opt/app/

        - name: Start application
          ansible.builtin.systemd:
            name: myapp
            state: started

        # Simuler une vérification qui échoue
        - name: Health check
          ansible.builtin.uri:
            url: http://localhost:8080/health
            status_code: 200
          register: health_check

      rescue:
        # === EN CAS D'ERREUR (Catch) ===
        - name: Rollback notification
          ansible.builtin.debug:
            msg: "Deployment failed. Rolling back to previous version."

        - name: Restore backup
          ansible.builtin.copy:
            src: /opt/app.backup/
            dest: /opt/app/
            remote_src: yes

        - name: Restart application with old version
          ansible.builtin.systemd:
            name: myapp
            state: restarted

        - name: Send alert to Slack
          ansible.builtin.uri:
            url: https://hooks.slack.com/services/YOUR/WEBHOOK/URL
            method: POST
            body_format: json
            body:
              text: "⚠️ Deployment failed on {{ inventory_hostname }}. Rollback performed."

      always:
        # === TOUJOURS EXÉCUTÉ (Finally) ===
        - name: Clean up temporary files
          ansible.builtin.file:
            path: /tmp/deploy-*
            state: absent

        - name: Log deployment attempt
          ansible.builtin.lineinfile:
            path: /var/log/deployments.log
            line: "{{ ansible_date_time.iso8601 }} - Deployment attempt on {{ inventory_hostname }}"
            create: yes
```

!!! tip "Astuce : Idempotence dans Rescue"
    Les tâches dans `rescue` doivent être idempotentes. Si le rollback échoue, vous voulez pouvoir le rejouer.

!!! danger "Attention : Rescue ne capture pas les erreurs de connexion"
    Si Ansible ne peut pas se connecter au host, le block/rescue ne s'exécute pas.

---

## Modules de "Survie" en Production

### `synchronize` : Performance avec rsync

**Pourquoi `synchronize` > `copy` ?**

| Module | Méthode | Performance | Cas d'Usage |
|--------|---------|-------------|----------|
| `copy` | Transfère tout via SSH | ❌ Lent pour gros fichiers | Fichiers uniques |
| `synchronize` | Utilise rsync (delta) | ✅ Rapide (delta uniquement) | Dossiers, gros volumes |

```yaml
---
- name: Efficient file synchronization
  hosts: webservers
  tasks:
    # MAUVAIS : copy d'un gros dossier
    # - name: Deploy website (slow)
    #   ansible.builtin.copy:
    #     src: /var/www/site/
    #     dest: /var/www/html/

    # BON : synchronize avec rsync
    - name: Deploy website (fast)
      ansible.posix.synchronize:
        src: /var/www/site/
        dest: /var/www/html/
        delete: yes              # Supprimer fichiers non présents dans src
        recursive: yes
        rsync_opts:
          - "--exclude=.git"     # Exclure .git
          - "--exclude=*.log"    # Exclure logs
          - "--chmod=D755,F644"  # Permissions

    # Synchroniser depuis le contrôleur vers les hosts
    - name: Push config files from controller
      ansible.posix.synchronize:
        src: /local/config/
        dest: /etc/myapp/
        mode: push

    # Synchroniser depuis un host vers le contrôleur
    - name: Pull logs from servers
      ansible.posix.synchronize:
        src: /var/log/myapp/
        dest: /backup/logs/{{ inventory_hostname }}/
        mode: pull
```

!!! tip "Installation requise"
    `synchronize` nécessite `rsync` installé sur le contrôleur ET les hosts cibles.
    ```yaml
    - name: Ensure rsync is installed
      ansible.builtin.package:
        name: rsync
        state: present
    ```

### `reboot` & `wait_for` : Mise à Jour Sécurisée

**Pattern classique :** Patch système → Reboot → Attendre SSH.

```yaml
---
- name: System update with reboot
  hosts: all
  serial: 1  # Un serveur à la fois !
  tasks:
    # Étape 1 : Mise à jour
    - name: Update all packages
      ansible.builtin.apt:
        upgrade: dist
        update_cache: yes
        cache_valid_time: 3600
      when: ansible_os_family == "Debian"

    # Étape 2 : Reboot si nécessaire
    - name: Check if reboot is required
      ansible.builtin.stat:
        path: /var/run/reboot-required
      register: reboot_required_file

    - name: Reboot the server
      ansible.builtin.reboot:
        msg: "Reboot initiated by Ansible"
        pre_reboot_delay: 5       # Attendre 5s avant reboot
        post_reboot_delay: 30     # Attendre 30s après reboot
        reboot_timeout: 600       # Timeout 10 minutes
      when: reboot_required_file.stat.exists

    # Étape 3 : Attendre que SSH revienne
    - name: Wait for SSH to be available
      ansible.builtin.wait_for:
        host: "{{ inventory_hostname }}"
        port: 22
        delay: 10               # Attendre 10s avant de tester
        timeout: 300            # Timeout 5 minutes
        state: started
      delegate_to: localhost

    # Étape 4 : Vérifier les services
    - name: Ensure critical services are running
      ansible.builtin.systemd:
        name: "{{ item }}"
        state: started
      loop:
        - nginx
        - mysql
        - redis
```

!!! danger "JAMAIS sans `serial` !"
    Rebooter tous les serveurs en parallèle = **DOWNTIME COMPLET**.
    Toujours utiliser `serial: 1` ou `serial: "25%"`.

### `assemble` : Configuration Modulaire

**Concept :** Construire un fichier à partir de fragments (pattern `conf.d/`).

```yaml
---
- name: Build modular configuration
  hosts: webservers
  tasks:
    # Scénario : Construire /etc/ssh/sshd_config depuis des fragments

    # Étape 1 : Créer le dossier de fragments
    - name: Create config fragments directory
      ansible.builtin.file:
        path: /etc/ssh/sshd_config.d
        state: directory
        mode: '0755'

    # Étape 2 : Déposer les fragments
    - name: Deploy base SSH config fragment
      ansible.builtin.copy:
        dest: /etc/ssh/sshd_config.d/00-base.conf
        content: |
          Port 22
          PermitRootLogin no
          PasswordAuthentication no

    - name: Deploy security fragment
      ansible.builtin.copy:
        dest: /etc/ssh/sshd_config.d/10-security.conf
        content: |
          MaxAuthTries 3
          MaxSessions 10
          ClientAliveInterval 300

    - name: Deploy allowed users fragment
      ansible.builtin.copy:
        dest: /etc/ssh/sshd_config.d/20-users.conf
        content: |
          AllowUsers deploy sysadmin

    # Étape 3 : Assembler le fichier final
    - name: Assemble final sshd_config
      ansible.builtin.assemble:
        src: /etc/ssh/sshd_config.d
        dest: /etc/ssh/sshd_config
        owner: root
        group: root
        mode: '0600'
        backup: yes              # Backup avant écrasement
        regexp: '\.conf$'        # Seulement les .conf
      notify: restart ssh

  handlers:
    - name: restart ssh
      ansible.builtin.systemd:
        name: sshd
        state: restarted
```

**Avantages :**
- Configuration modulaire (ajout/suppression de fragments)
- Gestion par rôles (chaque rôle dépose son fragment)
- Idempotence garantie

### `delegate_to` : Exécution Déportée

**Concept :** Exécuter une tâche sur un autre host (ou le contrôleur).

```yaml
---
- name: Blue-Green deployment with load balancer
  hosts: webservers
  serial: 1
  tasks:
    # Étape 1 : Sortir du load balancer (via API)
    - name: Remove server from load balancer
      ansible.builtin.uri:
        url: "https://lb.example.com/api/pool/remove"
        method: POST
        body_format: json
        body:
          server: "{{ inventory_hostname }}"
      delegate_to: localhost      # Exécuter depuis le contrôleur
      register: lb_removal

    # Étape 2 : Attendre que les connexions se terminent
    - name: Wait for active connections to drain
      ansible.builtin.wait_for:
        timeout: 30

    # Étape 3 : Déployer l'application
    - name: Deploy new version
      ansible.builtin.copy:
        src: app-v2.tar.gz
        dest: /opt/app/

    - name: Restart application
      ansible.builtin.systemd:
        name: myapp
        state: restarted

    # Étape 4 : Health check
    - name: Verify application health
      ansible.builtin.uri:
        url: "http://{{ inventory_hostname }}:8080/health"
        status_code: 200
      retries: 5
      delay: 10

    # Étape 5 : Remettre dans le load balancer
    - name: Add server back to load balancer
      ansible.builtin.uri:
        url: "https://lb.example.com/api/pool/add"
        method: POST
        body_format: json
        body:
          server: "{{ inventory_hostname }}"
      delegate_to: localhost

    # Étape 6 : Notifier Slack (depuis le contrôleur)
    - name: Send deployment notification
      ansible.builtin.uri:
        url: "{{ slack_webhook_url }}"
        method: POST
        body_format: json
        body:
          text: "✅ {{ inventory_hostname }} deployed successfully"
      delegate_to: localhost
      run_once: true            # Notification unique pour tout le batch
```

**Autres usages de `delegate_to` :**

```yaml
# Exécuter une commande sur un host de bastion
- name: Run command via bastion
  ansible.builtin.command: whoami
  delegate_to: bastion.example.com

# Mettre à jour un DNS (depuis le contrôleur)
- name: Update DNS record
  community.general.cloudflare_dns:
    zone: example.com
    record: "{{ inventory_hostname }}"
    type: A
    value: "{{ ansible_default_ipv4.address }}"
  delegate_to: localhost
```

---

## Stratégies de Déploiement (Rolling Updates)

### `serial` : Déploiements par Lots

**Concept :** Mettre à jour les serveurs par batch pour éviter le downtime.

```yaml
---
# EXEMPLE 1 : Un serveur à la fois
- name: Zero-downtime deployment (sequential)
  hosts: webservers
  serial: 1                    # Un par un
  tasks:
    - name: Deploy application
      ansible.builtin.copy:
        src: app.tar.gz
        dest: /opt/app/
```

```yaml
---
# EXEMPLE 2 : Par pourcentage
- name: Rolling update by percentage
  hosts: webservers
  serial: "25%"                # 25% des hosts à la fois
  tasks:
    - name: Update application
      ansible.builtin.apt:
        name: myapp
        state: latest
      notify: restart myapp

  handlers:
    - name: restart myapp
      ansible.builtin.systemd:
        name: myapp
        state: restarted
```

```yaml
---
# EXEMPLE 3 : Progression dynamique
- name: Canary deployment
  hosts: webservers
  serial:
    - 1         # Premier host (canary)
    - 25%       # Ensuite 25%
    - 50%       # Puis 50%
    - 100%      # Enfin tous les restants
  tasks:
    - name: Deploy canary version
      ansible.builtin.copy:
        src: app-canary.tar.gz
        dest: /opt/app/

    - name: Health check
      ansible.builtin.uri:
        url: "http://{{ inventory_hostname }}:8080/health"
        status_code: 200
      retries: 3
      delay: 5

    # Pause après le canary pour vérifier les métriques
    - name: Pause for monitoring
      ansible.builtin.pause:
        prompt: "Check metrics. Continue? (yes/no)"
      when: ansible_play_batch[0] == inventory_hostname  # Seulement sur le premier host
```

!!! tip "Stratégies Recommandées"
    - **Canary** : `serial: [1, "25%", "100%"]`
    - **Blue-Green** : `serial: "50%"` (moitié puis moitié)
    - **Production critique** : `serial: 1` (séquentiel strict)

### `run_once` : Tâches Uniques

**Concept :** Exécuter une tâche une seule fois, peu importe le nombre de hosts.

```yaml
---
- name: Database migration pattern
  hosts: webservers
  tasks:
    # Étape 1 : Déployer le code sur tous les serveurs
    - name: Deploy application code
      ansible.builtin.copy:
        src: app.tar.gz
        dest: /opt/app/

    # Étape 2 : Migration DB (UNE SEULE FOIS !)
    - name: Run database migration
      ansible.builtin.command:
        cmd: /opt/app/bin/migrate.sh
      run_once: true            # Exécuté sur le premier host uniquement
      delegate_to: "{{ groups['webservers'][0] }}"

    # Étape 3 : Purger le cache (UNE FOIS)
    - name: Clear application cache
      ansible.builtin.uri:
        url: https://api.example.com/cache/clear
        method: POST
      run_once: true
      delegate_to: localhost

    # Étape 4 : Redémarrer tous les serveurs
    - name: Restart application
      ansible.builtin.systemd:
        name: myapp
        state: restarted
```

**Différence `run_once` vs `delegate_to` :**

| Directive | Comportement |
|-----------|--------------|
| `run_once: true` | Exécute sur le **premier host** de la liste |
| `delegate_to: localhost` | Exécute sur le **contrôleur Ansible** |
| `run_once + delegate_to` | Combine les deux (souvent utilisé ensemble) |

```yaml
# Pattern commun : Notification unique
- name: Send deployment summary
  ansible.builtin.mail:
    to: ops@example.com
    subject: "Deployment completed"
    body: "Deployed to {{ ansible_play_hosts | length }} servers"
  run_once: true
  delegate_to: localhost
```

---

## Performance Tuning

### Optimiser `ansible.cfg`

**Fichier :** `ansible.cfg` (racine du projet ou `~/.ansible.cfg`)

```ini
[defaults]
# === PERFORMANCE ===

# Pipelining : Réduit les connexions SSH (GROS GAIN)
pipelining = True
# Attention : Nécessite "requiretty" désactivé dans /etc/sudoers

# Parallélisme : Nombre de hosts traités simultanément
forks = 20
# Par défaut : 5. Augmenter si vous avez beaucoup de hosts.

# Gather Facts : Désactiver par défaut (activer manuellement si besoin)
gathering = explicit
# Par défaut : implicit (toujours activé). Économise 2-3 secondes par host.

# SSH Multiplexing : Réutiliser les connexions SSH
[ssh_connection]
ssh_args = -o ControlMaster=auto -o ControlPersist=60s
control_path = ~/.ansible/cp/%%h-%%r

# === SÉCURITÉ ===
host_key_checking = False
# Attention : Désactiver seulement en environnement de confiance !

# === LOGS ===
log_path = /var/log/ansible.log
```

### `gather_facts: false` : Quand l'Utiliser ?

**Facts = informations système** (OS, IP, CPU...). Collectés automatiquement, mais **prennent 2-3 secondes par host**.

```yaml
---
# EXEMPLE 1 : Désactiver globalement
- name: Quick file deployment (no facts needed)
  hosts: all
  gather_facts: false         # Gain de temps
  tasks:
    - name: Copy file
      ansible.builtin.copy:
        src: config.yml
        dest: /etc/app/

# EXEMPLE 2 : Activer seulement si nécessaire
- name: Conditional OS tasks
  hosts: all
  gather_facts: true          # Nécessaire pour ansible_os_family
  tasks:
    - name: Install package on Debian
      ansible.builtin.apt:
        name: nginx
      when: ansible_os_family == "Debian"

# EXEMPLE 3 : Collecter manuellement (subset)
- name: Gather only network facts
  hosts: all
  gather_facts: false
  tasks:
    - name: Collect minimal facts
      ansible.builtin.setup:
        gather_subset:
          - '!all'              # Désactiver tout
          - 'network'           # Activer seulement network
      when: need_ip_address
```

**Quand désactiver les facts ?**
- ✅ Tâches simples (copy, template sans variables)
- ✅ Playbooks de déploiement rapide
- ✅ Tests/CI (gain de temps)

**Quand les garder ?**
- ❌ Utilisation de `ansible_*` variables
- ❌ Conditions `when:` basées sur l'OS
- ❌ Templates avec `{{ ansible_hostname }}`

### Comparaison : Avant/Après Optimisation

| Configuration | Temps d'Exécution (100 hosts) |
|---------------|-------------------------------|
| Défaut (forks=5, facts=on, no pipelining) | **5 minutes** |
| Optimisé (forks=20, facts=off, pipelining) | **45 secondes** |

```yaml
# PLAYBOOK DE BENCHMARK
---
- name: Performance test
  hosts: all
  gather_facts: false
  tasks:
    - name: Ping all hosts
      ansible.builtin.ping:

    - name: Display execution time
      ansible.builtin.debug:
        msg: "Execution time: {{ ansible_date_time.epoch }}"
```

```bash
# Test avant optimisation
time ansible-playbook benchmark.yml

# Test après optimisation (ansible.cfg configuré)
time ansible-playbook benchmark.yml
```

---

## Référence Rapide

### Modules Avancés

| Module | Utilisation | Exemple |
|--------|-------|---------|
| `register` | Capturer sortie | `register: result` |
| `set_fact` | Créer variable | `set_fact: db_host="..."` |
| `block/rescue/always` | Gestion erreurs | `block: [...] rescue: [...]` |
| `synchronize` | Rsync rapide | `synchronize: src=/src dest=/dst` |
| `reboot` | Reboot sécurisé | `reboot: timeout=600` |
| `wait_for` | Attendre port/fichier | `wait_for: port=22` |
| `assemble` | Fichier modulaire | `assemble: src=/conf.d dest=/conf` |
| `delegate_to` | Exécution déportée | `delegate_to: localhost` |

### Directives de Stratégie

| Directive | Effet | Exemple |
|-----------|-------|---------|
| `serial` | Déploiement par batch | `serial: "25%"` |
| `run_once` | Exécution unique | `run_once: true` |
| `gather_facts` | Collecter facts | `gather_facts: false` |
| `forks` | Parallélisme (ansible.cfg) | `forks = 20` |
| `pipelining` | SSH optimization (ansible.cfg) | `pipelining = True` |

### Patterns Courants

```yaml
# Reboot sécurisé
- name: Safe reboot
  ansible.builtin.reboot:
  serial: 1

# Migration DB unique
- name: DB migration
  command: migrate.sh
  run_once: true

# Rollback avec block/rescue
- block:
    - name: Deploy
      copy: ...
  rescue:
    - name: Rollback
      copy: ...

# Déploiement canary
serial: [1, "25%", "100%"]
```

---

## Ressources Complémentaires

- **Ansible Docs - Strategies** : https://docs.ansible.com/ansible/latest/plugins/strategy.html
- **Best Practices** : https://docs.ansible.com/ansible/latest/user_guide/playbooks_best_practices.html
- **Jinja2 Templating** : https://jinja.palletsprojects.com/
- **Formation Xavki (FR)** : https://www.youtube.com/@xavki

---

!!! example "Parcours Recommandé"
    **Vous avez terminé ce guide ?**

    → Pratiquez avec des playbooks réels (déploiement multi-tier)

    → Explorez les **Collections Ansible** (community.general, ansible.posix)

    → Approfondissez **Ansible Tower / AWX** pour l'orchestration d'équipe
