---
tags:
  - formation
  - ansible
  - automation
  - iac
  - devops
---

# Ansible : De Zéro à l'Indus - Introduction & Programme

![Ansible Execution Flow](../../assets/infographics/devops/ansible-execution-flow.jpeg)

## Objectifs de cette Formation

À l'issue de ce parcours, vous serez capable de :

- 🏗️ **Comprendre l'architecture Ansible** : Control node, managed nodes, inventaire, SSH
- 📜 **Écrire des playbooks** : Tasks, handlers, variables, facts, templates Jinja2
- 🎭 **Créer des roles** : Structurer le code, réutilisabilité, Ansible Galaxy
- 🔐 **Sécuriser les secrets** : Ansible Vault, variables sensibles, rotation des clés
- 🧪 **Tester et industrialiser** : Molecule, linting (ansible-lint), CI/CD GitLab

## Public Cible

Cette formation s'adresse aux **professionnels de l'automatisation IT** :

- Administrateurs systèmes cherchant à automatiser les tâches répétitives
- DevOps Engineers implémentant l'Infrastructure as Code (IaC)
- SRE (Site Reliability Engineers) gérant des flottes de serveurs
- Consultants techniques déployant des stacks applicatives

**Niveau requis :** Intermédiaire (Linux, SSH, YAML)

## Prérequis

!!! info "Connaissances Nécessaires"
    Avant de commencer, assurez-vous de maîtriser :

    - ✅ **Linux Administration** : Utilisateurs, services, permissions, systemd
    - ✅ **SSH** : Authentification par clés, configuration `~/.ssh/config`
    - ✅ **YAML** : Syntaxe de base (listes, dictionnaires, indentation)
    - ✅ **Git** : Clone, commit, branches (pour versionner les playbooks)

    **Ressources :**

    - [Guide Ansible Fundamentals ShellBook](../../devops/ansible/fundamentals.md)
    - [Guide Playbooks ShellBook](../../devops/ansible/playbooks.md)
    - [Guide Industrialization ShellBook](../../devops/ansible/industrialization.md)

## Programme

### Module 1 : Architecture Ansible (1h)

**Objectif :** Comprendre le modèle agentless et l'architecture push d'Ansible.

**Contenu :**

- **Ansible vs Puppet/Chef/SaltStack** : Agentless, push vs pull
- **Composants :**
  - Control Node : Machine où Ansible est installé
  - Managed Nodes : Serveurs cibles (Linux, Windows)
  - Inventaire : Fichier INI/YAML listant les hôtes
  - Modules : Unités de code exécutées sur les cibles (`yum`, `service`, `copy`)
- **Workflow d'exécution :**
  1. Control Node se connecte en SSH aux managed nodes
  2. Transfère les modules Python
  3. Exécute et retourne le résultat JSON
  4. Supprime les fichiers temporaires
- **Installation :**
  - Control Node : `pip install ansible` ou `dnf install ansible-core`
  - Managed Nodes : Aucune installation requise (SSH + Python)
- **Diagramme Mermaid :** Architecture Control Node → Managed Nodes

[:octicons-arrow-right-24: Commencer le Module 1](01-module.md){ .md-button .md-button--primary }

### Module 2 : Playbooks - De la Task au Rôle (2h)

**Objectif :** Écrire des playbooks Ansible pour automatiser l'installation et la configuration.

**Contenu :**

**Syntaxe de base :**

```yaml
- name: Installer et configurer Nginx
  hosts: webservers
  become: yes
  tasks:
    - name: Installer Nginx
      yum:
        name: nginx
        state: present

    - name: Démarrer Nginx
      service:
        name: nginx
        state: started
        enabled: yes
```

**Concepts avancés :**

- **Variables :** `vars:`, `vars_files:`, `group_vars/`, `host_vars/`
- **Facts :** Variables automatiques (`ansible_os_family`, `ansible_default_ipv4`)
- **Templates Jinja2 :** Générer des fichiers de configuration dynamiques
- **Handlers :** Redémarrer un service uniquement si la config change
- **Loops :** `loop:`, `with_items:`
- **Conditionnels :** `when: ansible_os_family == "RedHat"`

**Exemple complet :** Déployer une stack LAMP (Linux, Apache, MySQL, PHP)

[:octicons-arrow-right-24: Commencer le Module 2](02-module.md){ .md-button .md-button--primary }

### Module 3 : Roles - Structurer et Réutiliser (2h)

**Objectif :** Organiser le code Ansible en roles réutilisables.

**Contenu :**

**Structure d'un role :**

```text
roles/nginx/
├── tasks/
│   └── main.yml          # Tasks principales
├── handlers/
│   └── main.yml          # Handlers (restart nginx)
├── templates/
│   └── nginx.conf.j2     # Template Jinja2
├── files/
│   └── index.html        # Fichiers statiques
├── vars/
│   └── main.yml          # Variables du role
├── defaults/
│   └── main.yml          # Variables par défaut (surchargeable)
└── meta/
    └── main.yml          # Métadonnées (dépendances)
```

**Utiliser un role dans un playbook :**

```yaml
- name: Configurer serveurs web
  hosts: webservers
  roles:
    - nginx
    - php-fpm
```

**Ansible Galaxy :**

- Télécharger des roles publics : `ansible-galaxy install geerlingguy.nginx`
- Créer un squelette : `ansible-galaxy init mon-role`
- Publier sur Galaxy (contributions open source)

**Best Practices :**

- 1 role = 1 responsabilité (nginx, postgresql, docker)
- Versionner les roles dans Git
- Tester avec Molecule avant production

[:octicons-arrow-right-24: Commencer le Module 3](03-module.md){ .md-button .md-button--primary }

### Module 4 : Sécurité avec Ansible Vault (1h30)

**Objectif :** Chiffrer les secrets (mots de passe, clés API) avec Ansible Vault.

**Contenu :**

**Problématique :**

Stocker des secrets en clair dans Git est une **faille de sécurité critique**.

**Solution : Ansible Vault**

```bash
# Créer un fichier chiffré
ansible-vault create secrets.yml
# Entrer le mot de passe du vault
# Éditer le fichier (ouverture avec $EDITOR)

# Contenu de secrets.yml :
# db_password: "SuperSecret123!"
# api_key: "abc123xyz"

# Chiffrer un fichier existant
ansible-vault encrypt vars/prod.yml

# Éditer un fichier chiffré
ansible-vault edit secrets.yml

# Déchiffrer temporairement
ansible-vault view secrets.yml
```

**Utiliser le vault dans un playbook :**

```yaml
- name: Configurer la base de données
  hosts: dbservers
  vars_files:
    - secrets.yml
  tasks:
    - name: Créer utilisateur PostgreSQL
      postgresql_user:
        name: appuser
        password: "{{ db_password }}"
```

**Exécuter avec le vault :**

```bash
ansible-playbook site.yml --ask-vault-pass
# Ou avec un fichier de mot de passe
ansible-playbook site.yml --vault-password-file ~/.vault_pass
```

**Best Practices :**

- Ne jamais commiter `~/.vault_pass` dans Git (ajouter à `.gitignore`)
- Utiliser des vaults distincts par environnement (dev, staging, prod)
- Rotation régulière des secrets (`ansible-vault rekey`)

[:octicons-arrow-right-24: Commencer le Module 4](04-module.md){ .md-button .md-button--primary }

### Module 5 : TP Final - Industrialisation Complète (3h)

**Objectif :** Déployer une infrastructure multi-tier avec tests et CI/CD.

**Contexte :**

Vous êtes DevOps Engineer dans une startup. Votre mission : automatiser le déploiement d'une application 3-tier (Web + API + DB) avec Ansible, en respectant les standards industriels.

**Tâches :**

1. **Inventaire dynamique :**
   - Utiliser un inventaire YAML avec groupes (`webservers`, `appservers`, `dbservers`)
   - Configurer `group_vars/` pour chaque groupe

2. **Roles à créer :**
   - `common` : Utilisateurs, SSH, firewall, NTP
   - `nginx` : Reverse proxy pour l'API
   - `nodejs` : Application Node.js (API)
   - `postgresql` : Base de données avec vault pour le mot de passe

3. **Templates Jinja2 :**
   - `/etc/nginx/sites-available/api.conf` (upstream vers Node.js)
   - `/etc/postgresql/pg_hba.conf` (autoriser l'app server)

4. **Testing avec Molecule :**
   - Tester le role `nginx` dans un container Docker
   - Valider l'idempotence (2 runs successifs = 0 changes)

5. **CI/CD GitLab :**
   - Pipeline avec stages : `lint` (ansible-lint) → `test` (molecule) → `deploy` (production)
   - Déploiement automatique sur merge dans `main`

**Livrables :**

- Repository Git structuré (`roles/`, `inventories/`, `group_vars/`)
- Playbook principal `site.yml`
- Tests Molecule fonctionnels
- Pipeline `.gitlab-ci.yml` opérationnel
- Documentation (README.md avec diagramme d'architecture)

!!! warning "Module en cours de rédaction"
    Le TP Final sera bientôt disponible. En attendant, consolidez vos acquis avec les modules 1 à 4.

## Durée Estimée

| Module | Durée | Type |
|--------|-------|------|
| Module 1 : Architecture Ansible | 1h | Théorie + Installation |
| Module 2 : Playbooks | 2h | Pratique guidée |
| Module 3 : Roles | 2h | Refactoring |
| Module 4 : Ansible Vault | 1h30 | Sécurité |
| Module 5 : TP Final | 3h | Projet autonome |
| **Total** | **9h30** | **Formation complète** |

!!! tip "Organisation Recommandée"
    **Format présentiel :** 4 jours (2h30 par jour)

    **Format asynchrone :** 3 semaines à votre rythme

    **Environnement requis :** 3-4 VMs (1 control node + 2-3 managed nodes)

## Compétences Acquises

À la fin de cette formation, vous serez capable de :

- ✅ Comprendre l'architecture agentless d'Ansible
- ✅ Écrire des playbooks avec variables, loops, conditionnels
- ✅ Structurer le code en roles réutilisables
- ✅ Sécuriser les secrets avec Ansible Vault
- ✅ Tester avec Molecule et ansible-lint
- ✅ Intégrer Ansible dans un pipeline CI/CD
- ✅ Déployer des infrastructures multi-tier en production

## Certification

Cette formation prépare aux certifications suivantes :

- **Red Hat Certified Specialist in Ansible Automation** (EX407)
- **HashiCorp Certified: Terraform Associate** (complémentaire IaC)
- **AWS Certified DevOps Engineer** (module CI/CD)

Une fois la formation complétée, vous pouvez valider vos compétences avec le **TP Final** comme portfolio.

## Ressources Complémentaires

- [Documentation Ansible Officielle](https://docs.ansible.com/)
- [Ansible Galaxy](https://galaxy.ansible.com/) : Marketplace de roles
- [Jeff Geerling - Ansible for DevOps (Livre)](https://www.ansiblefordevops.com/)
- [Molecule Documentation](https://molecule.readthedocs.io/)
- [Guide Ansible ShellBook - Fundamentals](../../devops/ansible/fundamentals.md)
- [Guide Ansible ShellBook - Industrialization](../../devops/ansible/industrialization.md)

## Support

**Questions ou problèmes ?**

- 💬 [Discussions GitHub](https://github.com/VBlackJack/ShellBook/discussions)
- 🐛 [Issues GitHub](https://github.com/VBlackJack/ShellBook/issues)
- 📧 Contact : ansible@shellbook.io

---

**Prêt ?** [:octicons-arrow-right-24: Commencer le Module 1](01-module.md){ .md-button .md-button--primary }
