---
tags:
  - formation
  - ansible
  - tp
  - automation
---

# TP Final : Infrastructure Multi-Tier avec CI/CD

## Objectifs

À la fin de ce TP, vous aurez validé les compétences suivantes :

- Structurer un projet Ansible en roles réutilisables
- Utiliser Ansible Vault pour sécuriser les secrets
- Créer des templates Jinja2 dynamiques
- Configurer un inventaire multi-environnement
- Tester avec Molecule et ansible-lint
- Intégrer Ansible dans un pipeline CI/CD

**Durée :** 3 heures

---

## Contexte

Vous êtes DevOps Engineer dans une startup fintech. L'équipe de développement a créé une application web 3-tier composée de :

- **Frontend** : Application React servie par Nginx
- **Backend** : API Node.js
- **Database** : PostgreSQL

Votre mission : automatiser le déploiement complet de cette stack sur des serveurs Linux avec Ansible, en respectant les bonnes pratiques industrielles.

### Architecture Cible

```text
┌─────────────────────────────────────────────────────────────────────┐
│                         Infrastructure                               │
│                                                                      │
│  ┌──────────────┐      ┌──────────────┐      ┌──────────────┐      │
│  │   Nginx      │      │   Node.js    │      │  PostgreSQL  │      │
│  │   (Proxy)    │─────▶│   (API)      │─────▶│   (BDD)      │      │
│  │   :80/:443   │      │   :3000      │      │   :5432      │      │
│  └──────────────┘      └──────────────┘      └──────────────┘      │
│       webserver            appserver             dbserver           │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Cahier des Charges

### Partie 1 : Structure du Projet (45 min)

**Objectif :** Créer une structure de projet Ansible conforme aux bonnes pratiques.

#### 1.1 Arborescence

Créez la structure suivante :

```text
fintech-infra/
├── ansible.cfg
├── site.yml
├── inventories/
│   ├── dev/
│   │   ├── hosts.yml
│   │   └── group_vars/
│   │       ├── all.yml
│   │       ├── webservers.yml
│   │       ├── appservers.yml
│   │       └── dbservers.yml
│   └── prod/
│       ├── hosts.yml
│       └── group_vars/
│           └── ...
├── roles/
│   ├── common/
│   ├── nginx/
│   ├── nodejs/
│   └── postgresql/
└── vault/
    └── secrets.yml
```

#### 1.2 Inventaire

Configurez l'inventaire `inventories/dev/hosts.yml` :

```yaml
all:
  children:
    webservers:
      hosts:
        web01:
          ansible_host: 192.168.56.10
    appservers:
      hosts:
        app01:
          ansible_host: 192.168.56.11
    dbservers:
      hosts:
        db01:
          ansible_host: 192.168.56.12
```

#### 1.3 Configuration Ansible

Créez `ansible.cfg` avec les paramètres recommandés :

```ini
[defaults]
inventory = inventories/dev/hosts.yml
roles_path = roles
host_key_checking = False
retry_files_enabled = False

[privilege_escalation]
become = True
become_method = sudo
```

---

### Partie 2 : Création des Roles (1h15)

**Objectif :** Développer 4 roles Ansible fonctionnels.

#### 2.1 Role `common`

Ce role doit :

- Mettre à jour les paquets système
- Installer les paquets de base (vim, htop, curl, git)
- Configurer le timezone
- Créer un utilisateur de déploiement `deploy`
- Configurer le firewall (firewalld ou ufw)
- Configurer NTP

**Fichiers à créer :**

- `roles/common/tasks/main.yml`
- `roles/common/handlers/main.yml`
- `roles/common/defaults/main.yml`

#### 2.2 Role `nginx`

Ce role doit :

- Installer Nginx
- Configurer un virtual host pour le reverse proxy
- Activer HTTPS avec certificat auto-signé (dev) ou Let's Encrypt (prod)
- Configurer les headers de sécurité

**Template Jinja2 requis :** `roles/nginx/templates/api.conf.j2`

```nginx
upstream api_backend {
    server {{ api_server_host }}:{{ api_server_port }};
}

server {
    listen 80;
    server_name {{ domain_name }};

    location / {
        proxy_pass http://api_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

#### 2.3 Role `nodejs`

Ce role doit :

- Installer Node.js 20 LTS via NodeSource
- Créer un utilisateur applicatif `nodeapp`
- Déployer l'application depuis un repository Git
- Installer les dépendances npm
- Configurer un service systemd
- Gérer les variables d'environnement

**Variables attendues :**

```yaml
nodejs_version: "20"
app_repo: "https://github.com/company/api.git"
app_branch: "main"
app_directory: "/opt/api"
app_port: 3000
```

#### 2.4 Role `postgresql`

Ce role doit :

- Installer PostgreSQL 15
- Créer une base de données applicative
- Créer un utilisateur avec privilèges limités
- Configurer `pg_hba.conf` pour autoriser l'app server
- Activer les connexions réseau

**Secrets à chiffrer avec Vault :**

```yaml
# vault/secrets.yml
db_password: "SuperSecretPassword123!"
db_admin_password: "AdminPassword456!"
```

---

### Partie 3 : Intégration et Tests (1h)

**Objectif :** Tester, valider et industrialiser le déploiement.

#### 3.1 Playbook Principal

Créez `site.yml` qui orchestre tous les roles :

```yaml
---
- name: Configuration commune
  hosts: all
  roles:
    - common

- name: Configuration serveur web
  hosts: webservers
  roles:
    - nginx

- name: Configuration serveur applicatif
  hosts: appservers
  roles:
    - nodejs

- name: Configuration base de données
  hosts: dbservers
  roles:
    - postgresql
```

#### 3.2 Tests avec Molecule

Initialisez Molecule pour le role `nginx` :

```bash
cd roles/nginx
molecule init scenario -d docker
```

Configurez `molecule/default/molecule.yml` pour tester :

- L'installation de Nginx
- La présence du fichier de configuration
- Le démarrage du service

#### 3.3 Linting

Créez `.ansible-lint` à la racine :

```yaml
exclude_paths:
  - .cache/
  - vault/

skip_list:
  - yaml[line-length]
```

Validez avec : `ansible-lint site.yml`

#### 3.4 Pipeline CI/CD GitLab

Créez `.gitlab-ci.yml` :

```yaml
stages:
  - lint
  - test
  - deploy

lint:
  stage: lint
  image: python:3.11
  script:
    - pip install ansible ansible-lint
    - ansible-lint site.yml

test:
  stage: test
  image: docker:latest
  services:
    - docker:dind
  script:
    - pip install molecule[docker]
    - cd roles/nginx && molecule test

deploy_dev:
  stage: deploy
  script:
    - ansible-playbook -i inventories/dev/hosts.yml site.yml --vault-password-file $VAULT_PASSWORD_FILE
  environment: development
  only:
    - develop

deploy_prod:
  stage: deploy
  script:
    - ansible-playbook -i inventories/prod/hosts.yml site.yml --vault-password-file $VAULT_PASSWORD_FILE
  environment: production
  only:
    - main
  when: manual
```

---

## Livrables Attendus

- [ ] Structure de projet complète avec 4 roles
- [ ] Inventaires dev et prod configurés
- [ ] Playbook `site.yml` fonctionnel
- [ ] Secrets chiffrés avec Ansible Vault
- [ ] Templates Jinja2 pour Nginx et pg_hba.conf
- [ ] Tests Molecule pour au moins 1 role
- [ ] Configuration ansible-lint sans erreurs
- [ ] Pipeline CI/CD `.gitlab-ci.yml`
- [ ] README.md avec instructions de déploiement

---

## Critères d'Évaluation

| Critère | Points |
|---------|--------|
| Structure du projet conforme aux bonnes pratiques | /3 |
| Role `common` fonctionnel | /2 |
| Role `nginx` avec template Jinja2 | /3 |
| Role `nodejs` avec service systemd | /3 |
| Role `postgresql` avec sécurité | /3 |
| Utilisation correcte d'Ansible Vault | /2 |
| Tests Molecule fonctionnels | /2 |
| Pipeline CI/CD complet | /2 |
| **Total** | **/20** |

---

## Commandes Utiles

```bash
# Créer le vault
ansible-vault create vault/secrets.yml

# Tester la syntaxe
ansible-playbook site.yml --syntax-check

# Dry-run
ansible-playbook site.yml --check --diff

# Déployer
ansible-playbook -i inventories/dev/hosts.yml site.yml --ask-vault-pass

# Tester un role avec Molecule
cd roles/nginx && molecule test

# Linter
ansible-lint site.yml
```

---

## Ressources

- [Module 1 - Architecture Ansible](01-module.md)
- [Module 2 - Playbooks](02-module.md)
- [Module 3 - Roles](03-module.md)
- [Module 4 - Ansible Vault](04-module.md)
- [Guide Ansible Fundamentals](../../devops/ansible/fundamentals.md)
- [Guide Industrialization](../../devops/ansible/industrialization.md)

---

## Bonus (Points Supplémentaires)

- **+1 point** : Inventaire dynamique avec plugin AWS/Azure
- **+1 point** : Notification Slack en fin de déploiement
- **+1 point** : Healthcheck applicatif post-déploiement
- **+1 point** : Rolling update avec `serial: 1`

---

**Précédent :** [Module 4 - Ansible Vault](04-module.md)

**Retour au programme :** [Index](index.md)

---

## Navigation

| | |
|:---|---:|
| [← Module 4 : Sécurité & Secrets - Ansib...](04-module.md) | [Programme →](index.md) |

[Retour au Programme](index.md){ .md-button }
