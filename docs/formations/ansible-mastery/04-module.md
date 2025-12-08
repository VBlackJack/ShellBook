---
tags:
  - formation
  - ansible
  - security
  - vault
  - secrets
  - encryption
  - devops
  - secnumcloud
---

# Module 4 : Sécurité & Secrets - Ansible Vault

## Objectif du Module

Maîtriser Ansible Vault pour chiffrer et gérer les données sensibles (mots de passe, clés API, certificats), éviter les fuites de secrets dans Git, et déployer des infrastructures sécurisées conformes aux standards SecNumCloud et RGPD.

**Durée :** 2h30

## Introduction : Le Problème des Secrets en Clair

### Secrets in Git = Game Over

> **"Secrets in Git = Game Over."**
> — Principe fondamental DevSecOps

**Le scénario catastrophe (trop fréquent) :**

```yaml
# playbook.yml - COMMIT SUR GIT PUBLIC
---
- name: Déployer MySQL
  hosts: db
  vars:
    mysql_root_password: SuperSecret123     # ❌ EN CLAIR!
    api_key: sk-abc123xyz456                # ❌ EN CLAIR!
    aws_access_key: AKIAIOSFODNN7EXAMPLE    # ❌ EN CLAIR!

  tasks:
    - name: Configurer MySQL
      mysql_user:
        name: root
        password: "{{ mysql_root_password }}"
```

**Conséquences d'un commit de secrets :**

1. **Indexation immédiate par les bots** : GitHub/GitLab scannés en permanence
2. **Révocation impossible** : L'historique Git garde TOUT (même après suppression)
3. **Compromission complète** : Accès BDD, APIs, Cloud = faille totale
4. **Coût financier** : Factures AWS/Azure à 5 chiffres en quelques heures
5. **RGPD** : Fuite de données = amende jusqu'à 4% du CA mondial

### Statistiques Alarmantes

**Étude GitGuardian 2024 :**

- **10 millions de secrets** exposés publiquement sur GitHub en 2023
- **1 secret committé toutes les 3 secondes**
- **67% des secrets** ne sont JAMAIS révoqués après découverte
- **Temps moyen de détection** : 4-6 mois (trop tard)

**Exemples réels de fuites :**

| Entreprise | Secret fuité | Coût |
|------------|-------------|------|
| Uber (2016) | Clés AWS dans repo privé hacké | $148M (amende) |
| Tesla (2018) | Credentials Kubernetes publics | Minage crypto sur infra |
| Toyota (2023) | Token GitHub public | 300k clients exposés |

**Message clair :** **JAMAIS de secrets en clair dans Git.**

---

## Concept : Ansible Vault

### Qu'est-ce qu'Ansible Vault ?

**Définition :** Ansible Vault est un **système de chiffrement AES-256** intégré à Ansible pour protéger les fichiers et variables contenant des données sensibles.

**Analogie :** Si Git est un "coffre-fort transparent" (tout le monde voit le contenu), Vault est un "cadenas numérique" qui rend les fichiers illisibles sans la clé.

**Fonctionnement :**

```
Fichier en clair          Ansible Vault              Fichier chiffré
─────────────────         ────────────              ────────────────
mysql_password: Secret    ansible-vault encrypt     $ANSIBLE_VAULT;1.1;AES256
api_key: abc123           ──────────────>           66386439653865...
                          Mot de passe: ****        39383437643037...
                                                     [ILLISIBLE]
```

**Avantages :**

- ✅ **Chiffrement AES-256** : Standard militaire (NSA Suite B)
- ✅ **Intégré à Ansible** : Aucun outil externe
- ✅ **Transparent** : Ansible déchiffre automatiquement à l'exécution
- ✅ **Versionnable** : Fichiers chiffrés safe dans Git
- ✅ **Auditable** : Changements de secrets trackés (contenu chiffré)

**Limitations :**

- ⚠️ **1 mot de passe = 1 fichier** : Rotation complexe
- ⚠️ **Pas de gestion centralisée** : HashiCorp Vault pour ça
- ⚠️ **Déchiffrement en RAM** : Secrets exposés pendant exécution

---

### Files vs Strings - Deux Approches

**Ansible Vault supporte 2 niveaux de chiffrement :**

#### 1. Chiffrement de Fichiers Complets (Recommandé)

**Fichier `secrets.yml` en clair :**

```yaml
---
mysql_root_password: SuperSecret123
api_key: sk-abc123xyz456
ssl_private_key: |
  -----BEGIN PRIVATE KEY-----
  MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC...
  -----END PRIVATE KEY-----
```

**Après `ansible-vault encrypt secrets.yml` :**

```
$ANSIBLE_VAULT;1.1;AES256
66386439653865343966386166373038343037643037613962613834373530373938663834353033
3339613437663766623961393339326365303231313738330a373539656231303637383031613039
62333637353061636365373764633264393434313035303061363339326237653365373839643566
6265313464656635620a653665356232303738663037346337363837366536386137656232656335
...
[200+ lignes de hash illisible]
```

**Utilisation dans playbook :**

```yaml
---
- hosts: db
  vars_files:
    - secrets.yml    # Ansible déchiffre automatiquement

  tasks:
    - name: Configurer MySQL
      mysql_user:
        password: "{{ mysql_root_password }}"
```

**Avantages :**

- ✅ Tous les secrets dans 1 fichier centralisé
- ✅ Facile à gérer (1 commande pour encrypt/decrypt)
- ✅ Historique Git protégé (tout le fichier chiffré)

---

#### 2. Chiffrement de Variables Inline (Avancé)

**Pour chiffrer UNE SEULE variable dans un fichier mixte :**

```yaml
# group_vars/db.yml - Fichier PARTIELLEMENT chiffré
---
# Variables publiques (en clair)
mysql_port: 3306
mysql_host: localhost

# Variable secrète (chiffrée inline)
mysql_root_password: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          66386439653865343966386166373038343037643037613962613834373530373938663834353033
          3339613437663766623961393339326365303231313738330a373539656231303637383031613039
          ...
```

**Avantages :**

- ✅ Mélange clair + chiffré dans même fichier
- ✅ Historique Git lisible pour variables publiques
- ✅ Granularité fine (secret par secret)

**Inconvénient :**

- ⚠️ Plus complexe à gérer (chiffrer variable par variable)

**Commande pour chiffrer une string :**

```bash
ansible-vault encrypt_string 'SuperSecret123' --name 'mysql_root_password'
```

**Sortie :**

```yaml
mysql_root_password: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          66386439653865343966386166373038343037643037613962613834373530373938663834353033
          ...
```

**Copier-coller cette sortie dans votre fichier YAML.**

---

## Pratique : Commandes Ansible Vault

### Les 5 Commandes Essentielles

#### 1. `ansible-vault create` - Créer un Fichier Chiffré

**Créer un nouveau fichier chiffré :**

```bash
ansible-vault create secrets.yml
```

**Workflow :**

1. Demande un **mot de passe Vault** (à mémoriser !)
2. Demande confirmation du mot de passe
3. Ouvre l'éditeur par défaut (vim/nano)
4. Saisir le contenu YAML
5. Sauvegarder et quitter → fichier immédiatement chiffré

**Exemple de saisie dans l'éditeur :**

```yaml
---
mysql_root_password: SuperSecret123
api_key: sk-abc123xyz456
aws_access_key: AKIAIOSFODNN7EXAMPLE
aws_secret_key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

**Après sauvegarde, `cat secrets.yml` affiche :**

```
$ANSIBLE_VAULT;1.1;AES256
66386439653865343966386166373038343037643037613962613834373530373938663834353033
...
```

---

#### 2. `ansible-vault edit` - Éditer un Fichier Chiffré

**Modifier un fichier chiffré existant :**

```bash
ansible-vault edit secrets.yml
```

**Workflow :**

1. Demande le **mot de passe Vault**
2. Déchiffre temporairement le fichier
3. Ouvre l'éditeur avec le contenu en clair
4. Modifications possibles
5. Sauvegarder → re-chiffrement automatique

**Exemple d'utilisation :**

```bash
# Ajouter une nouvelle variable
ansible-vault edit secrets.yml

# Dans l'éditeur, ajouter :
# ssl_certificate_password: CertSecret456

# Sauvegarder → fichier re-chiffré avec la nouvelle variable
```

---

#### 3. `ansible-vault view` - Visualiser un Fichier Chiffré

**Afficher le contenu déchiffré sans éditer :**

```bash
ansible-vault view secrets.yml
```

**Demande le mot de passe → Affiche le contenu en clair :**

```yaml
---
mysql_root_password: SuperSecret123
api_key: sk-abc123xyz456
```

**Sortie en lecture seule (pas de modification).**

**Utile pour :**

- Vérifier rapidement une valeur
- Copier un secret dans le terminal
- Debugging sans risque de modification accidentelle

---

#### 4. `ansible-vault encrypt` - Chiffrer un Fichier Existant

**Chiffrer un fichier YAML existant :**

```bash
# Fichier en clair
cat secrets.yml
# mysql_root_password: SuperSecret123

# Chiffrement
ansible-vault encrypt secrets.yml
# New Vault password: ****
# Confirm New Vault password: ****
# Encryption successful

# Fichier maintenant chiffré
cat secrets.yml
# $ANSIBLE_VAULT;1.1;AES256
# 66386439653865...
```

**Options utiles :**

```bash
# Chiffrer plusieurs fichiers d'un coup
ansible-vault encrypt secrets.yml db_passwords.yml api_keys.yml

# Spécifier le mot de passe en ligne (DANGEREUX, à éviter)
ansible-vault encrypt secrets.yml --vault-password-file .vault_pass
```

---

#### 5. `ansible-vault decrypt` - Déchiffrer un Fichier

**Déchiffrer un fichier (⚠️ ATTENTION : fichier en clair après) :**

```bash
ansible-vault decrypt secrets.yml
# Vault password: ****
# Decryption successful

# Fichier maintenant en clair
cat secrets.yml
# mysql_root_password: SuperSecret123
```

**⚠️ DANGER :** Ne déchiffrer que temporairement, **JAMAIS commit en clair** !

**Usage recommandé :**

```bash
# Déchiffrer pour modification manuelle
ansible-vault decrypt secrets.yml
nano secrets.yml
# ... modifications ...

# RE-CHIFFRER IMMÉDIATEMENT
ansible-vault encrypt secrets.yml

# VÉRIFIER que le fichier est chiffré avant commit
cat secrets.yml | head -1
# $ANSIBLE_VAULT;1.1;AES256  ← OK, chiffré
```

---

### Chiffrer des Variables Individuelles

#### `ansible-vault encrypt_string` - Chiffrer une Chaîne

**Chiffrer une variable pour usage inline :**

```bash
ansible-vault encrypt_string 'SuperSecret123' --name 'mysql_root_password'
```

**Sortie :**

```yaml
mysql_root_password: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          66386439653865343966386166373038343037643037613962613834373530373938663834353033
          3339613437663766623961393339326365303231313738330a373539656231303637383031613039
          ...
```

**Copier-coller dans votre fichier YAML :**

```yaml
# group_vars/db.yml
mysql_port: 3306
mysql_root_password: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          66386439653865343966386166373038343037643037613962613834373530373938663834353033
          ...
```

**Lire depuis stdin (utile pour scripts) :**

```bash
echo -n 'SuperSecret123' | ansible-vault encrypt_string --stdin-name 'mysql_root_password'
```

---

## Pratique : Gestion des Mots de Passe Vault

### Problème : Entrer le Mot de Passe à Chaque Fois

**Par défaut, Ansible demande le mot de passe Vault :**

```bash
ansible-playbook site.yml --ask-vault-pass
# Vault password: ****
```

**Problème :** Impossible pour automation (CI/CD, cron jobs).

---

### Solution 1 : `--ask-vault-pass` (Interactif)

**Pour exécution manuelle :**

```bash
ansible-playbook site.yml --ask-vault-pass
```

**Avantages :**

- ✅ Sécurisé (mot de passe pas stocké)
- ✅ Audit (qui a exécuté)

**Inconvénients :**

- ❌ Manuel (pas d'automation)
- ❌ Fastidieux (répétitif)

---

### Solution 2 : Fichier `.vault_pass` (Automation)

**Créer un fichier contenant le mot de passe :**

```bash
echo 'VotreMotDePasseVault' > .vault_pass

# CRITIQUE : Protéger le fichier
chmod 600 .vault_pass

# AJOUTER AU .gitignore (OBLIGATOIRE)
echo '.vault_pass' >> .gitignore
```

**Utilisation :**

```bash
ansible-playbook site.yml --vault-password-file .vault_pass
```

**Configuration permanente dans `ansible.cfg` :**

```ini
[defaults]
vault_password_file = .vault_pass
```

**Après configuration, plus besoin de spécifier l'option :**

```bash
ansible-playbook site.yml
# Ansible utilise automatiquement .vault_pass
```

**⚠️ SÉCURITÉ :**

- ✅ `.vault_pass` dans `.gitignore`
- ✅ Permissions 600 (lisible uniquement par propriétaire)
- ✅ Stocké hors du repo Git (ou chiffré avec GPG)
- ❌ **JAMAIS commiter** `.vault_pass` en clair

---

### Solution 3 : Script de Récupération (Avancé)

**Pour intégration avec gestionnaires de secrets (1Password, Bitwarden, etc.) :**

```bash
# vault_password_script.sh
#!/bin/bash
# Récupérer le mot de passe depuis 1Password
op read "op://vault/ansible-vault/password"
```

**Rendre exécutable :**

```bash
chmod +x vault_password_script.sh
```

**Utilisation :**

```bash
ansible-playbook site.yml --vault-password-file vault_password_script.sh
```

**Ansible exécute le script et utilise sa sortie comme mot de passe.**

---

### Solution 4 : Variables d'Environnement (CI/CD)

**Pour pipelines GitLab CI / GitHub Actions :**

**GitLab CI `.gitlab-ci.yml` :**

```yaml
deploy:
  script:
    - echo "$VAULT_PASSWORD" > .vault_pass
    - ansible-playbook site.yml --vault-password-file .vault_pass
    - rm .vault_pass  # Nettoyage
  variables:
    VAULT_PASSWORD:
      value: VotreMotDePasseVault
      protected: true
      masked: true
```

**GitHub Actions `.github/workflows/deploy.yml` :**

```yaml
- name: Deploy with Ansible
  env:
    VAULT_PASSWORD: ${{ secrets.VAULT_PASSWORD }}
  run: |
    echo "$VAULT_PASSWORD" > .vault_pass
    ansible-playbook site.yml --vault-password-file .vault_pass
    rm .vault_pass
```

**Secrets stockés dans GitHub Secrets / GitLab CI Variables (chiffrés).**

---

## Pratique : Intégration dans les Playbooks

### Charger des Fichiers Chiffrés avec `vars_files`

**Playbook `site.yml` :**

```yaml
---
- name: Déployer application avec secrets
  hosts: all
  become: yes

  vars_files:
    - secrets.yml    # Fichier chiffré avec Vault

  tasks:
    - name: Afficher le mot de passe (DEBUG - À SUPPRIMER EN PROD)
      debug:
        msg: "Mot de passe MySQL : {{ mysql_root_password }}"

    - name: Configurer MySQL
      mysql_user:
        name: root
        password: "{{ mysql_root_password }}"
        host: localhost
        state: present
```

**Exécution :**

```bash
ansible-playbook site.yml --ask-vault-pass
# Vault password: ****
# PLAY [Déployer application avec secrets] ****
# TASK [Afficher le mot de passe] ****
# ok: [localhost] => {
#     "msg": "Mot de passe MySQL : SuperSecret123"
# }
```

**Ansible déchiffre automatiquement `secrets.yml` à l'exécution.**

---

### Variables Inline Chiffrées avec `!vault |`

**Fichier `group_vars/db.yml` :**

```yaml
---
# Variables publiques
mysql_port: 3306
mysql_host: localhost
mysql_database: production_db

# Variable secrète (chiffrée inline)
mysql_root_password: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          66386439653865343966386166373038343037643037613962613834373530373938663834353033
          3339613437663766623961393339326365303231313738330a373539656231303637383031613039
          62333637353061636365373764633264393434313035303061363339326237653365373839643566
          6265313464656635620a653665356232303738663037346337363837366536386137656232656335
          3632
```

**Playbook utilisant ces variables :**

```yaml
---
- name: Configuration MySQL
  hosts: db
  # Pas de vars_files, variables chargées depuis group_vars/db.yml

  tasks:
    - name: Installer MySQL
      apt:
        name: mysql-server
        state: present

    - name: Configurer root password
      mysql_user:
        name: root
        password: "{{ mysql_root_password }}"
```

**Exécution :**

```bash
ansible-playbook mysql.yml --ask-vault-pass
```

**Ansible déchiffre automatiquement la variable `!vault |`.**

---

### Best Practices de Structuration

**Organisation recommandée :**

```
ansible-project/
├── ansible.cfg
├── inventory/
│   └── production.ini
├── group_vars/
│   ├── all.yml              # Variables publiques
│   ├── web.yml              # Variables publiques web
│   └── db.yml               # Variables publiques db
├── secrets/
│   ├── all_secrets.yml      # Secrets communs (CHIFFRÉ)
│   ├── web_secrets.yml      # Secrets web (CHIFFRÉ)
│   └── db_secrets.yml       # Secrets db (CHIFFRÉ)
├── playbooks/
│   └── site.yml
└── .gitignore               # .vault_pass, *.retry
```

**Playbook chargeant les secrets :**

```yaml
---
- name: Déploiement complet
  hosts: all

  vars_files:
    - ../secrets/all_secrets.yml

- name: Serveurs Web
  hosts: web

  vars_files:
    - ../secrets/web_secrets.yml

  roles:
    - nginx

- name: Serveurs DB
  hosts: db

  vars_files:
    - ../secrets/db_secrets.yml

  roles:
    - mysql
```

**Avantages :**

- ✅ Séparation clair/chiffré
- ✅ Secrets groupés par fonction
- ✅ Audit facilité (historique Git des secrets chiffrés)

---

## Exercice : Base de Données Sécurisée

### Scénario

Vous devez déployer un serveur MySQL avec un mot de passe root **chiffré** dans Vault.

**Contraintes :**

- ❌ **Interdiction formelle** de stocker le mot de passe en clair
- ✅ Le mot de passe doit être dans un fichier `secrets.yml` chiffré
- ✅ Le playbook doit installer MySQL et configurer le mot de passe
- ✅ L'exécution doit demander le mot de passe Vault

---

### Mission

1. **Créer un fichier chiffré** `secrets.yml` contenant :
   - Variable `mysql_root_password` avec la valeur `SuperSecret123`

2. **Créer un playbook** `deploy_mysql.yml` qui :
   - Charge `secrets.yml`
   - Installe MySQL Server
   - Configure le mot de passe root

3. **Exécuter le playbook** en demandant le mot de passe Vault

---

### Étapes Détaillées

#### Étape 1 : Créer le Fichier de Secrets Chiffré

```bash
# Créer secrets.yml chiffré
ansible-vault create secrets.yml
```

**Dans l'éditeur, saisir :**

```yaml
---
mysql_root_password: SuperSecret123
mysql_database: production_db
mysql_user: app_user
mysql_user_password: AppSecret456
```

**Sauvegarder et quitter → fichier immédiatement chiffré.**

**Vérifier le chiffrement :**

```bash
cat secrets.yml
# $ANSIBLE_VAULT;1.1;AES256
# 66386439653865...  ← OK, chiffré
```

---

#### Étape 2 : Créer le Playbook

**Fichier `deploy_mysql.yml` :**

```yaml
---
- name: Déploiement MySQL sécurisé
  hosts: db
  become: yes

  vars_files:
    - secrets.yml

  tasks:
    - name: Installer MySQL Server
      apt:
        name:
          - mysql-server
          - python3-pymysql
        state: present
        update_cache: yes

    - name: Démarrer MySQL
      service:
        name: mysql
        state: started
        enabled: yes

    - name: Configurer le mot de passe root MySQL
      mysql_user:
        name: root
        password: "{{ mysql_root_password }}"
        host: localhost
        login_unix_socket: /var/run/mysqld/mysqld.sock
        state: present

    - name: Créer la base de données
      mysql_db:
        name: "{{ mysql_database }}"
        state: present
        login_unix_socket: /var/run/mysqld/mysqld.sock

    - name: Créer l'utilisateur applicatif
      mysql_user:
        name: "{{ mysql_user }}"
        password: "{{ mysql_user_password }}"
        priv: "{{ mysql_database }}.*:ALL"
        host: localhost
        login_unix_socket: /var/run/mysqld/mysqld.sock
        state: present
```

---

#### Étape 3 : Vérifier la Syntaxe

```bash
ansible-playbook --syntax-check deploy_mysql.yml
```

---

#### Étape 4 : Dry-Run

```bash
ansible-playbook --check deploy_mysql.yml --ask-vault-pass
# Vault password: ****
```

---

#### Étape 5 : Exécution Réelle

```bash
ansible-playbook deploy_mysql.yml --ask-vault-pass
```

**Sortie attendue :**

```
Vault password: ****

PLAY [Déploiement MySQL sécurisé] ******************************************

TASK [Installer MySQL Server] **********************************************
changed: [db1]

TASK [Démarrer MySQL] ******************************************************
ok: [db1]

TASK [Configurer le mot de passe root MySQL] ******************************
changed: [db1]

TASK [Créer la base de données] ********************************************
changed: [db1]

TASK [Créer l'utilisateur applicatif] **************************************
changed: [db1]

PLAY RECAP ******************************************************************
db1                        : ok=5    changed=4    unreachable=0    failed=0
```

---

#### Étape 6 : Validation

**Vérifier que MySQL fonctionne avec le mot de passe :**

```bash
# Sur le serveur db
mysql -u root -p
# Enter password: SuperSecret123
# mysql>  ← ✅ Connexion réussie
```

**Vérifier la base de données :**

```bash
mysql -u root -pSuperSecret123 -e "SHOW DATABASES;"
# +--------------------+
# | Database           |
# +--------------------+
# | production_db      |  ← ✅ Base créée
# +--------------------+
```

**Vérifier l'utilisateur applicatif :**

```bash
mysql -u app_user -pAppSecret456 -e "USE production_db; SHOW TABLES;"
# ✅ Accès OK
```

---

## Solution

??? quote "Solution Complète - Déploiement MySQL Sécurisé"

    ### Fichier `secrets.yml` (Chiffré)

    **Création :**

    ```bash
    ansible-vault create secrets.yml
    # New Vault password: ****
    # Confirm New Vault password: ****
    ```

    **Contenu (dans l'éditeur) :**

    ```yaml
    ---
    mysql_root_password: SuperSecret123
    mysql_database: production_db
    mysql_user: app_user
    mysql_user_password: AppSecret456
    ```

    **Après sauvegarde, vérifier :**

    ```bash
    cat secrets.yml
    ```

    **Sortie (fichier chiffré) :**

    ```
    $ANSIBLE_VAULT;1.1;AES256
    66386439653865343966386166373038343037643037613962613834373530373938663834353033
    3339613437663766623961393339326365303231313738330a373539656231303637383031613039
    62333637353061636365373764633264393434313035303061363339326237653365373839643566
    6265313464656635620a653665356232303738663037346337363837366536386137656232656335
    36323032373839663163373439633237383033373739326234653438623632626231653165646136
    ...
    ```

    ---

    ### Fichier `deploy_mysql.yml` (Playbook)

    ```yaml
    ---
    - name: Déploiement MySQL sécurisé avec Vault
      hosts: db
      become: yes

      vars_files:
        - secrets.yml

      vars:
        mysql_bind_address: "0.0.0.0"    # Écoute sur toutes les interfaces

      tasks:
        - name: Installer MySQL Server et dépendances Python
          apt:
            name:
              - mysql-server
              - python3-pymysql     # Requis pour les modules mysql_*
            state: present
            update_cache: yes
          tags:
            - install

        - name: Démarrer et activer MySQL
          service:
            name: mysql
            state: started
            enabled: yes
          tags:
            - service

        - name: Configurer le mot de passe root MySQL
          mysql_user:
            name: root
            password: "{{ mysql_root_password }}"
            host: localhost
            login_unix_socket: /var/run/mysqld/mysqld.sock
            state: present
          tags:
            - config

        - name: Créer le fichier .my.cnf pour root
          template:
            src: root_my.cnf.j2
            dest: /root/.my.cnf
            owner: root
            group: root
            mode: '0600'
          tags:
            - config

        - name: Créer la base de données
          mysql_db:
            name: "{{ mysql_database }}"
            state: present
            login_user: root
            login_password: "{{ mysql_root_password }}"
          tags:
            - database

        - name: Créer l'utilisateur applicatif
          mysql_user:
            name: "{{ mysql_user }}"
            password: "{{ mysql_user_password }}"
            priv: "{{ mysql_database }}.*:ALL"
            host: "%"    # Accès depuis n'importe quelle IP
            login_user: root
            login_password: "{{ mysql_root_password }}"
            state: present
          tags:
            - users

        - name: Supprimer les utilisateurs anonymes
          mysql_user:
            name: ""
            host_all: yes
            state: absent
            login_user: root
            login_password: "{{ mysql_root_password }}"
          tags:
            - security

        - name: Supprimer la base de données test
          mysql_db:
            name: test
            state: absent
            login_user: root
            login_password: "{{ mysql_root_password }}"
          tags:
            - security
    ```

    ---

    ### Template `templates/root_my.cnf.j2`

    **Fichier de configuration MySQL pour root (évite de taper le mot de passe) :**

    ```ini
    [client]
    user=root
    password={{ mysql_root_password }}
    ```

    **⚠️ Permissions critiques : 600 (owner-readable only)**

    ---

    ### Fichier `inventory.ini`

    ```ini
    [db]
    db1 ansible_host=localhost ansible_connection=local

    [db:vars]
    ansible_python_interpreter=/usr/bin/python3
    ```

    ---

    ### Fichier `ansible.cfg` (Optionnel)

    ```ini
    [defaults]
    inventory = inventory.ini
    host_key_checking = False

    # Optionnel : Spécifier le fichier de mot de passe Vault
    # vault_password_file = .vault_pass
    ```

    ---

    ### Commandes d'Exécution

    **1. Vérifier la syntaxe**

    ```bash
    ansible-playbook --syntax-check deploy_mysql.yml
    ```

    ---

    **2. Dry-run**

    ```bash
    ansible-playbook --check deploy_mysql.yml --ask-vault-pass
    ```

    **Sortie :**

    ```
    Vault password: ****

    PLAY [Déploiement MySQL sécurisé avec Vault] ******************************

    TASK [Installer MySQL Server et dépendances Python] ***********************
    changed: [db1]

    ...

    PLAY RECAP *****************************************************************
    db1                        : ok=8    changed=6    unreachable=0    failed=0
    ```

    ---

    **3. Exécution réelle**

    ```bash
    ansible-playbook deploy_mysql.yml --ask-vault-pass
    ```

    ---

    **4. Exécution avec fichier de mot de passe (automation)**

    **Créer `.vault_pass` :**

    ```bash
    echo 'VotreMotDePasseVault' > .vault_pass
    chmod 600 .vault_pass
    echo '.vault_pass' >> .gitignore
    ```

    **Exécution :**

    ```bash
    ansible-playbook deploy_mysql.yml --vault-password-file .vault_pass
    ```

    **OU configurer dans `ansible.cfg` :**

    ```ini
    [defaults]
    vault_password_file = .vault_pass
    ```

    **Puis simplement :**

    ```bash
    ansible-playbook deploy_mysql.yml
    ```

    ---

    ### Validations Post-Déploiement

    **Vérifier que MySQL fonctionne :**

    ```bash
    ansible db -m service -a "name=mysql state=started"
    ```

    **Sortie :**

    ```
    db1 | SUCCESS => {
        "changed": false,
        "name": "mysql",
        "state": "started"
    }
    ```

    ---

    **Tester la connexion MySQL :**

    ```bash
    ansible db -m shell -a "mysql -u root -pSuperSecret123 -e 'SELECT VERSION();'"
    ```

    **Sortie :**

    ```
    db1 | CHANGED | rc=0 >>
    +-----------+
    | VERSION() |
    +-----------+
    | 8.0.35    |
    +-----------+
    ```

    ---

    **Vérifier la base de données :**

    ```bash
    ansible db -m shell -a "mysql -u root -pSuperSecret123 -e 'SHOW DATABASES;'"
    ```

    **Sortie :**

    ```
    db1 | CHANGED | rc=0 >>
    +--------------------+
    | Database           |
    +--------------------+
    | information_schema |
    | mysql              |
    | performance_schema |
    | production_db      |  ← ✅ Base créée
    | sys                |
    +--------------------+
    ```

    ---

    **Tester l'utilisateur applicatif :**

    ```bash
    ansible db -m shell -a "mysql -u app_user -pAppSecret456 -e 'SHOW GRANTS;'"
    ```

    **Sortie :**

    ```
    db1 | CHANGED | rc=0 >>
    +------------------------------------------------------------+
    | Grants for app_user@%                                      |
    +------------------------------------------------------------+
    | GRANT USAGE ON *.* TO `app_user`@`%`                       |
    | GRANT ALL PRIVILEGES ON `production_db`.* TO `app_user`@`%`|
    +------------------------------------------------------------+
    ```

    ---

    ### Sécurité Additionnelle (Bonus)

    **Vérifier que le fichier `secrets.yml` est chiffré :**

    ```bash
    head -1 secrets.yml
    # $ANSIBLE_VAULT;1.1;AES256  ← ✅ Chiffré
    ```

    **Vérifier que `.vault_pass` est dans `.gitignore` :**

    ```bash
    grep vault_pass .gitignore
    # .vault_pass  ← ✅ Ignoré par Git
    ```

    **Vérifier les permissions de `.my.cnf` :**

    ```bash
    ansible db -m shell -a "ls -la /root/.my.cnf"
    ```

    **Sortie :**

    ```
    db1 | CHANGED | rc=0 >>
    -rw------- 1 root root 45 Nov 22 17:30 /root/.my.cnf
    # ✅ Permissions 600 (owner-readable only)
    ```

    ---

    ### Rotation du Mot de Passe (Bonus Avancé)

    **Pour changer le mot de passe Vault :**

    ```bash
    ansible-vault rekey secrets.yml
    # Vault password: ****  (ancien mot de passe)
    # New Vault password: ****  (nouveau mot de passe)
    # Confirm New Vault password: ****
    # Rekey successful
    ```

    **Le fichier est re-chiffré avec le nouveau mot de passe.**

    ---

    ### Intégration CI/CD (Bonus)

    **GitLab CI `.gitlab-ci.yml` :**

    ```yaml
    deploy_mysql:
      stage: deploy
      script:
        - echo "$VAULT_PASSWORD" > .vault_pass
        - ansible-playbook deploy_mysql.yml --vault-password-file .vault_pass
        - rm .vault_pass
      only:
        - main
      variables:
        VAULT_PASSWORD:
          value: $VAULT_PASSWORD_SECRET
          protected: true
          masked: true
    ```

    **Variable `VAULT_PASSWORD_SECRET` définie dans Settings > CI/CD > Variables**

## Conclusion du Module

### Ce que Vous Avez Appris

✅ **Risques des secrets en clair** : Statistiques alarmantes, exemples réels

✅ **Ansible Vault** : Chiffrement AES-256 pour fichiers et variables

✅ **Files vs Strings** : Chiffrement complet vs inline (`!vault |`)

✅ **Commandes Vault** : create, edit, view, encrypt, decrypt, encrypt_string

✅ **Gestion mots de passe** : `--ask-vault-pass`, `.vault_pass`, scripts, CI/CD

✅ **Intégration playbooks** : `vars_files`, variables inline chiffrées

✅ **Déploiement sécurisé** : MySQL avec credentials chiffrés

### Commandes Clés à Retenir

```bash
# Créer un fichier chiffré
ansible-vault create secrets.yml

# Éditer un fichier chiffré
ansible-vault edit secrets.yml

# Visualiser un fichier chiffré
ansible-vault view secrets.yml

# Chiffrer un fichier existant
ansible-vault encrypt secrets.yml

# Déchiffrer un fichier
ansible-vault decrypt secrets.yml

# Chiffrer une variable inline
ansible-vault encrypt_string 'MySecret' --name 'my_var'

# Exécuter avec mot de passe
ansible-playbook site.yml --ask-vault-pass

# Exécuter avec fichier
ansible-playbook site.yml --vault-password-file .vault_pass

# Changer le mot de passe Vault
ansible-vault rekey secrets.yml
```

### Best Practices Sécurité

**1. Toujours chiffrer les secrets**

```yaml
# ❌ JAMAIS
mysql_password: SuperSecret123

# ✅ TOUJOURS
mysql_password: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          ...
```

**2. `.vault_pass` dans `.gitignore`**

```bash
echo '.vault_pass' >> .gitignore
git add .gitignore
git commit -m "Add vault_pass to gitignore"
```

**3. Permissions strictes**

```bash
chmod 600 .vault_pass
chmod 600 secrets.yml  # Même chiffré, limiter l'accès
```

**4. Rotation des secrets**

```bash
# Changer le mot de passe Vault tous les 90 jours
ansible-vault rekey secrets.yml
```

**5. Audit des accès**

```bash
# Logger qui accède aux secrets (CI/CD)
echo "$(date) - $USER - Accessed vault" >> /var/log/vault_access.log
```

**6. Ne jamais logger les secrets**

```yaml
# ❌ DANGER
- debug: msg="{{ mysql_password }}"

# ✅ OK (masqué)
- debug: msg="Password configured"
```

**7. Séparer les environnements**

```
secrets/
├── dev_secrets.yml       # Vault password: DevPass123
├── staging_secrets.yml   # Vault password: StagingPass456
└── prod_secrets.yml      # Vault password: ProdPass789Secure!
```

**Chaque environnement = mot de passe Vault différent**

### Différence Vault vs Gestionnaires de Secrets

| **Aspect** | **Ansible Vault** | **HashiCorp Vault / AWS Secrets Manager** |
|------------|------------------|------------------------------------------|
| **Scope** | Fichiers Ansible | Toute l'infrastructure |
| **Centralisation** | ❌ Fichiers locaux | ✅ Serveur centralisé |
| **Rotation auto** | ❌ Manuelle | ✅ Automatique |
| **Audit détaillé** | ⚠️ Git commits | ✅ Logs complets |
| **Accès dynamique** | ❌ Fichiers statiques | ✅ Secrets générés à la demande |
| **Complexité** | ✅ Simple | ⚠️ Infrastructure supplémentaire |
| **Coût** | ✅ Gratuit | ⚠️ Payant (AWS/Azure) ou self-hosted |

**Règle d'or :**

- **< 10 serveurs** : Ansible Vault suffit
- **> 10 serveurs** : Envisager HashiCorp Vault

### Intégration HashiCorp Vault (Aperçu)

**Pour infrastructures avancées :**

```yaml
# Récupérer un secret depuis HashiCorp Vault
- name: Obtenir le mot de passe DB
  set_fact:
    mysql_password: "{{ lookup('hashi_vault', 'secret=secret/data/mysql:password') }}"
```

**Avantages :**

- ✅ Secrets jamais stockés dans Ansible
- ✅ Rotation automatique
- ✅ Audit complet (qui/quand/quoi)
- ✅ Accès révocables dynamiquement

**Module suivant potentiel : Intégration HashiCorp Vault**

### Prochaines Étapes

**Module 5 (optionnel) : Testing & CI/CD**

- Molecule (tests automatisés de rôles)
- Ansible Lint (validation best practices)
- Intégration GitLab CI / GitHub Actions
- Pipeline complet : Lint → Test → Deploy

**TP Final Ansible Mastery (potentiel) :**

- Déploiement application 3-tiers complète
- Rôles (common, web, db, monitoring)
- Secrets avec Vault
- Templates Jinja2
- CI/CD avec GitLab

### Ressources Complémentaires

**Documentation officielle :**

- [Ansible Vault](https://docs.ansible.com/ansible/latest/user_guide/vault.html)
- [Best Practices](https://docs.ansible.com/ansible/latest/user_guide/playbooks_best_practices.html#variables-and-vaults)

**Outils recommandés :**

- **git-secrets** : Prevent committing secrets
- **truffleHog** : Scan Git history for secrets
- **GitGuardian** : Monitor public repos for leaks
- **1Password / Bitwarden** : Team password managers

**Checklist pré-production :**

- [ ] Tous les secrets chiffrés avec Vault
- [ ] `.vault_pass` dans `.gitignore`
- [ ] Aucun secret en clair dans Git history
- [ ] Permissions 600 sur fichiers sensibles
- [ ] Mot de passe Vault complexe (16+ caractères)
- [ ] Rotation planifiée (90 jours)
- [ ] Backup du mot de passe Vault (1Password/Bitwarden)
- [ ] Documentation des secrets (quoi/où sans révéler valeurs)

---

**Félicitations ! Vous maîtrisez Ansible Vault et pouvez déployer des infrastructures sécurisées avec des secrets chiffrés, conformes aux standards DevSecOps et SecNumCloud.** 🎉🔒

**La formation Ansible Mastery est maintenant complète ! Vous êtes prêt à gérer des infrastructures à grande échelle avec automatisation, réutilisabilité et sécurité.**

---

## Navigation

| | |
|:---|---:|
| [← Module 3 : Roles & Templates - L'Indu...](03-module.md) | [TP Final : Infrastructure Multi-Tier ... →](05-tp-final.md) |

[Retour au Programme](index.md){ .md-button }
