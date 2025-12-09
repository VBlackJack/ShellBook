---
tags:
  - git
  - ops
  - versioning
---

# Git pour SysAdmins

Pourquoi chaque SysAdmin a besoin de Git, même si vous n'écrivez jamais de "vrai" code.

---

## Pourquoi Git? Les 5 Piliers

### 1. Backup

!!! danger "L'Ancienne Méthode"
    ```text
    script.sh
    script_backup.sh
    script_final.sh
    script_final_v2.sh
    script_final_v2_WORKING.sh
    script_final_v2_WORKING_monday.sh
    ```

**Avec Git:**

```bash
git init
git add script.sh
git commit -m "Initial version"

# Faire des changements...
git commit -am "Add error handling"

# Une erreur? Revenir en arrière
git log --oneline
git checkout abc123 -- script.sh
```

Plus de scripts perdus sur des disques crashés. Push vers le remote = backup instantané.

---

### 2. Partage

**Sans Git:**

- Pièces jointes email avec différentes versions
- Clés USB qui circulent
- "Tu peux m'envoyer la dernière version?"
- "Quelle version est en production?"

**Avec Git:**

```bash
# Cloner le repo, tout récupérer
git clone git@github.com:team/scripts.git

# Tout le monde a la même version
# Tout le monde sait quelle est la version actuelle
```

---

### 3. Collaboration

Plusieurs personnes peuvent travailler sur les mêmes fichiers sans s'écraser mutuellement.

```bash
# Alice travaille sur la feature A
git checkout -b feature-a
# ... fait des changements ...
git commit -am "Add monitoring script"
git push origin feature-a

# Bob travaille sur la feature B (en même temps)
git checkout -b feature-b
# ... fait des changements ...
git commit -am "Add backup script"
git push origin feature-b

# Les deux fusionnent vers main sans conflits
git checkout main
git merge feature-a
git merge feature-b
```

---

### 4. Documentation

**Messages de commit = "Pourquoi j'ai fait ça"**

```bash
git log --oneline

# Les bons commits racontent une histoire:
# a1b2c3d fix: nginx config for TLS 1.3 (CVE-2024-1234)
# d4e5f6g feat: add automated backup script
# g7h8i9j refactor: split monolithic script into modules
# j1k2l3m docs: add runbook for incident response
```

**Blame = "Qui a fait ça et quand?"**

```bash
# Trouver qui a changé la ligne 42 et pourquoi
git blame nginx.conf

# Sortie:
# a1b2c3d (Alice 2024-01-15) ssl_protocols TLSv1.2 TLSv1.3;
```

---

### 5. Passerelle CI/CD

Git est le déclencheur de l'automatisation moderne.

```bash
Push vers Git → Pipeline CI/CD → Déploiement Automatisé

Exemples:
- Push playbook Ansible → Auto-exécution sur serveurs
- Push Terraform → Auto-apply infrastructure
- Push changement config → Auto-déploiement en production
```

---

## Cas d'Usage pour SysAdmin

### Versionner les Configs /etc/

```bash
# Initialiser git dans /etc (prudence!)
cd /etc
sudo git init
sudo git add nginx/ ssh/
sudo git commit -m "Initial config snapshot"

# Après des changements
sudo git diff
sudo git commit -am "Harden SSH config"

# Oups, quelque chose est cassé?
sudo git checkout HEAD~1 -- ssh/sshd_config
sudo systemctl restart sshd
```

!!! tip "Utiliser etckeeper"
    `etckeeper` automatise le tracking Git de `/etc/`:

    ```bash
    sudo apt install etckeeper
    sudo etckeeper init
    # Maintenant /etc/ est auto-committé lors des changements de paquets
    ```

---

### Gérer les Playbooks Ansible

```text
ansible-repo/
├── inventory/
│   ├── production
│   └── staging
├── playbooks/
│   ├── webservers.yml
│   └── databases.yml
├── roles/
│   ├── nginx/
│   └── postgresql/
└── .gitignore
```

```bash
# .gitignore pour Ansible
*.retry
*.pyc
.vault_pass
inventory/secrets.yml
```

---

### State Terraform (Avec Précaution!)

```bash
# .gitignore pour Terraform
*.tfstate
*.tfstate.*
.terraform/
*.tfvars      # Peut contenir des secrets!

# À commiter
*.tf
terraform.lock.hcl
```

!!! warning "Fichiers State"
    **Ne jamais commiter tfstate dans Git!**

    Utiliser des backends distants à la place:

    - S3 + DynamoDB (AWS)
    - Azure Blob Storage
    - Terraform Cloud

---

### Bibliothèque de Scripts

```text
scripts/
├── backup/
│   ├── mysql_backup.sh
│   └── files_backup.sh
├── monitoring/
│   ├── check_disk.sh
│   └── check_services.sh
├── maintenance/
│   ├── cleanup_logs.sh
│   └── rotate_certs.sh
└── README.md
```

---

## Commandes Git Essentielles pour SysOps

```bash
# Configuration
git config --global user.name "Votre Nom"
git config --global user.email "vous@exemple.com"

# Workflow quotidien
git status              # Qu'est-ce qui a changé?
git diff               # Afficher les changements
git add .              # Stager tout
git commit -m "msg"    # Commit
git push               # Upload

# Voir l'historique
git log --oneline      # Historique compact
git log -p             # Avec les diffs
git blame file         # Qui a changé quoi

# Annuler des erreurs
git checkout -- file   # Abandonner les changements locaux
git reset HEAD~1       # Annuler le dernier commit (garder changements)
git revert abc123      # Créer un commit d'annulation

# Branches
git branch feature     # Créer une branche
git checkout feature   # Basculer vers une branche
git checkout -b feature # Créer + basculer
git merge feature      # Fusionner dans la branche actuelle

# Remote
git clone URL          # Télécharger le repo
git pull               # Récupérer la dernière version
git push               # Upload les changements
git remote -v          # Afficher les remotes
```

---

## Référence Rapide

| Commande | Objectif |
|---------|---------|
| `git init` | Initialiser nouveau repo |
| `git clone <url>` | Copier un repo distant |
| `git status` | Afficher l'état actuel |
| `git add .` | Stager tous les changements |
| `git commit -m "msg"` | Sauvegarder un snapshot |
| `git push` | Upload vers le remote |
| `git pull` | Télécharger depuis le remote |
| `git log --oneline` | Voir l'historique |
| `git diff` | Afficher changements non stagés |
| `git checkout -- <file>` | Abandonner les changements |
| `git branch <name>` | Créer une branche |
| `git merge <branch>` | Fusionner une branche |
| `git blame <file>` | Afficher l'historique des lignes |

---

!!! success "Commencer Aujourd'hui"
    Vous n'avez pas besoin d'être développeur pour bénéficier de Git.

    1. Choisir un répertoire (scripts, configs)
    2. `git init`
    3. En faire une habitude: changement → commit → push
    4. Se remercier dans 6 mois
