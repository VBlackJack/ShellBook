# Fondamentaux d'Ansible

`#ansible` `#iac` `#python` `#ssh`

Infrastructure as Code sans agents.

---

## Concepts Fondamentaux (Le "Pourquoi")

### Architecture Sans Agent

**Aucun logiciel à installer sur les cibles.** Ansible utilise SSH (Linux) ou WinRM (Windows).

```
┌─────────────────┐         SSH          ┌─────────────────┐
│  Control Node   │ ──────────────────►  │  Managed Node   │
│  (Ansible)      │                      │  (Just SSH)     │
└─────────────────┘                      └─────────────────┘
```

| Ansible | Chef/Puppet |
|---------|-------------|
| Sans agent (SSH) | Nécessite un agent |
| Modèle push | Modèle pull |
| Python sur le contrôleur | Écosystème Ruby |
| YAML simple | DSL à apprendre |

---

### Push vs Pull

**Push (Ansible):** Vous décidez quand appliquer les changements.

```bash
# Vous exécutez ceci quand vous êtes prêt
ansible-playbook deploy.yml
```

**Pull (Puppet/Chef):** Les agents interrogent périodiquement les changements.

```
L'agent vérifie toutes les 30min → applique la dérive
```

!!! tip "Push = Contrôle"
    Le modèle push vous donne un contrôle explicite sur **quand** les changements se produisent.
    Pas de mises à jour surprises à 3h du matin.

---

### Idempotence (Concept Critique)

!!! important "Exécuter deux fois = même résultat"
    Une task idempotente ne fait des changements que si nécessaire.

    ```yaml
    # Première exécution : installe nginx
    # Deuxième exécution : "ok" (déjà installé, aucun changement)
    - name: Install nginx
      apt:
        name: nginx
        state: present
    ```

**Pourquoi c'est important :**

- Réexécuter les playbooks en toute sécurité
- Auto-réparation (correction de la dérive)
- Pas de désastre "oups je l'ai exécuté deux fois"

**Non-idempotent (dangereux) :**

```yaml
# MAUVAIS : Ajoute à chaque exécution !
- name: Add line to file
  shell: echo "config=value" >> /etc/app.conf

# BON : N'ajoute que si absent
- name: Add line to file
  lineinfile:
    path: /etc/app.conf
    line: "config=value"
```

---

## Installation & Configuration

### Installer Ansible

```bash
# Recommandé : pip (dernière version)
pip install ansible

# Ou avec pipx (isolé)
pipx install ansible

# Vérifier
ansible --version
```

!!! warning "Évitez apt/yum pour Ansible"
    Les paquets de distribution sont souvent obsolètes.
    Utilisez `pip` pour les dernières fonctionnalités et modules.

---

### Fichier Inventory (`hosts`)

Listez vos serveurs gérés. Supporte le format INI ou YAML.

**Format INI (simple) :**

```ini
# inventory/hosts

[webservers]
web1.example.com
web2.example.com
192.168.1.10

[databases]
db1.example.com ansible_user=postgres
db2.example.com

[production:children]
webservers
databases

[all:vars]
ansible_user=deploy
ansible_python_interpreter=/usr/bin/python3
```

**Format YAML :**

```yaml
# inventory/hosts.yml
all:
  children:
    webservers:
      hosts:
        web1.example.com:
        web2.example.com:
    databases:
      hosts:
        db1.example.com:
          ansible_user: postgres
        db2.example.com:
  vars:
    ansible_user: deploy
```

---

### Configuration (`ansible.cfg`)

Placer à la racine du projet ou dans `~/.ansible.cfg`.

```ini
# ansible.cfg
[defaults]
inventory = ./inventory/hosts
remote_user = deploy
private_key_file = ~/.ssh/id_ed25519
host_key_checking = False
retry_files_enabled = False
gathering = smart
fact_caching = jsonfile
fact_caching_connection = /tmp/ansible_facts

[privilege_escalation]
become = True
become_method = sudo
become_user = root
become_ask_pass = False

[ssh_connection]
pipelining = True
control_path = /tmp/ansible-%%h-%%r
```

| Paramètre | Objectif |
|---------|---------|
| `host_key_checking = False` | Ignorer les invites SSH "Are you sure?" |
| `pipelining = True` | Exécution plus rapide (moins de connexions SSH) |
| `gathering = smart` | Mettre en cache les facts, ne pas les collecter à chaque fois |

!!! warning "host_key_checking"
    Désactiver est pratique pour l'automatisation mais réduit la sécurité.
    En production, utilisez plutôt la gestion de `known_hosts`.

---

## Authentification (SSH)

Ansible utilise vos clés SSH. Aucune configuration spéciale nécessaire.

### Préparer l'accès SSH

```bash
# Générer une clé si nécessaire
ssh-keygen -t ed25519 -C "ansible@control"

# Copier vers tous les nœuds gérés
ssh-copy-id user@web1.example.com
ssh-copy-id user@web2.example.com
ssh-copy-id user@db1.example.com

# Tester l'accès SSH
ssh user@web1.example.com "hostname"
```

### Tester la connexion Ansible

```bash
# Le "Hello World" d'Ansible
ansible all -m ping -i inventory/hosts

# Sortie :
# web1.example.com | SUCCESS => {
#     "changed": false,
#     "ping": "pong"
# }
```

!!! tip "Sudo sans mot de passe"
    Pour que `become` (sudo) fonctionne sans invites :

    ```bash
    # Sur les serveurs cibles, ajouter dans /etc/sudoers.d/ansible
    deploy ALL=(ALL) NOPASSWD: ALL
    ```

---

## Commandes Ad-Hoc (La CLI)

Exécuter des commandes ponctuelles sans écrire de playbook.

### Syntaxe

```bash
ansible <pattern> -m <module> -a "<arguments>" [options]
```

### Exemples Essentiels

```bash
# Ping tous les hôtes
ansible all -m ping

# Exécuter une commande shell
ansible all -m shell -a "uptime"
ansible webservers -m shell -a "df -h"

# Vérifier la mémoire sur les bases de données
ansible databases -m shell -a "free -m"

# Installer un paquet (avec sudo)
ansible webservers -m apt -a "name=nginx state=present" --become

# Démarrer un service
ansible webservers -m service -a "name=nginx state=started enabled=yes" --become

# Copier un fichier
ansible all -m copy -a "src=/local/file.conf dest=/etc/app/file.conf" --become

# Créer un utilisateur
ansible all -m user -a "name=deploy state=present" --become

# Collecter les facts
ansible web1.example.com -m setup

# Redémarrer les serveurs (prudence !)
ansible webservers -m reboot --become
```

### Cibler les hôtes

```bash
# Tous les hôtes
ansible all -m ping

# Groupe spécifique
ansible webservers -m ping

# Plusieurs groupes
ansible 'webservers:databases' -m ping

# Exclure un groupe
ansible 'all:!databases' -m ping

# Hôte unique
ansible web1.example.com -m ping

# Correspondance de motif
ansible '*.example.com' -m ping
ansible 'web*' -m ping
```

### Options Courantes

| Option | Objectif |
|--------|---------|
| `-i <inventory>` | Spécifier le fichier inventory |
| `-m <module>` | Module à utiliser |
| `-a "<args>"` | Arguments du module |
| `--become` / `-b` | Utiliser sudo |
| `--become-user` | Sudo vers un utilisateur spécifique |
| `-k` | Demander le mot de passe SSH |
| `-K` | Demander le mot de passe sudo |
| `-v` / `-vvv` | Sortie verbeuse |
| `--check` | Dry run (aucun changement) |
| `--diff` | Afficher les changements de fichiers |

---

## Référence Rapide

```bash
# Tester la connectivité
ansible all -m ping

# Exécuter une commande
ansible all -m shell -a "command"

# Installer un paquet
ansible all -m apt -a "name=pkg state=present" -b

# Copier un fichier
ansible all -m copy -a "src=X dest=Y" -b

# Démarrer un service
ansible all -m service -a "name=X state=started" -b

# Collecter les facts
ansible host -m setup

# Dry run
ansible-playbook playbook.yml --check --diff
```

---

## Structure de Projet (Bonne Pratique)

```
ansible-project/
├── ansible.cfg
├── inventory/
│   ├── production
│   └── staging
├── group_vars/
│   ├── all.yml
│   ├── webservers.yml
│   └── databases.yml
├── host_vars/
│   └── web1.example.com.yml
├── playbooks/
│   ├── site.yml
│   ├── webservers.yml
│   └── databases.yml
└── roles/
    ├── common/
    ├── nginx/
    └── postgresql/
```
