---
tags:
  - formation
  - python
  - installation
  - venv
---

# Module 01 - Environnement Python

Installer et configurer un environnement Python professionnel.

---

## Objectifs du Module

- Installer Python sur Linux et Windows
- Comprendre et utiliser les environnements virtuels
- Maîtriser pip et la gestion des dépendances
- Configurer un IDE adapté au SysOps

---

## 1. Installation de Python

### Linux (RHEL/Rocky/Fedora)

```bash
# Python est souvent préinstallé
python3 --version

# Si besoin d'installer
sudo dnf install python3 python3-pip python3-devel

# Installer une version spécifique (avec pyenv)
curl https://pyenv.run | bash
pyenv install 3.12.0
pyenv global 3.12.0
```

### Linux (Debian/Ubuntu)

```bash
sudo apt update
sudo apt install python3 python3-pip python3-venv

# Version spécifique
sudo add-apt-repository ppa:deadsnakes/ppa
sudo apt install python3.12 python3.12-venv
```

### Windows

```powershell
# Via winget
winget install Python.Python.3.12

# Ou télécharger depuis python.org
# Cocher "Add Python to PATH" lors de l'installation

# Vérifier
python --version
pip --version
```

### Vérification de l'Installation

```bash
# Version Python
python3 --version
# Python 3.12.0

# Version pip
pip3 --version
# pip 23.3.1 from /usr/lib/python3.12/site-packages/pip

# Chemin de l'interpréteur
which python3
# /usr/bin/python3
```

---

## 2. Environnements Virtuels

### Pourquoi des Environnements Virtuels ?

| Problème | Solution |
|----------|----------|
| Conflits de versions entre projets | Isolation des dépendances |
| Pollution du système | Packages installés localement |
| Reproductibilité | requirements.txt versionné |
| Permissions root | Installation sans sudo |

### Créer et Utiliser un venv

```bash
# Créer un environnement virtuel
python3 -m venv mon_projet_venv

# Activer (Linux/macOS)
source mon_projet_venv/bin/activate

# Activer (Windows PowerShell)
.\mon_projet_venv\Scripts\Activate.ps1

# Activer (Windows CMD)
mon_projet_venv\Scripts\activate.bat

# Vérifier l'activation
which python    # Doit pointer vers le venv
pip list        # Liste vide ou presque

# Désactiver
deactivate
```

### Structure d'un venv

```text
mon_projet_venv/
├── bin/                    # Scripts (activate, pip, python)
│   ├── activate
│   ├── pip
│   └── python -> python3.12
├── include/                # Headers C (pour compilation)
├── lib/
│   └── python3.12/
│       └── site-packages/  # Packages installés
└── pyvenv.cfg              # Configuration du venv
```

### Bonnes Pratiques venv

```bash
# Convention de nommage
python3 -m venv .venv       # Dans le répertoire du projet

# Ajouter au .gitignore
echo ".venv/" >> .gitignore
echo "__pycache__/" >> .gitignore
echo "*.pyc" >> .gitignore

# Script d'activation rapide dans ~/.bashrc
alias activate='source .venv/bin/activate'
```

---

## 3. Gestion des Dépendances avec pip

### Commandes de Base

```bash
# Installer un package
pip install requests

# Installer une version spécifique
pip install requests==2.31.0
pip install "requests>=2.28,<3.0"

# Mettre à jour
pip install --upgrade requests

# Désinstaller
pip uninstall requests

# Lister les packages installés
pip list
pip list --outdated

# Informations sur un package
pip show requests
```

### requirements.txt

```bash
# Générer le fichier des dépendances
pip freeze > requirements.txt

# Installer depuis requirements.txt
pip install -r requirements.txt

# Exemple de requirements.txt bien structuré
cat requirements.txt
```

```txt
# requirements.txt
# Core
requests>=2.31.0
pyyaml>=6.0

# AWS
boto3>=1.28.0

# SSH/Remote
paramiko>=3.3.0
fabric>=3.2.0

# CLI
click>=8.1.0
rich>=13.5.0

# Dev (optionnel)
# pytest>=7.4.0
# black>=23.9.0
```

### Fichiers de Dépendances Multiples

```bash
# Structure recommandée
requirements/
├── base.txt        # Dépendances de production
├── dev.txt         # Outils de développement
└── test.txt        # Dépendances de test
```

```txt
# requirements/dev.txt
-r base.txt
pytest>=7.4.0
black>=23.9.0
flake8>=6.1.0
mypy>=1.5.0
```

```bash
# Installer l'environnement de dev
pip install -r requirements/dev.txt
```

---

## 4. Le REPL Python

### Utilisation Interactive

```python
# Lancer le REPL
python3

>>> # Calculs rapides
>>> 2 ** 10
1024

>>> # Tester du code
>>> import os
>>> os.getcwd()
'/home/user'

>>> # Aide intégrée
>>> help(str.split)

>>> # Lister les méthodes
>>> dir(str)

>>> # Quitter
>>> exit()
# ou Ctrl+D (Linux) / Ctrl+Z (Windows)
```

### IPython - REPL Amélioré

```bash
# Installer
pip install ipython

# Lancer
ipython
```

```python
In [1]: # Autocomplétion avec Tab
In [1]: import os
In [2]: os.pa<TAB>
        os.path   os.pathconf   os.pathconf_names

In [3]: # Historique avec flèches
In [4]: # Aide avec ?
In [4]: os.path.join?

In [5]: # Code source avec ??
In [5]: os.path.join??

In [6]: # Magic commands
In [6]: %timeit sum(range(1000))
In [7]: %history
In [8]: %pwd
```

---

## 5. Configuration de l'IDE

### VS Code (Recommandé)

```bash
# Installer VS Code
# https://code.visualstudio.com/

# Extensions essentielles
code --install-extension ms-python.python
code --install-extension ms-python.vscode-pylance
code --install-extension ms-python.black-formatter
```

**settings.json** pour Python :

```json
{
    "python.defaultInterpreterPath": "${workspaceFolder}/.venv/bin/python",
    "python.formatting.provider": "black",
    "python.linting.enabled": true,
    "python.linting.flake8Enabled": true,
    "editor.formatOnSave": true,
    "[python]": {
        "editor.tabSize": 4,
        "editor.insertSpaces": true
    }
}
```

### PyCharm

```bash
# Community Edition (gratuit)
# https://www.jetbrains.com/pycharm/

# Configuration venv automatique
# File > Settings > Project > Python Interpreter
# Add Interpreter > Add Local Interpreter > Virtualenv
```

### Vim/Neovim

```vim
" ~/.vimrc ou ~/.config/nvim/init.vim

" Plugin python
Plug 'python-mode/python-mode', { 'for': 'python', 'branch': 'develop' }

" Autocomplétion
Plug 'neoclide/coc.nvim', {'branch': 'release'}
" :CocInstall coc-pyright

" Configuration
set tabstop=4
set shiftwidth=4
set expandtab
set autoindent
```

---

## 6. Structure d'un Projet Python

### Structure Minimale

```text
mon_projet/
├── .venv/                  # Environnement virtuel (gitignore)
├── .gitignore
├── README.md
├── requirements.txt
└── main.py                 # Script principal
```

### Structure Complète

```text
mon_projet/
├── .venv/
├── .git/
├── .gitignore
├── README.md
├── requirements/
│   ├── base.txt
│   ├── dev.txt
│   └── test.txt
├── src/
│   └── mon_projet/
│       ├── __init__.py
│       ├── main.py
│       ├── config.py
│       └── utils/
│           ├── __init__.py
│           └── helpers.py
├── tests/
│   ├── __init__.py
│   ├── test_main.py
│   └── conftest.py
├── scripts/
│   └── deploy.py
├── pyproject.toml          # Configuration moderne
└── setup.py                # Installation (legacy)
```

### .gitignore Python

```gitignore
# Environnement virtuel
.venv/
venv/
ENV/

# Bytecode
__pycache__/
*.py[cod]
*$py.class

# Distribution
dist/
build/
*.egg-info/

# IDE
.idea/
.vscode/
*.swp

# Logs et données locales
*.log
.env
*.sqlite3

# Tests
.pytest_cache/
.coverage
htmlcov/
```

---

## Exercices Pratiques

### Exercice 1 : Installation et Vérification

```bash
# 1. Vérifier votre version Python
# 2. Créer un répertoire python-sysops-labs
# 3. Créer un environnement virtuel .venv
# 4. Activer l'environnement
# 5. Installer requests et pyyaml
# 6. Générer requirements.txt
# 7. Vérifier avec pip list
```

### Exercice 2 : Explorer le REPL

```python
# Dans le REPL Python :
# 1. Importer le module os
# 2. Afficher le répertoire courant
# 3. Lister les variables d'environnement
# 4. Utiliser help() sur os.listdir
# 5. Lister tous les attributs de os.path avec dir()
```

### Exercice 3 : Premier Script

Créer `hello_sysops.py` :

```python
#!/usr/bin/env python3
"""Premier script Python pour SysOps."""

import os
import platform

def main():
    print("=== Informations Système ===")
    print(f"Hostname: {platform.node()}")
    print(f"OS: {platform.system()} {platform.release()}")
    print(f"Python: {platform.python_version()}")
    print(f"User: {os.getenv('USER', os.getenv('USERNAME', 'unknown'))}")
    print(f"CWD: {os.getcwd()}")

if __name__ == "__main__":
    main()
```

```bash
# Exécuter
python hello_sysops.py

# Rendre exécutable (Linux)
chmod +x hello_sysops.py
./hello_sysops.py
```

---

## Points Clés à Retenir

!!! success "Bonnes Pratiques"
    - Toujours utiliser un environnement virtuel
    - Versionner requirements.txt
    - Un venv par projet
    - Activer le venv avant de travailler

!!! warning "Erreurs Courantes"
    - Installer des packages en global (`sudo pip install`)
    - Oublier d'activer le venv
    - Ne pas versionner les dépendances
    - Utiliser Python 2 (EOL depuis 2020)

---

## Voir Aussi

- [Module 02 - Syntaxe de Base](02-syntaxe.md)
- [Python Fondamentaux](../../python/fundamentals.md)

---

## Navigation

| | |
|:---|---:|
| [← Programme](index.md) | [Module 02 - Syntaxe de Base →](02-syntaxe.md) |

[Retour au Programme](index.md){ .md-button }
