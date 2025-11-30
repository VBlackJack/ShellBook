---
tags:
  - formation
  - python
  - cli
  - argparse
  - click
  - rich
---

# Module 13 - Création d'Outils CLI

Créer des interfaces en ligne de commande professionnelles.

---

## Objectifs du Module

- Maîtriser argparse pour les CLI basiques
- Utiliser Click pour des CLI avancées
- Formater les sorties avec Rich
- Créer des outils interactifs

---

## 1. argparse - La Bibliothèque Standard

### CLI Simple

```python
#!/usr/bin/env python3
import argparse

def main():
    parser = argparse.ArgumentParser(
        description="Outil de gestion de serveurs"
    )

    parser.add_argument(
        "server",
        help="Nom ou IP du serveur"
    )

    parser.add_argument(
        "-p", "--port",
        type=int,
        default=22,
        help="Port SSH (défaut: 22)"
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Mode verbeux"
    )

    args = parser.parse_args()

    print(f"Connexion à {args.server}:{args.port}")
    if args.verbose:
        print("Mode verbeux activé")

if __name__ == "__main__":
    main()

# Usage:
# python script.py web01 -p 2222 -v
# python script.py --help
```

### Types d'Arguments

```python
import argparse

parser = argparse.ArgumentParser()

# Argument positionnel obligatoire
parser.add_argument("filename")

# Argument optionnel avec valeur par défaut
parser.add_argument("-n", "--number", type=int, default=10)

# Flag booléen
parser.add_argument("-v", "--verbose", action="store_true")
parser.add_argument("-q", "--quiet", action="store_false", dest="verbose")

# Compteur (-vvv = 3)
parser.add_argument("-v", "--verbose", action="count", default=0)

# Choix limités
parser.add_argument(
    "-f", "--format",
    choices=["json", "yaml", "csv"],
    default="json"
)

# Liste de valeurs
parser.add_argument(
    "-H", "--host",
    action="append",
    help="Ajouter un host (peut être répété)"
)
# Usage: -H host1 -H host2

# Plusieurs valeurs en une fois
parser.add_argument(
    "files",
    nargs="+",  # Au moins un
    help="Fichiers à traiter"
)
# Usage: script.py file1.txt file2.txt

# Valeur optionnelle (0 ou 1)
parser.add_argument(
    "-c", "--config",
    nargs="?",
    const="config.yml",
    default=None
)

# Argument requis
parser.add_argument("-t", "--token", required=True)
```

### Sous-commandes

```python
import argparse

def cmd_start(args):
    print(f"Starting {args.service}")

def cmd_stop(args):
    print(f"Stopping {args.service}")

def cmd_status(args):
    print(f"Status of {args.service}")

parser = argparse.ArgumentParser(prog="sysctl")
subparsers = parser.add_subparsers(dest="command", help="Commandes disponibles")

# Sous-commande start
start_parser = subparsers.add_parser("start", help="Démarrer un service")
start_parser.add_argument("service", help="Nom du service")
start_parser.set_defaults(func=cmd_start)

# Sous-commande stop
stop_parser = subparsers.add_parser("stop", help="Arrêter un service")
stop_parser.add_argument("service")
stop_parser.add_argument("-f", "--force", action="store_true")
stop_parser.set_defaults(func=cmd_stop)

# Sous-commande status
status_parser = subparsers.add_parser("status", help="Afficher le statut")
status_parser.add_argument("service", nargs="?", default="all")
status_parser.set_defaults(func=cmd_status)

args = parser.parse_args()

if hasattr(args, "func"):
    args.func(args)
else:
    parser.print_help()

# Usage:
# python sysctl.py start nginx
# python sysctl.py stop nginx --force
# python sysctl.py status
```

---

## 2. Click - CLI Moderne

### Installation

```bash
pip install click
```

### CLI Basique avec Click

```python
import click

@click.command()
@click.argument("name")
@click.option("-c", "--count", default=1, help="Nombre de salutations")
@click.option("-v", "--verbose", is_flag=True, help="Mode verbeux")
def hello(name, count, verbose):
    """Programme de salutation simple."""
    for _ in range(count):
        if verbose:
            click.echo(f"Bonjour très cher {name}!")
        else:
            click.echo(f"Bonjour {name}!")

if __name__ == "__main__":
    hello()
```

### Options et Arguments

```python
import click

@click.command()
# Arguments positionnels
@click.argument("source", type=click.Path(exists=True))
@click.argument("dest", type=click.Path())

# Options avec types
@click.option("-p", "--port", type=int, default=8080)
@click.option("-H", "--host", default="localhost")

# Choix
@click.option(
    "-f", "--format",
    type=click.Choice(["json", "yaml", "xml"]),
    default="json"
)

# Flags
@click.option("-v", "--verbose", is_flag=True)
@click.option("-q", "--quiet", is_flag=True)

# Multiple valeurs
@click.option("-t", "--tag", multiple=True)

# Prompt pour entrée
@click.option("--password", prompt=True, hide_input=True)

# Confirmation
@click.option("--yes", is_flag=True, expose_value=False, callback=confirm_callback)

# Fichier
@click.option("-o", "--output", type=click.File("w"), default="-")

def deploy(source, dest, port, host, format, verbose, quiet, tag, password, output):
    """Déploie une application."""
    click.echo(f"Deploying {source} to {dest}")
    click.echo(f"Tags: {tag}")
```

### Groupes de Commandes

```python
import click

@click.group()
@click.option("-v", "--verbose", is_flag=True)
@click.pass_context
def cli(ctx, verbose):
    """Outil de gestion de serveurs."""
    ctx.ensure_object(dict)
    ctx.obj["VERBOSE"] = verbose

@cli.command()
@click.argument("name")
@click.option("-t", "--type", default="web")
@click.pass_context
def create(ctx, name, type):
    """Crée un nouveau serveur."""
    if ctx.obj["VERBOSE"]:
        click.echo(f"Création du serveur {name} de type {type}...")
    click.echo(f"Serveur {name} créé!")

@cli.command()
@click.argument("name")
@click.option("-f", "--force", is_flag=True)
@click.pass_context
def delete(ctx, name, force):
    """Supprime un serveur."""
    if not force:
        click.confirm(f"Vraiment supprimer {name}?", abort=True)
    click.echo(f"Serveur {name} supprimé!")

@cli.command("list")
@click.option("--format", type=click.Choice(["table", "json"]), default="table")
def list_servers(format):
    """Liste les serveurs."""
    servers = ["web01", "web02", "db01"]
    if format == "json":
        import json
        click.echo(json.dumps(servers))
    else:
        for s in servers:
            click.echo(f"  - {s}")

if __name__ == "__main__":
    cli()

# Usage:
# python server.py --verbose create myserver -t database
# python server.py delete myserver --force
# python server.py list --format json
```

### Validation et Callbacks

```python
import click

def validate_port(ctx, param, value):
    """Valide que le port est dans la plage autorisée."""
    if value < 1 or value > 65535:
        raise click.BadParameter("Port doit être entre 1 et 65535")
    return value

def validate_hostname(ctx, param, value):
    """Valide le format du hostname."""
    import re
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9\-\.]*$', value):
        raise click.BadParameter("Hostname invalide")
    return value

@click.command()
@click.option("-p", "--port", type=int, callback=validate_port, default=8080)
@click.option("-H", "--host", callback=validate_hostname, required=True)
def connect(port, host):
    click.echo(f"Connexion à {host}:{port}")
```

---

## 3. Rich - Formatage Avancé

### Installation

```bash
pip install rich
```

### Sortie Colorée

```python
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

console = Console()

# Couleurs et styles
console.print("Texte normal")
console.print("[bold red]Erreur![/bold red] Quelque chose s'est mal passé")
console.print("[green]Succès[/green] - Opération terminée")
console.print("[bold blue]Info:[/bold blue] Version 1.0.0")

# Styles combinés
console.print("[bold italic yellow on red]Attention![/bold italic yellow on red]")

# Emojis
console.print(":rocket: Déploiement en cours...")
console.print(":white_check_mark: Terminé!")
console.print(":x: Échec!")

# Panel
console.print(Panel("Contenu important", title="Titre", border_style="green"))

# Règles
console.rule("[bold red]Section")
```

### Tableaux

```python
from rich.console import Console
from rich.table import Table

console = Console()

# Tableau simple
table = Table(title="Serveurs")
table.add_column("Nom", style="cyan", no_wrap=True)
table.add_column("IP", style="magenta")
table.add_column("Status", justify="center")
table.add_column("CPU", justify="right")

table.add_row("web01", "192.168.1.10", "[green]Running[/green]", "23%")
table.add_row("web02", "192.168.1.11", "[green]Running[/green]", "45%")
table.add_row("db01", "192.168.1.20", "[red]Stopped[/red]", "0%")

console.print(table)

# Tableau depuis données
def show_processes(processes):
    table = Table(title="Processus")
    table.add_column("PID")
    table.add_column("Nom")
    table.add_column("CPU %")
    table.add_column("Mémoire")

    for proc in processes:
        table.add_row(
            str(proc["pid"]),
            proc["name"],
            f"{proc['cpu']:.1f}%",
            f"{proc['memory']} MB"
        )

    console.print(table)
```

### Barre de Progression

```python
from rich.console import Console
from rich.progress import (
    Progress,
    SpinnerColumn,
    BarColumn,
    TextColumn,
    TimeRemainingColumn,
    TaskProgressColumn
)
import time

console = Console()

# Progress bar simple
from rich.progress import track

for item in track(range(100), description="Processing..."):
    time.sleep(0.02)

# Progress bar personnalisée
with Progress(
    SpinnerColumn(),
    TextColumn("[bold blue]{task.description}"),
    BarColumn(),
    TaskProgressColumn(),
    TimeRemainingColumn(),
) as progress:
    task1 = progress.add_task("Téléchargement...", total=100)
    task2 = progress.add_task("Installation...", total=100)

    while not progress.finished:
        progress.update(task1, advance=0.9)
        progress.update(task2, advance=0.5)
        time.sleep(0.02)

# Multiple tasks
with Progress() as progress:
    tasks = {
        "web01": progress.add_task("[cyan]web01", total=100),
        "web02": progress.add_task("[cyan]web02", total=100),
        "db01": progress.add_task("[cyan]db01", total=100),
    }

    for server, task_id in tasks.items():
        for i in range(100):
            progress.update(task_id, advance=1)
            time.sleep(0.01)
```

### Logging avec Rich

```python
import logging
from rich.logging import RichHandler

# Configuration du logging avec Rich
logging.basicConfig(
    level=logging.DEBUG,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True)]
)

log = logging.getLogger("rich")

log.debug("Message de debug")
log.info("Information")
log.warning("Attention")
log.error("Erreur")

try:
    1/0
except Exception:
    log.exception("Exception capturée")
```

---

## 4. CLI Complète

### Structure de Projet

```
myapp/
├── myapp/
│   ├── __init__.py
│   ├── cli.py
│   ├── commands/
│   │   ├── __init__.py
│   │   ├── server.py
│   │   └── deploy.py
│   └── utils/
│       ├── __init__.py
│       └── config.py
├── setup.py
└── pyproject.toml
```

### CLI Professionnelle

```python
# myapp/cli.py
import click
from rich.console import Console
from rich.table import Table
import logging

console = Console()

# Configuration globale
class Config:
    def __init__(self):
        self.verbose = False
        self.config_file = None

pass_config = click.make_pass_decorator(Config, ensure=True)

@click.group()
@click.option("-v", "--verbose", is_flag=True, help="Mode verbeux")
@click.option("-c", "--config", type=click.Path(), help="Fichier de configuration")
@click.version_option(version="1.0.0")
@pass_config
def cli(config, verbose, config_file):
    """
    MyApp - Outil de gestion d'infrastructure

    Exemple d'utilisation:

        myapp server list
        myapp deploy --env production
    """
    config.verbose = verbose
    config.config_file = config_file

    if verbose:
        logging.basicConfig(level=logging.DEBUG)

# Commandes serveur
@cli.group()
def server():
    """Gestion des serveurs."""
    pass

@server.command("list")
@click.option("--format", type=click.Choice(["table", "json"]), default="table")
@pass_config
def server_list(config, format):
    """Liste tous les serveurs."""
    servers = [
        {"name": "web01", "ip": "192.168.1.10", "status": "running"},
        {"name": "web02", "ip": "192.168.1.11", "status": "running"},
        {"name": "db01", "ip": "192.168.1.20", "status": "stopped"},
    ]

    if format == "json":
        import json
        console.print_json(json.dumps(servers))
    else:
        table = Table(title="Serveurs")
        table.add_column("Nom", style="cyan")
        table.add_column("IP")
        table.add_column("Status")

        for s in servers:
            status_style = "green" if s["status"] == "running" else "red"
            table.add_row(
                s["name"],
                s["ip"],
                f"[{status_style}]{s['status']}[/{status_style}]"
            )

        console.print(table)

@server.command("start")
@click.argument("name")
@click.option("-w", "--wait", is_flag=True, help="Attendre le démarrage")
@pass_config
def server_start(config, name, wait):
    """Démarre un serveur."""
    with console.status(f"[bold green]Démarrage de {name}..."):
        import time
        time.sleep(2)  # Simulation

    console.print(f":white_check_mark: Serveur [cyan]{name}[/cyan] démarré!")

@server.command("stop")
@click.argument("name")
@click.option("-f", "--force", is_flag=True, help="Forcer l'arrêt")
@click.confirmation_option(prompt="Êtes-vous sûr de vouloir arrêter ce serveur?")
@pass_config
def server_stop(config, name, force):
    """Arrête un serveur."""
    console.print(f":stop_sign: Serveur [cyan]{name}[/cyan] arrêté!")

# Commande de déploiement
@cli.command()
@click.option("-e", "--env", type=click.Choice(["dev", "staging", "prod"]), required=True)
@click.option("-t", "--tag", help="Tag de la release")
@click.option("--dry-run", is_flag=True, help="Simulation sans déploiement")
@pass_config
def deploy(config, env, tag, dry_run):
    """Déploie l'application."""
    if dry_run:
        console.print("[yellow]Mode dry-run activé[/yellow]")

    from rich.progress import Progress

    with Progress() as progress:
        task = progress.add_task(f"[green]Déploiement {env}...", total=100)
        for i in range(100):
            import time
            time.sleep(0.02)
            progress.update(task, advance=1)

    console.print(f":rocket: Déployé sur [bold]{env}[/bold]!")

# Point d'entrée
def main():
    cli()

if __name__ == "__main__":
    main()
```

### Configuration setup.py

```python
# setup.py
from setuptools import setup, find_packages

setup(
    name="myapp",
    version="1.0.0",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "click>=8.0",
        "rich>=10.0",
    ],
    entry_points={
        "console_scripts": [
            "myapp=myapp.cli:main",
        ],
    },
)
```

---

## 5. Interactivité

### Prompts

```python
import click
from rich.console import Console
from rich.prompt import Prompt, Confirm, IntPrompt

console = Console()

# Click prompts
name = click.prompt("Votre nom")
password = click.prompt("Mot de passe", hide_input=True)
age = click.prompt("Âge", type=int, default=25)

if click.confirm("Continuer?"):
    click.echo("OK!")

# Rich prompts
name = Prompt.ask("Entrez votre nom")
name = Prompt.ask("Nom", default="Anonymous")
age = IntPrompt.ask("Âge", default=25)

if Confirm.ask("Voulez-vous continuer?"):
    console.print("Continuing...")

# Choix
choice = Prompt.ask(
    "Choisir un environnement",
    choices=["dev", "staging", "prod"],
    default="dev"
)
```

### Menu Interactif

```python
from rich.console import Console
from rich.prompt import Prompt
from rich.panel import Panel

console = Console()

def show_menu():
    console.clear()
    console.print(Panel.fit(
        "[bold cyan]Menu Principal[/bold cyan]\n\n"
        "[1] Lister les serveurs\n"
        "[2] Créer un serveur\n"
        "[3] Supprimer un serveur\n"
        "[4] Configuration\n"
        "[q] Quitter",
        title="MyApp v1.0"
    ))

    choice = Prompt.ask("Choix", choices=["1", "2", "3", "4", "q"])
    return choice

def main():
    while True:
        choice = show_menu()

        if choice == "q":
            console.print("Au revoir!")
            break
        elif choice == "1":
            list_servers()
        elif choice == "2":
            create_server()
        # etc.

        Prompt.ask("\nAppuyez sur Entrée pour continuer...")

if __name__ == "__main__":
    main()
```

---

## 6. Bonnes Pratiques

### Gestion des Erreurs

```python
import click
import sys

class CLIError(Exception):
    """Erreur CLI personnalisée."""
    pass

def handle_error(func):
    """Décorateur pour gérer les erreurs."""
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except CLIError as e:
            click.echo(f"Erreur: {e}", err=True)
            sys.exit(1)
        except Exception as e:
            click.echo(f"Erreur inattendue: {e}", err=True)
            sys.exit(2)
    return wrapper

@click.command()
@handle_error
def main():
    raise CLIError("Quelque chose s'est mal passé")
```

### Configuration par Fichier

```python
import click
import yaml
from pathlib import Path

def load_config(config_file=None):
    """Charge la configuration depuis un fichier."""
    paths = [
        config_file,
        Path.home() / ".myapprc",
        Path("/etc/myapp/config.yml"),
    ]

    for path in paths:
        if path and Path(path).exists():
            with open(path) as f:
                return yaml.safe_load(f)

    return {}

@click.command()
@click.option("-c", "--config", type=click.Path(exists=True))
def main(config):
    cfg = load_config(config)
    click.echo(f"Loaded config: {cfg}")
```

---

## Exercices Pratiques

### Exercice 1 : Outil de Backup

```python
# Créer un CLI qui :
# - Accepte source et destination
# - Option pour compresser
# - Barre de progression
# - Log des opérations
```

### Exercice 2 : Gestionnaire de Services

```python
# Créer un CLI avec sous-commandes :
# - start/stop/restart/status
# - Liste des services avec statut coloré
# - Confirmation pour les actions destructives
```

### Exercice 3 : Dashboard Interactif

```python
# Créer un outil qui :
# - Affiche un dashboard de monitoring
# - Rafraîchissement automatique
# - Navigation au clavier
```

---

## Points Clés à Retenir

!!! success "Bonnes Pratiques"
    - Utiliser des noms de commandes clairs
    - Fournir une aide complète (--help)
    - Valider les entrées utilisateur
    - Gérer les erreurs proprement
    - Utiliser des codes de sortie appropriés

!!! warning "Pièges Courants"
    - Oublier le shebang (`#!/usr/bin/env python3`)
    - Ne pas gérer Ctrl+C proprement
    - Sorties non formatées pour les scripts
    - Absence de mode verbose/quiet

---

## Voir Aussi

- [Module 12 - SSH & Automatisation](12-ssh.md)
- [Module 14 - Cloud & AWS](14-cloud.md)
- [Cheatsheet Bibliothèques](cheatsheet-libs.md)
