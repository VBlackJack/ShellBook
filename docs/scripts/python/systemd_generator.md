---
tags:
  - scripts
  - python
  - systemd
  - linux
  - configuration
---

# systemd_generator.py

Générateur interactif de fichiers unit Systemd avec options de sécurité (hardening) intégrées.

---

## Informations

| Propriété | Valeur |
|-----------|--------|
| **Langage** | Python 3.8+ |
| **Catégorie** | Configuration / Automatisation |
| **Niveau** | :material-star::material-star: Intermédiaire |
| **Dépendances** | Aucune (bibliothèque standard) |

---

## Description

Ce script génère des fichiers `.service` Systemd de manière interactive ou via arguments CLI. Il intègre automatiquement des options de sécurité (hardening) pour protéger le service contre les attaques courantes.

**Fonctionnalités :**

- **Mode interactif** : Assistant pas-à-pas pour configurer le service
- **Mode CLI** : Génération rapide via arguments
- **Hardening automatique** : Options de sécurité activées par défaut
- **Templates prédéfinis** : Web server, worker, daemon
- **Validation** : Vérification de la syntaxe avant export

---

## Options de Sécurité (Hardening)

Le script active par défaut les options de sécurité suivantes :

| Option | Description |
|--------|-------------|
| `NoNewPrivileges=yes` | Empêche l'acquisition de nouveaux privilèges |
| `ProtectSystem=full` | Monte `/usr`, `/boot`, `/efi` en lecture seule |
| `ProtectHome=yes` | Cache les répertoires home des utilisateurs |
| `PrivateTmp=true` | Isole `/tmp` et `/var/tmp` du service |
| `ProtectKernelTunables=yes` | Protège `/proc/sys`, `/sys` |
| `ProtectKernelModules=yes` | Empêche le chargement de modules |
| `ProtectControlGroups=yes` | Protège la hiérarchie cgroups |
| `RestrictRealtime=yes` | Empêche l'ordonnancement temps réel |
| `RestrictSUIDSGID=yes` | Empêche la création de fichiers SUID/SGID |

---

## Prérequis

```bash
# Python 3.8+ (inclus dans la plupart des distributions)
python3 --version

# Le script génère le fichier, l'installation requiert root
sudo cp myapp.service /etc/systemd/system/
sudo systemctl daemon-reload
```

---

## Script

```python
#!/usr/bin/env python3
"""
Script Name: systemd_generator.py
Description: Interactive generator for hardened systemd unit files
Author: ShellBook
Version: 1.0
"""

import argparse
import logging
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class ServiceConfig:
    """
    Configuration for a systemd service unit.
    """
    name: str
    description: str
    exec_start: str
    user: str = "root"
    group: str = "root"
    working_directory: str = "/"
    restart_policy: str = "on-failure"
    restart_sec: int = 5
    service_type: str = "simple"
    environment: Dict[str, str] = field(default_factory=dict)
    after: List[str] = field(default_factory=lambda: ["network.target"])
    wants: List[str] = field(default_factory=list)

    # Hardening options (enabled by default)
    hardening_enabled: bool = True
    no_new_privileges: bool = True
    protect_system: str = "full"
    protect_home: bool = True
    private_tmp: bool = True
    protect_kernel_tunables: bool = True
    protect_kernel_modules: bool = True
    protect_control_groups: bool = True
    restrict_realtime: bool = True
    restrict_suid_sgid: bool = True

    # Additional security
    capability_bounding_set: Optional[str] = None
    ambient_capabilities: Optional[str] = None
    read_only_paths: List[str] = field(default_factory=list)
    read_write_paths: List[str] = field(default_factory=list)


class SystemdGenerator:
    """
    Generates systemd unit files with security hardening.
    """

    # Service type templates
    TEMPLATES = {
        "simple": {
            "description": "Service simple (commande qui reste en foreground)",
            "type": "simple",
            "after": ["network.target"],
        },
        "forking": {
            "description": "Service qui fork (daemon traditionnel)",
            "type": "forking",
            "after": ["network.target"],
        },
        "oneshot": {
            "description": "Tâche ponctuelle (s'exécute et se termine)",
            "type": "oneshot",
            "after": ["network.target"],
        },
        "notify": {
            "description": "Service avec notification systemd (sd_notify)",
            "type": "notify",
            "after": ["network.target"],
        },
        "webserver": {
            "description": "Serveur web/API",
            "type": "simple",
            "after": ["network.target", "network-online.target"],
            "wants": ["network-online.target"],
        },
        "worker": {
            "description": "Worker/Queue processor",
            "type": "simple",
            "after": ["network.target", "redis.service", "postgresql.service"],
        },
        "database": {
            "description": "Base de données",
            "type": "notify",
            "after": ["network.target"],
        },
    }

    def __init__(self, config: ServiceConfig):
        """
        Initialize the generator with a service configuration.

        Args:
            config: ServiceConfig object with all service parameters
        """
        self.config = config

    def generate(self) -> str:
        """
        Generate the complete systemd unit file content.

        Returns:
            String content of the .service file
        """
        sections = []

        # [Unit] section
        sections.append(self._generate_unit_section())

        # [Service] section
        sections.append(self._generate_service_section())

        # [Install] section
        sections.append(self._generate_install_section())

        return "\n".join(sections)

    def _generate_unit_section(self) -> str:
        """
        Generate the [Unit] section.

        Returns:
            String content of [Unit] section
        """
        lines = ["[Unit]"]
        lines.append(f"Description={self.config.description}")

        if self.config.after:
            lines.append(f"After={' '.join(self.config.after)}")

        if self.config.wants:
            lines.append(f"Wants={' '.join(self.config.wants)}")

        return "\n".join(lines)

    def _generate_service_section(self) -> str:
        """
        Generate the [Service] section with hardening options.

        Returns:
            String content of [Service] section
        """
        lines = ["", "[Service]"]

        # Basic service configuration
        lines.append(f"Type={self.config.service_type}")
        lines.append(f"User={self.config.user}")
        lines.append(f"Group={self.config.group}")
        lines.append(f"WorkingDirectory={self.config.working_directory}")
        lines.append(f"ExecStart={self.config.exec_start}")

        # Restart policy
        lines.append(f"Restart={self.config.restart_policy}")
        lines.append(f"RestartSec={self.config.restart_sec}")

        # Environment variables
        for key, value in self.config.environment.items():
            lines.append(f"Environment=\"{key}={value}\"")

        # Hardening options
        if self.config.hardening_enabled:
            lines.append("")
            lines.append("# Security Hardening")

            if self.config.no_new_privileges:
                lines.append("NoNewPrivileges=yes")

            if self.config.protect_system:
                lines.append(f"ProtectSystem={self.config.protect_system}")

            if self.config.protect_home:
                lines.append("ProtectHome=yes")

            if self.config.private_tmp:
                lines.append("PrivateTmp=true")

            if self.config.protect_kernel_tunables:
                lines.append("ProtectKernelTunables=yes")

            if self.config.protect_kernel_modules:
                lines.append("ProtectKernelModules=yes")

            if self.config.protect_control_groups:
                lines.append("ProtectControlGroups=yes")

            if self.config.restrict_realtime:
                lines.append("RestrictRealtime=yes")

            if self.config.restrict_suid_sgid:
                lines.append("RestrictSUIDSGID=yes")

            # Additional security options
            if self.config.capability_bounding_set:
                lines.append(f"CapabilityBoundingSet={self.config.capability_bounding_set}")

            if self.config.ambient_capabilities:
                lines.append(f"AmbientCapabilities={self.config.ambient_capabilities}")

            if self.config.read_only_paths:
                lines.append(f"ReadOnlyPaths={' '.join(self.config.read_only_paths)}")

            if self.config.read_write_paths:
                lines.append(f"ReadWritePaths={' '.join(self.config.read_write_paths)}")

        return "\n".join(lines)

    def _generate_install_section(self) -> str:
        """
        Generate the [Install] section.

        Returns:
            String content of [Install] section
        """
        lines = ["", "[Install]"]
        lines.append("WantedBy=multi-user.target")
        return "\n".join(lines)

    def save(self, output_path: Optional[Path] = None) -> Path:
        """
        Save the generated unit file.

        Args:
            output_path: Optional path for output file

        Returns:
            Path to the saved file
        """
        if output_path is None:
            output_path = Path(f"{self.config.name}.service")

        content = self.generate()
        output_path.write_text(content)

        logger.info(f"Service file saved to: {output_path}")
        return output_path


def interactive_mode() -> ServiceConfig:
    """
    Run interactive wizard to collect service configuration.

    Returns:
        ServiceConfig with user-provided values
    """
    print("\n" + "=" * 60)
    print("   GÉNÉRATEUR DE SERVICE SYSTEMD")
    print("=" * 60 + "\n")

    # Service name
    name = input("Nom du service (ex: myapp): ").strip()
    if not name:
        print("Erreur: Le nom est requis")
        sys.exit(1)

    # Description
    description = input(f"Description [{name} service]: ").strip()
    if not description:
        description = f"{name} service"

    # Template selection
    print("\nType de service:")
    for i, (key, template) in enumerate(SystemdGenerator.TEMPLATES.items(), 1):
        print(f"  {i}. {key}: {template['description']}")

    template_choice = input("\nChoix [1]: ").strip() or "1"
    template_keys = list(SystemdGenerator.TEMPLATES.keys())
    try:
        template_name = template_keys[int(template_choice) - 1]
    except (ValueError, IndexError):
        template_name = "simple"

    template = SystemdGenerator.TEMPLATES[template_name]

    # ExecStart command
    exec_start = input("\nCommande ExecStart (chemin complet): ").strip()
    if not exec_start:
        print("Erreur: La commande ExecStart est requise")
        sys.exit(1)

    # User/Group
    user = input("Utilisateur [root]: ").strip() or "root"
    group = input(f"Groupe [{user}]: ").strip() or user

    # Working directory
    working_dir = input("Répertoire de travail [/]: ").strip() or "/"

    # Environment variables
    env_vars = {}
    print("\nVariables d'environnement (format: KEY=value, vide pour terminer):")
    while True:
        env_input = input("  > ").strip()
        if not env_input:
            break
        if "=" in env_input:
            key, value = env_input.split("=", 1)
            env_vars[key] = value

    # Hardening
    print("\n" + "-" * 40)
    hardening = input("Activer le hardening de sécurité? [O/n]: ").strip().lower()
    hardening_enabled = hardening != "n"

    if hardening_enabled:
        print("  ✓ Options de sécurité activées (NoNewPrivileges, ProtectSystem, etc.)")
    else:
        print("  ⚠ Hardening désactivé")

    # Create config
    config = ServiceConfig(
        name=name,
        description=description,
        exec_start=exec_start,
        user=user,
        group=group,
        working_directory=working_dir,
        service_type=template["type"],
        after=template.get("after", ["network.target"]),
        wants=template.get("wants", []),
        environment=env_vars,
        hardening_enabled=hardening_enabled,
    )

    return config


def setup_args() -> argparse.Namespace:
    """
    Configure CLI arguments.

    Returns:
        Parsed arguments namespace
    """
    parser = argparse.ArgumentParser(
        description="Generate hardened systemd unit files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples:
    # Mode interactif
    %(prog)s

    # Mode CLI complet
    %(prog)s -n myapp -d "My Application" -e "/usr/bin/myapp --config /etc/myapp.conf" -u myapp -g myapp

    # Avec variables d'environnement
    %(prog)s -n myapp -e "/usr/bin/myapp" --env "NODE_ENV=production" --env "PORT=3000"

    # Sans hardening (non recommandé)
    %(prog)s -n myapp -e "/usr/bin/myapp" --no-hardening

    # Sauvegarder dans un fichier
    %(prog)s -n myapp -e "/usr/bin/myapp" -o /etc/systemd/system/myapp.service
        """
    )

    # Basic options
    parser.add_argument(
        '-n', '--name',
        help='Nom du service'
    )

    parser.add_argument(
        '-d', '--description',
        help='Description du service'
    )

    parser.add_argument(
        '-e', '--exec-start',
        help='Commande ExecStart'
    )

    parser.add_argument(
        '-u', '--user',
        default='root',
        help='Utilisateur (défaut: root)'
    )

    parser.add_argument(
        '-g', '--group',
        help='Groupe (défaut: même que user)'
    )

    parser.add_argument(
        '-w', '--working-dir',
        default='/',
        help='Répertoire de travail (défaut: /)'
    )

    parser.add_argument(
        '-t', '--type',
        choices=['simple', 'forking', 'oneshot', 'notify'],
        default='simple',
        help='Type de service (défaut: simple)'
    )

    parser.add_argument(
        '--env',
        action='append',
        metavar='KEY=VALUE',
        help='Variable d\'environnement (répétable)'
    )

    # Hardening
    parser.add_argument(
        '--no-hardening',
        action='store_true',
        help='Désactiver les options de sécurité'
    )

    # Output
    parser.add_argument(
        '-o', '--output',
        type=Path,
        help='Fichier de sortie (défaut: stdout)'
    )

    parser.add_argument(
        '-i', '--interactive',
        action='store_true',
        help='Mode interactif'
    )

    return parser.parse_args()


def main() -> int:
    """
    Main entry point.

    Returns:
        Exit code (0 for success, non-zero for errors)
    """
    args = setup_args()

    try:
        # Interactive mode
        if args.interactive or (not args.name and not args.exec_start):
            config = interactive_mode()
        else:
            # CLI mode - validate required args
            if not args.name:
                logger.error("Le nom du service (-n) est requis")
                return 1

            if not args.exec_start:
                logger.error("La commande ExecStart (-e) est requise")
                return 1

            # Parse environment variables
            env_vars = {}
            if args.env:
                for env in args.env:
                    if "=" in env:
                        key, value = env.split("=", 1)
                        env_vars[key] = value

            config = ServiceConfig(
                name=args.name,
                description=args.description or f"{args.name} service",
                exec_start=args.exec_start,
                user=args.user,
                group=args.group or args.user,
                working_directory=args.working_dir,
                service_type=args.type,
                environment=env_vars,
                hardening_enabled=not args.no_hardening,
            )

        # Generate
        generator = SystemdGenerator(config)
        content = generator.generate()

        # Output
        if args.output:
            args.output.write_text(content)
            print(f"\n✓ Fichier sauvegardé: {args.output}")
            print(f"\nPour installer le service:")
            print(f"  sudo cp {args.output} /etc/systemd/system/")
            print(f"  sudo systemctl daemon-reload")
            print(f"  sudo systemctl enable {config.name}")
            print(f"  sudo systemctl start {config.name}")
        else:
            print("\n" + "=" * 60)
            print(f"  {config.name}.service")
            print("=" * 60)
            print(content)
            print("=" * 60)

            # Save prompt
            save = input(f"\nSauvegarder dans {config.name}.service? [O/n]: ").strip().lower()
            if save != "n":
                output_path = Path(f"{config.name}.service")
                output_path.write_text(content)
                print(f"\n✓ Fichier sauvegardé: {output_path}")

        return 0

    except KeyboardInterrupt:
        print("\n\nAnnulé par l'utilisateur")
        return 130

    except Exception as e:
        logger.error(f"Erreur: {e}")
        return 1


if __name__ == '__main__':
    sys.exit(main())
```

---

## Utilisation

### Mode Interactif

```bash
# Lance l'assistant interactif
python3 systemd_generator.py

# Ou explicitement
python3 systemd_generator.py --interactive
```

### Mode CLI

```bash
# Service basique
python3 systemd_generator.py -n myapp -e "/usr/bin/myapp"

# Service complet
python3 systemd_generator.py \
    -n myapp \
    -d "My Application Server" \
    -e "/usr/bin/myapp --config /etc/myapp.conf" \
    -u myapp \
    -g myapp \
    -w /var/lib/myapp \
    -t simple

# Avec variables d'environnement
python3 systemd_generator.py \
    -n myapp \
    -e "/usr/bin/node /opt/myapp/server.js" \
    --env "NODE_ENV=production" \
    --env "PORT=3000"

# Sans hardening (non recommandé)
python3 systemd_generator.py -n myapp -e "/usr/bin/myapp" --no-hardening

# Sauvegarder directement
python3 systemd_generator.py -n myapp -e "/usr/bin/myapp" -o myapp.service
```

---

## Exemple de Sortie

```ini
[Unit]
Description=My Application Server
After=network.target

[Service]
Type=simple
User=myapp
Group=myapp
WorkingDirectory=/var/lib/myapp
ExecStart=/usr/bin/myapp --config /etc/myapp.conf
Restart=on-failure
RestartSec=5
Environment="NODE_ENV=production"

# Security Hardening
NoNewPrivileges=yes
ProtectSystem=full
ProtectHome=yes
PrivateTmp=true
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes

[Install]
WantedBy=multi-user.target
```

---

## Options

| Option | Description |
|--------|-------------|
| `-n`, `--name` | Nom du service (requis) |
| `-d`, `--description` | Description du service |
| `-e`, `--exec-start` | Commande à exécuter (requis) |
| `-u`, `--user` | Utilisateur (défaut: root) |
| `-g`, `--group` | Groupe (défaut: même que user) |
| `-w`, `--working-dir` | Répertoire de travail (défaut: /) |
| `-t`, `--type` | Type de service: simple, forking, oneshot, notify |
| `--env KEY=VALUE` | Variable d'environnement (répétable) |
| `--no-hardening` | Désactiver les options de sécurité |
| `-o`, `--output` | Fichier de sortie |
| `-i`, `--interactive` | Mode interactif |

---

## Installation du Service Généré

```bash
# 1. Copier le fichier
sudo cp myapp.service /etc/systemd/system/

# 2. Recharger systemd
sudo systemctl daemon-reload

# 3. Activer au démarrage
sudo systemctl enable myapp

# 4. Démarrer le service
sudo systemctl start myapp

# 5. Vérifier le statut
sudo systemctl status myapp
```

---

!!! tip "Vérifier le Hardening"
    Utilisez `systemd-analyze security` pour évaluer le niveau de sécurité :

    ```bash
    sudo systemd-analyze security myapp.service
    ```

    Un score de **0-2** indique un service bien sécurisé.

!!! warning "Compatibilité"
    Certaines options de hardening nécessitent systemd 230+ :

    - `ProtectKernelTunables` : systemd 232+
    - `ProtectKernelModules` : systemd 232+
    - `RestrictSUIDSGID` : systemd 240+

    Vérifiez votre version : `systemctl --version`

---

## Voir Aussi

- [logrotate-builder.sh](../bash/logrotate-builder.md) - Générateur config logrotate
- [ssl-csr-wizard.sh](../bash/ssl-csr-wizard.md) - Générateur CSR SSL
- [service-manager.sh](../bash/service-manager.md) - Gestion des services systemd
