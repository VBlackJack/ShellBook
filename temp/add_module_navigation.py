#!/usr/bin/env python3
"""
Add prev/next navigation to all formation modules.
"""
import os
import re
from pathlib import Path

FORMATIONS_DIR = Path(r"G:\_dev\ShellBook\docs\formations")

# Define formation module orders
FORMATIONS = {
    "devops-foundation": {
        "modules": ["01-module.md", "02-module.md", "03-module.md", "04-module.md", "05-tp-final.md"],
        "index": "index.md"
    },
    "cloud-fundamentals": {
        "modules": ["01-module.md", "02-module.md", "03-module.md", "04-module.md", "05-module.md",
                   "06-module.md", "07-module.md", "08-module.md", "09-module.md", "10-module.md",
                   "11-module.md", "12-tp-final.md"],
        "index": "index.md"
    },
    "pki-certificates": {
        "modules": ["01-module.md", "02-module.md", "03-module.md", "04-module.md", "05-tp-final.md"],
        "index": "index.md"
    },
    "linux-mastery": {
        "modules": ["01-decouverte.md", "02-navigation.md", "03-permissions.md", "04-editeurs.md",
                   "05-shell-intro.md", "06-paquets.md", "07-services.md", "08-stockage.md",
                   "09-reseau.md", "10-automatisation.md", "11-securite.md", "12-services-reseau.md",
                   "13-performance.md", "14-scripting-avance.md", "15-backup.md", "16-haute-disponibilite.md",
                   "17-conteneurs.md", "18-kubernetes.md", "19-iac.md", "20-projet-final.md"],
        "index": "index.md"
    },
    "linux-hardening": {
        "modules": ["01-module.md", "02-module.md", "03-module.md", "04-module.md", "05-tp-final.md"],
        "index": "index.md"
    },
    "windows-mastery": {
        "modules": ["01-decouverte.md", "02-powershell-basics.md", "03-utilisateurs-ntfs.md",
                   "04-outils-administration.md", "05-scripting-intro.md", "06-roles-features.md",
                   "07-services-processus.md", "08-stockage-disques.md", "09-reseau-dns-dhcp.md",
                   "10-automatisation-basique.md", "11-active-directory-core.md", "12-gpo-configuration.md",
                   "13-securite-hardening.md", "14-services-reseau-avances.md", "15-backup-disaster-recovery.md",
                   "16-haute-disponibilite.md", "17-conteneurs-windows.md", "18-hybrid-cloud.md",
                   "19-infrastructure-as-code.md", "20-projet-final.md"],
        "index": "index.md"
    },
    "windows-hardening": {
        "modules": ["01-module.md", "02-module.md", "03-module.md", "04-module.md", "05-tp-final.md"],
        "index": "index.md"
    },
    "windows-patching": {
        "modules": ["01-module.md", "02-module.md", "03-module.md", "04-module.md", "05-tp-final.md"],
        "index": "index.md"
    },
    "chocolatey": {
        "modules": ["01-module.md", "02-module.md", "03-module.md", "04-module.md", "05-tp-final.md"],
        "index": "index.md"
    },
    "ntlite": {
        "modules": ["01-module.md", "02-module.md", "03-module.md", "04-module.md", "05-tp-final.md", "06-scenario-vpn.md"],
        "index": "index.md"
    },
    "sql-server": {
        "modules": ["01-module.md", "02-module.md", "03-module.md", "04-module.md", "05-tp-final.md"],
        "index": "index.md"
    },
    "windows-server": {
        "modules": ["01-module.md", "02-module.md", "03-module.md", "04-tp-final.md"],
        "index": "index.md"
    },
    "docker-mastery": {
        "modules": ["01-module.md", "02-module.md", "03-module.md", "04-module.md", "05-module.md",
                   "06-module.md", "07-tp-final.md"],
        "index": "index.md"
    },
    "podman-mastery": {
        "modules": ["01-module.md", "02-module.md", "03-module.md", "04-module.md", "05-module.md",
                   "06-module.md", "07-tp-final.md"],
        "index": "index.md"
    },
    "kubernetes-mastery": {
        "modules": ["01-module.md", "02-module.md", "03-module.md", "04-module.md", "05-module.md",
                   "06-module.md", "07-module.md", "08-module.md", "09-module.md", "10-module.md",
                   "11-module.md", "12-tp-final.md"],
        "index": "index.md"
    },
    "observability": {
        "modules": ["01-module.md", "02-module.md", "03-module.md", "04-module.md", "05-module.md",
                   "06-tp-final.md"],
        "index": "index.md"
    },
    "ansible-mastery": {
        "modules": ["01-module.md", "02-module.md", "03-module.md", "04-module.md", "05-tp-final.md"],
        "index": "index.md"
    },
    "katello": {
        "modules": ["01-module.md", "02-module.md", "03-module.md", "04-module.md", "05-tp-final.md"],
        "index": "index.md"
    },
    "terraform-aci": {
        "modules": ["01-module.md", "02-module.md", "03-module.md", "04-module.md", "05-module.md",
                   "06-module.md", "07-module.md", "08-module.md", "09-module.md", "10-tp-final.md"],
        "index": "index.md"
    },
    "python-sysops": {
        "modules": ["01-environnement.md", "02-syntaxe.md", "03-structures.md", "04-fonctions.md",
                   "05-fichiers.md", "06-formats.md", "07-subprocess.md", "08-regex.md", "09-erreurs.md",
                   "10-reseau.md", "11-api-rest.md", "12-ssh.md", "13-cli.md", "14-cloud.md",
                   "15-tests.md", "16-tp-final.md"],
        "index": "index.md"
    },
    "aws-fundamentals": {
        "modules": ["01-module.md", "02-module.md", "03-module.md", "04-module.md", "05-module.md",
                   "06-tp-final.md", "07-module.md", "08-module.md", "09-module.md", "10-module.md"],
        "index": "index.md"
    },
    "azure-fundamentals": {
        "modules": ["01-module.md", "02-module.md", "03-module.md", "04-module.md", "05-module.md",
                   "06-tp-final.md", "07-module.md", "08-module.md", "09-module.md", "10-module.md"],
        "index": "index.md"
    },
    "gcp-fundamentals": {
        "modules": ["01-module.md", "02-module.md", "03-module.md", "04-module.md", "05-module.md",
                   "06-tp-final.md", "07-module.md", "08-module.md", "09-module.md", "10-module.md"],
        "index": "index.md"
    },
    "hacking-mastery": {
        "modules": ["01-module.md", "02-module.md", "03-module.md", "04-module.md", "05-module.md",
                   "06-tp-final.md"],
        "index": "index.md"
    },
    "ai-engineering": {
        "modules": ["01-module.md", "02-module.md", "03-module.md", "04-module.md", "05-tp-final.md"],
        "index": "index.md"
    },
}

NAV_TEMPLATE = """
---

## Navigation

| | |
|:---|---:|
| {prev_link} | {next_link} |

[Retour au Programme]({index_link}){{ .md-button }}
"""

def get_module_title(filepath):
    """Extract module title from file."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
            # Find first H1 heading
            match = re.search(r'^# (.+)$', content, re.MULTILINE)
            if match:
                title = match.group(1)
                # Shorten if too long
                if len(title) > 40:
                    title = title[:37] + "..."
                return title
    except:
        pass
    return "Module"

def has_navigation(content):
    """Check if file already has navigation section."""
    return "## Navigation" in content and "Retour au Programme" in content

def add_navigation(formation_name, config):
    """Add navigation to all modules in a formation."""
    formation_dir = FORMATIONS_DIR / formation_name
    if not formation_dir.exists():
        print(f"  [SKIP] {formation_name} - directory not found")
        return 0

    modules = config["modules"]
    index = config["index"]
    updated = 0

    for i, module in enumerate(modules):
        module_path = formation_dir / module
        if not module_path.exists():
            print(f"  [SKIP] {module} - file not found")
            continue

        # Read current content
        with open(module_path, 'r', encoding='utf-8') as f:
            content = f.read()

        # Skip if already has navigation
        if has_navigation(content):
            print(f"  [SKIP] {module} - already has navigation")
            continue

        # Build prev/next links
        if i == 0:
            prev_link = f"[← Programme]({index})"
        else:
            prev_module = modules[i-1]
            prev_title = get_module_title(formation_dir / prev_module)
            prev_link = f"[← {prev_title}]({prev_module})"

        if i == len(modules) - 1:
            next_link = f"[Programme →]({index})"
        else:
            next_module = modules[i+1]
            next_title = get_module_title(formation_dir / next_module)
            next_link = f"[{next_title} →]({next_module})"

        # Build navigation block
        nav_block = NAV_TEMPLATE.format(
            prev_link=prev_link,
            next_link=next_link,
            index_link=index
        )

        # Add navigation to end of file
        new_content = content.rstrip() + "\n" + nav_block

        with open(module_path, 'w', encoding='utf-8') as f:
            f.write(new_content)

        print(f"  [OK] {module}")
        updated += 1

    return updated

def main():
    total_updated = 0

    for formation_name, config in FORMATIONS.items():
        print(f"\n📚 {formation_name}")
        updated = add_navigation(formation_name, config)
        total_updated += updated

    print(f"\n✅ Total modules updated: {total_updated}")

if __name__ == "__main__":
    main()
