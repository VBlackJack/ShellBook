---
tags:
  - scripts
  - python
  - git
  - devops
  - automation
---

# git_repo_cleaner.py

:material-star::material-star: **Niveau : Intermédiaire**

Identification et nettoyage des branches Git obsolètes.

---

## Description

Ce script analyse un dépôt Git local pour identifier les branches qui :

- Ont été fusionnées dans `main` ou `master` mais non supprimées
- N'ont pas eu de commits depuis une période définie
- Sont orphelines (tracking branch supprimée sur le remote)

Il propose un mode **dry-run** (par défaut) pour prévisualiser les actions, et un mode **delete** pour effectuer le nettoyage.

---

## Prérequis

```bash
# Installation de GitPython
pip install gitpython

# Ou avec le fichier requirements
pip install -r requirements.txt
```

**requirements.txt :**
```text
gitpython>=3.1.0
```

---

## Script

```python
#!/usr/bin/env python3
"""
git_repo_cleaner.py - Identify and clean stale git branches

This script finds branches that have been merged but not deleted,
or branches with no recent activity, and optionally removes them.
"""

import argparse
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional, Tuple
from dataclasses import dataclass, field

try:
    import git
    from git import Repo, GitCommandError
    GIT_AVAILABLE = True
except ImportError:
    GIT_AVAILABLE = False


# ANSI color codes
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    GRAY = '\033[90m'
    BOLD = '\033[1m'
    RESET = '\033[0m'


@dataclass
class BranchInfo:
    """Information about a git branch"""
    name: str
    is_merged: bool = False
    is_stale: bool = False
    is_orphan: bool = False
    last_commit_date: Optional[datetime] = None
    last_commit_sha: str = ""
    last_commit_message: str = ""
    days_since_commit: int = 0
    tracking_branch: Optional[str] = None
    reasons: List[str] = field(default_factory=list)


class GitRepoCleaner:
    """Git repository branch cleaner"""

    def __init__(
        self,
        repo_path: str = ".",
        main_branch: str = "main",
        stale_days: int = 90,
        protected_patterns: Optional[List[str]] = None
    ):
        """
        Initialize the cleaner.

        Args:
            repo_path: Path to the git repository
            main_branch: Name of the main branch (main or master)
            stale_days: Days of inactivity to consider a branch stale
            protected_patterns: Branch name patterns to never delete
        """
        self.repo_path = Path(repo_path).resolve()
        self.main_branch = main_branch
        self.stale_days = stale_days
        self.protected_patterns = protected_patterns or [
            "main", "master", "develop", "release/*", "hotfix/*"
        ]

        # Initialize repository
        try:
            self.repo = Repo(self.repo_path)
            if self.repo.bare:
                raise ValueError("Cannot work with bare repositories")
        except git.InvalidGitRepositoryError:
            raise ValueError(f"Not a valid git repository: {self.repo_path}")

        # Auto-detect main branch if needed
        self._detect_main_branch()

    def _detect_main_branch(self):
        """Auto-detect the main branch name"""
        branches = [b.name for b in self.repo.branches]

        if self.main_branch in branches:
            return

        # Try common names
        for candidate in ["main", "master", "trunk", "develop"]:
            if candidate in branches:
                self.main_branch = candidate
                return

        # Use the first branch as fallback
        if branches:
            self.main_branch = branches[0]

    def _is_protected(self, branch_name: str) -> bool:
        """Check if a branch matches protected patterns"""
        import fnmatch

        for pattern in self.protected_patterns:
            if fnmatch.fnmatch(branch_name, pattern):
                return True
        return False

    def _get_merged_branches(self) -> List[str]:
        """Get list of branches merged into main"""
        try:
            # Get merged branches using git command
            merged_output = self.repo.git.branch("--merged", self.main_branch)
            merged = []

            for line in merged_output.split('\n'):
                branch = line.strip().lstrip('* ')
                if branch and branch != self.main_branch:
                    merged.append(branch)

            return merged
        except GitCommandError:
            return []

    def _get_branch_info(self, branch) -> BranchInfo:
        """Get detailed information about a branch"""
        info = BranchInfo(name=branch.name)

        try:
            # Get last commit info
            commit = branch.commit
            info.last_commit_sha = commit.hexsha[:8]
            info.last_commit_message = commit.message.split('\n')[0][:50]

            # Calculate commit date
            commit_dt = datetime.fromtimestamp(
                commit.committed_date,
                tz=timezone.utc
            )
            info.last_commit_date = commit_dt
            info.days_since_commit = (
                datetime.now(timezone.utc) - commit_dt
            ).days

            # Check if stale
            if info.days_since_commit > self.stale_days:
                info.is_stale = True
                info.reasons.append(
                    f"No commits for {info.days_since_commit} days"
                )

            # Check tracking branch
            try:
                tracking = branch.tracking_branch()
                if tracking:
                    info.tracking_branch = tracking.name
                    # Check if remote branch still exists
                    try:
                        tracking.commit
                    except (ValueError, TypeError):
                        info.is_orphan = True
                        info.reasons.append("Remote tracking branch deleted")
            except TypeError:
                pass

        except Exception as e:
            info.reasons.append(f"Error: {str(e)}")

        return info

    def analyze(self) -> List[BranchInfo]:
        """
        Analyze all branches and identify candidates for deletion.

        Returns:
            List of BranchInfo objects for branches that could be cleaned
        """
        candidates = []
        merged_branches = self._get_merged_branches()

        for branch in self.repo.branches:
            # Skip protected branches
            if self._is_protected(branch.name):
                continue

            # Skip current branch
            if branch.name == self.repo.active_branch.name:
                continue

            info = self._get_branch_info(branch)

            # Check if merged
            if branch.name in merged_branches:
                info.is_merged = True
                info.reasons.append(f"Merged into {self.main_branch}")

            # Add to candidates if there's a reason to clean
            if info.is_merged or info.is_stale or info.is_orphan:
                candidates.append(info)

        # Sort by priority: merged first, then by days since commit
        candidates.sort(
            key=lambda x: (not x.is_merged, -x.days_since_commit)
        )

        return candidates

    def delete_branch(
        self,
        branch_name: str,
        force: bool = False,
        delete_remote: bool = False
    ) -> Tuple[bool, str]:
        """
        Delete a local branch.

        Args:
            branch_name: Name of the branch to delete
            force: Force delete even if not fully merged
            delete_remote: Also delete the remote tracking branch

        Returns:
            Tuple of (success, message)
        """
        try:
            # Get branch reference
            branch = self.repo.branches[branch_name]

            # Delete remote first if requested
            if delete_remote and branch.tracking_branch():
                remote_name = branch.tracking_branch().remote_name
                remote_branch = branch.tracking_branch().name.replace(
                    f"{remote_name}/", ""
                )
                try:
                    remote = self.repo.remote(remote_name)
                    remote.push(refspec=f":{remote_branch}")
                except GitCommandError as e:
                    return False, f"Failed to delete remote: {e}"

            # Delete local branch
            if force:
                self.repo.git.branch("-D", branch_name)
            else:
                self.repo.git.branch("-d", branch_name)

            return True, f"Deleted branch: {branch_name}"

        except GitCommandError as e:
            return False, f"Failed to delete {branch_name}: {e}"
        except IndexError:
            return False, f"Branch not found: {branch_name}"


def print_analysis(
    candidates: List[BranchInfo],
    verbose: bool = False
):
    """Print analysis results in a formatted way"""
    print(f"\n{Colors.CYAN}{'='*70}{Colors.RESET}")
    print(f"{Colors.GREEN}  GIT REPOSITORY BRANCH ANALYSIS{Colors.RESET}")
    print(f"{Colors.CYAN}{'='*70}{Colors.RESET}")
    print(f"  Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{Colors.CYAN}{'-'*70}{Colors.RESET}\n")

    if not candidates:
        print(f"{Colors.GREEN}[OK]{Colors.RESET} No stale branches found!")
        return

    # Group by type
    merged = [c for c in candidates if c.is_merged]
    stale = [c for c in candidates if c.is_stale and not c.is_merged]
    orphan = [c for c in candidates if c.is_orphan and not c.is_merged]

    # Print merged branches
    if merged:
        print(f"{Colors.BOLD}Merged branches ({len(merged)}):{Colors.RESET}")
        for branch in merged:
            print(f"  {Colors.GREEN}[MERGED]{Colors.RESET} {branch.name}")
            if verbose:
                print(f"    {Colors.GRAY}Last commit: {branch.last_commit_sha} "
                      f"- {branch.last_commit_message}{Colors.RESET}")
                print(f"    {Colors.GRAY}{branch.days_since_commit} days ago{Colors.RESET}")
        print()

    # Print stale branches
    if stale:
        print(f"{Colors.BOLD}Stale branches ({len(stale)}):{Colors.RESET}")
        for branch in stale:
            print(f"  {Colors.YELLOW}[STALE]{Colors.RESET} {branch.name} "
                  f"({branch.days_since_commit} days)")
            if verbose:
                print(f"    {Colors.GRAY}Last commit: {branch.last_commit_sha} "
                      f"- {branch.last_commit_message}{Colors.RESET}")
        print()

    # Print orphan branches
    if orphan:
        print(f"{Colors.BOLD}Orphan branches ({len(orphan)}):{Colors.RESET}")
        for branch in orphan:
            print(f"  {Colors.RED}[ORPHAN]{Colors.RESET} {branch.name}")
            if verbose and branch.tracking_branch:
                print(f"    {Colors.GRAY}Was tracking: {branch.tracking_branch}{Colors.RESET}")
        print()

    # Summary
    print(f"{Colors.CYAN}{'='*70}{Colors.RESET}")
    print(f"  Total candidates: {len(candidates)}")
    print(f"    Merged: {len(merged)}  |  Stale: {len(stale)}  |  Orphan: {len(orphan)}")
    print(f"{Colors.CYAN}{'='*70}{Colors.RESET}\n")


def main():
    parser = argparse.ArgumentParser(
        description='Identify and clean stale git branches',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    %(prog)s                          # Dry-run analysis
    %(prog)s --delete                 # Delete stale branches
    %(prog)s --stale-days 30          # Custom stale threshold
    %(prog)s --path /path/to/repo     # Analyze specific repo
    %(prog)s --delete --force         # Force delete (even unmerged)
        """
    )

    parser.add_argument(
        '-p', '--path',
        default='.',
        help='Path to git repository (default: current directory)'
    )
    parser.add_argument(
        '-m', '--main-branch',
        default='main',
        help='Name of main branch (default: auto-detect)'
    )
    parser.add_argument(
        '-s', '--stale-days',
        type=int,
        default=90,
        help='Days of inactivity to consider stale (default: 90)'
    )
    parser.add_argument(
        '--delete',
        action='store_true',
        help='Actually delete branches (default: dry-run)'
    )
    parser.add_argument(
        '--force',
        action='store_true',
        help='Force delete even if not fully merged'
    )
    parser.add_argument(
        '--delete-remote',
        action='store_true',
        help='Also delete remote tracking branches'
    )
    parser.add_argument(
        '--merged-only',
        action='store_true',
        help='Only process merged branches'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Verbose output'
    )
    parser.add_argument(
        '--json',
        metavar='FILE',
        help='Export results to JSON file'
    )

    args = parser.parse_args()

    # Check dependencies
    if not GIT_AVAILABLE:
        print(f"{Colors.RED}Error: gitpython module required.{Colors.RESET}")
        print("Install with: pip install gitpython")
        sys.exit(1)

    # Initialize cleaner
    try:
        cleaner = GitRepoCleaner(
            repo_path=args.path,
            main_branch=args.main_branch,
            stale_days=args.stale_days
        )
    except ValueError as e:
        print(f"{Colors.RED}Error: {e}{Colors.RESET}")
        sys.exit(1)

    print(f"{Colors.CYAN}Repository:{Colors.RESET} {cleaner.repo_path}")
    print(f"{Colors.CYAN}Main branch:{Colors.RESET} {cleaner.main_branch}")
    print(f"{Colors.CYAN}Current branch:{Colors.RESET} {cleaner.repo.active_branch.name}")

    # Analyze branches
    candidates = cleaner.analyze()

    # Filter if merged-only
    if args.merged_only:
        candidates = [c for c in candidates if c.is_merged]

    # Print analysis
    print_analysis(candidates, args.verbose)

    # Export to JSON if requested
    if args.json:
        import json
        data = {
            'repository': str(cleaner.repo_path),
            'main_branch': cleaner.main_branch,
            'analysis_date': datetime.now().isoformat(),
            'branches': [
                {
                    'name': c.name,
                    'is_merged': c.is_merged,
                    'is_stale': c.is_stale,
                    'is_orphan': c.is_orphan,
                    'days_since_commit': c.days_since_commit,
                    'last_commit_sha': c.last_commit_sha,
                    'reasons': c.reasons
                }
                for c in candidates
            ]
        }
        with open(args.json, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"{Colors.GREEN}[OK]{Colors.RESET} Results exported to {args.json}")

    # Delete if requested
    if args.delete and candidates:
        print(f"\n{Colors.YELLOW}[ACTION]{Colors.RESET} Deleting branches...\n")

        deleted = 0
        failed = 0

        for branch in candidates:
            success, message = cleaner.delete_branch(
                branch.name,
                force=args.force,
                delete_remote=args.delete_remote
            )

            if success:
                print(f"  {Colors.GREEN}[OK]{Colors.RESET} {message}")
                deleted += 1
            else:
                print(f"  {Colors.RED}[FAIL]{Colors.RESET} {message}")
                failed += 1

        print(f"\n{Colors.CYAN}Deletion summary:{Colors.RESET}")
        print(f"  Deleted: {deleted}  |  Failed: {failed}")

    elif not args.delete and candidates:
        print(f"{Colors.YELLOW}[DRY-RUN]{Colors.RESET} No branches deleted. "
              f"Use --delete to remove them.")

    # Exit code
    if candidates:
        sys.exit(0 if args.delete else 1)
    sys.exit(0)


if __name__ == '__main__':
    main()
```

---

## Utilisation

### Mode analyse (dry-run par défaut)

```bash
# Analyser le dépôt courant
python git_repo_cleaner.py

# Analyser un dépôt spécifique
python git_repo_cleaner.py --path /chemin/vers/repo

# Analyse détaillée
python git_repo_cleaner.py --verbose
```

### Personnalisation des critères

```bash
# Branches inactives depuis plus de 30 jours
python git_repo_cleaner.py --stale-days 30

# Uniquement les branches fusionnées
python git_repo_cleaner.py --merged-only

# Spécifier la branche principale
python git_repo_cleaner.py --main-branch develop
```

### Mode suppression

```bash
# Supprimer les branches identifiées
python git_repo_cleaner.py --delete

# Forcer la suppression (même non fusionnées)
python git_repo_cleaner.py --delete --force

# Supprimer aussi sur le remote
python git_repo_cleaner.py --delete --delete-remote
```

### Export des résultats

```bash
# Export JSON pour intégration CI/CD
python git_repo_cleaner.py --json branches-report.json
```

---

## Sortie exemple

```sql
Repository: /home/user/myproject
Main branch: main
Current branch: feature/new-ui

======================================================================
  GIT REPOSITORY BRANCH ANALYSIS
======================================================================
  Date: 2024-11-30 15:45:22
----------------------------------------------------------------------

Merged branches (3):
  [MERGED] feature/login-page
    Last commit: a1b2c3d4 - Add login page components
    45 days ago
  [MERGED] bugfix/null-pointer
    Last commit: e5f6g7h8 - Fix null pointer in user service
    30 days ago
  [MERGED] feature/dark-mode
    Last commit: i9j0k1l2 - Implement dark mode toggle
    12 days ago

Stale branches (2):
  [STALE] experiment/new-api (120 days)
    Last commit: m3n4o5p6 - WIP: testing new API structure
  [STALE] old-refactor (95 days)
    Last commit: q7r8s9t0 - Partial refactoring attempt

Orphan branches (1):
  [ORPHAN] feature/removed-feature
    Was tracking: origin/feature/removed-feature

======================================================================
  Total candidates: 6
    Merged: 3  |  Stale: 2  |  Orphan: 1
======================================================================

[DRY-RUN] No branches deleted. Use --delete to remove them.
```

---

## Intégration CI/CD

### GitHub Actions

```yaml
name: Branch Cleanup

on:
  schedule:
    - cron: '0 6 * * 1'  # Every Monday at 6 AM
  workflow_dispatch:

jobs:
  cleanup:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: pip install gitpython

      - name: Analyze stale branches
        run: |
          python git_repo_cleaner.py --merged-only --json report.json

      - name: Upload report
        uses: actions/upload-artifact@v4
        with:
          name: branch-report
          path: report.json
```

---

!!! warning "Précautions avant suppression"
    - **Toujours exécuter en mode dry-run d'abord** pour vérifier les branches identifiées
    - Les branches protégées (`main`, `master`, `develop`, `release/*`, `hotfix/*`) ne sont **jamais supprimées**
    - L'option `--force` peut supprimer des branches avec du travail non fusionné
    - L'option `--delete-remote` modifie le dépôt distant - assurez-vous d'avoir les droits

    ```bash
    # Recommandé : prévisualiser avant de supprimer
    python git_repo_cleaner.py --verbose
    python git_repo_cleaner.py --delete  # Si OK
    ```

---

## Voir Aussi

- [cert_checker.py](cert_checker.md) - Vérification des certificats SSL
- [docker_health.py](docker_health.md) - Santé Docker
