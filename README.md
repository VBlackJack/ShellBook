# 🐚 ShellBook

> **L'Infrastructure qui se documente elle-même.**
> Base de Connaissance Ops & Framework d'Administration (SecNumCloud Ready).

![Status](https://img.shields.io/badge/Status-Production-success)
![Stack](https://img.shields.io/badge/Built%20With-MkDocs%20Material-blue)
![CLI](https://img.shields.io/badge/CLI-Bash%20Wrapper-orange)
![License](https://img.shields.io/badge/License-MIT-green)

🌐 **Site en ligne** : [https://vblackjack.github.io/ShellBook/](https://vblackjack.github.io/ShellBook/)

---

## 🚀 Concept

**ShellBook** n'est pas juste un wiki statique. C'est une **Plateforme d'Opérations (Ops Platform)** hybride.
Elle fusionne la théorie (Documentation) et la pratique (Scripts) grâce à un moteur d'extraction intelligent.

* 📚 **Knowledge Base :** +350 modules (Linux, Windows, K8s, Sécurité, Databases).
* 🛠️ **Ops Framework :** Une CLI unifiée (`sb`) pour piloter l'infrastructure.
* 🔄 **Self-Hydrating :** Les scripts sont stockés dans la documentation et extraits à la volée.
* 🎓 **Academy :** 23 parcours de formation structurés.

---

## ⚡ Quick Start (3 minutes)

### 1. Installation

Clonez le dépôt et initialisez l'environnement :

```bash
git clone https://github.com/VBlackJack/ShellBook.git
cd ShellBook

# 🪄 La Magie : Transforme la doc en exécutables
./sb hydrate

# Installe les dépendances Python (optionnel pour les outils avancés)
./sb install
```

### 2. Utilisation Immédiate

Une fois hydraté, utilisez le wrapper `sb` pour lancer les outils "God Mode" :

```bash
# 🕵️ Audit complet d'un serveur Linux (Découverte automatique)
./sb audit server -o rapport.md

# 🧹 Nettoyage intelligent de Docker (Dry-run par défaut)
./sb clean docker --dry-run

# 🔑 Audit des clés Redis
./sb audit redis --host localhost
```

---

## 🧰 L'Arsenal (CLI Capabilities)

Le script `./sb` est votre point d'entrée unique. Il route les commandes vers les scripts (Bash/Python/PS1) extraits dans `bin/`.

| Commande | Action | Cible |
|----------|--------|-------|
| `./sb hydrate` | **CRITIQUE.** Extrait le code des fichiers `.md` vers `./bin/`. | Core |
| `./sb install` | Installe les dépendances Python. | Core |
| `./sb list` | Liste les scripts disponibles dans `bin/`. | Core |
| `./sb audit server` | Scan complet (Hardware, Ports, Services) + Rapport MD. | Linux |
| `./sb audit redis` | Audit des clés Redis (SCAN non-bloquant). | BDD |
| `./sb clean docker` | Nettoyage sélectif (Images, Volumes orphelins). | Docker |
| `./sb clean git` | Supprime les branches mergées/stale. | Dev |
| `./sb generate systemd` | Assistant interactif pour créer un service `.service`. | Linux |
| `./sb generate ssl` | Génère un CSR SSL/TLS avec SANs. | Security |
| `./sb generate logrotate` | Génère une config logrotate. | Linux |

---

## 🗺️ Architecture de la Base

La documentation est organisée par piliers technologiques :

```
📂 docs/
├── 📂 cli/           # Documentation du CLI `sb`
├── 📂 playbooks/     # Playbooks d'incident response
├── 📂 linux/         # RHEL, Debian, Systemd, Tuning Kernel
├── 📂 windows/       # AD, PowerShell, IIS, Hardening
├── 📂 security/      # Normes SecNumCloud, OpenSSL, Vault
├── 📂 devops/        # Docker, K8s, Terraform, Ansible
│   └── 📂 pipelines/ # Templates CI/CD (GitLab/GitHub) prêts à l'emploi
├── 📂 scripts/       # Le code source des outils (Bash, Python, PS1)
│   ├── 📂 bash/        # 29 scripts
│   ├── 📂 python/      # 10 scripts
│   │   └── requirements.txt
│   └── 📂 powershell/  # 15 scripts
└── 📂 formations/    # 23 parcours de formation (500h+)
```

---

## 🎓 Formations Disponibles (23 parcours)

| Formation | Durée | Niveau |
|-----------|-------|--------|
| 🚀 DevOps Foundation | 6h | Débutant |
| 🐧 Linux Mastery | 150h | Zero to Hero |
| 🪟 Windows Mastery | 150h | Zero to Hero |
| 🪟 Windows Server | 20h | Intermédiaire |
| ☸️ Kubernetes Mastery | 35h | Intermédiaire |
| 🐳 Docker Mastery | 15h | Intermédiaire |
| 🦭 Podman Mastery | 10h | Intermédiaire |
| 💠 Ansible Mastery | 10h | Intermédiaire |
| 🔐 Hardening Linux | 10h | Intermédiaire |
| 🔐 Hardening Windows | 10h | Intermédiaire |
| 🐍 Python SysOps | 35h | Intermédiaire |
| ☁️ Cloud Fundamentals | 35h | Intermédiaire |
| ☁️ AWS Fundamentals | 15h | Intermédiaire |
| ☁️ Azure Fundamentals | 15h | Intermédiaire |
| ☁️ GCP Fundamentals | 15h | Intermédiaire |
| 🌍 Terraform ACI | 10h | Intermédiaire |
| 📊 Observability | 15h | Intermédiaire |
| 🔑 PKI & Certificates | 8h | Intermédiaire |
| 🦁 Katello Lifecycle | 15h | Avancé |
| 🛢️ SQL Server DBA | 22h | Avancé |
| 🍫 Chocolatey | 4h | Débutant |
| 🔧 NTLite | 4h | Débutant |
| 🔄 Windows Patching | 6h | Intermédiaire |

**Total** : 500+ heures de formation professionnelle

---

## 🔧 Contribution (Docs-as-Code)

1. Modifiez un fichier Markdown dans `docs/`.
2. Si vous modifiez un script à l'intérieur de la doc, le changement sera répercuté dans le binaire au prochain `./sb hydrate`.
3. Prévisualisez le site :

```bash
pip install -r requirements.txt
mkdocs serve
```

4. Commit et push :

```bash
git add .
git commit -m "feat(linux): Add new guide"
git push
```

Le déploiement sur GitHub Pages est automatique via GitHub Actions.

---

## 📊 Statistiques

- **Guides & Modules** : 350+ fichiers Markdown
- **Scripts** : 54 (29 Bash, 10 Python, 15 PowerShell)
- **Formations** : 23 parcours complets (500h+)
- **Templates CI/CD** : GitLab CI, GitHub Actions, Dockerfile

---

## 📄 License

MIT License - Voir [LICENSE](LICENSE) pour plus de détails.

---

<div align="center">
  <p><strong>Built with ❤️ for SysAdmin & DevOps Engineers.</strong></p>
  <p>📚 350+ Guides • 🛠️ 54 Scripts • 🎓 23 Formations • ⚡ CLI Unifié</p>
</div>
