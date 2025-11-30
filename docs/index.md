---
tags:
  - accueil
  - dashboard
  - secnumcloud
---

# ShellBook

<div style="text-align: center; margin: 2em 0;">
  <p style="font-size: 1.3em; color: #64748b;">Base de Connaissance Ops SecNumCloud</p>
  <span style="background: #1e3a8a; color: white; padding: 0.3em 0.8em; border-radius: 4px; margin: 0.3em;">🛡️ SecNumCloud</span>
  <span style="background: #047857; color: white; padding: 0.3em 0.8em; border-radius: 4px; margin: 0.3em;">🐧 Linux</span>
  <span style="background: #0369a1; color: white; padding: 0.3em 0.8em; border-radius: 4px; margin: 0.3em;">🪟 Windows</span>
  <span style="background: #326ce5; color: white; padding: 0.3em 0.8em; border-radius: 4px; margin: 0.3em;">☸️ Kubernetes</span>
</div>

---

## Dashboard Opérationnel

<div class="grid cards" markdown>

-   :fire:{ .lg .middle } **Urgence / Troubleshooting**

    ---

    **Le système est en feu ?** Accès direct aux scripts de survie et playbooks d'incident.

    - [Playbook Réponse Incident](playbooks/incident-response.md)
    - [Scripts Bash](scripts/bash/index.md) • [Scripts PowerShell](scripts/powershell/index.md)
    - [Scripts Python](scripts/python/index.md)

    [:octicons-flame-24: Voir les Playbooks](playbooks/incident-response.md){ .md-button .md-button--primary }

-   :rocket:{ .lg .middle } **CI/CD Factory**

    ---

    **Templates de production** pour pipelines et containerisation.

    - [GitLab CI Ultimate](devops/pipelines/gitlab-ci-ultimate.md)
    - [GitHub Actions Workflow](devops/pipelines/github-actions-workflow.md)
    - [Dockerfile Golden](devops/pipelines/dockerfile-golden.md)

    [:octicons-workflow-24: Voir les Pipelines](devops/pipelines/index.md){ .md-button }

-   :shield:{ .lg .middle } **Sécurité & Compliance**

    ---

    **Hardening et conformité** selon les standards SecNumCloud et ANSSI.

    - [Référentiel SecNumCloud](security/secnumcloud.md)
    - [Guides ANSSI](security/anssi-guides.md)
    - [Hardening Linux](formations/linux-hardening/index.md) • [Hardening Windows](formations/windows-hardening/index.md)

    [:octicons-shield-check-24: Voir la Sécurité](security/index.md){ .md-button }

-   :books:{ .lg .middle } **Encyclopédie**

    ---

    **Documentation technique** complète par domaine.

    - [Linux](linux/index.md) (30+ guides)
    - [Windows](windows/index.md) (9 guides)
    - [Kubernetes](devops/kubernetes-survival.md) (4 guides)
    - [Réseau](network/fundamentals.md)

    [:octicons-book-24: Explorer](linux/index.md){ .md-button }

</div>

---

## Quick Actions - God Scripts

!!! success "Audit Instantané"
    Ces scripts génèrent un **rapport Markdown complet** de l'état d'un serveur en quelques secondes.

<div class="grid cards" markdown>

-   :fontawesome-brands-linux:{ .lg .middle } **Linux Server Discovery**

    ---

    Audit complet : rôle, hardware, services, réseau, sécurité.

    ```bash
    # Audit complet avec rapport Markdown
    sudo ./server-discovery.sh -o audit_$(hostname).md
    ```

    [:octicons-terminal-24: Voir le Script](scripts/bash/server-discovery-audit.md){ .md-button .md-button--primary }

-   :fontawesome-brands-windows:{ .lg .middle } **Windows Server Audit**

    ---

    Audit complet : rôles, Defender, AD, ports, services.

    ```powershell
    # Audit complet avec rapport Markdown
    .\Invoke-ServerAudit.ps1 -OutputPath "C:\Audit\rapport.md"
    ```

    [:octicons-terminal-24: Voir le Script](scripts/powershell/Invoke-ServerAudit.md){ .md-button .md-button--primary }

</div>

---

## Accès Rapide par Situation

### En Urgence

| Symptôme | Action Immédiate | Script Recommandé |
|----------|------------------|-------------------|
| **Serveur ne répond plus** | Diagnostic complet | [server-discovery.sh](scripts/bash/server-discovery-audit.md) |
| **Disque plein** | Nettoyage système | [cleanup-system.sh](scripts/bash/cleanup-system.md) |
| **Pod K8s CrashLoop** | Inspection détaillée | [k8s-pod-inspector.sh](scripts/bash/k8s-pod-inspector.md) |
| **Conteneurs en folie** | Nettoyage Docker | [docker_cleaner_pro.py](scripts/python/docker_cleaner_pro.md) |
| **Base de données lente** | Analyse bloat PostgreSQL | [pg-bloat-check.sh](scripts/bash/pg-bloat-check.md) |
| **Besoin de logs** | Extraction ciblée | [logs-extractor.sh](scripts/bash/logs-extractor.md) |

### Mise en Place d'Infrastructure

| Besoin | Template / Guide |
|--------|------------------|
| **Pipeline GitLab** | [GitLab CI Ultimate](devops/pipelines/gitlab-ci-ultimate.md) |
| **Pipeline GitHub** | [GitHub Actions Workflow](devops/pipelines/github-actions-workflow.md) |
| **Dockerfile optimisé** | [Dockerfile Golden](devops/pipelines/dockerfile-golden.md) |
| **Service systemd** | [systemd_generator.py](scripts/python/systemd_generator.md) |
| **Certificat SSL/TLS** | [ssl-csr-wizard.sh](scripts/bash/ssl-csr-wizard.md) |
| **Rotation des logs** | [logrotate-builder.sh](scripts/bash/logrotate-builder.md) |

---

## Formations Recommandées

<div class="grid cards" markdown>

-   :material-school:{ .lg .middle } **Socle DevOps** (6h)

    ---

    Git, branches, CI/CD, qualité de code.

    [:octicons-arrow-right-24: Commencer](formations/devops-foundation/index.md)

-   :fontawesome-brands-linux:{ .lg .middle } **Linux Mastery** (150h)

    ---

    Du débutant à l'expert Linux.

    [:octicons-arrow-right-24: Commencer](formations/linux-mastery/index.md)

-   :fontawesome-brands-windows:{ .lg .middle } **Windows Mastery** (150h)

    ---

    Administration Windows Server.

    [:octicons-arrow-right-24: Commencer](formations/windows-mastery/index.md)

-   :material-kubernetes:{ .lg .middle } **Kubernetes Mastery** (35h)

    ---

    De l'architecture au GitOps.

    [:octicons-arrow-right-24: Commencer](formations/kubernetes-mastery/index.md)

</div>

---

## Cheatsheets Essentielles

| Outil | Fiche | Cas d'Usage |
|-------|-------|-------------|
| **OpenSSL** | [OpenSSL CLI](security/openssl-cli.md) | Certificats, CSR, chaînes TLS |
| **PowerShell** | [PowerShell Foundations](windows/powershell-foundations.md) | Objets, pipelines, remoting |
| **Git** | [Git for SysOps](devops/git-sysops.md) | Workflows, branches |
| **Kubectl** | [Kubectl Survival](devops/kubernetes-survival.md) | Debug pods, logs |
| **Ansible** | [Ansible Fundamentals](devops/ansible/fundamentals.md) | Inventaires, modules |

---

## Navigation

!!! tip "Raccourcis Clavier"
    - **Ctrl+K** (Cmd+K sur Mac) : Recherche rapide
    - Les **tags** filtrent par technologie
    - Les sections **Quick Reference** regroupent les commandes essentielles

---

<div style="text-align: center; color: #64748b; margin-top: 3em;">
  <p><strong>ShellBook</strong> - Base de Connaissance Ops SecNumCloud</p>
  <p>100+ Guides • 15+ Formations • 50+ Scripts</p>
  <p>Linux • Windows • Kubernetes • DevOps • Security</p>
</div>
