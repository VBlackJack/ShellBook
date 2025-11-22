# ShellBook

**La Base de Connaissance Opérationnelle pour l'Ingénieur SysOps & DevOps**

<div style="text-align: center; margin: 2em 0;">
  <span style="background: #1e3a8a; color: white; padding: 0.3em 0.8em; border-radius: 4px; margin: 0.3em;">🛡️ SecNumCloud Friendly</span>
  <span style="background: #047857; color: white; padding: 0.3em 0.8em; border-radius: 4px; margin: 0.3em;">🐧 Linux</span>
  <span style="background: #0369a1; color: white; padding: 0.3em 0.8em; border-radius: 4px; margin: 0.3em;">🪟 Windows</span>
  <span style="background: #326ce5; color: white; padding: 0.3em 0.8em; border-radius: 4px; margin: 0.3em;">☸️ K8s Ready</span>
</div>

---

## 🎯 Accès Rapide par Besoin

### 🔥 Urgence / Debug

**Votre système est en feu ?** Accès direct aux commandes de survie.

| Problème | Solution Express |
|----------|------------------|
| **Serveur Linux HS** | [Debugging Linux](linux/debugging.md) • [Performance Analysis](linux/performance-analysis.md) |
| **Pod K8s Crash** | [Kubectl Survival Kit](devops/kubernetes-survival.md) • [K8s Networking](devops/kubernetes-networking.md) |
| **Logs illisibles** | [Logs Management](linux/logs-management.md) • [Loki Stack](devops/observability-stack.md#loki-prometheus-pour-les-logs) |
| **Disque plein** | [Filesystem & Storage](linux/filesystem-and-storage.md) • [Archives & Compression](linux/archives-compression.md) |

### 🛡️ Sécurité & Hardening

**Renforcer votre infrastructure** selon les standards SecNumCloud.

| Action | Documentation |
|--------|---------------|
| **SSH Hardening** | [Bonnes Pratiques de Sécurité SSH](linux/ssh-hardening.md) |
| **Firewall Linux** | [UFW Configuration](linux/firewall-ufw.md) |
| **Windows Security** | [Defender, BitLocker & Events](windows/windows-security.md) |
| **Certificats TLS** | [Certificate Management](security/certificates.md) • [OpenSSL CLI](security/openssl-cli.md) |
| **Pentest Tools** | [Exegol Framework](security/exegol.md) • [CTF Guide](security/ctf-guide.md) |

### 🚀 Déploiement & Automatisation

**Déployer rapidement et de manière reproductible.**

| Besoin | Stack |
|--------|-------|
| **CI/CD** | [GitHub Actions for Ops](devops/cicd-github-actions.md) |
| **Orchestration** | [Ansible Playbooks](devops/ansible/playbooks.md) • [Ansible Industrialization](devops/ansible/industrialization.md) |
| **Conteneurs** | [Docker Advanced](devops/docker-advanced.md) |
| **Monitoring** | [Prometheus, Loki & Grafana](devops/observability-stack.md) |

---

## 📚 Architecture du Savoir

<div class="grid cards" markdown>

-   :fontawesome-brands-linux:{ .lg .middle } **Linux (30+ Guides)**

    ---

    Le cœur de l'infrastructure moderne : système, réseau, services et automatisation.

    **Couvre :** Boot & Services • Filesystem & LVM • SSH Hardening • Nginx/Apache • Bash Scripting

    [:octicons-arrow-right-24: Explorer Linux](linux/demo.md)

-   :fontawesome-brands-windows:{ .lg .middle } **Windows (9 Guides)**

    ---

    Administration Windows Server et Desktop : PowerShell, AD et sécurité.

    **Couvre :** PowerShell Foundations • Active Directory • GPO • BitLocker • Defender

    [:octicons-arrow-right-24: Explorer Windows](windows/index.md)

-   :material-kubernetes:{ .lg .middle } **Kubernetes (4 Guides)**

    ---

    Orchestration de conteneurs en production : CKA, debugging et networking.

    **Couvre :** CKA Prep • kubectl Survival • Services & Ingress • GitOps ArgoCD

    [:octicons-arrow-right-24: Explorer Kubernetes](devops/kubernetes-survival.md)

-   :material-shield-lock:{ .lg .middle } **Security (7 Guides)**

    ---

    Sécurité offensive et défensive : cryptographie, red team et hardening.

    **Couvre :** Certificates & OpenSSL • Exegol • CTF Methodology • HashiCorp Vault

    [:octicons-arrow-right-24: Explorer Security](security/certificates.md)

-   :material-layers-triple:{ .lg .middle } **DevOps (15+ Guides)**

    ---

    CI/CD, conteneurs et automatisation : Docker, Ansible, Terraform et GitOps.

    **Couvre :** GitHub Actions • GitLab CI • Docker Advanced • Ansible • Observability

    [:octicons-arrow-right-24: Explorer DevOps](devops/git-sysops.md)

-   :material-network:{ .lg .middle } **Réseau & Infrastructure**

    ---

    Fondamentaux réseau et haute disponibilité : CIDR, load balancing et database HA.

    **Couvre :** CIDR • TCP/IP • Load Balancing L4/L7 • Database Clustering

    [:octicons-arrow-right-24: Explorer Réseau](network/fundamentals.md)

</div>

---

## 🧰 Outils du Quotidien

### Cheatsheets Haute Densité

**Les fiches de référence à garder ouvertes dans un onglet.**

| Outil | Fiche | Cas d'Usage |
|-------|-------|-------------|
| **OpenSSL** | [OpenSSL CLI](security/openssl-cli.md) | Générer certificats, CSR, vérifier chaînes TLS |
| **PowerShell** | [PowerShell Foundations](windows/powershell-foundations.md) | Objets, pipelines, remoting |
| **Git** | [Git for SysOps](devops/git-sysops.md) | Workflows, branches, troubleshooting |
| **Kubectl** | [Kubectl Survival](devops/kubernetes-survival.md) | Debug pods, logs, port-forward |
| **Ansible** | [Ansible Fundamentals](devops/ansible/fundamentals.md) | Inventaires, modules, idempotence |
| **Prometheus** | [PromQL Basics](devops/observability-stack.md#prometheus-le-collecteur-de-metriques) | Métriques, alertes, exporters |

---

## 💡 Commencer

!!! tip "Navigation Rapide"
    - Utilisez **Ctrl+K** (ou **Cmd+K** sur Mac) pour rechercher n'importe quelle commande
    - Les **tags** en haut de chaque page permettent de filtrer par technologie
    - Les sections **Quick Reference** en fin de page regroupent les commandes essentielles

!!! example "Parcours Recommandés"
    **Nouveau sur Linux ?**
    → [Linux Productivity](linux/productivity.md) → [Modern Tools](linux/modern-tools.md) → [Bash Wizardry](linux/bash-wizardry.md)

    **Préparer la CKA ?**
    → [Kubernetes CKA](devops/kubernetes-cka.md) → [Kubectl Survival](devops/kubernetes-survival.md) → [K8s Networking](devops/kubernetes-networking.md)

    **Sécuriser un serveur ?**
    → [SSH Hardening](linux/ssh-hardening.md) → [Firewall UFW](linux/firewall-ufw.md) → [Logs Management](linux/logs-management.md)

---

## 🤝 Contribution

Ce projet suit les standards **SecNumCloud** pour la sécurité et la conformité.

- 📖 Documentation : Markdown + MkDocs Material
- 🚀 Déploiement : GitHub Actions → GitHub Pages
- 🔒 Sécurité : Pas de secrets hardcodés, validation manuelle en production

---

<div style="text-align: center; color: #64748b; margin-top: 3em;">
  <p><strong>ShellBook</strong> - Votre cerveau opérationnel externalisé</p>
  <p>Linux • Windows • Kubernetes • DevOps • Security</p>
</div>
