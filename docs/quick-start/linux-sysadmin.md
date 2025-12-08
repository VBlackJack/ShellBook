---
tags:
  - quick-start
  - linux
  - sysadmin
  - parcours
---

# Parcours Linux SysAdmin

Guide de démarrage rapide pour les administrateurs système Linux.

## Votre Boîte à Outils Essentielle

### Cheatsheets Indispensables

| Cheatsheet | Usage |
|------------|-------|
| [SSH](../linux/cheatsheet-ssh.md) | Connexions sécurisées, tunnels, clés |
| [Systemd](../linux/cheatsheet-systemd.md) | Gestion des services |
| [Health Check](../scripts/bash/health-check.md) | Vérification système |

### Scripts Prêts à l'Emploi

```bash
# Audit serveur complet
./server-discovery-audit.sh

# Vérification santé serveur
./health-check.sh --all

# Analyse des logs
./log-analyzer.sh /var/log/syslog
```

- [Server Audit](../scripts/bash/server-discovery-audit.md) - Audit complet du système
- [Log Analyzer](../scripts/bash/log-analyzer.md) - Analyse des logs
- [Backup Validator](../scripts/python/backup_validator.md) - Vérification des sauvegardes

---

## Parcours d'Apprentissage Recommandé

### Niveau 1 : Fondamentaux

```mermaid
graph LR
    A[Filesystem] --> B[Processus]
    B --> C[Services]
    C --> D[Réseau]
```

1. **Filesystem et Stockage**
   - [Filesystem et Stockage](../linux/filesystem-and-storage.md)
   - LVM, RAID, montages, quotas

2. **Boot et Services**
   - [Boot et Services](../linux/boot-and-services.md)
   - GRUB, systemd, targets

3. **Outils Modernes**
   - [Outils Modernes CLI](../linux/modern-tools.md)
   - bat, exa, ripgrep, fzf

### Niveau 2 : Administration Avancée

4. **Systemd Avancé**
   - [Systemd Avancé](../linux/systemd-advanced.md)
   - Timers, slices, journald

5. **SSH Avancé**
   - [Tunnels SSH](../linux/ssh-tunnels.md)
   - ProxyJump, SOCKS, port forwarding

6. **Audit et Conformité**
   - [RHEL Ops Audit](../linux/rhel-ops-audit.md)
   - Audit système, conformité

### Niveau 3 : Sécurité

7. **SELinux**
   - [RHEL Security SELinux](../linux/rhel-security-selinux.md)
   - Contextes, policies, troubleshooting

8. **Kernel Debugging**
   - [Kernel Debugging](../linux/kernel-debugging.md)
   - strace, perf, crash analysis

---

## Formation Structurée

Pour un apprentissage progressif et complet :

| Formation | Modules | Niveau |
|-----------|---------|--------|
| [Linux Mastery](../formations/linux-mastery/index.md) | 12 modules | Débutant → Intermédiaire |
| [Linux Hardening](../formations/linux-hardening/index.md) | 10 modules | Intermédiaire |
| [Python SysOps](../formations/python-sysops/index.md) | 10 modules | Intermédiaire |

---

## Tâches Quotidiennes

### Diagnostic Rapide

```bash
# État des services
systemctl --failed

# Espace disque
df -h | grep -E '^/dev'

# Processus gourmands
ps aux --sort=-%mem | head -10

# Connexions réseau
ss -tulpn

# Dernières connexions
last -n 20
```

### Maintenance

```bash
# Nettoyage des logs
journalctl --vacuum-time=7d

# Mise à jour sécurité (RHEL/CentOS)
dnf update --security

# Vérification intégrité
rpm -Va | grep -v '^.......T'
```

---

## Ressources Complémentaires

- [Linux Reference](../linux/index.md) - Référence complète
- [Scripts Bash](../scripts/bash/index.md) - Bibliothèque de scripts
- [Scripts Python](../scripts/python/index.md) - Outils d'administration

---

| [← Quick Start](index.md) | [Windows Admin →](windows-admin.md) |
|:--------------------------|------------------------------------:|

