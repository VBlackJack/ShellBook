---
tags:
  - formation
  - security
  - linux
  - hardening
  - secnumcloud
---

# Hardening Linux & Sécurité : Introduction & Programme

## Objectifs de cette Formation

À l'issue de ce parcours, vous serez capable de :

- 🔐 **Sécuriser SSH** : Désactiver root login, clés SSH, port knocking, fail2ban
- 👥 **Gérer les privilèges** : Configuration sudo, principe du moindre privilège, sudoers.d
- 🔥 **Configurer le firewall** : Maîtriser firewalld/ufw, zones, rich rules, filtrage applicatif
- 🔍 **Auditer le système** : OpenSCAP, AIDE, auditd, logs centralisés
- ✅ **Conformité SecNumCloud** : Appliquer les recommandations ANSSI pour le Cloud

## Public Cible

Cette formation s'adresse aux **professionnels de la sécurité IT** :

- Administrateurs systèmes Linux (RHEL, Ubuntu, Debian)
- Security Engineers responsables du hardening
- DevSecOps intégrant la sécurité dans les pipelines
- Auditeurs techniques (ISO 27001, SecNumCloud)

**Niveau requis :** Intermédiaire (administration Linux de base requise)

## Contexte : SecNumCloud

Le référentiel **SecNumCloud** de l'ANSSI définit les exigences de sécurité pour les offres de Cloud qualifiées en France. Cette formation couvre les contrôles techniques Linux du référentiel :

- **SEC-01** : Authentification forte (SSH keys, MFA)
- **SEC-02** : Gestion des privilèges (sudo, RBAC)
- **SEC-03** : Filtrage réseau (firewall, segmentation)
- **SEC-04** : Journalisation et audit (auditd, SIEM)
- **SEC-05** : Durcissement système (SELinux, AppArmor)

!!! info "Référentiel SecNumCloud"
    Le guide complet est disponible sur le site de l'ANSSI : [SecNumCloud Référentiel](https://www.ssi.gouv.fr/entreprise/qualifications/prestataires-de-services-de-confiance-qualifies/prestataires-de-service-dinformatique-en-nuage-secnumcloud/)

## Prérequis

!!! warning "Connaissances Nécessaires"
    Avant de commencer, assurez-vous de maîtriser :

    - ✅ **Linux Administration** : Gestion des paquets, services, permissions
    - ✅ **Réseau TCP/IP** : Modèle OSI, ports, protocoles (SSH, HTTP, HTTPS)
    - ✅ **Terminal Bash** : Commandes de base, pipes, redirections
    - ✅ **Accès root/sudo** : Environnement de test (VM ou container)

    **Ressources :**

    - [Guide SSH Hardening ShellBook](../../linux/ssh-hardening.md)
    - [RHEL Security & SELinux](../../linux/rhel-security-selinux.md)
    - [Firewalld & NetworkManager](../../linux/rhel-networking.md)

## Programme

### Module 1 : Sécuriser SSH (1h30)

**Objectif :** Transformer SSH en forteresse : authentification par clés, désactivation de root, fail2ban.

**Contenu :**

- Configuration `/etc/ssh/sshd_config` : Bonnes pratiques
- Authentification par clés SSH (génération, déploiement)
- Désactiver le login root (`PermitRootLogin no`)
- Changer le port SSH (sécurité par l'obscurité ?)
- Fail2ban : Bannir les attaques par force brute
- Port knocking avancé
- Diagramme : Flux d'authentification SSH avec clés

[:octicons-arrow-right-24: Module en cours de rédaction](#)

### Module 2 : Gestion des Utilisateurs & Sudo (1h)

**Objectif :** Appliquer le principe du moindre privilège avec sudo et les permissions.

**Contenu :**

- Créer des utilisateurs dédiés (pas de compte partagé)
- Configuration sudo : `/etc/sudoers` vs `/etc/sudoers.d/`
- Syntaxe sudoers : `User Host = (RunAs) Commands`
- Logs sudo : Traçabilité des actions privilégiées
- Exemples :
  - Permettre le redémarrage de nginx sans mot de passe
  - Restreindre un utilisateur à `systemctl restart postgresql`
- Diagramme : Matrice de permissions (User → Role → Commands)

[:octicons-arrow-right-24: Module en cours de rédaction](#)

### Module 3 : Firewall - Firewalld & UFW (2h)

**Objectif :** Maîtriser le filtrage réseau avec firewalld (RHEL) et ufw (Ubuntu).

**Contenu :**

**Firewalld (RHEL/CentOS):**

- Zones (public, trusted, drop, dmz)
- Services prédéfinis vs ports personnalisés
- Rich rules pour filtrage avancé
- Exemple : Autoriser SSH uniquement depuis un subnet `192.168.1.0/24`

**UFW (Ubuntu/Debian):**

- Syntaxe simplifiée (`ufw allow 22/tcp`)
- Application profiles (`ufw allow 'Nginx Full'`)
- Logs et monitoring (`ufw status verbose`)

**Cas pratique :**

- Serveur web : Autoriser 80/443, bloquer le reste
- Serveur DB : Autoriser PostgreSQL uniquement depuis l'app server

[:octicons-arrow-right-24: Module en cours de rédaction](#)

### Module 4 : Audit & Conformité (2h)

**Objectif :** Auditer le système avec OpenSCAP, AIDE et auditd.

**Contenu :**

**OpenSCAP (Compliance Scanning):**

- Installer `scap-security-guide`
- Lancer un scan : `oscap xccdf eval --profile stig ...`
- Interpréter le rapport HTML
- Remediation automatique (avec prudence)

**AIDE (Advanced Intrusion Detection Environment):**

- Créer une baseline de l'état du système
- Détecter les modifications non autorisées (`/etc/`, `/bin/`)
- Planifier les scans avec cron

**Auditd (Kernel Audit Framework):**

- Activer auditd (`systemctl enable auditd`)
- Règles d'audit : Surveiller `/etc/passwd`, `/etc/shadow`
- Rechercher dans les logs : `ausearch`, `aureport`
- Centraliser les logs avec rsyslog vers un SIEM

[:octicons-arrow-right-24: Module en cours de rédaction](#)

### Module 5 : TP Final - Hardening Complet (3h)

**Objectif :** Appliquer tous les concepts sur un serveur de production simulé.

**Contexte :**

Vous êtes Security Engineer dans une entreprise soumise à SecNumCloud. Votre mission : durcir un serveur RHEL 9 hébergeant une application web.

**Tâches :**

1. **SSH :** Configurer l'authentification par clés, désactiver root, activer fail2ban
2. **Users :** Créer un utilisateur `appuser` avec sudo restreint au service nginx
3. **Firewall :** Autoriser SSH (depuis VPN), HTTP/HTTPS (public), bloquer le reste
4. **Audit :** Lancer un scan OpenSCAP STIG, corriger les findings critiques
5. **Monitoring :** Configurer AIDE et auditd pour surveiller `/etc/` et `/var/www/`
6. **Documentation :** Rédiger un rapport de conformité SecNumCloud

**Livrables :**

- Configuration SSH (`/etc/ssh/sshd_config`)
- Règles sudo (`/etc/sudoers.d/appuser`)
- Règles firewall (commandes `firewall-cmd`)
- Rapport OpenSCAP HTML
- Rapport de conformité (Markdown)

[:octicons-arrow-right-24: Module en cours de rédaction](#)

## Durée Estimée

| Module | Durée | Type |
|--------|-------|------|
| Module 1 : SSH Hardening | 1h30 | Pratique guidée |
| Module 2 : Users & Sudo | 1h | Configuration |
| Module 3 : Firewall | 2h | Hands-on |
| Module 4 : Audit & Conformité | 2h | OpenSCAP + AIDE |
| Module 5 : TP Final | 3h | Projet autonome |
| **Total** | **9h30** | **Formation complète** |

!!! tip "Organisation Recommandée"
    **Format présentiel :** 3 jours (3h par jour)

    **Format asynchrone :** 2 semaines à votre rythme

    **Environnement requis :** VM RHEL 9 ou Ubuntu 22.04 avec accès root

## Compétences Acquises

À la fin de cette formation, vous serez capable de :

- ✅ Sécuriser SSH selon les standards ANSSI
- ✅ Configurer sudo avec le principe du moindre privilège
- ✅ Gérer un firewall Linux (firewalld/ufw)
- ✅ Auditer la conformité avec OpenSCAP
- ✅ Détecter les intrusions avec AIDE et auditd
- ✅ Rédiger un rapport de conformité SecNumCloud

## Certification

Cette formation prépare aux certifications suivantes :

- **RHCSA (Red Hat Certified System Administrator)** : Module Users & Firewall
- **CompTIA Security+** : Hardening & Audit
- **ANSSI SecNumCloud** : Conformité Cloud souverain

Une fois la formation complétée, vous pouvez valider vos compétences avec le **TP Final** comme portfolio.

## Ressources Complémentaires

- [Guide ANSSI - Recommandations de sécurité relatives à un système GNU/Linux](https://www.ssi.gouv.fr/guide/recommandations-de-securite-relatives-a-un-systeme-gnulinux/)
- [CIS Benchmarks for Linux](https://www.cisecurity.org/cis-benchmarks/)
- [RHEL Security Hardening Guide](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html/security_hardening/index)
- [OpenSCAP Documentation](https://www.open-scap.org/getting-started/)
- [Guide SSH Hardening ShellBook](../../linux/ssh-hardening.md)

## Support

**Questions ou problèmes ?**

- 💬 [Discussions GitHub](https://github.com/VBlackJack/ShellBook/discussions)
- 🐛 [Issues GitHub](https://github.com/VBlackJack/ShellBook/issues)
- 📧 Contact : security@shellbook.io

---

**Prêt ?** Module 1 en cours de rédaction 🚀
