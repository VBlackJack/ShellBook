---
tags:
  - formation
  - linux
  - glossaire
  - reference
---

# Glossaire Linux

Ce glossaire couvre les termes essentiels rencontrés dans la formation Linux Mastery.

---

## A

**ACL (Access Control List)**
: Liste de contrôle d'accès permettant des permissions plus granulaires que le système Unix standard (user/group/other).

**API (Application Programming Interface)**
: Interface de programmation permettant à des applications de communiquer entre elles.

**APT (Advanced Package Tool)**
: Gestionnaire de paquets pour les distributions Debian et dérivées (Ubuntu).

**Ansible**
: Outil d'automatisation IT open source pour la gestion de configuration et le déploiement d'applications.

**AppArmor**
: Module de sécurité Linux (LSM) utilisé par Ubuntu pour confiner les programmes.

---

## B

**Bash (Bourne Again Shell)**
: Interpréteur de commandes par défaut sur la plupart des distributions Linux.

**Bind Mount**
: Montage qui rend un répertoire disponible à un autre emplacement du système de fichiers.

**BIOS (Basic Input/Output System)**
: Firmware qui initialise le matériel au démarrage avant de passer le contrôle au bootloader.

**Block Device**
: Périphérique de stockage accessible par blocs (disques, SSD).

**Boot Loader**
: Programme qui charge le système d'exploitation (GRUB, systemd-boot).

**Borg**
: Outil de sauvegarde avec déduplication et compression.

---

## C

**Cgroups (Control Groups)**
: Fonctionnalité du noyau Linux pour limiter, comptabiliser et isoler les ressources.

**CI/CD (Continuous Integration/Continuous Deployment)**
: Pratique DevOps d'intégration et déploiement continus.

**Cluster**
: Groupe de serveurs travaillant ensemble comme un système unique.

**ConfigMap**
: Ressource Kubernetes pour stocker des données de configuration non-confidentielles.

**Container**
: Unité standardisée de logiciel qui empaquète le code et ses dépendances.

**Corosync**
: Système de communication pour clusters haute disponibilité.

**Cron**
: Planificateur de tâches Unix/Linux.

---

## D

**Daemon**
: Processus qui s'exécute en arrière-plan (service).

**DHCP (Dynamic Host Configuration Protocol)**
: Protocole d'attribution automatique d'adresses IP.

**DNS (Domain Name System)**
: Système de résolution de noms de domaine en adresses IP.

**Docker**
: Plateforme de conteneurisation permettant d'empaqueter des applications.

**DNF (Dandified YUM)**
: Gestionnaire de paquets pour les distributions Red Hat et dérivées.

**DRBD (Distributed Replicated Block Device)**
: Solution de réplication de données en temps réel entre serveurs.

---

## E

**ELK Stack**
: Suite Elasticsearch, Logstash, Kibana pour la gestion des logs.

**Environment Variable**
: Variable accessible à tous les processus d'une session.

**Ext4**
: Système de fichiers par défaut sur de nombreuses distributions Linux.

**ETCD**
: Base de données clé-valeur distribuée utilisée par Kubernetes.

---

## F

**Failover**
: Basculement automatique vers un système de secours en cas de panne.

**Firewall**
: Système de filtrage du trafic réseau.

**FHS (Filesystem Hierarchy Standard)**
: Standard définissant l'arborescence des répertoires Linux.

**Fork**
: Création d'un nouveau processus à partir d'un processus existant.

---

## G

**Git**
: Système de contrôle de version distribué.

**GitOps**
: Pratique utilisant Git comme source unique de vérité pour l'infrastructure.

**GRUB (Grand Unified Bootloader)**
: Chargeur d'amorçage utilisé par la plupart des distributions Linux.

**GlusterFS**
: Système de fichiers distribué pour le stockage en cluster.

---

## H

**HA (High Availability)**
: Architecture visant à minimiser les interruptions de service.

**HAProxy**
: Load balancer et proxy haute performance.

**Hardening**
: Processus de sécurisation d'un système.

**Health Check**
: Vérification de l'état de santé d'un service.

**Helm**
: Gestionnaire de paquets pour Kubernetes.

**HPA (Horizontal Pod Autoscaler)**
: Composant Kubernetes qui scale automatiquement les pods.

---

## I

**IaC (Infrastructure as Code)**
: Pratique de gestion de l'infrastructure via du code versionné.

**Idempotent**
: Propriété d'une opération produisant le même résultat si exécutée plusieurs fois.

**Ingress**
: Ressource Kubernetes gérant l'accès externe aux services.

**Init System**
: Premier processus lancé au démarrage (systemd, SysV init).

**Inode**
: Structure de données contenant les métadonnées d'un fichier.

**Iostat**
: Outil de monitoring des I/O disque.

---

## J

**Journald**
: Service de logging de systemd.

**JSON (JavaScript Object Notation)**
: Format d'échange de données léger et lisible.

---

## K

**Keepalived**
: Daemon pour la haute disponibilité avec VRRP.

**Kernel**
: Noyau du système d'exploitation Linux.

**Kubectl**
: Interface en ligne de commande pour Kubernetes.

**Kubernetes (K8s)**
: Plateforme d'orchestration de conteneurs.

---

## L

**LDAP (Lightweight Directory Access Protocol)**
: Protocole d'accès aux annuaires.

**Load Balancer**
: Répartiteur de charge entre plusieurs serveurs.

**Logrotate**
: Utilitaire de rotation et compression des logs.

**LVM (Logical Volume Manager)**
: Gestionnaire de volumes logiques pour une gestion flexible du stockage.

---

## M

**Microservices**
: Architecture où l'application est composée de services indépendants.

**Mount**
: Action d'attacher un système de fichiers à l'arborescence.

**MQ (Message Queue)**
: File d'attente de messages pour la communication asynchrone.

---

## N

**Namespace**
: Mécanisme d'isolation des ressources (Linux kernel, Kubernetes).

**NAT (Network Address Translation)**
: Traduction d'adresses réseau.

**NFS (Network File System)**
: Protocole de partage de fichiers en réseau.

**Nginx**
: Serveur web et reverse proxy haute performance.

**Node**
: Machine (physique ou virtuelle) dans un cluster.

---

## O

**OOM (Out of Memory)**
: Situation où le système manque de mémoire.

**OOM Killer**
: Mécanisme du kernel qui termine des processus en cas de manque de mémoire.

**Overlay Network**
: Réseau virtuel au-dessus d'un réseau physique.

---

## P

**Pacemaker**
: Gestionnaire de ressources pour clusters haute disponibilité.

**Partition**
: Division logique d'un disque.

**PID (Process ID)**
: Identifiant unique d'un processus.

**Pipe**
: Mécanisme de communication entre processus via `|`.

**Pod**
: Plus petite unité déployable dans Kubernetes (groupe de conteneurs).

**Podman**
: Alternative rootless à Docker.

**Prometheus**
: Système de monitoring et d'alerting.

**Proxy**
: Intermédiaire entre un client et un serveur.

**PV/PVC (PersistentVolume/PersistentVolumeClaim)**
: Ressources Kubernetes pour le stockage persistant.

---

## R

**RAID**
: Technologie de redondance des disques.

**RBAC (Role-Based Access Control)**
: Contrôle d'accès basé sur les rôles.

**Replica**
: Copie d'une donnée ou d'un service.

**ReplicaSet**
: Ressource Kubernetes maintenant un nombre spécifié de pods.

**Repository**
: Dépôt de code source ou de paquets.

**Reverse Proxy**
: Proxy qui transmet les requêtes vers des serveurs backend.

**RPO (Recovery Point Objective)**
: Perte de données maximale acceptable.

**RTO (Recovery Time Objective)**
: Temps de récupération maximal acceptable.

**Rsync**
: Utilitaire de synchronisation de fichiers.

---

## S

**Samba**
: Implémentation du protocole SMB/CIFS pour le partage avec Windows.

**Scheduler**
: Composant qui décide où exécuter les tâches/pods.

**Secret**
: Ressource Kubernetes pour les données sensibles.

**SELinux (Security-Enhanced Linux)**
: Module de sécurité pour le contrôle d'accès obligatoire.

**Service**
: Processus en arrière-plan ou ressource Kubernetes exposant des pods.

**Shell**
: Interface en ligne de commande.

**SIGTERM/SIGKILL**
: Signaux Unix pour terminer un processus.

**SLA (Service Level Agreement)**
: Accord définissant le niveau de service garanti.

**SSH (Secure Shell)**
: Protocole de connexion sécurisée à distance.

**SSL/TLS**
: Protocoles de chiffrement des communications.

**StatefulSet**
: Ressource Kubernetes pour les applications avec état.

**Strace**
: Outil de traçage des appels système.

**Swap**
: Espace disque utilisé comme extension de la mémoire RAM.

**Systemd**
: Système d'initialisation et gestionnaire de services moderne.

---

## T

**Tar**
: Utilitaire d'archivage Unix.

**TCP/UDP**
: Protocoles de transport réseau.

**Terraform**
: Outil d'infrastructure as code de HashiCorp.

**Timer (systemd)**
: Alternative moderne à cron pour la planification de tâches.

**Trap**
: Mécanisme Bash pour intercepter les signaux.

---

## U

**UEFI (Unified Extensible Firmware Interface)**
: Firmware moderne remplaçant le BIOS.

**UID/GID**
: Identifiants utilisateur/groupe numériques.

**Umask**
: Masque définissant les permissions par défaut des nouveaux fichiers.

**Uptime**
: Temps depuis le dernier démarrage du système.

---

## V

**VIP (Virtual IP)**
: Adresse IP flottante pour la haute disponibilité.

**VM (Virtual Machine)**
: Machine virtuelle exécutée par un hyperviseur.

**Volume**
: Stockage persistant attaché à un conteneur ou pod.

**VRRP (Virtual Router Redundancy Protocol)**
: Protocole de redondance pour les routeurs/IPs.

---

## W

**Worker Node**
: Serveur exécutant les charges de travail dans un cluster Kubernetes.

---

## X

**XFS**
: Système de fichiers haute performance utilisé par défaut sur RHEL/Rocky.

---

## Y

**YAML (YAML Ain't Markup Language)**
: Format de sérialisation de données lisible par l'humain.

**YUM (Yellowdog Updater Modified)**
: Ancien gestionnaire de paquets Red Hat (remplacé par DNF).

---

## Z

**Zombie Process**
: Processus terminé dont le parent n'a pas encore lu le code de sortie.

**Zone (DNS)**
: Partie de l'espace de noms DNS gérée par un serveur autoritaire.

---

**Retour au :** [Programme de la Formation](index.md)
