---
tags:
  - formation
  - gcp
  - google-cloud
  - cloud
  - infrastructure
  - devops
---

# GCP Fundamentals : De l'On-Premise au Cloud Google

## Objectifs de cette Formation

À l'issue de ce parcours, vous serez capable de :

- :material-google-cloud:{ .lg } **Naviguer** dans la Console GCP et gérer les projets/organisations
- :fontawesome-solid-user-shield: **Configurer** IAM avec le principe du moindre privilège (Service Accounts, Roles)
- :fontawesome-solid-server: **Déployer** des instances Compute Engine (VMs, templates, instance groups)
- :fontawesome-solid-network-wired: **Architector** des réseaux VPC (subnets, firewall rules, Cloud NAT, VPN)
- :fontawesome-solid-database: **Gérer** le stockage (Cloud Storage, Persistent Disks, Cloud SQL)
- :material-kubernetes: **Orchestrer** des containers avec GKE (Google Kubernetes Engine)
- :fontawesome-solid-terminal: **Automatiser** avec `gcloud` CLI et Infrastructure as Code

## Public Cible

Cette formation s'adresse aux **administrateurs systèmes migrant vers le cloud** :

- Administrateurs Linux/Windows souhaitant acquérir des compétences cloud
- Ingénieurs infrastructure préparant une migration on-premise → GCP
- DevOps Engineers étendant leurs compétences multi-cloud
- Candidats à la certification **Google Associate Cloud Engineer**

**Niveau requis :** Intermédiaire (Linux, Networking TCP/IP, concepts virtualisation)

## Prérequis

!!! info "Connaissances Nécessaires"
    Avant de commencer, assurez-vous de maîtriser :

    - ✅ **Linux Administration** : SSH, utilisateurs, services, firewall (iptables/firewalld)
    - ✅ **Networking** : TCP/IP, subnets, CIDR, NAT, DNS, VPN concepts
    - ✅ **Virtualisation** : Concepts VMs, hyperviseurs, images
    - ✅ **Ligne de commande** : Confort avec bash/shell

    **Optionnel mais recommandé :**

    - Expérience avec un autre cloud (AWS, Azure)
    - Notions de containers (Docker)
    - YAML pour la configuration

    **Ressources :**

    - [Guide Linux ShellBook](../../linux/index.md)
    - [Guide Networking](../../linux/hardware.md)

## Programme

### Module 1 : Console GCP, Projets & IAM (3h)

**Objectif :** Maîtriser l'organisation GCP et la gestion des identités.

**Contenu :**

- **Hiérarchie GCP** : Organisation → Folders → Projects → Resources
- **Console Cloud** : Navigation, Cloud Shell, APIs
- **IAM (Identity and Access Management)** :
    - Membres : Google Accounts, Service Accounts, Groups, Domains
    - Roles : Basic (Owner/Editor/Viewer), Predefined, Custom
    - Policies : Binding members ↔ roles au niveau projet/folder/org
- **Service Accounts** : Identités pour applications et VMs
- **gcloud CLI** : Installation, authentification, commandes essentielles
- **Best Practices** : Principe du moindre privilège, audit logs

[:octicons-arrow-right-24: Commencer le Module 1](01-module.md){ .md-button .md-button--primary }

### Module 2 : Compute Engine - VMs dans le Cloud (4h)

**Objectif :** Déployer et gérer des machines virtuelles GCP.

**Contenu :**

- **Compute Engine Basics** :
    - Machine types (standard, highmem, highcpu, custom)
    - Images : Public (Debian, Ubuntu, RHEL, Windows) vs Custom
    - Zones et Regions : Disponibilité et latence
- **Création de VMs** :
    - Console vs `gcloud compute instances create`
    - Startup scripts et metadata
    - SSH : Console, gcloud, OS Login
- **Disques** :
    - Persistent Disks (Standard, SSD, Balanced)
    - Local SSDs (éphémères, haute performance)
    - Snapshots et images
- **Instance Templates & Groups** :
    - Templates réutilisables
    - Managed Instance Groups (MIG) : Autoscaling, health checks
    - Unmanaged Instance Groups
- **Preemptible/Spot VMs** : Réduction de coûts jusqu'à 80%

[:octicons-arrow-right-24: Commencer le Module 2](02-module.md){ .md-button .md-button--primary }

### Module 3 : Networking - VPC & Connectivité (4h)

**Objectif :** Concevoir des architectures réseau sécurisées sur GCP.

**Contenu :**

- **VPC (Virtual Private Cloud)** :
    - VPC par défaut vs VPC custom
    - Subnets : Régionaux, auto-mode vs custom-mode
    - CIDR planning et IP ranges
- **Firewall Rules** :
    - Ingress/Egress, priority, targets (tags, service accounts)
    - Implied rules (deny all ingress, allow all egress)
    - Logging et monitoring
- **Connectivité externe** :
    - Cloud NAT : Accès Internet sans IP publique
    - Cloud Router : BGP dynamique
    - External IP : Static vs Ephemeral
- **Connectivité hybride** :
    - Cloud VPN : IPsec tunnels vers on-premise
    - Cloud Interconnect : Dedicated vs Partner
    - Peering VPC : Connecter des VPCs entre projets
- **Load Balancing** :
    - HTTP(S) Load Balancer (global, Layer 7)
    - Network Load Balancer (regional, Layer 4)
    - Internal Load Balancer

[:octicons-arrow-right-24: Commencer le Module 3](03-module.md){ .md-button .md-button--primary }

### Module 4 : Storage & Databases (4h)

**Objectif :** Choisir et configurer les solutions de stockage GCP.

**Contenu :**

- **Cloud Storage (Object Storage)** :
    - Buckets, objects, classes (Standard, Nearline, Coldline, Archive)
    - Lifecycle policies : Transition et expiration automatiques
    - Versioning et retention policies
    - IAM vs ACLs, signed URLs
    - `gsutil` CLI : cp, rsync, mb, rb
- **Persistent Disks** :
    - Types et performance (IOPS, throughput)
    - Resize sans downtime
    - Regional Persistent Disks (haute disponibilité)
- **Cloud SQL** :
    - MySQL, PostgreSQL, SQL Server managés
    - High Availability (failover automatique)
    - Backups, replicas, maintenance windows
    - Private IP vs Public IP
- **Autres options** :
    - Cloud Spanner : SQL distribué globalement
    - Firestore/Datastore : NoSQL document
    - BigQuery : Data warehouse analytique
    - Memorystore : Redis/Memcached managé

[:octicons-arrow-right-24: Commencer le Module 4](04-module.md){ .md-button .md-button--primary }

### Module 5 : GKE - Kubernetes sur GCP (4h)

**Objectif :** Déployer et opérer des applications containerisées avec GKE.

**Contenu :**

- **Containers & Kubernetes Basics** :
    - Docker concepts (images, containers, registries)
    - Kubernetes architecture : Control plane, nodes, pods
    - Pourquoi GKE vs self-managed Kubernetes
- **Créer un cluster GKE** :
    - Standard vs Autopilot mode
    - Node pools : Machine types, autoscaling
    - Networking : VPC-native, private clusters
- **Déployer des applications** :
    - `kubectl` : Deployments, Services, ConfigMaps, Secrets
    - Artifact Registry : Stocker les images Docker
    - Workload Identity : Service Accounts pour pods
- **Opérations** :
    - Upgrades de clusters (release channels)
    - Logging et monitoring (Cloud Operations)
    - Horizontal Pod Autoscaler (HPA)
- **Ingress & Services** :
    - ClusterIP, NodePort, LoadBalancer
    - GKE Ingress Controller (HTTP(S) LB intégré)

[:octicons-arrow-right-24: Commencer le Module 5](05-module.md){ .md-button .md-button--primary }

### Module 6 : TP Final - Infrastructure Production-Ready (4h)

**Objectif :** Concevoir et déployer une infrastructure complète sur GCP.

**Contexte :**

Vous êtes Cloud Engineer dans une entreprise migrant une application 3-tier vers GCP. Votre mission : déployer une infrastructure production-ready en respectant les best practices Google.

**Architecture cible :**

```
┌─────────────────────────────────────────────────────────────┐
│                        Internet                              │
└─────────────────────────┬───────────────────────────────────┘
                          │
                ┌─────────▼─────────┐
                │  Cloud Load       │
                │  Balancer (HTTPS) │
                └─────────┬─────────┘
                          │
         ┌────────────────┼────────────────┐
         │                │                │
    ┌────▼────┐     ┌────▼────┐     ┌────▼────┐
    │  GKE    │     │  GKE    │     │  GKE    │
    │  Pod 1  │     │  Pod 2  │     │  Pod 3  │
    │ (nginx) │     │ (nginx) │     │ (nginx) │
    └────┬────┘     └────┬────┘     └────┬────┘
         │               │               │
         └───────────────┼───────────────┘
                         │
              ┌──────────▼──────────┐
              │     Cloud SQL       │
              │    (PostgreSQL)     │
              │   Private IP only   │
              └─────────────────────┘
```

**Tâches :**

1. **Projet & IAM** :
    - Créer un projet dédié avec billing account
    - Configurer des Service Accounts (GKE, Cloud SQL)
    - Appliquer le principe du moindre privilège

2. **Réseau** :
    - VPC custom avec subnets (frontend, backend, database)
    - Firewall rules restrictives
    - Cloud NAT pour les nodes GKE

3. **Base de données** :
    - Cloud SQL PostgreSQL en High Availability
    - Private IP uniquement (pas d'accès public)
    - Backups automatiques

4. **Application** :
    - Cluster GKE Autopilot
    - Déployer une application de démo (nginx + backend)
    - Configurer Ingress avec certificat SSL managé

5. **Monitoring** :
    - Activer Cloud Operations (Logging, Monitoring)
    - Créer des alertes (CPU, erreurs 5xx)

**Livrables :**

- Scripts `gcloud` documentés
- Diagramme d'architecture Mermaid
- Documentation des choix techniques
- Estimation des coûts mensuels

[:octicons-arrow-right-24: Commencer le TP Final](06-tp-final.md){ .md-button .md-button--primary }

## Durée Estimée

| Module | Durée | Type |
|--------|-------|------|
| Module 1 : Console, Projets & IAM | 3h | Théorie + Pratique |
| Module 2 : Compute Engine | 4h | Pratique guidée |
| Module 3 : Networking & VPC | 4h | Architecture |
| Module 4 : Storage & Databases | 4h | Pratique + Design |
| Module 5 : GKE & Containers | 4h | Orchestration |
| Module 6 : TP Final | 4h | Projet autonome |
| **Total** | **23h** | **Formation complète** |

!!! tip "Organisation Recommandée"
    **Format présentiel :** 3 jours intensifs (8h/jour)

    **Format asynchrone :** 4-5 semaines à votre rythme

    **Environnement requis :** Compte GCP avec billing activé (Free Tier + $300 crédits nouveaux comptes)

## Compétences Acquises

À la fin de cette formation, vous serez capable de :

- ✅ Naviguer et administrer des projets GCP via Console et CLI
- ✅ Configurer IAM avec Service Accounts et roles appropriés
- ✅ Déployer des VMs avec templates et autoscaling
- ✅ Concevoir des architectures VPC sécurisées
- ✅ Choisir et configurer les solutions de stockage adaptées
- ✅ Déployer des applications sur GKE
- ✅ Estimer et optimiser les coûts cloud

## Certification

Cette formation prépare à la certification :

- **Google Cloud Associate Cloud Engineer**
    - Examen : 2h, 50 questions (QCM + études de cas)
    - Coût : $125 USD
    - Validité : 2 ans
    - [Guide officiel de l'examen](https://cloud.google.com/certification/cloud-engineer)

!!! info "Ressources de préparation"
    - [Examens pratiques officiels](https://cloud.google.com/certification/practice-exam/cloud-engineer)
    - [Coursera - Preparing for Google Cloud Certification](https://www.coursera.org/professional-certificates/cloud-engineering-gcp)
    - [Cloud Skills Boost (Qwiklabs)](https://www.cloudskillsboost.google/)

## Coûts GCP pour la Formation

!!! warning "Estimation des coûts"
    Les exercices de cette formation utilisent des ressources payantes. Estimation pour suivre la formation complète :

    | Ressource | Coût estimé |
    |-----------|-------------|
    | Compute Engine (e2-medium, ~20h) | ~$5 |
    | Cloud SQL (db-f1-micro, ~10h) | ~$3 |
    | GKE Autopilot (~5h) | ~$5 |
    | Cloud Storage | < $1 |
    | Network egress | < $1 |
    | **Total estimé** | **~$15** |

    **Tip :** Les nouveaux comptes GCP bénéficient de **$300 de crédits gratuits** pendant 90 jours.

## Ressources Complémentaires

- [Documentation Google Cloud](https://cloud.google.com/docs)
- [Google Cloud Architecture Center](https://cloud.google.com/architecture)
- [gcloud CLI Reference](https://cloud.google.com/sdk/gcloud/reference)
- [Cloud Skills Boost (Labs pratiques)](https://www.cloudskillsboost.google/)
- [Google Cloud Blog](https://cloud.google.com/blog/)
- [Awesome Google Cloud (GitHub)](https://github.com/GoogleCloudPlatform/awesome-google-cloud)

## Support

**Questions ou problèmes ?**

- :fontawesome-brands-github: [Discussions GitHub](https://github.com/VBlackJack/ShellBook/discussions)
- :fontawesome-solid-bug: [Issues GitHub](https://github.com/VBlackJack/ShellBook/issues)
- :fontawesome-solid-envelope: Contact : cloud@shellbook.io

---

**Prêt à migrer vers le cloud ?** [:octicons-arrow-right-24: Commencer le Module 1](01-module.md){ .md-button .md-button--primary }

---

**Retour au :** [Catalogue des Formations](../index.md)
