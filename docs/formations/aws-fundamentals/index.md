---
tags:
  - formation
  - aws
  - amazon-web-services
  - cloud
  - infrastructure
  - devops
---

# AWS Fundamentals : De l'On-Premise au Cloud Amazon

## Objectifs de cette Formation

À l'issue de ce parcours, vous serez capable de :

- :material-aws: **Naviguer** dans la Console AWS et gérer les comptes/organisations
- :fontawesome-solid-user-shield: **Configurer** IAM avec le principe du moindre privilège (Users, Roles, Policies)
- :fontawesome-solid-server: **Déployer** des instances EC2 (VMs, templates, Auto Scaling Groups)
- :fontawesome-solid-network-wired: **Architecturer** des réseaux VPC (subnets, Security Groups, NAT, VPN)
- :fontawesome-solid-database: **Gérer** le stockage (S3, EBS, RDS, Aurora, DynamoDB)
- :material-kubernetes: **Orchestrer** des containers avec EKS (Elastic Kubernetes Service)
- :fontawesome-solid-rocket: **Automatiser** les déploiements avec CodePipeline et CodeBuild
- :fontawesome-solid-bolt: **Créer** des applications serverless (Lambda, Fargate, Step Functions)
- :fontawesome-solid-shield-halved: **Sécuriser** avec WAF, Secrets Manager et KMS
- :fontawesome-solid-chart-line: **Superviser** avec CloudWatch, X-Ray et Synthetics

## Public Cible

Cette formation s'adresse aux **administrateurs systèmes migrant vers le cloud** :

- Administrateurs Linux/Windows souhaitant acquérir des compétences cloud
- Ingénieurs infrastructure préparant une migration on-premise → AWS
- DevOps Engineers étendant leurs compétences multi-cloud
- Candidats aux certifications **AWS Solutions Architect**, **SysOps Administrator**, **Cloud Practitioner**

**Niveau requis :** Intermédiaire (Linux, Networking TCP/IP, concepts virtualisation)

## Prérequis

!!! info "Connaissances Nécessaires"
    Avant de commencer, assurez-vous de maîtriser :

    - ✅ **Linux Administration** : SSH, utilisateurs, services, firewall (iptables/firewalld)
    - ✅ **Networking** : TCP/IP, subnets, CIDR, NAT, DNS, VPN concepts
    - ✅ **Virtualisation** : Concepts VMs, hyperviseurs, images
    - ✅ **Ligne de commande** : Confort avec bash/shell

    **Optionnel mais recommandé :**

    - Expérience avec un autre cloud (GCP, Azure)
    - Notions de containers (Docker)
    - YAML/JSON pour la configuration

    **Ressources :**

    - [Guide Linux ShellBook](../../linux/index.md)
    - [Guide Networking](../../network/fundamentals.md)

## Programme

### Module 1 : Console AWS, Comptes & IAM (3h)

**Objectif :** Maîtriser l'organisation AWS et la gestion des identités.

**Contenu :**

- **Hiérarchie AWS** : Organizations → OUs → Accounts → Resources
- **Console Cloud** : Navigation, CloudShell, APIs
- **IAM (Identity and Access Management)** :
    - Users, Groups, Roles
    - Policies : AWS Managed, Customer Managed, Inline
    - Service Control Policies (SCPs)
- **Best Practices** : Principe du moindre privilège, MFA, audit

[:octicons-arrow-right-24: Commencer le Module 1](01-module.md){ .md-button .md-button--primary }

### Module 2 : EC2 - Compute dans le Cloud (4h)

**Objectif :** Déployer et gérer des machines virtuelles AWS.

**Contenu :**

- **Instance Types** : Familles (t3, m6i, c6i, r6i), sizing
- **AMIs** : Amazon Machine Images, custom images
- **EBS** : Volumes, snapshots, types (gp3, io2)
- **Auto Scaling** : Launch Templates, ASG, scaling policies
- **Optimisation coûts** : Spot, Reserved, Savings Plans

[:octicons-arrow-right-24: Commencer le Module 2](02-module.md){ .md-button .md-button--primary }

### Module 3 : VPC & Networking (4h)

**Objectif :** Concevoir des architectures réseau sécurisées sur AWS.

**Contenu :**

- **VPC** : Subnets, CIDR, Internet Gateway
- **Security Groups & NACLs** : Firewall stateful vs stateless
- **Connectivité** : NAT Gateway, VPN, Transit Gateway
- **Load Balancing** : ALB, NLB, Target Groups
- **VPC Endpoints** : Gateway et Interface (PrivateLink)

[:octicons-arrow-right-24: Commencer le Module 3](03-module.md){ .md-button .md-button--primary }

### Module 4 : Storage & Databases (4h)

**Objectif :** Choisir et configurer les solutions de stockage AWS.

**Contenu :**

- **S3** : Buckets, classes de stockage, lifecycle, encryption
- **EBS** : Types, performance, snapshots
- **EFS** : Shared storage, mount targets
- **RDS** : Multi-AZ, read replicas, Aurora
- **DynamoDB** : NoSQL, capacity modes, GSI/LSI

[:octicons-arrow-right-24: Commencer le Module 4](04-module.md){ .md-button .md-button--primary }

### Module 5 : EKS & Containers (4h)

**Objectif :** Déployer et opérer des applications containerisées avec EKS.

**Contenu :**

- **ECR** : Registry Docker privé
- **EKS** : Cluster, node groups, Fargate profiles
- **IRSA** : IAM Roles for Service Accounts
- **Add-ons** : ALB Controller, EBS CSI Driver
- **Autoscaling** : HPA, Cluster Autoscaler, Karpenter

[:octicons-arrow-right-24: Commencer le Module 5](05-module.md){ .md-button .md-button--primary }

### Module 6 : TP Final - Infrastructure Production-Ready (4h)

**Objectif :** Concevoir et déployer une infrastructure complète sur AWS.

**Contexte :**

Vous êtes Cloud Engineer dans une startup déployant une application 3-tier. Votre mission : créer une infrastructure production-ready avec VPC, EKS, Aurora, et monitoring complet.

[:octicons-arrow-right-24: Commencer le TP Final](06-tp-final.md){ .md-button .md-button--primary }

### Module 7 : CI/CD avec CodePipeline & CodeBuild (3h)

**Objectif :** Automatiser les déploiements avec les outils DevOps AWS.

**Contenu :**

- **CodeBuild** : buildspec.yml, projets, caching
- **CodePipeline** : Stages, actions, approvals
- **CodeDeploy** : Blue/Green, Canary
- **Intégration EKS** : Déploiement Kubernetes

[:octicons-arrow-right-24: Commencer le Module 7](07-module.md){ .md-button .md-button--primary }

### Module 8 : Serverless - Lambda & Fargate (3h)

**Objectif :** Déployer des applications sans gérer d'infrastructure.

**Contenu :**

- **Lambda** : Functions, triggers, layers, container images
- **API Gateway** : HTTP APIs, REST APIs
- **Fargate** : Tasks, services, ECS
- **Step Functions** : Workflows, state machines
- **EventBridge** : Event routing, scheduling

[:octicons-arrow-right-24: Commencer le Module 8](08-module.md){ .md-button .md-button--primary }

### Module 9 : Security - WAF, Secrets Manager & KMS (3h)

**Objectif :** Sécuriser les applications et les données sur AWS.

**Contenu :**

- **WAF** : Web Application Firewall, rules, managed rule groups
- **Secrets Manager** : Gestion secrets, rotation automatique
- **KMS** : Customer Managed Keys, envelope encryption
- **IAM Access Analyzer** : Détection accès externes
- **Security Hub & GuardDuty** : Threat detection, compliance

[:octicons-arrow-right-24: Commencer le Module 9](09-module.md){ .md-button .md-button--primary }

### Module 10 : Observability - CloudWatch & X-Ray (3h)

**Objectif :** Superviser et debugger les applications en production.

**Contenu :**

- **CloudWatch Metrics** : Custom metrics, anomaly detection
- **CloudWatch Logs** : Logs Insights, metric filters
- **CloudWatch Alarms** : Composite alarms, actions
- **Dashboards** : Visualisation, widgets
- **X-Ray** : Distributed tracing, service map
- **Synthetics** : Canaries, SLO monitoring

[:octicons-arrow-right-24: Commencer le Module 10](10-module.md){ .md-button .md-button--primary }

## Durée Estimée

| Module | Durée | Type |
|--------|-------|------|
| Module 1 : Console, Comptes & IAM | 3h | Théorie + Pratique |
| Module 2 : EC2 - Compute | 4h | Pratique guidée |
| Module 3 : VPC & Networking | 4h | Architecture |
| Module 4 : Storage & Databases | 4h | Pratique + Design |
| Module 5 : EKS & Containers | 4h | Orchestration |
| Module 6 : TP Final | 4h | Projet autonome |
| Module 7 : CI/CD (CodePipeline) | 3h | DevOps |
| Module 8 : Serverless | 3h | Architecture moderne |
| Module 9 : Security | 3h | Sécurité avancée |
| Module 10 : Observability | 3h | Opérations |
| **Total** | **35h** | **Formation complète** |

!!! tip "Organisation Recommandée"
    **Format présentiel :** 5 jours intensifs (7h/jour)

    **Format asynchrone :** 5-6 semaines à votre rythme

    **Environnement requis :** Compte AWS avec billing activé (Free Tier + nouveaux comptes)

## Compétences Acquises

À la fin de cette formation, vous serez capable de :

- ✅ Naviguer et administrer des comptes AWS via Console et CLI
- ✅ Configurer IAM avec Users, Roles et policies appropriées
- ✅ Déployer des EC2 avec Auto Scaling et optimisation coûts
- ✅ Concevoir des architectures VPC sécurisées multi-AZ
- ✅ Choisir et configurer les solutions de stockage adaptées
- ✅ Déployer des applications sur EKS avec IRSA
- ✅ Automatiser les déploiements avec CodePipeline
- ✅ Créer des applications serverless (Lambda, Fargate)
- ✅ Sécuriser les workloads (WAF, Secrets Manager, KMS)
- ✅ Implémenter l'observabilité (CloudWatch, X-Ray)
- ✅ Estimer et optimiser les coûts cloud

## Certifications

Cette formation prépare aux certifications :

- **AWS Certified Cloud Practitioner** (CLF-C02)
    - Examen : 90 min, 65 questions
    - Coût : $100 USD
    - [Guide officiel](https://aws.amazon.com/certification/certified-cloud-practitioner/)

- **AWS Certified Solutions Architect - Associate** (SAA-C03)
    - Examen : 130 min, 65 questions
    - Coût : $150 USD
    - [Guide officiel](https://aws.amazon.com/certification/certified-solutions-architect-associate/)

- **AWS Certified SysOps Administrator - Associate** (SOA-C02)
    - Examen : 180 min, 65 questions + labs
    - Coût : $150 USD
    - [Guide officiel](https://aws.amazon.com/certification/certified-sysops-admin-associate/)

!!! info "Ressources de préparation"
    - [AWS Skill Builder](https://skillbuilder.aws/) (cours gratuits)
    - [AWS Hands-on Labs](https://aws.amazon.com/training/digital/)
    - [Examens pratiques officiels](https://aws.amazon.com/certification/certification-prep/)

## Coûts AWS pour la Formation

!!! warning "Estimation des coûts"
    Les exercices de cette formation utilisent des ressources payantes. Estimation pour suivre la formation complète :

    | Ressource | Coût estimé |
    |-----------|-------------|
    | EC2 (t3.medium, ~25h) | ~$8 |
    | RDS (db.t3.micro, ~10h) | ~$5 |
    | EKS (cluster + nodes, ~8h) | ~$15 |
    | S3, EBS, autres | ~$5 |
    | **Total estimé** | **~$35** |

    **Tips :**

    - Nouveau compte AWS = **$300 de crédits gratuits** (3 mois)
    - Toujours **supprimer les ressources** après les exercices
    - Utiliser les **instances Spot** quand possible

## Ressources Complémentaires

- [Documentation AWS](https://docs.aws.amazon.com/)
- [AWS Architecture Center](https://aws.amazon.com/architecture/)
- [AWS CLI Reference](https://awscli.amazonaws.com/v2/documentation/api/latest/index.html)
- [AWS Well-Architected Framework](https://aws.amazon.com/architecture/well-architected/)
- [AWS Blog](https://aws.amazon.com/blogs/)
- [Awesome AWS (GitHub)](https://github.com/donnemartin/awesome-aws)

## Support

**Questions ou problèmes ?**

- :fontawesome-brands-github: [Discussions GitHub](https://github.com/VBlackJack/ShellBook/discussions)
- :fontawesome-solid-bug: [Issues GitHub](https://github.com/VBlackJack/ShellBook/issues)

---

**Prêt à migrer vers le cloud AWS ?** [:octicons-arrow-right-24: Commencer le Module 1](01-module.md){ .md-button .md-button--primary }

---

**Retour au :** [Catalogue des Formations](../index.md)
