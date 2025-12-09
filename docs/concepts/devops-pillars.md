---
tags:
  - devops
  - architecture
  - culture
---

# Les 6 Piliers du DevOps

Ne vous perdez pas dans les outils. Il n'y a que **6 problèmes à résoudre**.

---

## 1. Configuration Management

**Concept :** Garantir que chaque serveur est configuré de manière identique, à chaque fois, sans intervention manuelle. Infrastructure as Code.

!!! tip "L'Analogie du Restaurant : La Recette"
    Un chef n'improvise pas chaque plat. Il suit une **recette standardisée** pour garantir la cohérence.

    Configuration management est votre livre de recettes - mêmes ingrédients, mêmes étapes, même résultat sur chaque serveur.

**Problème résolu :** Syndrome "ça marche sur ma machine", dérive de configuration, erreurs de configuration manuelle.

**Outils Leaders :**

| Outil | Type | Idéal Pour |
|------|------|----------|
| **Ansible** | Agentless, Push | Automatisation simple, multi-OS |
| **Terraform** | Déclaratif | Provisionnement d'infrastructure cloud |
| **Puppet** | Agent-based, Pull | Environnements d'entreprise larges |
| **Chef** | Agent-based, Ruby DSL | Configurations complexes |
| **SaltStack** | Hybride | Automatisation événementielle |

---

## 2. Containers

**Concept :** Empaqueter les applications avec toutes les dépendances dans des unités isolées et portables qui s'exécutent de manière identique partout.

!!! tip "L'Analogie du Restaurant : Le Repas Pré-emballé"
    Au lieu de cuisiner à partir de zéro, vous recevez un **repas pré-emballé** qui nécessite juste d'être réchauffé.

    Les containers livrent tout ce qui est nécessaire - pas d'ingrédients manquants, pas de problème "je n'ai pas cette épice".

**Problème résolu :** Enfer des dépendances, incohérences d'environnement, "ça marche sur mon laptop".

**Outils Leaders :**

| Outil | Objectif |
|------|---------|
| **Docker** | Runtime de containers (standard de l'industrie) |
| **Podman** | Alternative sans root, sans daemon |
| **containerd** | Runtime de bas niveau (utilisé par K8s) |
| **Buildah** | Construire des images OCI sans daemon |
| **Kaniko** | Construire des images dans Kubernetes |

---

## 3. CI/CD (Continuous Integration / Continuous Delivery)

**Concept :** Automatiser le pipeline de build, test et déploiement. Chaque changement de code déclenche un workflow automatisé.

!!! tip "L'Analogie du Restaurant : La Chaîne d'Assemblage de Cuisine"
    Les commandes arrivent, et la **chaîne d'assemblage** prend le relais - station de préparation, station de grill, dressage, livraison.

    CI/CD est votre cuisine automatisée : code en entrée, artefact testé en sortie, déployé en production.

**Problème résolu :** Déploiements manuels, bugs d'intégration découverts tard, cycles de release lents.

**Étapes du Pipeline :**

```text
Code → Build → Test → Security Scan → Deploy → Monitor
        ↓       ↓          ↓            ↓
      Compile  Unit    SAST/DAST    Staging → Prod
               E2E     Container
```

**Outils Leaders :**

| Outil | Type | Idéal Pour |
|------|------|----------|
| **GitLab CI** | Intégré | Plateforme DevOps complète |
| **GitHub Actions** | Cloud-native | Workflows centrés sur GitHub |
| **Jenkins** | Auto-hébergé | Flexibilité, plugins |
| **ArgoCD** | GitOps | Déploiements Kubernetes |
| **Tekton** | Cloud-native | Pipelines natifs Kubernetes |

---

## 4. Orchestration

**Concept :** Gérer le cycle de vie des containers à grande échelle - planification, mise à l'échelle, réseau et auto-réparation.

!!! tip "L'Analogie du Restaurant : Le Maître d'Hôtel"
    Le **maître d'hôtel** décide quelle table obtient quel serveur, équilibre les charges de travail, et réassigne le personnel quand quelqu'un appelle malade.

    L'orchestration place vos containers, équilibre la charge, et remplace les instances défaillantes automatiquement.

**Problème résolu :** Gestion manuelle des containers, décisions de mise à l'échelle, découverte de services, basculement.

**Capacités Clés :**

- **Scheduling :** Placer les containers sur les nœuds appropriés
- **Scaling :** Ajouter/supprimer des réplicas selon la charge
- **Self-healing :** Redémarrer les containers défaillants
- **Service discovery :** Les containers se trouvent entre eux
- **Rolling updates :** Déploiements sans temps d'arrêt

**Outils Leaders :**

| Outil | Complexité | Idéal Pour |
|------|------------|----------|
| **Kubernetes (K8s)** | Élevée | Production, toute échelle |
| **Docker Swarm** | Faible | Orchestration simple |
| **Nomad** | Moyenne | Multi-workload (containers + VMs) |
| **Amazon ECS** | Moyenne | Gestion de containers native AWS |
| **OpenShift** | Élevée | Kubernetes d'entreprise |

---

## 5. Cloud

**Concept :** Infrastructure à la demande qui évolue de manière élastique. Payez ce que vous utilisez, provisionnez en minutes au lieu de mois.

!!! tip "L'Analogie du Restaurant : Personnel Freelance"
    Pendant les heures de pointe, vous appelez du **personnel freelance**. Quand c'est calme, vous les renvoyez chez eux.

    Le cloud fournit une capacité élastique - lancez 100 serveurs pour le Black Friday, réduisez à 10 le lundi.

**Problème résolu :** Planification de capacité, délais d'approvisionnement matériel, serveurs sous-utilisés.

**Modèles de Service :**

| Modèle | Vous Gérez | Fournisseur Gère | Exemple |
|-------|------------|------------------|---------|
| **IaaS** | OS, Apps, Données | Matériel, Réseau | EC2, GCE |
| **PaaS** | Apps, Données | OS, Runtime | Heroku, App Engine |
| **SaaS** | Données seulement | Tout le reste | Gmail, Salesforce |
| **FaaS** | Code seulement | Tout le reste | Lambda, Cloud Functions |

**Fournisseurs Leaders :**

| Fournisseur | Force |
|----------|----------|
| **AWS** | Étendue des services, leader du marché |
| **Azure** | Intégration d'entreprise, cloud hybride |
| **GCP** | Data/ML, natif Kubernetes |
| **OVH** | Souveraineté européenne (SecNumCloud) |
| **Scaleway** | Européen, orienté développeurs |

---

## 6. Observability

**Concept :** Comprendre ce qui se passe à l'intérieur de vos systèmes via des métriques, des logs et des traces. Déboguer efficacement les problèmes de production.

!!! tip "L'Analogie du Restaurant : L'Inspecteur Qualité"
    L'**inspecteur qualité** vérifie chaque plat, surveille les températures de cuisine, et alerte quand quelque chose ne va pas.

    L'observabilité vous donne des yeux sur la production - l'app est-elle saine ? Pourquoi est-elle lente ? Où cette requête a-t-elle échoué ?

**Problème résolu :** Déploiements à l'aveugle, réponse lente aux incidents, "je ne sais pas pourquoi c'est en panne".

**Les Trois Piliers :**

| Pilier | Quoi | Exemples d'Outils |
|--------|------|---------------|
| **Metrics** | Mesures numériques au fil du temps | Prometheus, Datadog, Grafana |
| **Logs** | Enregistrements d'événements avec contexte | ELK Stack, Loki, Splunk |
| **Traces** | Flux de requête à travers les services | Jaeger, Zipkin, Tempo |

**Stacks Leaders :**

```text
Prometheus + Grafana + Alertmanager    → Métriques & Alerting
ELK (Elasticsearch + Logstash + Kibana) → Agrégation de logs
Grafana Loki                           → Logs légers
Jaeger / Tempo                         → Tracing distribué
```

---

## Tableau Récapitulatif

| Pilier | Problème Résolu | Analogie | Outil Clé |
|--------|----------------|---------|----------|
| **Configuration Mgmt** | Cohérence, dérive | La Recette | Ansible, Terraform |
| **Containers** | Isolation des dépendances | Repas Pré-emballé | Docker |
| **CI/CD** | Déploiements manuels | Chaîne d'Assemblage | GitLab CI, GitHub Actions |
| **Orchestration** | Cycle de vie des containers | Maître d'Hôtel | Kubernetes |
| **Cloud** | Élasticité, mise à l'échelle | Personnel Freelance | AWS, Azure, GCP |
| **Observability** | Visibilité, débogage | Inspecteur Qualité | Prometheus, Grafana |

---

!!! example "Vue d'Ensemble"
    ```text
    Code → Pipeline CI/CD → Image Container → Registry
                                    ↓
    Infrastructure Cloud ← Terraform/Ansible
                                    ↓
    Cluster Kubernetes → Déploie les Containers
                                    ↓
    Prometheus/Grafana → Surveille Tout
    ```

!!! warning "Les Outils Changent, Pas les Concepts"
    Jenkins peut être remplacé par GitLab CI. Docker Swarm a perdu face à Kubernetes.
    Mais les **6 piliers restent constants**. Maîtrisez les concepts, adaptez-vous aux outils.
