---
tags:
  - formation
  - cloud
  - conteneurs
  - docker
  - kubernetes
  - orchestration
---

# Module 8 : Introduction aux Conteneurs & Kubernetes

**Durée estimée :** 45 minutes

## Objectifs du Module

A la fin de ce module, vous serez capable de :

- :fontawesome-solid-box: Comprendre ce qu'est un conteneur et ses avantages
- :fontawesome-solid-docker: Connaître les concepts de base de Docker
- :fontawesome-solid-dharmachakra: Expliquer le rôle de Kubernetes
- :fontawesome-solid-scale-balanced: Comparer les services conteneurs des cloud providers
- :fontawesome-solid-lightbulb: Identifier les cas d'usage adaptés

---

## 1. Le Problème que Résolvent les Conteneurs

### 1.1 Le Cauchemar du "Ça Marche Sur Ma Machine"

```mermaid
graph TB
    subgraph "Avant les Conteneurs"
        DEV["💻 Poste Dev<br/>Python 3.8<br/>Ubuntu 20.04"]
        TEST["🧪 Serveur Test<br/>Python 3.6<br/>CentOS 7"]
        PROD["🏭 Production<br/>Python 3.9<br/>RHEL 8"]
    end

    DEV -->|"😱 Ça ne marche pas !"| TEST
    TEST -->|"😱 Bugs en prod !"| PROD

    style DEV fill:#4caf50,color:#fff
    style TEST fill:#FF9800800800,color:#fff
    style PROD fill:#f44336,color:#fff
```

**Problèmes classiques :**
- Versions de langages différentes
- Librairies manquantes ou incompatibles
- Configuration OS différente
- "Ça marche chez moi" devient la phrase la plus prononcée

### 1.2 La Solution : Les Conteneurs

```mermaid
graph TB
    subgraph "Avec les Conteneurs"
        CONTAINER["📦 Container<br/>App + Python 3.8 + Libs<br/>= Même partout"]

        DEV["💻 Poste Dev"]
        TEST["🧪 Serveur Test"]
        PROD["🏭 Production"]
    end

    CONTAINER --> DEV
    CONTAINER --> TEST
    CONTAINER --> PROD

    style CONTAINER fill:#2196f3,color:#fff
    style DEV fill:#4caf50,color:#fff
    style TEST fill:#4caf50,color:#fff
    style PROD fill:#4caf50,color:#fff
```

!!! success "Principe Clé"
    Un conteneur embarque l'application **ET** tout son environnement d'exécution. Ce qui tourne en dev tourne de façon identique en production.

---

## 2. Conteneurs vs Machines Virtuelles

### 2.1 Comparaison Visuelle

```mermaid
graph TB
    subgraph "Machine Virtuelle"
        VM_HW["🖥️ Hardware"]
        VM_HV["Hyperviseur"]
        VM_OS1["OS Complet<br/>(Linux)"]
        VM_OS2["OS Complet<br/>(Windows)"]
        VM_APP1["App 1"]
        VM_APP2["App 2"]

        VM_HW --> VM_HV
        VM_HV --> VM_OS1
        VM_HV --> VM_OS2
        VM_OS1 --> VM_APP1
        VM_OS2 --> VM_APP2
    end

    subgraph "Conteneurs"
        C_HW["🖥️ Hardware"]
        C_OS["OS Hôte (Linux)"]
        C_ENGINE["🐳 Container Engine"]
        C_APP1["📦 Container 1"]
        C_APP2["📦 Container 2"]
        C_APP3["📦 Container 3"]

        C_HW --> C_OS
        C_OS --> C_ENGINE
        C_ENGINE --> C_APP1
        C_ENGINE --> C_APP2
        C_ENGINE --> C_APP3
    end

    style VM_OS1 fill:#FF9800800800,color:#fff
    style VM_OS2 fill:#FF9800800800,color:#fff
    style C_ENGINE fill:#2196f3,color:#fff
```

### 2.2 Tableau Comparatif

| Caractéristique | Machine Virtuelle | Conteneur |
|-----------------|-------------------|-----------|
| **Isolation** | Complète (OS séparé) | Processus isolés |
| **Taille** | Go (OS complet) | Mo (juste l'app) |
| **Démarrage** | Minutes | Secondes |
| **Ressources** | Lourdes (RAM, CPU réservés) | Légères (partagées) |
| **Portabilité** | Moyenne (format VM) | Excellente (images) |
| **Densité** | 10-20 VMs/serveur | 100+ containers/serveur |
| **Usage** | Workloads isolés, multi-OS | Microservices, CI/CD |

### 2.3 Analogie du Transport

```mermaid
graph LR
    subgraph "VM = Camion avec remorque"
        TRUCK["🚛 Camion complet<br/>Moteur + Remorque<br/>= Lourd mais autonome"]
    end

    subgraph "Container = Conteneur maritime"
        SHIP["🚢 Bateau"]
        TRAIN["🚂 Train"]
        TRUCK2["🚛 Camion"]
        CONT["📦 Même conteneur<br/>sur tous les transports"]

        CONT --> SHIP
        CONT --> TRAIN
        CONT --> TRUCK2
    end

    style TRUCK fill:#FF9800800800,color:#fff
    style CONT fill:#2196f3,color:#fff
```

!!! info "Analogie"
    Un conteneur Docker est comme un conteneur maritime : standardisé, empilable, et transportable sur n'importe quelle infrastructure (bateau, train, camion = laptop, serveur, cloud).

---

## 3. Docker : Les Concepts de Base

### 3.1 Vocabulaire Essentiel

```mermaid
mindmap
  root((Docker))
    Image
      Template lecture seule
      Couches empilees
      Versionnee tag
    Container
      Instance d une image
      Processus isole
      Ephemere
    Registry
      Docker Hub
      AWS ECR
      Azure ACR
      Google GCR
    Dockerfile
      Recette de construction
      Instructions sequentielles
      Build automatise
```

### 3.2 Définitions Simples

| Concept | Définition Simple | Analogie |
|---------|-------------------|----------|
| **Image** | Modèle pour créer des conteneurs | Classe en programmation |
| **Container** | Instance en cours d'exécution | Objet instancié |
| **Dockerfile** | Recette pour construire une image | Makefile |
| **Registry** | Bibliothèque d'images | GitHub pour les images |
| **Volume** | Stockage persistant | Disque externe |
| **Network** | Réseau entre conteneurs | LAN virtuel |

### 3.3 Cycle de Vie d'un Conteneur

```mermaid
graph LR
    DOCKERFILE["📝 Dockerfile"]
    BUILD["🔨 docker build"]
    IMAGE["📦 Image"]
    PUSH["📤 docker push"]
    REGISTRY["🏛️ Registry"]
    PULL["📥 docker pull"]
    RUN["▶️ docker run"]
    CONTAINER["🐳 Container"]
    STOP["⏹️ docker stop"]

    DOCKERFILE --> BUILD --> IMAGE
    IMAGE --> PUSH --> REGISTRY
    REGISTRY --> PULL --> IMAGE
    IMAGE --> RUN --> CONTAINER
    CONTAINER --> STOP

    style IMAGE fill:#2196f3,color:#fff
    style CONTAINER fill:#4caf50,color:#fff
    style REGISTRY fill:#FF9800800800,color:#fff
```

### 3.4 Exemple Concret (Sans Code)

**Scénario** : Vous avez une application Python Flask

**Étapes simplifiées :**

1. **Écrire un Dockerfile** (recette) :
   - Partir d'une image Python officielle
   - Copier le code de l'application
   - Installer les dépendances
   - Définir la commande de démarrage

2. **Construire l'image** : `docker build`
   - Crée une image avec un tag (version)

3. **Tester localement** : `docker run`
   - Lance un conteneur basé sur l'image

4. **Publier** : `docker push`
   - Envoie l'image vers un registry

5. **Déployer** : Le serveur de production récupère la même image

!!! tip "Avantage"
    L'image est **identique** partout. Pas de surprise en production.

---

## 4. Kubernetes : L'Orchestrateur

### 4.1 Pourquoi un Orchestrateur ?

```mermaid
graph TB
    subgraph "Problème : Gérer Beaucoup de Conteneurs"
        Q1["❓ Comment déployer 100 conteneurs ?"]
        Q2["❓ Comment répartir la charge ?"]
        Q3["❓ Que faire si un conteneur plante ?"]
        Q4["❓ Comment faire une mise à jour sans coupure ?"]
        Q5["❓ Comment gérer les secrets ?"]
    end

    subgraph "Solution : Kubernetes"
        A1["✅ Déploiement déclaratif"]
        A2["✅ Load balancing automatique"]
        A3["✅ Self-healing (redémarrage auto)"]
        A4["✅ Rolling updates"]
        A5["✅ Gestion des secrets"]
    end

    Q1 --> A1
    Q2 --> A2
    Q3 --> A3
    Q4 --> A4
    Q5 --> A5

    style A1 fill:#4caf50,color:#fff
    style A2 fill:#4caf50,color:#fff
    style A3 fill:#4caf50,color:#fff
    style A4 fill:#4caf50,color:#fff
    style A5 fill:#4caf50,color:#fff
```

### 4.2 Architecture Simplifiée

```mermaid
graph TB
    subgraph "Kubernetes Cluster"
        subgraph "Control Plane (Cerveau)"
            API["🎯 API Server<br/>Point d'entrée"]
            SCHED["📋 Scheduler<br/>Placement"]
            CTRL["⚙️ Controllers<br/>Boucle de contrôle"]
        end

        subgraph "Worker Nodes (Muscles)"
            NODE1["🖥️ Node 1"]
            NODE2["🖥️ Node 2"]
            NODE3["🖥️ Node 3"]

            POD1["📦 Pod"]
            POD2["📦 Pod"]
            POD3["📦 Pod"]
            POD4["📦 Pod"]
        end
    end

    USER["👤 Utilisateur"] --> API
    API --> SCHED
    SCHED --> NODE1
    SCHED --> NODE2
    SCHED --> NODE3
    NODE1 --> POD1
    NODE1 --> POD2
    NODE2 --> POD3
    NODE3 --> POD4

    style API fill:#2196f3,color:#fff
    style POD1 fill:#4caf50,color:#fff
    style POD2 fill:#4caf50,color:#fff
    style POD3 fill:#4caf50,color:#fff
    style POD4 fill:#4caf50,color:#fff
```

### 4.3 Concepts Clés Kubernetes

| Concept | Description Simple | Analogie |
|---------|-------------------|----------|
| **Cluster** | Ensemble de machines (nodes) | Datacenter |
| **Node** | Une machine (physique ou VM) | Serveur |
| **Pod** | Plus petite unité, 1+ conteneurs | Appartement |
| **Deployment** | Gère les réplicas de Pods | Manager d'équipe |
| **Service** | Point d'entrée stable vers Pods | Numéro de téléphone |
| **Namespace** | Isolation logique | Dossier |
| **Ingress** | Routage HTTP/HTTPS externe | Réceptionniste |

### 4.4 Self-Healing en Action

```mermaid
sequenceDiagram
    participant User as 👤 Utilisateur
    participant K8s as ☸️ Kubernetes
    participant Pod as 📦 Pod

    User->>K8s: "Je veux 3 Pods"
    K8s->>Pod: Crée Pod 1, 2, 3
    Note over K8s,Pod: État souhaité = 3 Pods

    Pod->>K8s: Pod 2 crash ! 💥
    K8s->>K8s: Détecte : 2 Pods < 3 souhaités
    K8s->>Pod: Crée Pod 4
    Note over K8s,Pod: Retour à 3 Pods ✅

    Note right of K8s: Boucle continue 24/7
```

!!! success "Magie de Kubernetes"
    Vous déclarez l'état souhaité ("je veux 3 instances"), Kubernetes s'assure que cet état est maintenu en permanence.

---

## 5. Services Conteneurs Cloud

### 5.1 Panorama des Options

```mermaid
graph TB
    subgraph "Niveau d'Abstraction"
        SELF["🔧 Self-Managed<br/>(K8s sur VMs)"]
        MANAGED["☸️ Managed Kubernetes<br/>(EKS, AKS, GKE)"]
        SERVERLESS["λ Serverless Containers<br/>(Fargate, Cloud Run)"]
    end

    SELF -->|"Plus de contrôle"| MANAGED
    MANAGED -->|"Plus d'abstraction"| SERVERLESS

    style SELF fill:#f44336,color:#fff
    style MANAGED fill:#FF9800800800,color:#fff
    style SERVERLESS fill:#4caf50,color:#fff
```

### 5.2 Services par Provider

| Catégorie | AWS | Azure | GCP |
|-----------|-----|-------|-----|
| **Managed Kubernetes** | EKS | AKS | GKE |
| **Container Registry** | ECR | ACR | GCR / Artifact Registry |
| **Serverless Containers** | Fargate, App Runner | Container Apps | Cloud Run |
| **Container Instances** | - | Container Instances | - |

### 5.3 Quand Utiliser Quoi ?

```mermaid
flowchart TD
    START["🤔 Conteneurs : Quel service ?"] --> Q1{"Avez-vous besoin de<br/>Kubernetes ?"}

    Q1 -->|"Non, juste un conteneur"| Q2{"Trafic prévisible ?"}
    Q1 -->|"Oui, orchestration complexe"| MANAGED["☸️ Managed K8s<br/>(EKS/AKS/GKE)"]

    Q2 -->|"Non, sporadique"| SERVERLESS["λ Serverless<br/>(Cloud Run, Fargate)"]
    Q2 -->|"Oui, constant"| INSTANCES["📦 Container service simple<br/>(App Runner, Container Apps)"]

    style MANAGED fill:#FF9800800800,color:#fff
    style SERVERLESS fill:#4caf50,color:#fff
    style INSTANCES fill:#2196f3,color:#fff
```

| Cas d'Usage | Service Recommandé |
|-------------|-------------------|
| **Application simple, peu de trafic** | Serverless (Cloud Run, Fargate) |
| **Microservices complexes** | Managed Kubernetes |
| **Migration d'apps existantes** | Managed Kubernetes |
| **Batch processing** | Serverless containers |
| **Besoin de contrôle total** | Self-managed K8s (rare) |

---

## 6. Cas d'Usage Worldline

### 6.1 Microservices Payment Gateway

```mermaid
graph TB
    subgraph "Kubernetes Cluster"
        INGRESS["🚪 Ingress Controller"]

        subgraph "Namespace: payment"
            AUTH["🔐 Auth Service<br/>3 replicas"]
            PAYMENT["💳 Payment Service<br/>5 replicas"]
            FRAUD["🚨 Fraud Service<br/>3 replicas"]
            NOTIF["📧 Notification<br/>2 replicas"]
        end

        subgraph "Namespace: monitoring"
            PROM["📊 Prometheus"]
            GRAF["📈 Grafana"]
        end
    end

    MERCHANT["🏪 Marchand"] --> INGRESS
    INGRESS --> AUTH
    AUTH --> PAYMENT
    PAYMENT --> FRAUD
    PAYMENT --> NOTIF

    style AUTH fill:#2196f3,color:#fff
    style PAYMENT fill:#4caf50,color:#fff
    style FRAUD fill:#f44336,color:#fff
```

### 6.2 Avantages pour Worldline

| Avantage | Application |
|----------|-------------|
| **Scaling automatique** | Black Friday : x10 replicas automatiquement |
| **Déploiement sans coupure** | Rolling updates pendant les heures de pointe |
| **Isolation** | Chaque service peut scaler indépendamment |
| **Multi-cloud** | Même manifeste K8s sur AWS, Azure ou GCP |
| **Self-healing** | Si un pod crash, redémarrage automatique |

---

## 7. Quiz de Validation

!!! question "Question 1"
    Quelle est la principale différence entre une VM et un conteneur ?

    ??? success "Réponse"
        **Le conteneur partage le kernel de l'OS hôte**, alors que la VM embarque un OS complet.

        Conséquences :
        - Conteneur plus léger (Mo vs Go)
        - Démarrage plus rapide (secondes vs minutes)
        - Plus dense (plus de conteneurs par serveur)

!!! question "Question 2"
    Qu'est-ce qu'un Pod dans Kubernetes ?

    ??? success "Réponse"
        **La plus petite unité déployable**, contenant un ou plusieurs conteneurs qui partagent :
        - Le même réseau (localhost)
        - Le même stockage
        - La même IP

        Généralement, 1 Pod = 1 conteneur applicatif.

!!! question "Question 3"
    Pourquoi utiliser un orchestrateur comme Kubernetes ?

    ??? success "Réponse"
        Pour gérer automatiquement :
        - **Déploiement** : Déclaratif, reproductible
        - **Scaling** : Horizontal auto
        - **Self-healing** : Redémarrage auto des conteneurs crashés
        - **Load balancing** : Répartition du trafic
        - **Rolling updates** : Mises à jour sans downtime

!!! question "Question 4"
    Quel service cloud choisir pour un conteneur simple avec trafic sporadique ?

    ??? success "Réponse"
        **Serverless containers** : Cloud Run (GCP), Fargate (AWS), Container Apps (Azure)

        Avantages :
        - Pas de cluster à gérer
        - Scale to zero (économies)
        - Paiement à l'exécution

---

## 8. Pour Aller Plus Loin

### 8.1 Ressources Recommandées

| Ressource | Type | Description |
|-----------|------|-------------|
| [Docker 101](https://www.docker.com/101-tutorial/) | Tutoriel | Introduction officielle Docker |
| [Kubernetes Basics](https://kubernetes.io/docs/tutorials/kubernetes-basics/) | Tutoriel | Tutoriel interactif K8s |
| [Play with Docker](https://labs.play-with-docker.com/) | Lab gratuit | Environnement Docker en ligne |
| [Katacoda](https://www.katacoda.com/courses/kubernetes) | Lab gratuit | Labs Kubernetes interactifs |

### 8.2 Formations ShellBook Avancées

- [Kubernetes Survival Guide](../../devops/kubernetes-survival.md)
- [Kubernetes CKA](../../devops/kubernetes-cka.md)
- [Docker Advanced](../../devops/docker-advanced.md)

---

## 9. Glossaire Conteneurs

| Terme | Définition |
|-------|------------|
| **Container** | Environnement isolé contenant une application et ses dépendances |
| **Image** | Template immutable pour créer des conteneurs |
| **Registry** | Dépôt d'images (Docker Hub, ECR, ACR, GCR) |
| **Orchestrateur** | Outil de gestion de conteneurs à grande échelle |
| **Pod** | Groupe de conteneurs partageant ressources (K8s) |
| **Cluster** | Ensemble de machines exécutant Kubernetes |
| **Node** | Machine (physique ou VM) dans un cluster |
| **Namespace** | Isolation logique dans Kubernetes |
| **Deployment** | Ressource K8s gérant le cycle de vie des Pods |
| **Service** | Abstraction réseau exposant des Pods |

---

## Exercice : À Vous de Jouer

!!! example "Mise en Pratique"
    **Objectif** : Déployer une application microservices sur Kubernetes dans le cloud

    **Contexte** : Vous devez containeriser et déployer une API de paiement composée de 3 services (auth, payment, notification) sur un cluster Kubernetes managé (EKS/AKS/GKE).

    **Tâches à réaliser** :

    1. Choisissez entre ECS/Fargate (AWS), AKS (Azure), ou GKE (GCP) et justifiez
    2. Décrivez l'architecture Kubernetes : pods, services, ingress
    3. Configurez le scaling automatique (HPA) basé sur CPU et mémoire
    4. Proposez une stratégie de déploiement sans downtime (rolling update)

    **Critères de validation** :

    - [ ] Service Kubernetes managé sélectionné avec justification
    - [ ] Architecture avec 3 microservices isolés
    - [ ] HPA configuré correctement
    - [ ] Rolling update pour déploiement zero-downtime

??? quote "Solution"
    **1. Choix : GKE (Google Kubernetes Engine)**
    - Kubernetes natif de Google (créateurs de K8s)
    - Auto-scaling cluster intégré
    - Bonne intégration avec services GCP

    **2. Architecture Kubernetes :**
    ```bash
    # Déploiement des 3 microservices
    kubectl create deployment auth-service --image=auth:v1 --replicas=3
    kubectl create deployment payment-service --image=payment:v1 --replicas=5
    kubectl create deployment notif-service --image=notif:v1 --replicas=2

    # Services internes
    kubectl expose deployment auth-service --port=8080
    kubectl expose deployment payment-service --port=8081
    kubectl expose deployment notif-service --port=8082

    # Ingress pour exposition HTTPS
    kubectl apply -f ingress.yaml
    ```

    **3. HPA (Horizontal Pod Autoscaler) :**
    ```bash
    kubectl autoscale deployment payment-service \
      --cpu-percent=70 \
      --min=5 --max=50
    ```

    **4. Rolling update zero-downtime :**
    ```bash
    kubectl set image deployment/payment-service \
      payment=payment:v2 \
      --record

    # Stratégie : 25% max unavailable, 25% max surge
    ```

---

## Navigation

| Précédent | Suivant |
|-----------|---------|
| [Module 7 : Cas d'Usage Worldline](07-module.md) | [Module 9 : DevOps & CI/CD](09-module.md) |

---

## Navigation

| | |
|:---|---:|
| [← Module 7 : Cas d'Usage Worldline](07-module.md) | [Module 9 : DevOps & CI/CD pour Débutants →](09-module.md) |

[Retour au Programme](index.md){ .md-button }
