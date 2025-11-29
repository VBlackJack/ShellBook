---
tags:
  - formation
  - cloud
  - architecture
  - haute-disponibilite
  - disaster-recovery
  - scalabilite
---

# Module 5 : Architecture Cloud (HA, DR, Scalabilité)

## Objectifs du Module

À la fin de ce module, vous serez capable de :

- :fontawesome-solid-heart-pulse: Concevoir une architecture haute disponibilité
- :fontawesome-solid-rotate: Planifier une stratégie de Disaster Recovery
- :fontawesome-solid-arrows-up-down: Comprendre les types de scalabilité
- :fontawesome-solid-diagram-project: Reconnaître les patterns d'architecture cloud
- :fontawesome-solid-calculator: Calculer et interpréter les SLA

---

## 1. Haute Disponibilité (HA)

### 1.1 Qu'est-ce que la Haute Disponibilité ?

!!! info "Définition"
    La **haute disponibilité** est la capacité d'un système à rester opérationnel malgré la défaillance de certains composants.

```mermaid
graph TB
    subgraph "❌ Sans HA"
        SINGLE["💻 Serveur unique"]
        SINGLE --> FAIL["💥 Panne = Service DOWN"]
    end

    subgraph "✅ Avec HA"
        LB["⚖️ Load Balancer"]
        S1["💻 Serveur 1"]
        S2["💻 Serveur 2"]
        S3["💻 Serveur 3"]
        LB --> S1
        LB --> S2
        LB --> S3
        S1 --> OK["Panne S1 = Service OK"]
    end

    style FAIL fill:#f44336,color:#fff
    style OK fill:#4caf50,color:#fff
```

### 1.2 Les Niveaux de Disponibilité (SLA)

| Disponibilité | Downtime/an | Downtime/mois | Catégorie |
|---------------|-------------|---------------|-----------|
| **99%** | 3.65 jours | 7.3 heures | Standard |
| **99.9%** | 8.76 heures | 43.8 minutes | Élevé |
| **99.95%** | 4.38 heures | 21.9 minutes | Très élevé |
| **99.99%** | 52.6 minutes | 4.38 minutes | Critique |
| **99.999%** | 5.26 minutes | 26.3 secondes | Mission critique |

!!! example "SLA Cloud Providers"
    | Service | AWS | Azure | GCP |
    |---------|-----|-------|-----|
    | **VM unique** | 99.5% | 99.9% | 99.5% |
    | **VM multi-AZ** | 99.99% | 99.99% | 99.99% |
    | **Object Storage** | 99.99% | 99.99% | 99.99% |
    | **Managed DB multi-AZ** | 99.95% | 99.99% | 99.95% |

### 1.3 Calcul du SLA Composite

```mermaid
graph LR
    LB["Load Balancer<br/>99.99%"] --> APP["App (2 VMs)<br/>99.99%"]
    APP --> DB["Database<br/>99.95%"]

    TOTAL["SLA Total = ?"]

    style TOTAL fill:#ff9800,color:#fff
```

**Formule** : SLA composite = SLA1 × SLA2 × SLA3

```
SLA = 99.99% × 99.99% × 99.95% = 99.93%
```

!!! warning "Attention"
    Chaque composant **diminue** la disponibilité globale. Plus vous avez de composants, plus le SLA baisse.

### 1.4 Patterns de Haute Disponibilité

#### Active-Active

```mermaid
graph TB
    LB["⚖️ Load Balancer"]
    subgraph "Zone A"
        A1["💻 Server A1<br/>ACTIVE"]
    end
    subgraph "Zone B"
        A2["💻 Server A2<br/>ACTIVE"]
    end

    LB --> A1
    LB --> A2

    style A1 fill:#4caf50,color:#fff
    style A2 fill:#4caf50,color:#fff
```

- Les deux serveurs traitent le trafic
- Capacité = Server1 + Server2
- Si un tombe, l'autre absorbe la charge

#### Active-Passive (Standby)

```mermaid
graph TB
    LB["⚖️ Load Balancer"]
    subgraph "Zone A"
        A1["💻 Server A1<br/>ACTIVE"]
    end
    subgraph "Zone B"
        A2["💻 Server A2<br/>STANDBY"]
    end

    LB --> A1
    A1 -.->|"Failover"| A2

    style A1 fill:#4caf50,color:#fff
    style A2 fill:#ff9800,color:#fff
```

- Un seul serveur traite le trafic
- Le second attend en standby
- Bascule automatique en cas de panne

---

## 2. Disaster Recovery (DR)

### 2.1 RPO et RTO

```mermaid
graph LR
    subgraph "Timeline d'un Incident"
        BACKUP["📸 Dernier Backup"]
        DISASTER["💥 Incident"]
        RECOVERY["✅ Reprise"]
    end

    BACKUP -->|"RPO<br/>(données perdues)"| DISASTER
    DISASTER -->|"RTO<br/>(temps d'arrêt)"| RECOVERY

    style DISASTER fill:#f44336,color:#fff
    style RECOVERY fill:#4caf50,color:#fff
```

| Métrique | Définition | Question |
|----------|------------|----------|
| **RPO** (Recovery Point Objective) | Quantité de données qu'on accepte de perdre | "Combien de temps de données perdues est acceptable ?" |
| **RTO** (Recovery Time Objective) | Temps pour rétablir le service | "En combien de temps doit-on être de nouveau opérationnel ?" |

### 2.2 Stratégies de DR

```mermaid
graph TB
    subgraph "Stratégies DR (coût croissant)"
        BACKUP["💾 Backup/Restore<br/>RTO: heures/jours<br/>Coût: $"]
        PILOT["🔥 Pilot Light<br/>RTO: dizaines de minutes<br/>Coût: $$"]
        WARM["♨️ Warm Standby<br/>RTO: minutes<br/>Coût: $$$"]
        HOT["🔥 Hot Standby<br/>RTO: secondes<br/>Coût: $$$$"]
    end

    BACKUP --> PILOT --> WARM --> HOT

    style BACKUP fill:#4caf50,color:#fff
    style PILOT fill:#8bc34a,color:#fff
    style WARM fill:#ff9800,color:#fff
    style HOT fill:#f44336,color:#fff
```

| Stratégie | Description | RTO | RPO | Coût |
|-----------|-------------|-----|-----|------|
| **Backup/Restore** | Données sauvegardées, infra recréée | Heures/Jours | Heures | $ |
| **Pilot Light** | Core infra tourne, reste à démarrer | 10-30 min | Minutes | $$ |
| **Warm Standby** | Infra complète tourne à échelle réduite | Minutes | Minutes | $$$ |
| **Hot Standby** | Infra identique en active-active | Secondes | Temps réel | $$$$ |

### 2.3 Architecture Multi-Région

```mermaid
graph TB
    subgraph "Region: Europe (Primary)"
        LB1["⚖️ LB"]
        APP1["💻 App"]
        DB1["🗄️ DB Primary"]
    end

    subgraph "Region: US (DR)"
        LB2["⚖️ LB"]
        APP2["💻 App (scaled down)"]
        DB2["🗄️ DB Replica"]
    end

    DNS["🌐 DNS (Route 53, Traffic Manager)"]

    USER["👥 Users"] --> DNS
    DNS -->|"Normal"| LB1
    DNS -.->|"Failover"| LB2
    DB1 -->|"Replication"| DB2

    style DB1 fill:#4caf50,color:#fff
    style DB2 fill:#ff9800,color:#fff
```

---

## 3. Scalabilité

### 3.1 Scaling Vertical vs Horizontal

```mermaid
graph TB
    subgraph "⬆️ Scaling Vertical (Scale Up)"
        V1["💻 Small<br/>2 CPU, 4GB"]
        V2["💻 Medium<br/>4 CPU, 8GB"]
        V3["💻 Large<br/>8 CPU, 16GB"]
        V1 --> V2 --> V3
    end

    subgraph "➡️ Scaling Horizontal (Scale Out)"
        H1["💻 Server 1"]
        H2["💻 Server 2"]
        H3["💻 Server 3"]
        H4["💻 Server 4"]
    end

    style V3 fill:#4caf50,color:#fff
    style H4 fill:#2196f3,color:#fff
```

| Type | Description | Avantages | Inconvénients |
|------|-------------|-----------|---------------|
| **Vertical** | Augmenter la taille d'une machine | Simple, pas de changement d'archi | Limite physique, downtime |
| **Horizontal** | Ajouter plus de machines | Pas de limite, HA naturelle | Complexité (stateless, LB) |

### 3.2 Auto Scaling

```mermaid
graph LR
    subgraph "Auto Scaling"
        METRIC["📊 Métriques<br/>(CPU, RAM, Requests)"]
        POLICY["📜 Politique<br/>Si CPU > 70%"]
        ACTION["⚡ Action<br/>Ajouter 2 instances"]
    end

    METRIC --> POLICY --> ACTION

    style POLICY fill:#ff9800,color:#fff
```

**Métriques courantes pour le scaling :**

| Métrique | Description | Exemple de seuil |
|----------|-------------|------------------|
| **CPU** | Utilisation processeur | > 70% → scale up |
| **Memory** | Utilisation mémoire | > 80% → scale up |
| **Requests/sec** | Nombre de requêtes | > 1000 req/s → scale up |
| **Queue depth** | Messages en attente | > 100 messages → scale up |
| **Custom** | Métrique business | > X transactions/min |

### 3.3 Stateless vs Stateful

!!! warning "Clé du Scaling Horizontal"
    Pour scaler horizontalement, votre application doit être **stateless** (sans état local).

```mermaid
graph TB
    subgraph "❌ Stateful (Non scalable)"
        S1["💻 Server<br/>Session en mémoire"]
        USER1["👤 User A<br/>Session sur Server 1"]
    end

    subgraph "✅ Stateless (Scalable)"
        LB["⚖️ Load Balancer"]
        SS1["💻 Server 1"]
        SS2["💻 Server 2"]
        SS3["💻 Server 3"]
        CACHE["⚡ Redis<br/>(Sessions)"]

        LB --> SS1
        LB --> SS2
        LB --> SS3
        SS1 --> CACHE
        SS2 --> CACHE
        SS3 --> CACHE
    end

    style S1 fill:#f44336,color:#fff
    style CACHE fill:#4caf50,color:#fff
```

**Comment rendre une app stateless :**

- Sessions → Store externe (Redis, DynamoDB)
- Fichiers uploadés → Object Storage (S3)
- Cache → Cache distribué (ElastiCache)
- Base de données → Service managé (RDS)

---

## 4. Patterns d'Architecture Cloud

### 4.1 Architecture N-Tier

```mermaid
graph TB
    subgraph "Presentation Tier"
        WEB["🌐 Web Servers<br/>(Frontend)"]
    end

    subgraph "Application Tier"
        APP["⚙️ App Servers<br/>(Backend API)"]
    end

    subgraph "Data Tier"
        DB["🗄️ Database"]
        CACHE["⚡ Cache"]
    end

    WEB --> APP
    APP --> DB
    APP --> CACHE

    style WEB fill:#2196f3,color:#fff
    style APP fill:#4caf50,color:#fff
    style DB fill:#ff9800,color:#fff
```

### 4.2 Microservices

```mermaid
graph TB
    subgraph "Microservices Architecture"
        GW["🚪 API Gateway"]

        subgraph "Services"
            SVC1["👤 User Service"]
            SVC2["💳 Payment Service"]
            SVC3["📦 Order Service"]
            SVC4["📧 Notification Service"]
        end

        subgraph "Data"
            DB1["🗄️ User DB"]
            DB2["🗄️ Payment DB"]
            DB3["🗄️ Order DB"]
        end

        QUEUE["📬 Message Queue"]
    end

    GW --> SVC1
    GW --> SVC2
    GW --> SVC3
    SVC1 --> DB1
    SVC2 --> DB2
    SVC3 --> DB3
    SVC3 --> QUEUE
    QUEUE --> SVC4

    style GW fill:#9c27b0,color:#fff
```

**Avantages :**
- Scaling indépendant par service
- Déploiement indépendant
- Technologie adaptée par service
- Équipes autonomes

### 4.3 Event-Driven Architecture

```mermaid
graph LR
    subgraph "Producers"
        P1["📱 Mobile App"]
        P2["🌐 Web App"]
        P3["⚙️ Backend"]
    end

    BROKER["📬 Event Broker<br/>(Kafka, EventBridge)"]

    subgraph "Consumers"
        C1["📊 Analytics"]
        C2["📧 Notifications"]
        C3["🗄️ Data Lake"]
    end

    P1 --> BROKER
    P2 --> BROKER
    P3 --> BROKER
    BROKER --> C1
    BROKER --> C2
    BROKER --> C3

    style BROKER fill:#ff9800,color:#fff
```

---

## 5. Well-Architected Framework

### 5.1 Les 6 Piliers

```mermaid
mindmap
  root((Well-Architected))
    Operational Excellence
      Automatisation
      Observabilité
      Amélioration continue
    Security
      IAM
      Détection
      Protection données
    Reliability
      HA
      DR
      Gestion pannes
    Performance Efficiency
      Sélection ressources
      Monitoring
      Optimisation
    Cost Optimization
      FinOps
      Right-sizing
      Reserved capacity
    Sustainability
      Efficacité énergétique
      Impact environnemental
```

### 5.2 Questions Clés par Pilier

| Pilier | Questions à se poser |
|--------|----------------------|
| **Operational Excellence** | Comment déployez-vous ? Comment détectez-vous les problèmes ? |
| **Security** | Qui a accès ? Comment protégez-vous les données ? |
| **Reliability** | Que se passe-t-il si X tombe ? Quel est votre RTO/RPO ? |
| **Performance** | Comment gérez-vous les pics ? Avez-vous des goulots ? |
| **Cost Optimization** | Payez-vous pour des ressources inutilisées ? |
| **Sustainability** | Quel est l'impact carbone ? Pouvez-vous optimiser ? |

---

## 6. Quiz de Validation

!!! question "Question 1"
    Quelle est la différence entre RPO et RTO ?

    ??? success "Réponse"
        - **RPO** (Recovery Point Objective) : Quantité de données acceptable à perdre (temps depuis le dernier backup)
        - **RTO** (Recovery Time Objective) : Temps acceptable pour restaurer le service

        Exemple : RPO de 1h signifie qu'on accepte de perdre 1h de données. RTO de 30min signifie qu'on doit être opérationnel en 30 minutes.

!!! question "Question 2"
    Si vous avez 3 composants avec des SLA de 99.9%, 99.95% et 99.9%, quel est le SLA composite ?

    ??? success "Réponse"
        SLA = 99.9% × 99.95% × 99.9% = **99.75%**

        Le SLA composite est toujours inférieur au SLA le plus faible.

!!! question "Question 3"
    Quelle stratégie DR a le RTO le plus court ?

    ??? success "Réponse"
        **Hot Standby** (Active-Active)

        L'infrastructure de DR est identique et tourne en permanence. Le failover est quasi-instantané (secondes).

!!! question "Question 4"
    Pourquoi une application doit-elle être stateless pour scaler horizontalement ?

    ??? success "Réponse"
        Si l'état (session, fichiers) est stocké localement sur un serveur, les requêtes suivantes doivent aller sur le même serveur. Impossible de distribuer la charge.

        Avec une app stateless, n'importe quel serveur peut traiter n'importe quelle requête.

---

## 7. Résumé

| Concept | Description | Métrique clé |
|---------|-------------|--------------|
| **Haute Disponibilité** | Service reste up malgré pannes | SLA (99.9%, 99.99%...) |
| **Disaster Recovery** | Reprise après sinistre majeur | RTO, RPO |
| **Scalabilité Verticale** | Augmenter la taille | Limite physique |
| **Scalabilité Horizontale** | Ajouter des instances | Stateless requis |
| **Auto Scaling** | Scaling automatique | Métriques, seuils |

---

## Navigation

| Précédent | Suivant |
|-----------|---------|
| [← Module 4 : Sécurité & Conformité](04-module.md) | [Module 6 : FinOps & Coûts →](06-module.md) |
