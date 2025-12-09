---
tags:
  - mermaid
  - diagrams
  - flowchart
  - uml
  - visualization
---

# Module 3 : Mermaid - Diagrammes Professionnels

**Durée estimée :** 1 heure

---

## Objectifs

À la fin de ce module, vous saurez :

- Créer des flowcharts et organigrammes
- Dessiner des diagrammes de séquence UML
- Concevoir des diagrammes d'architecture
- Appliquer des styles et couleurs cohérents
- Utiliser les bonnes pratiques pour des diagrammes lisibles

---

## 1. Configuration Mermaid dans MkDocs

### Activer Mermaid

Dans `mkdocs.yml` :

```yaml
markdown_extensions:
  - pymdownx.superfences:
      custom_fences:
        - name: mermaid
          class: mermaid
          format: !!python/name:pymdownx.superfences.fence_code_format
```

### Syntaxe de Base

````markdown
```mermaid
flowchart LR
    A[Début] --> B[Fin]
```
````

**Rendu :**

```mermaid
flowchart LR
    A[Début] --> B[Fin]
```

---

## 2. Flowcharts (Organigrammes)

### Direction du Graphe

| Code | Direction |
|------|-----------|
| `TB` / `TD` | Top to Bottom (haut vers bas) |
| `BT` | Bottom to Top (bas vers haut) |
| `LR` | Left to Right (gauche vers droite) |
| `RL` | Right to Left (droite vers gauche) |

```mermaid
flowchart TD
    A[Top] --> B[Bottom]
```

```mermaid
flowchart LR
    A[Left] --> B[Right]
```

### Formes des Nœuds

```mermaid
flowchart LR
    A[Rectangle] --> B(Arrondi)
    B --> C{Losange}
    C --> D[[Sous-routine]]
    D --> E[(Base de données)]
    E --> F((Cercle))
    F --> G>Drapeau]
```

| Syntaxe | Forme | Usage |
|---------|-------|-------|
| `[texte]` | Rectangle | Action, étape |
| `(texte)` | Rectangle arrondi | Processus |
| `{texte}` | Losange | Décision, condition |
| `[[texte]]` | Sous-routine | Fonction, module |
| `[(texte)]` | Cylindre | Base de données |
| `((texte))` | Cercle | Point d'entrée/sortie |
| `>texte]` | Drapeau | Signal, événement |

### Types de Liens

```mermaid
flowchart LR
    A --> B
    B --- C
    C -.-> D
    D ==> E
    E --texte--> F
    F ---|label| G
```

| Syntaxe | Description |
|---------|-------------|
| `-->` | Flèche simple |
| `---` | Ligne sans flèche |
| `-.->` | Flèche pointillée |
| `==>` | Flèche épaisse |
| `--texte-->` | Flèche avec label |

### Exemple : Pipeline CI/CD

```mermaid
flowchart LR
    A[Code Push] --> B[Build]
    B --> C[Test]
    C --> D{Tests OK?}
    D -->|Oui| E[Deploy Staging]
    D -->|Non| F[Fix & Retry]
    F --> A
    E --> G{Validation?}
    G -->|Oui| H[Deploy Prod]
    G -->|Non| F

    style A fill:#2196F3,color:#fff
    style B fill:#FF9800,color:#fff
    style C fill:#9C27B0,color:#fff
    style D fill:#FF9800,color:#000
    style E fill:#4CAF50,color:#fff
    style F fill:#f44336,color:#fff
    style G fill:#FF9800,color:#000
    style H fill:#4CAF50,color:#fff
```

---

## 3. Subgraphs (Sous-graphes)

Groupez des éléments logiquement :

```mermaid
flowchart TB
    subgraph Frontend
        A[React App]
        B[Vue App]
    end

    subgraph Backend
        C[API Gateway]
        D[Auth Service]
        E[Data Service]
    end

    subgraph Database
        F[(PostgreSQL)]
        G[(Redis Cache)]
    end

    A --> C
    B --> C
    C --> D
    C --> E
    D --> F
    E --> F
    E --> G

    style A fill:#2196F3,color:#fff
    style B fill:#2196F3,color:#fff
    style C fill:#FF9800,color:#fff
    style D fill:#9C27B0,color:#fff
    style E fill:#9C27B0,color:#fff
    style F fill:#4CAF50,color:#fff
    style G fill:#f44336,color:#fff
```

### Subgraphs Imbriqués

```mermaid
flowchart TB
    subgraph Cloud
        subgraph Region-EU
            A[Server EU-1]
            B[Server EU-2]
        end
        subgraph Region-US
            C[Server US-1]
            D[Server US-2]
        end
    end

    LB[Load Balancer] --> A
    LB --> B
    LB --> C
    LB --> D

    style LB fill:#FF9800,color:#fff
    style A fill:#4CAF50,color:#fff
    style B fill:#4CAF50,color:#fff
    style C fill:#2196F3,color:#fff
    style D fill:#2196F3,color:#fff
```

---

## 4. Diagrammes de Séquence

### Syntaxe de Base

```mermaid
sequenceDiagram
    participant C as Client
    participant S as Server
    participant DB as Database

    C->>S: HTTP Request
    activate S
    S->>DB: SQL Query
    activate DB
    DB-->>S: Results
    deactivate DB
    S-->>C: HTTP Response
    deactivate S
```

### Types de Flèches

| Syntaxe | Description |
|---------|-------------|
| `->>` | Flèche pleine (synchrone) |
| `-->>` | Flèche pointillée (réponse) |
| `-x` | Croix (échec) |
| `-)` | Flèche ouverte (async) |

### Exemple : Authentification OAuth

```mermaid
sequenceDiagram
    autonumber
    participant U as User
    participant A as App
    participant O as OAuth Provider
    participant API as Protected API

    U->>A: Click "Login with Google"
    A->>O: Redirect to OAuth
    O->>U: Show login form
    U->>O: Enter credentials
    O->>A: Authorization code
    A->>O: Exchange code for token
    O-->>A: Access token + Refresh token
    A->>API: Request with token
    API-->>A: Protected data
    A-->>U: Display data

    Note over A,O: OAuth 2.0 Flow
```

### Boucles et Conditions

```mermaid
sequenceDiagram
    participant C as Client
    participant S as Server

    loop Every 5 seconds
        C->>S: Health check
        S-->>C: Status OK
    end

    alt Success
        S-->>C: 200 OK
    else Failure
        S-->>C: 500 Error
    end

    opt Cache available
        S-->>C: Return cached data
    end
```

---

## 5. Diagrammes de Classes

```mermaid
classDiagram
    class User {
        +int id
        +string name
        +string email
        +login()
        +logout()
    }

    class Order {
        +int id
        +date created_at
        +float total
        +addItem()
        +checkout()
    }

    class Product {
        +int id
        +string name
        +float price
        +int stock
    }

    User "1" --> "*" Order : places
    Order "*" --> "*" Product : contains
```

### Relations

| Syntaxe | Relation |
|---------|----------|
| `<\|--` | Héritage |
| `*--` | Composition |
| `o--` | Agrégation |
| `-->` | Association |
| `..>` | Dépendance |

---

## 6. Diagrammes d'État

```mermaid
stateDiagram-v2
    [*] --> Pending

    Pending --> Processing : submit
    Processing --> Approved : approve
    Processing --> Rejected : reject
    Approved --> [*]
    Rejected --> Pending : retry

    state Processing {
        [*] --> Validating
        Validating --> Reviewing
        Reviewing --> [*]
    }
```

---

## 7. Diagrammes ER (Entity Relationship)

```mermaid
erDiagram
    USER ||--o{ ORDER : places
    ORDER ||--|{ ORDER_ITEM : contains
    PRODUCT ||--o{ ORDER_ITEM : "ordered in"

    USER {
        int id PK
        string name
        string email UK
        date created_at
    }

    ORDER {
        int id PK
        int user_id FK
        float total
        string status
    }

    PRODUCT {
        int id PK
        string name
        float price
        int stock
    }

    ORDER_ITEM {
        int order_id FK
        int product_id FK
        int quantity
    }
```

---

## 8. Pie Charts & Autres

### Diagramme Circulaire

```mermaid
pie showData
    title Répartition du trafic
    "Direct" : 40
    "Search" : 30
    "Social" : 20
    "Referral" : 10
```

### Timeline

```mermaid
timeline
    title Évolution du projet
    2023 : Conception : Architecture
    2024 Q1 : Développement : MVP
    2024 Q2 : Tests : Beta
    2024 Q3 : Production : Launch
```

### Gantt

```mermaid
gantt
    title Planning Projet
    dateFormat YYYY-MM-DD
    section Analyse
        Spécifications    :a1, 2024-01-01, 14d
        Architecture      :a2, after a1, 7d
    section Développement
        Backend           :b1, after a2, 30d
        Frontend          :b2, after a2, 25d
    section Tests
        Tests unitaires   :c1, after b1, 7d
        Tests intégration :c2, after c1, 7d
```

---

## 9. Styling et Couleurs

### Palette Recommandée

Utilisez une palette cohérente pour vos diagrammes :

| Couleur | Hex | Usage |
|---------|-----|-------|
| Vert | `#4CAF50` | Succès, débutant, OK |
| Bleu | `#2196F3` | Info, intermédiaire |
| Orange | `#FF9800` | Warning, avancé |
| Violet | `#9C27B0` | Expert, spécial |
| Rouge | `#f44336` | Erreur, danger |

### Appliquer des Styles

```mermaid
flowchart LR
    A[Débutant] --> B[Intermédiaire]
    B --> C[Avancé]
    C --> D[Expert]

    style A fill:#4CAF50,color:#fff,stroke:#388E3C
    style B fill:#2196F3,color:#fff,stroke:#1976D2
    style C fill:#FF9800,color:#fff,stroke:#F57C00
    style D fill:#9C27B0,color:#fff,stroke:#7B1FA2
```

### Classes CSS

```mermaid
flowchart LR
    A[Success]:::success --> B[Warning]:::warning
    B --> C[Error]:::error

    classDef success fill:#4CAF50,color:#fff
    classDef warning fill:#FF9800,color:#fff
    classDef error fill:#f44336,color:#fff
```

### Appliquer une Classe à Plusieurs Nœuds

```mermaid
flowchart LR
    A[Server 1]:::server --> LB[Load Balancer]:::lb
    B[Server 2]:::server --> LB
    C[Server 3]:::server --> LB

    classDef server fill:#4CAF50,color:#fff
    classDef lb fill:#FF9800,color:#fff

    class A,B,C server
```

---

## 10. Bonnes Pratiques

### 1. Lisibilité

```mermaid
flowchart LR
    subgraph "❌ Mauvais"
        direction LR
        A1[a] --> B1[b] --> C1[c] --> D1[d] --> E1[e] --> F1[f]
    end
```

```mermaid
flowchart TB
    subgraph "✅ Bon"
        A2[Étape 1] --> B2[Étape 2]
        B2 --> C2[Étape 3]
        C2 --> D2[Étape 4]
    end

    style A2 fill:#4CAF50,color:#fff
    style D2 fill:#4CAF50,color:#fff
```

### 2. Labels Descriptifs

```text
❌ A --> B --> C
✅ Client --> API Gateway --> Database
```

### 3. Grouper Logiquement

Utilisez les subgraphs pour organiser les composants liés.

### 4. Cohérence des Couleurs

Utilisez toujours la même couleur pour le même type d'élément :

- Bases de données : Vert
- APIs : Bleu
- Utilisateurs : Orange
- Erreurs : Rouge

### 5. Éviter la Surcharge

- Maximum 10-15 nœuds par diagramme
- Créez plusieurs diagrammes si nécessaire
- Utilisez des sous-graphes pour regrouper

---

## 11. Exemples Pratiques

### Architecture Microservices

```mermaid
flowchart TB
    subgraph External
        U[Users]
        M[Mobile App]
    end

    subgraph Edge
        GW[API Gateway]
        AUTH[Auth Service]
    end

    subgraph Services
        US[User Service]
        OS[Order Service]
        PS[Product Service]
        NS[Notification Service]
    end

    subgraph Data
        PG[(PostgreSQL)]
        RD[(Redis)]
        MQ[RabbitMQ]
    end

    U --> GW
    M --> GW
    GW --> AUTH
    GW --> US
    GW --> OS
    GW --> PS

    US --> PG
    OS --> PG
    PS --> PG
    OS --> RD
    OS --> MQ
    MQ --> NS

    style GW fill:#FF9800,color:#fff
    style AUTH fill:#9C27B0,color:#fff
    style US fill:#2196F3,color:#fff
    style OS fill:#2196F3,color:#fff
    style PS fill:#2196F3,color:#fff
    style NS fill:#2196F3,color:#fff
    style PG fill:#4CAF50,color:#fff
    style RD fill:#f44336,color:#fff
    style MQ fill:#FF9800,color:#fff
```

### Workflow Git

```mermaid
flowchart LR
    A[main] --> B[feature/login]
    B --> C{Code Review}
    C -->|Approved| D[Merge to main]
    C -->|Changes| E[Update PR]
    E --> C
    D --> F[Deploy]

    style A fill:#4CAF50,color:#fff
    style B fill:#2196F3,color:#fff
    style C fill:#FF9800,color:#000
    style D fill:#4CAF50,color:#fff
    style E fill:#f44336,color:#fff
    style F fill:#9C27B0,color:#fff
```

---

## Exercice Pratique

### Objectif

Créer 3 diagrammes pour documenter une application web.

### Instructions

1. **Flowchart** : Processus de commande (panier → paiement → confirmation)
2. **Séquence** : Authentification utilisateur
3. **Architecture** : Frontend, Backend, Database avec subgraphs

### Critères

- [ ] Labels descriptifs
- [ ] Couleurs cohérentes avec la palette
- [ ] Subgraphs pour grouper
- [ ] Styles appliqués

---

## Ressources

| Ressource | Description |
|-----------|-------------|
| [Mermaid Live Editor](https://mermaid.live/) | Éditeur en ligne avec prévisualisation |
| [Mermaid Documentation](https://mermaid.js.org/) | Documentation officielle |
| [Mermaid Cheat Sheet](https://jojozhuang.github.io/tutorial/mermaid-cheat-sheet/) | Référence rapide |

---

## Prochaine Étape

Vous maîtrisez maintenant Mermaid ! Dans le prochain module, nous verrons la configuration avancée de MkDocs Material.

[:octicons-arrow-right-24: Module 4 : Configuration Avancée](04-module.md)
