---
tags:
  - architecture
  - soa
  - microservices
  - api
---

# Architecture Logicielle : Concepts & Patterns

Comprendre comment les systèmes modernes communiquent est essentiel pour un ingénieur DevOps. Nous sommes passés des monolithes aux microservices via le SOA.

## 1. L'Évolution des Architectures

### Gen 1 : Le Monolithe (Mainframe)
Une seule application géante qui fait tout.
*   **Avantages** : Simple à déployer (un seul binaire), appels de fonctions instantanés.
*   **Inconvénients** : Scalabilité difficile (tout ou rien), techno unique (si c'est du COBOL, tout est en COBOL), risque de casser tout le système au moindre changement.

### Gen 2 : Client-Serveur
Séparation entre l'interface (Client lourd) et la logique/données (Serveur).

### Gen 3 : SOA (Service Oriented Architecture)
Apparu vers 2004, c'est l'ancêtre des microservices.
*   **Concept** : Découper le SI en services métier réutilisables (Service Facturation, Service Client).
*   **Paradigme** : **Publish / Find / Consume**.
    *   Un service publie son contrat (WSDL) dans un annuaire (UDDI).
    *   Le consommateur trouve le service et l'appelle (SOAP).
*   **Problème** : Souvent implémenté avec des "Bus d'Entreprise" (ESB) très lourds et centraux.

### Gen 4 : Microservices (SOA "Léger")
L'approche moderne (Netflix, Uber, Google).
*   C'est du SOA, mais **décentralisé** et **sans état**.
*   Chaque service a sa propre base de données.
*   Communication via des protocoles web légers (REST, gRPC) plutôt que SOAP.

---

## 2. Concepts Clés du SOA & Microservices

### Couplage Lâche (Loose Coupling)
Le but ultime. Le client ne doit pas dépendre des détails internes du serveur.
*   **Abstraction (Boîte Noire)** : Je sais *ce que* fait le service, mais pas *comment* il le fait.
*   **Contrat d'Interface** : Le service promet "Si tu m'envoies X, je te réponds Y". Tant que le contrat est respecté, le code interne peut changer sans casser les clients.

### Stateless (Sans État)
Pour être scalable horizontalement, un service ne doit pas garder de "session" en mémoire.
*   Si le serveur A traite la requête 1, le serveur B doit pouvoir traiter la requête 2 du même utilisateur.
*   L'état est stocké dans une base de données externe (Redis, SQL).

### Composabilité
Un service complexe peut être créé en assemblant plusieurs services simples (Orchestration).

---

## 3. Protocoles d'Échange

### SOAP (Simple Object Access Protocol) - "L'Ancien"
*   Format : XML strict.
*   Contrat : WSDL (Web Services Description Language).
*   **Avantages** : Très rigoureux, sécurité (WS-Security), transactions atomiques.
*   **Inconvénients** : Verbeux, lourd, complexe à parser.
*   **Usage 2025** : Encore très présent dans les banques et les assurances (Legacy).

### REST (Representational State Transfer) - "Le Standard Web"
*   Format : Souvent JSON (plus léger que XML).
*   Utilise les verbes HTTP standards :
    *   `GET` : Lire (Idempotent).
    *   `POST` : Créer.
    *   `PUT` : Remplacer.
    *   `DELETE` : Supprimer.
*   **Ressources** : Tout est une URL (`/api/users/123`).
*   **Usage 2025** : Le standard de facto pour les API Web et Microservices.

### gRPC (Google RPC) - "La Performance"
*   Format : Binaire (Protocol Buffers).
*   **Usage** : Communication interne entre microservices (Kubernetes) où la latence doit être minimale.
