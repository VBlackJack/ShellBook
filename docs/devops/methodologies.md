---
tags:
  - devops
  - lean
  - agile
  - culture
---

# Méthodologies DevOps : Lean & Agile

Le DevOps n'est pas qu'une affaire d'outils (Docker, Kubernetes). C'est avant tout l'aboutissement de décennies d'évolution des méthodes de travail, héritées de l'industrie (Lean) et du développement logiciel (Agile).

## 1. Lean IT : L'Héritage Industriel

Le Lean vient du système de production **Toyota** (TPS). Son but unique : **Créer de la valeur pour le client en éliminant tout le reste.**

### Les Grands Principes
*   **Faire plus avec moins** : Maximiser la valeur, minimiser l'effort inutile.
*   **Flux tendu (Just-In-Time)** : Ne pas produire de stock inutile (en informatique : ne pas coder de fonctionnalités "au cas où").
*   **Amélioration Continue (Kaizen)** : De petits changements positifs réguliers valent mieux qu'une grande révolution brutale.

### La Chasse aux Gaspillages ("Muda")
Dans l'IT, le gaspillage prend des formes subtiles que le DevOps cherche à éliminer :

| Type de Gaspillage | En Usine | En IT / DevOps | Solution DevOps |
|--------------------|----------|----------------|-----------------|
| **Défauts** | Pièces cassées | Bugs en prod, Rollbacks | Tests automatisés, CI/CD |
| **Surproduction** | Trop de stock | Fonctionnalités jamais utilisées | MVP (Minimum Viable Product) |
| **Attente** | Machine à l'arrêt | Attendre une validation, un serveur | Self-Service, IaC, Automatisation |
| **Transport** | Déplacer des pièces | Déplacer du code (FTP, mails) | Git, Pipelines de déploiement |
| **Surtraitement** | Trop de peinture | Code trop complexe, Over-engineering | YAGNI (You Ain't Gonna Need It) |
| **Mouvement** | Ouvrier qui marche trop | Context switching (réunions, interruptions) | Kanban, Focus |

---

## 2. Agile & Scrum : L'Itératif

Là où le modèle "Cycle en V" (Waterfall) planifiait tout sur 2 ans (avec risque d'échec total à la fin), l'Agile propose de découper le projet en petits morceaux.

### Le Manifeste Agile (Simplifié pour Ops)
1.  **Individus et interactions** > Processus et outils.
2.  **Logiciel fonctionnel** > Documentation exhaustive.
3.  **Collaboration client** > Négociation contractuelle.
4.  **Adaptation au changement** > Suivi d'un plan.

### Scrum en Bref
Un cadre de travail populaire en Agile, basé sur des cycles courts appelés **Sprints** (souvent 2 semaines).
*   **Sprint Planning** : On décide ce qu'on fait dans les 2 semaines.
*   **Daily (Stand-up)** : 15 min debout chaque matin. "Ce que j'ai fait hier, ce que je fais aujourd'hui, mes blocages".
*   **Review** : On montre le produit fini au client.
*   **Retrospective** : L'équipe discute de *comment* elle a travaillé et comment s'améliorer (Lien direct avec le Kaizen).

---

## 3. La Synthèse DevOps

Le DevOps est la fusion de ces deux mondes :
*   **Culture (Lean)** : On cherche à fluidifier le flux de valeur du Dev vers l'Ops.
*   **Méthode (Agile)** : On livre petit à petit, souvent.
*   **Technique (Automation)** : On automatise tout ce qui est répétitif pour éliminer le gaspillage.

> **Le but ultime** : Réduire le *Time to Market* (temps entre l'idée et la prod) sans sacrifier la qualité.

### Le Mur de la Confusion
*   **Devs** : Veulent du changement (Nouvelles features). Sont payés pour innover.
*   **Ops** : Veulent de la stabilité (Uptime). Sont payés pour que ça ne plante pas.
*   **DevOps** : Brise ce mur en donnant aux Devs la responsabilité de leur code en prod ("You build it, you run it") et aux Ops des outils de développement (IaC).
