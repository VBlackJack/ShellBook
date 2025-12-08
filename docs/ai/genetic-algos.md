---
tags:
  - ai
  - genetic-algorithms
  - optimization
---

# Algorithmes Génétiques

Quand on ne connaît pas la solution à un problème complexe, on peut parfois laisser l'évolution la trouver pour nous. Les Algorithmes Génétiques s'inspirent de la théorie de l'évolution de Darwin.

## Le Concept : L'Évolution Artificielle

L'idée est de créer une population de "solutions potentielles" (même mauvaises) et de les faire évoluer sur des milliers de générations pour qu'elles s'améliorent.

### Le Cycle de la Vie (Algorithmique)

1.  **Population Initiale** : On génère 100 solutions au hasard (ex: 100 configurations d'un emploi du temps).
2.  **Évaluation (Fitness)** : On donne une note à chaque solution. (ex: Conflits d'horaires = Mauvaise note).
3.  **Sélection** : On garde les meilleurs "parents" (Survie du plus apte).
4.  **Reproduction (Crossover)** : On mélange le "code génétique" de deux parents pour créer un enfant. (ex: Moitié de l'emploi du temps de Papa + Moitié de Maman).
5.  **Mutation** : De temps en temps, on change un détail au hasard (ex: Un cours change de salle). Cela évite de tourner en rond.
6.  **Répétition** : On recommence à l'étape 2 avec la nouvelle génération.

## Analogie Biologique

| Biologie | Informatique (IA) |
|----------|-------------------|
| **ADN** | Code de la solution (010101...) |
| **Individu** | Une solution candidate |
| **Environnement** | Le problème à résoudre |
| **Survie** | Score de performance (Fitness) |
| **Mutation** | Changement aléatoire de paramètre |

## À quoi ça sert ?

C'est très puissant pour les problèmes d'**Optimisation** où il y a trop de combinaisons pour tout tester :
*   **Logistique** : Optimiser les tournées de livraison (Problème du voyageur de commerce).
*   **Design** : Créer la forme aérodynamique parfaite pour une antenne ou une aile d'avion (la NASA l'a fait).
*   **Jeux Vidéo** : Créer des niveaux ou équilibrer des unités automatiquement.

> **Note** : Ce n'est pas de l'apprentissage (Machine Learning) au sens strict, c'est de l'**Optimisation Stochastique** (Recherche aléatoire dirigée).
