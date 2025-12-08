---
tags:
  - ai
  - pathfinding
  - graph-theory
  - algorithms
---

# Pathfinding (Recherche de Chemin)

Comment une IA dans un jeu vidéo sait-elle aller du point A au point B sans se cogner dans les murs ? Grâce aux algorithmes de Pathfinding.

## La Théorie des Graphes

Pour un ordinateur, une carte (labyrinthe, ville, réseau routier) est un **Graphe**.
*   **Noeuds (Nodes)** : Les carrefours, les pièces, ou les cases d'une grille.
*   **Arcs (Edges)** : Les routes qui relient ces noeuds.
*   **Coût** : La "distance" ou la difficulté pour traverser un arc (Km, temps, danger...).

Le but est de trouver la suite de noeuds qui relie le Départ à l'Arrivée avec le **Coût Total** le plus faible.

## Les Algorithmes

### 1. Les Algorithmes Naïfs (Aveugles)
Ils explorent sans savoir où est l'arrivée.
*   **Parcours en Largeur (BFS)** : Explore comme une tache d'huile (toutes les cases à 1 mètre, puis toutes celles à 2 mètres...). Trouve toujours le chemin le plus court, mais très lent.
*   **Parcours en Profondeur (DFS)** : Fonce tête baissée dans une direction jusqu'à être bloqué, puis revient en arrière. Rapide mais trouve souvent des chemins horribles.

### 2. Dijkstra
L'ancêtre sérieux. Il explore méthodiquement en privilégiant toujours le chemin le "moins cher" connu. Il garantit le chemin optimal. Utilisé par les protocoles de routage Internet (OSPF).

### 3. A* (A-Star) : Le Roi du Pathfinding
C'est l'algorithme le plus utilisé (Jeux vidéo, GPS).
C'est une amélioration de Dijkstra qui utilise une **Heuristique** (une intuition).
*   **Principe** : Au lieu d'explorer dans toutes les directions, il privilégie les noeuds qui se rapprochent (à vol d'oiseau) de l'arrivée.
*   **Formule** : $f(n) = g(n) + h(n)$
    *   $g(n)$ : Coût réel depuis le départ (ce qu'on a déjà parcouru).
    *   $h(n)$ : Estimation du coût restant (distance à vol d'oiseau).

> **En résumé** : A* est intelligent car il combine la rigueur (Dijkstra) et l'intuition (Direction générale).
