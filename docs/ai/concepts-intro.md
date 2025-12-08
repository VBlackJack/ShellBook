---
tags:
  - ai
  - concepts
  - history
---

# Comprendre l'IA : De la Logique aux Neurones

L'Intelligence Artificielle (IA) effraie souvent par sa complexité mathématique. Pourtant, ses concepts fondamentaux sont simples. Historiquement, l'IA s'est divisée en deux grandes écoles de pensée : l'approche **Symbolique** (Logique) et l'approche **Connexionniste** (Apprentissage).

## 1. L'IA Symbolique (La Logique)
*L'ère des règles strictes (1950 - 1990)*

C'est l'approche "classique". On part du principe que l'intelligence peut être codée sous forme de **règles logiques**.
*   **Principe** : "Si [Condition] Alors [Action]".
*   **Analogie** : Un livre de cuisine géant. Si vous suivez la recette à la lettre, vous obtenez le résultat.
*   **Exemple** : Les **Systèmes Experts**. Pour diagnostiquer une panne de voiture, on code des milliers de règles : *Si le moteur ne démarre pas ET que les phares ne s'allument pas, ALORS la batterie est vide.*
*   **Limite** : Impossible de coder toutes les règles du monde réel (ex: reconnaître un chat sur une photo).

## 2. L'IA Connexionniste (L'Apprentissage)
*L'ère des données et des probabilités (1990 - Aujourd'hui)*

Au lieu de donner les règles, on donne les données et on laisse la machine **trouver** les règles elle-même. C'est le **Machine Learning**.
*   **Principe** : On simule le fonctionnement biologique du cerveau avec des **Réseaux de Neurones**.
*   **Analogie** : Un enfant qui apprend. On lui montre 1000 photos de chats en disant "Chat", et 1000 photos de chiens en disant "Chien". À la fin, il sait faire la différence sans qu'on lui ait expliqué la forme des oreilles.
*   **Exemple** : La reconnaissance d'images, ChatGPT, la traduction automatique.

---

## Le Neurone Artificiel : La brique de base

Pour comprendre le Deep Learning (l'IA moderne), il faut comprendre son unité de base : le **Neurone Formel** (inventé en 1943 !).

### L'inspiration Biologique
Dans notre cerveau, un neurone reçoit des signaux électriques via ses dendrites. Si la somme de ces signaux dépasse un certain seuil, il s'active et transmet l'info via son axone.
*   **Connexion forte** = Apprentissage (Le chemin se renforce).

### Le Modèle Mathématique Simplifié
Un neurone artificiel est une fonction mathématique très simple :
1.  **Entrées ($x$)** : Les données (ex: la couleur d'un pixel).
2.  **Poids ($w$)** : L'importance de chaque entrée. (C'est ce que la machine "apprend". Au début, les poids sont aléatoires).
3.  **Somme Pondérée** : On multiplie chaque entrée par son poids : $\sum (x \times w)$.
4.  **Activation** : On passe le résultat dans une "Fonction d'Activation" (ex: Sigmoïde) pour décider si le neurone "s'allume" (sortie proche de 1) ou reste éteint (sortie proche de 0).

> **En résumé** : Un réseau de neurones n'est qu'un immense ajustement de boutons (les poids) pour que, quand on met une image de chat en entrée, la lampe "Chat" s'allume en sortie.

---

## Les Différents types d'Intelligences
Il est important de ne pas voir l'IA comme un bloc monolithique. Tout comme Howard Gardner a théorisé les **intelligences multiples** chez l'humain (Logico-mathématique, Linguistique, Spatiale, etc.), les IA sont souvent spécialisées :
*   **IA Faible (Narrow AI)** : Excellente dans un seul domaine (ex: jouer aux échecs, reconnaître des visages). C'est toute l'IA actuelle.
*   **IA Forte (AGI)** : Capable de s'adapter à n'importe quelle tâche cognitive humaine. C'est encore de la science-fiction.
