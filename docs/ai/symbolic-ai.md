---
tags:
  - ai
  - symbolic
  - rules
  - expert-systems
---

# IA Symbolique : Les Systèmes Experts

Avant l'avènement du Deep Learning, l'IA régnait grâce aux **Systèmes Experts**. C'est une forme d'IA "déterministe" : elle ne devine pas, elle applique une logique implacable.

## Le Principe : Moteur d'Inférence

Un Système Expert est composé de deux parties distinctes :
1.  **La Base de Connaissances** : L'ensemble des faits et des règles (le savoir de l'expert humain).
2.  **Le Moteur d'Inférence** : Le logiciel qui raisonne en appliquant ces règles aux faits.

> **Avantage majeur** : Contrairement aux réseaux de neurones ("boîtes noires"), un système expert peut **expliquer** son raisonnement. "J'ai conclu X car la règle Y s'applique aux faits A et B".

## Exemple Concret : La Classification des Formes

Imaginons un système expert chargé de reconnaître des formes géométriques. Nous lui donnons des **règles** strictes.

### 1. La Base de Règles (Le Savoir)

*   **Règle 1** : SI (côtés = 3) ALORS [C'est un Triangle]
*   **Règle 2** : SI (Triangle) ET (angle_droit = 1) ALORS [Triangle Rectangle]
*   **Règle 3** : SI (Triangle) ET (côtés_égaux = 2) ALORS [Triangle Isocèle]
*   **Règle 4** : SI (côtés = 4) ET (côtés_parallèles = 2) ALORS [Trapèze]
*   **Règle 5** : SI (côtés = 4) ET (côtés_parallèles = 4) ET (angles_droits = 4) ALORS [Rectangle]
*   **Règle 6** : SI (Rectangle) ET (côtés_égaux = 4) ALORS [Carré]

### 2. L'Inférence (Le Raisonnement)

On présente un objet (Faits) au système :
*   *Fait A* : Il a 4 côtés.
*   *Fait B* : Il a 4 angles droits.
*   *Fait C* : Ses 4 côtés sont égaux.

**Le moteur raisonne (Chaînage Avant) :**
1.  Il voit "4 côtés" + "4 angles droits".
2.  Il active la **Règle 5** (Rectangle) car il sait implicitement qu'un rectangle a des côtés parallèles (règles géométriques de base). -> *Nouvel état : C'est un Rectangle.*
3.  Il voit "Rectangle" + "4 côtés égaux".
4.  Il active la **Règle 6** -> *Conclusion : C'est un Carré.*

## Pourquoi est-ce tombé en désuétude ? (Et pourquoi ça revient ?)

### Les Limites
*   **Explosion combinatoire** : Pour des problèmes complexes, le nombre de règles devient ingérable.
*   **Manque de souplesse** : Si une forme a 3.9 côtés (dessin mal fait), le système plante. Il ne gère pas l'incertitude (sauf avec la *Logique Floue*).
*   **Maintenance** : Ajouter une règle peut en contredire une autre.

### Le Retour (Hybridation)
Aujourd'hui, on redécouvre l'utilité de cette approche pour la **vérification**.
*   Un LLM (ChatGPT) peut écrire du code (Approche probabiliste/créative).
*   Un Système Expert (Linter/Compilateur) vérifie si le code respecte les règles de syntaxe (Approche logique/stricte).
*   C'est l'avenir de l'IA fiable : **Neuro-Symbolique** (Le cerveau pour l'intuition, la logique pour la rigueur).
