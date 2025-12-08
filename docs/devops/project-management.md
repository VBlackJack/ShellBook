---
tags:
  - project-management
  - devops
  - agile
  - leadership
---

# Gestion de Projet : Fondamentaux pour Tech Leads

Un bon Tech Lead/DevOps ne se contente pas de coder ou d'administrer. Il doit comprendre la dynamique d'un projet, ses enjeux business et ses contraintes.

---

## 1. Projet vs Opérations : La Différence Fondamentale

Ces deux activités coexistent mais ont des logiques opposées :

| Caractéristique | Projet | Opération |
|-----------------|---------------------------------|---------------------------------------|
| **Nature**      | Unique, temporaire, innovant      | Répétitive, continue, prédictible     |
| **Objectif**    | Créer un nouveau produit/service | Maintenir un produit/service existant |
| **Valeur**      | Création de valeur future (souvent négatif au début) | Génération de valeur actuelle (bénéfices) |
| **Gestion**     | Gestion du changement, incertitude | Optimisation, stabilité             |
| **Exemple**     | Déploiement d'une nouvelle plateforme | Maintenance d'un serveur en production |

**Le Défi** : Équilibrer les projets (risque pour l'avenir) et les opérations (rentabilité présente) au sein d'une même équipe.

## 2. Le Cycle de Vie d'un Projet

Un projet n'est pas linéaire, mais passe par des phases clés :

1.  **Idée** : Besoin initial, constat.
2.  **Faisabilité / Opportunité** : Analyse stratégique, alignement avec les objectifs de l'entreprise.
3.  **Projet** : Planification, exécution, suivi.
4.  **Production** : La solution est livrée, bascule en mode "Opération".

### Le Paradoxe du Projet
*   **Au début** : La capacité à prendre des décisions structurantes est maximale, mais la connaissance du projet est minimale.
*   **À la fin** : La connaissance du projet est maximale, mais la capacité à infléchir le cours du projet est minimale.

→ D'où l'importance de l'étape de **faisabilité** !

---

## 3. Les Instances de Pilotage

Deux comités clés assurent le suivi d'un projet :

### Comité de Pilotage (COPIL)
*   **Rôle** : Décisions stratégiques, alignement business, arbitrages majeurs (budget, délais).
*   **Composition** : Commanditaires, Métiers (bénéficiaires du projet), Direction.
*   **Fréquence** : Mensuelle ou Bimensuelle.

### Comité de Projet (COPROJ)
*   **Rôle** : Suivi opérationnel, avancement technique, résolution des problèmes quotidiens.
*   **Composition** : Chef de Projet, Équipe Projet (Dev, Ops, QA...).
*   **Fréquence** : Hebdomadaire ou bi-hebdomadaire.

## 4. Les Outils d'Analyse Pré-Projet

### Étude d'Opportunité & Business Case
Avant de se lancer, il faut prouver la valeur du projet.
*   **Business Case** : Document clé qui justifie l'investissement (financier, stratégique, image). Il doit être maintenu et adapté tout au long du projet.
*   **SWOT** (Strengths, Weaknesses, Opportunities, Threats) : Analyse des forces/faiblesses internes et des opportunités/menaces externes.

### Cahier des Charges
*   **Fonctionnel (CdCF)** : Décrit les "quoi" (les besoins métiers) et les objectifs, sans se préoccuper du "comment". Rédigé par la Maîtrise d'Ouvrage (MOA).
*   **Technique (CdCT)** : Décrit le "comment" (la solution technique). Rédigé par la Maîtrise d'Œuvre (MOE).

---

## 5. Le Triangle d'Or du Projet (QCD)

Tout projet est contraint par ces trois axes interdépendants. Modifier l'un affecte les autres.

1.  **Coût (Budget)** : Combien ça coûte ? (Humain, Matériel, Logiciel).
2.  **Qualité** : Quelle performance ? Quelles fonctionnalités ? (Fiabilité, Robustesse).
3.  **Délai** : Quand sera-ce livré ?

**Exemple** : Si le client veut une "meilleure qualité" (plus de tests) sans augmenter le "coût", il faudra allonger le "délai".

---

**Voir aussi :**
- [Méthodologies (Lean/Agile)](./methodologies.md)
