---
tags:
  - soft-skills
  - management
  - communication
  - devops-culture
---

# Soft Skills pour SysAdmin & DevOps

La technique ne fait que 50% du travail. Le reste ? Savoir communiquer, négocier et désamorcer les conflits. Voici les outils relationnels essentiels pour survivre en entreprise.

## 1. La Critique Constructive (Méthode DESC)

Comment dire à un collègue que son code casse tout, sans qu'il se braque ?
La méthode **DESC** permet de rester factuel et orienté solution.

1.  **D (Décrire)** : Présentez les faits, rien que les faits.
    *   *Mauvais :* "Tu codes n'importe comment."
    *   *Bon :* "Le commit d'hier a introduit une erreur 500 sur la prod."
2.  **E (Exprimer)** : Partagez votre ressenti (Je) pour humaniser l'échange.
    *   *Bon :* "Je suis inquiet car cela bloque le déploiement prévu ce soir."
3.  **S (Spécifier)** : Proposez une solution concrète et positive.
    *   *Bon :* "Peux-tu regarder les logs et faire un rollback si nécessaire ?"
4.  **C (Conséquences)** : Montrez le bénéfice pour tout le monde.
    *   *Bon :* "Comme ça, on pourra partir en week-end l'esprit tranquille."

> **Règle d'Or** : Toujours critiquer en privé (Face à face), jamais en public (Réunion, Slack général).

## 2. L'Art de dire "Non"

Le DevOps est souvent le goulot d'étranglement vers qui toutes les demandes affluent. Savoir dire non est une compétence de survie.

### Quand est-il légitime de dire Non ?
*   **Hors Périmètre** : "Peux-tu réparer l'imprimante ?" (Alors que vous gérez le Cloud).
*   **Hors Process** : "Mets ça en prod vite fait, sans passer par la CI/CD."
*   **Surcharge** : "Ajoute ce projet" (Alors que vous êtes déjà à 120%).
*   **Illégal/Non-éthique** : "Donne-moi les mots de passe admin."

### Comment dire Non (sans passer pour un tyran)
Le "Non" sec est agressif. Utilisez le "Non diplomatique" :

1.  **Écouter & Reformuler** : Montrez que vous avez compris l'importance de la demande.
    *   "Je comprends que tu as besoin de ce serveur pour ta démo demain."
2.  **Refuser clairement** : Ne laissez pas d'espoir flou ("Je vais voir...").
    *   "Ce n'est pas possible pour moi de le faire aujourd'hui."
3.  **Justifier (brièvement)** : Donnez la raison objective.
    *   "Je suis sur un incident critique de production."
4.  **Proposer une alternative** : C'est ce qui transforme le refus en collaboration.
    *   "Par contre, tu peux utiliser l'environnement de staging qui est déjà prêt."

## 3. Gestion de Conflit

*   **Le Conflit Destructeur** : Attaque personnelle, refus de dialogue, jeu de pouvoir.
*   **Le Conflit Constructif** : Désaccord sur les idées, respect mutuel, recherche de la meilleure solution technique.

**En cas de crise :**
1.  Coupez les écrans (Slack/Mail).
2.  Passez à l'oral (Visio ou Café).
3.  Revenez aux faits (Data, Logs) pour sortir de l'émotionnel.
