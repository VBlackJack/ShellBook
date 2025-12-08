---
tags:
  - finops
  - cloud
  - cost
  - optimization
---

# FinOps : Cloud Financial Management

Le Cloud n'est pas "juste l'ordinateur de quelqu'un d'autre". C'est un modèle économique (OPEX vs CAPEX) où chaque seconde de CPU est facturée. Le FinOps est l'art de maîtriser cette facture.

## 1. Le Cycle FinOps

Ce n'est pas une action "one-shot", c'est une boucle continue.

1.  **Informer (Visibility)** : Qui dépense quoi ?
    *   Impossible d'optimiser ce qu'on ne mesure pas.
    *   *Outil* : Cost Explorer, Dashboards.
2.  **Optimiser (Optimize)** : Réduire le gaspillage.
    *   Right-sizing (arrêter de payer une XL pour un script).
    *   Spot Instances.
3.  **Opérer (Operate)** : Automatiser la gouvernance.
    *   Budgets, Alertes, Arrêt auto des environnements de dev la nuit.

## 2. Les Leviers d'Économie

### Tagging Strategy
La base absolue. Chaque ressource doit avoir des tags :
*   `Environment` (Prod, Dev, Staging)
*   `Owner` (Team-Data, Team-Web)
*   `CostCenter` (Projet-Alpha)

Sans ça, la facture AWS est une "boîte noire" indéchiffrable de 10 000 lignes.

### Spot Instances
Des serveurs "soldés" (-70% à -90%) par AWS/Azure quand ils ont du surplus.
*   *Le piège* : Ils peuvent être repris avec un préavis de 2 minutes.
*   *L'usage* : Parfait pour le Stateless, le Batch, la CI/CD, le Big Data.

### Reserved Instances / Savings Plans
Vous vous engagez à payer X serveurs pendant 1 ou 3 ans.
*   *Gain* : -30% à -60%.
*   *Risque* : Manque de flexibilité. À réserver pour le "socle de base" (la charge minimale 24/7).

### Right-Sizing
Les dévs prennent souvent "large" ("Mets-moi 16GB de RAM au cas où").
*   Le FinOps regarde les métriques réelles (Max utilisé : 4GB) et réduit la taille de l'instance.

## 3. L'Économie Unitaire (Unit Economics)

Le but n'est pas forcément de baisser la facture, mais d'améliorer la **Marge**.

*   *Scénario A* : Facture Cloud +10%, Chiffre d'Affaire +50%. → **C'est bon.**
*   *Scénario B* : Facture Cloud +10%, Chiffre d'Affaire +0%. → **C'est mauvais.**

**Indicateur clé** : Coût Cloud par Client (ou par Commande).
*   Si ce coût baisse alors que vous grossissez, vous avez réussi votre passage à l'échelle.

---

## Outils
*   **Infracost** : Estime le coût d'une Pull Request Terraform *avant* le déploiement.
*   **Kubecost** : Répartit la facture K8s par Namespace/Pod (car K8s est une boîte noire pour la facturation Cloud classique).
