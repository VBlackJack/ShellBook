---
tags:
  - sre
  - reliability
  - google
  - slo
  - monitoring
---

# Site Reliability Engineering (SRE)

"SRE is what happens when you ask a software engineer to design an operations team." - Ben Treynor (Google).

Le SRE n'est pas un nouveau nom pour "Admin Sys". C'est une discipline qui traite les opérations comme un problème logiciel.

![SRE Golden Signals](../assets/infographics/devops/sre-golden-signals.jpeg)

## 1. Les Concepts Clés

### SLI, SLO, SLA : Ne plus jamais confondre

C'est la base de la discussion entre le Business et la Tech.

| Acronyme | Nom | Définition | Exemple | Qui décide ? |
|----------|-----|------------|---------|--------------|
| **SLI** | Service Level Indicator | **La Mesure**. Ce que le monitoring voit. | "Latence moyenne des requêtes HTTP" | Les Ingénieurs |
| **SLO** | Service Level Objective | **L'Objectif**. Le seuil à ne pas dépasser. | "99% des requêtes doivent répondre en < 200ms" | Le Produit (PO) |
| **SLA** | Service Level Agreement | **Le Contrat**. La pénalité financière si on rate l'objectif. | "Si < 99%, on rembourse 10% de l'abo" | Les Avocats/Ventes |

> **Règle d'or** : Ne réveillez jamais quelqu'un (astreinte) pour un SLA, mais pour un SLO qui brûle trop vite.

### Error Budget (Budget d'Erreur)

C'est la tolérance à la panne.
Si votre SLO est de **99.9%**, votre Error Budget est de **0.1%**.

*   Sur un mois (43 200 minutes) : vous avez le droit à **43 minutes** de panne.
*   **Tant qu'il reste du budget** : On peut déployer, innover, prendre des risques.
*   **Si le budget est épuisé** : On gèle les mises à jour (Code Freeze) et on travaille uniquement sur la stabilité.

### Toil (Le Labeur)

Le "Toil", c'est le travail :
1.  Manuel
2.  Répétitif
3.  Automatisable
4.  Sans valeur durable (ex: redémarrer un service à la main chaque jour).

**Objectif SRE** : Plafonner le Toil à 50% du temps. Les autres 50% doivent servir à coder des outils pour supprimer ce Toil.

## 2. L'Incident Management

### Blameless Post-Mortem
Après un crash, on ne cherche pas "Qui a fait l'erreur ?" (c'est inutile, l'humain fait toujours des erreurs), mais "Pourquoi le système a permis cette erreur ?".

*   *Mauvais :* "Michel a supprimé la prod."
*   *Bon :* "La commande de suppression n'avait pas de confirmation, et Michel avait les droits root sans 2FA."

### MTTR vs MTTF
*   **MTTF (Mean Time To Failure)** : Temps moyen entre deux pannes. (On essaie de l'augmenter).
*   **MTTR (Mean Time To Recovery)** : Temps moyen pour réparer. (C'est le KPI le plus important !).
    *   *Mieux vaut casser souvent mais réparer en 1 minute, que casser une fois par an et mettre 3 jours à réparer.*

## 3. Les 4 Signaux Dorés (Golden Signals)

Quoi monitorer si on part de zéro ? (Livre SRE Google)

1.  **Latency** : Temps pour servir une requête. (Succès vs Échec).
2.  **Traffic** : Demande sur le système (Req/sec, I/O).
3.  **Errors** : Taux d'échec (HTTP 500).
4.  **Saturation** : "A quel point sommes-nous pleins ?" (CPU, RAM, File d'attente).
