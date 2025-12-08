---
tags:
  - green-it
  - finops
  - sustainability
  - carbon
---

# Green IT & GreenOps

Le numérique pollue (4% des GES mondiaux, plus que l'aviation civile).
Le GreenOps est l'application des principes DevOps pour réduire cette empreinte.

## 1. Les Indicateurs Clés

### PUE (Power Usage Effectiveness)
L'efficacité du datacenter.
$$ \text{PUE} = \frac{\text{Énergie Totale}}{\text{Énergie Informatique}} $$
*   **1.0** : Idéal théorique (0% de perte).
*   **1.2** : Excellent (Google, Azure).
*   **2.0** : Médiocre (Pour 1W de calcul, on consomme 1W de clim).

### L'Intensité Carbone (gCO2eq/kWh)
L'électricité n'est pas égale partout.
*   **France/Suède** (Nucléaire/Hydro) : Très bas (~50g).
*   **Allemagne/Pologne** (Renouvelable) : Moyen.
*   **Pologne/Inde/USA** (Charbon) : Très haut (~700g).

> **Action GreenOps** : Déplacer un batch de calcul la nuit ou dans une région "verte".

## 2. Outils de Mesure

On ne peut pas améliorer ce qu'on ne mesure pas.

### Scaphandre
Agent open-source (Rust) qui mesure la consommation électrique des processus.
*   Il regarde les compteurs RAPL (Running Average Power Limit) du CPU.
*   Il exporte des métriques Prometheus.

### Kepler (Kubernetes-based Efficient Power Level Exporter)
Le standard pour Kubernetes.
*   Il utilise **eBPF** pour corréler les appels système avec la consommation d'énergie.
*   Il peut estimer la consommation même sans compteur matériel (via Machine Learning).

## 3. Bonnes Pratiques GreenOps

1.  **Éteindre (Scaling to Zero)** : Les environnements de Dev ne servent à rien la nuit et le weekend (-60% de conso).
2.  **Mutualiser** : Mieux vaut un gros serveur utilisé à 80% que 10 petits serveurs à 10% (Overhead de l'OS).
3.  **Coder mieux** : Un algo optimisé consomme moins de cycles CPU. (Python consomme 70x plus que le C ou Rust pour la même tâche).
4.  **Prolonger le matériel** : L'impact carbone de la fabrication (Scope 3) est souvent supérieur à l'usage. Garder un serveur 5 ans au lieu de 3 réduit l'impact de 40%.

## 4. Le lien FinOps / GreenOps

Souvent, **moins cher = moins polluant**.
*   Réduire la taille des instances (Right-sizing) → Moins de $ et moins de Watts.
*   Utiliser des Spot Instances (combler les trous de capacité) → Optimisation des ressources existantes.
