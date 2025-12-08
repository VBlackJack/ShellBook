---
tags:
  - ai
  - index
  - deep-learning
  - machine-learning
---

# Intelligence Artificielle

Comprendre les mécanismes derrière la magie. Cette section démystifie l'IA en séparant les approches historiques (Logique) des approches modernes (Apprentissage).

---

## Fondamentaux

| Article | Description | Niveau |
|---------|-------------|--------|
| [Concepts & Histoire](concepts-intro.md) | Comprendre la différence entre IA Symbolique et Connexionniste. | :material-star: |
| [IA Prompting](../concepts/ai-prompting.md) | Guide pratique pour parler aux LLM modernes. | :material-star: |

## Les Approches de l'IA

### 1. IA Symbolique (Logique & Règles)
L'approche "Old School", parfaite pour les problèmes aux règles claires et définies.
*   **Principe** : Si / Alors / Sinon.
*   **Articles** :
    *   [Systèmes Experts](symbolic-ai.md) : Le raisonnement par règles (Ex: Diagnostic, Classification).

### 2. IA Connexionniste & Évolution
L'approche "Moderne" et inspirée de la nature.
*   **Principe** : Données + Entraînement = Modèle.
*   **Articles** :
    *   [Algorithmes Génétiques](genetic-algos.md) : L'évolution darwinienne appliquée au code (Optimisation).

### 3. Autres Paradigmes
Des approches spécialisées pour des besoins précis.
*   [Logique Floue](fuzzy-logic.md) : Gérer l'imprécision ("Un peu chaud") et la nuance.
*   [Pathfinding (A*)](pathfinding.md) : Comment l'IA trouve son chemin (Graphes & Navigation).

---

## Panorama Rapide

```mermaid
graph TD
    AI[Intelligence Artificielle]
    
    Symbolic[IA Symbolique<br>(Règles & Logique)]
    Connect[IA Connexionniste<br>(Données & Stats)]
    
    AI --> Symbolic
    AI --> Connect
    
    Symbolic --> Expert[Systèmes Experts]
    Symbolic --> Logic[Logique Formelle]
    
    Connect --> ML[Machine Learning]
    ML --> DL[Deep Learning]
    ML --> RL[Reinforcement Learning]
    
    DL --> CNN[Vision (CNN)]
    DL --> RNN[Langage (RNN/Transformers)]
    RNN --> LLM[ChatGPT / Gemini]
```
