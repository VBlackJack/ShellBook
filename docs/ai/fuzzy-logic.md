---
tags:
  - ai
  - fuzzy-logic
  - logic
---

# Logique Floue (Fuzzy Logic)

L'informatique classique est binaire : C'est vrai (1) ou c'est faux (0).
La **Logique Floue** permet de gérer les nuances du monde réel : C'est "un peu vrai" ou "presque faux".

## Le Problème de la Logique Binaire

Imaginons un système de climatisation automatique.
*   Règle classique : `SI (Température > 25°C) ALORS [Clim ON]`
*   **Problème** : À 24.9°C, la clim est éteinte. À 25.1°C, elle démarre à fond. À 25.0°C, elle clignote. C'est brutal et inefficace.

## La Solution "Floue"

Introduite par Lotfi Zadeh en 1965, cette logique remplace les booléens par des **Degrés d'Appartenance** (compris entre 0 et 1).

### Incertitude vs Imprécision
*   **Incertitude** (Probabilités) : "Il y a 50% de chances qu'il pleuve demain." (L'événement futur est inconnu).
*   **Imprécision** (Logique Floue) : "Il fait un peu chaud." (L'événement est connu, mais sa définition est subjective).

### Fonction d'Appartenance
Au lieu de dire "Il fait Chaud" (Vrai/Faux), on définit des courbes.
Pour une température de 22°C, on pourrait dire :
*   Froid : 0%
*   Tiède : 80% (0.8)
*   Chaud : 20% (0.2)

Le système ne prend pas une décision brutale, il mélange les règles :
`Puissance Clim = (0.2 * Max) + (0.8 * Moyen)`

## Cas d'Usage
La logique floue est partout dans l'électronique grand public (Japon) :
*   **Machines à laver** : Ajuster l'eau selon si le linge est "plutôt sale" ou "très lourd".
*   **Appareils Photo** : Stabilisation d'image (compenser le tremblement "léger").
*   **Métros automatiques** : Freinage doux (au lieu d'accélérer/freiner par à-coups).

> **En résumé** : La Logique Floue permet aux machines de raisonner avec des concepts humains vagues ("vite", "loin", "fort") plutôt qu'avec des seuils numériques rigides.
