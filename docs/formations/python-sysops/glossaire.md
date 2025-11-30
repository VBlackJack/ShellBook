---
tags:
  - formation
  - python
  - glossaire
---

# Glossaire Python

Terminologie Python et concepts clés.

---

## A

**API (Application Programming Interface)**
: Interface permettant à des applications de communiquer entre elles. En Python, on interagit souvent avec des APIs REST via HTTP.

**Argument**
: Valeur passée à une fonction lors de son appel. Voir aussi : Paramètre.

**Assert**
: Instruction qui vérifie qu'une condition est vraie. Utilisée principalement dans les tests.

---

## B

**Binding**
: Association d'un nom (variable) à un objet en mémoire.

**Boolean**
: Type de données avec deux valeurs possibles : `True` ou `False`.

**Built-in**
: Fonctions, types ou exceptions fournis nativement par Python (`print`, `len`, `list`, etc.).

---

## C

**Callback**
: Fonction passée en argument à une autre fonction pour être appelée ultérieurement.

**Class**
: Modèle pour créer des objets. Définit attributs et méthodes.

**Closure**
: Fonction qui capture les variables de son environnement englobant.

**Compréhension (List/Dict/Set)**
: Syntaxe concise pour créer des collections : `[x*2 for x in range(10)]`.

**Context Manager**
: Objet gérant l'entrée et la sortie d'un bloc `with`. Utilisé pour les fichiers, connexions, etc.

---

## D

**Decorator**
: Fonction qui modifie le comportement d'une autre fonction. Syntaxe `@decorator`.

**Dictionary (dict)**
: Collection de paires clé-valeur. Accès O(1) par clé.

**Docstring**
: Chaîne de documentation au début d'une fonction, classe ou module.

**Duck Typing**
: Principe où le type d'un objet est déterminé par ses méthodes, pas sa classe. "If it walks like a duck..."

---

## E

**Exception**
: Erreur détectée à l'exécution. Peut être interceptée avec `try/except`.

**Expression**
: Code qui produit une valeur. Ex: `1 + 2`, `func()`.

---

## F

**f-string**
: Chaîne formatée avec préfixe `f`. Ex: `f"Hello {name}"`.

**Falsy**
: Valeurs évaluées à `False` en contexte booléen : `0`, `""`, `[]`, `None`, `{}`.

**First-class Function**
: Les fonctions sont des objets : peuvent être assignées, passées en argument, retournées.

---

## G

**Generator**
: Fonction qui utilise `yield` pour produire des valeurs paresseusement (lazy evaluation).

**GIL (Global Interpreter Lock)**
: Verrou qui empêche l'exécution parallèle de threads Python.

**Global**
: Variable accessible depuis tout le module. Mot-clé `global` pour modifier.

---

## I

**Immutable**
: Objet qui ne peut pas être modifié après création. Ex: `str`, `tuple`, `frozenset`.

**Import**
: Instruction pour charger un module ou package.

**Iterable**
: Objet sur lequel on peut itérer (boucle `for`). Ex: list, dict, str, fichier.

**Iterator**
: Objet qui produit des éléments un par un via `__next__()`.

---

## K

**Keyword Argument**
: Argument passé par nom : `func(name="value")`.

---

## L

**Lambda**
: Fonction anonyme sur une ligne : `lambda x: x * 2`.

**List**
: Collection ordonnée et mutable. Accès par index O(1).

**List Comprehension**
: `[expression for item in iterable if condition]`

---

## M

**Method**
: Fonction définie dans une classe. Premier paramètre `self`.

**Module**
: Fichier Python (`.py`) contenant du code réutilisable.

**Mutable**
: Objet modifiable après création. Ex: `list`, `dict`, `set`.

---

## N

**Namespace**
: Espace isolé pour les noms de variables. Évite les conflits.

**None**
: Singleton représentant l'absence de valeur. Équivalent de `null` dans d'autres langages.

---

## O

**Object**
: Tout en Python est un objet (instance d'une classe).

**OOP (Object-Oriented Programming)**
: Paradigme basé sur les objets et classes.

---

## P

**Package**
: Répertoire contenant des modules et un `__init__.py`.

**Parameter**
: Variable dans la définition d'une fonction. Voir aussi : Argument.

**PEP (Python Enhancement Proposal)**
: Documents décrivant les standards Python. PEP 8 : style, PEP 20 : Zen of Python.

**pip**
: Gestionnaire de paquets Python.

**Property**
: Attribut géré via getter/setter. Décorateur `@property`.

---

## R

**REPL (Read-Eval-Print Loop)**
: Interpréteur interactif Python.

**Requirements**
: Fichier (`requirements.txt`) listant les dépendances d'un projet.

---

## S

**Scope**
: Portée d'une variable. LEGB : Local, Enclosing, Global, Built-in.

**self**
: Premier paramètre des méthodes d'instance, référence à l'objet courant.

**Set**
: Collection non ordonnée d'éléments uniques.

**Slice**
: Extraction d'une portion de séquence : `list[1:5]`, `str[::2]`.

**Statement**
: Instruction qui effectue une action. Ex: `if`, `for`, `def`, `import`.

---

## T

**Tuple**
: Collection ordonnée et immutable. Souvent pour retours multiples.

**Type Hint**
: Annotation de type optionnelle : `def func(name: str) -> int:`

---

## U

**Unpacking**
: Extraction de valeurs : `a, b = (1, 2)`, `first, *rest = [1, 2, 3, 4]`.

---

## V

**venv**
: Environnement virtuel Python isolant les dépendances.

**Variable**
: Nom lié à une valeur/objet.

---

## Y

**yield**
: Mot-clé pour créer un générateur. Produit une valeur et suspend l'exécution.

---

## Voir Aussi

- [Cheatsheet Python](cheatsheet-python.md)
- [Programme de la formation](index.md)
