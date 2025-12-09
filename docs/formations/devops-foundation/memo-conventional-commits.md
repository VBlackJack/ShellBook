---
tags:
  - formation
  - devops
  - git
  - conventional-commits
  - memo
---

# Fiche Memo : Conventional Commits

Convention de nommage des commits Git pour un historique lisible et exploitable par des outils automatisés.

---

## Format Standard

```xml
<type>(<scope>): <description>

[body]

[footer(s)]
```

### Exemple Complet

```xml
feat(auth): Ajout authentification OAuth2

- Implémentation du flow Authorization Code
- Support Google et GitHub comme providers
- Stockage sécurisé des tokens en session

Closes #123
Co-authored-by: Alice <alice@example.com>
```

---

## Types Obligatoires

| Type | Description | Exemple |
|------|-------------|---------|
| `feat` | Nouvelle fonctionnalité | `feat: Ajout page de profil` |
| `fix` | Correction de bug | `fix: Correction erreur 500 sur /api/users` |

## Types Recommandés

| Type | Description | Exemple |
|------|-------------|---------|
| `docs` | Documentation uniquement | `docs: Mise à jour README` |
| `style` | Formatage (pas de logique) | `style: Correction indentation` |
| `refactor` | Refactoring sans changement fonctionnel | `refactor: Extraction méthode validateUser` |
| `perf` | Amélioration des performances | `perf: Optimisation requête SQL` |
| `test` | Ajout ou modification de tests | `test: Ajout tests unitaires auth` |
| `build` | Système de build, dépendances | `build: Mise à jour webpack 5.90` |
| `ci` | Configuration CI/CD | `ci: Ajout job de déploiement` |
| `chore` | Maintenance, tâches diverses | `chore: Nettoyage fichiers temporaires` |
| `revert` | Annulation d'un commit précédent | `revert: Annulation feat: dark mode` |

---

## Scope (Optionnel)

Le scope indique la **partie du code** affectée. Il est entre parenthèses après le type.

### Exemples de Scopes

```bash
feat(api): Ajout endpoint /users
fix(ui): Correction bouton submit
docs(readme): Ajout section installation
ci(github): Configuration des workflows
refactor(auth): Simplification du middleware
```

### Scopes Courants

| Scope | Usage |
|-------|-------|
| `api` | Backend, endpoints REST |
| `ui` | Interface utilisateur |
| `auth` | Authentification/autorisation |
| `db` | Base de données, migrations |
| `config` | Configuration |
| `deps` | Dépendances |
| `ci` | Pipeline CI/CD |

---

## Description

La description est un **résumé court** (< 72 caractères) qui :

- Commence par une **minuscule** (ou majuscule selon convention)
- Utilise l'**impératif** : "Ajoute" pas "Ajouté" ou "Ajout de"
- Ne termine **pas** par un point
- Répond à "Ce commit va..." : `feat: Ajouter la page de login`

### Bon vs Mauvais

| Mauvais | Bon |
|---------|-----|
| `fix: Fixed bug` | `fix: Corriger le crash au démarrage` |
| `feat: added new feature.` | `feat: Ajouter export CSV` |
| `update` | `docs: Mettre à jour le changelog` |
| `WIP` | `feat(api): Ajouter endpoint GET /users` |
| `misc changes` | `refactor: Extraire la logique de validation` |

---

## Body (Optionnel)

Le body fournit des **détails supplémentaires** :

- Séparé de la description par une **ligne vide**
- Explique le **pourquoi** et le **comment**
- Peut contenir des listes à puces
- Limite à **72 caractères par ligne** (soft wrap)

```text
feat(auth): Ajout support SAML 2.0

Le SSO SAML est requis pour les clients enterprise.
Cette implémentation utilise la bibliothèque passport-saml.

- Support des IdP : Okta, Azure AD, OneLogin
- Metadata endpoint pour configuration automatique
- Fallback vers login classique si SAML échoue
```

---

## Footer (Optionnel)

Les footers contiennent des **métadonnées** :

### Breaking Changes

```text
feat(api)!: Changer format de réponse /users

BREAKING CHANGE: Le champ `name` est remplacé par `firstName` et `lastName`.
Les clients doivent mettre à jour leur parsing.
```

**Note :** Le `!` après le type/scope indique aussi un breaking change.

### Références Issues

```text
fix(auth): Corriger expiration des tokens

Fixes #42
Closes #123
Resolves #456
```

### Co-auteurs

```xml
feat: Implémentation du nouveau dashboard

Co-authored-by: Bob <bob@example.com>
Co-authored-by: Charlie <charlie@example.com>
```

---

## Exemples par Situation

### Nouvelle Feature

```text
feat(orders): Ajouter filtrage par date

- Filtres: aujourd'hui, semaine, mois, custom
- Intégration avec le date picker existant
- Tests e2e ajoutés

Closes #234
```

### Bug Fix

```text
fix(cart): Corriger calcul total avec réductions

Le total n'incluait pas les réductions cumulées.
Ajout d'un test de régression.

Fixes #567
```

### Documentation

```text
docs: Ajouter guide de contribution

- Instructions pour fork et PR
- Standards de code
- Checklist de review
```

### Refactoring

```text
refactor(services): Extraire logique de notification

Préparation pour l'ajout de notifications push.
Aucun changement fonctionnel.
```

### CI/CD

```bash
ci(github): Ajouter cache npm pour accélérer le build

Réduit le temps de build de 5min à 2min.
```

### Breaking Change

```text
feat(api)!: Migrer vers API v2

BREAKING CHANGE:
- Endpoint /api/users → /api/v2/users
- Pagination par cursor au lieu d'offset
- Nouveau format d'erreur JSON

Migration guide: docs/migration-v2.md
```

### Revert

```text
revert: feat(ui): Ajouter mode sombre

This reverts commit abc123def.

Le mode sombre causait des problèmes d'accessibilité.
Une nouvelle implémentation est prévue.
```

---

## Outils & Automatisation

### Commitlint

Valide les messages de commit :

```bash
npm install --save-dev @commitlint/cli @commitlint/config-conventional
```

```javascript
// commitlint.config.js
module.exports = {
  extends: ['@commitlint/config-conventional']
};
```

### Commitizen

Assistant interactif pour les commits :

```bash
npm install --save-dev commitizen cz-conventional-changelog
npx cz  # Au lieu de git commit
```

### Husky (Git Hooks)

Valide avant chaque commit :

```bash
npm install --save-dev husky
npx husky add .husky/commit-msg 'npx commitlint --edit $1'
```

### Semantic Release

Génère automatiquement les versions et changelogs :

```bash
npm install --save-dev semantic-release
```

Mapping type → version :

| Commit | Version Bump |
|--------|--------------|
| `fix:` | PATCH (1.0.0 → 1.0.1) |
| `feat:` | MINOR (1.0.0 → 1.1.0) |
| `BREAKING CHANGE` | MAJOR (1.0.0 → 2.0.0) |

---

## Règles Rapides

1. **Un commit = une modification logique**
2. **Type obligatoire** : `feat`, `fix`, etc.
3. **Description concise** : < 72 caractères
4. **Impératif** : "Ajouter" pas "Ajouté"
5. **Pas de point final** dans la description
6. **Body pour le contexte** : pourquoi et comment
7. **Footer pour les références** : issues, breaking changes
8. **`!` pour breaking changes** : `feat!:` ou `feat(scope)!:`

---

## Aide-Mémoire Visuel

```text
┌──────────────────────────────────────────────────────────────┐
│  feat(auth): Ajouter authentification OAuth2                │
│  │     │     └── Description (impératif, < 72 chars)        │
│  │     └── Scope (optionnel, partie du code)                │
│  └── Type (obligatoire)                                      │
├──────────────────────────────────────────────────────────────┤
│  (ligne vide obligatoire si body)                            │
├──────────────────────────────────────────────────────────────┤
│  Body optionnel :                                            │
│  - Explique le pourquoi                                      │
│  - Détails d'implémentation                                  │
│  - 72 chars max par ligne                                    │
├──────────────────────────────────────────────────────────────┤
│  (ligne vide obligatoire si footer)                          │
├──────────────────────────────────────────────────────────────┤
│  BREAKING CHANGE: description du changement                  │
│  Closes #123                                                 │
│  Co-authored-by: Name <email>                                │
└──────────────────────────────────────────────────────────────┘
```

---

**Retour au :** [Programme de la Formation](index.md) | [Catalogue](../index.md)
