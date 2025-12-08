---
tags:
  - platform-engineering
  - idp
  - developer-experience
  - backstage
---

# Platform Engineering & DevEx

Après le DevOps ("You build it, you run it"), voici le Platform Engineering.
Le problème du DevOps pur : la **Charge Cognitive** (Cognitive Load). On demande aux dévs de connaître Python + Docker + K8s + Terraform + AWS + Sécurité... C'est trop.

## 1. Le Concept : Internal Developer Platform (IDP)

L'équipe Platform ne construit pas le produit final. Elle construit **l'usine** qui permet aux autres équipes de construire le produit.

**L'objectif** : Le Self-Service.
Un développeur ne doit pas ouvrir un ticket Jira "J'ai besoin d'une base de données". Il doit cliquer sur un bouton, et l'obtenir en 5 minutes, avec les bonnes pratiques de sécurité déjà appliquées.

## 2. Les "Golden Paths" (Paved Roads)

On ne force pas les dévs, on les incite.
*   "Tu peux faire ton infra à la main, mais tu te débrouilles pour la sécu et le monitoring."
*   "Si tu utilises notre **Golden Path** (le template standard), tu as le monitoring, les logs, le HTTPS et la CI/CD gratuits et configurés par défaut."

## 3. Backstage : Le Portail Unifié

Projet open-source (créé par Spotify) qui est devenu le standard des IDP.

### À quoi ça sert ?
1.  **Software Catalog** : Un annuaire de tous les microservices de la boîte (Qui est l'owner ? Où est la doc ? Où est la CI ?).
2.  **Scaffolding (Templates)** : "Créer un nouveau microservice SpringBoot". En un clic, le repo Git est créé avec le squelette, le Jenkinsfile et le Dockerfile validés.
3.  **Docs-as-Code** : Centralise toute la documentation technique (comme ShellBook !).

## 4. Platform as a Product

L'équipe Platform doit traiter les développeurs comme des **clients**.
*   Faire de la recherche utilisateur ("Qu'est-ce qui vous ralentit ?").
*   Avoir une Roadmap.
*   Vendre sa plateforme en interne (Marketing).

Si la plateforme est nulle, les dévs feront du "Shadow IT".
