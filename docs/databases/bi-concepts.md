---
tags:
  - databases
  - data
  - bi
  - warehousing
---

# Concepts Data & Business Intelligence

Avant de manipuler des Big Data, il faut comprendre l'architecture qui permet de transformer la donnée brute en information décisionnelle.

## 1. OLTP vs OLAP

La distinction fondamentale en gestion de données.

| Caractéristique | OLTP (Online Transaction Processing) | OLAP (Online Analytical Processing) |
|-----------------|--------------------------------------|-------------------------------------|
| **Objectif** | Gérer l'opérationnel au quotidien | Analyser, décider, prévoir |
| **Opérations** | Beaucoup de petites lectures/écritures rapides (INSERT/UPDATE) | Grosses lectures complexes (SELECT SUM...) |
| **Données** | Actuelles, détaillées, normalisées | Historisées, agrégées, dénormalisées |
| **Exemple** | Site E-commerce (Panier, Paiement) | Tableau de bord des ventes par région |
| **Technologies** | PostgreSQL, MySQL, MongoDB | Snowflake, BigQuery, Redshift, ClickHouse |

## 2. L'Entrepôt de Données (Data Warehouse)

C'est le cerveau de la BI. Il centralise toutes les données de l'entreprise (CRM, ERP, Site Web, Logs).
*   **Historisé** : On ne supprime jamais rien (contrairement à la prod qui efface les vieux paniers).
*   **Non-Volatile** : Une fois écrite, la donnée ne change plus.
*   **Orienté Sujet** : Organisé par thème (Ventes, Clients) et non par application.

### Data Mart
Un sous-ensemble du Data Warehouse, spécialisé pour un métier précis (ex: Data Mart Marketing, Data Mart RH).

## 3. Le Processus ETL (Extract, Transform, Load)

Comment la donnée arrive-t-elle dans l'entrepôt ?

1.  **Extract** : On aspire les données des sources (Bases de prod, API, Fichiers CSV).
2.  **Transform** : Le gros du travail.
    *   Nettoyage (Supprimer les doublons, corriger les fautes).
    *   Standardisation (Convertir "F", "Femme", "Female" -> "F").
    *   Anonymisation (RGPD).
3.  **Load** : On charge la donnée propre dans le Data Warehouse.

> *Note : Aujourd'hui, on fait souvent du **ELT** (Extract-Load-Transform). On charge tout en brut dans le Cloud (Data Lake), et on transforme ensuite via SQL (dbt).*

## 4. Modélisation Dimensionnelle (Kimball)

Comment structurer les tables pour l'analyse ? Surtout pas comme en production (3e Forme Normale).

### Table de Faits (Fact Table)
Le cœur du réacteur. Elle contient les **métriques** (chiffres).
*   Exemple : `Ventes`
*   Colonnes : `quantité`, `montant_total`, `marge`.
*   Clés étrangères vers les dimensions (`id_client`, `id_produit`, `id_temps`).

### Table de Dimensions
Le contexte ("Qui", "Quoi", "Où", "Quand").
*   Exemple : `Dim_Client` (`nom`, `ville`, `segment`), `Dim_Temps` (`année`, `mois`, `jour_férié`).

### Schémas

#### Schéma en Étoile (Star Schema)
Le plus simple et le plus performant.
*   Une table de Faits au centre.
*   Les Dimensions autour, reliées directement.
*   *Avantage* : Requêtes SQL simples et rapides.

#### Schéma en Flocon (Snowflake Schema)
*   Les dimensions sont elles-mêmes normalisées (ex: `Dim_Produit` pointe vers `Dim_Categorie`).
*   *Inconvénient* : Trop de jointures (JOIN), plus lent à lire. Moins utilisé aujourd'hui grâce à la puissance du stockage colonnaire.
