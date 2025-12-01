---
tags:
  - formation
  - terraform
  - aci
  - cisco
  - glossaire
  - reference
---

# Glossaire Terraform & Cisco ACI

Ce glossaire couvre les termes essentiels rencontrés dans la formation Terraform ACI.

---

## A

**ACI (Application Centric Infrastructure)**
: Solution SDN de Cisco fournissant une gestion centralisée des politiques réseau pour les datacenters.

**APIC (Application Policy Infrastructure Controller)**
: Contrôleur de gestion centralisé qui configure et supervise l'ensemble du fabric ACI.

**Application Profile (AP)**
: Conteneur logique regroupant les EPGs liés au sein d'un tenant.

**Argument**
: Paramètre nommé dans un bloc resource ou provider spécifiant les valeurs de configuration.

---

## B

**Backend**
: Emplacement de stockage pour les fichiers d'état Terraform (local, S3, Azure Blob, Terraform Cloud).

**Block**
: Structure conteneur regroupant des arguments liés (resource, provider, variable, output).

**Bridge Domain (BD)**
: Domaine de transfert Layer 2 équivalent fonctionnel d'un VLAN ; appartient à un seul VRF.

---

## C

**Contract**
: Politique de sécurité définissant les communications autorisées entre EPGs selon un modèle whitelist.

**COOP (Council of Oracles Protocol)**
: Base de données distribuée sur les Spines résolvant la localisation des endpoints dans le fabric.

**Count**
: Méta-argument créant plusieurs instances de ressources à partir d'un compteur numérique.

---

## D

**Data Source**
: Référence en lecture seule à une infrastructure existante non gérée par Terraform.

**Destroy**
: Commande Terraform supprimant toutes les ressources gérées définies dans la configuration.

**Distinguished Name (DN)**
: Chemin hiérarchique identifiant de manière unique un objet dans ACI.

**Dynamic Provisioning**
: Création automatique de ressources en réponse à des demandes basées sur des paramètres prédéfinis.

---

## E

**ECMP (Equal-Cost Multi-Path)**
: Mécanisme de routage utilisant simultanément plusieurs chemins de coût égal pour le load balancing.

**Endpoint**
: Périphérique physique ou virtuel (VM, serveur) connecté au fabric et membre d'un EPG.

**EPG (Endpoint Group)**
: Regroupement logique d'endpoints partageant les mêmes politiques de sécurité ; brique fondamentale de la micro-segmentation.

**External EPG (eEPG)**
: Représentation virtuelle des réseaux externes accessibles via L3Out pour les politiques de sécurité.

---

## F

**Fabric**
: Infrastructure réseau ACI complète incluant Spines, Leafs et contrôleurs APIC.

**Filter**
: Objet réutilisable contenant les spécifications protocole/port utilisées par les contracts.

**For_each**
: Méta-argument créant plusieurs instances de ressources à partir d'une map ou d'un set.

---

## G

**Graph**
: Représentation des dépendances entre ressources Terraform déterminant l'ordre d'exécution.

---

## H

**HCL (HashiCorp Configuration Language)**
: Langage déclaratif utilisé par Terraform pour décrire l'infrastructure as code.

---

## I

**IaC (Infrastructure as Code)**
: Pratique de gestion de l'infrastructure via du code versionné et reproductible.

**Import**
: Commande Terraform permettant d'importer des ressources existantes dans l'état géré.

**Init**
: Commande Terraform initialisant un répertoire de travail et téléchargeant les providers.

**Interpolation**
: Syntaxe permettant d'intégrer des références de variables ou ressources dans des chaînes.

---

## L

**L3Out (Layer 3 Outside)**
: Objet ACI gérant la connectivité externe Layer 3 via BGP, OSPF ou routage statique.

**Leaf**
: Couche de commutation edge dans le fabric ACI connectant les endpoints au réseau.

**Lifecycle**
: Méta-arguments contrôlant le comportement des ressources (prevent_destroy, ignore_changes).

**Local**
: Variable locale définie avec le bloc locals ; valeur calculée disponible dans tout le module.

---

## M

**Module**
: Conteneur réutilisable regroupant des ressources Terraform liées pour l'organisation du code.

**Multi-Pod**
: Architecture couvrant plusieurs pods physiques au sein du même fabric via IPN.

**Multi-Site**
: Architecture couvrant plusieurs fabrics ACI indépendants orchestrés par NDO.

---

## N

**NDO (Nexus Dashboard Orchestrator)**
: Outil d'orchestration pour les déploiements ACI multi-site.

---

## O

**OpFlex**
: Protocole de communication entre APIC et les switches du fabric pour la distribution des politiques.

**Output**
: Valeur exportée par une configuration Terraform, affichable ou référençable par d'autres modules.

---

## P

**Plan**
: Commande Terraform générant un plan d'exécution montrant les changements à appliquer.

**Preferred Group**
: Fonctionnalité permettant aux EPGs membres de communiquer sans contracts explicites.

**Provider**
: Plugin permettant à Terraform de communiquer avec des APIs et services externes.

---

## R

**Resource**
: Objet d'infrastructure gérable dans Terraform représentant des entités réelles.

**Refresh**
: Opération synchronisant l'état Terraform avec l'état réel de l'infrastructure.

---

## S

**Spine**
: Couche de commutation haute performance dans le fabric ACI gérant le transit entre Leafs.

**State File (terraform.tfstate)**
: Fichier JSON maintenant le mapping entre le code Terraform et les ressources réelles.

**State Locking**
: Mécanisme empêchant les modifications concurrentes du fichier d'état.

**Subnet**
: Passerelle IP dans un Bridge Domain fournissant le routage Layer 3.

---

## T

**Taboo Contract**
: Contract explicite de refus bloquant le trafic spécifié, prioritaire sur les contracts permissifs.

**Tenant**
: Conteneur fournissant l'isolation administrative et le multi-tenancy ; unité organisationnelle de plus haut niveau dans ACI.

**Terraform Cloud**
: Service SaaS HashiCorp pour la gestion collaborative des états et l'exécution des plans.

**Taint**
: Commande marquant une ressource pour recréation lors du prochain apply.

---

## V

**Validation**
: Règles de contrainte sur les variables garantissant que les valeurs respectent les conditions spécifiées.

**Variable**
: Valeur d'entrée paramétrée rendant le code Terraform flexible et réutilisable.

**VNI (VXLAN Network Identifier)**
: Identifiant 24 bits identifiant de manière unique un segment VXLAN.

**VRF (Virtual Routing and Forwarding)**
: Instance de routage isolée limitant la communication entre endpoints sauf autorisation via contracts.

**VTEP (VXLAN Tunnel Endpoint)**
: Adresse IP sur les Leafs servant de source/destination pour l'encapsulation VXLAN.

**VXLAN (Virtual Extensible LAN)**
: Technologie d'encapsulation overlay permettant l'extension de réseaux Layer 2 sur Layer 3.

---

## W

**Workspace**
: Environnement d'état isolé nommé permettant plusieurs configurations de la même infrastructure.

---

**Retour au :** [Programme de la Formation](index.md)
