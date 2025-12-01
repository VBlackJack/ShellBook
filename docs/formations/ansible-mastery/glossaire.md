---
tags:
  - formation
  - ansible
  - automation
  - glossaire
  - reference
---

# Glossaire Ansible

Ce glossaire couvre les termes essentiels rencontrés dans la formation Ansible Mastery.

---

## A

**Agentless**
: Architecture distinctive d'Ansible utilisant SSH au lieu d'agents installés sur les serveurs cibles.

**ansible.cfg**
: Fichier de configuration contrôlant le comportement d'Ansible (chemin inventaire, roles, escalade de privilèges).

**Ansible Galaxy**
: Hub central pour partager et découvrir des roles Ansible, accessible via la commande ansible-galaxy.

**Ansible Lint**
: Outil de vérification statique validant les bonnes pratiques dans les playbooks.

**Ansible Vault**
: Utilitaire de chiffrement AES-256 pour sécuriser les données sensibles dans les fichiers YAML.

**AWX**
: Version open source d'Ansible Tower fournissant une interface web et API REST.

---

## B

**Become**
: Mécanisme d'escalade de privilèges (typiquement sudo) pour exécuter des tâches avec des permissions élevées.

**Block**
: Structure regroupant des tâches avec gestion d'erreurs commune (rescue, always).

---

## C

**Check Mode (Dry Run)**
: Mode d'exécution simulant les changements sans les appliquer réellement (--check).

**Collection**
: Format de distribution regroupant roles, modules, plugins et documentation.

**Conditional (when)**
: Clause permettant l'exécution conditionnelle de tâches basée sur des expressions.

**Connection Plugin**
: Plugin définissant comment Ansible se connecte aux hôtes (ssh, local, docker).

**Control Node**
: Machine où Ansible est installé et depuis laquelle les playbooks sont exécutés.

---

## D

**Defaults**
: Variables de faible priorité dans roles/rolename/defaults/main.yml facilement personnalisables.

**Delegate_to**
: Directive exécutant une tâche sur un hôte différent de celui ciblé.

**Dynamic Inventory**
: Scripts ou plugins générant l'inventaire dynamiquement depuis des APIs cloud.

---

## F

**Fact**
: Variable collectée automatiquement sur les nœuds gérés (hostname, IP, OS) disponible comme ansible_*.

**Filter (Jinja2)**
: Fonction transformant les variables dans les templates (| upper, | lower, | default).

**Forks**
: Nombre de processus parallèles pour exécuter des tâches sur plusieurs hôtes simultanément.

---

## G

**Gather Facts**
: Processus de collecte automatique d'informations sur les hôtes gérés au début d'un play.

**Group**
: Collection nommée d'hôtes dans l'inventaire pour des opérations groupées.

**Group Variables (group_vars)**
: Variables dans le répertoire group_vars/ appliquées automatiquement à tous les hôtes d'un groupe.

---

## H

**Handler**
: Tâche spéciale déclenchée uniquement par des notifications d'autres tâches lors de changements.

**Host**
: Serveur individuel défini dans l'inventaire par nom d'hôte ou adresse IP.

**Host Variables (host_vars)**
: Variables dans le répertoire host_vars/ pour des configurations spécifiques à un hôte.

---

## I

**Idempotence**
: Propriété permettant d'exécuter un playbook plusieurs fois avec le même résultat, sans effets secondaires.

**Include**
: Directive incluant dynamiquement des tâches, handlers ou variables depuis des fichiers externes.

**Inventory**
: Fichier statique ou dynamique listant les nœuds gérés et leur organisation en groupes.

---

## J

**Jinja2**
: Moteur de templating Python utilisé par Ansible pour la génération dynamique de fichiers.

---

## L

**Lookup Plugin**
: Plugin accédant à des données externes (fichiers, variables d'environnement, services).

**Loop**
: Structure itérant sur une liste d'éléments pour exécuter une tâche plusieurs fois.

---

## M

**Managed Node**
: Serveur cible qu'Ansible configure via SSH ; nécessite Python, pas d'agent.

**Module**
: Unité de code Python réutilisable envoyée aux nœuds gérés pour exécuter des actions spécifiques.

**Molecule**
: Framework de test pour développer et tester des roles Ansible.

---

## N

**Notify**
: Mécanisme déclenchant des handlers quand une tâche rapporte des changements.

---

## P

**Play**
: Ensemble de tâches exécutées sur un groupe d'hôtes, défini avec hosts: et contenant une ou plusieurs tâches.

**Playbook**
: Fichier YAML contenant un ou plusieurs plays définissant les workflows d'automatisation.

**Plugin**
: Extension ajoutant des fonctionnalités à Ansible (connection, callback, filter, lookup).

**Privilege Escalation**
: Mécanisme permettant d'exécuter des commandes avec des privilèges élevés (become, sudo).

---

## R

**Register**
: Directive capturant la sortie d'une tâche dans une variable pour utilisation ultérieure.

**Role**
: Unité modulaire réutilisable avec une structure de répertoires standard (tasks, handlers, templates, files, vars, defaults, meta).

**Role Dependencies**
: Roles requis définis dans meta/main.yml automatiquement exécutés avant le role principal.

---

## S

**Serial**
: Paramètre contrôlant le nombre d'hôtes traités simultanément dans un play (rolling updates).

**Strategy**
: Plugin définissant l'ordre d'exécution des tâches (linear, free, debug).

---

## T

**Tag**
: Label attaché aux tâches permettant une exécution sélective (--tags, --skip-tags).

**Task**
: Action unique dans un playbook appelant un module Ansible pour effectuer un travail.

**Template**
: Fichier Jinja2 dans roles/rolename/templates/ pour générer des configurations dynamiques.

**Tower (Ansible Tower)**
: Produit commercial Red Hat fournissant interface web, API REST, RBAC et scheduling.

---

## V

**Variable**
: Valeur nommée substituable dans les playbooks, définie dans vars:, defaults/ ou fichiers externes.

**Vars**
: Variables de haute priorité dans roles/rolename/vars/main.yml difficiles à surcharger.

**Vars_files**
: Fichiers YAML externes contenant des variables chargées dans les playbooks.

**Vault Password**
: Phrase de passe maître protégeant les fichiers chiffrés, stockée séparément et jamais commitée.

**Verbosity**
: Niveau de détail des sorties contrôlé par les flags -v, -vv, -vvv, -vvvv.

---

## W

**When**
: Clause conditionnelle déterminant si une tâche doit s'exécuter basée sur une expression.

---

## Y

**YAML**
: Format de sérialisation de données lisible par l'humain utilisé pour les playbooks et configurations Ansible.

---

**Retour au :** [Programme de la Formation](index.md)
