---
tags:
  - formation
  - kubernetes
  - glossaire
  - reference
---

# Glossaire Kubernetes

Ce glossaire couvre les termes essentiels rencontrés dans la formation Kubernetes Mastery.

---

## A

**API Server**
: Point d'entrée central pour toutes les requêtes API Kubernetes. Gère l'authentification, l'autorisation et la validation des requêtes.

**Affinity (Node/Pod)**
: Règles de planification permettant de placer les pods sur des nœuds spécifiques ou à proximité d'autres pods selon des critères de labels.

---

## B

**Bridge Network**
: Réseau virtuel par défaut permettant la communication entre conteneurs sur un même hôte.

---

## C

**Calico**
: Plugin CNI populaire fournissant le réseau et les politiques de sécurité pour Kubernetes.

**Cilium**
: Plugin CNI basé sur eBPF offrant des fonctionnalités avancées de réseau et de sécurité.

**ClusterIP**
: Type de Service exposant les pods sur une adresse IP interne au cluster uniquement.

**ClusterRole**
: Ensemble de permissions s'appliquant à l'ensemble du cluster (pas limité à un namespace).

**ClusterRoleBinding**
: Liaison accordant les permissions d'un ClusterRole à des utilisateurs ou ServiceAccounts.

**CNI (Container Network Interface)**
: Architecture de plugins permettant à Kubernetes d'utiliser différentes implémentations réseau.

**ConfigMap**
: Ressource stockant des données de configuration non-confidentielles sous forme de paires clé-valeur.

**Container**
: Unité d'exécution isolée empaquetant le code applicatif et ses dépendances.

**Control Plane**
: Couche de gestion du cluster responsable des décisions et de l'état global (API Server, etcd, Scheduler, Controller Manager).

**Controller Manager**
: Composant exécutant les boucles de contrôle qui régulent l'état du cluster.

**CRD (Custom Resource Definition)**
: Extension de l'API Kubernetes permettant de définir des types de ressources personnalisés.

**CronJob**
: Ressource exécutant des Jobs selon un planning défini par une expression cron.

**CSI (Container Storage Interface)**
: Standard pour développer des drivers de stockage compatibles avec Kubernetes.

---

## D

**DaemonSet**
: Ressource garantissant qu'un pod s'exécute sur chaque nœud du cluster.

**Deployment**
: Ressource déclarative gérant les ReplicaSets et permettant les mises à jour progressives (rolling updates).

**DNS (Service Discovery)**
: Découverte automatique des services via DNS au format service-name.namespace.svc.cluster.local.

---

## E

**Endpoint**
: Représente les adresses IP et ports des pods sélectionnés par un Service.

**etcd**
: Base de données clé-valeur distribuée servant de source de vérité pour l'état du cluster.

**emptyDir**
: Volume éphémère existant uniquement pendant la durée de vie du pod.

---

## F

**Flannel**
: Plugin CNI simple fournissant un réseau overlay pour Kubernetes.

---

## G

**GitOps**
: Méthodologie de déploiement utilisant Git comme source unique de vérité pour l'infrastructure.

---

## H

**Headless Service**
: Service avec clusterIP: None retournant directement les IPs des pods individuels.

**Helm**
: Gestionnaire de paquets pour Kubernetes utilisant des Charts (templates YAML préconfigurés).

**HPA (Horizontal Pod Autoscaler)**
: Composant scalant automatiquement le nombre de réplicas selon les métriques CPU/mémoire.

---

## I

**Ingress**
: Ressource gérant l'accès HTTP/HTTPS externe aux services selon les noms d'hôtes et chemins.

**Ingress Controller**
: Composant implémentant les règles Ingress (nginx, traefik, HAProxy).

---

## J

**Job**
: Ressource exécutant des tâches batch jusqu'à complétion.

---

## K

**Kubectl**
: Interface en ligne de commande pour interagir avec Kubernetes.

**Kubelet**
: Agent primaire sur chaque nœud assurant l'exécution des conteneurs dans les pods.

**Kube-proxy**
: Composant réseau maintenant les règles de routage vers les Services sur chaque nœud.

**Kustomize**
: Outil de personnalisation des manifestes Kubernetes sans templates.

---

## L

**Label**
: Métadonnée clé-valeur attachée aux ressources pour l'organisation et la sélection.

**LimitRange**
: Ressource définissant les limites de ressources par défaut et maximales dans un namespace.

**Liveness Probe**
: Vérification périodique déterminant si un conteneur est vivant et doit être redémarré.

**LoadBalancer**
: Type de Service exposant les pods via un load balancer du cloud provider.

---

## M

**Metrics Server**
: Composant collectant les métriques CPU/mémoire pour l'autoscaling et kubectl top.

---

## N

**Namespace**
: Partition virtuelle du cluster permettant l'isolation des ressources entre équipes.

**NetworkPolicy**
: Ressource définissant les règles de communication réseau entre pods (pare-feu).

**Node**
: Machine (physique ou virtuelle) exécutant des workloads dans le cluster.

**NodePort**
: Type de Service exposant les pods sur un port statique de chaque nœud.

**NodeSelector**
: Contrainte simple forçant les pods à se planifier sur des nœuds avec des labels spécifiques.

---

## O

**Operator**
: Pattern étendant Kubernetes avec une logique applicative personnalisée via CRDs et contrôleurs.

---

## P

**PersistentVolume (PV)**
: Ressource représentant du stockage physique provisionné dans le cluster.

**PersistentVolumeClaim (PVC)**
: Demande de stockage par un pod se liant à un PersistentVolume.

**Pod**
: Plus petite unité déployable dans Kubernetes ; un ou plusieurs conteneurs partageant réseau et stockage.

**Pod Affinity**
: Règles de planification plaçant les pods à proximité d'autres pods selon leurs labels.

**Pod Security Standards (PSS)**
: Mécanisme intégré définissant les niveaux de sécurité des pods (privileged, baseline, restricted).

**Probe**
: Vérification de santé des conteneurs (Liveness, Readiness, Startup).

---

## R

**RBAC (Role-Based Access Control)**
: Système d'autorisation Kubernetes utilisant Roles, ClusterRoles et Bindings.

**Readiness Probe**
: Vérification déterminant si un conteneur est prêt à recevoir du trafic.

**ReplicaSet**
: Contrôleur maintenant un nombre stable de pods identiques en exécution.

**ResourceQuota**
: Limite sur la consommation totale de ressources dans un namespace.

**Role**
: Ensemble de permissions dans un namespace définissant les actions autorisées.

**RoleBinding**
: Liaison accordant les permissions d'un Role à des utilisateurs ou ServiceAccounts.

**Rolling Update**
: Stratégie de mise à jour remplaçant progressivement les pods sans interruption de service.

---

## S

**Scheduler**
: Composant décidant sur quel nœud planifier les nouveaux pods.

**Secret**
: Ressource stockant des données sensibles (mots de passe, tokens, certificats) encodées en base64.

**SecurityContext**
: Configuration de sécurité au niveau pod/conteneur (runAsUser, readOnlyRootFilesystem).

**Service**
: Abstraction exposant un groupe de pods comme service réseau avec un nom DNS stable.

**ServiceAccount**
: Identité pour les processus s'exécutant dans les pods pour s'authentifier auprès de l'API.

**Startup Probe**
: Vérification initiale déterminant si une application a fini de démarrer.

**StatefulSet**
: Ressource pour applications avec état nécessitant identités réseau stables et stockage persistant.

**StorageClass**
: Ressource définissant les paramètres de provisionnement dynamique du stockage.

---

## T

**Taint**
: Propriété sur un nœud repoussant les pods sans tolération correspondante.

**Toleration**
: Propriété d'un pod lui permettant de se planifier sur des nœuds avec des taints spécifiques.

---

## V

**Volume**
: Stockage attaché à un pod, pouvant être éphémère ou persistant.

**VolumeClaimTemplate**
: Template dans les StatefulSets créant automatiquement des PVCs uniques pour chaque réplica.

---

## W

**Weave Net**
: Plugin CNI fournissant un réseau mesh pour Kubernetes.

**Worker Node**
: Nœud exécutant les charges de travail (pods) sous contrôle du Control Plane.

---

## Y

**YAML**
: Format de sérialisation utilisé pour les manifestes Kubernetes.

---

**Retour au :** [Programme de la Formation](index.md)
