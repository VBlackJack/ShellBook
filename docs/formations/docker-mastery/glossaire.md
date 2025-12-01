---
tags:
  - formation
  - docker
  - conteneurs
  - glossaire
  - reference
---

# Glossaire Docker

Ce glossaire couvre les termes essentiels rencontrés dans la formation Docker Mastery.

---

## A

**ADD**
: Instruction Dockerfile similaire à COPY mais supportant les URLs et l'extraction automatique des archives.

**Alpine**
: Image de base minimale (~5 Mo) utilisant musl libc ; compromis entre taille et compatibilité.

**Anonymous Volume**
: Volume sans nom explicite créé avec un identifiant auto-généré.

**ARG**
: Instruction Dockerfile définissant des variables de build passées avec --build-arg.

---

## B

**Base Image**
: Image fondation spécifiée avec FROM ; fournit l'OS et l'environnement d'exécution.

**Bind Mount**
: Répertoire hôte monté dans le conteneur ; dépend de la structure du système de fichiers hôte.

**Bridge Network**
: Driver réseau Docker par défaut fournissant un réseau isolé avec NAT.

**Build Context**
: Ensemble des fichiers envoyés au daemon Docker lors du build d'une image.

---

## C

**Capability**
: Permission Linux granulaire permettant des opérations privilégiées spécifiques.

**cap-add**
: Option ajoutant des capabilities spécifiques nécessaires à l'application.

**cap-drop**
: Option supprimant des capabilities du conteneur pour réduire la surface d'attaque.

**CMD**
: Instruction Dockerfile fournissant la commande par défaut ; peut être surchargée au runtime.

**Compose Project**
: Collection nommée de services déployés ensemble depuis un fichier compose.

**Container**
: Environnement d'exécution léger et isolé empaquetant le code applicatif avec ses dépendances.

**Container Name**
: Paramètre Docker Compose nommant explicitement le conteneur.

**COPY**
: Instruction Dockerfile copiant des fichiers de l'hôte vers le système de fichiers du conteneur.

---

## D

**Daemon (dockerd)**
: Service en arrière-plan gérant les objets Docker et traitant les requêtes client.

**Depends On**
: Directive Docker Compose spécifiant l'ordre de démarrage et les conditions de santé.

**Digest**
: Hash SHA256 unique identifiant une version exacte d'image à travers les registries.

**Distroless**
: Image de base minimale contenant uniquement l'application et le runtime ; sans shell ni gestionnaire de paquets.

**Docker Hub**
: Registry public officiel hébergeant des millions d'images Docker.

**Dockerfile**
: Fichier texte contenant les instructions pour construire une image Docker.

**.dockerignore**
: Fichier excluant des fichiers du contexte de build pour améliorer les performances.

---

## E

**ENTRYPOINT**
: Instruction Dockerfile définissant l'exécutable principal ; CMD devient ses arguments.

**ENV**
: Instruction Dockerfile définissant des variables d'environnement.

**Environment File (.env)**
: Fichier contenant des variables référencées dans docker-compose.yml.

**EXPOSE**
: Instruction Dockerfile documentant les ports sur lesquels le conteneur écoute.

---

## F

**FROM**
: Instruction Dockerfile spécifiant l'image de base.

---

## H

**HEALTHCHECK**
: Instruction Dockerfile définissant une commande de vérification périodique de santé.

**Host Network**
: Driver réseau Docker partageant la pile réseau de l'hôte ; pas d'isolation mais performance maximale.

---

## I

**Image**
: Template en lecture seule utilisé pour créer des conteneurs ; composé de couches de système de fichiers.

**Internal Network**
: Configuration réseau Docker Compose empêchant l'accès à Internet externe.

---

## L

**LABEL**
: Instruction Dockerfile ajoutant des métadonnées clé-valeur à l'image.

**Layer**
: Snapshot de système de fichiers créé par une instruction Dockerfile ; mis en cache et réutilisable.

**Layer Caching**
: Optimisation Docker réutilisant les couches inchangées ; l'ordre des instructions impacte l'efficacité.

---

## M

**macvlan Network**
: Driver réseau Docker assignant une adresse MAC au conteneur ; apparaît comme un périphérique physique.

**Multi-Stage Build**
: Technique Dockerfile utilisant plusieurs instructions FROM pour réduire la taille de l'image finale.

---

## N

**Named Volume**
: Volume créé explicitement et identifié par un nom ; géré par Docker.

**Network Alias**
: Nom DNS alternatif pour accéder à un conteneur sur un réseau.

**none Network**
: Driver réseau Docker désactivant toute connectivité réseau.

---

## O

**Overlay Network**
: Driver réseau Docker permettant la communication multi-hôtes dans Docker Swarm.

---

## P

**Port Mapping**
: Liaison d'un port conteneur à un port hôte (format: hôte:conteneur).

**Port Publishing**
: Exposition d'un port conteneur pour l'accès externe via le flag -p.

**Profile**
: Fonctionnalité Docker Compose pour démarrer conditionnellement des services.

---

## R

**Read-Only Filesystem**
: Exécution d'un conteneur avec système de fichiers racine en lecture seule (--read-only).

**Registry**
: Dépôt centralisé pour stocker et distribuer des images Docker.

**Restart Policy**
: Paramètre contrôlant le comportement de redémarrage automatique du conteneur.

**Rootless Mode**
: Exécution du daemon Docker sans privilèges root pour une sécurité renforcée.

**RUN**
: Instruction Dockerfile exécutant des commandes pendant le build ; crée une nouvelle couche.

---

## S

**Scale**
: Opération Docker Compose créant plusieurs instances d'un service.

**Seccomp Profile**
: Mécanisme de filtrage des appels système restreignant l'accès du conteneur au kernel.

**Secret**
: Fonctionnalité Docker Swarm pour gérer les données sensibles de manière sécurisée.

**Security Option**
: Configuration de sécurité runtime Docker (no-new-privileges, profil seccomp).

**Service**
: Définition Docker Compose d'un conteneur ; représente un composant applicatif unique.

**SHELL**
: Instruction Dockerfile changeant le shell par défaut pour RUN, CMD, ENTRYPOINT.

---

## T

**Tag**
: Label identifiant des versions spécifiques d'images Docker (ex: nginx:1.25-alpine).

**tmpfs Mount**
: Système de fichiers temporaire en mémoire pour données sensibles ; non persistant.

---

## U

**USER**
: Instruction Dockerfile spécifiant un utilisateur non-root pour l'exécution du conteneur.

**User Namespace**
: Fonctionnalité de sécurité Linux isolant les IDs utilisateur entre hôte et conteneur.

---

## V

**Volume**
: Stockage persistant géré par Docker ; stocké dans /var/lib/docker/volumes/.

**VOLUME**
: Instruction Dockerfile déclarant un point de montage de stockage.

**Volume Backup**
: Processus d'exportation des données de volume vers une archive.

**Volume Driver**
: Plugin fournissant des backends de stockage alternatifs (NFS, local, etc.).

**Volume Restore**
: Processus d'importation de données archivées dans un volume Docker.

---

## W

**WORKDIR**
: Instruction Dockerfile définissant le répertoire de travail pour les commandes suivantes.

---

**Retour au :** [Programme de la Formation](index.md)
