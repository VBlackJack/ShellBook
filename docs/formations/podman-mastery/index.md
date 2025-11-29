---
tags:
  - formation
  - podman
  - containers
  - rhel
---

# Podman Mastery : Conteneurs pour l'Entreprise

## Présentation

Formation complète sur l'écosystème Podman (Red Hat). De l'installation à la production, maîtrisez les conteneurs sans daemon avec Podman, Buildah et Skopeo. Focus sur les environnements RHEL/Rocky Linux et l'intégration systemd.

## Objectifs

À l'issue de cette formation, vous serez capable de :

- Comprendre les différences Docker vs Podman
- Exécuter des conteneurs rootless en production
- Construire des images avec Buildah
- Gérer les registries avec Skopeo
- Créer des pods multi-conteneurs
- Intégrer les conteneurs avec systemd
- Déployer en production sur RHEL/Rocky

## Public Cible

- Administrateurs systèmes RHEL/Rocky
- DevOps en environnement Red Hat
- Ingénieurs migrant de Docker vers Podman
- Équipes souhaitant des conteneurs rootless

## Prérequis

- Connaissances Linux de base (shell, permissions)
- Notions de conteneurisation (concepts)
- Accès à une VM RHEL 9 / Rocky Linux 9

## Programme (15 heures)

```
PODMAN MASTERY - PARCOURS
══════════════════════════════════════════════════════════

Module 1 : Fondamentaux & Architecture (2h)
├── Docker vs Podman : philosophie et différences
├── Architecture daemonless et fork/exec
├── Installation sur RHEL/Rocky/Fedora
├── Configuration registries (registries.conf)
└── Premiers conteneurs

Module 2 : Conteneurs Rootless (2h)
├── Pourquoi rootless ? (sécurité, compliance)
├── User namespaces et subuid/subgid
├── Configuration utilisateur
├── Limitations et solutions
└── Bonnes pratiques production

Module 3 : Buildah & Construction d'Images (3h)
├── Buildah vs Dockerfile
├── Construction script (buildah from/run/commit)
├── Multi-stage builds
├── Optimisation et layers
└── Images UBI (Universal Base Image)

Module 4 : Skopeo & Gestion des Registries (2h)
├── Inspection d'images distantes
├── Copie entre registries
├── Signature et vérification
├── Registries privés (Quay, Harbor)
└── Mirroring et air-gap

Module 5 : Pods & Multi-Conteneurs (2h)
├── Concept de Pod (comme Kubernetes)
├── Création et gestion de pods
├── Networking intra-pod
├── Génération de YAML Kubernetes
└── Play kube : déployer des manifests K8s

Module 6 : Intégration Systemd (2h)
├── Génération d'unités systemd
├── podman generate systemd
├── Quadlet : conteneurs déclaratifs
├── Auto-update et rollback
└── Journald et logging

Module 7 : TP Final - Stack Production (2h)
├── Application 3-tiers rootless
├── Reverse proxy + API + Database
├── Persistance et volumes
├── Systemd avec auto-restart
└── Monitoring et healthchecks

══════════════════════════════════════════════════════════
```

## Outils Utilisés

| Outil | Usage |
|-------|-------|
| **Podman** | Runtime de conteneurs |
| **Buildah** | Construction d'images |
| **Skopeo** | Gestion des registries |
| **Systemd** | Orchestration locale |
| **Quadlet** | Conteneurs déclaratifs |

## Environnement Recommandé

```bash
# RHEL 9 / Rocky Linux 9
sudo dnf install -y podman buildah skopeo

# Vérifier les versions
podman --version    # 4.x+
buildah --version   # 1.29+
skopeo --version    # 1.11+
```

## Certifications Associées

- **Red Hat EX188** : Red Hat Certified Specialist in Containers
- **CKA** : Certified Kubernetes Administrator (pods concept)

## Navigation

| Module | Titre | Durée |
|--------|-------|-------|
| [Module 1](01-module.md) | Fondamentaux & Architecture | 2h |
| [Module 2](02-module.md) | Conteneurs Rootless | 2h |
| [Module 3](03-module.md) | Buildah & Construction | 3h |
| [Module 4](04-module.md) | Skopeo & Registries | 2h |
| [Module 5](05-module.md) | Pods & Multi-Conteneurs | 2h |
| [Module 6](06-module.md) | Intégration Systemd | 2h |
| [Module 7](07-tp-final.md) | TP Final | 2h |

---

**Commencer :** [Module 1 - Fondamentaux](01-module.md)
