---
tags:
  - formation
  - docker
  - containers
  - devops
---

# Docker Mastery

![Docker Multi-Stage Build](../../assets/infographics/devops/docker-multistage-build.jpeg)

![Containers vs VMs](../../assets/infographics/devops/container-vs-vm.jpeg)

## Informations Générales

| Élément | Description |
|---------|-------------|
| **Durée totale** | 15 heures |
| **Niveau** | Débutant à Intermédiaire |
| **Prérequis** | Linux basics, ligne de commande |
| **Certification visée** | DCA (Docker Certified Associate) |

---

## Objectifs de la Formation

À l'issue de cette formation, vous serez capable de :

- Comprendre la conteneurisation et ses avantages
- Créer et gérer des images Docker optimisées
- Orchestrer des applications multi-containers avec Compose
- Configurer le networking et le stockage Docker
- Implémenter les bonnes pratiques de sécurité
- Déployer en production

---

## Programme

### Module 1 : Fondamentaux Docker (2h)
- Containers vs VMs
- Architecture Docker
- Installation et configuration
- Commandes de base

[Accéder au Module 1](01-module.md)

### Module 2 : Images et Dockerfile (3h)
- Anatomie d'une image
- Dockerfile best practices
- Multi-stage builds
- Optimisation des layers

[Accéder au Module 2](02-module.md)

### Module 3 : Docker Compose (3h)
- Syntaxe YAML
- Services, networks, volumes
- Variables d'environnement
- Profiles et extends

[Accéder au Module 3](03-module.md)

### Module 4 : Networking (2h)
- Bridge, host, overlay
- Ports et exposition
- DNS interne
- Load balancing

[Accéder au Module 4](04-module.md)

### Module 5 : Volumes et Persistance (2h)
- Types de volumes
- Bind mounts
- Volume drivers
- Backup et migration

[Accéder au Module 5](05-module.md)

### Module 6 : Sécurité (2h)
- User namespaces
- Capabilities
- Secrets management
- Scanning d'images

[Accéder au Module 6](06-module.md)

### Module 7 : TP Final (1h)
- Application complète
- CI/CD ready
- Production deployment

[Accéder au TP Final](07-tp-final.md)

---

## Méthodologie

- **30%** Théorie
- **70%** Pratique

---

## Environnement

```text
DOCKER ARCHITECTURE
═══════════════════

┌─────────────────────────────────────────────────────────┐
│                     Docker Host                          │
│                                                          │
│  ┌──────────────┐                                       │
│  │ Docker       │                                       │
│  │ Daemon       │◄─── docker CLI / API                  │
│  │ (dockerd)    │                                       │
│  └──────┬───────┘                                       │
│         │                                               │
│    ┌────┴────┐                                          │
│    │containerd│                                          │
│    └────┬────┘                                          │
│         │                                               │
│  ┌──────┴──────────────────────────────────────┐       │
│  │                                              │       │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────┐     │       │
│  │  │Container│  │Container│  │Container│     │       │
│  │  │   A     │  │   B     │  │   C     │     │       │
│  │  └─────────┘  └─────────┘  └─────────┘     │       │
│  │                                              │       │
│  └──────────────────────────────────────────────┘       │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

---

**Commencer :** [Module 1 - Fondamentaux](01-module.md)
