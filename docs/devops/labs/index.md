---
tags:
  - labs
  - pratique
  - hands-on
  - devops
---

# Ateliers Pratiques (Labs)

Bienvenue dans la section **Labs** de ShellBook. Ces ateliers pratiques vous permettent de mettre en œuvre les concepts appris dans les formations dans des scénarios réalistes.

## Philosophie des Labs

- **Production-Ready** : Configurations issues du terrain
- **Progressif** : Plusieurs niveaux de complexité
- **Autonome** : Chaque lab est indépendant
- **Docker-First** : La plupart utilisent Docker/Podman

---

## Labs Disponibles

<div class="grid cards" markdown>

-   :material-email:{ .lg .middle } **Docker Mail Server**

    ---

    Déployez une infrastructure mail complète en 3 niveaux de complexité : relais SMTP simple, séparation SMTP/IMAP, puis architecture ISP complète.

    **Technologies** : Postfix, Dovecot, Docker Compose
    **Durée** : 2-4 heures
    **Niveau** : Intermédiaire

    [:octicons-arrow-right-24: Commencer](docker-mail-server.md)

</div>

---

## Labs à Venir

| Lab | Description | Statut |
|-----|-------------|--------|
| **Kubernetes HA Cluster** | Déployer un cluster K8s multi-master avec kubeadm | 🚧 En cours |
| **GitOps avec ArgoCD** | Pipeline GitOps complet de A à Z | 📝 Planifié |
| **Observability Stack** | Prometheus + Grafana + Loki + Tempo | 📝 Planifié |
| **Terraform Multi-Cloud** | Infrastructure AWS + Azure avec Terraform | 📝 Planifié |
| **Disaster Recovery Drill** | Test de restauration complète | 📝 Planifié |

---

## Prérequis Généraux

Avant de commencer un lab, assurez-vous d'avoir :

- **Docker** ou **Podman** installé
- **4-8 Go de RAM** disponibles
- **20 Go d'espace disque** libre
- Accès à Internet (pour télécharger les images)

!!! tip "Environnement Recommandé"
    Utilisez une VM dédiée ou WSL2 pour isoler vos expérimentations.

---

## Contribution

Vous avez une idée de lab ? Proposez-la via une [Pull Request](https://github.com/VBlackJack/ShellBook) !

Structure attendue :
```
docs/devops/labs/
├── index.md                    # Cette page
├── mon-lab/
│   ├── index.md               # Description et objectifs
│   ├── files/                 # Fichiers de configuration
│   │   ├── docker-compose.yml
│   │   └── config/
│   └── solution.md            # Solution détaillée (optionnel)
└── autre-lab.md               # Lab simple (fichier unique)
```
