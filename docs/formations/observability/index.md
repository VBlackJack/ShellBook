---
tags:
  - formation
  - observability
  - prometheus
  - grafana
  - monitoring
  - alerting
---

# Observabilité : Prometheus & Grafana

## Informations Générales

| Élément | Description |
|---------|-------------|
| **Durée totale** | 15 heures |
| **Niveau** | Intermédiaire |
| **Prérequis** | Linux, Docker, notions réseau |
| **Certification visée** | - |

---

## Objectifs de la Formation

À l'issue de cette formation, vous serez capable de :

- Concevoir une architecture d'observabilité complète
- Déployer et configurer Prometheus pour la collecte de métriques
- Créer des dashboards Grafana professionnels
- Mettre en place un système d'alerting efficace
- Monitorer des applications et infrastructures variées
- Intégrer les logs avec Loki

---

## Public Cible

- Administrateurs système et DevOps
- Ingénieurs SRE
- Développeurs souhaitant monitorer leurs applications
- Architectes cloud

---

## Programme

### Module 1 : Fondamentaux de l'Observabilité (2h)
- Les 3 piliers : Métriques, Logs, Traces
- Architecture d'une stack d'observabilité
- Prometheus vs autres solutions (Zabbix, Nagios, InfluxDB)
- PromQL : premiers pas

[Accéder au Module 1](01-module.md)

### Module 2 : Prometheus - Déploiement et Configuration (3h)
- Installation (Docker, binaire, Kubernetes)
- Configuration du scraping
- Service discovery
- Relabeling et filtrage
- Federation et haute disponibilité

[Accéder au Module 2](02-module.md)

### Module 3 : Exporters et Instrumentation (3h)
- Node Exporter pour les systèmes
- Blackbox Exporter pour les endpoints
- Custom exporters
- Instrumentation d'applications (Go, Python, Java)
- Pushgateway pour les jobs batch

[Accéder au Module 3](03-module.md)

### Module 4 : Grafana - Dashboards Avancés (3h)
- Installation et configuration
- Création de dashboards
- Variables et templates
- Panels avancés (heatmaps, logs, alertes)
- Provisioning as Code

[Accéder au Module 4](04-module.md)

### Module 5 : Alerting et Notifications (2h)
- Alertmanager : configuration
- Règles d'alerte Prometheus
- Routage et silencing
- Intégrations (Slack, PagerDuty, Email)
- Bonnes pratiques d'alerting

[Accéder au Module 5](05-module.md)

### Module 6 : TP Final - Stack Complète (2h)
- Déploiement d'une stack de monitoring complète
- Monitoring d'une application multi-tiers
- Création de SLOs et SLIs
- Incident response avec dashboards

[Accéder au TP Final](06-tp-final.md)

---

## Méthodologie

- **40%** Théorie et concepts
- **60%** Travaux pratiques

Chaque module inclut :
- Explications détaillées avec schémas
- Configurations commentées
- Exercices pratiques progressifs
- Quiz de validation

---

## Environnement Technique

![Observability Stack - 3 Pillars](../../assets/diagrams/observability-stack-3-pillars.jpeg)

```
STACK TECHNIQUE
═══════════════

┌─────────────────────────────────────────────────────┐
│                    VISUALISATION                     │
│                      Grafana                         │
│         Dashboards │ Alertes │ Exploration          │
└─────────────────────────────────────────────────────┘
                          │
        ┌─────────────────┼─────────────────┐
        ▼                 ▼                 ▼
┌───────────────┐ ┌───────────────┐ ┌───────────────┐
│  Prometheus   │ │     Loki      │ │    Tempo      │
│   Métriques   │ │     Logs      │ │    Traces     │
└───────────────┘ └───────────────┘ └───────────────┘
        ▲                 ▲                 ▲
        │                 │                 │
┌───────────────────────────────────────────────────┐
│                    COLLECTE                        │
│  Node Exporter │ Promtail │ OpenTelemetry         │
└───────────────────────────────────────────────────┘
        ▲                 ▲                 ▲
┌───────────────────────────────────────────────────┐
│              INFRASTRUCTURE / APPS                 │
│    Serveurs │ Containers │ Applications           │
└───────────────────────────────────────────────────┘
```

---

## Ressources Fournies

- Fichiers de configuration Prometheus/Grafana
- Dashboards JSON importables
- Docker Compose pour lab local
- Scripts d'automatisation
- Cheatsheet PromQL

---

## Évaluation

- Quiz à chaque fin de module
- TP Final noté
- Capacité à diagnostiquer des incidents

**Seuil de réussite :** 70%

---

**Commencer :** [Module 1 - Fondamentaux](01-module.md)
