# The 6 Pillars of DevOps

`#devops` `#architecture` `#culture`

Don't get lost in the tools. There are only **6 problems to solve**.

---

## 1. Configuration Management

**Concept:** Ensure every server is configured identically, every time, without manual intervention. Infrastructure as Code.

!!! tip "The Restaurant Analogy: The Recipe"
    A chef doesn't improvise every dish. They follow a **standardized recipe** to ensure consistency.

    Config management is your recipe book—same ingredients, same steps, same result on every server.

**Problem Solved:** "Works on my machine" syndrome, configuration drift, manual setup errors.

**Leading Tools:**

| Tool | Type | Best For |
|------|------|----------|
| **Ansible** | Agentless, Push | Simple automation, multi-OS |
| **Terraform** | Declarative | Cloud infrastructure provisioning |
| **Puppet** | Agent-based, Pull | Large enterprise environments |
| **Chef** | Agent-based, Ruby DSL | Complex configurations |
| **SaltStack** | Hybrid | Event-driven automation |

---

## 2. Containers

**Concept:** Package applications with all dependencies into isolated, portable units that run identically everywhere.

!!! tip "The Restaurant Analogy: The Pre-packaged Meal"
    Instead of cooking from scratch, you receive a **pre-packaged meal** that just needs heating.

    Containers ship everything needed—no missing ingredients, no "but I don't have that spice" problems.

**Problem Solved:** Dependency hell, environment inconsistencies, "it works on my laptop."

**Leading Tools:**

| Tool | Purpose |
|------|---------|
| **Docker** | Container runtime (industry standard) |
| **Podman** | Rootless, daemonless alternative |
| **containerd** | Low-level runtime (used by K8s) |
| **Buildah** | Build OCI images without daemon |
| **Kaniko** | Build images in Kubernetes |

---

## 3. CI/CD (Continuous Integration / Continuous Delivery)

**Concept:** Automate the build, test, and deployment pipeline. Every code change triggers an automated workflow.

!!! tip "The Restaurant Analogy: The Kitchen Assembly Line"
    Orders come in, and the **assembly line** takes over—prep station, grill station, plating, delivery.

    CI/CD is your automated kitchen: code in, tested artifact out, deployed to production.

**Problem Solved:** Manual deployments, integration bugs discovered late, slow release cycles.

**Pipeline Stages:**

```
Code → Build → Test → Security Scan → Deploy → Monitor
        ↓       ↓          ↓            ↓
      Compile  Unit    SAST/DAST    Staging → Prod
               E2E     Container
```

**Leading Tools:**

| Tool | Type | Best For |
|------|------|----------|
| **GitLab CI** | Integrated | Full DevOps platform |
| **GitHub Actions** | Cloud-native | GitHub-centric workflows |
| **Jenkins** | Self-hosted | Flexibility, plugins |
| **ArgoCD** | GitOps | Kubernetes deployments |
| **Tekton** | Cloud-native | Kubernetes-native pipelines |

---

## 4. Orchestration

**Concept:** Manage the lifecycle of containers at scale—scheduling, scaling, networking, and self-healing.

!!! tip "The Restaurant Analogy: The Head Waiter"
    The **head waiter** decides which table gets which server, balances workloads, and reassigns staff when someone calls in sick.

    Orchestration places your containers, balances load, and replaces failed instances automatically.

**Problem Solved:** Manual container management, scaling decisions, service discovery, failover.

**Key Capabilities:**

- **Scheduling:** Place containers on appropriate nodes
- **Scaling:** Add/remove replicas based on load
- **Self-healing:** Restart failed containers
- **Service discovery:** Containers find each other
- **Rolling updates:** Zero-downtime deployments

**Leading Tools:**

| Tool | Complexity | Best For |
|------|------------|----------|
| **Kubernetes (K8s)** | High | Production, any scale |
| **Docker Swarm** | Low | Simple orchestration |
| **Nomad** | Medium | Multi-workload (containers + VMs) |
| **Amazon ECS** | Medium | AWS-native container management |
| **OpenShift** | High | Enterprise Kubernetes |

---

## 5. Cloud

**Concept:** On-demand infrastructure that scales elastically. Pay for what you use, provision in minutes instead of months.

!!! tip "The Restaurant Analogy: Freelance Staff"
    During rush hour, you call in **freelance staff**. When it's quiet, you send them home.

    Cloud provides elastic capacity—spin up 100 servers for Black Friday, scale down to 10 on Monday.

**Problem Solved:** Capacity planning, hardware procurement delays, underutilized servers.

**Service Models:**

| Model | You Manage | Provider Manages | Example |
|-------|------------|------------------|---------|
| **IaaS** | OS, Apps, Data | Hardware, Network | EC2, GCE |
| **PaaS** | Apps, Data | OS, Runtime | Heroku, App Engine |
| **SaaS** | Data only | Everything else | Gmail, Salesforce |
| **FaaS** | Code only | Everything else | Lambda, Cloud Functions |

**Leading Providers:**

| Provider | Strength |
|----------|----------|
| **AWS** | Breadth of services, market leader |
| **Azure** | Enterprise integration, hybrid cloud |
| **GCP** | Data/ML, Kubernetes-native |
| **OVH** | European sovereignty (SecNumCloud) |
| **Scaleway** | European, developer-friendly |

---

## 6. Observability

**Concept:** Understand what's happening inside your systems through metrics, logs, and traces. Debug production issues effectively.

!!! tip "The Restaurant Analogy: The Quality Inspector"
    The **quality inspector** checks every dish, monitors kitchen temperatures, and alerts when something's wrong.

    Observability gives you eyes into production—is the app healthy? Why is it slow? Where did that request fail?

**Problem Solved:** Blind deployments, slow incident response, "I don't know why it's down."

**The Three Pillars:**

| Pillar | What | Tool Examples |
|--------|------|---------------|
| **Metrics** | Numerical measurements over time | Prometheus, Datadog, Grafana |
| **Logs** | Event records with context | ELK Stack, Loki, Splunk |
| **Traces** | Request flow across services | Jaeger, Zipkin, Tempo |

**Leading Stacks:**

```
Prometheus + Grafana + Alertmanager    → Metrics & Alerting
ELK (Elasticsearch + Logstash + Kibana) → Log aggregation
Grafana Loki                           → Lightweight logs
Jaeger / Tempo                         → Distributed tracing
```

---

## Summary Table

| Pillar | Problem Solved | Analogy | Key Tool |
|--------|----------------|---------|----------|
| **Configuration Mgmt** | Consistency, drift | The Recipe | Ansible, Terraform |
| **Containers** | Dependency isolation | Pre-packaged Meal | Docker |
| **CI/CD** | Manual deployments | Assembly Line | GitLab CI, GitHub Actions |
| **Orchestration** | Container lifecycle | Head Waiter | Kubernetes |
| **Cloud** | Elasticity, scaling | Freelance Staff | AWS, Azure, GCP |
| **Observability** | Visibility, debugging | Quality Inspector | Prometheus, Grafana |

---

!!! example "The Full Picture"
    ```
    Code → CI/CD Pipeline → Container Image → Registry
                                    ↓
    Cloud Infrastructure ← Terraform/Ansible
                                    ↓
    Kubernetes Cluster → Deploys Containers
                                    ↓
    Prometheus/Grafana → Monitors Everything
    ```

!!! warning "Tools Change, Concepts Don't"
    Jenkins may be replaced by GitLab CI. Docker Swarm lost to Kubernetes.
    But the **6 pillars remain constant**. Master the concepts, adapt to the tools.
