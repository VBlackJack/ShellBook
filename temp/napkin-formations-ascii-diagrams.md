# Schémas ASCII à convertir en Napkin.ai - Formations

## Priorité Haute (Diagrammes architecturaux importants)

---

### 1. TechShop Observability Architecture
**Fichier:** `formations/observability/06-tp-final.md`
**Prompt Napkin.ai:**
```
Create an architecture diagram for TechShop e-commerce monitoring stack showing:

TOP LAYER - MONITORING:
- Prometheus (port 9090) for metrics collection
- Grafana (port 3000) for visualization
- Alertmanager (port 9093) for alerts

MIDDLE LAYER - APPLICATION:
- Nginx Frontend (port 80) with Nginx Exporter (port 9113)
- Flask API Backend (port 5000) with /metrics endpoint
- Node Exporter (port 9100) on each server

BOTTOM LAYER - DATA:
- PostgreSQL (port 5432) with Postgres Exporter (port 9187)
- Redis (port 6379) with Redis Exporter (port 9121)
- Blackbox Exporter (port 9115) for endpoint probing

Show scrape connections from Prometheus to all exporters.
Use monitoring/observability color scheme (orange/purple/blue).
Professional technical diagram style.
```
**Nom fichier:** `observability-techshop-architecture.jpeg`

---

### 2. Grafana Dashboard Layout
**Fichier:** `formations/observability/06-tp-final.md`
**Prompt Napkin.ai:**
```
Create a Grafana dashboard layout mockup for TechShop monitoring showing:

ROW 1 - Overview (4 stat panels):
- Uptime | Requests/s | Error Rate | P95 Latency

ROW 2 - Traffic:
- Full width time series graph "Requests per Second by endpoint"

ROW 3 - Performance (2 panels):
- Latency Distribution Heatmap | Error Rate by Endpoint Time Series

ROW 4 - Business Metrics (2 panels):
- Orders/min Time Series | Cart Value Histogram

ROW 5 - Infrastructure (4 gauges):
- CPU % | Memory % | Redis Ops | PostgreSQL Connections

Use Grafana dark theme colors.
Dashboard wireframe/mockup style.
```
**Nom fichier:** `grafana-dashboard-layout-techshop.jpeg`

---

### 3. Observability Stack Architecture (3 Pillars)
**Fichier:** `formations/observability/index.md`
**Prompt Napkin.ai:**
```
Create an observability stack architecture diagram showing the 3 pillars:

TOP LAYER - VISUALIZATION:
- Grafana (Dashboards | Alerts | Exploration)

MIDDLE LAYER - STORAGE (3 boxes):
- Prometheus (Metrics)
- Loki (Logs)
- Tempo (Traces)

BOTTOM LAYER - COLLECTION:
- Node Exporter | Promtail | OpenTelemetry

BASE LAYER - SOURCES:
- Servers | Containers | Applications

Show data flow arrows from bottom to top.
Use modern observability colors (orange for metrics, blue for logs, green for traces).
Clean architecture diagram style.
```
**Nom fichier:** `observability-stack-3-pillars.jpeg`

---

### 4. Windows Default Vulnerabilities
**Fichier:** `formations/windows-server/03-module.md`
**Prompt Napkin.ai:**
```
Create an infographic showing Windows Server default installation vulnerabilities:

Title: "Windows Server: Default Installation = Vulnerable"

List of security issues with red X marks:
- SMBv1 enabled (EternalBlue, WannaCry)
- LLMNR/NBT-NS enabled (Responder poisoning)
- Local admin: same password everywhere
- Audit logs disabled (forensic impossible)
- Permissive firewall (all apps allowed)
- BitLocker disabled (data in cleartext)
- Defender: outdated signatures
- PowerShell v2 installed (log bypass)

Bottom text: "Result: Compromised in minutes"

Use warning/danger color scheme (red, orange, dark).
Security compliance checklist style.
```
**Nom fichier:** `windows-default-vulnerabilities.jpeg`

---

### 5. Pass-the-Hash Attack (Without Tiering)
**Fichier:** `formations/windows-server/03-module.md`
**Prompt Napkin.ai:**
```
Create a cyberattack flow diagram showing Pass-the-Hash attack without Tiering Model:

STEP 1: Domain Admin logs into their PC (Tier 2) to read emails
STEP 2: Malware on PC captures NTLM hash from memory (mimikatz)
STEP 3: Attacker uses Pass-the-Hash to connect to Domain Controller (Tier 0)
STEP 4: Attacker now has total control of Active Directory

Timeline: 5 minutes from start to full compromise

Show escalation path with arrows.
Use red/dark cybersecurity attack visualization style.
Include attacker icon and compromised systems.
```
**Nom fichier:** `attack-pass-the-hash-no-tiering.jpeg`

---

### 6. Defense with Tiering Model
**Fichier:** `formations/windows-server/03-module.md`
**Prompt Napkin.ai:**
```
Create a defense diagram showing Tiering Model protection:

PROTECTED SCENARIO:
1. Domain Admin uses only PAW (Privileged Access Workstation) for Tier 0
2. PAW = Hardened machine, no internet, no email
3. Domain Admin uses SEPARATE ACCOUNT for emails on standard PC (Tier 2)
4. Malware compromises PC -> captures user account hash
5. Attacker CANNOT access Tier 0 (user account != Domain Admin account)

Result: Tier 0 Protected (green shield)

Show blocked attack path with X mark.
Use green/blue security defense color scheme.
Split view: Protected vs Compromised.
```
**Nom fichier:** `defense-tiering-model-protection.jpeg`

---

### 7. LAPS Problem and Solution
**Fichier:** `formations/windows-server/03-module.md`
**Prompt Napkin.ai:**
```
Create a before/after comparison diagram for LAPS:

LEFT SIDE - THE PROBLEM (red):
"Classic Installation (BAD PRACTICE)"
1. Windows installed with local Admin "Password123!"
2. Same password on ALL servers/workstations
3. Attacker compromises one workstation
4. Uses Pass-the-Hash to access ALL other machines
Result: Trivial lateral movement

RIGHT SIDE - THE SOLUTION: LAPS (green):
1. LAPS generates unique random password per PC
2. Password stored in AD (attribute)
3. Automatic rotation every 30 days
4. Only AD admins can read the password
Result: Each machine has unique password = Lateral movement blocked

Use split screen comparison style.
Red theme for problem, green theme for solution.
```
**Nom fichier:** `laps-problem-vs-solution.jpeg`

---

### 8. SMBv1 Security Risks
**Fichier:** `formations/windows-server/03-module.md`
**Prompt Napkin.ai:**
```
Create an infographic explaining why SMBv1 must be disabled:

Title: "Why Disable SMBv1?"

RISKS (red X marks):
- Critical vulnerabilities (EternalBlue/MS17-010)
- Exploited by WannaCry, NotPetya, Bad Rabbit
- No encryption
- No strong authentication
- Lower performance than SMBv2/v3

BENEFITS of SMBv2/v3 (green checkmarks):
- Secure and performant
- SMBv3 supports AES-CCM/AES-GCM encryption

Bottom banner: "SecNumCloud: SMBv1 MUST be disabled"

Use security compliance infographic style.
Red for risks, green for benefits.
```
**Nom fichier:** `smbv1-security-risks.jpeg`

---

### 9. Responder Attack Flow
**Fichier:** `formations/windows-server/03-module.md`
**Prompt Napkin.ai:**
```
Create a network attack diagram showing Responder poisoning:

ATTACK STEPS:
1. Victim searches for \\fileserver (typo or server down)
2. LLMNR/NBT-NS broadcast on network
3. Attacker responds "I am fileserver!"
4. Victim sends NTLMv2 hash to attacker
5. Attacker cracks hash offline (Hashcat)
6. Attacker recovers cleartext password

SOLUTION: Disable LLMNR/NBT-NS via GPO

Show network broadcast with attacker intercepting.
Use red/orange attack flow visualization.
Include victim workstation, attacker machine, and fake server.
```
**Nom fichier:** `attack-responder-llmnr-poisoning.jpeg`

---

## Priorité Moyenne

---

### 10. Windows Account Types Comparison
**Fichier:** `formations/windows-mastery/03-utilisateurs-ntfs.md`
**Prompt Napkin.ai:**
```
Create a comparison diagram for Windows account types:

LEFT SIDE - LOCAL ACCOUNTS:
- Stored in local SAM database
- Format: COMPUTERNAME\User
- Valid on 1 machine only
- Use cases: Standalone servers, Service accounts, Emergency access

RIGHT SIDE - DOMAIN ACCOUNTS:
- Stored in Active Directory
- Format: DOMAIN\User
- Valid across entire domain
- Use cases: Enterprise environment, Centralized auth, GPO policies

Use split screen comparison style.
Windows blue theme colors.
Clean corporate diagram style.
```
**Nom fichier:** `windows-account-types-local-vs-domain.jpeg`

---

### 11. Groups Best Practices
**Fichier:** `formations/windows-mastery/03-utilisateurs-ntfs.md`
**Prompt Napkin.ai:**
```
Create a best practices infographic for Windows groups management:

Title: "Best Practices - Groups"

Checklist with green checkmarks:
- Use groups to assign permissions (never directly to users)
- Create groups by role/function (Developers, DBAdmins, Helpdesk)
- Minimize members of Administrators group
- Document the reason for each group membership
- Regularly audit members of sensitive groups

Use compliance/best practices style.
Green checkmarks with clear icons.
Corporate security theme.
```
**Nom fichier:** `windows-groups-best-practices.jpeg`

---

### 12. NTFS Permissions Overview
**Fichier:** `formations/windows-mastery/03-utilisateurs-ntfs.md`
**Prompt Napkin.ai:**
```
Create a reference diagram for NTFS permissions:

LEFT COLUMN - BASIC PERMISSIONS:
- Full Control
- Modify
- Read & Execute
- List Folder Contents
- Read
- Write

RIGHT COLUMN - ADVANCED PERMISSIONS:
- Traverse Folder
- List Folder
- Read Attributes
- Read Extended Attributes
- Create Files
- Create Folders
- Write Attributes
- Write Extended Attributes
- Delete Subfolders and Files
- Delete
- Read Permissions
- Change Permissions
- Take Ownership

Show hierarchy/mapping between basic and advanced.
Use Windows file system theme.
Reference card/cheatsheet style.
```
**Nom fichier:** `ntfs-permissions-basic-vs-advanced.jpeg`

---

### 13. Chocolatey Package Flow
**Fichier:** `formations/chocolatey/03-module.md`
**Prompt Napkin.ai:**
```
Create a flow diagram for Chocolatey package deployment:

TOP: Chocolatey Repository (Community or Internal)

MIDDLE: Chocolatey Package Server
- Contains: Package metadata, install scripts, dependencies

BOTTOM: Target Machines (3 boxes)
- Workstation 1
- Workstation 2
- Server

Show flow arrows: Repository -> Server -> Machines
Include package icons and installation arrows.
Use Chocolatey brown/orange theme colors.
Clean deployment architecture style.
```
**Nom fichier:** `chocolatey-package-deployment-flow.jpeg`

---

### 14. Cloud IaaS/PaaS/SaaS Comparison
**Fichier:** `formations/cloud-fundamentals/fiches-memo.md`
**Prompt Napkin.ai:**
```
Create a comparison diagram showing cloud service models:

3 COLUMNS (IaaS | PaaS | SaaS):

Stack layers from bottom to top:
- Networking (managed by: provider for all)
- Storage (managed by: provider for all)
- Servers (managed by: provider for all)
- Virtualization (managed by: provider for all)
- OS (IaaS: customer | PaaS: provider | SaaS: provider)
- Middleware (IaaS: customer | PaaS: provider | SaaS: provider)
- Runtime (IaaS: customer | PaaS: provider | SaaS: provider)
- Data (IaaS: customer | PaaS: customer | SaaS: provider)
- Applications (IaaS: customer | PaaS: customer | SaaS: provider)

Color code: Customer managed (blue) vs Provider managed (green)
Examples: IaaS=EC2, PaaS=Heroku, SaaS=Gmail
```
**Nom fichier:** `cloud-iaas-paas-saas-comparison.jpeg`

---

### 15. Kubernetes TP Architecture
**Fichier:** `formations/kubernetes-mastery/12-tp-final.md`
**Prompt Napkin.ai:**
```
Create a Kubernetes deployment architecture for a microservices TP:

INGRESS LAYER:
- Nginx Ingress Controller with external IP

SERVICE LAYER (3 services):
- Frontend Service (ClusterIP)
- API Service (ClusterIP)
- Database Service (ClusterIP)

POD LAYER:
- Frontend Deployment (2 replicas)
- API Deployment (3 replicas)
- Database StatefulSet (1 replica with PVC)

STORAGE:
- PersistentVolumeClaim for database

Show connections between layers.
Use Kubernetes official colors (blue).
Clean microservices architecture style.
```
**Nom fichier:** `k8s-tp-microservices-architecture.jpeg`

---

## Priorité Basse (Schémas simples ou répétitifs)

---

## Instructions

1. Copier chaque prompt dans Napkin.ai
2. Générer l'image
3. Télécharger en JPEG
4. Renommer selon le nom de fichier indiqué
5. Placer dans `temp/` pour intégration

## Mapping fichiers cibles

| Image | Fichier cible | Section |
|-------|---------------|---------|
| observability-techshop-architecture.jpeg | observability/06-tp-final.md | Architecture |
| grafana-dashboard-layout-techshop.jpeg | observability/06-tp-final.md | Dashboard |
| observability-stack-3-pillars.jpeg | observability/index.md | Stack Technique |
| windows-default-vulnerabilities.jpeg | windows-server/03-module.md | Introduction |
| attack-pass-the-hash-no-tiering.jpeg | windows-server/03-module.md | Tiering Model |
| defense-tiering-model-protection.jpeg | windows-server/03-module.md | Tiering Model |
| laps-problem-vs-solution.jpeg | windows-server/03-module.md | LAPS |
| smbv1-security-risks.jpeg | windows-server/03-module.md | Hardening |
| attack-responder-llmnr-poisoning.jpeg | windows-server/03-module.md | LLMNR |
