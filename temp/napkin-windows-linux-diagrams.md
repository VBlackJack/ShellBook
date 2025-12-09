# Schémas ASCII à convertir - Windows & Linux

## WINDOWS (Priorité Haute)

---

### 1. AD Trusts - Direction Diagram
**Fichier:** `windows/ad-trusts.md`
**Prompt Napkin.ai:**
```
Create a diagram showing Active Directory trust directions:

SECTION 1 - ONE-WAY TRUST:
Domain A (Trusting) <---- Domain B (Trusted)
Arrow shows: "Access to resources"
Caption: "Users from B can access resources in A"
Caption: "Users from A CANNOT access resources in B"

SECTION 2 - TWO-WAY TRUST:
Domain A <----> Domain B
Double arrow shows: "Mutual access"
Caption: "Users from A can access resources in B"
Caption: "Users from B can access resources in A"
Note: "Two-way trust = 2 one-way trusts"

Use Active Directory blue/purple colors.
Clean technical diagram style.
```
**Nom fichier:** `ad-trust-directions.jpeg`

---

### 2. AD Trusts - Transitivity
**Fichier:** `windows/ad-trusts.md`
**Prompt Napkin.ai:**
```
Create a diagram showing AD trust transitivity:

TRANSITIVE TRUST:
A <--> B <--> C
With dashed line A....C
Caption: "If A trusts B and B trusts C, then A trusts C automatically"
Used in: Forest trusts, Parent-Child, Tree-Root

NON-TRANSITIVE TRUST:
A <--> B     C (separate, no connection)
Caption: "If A trusts B, A does NOT automatically trust C"
Caption: "A must create explicit trust with C"
Used in: External trusts, Realm trusts

Use AD trust diagram colors.
Side-by-side comparison style.
```
**Nom fichier:** `ad-trust-transitivity.jpeg`

---

### 3. AD Parent-Child Trust
**Fichier:** `windows/ad-trusts.md`
**Prompt Napkin.ai:**
```
Create a hierarchical diagram showing AD Parent-Child trusts:

TOP: corp.local (Forest Root)
|
├── paris.corp.local (Child domain)
├── lyon.corp.local (Child domain)
└── marseille.corp.local (Child domain)

Show bidirectional arrows between parent and each child.

Characteristics box:
- Created automatically when adding child domain
- Bidirectional and transitive
- Cannot be deleted
- Kerberos authentication

Use AD forest hierarchy style with blue/purple colors.
```
**Nom fichier:** `ad-trust-parent-child.jpeg`

---

### 4. AD Tree-Root Trust
**Fichier:** `windows/ad-trusts.md`
**Prompt Napkin.ai:**
```
Create a diagram showing AD Tree-Root trusts in a forest:

LEFT TREE:
corp.local (Tree 1 Root)
├── paris.corp.local
└── lyon.corp.local

RIGHT TREE:
partner.local (Tree 2 Root)
├── berlin.partner.local
└── munich.partner.local

Show Tree-Root Trust line connecting corp.local and partner.local
Label: "Tree-Root Trust (automatic in forest)"

Characteristics:
- Created automatically when adding new tree
- Bidirectional and transitive
- Links tree roots to Forest Root

Use AD multi-tree forest diagram style.
```
**Nom fichier:** `ad-trust-tree-root.jpeg`

---

### 5. NXLog Log Centralization Architecture
**Fichier:** `windows/nxlog.md`
**Prompt Napkin.ai:**
```
Create a log centralization architecture diagram for SecNumCloud:

TOP ROW (Sources):
- Windows Servers box (NXLog CE, port 514)
- Linux Servers box (rsyslog, port 514)

MIDDLE (Transport):
Arrows pointing down labeled "Syslog/TCP/TLS"

CENTER (Aggregation):
- Log Concentrator box (Syslog/Graylog/ELK/SIEM)

BOTTOM (Storage & Analysis):
- SIEM Storage box (Analysis, Alerting, Compliance, Audit)

SIDE BOX - SecNumCloud Requirements:
- Mandatory centralization of security logs
- Log integrity (TLS recommended)
- Minimum retention (6 months online, 1 year archive)
- Reliable timestamps (NTP synchronized)
- Traceability of privileged access

Use security/compliance color scheme (blue, green).
Enterprise architecture diagram style.
```
**Nom fichier:** `nxlog-secnumcloud-architecture.jpeg`

---

### 6. Windows Security Events Matrix
**Fichier:** `windows/nxlog.md`
**Prompt Napkin.ai:**
```
Create an infographic showing critical Windows Security Event IDs:

SECTION 1 - AUTHENTICATION & ACCESS:
4624 - Successful logon
4625 - Failed logon
4648 - Explicit credentials logon
4672 - Special privileges assigned (admin)
4768 - Kerberos TGT requested
4769 - Kerberos service ticket requested

SECTION 2 - ACCOUNT MANAGEMENT:
4720 - User account created
4722 - User account enabled
4724 - Password reset
4725 - User account disabled
4726 - User account deleted
4740 - Account locked out

SECTION 3 - GROUP CHANGES:
4728 - Member added to global group
4732 - Member added to local group
4756 - Member added to universal group

Use security event log color coding.
Reference card/cheatsheet style with icons.
```
**Nom fichier:** `windows-security-events-matrix.jpeg`

---

### 7. Server Core vs Desktop Experience
**Fichier:** `windows/server-administration.md`
**Prompt Napkin.ai:**
```
Create a comparison infographic for Server Core vs Desktop Experience:

LEFT - SERVER CORE (Green checkmarks):
✓ Reduced attack surface
✓ Fewer updates required
✓ Lower RAM consumption
✓ No accidental RDP use
✓ Forces automation

RIGHT - DESKTOP EXPERIENCE (Red X marks):
✗ More components = larger attack surface
✗ More monthly patches
✗ GUI = ~2GB additional RAM
✗ Tempting to use RDP
✗ Encourages "click-click" admin

COMPARISON TABLE:
| Aspect | Server Core | Desktop |
| Disk size | ~6 GB | ~10+ GB |
| RAM at boot | ~800 MB | ~2.5 GB |
| Monthly patches | ~30% fewer | More patches |

Use Windows Server blue theme.
Split comparison infographic style.
```
**Nom fichier:** `server-core-vs-desktop.jpeg`

---

### 8. sconfig Menu
**Fichier:** `windows/server-administration.md`
**Prompt Napkin.ai:**
```
Create a visual representation of Windows Server sconfig menu:

Title: "Server Configuration (sconfig)"

Menu options in a terminal-style box:
1) Domain/Workgroup
2) Computer Name
3) Add Local Administrator
4) Configure Remote Management
5) Windows Update Settings
6) Download and Install Updates
7) Remote Desktop
8) Network Settings
9) Date and Time
10) Telemetry settings
11) Windows Activation
12) Log Off User
13) Restart Server
14) Shut Down Server
15) Exit to Command Line

Note: "Available on Server Core 2019/2022/2025"

Use Windows terminal/console style (dark background).
CLI menu mockup style.
```
**Nom fichier:** `sconfig-menu.jpeg`

---

### 9. RDS Remote Desktop Architecture
**Fichier:** `windows/rds-remote-desktop.md`
**Prompt Napkin.ai:**
```
Create an RDS deployment architecture diagram:

EXTERNAL:
- Users/Clients connecting via HTTPS (443)

DMZ LAYER:
- RD Gateway (HTTPS termination)
- RD Web Access (Web portal)

INTERNAL LAYER:
- RD Connection Broker (Session management)
- RD Licensing Server

SESSION HOSTS:
- RD Session Host 1
- RD Session Host 2
- RD Session Host N

STORAGE:
- User Profile Disks (UPD)
- File Server

Show connection flow from users through gateway to session hosts.
Use Microsoft RDS official colors.
Enterprise architecture style.
```
**Nom fichier:** `rds-architecture.jpeg`

---

### 10. Windows Failover Cluster Architecture
**Fichier:** `windows/failover-cluster.md`
**Prompt Napkin.ai:**
```
Create a Windows Failover Cluster architecture diagram:

TOP: Cluster Virtual IP / Cluster Name Object (CNO)

NODES (2-3 boxes):
- Node 1 (Active)
- Node 2 (Passive/Standby)
- Node 3 (Optional)

SHARED STORAGE:
- SAN/iSCSI Storage
- Cluster Shared Volumes (CSV)

NETWORKS:
- Client Network (for user access)
- Cluster Network (heartbeat/private)
- Storage Network (iSCSI/FC)

WITNESS:
- File Share Witness or Cloud Witness (Azure)

Show heartbeat connections between nodes.
Use Windows Server cluster blue/green colors.
High availability architecture style.
```
**Nom fichier:** `failover-cluster-architecture.jpeg`

---

## LINUX (Priorité Haute)

---

### 11. KVM Virtualization Architecture
**Fichier:** `linux/virtualization-kvm.md`
**Prompt Napkin.ai:**
```
Create a KVM/QEMU virtualization stack diagram:

LAYERS (bottom to top):

1. HARDWARE LAYER:
- CPU (Intel VT-x / AMD-V)
- RAM
- Storage (NVMe/SSD)
- Network (NICs)

2. KERNEL LAYER:
- Linux Kernel with KVM module
- /dev/kvm device

3. EMULATION LAYER:
- QEMU (hardware emulation)

4. MANAGEMENT LAYER:
- libvirt daemon (libvirtd)
- virsh CLI
- virt-manager GUI
- Cockpit Web UI

5. VIRTUAL MACHINES:
- VM 1, VM 2, VM 3 (with vCPU, vRAM, vDisk icons)

Show data flow arrows between layers.
Use Linux/KVM red/black color scheme.
Virtualization stack diagram style.
```
**Nom fichier:** `kvm-virtualization-stack.jpeg`

---

### 12. Linux Web Server Architecture (Nginx/Apache)
**Fichier:** `linux/web-servers.md`
**Prompt Napkin.ai:**
```
Create a Linux web server architecture diagram:

INTERNET:
- Users/Browsers

REVERSE PROXY LAYER:
- Nginx (Load Balancer / SSL Termination)
- Port 80/443

APPLICATION LAYER:
- App Server 1 (PHP-FPM / Gunicorn / Node.js)
- App Server 2
- App Server 3

DATABASE LAYER:
- PostgreSQL / MySQL
- Redis Cache

STORAGE:
- NFS / GlusterFS for shared files

Show request flow from users through proxy to app servers.
Use Linux/Nginx green color scheme.
Web infrastructure diagram style.
```
**Nom fichier:** `linux-webserver-architecture.jpeg`

---

### 13. Linux Backup Architecture (rsync/Borg)
**Fichier:** `linux/backup-transfer.md`
**Prompt Napkin.ai:**
```
Create a Linux backup strategy diagram:

SOURCE SERVERS:
- Production Server 1
- Production Server 2
- Database Server

BACKUP METHODS:
- rsync (incremental file sync)
- Borg Backup (deduplicated, encrypted)
- pg_dump / mysqldump (database)

LOCAL BACKUP:
- NAS / Backup Server
- Daily incremental backups

OFFSITE BACKUP:
- Remote Datacenter or Cloud (S3/Glacier)
- Weekly full backups

RETENTION POLICY:
- 7 daily, 4 weekly, 12 monthly

Show backup flow with arrows and schedules.
Use backup/DR color scheme (blue/orange).
Disaster recovery diagram style.
```
**Nom fichier:** `linux-backup-architecture.jpeg`

---

### 14. WireGuard VPN Architecture
**Fichier:** `linux/vpn-wireguard.md`
**Prompt Napkin.ai:**
```
Create a WireGuard VPN architecture diagram:

SITE A (Headquarters):
- WireGuard Server (wg0 interface)
- Internal Network 10.0.1.0/24
- Public IP: A.A.A.A

SITE B (Branch Office):
- WireGuard Client/Peer
- Internal Network 10.0.2.0/24
- Public IP: B.B.B.B

REMOTE WORKERS:
- Laptop with WireGuard client
- Mobile device with WireGuard app

VPN TUNNEL:
- Encrypted tunnel (UDP 51820)
- WireGuard interface: 10.10.0.0/24

Show encrypted tunnel connections.
Use VPN/security green/blue colors.
Site-to-site VPN diagram style.
```
**Nom fichier:** `wireguard-vpn-architecture.jpeg`

---

### 15. LDAP/389DS Directory Architecture
**Fichier:** `linux/ldap-389ds.md`
**Prompt Napkin.ai:**
```
Create an LDAP directory service architecture:

LDAP SERVERS:
- Primary 389DS Server (Read/Write)
- Replica 389DS Server (Read-only)
- Replication arrows between them

CLIENTS:
- Linux Servers (SSSD/PAM)
- Applications (LDAP auth)
- Web Apps (LDAP bind)

DIRECTORY STRUCTURE (Tree):
dc=corp,dc=local
├── ou=People (users)
├── ou=Groups (groups)
├── ou=Services (service accounts)
└── ou=Hosts (computer objects)

Show LDAP queries (389/636) from clients to servers.
Use directory services blue/purple colors.
Enterprise directory architecture style.
```
**Nom fichier:** `ldap-389ds-architecture.jpeg`

---

## Instructions

1. Générer chaque image dans Napkin.ai avec le prompt fourni
2. Télécharger en JPEG
3. Nommer selon le nom de fichier indiqué
4. Placer dans `temp/`

## Résumé

| # | Nom | Catégorie |
|---|-----|-----------|
| 1-4 | AD Trusts diagrams | Windows/AD |
| 5-6 | NXLog/Security Events | Windows/Security |
| 7-8 | Server Admin | Windows/Core |
| 9 | RDS Architecture | Windows/Services |
| 10 | Failover Cluster | Windows/HA |
| 11 | KVM Stack | Linux/Virtualization |
| 12 | Web Server | Linux/Services |
| 13 | Backup | Linux/DR |
| 14 | WireGuard | Linux/VPN |
| 15 | LDAP/389DS | Linux/Directory |

**Total: 15 diagrammes** (10 Windows + 5 Linux)
