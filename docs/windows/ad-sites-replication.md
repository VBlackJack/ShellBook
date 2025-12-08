---
tags:
  - windows
  - active-directory
  - sites
  - replication
  - dfs-r
---

# Sites AD et Réplication

La topologie de sites AD optimise l'authentification et contrôle la réplication entre contrôleurs de domaine géographiquement distribués.

## Concepts Fondamentaux

### Qu'est-ce qu'un Site AD ?

Un site = un ensemble de sous-réseaux bien connectés (LAN)

![AD Sites Topology](../assets/diagrams/windows-ad-sites-topology.jpeg)

### Avantages des Sites

| Fonction | Bénéfice |
|----------|----------|
| **Authentification** | Clients contactent le DC du site local |
| **Réplication** | Contrôle de la bande passante WAN |
| **DFS** | Referrals vers serveurs locaux |
| **Services** | Exchange, SCCM utilisent les sites |

---

## Configuration des Sites

### Créer un Site

```powershell
# Créer un nouveau site
New-ADReplicationSite -Name "Lyon" -Description "Site de Lyon"

# Lister les sites
Get-ADReplicationSite -Filter * | Select-Object Name, Description

# Renommer un site
Rename-ADObject -Identity "CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=corp,DC=local" -NewName "Paris"
```

### Gérer les Sous-réseaux

```powershell
# Créer un sous-réseau et l'associer à un site
New-ADReplicationSubnet -Name "10.10.0.0/16" -Site "Paris" -Description "LAN Paris"
New-ADReplicationSubnet -Name "10.20.0.0/16" -Site "Lyon" -Description "LAN Lyon"
New-ADReplicationSubnet -Name "10.30.0.0/16" -Site "Marseille" -Description "LAN Marseille"

# Lister les sous-réseaux
Get-ADReplicationSubnet -Filter * | Select-Object Name, Site

# Modifier l'association d'un sous-réseau
Set-ADReplicationSubnet -Identity "10.10.0.0/16" -Site "Paris-New"

# Supprimer un sous-réseau
Remove-ADReplicationSubnet -Identity "10.99.0.0/24"
```

### Vérifier l'Association Client-Site

```powershell
# Sur un client, voir le site assigné
nltest /dsgetsite

# Forcer la découverte du site
nltest /dsgetdc:corp.local /force

# Voir le DC utilisé
echo %LOGONSERVER%
```

---

## Site Links (Liens de Sites)

### Concept

Un Site Link connecte 2+ sites pour la réplication.

![AD Site Link](../assets/diagrams/windows-ad-site-link.jpeg)

### Configurer les Site Links

```powershell
# Créer un site link
New-ADReplicationSiteLink -Name "PARIS-LYON" `
    -SitesIncluded "Paris","Lyon" `
    -Cost 100 `
    -ReplicationFrequencyInMinutes 60 `
    -InterSiteTransportProtocol IP

# Modifier le coût (priorité)
Set-ADReplicationSiteLink -Identity "PARIS-LYON" -Cost 50

# Modifier l'intervalle de réplication
Set-ADReplicationSiteLink -Identity "PARIS-LYON" -ReplicationFrequencyInMinutes 30

# Lister les site links
Get-ADReplicationSiteLink -Filter * |
    Select-Object Name, Cost, ReplicationFrequencyInMinutes, SitesIncluded

# Ajouter un site à un link existant
Set-ADReplicationSiteLink -Identity "PARIS-LYON" -SitesIncluded @{Add="Marseille"}
```

### Schedule de Réplication

```powershell
# Configurer le schedule (heures de réplication)
# Par défaut : 24/7

# Via ADSI (pas de cmdlet native simple)
$siteLink = [ADSI]"LDAP://CN=PARIS-LYON,CN=IP,CN=Inter-Site Transports,CN=Sites,CN=Configuration,DC=corp,DC=local"

# Le schedule est un tableau de 168 bytes (24h x 7 jours)
# Chaque byte = 1 heure, valeur 0 = pas de réplication
```

---

## Site Link Bridges

Permettent la transitivité entre site links.

![AD Site Link Bridge](../assets/diagrams/windows-ad-site-link-bridge.jpeg)

```powershell
# Créer un bridge explicite (si Bridge All désactivé)
New-ADReplicationSiteLinkBridge -Name "France-Bridge" `
    -SiteLinksIncluded "PARIS-LYON","LYON-MARSEILLE"

# Vérifier le paramètre Bridge All Site Links
Get-ADReplicationSiteLink -Filter * | Select-Object Options
# Options inclut 0x1 si bridging désactivé

# Désactiver Bridge All (non recommandé sauf topologie spécifique)
# Via Active Directory Sites and Services GUI
```

---

## Réplication AD

### Types de Réplication

```
RÉPLICATION INTRA-SITE VS INTER-SITE
══════════════════════════════════════════════════════════

INTRA-SITE (même site)
──────────────────────
• Déclenchée immédiatement (notification)
• Non compressée
• Toutes les 15 secondes après un changement
• Utilise RPC over IP

INTER-SITE (entre sites)
────────────────────────
• Planifiée (selon schedule)
• Compressée (≈85% réduction)
• Intervalle minimum 15 minutes
• Utilise RPC over IP ou SMTP (rare)
```

### KCC (Knowledge Consistency Checker)

```powershell
# Le KCC génère automatiquement la topologie de réplication
# Il s'exécute toutes les 15 minutes

# Forcer le KCC à recalculer
repadmin /kcc

# Voir la topologie générée
repadmin /showrepl

# Voir les connexions de réplication
Get-ADReplicationConnection -Filter * |
    Select-Object Name, ReplicateFromDirectoryServer, ReplicateToDirectoryServer
```

### Vérifier la Réplication

```powershell
# État de la réplication
repadmin /replsummary

# Réplication détaillée d'un DC
repadmin /showrepl DC01.corp.local

# Voir les partenaires de réplication
repadmin /showrepl DC01.corp.local /csv | ConvertFrom-Csv

# Vérifier la convergence
repadmin /syncall DC01.corp.local /A /e /P

# Tester la réplication d'une partition
repadmin /replicate DC02.corp.local DC01.corp.local "DC=corp,DC=local"
```

### Forcer la Réplication

```powershell
# Forcer la réplication immédiate (inter-site)
repadmin /syncall /A /e /P

# Options :
# /A = Toutes les partitions
# /e = Enterprise (tous les sites)
# /P = Push (pousser vers les partenaires)
# /d = Identifier les serveurs par DN

# Forcer entre deux DCs spécifiques
repadmin /replicate DC02 DC01 "DC=corp,DC=local"

# Via PowerShell
Sync-ADObject -Object "CN=User1,OU=Users,DC=corp,DC=local" -Source DC01 -Destination DC02
```

---

## SYSVOL et DFS-R

### Structure SYSVOL

```
SYSVOL
══════════════════════════════════════════════════════════

C:\Windows\SYSVOL\
├── domain\
│   ├── Policies\          ← GPO (GUID folders)
│   │   ├── {31B2F340-...}
│   │   └── {6AC1786C-...}
│   ├── scripts\           ← Logon scripts
│   └── StarterGPOs\
└── sysvol\
    └── corp.local\        ← Partagé en \\corp.local\SYSVOL

Réplication :
• DFS-R (depuis 2008 R2+)
• FRS (legacy, obsolète)
```

### Vérifier DFS-R

```powershell
# État DFS-R
Get-DfsrMember -GroupName "Domain System Volume"

# Backlog de réplication (fichiers en attente)
Get-DfsrBacklog -GroupName "Domain System Volume" `
    -SourceComputerName DC01 `
    -DestinationComputerName DC02 -Verbose

# État de la réplication
dfsrdiag ReplicationState

# Forcer la réplication
Sync-DfsReplicationGroup -GroupName "Domain System Volume" -SourceComputerName DC01

# Rapport DFS-R
dfsrdiag backlog /rgname:"Domain System Volume" /rfname:"SYSVOL Share" /smem:DC01 /rmem:DC02
```

### Troubleshooting SYSVOL

```powershell
# Vérifier la santé SYSVOL
dcdiag /test:sysvolcheck /test:advertising

# Comparer le contenu entre DCs
$dc1 = Get-ChildItem "\\DC01\SYSVOL\corp.local\Policies" -Recurse
$dc2 = Get-ChildItem "\\DC02\SYSVOL\corp.local\Policies" -Recurse
Compare-Object $dc1 $dc2 -Property Name, Length

# Event logs DFS-R
Get-WinEvent -LogName "DFS Replication" -MaxEvents 50 |
    Where-Object { $_.Level -in 2,3 }  # Error, Warning
```

---

## Bridgehead Servers

```
BRIDGEHEAD SERVERS
══════════════════════════════════════════════════════════

DC désigné pour la réplication inter-site.

     SITE PARIS                    SITE LYON
    ┌──────────────┐              ┌──────────────┐
    │   DC-01      │              │   DC-03      │
    │(Bridgehead)◄─┼──── WAN ────►│(Bridgehead)  │
    │              │              │              │
    │   DC-02      │              │   DC-04      │
    │              │              │              │
    └──────────────┘              └──────────────┘

Avantages :
• Contrôle du DC qui réplique sur le WAN
• Optimisation bande passante
• Failover automatique
```

```powershell
# Désigner un Bridgehead préféré
Set-ADObject -Identity "CN=DC01,OU=Domain Controllers,DC=corp,DC=local" `
    -Add @{bridgeheadTransportList="CN=IP,CN=Inter-Site Transports,CN=Sites,CN=Configuration,DC=corp,DC=local"}

# Voir les bridgeheads actuels
Get-ADDomainController -Filter * |
    Select-Object Name, Site, @{N='IsBridgehead';E={
        (Get-ADObject $_.ComputerObjectDN -Properties bridgeheadTransportList).bridgeheadTransportList -ne $null
    }}

# Laisser le KCC choisir (supprimer la désignation)
Set-ADObject -Identity "CN=DC01,OU=Domain Controllers,DC=corp,DC=local" `
    -Clear bridgeheadTransportList
```

---

## Diagnostic et Troubleshooting

### Outils de Diagnostic

```powershell
# DCDiag - Tests complets
dcdiag /v /c /e

# Tests spécifiques
dcdiag /test:replications
dcdiag /test:connectivity
dcdiag /test:services
dcdiag /test:topology

# Repadmin - État de la réplication
repadmin /replsummary
repadmin /showrepl * /csv | ConvertFrom-Csv | Where-Object { $_.'Number of Failures' -gt 0 }

# Vérifier les erreurs de réplication
repadmin /showrepl * /errorsonly
```

### Problèmes Courants

```
TROUBLESHOOTING RÉPLICATION
══════════════════════════════════════════════════════════

Erreur : "Access Denied" (8453)
───────────────────────────────
Cause : Permissions incorrectes
Solution :
  repadmin /syncall /A /P /e
  Vérifier les groupes Enterprise Admins

Erreur : "Target principal name is incorrect" (8524)
────────────────────────────────────────────────────
Cause : SPN Kerberos incorrect
Solution :
  setspn -L DC01
  Réinitialiser le compte machine si nécessaire

Erreur : "RPC server unavailable" (1722)
────────────────────────────────────────
Cause : Connectivité réseau/firewall
Solution :
  Test-NetConnection DC02 -Port 135
  Test-NetConnection DC02 -Port 389
  Vérifier DNS

Erreur : "Replication link failure" (8606)
──────────────────────────────────────────
Cause : Attributs en conflit
Solution :
  repadmin /removelingeringobjects DC01 DC02 DC=corp,DC=local
```

### Event IDs Importants

| Event ID | Source | Signification |
|----------|--------|---------------|
| 1864 | NTDS Replication | Réplication échouée depuis > 1 jour |
| 1865 | NTDS Replication | Réplication réussie après échec |
| 2042 | NTDS Replication | Tombstone lifetime dépassé |
| 4012 | DFS-R | Réplication SYSVOL arrêtée |
| 4112 | DFS-R | Réplication SYSVOL reprise |

---

## Bonnes Pratiques

### Design des Sites

```yaml
Checklist Sites AD:
  Planning:
    - [ ] Un site par location géographique
    - [ ] Sous-réseaux correctement associés
    - [ ] Au moins 2 DCs par site principal

  Site Links:
    - [ ] Cost reflète la qualité du lien
    - [ ] Interval adapté à la bande passante
    - [ ] Schedule si WAN limité

  Maintenance:
    - [ ] Monitorer la réplication
    - [ ] Vérifier les erreurs régulièrement
    - [ ] Documenter la topologie
```

### Monitoring

```powershell
# Script de monitoring réplication
$results = @()
$dcs = Get-ADDomainController -Filter *

foreach ($dc in $dcs) {
    $repl = repadmin /showrepl $dc.HostName /csv | ConvertFrom-Csv

    foreach ($r in $repl) {
        $results += [PSCustomObject]@{
            DC = $dc.HostName
            Partner = $r.'Source DSA'
            Partition = $r.'Naming Context'
            LastSuccess = $r.'Last Success Time'
            Failures = $r.'Number of Failures'
            LastError = $r.'Last Failure Status'
        }
    }
}

# Afficher les problèmes
$results | Where-Object { $_.Failures -gt 0 } | Format-Table
```

---

## Références

- [Microsoft Docs - AD Sites](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/designing-the-site-topology)
- [Microsoft Docs - Replication](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/replication/active-directory-replication-concepts)
- [DFS-R Troubleshooting](https://docs.microsoft.com/en-us/windows-server/storage/dfs-replication/dfsr-overview)

---

**Voir aussi :**

- [Active Directory](active-directory.md) - Fondamentaux AD
- [AD Trusts](ad-trusts.md) - Relations d'approbation
- [DNS Server](dns-server.md) - Configuration DNS
