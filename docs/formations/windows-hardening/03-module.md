---
tags:
  - formation
  - windows
  - securite
  - hardening
  - firewall
---

# Module 3 : Réseau & Firewall

## Objectifs du Module

- Configurer Windows Firewall avancé
- Créer des règles de sécurité personnalisées
- Implémenter IPsec pour le chiffrement réseau
- Segmenter et isoler les flux

**Durée :** 2 heures

---

## 1. Windows Firewall avec Sécurité Avancée

### 1.1 Profils de Firewall

```powershell
# Trois profils
# - Domain   : Connecté à un réseau avec DC accessible
# - Private  : Réseau de confiance (maison, bureau)
# - Public   : Réseau non fiable (hôtel, café)

# Vérifier l'état des profils
Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction

# Activer tous les profils
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

# Configurer les actions par défaut
Set-NetFirewallProfile -Profile Domain -DefaultInboundAction Block -DefaultOutboundAction Allow
Set-NetFirewallProfile -Profile Private -DefaultInboundAction Block -DefaultOutboundAction Allow
Set-NetFirewallProfile -Profile Public -DefaultInboundAction Block -DefaultOutboundAction Block
```

### 1.2 Journalisation

```powershell
# Activer la journalisation pour tous les profils
Set-NetFirewallProfile -Profile Domain,Private,Public `
    -LogBlocked True `
    -LogAllowed False `
    -LogFileName "%systemroot%\system32\LogFiles\Firewall\pfirewall.log" `
    -LogMaxSizeKilobytes 16384

# Vérifier la configuration
Get-NetFirewallProfile | Select-Object Name, LogBlocked, LogAllowed, LogFileName

# Lire les logs
Get-Content "$env:systemroot\system32\LogFiles\Firewall\pfirewall.log" -Tail 50
```

---

## 2. Gestion des Règles

### 2.1 Règles Entrantes (Inbound)

```powershell
# Lister les règles actives
Get-NetFirewallRule -Enabled True -Direction Inbound |
    Select-Object DisplayName, Profile, Action |
    Sort-Object DisplayName

# Créer une règle pour autoriser SSH (exemple)
New-NetFirewallRule -DisplayName "SSH Inbound" `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort 22 `
    -Action Allow `
    -Profile Domain `
    -RemoteAddress "192.168.1.0/24"

# Créer une règle pour RDP restreint
New-NetFirewallRule -DisplayName "RDP - Admin Only" `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort 3389 `
    -Action Allow `
    -Profile Domain,Private `
    -RemoteAddress "10.0.0.0/24","192.168.100.0/24"

# Créer une règle pour WinRM HTTPS
New-NetFirewallRule -DisplayName "WinRM HTTPS" `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort 5986 `
    -Action Allow `
    -Profile Domain `
    -RemoteAddress "10.0.0.0/8"
```

### 2.2 Règles Sortantes (Outbound)

```powershell
# Bloquer les connexions sortantes suspectes (profil Public)
New-NetFirewallRule -DisplayName "Block Outbound SMB" `
    -Direction Outbound `
    -Protocol TCP `
    -RemotePort 445 `
    -Action Block `
    -Profile Public

# Bloquer Telnet sortant
New-NetFirewallRule -DisplayName "Block Outbound Telnet" `
    -Direction Outbound `
    -Protocol TCP `
    -RemotePort 23 `
    -Action Block `
    -Profile Domain,Private,Public

# Autoriser uniquement certaines destinations
New-NetFirewallRule -DisplayName "Allow DNS to Internal" `
    -Direction Outbound `
    -Protocol UDP `
    -RemotePort 53 `
    -Action Allow `
    -RemoteAddress "10.0.0.10","10.0.0.11"
```

### 2.3 Règles par Application

```powershell
# Autoriser une application spécifique
New-NetFirewallRule -DisplayName "Allow SQL Server" `
    -Direction Inbound `
    -Program "C:\Program Files\Microsoft SQL Server\MSSQL15.MSSQLSERVER\MSSQL\Binn\sqlservr.exe" `
    -Action Allow `
    -Profile Domain

# Bloquer une application
New-NetFirewallRule -DisplayName "Block PowerShell Outbound" `
    -Direction Outbound `
    -Program "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" `
    -Action Block `
    -Profile Public
```

---

## 3. Règles de Sécurité Avancées

### 3.1 Règles Basées sur les Services

```powershell
# Règle pour un service Windows
New-NetFirewallRule -DisplayName "IIS HTTP" `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort 80,443 `
    -Action Allow `
    -Service "W3SVC" `
    -Profile Domain,Private

# Règle pour DNS Server
New-NetFirewallRule -DisplayName "DNS Server" `
    -Direction Inbound `
    -Protocol UDP `
    -LocalPort 53 `
    -Action Allow `
    -Service "DNS"
```

### 3.2 Règles avec Authentification

```powershell
# Règle nécessitant une authentification IPsec
New-NetFirewallRule -DisplayName "Secure Admin Access" `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort 5986 `
    -Action Allow `
    -Authentication Required `
    -Encryption Required `
    -Profile Domain
```

### 3.3 Groupes de Règles

```powershell
# Activer/Désactiver un groupe de règles
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
Disable-NetFirewallRule -DisplayGroup "File and Printer Sharing"

# Lister les groupes
Get-NetFirewallRule |
    Select-Object -ExpandProperty DisplayGroup -Unique |
    Sort-Object
```

---

## 4. IPsec

### 4.1 Règles de Sécurité de Connexion

```powershell
# Créer une règle IPsec pour le trafic serveur-serveur
New-NetIPsecRule -DisplayName "Server-to-Server Encryption" `
    -InboundSecurity Require `
    -OutboundSecurity Require `
    -Phase1AuthSet "ComputerKerberos" `
    -Phase2AuthSet "UserKerberos" `
    -RemoteAddress "10.0.1.0/24"

# Voir les règles IPsec existantes
Get-NetIPsecRule | Select-Object DisplayName, InboundSecurity, OutboundSecurity
```

### 4.2 Authentification IPsec

```powershell
# Créer un ensemble d'authentification Phase 1 (IKE)
$Phase1Auth = New-NetIPsecAuthProposal -Machine -Kerberos

# Créer un ensemble de phase 2
$Phase2Auth = New-NetIPsecAuthProposal -User -Kerberos

# Appliquer à une règle
New-NetIPsecRule -DisplayName "Authenticated Traffic" `
    -Phase1AuthSet $Phase1Auth `
    -Phase2AuthSet $Phase2Auth `
    -InboundSecurity Require `
    -OutboundSecurity Request `
    -RemoteAddress "10.0.0.0/8"
```

---

## 5. Stratégies de Segmentation

### 5.1 Isolation par Rôle

```powershell
# Serveur Web - N'accepte que HTTP/HTTPS
$WebServerRules = @(
    @{Name="HTTP"; Port=80; Protocol="TCP"},
    @{Name="HTTPS"; Port=443; Protocol="TCP"},
    @{Name="RDP-Admin"; Port=3389; Protocol="TCP"; Remote="10.0.100.0/24"}
)

foreach ($rule in $WebServerRules) {
    $params = @{
        DisplayName = "WebServer-$($rule.Name)"
        Direction = "Inbound"
        Protocol = $rule.Protocol
        LocalPort = $rule.Port
        Action = "Allow"
        Profile = "Domain"
    }
    if ($rule.Remote) {
        $params.RemoteAddress = $rule.Remote
    }
    New-NetFirewallRule @params
}

# Bloquer tout le reste
Set-NetFirewallProfile -Profile Domain -DefaultInboundAction Block
```

### 5.2 Isolation Serveur de Base de Données

```powershell
# SQL Server - Accès limité aux serveurs applicatifs
$AppServers = @("10.0.1.10", "10.0.1.11", "10.0.1.12")

New-NetFirewallRule -DisplayName "SQL Server - App Tier Only" `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort 1433 `
    -Action Allow `
    -RemoteAddress $AppServers `
    -Profile Domain

# Bloquer SQL depuis autres sources
New-NetFirewallRule -DisplayName "SQL Server - Block Others" `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort 1433 `
    -Action Block `
    -Profile Domain,Private,Public
```

### 5.3 Template de Hardening Complet

```powershell
# hardening-firewall.ps1
param(
    [ValidateSet("WebServer","DatabaseServer","DomainController","FileServer")]
    [string]$ServerRole
)

# Reset des règles (attention en production!)
# Get-NetFirewallRule | Remove-NetFirewallRule

# Règles de base pour tous les serveurs
$BaseRules = @(
    @{Name="ICMP-Ping"; Protocol="ICMPv4"; IcmpType=8; Action="Allow"; Profile="Domain"},
    @{Name="RDP-Admin"; Port=3389; Protocol="TCP"; Remote="10.0.100.0/24"; Action="Allow"},
    @{Name="WinRM-HTTPS"; Port=5986; Protocol="TCP"; Remote="10.0.100.0/24"; Action="Allow"}
)

# Règles spécifiques par rôle
$RoleRules = @{
    "WebServer" = @(
        @{Name="HTTP"; Port=80; Protocol="TCP"; Action="Allow"},
        @{Name="HTTPS"; Port=443; Protocol="TCP"; Action="Allow"}
    )
    "DatabaseServer" = @(
        @{Name="SQL"; Port=1433; Protocol="TCP"; Remote="10.0.1.0/24"; Action="Allow"}
    )
    "DomainController" = @(
        @{Name="LDAP"; Port=389; Protocol="TCP"; Action="Allow"},
        @{Name="LDAPS"; Port=636; Protocol="TCP"; Action="Allow"},
        @{Name="Kerberos"; Port=88; Protocol="TCP"; Action="Allow"},
        @{Name="DNS"; Port=53; Protocol="UDP"; Action="Allow"},
        @{Name="DNS-TCP"; Port=53; Protocol="TCP"; Action="Allow"}
    )
    "FileServer" = @(
        @{Name="SMB"; Port=445; Protocol="TCP"; Remote="10.0.0.0/8"; Action="Allow"}
    )
}

# Appliquer les règles
foreach ($rule in ($BaseRules + $RoleRules[$ServerRole])) {
    Write-Host "Creating rule: $($rule.Name)"
    # Création de la règle...
}
```

---

## 6. Monitoring et Troubleshooting

### 6.1 Diagnostic des Connexions

```powershell
# Connexions actives
Get-NetTCPConnection -State Established |
    Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess |
    Sort-Object RemoteAddress

# Ports en écoute
Get-NetTCPConnection -State Listen |
    Select-Object LocalAddress, LocalPort, OwningProcess

# Avec nom du processus
Get-NetTCPConnection -State Listen | ForEach-Object {
    $process = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    [PSCustomObject]@{
        LocalPort = $_.LocalPort
        Process = $process.ProcessName
        PID = $_.OwningProcess
    }
} | Sort-Object LocalPort
```

### 6.2 Test de Règles

```powershell
# Tester si un port est accessible
Test-NetConnection -ComputerName "server01" -Port 3389

# Vérifier quelle règle s'applique
Get-NetFirewallRule -Direction Inbound |
    Where-Object { $_.Enabled -eq 'True' } |
    Get-NetFirewallPortFilter |
    Where-Object { $_.LocalPort -eq 3389 }
```

---

## 7. Exercice : À Vous de Jouer

!!! example "Mise en Pratique : Configurer le Firewall d'un Serveur Web"
    **Objectif** : Configurer Windows Firewall pour un serveur web en production.

    **Contexte** : Votre serveur IIS doit être accessible publiquement en HTTP/HTTPS mais l'administration doit être restreinte.

    **Tâches à réaliser** :

    1. Activer le firewall sur tous les profils
    2. Configurer le blocage par défaut des connexions entrantes
    3. Créer des règles pour HTTP (80) et HTTPS (443) publics
    4. Restreindre RDP (3389) au réseau d'administration uniquement
    5. Activer le logging des connexions bloquées

    **Critères de validation** :

    - [ ] Firewall actif sur tous les profils
    - [ ] Inbound par défaut = Block
    - [ ] HTTP/HTTPS accessibles depuis Internet
    - [ ] RDP accessible uniquement depuis 10.0.100.0/24
    - [ ] Logs activés dans pfirewall.log

??? quote "Solution"
    ```powershell
    # 1. Activer le firewall
    Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True

    # 2. Bloquer par défaut
    Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block

    # 3. Règles spécifiques
    New-NetFirewallRule -DisplayName "Web-HTTP" -Direction Inbound -Protocol TCP -LocalPort 80 -Action Allow
    New-NetFirewallRule -DisplayName "Web-HTTPS" -Direction Inbound -Protocol TCP -LocalPort 443 -Action Allow
    New-NetFirewallRule -DisplayName "Admin-RDP" -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Allow -RemoteAddress "10.0.100.0/24"

    # 4. Logging
    Set-NetFirewallProfile -Profile Domain,Private,Public -LogBlocked True -LogFileName "%systemroot%\system32\LogFiles\Firewall\pfirewall.log"
    ```

    **Vérification** :
    ```powershell
    Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction
    Get-NetFirewallRule -DisplayName "Web-*" | Select-Object DisplayName, Enabled, Action
    ```

---

## Quiz

1. **Quel profil firewall est utilisé quand connecté à un domaine AD ?**
   - [ ] A. Public
   - [ ] B. Private
   - [ ] C. Domain

2. **Quelle action par défaut est recommandée pour les connexions entrantes ?**
   - [ ] A. Allow
   - [ ] B. Block
   - [ ] C. Log

**Réponses :** 1-C, 2-B

---

**Précédent :** [Module 2 - Services & Protocoles](02-module.md)

**Suivant :** [Module 4 - Active Directory](04-module.md)

---

## Navigation

| | |
|:---|---:|
| [← Module 2 : Services & Protocoles](02-module.md) | [Module 4 : Active Directory →](04-module.md) |

[Retour au Programme](index.md){ .md-button }
