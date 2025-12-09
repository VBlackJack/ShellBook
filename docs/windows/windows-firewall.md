---
tags:
  - windows
  - firewall
  - security
  - networking
---

# Windows Firewall Avancé

Configuration avancée du pare-feu Windows via PowerShell et GPO.

## Concepts

```text
PROFILS DE FIREWALL
══════════════════════════════════════════════════════════

DOMAIN     Connecté à un réseau avec DC accessible
           (détecté via NLA - Network Location Awareness)

PRIVATE    Réseau de confiance (maison, bureau privé)
           Choisi manuellement par l'utilisateur

PUBLIC     Réseau non fiable (WiFi public, hôtel)
           Profil par défaut, le plus restrictif
```

---

## Gestion via PowerShell

### État du Firewall

```powershell
# Voir l'état de tous les profils
Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction

# Activer/Désactiver un profil
Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True

# Configurer l'action par défaut
Set-NetFirewallProfile -Profile Domain -DefaultInboundAction Block -DefaultOutboundAction Allow

# Activer le logging
Set-NetFirewallProfile -Profile Domain `
    -LogFileName "C:\Windows\System32\LogFiles\Firewall\pfirewall.log" `
    -LogMaxSizeKilobytes 16384 `
    -LogAllowed True `
    -LogBlocked True
```

### Règles Inbound

```powershell
# Lister les règles actives
Get-NetFirewallRule -Enabled True -Direction Inbound | Select-Object Name, DisplayName, Action

# Créer une règle (port)
New-NetFirewallRule -DisplayName "Allow HTTPS Inbound" `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort 443 `
    -Action Allow `
    -Profile Domain,Private

# Créer une règle (programme)
New-NetFirewallRule -DisplayName "Allow MyApp" `
    -Direction Inbound `
    -Program "C:\Apps\MyApp.exe" `
    -Action Allow `
    -Profile Domain

# Créer une règle (service)
New-NetFirewallRule -DisplayName "Allow SQL Server" `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort 1433 `
    -Service "MSSQLSERVER" `
    -Action Allow

# Créer une règle avec IP source
New-NetFirewallRule -DisplayName "Allow SSH from Admin" `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort 22 `
    -RemoteAddress 10.10.1.0/24,10.10.2.50 `
    -Action Allow
```

### Règles Outbound

```powershell
# Bloquer une application sortante
New-NetFirewallRule -DisplayName "Block Telemetry" `
    -Direction Outbound `
    -Program "C:\Windows\System32\CompatTelRunner.exe" `
    -Action Block

# Autoriser uniquement certains ports sortants
New-NetFirewallRule -DisplayName "Allow DNS Outbound" `
    -Direction Outbound `
    -Protocol UDP `
    -RemotePort 53 `
    -Action Allow

# Bloquer tout sauf whitelist
Set-NetFirewallProfile -Profile Public -DefaultOutboundAction Block
# Puis créer les règles Allow nécessaires
```

### Gestion des Règles

```powershell
# Activer/Désactiver une règle
Enable-NetFirewallRule -DisplayName "Allow HTTPS Inbound"
Disable-NetFirewallRule -DisplayName "Allow HTTPS Inbound"

# Modifier une règle
Set-NetFirewallRule -DisplayName "Allow HTTPS Inbound" -RemoteAddress 10.0.0.0/8

# Supprimer une règle
Remove-NetFirewallRule -DisplayName "Old Rule"

# Rechercher des règles
Get-NetFirewallRule -DisplayName "*SQL*"
Get-NetFirewallRule | Where-Object { $_.LocalPort -eq 443 }

# Exporter les règles
netsh advfirewall export "C:\firewall-backup.wfw"

# Importer les règles
netsh advfirewall import "C:\firewall-backup.wfw"
```

---

## Règles via GPO

### Emplacement

```text
Computer Configuration > Policies > Windows Settings >
Security Settings > Windows Defender Firewall with Advanced Security
```

### Import de Règles

```powershell
# Exporter pour GPO
Get-NetFirewallRule -DisplayName "Allow*" | Export-Clixml "C:\rules-export.xml"

# Créer les règles dans la GPO via GPMC
# Ou utiliser des scripts de démarrage PowerShell
```

### Règles Prédéfinies

```powershell
# Activer les règles prédéfinies (ex: Remote Desktop)
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

# Voir les groupes disponibles
Get-NetFirewallRule | Select-Object -ExpandProperty DisplayGroup -Unique | Sort-Object

# Groupes courants :
# - Remote Desktop
# - File and Printer Sharing
# - Windows Remote Management
# - Core Networking
# - Remote Event Log Management
```

---

## IPSec et Connection Security

```powershell
# Créer une règle de sécurité de connexion (IPSec)
New-NetIPsecRule -DisplayName "Require Auth to Servers" `
    -InboundSecurity Require `
    -OutboundSecurity Request `
    -LocalAddress 10.10.1.0/24 `
    -RemoteAddress 10.10.2.0/24

# Règle avec authentification Kerberos
New-NetIPsecRule -DisplayName "Kerberos Auth" `
    -InboundSecurity Require `
    -OutboundSecurity Require `
    -Phase1AuthSet (
        New-NetIPsecAuthProposal -Machine -Kerberos
    )

# Voir les associations de sécurité
Get-NetIPsecMainModeSA
Get-NetIPsecQuickModeSA
```

---

## Scénarios Courants

### Serveur Web

```powershell
# HTTP/HTTPS
New-NetFirewallRule -DisplayName "HTTP" -Direction Inbound -Protocol TCP -LocalPort 80 -Action Allow
New-NetFirewallRule -DisplayName "HTTPS" -Direction Inbound -Protocol TCP -LocalPort 443 -Action Allow
```

### SQL Server

```powershell
# SQL Server
New-NetFirewallRule -DisplayName "SQL Server" -Direction Inbound -Protocol TCP -LocalPort 1433 -Action Allow
New-NetFirewallRule -DisplayName "SQL Browser" -Direction Inbound -Protocol UDP -LocalPort 1434 -Action Allow
```

### Domain Controller

```powershell
# Ports DC essentiels
$dcPorts = @(
    @{Name="DNS-TCP"; Port=53; Protocol="TCP"},
    @{Name="DNS-UDP"; Port=53; Protocol="UDP"},
    @{Name="Kerberos-TCP"; Port=88; Protocol="TCP"},
    @{Name="Kerberos-UDP"; Port=88; Protocol="UDP"},
    @{Name="RPC"; Port=135; Protocol="TCP"},
    @{Name="LDAP"; Port=389; Protocol="TCP"},
    @{Name="LDAPS"; Port=636; Protocol="TCP"},
    @{Name="SMB"; Port=445; Protocol="TCP"},
    @{Name="GC"; Port=3268; Protocol="TCP"}
)

foreach ($port in $dcPorts) {
    New-NetFirewallRule -DisplayName "DC-$($port.Name)" `
        -Direction Inbound `
        -Protocol $port.Protocol `
        -LocalPort $port.Port `
        -Action Allow
}
```

---

## Monitoring et Logs

```powershell
# Voir les connexions bloquées
Get-Content "C:\Windows\System32\LogFiles\Firewall\pfirewall.log" | Select-Object -Last 100

# Parser les logs
$logs = Get-Content "C:\Windows\System32\LogFiles\Firewall\pfirewall.log" |
    Where-Object { $_ -notmatch "^#" } |
    ConvertFrom-Csv -Delimiter " " -Header @(
        "date","time","action","protocol","src-ip","dst-ip","src-port","dst-port","size","tcpflags","tcpsyn","tcpack","tcpwin","icmptype","icmpcode","info","path"
    )

$logs | Where-Object { $_.action -eq "DROP" } | Group-Object "src-ip" | Sort-Object Count -Descending

# Event Viewer
Get-WinEvent -LogName "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall" -MaxEvents 50
```

---

## Bonnes Pratiques

```yaml
Checklist Firewall:
  Configuration:
    - [ ] Activé sur tous les profils
    - [ ] Inbound = Block par défaut
    - [ ] Outbound = Allow (ou Block + whitelist)
    - [ ] Logging activé

  Règles:
    - [ ] Noms descriptifs
    - [ ] Scope IP restreint si possible
    - [ ] Profil approprié (Domain vs Public)
    - [ ] Documenter chaque règle

  GPO:
    - [ ] Règles centralisées via GPO
    - [ ] Merge (pas Replace) pour flexibilité
    - [ ] Tester avant déploiement
```

---

**Voir aussi :**

- [Windows Security](windows-security.md) - Sécurité Windows
- [Network Troubleshooting](network-troubleshooting.md) - Diagnostic réseau
- [GPO](ad-gpo.md) - Déploiement via GPO
