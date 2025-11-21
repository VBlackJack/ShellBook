# PowerShell for Linux Admins

`#powershell` `#scripting` `#objects` `#pipeline`

Transition Bash → PowerShell : penser en objets, pas en texte.

---

## Le Choc Culturel : Objets vs Texte

### La Différence Fondamentale

```
┌─────────────────────────────────────────────────────────────┐
│                         BASH                                 │
│  Commande → Stream de TEXTE → Commande → Stream de TEXTE    │
│                                                              │
│  ls -l | grep "Dec" | awk '{print $9}'                      │
│         ↓           ↓                                       │
│      Texte       Parse du texte                             │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                      POWERSHELL                              │
│  Cmdlet → Stream d'OBJETS → Cmdlet → Stream d'OBJETS        │
│                                                              │
│  Get-ChildItem | Where-Object { $_.LastWriteTime.Month -eq 12 }
│                ↓                    ↓                       │
│            Objets .NET        Propriétés typées             │
└─────────────────────────────────────────────────────────────┘
```

### Exemple Frappant

**Objectif :** Lister les fichiers modifiés en décembre

=== "Bash"
    ```bash
    # Parse du texte (fragile si format change)
    ls -l | grep "Dec"

    # Plus robuste mais verbeux
    find . -type f -newermt "2024-12-01" ! -newermt "2025-01-01"
    ```

=== "PowerShell"
    ```powershell
    # Manipulation directe de propriétés (toujours fiable)
    Get-ChildItem | Where-Object { $_.LastWriteTime.Month -eq 12 }

    # Avec raccourcis
    gci | ? { $_.LastWriteTime.Month -eq 12 }
    ```

### Pourquoi C'est Puissant

```powershell
# L'objet FileInfo a des propriétés typées
$file = Get-Item "document.txt"

$file.Name              # String: "document.txt"
$file.Length            # Int64: 1024
$file.LastWriteTime     # DateTime: 2024-01-15 10:30:00
$file.Extension         # String: ".txt"
$file.Directory         # DirectoryInfo: C:\Users\...

# On peut appeler des méthodes
$file.CopyTo("backup.txt")
$file.Delete()
```

---

## La Grammaire (Verb-Noun)

### Structure Standardisée

Toutes les cmdlets suivent le pattern **Verbe-Nom** :

| Verbe | Action | Exemples |
|-------|--------|----------|
| `Get-` | Récupérer | `Get-Process`, `Get-Service`, `Get-Content` |
| `Set-` | Modifier | `Set-Location`, `Set-Content`, `Set-Variable` |
| `New-` | Créer | `New-Item`, `New-Object`, `New-Service` |
| `Remove-` | Supprimer | `Remove-Item`, `Remove-Service` |
| `Start-` | Démarrer | `Start-Process`, `Start-Service` |
| `Stop-` | Arrêter | `Stop-Process`, `Stop-Service` |
| `Restart-` | Redémarrer | `Restart-Service`, `Restart-Computer` |
| `Test-` | Tester | `Test-Path`, `Test-NetConnection` |
| `Invoke-` | Exécuter | `Invoke-Command`, `Invoke-WebRequest` |

```powershell
# Lister tous les verbes approuvés
Get-Verb

# Trouver les cmdlets pour les services
Get-Command -Noun Service
# Get-Service, Set-Service, Start-Service, Stop-Service, Restart-Service...

# Trouver les cmdlets "Get-*"
Get-Command -Verb Get
```

### Les Alias : Le Piège !

!!! danger "Attention : Ces commandes ne sont PAS les binaires Linux"
    PowerShell définit des alias qui ressemblent aux commandes Unix mais ont un comportement différent.

| Alias PS | Cmdlet réelle | Binaire Linux |
|----------|---------------|---------------|
| `ls` | `Get-ChildItem` | `/bin/ls` |
| `dir` | `Get-ChildItem` | - |
| `cat` | `Get-Content` | `/bin/cat` |
| `cp` | `Copy-Item` | `/bin/cp` |
| `mv` | `Move-Item` | `/bin/mv` |
| `rm` | `Remove-Item` | `/bin/rm` |
| `pwd` | `Get-Location` | `/bin/pwd` |
| `cd` | `Set-Location` | builtin |
| `curl` | `Invoke-WebRequest` | `/usr/bin/curl` |
| `wget` | `Invoke-WebRequest` | `/usr/bin/wget` |

```powershell
# Voir la vraie commande derrière un alias
Get-Alias ls
# Alias: ls -> Get-ChildItem

Get-Alias curl
# Alias: curl -> Invoke-WebRequest

# Piège : les options Linux ne marchent pas !
ls -la          # ERREUR
ls -Force       # OK (option PowerShell)
Get-ChildItem -Force  # Explicite et clair
```

!!! tip "Bonne pratique"
    En scripts, utilisez les noms complets des cmdlets, pas les alias.

    - Scripts : `Get-ChildItem`, `Get-Content`
    - Interactif : `ls`, `cat`, `gci` (OK pour taper vite)

---

## Le Pipeline & Filtrage

### Get-Member : Le "man" Interactif

`Get-Member` (alias `gm`) révèle la structure d'un objet : ses propriétés et méthodes.

```powershell
# Voir les membres d'un objet Process
Get-Process | Get-Member

# Output:
#    TypeName: System.Diagnostics.Process
#
# Name                       MemberType     Definition
# ----                       ----------     ----------
# Kill                       Method         void Kill()
# Start                      Method         bool Start()
# CPU                        Property       double CPU {get;}
# Id                         Property       int Id {get;}
# ProcessName                Property       string ProcessName {get;}
# WorkingSet64               Property       long WorkingSet64 {get;}

# Voir les propriétés uniquement
Get-Process | gm -MemberType Property

# Voir les méthodes
Get-Process | gm -MemberType Method
```

### Select-Object : Choisir des Colonnes

Équivalent de `awk '{print $1, $3}'` mais typé.

```powershell
# Sélectionner des propriétés
Get-Process | Select-Object Name, Id, CPU

# Alias court
Get-Process | select Name, Id, CPU

# Premiers/derniers éléments
Get-Process | Select-Object -First 5
Get-Process | Select-Object -Last 3

# Propriétés calculées
Get-Process | Select-Object Name, @{N='RAM_MB';E={$_.WorkingSet64/1MB}}
```

### Where-Object : Filtrer

Équivalent de `grep` mais sur les propriétés des objets.

```powershell
# Filtrer par condition
Get-Process | Where-Object { $_.CPU -gt 100 }

# Alias courts
Get-Process | ? { $_.CPU -gt 100 }
Get-Process | where CPU -gt 100    # Syntaxe simplifiée

# Conditions multiples
Get-Service | Where-Object { $_.Status -eq "Running" -and $_.Name -like "Win*" }

# Opérateurs de comparaison
# -eq    : Égal
# -ne    : Différent
# -gt    : Plus grand
# -lt    : Plus petit
# -ge    : Plus grand ou égal
# -le    : Plus petit ou égal
# -like  : Pattern matching (* et ?)
# -match : Regex
```

### Sort-Object : Trier

```powershell
# Trier par propriété
Get-Process | Sort-Object CPU

# Tri descendant
Get-Process | Sort-Object CPU -Descending

# Tri multiple
Get-ChildItem | Sort-Object Extension, Name

# Alias
Get-Process | sort CPU -Descending
```

### Enchaînement Complet

```powershell
# Processus utilisant le plus de CPU, top 5
Get-Process |
    Sort-Object CPU -Descending |
    Select-Object -First 5 Name, Id, CPU

# Services Windows en cours, triés par nom
Get-Service |
    Where-Object Status -eq "Running" |
    Sort-Object DisplayName |
    Select-Object DisplayName, Status
```

---

## One-Liners de Survie

### Fichiers et Dossiers

```powershell
# Top 5 des plus gros fichiers
Get-ChildItem -Recurse | Sort-Object Length -Descending | Select-Object -First 5

# Alias court
gci -Recurse | sort Length -Desc | select -First 5 Name, @{N='Size_MB';E={$_.Length/1MB}}

# Trouver les fichiers > 100MB
gci -Recurse | ? { $_.Length -gt 100MB }

# Fichiers modifiés ces 7 derniers jours
gci -Recurse | ? { $_.LastWriteTime -gt (Get-Date).AddDays(-7) }

# Supprimer les fichiers .tmp
gci -Recurse -Filter "*.tmp" | Remove-Item -Force
```

### Processus

```powershell
# Tuer un processus par nom
Stop-Process -Name notepad -Force

# Tuer par PID
Stop-Process -Id 1234 -Force

# Processus consommant > 500MB de RAM
Get-Process | ? { $_.WorkingSet64 -gt 500MB } | select Name, @{N='RAM_MB';E={[int]($_.WorkingSet64/1MB)}}

# Lancer un programme
Start-Process notepad
Start-Process "C:\Program Files\App\app.exe" -ArgumentList "-config", "file.conf"
```

### Réseau

```powershell
# Test de port (équivalent nc/telnet)
Test-NetConnection -ComputerName google.com -Port 443

# Output:
# ComputerName     : google.com
# RemoteAddress    : 142.250.179.110
# RemotePort       : 443
# TcpTestSucceeded : True

# Alias rapide
tnc google.com -Port 443

# Ping
Test-NetConnection google.com

# Résolution DNS
Resolve-DnsName google.com

# Connexions actives (comme netstat)
Get-NetTCPConnection | ? State -eq "Established"

# Ports en écoute
Get-NetTCPConnection -State Listen | select LocalPort, OwningProcess
```

### Services Windows

```powershell
# État d'un service
Get-Service -Name wuauserv

# Démarrer/Arrêter
Start-Service -Name wuauserv
Stop-Service -Name wuauserv
Restart-Service -Name wuauserv

# Services en échec
Get-Service | ? Status -eq "Stopped"
```

### Remote / Web

```powershell
# Télécharger un fichier (le "wget" de PowerShell)
Invoke-WebRequest -Uri "https://example.com/file.zip" -OutFile "file.zip"

# API REST
$response = Invoke-RestMethod -Uri "https://api.github.com/users/octocat"
$response.name

# Exécution distante (WinRM)
Invoke-Command -ComputerName Server01 -ScriptBlock { Get-Process }
```

---

## Quick Reference

```powershell
# === DÉCOUVERTE ===
Get-Command *service*              # Chercher une cmdlet
Get-Help Get-Process -Examples     # Aide avec exemples
Get-Process | Get-Member           # Structure d'un objet

# === PIPELINE ===
| Select-Object Name, Id           # Choisir colonnes
| Where-Object { $_.CPU -gt 10 }   # Filtrer
| Sort-Object CPU -Descending      # Trier
| Select-Object -First 5           # Top N

# === FICHIERS ===
Get-ChildItem -Recurse             # ls -R
Get-Content file.txt               # cat
Set-Content file.txt "text"        # echo > file
Add-Content file.txt "more"        # echo >> file

# === PROCESS ===
Get-Process                        # ps
Stop-Process -Name notepad         # kill

# === RÉSEAU ===
Test-NetConnection host -Port 443  # nc -zv
Get-NetTCPConnection               # netstat

# === ALIAS COURANTS ===
gci    = Get-ChildItem
gc     = Get-Content
?      = Where-Object
%      = ForEach-Object
select = Select-Object
sort   = Sort-Object
gm     = Get-Member
```
