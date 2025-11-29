---
tags:
  - formation
  - windows-server
  - powershell
  - debutant
---

# Module 02 : PowerShell Basics

## Objectifs du Module

Ce module vous introduit à PowerShell, le shell moderne de Windows :

- Comprendre la philosophie PowerShell (objets vs texte)
- Maîtriser les cmdlets fondamentales
- Utiliser le pipeline et les opérateurs
- Naviguer dans le système de fichiers et le registre
- Obtenir de l'aide et explorer les commandes

**Durée :** 6 heures

**Niveau :** Débutant

---

## 1. Introduction à PowerShell

### 1.1 Qu'est-ce que PowerShell ?

PowerShell est :

- Un **shell de ligne de commande** moderne
- Un **langage de scripting** complet
- Basé sur **.NET Framework**
- **Orienté objet** (contrairement à Bash)

```
┌─────────────────────────────────────────────────────────────┐
│                 BASH vs POWERSHELL                           │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  BASH (Linux)                   POWERSHELL (Windows)         │
│  ───────────                    ────────────────────         │
│                                                              │
│  Manipule du TEXTE              Manipule des OBJETS          │
│                                                              │
│  $ ps aux | grep ssh            Get-Process | Where-Object   │
│  │                              Name -eq "sshd"              │
│  └─ Texte brut                  │                            │
│     à parser                    └─ Objets .NET               │
│                                    avec propriétés           │
│                                                              │
│  Pipe: stream de texte          Pipe: stream d'objets        │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### 1.2 Versions de PowerShell

| Version | Type | Inclus Dans | .NET |
|---------|------|-------------|------|
| PowerShell 5.1 | Windows | Windows 10/Server 2016+ | .NET Framework |
| PowerShell 7+ | Cross-Platform | Installation séparée | .NET Core |

```powershell
# Vérifier la version
$PSVersionTable

# Installer PowerShell 7 (recommandé)
winget install Microsoft.PowerShell
```

!!! tip "PowerShell 7"
    Utilisez **PowerShell 7** pour les fonctionnalités modernes et la compatibilité cross-platform.

### 1.3 Lancer PowerShell

```powershell
# Méthodes pour lancer PowerShell
# 1. Windows Terminal (recommandé)
# 2. Win + X → Windows Terminal (Admin)
# 3. Tapez "pwsh" ou "powershell" dans cmd
# 4. Bouton droit → Terminal ici

# Vérifier si vous êtes administrateur
[Security.Principal.WindowsIdentity]::GetCurrent().Groups -contains 'S-1-5-32-544'
```

---

## 2. Syntaxe des Cmdlets

### 2.1 Structure Verbe-Nom

PowerShell utilise une convention **Verbe-Nom** :

```
Verbe-Nom -Paramètre Valeur

Exemples :
Get-Process
Set-Location -Path C:\Windows
New-Item -Name "fichier.txt" -ItemType File
```

### 2.2 Verbes Courants

| Verbe | Action | Exemple |
|-------|--------|---------|
| **Get** | Obtenir/Lire | `Get-Process`, `Get-Service` |
| **Set** | Modifier | `Set-Location`, `Set-Item` |
| **New** | Créer | `New-Item`, `New-Object` |
| **Remove** | Supprimer | `Remove-Item`, `Remove-Service` |
| **Start** | Démarrer | `Start-Process`, `Start-Service` |
| **Stop** | Arrêter | `Stop-Process`, `Stop-Service` |
| **Restart** | Redémarrer | `Restart-Service`, `Restart-Computer` |
| **Enable** | Activer | `Enable-PSRemoting` |
| **Disable** | Désactiver | `Disable-PSRemoting` |
| **Test** | Tester | `Test-Path`, `Test-Connection` |
| **Invoke** | Exécuter | `Invoke-Command`, `Invoke-WebRequest` |

### 2.3 Paramètres

```powershell
# Paramètres nommés
Get-Process -Name "explorer"

# Paramètres positionnels (premier paramètre)
Get-Process explorer       # -Name est implicite

# Paramètres switch (booléens)
Get-ChildItem -Recurse -Force

# Paramètres avec valeurs multiples
Get-Process -Name "explorer", "notepad"

# Paramètres communs (disponibles partout)
Get-Process -ErrorAction SilentlyContinue
Get-Process -Verbose
Get-Process -WhatIf    # Simulation
```

---

## 3. Obtenir de l'Aide

### 3.1 Get-Help

```powershell
# Mettre à jour l'aide (première fois)
Update-Help -Force -ErrorAction SilentlyContinue

# Aide de base
Get-Help Get-Process

# Aide détaillée
Get-Help Get-Process -Detailed

# Exemples uniquement
Get-Help Get-Process -Examples

# Aide complète
Get-Help Get-Process -Full

# Aide en ligne
Get-Help Get-Process -Online

# Rechercher des commandes
Get-Help *process*
Get-Help *-Service
```

### 3.2 Get-Command

```powershell
# Lister toutes les commandes
Get-Command

# Filtrer par nom
Get-Command *Process*
Get-Command Get-*

# Filtrer par verbe
Get-Command -Verb Get
Get-Command -Verb Set

# Filtrer par nom
Get-Command -Noun Process
Get-Command -Noun Service

# Filtrer par module
Get-Command -Module Microsoft.PowerShell.Management

# Voir les paramètres d'une commande
Get-Command Get-Process -Syntax
```

### 3.3 Get-Member

```powershell
# Voir les propriétés et méthodes d'un objet
Get-Process | Get-Member

# Filtrer par type
Get-Process | Get-Member -MemberType Property
Get-Process | Get-Member -MemberType Method

# Raccourci
Get-Process | gm
```

---

## 4. Manipulation des Objets

### 4.1 Comprendre les Objets

```powershell
# Chaque cmdlet retourne des objets .NET
$proc = Get-Process explorer

# Voir le type de l'objet
$proc.GetType().FullName
# System.Diagnostics.Process

# Accéder aux propriétés
$proc.Name
$proc.Id
$proc.CPU
$proc.WorkingSet64

# Appeler des méthodes
$proc.Kill()    # Attention !
```

### 4.2 Select-Object

```powershell
# Sélectionner des propriétés spécifiques
Get-Process | Select-Object Name, Id, CPU

# Renommer des propriétés
Get-Process | Select-Object Name, @{Name="Memory(MB)";Expression={$_.WorkingSet64/1MB}}

# Premiers/Derniers éléments
Get-Process | Select-Object -First 5
Get-Process | Select-Object -Last 3

# Propriétés uniques
Get-Process | Select-Object Name -Unique

# Exclure des propriétés
Get-Process | Select-Object * -ExcludeProperty *64
```

### 4.3 Where-Object (Filtrage)

```powershell
# Syntaxe moderne (PowerShell 3+)
Get-Process | Where-Object CPU -gt 10
Get-Service | Where-Object Status -eq "Running"

# Syntaxe script block (plus flexible)
Get-Process | Where-Object { $_.CPU -gt 10 }
Get-Process | Where-Object { $_.Name -like "power*" }
Get-Process | Where-Object { $_.WorkingSet64 -gt 100MB }

# Opérateurs de comparaison
# -eq    égal
# -ne    différent
# -gt    supérieur
# -lt    inférieur
# -ge    supérieur ou égal
# -le    inférieur ou égal
# -like  wildcard (*, ?)
# -match regex
# -contains  tableau contient

# Conditions multiples
Get-Process | Where-Object { $_.CPU -gt 5 -and $_.Name -notlike "System*" }
Get-Service | Where-Object { $_.Status -eq "Running" -or $_.Status -eq "Paused" }
```

### 4.4 Sort-Object (Tri)

```powershell
# Tri simple
Get-Process | Sort-Object CPU

# Tri descendant
Get-Process | Sort-Object CPU -Descending

# Tri multiple
Get-Process | Sort-Object Status, Name

# Top N
Get-Process | Sort-Object CPU -Descending | Select-Object -First 10
```

### 4.5 Group-Object

```powershell
# Grouper par propriété
Get-Service | Group-Object Status

# Voir le détail
Get-Process | Group-Object Company | Sort-Object Count -Descending

# Utiliser les groupes
(Get-Service | Group-Object Status).Group
```

### 4.6 Measure-Object

```powershell
# Compter
Get-Service | Measure-Object

# Statistiques
Get-Process | Measure-Object CPU -Sum -Average -Maximum -Minimum

# Compter les lignes d'un fichier
Get-Content C:\Windows\System32\drivers\etc\hosts | Measure-Object -Line
```

---

## 5. Le Pipeline

### 5.1 Concept du Pipeline

```powershell
# Le pipeline (|) passe des OBJETS entre cmdlets
Get-Process | Where-Object CPU -gt 10 | Sort-Object CPU -Descending | Select-Object -First 5

# Chaque étape reçoit l'objet de l'étape précédente
# $_ représente l'objet courant dans le pipeline
```

```
┌─────────────────────────────────────────────────────────────┐
│                      PIPELINE                                │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Get-Process                                                 │
│       │                                                      │
│       ▼  [Process1, Process2, Process3, ...]                │
│  Where-Object { $_.CPU -gt 10 }                             │
│       │                                                      │
│       ▼  [ProcessA, ProcessB]  (filtrés)                    │
│  Sort-Object CPU -Descending                                 │
│       │                                                      │
│       ▼  [ProcessB, ProcessA]  (triés)                      │
│  Select-Object -First 1                                      │
│       │                                                      │
│       ▼  [ProcessB]  (résultat final)                       │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### 5.2 ForEach-Object

```powershell
# Exécuter une action pour chaque objet
Get-Process | ForEach-Object { Write-Host "Process: $($_.Name)" }

# Raccourci avec %
Get-Service | % { $_.Status }

# Bloc Begin/Process/End
1..10 | ForEach-Object -Begin { $sum = 0 } `
                       -Process { $sum += $_ } `
                       -End { Write-Host "Total: $sum" }
```

### 5.3 Tee-Object

```powershell
# Envoyer la sortie vers un fichier ET continuer le pipeline
Get-Process | Tee-Object -FilePath C:\processes.txt | Where-Object CPU -gt 10
```

---

## 6. Navigation

### 6.1 Système de Fichiers

```powershell
# Emplacement courant
Get-Location    # ou pwd

# Changer de répertoire
Set-Location C:\Windows    # ou cd
Push-Location C:\Temp      # Empiler l'emplacement
Pop-Location               # Dépiler

# Lister le contenu
Get-ChildItem              # ou ls, dir
Get-ChildItem -Path C:\Windows -Recurse -Filter *.exe
Get-ChildItem -Hidden
Get-ChildItem -File        # Fichiers uniquement
Get-ChildItem -Directory   # Dossiers uniquement

# Tester l'existence
Test-Path C:\Windows
Test-Path C:\Windows -PathType Container  # Dossier
Test-Path C:\Windows\notepad.exe -PathType Leaf  # Fichier

# Résoudre un chemin
Resolve-Path C:\Windows\..

# Joindre des chemins
Join-Path -Path C:\Users -ChildPath Administrator

# Diviser un chemin
Split-Path C:\Windows\System32\notepad.exe -Parent
Split-Path C:\Windows\System32\notepad.exe -Leaf
```

### 6.2 Providers PowerShell

PowerShell utilise des "providers" pour accéder à différents datastores :

```powershell
# Lister les providers
Get-PSProvider

# Providers disponibles
# FileSystem   - C:\, D:\
# Registry     - HKLM:\, HKCU:\
# Alias        - Alias:\
# Environment  - Env:\
# Function     - Function:\
# Variable     - Variable:\
# Certificate  - Cert:\

# Naviguer dans le registre
Set-Location HKLM:\SOFTWARE\Microsoft
Get-ChildItem

# Lire les variables d'environnement
Get-ChildItem Env:
$env:PATH
$env:COMPUTERNAME

# Naviguer dans les certificats
Set-Location Cert:\LocalMachine\My
Get-ChildItem
```

### 6.3 Manipulation de Fichiers

```powershell
# Créer un fichier
New-Item -Path C:\Temp\test.txt -ItemType File
New-Item -Path C:\Temp\test.txt -ItemType File -Value "Contenu initial"

# Créer un dossier
New-Item -Path C:\Temp\MonDossier -ItemType Directory
# ou
mkdir C:\Temp\MonDossier

# Copier
Copy-Item C:\source.txt C:\dest.txt
Copy-Item C:\source\ C:\dest\ -Recurse

# Déplacer/Renommer
Move-Item C:\source.txt C:\dest.txt
Rename-Item C:\ancien.txt -NewName nouveau.txt

# Supprimer
Remove-Item C:\fichier.txt
Remove-Item C:\dossier\ -Recurse -Force

# Lire le contenu
Get-Content C:\fichier.txt
Get-Content C:\fichier.txt -First 10   # Premières lignes
Get-Content C:\fichier.txt -Tail 5     # Dernières lignes
Get-Content C:\log.txt -Wait           # Suivre en temps réel

# Écrire du contenu
Set-Content C:\fichier.txt -Value "Nouveau contenu"
Add-Content C:\fichier.txt -Value "Ligne ajoutée"

# Remplacer du contenu
(Get-Content C:\fichier.txt) -replace "ancien", "nouveau" | Set-Content C:\fichier.txt
```

---

## 7. Formatage de la Sortie

### 7.1 Format-Table

```powershell
# Format tableau (par défaut pour peu de propriétés)
Get-Process | Format-Table

# Colonnes spécifiques
Get-Process | Format-Table Name, Id, CPU -AutoSize

# Wrapping
Get-Process | Format-Table -Wrap

# Grouper
Get-Service | Format-Table -GroupBy Status
```

### 7.2 Format-List

```powershell
# Format liste (par défaut pour beaucoup de propriétés)
Get-Process explorer | Format-List

# Toutes les propriétés
Get-Process explorer | Format-List *

# Propriétés spécifiques
Get-Process | Format-List Name, Id, Path
```

### 7.3 Format-Wide

```powershell
# Affichage sur colonnes
Get-ChildItem | Format-Wide -Column 4
Get-Process | Format-Wide -Property Name -Column 3
```

### 7.4 Out-GridView

```powershell
# Interface graphique (GUI)
Get-Process | Out-GridView

# Avec sélection
Get-Process | Out-GridView -PassThru | Stop-Process -WhatIf
```

---

## 8. Export et Import

### 8.1 Fichiers CSV

```powershell
# Exporter en CSV
Get-Process | Select-Object Name, Id, CPU | Export-Csv C:\processes.csv -NoTypeInformation

# Importer un CSV
$data = Import-Csv C:\processes.csv
$data | Where-Object CPU -gt 10
```

### 8.2 Fichiers JSON

```powershell
# Exporter en JSON
Get-Process | Select-Object Name, Id | ConvertTo-Json | Set-Content C:\processes.json

# Importer du JSON
$data = Get-Content C:\processes.json | ConvertFrom-Json
```

### 8.3 Fichiers XML

```powershell
# Exporter en XML
Get-Process | Export-Clixml C:\processes.xml

# Importer du XML
$data = Import-Clixml C:\processes.xml
```

### 8.4 Fichier Texte

```powershell
# Redirection vers fichier
Get-Process | Out-File C:\processes.txt

# Avec encodage spécifique
Get-Process | Out-File C:\processes.txt -Encoding UTF8

# Append
Get-Process | Out-File C:\processes.txt -Append
```

---

## 9. Alias

### 9.1 Alias Courants

```powershell
# Lister les alias
Get-Alias

# Alias -> Cmdlet
Get-Alias dir          # Get-ChildItem
Get-Alias ls           # Get-ChildItem
Get-Alias cd           # Set-Location
Get-Alias pwd          # Get-Location
Get-Alias cat          # Get-Content
Get-Alias echo         # Write-Output
Get-Alias cls          # Clear-Host
Get-Alias %            # ForEach-Object
Get-Alias ?            # Where-Object
Get-Alias select       # Select-Object
Get-Alias sort         # Sort-Object
```

### 9.2 Créer des Alias

```powershell
# Créer un alias (session courante)
New-Alias -Name np -Value notepad.exe

# Alias persistant (ajouter au profil)
# $PROFILE
New-Alias -Name ll -Value Get-ChildItem
```

---

## 10. Exercices Pratiques

### Exercice 1 : Exploration des Processus

**Objectif :** Manipuler les processus avec PowerShell.

**Tâches :**

1. Lister tous les processus
2. Trouver les 5 processus utilisant le plus de CPU
3. Compter les processus par entreprise
4. Exporter la liste en CSV

**Solution :**

```powershell
# 1. Lister tous les processus
Get-Process

# 2. Top 5 CPU
Get-Process | Sort-Object CPU -Descending | Select-Object -First 5 Name, Id, CPU

# 3. Grouper par Company
Get-Process | Group-Object Company | Sort-Object Count -Descending | Select-Object Name, Count

# 4. Exporter
Get-Process | Select-Object Name, Id, CPU, WorkingSet64 | Export-Csv C:\Temp\processes.csv -NoTypeInformation
```

---

### Exercice 2 : Gestion des Services

**Objectif :** Explorer et gérer les services Windows.

**Tâches :**

1. Lister les services en cours d'exécution
2. Trouver les services qui démarrent automatiquement mais sont arrêtés
3. Compter les services par état

**Solution :**

```powershell
# 1. Services running
Get-Service | Where-Object Status -eq "Running"

# 2. Services auto mais arrêtés
Get-Service | Where-Object { $_.StartType -eq "Automatic" -and $_.Status -ne "Running" }

# 3. Comptage par état
Get-Service | Group-Object Status
```

---

### Exercice 3 : Navigation et Fichiers

**Objectif :** Manipuler les fichiers et dossiers.

**Tâches :**

1. Créer un dossier C:\LabPS avec 3 sous-dossiers
2. Créer 5 fichiers texte avec du contenu
3. Lister tous les fichiers .txt récursivement
4. Trouver les fichiers de plus de 1 KB

**Solution :**

```powershell
# 1. Créer la structure
New-Item -Path C:\LabPS -ItemType Directory
"Logs", "Scripts", "Data" | ForEach-Object { New-Item -Path "C:\LabPS\$_" -ItemType Directory }

# 2. Créer les fichiers
1..5 | ForEach-Object {
    Set-Content -Path "C:\LabPS\file$_.txt" -Value ("Line " * 100)
}

# 3. Lister les .txt
Get-ChildItem -Path C:\LabPS -Filter *.txt -Recurse

# 4. Fichiers > 1KB
Get-ChildItem -Path C:\LabPS -Recurse | Where-Object { $_.Length -gt 1KB }
```

---

### Exercice 4 : Pipeline Avancé

**Objectif :** Maîtriser les chaînes de pipeline complexes.

**Tâche :** Créer une seule commande qui :

1. Récupère tous les fichiers .log dans C:\Windows\Logs
2. Filtre ceux modifiés dans les 7 derniers jours
3. Trie par taille décroissante
4. Affiche le nom et la taille en MB
5. Exporte en CSV

**Solution :**

```powershell
Get-ChildItem -Path C:\Windows\Logs -Filter *.log -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) } |
    Sort-Object Length -Descending |
    Select-Object Name, @{Name="SizeMB";Expression={[math]::Round($_.Length/1MB, 2)}}, LastWriteTime |
    Export-Csv C:\Temp\recent-logs.csv -NoTypeInformation
```

---

## 11. Quiz de Validation

### Questions

1. **Quel est le verbe PowerShell pour créer un nouvel élément ?**
   - [ ] A. Create
   - [ ] B. New
   - [ ] C. Add

2. **Quelle cmdlet permet de voir les propriétés d'un objet ?**
   - [ ] A. Get-Property
   - [ ] B. Get-Member
   - [ ] C. Show-Object

3. **Quel opérateur utilise-t-on pour filtrer dans le pipeline ?**
   - [ ] A. Filter-Object
   - [ ] B. Where-Object
   - [ ] C. Select-Object

4. **Comment accéder au registre dans PowerShell ?**
   - [ ] A. Get-Registry
   - [ ] B. Set-Location HKLM:\
   - [ ] C. Open-Registry

5. **Quel caractère représente l'objet courant dans le pipeline ?**
   - [ ] A. $this
   - [ ] B. $_
   - [ ] C. $object

### Réponses

1. **B** - New (New-Item, New-Object, etc.)
2. **B** - Get-Member
3. **B** - Where-Object
4. **B** - Set-Location HKLM:\
5. **B** - $_

---

## 12. Ressources

- [PowerShell Documentation](https://docs.microsoft.com/powershell/)
- [PowerShell Gallery](https://www.powershellgallery.com/)
- [PowerShell GitHub](https://github.com/PowerShell/PowerShell)

---

**Précédent :** [Module 01 : Découverte Windows Server](01-decouverte.md)

**Suivant :** [Module 03 : Utilisateurs & NTFS](03-utilisateurs-ntfs.md)
