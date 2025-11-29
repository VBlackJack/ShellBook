---
tags:
  - formation
  - windows-server
  - powershell
  - scripting
---

# Module 05 : Introduction au Scripting

## Objectifs du Module

Ce module introduit les bases du scripting PowerShell :

- Comprendre les variables et types de données
- Maîtriser les structures conditionnelles
- Utiliser les boucles et itérations
- Créer des fonctions réutilisables
- Gérer les erreurs et le debugging

**Durée :** 6 heures

**Niveau :** Débutant

---

## 1. Premiers Scripts

### 1.1 Créer un Script

```powershell
# Un script PowerShell est un fichier .ps1

# Créer un script simple
@'
# Mon premier script
Write-Host "Hello, World!"
Write-Host "Date: $(Get-Date)"
'@ | Set-Content -Path C:\Scripts\hello.ps1

# Exécuter le script
C:\Scripts\hello.ps1

# Ou avec le chemin relatif
.\hello.ps1
```

### 1.2 Politique d'Exécution

```powershell
# Vérifier la politique actuelle
Get-ExecutionPolicy

# Politiques disponibles
# Restricted    - Aucun script (défaut sur clients)
# AllSigned     - Scripts signés uniquement
# RemoteSigned  - Local OK, distant doit être signé
# Unrestricted  - Tout exécuter (avertissement)
# Bypass        - Aucune restriction

# Changer la politique (admin requis)
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
Set-ExecutionPolicy RemoteSigned -Scope LocalMachine

# Exécuter un script malgré la politique
powershell -ExecutionPolicy Bypass -File C:\Scripts\hello.ps1
```

### 1.3 Structure d'un Script

```powershell
<#
.SYNOPSIS
    Description courte du script.

.DESCRIPTION
    Description détaillée du script.

.PARAMETER Param1
    Description du paramètre.

.EXAMPLE
    .\MonScript.ps1 -Param1 "Valeur"

.NOTES
    Auteur: Votre Nom
    Date: 2025-01-01
#>

# Paramètres
param(
    [string]$Param1 = "Défaut"
)

# Configuration
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Variables globales
$logFile = "C:\Logs\script.log"

# Fonctions
function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Add-Content -Path $logFile
}

# Code principal
try {
    Write-Log "Script démarré"
    # Votre code ici
    Write-Log "Script terminé"
}
catch {
    Write-Log "ERREUR: $_"
    throw
}
```

---

## 2. Variables

### 2.1 Déclaration et Types

```powershell
# Déclaration simple (type automatique)
$name = "Windows"
$version = 2022
$isServer = $true
$price = 99.99

# Vérifier le type
$name.GetType().Name      # String
$version.GetType().Name   # Int32

# Déclaration typée (fortement recommandé)
[string]$name = "Windows"
[int]$version = 2022
[bool]$isServer = $true
[double]$price = 99.99
[datetime]$date = Get-Date
[array]$list = @(1, 2, 3)
[hashtable]$dict = @{key = "value"}

# Constantes
Set-Variable -Name MAX_RETRIES -Value 3 -Option ReadOnly
$MAX_RETRIES = 5  # Erreur !

# Variables spéciales
$null                    # Null
$true / $false          # Booléens
$_                      # Objet courant (pipeline)
$PSVersionTable         # Version PowerShell
$env:COMPUTERNAME       # Variable d'environnement
$LASTEXITCODE          # Code retour dernière commande
$?                     # Succès dernière commande
```

### 2.2 Portée des Variables (Scope)

```powershell
# Portées
# Global    - Disponible partout
# Script    - Dans le script uniquement
# Local     - Bloc courant (défaut)
# Private   - Bloc courant, non hérité

$global:var = "Global"
$script:var = "Script"
$local:var = "Local"
$private:var = "Private"

# Exemple
$outerVar = "Outer"

function Test-Scope {
    $innerVar = "Inner"
    Write-Host "Dans la fonction: $outerVar"  # Accessible
    Write-Host "Variable locale: $innerVar"
}

Test-Scope
Write-Host "Hors fonction: $innerVar"  # N'existe pas !
```

### 2.3 Manipulation de Chaînes

```powershell
# Concaténation
$first = "Hello"
$second = "World"
$combined = "$first $second"           # "Hello World"
$combined = $first + " " + $second     # "Hello World"

# Guillemets simples vs doubles
$name = "Admin"
'Hello $name'   # Hello $name (littéral)
"Hello $name"   # Hello Admin (interprété)

# Sous-expressions
"Date: $(Get-Date)"
"Processes: $((Get-Process).Count)"

# Here-string (multilignes)
$text = @"
Ligne 1
Ligne 2 avec $name
Ligne 3
"@

# Méthodes de chaînes
$str = "Hello World"
$str.ToUpper()           # HELLO WORLD
$str.ToLower()           # hello world
$str.Length              # 11
$str.Contains("World")   # True
$str.Replace("World", "PowerShell")  # Hello PowerShell
$str.Split(" ")          # @("Hello", "World")
$str.Substring(0, 5)     # Hello
$str.Trim()              # Supprime espaces
$str.StartsWith("Hello") # True
$str.EndsWith("World")   # True
```

### 2.4 Tableaux (Arrays)

```powershell
# Création
$array = @()                    # Tableau vide
$array = @(1, 2, 3, 4, 5)      # Avec valeurs
$array = 1..10                  # Range (1 à 10)
$array = "a", "b", "c"          # Chaînes

# Accès
$array[0]                       # Premier élément
$array[-1]                      # Dernier élément
$array[0..2]                    # Trois premiers
$array[1, 3, 5]                 # Éléments spécifiques

# Propriétés
$array.Count                    # Nombre d'éléments
$array.Length                   # Idem

# Modification
$array += 6                     # Ajouter (crée nouveau tableau)
$array = $array | Where-Object { $_ -ne 3 }  # Retirer le 3

# ArrayList (modifiable efficacement)
$list = [System.Collections.ArrayList]@()
$list.Add("item")               # Retourne l'index
[void]$list.Add("item2")        # Sans retour
$list.Remove("item")
$list.Clear()

# Recherche
$array -contains 5              # True/False
$array.IndexOf(3)               # Position (ou -1)
```

### 2.5 Hashtables (Dictionnaires)

```powershell
# Création
$hash = @{}                     # Vide
$hash = @{
    Name = "Server01"
    IP   = "192.168.1.10"
    Role = "DC"
}

# Accès
$hash["Name"]                   # Server01
$hash.Name                      # Server01
$hash.Keys                      # Toutes les clés
$hash.Values                    # Toutes les valeurs

# Modification
$hash["OS"] = "Windows Server"  # Ajouter/Modifier
$hash.Add("RAM", "16GB")        # Ajouter (erreur si existe)
$hash.Remove("RAM")             # Supprimer

# Vérification
$hash.ContainsKey("Name")       # True
$hash.ContainsValue("DC")       # True

# Itération
foreach ($key in $hash.Keys) {
    Write-Host "$key = $($hash[$key])"
}

# Ordered hashtable (conserve l'ordre)
$ordered = [ordered]@{
    First  = 1
    Second = 2
    Third  = 3
}
```

---

## 3. Opérateurs

### 3.1 Opérateurs de Comparaison

```powershell
# Égalité
5 -eq 5      # True (equal)
5 -ne 3      # True (not equal)

# Comparaison numérique
5 -gt 3      # True (greater than)
5 -ge 5      # True (greater or equal)
3 -lt 5      # True (less than)
3 -le 5      # True (less or equal)

# Comparaison de chaînes (insensible à la casse par défaut)
"abc" -eq "ABC"    # True
"abc" -ceq "ABC"   # False (case-sensitive)
"abc" -ieq "ABC"   # True (case-insensitive, explicite)

# Pattern matching
"Hello" -like "H*"       # True (wildcard)
"Hello" -like "H???o"    # True (? = 1 char)
"Hello" -match "^H"      # True (regex)

# Contenu
@(1,2,3) -contains 2     # True
2 -in @(1,2,3)           # True
"Hello" -in "Hello","World"  # True
```

### 3.2 Opérateurs Logiques

```powershell
# AND, OR, NOT
$true -and $false   # False
$true -or $false    # True
-not $true          # False
!$true              # False (alias)

# XOR
$true -xor $false   # True

# Exemples pratiques
if ($user -and $user.Enabled) {
    # User existe ET est activé
}

if ($error -or $warning) {
    # Erreur OU avertissement
}
```

### 3.3 Opérateurs Arithmétiques

```powershell
# Basiques
5 + 3    # 8
5 - 3    # 2
5 * 3    # 15
5 / 3    # 1.666...
5 % 3    # 2 (modulo)

# Incrémentation
$i = 0
$i++     # $i = 1
$i--     # $i = 0
$i += 5  # $i = 5
$i -= 2  # $i = 3
$i *= 2  # $i = 6
```

### 3.4 Opérateurs de Texte

```powershell
# Split et Join
"a,b,c" -split ","        # @("a", "b", "c")
@("a", "b", "c") -join "-" # "a-b-c"

# Replace
"Hello World" -replace "World", "PowerShell"  # Regex
"Hello World".Replace("World", "PS")           # Méthode

# Format
"Name: {0}, Age: {1}" -f "John", 30   # "Name: John, Age: 30"
"{0:N2}" -f 1234.5                     # "1,234.50"
"{0:D8}" -f 123                        # "00000123"
```

---

## 4. Structures Conditionnelles

### 4.1 If/ElseIf/Else

```powershell
# Structure de base
if ($condition) {
    # Code si vrai
}

# Avec else
if ($condition) {
    # Code si vrai
}
else {
    # Code si faux
}

# Avec elseif
$score = 85

if ($score -ge 90) {
    Write-Host "A"
}
elseif ($score -ge 80) {
    Write-Host "B"
}
elseif ($score -ge 70) {
    Write-Host "C"
}
else {
    Write-Host "F"
}

# Conditions multiples
if ($user -and $user.Enabled -and $user.Department -eq "IT") {
    # Utilisateur IT actif
}

# Opérateur ternaire (PowerShell 7+)
$result = $condition ? "Vrai" : "Faux"

# Alternative (toutes versions)
$result = if ($condition) { "Vrai" } else { "Faux" }
```

### 4.2 Switch

```powershell
# Switch simple
$day = (Get-Date).DayOfWeek

switch ($day) {
    "Monday"    { Write-Host "Début de semaine" }
    "Friday"    { Write-Host "Presque le weekend!" }
    "Saturday"  { Write-Host "Weekend!" }
    "Sunday"    { Write-Host "Weekend!" }
    default     { Write-Host "Milieu de semaine" }
}

# Switch avec conditions multiples
switch ($day) {
    { $_ -in "Saturday", "Sunday" } { Write-Host "Weekend" }
    default { Write-Host "Semaine" }
}

# Switch avec regex
$email = "admin@company.com"

switch -Regex ($email) {
    "^admin"     { Write-Host "Compte admin" }
    "@company"   { Write-Host "Email interne" }
    "\.com$"     { Write-Host "Domaine .com" }
}

# Switch avec wildcard
switch -Wildcard ($filename) {
    "*.txt"  { Write-Host "Fichier texte" }
    "*.ps1"  { Write-Host "Script PowerShell" }
    "*.log"  { Write-Host "Fichier log" }
}

# Switch sur tableau
$numbers = 1, 2, 3, 4, 5

switch ($numbers) {
    { $_ % 2 -eq 0 } { Write-Host "$_ est pair" }
    { $_ % 2 -ne 0 } { Write-Host "$_ est impair" }
}
```

---

## 5. Boucles

### 5.1 ForEach

```powershell
# ForEach-Object (pipeline)
Get-Process | ForEach-Object { Write-Host $_.Name }
Get-Process | ForEach-Object Name   # Raccourci propriété

# foreach (statement)
$servers = @("SRV01", "SRV02", "SRV03")

foreach ($server in $servers) {
    Write-Host "Processing: $server"
    # Ping, connect, etc.
}

# ForEach avec index
$array = "a", "b", "c"
for ($i = 0; $i -lt $array.Count; $i++) {
    Write-Host "Index $i = $($array[$i])"
}
```

### 5.2 For

```powershell
# Boucle for classique
for ($i = 0; $i -lt 10; $i++) {
    Write-Host "Iteration: $i"
}

# Compte à rebours
for ($i = 10; $i -gt 0; $i--) {
    Write-Host "T-$i"
}

# Pas personnalisé
for ($i = 0; $i -le 100; $i += 10) {
    Write-Host "Pourcentage: $i%"
}
```

### 5.3 While et Do-While

```powershell
# While (condition d'abord)
$i = 0
while ($i -lt 5) {
    Write-Host "Count: $i"
    $i++
}

# Do-While (exécute au moins une fois)
$i = 0
do {
    Write-Host "Count: $i"
    $i++
} while ($i -lt 5)

# Do-Until (inverse de while)
$i = 0
do {
    Write-Host "Count: $i"
    $i++
} until ($i -ge 5)

# Exemple pratique : Attendre un service
$maxAttempts = 10
$attempt = 0

do {
    $service = Get-Service -Name "Spooler"
    if ($service.Status -eq "Running") {
        Write-Host "Service démarré!"
        break
    }
    Write-Host "Attente... (tentative $attempt)"
    Start-Sleep -Seconds 2
    $attempt++
} while ($attempt -lt $maxAttempts)
```

### 5.4 Contrôle de Boucle

```powershell
# break - Sort de la boucle
foreach ($num in 1..10) {
    if ($num -eq 5) { break }
    Write-Host $num
}
# Affiche: 1, 2, 3, 4

# continue - Passe à l'itération suivante
foreach ($num in 1..10) {
    if ($num % 2 -eq 0) { continue }
    Write-Host $num
}
# Affiche: 1, 3, 5, 7, 9

# return - Sort de la fonction
function Find-Number {
    foreach ($num in 1..100) {
        if ($num -eq 50) {
            return $num
        }
    }
}
```

---

## 6. Fonctions

### 6.1 Fonctions de Base

```powershell
# Fonction simple
function Say-Hello {
    Write-Host "Hello, World!"
}

Say-Hello

# Fonction avec paramètre
function Say-HelloTo {
    param([string]$Name)
    Write-Host "Hello, $Name!"
}

Say-HelloTo -Name "Admin"

# Syntaxe alternative
function Say-HelloTo($Name) {
    Write-Host "Hello, $Name!"
}
```

### 6.2 Paramètres Avancés

```powershell
function Get-ServerInfo {
    [CmdletBinding()]
    param(
        # Paramètre obligatoire
        [Parameter(Mandatory = $true)]
        [string]$ServerName,

        # Paramètre avec valeur par défaut
        [Parameter()]
        [int]$Port = 80,

        # Paramètre validé
        [Parameter()]
        [ValidateSet("HTTP", "HTTPS", "RDP")]
        [string]$Protocol = "HTTP",

        # Paramètre avec validation regex
        [Parameter()]
        [ValidatePattern("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")]
        [string]$IPAddress,

        # Paramètre switch (booléen)
        [Parameter()]
        [switch]$Verbose,

        # Accepte depuis le pipeline
        [Parameter(ValueFromPipeline = $true)]
        [string[]]$ComputerName
    )

    begin {
        Write-Host "Début du traitement"
    }

    process {
        foreach ($computer in $ComputerName) {
            Write-Host "Traitement de: $computer"
        }
    }

    end {
        Write-Host "Fin du traitement"
    }
}

# Utilisation
Get-ServerInfo -ServerName "SRV01" -Protocol HTTPS

# Depuis le pipeline
"SRV01", "SRV02" | Get-ServerInfo -ServerName "Base"
```

### 6.3 Valeurs de Retour

```powershell
# Retour implicite (tout ce qui n'est pas capturé)
function Get-Double {
    param([int]$Number)
    $Number * 2  # Retourné automatiquement
}

$result = Get-Double -Number 5  # $result = 10

# Retour explicite
function Get-Triple {
    param([int]$Number)
    return $Number * 3
}

# Retourner plusieurs valeurs (tableau)
function Get-MinMax {
    param([int[]]$Numbers)
    return @(($Numbers | Measure-Object -Minimum).Minimum,
             ($Numbers | Measure-Object -Maximum).Maximum)
}

$min, $max = Get-MinMax -Numbers 5, 2, 8, 1, 9

# Retourner un objet personnalisé
function Get-ServerStatus {
    param([string]$ServerName)

    [PSCustomObject]@{
        Name      = $ServerName
        Online    = Test-Connection $ServerName -Count 1 -Quiet
        Timestamp = Get-Date
    }
}
```

---

## 7. Gestion des Erreurs

### 7.1 Try/Catch/Finally

```powershell
try {
    # Code qui peut échouer
    $result = 1 / 0  # Division par zéro
}
catch {
    # Gestion de l'erreur
    Write-Host "Erreur: $_"
    Write-Host "Type: $($_.Exception.GetType().Name)"
}
finally {
    # Toujours exécuté
    Write-Host "Nettoyage"
}

# Catch spécifique par type d'exception
try {
    Get-Content "C:\fichier_inexistant.txt" -ErrorAction Stop
}
catch [System.IO.FileNotFoundException] {
    Write-Host "Fichier non trouvé"
}
catch [System.UnauthorizedAccessException] {
    Write-Host "Accès refusé"
}
catch {
    Write-Host "Autre erreur: $_"
}
```

### 7.2 ErrorAction

```powershell
# Comportements d'erreur
# Continue     - Afficher l'erreur, continuer (défaut)
# Stop         - Arrêter et lancer exception
# SilentlyContinue - Ignorer silencieusement
# Inquire      - Demander à l'utilisateur

# Par commande
Get-Content "C:\inexistant.txt" -ErrorAction SilentlyContinue
Get-Content "C:\inexistant.txt" -ErrorAction Stop

# Global pour le script
$ErrorActionPreference = "Stop"

# Vérifier $?
Get-Content "C:\inexistant.txt" -ErrorAction SilentlyContinue
if (-not $?) {
    Write-Host "La commande a échoué"
}

# Variable $Error
$Error[0]           # Dernière erreur
$Error.Clear()      # Effacer les erreurs
```

### 7.3 Validation des Entrées

```powershell
function Process-File {
    param(
        [Parameter(Mandatory)]
        [ValidateScript({ Test-Path $_ })]
        [string]$FilePath,

        [ValidateRange(1, 100)]
        [int]$Percentage,

        [ValidateNotNullOrEmpty()]
        [string]$Name
    )

    # Le code ne s'exécute que si les validations passent
    Write-Host "Traitement de $FilePath"
}

# Validation manuelle
function Validate-Input {
    param([string]$Email)

    if ($Email -notmatch "^[\w.-]+@[\w.-]+\.\w+$") {
        throw "Format d'email invalide"
    }
}
```

---

## 8. Exercices Pratiques

### Exercice 1 : Script de Rapport Système

**Objectif :** Créer un script qui génère un rapport système.

**Tâches :**

1. Collecter : nom, OS, CPU%, RAM%, espace disque
2. Afficher un résumé coloré
3. Exporter en CSV

**Solution :**

```powershell
# SystemReport.ps1
param(
    [string]$OutputPath = "C:\Temp\SystemReport.csv"
)

function Get-SystemReport {
    $cpu = (Get-Counter '\Processor(_Total)\% Processor Time').CounterSamples.CookedValue
    $memory = Get-CimInstance Win32_OperatingSystem
    $disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"

    [PSCustomObject]@{
        ComputerName = $env:COMPUTERNAME
        DateTime     = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        OS           = (Get-CimInstance Win32_OperatingSystem).Caption
        CPUPercent   = [math]::Round($cpu, 2)
        RAMTotalGB   = [math]::Round($memory.TotalVisibleMemorySize / 1MB, 2)
        RAMFreeGB    = [math]::Round($memory.FreePhysicalMemory / 1MB, 2)
        RAMPercent   = [math]::Round((1 - $memory.FreePhysicalMemory / $memory.TotalVisibleMemorySize) * 100, 2)
        DiskTotalGB  = [math]::Round($disk.Size / 1GB, 2)
        DiskFreeGB   = [math]::Round($disk.FreeSpace / 1GB, 2)
        DiskPercent  = [math]::Round((1 - $disk.FreeSpace / $disk.Size) * 100, 2)
    }
}

# Générer le rapport
$report = Get-SystemReport

# Affichage coloré
Write-Host "`n=== RAPPORT SYSTÈME ===" -ForegroundColor Cyan
Write-Host "Serveur: $($report.ComputerName)" -ForegroundColor White
Write-Host "OS: $($report.OS)" -ForegroundColor White

$cpuColor = if ($report.CPUPercent -gt 80) { "Red" } elseif ($report.CPUPercent -gt 50) { "Yellow" } else { "Green" }
Write-Host "CPU: $($report.CPUPercent)%" -ForegroundColor $cpuColor

$ramColor = if ($report.RAMPercent -gt 80) { "Red" } elseif ($report.RAMPercent -gt 50) { "Yellow" } else { "Green" }
Write-Host "RAM: $($report.RAMPercent)% ($($report.RAMFreeGB) GB libre)" -ForegroundColor $ramColor

$diskColor = if ($report.DiskPercent -gt 80) { "Red" } elseif ($report.DiskPercent -gt 50) { "Yellow" } else { "Green" }
Write-Host "Disque C: $($report.DiskPercent)% ($($report.DiskFreeGB) GB libre)" -ForegroundColor $diskColor

# Export CSV
$report | Export-Csv -Path $OutputPath -NoTypeInformation -Append
Write-Host "`nRapport exporté vers: $OutputPath" -ForegroundColor Green
```

---

### Exercice 2 : Gestionnaire d'Utilisateurs

**Objectif :** Script interactif pour gérer les utilisateurs locaux.

**Solution :**

```powershell
# UserManager.ps1
function Show-Menu {
    Clear-Host
    Write-Host "=== GESTIONNAIRE D'UTILISATEURS ===" -ForegroundColor Cyan
    Write-Host "1. Lister les utilisateurs"
    Write-Host "2. Créer un utilisateur"
    Write-Host "3. Supprimer un utilisateur"
    Write-Host "4. Activer/Désactiver un utilisateur"
    Write-Host "5. Quitter"
    Write-Host ""
}

function List-Users {
    Write-Host "`nUtilisateurs locaux:" -ForegroundColor Yellow
    Get-LocalUser | Format-Table Name, Enabled, LastLogon -AutoSize
    Read-Host "Appuyez sur Entrée pour continuer"
}

function Create-User {
    $name = Read-Host "Nom de l'utilisateur"
    $password = Read-Host "Mot de passe" -AsSecureString
    $description = Read-Host "Description"

    try {
        New-LocalUser -Name $name -Password $password -Description $description -ErrorAction Stop
        Write-Host "Utilisateur '$name' créé avec succès!" -ForegroundColor Green
    }
    catch {
        Write-Host "Erreur: $_" -ForegroundColor Red
    }
    Read-Host "Appuyez sur Entrée pour continuer"
}

function Delete-User {
    $name = Read-Host "Nom de l'utilisateur à supprimer"
    $confirm = Read-Host "Confirmer la suppression de '$name'? (O/N)"

    if ($confirm -eq "O") {
        try {
            Remove-LocalUser -Name $name -ErrorAction Stop
            Write-Host "Utilisateur '$name' supprimé!" -ForegroundColor Green
        }
        catch {
            Write-Host "Erreur: $_" -ForegroundColor Red
        }
    }
    Read-Host "Appuyez sur Entrée pour continuer"
}

function Toggle-User {
    $name = Read-Host "Nom de l'utilisateur"
    $user = Get-LocalUser -Name $name -ErrorAction SilentlyContinue

    if ($user) {
        if ($user.Enabled) {
            Disable-LocalUser -Name $name
            Write-Host "Utilisateur '$name' désactivé" -ForegroundColor Yellow
        }
        else {
            Enable-LocalUser -Name $name
            Write-Host "Utilisateur '$name' activé" -ForegroundColor Green
        }
    }
    else {
        Write-Host "Utilisateur non trouvé" -ForegroundColor Red
    }
    Read-Host "Appuyez sur Entrée pour continuer"
}

# Boucle principale
do {
    Show-Menu
    $choice = Read-Host "Choix"

    switch ($choice) {
        "1" { List-Users }
        "2" { Create-User }
        "3" { Delete-User }
        "4" { Toggle-User }
        "5" { Write-Host "Au revoir!" -ForegroundColor Cyan }
        default { Write-Host "Choix invalide" -ForegroundColor Red }
    }
} while ($choice -ne "5")
```

---

## 9. Quiz de Validation

### Questions

1. **Comment déclarer une variable typée en entier ?**
   - [ ] A. int $var = 5
   - [ ] B. [int]$var = 5
   - [ ] C. $var = (int)5

2. **Quel opérateur teste si un tableau contient une valeur ?**
   - [ ] A. -in
   - [ ] B. -contains
   - [ ] C. -has

3. **Quelle structure exécute du code au moins une fois ?**
   - [ ] A. while
   - [ ] B. for
   - [ ] C. do-while

4. **Comment rendre un paramètre obligatoire ?**
   - [ ] A. [Required]
   - [ ] B. [Parameter(Mandatory)]
   - [ ] C. [Mandatory]

5. **Quelle variable contient la dernière erreur ?**
   - [ ] A. $LastError
   - [ ] B. $Error[0]
   - [ ] C. $Exception

### Réponses

1. **B** - [int]$var = 5
2. **B** - -contains
3. **C** - do-while
4. **B** - [Parameter(Mandatory)]
5. **B** - $Error[0]

---

## 10. Ressources

- [PowerShell Scripting Guide](https://docs.microsoft.com/powershell/scripting/)
- [About Functions](https://docs.microsoft.com/powershell/module/microsoft.powershell.core/about/about_functions)
- [About Try Catch Finally](https://docs.microsoft.com/powershell/module/microsoft.powershell.core/about/about_try_catch_finally)

---

**Précédent :** [Module 04 : Outils d'Administration](04-outils-administration.md)

**Suivant :** [Module 06 : Rôles & Features](06-roles-features.md)

---

**Fin du Niveau 1 - Fondations**

Vous avez maintenant les bases solides pour administrer Windows Server avec PowerShell. Le Niveau 2 approfondit ces compétences avec la gestion des rôles, services, stockage et réseau.
