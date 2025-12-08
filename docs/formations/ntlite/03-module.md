---
tags:
  - formation
  - ntlite
  - windows
  - drivers
  - updates
  - module
---

# Module 3 : Intégration - Drivers & Updates

## Introduction

> **"Don't wait for Windows Update"**

L'objectif d'une image professionnelle n'est **pas** de déployer Windows "nu" puis d'attendre 2 heures de téléchargements. L'objectif est une **machine prête à l'emploi dès le premier boot** :

- ✅ **Tous les drivers matériels intégrés** (réseau, stockage, GPU, Wi-Fi)
- ✅ **Mises à jour de sécurité déjà appliquées** (LCU du mois en cours)
- ✅ **Zéro redémarrage post-installation** pour "installer les pilotes"
- ✅ **Image standardisée** pour 100 machines identiques

Cette approche réduit le **temps de provisioning de 3h à 30 minutes** en environnement entreprise.

---

## Concept : Drivers

### Les Formats (INF vs EXE)

NTLite ne peut **PAS** injecter n'importe quoi :

| Type | Format | Compatible NTLite | Exemple |
|------|--------|-------------------|---------|
| **Driver matériel** | `.inf` + `.sys` + `.cat` | ✅ OUI | Pilote réseau Intel |
| **Logiciel constructeur** | `.exe` / `.msi` | ❌ NON | Dell Command Update |
| **Driver packagé** | `.cab` | ✅ OUI | Drivers Windows Update |

**Le piège classique** :
```
Vous téléchargez : "NVIDIA_GeForce_Setup.exe" (600 MB)
Contenu réel : Driver (50 MB) + GeForce Experience (550 MB de bloat)
```

**Solution professionnelle** :
1. Extraire le `.exe` avec 7-Zip
2. Chercher le dossier contenant `.inf` + `.sys`
3. N'intégrer **QUE** ce dossier dans NTLite

### Boot.wim vs Install.wim : La Distinction Critique

Windows utilise **deux images** pendant l'installation :

#### 1. Boot.wim (WinPE)
**Rôle** : Mini-OS temporaire pour lancer l'installation

**Drivers nécessaires** :
- 🔌 **Stockage** : NVMe, SATA, RAID (sinon "Aucun disque détecté")
- 🌐 **Réseau** : Si installation via PXE ou réseau

**Symptôme si manquant** :
```
"Windows ne trouve pas de disque dur"
"Impossible de se connecter au serveur de déploiement"
```

#### 2. Install.wim (OS complet)
**Rôle** : Le Windows qui sera installé sur le disque

**Drivers nécessaires** :
- Tous les drivers du `boot.wim`
- 📶 Wi-Fi (si utilisation sans câble Ethernet)
- 🎮 GPU (pour l'affichage optimal)
- 🔊 Audio, Bluetooth, Webcam, etc.

**Règle d'or** :
> Si le driver doit fonctionner **pendant** l'installation → `boot.wim`
> Si le driver doit fonctionner **après** l'installation → `install.wim`
> En cas de doute → **Injecter dans les deux**

---

## Concept : Updates

### La Hiérarchie des Mises à Jour

Windows impose un **ordre strict** d'installation :

```
1. SSU (Servicing Stack Update)
   ↓
2. LCU (Latest Cumulative Update)
   ↓
3. .NET Framework Updates
   ↓
4. Mises à jour facultatives
```

**Pourquoi cet ordre ?**

| Mise à jour | Rôle | Conséquence si installée en désordre |
|-------------|------|--------------------------------------|
| **SSU** | Met à jour le moteur de mise à jour | Les LCU suivantes peuvent échouer |
| **LCU** | Correctifs de sécurité cumulés | - |
| **.NET** | Framework applicatif | Peut échouer si LCU manquante |

**NTLite gère cet ordre automatiquement** si vous ajoutez les fichiers `.msu` dans le bon dossier.

### Component Store Cleanup (ResetBase)

**Le problème** :
```
Image initiale : 4.5 GB
+ LCU Janvier 2025 : +800 MB
+ LCU Février 2025 : +850 MB
Image finale : 6.2 GB (!!)
```

**Pourquoi ?** Windows garde les anciennes versions des fichiers pour permettre la **désinstallation** des mises à jour.

**Solution : ResetBase**

NTLite peut activer l'option **"Clean update backup"** :
- Fusionne les mises à jour dans le système
- Supprime les backups de désinstallation
- ⚠️ **Irréversible** : Impossible de désinstaller les updates après

**Résultat** :
```
Image initiale : 4.5 GB
+ LCU Février 2025 : +200 MB (au lieu de 1.6 GB cumulé)
Image finale : 4.7 GB ✅
```

**Recommandation** :
- ✅ Activer pour images de production (stabilité > réversibilité)
- ❌ Désactiver pour images de test (besoin de rollback)

---

## Pratique : Export & Import

### Le PowerShell Trick (Export depuis un PC réel)

**Scenario** : Vous avez un PC Dell OptiPlex 7090 **déjà configuré** avec tous les drivers fonctionnels.

**Méthode professionnelle** :

```powershell
# Exporter TOUS les drivers tiers (non-Microsoft)
Export-WindowsDriver -Online -Destination C:\DriversExport

# Alternative : Exporter depuis une image hors-ligne
Export-WindowsDriver -Path "C:\mount" -Destination C:\DriversExport
```

**Résultat** :
```
C:\DriversExport\
├── Intel_Network\
│   ├── e1d68x64.inf
│   ├── e1d68x64.sys
│   └── e1d68x64.cat
├── Realtek_Audio\
│   └── [...]
└── Dell_Touchpad\
    └── [...]
```

**Avantages** :
- ✅ Capture **exactement** les drivers qui fonctionnent
- ✅ Inclut les drivers exotiques (touchpad, capteurs)
- ✅ Évite de chercher sur le site du constructeur

### Intégration NTLite

**Étapes** :

1. **Charger l'image** (celle créée aux Modules 1-2)

2. **Drivers > Add > Insert Driver folder**
   ```
   Chemin : C:\DriversExport
   Options : ☑ Integrate recursively
   ```

3. **Gestion des doublons**

NTLite affiche un avertissement si :
- Même driver en version différente
- Driver Microsoft vs Constructeur

**Règle de décision** :
```
Driver constructeur (ex: Dell) version 2024.10.1
VS
Driver Microsoft (inbox) version 2022.03.5

→ Toujours privilégier le driver constructeur (plus récent)
```

4. **Choisir la cible**
   - ☑ **Install.wim** (obligatoire)
   - ☑ **Boot.wim** (si drivers réseau/stockage)

5. **Vérifier "Pending Changes"**
   ```
   ✓ 47 drivers will be integrated
   ⚠ 3 duplicates detected (review recommended)
   ```

---

## Pratique : Intégration des Updates

### Téléchargement des Mises à Jour

**Sources officielles** :

1. **Microsoft Update Catalog** : https://www.catalog.update.microsoft.com
   - Rechercher : `Windows 11 23H2 Cumulative Update`
   - Télécharger les fichiers `.msu`

2. **Via NTLite (automatique)**
   - `Updates > Download > Latest`
   - NTLite récupère SSU + LCU automatiquement

**Structure typique** :
```
Downloads\
├── SSU-KB5034848-x64.msu          (Servicing Stack)
├── LCU-KB5034843-x64.msu          (Cumulative Update)
└── NET-KB5034129-x64.msu          (.NET Framework)
```

### Intégration dans NTLite

**Étapes** :

1. **Updates > Add > Select files**
   - Sélectionner tous les `.msu`
   - NTLite les trie automatiquement par ordre

2. **Options recommandées** :
   ```
   ☑ Integrate updates
   ☑ Clean update backup (ResetBase)
   ☐ Integrate .NET updates (seulement si utilisé)
   ```

3. **Vérifier l'ordre** :
   ```
   1. [SSU] KB5034848 ✓
   2. [LCU] KB5034843 ✓
   3. [NET] KB5034129 ✓
   ```

4. **Appliquer** (peut prendre 10-20 minutes)

**Indicateur de progression** :
```
Processing updates... (15%)
Integrating KB5034843... (45%)
Cleaning component store... (78%)
Rebuilding image... (95%)
Done ✓
```

---

## Exercice : "Flotte Dell"

### Scenario

Votre entreprise vient de recevoir **50 laptops Dell Latitude 5440**. Vous devez :
- Préparer une image standardisée
- Inclure tous les drivers Dell
- Intégrer les mises à jour de janvier 2025
- Garantir zéro téléchargement lors du déploiement

### Mission

#### Étape 1 : Simuler l'export de drivers

Vous avez accès à **un laptop de référence déjà configuré**.

```powershell
# Sur le laptop de référence (en tant qu'admin)
Export-WindowsDriver -Online -Destination D:\Dell_Drivers_Latitude5440
```

**Questions** :
- Combien de drivers ont été exportés ?
- Y a-t-il des drivers Intel ? Realtek ?

---

#### Étape 2 : Injection des drivers critiques

Dans NTLite :

1. **Charger votre image Windows 11 Pro** (du Module 2)

2. **Drivers > Add > Insert Driver folder**
   - Chemin : `D:\Dell_Drivers_Latitude5440`
   - ☑ Integrate recursively

3. **Filtrer les drivers critiques** :
   - Chercher "Network" dans la liste
   - Chercher "Storage" ou "NVMe"
   - Chercher "Intel Wi-Fi" (si Wi-Fi utilisé)

4. **Cibler boot.wim ET install.wim** :
   - Clic droit sur les drivers réseau/stockage
   - `Properties > Integrate in Boot.wim`

---

#### Étape 3 : Ajout d'une Cumulative Update

1. **Télécharger la LCU** :
   - URL : https://www.catalog.update.microsoft.com
   - Rechercher : `2025-01 Cumulative Update Windows 11 23H2 x64`
   - Télécharger le fichier `.msu` (~500 MB)

2. **Intégrer dans NTLite** :
   - `Updates > Add`
   - Sélectionner le `.msu` téléchargé

3. **Activer le nettoyage** :
   - ☑ `Clean update backup`

---

#### Étape 4 : Validation

Avant d'appliquer, vérifier :

- [ ] Au moins 1 driver réseau intégré dans `boot.wim`
- [ ] Au moins 1 driver stockage intégré dans `boot.wim`
- [ ] La LCU apparaît dans "Pending Changes"
- [ ] L'option "Clean update backup" est activée
- [ ] La taille finale estimée < 5 GB

**Appliquer** et noter le temps de traitement.

---

## Solution

<details>
<summary>📋 Commandes & Étapes Complètes (Cliquez pour déplier)</summary>

### 1. Export PowerShell depuis PC de référence

```powershell
# Méthode 1 : Export depuis un PC en ligne
Export-WindowsDriver -Online -Destination C:\DriversExport

# Méthode 2 : Export depuis une image montée
Dism /Mount-Wim /WimFile:"C:\Images\install.wim" /Index:1 /MountDir:"C:\Mount"
Export-WindowsDriver -Path "C:\Mount" -Destination C:\DriversExport
Dism /Unmount-Wim /MountDir:"C:\Mount" /Discard
```

**Résultat attendu** :
```
Exporting drivers...
Successfully exported 52 driver packages to C:\DriversExport
```

---

### 2. Intégration NTLite - Drivers

**Navigation** :
```
NTLite > Load Image > Drivers (onglet)
```

**Actions** :
1. **Add > Insert Driver folder**
   ```
   Folder: C:\DriversExport
   ☑ Scan recursively
   ☐ Keep folder structure (recommandé de décocher)
   ```

2. **Sélectionner les drivers critiques** :
   ```
   ☑ Intel(R) Ethernet Connection I219-LM
   ☑ Intel(R) Wi-Fi 6 AX201 160MHz
   ☑ Samsung NVMe Controller (si NVMe)
   ☑ Realtek High Definition Audio
   ```

3. **Cibler boot.wim pour réseau/stockage** :
   - Clic droit sur driver réseau
   - `Integrate into Boot image`

4. **Gérer les doublons** :
   ```
   ⚠ Duplicate detected: Intel Network Driver
     • Version 27.3.0 (Microsoft)
     • Version 28.1.0 (Intel)

   → Sélectionner 28.1.0 (plus récent)
   ```

---

### 3. Intégration NTLite - Updates

**Téléchargement** :
```
Option A : Automatique via NTLite
  Updates > Download > Latest (SSU + LCU)

Option B : Manuel
  1. Aller sur https://www.catalog.update.microsoft.com
  2. Rechercher : "2025-01 Cumulative Update for Windows 11 Version 23H2 for x64"
  3. Télécharger le .msu (~500-800 MB)
```

**Intégration** :
```
NTLite > Updates (onglet)
1. Add > Select downloaded .msu files
2. ☑ Integrate updates
3. ☑ Clean update backup (ResetBase)
4. Apply
```

**Ordre automatique** (vérifié par NTLite) :
```
1. [SSU] KB5034848 - Servicing Stack Update
2. [LCU] KB5034843 - 2025-01 Cumulative Update
3. [NET] KB5034129 - .NET Framework 4.8.1 Update
```

---

### 4. Validation Finale

**Checklist avant Apply** :

```
Drivers (install.wim) :
✓ 52 drivers will be integrated
✓ Network drivers: 3
✓ Storage drivers: 2
✓ Audio drivers: 1

Drivers (boot.wim) :
✓ 5 drivers will be integrated (Network + Storage only)

Updates :
✓ SSU KB5034848
✓ LCU KB5034843
✓ Clean update backup: Enabled

Image Size :
Original: 4.2 GB
Estimated: 4.6 GB (+400 MB)
```

**Temps de traitement estimé** :
- Drivers : 5-10 minutes
- Updates : 15-25 minutes
- **Total : ~30-35 minutes**

---

### 5. Vérification Post-Intégration

**Méthode 1 : DISM** (sans NTLite)

```powershell
# Monter l'image
Dism /Mount-Wim /WimFile:"C:\CustomImage\install.wim" /Index:1 /MountDir:"C:\Mount"

# Lister les drivers tiers
Dism /Image:"C:\Mount" /Get-Drivers

# Lister les packages (updates)
Dism /Image:"C:\Mount" /Get-Packages

# Démonter
Dism /Unmount-Wim /MountDir:"C:\Mount" /Discard
```

**Méthode 2 : Test en VM**

1. Créer une VM VirtualBox/Hyper-V
2. Booter sur l'ISO personnalisée
3. **Vérifier pendant l'installation** :
   - Les disques sont détectés immédiatement ✓
   - Le réseau est fonctionnel (si PXE) ✓
4. **Après installation** :
   - `winver` affiche la version LCU ✓
   - Gestionnaire de périphériques : aucun point d'exclamation ✓

---

### 6. Script d'Export Avancé (Bonus)

Pour les flottes hétérogènes (Dell + HP + Lenovo) :

```powershell
# Export_Drivers_Fleet.ps1
param(
    [string]$Manufacturer = "Dell",
    [string]$Model = "Latitude 5440"
)

$ExportPath = "D:\DriverLibrary\${Manufacturer}_${Model}"
New-Item -Path $ExportPath -ItemType Directory -Force

Write-Host "Exporting drivers for $Manufacturer $Model..." -ForegroundColor Cyan
Export-WindowsDriver -Online -Destination $ExportPath

# Créer un fichier de métadonnées
$Metadata = @{
    Manufacturer = $Manufacturer
    Model = $Model
    ExportDate = Get-Date -Format "yyyy-MM-dd"
    DriverCount = (Get-ChildItem $ExportPath -Recurse -Filter "*.inf").Count
}
$Metadata | ConvertTo-Json | Out-File "$ExportPath\metadata.json"

Write-Host "Export completed: $($Metadata.DriverCount) drivers" -ForegroundColor Green
```

**Usage** :
```powershell
.\Export_Drivers_Fleet.ps1 -Manufacturer "Dell" -Model "Latitude 5440"
.\Export_Drivers_Fleet.ps1 -Manufacturer "HP" -Model "EliteBook 840 G9"
```

</details>

---

## Points Clés à Retenir

1. **INF vs EXE** : NTLite ne peut intégrer que les drivers matériels (.inf), pas les logiciels constructeurs
2. **Boot.wim critique** : Les drivers réseau/stockage doivent être dans boot.wim pour détecter les disques
3. **Export PowerShell** : `Export-WindowsDriver -Online` est la méthode professionnelle pour capturer les drivers
4. **Ordre des updates** : SSU → LCU → .NET (NTLite gère automatiquement)
5. **ResetBase obligatoire** : Activer "Clean update backup" pour éviter le bloat de l'image

---

## Astuces Professionnelles

### Gestion de Bibliothèque de Drivers

Pour les grandes flottes :

```
D:\DriverLibrary\
├── Dell\
│   ├── Latitude_5440\
│   ├── OptiPlex_7090\
│   └── Precision_5570\
├── HP\
│   ├── EliteBook_840\
│   └── ProDesk_600\
└── Lenovo\
    └── ThinkPad_X1_Carbon\
```

**Avantage** : Réutilisable pour chaque nouvelle image Windows (11 → 11 24H2 → 12).

### Drivers Universels (Dell Command | Update)

Certains constructeurs proposent des **packs de drivers universels** :

| Constructeur | Outil | Lien |
|--------------|-------|------|
| Dell | Dell Command Update | https://www.dell.com/support/kbdoc/en-us/000177325 |
| HP | HP Image Assistant | https://ftp.hp.com/pub/caps-softpaq/cmit/HPIA.html |
| Lenovo | Lenovo System Update | https://support.lenovo.com/us/en/solutions/ht037099 |

**Usage** :
1. Installer l'outil sur le PC de référence
2. Télécharger tous les drivers
3. Exporter avec `Export-WindowsDriver`

### Mises à Jour Mensuelles

**Workflow conseillé** :

```
Chaque 2ème mardi du mois (Patch Tuesday) :
1. Télécharger la nouvelle LCU
2. Charger l'image du mois dernier
3. Remplacer l'ancienne LCU par la nouvelle
4. Apply > Export ISO
5. Tester en VM
6. Déployer
```

**Automatisation possible** avec PowerShell + NTLite CLI (Module 5).

---

## Prochaine Étape

Dans le **Module 4**, nous verrons :
- 🎨 **Customization** : Fonds d'écran, thèmes, raccourcis bureau
- 📝 **Unattended Setup** : Automatiser l'installation (AutoUnattend.xml)
- 🔑 **OOBE Tweaks** : Désactiver les écrans de bienvenue, créer un compte local par défaut

Rendez-vous au prochain module pour créer une **expérience utilisateur sur mesure** !

---

## Navigation

| | |
|:---|---:|
| [← Module 2 : Le Grand Nettoyage (Debloa...](02-module.md) | [Module 4 : Automatisation - L'Install... →](04-module.md) |

[Retour au Programme](index.md){ .md-button }
