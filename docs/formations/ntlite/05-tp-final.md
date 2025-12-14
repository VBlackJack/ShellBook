---
tags:
  - formation
  - ntlite
  - windows
  - tp-final
  - vdi
  - projet
---

# Module 5 : TP Final - L'Image Master "Golden ISO"

**Durée estimée :** 1 heure

## Scenario : Project VDI-Lite

### Contexte Mission

Votre entreprise déploie une **infrastructure VDI (Virtual Desktop Infrastructure)** pour permettre le télétravail :

- **Plateforme** : Proxmox VE / KVM (hyperviseur open-source)
- **Cible** : 50 machines virtuelles Windows 11 Enterprise
- **Contraintes** :
  - 🎯 **Légèreté** : Les VMs ont 2 vCPU / 4 GB RAM / 60 GB disque
  - ⚡ **Rapidité** : Provisioning d'une nouvelle VM en < 15 minutes
  - 🤖 **Automatisation** : Zéro interaction manuelle (déploiement nocturne)
  - 🔒 **Sécurité** : Compte utilisateur pré-configuré, télémétrie désactivée

### Objectifs Mesurables

| Métrique | Baseline Windows 11 | Objectif Golden ISO | Critère de réussite |
|----------|---------------------|---------------------|---------------------|
| **Taille ISO** | ~5.2 GB | < 4.0 GB | ✅ Réduction de 23% |
| **Installation complète** | 25-30 min | < 10 min | ✅ Gain de 66% |
| **Clics utilisateur** | ~15 écrans | 0 clic | ✅ 100% automatisé |
| **RAM au boot** | ~2.5 GB | < 1.8 GB | ✅ Économie de 700 MB |
| **Services actifs** | ~180 | < 120 | ✅ Réduction de 33% |

---

## Étape 1 : La Base (Module 1)

### 1.1 Téléchargement de l'image source

**Source officielle** :
```text
Microsoft Evaluation Center
URL : https://www.microsoft.com/en-us/evalcenter/evaluate-windows-11-enterprise

Version recommandée : Windows 11 Enterprise 23H2 (x64)
Format : ISO (~5.2 GB)
```

**Alternative avec Media Creation Tool** :
```powershell
# Télécharger Media Creation Tool
Invoke-WebRequest -Uri "https://go.microsoft.com/fwlink/?LinkId=691209" -OutFile "MediaCreationTool.exe"

# Sélectionner :
# - Edition : Windows 11
# - Language : French
# - Architecture : 64-bit
# - Format : ISO file
```

---

### 1.2 Montage dans NTLite

**Actions** :

1. **Lancer NTLite**
2. **Image history > Add > Image file (install.wim/esd)**
3. **Naviguer vers** : `G:\ISO\Win11_Enterprise_23H2.iso`
4. **Sélectionner** : `sources\install.wim`
5. **Charger l'édition** : `Windows 11 Enterprise`

**Vérifications** :
```text
✓ Edition : Windows 11 Enterprise
✓ Version : 23H2 (Build 22631.xxxx)
✓ Architecture : x64
✓ Language : fr-FR (ou en-US si langue française ajoutée après)
```

---

### 1.3 Sauvegarde du projet

**Créer un preset réutilisable** :

```text
File > Save preset
Nom : VDI-Lite-Golden-v1.0
Description : Image optimisée pour VDI Proxmox (50 VMs, 4GB RAM)
```

**Avantage** : Vous pourrez réappliquer cette configuration chaque mois lors des mises à jour.

---

## Étape 2 : Le Régime (Module 2)

### 2.1 Activation du mode Compatibility

**Avant toute suppression** :

```text
Components > Compatibility (onglet en haut)
☑ Enable compatibility warnings
☑ Prevent removal of networking components
☑ Prevent removal of storage drivers
```

---

### 2.2 Suppression des Modern Apps (UWP)

**Cible** : Toutes les applications métiers inutiles en VDI

#### Applications à supprimer :

**Navigation** : `Components > Applications`

```text
☑ Microsoft.BingNews
☑ Microsoft.BingWeather
☑ Microsoft.GetHelp
☑ Microsoft.Getstarted
☑ Microsoft.Microsoft3DViewer
☑ Microsoft.MicrosoftOfficeHub (si Office déployé séparément)
☑ Microsoft.MicrosoftSolitaireCollection
☑ Microsoft.MixedReality.Portal
☑ Microsoft.Office.OneNote (version UWP)
☑ Microsoft.People
☑ Microsoft.SkypeApp
☑ Microsoft.Wallet
☑ Microsoft.WindowsAlarms
☑ Microsoft.WindowsCamera
☑ Microsoft.WindowsFeedbackHub
☑ Microsoft.WindowsMaps
☑ Microsoft.WindowsSoundRecorder
☑ Microsoft.Xbox.TCUI
☑ Microsoft.XboxApp
☑ Microsoft.XboxGameOverlay
☑ Microsoft.XboxGamingOverlay
☑ Microsoft.XboxIdentityProvider
☑ Microsoft.XboxSpeechToTextOverlay
☑ Microsoft.YourPhone
☑ Microsoft.ZuneMusic
☑ Microsoft.ZuneVideo
```

**Économie estimée** : ~800 MB

---

#### Applications à CONSERVER :

```text
✓ Microsoft.WindowsCalculator (utilitaire de base)
✓ Microsoft.WindowsStore (peut être requis pour certaines LOB apps)
✓ Microsoft.WindowsTerminal (si utilisateurs avancés)
✓ Microsoft.Paint (Paint moderne)
✓ Microsoft.ScreenSketch (captures d'écran)
✓ Microsoft.HEIFImageExtension (support HEIF/HEIC)
✓ Microsoft.VP9VideoExtensions (support vidéo)
✓ Microsoft.WebMediaExtensions (support média web)
```

---

### 2.3 Suppression de composants système

**Navigation** : `Components > System`

#### À supprimer (VDI sans matériel physique) :

```text
☑ Cortana
☑ OneDrive (si SharePoint/serveur de fichiers utilisé)
☑ Windows Mixed Reality
☑ Windows Hello Face (pas de caméra en VDI)
☑ Retail Demo Content
☑ Windows Insider Hub
☑ Geo-location Service
☑ Advertising ID
☑ Steps Recorder (psr.exe)
☑ Internet Explorer 11 (obsolète)
☑ Windows Media Player (legacy)
☑ WordPad
☑ XPS Viewer & Services
```

**Économie estimée** : ~400 MB

---

#### À CONSERVER (Critique pour VDI) :

```sql
✓ Windows Defender (sécurité de base - IMPORTANT)
✓ Remote Desktop Services (accès RDP si nécessaire)
✓ Print Spooler (impression redirigée)
✓ Windows Update (mises à jour de sécurité)
✓ .NET Framework 3.5 + 4.8
✓ PowerShell
✓ Windows Search (indexation)
```

**⚠️ IMPORTANT** : Ne PAS supprimer Windows Defender en VDI, même si un antivirus tiers est prévu. Defender fournit une protection de base pendant le provisioning.

---

### 2.4 Edge Chromium : Décision

**Problème** : Edge est intégré à Windows 11 (composants système)

**Recommandation** :
```text
☐ NE PAS supprimer Edge via NTLite (risque de casser des composants)

Alternative :
✓ Désactiver Edge via GPO après déploiement
✓ Installer Chrome/Firefox comme navigateur par défaut
✓ Bloquer les mises à jour Edge via Registry
```

---

### 2.5 Vérification "Pending Changes"

Avant d'appliquer :

```text
Pending Changes (onglet en bas)
→ Vérifier qu'aucune ligne rouge n'apparaît
→ Total supprimé : ~1.2 GB
```

---

## Étape 3 : Les Pilotes (Module 3)

### 3.1 Context VDI : Pourquoi VirtIO ?

En environnement **Proxmox/KVM**, Windows ne dispose PAS des drivers natifs pour :
- 💾 **VirtIO SCSI** : Contrôleur de disque virtuel (performances optimales)
- 🌐 **VirtIO Network** : Carte réseau virtuelle (30% plus rapide que e1000)
- 🖥️ **QXL/VirtIO GPU** : Affichage optimisé

**Sans ces drivers** :
```text
❌ Windows Setup affiche : "Aucun lecteur n'a été trouvé"
❌ Le réseau ne fonctionne pas après installation
❌ Les performances sont dégradées (émulation e1000)
```

---

### 3.2 Téléchargement des drivers VirtIO

**Source officielle** :

```text
Fedora VirtIO Drivers (certifiés Microsoft)
URL : https://github.com/virtio-win/virtio-win-pkg-scripts/blob/master/README.md
Lien direct ISO : https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/virtio-win.iso
Taille : ~500 MB
```

**Extraire l'ISO** :

```powershell
# Monter l'ISO VirtIO
Mount-DiskImage -ImagePath "C:\Downloads\virtio-win.iso"

# Copier les drivers Windows 11
$DriveLetter = (Get-DiskImage -ImagePath "C:\Downloads\virtio-win.iso" | Get-Volume).DriveLetter
Copy-Item "${DriveLetter}:\viostor\w11\amd64" -Destination "C:\Drivers\VirtIO_Storage" -Recurse
Copy-Item "${DriveLetter}:\NetKVM\w11\amd64" -Destination "C:\Drivers\VirtIO_Network" -Recurse
Copy-Item "${DriveLetter}:\vioscsi\w11\amd64" -Destination "C:\Drivers\VirtIO_SCSI" -Recurse
Copy-Item "${DriveLetter}:\qxldod\w11\amd64" -Destination "C:\Drivers\VirtIO_Display" -Recurse

# Démonter
Dismount-DiskImage -ImagePath "C:\Downloads\virtio-win.iso"
```

**Résultat** :
```text
C:\Drivers\
├── VirtIO_Storage\
│   ├── viostor.inf
│   ├── viostor.sys
│   └── viostor.cat
├── VirtIO_Network\
│   └── [...]
├── VirtIO_SCSI\
│   └── [...]
└── VirtIO_Display\
    └── [...]
```

---

### 3.3 Intégration dans NTLite

**Actions** :

1. **Drivers (onglet)**
2. **Add > Insert Driver folder**
   ```text
   Folder : C:\Drivers
   ☑ Scan recursively
   ```

3. **Résultat** :
   ```text
   ✓ 4 driver packages detected
   - Red Hat VirtIO SCSI controller
   - Red Hat VirtIO Ethernet Adapter
   - Red Hat VirtIO SCSI pass-through controller
   - QXL display adapter
   ```

4. **Cibler boot.wim ET install.wim** :
   - Clic droit sur **VirtIO Storage**
   - `Properties > ☑ Integrate into Boot image`
   - Répéter pour **VirtIO Network**

**⚠️ CRITIQUE** : Sans drivers dans `boot.wim`, l'installateur ne détectera pas le disque virtuel.

---

### 3.4 Intégration des mises à jour

**Téléchargement** :

```bash
Microsoft Update Catalog
Rechercher : "2025-01 Cumulative Update Windows 11 Version 23H2 for x64"
Télécharger :
- SSU (Servicing Stack Update) : KB5034848
- LCU (Latest Cumulative Update) : KB5034843
```

**Intégration** :

```sql
Updates (onglet)
Add > Select files
→ Sélectionner SSU + LCU
☑ Integrate updates
☑ Clean update backup (ResetBase)
Apply
```

**Temps estimé** : 15-20 minutes

---

## Étape 4 : Le Pilote Automatique (Module 4)

### 4.1 Configuration de la langue

**Navigation** : `Unattended > Localization`

```text
Input Locale : fr-FR
System Locale : fr-FR
UI Language : fr-FR
User Locale : fr-FR
Time Zone : Romance Standard Time
```

---

### 4.2 Création du compte utilisateur

**Navigation** : `Unattended > Users`

**Configuration** :

```bash
Add > Local Account

Username : VDI-User
Full Name : Utilisateur VDI
Password : SecurePass!
Confirm Password : SecurePass!
Groups : Users (PAS Administrators - principe du moindre privilège)
Auto-logon count : 0 (désactivé - l'utilisateur saisit son mot de passe)
```

**Justification** :
- ❌ Pas d'auto-logon en VDI (sécurité multi-utilisateurs)
- ❌ Pas de droits Administrateur par défaut (réduction de surface d'attaque)
- ✅ Mot de passe fort obligatoire

---

### 4.3 Configuration OOBE

**Navigation** : `Unattended > General`

```text
☑ Auto-fill defaults
☑ Hide account pages (compte déjà créé)
☑ Skip machine OOBE
☐ Express settings (désactivé pour vie privée)
```

**Navigation** : `Unattended > OOBE Extended`

```text
☑ Skip EULA
☑ Skip Privacy Settings
☑ Skip Wireless Setup
☑ Skip MSA (Microsoft Account)
☑ Skip Cortana
☑ Skip OneDrive
☑ Skip Region
☑ Skip Keyboard
```

---

### 4.4 Partitionnement automatique

**Navigation** : `Unattended > Disk Configuration`

**Configuration** :

```text
Mode : Automatic
☑ Wipe disk 0
Partition scheme : UEFI (GPT)
```

**Résultat** :
```text
Disk 0 (60 GB) :
├── EFI System Partition (100 MB)
├── MSR (Microsoft Reserved) (16 MB)
└── Windows (C:) (59.9 GB)
```

**⚠️ SÉCURITÉ VDI** : Cette option est SAFE en VDI car les VMs sont provisionnées à partir de zéro.

---

## Étape 5 : La Touche Finale (Post-Setup)

### 5.1 Objectif : Installation automatique de Chocolatey

**Pourquoi Chocolatey en VDI ?**
- ✅ Installation silencieuse d'applications (Chrome, VSCode, 7zip)
- ✅ Mises à jour centralisées via script
- ✅ Pas de manipulation manuelle de .exe/.msi

---

### 5.2 Création du script SetupComplete.cmd

**Navigation** : `Unattended > RunOnce > Add`

**⚠️ CORRECTION** : NTLite utilise `$OEM$` folders, pas "RunOnce" directement.

**Méthode correcte** :

**Navigation** : `Post-Setup (onglet en haut, à côté de Unattended)`

**Créer le fichier localement** :

```batch
REM C:\Temp\SetupComplete.cmd
@echo off
REM ========================================
REM Script exécuté à la fin de l'installation Windows
REM ========================================

echo [%date% %time%] Installation de Chocolatey... >> C:\Windows\Temp\setup.log

REM Autoriser l'exécution de scripts PowerShell
powershell.exe -NoProfile -Command "Set-ExecutionPolicy Bypass -Scope LocalMachine -Force"

REM Installer Chocolatey
powershell.exe -NoProfile -Command "[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))"

echo [%date% %time%] Chocolatey installé. >> C:\Windows\Temp\setup.log

REM Installer des applications de base (optionnel)
REM choco install googlechrome 7zip notepadplusplus -y

echo [%date% %time%] Setup terminé. >> C:\Windows\Temp\setup.log
exit 0
```

---

### 5.3 Intégration dans NTLite

**Méthode 1 : Via Post-Setup** (recommandé)

**Navigation** : `Post-Setup > $OEM$ folders > Add folder`

**Structure à créer** :

```text
C:\NTLite_PostSetup\
└── $OEM$/
    └── $$\
        └── Setup\
            └── Scripts\
                └── SetupComplete.cmd
```

**Actions dans NTLite** :

1. Créer le dossier `C:\NTLite_PostSetup\$OEM$\$$\Setup\Scripts\`
2. Placer le fichier `SetupComplete.cmd` dedans
3. Dans NTLite : `Post-Setup > Add folder`
4. Sélectionner `C:\NTLite_PostSetup\$OEM$`

**Résultat** : Le script sera copié dans `C:\Windows\Setup\Scripts\SetupComplete.cmd` et exécuté automatiquement.

---

**Méthode 2 : Via interface NTLite simplifiée**

**Navigation** : `Unattended > RunOnce Commands (ou First Logon Commands)`

```powershell
Add Command:
cmd.exe /c "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))\""

Description: Install Chocolatey
Order: 1
```

**⚠️ Limitation** : Cette méthode exécute au **premier logon utilisateur**, pas en post-setup système.

---

### 5.4 Vérification

**Dans Pending Changes** :

```text
✓ $OEM$ folder will be integrated
✓ SetupComplete.cmd detected
```

---

## Étape 6 : Build & Test

### 6.1 Génération de l'ISO

**Actions** :

1. **Vérifier toutes les sections** :
   ```text
   ✓ Components : 25 apps supprimées
   ✓ Drivers : 4 VirtIO drivers intégrés
   ✓ Updates : SSU + LCU intégrés
   ✓ Unattended : Configuré (fr-FR, VDI-User, OOBE skip)
   ✓ Post-Setup : SetupComplete.cmd présent
   ```

2. **Apply > Create ISO**

3. **Paramètres ISO** :
   ```bash
   ISO Label : WIN11_VDI_LITE_v1.0
   Output path : G:\ISO\Win11_VDI_Lite_Golden_v1.0.iso
   ☑ Include ISO boot files (UEFI + BIOS)
   ☑ Optimize file order for faster installation
   ```

4. **Lancer** : Durée estimée 10-30 minutes selon CPU

---

### 6.2 Vérification de la taille

**Objectif** : < 4.0 GB

```powershell
$ISO = Get-Item "G:\ISO\Win11_VDI_Lite_Golden_v1.0.iso"
$SizeGB = [math]::Round($ISO.Length / 1GB, 2)
Write-Host "Taille ISO : $SizeGB GB" -ForegroundColor $(if ($SizeGB -lt 4.0) {"Green"} else {"Red"})

# Sortie attendue : "Taille ISO : 3.75 GB" (en vert)
```

---

### 6.3 Test en Machine Virtuelle

**Plateforme** : VirtualBox ou Hyper-V (ou Proxmox si disponible)

#### Configuration VM de test :

```text
Nom : VDI-Lite-Test
Type : Windows 11 (64-bit)
CPU : 2 vCPU
RAM : 4096 MB
Disque : 60 GB (VirtIO SCSI si Proxmox/KVM, SATA si VirtualBox)
Réseau : Bridged (VirtIO Network si Proxmox/KVM)
Boot : ISO Win11_VDI_Lite_Golden_v1.0.iso
```

---

#### Scénario de test :

**Phase 1 : Installation (chronométrer)**

```text
1. Démarrer la VM sur l'ISO
2. [T0] Noter l'heure de début
3. Observer : AUCUN écran d'interaction ne doit apparaître
4. Vérifier : Le disque est détecté immédiatement (drivers VirtIO OK)
5. [T1] Noter l'heure d'arrivée sur l'écran de connexion
```

**Objectif** : T1 - T0 < 10 minutes

---

**Phase 2 : Connexion**

```text
6. Connexion avec :
   - Username : VDI-User
   - Password : SecurePass!
7. Vérifier : Arrivée directe sur le bureau (pas d'OOBE)
```

---

**Phase 3 : Validation technique**

```powershell
# Vérifier la taille installée
Get-PSDrive C | Select-Object Used, Free
# Objectif : Used < 20 GB

# Vérifier les services actifs
(Get-Service | Where-Object {$_.Status -eq 'Running'}).Count
# Objectif : < 120 services

# Vérifier la RAM utilisée
(Get-Counter '\Memory\Available MBytes').CounterSamples.CookedValue
# Objectif : RAM libre > 2 GB (sur 4 GB total)

# Vérifier Chocolatey
choco --version
# Sortie attendue : 2.x.x (si SetupComplete.cmd a fonctionné)
```

---

**Phase 4 : Vérification fonctionnelle**

```sql
☐ Le réseau est fonctionnel (ping 8.8.8.8)
☐ Le navigateur Edge fonctionne (même si on le remplacera)
☐ L'explorateur de fichiers s'ouvre sans erreur
☐ Le Panneau de configuration est accessible
☐ Windows Update fonctionne (optionnel en VDI)
☐ Aucun point d'exclamation dans le Gestionnaire de périphériques
```

---

### 6.4 Benchmark de performance

**Comparer avec une installation standard** :

| Métrique | Windows 11 Standard | Golden ISO VDI-Lite | Gain |
|----------|---------------------|---------------------|------|
| Taille ISO | 5.2 GB | 3.75 GB | **-28%** |
| Temps d'installation | 25 min | 8 min | **-68%** |
| Clics requis | 15 | 0 | **-100%** |
| Espace disque utilisé | 28 GB | 18 GB | **-36%** |
| RAM au boot | 2.5 GB | 1.7 GB | **-32%** |
| Services actifs | 178 | 115 | **-35%** |

---

## Étape 7 : Déploiement (Production)

### 7.1 Création du Template Proxmox

**Méthode recommandée** : Convertir la VM de test en template

```bash
# Sur le nœud Proxmox
# 1. Arrêter la VM
qm stop 100

# 2. Convertir en template
qm template 100

# 3. Renommer
qm set 100 --name "WIN11-VDI-LITE-TEMPLATE-v1.0"

# 4. Cloner pour créer de nouvelles VMs
qm clone 100 200 --name "VDI-USER-001" --full
qm clone 100 201 --name "VDI-USER-002" --full
# [...]
```

**Temps de provisioning par VM** : 2-3 minutes (clonage de template).

---

### 7.2 Automatisation du déploiement

**Script PowerShell** (exécuté depuis Proxmox CLI) :

```bash
#!/bin/bash
# deploy_vdi_fleet.sh
# Déploie 50 VMs VDI en série

TEMPLATE_ID=100
START_ID=200
COUNT=50

for i in $(seq 0 $((COUNT-1))); do
    VM_ID=$((START_ID + i))
    VM_NAME="VDI-USER-$(printf '%03d' $((i+1)))"

    echo "Déploiement de $VM_NAME (VMID: $VM_ID)..."

    # Cloner le template
    qm clone $TEMPLATE_ID $VM_ID --name "$VM_NAME" --full

    # Configurer les ressources
    qm set $VM_ID --memory 4096 --cores 2

    # Démarrer la VM
    qm start $VM_ID

    echo "$VM_NAME déployée avec succès."
done

echo "Déploiement terminé : $COUNT VMs créées."
```

**Exécution** :
```bash
chmod +x deploy_vdi_fleet.sh
./deploy_vdi_fleet.sh
```

**Temps total** : 50 VMs déployées en ~15 minutes.

---

## Étape 8 : Maintenance de l'Image

### 8.1 Cycle de mise à jour mensuel

**Workflow recommandé** (chaque Patch Tuesday) :

```text
1. Télécharger la nouvelle LCU du mois
2. Ouvrir le projet NTLite sauvegardé
3. Updates > Remove old LCU > Add new LCU
4. Apply > Create ISO
5. Tester en VM
6. Recréer le template Proxmox
7. Déployer progressivement (rolling update)
```

---

### 8.2 Versioning de l'image

**Convention de nommage** :

```text
Format : WIN11_VDI_LITE_vX.Y_YYYY-MM

Exemples :
- WIN11_VDI_LITE_v1.0_2025-01.iso (version initiale, janvier 2025)
- WIN11_VDI_LITE_v1.1_2025-02.iso (mise à jour février)
- WIN11_VDI_LITE_v2.0_2025-06.iso (changement majeur)
```

---

### 8.3 Documentation de l'image

**Créer un fichier README.md** :

```markdown
# Golden ISO VDI-Lite v1.0

## Informations
- **Version Windows** : Windows 11 Enterprise 23H2 (Build 22631.3085)
- **Date de création** : 2025-01-15
- **Mises à jour intégrées** : SSU KB5034848, LCU KB5034843
- **Taille** : 3.75 GB

## Composants supprimés
- Toutes les applications Xbox
- Cortana, OneDrive, Mixed Reality
- 25 applications UWP au total

## Drivers intégrés
- VirtIO Storage (viostor)
- VirtIO Network (NetKVM)
- VirtIO SCSI (vioscsi)
- QXL Display

## Configuration Unattended
- **Langue** : Français (fr-FR)
- **Compte** : VDI-User / SecurePass!
- **Auto-logon** : Désactivé
- **OOBE** : Tous les écrans skip

## Post-Setup
- Installation automatique de Chocolatey
- ExecutionPolicy configurée en Bypass

## Utilisation
1. Monter l'ISO dans Proxmox
2. Créer une VM (2 vCPU, 4GB RAM, 60GB Disk)
3. Booter sur l'ISO
4. Attendre 8-10 minutes
5. Connexion avec VDI-User / SecurePass!

## Tests
- ✅ Installation : 8 min 23 sec
- ✅ RAM au boot : 1.65 GB
- ✅ Services actifs : 112
- ✅ Espace disque : 17.8 GB

## Changelog
### v1.0 (2025-01-15)
- Version initiale
- Intégration VirtIO drivers
- Configuration OOBE complète
```

---

## Conclusion : Vous êtes maintenant un Image Master

### Compétences acquises

Au cours de cette formation **NTLite Mastery**, vous avez appris à :

1. ✅ **Manipuler les fichiers WIM/ESD** (Module 1)
   - Montage/démontage d'images
   - Extraction d'éditions spécifiques
   - Création d'ISO bootables

2. ✅ **Optimiser Windows pour des cas d'usage spécifiques** (Module 2)
   - Suppression de composants en toute sécurité (Compatibility mode)
   - Réduction de 30% de la taille d'installation
   - Désactivation de la télémétrie et bloatware

3. ✅ **Intégrer drivers et mises à jour** (Module 3)
   - Distinction boot.wim vs install.wim
   - Export de drivers via PowerShell
   - Intégration de LCU avec ResetBase
   - Drivers VirtIO pour KVM/Proxmox

4. ✅ **Automatiser l'installation** (Module 4)
   - Génération de fichiers autounattend.xml
   - Configuration OOBE Skip
   - Création de comptes locaux
   - Partitionnement automatique

5. ✅ **Créer une Golden Image production-ready** (Module 5)
   - Intégration de post-setup scripts
   - Tests et validation en VM
   - Déploiement à grande échelle (50+ VMs)
   - Maintenance et versioning

---

### Prochaines étapes

Pour aller plus loin :

1. **Intégration MDT/WDS** : Déployer via réseau PXE
2. **SCCM/Intune** : Gestion centralisée du parc
3. **VDI avancé** : Intégration Citrix/VMware Horizon
4. **NTLite CLI** : Automatiser avec PowerShell
5. **Sysprep & Capture** : Créer des images de référence personnalisées

---

### Ressources complémentaires

| Ressource | Type | URL |
|-----------|------|-----|
| **Documentation NTLite** | Officiel | https://www.ntlite.com/documentation/ |
| **VirtIO Drivers** | Drivers | https://github.com/virtio-win/virtio-win-pkg-scripts |
| **Microsoft Docs - Unattend** | Doc | https://learn.microsoft.com/windows-hardware/customize/desktop/unattend/ |
| **Chocolatey Packages** | Repository | https://community.chocolatey.org/packages |
| **r/sysadmin** | Communauté | https://reddit.com/r/sysadmin |

---

## Solution : Checklist Complète du TP

<details>
<summary>📋 Récapitulatif de Configuration (Cliquez pour déplier)</summary>

### 1. Image de base

```text
Source : Windows 11 Enterprise 23H2 (x64)
Edition : Enterprise
Language : fr-FR (ou en-US avec langue ajoutée)
```

---

### 2. Components (Module 2)

**Applications supprimées (25 total)** :
```text
☑ Bing News, Weather
☑ Get Help, Get Started
☑ 3D Viewer
☑ Office Hub (UWP)
☑ Solitaire, Mixed Reality
☑ OneNote (UWP)
☑ People, Skype
☑ Wallet, Alarms, Camera
☑ Feedback Hub, Maps, Sound Recorder
☑ Tout l'écosystème Xbox (5 apps)
☑ Your Phone, Zune Music/Video
```

**Composants système supprimés (12 total)** :
```text
☑ Cortana
☑ OneDrive
☑ Windows Mixed Reality
☑ Windows Hello Face
☑ Retail Demo Content
☑ Windows Insider Hub
☑ Geo-location Service
☑ Advertising ID
☑ Steps Recorder
☑ Internet Explorer 11
☑ Windows Media Player (legacy)
☑ WordPad, XPS Services
```

**Conservés (CRITIQUE)** :
```text
✓ Windows Defender
✓ Remote Desktop Services
✓ Print Spooler
✓ Windows Update
✓ .NET Framework 3.5 + 4.8
✓ PowerShell
✓ Edge (intégré, désactivation via GPO après)
```

---

### 3. Drivers (Module 3)

**VirtIO pour Proxmox/KVM** :
```text
✓ VirtIO Storage (viostor) → boot.wim + install.wim
✓ VirtIO Network (NetKVM) → boot.wim + install.wim
✓ VirtIO SCSI (vioscsi) → install.wim
✓ QXL Display (qxldod) → install.wim
```

**Source** : https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/virtio-win.iso

---

### 4. Updates (Module 3)

```sql
✓ SSU KB5034848 (Servicing Stack Update)
✓ LCU KB5034843 (Cumulative Update 2025-01)
☑ Clean update backup (ResetBase) : Activé
```

---

### 5. Unattended (Module 4)

**Localization** :
```text
Input Locale : fr-FR
System Locale : fr-FR
UI Language : fr-FR
User Locale : fr-FR
Time Zone : Romance Standard Time
```

**Users** :
```text
Username : VDI-User
Password : SecurePass!
Groups : Users
Auto-logon : 0 (désactivé)
```

**General** :
```text
☑ Auto-fill defaults
☑ Hide account pages
☑ Skip machine OOBE
```

**OOBE Extended** :
```text
☑ Skip EULA
☑ Skip Privacy Settings
☑ Skip Wireless Setup
☑ Skip MSA
☑ Skip Cortana
☑ Skip OneDrive
☑ Skip Region
☑ Skip Keyboard
```

**Disk Configuration** :
```text
Mode : Automatic
☑ Wipe disk 0
Partition scheme : UEFI (GPT)
```

---

### 6. Post-Setup (Module 5)

**SetupComplete.cmd** :
```batch
@echo off
powershell.exe -NoProfile -Command "Set-ExecutionPolicy Bypass -Scope LocalMachine -Force"
powershell.exe -NoProfile -Command "[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))"
exit 0
```

**Emplacement** : `$OEM$\$$\Setup\Scripts\SetupComplete.cmd`

---

### 7. ISO Creation

```text
ISO Label : WIN11_VDI_LITE_v1.0
Output : G:\ISO\Win11_VDI_Lite_Golden_v1.0.iso
☑ Include boot files (UEFI + BIOS)
☑ Optimize file order
```

---

### 8. Tests de validation

**Métriques cibles** :
```text
✓ Taille ISO : < 4.0 GB (objectif : 3.75 GB)
✓ Temps installation : < 10 min (objectif : 8 min)
✓ Clics requis : 0
✓ RAM au boot : < 1.8 GB (objectif : 1.65 GB)
✓ Services actifs : < 120 (objectif : 112)
✓ Espace disque : < 20 GB (objectif : 17.8 GB)
```

**Tests fonctionnels** :
```text
☐ Réseau fonctionnel (ping, navigation web)
☐ Gestionnaire de périphériques : aucun point d'exclamation
☐ Chocolatey installé (choco --version)
☐ Connexion avec VDI-User / SecurePass!
☐ Interface en français
☐ Clavier AZERTY
```

---

### 9. Structure XML résultante (extraits clés)

```xml
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">

    <!-- Langue et clavier -->
    <settings pass="windowsPE">
        <component name="Microsoft-Windows-International-Core-WinPE">
            <InputLocale>fr-FR</InputLocale>
            <SystemLocale>fr-FR</SystemLocale>
            <UILanguage>fr-FR</UILanguage>
            <UserLocale>fr-FR</UserLocale>
        </component>

        <!-- Partitionnement auto -->
        <component name="Microsoft-Windows-Setup">
            <DiskConfiguration>
                <Disk wcm:action="add">
                    <DiskID>0</DiskID>
                    <WillWipeDisk>true</WillWipeDisk>
                    <!-- Partitions UEFI/GPT créées automatiquement -->
                </Disk>
            </DiskConfiguration>
            <UserData>
                <AcceptEula>true</AcceptEula>
            </UserData>
        </component>
    </settings>

    <!-- Configuration machine -->
    <settings pass="specialize">
        <component name="Microsoft-Windows-Shell-Setup">
            <TimeZone>Romance Standard Time</TimeZone>
        </component>
    </settings>

    <!-- OOBE et utilisateur -->
    <settings pass="oobeSystem">
        <component name="Microsoft-Windows-Shell-Setup">
            <OOBE>
                <HideEULAPage>true</HideEULAPage>
                <HideOnlineAccountScreens>true</HideOnlineAccountScreens>
                <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>
                <ProtectYourPC>3</ProtectYourPC>
            </OOBE>

            <UserAccounts>
                <LocalAccounts>
                    <LocalAccount wcm:action="add">
                        <Name>VDI-User</Name>
                        <DisplayName>Utilisateur VDI</DisplayName>
                        <Group>Users</Group>
                        <Password>
                            <Value>SecurePass!</Value>
                            <PlainText>false</PlainText>
                        </Password>
                    </LocalAccount>
                </LocalAccounts>
            </UserAccounts>
        </component>
    </settings>

</unattend>
```

---

### 10. Commandes de vérification PowerShell

```powershell
# Vérifier la taille de l'ISO
$ISO = Get-Item "G:\ISO\Win11_VDI_Lite_Golden_v1.0.iso"
[math]::Round($ISO.Length / 1GB, 2)
# Objectif : < 4.0 GB

# Après installation en VM :

# Taille disque utilisée
(Get-PSDrive C).Used / 1GB
# Objectif : < 20 GB

# Services actifs
(Get-Service | Where-Object {$_.Status -eq 'Running'}).Count
# Objectif : < 120

# RAM disponible
(Get-Counter '\Memory\Available MBytes').CounterSamples.CookedValue
# Objectif : > 2000 MB (sur 4 GB total)

# Chocolatey installé ?
choco --version
# Doit retourner une version (ex: 2.2.2)

# Drivers VirtIO chargés ?
Get-PnpDevice | Where-Object {$_.FriendlyName -like "*VirtIO*"}
# Doit afficher 2-4 devices
```

</details>

---

## Félicitations !

Vous avez terminé la formation **NTLite Mastery** et créé une **Golden Image production-ready** pour un environnement VDI.

Vous maîtrisez maintenant :
- ✅ L'optimisation de Windows à l'échelle entreprise
- ✅ L'intégration de drivers et mises à jour
- ✅ L'automatisation complète du déploiement
- ✅ La maintenance et le versioning d'images

**Vous êtes officiellement un Image Master.** 🎓

N'hésitez pas à partager vos créations et à contribuer à la communauté !

---

**Retour au :** [Programme de la Formation](index.md) | [Catalogue des Formations](../index.md)

---

## Navigation

| | |
|:---|---:|
| [← Module 4 : Automatisation - L'Install...](04-module.md) | [Module 6 : Cas d'Usage Avancé - ISO S... →](06-scenario-vpn.md) |

[Retour au Programme](index.md){ .md-button }
