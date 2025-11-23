# Module 6 : Cas d'Usage Avancé - ISO Sécurisé (VPN & Certificats)

`#ntlite` `#windows` `#vpn` `#globalprotect` `#pki` `#enterprise` `#post-setup`

**Durée estimée :** 4 heures

---

## 🎯 Objectifs du Module

Ce module présente un **scénario entreprise réel** : la création d'une ISO Windows sécurisée intégrant :

- 🔐 **Client VPN GlobalProtect** (Palo Alto Networks)
- 📜 **Certificats Root CA** de l'entreprise
- 🛡️ **Outils de sécurité** (CrowdStrike, agents de monitoring)
- ⚙️ **Configuration pré-déployée** via Registry et Post-Setup

**Cas d'usage :** Déploiement massif de postes sécurisés nécessitant une connexion VPN dès le premier démarrage, avant même l'authentification utilisateur.

---

## 📋 Contexte Métier

### Problématique Entreprise

Dans un environnement Zero Trust, les postes de travail doivent :

1. **Se connecter au VPN** avant le logon utilisateur (Pre-Logon VPN)
2. **Valider les certificats** de l'infrastructure interne (PKI)
3. **Installer les agents de sécurité** dès le premier boot
4. **Minimiser les interventions manuelles** post-installation

### Solution : ISO Pré-Configurée

L'ISO intègre tous les composants nécessaires et les configure automatiquement via :

- **NTLite Integration** : Fichiers, certificats, exécutables
- **Post-Setup Commands** : Installation silencieuse et configuration Registry
- **Unattended.xml** : OOBE automatisée

---

## 🛠️ Prérequis

!!! info "Fichiers & Outils Nécessaires"

    **Logiciels :**

    - NTLite 2024+ (version complète recommandée)
    - GlobalProtect MSI (exemple : `GlobalProtect64-6.2.msi`)
    - ISO Windows 10/11 officielle

    **Fichiers de Configuration :**

    - Certificats Root CA au format `.cer` ou `.crt`
    - Portal GlobalProtect de l'entreprise (exemple : `vpn.entreprise.com`)
    - Fichiers de configuration spécifiques (agents, scripts)

    **Droits :**

    - Administrateur local pour NTLite
    - Accès à un dossier de travail (exemple : `D:\NTLite\PROJET_ISO\`)

---

## 📁 Structure du Projet

Organisation du dossier de travail pour ce scénario :

```
D:\NTLite\PROJET_ISO\
│
├── ISO_SOURCE\                      # ISO Windows montée/extraite
│   ├── sources\
│   │   ├── boot.wim
│   │   └── install.wim
│   └── ...
│
├── INTEGRATION\                     # Fichiers à intégrer
│   ├── VPN\
│   │   └── GlobalProtect64-6.2.msi
│   │
│   ├── Certificates\
│   │   ├── RootCA-Entreprise.cer
│   │   ├── SubCA-Infra.cer
│   │   └── SubCA-Users.cer
│   │
│   ├── Security\
│   │   ├── CrowdStrike-Installer.exe
│   │   └── monitoring-agent.msi
│   │
│   └── Scripts\
│       └── configure-vpn.ps1
│
├── POST_SETUP\                      # Commandes Post-Setup NTLite
│   └── (défini dans l'interface NTLite)
│
└── ISO_FINALE\                      # ISO générée
    └── Windows11_Enterprise_VPN.iso
```

---

## 🔧 Phase 1 : Préparation de l'Image

### 1.1 Charger l'Image dans NTLite

1. **Lancer NTLite** et créer un nouveau projet
2. **Add Image Directory** → Sélectionner `D:\NTLite\PROJET_ISO\ISO_SOURCE\`
3. Choisir **install.wim** → Index **Windows 11 Enterprise**
4. **Load** l'image

### 1.2 Désactiver les Composants Inutiles (Debloat Léger)

!!! warning "Attention aux Dépendances"
    Pour un scénario VPN/Sécurité, garder les composants réseau critiques :

    - **Ne PAS supprimer :** Windows Defender, Firewall, Hyper-V (si VPN nécessite)
    - **OK pour supprimer :** Xbox, Cortana, OneDrive (selon politique entreprise)

**Composants à désactiver (exemples) :**

- Windows Media Player (legacy)
- Internet Explorer 11
- XPS Services
- Fax & Scan

**Vérifier Compatibility :**

- Activer **Compatibility** mode dans NTLite
- Vérifier qu'aucun composant VPN/réseau n'est marqué en rouge

---

## 📦 Phase 2 : Intégration des Fichiers

### 2.1 Intégrer le Client VPN GlobalProtect

**Étape :** `Files` → `Add Files/Folders`

| Source | Destination dans l'ISO |
|--------|------------------------|
| `D:\NTLite\PROJET_ISO\INTEGRATION\VPN\GlobalProtect64-6.2.msi` | `C:\Windows\Setup\Files\GlobalProtect64-6.2.msi` |

!!! tip "Chemin Recommandé"
    `C:\Windows\Setup\Files\` est un emplacement standard non nettoyé par Windows Update.

### 2.2 Intégrer les Certificats Root CA

**Étape :** `Files` → `Add Files/Folders`

| Certificat | Destination |
|------------|-------------|
| `RootCA-Entreprise.cer` | `C:\Windows\Setup\Files\Certificates\RootCA-Entreprise.cer` |
| `SubCA-Infra.cer` | `C:\Windows\Setup\Files\Certificates\SubCA-Infra.cer` |
| `SubCA-Users.cer` | `C:\Windows\Setup\Files\Certificates\SubCA-Users.cer` |

### 2.3 Intégrer les Outils de Sécurité

| Outil | Destination |
|-------|-------------|
| `CrowdStrike-Installer.exe` | `C:\Windows\Setup\Files\Security\CrowdStrike-Installer.exe` |
| `monitoring-agent.msi` | `C:\Windows\Setup\Files\Security\monitoring-agent.msi` |

---

## ⚙️ Phase 3 : Configuration Post-Setup

### 3.1 Principe des Post-Setup Commands

NTLite propose deux types de commandes dans l'onglet **Post-Setup** :

| Type | Exécution | Contexte | Usage |
|------|-----------|----------|-------|
| **Run** | Asynchrone | SYSTEM | Scripts indépendants, agents |
| **Command** | Synchrone | SYSTEM | Installations critiques, Registry |

!!! warning "Ordre d'Exécution Critique"
    Les commandes sont exécutées **dans l'ordre de la liste NTLite**, après le premier boot, avant l'OOBE.

### 3.2 Installation des Certificats Root CA

**Objectif :** Installer les certificats dans le magasin **Trusted Root Certification Authorities** du système.

**Post-Setup Command :**

```powershell
# Type: Command (Synchrone)
# Description: Install Root CA - Entreprise

certutil.exe -addstore -f "Root" "C:\Windows\Setup\Files\Certificates\RootCA-Entreprise.cer"
```

```powershell
# Type: Command (Synchrone)
# Description: Install SubCA - Infrastructure

certutil.exe -addstore -f "CA" "C:\Windows\Setup\Files\Certificates\SubCA-Infra.cer"
```

```powershell
# Type: Command (Synchrone)
# Description: Install SubCA - Users

certutil.exe -addstore -f "CA" "C:\Windows\Setup\Files\Certificates\SubCA-Users.cer"
```

!!! info "Magasins de Certificats"
    - **Root** : Autorités racines de confiance (Root CA)
    - **CA** : Autorités intermédiaires (Subordinate CA)
    - **My** : Certificats personnels (utilisé pour les certificats machine/utilisateur)

### 3.3 Installation Silencieuse de GlobalProtect

**Post-Setup Command :**

```batch
REM Type: Command (Synchrone)
REM Description: Install GlobalProtect VPN Client

msiexec.exe /i "C:\Windows\Setup\Files\GlobalProtect64-6.2.msi" /qn /norestart PORTAL=vpn.entreprise.com HIDETRAY=NO
```

**Paramètres MSI :**

| Paramètre | Valeur | Description |
|-----------|--------|-------------|
| `/i` | `GlobalProtect64-6.2.msi` | Install mode |
| `/qn` | - | Silent installation (no UI) |
| `/norestart` | - | Ne pas redémarrer après installation |
| `PORTAL` | `vpn.entreprise.com` | Adresse du portail GlobalProtect |
| `HIDETRAY` | `NO` | Afficher l'icône dans la barre système |

!!! tip "Paramètres Additionnels GlobalProtect"
    Consulter la documentation Palo Alto pour :

    - `PRELOGON=YES` : Activer le VPN pré-logon
    - `USERAUTHENTICATION=SAML` : Méthode d'authentification
    - `CONNECTMETHOD=pre-logon` : Connexion automatique avant logon

### 3.4 Configuration Registry pour Pre-Logon VPN

**Objectif :** Activer la fonctionnalité Pre-Logon de GlobalProtect via le Registre.

**Post-Setup Command :**

```batch
REM Type: Command (Synchrone)
REM Description: Enable GlobalProtect Pre-Logon

reg.exe add "HKLM\SOFTWARE\Palo Alto Networks\GlobalProtect\Settings" /v "PortalAddress" /t REG_SZ /d "vpn.entreprise.com" /f
```

```batch
REM Type: Command (Synchrone)
REM Description: Enable Pre-Logon Mode

reg.exe add "HKLM\SOFTWARE\Palo Alto Networks\GlobalProtect\Settings" /v "PreLogon" /t REG_DWORD /d 1 /f
```

```batch
REM Type: Command (Synchrone)
REM Description: Hide Tray Icon for Standard Users

reg.exe add "HKLM\SOFTWARE\Palo Alto Networks\GlobalProtect\Settings" /v "HideTrayIcon" /t REG_DWORD /d 0 /f
```

**Clés Registry Importantes :**

| Clé | Type | Valeur | Description |
|-----|------|--------|-------------|
| `PortalAddress` | REG_SZ | `vpn.entreprise.com` | URL du portail GP |
| `PreLogon` | REG_DWORD | `1` | Activer VPN pré-logon |
| `HideTrayIcon` | REG_DWORD | `0` | Afficher icône (0=visible) |
| `ConnectMethod` | REG_SZ | `on-demand` | Mode de connexion |

### 3.5 Installation des Agents de Sécurité

**CrowdStrike Falcon :**

```batch
REM Type: Run (Asynchrone)
REM Description: Install CrowdStrike Falcon Agent

"C:\Windows\Setup\Files\Security\CrowdStrike-Installer.exe" /install /quiet /norestart CID=VOTRE-CUSTOMER-ID
```

**Agent de Monitoring :**

```batch
REM Type: Command (Synchrone)
REM Description: Install Monitoring Agent

msiexec.exe /i "C:\Windows\Setup\Files\Security\monitoring-agent.msi" /qn SERVER=monitor.entreprise.com
```

---

## 🎨 Phase 4 : Configuration Unattended (OOBE)

### 4.1 Paramètres Unattended Recommandés

**Onglet NTLite : Unattended**

| Section | Paramètre | Valeur | Objectif |
|---------|-----------|--------|----------|
| **Settings → Display** | Skip User OOBE | ✅ Enabled | Passer les questions utilisateur |
| **Settings → Privacy** | Disable Telemetry | ✅ Enabled | Conformité RGPD |
| **Settings → Privacy** | Disable Advertising ID | ✅ Enabled | Désactiver tracking |
| **User Accounts** | Administrator | `Admin` / `P@ssw0rd!` | Compte admin temporaire |
| **Autologon** | Enable Autologon | ✅ 1 time | Premier boot automatique |
| **Computer Name** | Pattern | `PC-%RAND:6%` | Nom unique généré |

!!! danger "Sécurité du Compte Administrateur"
    Le compte admin temporaire doit être :

    - **Désactivé** après le déploiement (via GPO ou script)
    - **Mot de passe complexe** conforme à la politique entreprise
    - **Remplacé** par un compte admin local LAPS (Local Admin Password Solution)

### 4.2 Exemple Autounattend.xml (Extrait)

Le fichier généré par NTLite contiendra :

```xml
<component name="Microsoft-Windows-Shell-Setup">
    <OOBE>
        <HideEULAPage>true</HideEULAPage>
        <HideOEMRegistrationScreen>true</HideOEMRegistrationScreen>
        <HideOnlineAccountScreens>true</HideOnlineAccountScreens>
        <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>
        <ProtectYourPC>3</ProtectYourPC> <!-- Disable privacy questions -->
    </OOBE>
    <UserAccounts>
        <AdministratorPassword>
            <Value>UABAAHMAcwB3ADAAcgBkACEA</Value> <!-- Base64: P@ssw0rd! -->
            <PlainText>false</PlainText>
        </AdministratorPassword>
    </UserAccounts>
    <AutoLogon>
        <Enabled>true</Enabled>
        <Username>Administrator</Username>
        <Password>
            <Value>UABAAHMAcwB3ADAAcgBkACEA</Value>
            <PlainText>false</PlainText>
        </Password>
        <LogonCount>1</LogonCount>
    </AutoLogon>
</component>
```

---

## 🚀 Phase 5 : Création de l'ISO

### 5.1 Vérification Finale

**Checklist avant Apply :**

- [ ] Tous les fichiers sont dans `Files` (VPN, Certificats, Agents)
- [ ] Post-Setup Commands dans le bon ordre
- [ ] Unattended configuré (OOBE skip, autologon)
- [ ] Compatibility mode activé (pas d'erreurs rouges)

### 5.2 Apply & Create ISO

1. **Pending Changes** → Vérifier la liste des modifications
2. **Process** → **Apply**
3. Attendre la fin du traitement (15-30 minutes)
4. **Create ISO** → Choisir la destination :
   ```
   D:\NTLite\PROJET_ISO\ISO_FINALE\Windows11_Enterprise_VPN.iso
   ```

### 5.3 Options de Création ISO

| Option | Recommandation | Raison |
|--------|----------------|--------|
| **Label** | `WIN11_ENT_VPN` | Identification claire |
| **Bootable** | ✅ Enabled | ISO bootable sur USB/VM |
| **File System** | UDF | Compatible UEFI |

---

## 🧪 Phase 6 : Test & Validation

### 6.1 Déploiement de Test (VM)

**Environnement recommandé :**

- **Hyperviseur :** Hyper-V, VMware Workstation, VirtualBox
- **Specs VM :**
  - 4 GB RAM minimum
  - 2 vCPU
  - 60 GB disk (UEFI boot)
  - Network adapter en mode **Bridged** (pour test VPN)

### 6.2 Checklist de Validation

!!! check "Validation Post-Déploiement"

    **Étape 1 : Premier Boot**

    - [ ] L'OOBE est automatiquement passée (aucune question posée)
    - [ ] Autologon fonctionne (connexion automatique en `Administrator`)
    - [ ] Le bureau Windows s'affiche sans erreur

    **Étape 2 : Vérification des Certificats**

    Ouvrir une console PowerShell **en Administrateur** :

    ```powershell
    # Lister les certificats Root CA
    Get-ChildItem -Path Cert:\LocalMachine\Root | Where-Object { $_.Subject -like "*Entreprise*" }

    # Lister les certificats SubCA
    Get-ChildItem -Path Cert:\LocalMachine\CA | Where-Object { $_.Subject -like "*Infra*" }
    ```

    **Résultat attendu :**
    ```
    Subject: CN=RootCA-Entreprise, O=Entreprise, C=FR
    Thumbprint: A1B2C3D4E5F6...
    ```

    **Étape 3 : Vérification GlobalProtect**

    ```batch
    REM Vérifier l'installation du service
    sc query PanGPS

    REM Vérifier les clés Registry
    reg query "HKLM\SOFTWARE\Palo Alto Networks\GlobalProtect\Settings"
    ```

    **Résultat attendu :**
    ```
    SERVICE_NAME: PanGPS
    STATE       : RUNNING

    PortalAddress    REG_SZ    vpn.entreprise.com
    PreLogon         REG_DWORD 0x1
    ```

    **Étape 4 : Test de Connexion VPN**

    - [ ] L'icône GlobalProtect est visible dans la barre système
    - [ ] Cliquer sur l'icône → Le portail `vpn.entreprise.com` est pré-rempli
    - [ ] Se connecter avec des identifiants de test
    - [ ] Vérifier la connexion : `ipconfig /all` (adapter VPN actif)

    **Étape 5 : Vérification Agents de Sécurité**

    ```powershell
    # CrowdStrike Falcon
    Get-Service -Name CSFalconService

    # Monitoring Agent
    Get-Service -Name MonitoringAgent
    ```

    **Résultat attendu :**
    ```
    Status   Name               DisplayName
    ------   ----               -----------
    Running  CSFalconService    CrowdStrike Falcon Sensor
    Running  MonitoringAgent    Enterprise Monitoring Agent
    ```

### 6.3 Test Pre-Logon VPN (Avancé)

**Objectif :** Vérifier que le VPN se connecte **avant** le logon utilisateur.

**Procédure :**

1. **Fermer la session** Windows
2. Sur l'écran de **connexion** (Ctrl+Alt+Del), observer la barre système
3. **Vérifier** que l'icône GlobalProtect est présente
4. **Cliquer** sur l'icône → Connexion VPN disponible avant authentification
5. **Se connecter au VPN**, puis se loguer avec un compte utilisateur

!!! warning "Prérequis Pre-Logon"
    Le Pre-Logon VPN nécessite :

    - **Credential Provider** GlobalProtect installé
    - **Configuration GPO** pour activer le Credential Provider
    - **Réseau accessible** (Ethernet ou Wi-Fi pré-configuré)

---

## 🎯 Phase 7 : Déploiement en Production

### 7.1 Stratégie de Déploiement

**Options de déploiement :**

| Méthode | Cas d'Usage | Avantages |
|---------|-------------|-----------|
| **USB Bootable** | Postes isolés, techniciens terrain | Simple, autonome |
| **MDT/SCCM** | Déploiement massif (100+ postes) | Automatisation complète, reporting |
| **WDS (PXE Boot)** | Réseau LAN, postes fixes | Pas de média physique |
| **ISO Cloud** | VM cloud, Azure/AWS | Déploiement infrastructure as code |

### 7.2 Recommandations Sécurité

!!! danger "Hardening Post-Déploiement"

    **Actions obligatoires après déploiement :**

    1. **Désactiver le compte Admin temporaire** :
       ```powershell
       Disable-LocalUser -Name "Administrator"
       ```

    2. **Activer LAPS** (Local Admin Password Solution) :
       - Installer l'extension AD LAPS
       - Appliquer la GPO LAPS au poste

    3. **Forcer la rotation du mot de passe** :
       ```powershell
       Set-LocalUser -Name "Administrator" -PasswordNeverExpires $false
       ```

    4. **Activer BitLocker** :
       ```powershell
       Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAes256 -RecoveryPasswordProtector
       ```

    5. **Appliquer les GPO de sécurité** :
       - Désactiver SMBv1
       - Activer Windows Defender ATP
       - Configurer les règles Firewall

### 7.3 Documentation de Déploiement

**Créer une fiche technique contenant :**

- **Version de l'ISO** : `Windows11_Enterprise_VPN_v1.2_2024-11`
- **Hash SHA256** : `sha256sum Windows11_Enterprise_VPN.iso`
- **Composants intégrés** :
  - GlobalProtect 6.2.0
  - CrowdStrike Falcon 7.14
  - Certificats Root CA (validité jusqu'au 2030-12-31)
- **Configuration par défaut** :
  - Compte admin : `Administrator` (à désactiver)
  - VPN Portal : `vpn.entreprise.com`
  - PreLogon : Activé
- **Prérequis réseau** :
  - Accès HTTPS port 443 vers `vpn.entreprise.com`
  - DNS résolu (interne ou public)

---

## 📊 Comparaison : Avant/Après NTLite

| Étape | Déploiement Manuel | Déploiement ISO Automatisé |
|-------|-------------------|----------------------------|
| **Installation Windows** | 30 minutes | 30 minutes |
| **Installation GlobalProtect** | 10 minutes | ✅ **Automatique** |
| **Installation Certificats** | 15 minutes (manuel) | ✅ **Automatique** |
| **Configuration VPN** | 10 minutes (Registry) | ✅ **Automatique** |
| **Installation Agents** | 20 minutes | ✅ **Automatique** |
| **OOBE Questions** | 5 minutes | ✅ **Skip (0 min)** |
| **Total** | **90 minutes** | **30 minutes** |
| **Intervention Technicien** | Élevée | ✅ **Minimale** |

**ROI pour 100 postes :**

- Temps économisé : `(90 - 30) × 100 = 6000 minutes = 100 heures`
- Coût technicien (50€/h) : **5000€ économisés**

---

## 🔍 Troubleshooting

### Problème 1 : GlobalProtect ne s'installe pas

**Symptômes :**

- Service `PanGPS` absent
- Aucune icône dans la barre système

**Causes possibles :**

1. **MSI corrompu** : Re-télécharger GlobalProtect depuis le portail Palo Alto
2. **Paramètres MSI incorrects** : Vérifier `PORTAL=vpn.entreprise.com`
3. **Dépendances manquantes** : Installer `.NET Framework 4.8` (intégrer dans NTLite)

**Solution :**

```powershell
# Vérifier les logs d'installation MSI
Get-Content "C:\Windows\Temp\GlobalProtect_Install.log"

# Réinstaller manuellement pour tester
msiexec.exe /i "C:\Windows\Setup\Files\GlobalProtect64-6.2.msi" /L*v "C:\gp-install.log" PORTAL=vpn.entreprise.com
```

### Problème 2 : Certificats non installés

**Symptômes :**

- Erreur SSL lors de la connexion VPN
- `Get-ChildItem Cert:\LocalMachine\Root` ne liste pas les certificats

**Causes possibles :**

1. **Format certificat incorrect** : Utiliser `.cer` ou `.crt` (pas `.pfx`)
2. **Commande certutil échouée** : Vérifier les logs Post-Setup

**Solution :**

```powershell
# Installer manuellement pour tester
certutil.exe -addstore -f "Root" "C:\Windows\Setup\Files\Certificates\RootCA-Entreprise.cer"

# Vérifier l'erreur
echo $LASTEXITCODE  # 0 = succès
```

### Problème 3 : Pre-Logon VPN non disponible

**Symptômes :**

- Pas d'icône GlobalProtect sur l'écran de connexion
- VPN fonctionne uniquement après logon

**Causes possibles :**

1. **Clé Registry `PreLogon` manquante**
2. **Credential Provider non installé** (version GlobalProtect trop ancienne)
3. **GPO bloquant le Credential Provider**

**Solution :**

```batch
REM Vérifier la clé Registry
reg query "HKLM\SOFTWARE\Palo Alto Networks\GlobalProtect\Settings" /v PreLogon

REM Forcer l'activation
reg add "HKLM\SOFTWARE\Palo Alto Networks\GlobalProtect\Settings" /v PreLogon /t REG_DWORD /d 1 /f

REM Redémarrer le service
net stop PanGPS && net start PanGPS
```

### Problème 4 : OOBE non skippée

**Symptômes :**

- Questions de confidentialité, région, clavier apparaissent

**Causes possibles :**

1. **Autounattend.xml mal généré** par NTLite
2. **Paramètres OOBE non cochés** dans l'interface

**Solution :**

- Vérifier dans NTLite : `Unattended → Settings → Skip User OOBE` = **Enabled**
- Ré-appliquer l'image et recréer l'ISO

---

## 📚 Ressources Complémentaires

### Documentation Officielle

- **GlobalProtect Admin Guide** : [Palo Alto Networks Docs](https://docs.paloaltonetworks.com/globalprotect)
- **NTLite Post-Setup** : [NTLite Documentation](https://www.ntlite.com/documentation/)
- **Windows Unattended Reference** : [Microsoft Docs - Answer Files](https://learn.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/)

### Commandes Utiles

```powershell
# Lister tous les certificats installés (Root + CA)
Get-ChildItem -Path Cert:\LocalMachine\Root, Cert:\LocalMachine\CA | Format-Table Subject, Thumbprint

# Exporter la configuration Registry GlobalProtect
reg export "HKLM\SOFTWARE\Palo Alto Networks\GlobalProtect" "C:\gp-config.reg"

# Vérifier les services en cours
Get-Service | Where-Object { $_.DisplayName -like "*Global*" -or $_.DisplayName -like "*Falcon*" }

# Tester la connectivité VPN
Test-NetConnection -ComputerName vpn.entreprise.com -Port 443
```

---

## 🎓 Exercice Pratique

### Énoncé

Vous devez créer une ISO Windows 11 Entreprise pour un client avec les spécifications suivantes :

**Exigences :**

1. **VPN Client :** Cisco AnyConnect (fichier fourni : `anyconnect-win-4.10.msi`)
2. **Certificats :** 2 Root CA (`RootCA-Client.cer`, `RootCA-External.cer`)
3. **Agent EDR :** SentinelOne (`SentinelInstaller.exe`)
4. **Configuration VPN :**
   - Portal : `vpn-client.example.com`
   - Pre-Logon activé
5. **OOBE :** Complètement automatisée
6. **Compte admin :** `LocalAdmin` / `C0mpl3xP@ss!`

**Tâches :**

1. Créer la structure de dossiers pour le projet
2. Lister les Post-Setup Commands nécessaires (ordre et type)
3. Identifier les clés Registry pour Cisco AnyConnect Pre-Logon
4. Créer la checklist de validation

### Solution (Aperçu)

<details>
<summary>Cliquer pour afficher la solution</summary>

**Structure de Dossiers :**

```
D:\NTLite\CLIENT_ISO\
├── ISO_SOURCE\
├── INTEGRATION\
│   ├── VPN\anyconnect-win-4.10.msi
│   ├── Certificates\RootCA-Client.cer
│   ├── Certificates\RootCA-External.cer
│   └── Security\SentinelInstaller.exe
└── ISO_FINALE\
```

**Post-Setup Commands (ordre) :**

```batch
REM 1. Certificats (Command - Synchrone)
certutil.exe -addstore -f "Root" "C:\Windows\Setup\Files\Certificates\RootCA-Client.cer"
certutil.exe -addstore -f "Root" "C:\Windows\Setup\Files\Certificates\RootCA-External.cer"

REM 2. Installation VPN (Command - Synchrone)
msiexec.exe /i "C:\Windows\Setup\Files\anyconnect-win-4.10.msi" /qn /norestart PRE_DEPLOY_DISABLE_VPN=0 LOCKDOWN=1

REM 3. Configuration VPN Registry (Command - Synchrone)
reg.exe add "HKLM\SOFTWARE\Cisco\Cisco AnyConnect Secure Mobility Client" /v "ServerAddress" /t REG_SZ /d "vpn-client.example.com" /f
reg.exe add "HKLM\SOFTWARE\Cisco\Cisco AnyConnect Secure Mobility Client" /v "EnablePreLogon" /t REG_DWORD /d 1 /f

REM 4. Installation SentinelOne (Run - Asynchrone)
"C:\Windows\Setup\Files\Security\SentinelInstaller.exe" /quiet /site-token=VOTRE_TOKEN
```

**Unattended Settings :**

- Skip User OOBE : ✅
- Administrator : `LocalAdmin` / `C0mpl3xP@ss!`
- Autologon : 1 time

**Checklist Validation :**

- [ ] Certificats installés : `Get-ChildItem Cert:\LocalMachine\Root`
- [ ] Service VPN : `sc query vpnagent`
- [ ] Registry VPN : `reg query "HKLM\SOFTWARE\Cisco\Cisco AnyConnect Secure Mobility Client"`
- [ ] SentinelOne : `Get-Service -Name SentinelAgent`
- [ ] Pre-Logon : Icône Cisco sur écran de connexion

</details>

---

## 🎯 Points Clés à Retenir

!!! success "Résumé du Module"

    **Compétences Acquises :**

    ✅ Intégrer un client VPN entreprise (GlobalProtect, AnyConnect) dans une ISO
    ✅ Installer des certificats Root CA via Post-Setup (`certutil`)
    ✅ Configurer le Pre-Logon VPN via Registry (`reg.exe`)
    ✅ Automatiser l'installation d'agents de sécurité (EDR, monitoring)
    ✅ Créer une ISO "ready-to-deploy" conforme aux exigences Zero Trust

    **Différence Run vs Command :**

    - **Command** : Installation critique, ordre strict (VPN, Certificats)
    - **Run** : Agents indépendants, peuvent s'exécuter en parallèle

    **ROI Déploiement :**

    - Temps économisé : **60 minutes par poste**
    - Réduction erreurs humaines : **90%**
    - Conformité sécurité : **Garantie dès le premier boot**

---

## 🚀 Prochaine Étape

Ce module complète la formation **NTLite Mastery** avec un cas d'usage entreprise réel.

**Pour aller plus loin :**

- **Module 7 (Optionnel) :** Intégration MDT/SCCM avec ISO NTLite
- **Module 8 (Optionnel) :** Création d'ISO multi-langues (MUI)
- **Certification :** Windows Deployment Specialist (autodidacte)

**Projet Final Suggéré :**

Créer une ISO complète pour votre entreprise incluant :

- Client VPN (choix : GlobalProtect, AnyConnect, Fortinet)
- Certificats PKI internes
- Suite Office 365 (déploiement silencieux)
- Agents de sécurité (EDR + DLP)
- Configuration SCCM Client
- Hardening Niveau 2 (CIS Benchmark)

---

**🎓 Félicitations ! Vous maîtrisez maintenant les scénarios avancés NTLite pour des déploiements entreprise sécurisés.**
