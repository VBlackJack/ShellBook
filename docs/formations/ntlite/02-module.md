---
tags:
  - formation
  - ntlite
  - windows
  - customization
  - module
---

# Module 2 : Le Grand Nettoyage (Debloating)

## Introduction

> **"Less is More"**

Dans le monde du déploiement Windows, cette maxime prend tout son sens. Un système d'exploitation allégé, c'est :

- ✅ **Moins de surface d'attaque** pour les vulnérabilités
- ✅ **Temps de démarrage réduits** (moins de services à lancer)
- ✅ **Consommation mémoire optimisée** (crucial sur des machines avec 4-8 GB RAM)
- ✅ **Mises à jour plus rapides** (moins de composants = moins de patches)
- ✅ **Image ISO plus compacte** (économies de stockage et bande passante)

Le debloating n'est pas du "tuning amateur" : c'est une approche professionnelle pour créer des images adaptées à vos cas d'usage métier.

---

## Concept : Sécurité & Stabilité

### Dependency Hell

La suppression de composants n'est **PAS sans risque** :

```
Vous supprimez : "Windows Media Player"
Conséquence cachée : Certaines applications métier utilisent ses codecs
Résultat : L'app métier ne démarre plus ❌
```

**Le piège classique** :
- Supprimer "WLAN AutoConfig" → Plus de Wi-Fi fonctionnel
- Supprimer "Print Spooler" → L'imprimante réseau devient invisible
- Supprimer "Windows Search" → Outlook ne peut plus indexer les emails

### La Fonctionnalité "Compatibility"

NTLite intègre un système de **protection intelligente** :

1. **Verrouillage de dépendances** :
   - Si vous activez "Compatibility" pour le Wi-Fi, NTLite empêche la suppression de `WLAN AutoConfig`
   - Les composants critiques sont marqués avec ⚠️

2. **Indicateurs visuels** :
   - 🟢 Vert : Sans risque
   - 🟡 Jaune : Attention, impact possible
   - 🔴 Rouge : Composant système critique

3. **Pending Changes** :
   - Toujours vérifier cet onglet avant d'appliquer
   - NTLite vous alerte sur les conflits potentiels

### Privacy : La Face Cachée de Windows

Composants à surveiller pour la confidentialité :

| Composant | Impact Privacy | Recommandation |
|-----------|----------------|----------------|
| **DiagTrack** | Télémétrie complète vers Microsoft | ❌ Supprimer (sauf contrainte GPO) |
| **Advertising ID** | Profilage publicitaire | ❌ Supprimer |
| **Cortana** | Envoi requêtes vocales au cloud | ❌ Supprimer (inutile en entreprise) |
| **OneDrive** | Synchronisation cloud automatique | ⚠️ Selon politique IT |
| **Bing dans la recherche** | Requêtes réseau lors de recherches locales | ❌ Désactiver |

---

## Pratique : La "Kill List" Standard

### Modern Apps (UWP)

Les applications UWP (Universal Windows Platform) sont souvent superflues en environnement professionnel :

#### Xbox Ecosystem
```
- Xbox Game Bar
- Xbox Identity Provider
- Xbox Live Services
- Xbox Speech to Text Overlay
```
**Impact** : Économie de ~200 MB + services en arrière-plan désactivés

#### Bloatware Classique
```
- Microsoft Solitaire Collection
- Mixed Reality Portal
- Skype (version UWP, pas le client Pro)
- 3D Viewer / Paint 3D
- Weather / News / Maps (sauf besoins spécifiques)
```

#### Cas Particulier : Microsoft Store
⚠️ **Attention** : Certaines entreprises utilisent le Store pour déployer des apps métier (LOB apps)
- Si vous utilisez InTune/Endpoint Manager → **Conserver**
- Pour un poste fixe isolé → Peut être supprimé

### System Components

#### Cortana
```
Chemin NTLite : Components > System > Cortana
```
- Économie : ~50 MB
- Services désactivés : `CDPUserSvc`, `OneSyncSvc`
- **Effet de bord** : La barre de recherche Windows reste fonctionnelle

#### OneDrive
```
Chemin NTLite : Components > System > OneDrive
```
⚠️ **Décision métier** :
- Si votre entreprise utilise SharePoint/OneDrive → **Conserver**
- Pour un environnement on-premise pur → Supprimer

#### Edge (Chromium)
```
Chemin NTLite : Components > Browsers > Microsoft Edge
```
🚨 **DANGER** : Depuis Windows 11, Edge est intégré à plusieurs composants système
- **Recommandation 2025** : Ne PAS supprimer, désactiver via GPO à la place
- Alternative : Bloquer via Registry (`HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate`)

### Hardware Support

#### Drivers Obsolètes
Pour gagner de l'espace sur des environnements standardisés :

| Driver | Cas d'usage | Économie |
|--------|-------------|----------|
| **Floppy Disk** | Héritage MS-DOS | ~5 MB |
| **Serial/Parallel Ports** | Ancien matériel industriel | ~10 MB |
| **Modem** | Connexion RTC (obsolète) | ~8 MB |
| **Infrared** | PDA années 2000 | ~3 MB |

**Méthode** :
```
NTLite > Drivers > [Sélectionner le driver] > Remove
```

⚠️ **Exception** : Si vous gérez du matériel industriel (automates, caisses enregistreuses), vérifier avant suppression !

---

## Exercice : "Profil Comptable"

### Scenario

Vous préparez une image pour le **service comptabilité** :
- Utilisateurs non-techniques
- Besoin : Sage/EBP, Excel, PDF, Impression réseau
- Contraintes : Zéro distraction, stabilité maximale

### Mission

1. **Charger votre image Windows 11 Pro** dans NTLite (celle créée au Module 1)

2. **Activer "Compatibility" pour** :
   - 🖨️ **Printing** (Print Spooler + drivers réseau)
   - 🌐 **RDP** (Remote Desktop - pour le support IT)
   - 🔍 **Network Discovery** (partages réseau Samba/SMB)

3. **Supprimer les composants suivants** :
   - Tout l'écosystème Xbox (4 composants)
   - Geo-location Services (vie privée)
   - Retail Demo Content (démos en magasin)
   - Windows Insider Hub (bêta-testeurs)
   - Mixed Reality Portal
   - Cortana
   - OneDrive (l'entreprise utilise un NAS local)

4. **Vérifier l'onglet "Pending Changes"** :
   - Aucun warning rouge ne doit apparaître
   - Confirmer que Print Spooler est toujours présent

### Validation

Avant d'appliquer, vérifiez :
- [ ] Aucune dépendance cassée dans "Pending Changes"
- [ ] Le composant "Print Spooler" est présent (vital pour l'impression)
- [ ] La taille estimée de l'image a diminué d'au moins 300 MB
- [ ] Les services réseau (SMB, TCP/IP) sont intacts

---

## Solution

<details>
<summary>📋 Checklist Complète (Cliquez pour déplier)</summary>

### ✅ Composants à CONSERVER

```
[Système]
✓ Print Spooler (impression)
✓ Remote Desktop Services (support IT)
✓ SMB 1.0/CIFS (partages réseau anciens si nécessaire)
✓ Windows Defender (sécurité de base)
✓ Windows Update (patches critiques)
✓ .NET Framework 3.5 + 4.8 (applications métier)
✓ Windows Search (indexation Outlook si utilisé)

[Réseau]
✓ Network Discovery
✓ TCP/IP Stack
✓ DNS Client
✓ DHCP Client

[Hardware]
✓ USB Support
✓ SATA/NVMe Drivers
✓ Network Adapters (Ethernet)
```

### ❌ Composants à SUPPRIMER

```
[UWP Apps]
✗ Xbox Game Bar
✗ Xbox Identity Provider
✗ Xbox Live Services
✗ Xbox Speech to Text Overlay
✗ Microsoft Solitaire Collection
✗ Mixed Reality Portal
✗ 3D Viewer
✗ Paint 3D

[Système]
✗ Cortana
✗ OneDrive
✗ Retail Demo Content
✗ Windows Insider Hub
✗ Geo-location Service
✗ Advertising ID

[Hardware - Si non utilisé]
✗ Floppy Disk Support
✗ Modem Support
✗ Infrared Support
✗ Serial Port Support (sauf si TPE/automates)
```

### 📊 Résultat Attendu

| Métrique | Avant | Après | Gain |
|----------|-------|-------|------|
| Taille ISO | ~4.8 GB | ~4.3 GB | **-500 MB** |
| Services au boot | ~180 | ~145 | **-35 services** |
| RAM au démarrage | ~2.1 GB | ~1.7 GB | **-400 MB** |
| Apps UWP | ~40 | ~15 | **-25 apps** |

### ⚠️ Points de Vigilance

1. **Test d'impression réseau** : Toujours valider après déploiement
2. **Partages réseau** : Vérifier l'accès au NAS en `\\serveur\compta`
3. **Applications métier** : Tester Sage/EBP sur la machine cible
4. **Mises à jour** : Vérifier que Windows Update fonctionne toujours

</details>

---

## Points Clés à Retenir

1. **Toujours activer "Compatibility"** avant de supprimer des composants
2. **Le debloating n'est pas une course** : mieux vaut conserver un composant douteux que casser une fonctionnalité
3. **Tester sur VM avant production** : 1 machine test = 100 tickets de support évités
4. **Documenter vos choix** : Créer un fichier `REMOVED_COMPONENTS.md` dans votre repo

---

## Prochaine Étape

Dans le **Module 3**, nous verrons :
- 🔧 **Tweaks & Registry** : Les modifications avancées (désactiver Windows Update, personnaliser l'interface)
- 🎨 **Customization** : Fonds d'écran, thèmes, paramètres par défaut
- 📦 **Unattended Setup** : Automatiser l'installation (AutoUnattend.xml)

Rendez-vous au prochain module pour transformer votre image allégée en **machine de guerre configurée** !
