---
tags:
  - ntlite
  - windows
  - customization
  - iso
  - deployment
---

# NTLite : Maîtriser l'Image Windows

## Introduction

> **"L'image parfaite n'existe pas... jusqu'à ce que vous la créiez."**

**NTLite** est l'outil de référence pour **personnaliser les images Windows** (ISO) avant déploiement. Que vous soyez administrateur système, technicien de déploiement ou passionné d'optimisation, NTLite vous permet de créer des images Windows **sur mesure** qui répondent exactement à vos besoins.

**Pourquoi personnaliser une image Windows ?**

| Problème avec les ISOs standard | Solution avec NTLite |
|----------------------------------|----------------------|
| **Bloatware** : Applications inutiles (Candy Crush, Xbox, etc.) | Suppression complète avant installation |
| **Empreinte disque** : Windows 11 = 25+ GB | Réduction à 10-15 GB (debloating) |
| **Mises à jour** : Installer Windows → Attendre 2h d'updates | Intégration des updates dans l'ISO |
| **Drivers manquants** : Pas de réseau après installation | Intégration drivers (WiFi, Ethernet, GPU) |
| **Configuration manuelle** : OOBE, création utilisateur, etc. | Automatisation complète (Unattended) |
| **Multiples éditions** : Pro/Enterprise/Education dans 1 ISO | Extraction d'une seule édition (gain 5+ GB) |

**Cas d'usage réels :**

- 🏢 **Entreprise** : Déployer 500 postes avec une image standardisée (drivers, apps, config)
- 🎮 **Gaming** : Windows optimisé sans bloatware (gain 30% RAM)
- 💻 **Technicien** : ISO réparation avec drivers intégrés
- 🔧 **Passionné** : Windows minimal pour machines virtuelles
- 🏫 **Éducation** : Image verrouillée pour salles de TP

---

## Qu'est-ce que NTLite ?

**NTLite** est un logiciel Windows (gratuit en version Free, payant en version Pro) qui permet de :

- ✅ **Charger** une image Windows (ISO, WIM, ESD)
- ✅ **Modifier** l'image :
  - Supprimer des composants (Debloating)
  - Intégrer des drivers
  - Intégrer des mises à jour (Cumulative Updates)
  - Configurer les paramètres système
  - Créer un fichier Unattended (installation automatisée)
- ✅ **Exporter** l'image modifiée (nouvelle ISO bootable)

**Versions :**

| Version | Prix | Limitations |
|---------|------|-------------|
| **Free** | 🆓 Gratuit | Modifications limitées (max 10 composants supprimés) |
| **Home** | 💰 ~40€ | Usage personnel, 1 PC |
| **Professional** | 💰 ~70€ | Usage commercial, 3 PCs |
| **Business** | 💰 ~300€ | Entreprise, 10+ PCs |

**Note :** Pour ce cours, la version **Free** suffit pour apprendre les concepts. En production, utiliser **Professional** ou **Business**.

---

## Objectifs de la Formation

À la fin de cette formation, vous serez capable de :

1. ✅ **Comprendre** l'architecture des images Windows (WIM, ESD, ISO)
2. ✅ **Charger et monter** une image dans NTLite
3. ✅ **Supprimer** les applications et composants inutiles (Debloating)
4. ✅ **Intégrer** des drivers et mises à jour
5. ✅ **Automatiser** l'installation avec un fichier Unattended
6. ✅ **Créer** une ISO bootable personnalisée
7. ✅ **Déployer** l'image sur des machines physiques/virtuelles

---

## Programme de la Formation

### 📘 Module 1 : Prise en main & Architecture WIM

**Durée :** 2 heures

**Contenu :**

- Comprendre les formats d'image Windows (ISO, WIM, ESD)
- Architecture du fichier `install.wim` (indices, éditions)
- Interface NTLite (Source, Edition, Composants)
- Charger et monter une image Windows
- Naviguer dans l'arborescence des composants

**Exercice :** Charger une ISO Windows 10/11 et identifier l'édition Pro

---

### 📗 Module 2 : Debloating & Suppression de Composants

**Durée :** 3 heures

**Contenu :**

- Qu'est-ce que le debloating ?
- Catégories de composants (Apps, Features, Services)
- Applications à supprimer (liste safe vs risquée)
- Features Windows optionnelles (Hyper-V, WSL, .NET, etc.)
- Suppression de Edge, OneDrive, Cortana
- Optimisation des services Windows

**Exercice :** Créer une image Windows "minimal" (<12 GB)

---

### 📙 Module 3 : Intégration (Drivers & Updates)

**Durée :** 2 heures

**Contenu :**

- Intégrer des drivers (WiFi, Ethernet, GPU, Chipset)
- Sources de drivers (constructeurs, DriverPack, Snappy Driver)
- Intégrer les Cumulative Updates (Windows Update)
- Intégrer .NET Framework, Visual C++ Redistributables
- Gestion des langues et packs linguistiques

**Exercice :** Intégrer les drivers d'un laptop Dell XPS

---

### 📕 Module 4 : Automatisation (Unattended XML)

**Durée :** 3 heures

**Contenu :**

- Qu'est-ce qu'un fichier Unattended (`autounattend.xml`) ?
- Phases de l'installation Windows (windowsPE, specialize, oobeSystem)
- Automatiser :
  - Partitionnement disque
  - Sélection édition
  - Création utilisateur
  - Configuration réseau
  - Scripts post-installation
- Intégrer le fichier Unattend dans l'ISO

**Exercice :** Créer une installation 100% automatique (zero-touch)

---

### 📓 Module 5 : TP Final - L'ISO Entreprise

**Durée :** 4 heures

**Scénario :**

Vous êtes IT Manager dans **TechCorp** (250 employés). Votre mission : créer une **Golden Image** Windows 11 Pro pour déploiement sur les nouveaux laptops Dell Latitude.

**Contraintes :**

- ✅ Windows 11 Pro uniquement (pas Home/Enterprise)
- ✅ Debloating complet (suppression bloatware)
- ✅ Drivers Dell intégrés (WiFi, Ethernet, GPU)
- ✅ Cumulative Update du mois intégré
- ✅ Installation automatisée (compte admin local pré-créé)
- ✅ Configuration réseau (DHCP + DNS d'entreprise)
- ✅ Scripts post-install (installation Chocolatey + packages)

**Livrable :** ISO bootable `TechCorp_Win11Pro_v2024.11.iso`

---

### 📘 Module 6 : Cas d'Usage Avancé - ISO Sécurisé (VPN & Certificats)

**Durée :** 4 heures

**Scénario :**

Dans un environnement **Zero Trust**, créer une ISO Windows sécurisée intégrant un client VPN GlobalProtect, des certificats Root CA d'entreprise et des agents de sécurité (EDR), le tout configuré automatiquement via Post-Setup.

**Contraintes :**

- ✅ Client VPN GlobalProtect intégré et pré-configuré
- ✅ Certificats Root CA installés automatiquement
- ✅ Pre-Logon VPN activé (connexion avant authentification)
- ✅ Agents de sécurité déployés (CrowdStrike, monitoring)
- ✅ Configuration Registry automatisée
- ✅ OOBE complètement automatisée

**Livrable :** ISO bootable `Windows11_Enterprise_VPN.iso`

**Compétences :**

- Post-Setup Commands (Run vs Command)
- Installation MSI silencieuse (GlobalProtect)
- Gestion certificats PKI (certutil)
- Configuration Registry avancée
- Déploiement massif en entreprise

---

## Prérequis

### Connaissances

- ✅ **Windows** : Utilisation avancée (ligne de commande, OOBE, éditions)
- ✅ **Virtualisation** : Hyper-V, VMware ou VirtualBox (pour tester les ISOs)
- ⚠️ **Notions PowerShell** : Utiles mais pas obligatoires

### Matériel Recommandé

| Composant | Spécification | Raison |
|-----------|---------------|--------|
| **CPU** | 4 cores minimum | Montage/démontage d'images |
| **RAM** | 16 GB minimum | NTLite consomme 2-4 GB, VM de test 4-8 GB |
| **Disque** | 100 GB libre (SSD recommandé) | ISOs (5-6 GB) + Images montées (15-20 GB) + Temp |
| **OS** | Windows 10/11 Pro ou Entreprise | NTLite fonctionne sur Windows |

### Logiciels Requis

| Logiciel | Version | Lien |
|----------|---------|------|
| **NTLite** | 2024.11+ (Free ou Pro) | [https://ntlite.com](https://ntlite.com) |
| **ISO Windows** | Windows 10 22H2 ou 11 23H2 | [Media Creation Tool](https://www.microsoft.com/software-download) |
| **Hyper-V / VMware** | Dernière version | Pour tester les ISOs |
| **7-Zip** (optionnel) | Dernière version | Extraire manuellement les ISOs |

---

## Méthodologie Pédagogique

### CoPrEx : Le Pattern de Chaque Module

Chaque module suit la structure **CoPrEx** :

1. **Co**ncept : Explication théorique (avec diagrammes Mermaid)
2. **Pr**atique : Étapes détaillées dans NTLite
3. **Ex**ercice : Mise en situation réelle
4. **Solution** : Correction détaillée (collapsible)

**Exemple (Module 1) :**

- **Concept** : Qu'est-ce qu'un fichier WIM ? Diagramme de l'architecture.
- **Pratique** : Comment charger une ISO dans NTLite (étapes GUI).
- **Exercice** : Charger Windows 10 Pro et identifier l'index.
- **Solution** : Copie d'écran textuelle des actions.

---

## Philosophie de la Formation

### "Measure Twice, Cut Once"

- ⚠️ **Tester TOUJOURS** l'ISO dans une VM avant déploiement réel
- ⚠️ **Sauvegarder** les presets NTLite (fichiers `.xml`)
- ⚠️ **Documenter** les changements (checklist de ce qui a été supprimé)
- ⚠️ **Valider** avec l'entreprise (certains composants peuvent être requis)

### Les 3 Niveaux de Debloating

| Niveau | Suppression | Risque | Usage |
|--------|-------------|--------|-------|
| **Conservateur** | Apps évidentes (Candy Crush, Xbox) | ⭐ Très faible | Entreprise, production |
| **Modéré** | Apps + Features non essentielles | ⭐⭐ Faible | Power users, gaming |
| **Agressif** | Maximum de composants | ⭐⭐⭐⭐ Élevé | VM, environnements contrôlés |

**Recommandation :** Commencer **Conservateur**, augmenter progressivement.

---

## Ressources Complémentaires

### Documentation Officielle

- [NTLite Documentation](https://www.ntlite.com/documentation/)
- [NTLite Forums](https://www.ntlite.com/community/)
- [Microsoft Docs - Windows Imaging](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/)

### Communauté

- [r/NTLite (Reddit)](https://www.reddit.com/r/NTLite/)
- [WinReducer Forum](https://www.winreducer.net/) (alternative à NTLite)
- [MyDigitalLife Forums](https://forums.mydigitallife.net/) (optimisation Windows)

### Outils Complémentaires

| Outil | Usage | Lien |
|-------|-------|------|
| **Rufus** | Créer une clé USB bootable depuis l'ISO | [rufus.ie](https://rufus.ie) |
| **DISM** | Ligne de commande pour manipuler les WIM | Inclus dans Windows |
| **WinPE** | Environnement de préinstallation (dépannage) | Microsoft ADK |

---

## Avertissements Légaux

### Licence Windows

⚠️ **IMPORTANT** : La modification d'images Windows doit respecter les termes de la licence Microsoft.

- ✅ **Autorisé** : Personnaliser une image pour usage interne (entreprise, personnel)
- ✅ **Autorisé** : Supprimer des composants non essentiels
- ❌ **INTERDIT** : Redistribuer des ISOs modifiées publiquement
- ❌ **INTERDIT** : Supprimer les mécanismes d'activation Windows

**Règle d'or :** Si vous avez une licence Windows légitime, vous pouvez personnaliser l'image pour votre usage.

### Support Microsoft

⚠️ Les images modifiées peuvent **perdre le support Microsoft**. En cas de problème, Microsoft peut refuser l'assistance.

**Solution :** Garder une image stock pour reproduire les bugs avant de contacter le support.

---

## Roadmap de la Formation

| Module | Statut | Durée |
|--------|--------|-------|
| Introduction & Programme | ✅ Disponible | - |
| Module 1 - Bases | ✅ Disponible | 2h |
| Module 2 - Debloating | ✅ Disponible | 3h |
| Module 3 - Intégration | ✅ Disponible | 2h |
| Module 4 - Automatisation | ✅ Disponible | 3h |
| Module 5 - TP Final | ✅ Disponible | 4h |
| Module 6 - Cas Réel VPN | ✅ Disponible | 4h |

**Durée totale :** 18 heures (base) ou **14 heures** (modules essentiels 1-5)

---

## 📑 Accès aux Modules

| Module | Titre | Durée |
|--------|-------|-------|
| [Module 1](01-module.md) | Prise en main & Architecture WIM | 2h |
| [Module 2](02-module.md) | Debloating & Suppression de Composants | 3h |
| [Module 3](03-module.md) | Intégration (Drivers & Updates) | 2h |
| [Module 4](04-module.md) | Automatisation (Unattended XML) | 3h |
| [TP Final](05-tp-final.md) | L'ISO Entreprise | 4h |
| [Cas Avancé](06-scenario-vpn.md) | ISO Sécurisé (VPN & Certificats) | 4h |

## Prêt à Commencer ?

**Accédez au [Module 1 : Prise en main & Architecture WIM](01-module.md)** pour démarrer votre apprentissage de NTLite !

Ou consultez le [guide de contribution](../../devops/docs-as-code.md) si vous souhaitez améliorer cette formation.

---

**Besoin d'aide ?** Ouvrez une [issue GitHub](https://github.com/VBlackJack/ShellBook/issues) ou consultez les [forums NTLite](https://www.ntlite.com/community/).
