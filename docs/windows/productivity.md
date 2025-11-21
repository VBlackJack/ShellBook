# Productivité Windows & PowerToys

`#windows` `#wsl` `#powertoys` `#workflow`

Transformez Windows en poste de travail pour utilisateurs avancés.

---

## WSL (Windows Subsystem for Linux)

**Concept:** Le meilleur des deux mondes—terminal Linux natif (Bash, ssh, grep, awk) sans VM.

### Installation

```powershell
# Installer WSL avec Ubuntu (par défaut)
wsl --install

# Ou choisir une distribution spécifique
wsl --install -d Debian
wsl --install -d kali-linux

# Lister les distributions disponibles
wsl --list --online
```

### Commandes Essentielles

```powershell
# Démarrer la distribution par défaut
wsl

# Démarrer une distribution spécifique
wsl -d Ubuntu

# Arrêter toutes les instances WSL
wsl --shutdown

# Vérifier la version de WSL
wsl --version

# Définir la distribution par défaut
wsl --set-default Ubuntu
```

### Accéder aux Fichiers Entre les Systèmes

```bash
# Depuis WSL: Accéder aux fichiers Windows
cd /mnt/c/Users/VotreNom/Documents

# Depuis Windows: Accéder aux fichiers Linux
# Naviguer vers: \\wsl$\Ubuntu\home\username
```

!!! tip "Windows Terminal"
    Utilisez **Windows Terminal** (depuis le Microsoft Store) pour gérer PowerShell, CMD et WSL dans des onglets côte à côte.

    - ++ctrl+shift+1++ → PowerShell
    - ++ctrl+shift+2++ → WSL/Ubuntu
    - Diviser les panneaux: ++alt+shift+d++

---

## Microsoft PowerToys (Indispensable)

Utilitaires système open-source qui devraient être intégrés à Windows.

### Installation

```powershell
# Via winget
winget install Microsoft.PowerToys

# Ou télécharger depuis les releases GitHub
# https://github.com/microsoft/PowerToys
```

### FancyZones (Gestion des Fenêtres)

Dispositions de fenêtres personnalisées pour une productivité multi-écrans.

| Action | Comment |
|--------|-----|
| Ouvrir l'éditeur de disposition | ++win+shift+grave++ |
| Ancrer une fenêtre dans une zone | ++shift++ + Glisser la fenêtre |
| Changer rapidement de disposition | ++win+ctrl+alt+number++ |

**Configuration:**

1. Ouvrir les paramètres PowerToys → FancyZones
2. Lancer l'Éditeur de Disposition
3. Créer des zones personnalisées (ex: division 70/30, grille)
4. Maintenir ++shift++ en glissant les fenêtres pour les ancrer

### PowerToys Run (Lanceur)

**Raccourci:** ++alt+space++

| Préfixe | Fonction | Exemple |
|--------|----------|---------|
| (aucun) | Recherche d'application | `code` → VS Code |
| `=` | Calculatrice | `= 15% of 200` |
| `?` | Recherche Web | `? docker tutorial` |
| `>` | Commande Shell | `> ipconfig` |
| `//` | Convertisseur d'unités | `// 100 USD to EUR` |
| `{` | Recherche dans le Registre | `{ HKLM` |

### Text Extractor (OCR)

**Raccourci:** ++win+shift+t++

Extraire du texte depuis n'importe où à l'écran—images, vidéos, PDFs verrouillés.

1. Appuyer sur ++win+shift+t++
2. Dessiner un rectangle autour du texte
3. Le texte est copié dans le presse-papier

!!! example "Cas d'Usage"
    - Copier des messages d'erreur depuis des boîtes de dialogue
    - Extraire du texte depuis des captures d'écran
    - Récupérer du code depuis des tutoriels vidéo

### Keyboard Manager (Remapper les Touches)

Remapper n'importe quelle touche ou créer des raccourcis.

**Remaps populaires:**

| Original | Remappé Vers | Pourquoi |
|----------|----------|-----|
| CapsLock | Escape | Utilisateurs Vim |
| CapsLock | Ctrl | Utilisateurs Emacs |
| Insert | Delete | Éviter l'écrasement accidentel |
| Right Alt | Win | Confort sur portable |

### Autres Outils Utiles

| Outil | Fonction |
|------|----------|
| **Color Picker** | ++win+shift+c++ → Obtenir hex/RGB depuis n'importe où |
| **Image Resizer** | Clic droit sur images → Redimensionner |
| **File Locksmith** | Clic droit → Voir ce qui verrouille un fichier |
| **Hosts File Editor** | Interface graphique pour éditer le fichier hosts |
| **Paste as Plain Text** | ++win+ctrl+alt+v++ → Supprimer le formatage |

---

## Raccourcis Natifs - Aide-Mémoire

| Raccourci | Action |
|----------|--------|
| ++win+v++ | Historique du Presse-papier (activer d'abord!) |
| ++win+period++ | Panneau Emoji & Symboles |
| ++win+shift+s++ | Outil de Capture (Capture d'écran) |
| ++win+ctrl+left++ / ++right++ | Changer de Bureau Virtuel |
| ++win+tab++ | Vue des Tâches (toutes les fenêtres + bureaux) |
| ++win+d++ | Afficher le Bureau |
| ++win+l++ | Verrouiller la session |
| ++win+e++ | Explorateur de Fichiers |
| ++win+i++ | Paramètres |
| ++win+x++ | Menu Utilisateur Avancé |
| ++win+number++ | Ouvrir/basculer vers l'application de la barre des tâches |
| ++alt+tab++ | Changer de fenêtre |
| ++win+ctrl+d++ | Créer un nouveau Bureau Virtuel |
| ++win+ctrl+f4++ | Fermer le Bureau Virtuel actuel |

### Activer l'Historique du Presse-papier

```
Paramètres → Système → Presse-papiers → Historique du presse-papiers → ACTIVÉ
```

!!! tip "Synchroniser entre appareils"
    Activer "Synchroniser entre appareils" pour partager le presse-papier entre vos machines Windows.

---

## L'Easter Egg "God Mode"

Accéder à **tous** les paramètres du Panneau de Configuration dans un seul dossier.

### Comment Activer

1. Créer un nouveau dossier n'importe où (Bureau recommandé)
2. Le renommer exactement en:

```
GodMode.{ED7BA470-8E54-465E-825C-99712043E01C}
```

3. L'icône du dossier change et contient plus de 200 raccourcis de paramètres

### Contenu

- Tous les éléments du Panneau de Configuration dans une liste consultable
- Outils d'Administration
- Raccourcis vers le Gestionnaire de Périphériques
- Paramètres réseau
- Contrôles des comptes utilisateurs
- Et bien plus...

!!! info "Autres Dossiers Cachés"
    ```
    # Programmes par Défaut
    Default.{17cd9488-1228-4b2f-88ce-4298e93e0966}

    # Connexions Réseau
    Network.{992CFFA0-F557-101A-88EC-00DD010CCC48}

    # Imprimantes
    Printers.{2227A280-3AEA-1069-A2DE-08002B30309D}
    ```

---

## Conseil de Sécurité

!!! danger "Critique: Toujours Afficher les Extensions de Fichiers"
    **Pourquoi?** Pour détecter les malwares à double extension.

    Les attaquants utilisent des noms comme:

    - `invoice.pdf.exe` (apparaît comme `invoice.pdf`)
    - `photo.jpg.scr` (apparaît comme `photo.jpg`)
    - `document.docx.vbs` (apparaît comme `document.docx`)

    **Activer dans l'Explorateur de Fichiers:**

    1. Ouvrir l'Explorateur de Fichiers
    2. Affichage → Afficher → Extensions de noms de fichiers ✓

    **Ou via PowerShell:**

    ```powershell
    # Afficher les extensions de fichiers
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 0

    # Redémarrer l'Explorateur pour appliquer
    Stop-Process -Name explorer -Force
    ```

!!! warning "Activer aussi: Afficher les fichiers cachés"
    ```powershell
    # Afficher les fichiers cachés
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Value 1
    ```

---

## Productivité PowerShell Rapide

```powershell
# Infos système
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"

# Lister les programmes installés
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
    Select DisplayName, DisplayVersion | Sort DisplayName

# Trouver les gros fichiers
Get-ChildItem -Path C:\ -Recurse -ErrorAction SilentlyContinue |
    Where-Object {$_.Length -gt 100MB} |
    Sort-Object Length -Descending |
    Select-Object FullName, @{N='Size(MB)';E={[math]::Round($_.Length/1MB,2)}}

# Vider le cache DNS
ipconfig /flushdns

# Connexions réseau
Get-NetTCPConnection | Where-Object State -eq 'Established'
```
