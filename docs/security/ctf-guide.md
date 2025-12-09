---
tags:
  - ctf
  - pwn
  - osint
  - hardware
---

# Introduction aux CTF (Capture The Flag)

Votre guide de survie pour les compétitions de hacking légal.

---

## Qu'est-ce qu'un CTF ?

Les compétitions **Capture The Flag** sont des challenges de hacking légal où les participants trouvent des "flags" cachés (chaînes de texte comme `FLAG{y0u_found_m3}`) pour marquer des points.

**Types de CTF :**

| Type | Format |
|------|--------|
| **Jeopardy** | Challenges individuels, choisissez ce que vous voulez |
| **Attack-Defense** | Les équipes défendent leurs serveurs tout en attaquant les autres |
| **King of the Hill** | Maintenir le contrôle d'un système cible |

**Où pratiquer :**

- [HackTheBox](https://hackthebox.com) - Machines réalistes
- [TryHackMe](https://tryhackme.com) - Parcours d'apprentissage guidés
- [PicoCTF](https://picoctf.org) - Adapté aux débutants
- [Root-Me](https://root-me.org) - Plateforme française, excellents challenges
- [CTFtime](https://ctftime.org) - Calendrier des compétitions en direct

---

## Catégorie 1 : Pwn (Binary Exploitation)

**Objectif :** Exploiter les vulnérabilités de corruption de mémoire dans les programmes compilés (C/C++) pour obtenir l'exécution de code arbitraire.

### La Trinité des Outils

| Rôle | Outil | Objectif |
|------|------|---------|
| **Disassembler** | Ghidra, IDA Pro | Reverse engineer le binaire → voir assembly/pseudocode |
| **Debugger** | GDB + GEF/Pwndbg | Inspecter la mémoire, les registres, exécuter pas à pas |
| **Exploitation** | Pwntools (Python) | Scripter la livraison de payload et l'interaction shell |

### Vulnérabilités Courantes

| Vulnérabilité | Description |
|---------------|-------------|
| **Buffer Overflow** | Écrire au-delà des limites du buffer, écraser l'adresse de retour |
| **Format String** | Abuser de `printf(user_input)` pour lire/écrire en mémoire |
| **Use After Free** | Accéder à la mémoire libérée, corrompre les structures heap |
| **ROP (Return Oriented Programming)** | Chaîner des gadgets de code existants pour contourner NX |

### Exemple Rapide Pwntools

```python
from pwn import *

# Connexion au challenge
p = remote('ctf.example.com', 1337)
# Ou local: p = process('./vulnerable')

# Créer le payload
payload = b'A' * 64          # Remplir le buffer
payload += p64(0xdeadbeef)   # Écraser l'adresse de retour

# Envoyer et obtenir un shell
p.sendline(payload)
p.interactive()
```

### Commandes GDB Essentielles (avec GEF)

```bash
# Démarrer le débogage
gdb ./binary

# Commandes GEF/Pwndbg
checksec          # Vérifier les protections de sécurité (NX, ASLR, Canary)
vmmap             # Voir la disposition de la mémoire
pattern create 100  # Générer un motif cyclique
pattern offset 0x41414141  # Trouver l'offset

# Breakpoints et exécution
b *main           # Break à main
b *0x401234       # Break à une adresse
r                 # Lancer
c                 # Continuer
ni                # Instruction suivante
si                # Entrer dans

# Inspection
x/20x $rsp        # Examiner 20 mots hex à RSP
x/s 0x401234      # Examiner comme chaîne
info registers    # Afficher tous les registres
```

!!! tip "Apprendre les Bases"
    Commencez par de simples buffer overflows de pile avant de vous attaquer à l'exploitation du heap.

    Ressources :

    - [Nightmare](https://guyinatuxedo.github.io/) - Cours d'exploitation binaire
    - [pwn.college](https://pwn.college/) - Cours gratuit de l'ASU

---

## Catégorie 2 : Hardware Hacking

**Objectif :** Intercepter et décoder les signaux physiques entre composants électroniques.

### Méthodologie

```text
1. IDENTIFIER    →    2. CONNECTER    →    3. DÉCODER
   La puce            Logic Analyzer      Signal → Données
   (Datasheet)        (Saleae, etc.)      (CyberChef)
```

### Étape 1 : Identifier la Puce

- Lire les marquages sur la puce
- Rechercher la **Datasheet** (pinout, protocoles)
- Protocoles courants : UART, SPI, I2C, JTAG

### Étape 2 : Connecter & Capturer

| Outil | Objectif | Gamme de Prix |
|------|---------|-------------|
| **Logic Analyzer** | Capturer les signaux numériques | $10-$500 |
| **Saleae Logic** | Analyseur professionnel + logiciel | $$$$ |
| **Bus Pirate** | Sniffer multi-protocole | $30 |
| **FTDI Adapter** | Communication UART/Serial | $5-15 |
| **JTAGulator** | Auto-détection du pinout JTAG | $150 |

### Étape 3 : Décoder le Signal

```text
Signal Brut → Binaire → Hex → Données ASCII/Protocole
```

**Outils :**

- **Saleae Logic Software** - Analyseurs de protocole intégrés
- **PulseView** - Analyseur logique open-source
- **CyberChef** - Couteau suisse pour la transformation de données

### Protocoles Courants

| Protocole | Fils | Cas d'Usage |
|----------|-------|----------|
| **UART** | TX, RX, GND | Consoles de debug, sortie série |
| **SPI** | MOSI, MISO, CLK, CS | Mémoire flash, capteurs |
| **I2C** | SDA, SCL | Périphériques basse vitesse |
| **JTAG** | TDI, TDO, TCK, TMS | Débogage, extraction firmware |

!!! example "Scénario CTF"
    Le challenge vous donne un fichier de capture d'analyseur logique.

    1. Ouvrir dans PulseView/Saleae
    2. Ajouter un décodeur de protocole (UART @ 115200 baud)
    3. Lire le flag transmis

---

## Catégorie 3 : OSINT (Open Source Intelligence)

**Objectif :** Rassembler des renseignements en utilisant des informations publiquement disponibles.

!!! tip "La Règle d'Or"
    **Tout est un indice.**

    Une photo d'un badge d'employé sur LinkedIn peut révéler :

    - Format de l'ID du badge (séquentiel ? aléatoire ?)
    - Version du logo de l'entreprise (chronologie)
    - Disposition du bâtiment (arrière-plan)
    - Technologie de la carte d'accès (type RFID visible)

### Boîte à Outils OSINT

| Outil | Objectif |
|------|---------|
| **Google Dorks** | Opérateurs de recherche avancés |
| **Maltego** | Analyse visuelle des liens |
| **Sherlock** | Recherche de nom d'utilisateur sur les plateformes |
| **theHarvester** | Énumération email & sous-domaines |
| **Wayback Machine** | Snapshots historiques de sites web |
| **ExifTool** | Extraction de métadonnées d'images |
| **GeoGuessr skills** | Identification de lieu depuis des photos |

### Aide-mémoire Google Dorks

```text
site:example.com              # Rechercher dans le domaine
filetype:pdf confidential     # Trouver des types de fichiers spécifiques
intitle:"index of"            # Listages de répertoires
inurl:admin                   # URLs contenant "admin"
"password" filetype:log       # Fichiers logs exposés
cache:example.com             # Version en cache de Google
```

### Analyse d'Images

```bash
# Extraire les métadonnées
exiftool image.jpg

# Rechercher :
# - Coordonnées GPS
# - Modèle d'appareil photo
# - Date de création
# - Logiciel utilisé
# - Miniatures embarquées
```

### OSINT sur les Réseaux Sociaux

- **LinkedIn :** Noms d'employés, titres de postes, technologies utilisées
- **Twitter/X :** Événements en temps réel, opinions, gaffes
- **GitHub :** Code, emails, clés API dans les commits
- **Instagram :** Tags de localisation, détails d'arrière-plan

!!! warning "Éthique & Légalité"
    OSINT utilise **uniquement** des données publiques. N'accédez jamais à des comptes privés, ne hackez pas de systèmes, et ne vous faites pas passer pour quelqu'un d'autre. Restez légal.

---

## Catégorie 4 : Lockpicking (Sécurité Physique)

Le côté physique du hacking, souvent présent dans les CTF sur site et les conférences de sécurité.

### Outils de Base

| Outil | Objectif |
|------|---------|
| **Tension Wrench** | Appliquer une pression rotationnelle |
| **Hook Pick** | Manipuler les goupilles individuelles |
| **Rake** | Positionner rapidement plusieurs goupilles |
| **Bump Key** | Ouverture par frappe |

### La Technique (Serrures à Goupilles)

```text
1. Insérer la clé de tension, appliquer une légère rotation
2. Insérer le crochet, sentir la goupille bloquée
3. Pousser la goupille bloquée jusqu'à la ligne de cisaillement
4. Répéter pour les goupilles restantes
5. La serrure s'ouvre quand toutes les goupilles sont positionnées
```

### Ressources pour Pratiquer

- **Practice locks** - Serrures transparentes/découpées pour voir le mécanisme
- **Lock Sport** communautés - Focus légal et éducatif
- **TOOOL** - The Open Organisation Of Lockpickers

!!! info "Pourquoi C'est Important"
    La sécurité physique est souvent le maillon le plus faible. Social engineering + accès physique = game over pour la plupart des organisations.

---

## Résumé de la Boîte à Outils CTF

```bash
# Outils indispensables (Kali/Debian/Ubuntu - les outils CTF sont souvent sur Debian-based)
sudo apt install -y \
    gdb \
    ghidra \
    binwalk \          # Analyse de firmware
    steghide \         # Steganography
    exiftool \         # Métadonnées
    john \             # Cassage de mots de passe
    hashcat \          # Cassage GPU
    wireshark \        # Analyse de paquets
    burpsuite          # Test web

# Sur RHEL/Rocky (via EPEL pour certains outils)
# sudo dnf install epel-release -y
# sudo dnf install gdb wireshark binwalk ...

# Bibliothèques Python
pip install pwntools pycryptodome requests
```

### Recettes CyberChef à Connaître

- **From Hex** / **To Hex**
- **Base64 Decode**
- **ROT13** / **ROT47**
- **XOR** avec clé
- **Magic** (auto-détection d'encodage)

---

!!! success "Astuces de Pro"
    1. **Lisez attentivement la description du challenge** - les indices sont souvent cachés
    2. **Vérifiez les signatures de fichiers** - `file mystery.bin`, `binwalk mystery.bin`
    3. **Strings sur tout** - `strings -n 8 binary | grep -i flag`
    4. **Googlez les messages d'erreur** - quelqu'un d'autre l'a probablement résolu
    5. **Faites des pauses** - des yeux frais trouvent les flags plus vite
    6. **Documentez tout** - prenez des notes au fur et à mesure
