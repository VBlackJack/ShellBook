---
tags:
  - security
  - steganography
  - forensics
  - ctf
  - metadata
---

# Stéganographie & Forensics

La stéganographie est l'art de cacher de l'information dans un autre fichier (image, audio) sans que cela soit visible à l'œil nu. Très utilisé en CTF et par certains malwares pour exfiltrer des données.

## 1. Steghide : Le Classique

Idéal pour cacher un fichier texte dans une image JPEG ou un fichier audio WAV.

### Cacher des données (Embed)
```bash
# Cache secret.txt dans image.jpg
steghide embed -cf image.jpg -ef secret.txt
# On vous demandera une passphrase
```

### Extraire des données (Extract)
```bash
# Récupère le fichier caché
steghide extract -sf image.jpg
```

## 2. Binwalk : Analyse de Firmware & Fichiers Composés

Binwalk scanne un fichier binaire à la recherche de "signatures" connues (en-têtes de fichiers ZIP, images, systèmes de fichiers).
Très puissant pour analyser des firmwares IoT ou des images PNG qui contiennent des ZIP cachés.

### Analyse simple
```bash
binwalk firmware.bin

# Output exemple :
# DECIMAL       HEXADECIMAL     DESCRIPTION
# --------------------------------------------------------------------------------
# 0             0x0             TRX firmware header, little endian...
# 28            0x1C            gzip compressed data, maximum compression...
```

### Extraction Automatique
L'option `-e` extrait tout ce qu'il trouve.
```bash
binwalk -e image_suspecte.png
```
*Cela créera un dossier `_image_suspecte.png.extracted` contenant les fichiers trouvés.*

## 3. ExifTool : Les Métadonnées

Les images contiennent souvent des infos invisibles (GPS, Modèle appareil, Auteur, Logiciel utilisé).

### Lire les métadonnées
```bash
exiftool image.jpg
```

### Nettoyer les métadonnées (OpSec)
Avant de publier une photo, supprimez tout.
```bash
exiftool -all= image.jpg
```

## 4. Strings : Le Couteau Suisse

Parfois, le secret est juste écrit en clair dans le binaire.
```bash
strings programme.exe | grep "password"
```
ou pour chercher des drapeaux CTF :
```bash
strings image.jpg | grep "FLAG{"
```

## 5. Zsteg (Pour les PNG)

Spécialisé pour les images PNG et BMP. Il détecte les données cachées dans les bits de poids faible (LSB).

```bash
gem install zsteg
zsteg image.png
```
