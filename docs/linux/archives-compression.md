---
tags:
  - tar
  - gzip
  - zip
  - backup
---

# Archives (Tar) & Compression

Archivage et compression de fichiers sous Linux.

---

## Tar (Tape ARchive) - Le Standard

### Concept

```text
┌─────────────────────────────────────────────────────────────┐
│                        ARCHIVAGE                             │
│  Fichier1 + Fichier2 + Dossier → archive.tar (même taille)  │
├─────────────────────────────────────────────────────────────┤
│                       COMPRESSION                            │
│  archive.tar → archive.tar.gz (taille réduite)              │
└─────────────────────────────────────────────────────────────┘
```

| Action | Outil | Résultat |
|--------|-------|----------|
| **Archiver** | `tar` | Regroupe plusieurs fichiers en un seul |
| **Compresser** | `gzip`, `bzip2`, `xz` | Réduit la taille |
| **Archiver + Compresser** | `tar` + option | Fait les deux en une commande |

### La Table de Vérité des Options

| Option | Signification | Mnémonique |
|--------|---------------|------------|
| `c` | **C**reate | Créer une archive |
| `x` | E**x**tract | Extraire une archive |
| `t` | Lis**t** | Lister le contenu |
| `v` | **V**erbose | Afficher les fichiers traités |
| `z` | G**z**ip | Compression gzip (.gz) |
| `j` | Bzip2 | Compression bzip2 (.bz2) |
| `J` | Xz | Compression xz (.xz) |
| `f` | **F**ile | Spécifier le fichier archive |

!!! warning "Option -f toujours en dernier"
    L'option `f` doit être suivie du nom du fichier. Placez-la toujours à la fin des options.

    ```bash
    tar cvzf archive.tar.gz    # Correct
    tar cfvz archive.tar.gz    # Peut poser problème
    ```

### Exemples de Survie

#### Créer une Archive

```bash
# Archive simple (sans compression)
tar cvf backup.tar /var/www

# Archive compressée gzip (.tar.gz ou .tgz)
tar cvzf backup.tar.gz /var/www

# Archive compressée bzip2 (.tar.bz2)
tar cvjf backup.tar.bz2 /var/www

# Archive compressée xz (.tar.xz)
tar cvJf backup.tar.xz /var/www

# Exclure des fichiers/dossiers
tar cvzf backup.tar.gz /var/www --exclude='*.log' --exclude='cache'

# Backup avec date dans le nom
tar cvzf "backup-$(date +%Y%m%d).tar.gz" /var/www
```

#### Extraire une Archive

```bash
# Extraire dans le répertoire courant
tar xvzf backup.tar.gz

# Extraire dans un répertoire spécifique
tar xvzf backup.tar.gz -C /tmp/restore

# Extraire un seul fichier
tar xvzf backup.tar.gz var/www/index.html

# Tar détecte automatiquement la compression
tar xvf backup.tar.gz    # Fonctionne aussi
tar xvf backup.tar.bz2   # Fonctionne aussi
```

#### Lister le Contenu (sans extraire)

```bash
# Lister tous les fichiers
tar tf backup.tar.gz

# Lister avec détails (permissions, taille)
tar tvf backup.tar.gz

# Filtrer la liste
tar tf backup.tar.gz | grep "\.conf$"
```

### Récapitulatif Tar

```bash
# CRÉER
tar cvzf archive.tar.gz dossier/    # Gzip
tar cvjf archive.tar.bz2 dossier/   # Bzip2
tar cvJf archive.tar.xz dossier/    # Xz

# EXTRAIRE
tar xvzf archive.tar.gz             # Gzip
tar xvf archive.tar.bz2             # Auto-détection
tar xvf archive.tar.xz -C /dest     # Vers destination

# LISTER
tar tf archive.tar.gz               # Liste simple
tar tvf archive.tar.gz              # Liste détaillée
```

---

## Compression (Gzip, Bzip2, Xz)

### Comparatif

| Outil | Extension | Vitesse | Compression | Usage |
|-------|-----------|---------|-------------|-------|
| `gzip` | `.gz` | Rapide | Bonne | Standard, usage quotidien |
| `bzip2` | `.bz2` | Moyen | Meilleure | Archivage long terme |
| `xz` | `.xz` | Lent | Excellente | Distributions, sources |

```text
Fichier original : 100 MB
├── gzip  → ~25 MB  (rapide)
├── bzip2 → ~20 MB  (moyen)
└── xz    → ~15 MB  (lent)
```

### Utilisation Directe (fichier unique)

```bash
# Gzip
gzip file.txt           # Crée file.txt.gz, supprime l'original
gzip -k file.txt        # -k : Keep original
gzip -d file.txt.gz     # Décompresse
gunzip file.txt.gz      # Équivalent

# Bzip2
bzip2 file.txt          # Crée file.txt.bz2
bzip2 -k file.txt       # Keep original
bzip2 -d file.txt.bz2   # Décompresse
bunzip2 file.txt.bz2    # Équivalent

# Xz
xz file.txt             # Crée file.txt.xz
xz -k file.txt          # Keep original
xz -d file.txt.xz       # Décompresse
unxz file.txt.xz        # Équivalent
```

### Lire un Fichier Compressé (sans extraire)

```bash
# Gzip
zcat file.txt.gz        # Affiche le contenu
zgrep "error" file.gz   # Grep dans fichier compressé
zless file.txt.gz       # Less dans fichier compressé

# Bzip2
bzcat file.txt.bz2
bzgrep "error" file.bz2

# Xz
xzcat file.txt.xz
xzgrep "error" file.xz
```

---

## Compatibilité Windows (Zip)

### Pourquoi Zip ?

| Contexte | Format Recommandé |
|----------|-------------------|
| Échange avec Windows/Mac | **zip** |
| Backup Linux | tar.gz |
| Distribution sources | tar.xz |
| Archivage long terme | tar.bz2 |

### Commandes Zip

```bash
# Installation (si nécessaire)
sudo apt install zip unzip

# Créer une archive zip
zip archive.zip file1.txt file2.txt

# Créer récursivement (dossier)
zip -r data.zip folder/

# Avec compression maximale
zip -9 -r data.zip folder/

# Exclure des fichiers
zip -r data.zip folder/ -x "*.log" -x "*.tmp"

# Protéger par mot de passe
zip -e -r secret.zip folder/
```

### Commandes Unzip

```bash
# Extraire
unzip data.zip

# Extraire vers un répertoire
unzip data.zip -d /tmp/extract

# Lister le contenu
unzip -l data.zip

# Extraire un seul fichier
unzip data.zip path/to/file.txt

# Tester l'intégrité
unzip -t data.zip
```

---

## Référence Rapide

```bash
# === TAR ===
# Créer
tar cvzf archive.tar.gz dossier/     # Gzip
tar cvjf archive.tar.bz2 dossier/    # Bzip2
tar cvJf archive.tar.xz dossier/     # Xz

# Extraire
tar xvzf archive.tar.gz              # Gzip
tar xvf archive.tar.* -C /dest       # Auto + destination

# Lister
tar tf archive.tar.gz

# === COMPRESSION DIRECTE ===
gzip file.txt                        # → file.txt.gz
gunzip file.txt.gz                   # → file.txt
zcat file.txt.gz                     # Afficher sans extraire

# === ZIP (Windows) ===
zip -r data.zip folder/              # Créer
unzip data.zip                       # Extraire
unzip -l data.zip                    # Lister
```
