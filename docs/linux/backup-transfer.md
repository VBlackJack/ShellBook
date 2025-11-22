---
tags:
  - rsync
  - scp
  - sftp
  - backup
---

# Rsync & Secure Transfer

Synchronisation et transfert sécurisé de fichiers.

---

## Rsync (Remote Sync)

### Pourquoi Rsync est Magique

!!! tip "Delta Transfer : Ne copie que ce qui a changé"
    Rsync compare source et destination, puis transfère uniquement les **différences**.

    - Premier backup : 10 GB transférés
    - Backups suivants : Seulement les fichiers modifiés (quelques MB)

```
┌─────────────────┐                    ┌─────────────────┐
│     SOURCE      │                    │   DESTINATION   │
├─────────────────┤     Delta Only     ├─────────────────┤
│ file1.txt  [=]  │ ─────────────────► │ file1.txt  [=]  │
│ file2.txt  [M]  │ ═══════════════════│ file2.txt  [M]  │  ← Modifié
│ file3.txt  [=]  │ ─────────────────► │ file3.txt  [=]  │
│ file4.txt  [N]  │ ═══════════════════│ file4.txt  [N]  │  ← Nouveau
└─────────────────┘                    └─────────────────┘
     [=] Ignoré    [M] Modifié    [N] Nouveau
```

### Les Flags Indispensables

```bash
rsync -avzP source/ destination/
```

| Flag | Signification | Pourquoi c'est vital |
|------|---------------|----------------------|
| `-a` | **A**rchive | Préserve permissions, dates, symlinks, propriétaire |
| `-v` | **V**erbose | Affiche les fichiers traités |
| `-z` | Compres**z** | Compresse pendant le transfert (économise bande passante) |
| `-P` | **P**rogress + Partial | Barre de progression + reprise si coupure |

#### Autres Options Utiles

| Flag | Description |
|------|-------------|
| `--delete` | Supprime les fichiers absents de la source |
| `--dry-run` | Simule sans rien faire (test) |
| `--exclude` | Exclut des fichiers/patterns |
| `-n` | Alias de --dry-run |
| `-e ssh` | Spécifie la méthode de transport (SSH par défaut) |
| `--bwlimit=1000` | Limite bande passante (KB/s) |

### Le Piège du Slash

!!! danger "Trailing Slash : Attention au comportement !"
    La présence ou absence du `/` final change **tout**.

```bash
# AVEC slash : copie le CONTENU de src dans dest
rsync -av src/ dest/
# Résultat : dest/file1.txt, dest/file2.txt

# SANS slash : copie le DOSSIER src dans dest
rsync -av src dest/
# Résultat : dest/src/file1.txt, dest/src/file2.txt
```

```
src/                          src
├── file1.txt                 ├── file1.txt
└── file2.txt                 └── file2.txt

rsync -av src/ dest/          rsync -av src dest/
         ↓                             ↓
dest/                         dest/
├── file1.txt                 └── src/
└── file2.txt                     ├── file1.txt
                                  └── file2.txt
```

### Exemples Pratiques

#### Sync Local

```bash
# Backup simple
rsync -avzP /var/www/ /backup/www/

# Avec suppression des fichiers obsolètes
rsync -avzP --delete /var/www/ /backup/www/

# Test avant exécution (dry-run)
rsync -avzP --delete --dry-run /var/www/ /backup/www/

# Exclure des fichiers
rsync -avzP --exclude='*.log' --exclude='cache/' /var/www/ /backup/www/
```

#### Sync Distant (over SSH)

```bash
# Local → Distant
rsync -avzP /var/www/ user@server:/backup/www/

# Distant → Local
rsync -avzP user@server:/var/www/ /local/backup/

# Avec port SSH non standard
rsync -avzP -e 'ssh -p 2222' /var/www/ user@server:/backup/

# Avec clé SSH spécifique
rsync -avzP -e 'ssh -i ~/.ssh/backup_key' /var/www/ user@server:/backup/
```

#### Backup Incrémental avec Date

```bash
#!/bin/bash
# Backup incrémental avec hardlinks (économise espace)
DATE=$(date +%Y-%m-%d)
LATEST="/backup/latest"
DEST="/backup/$DATE"

rsync -avzP --delete \
    --link-dest="$LATEST" \
    /var/www/ "$DEST/"

# Met à jour le lien "latest"
ln -snf "$DEST" "$LATEST"
```

---

## SCP & SFTP (Transfert SSH Simple)

### SCP (Secure Copy)

!!! warning "SCP est déprécié"
    OpenSSH recommande désormais `sftp` ou `rsync` à la place de `scp`.
    SCP reste omniprésent mais ne supporte pas la reprise sur coupure.

```bash
# Local → Distant
scp file.txt user@server:/remote/path/

# Distant → Local
scp user@server:/remote/file.txt /local/path/

# Récursif (dossier)
scp -r folder/ user@server:/remote/path/

# Port non standard
scp -P 2222 file.txt user@server:/path/

# Préserver les attributs
scp -p file.txt user@server:/path/
```

### SFTP (SSH File Transfer Protocol)

Mode interactif, comme FTP mais sécurisé.

```bash
# Connexion
sftp user@server

# Commandes interactives
sftp> pwd                    # Répertoire distant actuel
sftp> lpwd                   # Répertoire local actuel
sftp> ls                     # Liste distante
sftp> lls                    # Liste locale
sftp> cd /var/www            # Change dir distant
sftp> lcd /local/path        # Change dir local
sftp> get file.txt           # Download
sftp> put file.txt           # Upload
sftp> get -r folder/         # Download récursif
sftp> put -r folder/         # Upload récursif
sftp> bye                    # Quitter
```

#### SFTP en Mode Batch

```bash
# Commande unique
sftp user@server:/remote/file.txt /local/

# Fichier batch
echo "get /var/log/app.log" | sftp user@server

# Script batch
sftp -b commands.txt user@server
```

### Comparatif

| Outil | Avantages | Inconvénients |
|-------|-----------|---------------|
| **rsync** | Delta, reprise, compression | Syntaxe à maîtriser |
| **scp** | Simple, partout | Pas de reprise, déprécié |
| **sftp** | Interactif, standard | Moins pratique pour scripts |

---

## Stratégie de Sauvegarde (SecNumCloud)

### Règle 3-2-1

```
┌─────────────────────────────────────────────────────────────┐
│                    RÈGLE 3-2-1                               │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   3  copies de vos données                                  │
│      └─ Original + 2 backups                                │
│                                                              │
│   2  supports différents                                    │
│      └─ Disque local + NAS/Cloud/Bande                      │
│                                                              │
│   1  copie hors-site (off-site)                             │
│      └─ Datacenter distant, Cloud, coffre-fort              │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

| Copie | Support | Localisation | Exemple |
|-------|---------|--------------|---------|
| **1** | Disque local | On-site | `/var/www` (original) |
| **2** | NAS/SAN | On-site | `rsync → nas.local:/backup` |
| **3** | Cloud/Distant | **Off-site** | `rsync → backup.datacenter2.com` |

### Chiffrement Avant Transfert

!!! danger "SecNumCloud : Chiffrer les backups sensibles"
    Les données en transit ET au repos doivent être chiffrées.
    Voir [OpenSSL CLI](../security/openssl-cli.md) pour les détails.

```bash
# Méthode 1 : Chiffrer l'archive avant transfert
tar cvzf - /var/www | openssl enc -aes-256-cbc -salt -pbkdf2 \
    -out backup.tar.gz.enc

# Transférer
rsync -avzP backup.tar.gz.enc user@backup-server:/offsite/

# Déchiffrer
openssl enc -d -aes-256-cbc -pbkdf2 -in backup.tar.gz.enc | tar xvzf -
```

```bash
# Méthode 2 : GPG (asymétrique)
tar cvzf - /var/www | gpg --encrypt --recipient backup@company.com \
    > backup.tar.gz.gpg

rsync -avzP backup.tar.gz.gpg user@backup-server:/offsite/
```

### Script de Backup Complet

```bash
#!/bin/bash
set -euo pipefail

# Configuration
SOURCE="/var/www"
LOCAL_BACKUP="/backup/local"
REMOTE_USER="backup"
REMOTE_HOST="backup.datacenter2.com"
REMOTE_PATH="/offsite/$(hostname)"
DATE=$(date +%Y-%m-%d_%H%M)
LOG="/var/log/backup.log"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG"; }

# Backup local
log "Starting local backup..."
rsync -az --delete "$SOURCE/" "$LOCAL_BACKUP/"

# Backup distant (chiffré)
log "Creating encrypted archive..."
tar czf - "$LOCAL_BACKUP" | openssl enc -aes-256-cbc -salt -pbkdf2 \
    -pass file:/root/.backup_pass > "/tmp/backup-$DATE.tar.gz.enc"

log "Transferring to off-site..."
rsync -avzP "/tmp/backup-$DATE.tar.gz.enc" \
    "$REMOTE_USER@$REMOTE_HOST:$REMOTE_PATH/"

# Cleanup
rm -f "/tmp/backup-$DATE.tar.gz.enc"
log "Backup completed successfully"
```

---

## Référence Rapide

```bash
# === RSYNC ===
rsync -avzP src/ dest/                    # Local
rsync -avzP src/ user@host:/dest/         # Distant
rsync -avzP --delete src/ dest/           # Miroir exact
rsync -avzP --dry-run src/ dest/          # Test

# Attention au slash !
rsync -av src/ dest/    # Contenu de src → dest
rsync -av src dest/     # Dossier src → dest/src

# === SCP ===
scp file.txt user@host:/path/             # Upload
scp user@host:/path/file.txt ./           # Download
scp -r folder/ user@host:/path/           # Récursif

# === SFTP ===
sftp user@host                            # Interactif
# get, put, ls, cd, lcd, bye

# === BACKUP CHIFFRÉ ===
tar czf - /data | openssl enc -aes-256-cbc -salt -pbkdf2 > backup.enc
```
