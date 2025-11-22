# Secure File Exchange Gateway

`#security` `#clamav` `#audit` `#scripting`

Zone tampon sécurisée ("Sas") pour l'échange de fichiers avec scan antivirus automatique et audit complet.

---

## Concept : Le "Sas" de Sécurité

**Le Sas = Zone tampon isolée où les fichiers sont analysés avant distribution**

```
┌─────────────────────────────────────────────────────────────┐
│                  PROBLÈME SANS SAS                           │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Utilisateur externe → Upload fichier → Production          │
│                                                              │
│  ✗ Pas de scan antivirus                                    │
│  ✗ Pas d'audit (qui a envoyé quoi ?)                        │
│  ✗ Malware peut se propager instantanément                  │
│  ✗ Fichiers restent indéfiniment (saturation disque)        │
│                                                              │
│  Résultat : Vecteur d'attaque ouvert                        │
│                                                              │
├─────────────────────────────────────────────────────────────┤
│                  SOLUTION : SAS SÉCURISÉ                     │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Utilisateur → Upload → SAS → Scan → Audit → Production     │
│                                                              │
│  ✓ Scan antivirus automatique (ClamAV)                      │
│  ✓ Calcul SHA256 (intégrité)                                │
│  ✓ Logs centralisés (Syslog)                                │
│  ✓ Quarantaine fichiers infectés                            │
│  ✓ Nettoyage automatique (24h)                              │
│                                                              │
│  Résultat : Défense en profondeur                           │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

**Cas d'usage :**
- Échange de fichiers avec des partenaires externes
- Upload de documents par les utilisateurs (portail web)
- Réception de factures/documents par email
- DMZ sécurisée pour fichiers sensibles

---

## Architecture du Workflow

### Vue d'Ensemble

```
┌─────────────────────────────────────────────────────────────┐
│                  WORKFLOW COMPLET                            │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  1. DÉPOSE                                                  │
│     Utilisateur → SFTP/SMB → /DATA/IN/                      │
│                                                              │
│  2. DÉTECTION (inotifywait)                                 │
│     detect_file.sh surveille /DATA/IN/                      │
│     Événement : CREATE, CLOSE_WRITE                         │
│                                                              │
│  3. SCAN ANTIVIRUS (ClamAV)                                 │
│     clamdscan /DATA/IN/fichier.pdf                          │
│     - Si OK   → Déplacer vers /DATA/OUT/                    │
│     - Si KO   → Déplacer vers /DATA/QUARANTINE/             │
│                                                              │
│  4. AUDIT (SHA256 + Syslog)                                 │
│     sha256sum fichier.pdf                                   │
│     logger "Fichier scanné : hash=ABC123... status=OK"      │
│                                                              │
│  5. NETTOYAGE (Cron)                                        │
│     Suppression automatique après 24 heures                 │
│     find /DATA/OUT -mtime +1 -delete                        │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Structure des Répertoires

```
/DATA/
├── IN/              # Zone de dépôt (inotifywait actif)
├── OUT/             # Fichiers sains (après scan OK)
├── QUARANTINE/      # Fichiers infectés (isolés)
└── LOGS/            # Logs locaux (backup syslog)
```

---

## Installation des Dépendances

### ClamAV (Antivirus)

```bash
# Installation ClamAV (Debian/Ubuntu)
sudo apt update
sudo apt install -y clamav clamav-daemon clamav-freshclam

# Installation ClamAV (RHEL/Rocky Linux)
sudo dnf install -y clamav clamav-update clamd

# Mettre à jour les signatures antivirus
sudo freshclam

# Démarrer le daemon ClamAV
sudo systemctl enable --now clamav-daemon

# Vérifier le service
sudo systemctl status clamav-daemon

# Tester un scan
clamdscan --version
# Output : ClamAV 1.0.x
```

### inotify-tools (Détection de fichiers)

```bash
# Installation inotify-tools (Debian/Ubuntu)
sudo apt install -y inotify-tools

# Installation inotify-tools (RHEL/Rocky Linux)
sudo dnf install -y inotify-tools

# Tester inotifywait
inotifywait --version
# Output : inotifywait 3.x
```

### Créer la Structure de Répertoires

```bash
# Créer les répertoires
sudo mkdir -p /DATA/{IN,OUT,QUARANTINE,LOGS}

# Permissions strictes
sudo chmod 770 /DATA/IN
sudo chmod 750 /DATA/OUT
sudo chmod 700 /DATA/QUARANTINE
sudo chmod 755 /DATA/LOGS

# Propriétaire : utilisateur dédié
sudo useradd -r -s /bin/bash -d /DATA securescan
sudo chown -R securescan:securescan /DATA

# Vérifier
ls -la /DATA/

# Output attendu :
# drwxrwx---  2 securescan securescan  4096 Jan 15 14:00 IN
# drwxr-x---  2 securescan securescan  4096 Jan 15 14:00 OUT
# drwx------  2 securescan securescan  4096 Jan 15 14:00 QUARANTINE
# drwxr-xr-x  2 securescan securescan  4096 Jan 15 14:00 LOGS
```

---

## Script 1 : Détection de Fichiers (detect_file.sh)

**Ce script surveille `/DATA/IN/` et déclenche le scan à chaque nouveau fichier.**

```bash
#!/bin/bash
# /usr/local/bin/detect_file.sh
# Détection automatique de nouveaux fichiers dans /DATA/IN/

WATCH_DIR="/DATA/IN"
SCAN_SCRIPT="/usr/local/bin/scan_data.sh"
LOG_FILE="/DATA/LOGS/detect_file.log"

# Fonction de logging
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a ${LOG_FILE}
}

log "=== Démarrage de la surveillance : ${WATCH_DIR} ==="

# Boucle infinie de surveillance avec inotifywait
inotifywait -m -e close_write,moved_to "${WATCH_DIR}" --format '%w%f' |
while read FILE; do
    log "[DÉTECTION] Nouveau fichier : ${FILE}"

    # Vérifier que le fichier existe encore (race condition)
    if [ ! -f "${FILE}" ]; then
        log "[AVERTISSEMENT] Fichier disparu : ${FILE}"
        continue
    fi

    # Vérifier que le fichier n'est pas vide
    FILE_SIZE=$(stat -c%s "${FILE}")
    if [ ${FILE_SIZE} -eq 0 ]; then
        log "[AVERTISSEMENT] Fichier vide ignoré : ${FILE}"
        rm -f "${FILE}"
        continue
    fi

    # Lancer le scan en arrière-plan
    log "[TRAITEMENT] Lancement du scan pour : ${FILE}"
    ${SCAN_SCRIPT} "${FILE}" &

    # Limiter le nombre de scans parallèles (max 5)
    while [ $(jobs -r | wc -l) -ge 5 ]; do
        sleep 1
    done
done

# Ce point ne devrait jamais être atteint (boucle infinie)
log "[ERREUR] Surveillance interrompue !"
```

**Installation du service systemd :**

```bash
# Créer le fichier de service
sudo cat > /etc/systemd/system/detect-file.service <<EOF
[Unit]
Description=Secure File Exchange - Detection Service
After=network.target

[Service]
Type=simple
User=securescan
Group=securescan
ExecStart=/usr/local/bin/detect_file.sh
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Rendre le script exécutable
sudo chmod +x /usr/local/bin/detect_file.sh

# Activer et démarrer le service
sudo systemctl daemon-reload
sudo systemctl enable --now detect-file

# Vérifier le service
sudo systemctl status detect-file

# Voir les logs en temps réel
sudo journalctl -u detect-file -f
```

---

## Script 2 : Scan Antivirus et Audit (scan_data.sh)

**Ce script analyse le fichier, calcule le SHA256, et logue tout dans Syslog.**

```bash
#!/bin/bash
# /usr/local/bin/scan_data.sh
# Scan antivirus, calcul SHA256, audit et déplacement

FILE="$1"
OUT_DIR="/DATA/OUT"
QUARANTINE_DIR="/DATA/QUARANTINE"
LOG_FILE="/DATA/LOGS/scan_data.log"
SYSLOG_TAG="secure-file-exchange"

# Vérifier que le fichier existe
if [ ! -f "${FILE}" ]; then
    echo "[ERREUR] Fichier introuvable : ${FILE}"
    exit 1
fi

# Fonction de logging (local + syslog)
log() {
    local LEVEL=$1
    local MESSAGE=$2
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [${LEVEL}] ${MESSAGE}" | tee -a ${LOG_FILE}
    logger -t ${SYSLOG_TAG} -p user.${LEVEL} "${MESSAGE}"
}

# Récupérer le nom du fichier
FILENAME=$(basename "${FILE}")

log "info" "=== Début du scan : ${FILENAME} ==="

# Calcul du SHA256 (avant scan, pour intégrité)
SHA256=$(sha256sum "${FILE}" | awk '{print $1}')
log "info" "SHA256 calculé : ${SHA256}"

# Récupérer la taille du fichier
FILE_SIZE=$(stat -c%s "${FILE}")
FILE_SIZE_MB=$(echo "scale=2; ${FILE_SIZE}/1024/1024" | bc)
log "info" "Taille du fichier : ${FILE_SIZE_MB} MB"

# Scan antivirus avec ClamAV
log "info" "Lancement du scan ClamAV..."
SCAN_RESULT=$(clamdscan --no-summary "${FILE}" 2>&1)
SCAN_EXIT_CODE=$?

# Analyser le résultat du scan
if [ ${SCAN_EXIT_CODE} -eq 0 ]; then
    # Fichier sain
    log "notice" "SCAN OK - Fichier sain : ${FILENAME}"

    # Déplacer vers OUT
    mv "${FILE}" "${OUT_DIR}/"
    log "info" "Fichier déplacé vers : ${OUT_DIR}/${FILENAME}"

    # Audit final (syslog centralisé)
    logger -t ${SYSLOG_TAG} -p user.notice \
        "FILE_SCANNED: filename=${FILENAME} sha256=${SHA256} size_mb=${FILE_SIZE_MB} status=CLEAN destination=${OUT_DIR}"

    # Notification optionnelle (email, Slack, etc.)
    # echo "Fichier sain reçu : ${FILENAME}" | mail -s "Secure File Exchange" admin@mycorp.com

elif [ ${SCAN_EXIT_CODE} -eq 1 ]; then
    # Fichier infecté
    VIRUS_NAME=$(echo "${SCAN_RESULT}" | grep FOUND | awk '{print $NF}')
    log "warning" "SCAN KO - VIRUS DÉTECTÉ : ${VIRUS_NAME}"

    # Déplacer vers QUARANTINE
    mv "${FILE}" "${QUARANTINE_DIR}/"
    log "warning" "Fichier mis en quarantaine : ${QUARANTINE_DIR}/${FILENAME}"

    # Audit critique (syslog + alerte)
    logger -t ${SYSLOG_TAG} -p user.warning \
        "VIRUS_DETECTED: filename=${FILENAME} sha256=${SHA256} virus=${VIRUS_NAME} action=QUARANTINE"

    # Notification critique
    echo "ALERTE SÉCURITÉ: Virus détecté dans ${FILENAME} (${VIRUS_NAME})" | \
        mail -s "VIRUS DÉTECTÉ - Secure File Exchange" security@mycorp.com

else
    # Erreur de scan (fichier corrompu, ClamAV down, etc.)
    log "err" "SCAN ERROR - Code de sortie : ${SCAN_EXIT_CODE}"
    log "err" "Détails : ${SCAN_RESULT}"

    # Laisser le fichier dans IN pour investigation manuelle
    logger -t ${SYSLOG_TAG} -p user.err \
        "SCAN_ERROR: filename=${FILENAME} sha256=${SHA256} exit_code=${SCAN_EXIT_CODE}"
fi

log "info" "=== Fin du scan : ${FILENAME} ==="
```

**Installation :**

```bash
# Rendre le script exécutable
sudo chmod +x /usr/local/bin/scan_data.sh

# Tester manuellement
sudo su - securescan
echo "Test file" > /DATA/IN/test.txt

# Vérifier les logs
tail -f /DATA/LOGS/scan_data.log
journalctl -t secure-file-exchange -f
```

---

## Nettoyage Automatique (Cron)

**Supprimer automatiquement les fichiers de plus de 24 heures.**

```bash
#!/bin/bash
# /usr/local/bin/cleanup_data.sh
# Nettoyage automatique des fichiers anciens

OUT_DIR="/DATA/OUT"
QUARANTINE_DIR="/DATA/QUARANTINE"
RETENTION_HOURS=24
LOG_FILE="/DATA/LOGS/cleanup.log"
SYSLOG_TAG="secure-file-exchange-cleanup"

# Fonction de logging
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a ${LOG_FILE}
    logger -t ${SYSLOG_TAG} "$1"
}

log "=== Début du nettoyage automatique ==="

# Compter les fichiers avant nettoyage
OUT_COUNT_BEFORE=$(find ${OUT_DIR} -type f | wc -l)
QUARANTINE_COUNT_BEFORE=$(find ${QUARANTINE_DIR} -type f | wc -l)

log "Fichiers dans OUT avant nettoyage : ${OUT_COUNT_BEFORE}"
log "Fichiers dans QUARANTINE avant nettoyage : ${QUARANTINE_COUNT_BEFORE}"

# Supprimer les fichiers de OUT de plus de 24h
log "Suppression des fichiers OUT de plus de ${RETENTION_HOURS}h..."
find ${OUT_DIR} -type f -mmin +$((RETENTION_HOURS * 60)) -delete

# Supprimer les fichiers de QUARANTINE de plus de 7 jours (rétention plus longue)
log "Suppression des fichiers QUARANTINE de plus de 7 jours..."
find ${QUARANTINE_DIR} -type f -mtime +7 -delete

# Compter les fichiers après nettoyage
OUT_COUNT_AFTER=$(find ${OUT_DIR} -type f | wc -l)
QUARANTINE_COUNT_AFTER=$(find ${QUARANTINE_DIR} -type f | wc -l)

log "Fichiers dans OUT après nettoyage : ${OUT_COUNT_AFTER}"
log "Fichiers dans QUARANTINE après nettoyage : ${QUARANTINE_COUNT_AFTER}"

# Calculer les fichiers supprimés
OUT_DELETED=$((OUT_COUNT_BEFORE - OUT_COUNT_AFTER))
QUARANTINE_DELETED=$((QUARANTINE_COUNT_BEFORE - QUARANTINE_COUNT_AFTER))

log "Fichiers supprimés : OUT=${OUT_DELETED}, QUARANTINE=${QUARANTINE_DELETED}"

# Vérifier l'espace disque
DISK_USAGE=$(df -h /DATA | tail -1 | awk '{print $5}' | sed 's/%//')
log "Utilisation disque /DATA : ${DISK_USAGE}%"

if [ ${DISK_USAGE} -gt 80 ]; then
    log "[ALERTE] Espace disque faible : ${DISK_USAGE}%"
    logger -t ${SYSLOG_TAG} -p user.warning "ALERTE: Espace disque /DATA à ${DISK_USAGE}%"
fi

log "=== Nettoyage terminé ==="
```

**Ajouter au cron :**

```bash
# Rendre le script exécutable
sudo chmod +x /usr/local/bin/cleanup_data.sh

# Ajouter au cron (toutes les heures)
echo "0 * * * * securescan /usr/local/bin/cleanup_data.sh" | sudo tee /etc/cron.d/cleanup-data

# Tester manuellement
sudo su - securescan -c "/usr/local/bin/cleanup_data.sh"
```

---

## Configuration Syslog Centralisé

**Envoyer les logs vers un serveur Syslog distant (ex: Graylog, ELK).**

```bash
# Configuration rsyslog pour envoyer les logs du tag "secure-file-exchange"
sudo cat > /etc/rsyslog.d/50-secure-file-exchange.conf <<EOF
# Envoyer les logs secure-file-exchange vers le serveur central
if \$programname == 'secure-file-exchange' then @syslog.mycorp.internal:514
if \$programname == 'secure-file-exchange' then stop
EOF

# Redémarrer rsyslog
sudo systemctl restart rsyslog

# Tester l'envoi de logs
logger -t secure-file-exchange "Test de log centralisé"

# Vérifier sur le serveur Syslog distant
# ssh syslog.mycorp.internal
# tail -f /var/log/syslog | grep secure-file-exchange
```

---

## Accès SFTP Sécurisé

**Permettre aux utilisateurs de déposer des fichiers via SFTP dans `/DATA/IN/`.**

### Créer un Utilisateur SFTP

```bash
# Créer un utilisateur dédié (chroot SFTP)
sudo useradd -m -s /bin/bash sftpuser

# Créer un mot de passe fort
sudo passwd sftpuser

# Créer le répertoire de dépôt
sudo mkdir -p /home/sftpuser/upload
sudo chown sftpuser:sftpuser /home/sftpuser/upload

# Lier /DATA/IN/ au répertoire de l'utilisateur SFTP
sudo mount --bind /DATA/IN /home/sftpuser/upload
echo "/DATA/IN /home/sftpuser/upload none bind 0 0" | sudo tee -a /etc/fstab
```

### Configuration SSH (Chroot SFTP)

```bash
# Éditer /etc/ssh/sshd_config
sudo tee -a /etc/ssh/sshd_config <<EOF

# Configuration SFTP sécurisé
Match User sftpuser
    ChrootDirectory /home/sftpuser
    ForceCommand internal-sftp
    AllowTcpForwarding no
    X11Forwarding no
    PasswordAuthentication yes
EOF

# Vérifier la configuration
sudo sshd -t

# Redémarrer SSH
sudo systemctl restart sshd

# Tester la connexion SFTP
sftp sftpuser@localhost

# Dans SFTP :
# sftp> cd upload
# sftp> put test.txt
# sftp> ls
# sftp> exit
```

---

## Monitoring & Alerting

### Dashboard de Monitoring

```bash
#!/bin/bash
# /usr/local/bin/monitor_sas.sh
# Dashboard de monitoring du Sas sécurisé

echo "========================================="
echo "  Secure File Exchange - Dashboard"
echo "========================================="
echo ""

# Service de détection
echo "[*] Service de détection :"
systemctl is-active detect-file --quiet && echo "    ✓ detect-file.service : ACTIF" || echo "    ✗ detect-file.service : INACTIF"
echo ""

# Service ClamAV
echo "[*] Service ClamAV :"
systemctl is-active clamav-daemon --quiet && echo "    ✓ clamav-daemon : ACTIF" || echo "    ✗ clamav-daemon : INACTIF"
echo ""

# Signatures antivirus
echo "[*] Signatures antivirus :"
CLAMAV_VERSION=$(clamdscan --version | head -1)
echo "    ${CLAMAV_VERSION}"
LAST_UPDATE=$(stat -c %y /var/lib/clamav/daily.cvd 2>/dev/null | cut -d' ' -f1)
echo "    Dernière mise à jour : ${LAST_UPDATE}"
echo ""

# Statistiques fichiers
echo "[*] Statistiques fichiers :"
IN_COUNT=$(find /DATA/IN -type f 2>/dev/null | wc -l)
OUT_COUNT=$(find /DATA/OUT -type f 2>/dev/null | wc -l)
QUARANTINE_COUNT=$(find /DATA/QUARANTINE -type f 2>/dev/null | wc -l)

echo "    Fichiers en attente (IN)        : ${IN_COUNT}"
echo "    Fichiers traités (OUT)          : ${OUT_COUNT}"
echo "    Fichiers en quarantaine         : ${QUARANTINE_COUNT}"
echo ""

# Espace disque
echo "[*] Espace disque /DATA :"
df -h /DATA | tail -1
echo ""

# Derniers scans (via syslog)
echo "[*] Derniers scans (5 derniers) :"
journalctl -t secure-file-exchange --no-pager -n 5 --output=short-iso
echo ""

echo "========================================="
```

**Ajouter au cron (toutes les 15 minutes) :**

```bash
sudo chmod +x /usr/local/bin/monitor_sas.sh

# Ajouter au cron
echo "*/15 * * * * root /usr/local/bin/monitor_sas.sh | mail -s 'Secure File Exchange - Status' admin@mycorp.com" | \
    sudo tee /etc/cron.d/monitor-sas
```

---

## Tests de Validation

### Test 1 : Fichier Sain

```bash
# Créer un fichier de test
echo "Fichier de test sain" > /tmp/test-clean.txt

# Copier dans IN
sudo cp /tmp/test-clean.txt /DATA/IN/

# Observer les logs
tail -f /DATA/LOGS/scan_data.log

# Vérifier que le fichier est dans OUT
ls -la /DATA/OUT/
```

### Test 2 : Fichier Infecté (EICAR)

```bash
# Créer le fichier de test EICAR (signature de test standard)
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar.txt

# Copier dans IN
sudo cp /tmp/eicar.txt /DATA/IN/

# Observer les logs
tail -f /DATA/LOGS/scan_data.log

# Vérifier que le fichier est en QUARANTINE
ls -la /DATA/QUARANTINE/

# Vérifier les alertes syslog
journalctl -t secure-file-exchange | grep VIRUS_DETECTED
```

### Test 3 : Performance (Fichiers Multiples)

```bash
# Créer 100 fichiers de test
for i in {1..100}; do
    echo "Test file $i" > /tmp/test-$i.txt
done

# Copier tous les fichiers d'un coup
sudo cp /tmp/test-*.txt /DATA/IN/

# Observer le traitement parallèle
watch -n 1 'ls -1 /DATA/IN/ | wc -l; ls -1 /DATA/OUT/ | wc -l'

# Vérifier les logs de performance
journalctl -u detect-file -f
```

---

## Référence Rapide

```bash
# === SERVICES ===
sudo systemctl status detect-file          # Service de détection
sudo systemctl status clamav-daemon        # ClamAV daemon
sudo systemctl restart detect-file         # Redémarrer détection

# === LOGS ===
tail -f /DATA/LOGS/detect_file.log         # Détection fichiers
tail -f /DATA/LOGS/scan_data.log           # Scan antivirus
tail -f /DATA/LOGS/cleanup.log             # Nettoyage
journalctl -t secure-file-exchange -f     # Syslog centralisé

# === STATISTIQUES ===
find /DATA/IN -type f | wc -l              # Fichiers en attente
find /DATA/OUT -type f | wc -l             # Fichiers traités
find /DATA/QUARANTINE -type f | wc -l      # Fichiers en quarantaine

# === MAINTENANCE ===
/usr/local/bin/cleanup_data.sh             # Nettoyage manuel
/usr/local/bin/monitor_sas.sh              # Dashboard
sudo freshclam                             # MAJ signatures ClamAV

# === TEST ===
clamdscan /DATA/IN/fichier.txt             # Test scan manuel
sha256sum /DATA/OUT/fichier.txt            # Vérifier intégrité
```

---

## Sécurité Avancée

### Chiffrement des Fichiers au Repos

**Chiffrer `/DATA/OUT/` avec LUKS pour protéger les fichiers sains.**

```bash
# Créer une partition chiffrée LUKS
sudo cryptsetup luksFormat /dev/sdb1

# Ouvrir la partition
sudo cryptsetup luksOpen /dev/sdb1 data-encrypted

# Créer un système de fichiers
sudo mkfs.ext4 /dev/mapper/data-encrypted

# Monter automatiquement au démarrage
echo "data-encrypted /dev/sdb1 none luks" | sudo tee -a /etc/crypttab
echo "/dev/mapper/data-encrypted /DATA/OUT ext4 defaults 0 2" | sudo tee -a /etc/fstab
```

### Intégration avec Fail2Ban (Protection Bruteforce SFTP)

```bash
# Installer Fail2Ban
sudo apt install -y fail2ban

# Configuration pour SFTP
sudo cat > /etc/fail2ban/jail.d/sftp.conf <<EOF
[sshd]
enabled = true
port = 22
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
EOF

# Redémarrer Fail2Ban
sudo systemctl restart fail2ban

# Vérifier les bans
sudo fail2ban-client status sshd
```

### Limitation de Taille de Fichiers

**Rejeter les fichiers trop volumineux (ex: > 100 MB).**

```bash
# Modifier detect_file.sh pour ajouter :
FILE_SIZE_MB=$(stat -c%s "${FILE}" | awk '{print int($1/1024/1024)}')
MAX_SIZE_MB=100

if [ ${FILE_SIZE_MB} -gt ${MAX_SIZE_MB} ]; then
    log "[REJET] Fichier trop volumineux : ${FILE_SIZE_MB} MB (max: ${MAX_SIZE_MB} MB)"
    mv "${FILE}" "${QUARANTINE_DIR}/"
    logger -t ${SYSLOG_TAG} -p user.warning "FILE_TOO_LARGE: filename=${FILENAME} size_mb=${FILE_SIZE_MB}"
    continue
fi
```
