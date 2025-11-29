---
tags:
  - formation
  - linux
  - cheatsheet
  - commandes
  - reference
---

# Cheatsheet Commandes Linux

Référence rapide des commandes Linux essentielles.

---

## Navigation & Fichiers

```bash
# Navigation
pwd                     # Répertoire courant
cd /path/to/dir         # Changer de répertoire
cd ~                    # Home directory
cd -                    # Répertoire précédent
ls -la                  # Liste détaillée avec fichiers cachés
ls -lh                  # Tailles lisibles (human readable)
tree -L 2               # Arborescence (2 niveaux)

# Manipulation de fichiers
cp source dest          # Copier
cp -r src/ dest/        # Copier récursif
mv source dest          # Déplacer/renommer
rm fichier              # Supprimer
rm -rf dossier/         # Supprimer récursif (ATTENTION!)
mkdir -p a/b/c          # Créer répertoires imbriqués
touch fichier           # Créer fichier vide

# Liens
ln -s target linkname   # Lien symbolique
ln target linkname      # Lien physique

# Recherche
find / -name "*.log"                    # Par nom
find / -type f -size +100M              # Fichiers > 100MB
find / -mtime -7                        # Modifiés < 7 jours
find / -user root -perm 777             # Par user et perms
locate fichier                          # Recherche rapide (base de données)
which commande                          # Chemin d'une commande
whereis commande                        # Binaire, sources, man
```

---

## Permissions

```bash
# Lecture des permissions
# -rwxr-xr-x = user(rwx) group(r-x) other(r-x)

# chmod - Modifier les permissions
chmod 755 fichier       # rwxr-xr-x
chmod 644 fichier       # rw-r--r--
chmod u+x fichier       # Ajouter exec pour user
chmod go-w fichier      # Retirer write pour group/other
chmod -R 755 dossier/   # Récursif

# chown - Modifier propriétaire
chown user fichier
chown user:group fichier
chown -R user:group /path/

# Permissions spéciales
chmod u+s fichier       # SUID
chmod g+s dossier       # SGID
chmod +t dossier        # Sticky bit

# umask
umask                   # Voir le masque actuel
umask 022              # Définir (fichiers=644, dossiers=755)

# ACL
getfacl fichier
setfacl -m u:user:rwx fichier
setfacl -m g:group:rx fichier
setfacl -x u:user fichier  # Supprimer
```

---

## Texte & Filtres

```bash
# Affichage
cat fichier             # Tout le contenu
head -20 fichier        # 20 premières lignes
tail -50 fichier        # 50 dernières lignes
tail -f fichier         # Suivre en temps réel
less fichier            # Pagination

# Recherche dans fichiers
grep "pattern" fichier
grep -r "pattern" /path/         # Récursif
grep -i "pattern" fichier        # Insensible à la casse
grep -v "pattern" fichier        # Inverser (exclure)
grep -E "regex" fichier          # Extended regex
grep -c "pattern" fichier        # Compter les matches
grep -l "pattern" *.txt          # Fichiers contenant

# Manipulation de texte
sed 's/old/new/g' fichier        # Remplacer
sed -i 's/old/new/g' fichier     # Remplacer in-place
sed -n '10,20p' fichier          # Lignes 10-20
awk '{print $1, $3}' fichier     # Colonnes 1 et 3
awk -F: '{print $1}' /etc/passwd # Delimiter :
cut -d: -f1 /etc/passwd          # Couper par delimiter
sort fichier                     # Trier
sort -n fichier                  # Tri numérique
sort -r fichier                  # Tri inverse
uniq                             # Supprimer doublons consécutifs
sort | uniq -c                   # Compter occurrences
wc -l fichier                    # Compter lignes
tr 'a-z' 'A-Z'                   # Transformer
```

---

## Processus

```bash
# Affichage
ps aux                  # Tous les processus
ps aux --sort=-%cpu     # Trié par CPU
ps aux --sort=-%mem     # Trié par mémoire
ps -ef --forest         # Arborescence
pstree -p               # Arbre avec PIDs
top                     # Moniteur interactif
htop                    # Moniteur amélioré

# Gestion
kill PID                # Terminer (SIGTERM)
kill -9 PID             # Forcer (SIGKILL)
killall nom             # Par nom
pkill -f "pattern"      # Par pattern
pgrep -f "pattern"      # Trouver PID

# Background/Foreground
commande &              # Lancer en background
jobs                    # Lister les jobs
fg %1                   # Ramener au premier plan
bg %1                   # Envoyer en background
nohup commande &        # Persist après déconnexion
disown                  # Détacher du shell

# Priorité
nice -n 10 commande     # Lancer avec priorité basse
renice 10 -p PID        # Modifier priorité
```

---

## Système

```bash
# Informations système
uname -a                # Info kernel
hostnamectl             # Hostname et OS
cat /etc/os-release     # Distribution
uptime                  # Temps depuis boot
date                    # Date/heure

# Ressources
free -h                 # Mémoire
df -h                   # Espace disque
du -sh /path/           # Taille d'un dossier
du -h --max-depth=1     # Taille par sous-dossier
lscpu                   # Info CPU
lsblk                   # Périphériques bloc
lspci                   # Périphériques PCI
lsusb                   # Périphériques USB

# Logs
journalctl              # Tous les logs
journalctl -u service   # Logs d'un service
journalctl -f           # Suivre en temps réel
journalctl -p err       # Erreurs seulement
journalctl --since "1 hour ago"
dmesg                   # Messages kernel
```

---

## Services (systemd)

```bash
# Gestion des services
systemctl status service
systemctl start service
systemctl stop service
systemctl restart service
systemctl reload service
systemctl enable service
systemctl disable service
systemctl enable --now service  # Enable + start

# Informations
systemctl list-units --type=service
systemctl list-units --failed
systemctl is-active service
systemctl is-enabled service
systemctl cat service           # Afficher le fichier unit

# Logs
journalctl -u service -f
```

---

## Réseau

```bash
# Configuration
ip addr                 # Interfaces et IPs
ip -4 addr              # IPv4 seulement
ip route                # Table de routage
ip link set eth0 up/down
nmcli device status     # NetworkManager
nmcli con show          # Connexions

# Diagnostic
ping -c 4 host          # Test connectivité
traceroute host         # Chemin réseau
tracepath host          # Alternative sans root
mtr host                # Traceroute interactif
dig domain              # Résolution DNS
nslookup domain         # DNS lookup
host domain             # DNS simple

# Ports et connexions
ss -tuln                # Ports en écoute
ss -tulnp               # Avec PIDs
ss -tn state established # Connexions établies
netstat -tulnp          # Alternative (deprecated)
lsof -i :80             # Qui utilise le port 80

# Transfert
curl -O url             # Télécharger fichier
curl -I url             # Headers seulement
wget url                # Télécharger
scp file user@host:/path/ # Copie SSH
rsync -avz src/ dest/   # Synchronisation
```

---

## Paquets

### APT (Debian/Ubuntu)

```bash
apt update              # Mettre à jour la liste
apt upgrade             # Mettre à jour les paquets
apt install package
apt remove package
apt purge package       # Remove + config
apt search keyword
apt show package
apt list --installed
apt autoremove          # Supprimer orphelins
```

### DNF (RHEL/Rocky/Fedora)

```bash
dnf update              # Mettre à jour
dnf install package
dnf remove package
dnf search keyword
dnf info package
dnf list installed
dnf provides /path/file # Qui fournit ce fichier
dnf history             # Historique transactions
dnf clean all           # Nettoyer cache
```

---

## Stockage & LVM

```bash
# Partitions
fdisk -l                # Lister les disques
fdisk /dev/sdb          # Partitionner
parted /dev/sdb         # Alternative moderne
mkfs.ext4 /dev/sdb1     # Formater
mkfs.xfs /dev/sdb1

# Montage
mount /dev/sdb1 /mnt
umount /mnt
mount -a                # Monter tout /etc/fstab

# LVM
pvs                     # Physical Volumes
vgs                     # Volume Groups
lvs                     # Logical Volumes
pvcreate /dev/sdb
vgcreate vg_data /dev/sdb
lvcreate -L 10G -n lv_data vg_data
lvextend -L +5G /dev/vg_data/lv_data
resize2fs /dev/vg_data/lv_data  # ext4
xfs_growfs /mount/point         # xfs
```

---

## Utilisateurs & Groupes

```bash
# Utilisateurs
useradd -m -s /bin/bash user    # Créer avec home
useradd -r -s /sbin/nologin svc # Service account
usermod -aG group user          # Ajouter au groupe
userdel -r user                 # Supprimer avec home
passwd user                     # Changer mot de passe
chsh -s /bin/zsh user           # Changer shell

# Groupes
groupadd group
groupdel group
groups user             # Groupes d'un user

# Informations
id user                 # UID, GID, groupes
whoami                  # User courant
who                     # Users connectés
last                    # Historique connexions

# Sudo
visudo                  # Éditer sudoers
sudo -l                 # Lister ses droits sudo
sudo -u user commande   # Exécuter en tant que
```

---

## Archives & Compression

```bash
# tar
tar -cvf archive.tar /path/     # Créer
tar -czvf archive.tar.gz /path/ # Créer compressé gzip
tar -cjvf archive.tar.bz2 /path/ # Créer compressé bzip2
tar -xvf archive.tar            # Extraire
tar -xzvf archive.tar.gz        # Extraire gzip
tar -xvf archive.tar -C /dest/  # Extraire vers
tar -tvf archive.tar            # Lister contenu

# Compression
gzip fichier            # → fichier.gz
gunzip fichier.gz       # Décompresser
bzip2 fichier           # → fichier.bz2
bunzip2 fichier.bz2
xz fichier              # → fichier.xz
unxz fichier.xz
zip -r archive.zip dossier/
unzip archive.zip
```

---

## SSH

```bash
# Connexion
ssh user@host
ssh -p 2222 user@host           # Port custom
ssh -i key.pem user@host        # Clé spécifique

# Clés
ssh-keygen -t ed25519           # Générer clé
ssh-copy-id user@host           # Copier clé publique
ssh-agent bash                  # Démarrer agent
ssh-add ~/.ssh/id_ed25519       # Ajouter clé

# Tunnel
ssh -L 8080:localhost:80 user@host  # Local forward
ssh -R 8080:localhost:80 user@host  # Remote forward
ssh -D 1080 user@host               # SOCKS proxy

# Transfert
scp file user@host:/path/
scp -r dir/ user@host:/path/
rsync -avz -e ssh src/ user@host:/dest/
```

---

## Scripting Bash

```bash
#!/bin/bash
set -euo pipefail       # Mode strict

# Variables
VAR="value"
VAR=${VAR:-default}     # Valeur par défaut
readonly CONST="value"  # Constante

# Conditions
if [[ $VAR == "value" ]]; then
    echo "match"
elif [[ $VAR =~ ^[0-9]+$ ]]; then
    echo "number"
else
    echo "other"
fi

# Boucles
for item in a b c; do
    echo "$item"
done

for i in {1..10}; do
    echo "$i"
done

while read -r line; do
    echo "$line"
done < fichier

# Fonctions
my_function() {
    local var=$1
    echo "Arg: $var"
    return 0
}

# Tableaux
arr=("a" "b" "c")
echo "${arr[0]}"        # Premier élément
echo "${arr[@]}"        # Tous
echo "${#arr[@]}"       # Longueur

# Substitutions
$(commande)             # Command substitution
${VAR%suffix}           # Remove suffix
${VAR#prefix}           # Remove prefix
${VAR/old/new}          # Replace first
${VAR//old/new}         # Replace all
```

---

## Docker

```bash
# Images
docker pull image:tag
docker images
docker rmi image
docker build -t name:tag .

# Conteneurs
docker run -d --name c1 -p 8080:80 image
docker ps
docker ps -a
docker logs -f container
docker exec -it container /bin/sh
docker stop container
docker rm container

# Volumes & Réseaux
docker volume create vol
docker network create net
docker run -v vol:/data -v /host:/container image
docker run --network net image

# Compose
docker compose up -d
docker compose down
docker compose logs -f
docker compose ps

# Nettoyage
docker system prune -a
```

---

## Kubernetes (kubectl)

```bash
# Ressources
kubectl get pods
kubectl get pods -o wide
kubectl get all
kubectl get svc,deploy,pods

# Détails
kubectl describe pod name
kubectl logs -f pod
kubectl exec -it pod -- /bin/sh

# CRUD
kubectl apply -f manifest.yaml
kubectl delete -f manifest.yaml
kubectl create deployment name --image=image

# Scaling & Updates
kubectl scale deploy/name --replicas=3
kubectl set image deploy/name container=image:tag
kubectl rollout status deploy/name
kubectl rollout undo deploy/name

# Debug
kubectl get events --sort-by='.lastTimestamp'
kubectl top pods
kubectl port-forward pod 8080:80
```

---

**Retour au :** [Programme de la Formation](index.md)
