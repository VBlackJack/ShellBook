---
tags:
  - tlog
  - audit
  - tuned
  - performance
  - sosreport
  - cockpit
---

# RHEL Ops : Session Recording & Tuning

## Session Recording (tlog) : L'Enregistreur de Sessions

**tlog** permet d'enregistrer les sessions SSH des administrateurs (comme une "vidéo" du terminal). C'est une exigence **SecNumCloud** et **PCI-DSS** pour tracer les actions privilégiées.

### Concept

À la différence d'**auditd** (qui log les syscalls), **tlog** enregistre **tout ce qui est tapé et affiché** dans un terminal :

- Commandes exécutées
- Sorties des commandes
- Erreurs
- Timing (horodatage précis)

Les sessions sont stockées dans **systemd journal** ou **syslog** et peuvent être **rejouées** avec `tlog-play`.

### Installation

```bash
# Installer tlog
dnf install tlog -y

# Vérifier
rpm -qa | grep tlog
# tlog-14-1.el9.x86_64
```

### Configuration : Enregistrer un Groupe d'Admins

#### 1. Créer un Groupe Surveillé

```bash
# Créer le groupe "admins-audit"
groupadd admins-audit

# Ajouter des utilisateurs
usermod -aG admins-audit john
usermod -aG admins-audit alice

# Vérifier
getent group admins-audit
# admins-audit:x:1001:john,alice
```

#### 2. Configurer SSSD pour Utiliser tlog

```bash
# Éditer la configuration SSSD
vim /etc/sssd/sssd.conf

# Ajouter à la fin :
[session_recording]
scope = some
users = john, alice
groups = admins-audit

# Redémarrer SSSD
systemctl restart sssd
```

#### 3. Tester l'Enregistrement

```bash
# Se connecter en tant qu'utilisateur surveillé
ssh john@localhost

# La session est maintenant enregistrée !
# Toute commande tapée sera loggée

# Sortir
exit
```

### Visualiser les Sessions Enregistrées

#### Lister les Sessions

```bash
# Voir les sessions dans journalctl
journalctl -o verbose TLOG_REC | grep TLOG_REC

# Exemple de sortie :
# Jan 15 10:30:00 server tlog-rec-session[12345]: {"ver":"2.3","host":"server",...}
```

#### Rejouer une Session (tlog-play)

```bash
# Trouver l'ID de la session
journalctl -o json TLOG_REC | jq -r '.TLOG_REC' | head -1
# ID: abc123def456

# Rejouer la session (comme une vidéo)
tlog-play -r journal -M TLOG_REC=abc123def456

# Contrôles :
# Espace = Pause/Play
# < / >  = Vitesse (plus lent / plus rapide)
# q      = Quitter
```

#### Exemple Concret

```bash
# Session enregistrée :
john@server:~$ sudo rm -rf /var/log/critical.log
john@server:~$ systemctl restart firewalld
john@server:~$ exit

# Plus tard, l'auditeur peut rejouer EXACTEMENT ce qui a été fait :
tlog-play -r journal -M TLOG_REC=abc123def456

# La "vidéo" se rejoue avec les mêmes timings !
```

### Exporter les Sessions pour Archivage

```bash
# Exporter une session en JSON
journalctl -o json TLOG_REC=abc123def456 > /var/log/tlog/session-abc123.json

# Compresser pour archivage long terme
gzip /var/log/tlog/session-abc123.json

# Les sessions peuvent être rejouées plus tard depuis le JSON
tlog-play -i /var/log/tlog/session-abc123.json.gz
```

### Intégration avec Cockpit

**Cockpit** (l'interface web RHEL) peut afficher les sessions tlog.

```bash
# Installer le module Session Recording
dnf install cockpit-session-recording -y

# Redémarrer Cockpit
systemctl restart cockpit.socket

# Accéder à l'interface
# https://server:9090
# Menu : Session Recording

# Fonctionnalités :
# - Lister toutes les sessions enregistrées
# - Filtrer par utilisateur, date, durée
# - Rejouer dans le navigateur web (player HTML5)
# - Télécharger les sessions
```

### Configuration Avancée : Syslog Distant

Pour centraliser les enregistrements sur un serveur de logs :

```bash
# Configurer tlog pour envoyer vers syslog
vim /etc/tlog/tlog-rec-session.conf

# Modifier :
{
  "writer": "syslog",
  "syslog": {
    "facility": "authpriv",
    "priority": "info"
  }
}

# Configurer rsyslog pour forwarder
vim /etc/rsyslog.d/tlog.conf

# Ajouter :
authpriv.* @@logserver.example.com:514

# Redémarrer rsyslog
systemctl restart rsyslog
```

!!! warning "RGPD & Enregistrement de Sessions"
    Les sessions enregistrées contiennent **tout** ce qui est tapé, y compris :

    - Mots de passe tapés en clair (si l'admin fait une erreur)
    - Données sensibles affichées (commandes `cat /etc/shadow`)
    - Informations personnelles

    **Bonnes pratiques :**

    - Informer les admins qu'ils sont enregistrés (banner SSH)
    - Définir une politique de rétention (30/90 jours max)
    - Restreindre l'accès aux sessions (chmod 600, ACL)
    - Chiffrer le stockage (LUKS, vault)

## Performance Tuning : tuned

**tuned** est un démon qui ajuste automatiquement les paramètres système pour optimiser les performances selon un **profil**.

### Concept

Au lieu de tuner manuellement `/etc/sysctl.conf`, tuned applique des **profils préconfigurés** qui modifient :

- Paramètres kernel (`vm.swappiness`, `net.core.rmem_max`, etc.)
- Governor CPU (performance vs économie d'énergie)
- Politiques I/O disque (deadline, cfq, noop)
- Paramètres réseau (TCP window, backlog)

### Installation & État

```bash
# Installer tuned (déjà présent sur RHEL minimal)
dnf install tuned -y

# Activer et démarrer
systemctl enable --now tuned

# Vérifier l'état
systemctl status tuned
# Active: active (running)

# Voir le profil actif
tuned-adm active
# Current active profile: virtual-guest
```

### Lister les Profils Disponibles

```bash
# Lister tous les profils
tuned-adm list

# Sortie :
# Available profiles:
# - accelerator-performance
# - balanced
# - desktop
# - hpc-compute
# - latency-performance
# - network-latency
# - network-throughput
# - powersave
# - throughput-performance
# - virtual-guest
# - virtual-host
# Current active profile: virtual-guest
```

### Tableau des Profils Recommandés

| Profil | Use Case | Optimisations Clés | Environnement |
|--------|----------|-------------------|---------------|
| **virtual-guest** | VM (défaut) | Swap réduit, I/O adapté virtuel | VMs KVM/VMware |
| **virtual-host** | Hyperviseur | CPU performance, I/O aggresif | Serveur KVM/oVirt |
| **throughput-performance** | Débit max | I/O deadline, TCP large windows | BDD, File Server, NAS |
| **latency-performance** | Latence min | CPU governor performance, irqbalance | Trading, VoIP, Gaming |
| **network-latency** | Réseau faible latence | TCP no delay, buffer tuning | API Gateway, Proxy |
| **network-throughput** | Réseau gros débit | MTU 9000, TSO enabled | Data Transfer, Backup |
| **balanced** | Usage général | Compromis performance/power | Desktop, Dev |
| **powersave** | Économie d'énergie | CPU ondemand, disques spin-down | Laptop, Edge devices |

### Changer de Profil

```bash
# Passer en mode haute performance
tuned-adm profile throughput-performance

# Vérifier
tuned-adm active
# Current active profile: throughput-performance

# Voir les paramètres appliqués
tuned-adm profile_info throughput-performance

# Redémarrer tuned (si nécessaire)
systemctl restart tuned
```

### Exemples Pratiques

#### Serveur de Base de Données (PostgreSQL/MySQL)

```bash
# Optimiser pour le débit I/O et CPU
tuned-adm profile throughput-performance

# Vérifier les changements appliqués
sysctl vm.swappiness
# vm.swappiness = 10  (au lieu de 60 par défaut)

cat /sys/block/sda/queue/scheduler
# [deadline] cfq noop  (deadline sélectionné)
```

#### Serveur Web (Nginx/Apache)

```bash
# Optimiser pour le réseau à faible latence
tuned-adm profile network-latency

# Vérifier TCP tuning
sysctl net.ipv4.tcp_low_latency
# net.ipv4.tcp_low_latency = 1
```

#### VM (KVM Guest)

```bash
# Profil par défaut recommandé
tuned-adm profile virtual-guest

# Optimisations appliquées :
# - vm.swappiness = 30
# - I/O scheduler : deadline (meilleur pour VirtIO)
# - CPU governor : ondemand (balance perf/power)
```

### Créer un Profil Custom

```bash
# Créer un profil basé sur throughput-performance
mkdir /etc/tuned/my-custom-profile

# Créer la config
cat > /etc/tuned/my-custom-profile/tuned.conf <<EOF
[main]
summary=Custom profile for my app
include=throughput-performance

[sysctl]
# Augmenter les buffers réseau
net.core.rmem_max=134217728
net.core.wmem_max=134217728

# Swappiness ultra-low pour BDD
vm.swappiness=5

[vm]
transparent_hugepages=always
EOF

# Activer le profil custom
tuned-adm profile my-custom-profile

# Vérifier
tuned-adm active
# Current active profile: my-custom-profile
```

### Désactiver tuned (si nécessaire)

```bash
# Passer en mode "off"
tuned-adm off

# Stopper le service
systemctl stop tuned
systemctl disable tuned

# Les paramètres système reviennent aux valeurs par défaut
```

## Cockpit : Interface Web d'Administration (Web Console)

**Cockpit** est l'interface web officielle de RHEL/CentOS (port **9090**). Souvent sous-estimée, elle est pourtant indispensable pour les Ops modernes.

### Pourquoi l'utiliser ?
*   **Monitoring Temps Réel** : Graphes CPU/RAM/Disque/Réseau fluides (via PCP).
*   **Gestion du Stockage** : Redimensionner un volume LVM ou monter un NFS en 2 clics (plus sûr que la CLI).
*   **Session Recording** : Visualiser les sessions `tlog` comme une vidéo YouTube.
*   **Conteneurs** : Gérer Podman (images, conteneurs) visuellement.
*   **Terminal Web** : Un shell root d'urgence accessible même si SSH est cassé (si le service web tourne).

### Installation & Activation

```bash
# Installer Cockpit (déjà présent sur RHEL 8+)
dnf install cockpit -y

# Activer et démarrer
systemctl enable --now cockpit.socket

# Ouvrir le firewall
firewall-cmd --add-service=cockpit --permanent
firewall-cmd --reload

# Accéder à l'interface
# https://server:9090
# Login : root ou user avec sudo
```

### Modules Essentiels pour les Ops

Pour tirer le plein potentiel de Cockpit, installez ces plugins :

```bash
# Métriques historiques (PCP - Performance Co-Pilot)
# Permet de voir l'historique CPU/RAM des jours précédents
dnf install cockpit-pcp -y

# Session Recording (tlog)
# Pour voir les replays des sessions SSH
dnf install cockpit-session-recording -y

# Gestion des machines virtuelles (KVM/Libvirt)
dnf install cockpit-machines -y

# Gestion Podman (Conteneurs)
dnf install cockpit-podman -y

# Gestion des mises à jour (Kpatch, DNF)
dnf install cockpit-packagekit -y

# Redémarrer Cockpit pour prendre en compte les modules
systemctl restart cockpit.socket
```

### Fonctionnalités Clés en Détail

#### 1. Stockage (Storage)
Le module le plus puissant. Il visualise :
*   Les disques physiques
*   Les groupes de volumes LVM (VG)
*   Les volumes logiques (LV) et leur remplissage
*   Les montages NFS/iSCSI
*   Les logs d'erreurs disque (SMART)

**Action typique :** Agrandir un FS à chaud.
1.  Cliquer sur le Volume Group.
2.  Cliquer sur le Logical Volume.
3.  "Grow" -> Slider vers la nouvelle taille -> "Apply".
4.  C'est fait (lvextend + resizefs automatique).

#### 2. Réseau (Networking)
*   Créer un **Bonding** (agrégation de cartes) ou un **Bridge** (pour VMs).
*   Configurer le pare-feu **Firewalld** (ouvrir des ports) sans connaître la syntaxe riche.
*   Voir les logs réseau en temps réel.

#### 3. Diagnostic (Logs & SELinux)
Cockpit agrège `journalctl` et `audit.log`.
*   Si SELinux bloque quelque chose, une alerte apparaît avec un bouton "Troubleshoot" qui propose la solution (le booléen à activer). C'est `audit2why` intégré !

### Accès Distant Sécurisé

```bash
# Par défaut, Cockpit écoute sur toutes les interfaces
# Pour restreindre à localhost + reverse proxy :
vim /etc/systemd/system/cockpit.socket.d/listen.conf

[Socket]
ListenStream=
ListenStream=127.0.0.1:9090

# Redémarrer
systemctl daemon-reload
systemctl restart cockpit.socket

# Configurer Nginx reverse proxy avec authentification
# (exemple dans le guide rhel-networking.md)
```

### Activer l'Authentification 2FA (PAM)

```bash
# Installer Google Authenticator PAM
dnf install google-authenticator -y

# Configurer pour un user
google-authenticator

# Éditer PAM pour Cockpit
vim /etc/pam.d/cockpit

# Ajouter APRÈS la ligne auth include system-auth :
auth required pam_google_authenticator.so

# Redémarrer
systemctl restart cockpit.socket

# Maintenant, login nécessite mot de passe + code TOTP
```

## Diagnostic Support : sosreport

**sosreport** génère une archive complète du système pour le **support Red Hat**. C'est la première chose à fournir lors d'un ticket.

### Génération d'un Rapport

```bash
# Installer sos
dnf install sos -y

# Générer le rapport (interactif)
sos report

# Répondre aux questions :
# - Entrer un numéro de ticket (case ID)
# - Confirmer

# Le rapport est généré dans /var/tmp/
# Sortie :
# Your sosreport has been generated and saved in:
#   /var/tmp/sosreport-server-2025-01-15-abc123.tar.xz
```

### Contenu du Rapport

Le sosreport capture :

- **Logs** : `/var/log/*`, journalctl
- **Configuration** : `/etc/*` (sanitisé)
- **État système** : `uname`, `lsblk`, `ip addr`, `ps aux`
- **Paquets** : `rpm -qa`
- **Services** : `systemctl list-units`
- **Kernel** : `dmesg`, modules chargés
- **Réseau** : Routes, firewall, SELinux
- **Performance** : `free`, `top`, `vmstat`

**Ce qui est EXCLU :**
- Mots de passe (sanitisés automatiquement)
- Données utilisateur dans `/home`
- Bases de données (contenu)

### Options Utiles

```bash
# Générer sans confirmation (batch mode)
sos report --batch

# Ajouter un numéro de case
sos report --case-id=12345678

# Collecter seulement certains plugins
sos report --only-plugins=firewalld,selinux,networking

# Exclure des plugins (ex: MySQL si trop gros)
sos report --skip-plugins=mysql

# Activer le debug (capture plus de détails)
sos report --debug

# Uploader directement vers Red Hat (nécessite subscription)
sos report --upload
```

### Envoyer le Rapport au Support

```bash
# Via Red Hat Customer Portal
# 1. Se connecter : https://access.redhat.com/support/cases/
# 2. Ouvrir le ticket
# 3. Cliquer "Attach files"
# 4. Uploader /var/tmp/sosreport-*.tar.xz

# Ou via FTP Red Hat (si accès direct)
redhat-support-tool addattachment --case-number=12345678 \
  /var/tmp/sosreport-server-2025-01-15-abc123.tar.xz
```

### sosreport Automatique en Cas de Kernel Panic

```bash
# Installer kdump (capture dump kernel)
dnf install kexec-tools -y

# Activer
systemctl enable kdump

# Réserver mémoire pour kdump (reboot requis)
grubby --update-kernel=ALL --args="crashkernel=auto"
reboot

# En cas de kernel panic, un vmcore sera généré dans /var/crash/
# Puis générer un sosreport incluant le crash
sos report --plugin-option=kdump.include-vmcore=yes
```

## Checklist Ops Production

```bash
# 1. Session Recording actif pour les admins
systemctl is-active sssd
journalctl -u tlog-rec-session --since "1 day ago" | wc -l
# > 0 (des sessions enregistrées)

# 2. Profil tuned adapté à l'usage
tuned-adm active
# Doit correspondre au rôle du serveur

# 3. Cockpit accessible et sécurisé
systemctl is-active cockpit.socket
firewall-cmd --list-services | grep cockpit

# 4. SOS installé et fonctionnel
sos report --batch --dry-run
# (Ne génère pas vraiment, juste un test)

# 5. Métriques historiques activées (PCP)
rpm -qa | grep cockpit-pcp
systemctl is-active pmlogger

# 6. Logs centralisés (rsyslog distant)
grep "@@logserver" /etc/rsyslog.conf

# 7. Backup des sessions tlog
ls -lh /var/log/tlog/ | wc -l
```

## Comparaison : tlog vs auditd vs script

| Critère | tlog | auditd | script (command) |
|---------|------|--------|------------------|
| **Ce qui est capturé** | Terminal complet (in/out) | Syscalls + commandes | Terminal complet |
| **Format** | JSON (rejouable) | Logs texte | Script typescript |
| **Intégration** | SSSD, Cockpit, journal | Natif kernel | Manuel |
| **Performance** | Faible impact | Impact modéré | Impact très faible |
| **Conformité** | SecNumCloud, PCI-DSS | Toutes (basique) | Non (pas d'horodatage fiable) |
| **Lecture** | tlog-play (vidéo) | ausearch/aureport | scriptreplay |
| **Stockage** | Centralisable (syslog) | /var/log/audit/ | Fichiers locaux |

!!! tip "Combinaison Recommandée"
    En production SecNumCloud :

    - **auditd** : Audit système (fichiers critiques, syscalls)
    - **tlog** : Enregistrement sessions admins (traçabilité complète)
    - **OpenSCAP** : Conformité automatisée (voir rhel-openscap-compliance.md)

## Liens Utiles

- [tlog Documentation](https://github.com/Scribery/tlog)
- [tuned Performance Guide](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html/monitoring_and_managing_system_status_and_performance/customizing-tuned-profiles_monitoring-and-managing-system-status-and-performance)
- [Cockpit Documentation](https://cockpit-project.org/guide/latest/)
- [sosreport User Guide](https://access.redhat.com/solutions/3592)
- [Red Hat Performance Tuning Guide](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html/monitoring_and_managing_system_status_and_performance/)
