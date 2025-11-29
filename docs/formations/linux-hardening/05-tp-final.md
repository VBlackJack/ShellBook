---
tags:
  - formation
  - security
  - hardening
  - lab
  - tp
  - secnumcloud
  - challenge
---

# Module 5 : TP Final - Le Hardening Challenge

## Objectif du TP

Mettre en pratique l'ensemble des compétences acquises dans les Modules 1 à 4 pour transformer un serveur vulnérable en forteresse sécurisée conforme aux standards SecNumCloud.

**Durée :** 3 heures

**Type :** Travaux Pratiques (Hands-on Lab)

## Scénario : Le Serveur Passoire

### Contexte de Mission

**Lundi 08h00 - Votre premier jour :**

Vous venez d'être embauché comme **Ingénieur Sécurité** dans une startup en pleine croissance. Votre manager vous accueille avec un café... et une mauvaise nouvelle :

> **Manager :** "Bienvenue ! Mauvaise nouvelle : notre ancien admin est parti en urgence vendredi. Il a laissé un serveur 'presque prêt' pour la prod. Sauf que... notre audit de sécurité vient de révéler que c'est une **passoire**. On le met en prod demain à 18h. Tu as jusqu'à ce soir pour le sécuriser. Bonne chance !"

**Informations du serveur :**

- **IP :** `192.168.1.100` (exemple)
- **OS :** Ubuntu 22.04 LTS / RHEL 9
- **Services :** SSH, Nginx (application web)
- **Utilisateurs :** 5 comptes (admin parti, stagiaire parti, comptes test...)
- **État actuel :** ❌ **AUCUNE** sécurisation

### Votre Mission

**Transformer ce serveur en forteresse SecNumCloud-ready en appliquant :**

1. ✅ **Module 1** : Hardening SSH
2. ✅ **Module 2** : Gestion utilisateurs et sudo
3. ✅ **Module 3** : Firewall et IPS
4. ✅ **Module 4** : Audit et traçabilité

**Contrainte de temps :** Vous avez 3 heures (simulation réaliste).

**Critère de succès :** Le serveur doit passer un test de pénétration basique (Étape 6).

---

## Étape 1 : L'Audit Initial - Reconnaissance

### Objectif

**Avant de sécuriser, il faut comprendre l'état actuel du système.**

Vous devez répondre à ces questions :

1. **Quels ports sont ouverts ?** (Risque d'exposition)
2. **Quels utilisateurs existent ?** (Comptes obsolètes ?)
3. **Qui peut utiliser sudo ?** (Permissions trop larges ?)
4. **SSH accepte-t-il les mots de passe ?** (Risque brute-force)
5. **Y a-t-il un firewall actif ?** (Probablement non...)

### Commandes d'Audit

#### 1. Scan des Ports Ouverts

```bash
# Lister tous les ports en écoute
sudo ss -tulpn

# OU (si netstat installé)
sudo netstat -tulpn | grep LISTEN
```

**Exemple de sortie (serveur non sécurisé) :**

```
LISTEN  0.0.0.0:22       0.0.0.0:*    users:(("sshd",pid=1234))
LISTEN  0.0.0.0:80       0.0.0.0:*    users:(("nginx",pid=5678))
LISTEN  0.0.0.0:3000     0.0.0.0:*    users:(("node",pid=9012))   ← ❌ EXPOSÉ!
LISTEN  0.0.0.0:5432     0.0.0.0:*    users:(("postgres",pid=3456)) ← ❌ EXPOSÉ!
LISTEN  0.0.0.0:6379     0.0.0.0:*    users:(("redis",pid=7890))   ← ❌ EXPOSÉ!
```

**⚠️ Problème détecté :**

- Backend (3000), PostgreSQL (5432), Redis (6379) sont **exposés publiquement** !

#### 2. Liste des Utilisateurs

```bash
# Afficher tous les utilisateurs
cat /etc/passwd

# Filtrer les utilisateurs avec shell de connexion (UID >= 1000)
awk -F: '$3 >= 1000 {print $1, $3, $7}' /etc/passwd
```

**Exemple de sortie :**

```
alice 1001 /bin/bash       ← Admin actuel (OK)
bob 1002 /bin/bash         ← Ancien admin (parti) ❌
charlie 1003 /bin/bash     ← Stagiaire (parti) ❌
testuser 1004 /bin/bash    ← Compte de test ❌
deploy 1005 /bin/bash      ← Service account (OK)
```

**⚠️ Problème détecté :**

- 3 comptes obsolètes (`bob`, `charlie`, `testuser`)

#### 3. Vérification Sudo

```bash
# Qui peut utiliser sudo ?
sudo grep -E '^[^#]' /etc/sudoers

# Vérifier les fichiers dans sudoers.d
sudo ls -la /etc/sudoers.d/
sudo cat /etc/sudoers.d/*
```

**Exemple de sortie dangereuse :**

```bash
# /etc/sudoers
bob ALL=(ALL) NOPASSWD: ALL    ← ❌ DANGEREUX (user parti!)
charlie ALL=(ALL) ALL          ← ❌ DANGEREUX (user parti!)
testuser ALL=(ALL) ALL         ← ❌ DANGEREUX
```

**⚠️ Problème détecté :**

- Comptes obsolètes avec droits sudo complets

#### 4. Configuration SSH Actuelle

```bash
# Vérifier si SSH accepte les mots de passe
sudo grep -E '^PasswordAuthentication|^PermitRootLogin|^PubkeyAuthentication' /etc/ssh/sshd_config
```

**Exemple de sortie (configuration non sécurisée) :**

```
PermitRootLogin yes                    ← ❌ ROOT AUTORISÉ!
PasswordAuthentication yes             ← ❌ BRUTE-FORCE POSSIBLE!
PubkeyAuthentication yes               ← ✅ OK
```

#### 5. État du Firewall

```bash
# Ubuntu/Debian (UFW)
sudo ufw status

# RHEL/CentOS (Firewalld)
sudo firewall-cmd --state
```

**Exemple de sortie :**

```
Status: inactive    ← ❌ FIREWALL DÉSACTIVÉ!
```

### Rapport d'Audit Initial

**Créez un document récapitulatif :**

```markdown
# Audit Sécurité - Serveur 192.168.1.100
Date: [Date du jour]
Auditeur: [Votre nom]

## Vulnérabilités Critiques Détectées

1. ❌ **Ports exposés inutilement** : PostgreSQL (5432), Redis (6379), Backend (3000)
2. ❌ **Firewall désactivé** : Aucune protection réseau
3. ❌ **SSH accepte les mots de passe** : Risque brute-force élevé
4. ❌ **Root login SSH activé** : Cible privilégiée des attaquants
5. ❌ **3 comptes utilisateurs obsolètes** avec shell actif
6. ❌ **Droits sudo trop larges** : NOPASSWD sur comptes obsolètes
7. ❌ **Aucun audit/logging** : Pas de traçabilité

## Score de Sécurité : 2/10 ⚠️ CRITIQUE

## Actions Requises
- Hardening SSH (Module 1)
- Nettoyage utilisateurs + sudo (Module 2)
- Activation firewall (Module 3)
- Configuration audit (Module 4)
```

---

## Étape 2 : Verrouillage SSH - La Porte Blindée

### Objectif

**Appliquer le Module 1 : SSH Hardening**

Transformer SSH en point d'entrée ultra-sécurisé :

1. ✅ Désactiver l'authentification par mot de passe
2. ✅ Désactiver le login root
3. ✅ Changer le port SSH (bonus)
4. ✅ Limiter les utilisateurs autorisés

### Actions à Réaliser

#### 1. Sauvegarde de la Configuration Actuelle

```bash
# TOUJOURS faire une backup avant modification
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%F)

# Vérifier la backup
ls -l /etc/ssh/sshd_config.backup.*
```

#### 2. Modification de la Configuration SSH

**⚠️ IMPORTANT :** Gardez votre session SSH actuelle **OUVERTE** pendant toute la manipulation !

```bash
# Éditer la configuration
sudo nano /etc/ssh/sshd_config
```

**Modifications à appliquer :**

```bash
# 1. Désactiver root login
PermitRootLogin no

# 2. Désactiver authentification par mot de passe
PasswordAuthentication no
ChallengeResponseAuthentication no
UsePAM yes

# 3. Activer uniquement clés publiques
PubkeyAuthentication yes

# 4. Limiter les utilisateurs autorisés (optionnel mais recommandé)
AllowUsers alice deploy

# 5. Bonus : Changer le port (optionnel)
Port 2222

# 6. Autres hardenings recommandés
PermitEmptyPasswords no
X11Forwarding no
MaxAuthTries 3
LoginGraceTime 30
```

#### 3. Vérification de la Configuration

```bash
# Tester la syntaxe (CRITIQUE avant redémarrage)
sudo sshd -t

# Si OK, aucun message d'erreur
# Si KO, corriger les erreurs affichées
```

#### 4. Redémarrage du Service SSH

```bash
# Ubuntu/Debian
sudo systemctl restart ssh

# RHEL/CentOS
sudo systemctl restart sshd

# Vérifier que le service est actif
sudo systemctl status ssh
```

#### 5. Test de Validation (Sans Fermer la Session Actuelle)

**Ouvrir un NOUVEAU terminal et tester :**

```bash
# Si vous avez changé le port
ssh -p 2222 alice@192.168.1.100

# Test : Essayer de se connecter en root (doit échouer)
ssh -p 2222 root@192.168.1.100
# Permission denied (publickey).   ← ✅ SUCCÈS

# Test : Essayer avec mot de passe (doit échouer)
ssh -o PubkeyAuthentication=no -p 2222 alice@192.168.1.100
# Permission denied (publickey).   ← ✅ SUCCÈS
```

!!! success "Étape 2 Validée"
    ✅ SSH n'accepte plus que les clés publiques

    ✅ Root ne peut plus se connecter

    ✅ Service SSH fonctionne correctement

---

## Étape 3 : Nettoyage Utilisateurs - Réduire la Surface d'Attaque

### Objectif

**Appliquer le Module 2 : Gestion Utilisateurs & Sudo**

1. ✅ Verrouiller/Supprimer les comptes obsolètes
2. ✅ Nettoyer les permissions sudo
3. ✅ Appliquer le principe du moindre privilège

### Actions à Réaliser

#### 1. Verrouillage des Comptes Obsolètes

```bash
# Lister les comptes avec shell
awk -F: '$3 >= 1000 {print $1}' /etc/passwd

# Verrouiller les comptes inutilisés
sudo usermod -L bob          # Lock password
sudo usermod -s /sbin/nologin bob   # Disable shell

sudo usermod -L charlie
sudo usermod -s /sbin/nologin charlie

sudo usermod -L testuser
sudo usermod -s /sbin/nologin testuser
```

**OU supprimer complètement (si certains que non nécessaires) :**

```bash
# Supprimer utilisateur et son home
sudo userdel -r bob
sudo userdel -r charlie
sudo userdel -r testuser

# Vérifier la suppression
cat /etc/passwd | grep -E "bob|charlie|testuser"
# (aucun résultat = suppression réussie)
```

#### 2. Nettoyage de la Configuration Sudo

```bash
# Backup du fichier sudoers
sudo cp /etc/sudoers /etc/sudoers.backup.$(date +%F)

# Éditer avec visudo (vérification syntaxe automatique)
sudo visudo
```

**Supprimer les lignes dangereuses :**

```bash
# AVANT (dangereux)
bob ALL=(ALL) NOPASSWD: ALL        ← SUPPRIMER
charlie ALL=(ALL) ALL              ← SUPPRIMER
testuser ALL=(ALL) ALL             ← SUPPRIMER

# APRÈS (sécurisé)
# Uniquement alice avec mot de passe requis
alice ALL=(ALL:ALL) ALL

# deploy avec NOPASSWD limité aux commandes spécifiques
deploy ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart myapp.service, \
                          /usr/bin/systemctl status myapp.service
```

**Nettoyer les fichiers dans sudoers.d :**

```bash
# Vérifier le contenu
sudo ls -la /etc/sudoers.d/

# Supprimer les fichiers obsolètes
sudo rm /etc/sudoers.d/bob
sudo rm /etc/sudoers.d/charlie
```

#### 3. Vérification des Groupes Sudo

```bash
# Vérifier qui est dans le groupe sudo/wheel
grep sudo /etc/group        # Ubuntu/Debian
grep wheel /etc/group       # RHEL/CentOS

# Exemple de sortie
# sudo:x:27:alice,deploy
```

**Supprimer les utilisateurs obsolètes des groupes :**

```bash
# Si bob était dans le groupe sudo
sudo gpasswd -d bob sudo

# Vérifier
grep sudo /etc/group
# sudo:x:27:alice,deploy   ← bob retiré
```

#### 4. Validation de la Configuration Sudo

```bash
# Tester la syntaxe sudoers
sudo visudo -c
# parsed OK   ← ✅ SUCCÈS

# Tester sudo en tant qu'alice (dans un nouveau terminal)
sudo whoami
# [sudo] password for alice:
# root   ← ✅ FONCTIONNE

# Vérifier que bob ne peut plus utiliser sudo
su - bob
sudo whoami
# bash: /bin/bash: Permission denied   ← ✅ SUCCÈS (shell disabled)
```

!!! success "Étape 3 Validée"
    ✅ Comptes obsolètes verrouillés/supprimés

    ✅ Configuration sudo nettoyée

    ✅ Principe du moindre privilège appliqué

---

## Étape 4 : Forteresse Réseau - Firewall & IPS

### Objectif

**Appliquer le Module 3 : Firewall (UFW/Firewalld) + Fail2Ban**

1. ✅ Activer le firewall
2. ✅ Politique par défaut : DENY ALL INCOMING
3. ✅ Autoriser UNIQUEMENT : SSH, HTTP, HTTPS
4. ✅ Installer Fail2Ban pour protection brute-force

### Actions à Réaliser

!!! info "Choix du Firewall"
    - **RHEL/Rocky/CentOS** : Utilisez **firewalld** (installé par défaut)
    - **Debian/Ubuntu** : Utilisez **UFW** (interface simplifiée pour iptables)

#### Option A : RHEL/Rocky avec firewalld (Recommandé en entreprise)

##### 1. Activation firewalld

```bash
# firewalld est préinstallé sur RHEL/Rocky
sudo systemctl enable --now firewalld

# Vérifier le statut
sudo firewall-cmd --state
# running
```

#### Option B : Debian/Ubuntu avec UFW

##### 1. Installation UFW

```bash
# Installer UFW
sudo apt update
sudo apt install ufw -y
```

##### 2. Configuration des Règles

```bash
# Politique par défaut
sudo ufw default deny incoming
sudo ufw default allow outgoing

# CRITIQUE : Autoriser SSH AVANT d'activer
# Si port par défaut (22)
sudo ufw allow 22/tcp

# Si port personnalisé (ex: 2222)
sudo ufw allow 2222/tcp

# Autoriser HTTP et HTTPS
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Vérifier les règles AVANT activation
sudo ufw show added
```

##### 3. Activation du Firewall

```bash
# Activer UFW
sudo ufw enable

# Vérifier l'état
sudo ufw status verbose
```

**Exemple de sortie attendue :**

```
Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)

To                         Action      From
--                         ------      ----
2222/tcp                   ALLOW IN    Anywhere
80/tcp                     ALLOW IN    Anywhere
443/tcp                    ALLOW IN    Anywhere
```

##### 4. Validation

```bash
# Tester que SSH fonctionne toujours (nouveau terminal)
ssh -p 2222 alice@192.168.1.100
# ✅ Connexion réussie

# Vérifier que les ports non autorisés sont bloqués
# (depuis une autre machine)
nc -zv 192.168.1.100 5432
# nc: connect to 192.168.1.100 port 5432 (tcp) failed: Connection refused
# ✅ PostgreSQL bloqué
```

#### Option B : RHEL/CentOS avec Firewalld

##### 1. Installation et Activation

```bash
# Installer Firewalld
sudo dnf install firewalld -y

# Activer et démarrer
sudo systemctl enable --now firewalld

# Vérifier l'état
sudo firewall-cmd --state
# running
```

##### 2. Configuration des Règles

```bash
# Vérifier la zone par défaut
sudo firewall-cmd --get-default-zone
# public

# Ajouter SSH (si port personnalisé)
sudo firewall-cmd --zone=public --add-port=2222/tcp --permanent

# Ajouter HTTP et HTTPS
sudo firewall-cmd --zone=public --add-service=http --permanent
sudo firewall-cmd --zone=public --add-service=https --permanent

# Recharger la configuration
sudo firewall-cmd --reload

# Vérifier les règles actives
sudo firewall-cmd --zone=public --list-all
```

#### Installation et Configuration Fail2Ban

##### 1. Installation

=== "RHEL/Rocky"

    ```bash
    sudo dnf install epel-release -y
    sudo dnf install fail2ban -y
    ```

=== "Debian/Ubuntu"

    ```bash
    sudo apt install fail2ban -y
    ```

##### 2. Configuration

```bash
# Copier la configuration par défaut
sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local

# Éditer la configuration
sudo nano /etc/fail2ban/jail.local
```

**Configuration recommandée :**

```ini
[DEFAULT]
# Temps de bannissement (1 heure)
bantime = 3600

# Fenêtre de détection (10 minutes)
findtime = 600

# Nombre de tentatives avant ban
maxretry = 5

# Action : Ban via UFW ou Firewalld
# Ubuntu/Debian
banaction = ufw

# RHEL/CentOS
# banaction = firewallcmd-rich-rules

[sshd]
enabled = true
port = 2222        # Adapter au port SSH configuré
logpath = /var/log/auth.log
maxretry = 3       # SSH plus strict

[nginx-http-auth]
enabled = true
port = http,https
logpath = /var/log/nginx/error.log
maxretry = 3
```

##### 3. Activation Fail2Ban

```bash
# Démarrer et activer
sudo systemctl enable --now fail2ban

# Vérifier l'état
sudo systemctl status fail2ban

# Vérifier les jails actives
sudo fail2ban-client status
# Status
# |- Number of jail:      2
# `- Jail list:   nginx-http-auth, sshd

# Détails d'une jail
sudo fail2ban-client status sshd
```

##### 4. Test Fail2Ban (Optionnel)

```bash
# Simuler 3 échecs SSH depuis une autre machine
ssh bob@192.168.1.100  # Tentative 1 (échec)
ssh bob@192.168.1.100  # Tentative 2 (échec)
ssh bob@192.168.1.100  # Tentative 3 (échec)

# Vérifier le bannissement
sudo fail2ban-client status sshd
# Status for the jail: sshd
# |- Filter
# |  |- Currently failed: 0
# |  |- Total failed:     3
# |  `- File list:        /var/log/auth.log
# `- Actions
#    |- Currently banned: 1
#    |- Total banned:     1
#    `- Banned IP list:   192.168.1.50   ← IP bannie

# Débannir manuellement (pour test)
sudo fail2ban-client unban 192.168.1.50
```

!!! success "Étape 4 Validée"
    ✅ Firewall activé avec politique DENY ALL

    ✅ Ports autorisés : SSH (2222), HTTP (80), HTTPS (443)

    ✅ Fail2Ban actif sur SSH et Nginx

    ✅ Protection contre brute-force opérationnelle

---

## Étape 5 : Surveillance - L'Œil de Moscou

### Objectif

**Appliquer le Module 4 : Audit & Conformité**

1. ✅ Installer et configurer Auditd
2. ✅ Surveiller les fichiers critiques (`/etc/shadow`, `/etc/ssh/sshd_config`)
3. ✅ Surveiller les commandes sudo
4. ✅ Activer le mode immutable (production)

### Actions à Réaliser

#### 1. Installation Auditd

=== "RHEL/Rocky"

    ```bash
    sudo dnf install audit -y

    # Vérifier l'installation
    sudo systemctl enable --now auditd
    sudo systemctl status auditd
    ```

=== "Debian/Ubuntu"

    ```bash
    sudo apt install auditd audispd-plugins -y

    # Vérifier l'installation
    sudo systemctl status auditd
    ```

#### 2. Configuration des Règles d'Audit

```bash
# Éditer le fichier de règles
sudo nano /etc/audit/rules.d/audit.rules
```

**Configuration de sécurité pour production :**

```bash
# Supprimer les règles précédentes
-D

# Augmenter le buffer
-b 8192

# En cas de buffer plein, arrêter plutôt que perdre des événements
-f 2

## 1. Fichiers d'identité système
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity

## 2. Configuration SSH (critique pour sécurité)
-w /etc/ssh/sshd_config -p wa -k sshd-config-change
-w /root/.ssh/authorized_keys -p wa -k ssh-key-change
-w /home/alice/.ssh/authorized_keys -p wa -k ssh-key-change
-w /home/deploy/.ssh/authorized_keys -p wa -k ssh-key-change

## 3. Configuration Sudo
-w /etc/sudoers -p wa -k sudoers-change
-w /etc/sudoers.d/ -p wa -k sudoers-change

## 4. Binaires système critiques
-w /usr/bin/passwd -p x -k passwd-exec
-w /usr/bin/sudo -p x -k sudo-exec
-w /usr/sbin/useradd -p x -k user-mgmt
-w /usr/sbin/userdel -p x -k user-mgmt
-w /usr/sbin/usermod -p x -k user-mgmt

## 5. Firewall et configuration réseau
-w /etc/ufw/ -p wa -k firewall-change
-w /etc/firewalld/ -p wa -k firewall-change

## 6. Syscalls critiques
# Suppressions de fichiers
-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=unset -k file-deletion

# Modifications de permissions
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -k perm-change
-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid>=1000 -k ownership-change

# Élévation de privilèges
-a always,exit -F arch=b64 -S setuid,setgid,setreuid,setregid -k privilege-escalation

## 7. Mode immutable (activer EN DERNIER après validation)
# Décommenter après tests de validation
# -e 2
```

#### 3. Application des Règles

```bash
# Charger les règles
sudo augenrules --load

# Vérifier les règles actives
sudo auditctl -l | head -20

# Redémarrer auditd
sudo systemctl restart auditd
```

#### 4. Test de Validation

```bash
# Modifier un fichier surveillé
sudo nano /etc/ssh/sshd_config
# (Ajouter un commentaire, sauvegarder)

# Rechercher l'événement d'audit
sudo ausearch -k sshd-config-change -i

# Exemple de sortie attendue
# type=SYSCALL msg=audit(...): arch=x86_64 syscall=openat success=yes
#   auid=alice uid=root comm="nano" exe="/usr/bin/nano"
#   key="sshd-config-change"
```

#### 5. Vérification Continue

```bash
# Voir les événements récents
sudo ausearch -ts recent -i | tail -50

# Rapport d'activité du jour
sudo aureport -ts today --summary

# Top utilisateurs par activité
sudo aureport -u
```

!!! success "Étape 5 Validée"
    ✅ Auditd installé et configuré

    ✅ Surveillance active sur fichiers critiques

    ✅ Traçabilité des actions sudo et modifications système

    ✅ Conformité SecNumCloud atteinte

---

## Étape 6 : Le Test de Pénétration - La Validation Finale

### Objectif

**Valider que toutes les sécurisations fonctionnent correctement.**

Vous allez simuler les attaques les plus courantes pour vérifier que le serveur résiste.

### Tests à Réaliser

#### Test 1 : Tentative de Connexion Root SSH

**Objectif :** Vérifier que root ne peut plus se connecter.

```bash
# Depuis une autre machine (ou localhost)
ssh -p 2222 root@192.168.1.100

# Résultat attendu
# Permission denied (publickey).
```

✅ **SUCCÈS** : Root est bloqué

❌ **ÉCHEC** : Retourner à l'Étape 2, vérifier `PermitRootLogin no`

---

#### Test 2 : Tentative de Connexion par Mot de Passe

**Objectif :** Vérifier que l'authentification par mot de passe est désactivée.

```bash
# Forcer l'authentification par mot de passe
ssh -o PubkeyAuthentication=no -p 2222 alice@192.168.1.100

# Résultat attendu
# Permission denied (publickey).
```

✅ **SUCCÈS** : Authentification par mot de passe bloquée

❌ **ÉCHEC** : Retourner à l'Étape 2, vérifier `PasswordAuthentication no`

---

#### Test 3 : Scan de Ports (Reconnaissance Attaquant)

**Objectif :** Vérifier que seuls les ports autorisés sont ouverts.

```bash
# Scan de ports depuis une autre machine
nmap -p 1-10000 192.168.1.100

# OU avec nc (netcat)
for port in 22 80 443 3000 5432 6379; do
  nc -zv 192.168.1.100 $port 2>&1 | grep -E "succeeded|refused"
done
```

**Résultat attendu :**

```
192.168.1.100:2222 - succeeded    ← ✅ SSH autorisé
192.168.1.100:80 - succeeded      ← ✅ HTTP autorisé
192.168.1.100:443 - succeeded     ← ✅ HTTPS autorisé
192.168.1.100:3000 - refused      ← ✅ Backend bloqué
192.168.1.100:5432 - refused      ← ✅ PostgreSQL bloqué
192.168.1.100:6379 - refused      ← ✅ Redis bloqué
```

✅ **SUCCÈS** : Firewall fonctionne correctement

❌ **ÉCHEC** : Retourner à l'Étape 4, vérifier les règles firewall

---

#### Test 4 : Brute-Force SSH (Test Fail2Ban)

**Objectif :** Vérifier que Fail2Ban détecte et bannit les tentatives répétées.

```bash
# Depuis une autre machine, faire 3 tentatives échouées
ssh wronguser@192.168.1.100  # Tentative 1
ssh wronguser@192.168.1.100  # Tentative 2
ssh wronguser@192.168.1.100  # Tentative 3

# Sur le serveur, vérifier le bannissement
sudo fail2ban-client status sshd
```

**Résultat attendu :**

```
Status for the jail: sshd
|- Currently banned: 1
`- Banned IP list:   192.168.1.50
```

✅ **SUCCÈS** : Fail2Ban bannit après 3 tentatives

❌ **ÉCHEC** : Retourner à l'Étape 4, vérifier configuration Fail2Ban

---

#### Test 5 : Vérification des Logs d'Audit

**Objectif :** Vérifier que les tentatives d'attaque sont loguées.

```bash
# Rechercher les tentatives de connexion échouées
sudo ausearch -m USER_LOGIN -sv no -i

# Rechercher les modifications SSH
sudo ausearch -k sshd-config-change -i

# Vérifier les actions sudo du jour
sudo aureport -ts today -x | grep sudo
```

**Résultat attendu :** Tous les événements sont tracés avec timestamp, auid, etc.

✅ **SUCCÈS** : Audit fonctionne, traçabilité complète

❌ **ÉCHEC** : Retourner à l'Étape 5, vérifier configuration auditd

---

#### Test 6 : Vérification des Utilisateurs Obsolètes

**Objectif :** Vérifier que les comptes obsolètes ne peuvent plus se connecter.

```bash
# Tenter de basculer vers bob
su - bob

# Résultat attendu
# This account is currently not available.
```

```bash
# Vérifier les shells
grep -E "bob|charlie|testuser" /etc/passwd

# Résultat attendu
# bob:x:1002:1002::/home/bob:/sbin/nologin        ← ✅ Shell désactivé
# charlie:x:1003:1003::/home/charlie:/sbin/nologin
# testuser:x:1004:1004::/home/testuser:/sbin/nologin
```

✅ **SUCCÈS** : Comptes obsolètes verrouillés

❌ **ÉCHEC** : Retourner à l'Étape 3, vérifier verrouillage utilisateurs

---

### Tableau de Validation Finale

| **Test** | **Objectif** | **Commande** | **Statut** |
|----------|-------------|-------------|-----------|
| 1. Root SSH | Root bloqué | `ssh root@IP` | ✅/❌ |
| 2. Password Auth | Mot de passe bloqué | `ssh -o PubkeyAuthentication=no` | ✅/❌ |
| 3. Port Scan | Ports filtrés | `nmap 192.168.1.100` | ✅/❌ |
| 4. Brute-Force | Fail2Ban ban | Tentatives répétées | ✅/❌ |
| 5. Audit Logs | Traçabilité | `ausearch -m USER_LOGIN` | ✅/❌ |
| 6. Comptes Obsolètes | Verrouillage | `su - bob` | ✅/❌ |

**Score de Sécurité Final :** ✅✅✅✅✅✅ = **6/6 → 10/10** 🎉

---

## Conclusion : Mission Accomplie

### Avant vs Après

| **Aspect** | **AVANT (Passoire)** | **APRÈS (Forteresse)** |
|------------|---------------------|----------------------|
| **SSH** | ❌ Root OK, Password OK | ✅ Root bloqué, Clés uniquement |
| **Utilisateurs** | ❌ 5 comptes, 3 obsolètes | ✅ 2 comptes actifs, sudo sécurisé |
| **Firewall** | ❌ Désactivé, tous ports ouverts | ✅ Actif, 3 ports autorisés uniquement |
| **IPS** | ❌ Aucune protection brute-force | ✅ Fail2Ban actif, ban après 3 tentatives |
| **Audit** | ❌ Aucune traçabilité | ✅ Auditd complet, SecNumCloud-ready |
| **Score Sécurité** | ❌ **2/10** | ✅ **10/10** |

### Conformité SecNumCloud Atteinte

| **Exigence SecNumCloud** | **Implémentation** | **Validé** |
|-------------------------|-------------------|-----------|
| Authentification forte | SSH clés publiques uniquement | ✅ |
| Restriction accès privilégié | Root bloqué, sudo contrôlé | ✅ |
| Filtrage réseau | Firewall UFW/Firewalld | ✅ |
| Protection contre brute-force | Fail2Ban configuré | ✅ |
| Traçabilité actions admin | Auditd sur fichiers critiques | ✅ |
| Principe moindre privilège | Comptes verrouillés, sudo minimal | ✅ |

### Compétences Maîtrisées

Au terme de ce TP Final, vous êtes capable de :

✅ **Auditer** un serveur pour identifier ses vulnérabilités

✅ **Sécuriser SSH** selon les standards de l'industrie

✅ **Gérer les utilisateurs** avec principe du moindre privilège

✅ **Configurer un firewall** avec politique deny-by-default

✅ **Déployer un IPS** (Fail2Ban) contre les attaques automatisées

✅ **Implémenter l'audit système** pour conformité réglementaire

✅ **Valider la sécurisation** avec des tests de pénétration basiques

### Certification Informelle

```
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║              CERTIFICAT DE COMPÉTENCE                    ║
║                                                          ║
║  Formation : Hardening Linux - ShellBook                ║
║  Module : TP Final - Le Hardening Challenge              ║
║                                                          ║
║  Compétences Validées :                                  ║
║    ✅ Audit de sécurité système                         ║
║    ✅ Hardening SSH (Module 1)                          ║
║    ✅ Gestion utilisateurs sécurisée (Module 2)         ║
║    ✅ Configuration firewall (Module 3)                 ║
║    ✅ Audit & Conformité (Module 4)                     ║
║    ✅ Tests de pénétration basiques                     ║
║                                                          ║
║  Niveau : SecNumCloud-Ready                              ║
║                                                          ║
║  Date : [Votre date de réussite]                         ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝
```

---

## Solution Complète

??? quote "Solution Complète - Tous les Commandes du Hardening"

    ### Étape 1 : Audit Initial

    ```bash
    # Ports ouverts
    sudo ss -tulpn

    # Utilisateurs
    awk -F: '$3 >= 1000 {print $1, $3, $7}' /etc/passwd

    # Configuration sudo
    sudo grep -E '^[^#]' /etc/sudoers
    sudo cat /etc/sudoers.d/*

    # Configuration SSH
    sudo grep -E '^PasswordAuthentication|^PermitRootLogin' /etc/ssh/sshd_config

    # État firewall
    sudo ufw status  # OU sudo firewall-cmd --state
    ```

    ---

    ### Étape 2 : Hardening SSH

    ```bash
    # Backup configuration
    sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%F)

    # Éditer la configuration
    sudo nano /etc/ssh/sshd_config
    ```

    **Modifications dans sshd_config :**

    ```bash
    PermitRootLogin no
    PasswordAuthentication no
    ChallengeResponseAuthentication no
    PubkeyAuthentication yes
    AllowUsers alice deploy
    Port 2222                    # Optionnel
    PermitEmptyPasswords no
    X11Forwarding no
    MaxAuthTries 3
    LoginGraceTime 30
    ```

    ```bash
    # Tester la syntaxe
    sudo sshd -t

    # Redémarrer SSH
    sudo systemctl restart ssh    # Ubuntu/Debian
    sudo systemctl restart sshd   # RHEL/CentOS

    # Tester (nouveau terminal)
    ssh -p 2222 alice@192.168.1.100
    ```

    ---

    ### Étape 3 : Nettoyage Utilisateurs

    ```bash
    # Verrouiller comptes obsolètes
    sudo usermod -L bob && sudo usermod -s /sbin/nologin bob
    sudo usermod -L charlie && sudo usermod -s /sbin/nologin charlie
    sudo usermod -L testuser && sudo usermod -s /sbin/nologin testuser

    # OU supprimer complètement
    sudo userdel -r bob
    sudo userdel -r charlie
    sudo userdel -r testuser

    # Nettoyer sudo
    sudo cp /etc/sudoers /etc/sudoers.backup.$(date +%F)
    sudo visudo
    # Supprimer les lignes avec bob, charlie, testuser
    # Garder uniquement :
    # alice ALL=(ALL:ALL) ALL
    # deploy ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart myapp.service

    # Nettoyer sudoers.d
    sudo rm /etc/sudoers.d/bob
    sudo rm /etc/sudoers.d/charlie

    # Retirer des groupes sudo
    sudo gpasswd -d bob sudo
    sudo gpasswd -d charlie sudo

    # Vérifier
    sudo visudo -c
    grep sudo /etc/group
    ```

    ---

    ### Étape 4 : Firewall et Fail2Ban

    #### UFW (Ubuntu/Debian)

    ```bash
    # Installation
    sudo apt update && sudo apt install ufw fail2ban -y

    # Configuration UFW
    sudo ufw default deny incoming
    sudo ufw default allow outgoing
    sudo ufw allow 2222/tcp    # SSH (adapter au port configuré)
    sudo ufw allow 80/tcp
    sudo ufw allow 443/tcp

    # Activer
    sudo ufw enable

    # Vérifier
    sudo ufw status verbose
    ```

    #### Firewalld (RHEL/CentOS)

    ```bash
    # Installation
    sudo dnf install firewalld fail2ban -y

    # Activation
    sudo systemctl enable --now firewalld

    # Configuration
    sudo firewall-cmd --zone=public --add-port=2222/tcp --permanent
    sudo firewall-cmd --zone=public --add-service=http --permanent
    sudo firewall-cmd --zone=public --add-service=https --permanent
    sudo firewall-cmd --reload

    # Vérifier
    sudo firewall-cmd --zone=public --list-all
    ```

    #### Fail2Ban (Tous systèmes)

    ```bash
    # Configuration
    sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
    sudo nano /etc/fail2ban/jail.local
    ```

    **Dans jail.local :**

    ```ini
    [DEFAULT]
    bantime = 3600
    findtime = 600
    maxretry = 5

    # Ubuntu/Debian
    banaction = ufw
    # RHEL/CentOS
    # banaction = firewallcmd-rich-rules

    [sshd]
    enabled = true
    port = 2222
    logpath = /var/log/auth.log
    maxretry = 3

    [nginx-http-auth]
    enabled = true
    port = http,https
    logpath = /var/log/nginx/error.log
    maxretry = 3
    ```

    ```bash
    # Activer Fail2Ban
    sudo systemctl enable --now fail2ban

    # Vérifier
    sudo fail2ban-client status
    sudo fail2ban-client status sshd
    ```

    ---

    ### Étape 5 : Audit avec Auditd

    ```bash
    # Installation
    sudo apt install auditd audispd-plugins -y    # Ubuntu/Debian
    sudo dnf install audit -y                      # RHEL/CentOS

    # Configuration
    sudo nano /etc/audit/rules.d/audit.rules
    ```

    **Règles complètes (/etc/audit/rules.d/audit.rules) :**

    ```bash
    -D
    -b 8192
    -f 2

    # Fichiers d'identité
    -w /etc/passwd -p wa -k identity
    -w /etc/group -p wa -k identity
    -w /etc/shadow -p wa -k identity
    -w /etc/gshadow -p wa -k identity

    # Configuration SSH
    -w /etc/ssh/sshd_config -p wa -k sshd-config-change
    -w /root/.ssh/authorized_keys -p wa -k ssh-key-change
    -w /home/alice/.ssh/authorized_keys -p wa -k ssh-key-change

    # Sudo
    -w /etc/sudoers -p wa -k sudoers-change
    -w /etc/sudoers.d/ -p wa -k sudoers-change

    # Binaires critiques
    -w /usr/bin/passwd -p x -k passwd-exec
    -w /usr/bin/sudo -p x -k sudo-exec
    -w /usr/sbin/useradd -p x -k user-mgmt
    -w /usr/sbin/userdel -p x -k user-mgmt
    -w /usr/sbin/usermod -p x -k user-mgmt

    # Firewall
    -w /etc/ufw/ -p wa -k firewall-change
    -w /etc/firewalld/ -p wa -k firewall-change

    # Syscalls
    -a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=unset -k file-deletion
    -a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -k perm-change
    -a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid>=1000 -k ownership-change
    -a always,exit -F arch=b64 -S setuid,setgid,setreuid,setregid -k privilege-escalation

    # Mode immutable (décommenter après validation)
    # -e 2
    ```

    ```bash
    # Appliquer les règles
    sudo augenrules --load

    # Redémarrer auditd
    sudo systemctl restart auditd

    # Vérifier
    sudo auditctl -l | head -20
    sudo ausearch -ts recent -i | tail -20
    ```

    ---

    ### Étape 6 : Tests de Validation

    ```bash
    # Test 1 : Root SSH bloqué
    ssh -p 2222 root@192.168.1.100
    # Résultat attendu : Permission denied (publickey)

    # Test 2 : Password auth bloquée
    ssh -o PubkeyAuthentication=no -p 2222 alice@192.168.1.100
    # Résultat attendu : Permission denied (publickey)

    # Test 3 : Scan de ports
    nmap -p 22,80,443,3000,5432,6379 192.168.1.100
    # Résultat attendu : Seuls 2222, 80, 443 ouverts

    # Test 4 : Fail2Ban
    # (Faire 3 tentatives SSH échouées depuis une autre machine)
    sudo fail2ban-client status sshd
    # Résultat attendu : 1 IP bannie

    # Test 5 : Audit logs
    sudo ausearch -k sshd-config-change -i
    sudo aureport -ts today --summary

    # Test 6 : Comptes verrouillés
    su - bob
    # Résultat attendu : This account is currently not available
    ```

    ---

    ### Commandes de Vérification Finale

    ```bash
    # Résumé de l'état de sécurité
    echo "=== SSH Configuration ==="
    sudo grep -E '^PermitRootLogin|^PasswordAuthentication' /etc/ssh/sshd_config

    echo -e "\n=== Active Users ==="
    awk -F: '$3 >= 1000 && $7 !~ /nologin|false/ {print $1, $7}' /etc/passwd

    echo -e "\n=== Sudo Users ==="
    grep sudo /etc/group

    echo -e "\n=== Firewall Status ==="
    sudo ufw status verbose || sudo firewall-cmd --list-all

    echo -e "\n=== Fail2Ban Status ==="
    sudo fail2ban-client status

    echo -e "\n=== Audit Rules ==="
    sudo auditctl -l | wc -l
    echo "règles d'audit actives"

    echo -e "\n=== Open Ports ==="
    sudo ss -tulpn | grep LISTEN
    ```

    ---

    ### Script de Hardening Automatisé (Bonus)

    === "RHEL/Rocky - `hardening-rhel.sh`"

        ```bash
        #!/bin/bash
        # Script de hardening automatisé pour RHEL/Rocky Linux
        # À utiliser avec précaution et validation manuelle

        set -e  # Arrêt en cas d'erreur

        echo "=== Début du Hardening (RHEL/Rocky) ==="

        # Backup
        echo "[1/6] Création des backups..."
        sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%F)
        sudo cp /etc/sudoers /etc/sudoers.backup.$(date +%F)

        # SSH Hardening
        echo "[2/6] Hardening SSH..."
        sudo sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
        sudo sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
        sudo systemctl restart sshd

        # Utilisateurs
        echo "[3/6] Verrouillage utilisateurs obsolètes..."
        for user in bob charlie testuser; do
            sudo usermod -L $user 2>/dev/null || true
            sudo usermod -s /sbin/nologin $user 2>/dev/null || true
        done

        # Firewall (firewalld)
        echo "[4/6] Configuration firewall..."
        sudo systemctl enable --now firewalld
        sudo firewall-cmd --set-default-zone=drop
        sudo firewall-cmd --permanent --add-service=ssh
        sudo firewall-cmd --permanent --add-service=http
        sudo firewall-cmd --permanent --add-service=https
        sudo firewall-cmd --reload

        # Fail2Ban
        echo "[5/6] Configuration Fail2Ban..."
        sudo dnf install epel-release -y
        sudo dnf install fail2ban -y
        sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
        sudo systemctl enable --now fail2ban

        # Audit
        echo "[6/6] Configuration Audit..."
        sudo dnf install audit -y
        sudo systemctl enable --now auditd

        echo "=== Hardening Terminé ==="
        echo "⚠️  IMPORTANT : Tester SSH avant de fermer cette session!"
        ```

    === "Debian/Ubuntu - `hardening-debian.sh`"

        ```bash
        #!/bin/bash
        # Script de hardening automatisé pour Debian/Ubuntu
        # À utiliser avec précaution et validation manuelle

        set -e  # Arrêt en cas d'erreur

        echo "=== Début du Hardening (Debian/Ubuntu) ==="

        # Backup
        echo "[1/6] Création des backups..."
        sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%F)
        sudo cp /etc/sudoers /etc/sudoers.backup.$(date +%F)

        # SSH Hardening
        echo "[2/6] Hardening SSH..."
        sudo sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
        sudo sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
        sudo systemctl restart ssh

        # Utilisateurs
        echo "[3/6] Verrouillage utilisateurs obsolètes..."
        for user in bob charlie testuser; do
            sudo usermod -L $user 2>/dev/null || true
            sudo usermod -s /sbin/nologin $user 2>/dev/null || true
        done

        # Firewall (UFW)
        echo "[4/6] Configuration firewall..."
        sudo apt install ufw fail2ban -y
        sudo ufw --force enable
        sudo ufw default deny incoming
        sudo ufw default allow outgoing
        sudo ufw allow 22/tcp
        sudo ufw allow 80/tcp
        sudo ufw allow 443/tcp

        # Fail2Ban
        echo "[5/6] Configuration Fail2Ban..."
        sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
        sudo systemctl enable --now fail2ban

        # Audit
        echo "[6/6] Configuration Audit..."
        sudo apt install auditd -y
        sudo systemctl enable --now auditd

        echo "=== Hardening Terminé ==="
        echo "⚠️  IMPORTANT : Tester SSH avant de fermer cette session!"
        ```

    **Utilisation :**

    ```bash
    chmod +x hardening-*.sh
    # Sur RHEL/Rocky :
    sudo ./hardening-rhel.sh
    # Sur Debian/Ubuntu :
    sudo ./hardening-debian.sh
    ```

## Prochaines Étapes

### Pour Aller Plus Loin

1. **Automatisation avec Ansible**
   - Créer un playbook Ansible pour appliquer ce hardening sur un parc de serveurs
   - Gérer les configurations avec des templates Jinja2

2. **Intégration SIEM**
   - Configurer un forwarding des logs audit vers Wazuh/ELK
   - Créer des alertes sur événements critiques

3. **Hardening Avancé**
   - AppArmor/SELinux (MAC - Mandatory Access Control)
   - Chiffrement disque LUKS
   - Kernel hardening (sysctl)

4. **Certification Professionnelle**
   - CompTIA Security+
   - Linux Foundation LFCS (Linux Foundation Certified SysAdmin)
   - (ISC)² SSCP (Systems Security Certified Practitioner)

---

**Félicitations ! Vous avez complété la formation "Hardening Linux" et transformé une passoire en forteresse SecNumCloud-ready ! 🎉🔒**

---

**Retour au :** [Programme de la Formation](index.md) | [Catalogue des Formations](../index.md)
