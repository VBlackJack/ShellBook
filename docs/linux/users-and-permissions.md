# Users, Groups & Permissions

`#permissions` `#sudo` `#acl` `#security`

Gestion des accès et principe du moindre privilège.

---

## Gestion Utilisateurs & Groupes

### useradd vs adduser

| Commande | Type | Comportement |
|----------|------|--------------|
| `useradd` | Bas niveau | Crée l'utilisateur, c'est tout. Pas de home, pas de shell par défaut. |
| `adduser` | Script interactif | Crée home, copie `/etc/skel`, demande mot de passe. (Debian/Ubuntu) |

```bash
# Bas niveau (nécessite options explicites)
useradd -m -s /bin/bash -G sudo john

# Interactif (recommandé sur Debian/Ubuntu)
adduser john

# Supprimer un utilisateur
userdel john           # Garde le home
userdel -r john        # Supprime home + mail
deluser --remove-home john   # Debian
```

---

### Fichiers Clés

| Fichier | Contenu | Permissions |
|---------|---------|-------------|
| `/etc/passwd` | Info utilisateurs (UID, GID, home, shell) | `644` (lisible par tous) |
| `/etc/shadow` | Hash des mots de passe | `640` (root only) |
| `/etc/group` | Définition des groupes | `644` |
| `/etc/gshadow` | Mots de passe groupes | `640` |

**Structure de `/etc/passwd` :**

```
username:x:UID:GID:GECOS:home:shell
john:x:1001:1001:John Doe:/home/john:/bin/bash
```

**Structure de `/etc/shadow` :**

```
username:$hash:lastchange:min:max:warn:inactive:expire:
john:$6$salt$hash...:19500:0:99999:7:::
```

!!! danger "Protéger /etc/shadow"
    Ce fichier contient les hash des mots de passe.
    Permissions incorrectes = fuite de hash = brute-force offline possible.

    ```bash
    # Vérifier les permissions
    ls -la /etc/shadow
    # -rw-r----- 1 root shadow

    # Corriger si nécessaire
    chmod 640 /etc/shadow
    chown root:shadow /etc/shadow
    ```

---

### Commandes Utiles

```bash
# Qui suis-je ?
whoami
id
id john

# Output id:
# uid=1001(john) gid=1001(john) groups=1001(john),27(sudo),999(docker)

# Ajouter un utilisateur à un groupe secondaire
usermod -aG docker john    # -a = append, -G = groupe secondaire
usermod -aG sudo john

# ⚠️ Sans -a, écrase les groupes existants !
usermod -G docker john     # DANGER: retire john de tous les autres groupes

# Changer le shell
usermod -s /bin/zsh john

# Verrouiller/déverrouiller un compte
usermod -L john    # Lock
usermod -U john    # Unlock

# Créer un groupe
groupadd developers
groupdel developers

# Voir les groupes d'un utilisateur
groups john
```

---

## Permissions Standards (rwx)

### Notation Octale vs Symbolique

| Octal | Binaire | Symbolique | Signification |
|-------|---------|------------|---------------|
| 0 | 000 | `---` | Aucun droit |
| 1 | 001 | `--x` | Exécution |
| 2 | 010 | `-w-` | Écriture |
| 3 | 011 | `-wx` | Écriture + Exécution |
| 4 | 100 | `r--` | Lecture |
| 5 | 101 | `r-x` | Lecture + Exécution |
| 6 | 110 | `rw-` | Lecture + Écriture |
| 7 | 111 | `rwx` | Tous les droits |

### Lecture des Permissions

```
-rwxr-xr-- 1 john developers 4096 Jan 15 10:00 script.sh
│└┬┘└┬┘└┬┘
│ │  │  └── Others (autres)
│ │  └───── Group (groupe)
│ └──────── User/Owner (propriétaire)
└────────── Type (- = fichier, d = dir, l = lien)
```

### chmod (Modifier les permissions)

```bash
# Notation octale
chmod 755 script.sh    # rwxr-xr-x
chmod 644 config.txt   # rw-r--r--
chmod 600 secret.key   # rw-------

# Notation symbolique
chmod u+x script.sh    # Ajouter exec pour user
chmod g-w file.txt     # Retirer write pour group
chmod o-rwx private/   # Retirer tout pour others
chmod a+r readme.txt   # Ajouter read pour all

# Récursif
chmod -R 755 /var/www/html/
chmod -R u+rwX,go+rX,go-w /var/www/  # X = exec seulement sur dirs
```

### chown (Changer propriétaire)

```bash
# Changer propriétaire
chown john file.txt

# Changer propriétaire et groupe
chown john:developers file.txt

# Groupe seulement
chown :developers file.txt
chgrp developers file.txt

# Récursif
chown -R www-data:www-data /var/www/html/
```

!!! warning "Bonne Pratique : Jamais chmod 777"
    `chmod 777` = **tout le monde peut tout faire**.

    ```bash
    # INTERDIT en production
    chmod 777 /var/www/html/   # N'IMPORTE QUI peut modifier/supprimer

    # Correct
    chmod 755 /var/www/html/           # Dirs: rwxr-xr-x
    chmod 644 /var/www/html/*.html     # Files: rw-r--r--
    chown -R www-data:www-data /var/www/html/
    ```

    **Principe du moindre privilège :** Accorder uniquement les droits nécessaires.

### Permissions Communes

| Cible | Permissions | Raison |
|-------|-------------|--------|
| Scripts exécutables | `755` | Lecture/exec pour tous |
| Fichiers de config | `644` | Lecture pour tous |
| Clés privées SSH | `600` | Propriétaire uniquement |
| `.ssh/` directory | `700` | Propriétaire uniquement |
| `/etc/shadow` | `640` | root + groupe shadow |
| Répertoires web | `755` | Lecture/traversée |
| Fichiers web | `644` | Lecture |

---

## Les "Special Bits" (Danger Zone)

### Vue d'ensemble

```
┌─────────────────────────────────────────────────────────────┐
│              SPECIAL BITS (4 bits supplémentaires)          │
├─────────────────────────────────────────────────────────────┤
│  SUID (4)     │  Exécuter avec droits du propriétaire       │
│  SGID (2)     │  Exécuter avec droits du groupe / héritage  │
│  Sticky (1)   │  Seul le proprio peut supprimer             │
└─────────────────────────────────────────────────────────────┘

Notation : chmod XYYY où X = special bits, YYY = permissions
Exemple  : chmod 4755 = SUID + rwxr-xr-x
```

---

### SUID (Set User ID) - Bit 4

**Effet :** Le programme s'exécute avec les droits de son **propriétaire**, pas de l'utilisateur qui le lance.

```
-rwsr-xr-x 1 root root 59976 /usr/bin/passwd
   ^
   └── 's' au lieu de 'x' = SUID activé
```

**Cas d'usage légitime :**

```bash
# passwd doit modifier /etc/shadow (owned by root)
# Sans SUID, un utilisateur ne pourrait pas changer son mot de passe
ls -la /usr/bin/passwd
# -rwsr-xr-x 1 root root ... /usr/bin/passwd
```

**Gestion :**

```bash
# Activer SUID
chmod u+s program
chmod 4755 program

# Désactiver SUID
chmod u-s program
chmod 0755 program

# Trouver tous les binaires SUID sur le système
find / -perm -4000 -type f 2>/dev/null
```

!!! danger "Risque de Sécurité SUID"
    Un binaire SUID vulnérable = **élévation de privilèges**.

    ```bash
    # Si /usr/bin/vulnerable est SUID root et a une faille...
    # Un attaquant peut obtenir un shell root !

    # Audit régulier des binaires SUID
    find / -perm -4000 -user root -type f 2>/dev/null

    # Comparer avec une liste de référence
    ```

---

### SGID (Set Group ID) - Bit 2

**Sur un fichier :** Exécution avec les droits du groupe propriétaire.

**Sur un répertoire :** Les fichiers créés héritent du groupe du répertoire (pas du groupe de l'utilisateur).

```
drwxrwsr-x 2 root developers 4096 /shared/
      ^
      └── 's' sur group = SGID activé
```

**Cas d'usage : Dossier partagé d'équipe**

```bash
# Créer un dossier partagé pour l'équipe dev
mkdir /shared/project
chown root:developers /shared/project
chmod 2775 /shared/project

# Résultat :
# - Tous les membres de "developers" peuvent écrire
# - Nouveaux fichiers appartiennent au groupe "developers"
# - Pas besoin de chgrp après chaque création
```

**Gestion :**

```bash
# Activer SGID
chmod g+s directory/
chmod 2755 directory/

# Désactiver
chmod g-s directory/

# Trouver les répertoires SGID
find / -perm -2000 -type d 2>/dev/null
```

---

### Sticky Bit - Bit 1

**Effet :** Dans un répertoire, seuls peuvent supprimer un fichier :
- Le propriétaire du fichier
- Le propriétaire du répertoire
- root

```
drwxrwxrwt 10 root root 4096 /tmp/
         ^
         └── 't' à la fin = Sticky bit activé
```

**Cas d'usage : /tmp**

```bash
# Sans sticky bit sur /tmp :
# N'importe qui pourrait supprimer les fichiers des autres !

ls -ld /tmp
# drwxrwxrwt 10 root root 4096 Jan 15 10:00 /tmp
```

**Gestion :**

```bash
# Activer sticky bit
chmod +t directory/
chmod 1777 directory/

# Désactiver
chmod -t directory/

# Trouver les répertoires avec sticky bit
find / -perm -1000 -type d 2>/dev/null
```

---

### Résumé Special Bits

| Bit | Valeur | Sur Fichier | Sur Répertoire |
|-----|--------|-------------|----------------|
| SUID | 4 | Exécute avec droits proprio | (ignoré) |
| SGID | 2 | Exécute avec droits groupe | Héritage du groupe |
| Sticky | 1 | (ignoré) | Protection suppression |

```bash
# Exemples combinés
chmod 4755 file    # SUID + rwxr-xr-x
chmod 2775 dir     # SGID + rwxrwxr-x
chmod 1777 dir     # Sticky + rwxrwxrwx

# Notation symbolique
chmod u+s file     # SUID
chmod g+s dir      # SGID
chmod +t dir       # Sticky
```

---

## Sudoers & Sécurité

### Modification Sécurisée

```bash
# TOUJOURS utiliser visudo
sudo visudo

# Pourquoi ?
# - Vérifie la syntaxe avant sauvegarde
# - Évite de se bloquer dehors avec une erreur
```

!!! danger "Ne jamais éditer directement"
    ```bash
    # INTERDIT
    nano /etc/sudoers    # Une erreur de syntaxe = plus de sudo !

    # CORRECT
    visudo               # Vérifie la syntaxe avant sauvegarde
    ```

### Structure d'une Règle Sudo

```
user    host=(runas)    commands
│       │    │          │
│       │    │          └── Commandes autorisées
│       │    └──────────── Utilisateur cible (défaut: root)
│       └───────────────── Machine (ALL = toutes)
└───────────────────────── Utilisateur ou %groupe
```

**Exemples :**

```bash
# Accès total (dangereux)
john    ALL=(ALL)       ALL

# Groupe sudo standard
%sudo   ALL=(ALL:ALL)   ALL

# Commandes spécifiques seulement
john    ALL=(root)      /usr/bin/apt update, /usr/bin/apt upgrade

# Sans mot de passe (éviter pour admins)
deploy  ALL=(ALL)       NOPASSWD: /usr/bin/systemctl restart nginx

# Alias pour lisibilité
Cmnd_Alias SERVICES = /usr/bin/systemctl start *, /usr/bin/systemctl stop *, /usr/bin/systemctl restart *
john    ALL=(root)      SERVICES
```

### Vérifier ses Droits

```bash
# Lister ses droits sudo
sudo -l

# Output exemple :
# User john may run the following commands on server:
#     (ALL : ALL) ALL
#     (root) NOPASSWD: /usr/bin/systemctl restart nginx
```

!!! danger "SecNumCloud : Hardening Sudoers"
    **Règles de durcissement ANSSI :**

    1. **Éviter `ALL=(ALL) ALL`** pour les utilisateurs standards
       ```bash
       # MAUVAIS
       john ALL=(ALL) ALL

       # BON : Commandes spécifiques
       john ALL=(root) /usr/bin/apt, /usr/bin/systemctl
       ```

    2. **Toujours demander le mot de passe**
       ```bash
       # MAUVAIS (pour comptes admin)
       admin ALL=(ALL) NOPASSWD: ALL

       # BON
       admin ALL=(ALL) ALL
       # Le mot de passe est demandé à chaque session
       ```

    3. **Configurer le timeout**
       ```bash
       # Dans /etc/sudoers
       Defaults    timestamp_timeout=5    # Re-demande mdp après 5 min
       Defaults    passwd_tries=3         # 3 tentatives max
       ```

    4. **Logger toutes les commandes sudo**
       ```bash
       Defaults    logfile=/var/log/sudo.log
       Defaults    log_input, log_output
       ```

    5. **Restreindre l'éditeur**
       ```bash
       Defaults    editor=/usr/bin/vim
       Defaults    !visiblepw    # Cache le mot de passe
       ```

### Fichiers de Configuration

```bash
# Configuration principale
/etc/sudoers

# Configurations additionnelles (incluses)
/etc/sudoers.d/

# Ajouter une config spécifique
sudo visudo -f /etc/sudoers.d/deploy
```

---

## Référence Rapide

```bash
# Utilisateurs
id                              # Info utilisateur courant
useradd -m -s /bin/bash user    # Créer utilisateur
usermod -aG group user          # Ajouter au groupe

# Permissions
chmod 755 dir/                  # rwxr-xr-x
chmod 644 file                  # rw-r--r--
chmod u+s file                  # SUID
chmod g+s dir/                  # SGID
chmod +t dir/                   # Sticky

# Propriétaire
chown user:group file           # Changer proprio
chown -R www-data:www-data /var/www/

# Sudo
sudo -l                         # Lister ses droits
visudo                          # Éditer sudoers

# Audit sécurité
find / -perm -4000 -type f      # Binaires SUID
find / -perm -2000 -type d      # Répertoires SGID
```
