---
tags:
  - lpi
  - certification
  - linux-foundation
  - sysadmin
---

# Parcours Certification LPI (Cartes Mentales)

Cartes mentales visuelles pour réviser les concepts clés des examens LPIC-1 et LPIC-2.

---

!!! info "À Propos de cette Page"
    Cette page fournit des **cartes mentales structurées** utilisant des diagrammes Mermaid pour visualiser les concepts Linux essentiels à maîtriser pour les certifications LPI.

    **Avantage :** Contenu auto-suffisant (pas de dépendance externe), diagrammes interactifs, navigation rapide vers les guides détaillés.

---

## Section 1 : Démarrage & Système (LPIC-1)

### Boot Process - Séquence de Démarrage Linux

```mermaid
flowchart LR
    A[BIOS/UEFI] -->|POST Hardware| B[Bootloader<br/>GRUB2]
    B -->|Charge| C[Kernel Linux<br/>vmlinuz]
    C -->|Monte| D[initramfs<br/>Système Initial]
    D -->|Démarre| E[Init System<br/>Systemd/SysV]
    E -->|Lance| F[Services<br/>Userspace]
    F -->|Atteint| G[Target/Runlevel<br/>multi-user.target]

    style A fill:#e74c3c,color:#fff
    style C fill:#3498db,color:#fff
    style E fill:#2ecc71,color:#fff
    style G fill:#9b59b6,color:#fff
```

**Étapes Détaillées :**

1. **BIOS/UEFI** : POST (Power-On Self-Test), détection matériel
2. **GRUB2** : Menu de boot, charge le kernel avec paramètres (`/boot/grub/grub.cfg`)
3. **Kernel** : Décompression, initialisation drivers, monte système de fichiers root
4. **initramfs** : Système minimal en RAM pour démarrer les modules critiques
5. **Init (Systemd)** : Premier processus (PID 1), gestion des services
6. **Userspace** : Services réseau, ssh, bases de données, etc.
7. **Target** : État final (graphical.target, multi-user.target)

!!! tip "Guide Complet"
    → [Boot & Services : Systemd, GRUB, Targets](boot-and-services.md)

---

## Section 2 : Commandes Essentielles (LPIC-1)

### Text Processing Tools - Boîte à Outils CLI

```mermaid
graph TD
    A[Text Processing<br/>Traitement de Texte] --> B[Flux & Redirection]
    A --> C[Filtres & Recherche]
    A --> D[Manipulation Fichiers]

    B --> B1["|" Pipe]
    B --> B2[">" Redirection]
    B --> B3[">>" Append]
    B --> B4["2>&1" Stderr]

    C --> C1["grep - Recherche Pattern"]
    C --> C2["sed - Substitution"]
    C --> C3["awk - Colonnes & Calculs"]
    C --> C4["cut - Extraction Champs"]
    C --> C5["sort/uniq - Tri & Déduplication"]

    D --> D1["find - Recherche Fichiers"]
    D --> D2["locate - Index Rapide"]
    D --> D3["ls - Listing Détaillé"]
    D --> D4["wc - Comptage Lignes/Mots"]

    style A fill:#34495e,color:#fff
    style B fill:#3498db,color:#fff
    style C fill:#2ecc71,color:#fff
    style D fill:#e67e22,color:#fff
```

**Exemples Typiques LPIC-1 :**

```bash
# Compter les utilisateurs shell valides
grep -v '/nologin' /etc/passwd | wc -l

# Extraire IPs uniques des logs Apache
awk '{print $1}' /var/log/apache2/access.log | sort -u

# Trouver fichiers modifiés dernières 24h
find /var/log -type f -mtime -1

# Remplacer texte dans multiple fichiers
sed -i 's/old_hostname/new_hostname/g' /etc/hosts
```

!!! tip "Guides Associés"
    → [Text Processing : grep, sed, awk, regex](text-processing.md)
    → [Bash Wizardry : Scripts & Pipelines Avancés](bash-wizardry.md)

---

## Section 3 : Sécurité & Accès (LPIC-1)

### SSH Architecture - Client/Server

```mermaid
graph TB
    subgraph "SSH Server (sshd)"
        S1["/etc/ssh/sshd_config<br/>Configuration Serveur"]
        S2["~/.ssh/authorized_keys<br/>Clés Publiques Autorisées"]
        S3["/etc/ssh/ssh_host_*_key<br/>Clés Hôte (Identité Serveur)"]

        S1 -.->|Port 22| S4[Daemon sshd]
        S2 -.->|Authentification| S4
        S3 -.->|Signature Hôte| S4
    end

    subgraph "SSH Client"
        C1["~/.ssh/config<br/>Configuration Client"]
        C2["~/.ssh/known_hosts<br/>Empreintes Serveurs"]
        C3["~/.ssh/id_rsa<br/>Clé Privée (SECRET)"]
        C4["~/.ssh/id_rsa.pub<br/>Clé Publique"]

        C1 -.->|Connexion| C5[ssh command]
        C2 -.->|Vérification Hôte| C5
        C3 -.->|Signature| C5
    end

    C5 <-->|"Tunnel Chiffré<br/>(AES-256)"| S4

    style S4 fill:#e74c3c,color:#fff
    style C5 fill:#3498db,color:#fff
    style C3 fill:#c0392b,color:#fff
    style S2 fill:#27ae60,color:#fff
```

**Flux d'Authentification :**

1. **Client** : `ssh user@server` → Lecture `~/.ssh/config`
2. **Handshake** : Serveur envoie clé hôte → Client vérifie dans `known_hosts`
3. **Auth** : Client signe challenge avec `id_rsa` → Serveur vérifie avec `authorized_keys`
4. **Session** : Tunnel chiffré établi, shell interactif

**Fichiers Critiques :**

| Fichier | Permissions | Rôle |
|---------|-------------|------|
| `~/.ssh/id_rsa` | `600` | Clé privée (jamais partagée) |
| `~/.ssh/id_rsa.pub` | `644` | Clé publique (à copier sur serveurs) |
| `~/.ssh/authorized_keys` | `600` | Liste clés autorisées (serveur) |
| `~/.ssh/known_hosts` | `644` | Empreintes serveurs connus |
| `/etc/ssh/sshd_config` | `644` | Config daemon SSH |

!!! tip "Guide Sécurité SSH"
    → [SSH Hardening : Clés ED25519, Bastion, MFA](ssh-hardening.md)

---

## Section 4 : Infrastructure & Réseau (LPIC-2)

### LDAP Architecture - Directory Information Tree

```mermaid
graph TD
    A["dc=corp,dc=example,dc=com<br/>(DIT Root - Suffix)"] --> B1["ou=users<br/>(Organizational Unit)"]
    A --> B2["ou=groups<br/>(Organizational Unit)"]
    A --> B3["ou=computers<br/>(Organizational Unit)"]

    B1 --> C1["uid=jdoe,ou=users<br/>(Entry - Utilisateur)"]
    B1 --> C2["uid=asmith,ou=users<br/>(Entry - Utilisateur)"]

    B2 --> D1["cn=admins,ou=groups<br/>(Group Entry)"]
    B2 --> D2["cn=developers,ou=groups<br/>(Group Entry)"]

    B3 --> E1["cn=WKS-01,ou=computers<br/>(Computer Entry)"]

    C1 -.->|memberOf| D1
    C2 -.->|memberOf| D2

    style A fill:#34495e,color:#fff
    style B1 fill:#3498db,color:#fff
    style B2 fill:#2ecc71,color:#fff
    style B3 fill:#e67e22,color:#fff
    style D1 fill:#9b59b6,color:#fff
```

**Composants DN (Distinguished Name) :**

| Attribut | Signification | Exemple |
|----------|---------------|---------|
| `dc` | Domain Component | `dc=example,dc=com` |
| `ou` | Organizational Unit | `ou=users` |
| `cn` | Common Name | `cn=admins` |
| `uid` | User ID | `uid=jdoe` |

**Requête LDAP Typique :**

```bash
# Rechercher tous les utilisateurs dans ou=users
ldapsearch -x -b "ou=users,dc=corp,dc=example,dc=com" "(objectClass=posixAccount)"

# Vérifier appartenance groupe
ldapsearch -x -b "cn=admins,ou=groups,dc=corp,dc=example,dc=com" member

# Modifier mot de passe utilisateur
ldappasswd -x -D "cn=admin,dc=corp,dc=example,dc=com" -W \
  -S "uid=jdoe,ou=users,dc=corp,dc=example,dc=com"
```

**ObjectClasses Courants :**

- `posixAccount` : Compte Unix/Linux
- `posixGroup` : Groupe Unix/Linux
- `inetOrgPerson` : Utilisateur avec attributs étendus (mail, téléphone)
- `organizationalUnit` : Container logique

!!! tip "Guide LDAP Complet"
    → [389 Directory Server : Installation, Schema, Réplication](ldap-389ds.md)

---

## Stratégies de Révision

### Méthode "Carte → Pratique → Vérification"

```mermaid
flowchart LR
    A[Étudier<br/>Carte Mentale] --> B[Pratiquer<br/>Commandes/Configs]
    B --> C[Vérifier<br/>avec Exam Questions]
    C -->|Échec| A
    C -->|Réussite| D[Concept Maîtrisé]

    style A fill:#3498db,color:#fff
    style B fill:#2ecc71,color:#fff
    style C fill:#f39c12,color:#fff
    style D fill:#27ae60,color:#fff
```

### Ressources Complémentaires

| Domaine | Guides ShellBook |
|---------|------------------|
| **Système de Fichiers** | [Filesystem & Storage](filesystem-and-storage.md) • [LVM](lvm-raid.md) |
| **Réseau** | [Network Management](network-management.md) • [Firewall UFW](firewall-ufw.md) |
| **Services** | [Nginx](nginx-webserver.md) • [MariaDB](mariadb-mysql.md) |
| **Automatisation** | [Cron & Systemd Timers](cron-systemd-timers.md) |
| **Performance** | [Performance Analysis](performance-analysis.md) • [Debugging](debugging.md) |

---

## Référence Rapide

### Commandes LPIC-1 Critiques

```bash
# === SYSTÈME ===
systemctl status <service>           # État service
journalctl -u <service> -f           # Logs temps réel
lsblk -f                             # Partitions & filesystems
df -h                                # Utilisation disques
free -h                              # Mémoire RAM/Swap

# === RÉSEAU ===
ip addr show                         # Interfaces réseau
ss -tulpn                            # Ports en écoute
ping -c 4 <host>                     # Test connectivité
traceroute <host>                    # Route réseau

# === SÉCURITÉ ===
chmod 600 ~/.ssh/id_rsa              # Permissions clé privée
ssh-keygen -t ed25519                # Générer paire clés SSH
sudo -l                              # Privilèges sudo
last -n 10                           # Dernières connexions

# === FICHIERS ===
find / -name "*.log" -mtime -7       # Logs 7 derniers jours
grep -r "error" /var/log/            # Recherche récursive
tar -czf backup.tar.gz /data/        # Archiver & compresser
```

### Commandes LPIC-2 Avancées

```bash
# === LDAP ===
ldapsearch -x -b "dc=example,dc=com" "(uid=jdoe)"
ldapadd -x -D "cn=admin,dc=example,dc=com" -W -f user.ldif
ldapmodify -x -D "cn=admin,dc=example,dc=com" -W -f modify.ldif

# === DNS (BIND) ===
named-checkconf                      # Valider named.conf
named-checkzone example.com db.example.com
dig @localhost example.com           # Test résolution locale

# === NFS ===
exportfs -ra                         # Recharger /etc/exports
showmount -e <server>                # Lister partages NFS

# === SMTP (Postfix) ===
postconf -n                          # Config non-default
postqueue -p                         # File d'attente mails
mailq                                # Alias de postqueue -p
```

!!! success "Bonne Chance pour vos Certifications !"
    Ces cartes mentales couvrent les concepts fondamentaux. Consultez les guides détaillés liés pour approfondir chaque sujet.
