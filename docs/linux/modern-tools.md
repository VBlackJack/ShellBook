# Remplacements Modernes (Legacy vs Nouveau)

Arrêtez d'utiliser les `net-tools` obsolètes. Passez à `iproute2` et aux alternatives modernes.

---

## Commandes Réseau : net-tools → iproute2

!!! danger "Avertissement de Dépréciation"
    `net-tools` (ifconfig, netstat, route) est déprécié et non maintenu depuis 2001.
    Utilisez `iproute2` pour les noyaux modernes et les nouvelles fonctionnalités.

| Legacy (net-tools) | Moderne (iproute2) | Usage |
|--------------------|-------------------|---------|
| `ifconfig` | `ip addr` / `ip a` | Afficher les adresses IP |
| `ifconfig eth0 up` | `ip link set eth0 up` | Activer l'interface |
| `netstat -tulpn` | `ss -tulpn` | Afficher les ports en écoute |
| `netstat -an` | `ss -an` | Toutes les connexions |
| `route -n` | `ip route` / `ip r` | Afficher la table de routage |
| `route add` | `ip route add` | Ajouter une route |
| `arp -a` | `ip neigh` | Table ARP |
| `hostname -I` | `ip -br addr` | Résumé IP concis |

### Exemples Rapides

```bash
# Afficher toutes les IPs (format concis)
ip -br addr

# Afficher uniquement IPv4
ip -4 addr

# Afficher TCP/UDP en écoute avec noms de processus
ss -tulpn

# Afficher les connexions établies
ss -t state established
```

---

## Monitoring Processus : top → htop/btop

| Outil | Installation | Fonctionnalités |
|------|---------|----------|
| `top` | Intégré | Basique, pas de souris |
| `htop` | `apt install htop` | Couleurs, souris, vue arbre, kill processus |
| `btop` | `apt install btop` | UI moderne, graphiques, thèmes |

```bash
# Installer les alternatives modernes
sudo apt install htop btop    # Debian/Ubuntu
sudo dnf install htop btop    # RHEL/Fedora
```

!!! tip "Raccourcis htop"
    - `F5` → Vue arbre
    - `F6` → Trier par colonne
    - `F9` → Tuer le processus
    - `t` → Basculer arbre
    - `H` → Masquer les threads utilisateur

---

## Recherche de Fichiers : find → fd

`fd` est une alternative rapide et conviviale à `find`.

| Tâche | find | fd |
|------|------|-----|
| Chercher par nom | `find . -name "*.log"` | `fd ".log$"` |
| Insensible à la casse | `find . -iname "*.LOG"` | `fd -i ".log$"` |
| Trouver répertoires | `find . -type d -name config` | `fd -t d config` |
| Exclure répertoire | `find . -path ./node_modules -prune -o -name "*.js"` | `fd -E node_modules ".js$"` |

```bash
# Installer fd
sudo apt install fd-find      # Debian/Ubuntu (binaire: fdfind)
sudo dnf install fd-find      # RHEL/Fedora

# Créer un alias si nécessaire
alias fd='fdfind'
```

---

## Recherche de Texte : grep → ripgrep

`ripgrep` (`rg`) est significativement plus rapide que `grep` pour les grandes bases de code.

```bash
# Installer
sudo apt install ripgrep

# Utilisation
rg "pattern"                  # Récursif par défaut
rg -i "error"                 # Insensible à la casse
rg -t py "import"             # Seulement fichiers Python
rg --hidden "secret"          # Inclure fichiers cachés
```
