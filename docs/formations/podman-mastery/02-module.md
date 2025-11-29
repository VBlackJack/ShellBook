---
tags:
  - formation
  - podman
  - rootless
  - security
---

# Module 2 : Conteneurs Rootless

## Objectifs du Module

- Comprendre les enjeux sécurité du rootless
- Configurer les user namespaces
- Exécuter des conteneurs sans privilèges
- Résoudre les problèmes courants

**Durée :** 2 heures

---

## 1. Pourquoi Rootless ?

```
SÉCURITÉ : ROOT VS ROOTLESS
════════════════════════════════════════════════════════

CONTENEUR ROOT (traditionnel)
─────────────────────────────
Host                    Container
┌─────────────────┐    ┌─────────────────┐
│ root (UID 0)    │◄───│ root (UID 0)    │
│                 │    │ ⚠️ Si escape,   │
│                 │    │   devient root  │
│                 │    │   sur l'hôte!   │
└─────────────────┘    └─────────────────┘

CONTENEUR ROOTLESS
──────────────────
Host                    Container
┌─────────────────┐    ┌─────────────────┐
│ user (UID 1000) │◄───│ root (UID 0)    │
│                 │    │ ✓ Si escape,    │
│                 │    │   reste user    │
│                 │    │   non privilégié│
└─────────────────┘    └─────────────────┘

User namespace mapping:
Container UID 0  → Host UID 100000
Container UID 1  → Host UID 100001
...
```

### Avantages Compliance

| Exigence | Rootless |
|----------|----------|
| PCI-DSS 2.2 | Pas de services root inutiles |
| CIS Benchmark | Conteneurs non-privilégiés |
| SecNumCloud | Isolation renforcée |
| Zero Trust | Principe du moindre privilège |

---

## 2. Configuration User Namespaces

### Vérifier la Configuration

```bash
# Vérifier que les user namespaces sont activés
cat /proc/sys/user/max_user_namespaces
# Doit être > 0 (défaut: 15000)

# Vérifier les mappings pour votre utilisateur
cat /etc/subuid
# username:100000:65536

cat /etc/subgid
# username:100000:65536
```

### Configurer un Nouvel Utilisateur

```bash
# Créer un utilisateur dédié aux conteneurs
sudo useradd -m podman-user

# Configurer les subuid/subgid automatiquement
sudo usermod --add-subuids 200000-265535 --add-subgids 200000-265535 podman-user

# Vérifier
grep podman-user /etc/subuid /etc/subgid
```

### Migration des Mappings

```bash
# Si vous changez les mappings, réinitialiser le storage
podman system migrate

# Ou reset complet
podman system reset
```

---

## 3. Différences Root vs Rootless

### Stockage

```bash
# Rootful (en tant que root)
sudo podman info --format '{{.Store.GraphRoot}}'
# /var/lib/containers/storage

# Rootless (en tant qu'utilisateur)
podman info --format '{{.Store.GraphRoot}}'
# /home/user/.local/share/containers/storage
```

### Réseau

```bash
# Rootful : accès aux ports < 1024
sudo podman run -d -p 80:80 nginx

# Rootless : ports >= 1024 par défaut
podman run -d -p 8080:80 nginx

# Autoriser les ports bas en rootless
sudo sysctl net.ipv4.ip_unprivileged_port_start=80
# Ou permanent dans /etc/sysctl.d/podman.conf
```

### Ping et ICMP

```bash
# Rootless : ping peut ne pas fonctionner
podman run --rm alpine ping -c1 google.com
# ping: permission denied

# Solution : autoriser le ping
sudo sysctl net.ipv4.ping_group_range="0 65536"
```

---

## 4. Configuration Rootless

### Fichiers de Configuration

```bash
# Configuration globale
/etc/containers/containers.conf

# Configuration utilisateur (prioritaire)
~/.config/containers/containers.conf
```

### Exemple de Configuration

```toml
# ~/.config/containers/containers.conf

[containers]
# User par défaut dans les conteneurs
userns = "auto"

# Capabilities par défaut (réduites)
default_capabilities = [
  "CHOWN",
  "DAC_OVERRIDE",
  "FOWNER",
  "FSETID",
  "KILL",
  "NET_BIND_SERVICE",
  "SETFCAP",
  "SETGID",
  "SETPCAP",
  "SETUID",
]

[engine]
# Activer les événements
events_logger = "journald"

# Runtime (crun recommandé)
runtime = "crun"

[network]
# Driver réseau par défaut
default_network = "podman"
```

---

## 5. Gestion des Permissions

### Volumes et SELinux

```bash
# Problème : permission denied sur les volumes
podman run -v /data:/data:ro alpine ls /data
# ls: /data: Permission denied

# Solution 1 : Label SELinux
podman run -v /data:/data:ro,Z alpine ls /data

# Solution 2 : Désactiver SELinux pour ce volume (non recommandé)
podman run -v /data:/data:ro --security-opt label=disable alpine ls /data

# Options de volume
# :Z = label privé (container seul)
# :z = label partagé (plusieurs containers)
```

### Ownership des Fichiers

```bash
# Problème : fichiers créés avec mauvais owner
podman run -v ./data:/data alpine touch /data/file
ls -la ./data/file
# -rw-r--r-- 1 100000 100000 ... file  (UID mappé!)

# Solution : --userns=keep-id
podman run --userns=keep-id -v ./data:/data alpine touch /data/file
ls -la ./data/file
# -rw-r--r-- 1 user user ... file  (votre UID!)
```

---

## 6. Troubleshooting Rootless

### Problèmes Courants

```bash
# Erreur : ERRO[0000] cannot find UID/GID for user
# Solution : vérifier /etc/subuid et /etc/subgid
grep $USER /etc/subuid /etc/subgid

# Erreur : Error: could not get runtime: cannot open...
# Solution : reset du storage
podman system reset

# Erreur : permission denied sur /var/run/...
# Solution : vérifier XDG_RUNTIME_DIR
echo $XDG_RUNTIME_DIR
# Doit être /run/user/$(id -u)

# Erreur : WARN[0000] "/" is not a shared mount
# Solution :
findmnt -o PROPAGATION /
# Si "private", reconfigurer systemd
```

### Diagnostic Complet

```bash
# Script de diagnostic
podman info --debug 2>&1 | head -50

# Vérifier les capabilities
podman run --rm alpine cat /proc/self/status | grep Cap

# Tester les user namespaces
podman unshare cat /proc/self/uid_map

# Vérifier le réseau
podman network ls
podman network inspect podman
```

---

## 7. Exercice Pratique

### Objectif

Configurer un environnement rootless complet et résoudre les problèmes de permissions.

### Étapes

```bash
# 1. Vérifier votre configuration
echo "=== User Namespaces ==="
cat /proc/sys/user/max_user_namespaces

echo "=== SubUID/SubGID ==="
grep $USER /etc/subuid /etc/subgid

echo "=== Podman Info ==="
podman info | grep -E "(rootless|graphRoot)"

# 2. Créer un répertoire avec des données
mkdir -p ~/podman-lab/rootless-test
echo "Hello Rootless" > ~/podman-lab/rootless-test/data.txt
chmod 644 ~/podman-lab/rootless-test/data.txt

# 3. Tester sans keep-id (problème de permissions)
podman run --rm \
  -v ~/podman-lab/rootless-test:/data:Z \
  registry.access.redhat.com/ubi9/ubi-minimal \
  cat /data/data.txt

# 4. Créer un fichier depuis le conteneur
podman run --rm \
  -v ~/podman-lab/rootless-test:/data:Z \
  registry.access.redhat.com/ubi9/ubi-minimal \
  sh -c "echo 'Created by container' > /data/container.txt"

# Vérifier l'ownership (sera mappé)
ls -la ~/podman-lab/rootless-test/

# 5. Utiliser keep-id pour conserver les UIDs
podman run --rm \
  --userns=keep-id \
  -v ~/podman-lab/rootless-test:/data:Z \
  registry.access.redhat.com/ubi9/ubi-minimal \
  sh -c "echo 'Created with keep-id' > /data/keepid.txt"

# Vérifier l'ownership (sera votre user)
ls -la ~/podman-lab/rootless-test/

# 6. Cleanup
rm -rf ~/podman-lab/rootless-test
```

---

## 8. Bonnes Pratiques Production

```yaml
# Checklist Rootless Production
# ═══════════════════════════════

Configuration Système:
  - [ ] User namespaces activés (max_user_namespaces > 0)
  - [ ] subuid/subgid configurés (65536 UIDs minimum)
  - [ ] Linger activé (loginctl enable-linger)
  - [ ] XDG_RUNTIME_DIR défini

Sécurité:
  - [ ] Pas de --privileged
  - [ ] Capabilities minimales
  - [ ] SELinux enforcing avec labels :Z
  - [ ] read_only: true quand possible

Réseau:
  - [ ] Ports > 1024 (ou net.ipv4.ip_unprivileged_port_start)
  - [ ] Réseau dédié par application
  - [ ] Pas de --network=host

Volumes:
  - [ ] Labels SELinux (:Z ou :z)
  - [ ] --userns=keep-id si besoin d'ownership cohérent
  - [ ] Pas de bind mounts sur /etc, /var sensibles
```

---

## Quiz

1. **Quel fichier définit les UIDs disponibles pour les user namespaces ?**
   - [ ] A. /etc/passwd
   - [ ] B. /etc/subuid
   - [ ] C. /etc/containers/uid.conf

**Réponse :** B

2. **Quelle option préserve l'UID de l'utilisateur dans le conteneur ?**
   - [ ] A. --user=keep
   - [ ] B. --userns=keep-id
   - [ ] C. --preserve-uid

**Réponse :** B

3. **Quel port minimum est autorisé par défaut en rootless ?**
   - [ ] A. 80
   - [ ] B. 443
   - [ ] C. 1024

**Réponse :** C (ports < 1024 nécessitent une configuration spéciale)

---

**Précédent :** [Module 1 - Fondamentaux](01-module.md)

**Suivant :** [Module 3 - Buildah & Construction](03-module.md)
