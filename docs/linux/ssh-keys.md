---
tags:
  - ssh
  - security
  - keys
  - encryption
  - linux
---

# Clés SSH Sécurisées

Gestion complète des clés SSH : génération, déploiement, agent et bonnes pratiques de sécurité.

---

## Générer une Paire de Clés

!!! info "Recommandation ANSSI"
    Selon les directives ANSSI, les clés RSA doivent faire **minimum 3072 bits**.
    **Ed25519 est préféré** : plus rapide, plus sûr, clés plus courtes.

### Ed25519 (Recommandé)

=== "Linux/macOS"

    ```bash
    ssh-keygen -t ed25519 -C "user@domain.com" -f ~/.ssh/id_ed25519
    ```

=== "Windows (PowerShell)"

    ```powershell
    ssh-keygen -t ed25519 -C "user@domain.com" -f "$env:USERPROFILE\.ssh\id_ed25519"
    ```

### RSA 4096 bits (Compatibilité)

```bash
ssh-keygen -t rsa -b 4096 -C "user@domain.com" -f ~/.ssh/id_rsa_secure
```

!!! warning "Passphrase obligatoire"
    Toujours définir une phrase de passe forte. Sans passphrase, une clé volée = accès total.

---

## Déployer la Clé Publique

### Méthode 1 : ssh-copy-id (recommandé)

```bash
ssh-copy-id -i ~/.ssh/id_ed25519.pub user@server
```

### Méthode 2 : Manuelle

```bash
# Copier la clé publique
cat ~/.ssh/id_ed25519.pub | ssh user@server "mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
```

### Méthode 3 : Cloud-init / Ansible

```yaml
# cloud-init
users:
  - name: deploy
    ssh_authorized_keys:
      - ssh-ed25519 AAAA... user@domain.com
```

---

## SSH Agent

L'agent garde les clés déchiffrées en mémoire pour éviter de ressaisir la passphrase.

```bash
# Démarrer l'agent
eval "$(ssh-agent -s)"

# Ajouter une clé (demande la passphrase une fois)
ssh-add ~/.ssh/id_ed25519

# Lister les clés chargées
ssh-add -l

# Supprimer toutes les clés
ssh-add -D
```

### Persistance (Linux)

```bash
# ~/.bashrc ou ~/.zshrc
if [ -z "$SSH_AUTH_SOCK" ]; then
    eval "$(ssh-agent -s)"
    ssh-add ~/.ssh/id_ed25519 2>/dev/null
fi
```

### Agent Forwarding

```bash
# Connexion avec forwarding de l'agent
ssh -A user@bastion

# Depuis le bastion, accès au serveur final sans clé locale
ssh user@internal-server
```

!!! danger "Risque Agent Forwarding"
    Un admin root sur le bastion peut utiliser votre agent. Préférer **ProxyJump**.

---

## Configuration SSH (~/.ssh/config)

```text
# Serveur par défaut
Host *
    AddKeysToAgent yes
    IdentitiesOnly yes

# Bastion avec ProxyJump
Host internal-*
    ProxyJump bastion.example.com
    User admin

Host bastion.example.com
    User jump
    IdentityFile ~/.ssh/id_ed25519_bastion

# Serveur spécifique
Host prod-db
    HostName 10.0.1.50
    User postgres
    IdentityFile ~/.ssh/id_ed25519_prod
    Port 2222
```

---

## Permissions Correctes

```bash
# Répertoire .ssh
chmod 700 ~/.ssh

# Clé privée (CRITIQUE)
chmod 600 ~/.ssh/id_ed25519

# Clé publique
chmod 644 ~/.ssh/id_ed25519.pub

# authorized_keys
chmod 600 ~/.ssh/authorized_keys

# config
chmod 600 ~/.ssh/config
```

!!! warning "Erreur courante"
    SSH refuse de fonctionner si les permissions sont trop permissives.
    ```text
    Permissions 0644 for '/home/user/.ssh/id_ed25519' are too open.
    ```

---

## Rotation des Clés

```bash
# 1. Générer nouvelle clé
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519_new -C "user@domain.com $(date +%Y)"

# 2. Déployer sur tous les serveurs
ssh-copy-id -i ~/.ssh/id_ed25519_new.pub user@server1
ssh-copy-id -i ~/.ssh/id_ed25519_new.pub user@server2

# 3. Tester la nouvelle clé
ssh -i ~/.ssh/id_ed25519_new user@server1

# 4. Supprimer l'ancienne clé des serveurs
ssh user@server1 "sed -i '/OLD_KEY_FINGERPRINT/d' ~/.ssh/authorized_keys"

# 5. Remplacer localement
mv ~/.ssh/id_ed25519 ~/.ssh/id_ed25519_old
mv ~/.ssh/id_ed25519_new ~/.ssh/id_ed25519
```

---

## Dépannage

### Permission denied (publickey)

```bash
# Vérifier que la clé est chargée
ssh-add -l

# Tester avec verbose
ssh -vvv user@server

# Vérifier les permissions côté serveur
ssh user@server "ls -la ~/.ssh/"
```

### Causes courantes

| Erreur | Cause | Solution |
|--------|-------|----------|
| `Permission denied` | Clé pas dans authorized_keys | `ssh-copy-id` |
| `Bad permissions` | chmod incorrect | `chmod 600 ~/.ssh/id_*` |
| `Agent refused` | Agent pas démarré | `eval $(ssh-agent)` |
| `Host key changed` | Serveur réinstallé | `ssh-keygen -R server` |

---

## Référence Rapide

```bash
# === GÉNÉRATION ===
ssh-keygen -t ed25519 -C "comment"          # Générer Ed25519
ssh-keygen -t rsa -b 4096 -C "comment"      # Générer RSA

# === DÉPLOIEMENT ===
ssh-copy-id -i ~/.ssh/key.pub user@server   # Copier clé publique
cat ~/.ssh/key.pub                           # Afficher clé publique

# === AGENT ===
eval "$(ssh-agent -s)"                       # Démarrer agent
ssh-add ~/.ssh/id_ed25519                    # Ajouter clé
ssh-add -l                                   # Lister clés

# === PERMISSIONS ===
chmod 700 ~/.ssh                             # Répertoire
chmod 600 ~/.ssh/id_*                        # Clés privées
chmod 600 ~/.ssh/authorized_keys             # Clés autorisées

# === DEBUG ===
ssh -vvv user@server                         # Mode verbose
ssh-keygen -lf ~/.ssh/id_ed25519.pub         # Fingerprint
```

---

## Voir Aussi

- [SSH Tunnels](ssh-tunnels.md) - Port forwarding et tunnels
- [SSH Hardening](ssh-hardening.md) - Sécurisation serveur SSH
- [Cheatsheet SSH](cheatsheet-ssh.md) - Référence rapide complète
