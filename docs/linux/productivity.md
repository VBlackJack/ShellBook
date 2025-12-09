---
tags:
  - productivity
  - terminal
  - shortcuts
  - bash
  - tips
---

# Productivité Terminal & Astuces

Maîtrisez ces raccourcis pour naviguer et travailler plus vite dans n'importe quel environnement Linux.

---

## Raccourcis de Navigation

### Basculer vers le Répertoire Précédent

```bash
cd /var/log
cd /etc/nginx
cd -          # Retourne vers /var/log
cd -          # Retourne vers /etc/nginx
```

### Navigation par Pile (pushd/popd)

```bash
pushd /var/log      # Empile le répertoire actuel, cd vers /var/log
pushd /etc/nginx    # Empile /var/log, cd vers /etc/nginx
pushd /home/user    # Empile /etc/nginx

dirs -v             # Afficher la pile avec index
popd                # Retourner vers /etc/nginx
popd                # Retourner vers /var/log
```

| Commande | Description |
|---------|-------------|
| `pushd <dir>` | Sauvegarder la position actuelle et aller vers `<dir>` |
| `popd` | Retourner à la dernière position sauvegardée |
| `dirs -v` | Afficher la pile de répertoires |
| `cd ~2` | Aller à la position 2 de la pile (zsh) |

---

## Manipulation de l'Historique

| Raccourci | Description |
|----------|-------------|
| ++ctrl+r++ | Recherche inversée dans l'historique |
| `!!` | Répéter la dernière commande |
| `sudo !!` | Exécuter la dernière commande avec sudo |
| `!$` | Dernier argument de la commande précédente |
| `!*` | Tous les arguments de la commande précédente |
| `!ssh` | Exécuter la dernière commande commençant par `ssh` |
| `!42` | Exécuter la commande #42 de l'historique |

### Recherche Inversée (CTRL+R)

```bash
(reverse-i-search)`nginx': systemctl restart nginx
```

- ++ctrl+r++ à nouveau → parcourir les résultats
- ++enter++ → exécuter
- ++ctrl+g++ → annuler

---

## Alias de Sécurité

=== "Bash (~/.bashrc)"

    ```bash
    # Filets de sécurité - toujours demander avant action destructive
    alias rm='rm -i'
    alias cp='cp -i'
    alias mv='mv -i'

    # Opérations verbeuses
    alias mkdir='mkdir -pv'
    alias chmod='chmod -v'
    alias chown='chown -v'

    # Sortie colorisée
    alias ls='ls --color=auto'
    alias ll='ls -lahF'
    alias grep='grep --color=auto'

    # Navigation rapide
    alias ..='cd ..'
    alias ...='cd ../..'
    alias ....='cd ../../..'
    ```

=== "Zsh (~/.zshrc)"

    ```zsh
    # Filets de sécurité
    alias rm='rm -i'
    alias cp='cp -i'
    alias mv='mv -i'

    # Opérations verbeuses
    alias mkdir='mkdir -pv'

    # Sortie colorisée
    alias ls='ls --color=auto'
    alias ll='ls -lahF'
    alias grep='grep --color=auto'

    # Extras Zsh
    alias reload='source ~/.zshrc'
    alias path='echo $PATH | tr ":" "\n"'
    ```

!!! tip "Astuce Pro : Fichier de Config Personnalisé"
    Conservez vos alias dans un fichier `~/.bashrc_custom` séparé :

    ```bash
    # Dans ~/.bashrc, ajouter à la fin :
    [ -f ~/.bashrc_custom ] && source ~/.bashrc_custom
    ```

    Cela garde vos personnalisations portables et séparées des paramètres système.

!!! warning "Contourner un Alias"
    Pour exécuter la commande originale sans alias : `\rm file` ou `command rm file`
