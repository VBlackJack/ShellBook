---
tags:
  - bash
  - shell
  - configuration
  - productivity
  - terminal
---

# Bashrc Optimisé

Configuration complète d'un `.bashrc` professionnel pour sysadmins et DevOps.

---

## Structure Recommandée

```bash
~/.bashrc              # Configuration principale
~/.bashrc.d/           # Répertoire pour modules (optionnel)
├── aliases.sh
├── functions.sh
├── prompt.sh
└── completions.sh
~/.bash_profile        # Chargé au login (source ~/.bashrc)
```

!!! tip "Modularité"
    Pour un `.bashrc` maintenable, séparez la configuration en fichiers :
    ```bash
    # À la fin de ~/.bashrc
    for file in ~/.bashrc.d/*.sh; do
        [ -r "$file" ] && source "$file"
    done
    ```

---

## Configuration de Base

### Options Shell Essentielles

```bash
# ══════════════════════════════════════════════════════════════
# OPTIONS SHELL
# ══════════════════════════════════════════════════════════════

# Historique
HISTSIZE=10000                    # Lignes en mémoire
HISTFILESIZE=20000                # Lignes dans le fichier
HISTCONTROL=ignoreboth:erasedups  # Ignore doublons et espaces
HISTTIMEFORMAT="%Y-%m-%d %H:%M:%S  "  # Timestamp
HISTIGNORE="ls:ll:cd:pwd:exit:clear:history"  # Commandes ignorées

shopt -s histappend               # Append plutôt qu'écraser
shopt -s cmdhist                  # Commandes multi-lignes sur une ligne

# Navigation
shopt -s autocd                   # cd sans taper cd
shopt -s cdspell                  # Correction typos cd
shopt -s dirspell                 # Correction typos répertoires
shopt -s direxpand                # Expansion des variables dans les chemins

# Glob et Pattern Matching
shopt -s globstar                 # ** pour récursif
shopt -s extglob                  # Patterns étendus !(pattern)
shopt -s nocaseglob               # Glob insensible à la casse
shopt -s dotglob                  # Inclure fichiers cachés dans glob

# Divers
shopt -s checkwinsize             # Mise à jour LINES/COLUMNS
shopt -s no_empty_cmd_completion  # Pas de completion sur ligne vide
```

### Variables d'Environnement

```bash
# ══════════════════════════════════════════════════════════════
# ENVIRONNEMENT
# ══════════════════════════════════════════════════════════════

# Éditeur par défaut
export EDITOR=vim
export VISUAL=vim

# Pager
export PAGER=less
export LESS='-R -F -X -i -M -S'
# -R : Couleurs ANSI
# -F : Quit si < 1 écran
# -X : Pas d'init/deinit termcap
# -i : Recherche insensible casse
# -M : Prompt verbose
# -S : Pas de wrap lignes longues

# Couleurs man pages
export LESS_TERMCAP_mb=$'\e[1;32m'      # Début blink
export LESS_TERMCAP_md=$'\e[1;34m'      # Début bold (titres)
export LESS_TERMCAP_me=$'\e[0m'         # Fin mode
export LESS_TERMCAP_so=$'\e[1;33m'      # Début standout (status)
export LESS_TERMCAP_se=$'\e[0m'         # Fin standout
export LESS_TERMCAP_us=$'\e[1;4;36m'    # Début underline
export LESS_TERMCAP_ue=$'\e[0m'         # Fin underline

# Locale
export LANG=en_US.UTF-8
export LC_ALL=en_US.UTF-8

# Path personnel
export PATH="$HOME/.local/bin:$HOME/bin:$PATH"
```

---

## Prompt Personnalisé (PS1)

### Prompt Simple et Efficace

```bash
# ══════════════════════════════════════════════════════════════
# PROMPT
# ══════════════════════════════════════════════════════════════

# Couleurs
RED='\[\e[0;31m\]'
GREEN='\[\e[0;32m\]'
YELLOW='\[\e[0;33m\]'
BLUE='\[\e[0;34m\]'
PURPLE='\[\e[0;35m\]'
CYAN='\[\e[0;36m\]'
WHITE='\[\e[0;37m\]'
BOLD='\[\e[1m\]'
RESET='\[\e[0m\]'

# Prompt simple : user@host:path$
PS1="${GREEN}\u${RESET}@${CYAN}\h${RESET}:${BLUE}\w${RESET}\$ "

# Pour root (rouge)
if [ "$EUID" -eq 0 ]; then
    PS1="${RED}\u${RESET}@${CYAN}\h${RESET}:${BLUE}\w${RESET}# "
fi
```

### Prompt avec Git

```bash
# Fonction Git pour le prompt
__git_ps1_custom() {
    local branch=$(git symbolic-ref --short HEAD 2>/dev/null)
    if [ -n "$branch" ]; then
        local status=""
        # Fichiers modifiés
        git diff --quiet 2>/dev/null || status+="*"
        # Fichiers staged
        git diff --cached --quiet 2>/dev/null || status+="+"
        # Fichiers untracked
        [ -n "$(git ls-files --others --exclude-standard 2>/dev/null)" ] && status+="?"

        echo " (${branch}${status})"
    fi
}

# Prompt avec Git
PS1="${GREEN}\u${RESET}@${CYAN}\h${RESET}:${BLUE}\w${YELLOW}\$(__git_ps1_custom)${RESET}\$ "
```

### Prompt Avancé avec Indicateurs

```bash
# Prompt multi-ligne avec informations système
__prompt_command() {
    local EXIT="$?"
    local exit_indicator=""

    # Indicateur code de sortie
    if [ $EXIT -ne 0 ]; then
        exit_indicator="${RED}[$EXIT]${RESET} "
    fi

    # Nombre de jobs en background
    local jobs_count=$(jobs -p | wc -l)
    local jobs_indicator=""
    [ $jobs_count -gt 0 ] && jobs_indicator="${YELLOW}[jobs:$jobs_count]${RESET} "

    # SSH indicator
    local ssh_indicator=""
    [ -n "$SSH_CLIENT" ] && ssh_indicator="${PURPLE}[SSH]${RESET} "

    # Construction du prompt
    PS1="\n${ssh_indicator}${jobs_indicator}${exit_indicator}"
    PS1+="${GREEN}\u${RESET}@${CYAN}\h${RESET}:${BLUE}\w${YELLOW}\$(__git_ps1_custom)${RESET}"
    PS1+="\n\$ "
}

PROMPT_COMMAND=__prompt_command
```

---

## Alias Essentiels

### Navigation et Fichiers

```bash
# ══════════════════════════════════════════════════════════════
# ALIAS - NAVIGATION
# ══════════════════════════════════════════════════════════════

# Navigation rapide
alias ..='cd ..'
alias ...='cd ../..'
alias ....='cd ../../..'
alias .....='cd ../../../..'
alias -- -='cd -'

# Listing
alias ls='ls --color=auto --group-directories-first'
alias ll='ls -lhF'
alias la='ls -lhFA'
alias l='ls -CF'
alias lt='ls -lhFtr'          # Par date, récent en dernier
alias lS='ls -lhFS'           # Par taille, gros en premier
alias lsd='ls -d */'          # Répertoires seulement
alias lsh='ls -d .*'          # Fichiers cachés

# Tree (si installé)
alias tree='tree -C --dirsfirst'
alias t='tree -L 2'
alias t3='tree -L 3'

# Grep coloré
alias grep='grep --color=auto'
alias egrep='egrep --color=auto'
alias fgrep='fgrep --color=auto'

# Recherche
alias ff='find . -type f -name'   # ff "*.log"
alias fd='find . -type d -name'   # fd "config*"
```

### Sécurité et Opérations

```bash
# ══════════════════════════════════════════════════════════════
# ALIAS - SECURITE
# ══════════════════════════════════════════════════════════════

# Confirmation avant action destructive
alias rm='rm -I --preserve-root'
alias cp='cp -i'
alias mv='mv -i'
alias ln='ln -i'

# Protection root
alias chown='chown --preserve-root'
alias chmod='chmod --preserve-root'
alias chgrp='chgrp --preserve-root'

# Création verbose
alias mkdir='mkdir -pv'

# Diff coloré
alias diff='diff --color=auto'
```

### Système et Monitoring

```bash
# ══════════════════════════════════════════════════════════════
# ALIAS - SYSTEME
# ══════════════════════════════════════════════════════════════

# Mémoire et disque
alias df='df -h'
alias du='du -h'
alias du1='du -h --max-depth=1 | sort -hr'
alias free='free -h'

# Processus
alias ps='ps auxf'
alias psg='ps aux | grep -v grep | grep -i'  # psg nginx
alias top='htop 2>/dev/null || top'

# Réseau
alias ports='ss -tulanp'
alias myip='curl -s ifconfig.me && echo'
alias localip="ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v 127.0.0.1"

# Systemd
alias sc='systemctl'
alias scs='systemctl status'
alias scr='systemctl restart'
alias sce='systemctl enable'
alias scd='systemctl disable'
alias scl='systemctl list-units --type=service'
alias jc='journalctl'
alias jcf='journalctl -f'
alias jcu='journalctl -u'

# Date
alias now='date +"%Y-%m-%d %H:%M:%S"'
alias timestamp='date +%s'
```

### Git

```bash
# ══════════════════════════════════════════════════════════════
# ALIAS - GIT
# ══════════════════════════════════════════════════════════════

alias g='git'
alias gs='git status -sb'
alias ga='git add'
alias gaa='git add -A'
alias gc='git commit -m'
alias gca='git commit -am'
alias gp='git push'
alias gpl='git pull'
alias gf='git fetch --all --prune'
alias gd='git diff'
alias gds='git diff --staged'
alias gl='git log --oneline -20'
alias glg='git log --graph --oneline --decorate -20'
alias gco='git checkout'
alias gcb='git checkout -b'
alias gb='git branch -av'
alias gm='git merge'
alias gst='git stash'
alias gstp='git stash pop'
alias grh='git reset --hard'
alias grhh='git reset --hard HEAD'
alias gwip='git add -A && git commit -m "WIP"'
```

### Docker et Kubernetes

```bash
# ══════════════════════════════════════════════════════════════
# ALIAS - CONTENEURS
# ══════════════════════════════════════════════════════════════

# Docker
alias d='docker'
alias dps='docker ps --format "table {{.ID}}\t{{.Names}}\t{{.Status}}\t{{.Ports}}"'
alias dpsa='docker ps -a --format "table {{.ID}}\t{{.Names}}\t{{.Status}}\t{{.Ports}}"'
alias di='docker images'
alias dex='docker exec -it'
alias dl='docker logs -f'
alias dprune='docker system prune -af'
alias dc='docker compose'
alias dcu='docker compose up -d'
alias dcd='docker compose down'
alias dcl='docker compose logs -f'

# Kubernetes
alias k='kubectl'
alias kgp='kubectl get pods'
alias kgpa='kubectl get pods -A'
alias kgs='kubectl get svc'
alias kgd='kubectl get deployments'
alias kgn='kubectl get nodes'
alias kd='kubectl describe'
alias kl='kubectl logs -f'
alias kex='kubectl exec -it'
alias kaf='kubectl apply -f'
alias kdf='kubectl delete -f'
alias kctx='kubectl config current-context'
alias kns='kubectl config set-context --current --namespace'
```

---

## Fonctions Utiles

### Navigation et Fichiers

```bash
# ══════════════════════════════════════════════════════════════
# FONCTIONS - NAVIGATION
# ══════════════════════════════════════════════════════════════

# Créer et entrer dans un répertoire
mkcd() {
    mkdir -p "$1" && cd "$1"
}

# Backup d'un fichier avec timestamp
bak() {
    cp "$1" "$1.bak.$(date +%Y%m%d_%H%M%S)"
}

# Extraire n'importe quelle archive
extract() {
    if [ -f "$1" ]; then
        case "$1" in
            *.tar.bz2)   tar xjf "$1"    ;;
            *.tar.gz)    tar xzf "$1"    ;;
            *.tar.xz)    tar xJf "$1"    ;;
            *.bz2)       bunzip2 "$1"    ;;
            *.rar)       unrar x "$1"    ;;
            *.gz)        gunzip "$1"     ;;
            *.tar)       tar xf "$1"     ;;
            *.tbz2)      tar xjf "$1"    ;;
            *.tgz)       tar xzf "$1"    ;;
            *.zip)       unzip "$1"      ;;
            *.Z)         uncompress "$1" ;;
            *.7z)        7z x "$1"       ;;
            *)           echo "'$1' format non supporté" ;;
        esac
    else
        echo "'$1' n'est pas un fichier valide"
    fi
}

# Recherche récursive dans les fichiers
rgrep() {
    grep -rn --color=auto "$1" "${2:-.}"
}

# Trouver les fichiers les plus gros
bigfiles() {
    find "${1:-.}" -type f -exec du -h {} + 2>/dev/null | sort -rh | head -20
}

# Trouver les répertoires les plus gros
bigdirs() {
    du -h --max-depth=1 "${1:-.}" 2>/dev/null | sort -rh | head -20
}
```

### Système et Réseau

```bash
# ══════════════════════════════════════════════════════════════
# FONCTIONS - SYSTEME
# ══════════════════════════════════════════════════════════════

# Informations système rapides
sysinfo() {
    echo "=== SYSTEM ==="
    uname -a
    echo ""
    echo "=== CPU ==="
    lscpu | grep -E "^(Model name|CPU\(s\)|Thread|Core)"
    echo ""
    echo "=== MEMORY ==="
    free -h
    echo ""
    echo "=== DISK ==="
    df -h / /home 2>/dev/null
    echo ""
    echo "=== UPTIME ==="
    uptime
}

# Qui utilise un port ?
port() {
    ss -tulpn | grep ":$1 " || echo "Port $1 non utilisé"
}

# Tester la connectivité
testconn() {
    local host="${1:-8.8.8.8}"
    echo "Testing DNS..."
    dig +short google.com @8.8.8.8 && echo "DNS: OK" || echo "DNS: FAIL"
    echo ""
    echo "Testing connectivity to $host..."
    ping -c 3 "$host"
}

# Suivre un processus
watch_proc() {
    watch -n 1 "ps aux | grep -v grep | grep -i $1"
}

# Historique avec recherche
h() {
    if [ -n "$1" ]; then
        history | grep -i "$1"
    else
        history | tail -30
    fi
}
```

### Docker et Logs

```bash
# ══════════════════════════════════════════════════════════════
# FONCTIONS - DOCKER
# ══════════════════════════════════════════════════════════════

# Shell dans un conteneur
dsh() {
    docker exec -it "$1" bash 2>/dev/null || docker exec -it "$1" sh
}

# Nettoyer Docker complètement
docker_clean() {
    echo "Stopping all containers..."
    docker stop $(docker ps -aq) 2>/dev/null
    echo "Removing all containers..."
    docker rm $(docker ps -aq) 2>/dev/null
    echo "Removing unused images..."
    docker image prune -af
    echo "Removing unused volumes..."
    docker volume prune -f
    echo "Removing unused networks..."
    docker network prune -f
    echo "Done!"
}

# Logs avec timestamp
dlog() {
    docker logs -f --timestamps "$1" 2>&1 | while read line; do
        echo "$(date '+%H:%M:%S') $line"
    done
}
```

### Développement

```bash
# ══════════════════════════════════════════════════════════════
# FONCTIONS - DEV
# ══════════════════════════════════════════════════════════════

# Serveur HTTP rapide
serve() {
    local port="${1:-8000}"
    echo "Serving on http://localhost:$port"
    python3 -m http.server "$port" 2>/dev/null || python -m SimpleHTTPServer "$port"
}

# JSON pretty print
json() {
    if [ -t 0 ]; then
        python3 -m json.tool "$@"
    else
        python3 -m json.tool
    fi
}

# Encoder/Décoder base64
b64e() { echo -n "$1" | base64; }
b64d() { echo -n "$1" | base64 -d; echo; }

# Générer mot de passe
genpass() {
    local len="${1:-20}"
    tr -dc 'A-Za-z0-9!@#$%^&*' </dev/urandom | head -c "$len"
    echo
}

# Générer UUID
genuuid() {
    cat /proc/sys/kernel/random/uuid
}
```

---

## Complétion Avancée

```bash
# ══════════════════════════════════════════════════════════════
# COMPLETION
# ══════════════════════════════════════════════════════════════

# Charger bash-completion si disponible
if [ -f /etc/bash_completion ]; then
    . /etc/bash_completion
elif [ -f /usr/share/bash-completion/bash_completion ]; then
    . /usr/share/bash-completion/bash_completion
fi

# Complétion insensible à la casse
bind 'set completion-ignore-case on'

# Afficher toutes les possibilités d'un coup
bind 'set show-all-if-ambiguous on'

# Couleurs pour la complétion
bind 'set colored-stats on'

# Ajouter / aux répertoires
bind 'set mark-directories on'
bind 'set mark-symlinked-directories on'

# Complétion visible-stats (type indicator)
bind 'set visible-stats on'

# Skip common prefix
bind 'set completion-prefix-display-length 2'
```

---

## Bashrc Complet

??? example "Fichier ~/.bashrc Complet (Cliquer pour déplier)"

    ```bash
    #!/bin/bash
    # ══════════════════════════════════════════════════════════════
    # BASHRC OPTIMISE - SysAdmin/DevOps
    # ══════════════════════════════════════════════════════════════

    # Si non-interactif, ne rien faire
    case $- in
        *i*) ;;
          *) return;;
    esac

    # ══════════════════════════════════════════════════════════════
    # OPTIONS SHELL
    # ══════════════════════════════════════════════════════════════

    # Historique
    HISTSIZE=10000
    HISTFILESIZE=20000
    HISTCONTROL=ignoreboth:erasedups
    HISTTIMEFORMAT="%Y-%m-%d %H:%M:%S  "
    HISTIGNORE="ls:ll:cd:pwd:exit:clear:history"

    shopt -s histappend
    shopt -s cmdhist

    # Navigation
    shopt -s autocd 2>/dev/null
    shopt -s cdspell
    shopt -s dirspell 2>/dev/null
    shopt -s direxpand 2>/dev/null

    # Glob
    shopt -s globstar 2>/dev/null
    shopt -s extglob
    shopt -s nocaseglob

    # Divers
    shopt -s checkwinsize
    shopt -s no_empty_cmd_completion

    # ══════════════════════════════════════════════════════════════
    # ENVIRONNEMENT
    # ══════════════════════════════════════════════════════════════

    export EDITOR=vim
    export VISUAL=vim
    export PAGER=less
    export LESS='-R -F -X -i -M -S'

    # Couleurs man
    export LESS_TERMCAP_mb=$'\e[1;32m'
    export LESS_TERMCAP_md=$'\e[1;34m'
    export LESS_TERMCAP_me=$'\e[0m'
    export LESS_TERMCAP_so=$'\e[1;33m'
    export LESS_TERMCAP_se=$'\e[0m'
    export LESS_TERMCAP_us=$'\e[1;4;36m'
    export LESS_TERMCAP_ue=$'\e[0m'

    export PATH="$HOME/.local/bin:$HOME/bin:$PATH"

    # ══════════════════════════════════════════════════════════════
    # PROMPT
    # ══════════════════════════════════════════════════════════════

    RED='\[\e[0;31m\]'
    GREEN='\[\e[0;32m\]'
    YELLOW='\[\e[0;33m\]'
    BLUE='\[\e[0;34m\]'
    PURPLE='\[\e[0;35m\]'
    CYAN='\[\e[0;36m\]'
    RESET='\[\e[0m\]'

    __git_ps1_custom() {
        local branch=$(git symbolic-ref --short HEAD 2>/dev/null)
        if [ -n "$branch" ]; then
            local status=""
            git diff --quiet 2>/dev/null || status+="*"
            git diff --cached --quiet 2>/dev/null || status+="+"
            [ -n "$(git ls-files --others --exclude-standard 2>/dev/null)" ] && status+="?"
            echo " (${branch}${status})"
        fi
    }

    if [ "$EUID" -eq 0 ]; then
        PS1="${RED}\u${RESET}@${CYAN}\h${RESET}:${BLUE}\w${YELLOW}\$(__git_ps1_custom)${RESET}# "
    else
        PS1="${GREEN}\u${RESET}@${CYAN}\h${RESET}:${BLUE}\w${YELLOW}\$(__git_ps1_custom)${RESET}\$ "
    fi

    # ══════════════════════════════════════════════════════════════
    # ALIAS
    # ══════════════════════════════════════════════════════════════

    # Navigation
    alias ..='cd ..'
    alias ...='cd ../..'
    alias ....='cd ../../..'
    alias -- -='cd -'

    # Listing
    alias ls='ls --color=auto --group-directories-first'
    alias ll='ls -lhF'
    alias la='ls -lhFA'
    alias lt='ls -lhFtr'
    alias lS='ls -lhFS'

    # Sécurité
    alias rm='rm -I --preserve-root'
    alias cp='cp -i'
    alias mv='mv -i'
    alias mkdir='mkdir -pv'

    # Grep coloré
    alias grep='grep --color=auto'
    alias egrep='egrep --color=auto'
    alias fgrep='fgrep --color=auto'

    # Système
    alias df='df -h'
    alias du='du -h'
    alias du1='du -h --max-depth=1 | sort -hr'
    alias free='free -h'
    alias ports='ss -tulanp'

    # Systemd
    alias sc='systemctl'
    alias scs='systemctl status'
    alias scr='systemctl restart'
    alias jcf='journalctl -f'

    # Git
    alias g='git'
    alias gs='git status -sb'
    alias ga='git add'
    alias gc='git commit -m'
    alias gp='git push'
    alias gpl='git pull'
    alias gd='git diff'
    alias gl='git log --oneline -20'

    # Docker
    alias d='docker'
    alias dps='docker ps --format "table {{.ID}}\t{{.Names}}\t{{.Status}}"'
    alias dc='docker compose'

    # Kubernetes
    alias k='kubectl'
    alias kgp='kubectl get pods'
    alias kgpa='kubectl get pods -A'

    # ══════════════════════════════════════════════════════════════
    # FONCTIONS
    # ══════════════════════════════════════════════════════════════

    mkcd() { mkdir -p "$1" && cd "$1"; }
    bak() { cp "$1" "$1.bak.$(date +%Y%m%d_%H%M%S)"; }

    extract() {
        if [ -f "$1" ]; then
            case "$1" in
                *.tar.bz2) tar xjf "$1" ;;
                *.tar.gz)  tar xzf "$1" ;;
                *.tar.xz)  tar xJf "$1" ;;
                *.bz2)     bunzip2 "$1" ;;
                *.gz)      gunzip "$1" ;;
                *.tar)     tar xf "$1" ;;
                *.tbz2)    tar xjf "$1" ;;
                *.tgz)     tar xzf "$1" ;;
                *.zip)     unzip "$1" ;;
                *.7z)      7z x "$1" ;;
                *)         echo "'$1' format non supporté" ;;
            esac
        else
            echo "'$1' n'est pas un fichier valide"
        fi
    }

    port() { ss -tulpn | grep ":$1 " || echo "Port $1 non utilisé"; }
    h() { if [ -n "$1" ]; then history | grep -i "$1"; else history | tail -30; fi; }

    serve() {
        local port="${1:-8000}"
        echo "Serving on http://localhost:$port"
        python3 -m http.server "$port"
    }

    genpass() { tr -dc 'A-Za-z0-9!@#$%^&*' </dev/urandom | head -c "${1:-20}"; echo; }

    # ══════════════════════════════════════════════════════════════
    # COMPLETION
    # ══════════════════════════════════════════════════════════════

    if [ -f /etc/bash_completion ]; then
        . /etc/bash_completion
    elif [ -f /usr/share/bash-completion/bash_completion ]; then
        . /usr/share/bash-completion/bash_completion
    fi

    bind 'set completion-ignore-case on'
    bind 'set show-all-if-ambiguous on'
    bind 'set colored-stats on'

    # ══════════════════════════════════════════════════════════════
    # FICHIERS ADDITIONNELS
    # ══════════════════════════════════════════════════════════════

    # Charger les configurations locales
    [ -f ~/.bashrc.local ] && source ~/.bashrc.local

    # Charger les modules
    for file in ~/.bashrc.d/*.sh; do
        [ -r "$file" ] && source "$file"
    done
    ```

---

## Tips et Bonnes Pratiques

!!! tip "Tester avant d'appliquer"
    ```bash
    # Tester la syntaxe
    bash -n ~/.bashrc

    # Recharger sans fermer le terminal
    source ~/.bashrc
    # ou
    . ~/.bashrc
    ```

!!! warning "Attention aux Alias Dangereux"
    - Évitez `alias rm='rm -rf'` - trop dangereux
    - Préférez `rm -I` à `rm -i` pour les suppressions multiples
    - Ne jamais aliaser `sudo` vers autre chose

!!! info "Portabilité"
    Certaines options `shopt` ne sont pas disponibles sur toutes les versions de Bash.
    Utilisez `2>/dev/null` pour ignorer les erreurs :
    ```bash
    shopt -s autocd 2>/dev/null
    ```

---

## Voir Aussi

- [Productivité Terminal](productivity.md) - Raccourcis et astuces
- [Bash Wizardry](bash-wizardry.md) - Caractères spéciaux et redirections
- [Standards Scripting](scripting-standards.md) - Bonnes pratiques de scripting
