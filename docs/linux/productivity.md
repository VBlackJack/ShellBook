# Terminal Productivity & Tricks

Master these shortcuts to navigate and work faster in any Linux environment.

---

## Navigation Shortcuts

### Toggle Previous Directory

```bash
cd /var/log
cd /etc/nginx
cd -          # Returns to /var/log
cd -          # Returns to /etc/nginx
```

### Stack Navigation (pushd/popd)

```bash
pushd /var/log      # Push current dir to stack, cd to /var/log
pushd /etc/nginx    # Push /var/log to stack, cd to /etc/nginx
pushd /home/user    # Push /etc/nginx to stack

dirs -v             # View stack with indexes
popd                # Return to /etc/nginx
popd                # Return to /var/log
```

| Command | Description |
|---------|-------------|
| `pushd <dir>` | Save current location and jump to `<dir>` |
| `popd` | Return to last saved location |
| `dirs -v` | Show directory stack |
| `cd ~2` | Jump to stack position 2 (zsh) |

---

## History Manipulation

| Shortcut | Description |
|----------|-------------|
| ++ctrl+r++ | Reverse search through history |
| `!!` | Repeat last command |
| `sudo !!` | Run last command with sudo |
| `!$` | Last argument of previous command |
| `!*` | All arguments of previous command |
| `!ssh` | Run last command starting with `ssh` |
| `!42` | Run command #42 from history |

### Reverse Search (CTRL+R)

```
(reverse-i-search)`nginx': systemctl restart nginx
```

- ++ctrl+r++ again → cycle through matches
- ++enter++ → execute
- ++ctrl+g++ → cancel

---

## Safety Aliases

=== "Bash (~/.bashrc)"

    ```bash
    # Safety nets - always ask before destructive actions
    alias rm='rm -i'
    alias cp='cp -i'
    alias mv='mv -i'

    # Verbose operations
    alias mkdir='mkdir -pv'
    alias chmod='chmod -v'
    alias chown='chown -v'

    # Colorized output
    alias ls='ls --color=auto'
    alias ll='ls -lahF'
    alias grep='grep --color=auto'

    # Quick navigation
    alias ..='cd ..'
    alias ...='cd ../..'
    alias ....='cd ../../..'
    ```

=== "Zsh (~/.zshrc)"

    ```zsh
    # Safety nets
    alias rm='rm -i'
    alias cp='cp -i'
    alias mv='mv -i'

    # Verbose operations
    alias mkdir='mkdir -pv'

    # Colorized output
    alias ls='ls --color=auto'
    alias ll='ls -lahF'
    alias grep='grep --color=auto'

    # Zsh extras
    alias reload='source ~/.zshrc'
    alias path='echo $PATH | tr ":" "\n"'
    ```

!!! tip "Pro Tip: Custom Config File"
    Keep your aliases in a separate `~/.bashrc_custom` file:

    ```bash
    # In ~/.bashrc, add at the end:
    [ -f ~/.bashrc_custom ] && source ~/.bashrc_custom
    ```

    This keeps your customizations portable and separated from system defaults.

!!! warning "Bypass Alias"
    To run the original command without alias: `\rm file` or `command rm file`
