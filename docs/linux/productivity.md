# Linux Terminal Productivity

Essential shortcuts and aliases to save time daily.

---

## Navigation & History

| Shortcut | Description |
|----------|-------------|
| `cd -` | Return to previous directory |
| `cd ~` | Go to home directory |
| `!!` | Re-run last command |
| `sudo !!` | Re-run last command with sudo (lifesaver!) |
| `!$` | Last argument of previous command |
| `!^` | First argument of previous command |
| `!*` | All arguments of previous command |
| `!n` | Run command number `n` from history |
| `!string` | Run last command starting with `string` |

### Reverse Search (CTRL+R)

Press ++ctrl+r++ and start typing to search through command history.

```
(reverse-i-search)`ssh': ssh user@server.example.com
```

- Press ++ctrl+r++ again to cycle through matches
- Press ++enter++ to execute
- Press ++ctrl+g++ to cancel

---

## Useful Aliases

=== "Bash (~/.bashrc)"

    ```bash
    # Navigation
    alias ll='ls -lahF --color=auto'
    alias la='ls -A'
    alias ..='cd ..'
    alias ...='cd ../..'

    # Safety nets
    alias rm='rm -i'
    alias cp='cp -i'
    alias mv='mv -i'

    # Colorized output
    alias grep='grep --color=auto'
    alias diff='diff --color=auto'

    # Create parent directories
    alias mkdir='mkdir -pv'

    # Quick clear
    alias c='clear'
    alias h='history'
    ```

=== "Zsh (~/.zshrc)"

    ```zsh
    # Navigation
    alias ll='ls -lahF --color=auto'
    alias la='ls -A'
    alias ..='cd ..'
    alias ...='cd ../..'
    alias ....='cd ../../..'

    # Safety nets
    alias rm='rm -i'
    alias cp='cp -i'
    alias mv='mv -i'

    # Colorized output
    alias grep='grep --color=auto'
    alias diff='diff --color=auto'

    # Create parent directories
    alias mkdir='mkdir -pv'

    # Zsh specific
    alias reload='source ~/.zshrc'
    ```

!!! note "Apply Changes"
    After editing, reload your shell config:
    ```bash
    source ~/.bashrc  # or ~/.zshrc
    ```

---

## Real-World Scenarios

!!! tip "Safety First"
    **Always add interactive flags** to destructive commands in your aliases:

    ```bash
    alias rm='rm -i'   # Prompt before every removal
    alias cp='cp -i'   # Prompt before overwrite
    alias mv='mv -i'   # Prompt before overwrite
    ```

    This simple habit has saved countless files from accidental deletion.

    To bypass temporarily: `\rm filename` (backslash ignores alias).

!!! example "Quick Server Check"
    Create a system overview alias:
    ```bash
    alias sysinfo='echo "=== DISK ===" && df -h && echo "=== MEM ===" && free -h && echo "=== LOAD ===" && uptime'
    ```

!!! warning "Production Servers"
    On critical servers, consider adding this to root's `.bashrc`:
    ```bash
    alias rm='rm -I --preserve-root'
    ```
    The `-I` flag prompts once before removing more than 3 files.
