# Modern Replacements (Legacy vs New)

Stop using deprecated `net-tools`. Switch to `iproute2` and modern alternatives.

---

## Network Commands: net-tools → iproute2

!!! danger "Deprecation Warning"
    `net-tools` (ifconfig, netstat, route) is deprecated and unmaintained since 2001.
    Use `iproute2` for modern kernels and features.

| Legacy (net-tools) | Modern (iproute2) | Purpose |
|--------------------|-------------------|---------|
| `ifconfig` | `ip addr` / `ip a` | Show IP addresses |
| `ifconfig eth0 up` | `ip link set eth0 up` | Enable interface |
| `netstat -tulpn` | `ss -tulpn` | Show listening ports |
| `netstat -an` | `ss -an` | All connections |
| `route -n` | `ip route` / `ip r` | Show routing table |
| `route add` | `ip route add` | Add route |
| `arp -a` | `ip neigh` | ARP table |
| `hostname -I` | `ip -br addr` | Brief IP summary |

### Quick Examples

```bash
# Show all IPs (brief format)
ip -br addr

# Show only IPv4
ip -4 addr

# Show listening TCP/UDP with process names
ss -tulpn

# Show established connections
ss -t state established
```

---

## Process Monitoring: top → htop/btop

| Tool | Install | Features |
|------|---------|----------|
| `top` | Built-in | Basic, no mouse support |
| `htop` | `apt install htop` | Colors, mouse, tree view, kill processes |
| `btop` | `apt install btop` | Modern UI, graphs, themes |

```bash
# Install modern alternatives
sudo apt install htop btop    # Debian/Ubuntu
sudo dnf install htop btop    # RHEL/Fedora
```

!!! tip "htop Shortcuts"
    - `F5` → Tree view
    - `F6` → Sort by column
    - `F9` → Kill process
    - `t` → Toggle tree
    - `H` → Hide user threads

---

## File Search: find → fd

`fd` is a fast, user-friendly alternative to `find`.

| Task | find | fd |
|------|------|-----|
| Find by name | `find . -name "*.log"` | `fd ".log$"` |
| Case insensitive | `find . -iname "*.LOG"` | `fd -i ".log$"` |
| Find directories | `find . -type d -name config` | `fd -t d config` |
| Exclude dir | `find . -path ./node_modules -prune -o -name "*.js"` | `fd -E node_modules ".js$"` |

```bash
# Install fd
sudo apt install fd-find      # Debian/Ubuntu (binary: fdfind)
sudo dnf install fd-find      # RHEL/Fedora

# Create alias if needed
alias fd='fdfind'
```

---

## Text Search: grep → ripgrep

`ripgrep` (`rg`) is significantly faster than `grep` for large codebases.

```bash
# Install
sudo apt install ripgrep

# Usage
rg "pattern"                  # Recursive by default
rg -i "error"                 # Case insensitive
rg -t py "import"             # Only Python files
rg --hidden "secret"          # Include hidden files
```
