# Windows Productivity & PowerToys

`#windows` `#wsl` `#powertoys` `#workflow`

Transform Windows into a power-user workstation.

---

## WSL (Windows Subsystem for Linux)

**Concept:** The best of both worlds—native Linux terminal (Bash, ssh, grep, awk) without a VM.

### Installation

```powershell
# Install WSL with Ubuntu (default)
wsl --install

# Or choose a specific distro
wsl --install -d Debian
wsl --install -d kali-linux

# List available distros
wsl --list --online
```

### Essential Commands

```powershell
# Start default distro
wsl

# Start specific distro
wsl -d Ubuntu

# Shutdown all WSL instances
wsl --shutdown

# Check WSL version
wsl --version

# Set default distro
wsl --set-default Ubuntu
```

### Access Files Between Systems

```bash
# From WSL: Access Windows files
cd /mnt/c/Users/YourName/Documents

# From Windows: Access Linux files
# Navigate to: \\wsl$\Ubuntu\home\username
```

!!! tip "Windows Terminal"
    Use **Windows Terminal** (from Microsoft Store) to manage PowerShell, CMD, and WSL tabs side-by-side.

    - ++ctrl+shift+1++ → PowerShell
    - ++ctrl+shift+2++ → WSL/Ubuntu
    - Split panes: ++alt+shift+d++

---

## Microsoft PowerToys (Must Have)

Open-source system utilities that should be built into Windows.

### Installation

```powershell
# Via winget
winget install Microsoft.PowerToys

# Or download from GitHub releases
# https://github.com/microsoft/PowerToys
```

### FancyZones (Window Management)

Custom window layouts for multi-monitor productivity.

| Action | How |
|--------|-----|
| Open layout editor | ++win+shift+grave++ |
| Snap window to zone | ++shift++ + Drag window |
| Quick switch layout | ++win+ctrl+alt+number++ |

**Setup:**

1. Open PowerToys Settings → FancyZones
2. Launch Layout Editor
3. Create custom zones (e.g., 70/30 split, grid)
4. Hold ++shift++ while dragging windows to snap

### PowerToys Run (Launcher)

**Shortcut:** ++alt+space++

| Prefix | Function | Example |
|--------|----------|---------|
| (none) | App search | `code` → VS Code |
| `=` | Calculator | `= 15% of 200` |
| `?` | Web search | `? docker tutorial` |
| `>` | Shell command | `> ipconfig` |
| `//` | Unit converter | `// 100 USD to EUR` |
| `{` | Registry search | `{ HKLM` |

### Text Extractor (OCR)

**Shortcut:** ++win+shift+t++

Extract text from anywhere on screen—images, videos, locked PDFs.

1. Press ++win+shift+t++
2. Draw rectangle around text
3. Text is copied to clipboard

!!! example "Use Cases"
    - Copy error messages from dialog boxes
    - Extract text from screenshots
    - Grab code from video tutorials

### Keyboard Manager (Remap Keys)

Remap any key or create shortcuts.

**Popular remaps:**

| Original | Remap To | Why |
|----------|----------|-----|
| CapsLock | Escape | Vim users |
| CapsLock | Ctrl | Emacs users |
| Insert | Delete | Stop accidental overwrite |
| Right Alt | Win | Laptop convenience |

### Other Useful Tools

| Tool | Function |
|------|----------|
| **Color Picker** | ++win+shift+c++ → Get hex/RGB from anywhere |
| **Image Resizer** | Right-click images → Resize |
| **File Locksmith** | Right-click → See what's locking a file |
| **Hosts File Editor** | GUI for editing hosts file |
| **Paste as Plain Text** | ++win+ctrl+alt+v++ → Strip formatting |

---

## Native Shortcuts Cheatsheet

| Shortcut | Action |
|----------|--------|
| ++win+v++ | Clipboard History (enable first!) |
| ++win+period++ | Emoji & Symbol panel |
| ++win+shift+s++ | Snipping Tool (Screenshot) |
| ++ctrl+win+left++ / ++right++ | Switch Virtual Desktops |
| ++win+tab++ | Task View (all windows + desktops) |
| ++win+d++ | Show Desktop |
| ++win+l++ | Lock workstation |
| ++win+e++ | File Explorer |
| ++win+i++ | Settings |
| ++win+x++ | Power User menu |
| ++win+number++ | Open/switch to taskbar app |
| ++alt+tab++ | Switch windows |
| ++win+ctrl+d++ | Create new Virtual Desktop |
| ++win+ctrl+f4++ | Close current Virtual Desktop |

### Enable Clipboard History

```
Settings → System → Clipboard → Clipboard history → ON
```

!!! tip "Sync across devices"
    Enable "Sync across devices" to share clipboard between your Windows machines.

---

## The "God Mode" Easter Egg

Access **every** Control Panel setting in a single folder.

### How to Enable

1. Create a new folder anywhere (Desktop recommended)
2. Rename it to exactly:

```
GodMode.{ED7BA470-8E54-465E-825C-99712043E01C}
```

3. The folder icon changes and contains 200+ settings shortcuts

### What's Inside

- All Control Panel items in one searchable list
- Administrative Tools
- Device Manager shortcuts
- Network settings
- User account controls
- And much more...

!!! info "Other Hidden Folders"
    ```
    # Default Programs
    Default.{17cd9488-1228-4b2f-88ce-4298e93e0966}

    # Network Connections
    Network.{992CFFA0-F557-101A-88EC-00DD010CCC48}

    # Printers
    Printers.{2227A280-3AEA-1069-A2DE-08002B30309D}
    ```

---

## Security Tip

!!! danger "Critical: Always Show File Extensions"
    **Why?** To detect double-extension malware.

    Attackers use names like:

    - `invoice.pdf.exe` (appears as `invoice.pdf`)
    - `photo.jpg.scr` (appears as `photo.jpg`)
    - `document.docx.vbs` (appears as `document.docx`)

    **Enable in File Explorer:**

    1. Open File Explorer
    2. View → Show → File name extensions ✓

    **Or via PowerShell:**

    ```powershell
    # Show file extensions
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 0

    # Restart Explorer to apply
    Stop-Process -Name explorer -Force
    ```

!!! warning "Also enable: Show hidden files"
    ```powershell
    # Show hidden files
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Value 1
    ```

---

## Quick PowerShell Productivity

```powershell
# System info
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"

# List installed programs
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
    Select DisplayName, DisplayVersion | Sort DisplayName

# Find large files
Get-ChildItem -Path C:\ -Recurse -ErrorAction SilentlyContinue |
    Where-Object {$_.Length -gt 100MB} |
    Sort-Object Length -Descending |
    Select-Object FullName, @{N='Size(MB)';E={[math]::Round($_.Length/1MB,2)}}

# Flush DNS
ipconfig /flushdns

# Network connections
Get-NetTCPConnection | Where-Object State -eq 'Established'
```
