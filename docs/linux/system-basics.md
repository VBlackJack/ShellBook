# Linux System: Boot, Disks & Init

`#boot` `#systemd` `#fhs` `#grub`

Understanding how Linux starts and where things live.

---

## The Boot Process (4 Stages)

```
┌─────────────────────────────────────────────────────────────────────┐
│  POWER ON                                                           │
│      │                                                              │
│      ▼                                                              │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐          │
│  │ 1. BIOS/UEFI │ -> │ 2. GRUB2     │ -> │ 3. KERNEL    │          │
│  │    (POST)    │    │  Bootloader  │    │   (vmlinuz)  │          │
│  └──────────────┘    └──────────────┘    └──────────────┘          │
│                                                 │                   │
│                                                 ▼                   │
│                                          ┌──────────────┐          │
│                                          │ 4. SYSTEMD   │          │
│                                          │   (PID 1)    │          │
│                                          └──────────────┘          │
│                                                 │                   │
│                                                 ▼                   │
│                                          LOGIN PROMPT               │
└─────────────────────────────────────────────────────────────────────┘
```

### Stage 1: BIOS/UEFI

**What happens:**

- Power-On Self-Test (POST)
- Hardware initialization (CPU, RAM, Storage)
- Finds bootable device (disk, USB, network)
- Loads bootloader from MBR/ESP

| BIOS (Legacy) | UEFI (Modern) |
|---------------|---------------|
| MBR partitioning | GPT partitioning |
| 2TB disk limit | 9ZB disk limit |
| 4 primary partitions | 128 partitions |
| No secure boot | Secure Boot support |

---

### Stage 2: Bootloader (GRUB2)

**Location:** `/boot/grub/grub.cfg`

**What happens:**

- Displays boot menu (kernel selection)
- Loads kernel (`vmlinuz-*`)
- Loads Initial RAM Disk (`initrd.img-*` or `initramfs-*`)
- Passes parameters to kernel

```bash
# View GRUB config
cat /boot/grub/grub.cfg

# Edit default options
sudo nano /etc/default/grub

# Regenerate GRUB config
sudo update-grub          # Debian/Ubuntu
sudo grub2-mkconfig -o /boot/grub2/grub.cfg  # RHEL/CentOS
```

**Common GRUB Parameters:**

```bash
# /etc/default/grub
GRUB_TIMEOUT=5
GRUB_CMDLINE_LINUX_DEFAULT="quiet splash"
GRUB_CMDLINE_LINUX="net.ifnames=0"    # Classic eth0 naming
```

---

### Stage 3: Kernel

**What happens:**

- Decompresses itself into memory
- Initializes hardware (drivers from initrd)
- Mounts root filesystem (`/`)
- Starts init process (PID 1)

```bash
# Current kernel version
uname -r

# All installed kernels
ls /boot/vmlinuz-*

# Kernel boot messages
dmesg | head -50
journalctl -k
```

**initrd/initramfs:**

Temporary root filesystem in RAM containing drivers needed to mount the real root.

```bash
# List initramfs contents
lsinitramfs /boot/initrd.img-$(uname -r)

# Rebuild initramfs
sudo update-initramfs -u     # Debian/Ubuntu
sudo dracut --force          # RHEL/CentOS
```

---

### Stage 4: Systemd (PID 1)

**The init system.** Manages all services, mounts, and targets.

```bash
# Verify PID 1
ps -p 1 -o comm=
# Output: systemd
```

**Boot Targets (Runlevels):**

| Target | Old Runlevel | Description |
|--------|--------------|-------------|
| `poweroff.target` | 0 | Shutdown |
| `rescue.target` | 1 | Single user (recovery) |
| `multi-user.target` | 3 | Multi-user, no GUI |
| `graphical.target` | 5 | Multi-user with GUI |
| `reboot.target` | 6 | Reboot |

```bash
# Check default target
systemctl get-default

# Set default target
sudo systemctl set-default multi-user.target

# Change target now (like switching runlevel)
sudo systemctl isolate rescue.target
```

---

## Systemd Management

### Service Control

```bash
# Status (most useful)
systemctl status nginx

# Start/Stop/Restart
sudo systemctl start nginx
sudo systemctl stop nginx
sudo systemctl restart nginx
sudo systemctl reload nginx    # Reload config without restart

# Enable/Disable at boot
sudo systemctl enable nginx
sudo systemctl disable nginx

# Enable AND start
sudo systemctl enable --now nginx

# Check if enabled
systemctl is-enabled nginx
systemctl is-active nginx
```

### Logs (journalctl)

```bash
# Service logs
journalctl -u nginx

# Follow logs (like tail -f)
journalctl -u nginx -f

# Last 100 lines
journalctl -u nginx -n 100

# Since last boot
journalctl -u nginx -b

# Debug crashes (with explanation)
journalctl -xe

# Errors only
journalctl -p err

# Time range
journalctl --since "1 hour ago"
journalctl --since "2024-01-01" --until "2024-01-02"

# Disk usage
journalctl --disk-usage

# Clean old logs
sudo journalctl --vacuum-time=7d
sudo journalctl --vacuum-size=500M
```

### Boot Analysis

```bash
# Total boot time
systemd-analyze

# Blame (slowest services)
systemd-analyze blame

# Critical chain (blocking path)
systemd-analyze critical-chain

# Plot boot timeline (SVG)
systemd-analyze plot > boot.svg
```

### List Services

```bash
# All services
systemctl list-units --type=service

# Failed services
systemctl --failed

# All enabled services
systemctl list-unit-files --type=service --state=enabled
```

---

## Filesystem Hierarchy (FHS)

Where things live in Linux.

```
/
├── bin/      → /usr/bin     # Essential binaries (ls, cp, cat)
├── sbin/     → /usr/sbin    # System binaries (fdisk, mount)
├── lib/      → /usr/lib     # Libraries
├── boot/                    # Kernel, initramfs, GRUB
├── dev/                     # Device files (sda, tty, null)
├── etc/                     # Configuration files
├── home/                    # User home directories
├── opt/                     # Optional/third-party software
├── proc/                    # Virtual FS (process info)
├── root/                    # Root user's home
├── run/                     # Runtime data (PIDs, sockets)
├── srv/                     # Service data (web, ftp)
├── sys/                     # Virtual FS (kernel/hardware)
├── tmp/                     # Temporary files (cleared on boot)
├── usr/                     # User programs (read-only)
│   ├── bin/                 # User binaries
│   ├── lib/                 # Libraries
│   ├── local/               # Locally installed software
│   └── share/               # Architecture-independent data
└── var/                     # Variable data
    ├── log/                 # Log files
    ├── cache/               # Application caches
    ├── lib/                 # Persistent data (databases)
    ├── spool/               # Queues (mail, print)
    └── www/                 # Web server content
```

### Key Directories

| Directory | Purpose | Writable? |
|-----------|---------|-----------|
| `/etc` | Configuration files | Yes (root) |
| `/var` | Variable data (logs, databases) | Yes |
| `/usr` | User binaries, libraries | No (read-only) |
| `/home` | User data | Yes (users) |
| `/tmp` | Temporary (disk) | Yes (everyone) |
| `/run` | Runtime (RAM, tmpfs) | Yes (services) |
| `/opt` | Third-party software | Yes (root) |

### /tmp vs /run

| `/tmp` | `/run` |
|--------|--------|
| On disk (persists until reboot) | In RAM (tmpfs) |
| Any user can write | Mostly for services |
| Cleared on boot | Cleared on boot |
| Large files OK | Size limited by RAM |

---

## Partitioning Concepts

### Block Device Hierarchy

```bash
# List block devices
lsblk

# Output:
NAME   MAJ:MIN RM   SIZE RO TYPE MOUNTPOINT
sda      8:0    0   500G  0 disk
├─sda1   8:1    0   512M  0 part /boot/efi
├─sda2   8:2    0     1G  0 part /boot
└─sda3   8:3    0 498.5G  0 part
  ├─vg0-root  253:0  0   50G  0 lvm  /
  ├─vg0-swap  253:1  0    8G  0 lvm  [SWAP]
  └─vg0-home  253:2  0  440G  0 lvm  /home
```

### Swap Space

Virtual memory for RAM overflow.

**Why swap:**

- Prevents OOM (Out of Memory) crashes
- Hibernation support
- Handles memory spikes

**Sizing guidelines:**

| RAM | Swap (No Hibernate) | Swap (Hibernate) |
|-----|---------------------|------------------|
| ≤2GB | 2x RAM | 3x RAM |
| 2-8GB | = RAM | 2x RAM |
| 8-64GB | 4-8GB | 1.5x RAM |
| >64GB | 4GB minimum | Not recommended |

```bash
# Check swap
free -h
swapon --show

# Create swap file
sudo fallocate -l 4G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile

# Make permanent (add to /etc/fstab)
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab

# Adjust swappiness (0-100, lower = less swap use)
cat /proc/sys/vm/swappiness           # View
sudo sysctl vm.swappiness=10          # Set temporarily
echo 'vm.swappiness=10' | sudo tee -a /etc/sysctl.conf  # Permanent
```

---

### LVM (Logical Volume Manager)

Flexible partitioning—resize without repartitioning.

```
┌─────────────────────────────────────────────────────────┐
│                    PHYSICAL VIEW                         │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐               │
│  │  sda3    │  │  sdb1    │  │  sdc1    │  (PV)         │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘               │
│       └─────────────┼─────────────┘                     │
│                     ▼                                    │
│              ┌──────────────┐                           │
│              │   vg_data    │  (VG - Volume Group)      │
│              └──────┬───────┘                           │
│         ┌───────────┼───────────┐                       │
│         ▼           ▼           ▼                       │
│    ┌─────────┐ ┌─────────┐ ┌─────────┐                  │
│    │ lv_root │ │ lv_home │ │ lv_var  │  (LV)           │
│    │   /     │ │  /home  │ │  /var   │                  │
│    └─────────┘ └─────────┘ └─────────┘                  │
└─────────────────────────────────────────────────────────┘
```

**LVM Commands:**

```bash
# Physical Volumes
sudo pvs                      # List PVs
sudo pvcreate /dev/sdb1       # Create PV

# Volume Groups
sudo vgs                      # List VGs
sudo vgcreate vg_data /dev/sdb1  # Create VG
sudo vgextend vg_data /dev/sdc1  # Add disk to VG

# Logical Volumes
sudo lvs                      # List LVs
sudo lvcreate -L 50G -n lv_data vg_data   # Create 50GB LV
sudo lvextend -L +10G /dev/vg_data/lv_data  # Extend by 10GB
sudo lvextend -l +100%FREE /dev/vg_data/lv_data  # Use all free space

# Resize filesystem after extending LV
sudo resize2fs /dev/vg_data/lv_data       # ext4
sudo xfs_growfs /dev/vg_data/lv_data      # xfs
```

---

### Essential Disk Tools

```bash
# List block devices
lsblk
lsblk -f              # With filesystem info

# Disk usage
df -h                 # Mounted filesystems
df -i                 # Inode usage
du -sh /var/log       # Directory size

# Partition table
sudo fdisk -l /dev/sda
sudo parted -l

# Filesystem check (unmounted only!)
sudo fsck /dev/sda1

# Mount/Unmount
sudo mount /dev/sda1 /mnt
sudo umount /mnt

# UUID (for fstab)
blkid
```

---

## Quick Reference

| Task | Command |
|------|---------|
| Service status | `systemctl status nginx` |
| Start service | `sudo systemctl start nginx` |
| Enable at boot | `sudo systemctl enable nginx` |
| View logs | `journalctl -u nginx -f` |
| Boot time | `systemd-analyze blame` |
| List disks | `lsblk` |
| Disk usage | `df -h` |
| Check swap | `free -h` |
| Kernel version | `uname -r` |
| Boot messages | `dmesg` or `journalctl -k` |
