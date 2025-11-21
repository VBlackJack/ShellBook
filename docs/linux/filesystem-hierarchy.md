# Linux Filesystem Decoded

`#kernel` `#fhs` `#interview`

Understanding the Filesystem Hierarchy Standard (FHS) and the secrets hidden in virtual filesystems.

---

## The Virtual Filesystems (Not on Disk!)

!!! warning "Live Kernel Data"
    `/proc` and `/sys` are **virtual filesystems in RAM**. They don't exist on disk.
    Editing them changes system behavior **immediately** without reboot.

### /proc (Process Information)

`/proc` is a window into the kernel's state and running processes.

```bash
# CPU information
cat /proc/cpuinfo

# Memory stats
cat /proc/meminfo

# Kernel version
cat /proc/version

# Mounted filesystems
cat /proc/mounts
```

#### Per-Process Information (`/proc/[PID]/`)

```bash
# Spy on a process's environment variables
cat /proc/1234/environ | tr '\0' '\n'

# See all open file descriptors
ls -la /proc/1234/fd

# View the actual command line
cat /proc/1234/cmdline | tr '\0' ' '

# Memory map
cat /proc/1234/maps

# Current working directory
ls -la /proc/1234/cwd
```

!!! tip "Security Implication"
    `/proc/[PID]/environ` exposes environment variables.
    **Never pass secrets via ENV** on shared systems—other users may read them.

### /sys (System & Hardware Control)

`/sys` exposes kernel objects and allows real-time hardware control.

```bash
# List block devices
ls /sys/block/

# CPU frequency scaling
cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor
echo "performance" | sudo tee /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor

# Laptop backlight brightness
cat /sys/class/backlight/*/brightness
echo 500 | sudo tee /sys/class/backlight/intel_backlight/brightness

# Network interface state
cat /sys/class/net/eth0/operstate
```

---

## The Binary Confusion (/bin vs /usr/bin)

### Historical Context (1970s)

In early UNIX, disk space was extremely limited:

- **`/bin`** - Essential binaries needed for single-user/rescue mode
- **`/usr/bin`** - Non-essential binaries (could be on separate disk)
- **`/sbin`** - System administration binaries (root only)

### Modern Reality (2012+)

Most distributions have **merged** these directories:

```
/bin       →  /usr/bin      (symlink)
/sbin      →  /usr/sbin     (symlink)
/lib       →  /usr/lib      (symlink)
/lib64     →  /usr/lib64    (symlink)
```

**Verify on your system:**

```bash
ls -la /bin /sbin /lib
# lrwxrwxrwx  1 root root 7 Jan  1 00:00 /bin -> usr/bin
# lrwxrwxrwx  1 root root 8 Jan  1 00:00 /sbin -> usr/sbin
```

!!! info "Why the merge?"
    - Simplifies package management
    - `/usr` is always available at boot (initramfs handles early boot)
    - Eliminates confusion about which directory to use

---

## Special Devices (/dev)

### /dev/null - The Black Hole

Everything written to it disappears. Reads return EOF.

```bash
# Discard stdout
command > /dev/null

# Discard both stdout and stderr
command > /dev/null 2>&1
command &> /dev/null  # Bash shorthand

# Test write speed (no disk I/O)
dd if=/dev/zero of=/dev/null bs=1M count=1000
```

### /dev/zero - Infinite Zeros

```bash
# Create a 1GB file filled with zeros
dd if=/dev/zero of=zeros.bin bs=1M count=1024

# Securely wipe a disk (basic)
dd if=/dev/zero of=/dev/sdX bs=1M status=progress
```

### /dev/random vs /dev/urandom

| Feature | `/dev/random` | `/dev/urandom` |
|---------|---------------|----------------|
| Blocking | **Yes** - blocks when entropy pool is low | **No** - never blocks |
| Speed | Slow (waits for entropy) | Fast (uses CSPRNG) |
| Use case | Key generation (paranoid) | **Everything else** |
| Modern recommendation | Avoid | **Preferred** |

!!! tip "Use /dev/urandom"
    Since Linux 4.8, `/dev/urandom` is cryptographically secure.
    `/dev/random` blocking behavior causes more problems than it solves.

    ```bash
    # Generate random password
    head -c 32 /dev/urandom | base64

    # Generate UUID
    cat /proc/sys/kernel/random/uuid
    ```

---

## The Root Exception

### Why is `/root` not `/home/root`?

**The Rescue Scenario:**

```
Disk Layout:
├── /          (root partition - always mounted)
│   └── /root  (root's home - on root partition)
└── /home      (separate partition - may fail to mount)
    ├── alice
    └── bob
```

**Problem:** If `/home` is on a separate partition/NFS share and fails to mount:

- Regular users cannot login (home directory unavailable)
- **Root must still be able to login** to fix the problem

**Solution:** Root's home (`/root`) lives on the root filesystem, ensuring access even when `/home` fails.

```bash
# Check mount points
df -h /root /home

# Typical output showing separate partitions:
# /dev/sda1  20G  /
# /dev/sda3  100G /home
```

!!! example "Real-World Scenario"
    ```bash
    # /home fails to mount due to disk error
    # User alice cannot login - "No home directory"
    # Root CAN login because /root is on /

    # Root fixes the issue:
    fsck /dev/sda3
    mount /home
    ```
