# System Debugging & Logs

Essential commands for troubleshooting Linux systems.

---

## Systemd Logs (journalctl)

### View Service Logs

```bash
# Logs for a specific service
journalctl -u nginx
journalctl -u ssh

# Follow logs in real-time
journalctl -u nginx -f

# Last 100 lines
journalctl -u nginx -n 100
```

### Time-Based Filtering

```bash
# Since 1 hour ago
journalctl --since "1 hour ago"

# Since specific time
journalctl --since "2024-01-15 10:00:00"

# Time range
journalctl --since "2024-01-15" --until "2024-01-16"

# Since last boot
journalctl -b

# Previous boot
journalctl -b -1
```

### Filter by Priority

```bash
# Errors only
journalctl -p err

# Errors and warnings
journalctl -p warning

# Priority levels: emerg, alert, crit, err, warning, notice, info, debug
```

| Option | Description |
|--------|-------------|
| `-u <service>` | Filter by systemd unit |
| `-f` | Follow (like tail -f) |
| `-n <N>` | Show last N lines |
| `-p <level>` | Filter by priority |
| `-b` | Current boot only |
| `--since` | Start time filter |
| `--no-pager` | Output without pagination |

---

## File & Port Inspection (lsof)

### Find Process Using a Port

```bash
# What's using port 80?
lsof -i :80

# What's using port 443? (TCP only)
lsof -i TCP:443

# All network connections
lsof -i

# All listening ports
lsof -i -P -n | grep LISTEN
```

### Find Open Files

```bash
# Files opened by a user
lsof -u root
lsof -u www-data

# Files opened by a process
lsof -p 1234

# Who has this file open?
lsof /var/log/syslog

# Files in a directory
lsof +D /var/log/
```

!!! tip "Alternative: ss + fuser"
    ```bash
    # Find process on port
    ss -tulpn | grep :80

    # Kill process using a file
    fuser -k /var/lock/lockfile
    ```

---

## Kernel Messages (dmesg)

```bash
# Human-readable timestamps
dmesg -T

# Follow kernel messages
dmesg -w

# Filter by level
dmesg --level=err,warn

# Filter by facility
dmesg -f kern

# Clear ring buffer (requires root)
dmesg -c
```

### Common Use Cases

```bash
# USB device issues
dmesg -T | grep -i usb

# Disk errors
dmesg -T | grep -iE "(sda|nvme|error|fail)"

# Memory issues
dmesg -T | grep -iE "(oom|memory|killed)"
```

---

## The Nuclear Option (strace)

!!! danger "Performance Impact"
    `strace` significantly slows down traced processes.
    **Never use on high-load production systems** without understanding the impact.
    Consider `perf` or `eBPF` tools for production debugging.

### Basic Usage

```bash
# Trace a running process
strace -p <PID>

# Trace a command
strace ls -la

# Trace with timestamps
strace -t -p <PID>

# Trace specific syscalls only
strace -e open,read,write -p <PID>

# Summary of syscalls
strace -c ls -la
```

### Practical Examples

```bash
# Why is this process stuck?
strace -p $(pgrep -f "stuck_process")

# What files is this accessing?
strace -e openat -p <PID>

# Network activity
strace -e network -p <PID>

# Save output to file
strace -o /tmp/trace.log -p <PID>
```

!!! tip "Alternatives for Production"
    - `ltrace` - Library call tracing
    - `perf trace` - Lower overhead
    - `bpftrace` - eBPF-based, minimal impact
