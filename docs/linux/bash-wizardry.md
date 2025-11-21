# Bash Special Characters & Redirections

`#bash` `#shell` `#scripting`

Master the magic symbols that make Bash powerful.

---

## The Dollar Signs

### Exit Codes (`$?`)

Every command returns an exit code. Check it immediately after execution.

```bash
ls /existing/path
echo $?    # 0 = Success

ls /nonexistent/path
echo $?    # 2 = Error (No such file)
```

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | General error |
| `2` | Misuse of shell command |
| `126` | Permission denied |
| `127` | Command not found |
| `130` | Interrupted (Ctrl+C) |

```bash
# Use in scripts
if [ $? -eq 0 ]; then
    echo "Command succeeded"
else
    echo "Command failed"
fi

# Or shorter
command && echo "Success" || echo "Failed"
```

### Script Arguments

```bash
#!/bin/bash
# Save as: myscript.sh

echo "Script name: $0"
echo "First arg:   $1"
echo "Second arg:  $2"
echo "All args:    $@"
echo "Arg count:   $#"
```

```bash
./myscript.sh hello world

# Output:
# Script name: ./myscript.sh
# First arg:   hello
# Second arg:  world
# All args:    hello world
# Arg count:   2
```

| Variable | Description |
|----------|-------------|
| `$0` | Script name |
| `$1` - `$9` | Positional arguments |
| `${10}` | 10th+ argument (braces required) |
| `$@` | All arguments (as separate strings) |
| `$*` | All arguments (as single string) |
| `$#` | Number of arguments |
| `$$` | Current process PID |
| `$!` | Last background process PID |

---

## Redirections (The Plumbing)

### Output Redirection

```bash
# Overwrite file (creates if not exists)
echo "Hello" > file.txt

# Append to file
echo "World" >> file.txt

# Redirect STDERR (2)
command 2> errors.log

# Redirect STDOUT and STDERR to same file
command > output.log 2>&1
command &> output.log    # Shorthand (Bash 4+)

# Discard output
command > /dev/null 2>&1
command &> /dev/null     # Shorthand
```

### Input Redirection

```bash
# Read from file
grep "pattern" < file.txt

# Same as (but technically different)
grep "pattern" file.txt
```

### Pipes (`|`)

Output of command A becomes input of command B.

```bash
# Chain commands
cat /var/log/syslog | grep "error" | wc -l

# Common patterns
ps aux | grep nginx
history | tail -20
df -h | grep /dev/sda
cat file.txt | sort | uniq
```

### Heredoc (`<< EOF`)

Multi-line input. **Critical for generating config files in scripts.**

```bash
# Basic heredoc
cat << EOF
This is line 1
This is line 2
Variable: $HOME
EOF

# Write to file
cat << EOF > /etc/myapp/config.conf
server=localhost
port=8080
user=$USER
EOF

# Prevent variable expansion (quote EOF)
cat << 'EOF' > script.sh
echo $HOME    # Literal $HOME, not expanded
EOF
```

!!! tip "Heredoc in Scripts"
    Perfect for:

    - Generating config files
    - Multi-line SQL queries
    - Creating scripts within scripts
    - SSH remote commands

    ```bash
    ssh user@server << 'EOF'
    cd /var/www
    git pull
    systemctl restart app
    EOF
    ```

---

## Control Operators

### AND (`&&`)

Run second command **ONLY if first succeeds** (exit code 0).

```bash
# Only deploy if tests pass
./run_tests.sh && ./deploy.sh

# Create dir and enter it
mkdir myproject && cd myproject

# Update and upgrade
apt update && apt upgrade -y
```

### OR (`||`)

Run second command **ONLY if first fails** (exit code != 0).

```bash
# Fallback behavior
ping -c 1 server1 || ping -c 1 server2

# Default value pattern
grep "config" file.txt || echo "Not found"

# Exit on failure
cd /important/dir || exit 1
```

### Combining AND/OR

```bash
# Success message or error
command && echo "Done!" || echo "Failed!"

# Ensure directory exists
[ -d "$DIR" ] || mkdir -p "$DIR"

# Try primary, fallback to secondary
wget "$URL1" && echo "Downloaded from primary" || wget "$URL2"
```

### Background (`&`)

Run command in background, don't block terminal.

```bash
# Run in background
./long_task.sh &

# Get its PID
echo $!

# Run multiple in parallel
./task1.sh &
./task2.sh &
./task3.sh &
wait    # Wait for all background jobs

# Disown (keeps running after terminal closes)
./server.sh &
disown
```

---

## Quick Reference

| Symbol | Name | Purpose |
|--------|------|---------|
| `$?` | Exit code | Previous command result |
| `$1-$9` | Args | Script parameters |
| `$@` | All args | Argument list |
| `$#` | Arg count | Number of arguments |
| `$$` | PID | Current process ID |
| `>` | Redirect | Overwrite file |
| `>>` | Append | Add to file |
| `2>` | STDERR | Redirect errors |
| `&>` | Both | STDOUT + STDERR |
| `<` | Input | Read from file |
| `<<` | Heredoc | Multi-line input |
| `\|` | Pipe | Chain commands |
| `&&` | AND | If success, then |
| `\|\|` | OR | If failure, then |
| `&` | Background | Don't block |

---

## Practical Examples

```bash
#!/bin/bash
# Backup script with proper error handling

BACKUP_DIR="/backup"
SOURCE="/var/www"
DATE=$(date +%Y%m%d)

# Ensure backup dir exists
[ -d "$BACKUP_DIR" ] || mkdir -p "$BACKUP_DIR"

# Create backup, log errors
tar -czf "$BACKUP_DIR/www_$DATE.tar.gz" "$SOURCE" 2>> /var/log/backup.log \
    && echo "Backup successful" \
    || { echo "Backup failed"; exit 1; }

# Cleanup old backups (keep last 7)
find "$BACKUP_DIR" -name "*.tar.gz" -mtime +7 -delete
```
