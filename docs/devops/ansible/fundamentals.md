# Ansible Fundamentals

`#ansible` `#iac` `#python` `#ssh`

Infrastructure as Code with zero agents.

---

## Core Concepts (The "Why")

### Agentless Architecture

**No software to install on targets.** Ansible uses SSH (Linux) or WinRM (Windows).

```
┌─────────────────┐         SSH          ┌─────────────────┐
│  Control Node   │ ──────────────────►  │  Managed Node   │
│  (Ansible)      │                      │  (Just SSH)     │
└─────────────────┘                      └─────────────────┘
```

| Ansible | Chef/Puppet |
|---------|-------------|
| Agentless (SSH) | Requires agent |
| Push model | Pull model |
| Python on control | Ruby ecosystem |
| Simple YAML | DSL to learn |

---

### Push vs Pull

**Push (Ansible):** You decide when to apply changes.

```bash
# You run this when ready
ansible-playbook deploy.yml
```

**Pull (Puppet/Chef):** Agents poll for changes periodically.

```
Agent checks every 30min → applies drift
```

!!! tip "Push = Control"
    Push model gives you explicit control over **when** changes happen.
    No surprise updates at 3 AM.

---

### Idempotence (Critical Concept)

!!! important "Running twice = same result"
    An idempotent task only makes changes if needed.

    ```yaml
    # First run: installs nginx
    # Second run: "ok" (already installed, no change)
    - name: Install nginx
      apt:
        name: nginx
        state: present
    ```

**Why it matters:**

- Safe to re-run playbooks
- Self-healing (drift correction)
- No "oops I ran it twice" disasters

**Non-idempotent (dangerous):**

```yaml
# BAD: Appends every time you run!
- name: Add line to file
  shell: echo "config=value" >> /etc/app.conf

# GOOD: Only adds if not present
- name: Add line to file
  lineinfile:
    path: /etc/app.conf
    line: "config=value"
```

---

## Installation & Setup

### Install Ansible

```bash
# Recommended: pip (latest version)
pip install ansible

# Or with pipx (isolated)
pipx install ansible

# Verify
ansible --version
```

!!! warning "Avoid apt/yum for Ansible"
    Distribution packages are often outdated.
    Use `pip` for the latest features and modules.

---

### Inventory File (`hosts`)

List your managed servers. Supports INI or YAML format.

**INI Format (simple):**

```ini
# inventory/hosts

[webservers]
web1.example.com
web2.example.com
192.168.1.10

[databases]
db1.example.com ansible_user=postgres
db2.example.com

[production:children]
webservers
databases

[all:vars]
ansible_user=deploy
ansible_python_interpreter=/usr/bin/python3
```

**YAML Format:**

```yaml
# inventory/hosts.yml
all:
  children:
    webservers:
      hosts:
        web1.example.com:
        web2.example.com:
    databases:
      hosts:
        db1.example.com:
          ansible_user: postgres
        db2.example.com:
  vars:
    ansible_user: deploy
```

---

### Configuration (`ansible.cfg`)

Place in project root or `~/.ansible.cfg`.

```ini
# ansible.cfg
[defaults]
inventory = ./inventory/hosts
remote_user = deploy
private_key_file = ~/.ssh/id_ed25519
host_key_checking = False
retry_files_enabled = False
gathering = smart
fact_caching = jsonfile
fact_caching_connection = /tmp/ansible_facts

[privilege_escalation]
become = True
become_method = sudo
become_user = root
become_ask_pass = False

[ssh_connection]
pipelining = True
control_path = /tmp/ansible-%%h-%%r
```

| Setting | Purpose |
|---------|---------|
| `host_key_checking = False` | Skip SSH "Are you sure?" prompts |
| `pipelining = True` | Faster execution (fewer SSH connections) |
| `gathering = smart` | Cache facts, don't gather every time |

!!! warning "host_key_checking"
    Disabling is convenient for automation but reduces security.
    In production, use `known_hosts` management instead.

---

## Authentication (SSH)

Ansible uses your SSH keys. No special setup needed.

### Prepare SSH Access

```bash
# Generate key if needed
ssh-keygen -t ed25519 -C "ansible@control"

# Copy to all managed nodes
ssh-copy-id user@web1.example.com
ssh-copy-id user@web2.example.com
ssh-copy-id user@db1.example.com

# Test SSH access
ssh user@web1.example.com "hostname"
```

### Test Ansible Connection

```bash
# The "Hello World" of Ansible
ansible all -m ping -i inventory/hosts

# Output:
# web1.example.com | SUCCESS => {
#     "changed": false,
#     "ping": "pong"
# }
```

!!! tip "Passwordless Sudo"
    For `become` (sudo) to work without prompts:

    ```bash
    # On target servers, add to /etc/sudoers.d/ansible
    deploy ALL=(ALL) NOPASSWD: ALL
    ```

---

## Ad-Hoc Commands (The CLI)

Run one-off commands without writing a playbook.

### Syntax

```bash
ansible <pattern> -m <module> -a "<arguments>" [options]
```

### Essential Examples

```bash
# Ping all hosts
ansible all -m ping

# Run shell command
ansible all -m shell -a "uptime"
ansible webservers -m shell -a "df -h"

# Check memory on databases
ansible databases -m shell -a "free -m"

# Install package (with sudo)
ansible webservers -m apt -a "name=nginx state=present" --become

# Start service
ansible webservers -m service -a "name=nginx state=started enabled=yes" --become

# Copy file
ansible all -m copy -a "src=/local/file.conf dest=/etc/app/file.conf" --become

# Create user
ansible all -m user -a "name=deploy state=present" --become

# Gather facts
ansible web1.example.com -m setup

# Reboot servers (careful!)
ansible webservers -m reboot --become
```

### Targeting Hosts

```bash
# All hosts
ansible all -m ping

# Specific group
ansible webservers -m ping

# Multiple groups
ansible 'webservers:databases' -m ping

# Exclude group
ansible 'all:!databases' -m ping

# Single host
ansible web1.example.com -m ping

# Pattern matching
ansible '*.example.com' -m ping
ansible 'web*' -m ping
```

### Common Options

| Option | Purpose |
|--------|---------|
| `-i <inventory>` | Specify inventory file |
| `-m <module>` | Module to use |
| `-a "<args>"` | Module arguments |
| `--become` / `-b` | Use sudo |
| `--become-user` | Sudo to specific user |
| `-k` | Ask for SSH password |
| `-K` | Ask for sudo password |
| `-v` / `-vvv` | Verbose output |
| `--check` | Dry run (no changes) |
| `--diff` | Show file changes |

---

## Quick Reference

```bash
# Test connectivity
ansible all -m ping

# Run command
ansible all -m shell -a "command"

# Install package
ansible all -m apt -a "name=pkg state=present" -b

# Copy file
ansible all -m copy -a "src=X dest=Y" -b

# Start service
ansible all -m service -a "name=X state=started" -b

# Gather facts
ansible host -m setup

# Dry run
ansible-playbook playbook.yml --check --diff
```

---

## Project Structure (Best Practice)

```
ansible-project/
├── ansible.cfg
├── inventory/
│   ├── production
│   └── staging
├── group_vars/
│   ├── all.yml
│   ├── webservers.yml
│   └── databases.yml
├── host_vars/
│   └── web1.example.com.yml
├── playbooks/
│   ├── site.yml
│   ├── webservers.yml
│   └── databases.yml
└── roles/
    ├── common/
    ├── nginx/
    └── postgresql/
```
