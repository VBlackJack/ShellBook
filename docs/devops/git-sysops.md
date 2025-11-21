# Git for SysAdmins

`#git` `#ops` `#versioning`

Why every SysAdmin needs Git, even if you never write "real" code.

---

## Why Git? The 5 Pillars

### 1. Backup

!!! danger "The Old Way"
    ```
    script.sh
    script_backup.sh
    script_final.sh
    script_final_v2.sh
    script_final_v2_WORKING.sh
    script_final_v2_WORKING_monday.sh
    ```

**With Git:**

```bash
git init
git add script.sh
git commit -m "Initial version"

# Make changes...
git commit -am "Add error handling"

# Made a mistake? Go back
git log --oneline
git checkout abc123 -- script.sh
```

No more lost scripts on crashed disks. Push to remote = instant backup.

---

### 2. Sharing

**Without Git:**

- Email attachments with different versions
- USB drives passed around
- "Can you send me the latest?"
- "Which version is production?"

**With Git:**

```bash
# Clone the repo, get everything
git clone git@github.com:team/scripts.git

# Everyone has the same version
# Everyone knows what's current
```

---

### 3. Collaboration

Multiple people can work on the same files without overwriting each other.

```bash
# Alice works on feature A
git checkout -b feature-a
# ... makes changes ...
git commit -am "Add monitoring script"
git push origin feature-a

# Bob works on feature B (same time)
git checkout -b feature-b
# ... makes changes ...
git commit -am "Add backup script"
git push origin feature-b

# Both merge to main without conflicts
git checkout main
git merge feature-a
git merge feature-b
```

---

### 4. Documentation

**Commit messages = "Why I did this"**

```bash
git log --oneline

# Good commits tell a story:
# a1b2c3d fix: nginx config for TLS 1.3 (CVE-2024-1234)
# d4e5f6g feat: add automated backup script
# g7h8i9j refactor: split monolithic script into modules
# j1k2l3m docs: add runbook for incident response
```

**Blame = "Who did this and when?"**

```bash
# Find who changed line 42 and why
git blame nginx.conf

# Output:
# a1b2c3d (Alice 2024-01-15) ssl_protocols TLSv1.2 TLSv1.3;
```

---

### 5. CI/CD Gateway

Git is the trigger for modern automation.

```
Push to Git → CI/CD Pipeline → Automated Deployment

Examples:
- Push Ansible playbook → Auto-run on servers
- Push Terraform → Auto-apply infrastructure
- Push config change → Auto-deploy to production
```

---

## The SysAdmin Use Cases

### Versioning /etc/ Configs

```bash
# Initialize git in /etc (careful!)
cd /etc
sudo git init
sudo git add nginx/ ssh/
sudo git commit -m "Initial config snapshot"

# After changes
sudo git diff
sudo git commit -am "Harden SSH config"

# Oops, broke something?
sudo git checkout HEAD~1 -- ssh/sshd_config
sudo systemctl restart sshd
```

!!! tip "Use etckeeper"
    `etckeeper` automates Git tracking of `/etc/`:

    ```bash
    sudo apt install etckeeper
    sudo etckeeper init
    # Now /etc/ is auto-committed on package changes
    ```

---

### Managing Ansible Playbooks

```
ansible-repo/
├── inventory/
│   ├── production
│   └── staging
├── playbooks/
│   ├── webservers.yml
│   └── databases.yml
├── roles/
│   ├── nginx/
│   └── postgresql/
└── .gitignore
```

```bash
# .gitignore for Ansible
*.retry
*.pyc
.vault_pass
inventory/secrets.yml
```

---

### Terraform State (Carefully!)

```bash
# .gitignore for Terraform
*.tfstate
*.tfstate.*
.terraform/
*.tfvars      # May contain secrets!

# DO commit
*.tf
terraform.lock.hcl
```

!!! warning "State Files"
    **Never commit tfstate to Git!**

    Use remote backends instead:

    - S3 + DynamoDB (AWS)
    - Azure Blob Storage
    - Terraform Cloud

---

### Script Library

```
scripts/
├── backup/
│   ├── mysql_backup.sh
│   └── files_backup.sh
├── monitoring/
│   ├── check_disk.sh
│   └── check_services.sh
├── maintenance/
│   ├── cleanup_logs.sh
│   └── rotate_certs.sh
└── README.md
```

---

## Essential Git Commands for SysOps

```bash
# Setup
git config --global user.name "Your Name"
git config --global user.email "you@example.com"

# Daily workflow
git status              # What changed?
git diff               # Show changes
git add .              # Stage all
git commit -m "msg"    # Commit
git push               # Upload

# Viewing history
git log --oneline      # Compact history
git log -p             # With diffs
git blame file         # Who changed what

# Undoing mistakes
git checkout -- file   # Discard local changes
git reset HEAD~1       # Undo last commit (keep changes)
git revert abc123      # Create undo commit

# Branching
git branch feature     # Create branch
git checkout feature   # Switch to branch
git checkout -b feature # Create + switch
git merge feature      # Merge into current

# Remote
git clone URL          # Download repo
git pull               # Get latest
git push               # Upload changes
git remote -v          # Show remotes
```

---

## Quick Reference

| Command | Purpose |
|---------|---------|
| `git init` | Initialize new repo |
| `git clone <url>` | Copy remote repo |
| `git status` | Show current state |
| `git add .` | Stage all changes |
| `git commit -m "msg"` | Save snapshot |
| `git push` | Upload to remote |
| `git pull` | Download from remote |
| `git log --oneline` | View history |
| `git diff` | Show unstaged changes |
| `git checkout -- <file>` | Discard changes |
| `git branch <name>` | Create branch |
| `git merge <branch>` | Merge branch |
| `git blame <file>` | Show line history |

---

!!! success "Start Today"
    You don't need to be a developer to benefit from Git.

    1. Pick one directory (scripts, configs)
    2. `git init`
    3. Make it a habit: change → commit → push
    4. Thank yourself in 6 months
