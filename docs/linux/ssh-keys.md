---
tags:
  - ssh
  - security
  - keys
  - encryption
---

# Clés SSH Sécurisées

## Générer une Paire de Clés SSH Sécurisée

!!! info "Recommandation ANSSI"
    Selon les directives ANSSI, les clés RSA doivent faire **minimum 3072 bits** pour des opérations sécurisées.
    Ed25519 est préféré lorsque supporté.

### RSA 4096 bits

=== "Bash (Linux/macOS)"

    ```bash
    ssh-keygen -t rsa -b 4096 -C "user@domain.com" -f ~/.ssh/id_rsa_secure
    ```

=== "PowerShell (Windows)"

    ```powershell
    ssh-keygen -t rsa -b 4096 -C "user@domain.com" -f "$env:USERPROFILE\.ssh\id_rsa_secure"
    ```

### Ed25519 (Recommandé)

=== "Bash (Linux/macOS)"

    ```bash
    ssh-keygen -t ed25519 -C "user@domain.com" -f ~/.ssh/id_ed25519
    ```

=== "PowerShell (Windows)"

    ```powershell
    ssh-keygen -t ed25519 -C "user@domain.com" -f "$env:USERPROFILE\.ssh\id_ed25519"
    ```

---

!!! warning "Sécurité"
    Toujours définir une phrase de passe forte lors de la génération de clés SSH.
