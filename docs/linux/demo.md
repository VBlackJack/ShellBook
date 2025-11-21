# Secure SSH Keys

## Generate a Secure SSH Key Pair

!!! info "ANSSI Recommendation"
    According to ANSSI guidelines, RSA keys must be **minimum 3072 bits** for secure operations.
    Ed25519 is preferred when supported.

### RSA 4096 bits

=== "Bash (Linux/macOS)"

    ```bash
    ssh-keygen -t rsa -b 4096 -C "user@domain.com" -f ~/.ssh/id_rsa_secure
    ```

=== "PowerShell (Windows)"

    ```powershell
    ssh-keygen -t rsa -b 4096 -C "user@domain.com" -f "$env:USERPROFILE\.ssh\id_rsa_secure"
    ```

### Ed25519 (Recommended)

=== "Bash (Linux/macOS)"

    ```bash
    ssh-keygen -t ed25519 -C "user@domain.com" -f ~/.ssh/id_ed25519
    ```

=== "PowerShell (Windows)"

    ```powershell
    ssh-keygen -t ed25519 -C "user@domain.com" -f "$env:USERPROFILE\.ssh\id_ed25519"
    ```

---

!!! warning "Security"
    Always set a strong passphrase when generating SSH keys.
