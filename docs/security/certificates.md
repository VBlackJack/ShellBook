# OpenSSL & Certificate Lifecycle Management

`#openssl` `#pki` `#anssi` `#secnumcloud`

A comprehensive reference for managing X.509 certificates in SecNumCloud environments.

---

## Certificate Lifecycle Overview

```mermaid
flowchart LR
    A[🔑 Private Key] --> B[📄 CSR]
    B --> C[🏛️ CA]
    C --> D[✅ Public Certificate]
    D --> E[📦 Deployment]
    E --> F[🔄 Renewal]
    F --> B
```

---

!!! danger "Critical Security"
    The **Private Key** must **NEVER** leave the secure server where it was generated.
    Never transmit private keys via email, chat, or unencrypted channels.
    Store keys with restrictive permissions: `chmod 600`.

!!! info "ANSSI Standards"
    According to ANSSI recommendations for SecNumCloud:

    - **RSA**: Minimum **3072 bits** (4096 recommended)
    - **ECDSA**: Minimum **P-256** curve (P-384 recommended)
    - **Hash**: SHA-256 minimum (SHA-384/512 for long-term)
    - **Validity**: Maximum 1 year for public-facing certificates

---

## Generating a Private Key

=== "Bash (Linux)"

    ```bash
    # RSA 4096 bits
    openssl genrsa -aes256 -out private.key 4096

    # ECDSA P-384 (recommended)
    openssl ecparam -genkey -name secp384r1 | openssl ec -aes256 -out private-ec.key
    ```

=== "PowerShell (Windows)"

    ```powershell
    # Using OpenSSL on Windows
    openssl genrsa -aes256 -out private.key 4096

    # Using native certreq (generate with INF file)
    certreq -new request.inf private.key
    ```

---

## Generating a CSR (Certificate Signing Request)

=== "Bash (Linux)"

    ```bash
    openssl req -new -key private.key -out request.csr \
        -subj "/C=FR/ST=IDF/L=Paris/O=MyCompany/OU=IT/CN=server.example.com"
    ```

=== "PowerShell (Windows)"

    ```powershell
    # Using OpenSSL
    openssl req -new -key private.key -out request.csr `
        -subj "/C=FR/ST=IDF/L=Paris/O=MyCompany/OU=IT/CN=server.example.com"

    # Using certreq with INF template
    certreq -new csr_template.inf request.csr
    ```

??? note "CSR Template for Windows (csr_template.inf)"
    ```ini
    [Version]
    Signature="$Windows NT$"

    [NewRequest]
    Subject = "CN=server.example.com,O=MyCompany,L=Paris,C=FR"
    KeySpec = 1
    KeyLength = 4096
    HashAlgorithm = SHA256
    MachineKeySet = TRUE
    Exportable = FALSE
    ```

---

## OpenSSL Cheatsheet

| Task | Command |
|------|---------|
| Check certificate expiration | `openssl x509 -enddate -noout -in cert.pem` |
| View certificate details | `openssl x509 -text -noout -in cert.pem` |
| Check CSR content | `openssl req -text -noout -in request.csr` |
| Verify key matches certificate | `openssl x509 -modulus -noout -in cert.pem \| md5sum` |
| Convert PEM to PFX/PKCS12 | `openssl pkcs12 -export -out cert.pfx -inkey key.pem -in cert.pem` |
| Convert PFX to PEM | `openssl pkcs12 -in cert.pfx -out cert.pem -nodes` |
| Check remote certificate | `openssl s_client -connect host:443 -servername host` |
| Verify certificate chain | `openssl verify -CAfile ca-bundle.crt cert.pem` |

---

## Quick Verification Script

=== "Bash (Linux)"

    ```bash
    #!/bin/bash
    # Check certificate expiration
    CERT="$1"
    EXPIRY=$(openssl x509 -enddate -noout -in "$CERT" | cut -d= -f2)
    EXPIRY_EPOCH=$(date -d "$EXPIRY" +%s)
    NOW_EPOCH=$(date +%s)
    DAYS_LEFT=$(( (EXPIRY_EPOCH - NOW_EPOCH) / 86400 ))

    echo "Certificate expires in $DAYS_LEFT days"
    [[ $DAYS_LEFT -lt 30 ]] && echo "⚠️  WARNING: Renewal required soon!"
    ```

=== "PowerShell (Windows)"

    ```powershell
    # Check certificate expiration
    param([string]$CertPath)
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CertPath)
    $daysLeft = ($cert.NotAfter - (Get-Date)).Days

    Write-Host "Certificate expires in $daysLeft days"
    if ($daysLeft -lt 30) { Write-Warning "Renewal required soon!" }
    ```
