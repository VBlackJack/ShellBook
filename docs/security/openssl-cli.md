# OpenSSL CLI Cheatsheet

`#openssl` `#cli` `#commands`

Essential OpenSSL commands for daily security operations.

---

## Encoding & Decoding

### Base64

```bash
# Encode string
echo -n "Xavki" | openssl base64
# Output: WGF2a2k=

# Decode
echo "WGF2a2k=" | openssl base64 -d
# Output: Xavki

# Encode file
openssl base64 -in file.bin -out file.b64

# Decode file
openssl base64 -d -in file.b64 -out file.bin
```

### Hex Encoding

```bash
# String to hex
echo -n "Hello" | xxd -p
# Output: 48656c6c6f

# Hex to string
echo "48656c6c6f" | xxd -r -p
# Output: Hello
```

---

## Hashing (Checksums)

```bash
# SHA256 (recommended)
echo -n "data" | openssl dgst -sha256
# Output: SHA2-256(stdin)= 3a6eb0790f39ac87...

# SHA512
echo -n "data" | openssl dgst -sha512

# MD5 (deprecated, but still used for checksums)
echo -n "data" | openssl dgst -md5

# Hash a file
openssl dgst -sha256 file.txt

# Output raw binary (no hex)
openssl dgst -sha256 -binary file.txt > file.sha256

# Verify file integrity
sha256sum -c checksums.txt
```

### Available Algorithms

```bash
# List all digest algorithms
openssl list -digest-algorithms

# Common ones:
# -md5        (128-bit, broken, avoid for security)
# -sha1       (160-bit, deprecated)
# -sha256     (256-bit, recommended)
# -sha384     (384-bit)
# -sha512     (512-bit)
# -sha3-256   (SHA-3 family)
```

---

## Symmetric Encryption (File Encryption)

### Encrypt a File

```bash
# AES-256-CBC with password (interactive prompt)
openssl enc -aes-256-cbc -salt -pbkdf2 -in secret.txt -out secret.enc

# With password on command line (less secure)
openssl enc -aes-256-cbc -salt -pbkdf2 -in secret.txt -out secret.enc -pass pass:MyPassword

# With password from file
openssl enc -aes-256-cbc -salt -pbkdf2 -in secret.txt -out secret.enc -pass file:password.txt
```

### Decrypt a File

```bash
# Decrypt (will prompt for password)
openssl enc -d -aes-256-cbc -pbkdf2 -in secret.enc -out secret.txt

# With password
openssl enc -d -aes-256-cbc -pbkdf2 -in secret.enc -out secret.txt -pass pass:MyPassword
```

### Options Explained

| Option | Purpose |
|--------|---------|
| `-aes-256-cbc` | Algorithm (AES 256-bit, CBC mode) |
| `-salt` | Add random salt (prevents rainbow tables) |
| `-pbkdf2` | Use PBKDF2 key derivation (recommended) |
| `-iter 100000` | Iterations for PBKDF2 (slower = more secure) |
| `-in` | Input file |
| `-out` | Output file |
| `-d` | Decrypt mode |
| `-pass` | Password source |

### List Available Ciphers

```bash
openssl enc -list

# Recommended ciphers:
# -aes-256-cbc     (AES 256-bit, CBC mode)
# -aes-256-gcm     (AES 256-bit, GCM mode - authenticated)
# -chacha20        (ChaCha20 stream cipher)
```

!!! tip "Always Use Salt and PBKDF2"
    ```bash
    # Good
    openssl enc -aes-256-cbc -salt -pbkdf2 -iter 100000 ...

    # Bad (vulnerable)
    openssl enc -aes-256-cbc ...
    ```

---

## Asymmetric Keys (RSA)

### Generate RSA Private Key

```bash
# Generate 4096-bit RSA private key
openssl genrsa -out private.pem 4096

# With passphrase protection
openssl genrsa -aes256 -out private.pem 4096
```

### Extract Public Key

```bash
# Extract public key from private key
openssl rsa -in private.pem -pubout -out public.pem

# View public key
openssl rsa -in private.pem -pubout -text
```

### View Key Details

```bash
# View private key details
openssl rsa -in private.pem -text -noout

# View public key details
openssl rsa -pubin -in public.pem -text -noout
```

!!! info "Foundation of SSH and HTTPS"
    These RSA keys are the same format used by:

    - **SSH:** `~/.ssh/id_rsa` (private) and `~/.ssh/id_rsa.pub` (public)
    - **TLS/HTTPS:** Server private key + certificate

---

## Asymmetric Encryption (RSA)

```bash
# Encrypt file with public key
openssl rsautl -encrypt -pubin -inkey public.pem -in secret.txt -out secret.enc

# Decrypt with private key
openssl rsautl -decrypt -inkey private.pem -in secret.enc -out secret.txt

# Using pkeyutl (newer, recommended)
openssl pkeyutl -encrypt -pubin -inkey public.pem -in secret.txt -out secret.enc
openssl pkeyutl -decrypt -inkey private.pem -in secret.enc -out secret.txt
```

!!! warning "RSA Size Limitation"
    RSA can only encrypt data smaller than the key size minus padding.
    For 4096-bit key: max ~470 bytes.

    **For larger files:** Encrypt with symmetric key, then encrypt the key with RSA.

---

## Digital Signatures

### Sign a File

```bash
# Create signature
openssl dgst -sha256 -sign private.pem -out signature.bin file.txt

# Create signature (base64 encoded)
openssl dgst -sha256 -sign private.pem file.txt | openssl base64 > signature.b64
```

### Verify Signature

```bash
# Verify signature
openssl dgst -sha256 -verify public.pem -signature signature.bin file.txt
# Output: Verified OK

# Verify base64 signature
openssl base64 -d -in signature.b64 -out signature.bin
openssl dgst -sha256 -verify public.pem -signature signature.bin file.txt
```

---

## Random Data Generation

```bash
# Generate 32 random bytes (hex)
openssl rand -hex 32

# Generate 32 random bytes (base64)
openssl rand -base64 32

# Generate random bytes to file
openssl rand -out random.bin 256

# Generate password-safe random string
openssl rand -base64 24 | tr -d '=/+' | cut -c1-16
```

---

## Quick Reference Table

| Task | Command |
|------|---------|
| Base64 encode | `echo -n "text" \| openssl base64` |
| Base64 decode | `echo "dGV4dA==" \| openssl base64 -d` |
| SHA256 hash | `openssl dgst -sha256 file.txt` |
| Encrypt file (symmetric) | `openssl enc -aes-256-cbc -salt -pbkdf2 -in f.txt -out f.enc` |
| Decrypt file | `openssl enc -d -aes-256-cbc -pbkdf2 -in f.enc -out f.txt` |
| Generate RSA key | `openssl genrsa -out private.pem 4096` |
| Extract public key | `openssl rsa -in private.pem -pubout -out public.pem` |
| Sign file | `openssl dgst -sha256 -sign private.pem -out sig.bin file` |
| Verify signature | `openssl dgst -sha256 -verify public.pem -signature sig.bin file` |
| Random bytes | `openssl rand -hex 32` |

---

## Practical Examples

### Secure File Transfer

```bash
# Sender: Encrypt file for recipient
openssl rand -out session.key 32
openssl enc -aes-256-cbc -salt -pbkdf2 -in data.tar.gz -out data.enc -pass file:session.key
openssl pkeyutl -encrypt -pubin -inkey recipient_public.pem -in session.key -out session.key.enc

# Send: data.enc + session.key.enc

# Recipient: Decrypt
openssl pkeyutl -decrypt -inkey my_private.pem -in session.key.enc -out session.key
openssl enc -d -aes-256-cbc -pbkdf2 -in data.enc -out data.tar.gz -pass file:session.key
```

### Quick Password Generator

```bash
# 16-character alphanumeric password
openssl rand -base64 12

# 32-character hex password
openssl rand -hex 16
```
