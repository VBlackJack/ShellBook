---
title: "OpenSSL Cheatsheet"
description: "Complete OpenSSL guide for certificates, keys, CSR generation, and SSL/TLS debugging"
tags: ["openssl", "ssl", "tls", "certificates", "security", "cheatsheet"]
---

# OpenSSL Cheatsheet

## Key Generation

### RSA Keys

```bash
# Generate private key (2048-bit)
openssl genrsa -out private.key 2048

# Generate private key (4096-bit)
openssl genrsa -out private.key 4096

# Generate encrypted private key
openssl genrsa -aes256 -out private.key 2048

# Remove passphrase from key
openssl rsa -in encrypted.key -out decrypted.key

# Add passphrase to key
openssl rsa -aes256 -in decrypted.key -out encrypted.key

# Generate public key from private key
openssl rsa -in private.key -pubout -out public.key

# View private key details
openssl rsa -in private.key -text -noout

# Check private key
openssl rsa -in private.key -check
```

### ECDSA Keys (Elliptic Curve)

```bash
# List available curves
openssl ecparam -list_curves

# Generate EC private key (P-256)
openssl ecparam -name prime256v1 -genkey -out ec-private.key

# Generate EC private key (P-384)
openssl ecparam -name secp384r1 -genkey -out ec-private.key

# Generate encrypted EC key
openssl ecparam -name prime256v1 -genkey | openssl ec -aes256 -out ec-private.key

# Extract public key
openssl ec -in ec-private.key -pubout -out ec-public.key

# View EC key details
openssl ec -in ec-private.key -text -noout
```

### DSA Keys

```bash
# Generate DSA parameters
openssl dsaparam -out dsaparam.pem 2048

# Generate DSA private key
openssl gendsa -out dsa-private.key dsaparam.pem

# Extract public key
openssl dsa -in dsa-private.key -pubout -out dsa-public.key
```

### Ed25519 Keys (Modern)

```bash
# Generate Ed25519 private key
openssl genpkey -algorithm ED25519 -out ed25519-private.key

# Extract public key
openssl pkey -in ed25519-private.key -pubout -out ed25519-public.key

# View key details
openssl pkey -in ed25519-private.key -text -noout
```

## Certificate Signing Requests (CSR)

### Generate CSR

```bash
# Generate CSR from existing key
openssl req -new -key private.key -out request.csr

# Generate CSR with subject inline
openssl req -new -key private.key -out request.csr \
  -subj "/C=US/ST=California/L=San Francisco/O=Example Inc/CN=example.com"

# Generate key and CSR in one command
openssl req -newkey rsa:2048 -nodes -keyout private.key -out request.csr

# Generate CSR with SANs (Subject Alternative Names)
openssl req -new -key private.key -out request.csr -config <(cat <<EOF
[req]
default_bits = 2048
prompt = no
default_md = sha256
req_extensions = req_ext
distinguished_name = dn

[dn]
C = US
ST = California
L = San Francisco
O = Example Inc
CN = example.com

[req_ext]
subjectAltName = @alt_names

[alt_names]
DNS.1 = example.com
DNS.2 = www.example.com
DNS.3 = api.example.com
IP.1 = 192.168.1.100
EOF
)

# View CSR details
openssl req -in request.csr -text -noout

# Verify CSR signature
openssl req -in request.csr -verify -noout

# Extract public key from CSR
openssl req -in request.csr -pubkey -noout
```

### Subject Fields

| Field | Description | Example |
|-------|-------------|---------|
| C | Country | US |
| ST | State/Province | California |
| L | Locality/City | San Francisco |
| O | Organization | Example Inc |
| OU | Organizational Unit | IT Department |
| CN | Common Name | example.com |
| emailAddress | Email | admin@example.com |

## Certificate Generation

### Self-Signed Certificates

```bash
# Generate self-signed certificate (1 year)
openssl req -x509 -newkey rsa:2048 -keyout private.key -out cert.crt -days 365 -nodes

# Generate from existing key
openssl req -x509 -key private.key -out cert.crt -days 365

# Self-signed with custom subject
openssl req -x509 -newkey rsa:2048 -keyout private.key -out cert.crt -days 365 -nodes \
  -subj "/C=US/ST=CA/L=SF/O=Example/CN=example.com"

# Self-signed with SANs
openssl req -x509 -newkey rsa:2048 -keyout private.key -out cert.crt -days 365 -nodes \
  -extensions v3_req -config <(cat <<EOF
[req]
default_bits = 2048
prompt = no
default_md = sha256
req_extensions = v3_req
distinguished_name = dn

[dn]
C = US
ST = California
CN = example.com

[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = example.com
DNS.2 = *.example.com
EOF
)

# Generate wildcard certificate
openssl req -x509 -newkey rsa:2048 -keyout wildcard.key -out wildcard.crt -days 365 -nodes \
  -subj "/CN=*.example.com"
```

### Sign CSR (CA Signing)

```bash
# Sign CSR with CA
openssl x509 -req -in request.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out cert.crt -days 365

# Sign with specific serial number
openssl x509 -req -in request.csr -CA ca.crt -CAkey ca.key -set_serial 01 \
  -out cert.crt -days 365

# Sign with SHA-256
openssl x509 -req -in request.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out cert.crt -days 365 -sha256

# Sign with extensions
openssl x509 -req -in request.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out cert.crt -days 365 -extensions v3_req -extfile <(cat <<EOF
[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = example.com
DNS.2 = www.example.com
EOF
)
```

### Create Certificate Authority

```bash
# Generate CA private key
openssl genrsa -aes256 -out ca.key 4096

# Generate CA certificate
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 -out ca.crt \
  -subj "/C=US/ST=CA/O=Example CA/CN=Example Root CA"

# Generate intermediate CA
openssl genrsa -aes256 -out intermediate.key 4096
openssl req -new -key intermediate.key -out intermediate.csr \
  -subj "/C=US/ST=CA/O=Example CA/CN=Example Intermediate CA"
openssl x509 -req -in intermediate.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out intermediate.crt -days 1825 -sha256 \
  -extensions v3_ca -extfile <(cat <<EOF
[v3_ca]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,digitalSignature,keyCertSign,cRLSign
EOF
)

# Create certificate chain
cat intermediate.crt ca.crt > chain.crt
```

## Certificate Verification

### View Certificates

```bash
# View certificate details
openssl x509 -in cert.crt -text -noout

# View certificate subject
openssl x509 -in cert.crt -subject -noout

# View certificate issuer
openssl x509 -in cert.crt -issuer -noout

# View certificate dates
openssl x509 -in cert.crt -dates -noout

# View certificate serial number
openssl x509 -in cert.crt -serial -noout

# View certificate fingerprint (SHA-256)
openssl x509 -in cert.crt -fingerprint -sha256 -noout

# View certificate fingerprint (SHA-1)
openssl x509 -in cert.crt -fingerprint -sha1 -noout

# View certificate in different formats
openssl x509 -in cert.crt -text           # Text
openssl x509 -in cert.crt -purpose        # Purpose
openssl x509 -in cert.crt -subject_hash   # Subject hash
openssl x509 -in cert.crt -issuer_hash    # Issuer hash

# Extract all SANs
openssl x509 -in cert.crt -text -noout | grep "DNS:"

# Check certificate expiration
openssl x509 -in cert.crt -noout -enddate

# Check if certificate expires in 30 days
openssl x509 -in cert.crt -noout -checkend 2592000
```

### Verify Certificates

```bash
# Verify certificate against CA
openssl verify -CAfile ca.crt cert.crt

# Verify certificate chain
openssl verify -CAfile ca.crt -untrusted intermediate.crt cert.crt

# Verify certificate with CRL
openssl verify -CAfile ca.crt -CRLfile crl.pem -crl_check cert.crt

# Check if private key matches certificate
openssl x509 -in cert.crt -noout -modulus | openssl md5
openssl rsa -in private.key -noout -modulus | openssl md5

# Check if CSR matches private key
openssl req -in request.csr -noout -modulus | openssl md5
openssl rsa -in private.key -noout -modulus | openssl md5
```

## Format Conversions

### PEM Conversions

```bash
# PEM to DER
openssl x509 -in cert.pem -outform DER -out cert.der
openssl rsa -in key.pem -outform DER -out key.der

# DER to PEM
openssl x509 -in cert.der -inform DER -out cert.pem
openssl rsa -in key.der -inform DER -out key.pem

# PEM to PKCS#7
openssl crl2pkcs7 -nocrl -certfile cert.pem -out cert.p7b

# PKCS#7 to PEM
openssl pkcs7 -in cert.p7b -print_certs -out cert.pem

# PEM to PKCS#12 (with key and cert)
openssl pkcs12 -export -out cert.p12 -inkey private.key -in cert.crt -certfile ca.crt

# PKCS#12 to PEM
openssl pkcs12 -in cert.p12 -out cert.pem -nodes

# Extract only certificate from PKCS#12
openssl pkcs12 -in cert.p12 -clcerts -nokeys -out cert.pem

# Extract only key from PKCS#12
openssl pkcs12 -in cert.p12 -nocerts -nodes -out private.key

# Extract CA certificates from PKCS#12
openssl pkcs12 -in cert.p12 -cacerts -nokeys -out ca.pem
```

### Java Keystore Conversions

```bash
# Convert PKCS#12 to JKS (use keytool)
keytool -importkeystore -srckeystore cert.p12 -srcstoretype PKCS12 \
  -destkeystore keystore.jks -deststoretype JKS

# Export from JKS to PEM (via PKCS#12)
keytool -importkeystore -srckeystore keystore.jks -destkeystore cert.p12 \
  -deststoretype PKCS12
openssl pkcs12 -in cert.p12 -out cert.pem -nodes

# Import PEM to JKS
openssl pkcs12 -export -in cert.pem -inkey private.key -out cert.p12
keytool -importkeystore -srckeystore cert.p12 -srcstoretype PKCS12 \
  -destkeystore keystore.jks
```

## SSL/TLS Testing

### Test SSL Connection

```bash
# Connect to HTTPS server
openssl s_client -connect example.com:443

# Show certificate chain
openssl s_client -connect example.com:443 -showcerts

# Test with SNI (Server Name Indication)
openssl s_client -connect example.com:443 -servername example.com

# Test with specific protocol
openssl s_client -connect example.com:443 -tls1_2
openssl s_client -connect example.com:443 -tls1_3

# Test STARTTLS (SMTP)
openssl s_client -connect mail.example.com:25 -starttls smtp

# Test STARTTLS (IMAP)
openssl s_client -connect mail.example.com:143 -starttls imap

# Test STARTTLS (POP3)
openssl s_client -connect mail.example.com:110 -starttls pop3

# Test STARTTLS (FTP)
openssl s_client -connect ftp.example.com:21 -starttls ftp

# Show certificate only
openssl s_client -connect example.com:443 </dev/null 2>/dev/null | \
  openssl x509 -text -noout

# Extract certificate from server
openssl s_client -connect example.com:443 </dev/null 2>/dev/null | \
  openssl x509 -outform PEM -out server-cert.pem

# Verify certificate from server
openssl s_client -connect example.com:443 -CAfile ca.crt

# Test cipher suite
openssl s_client -connect example.com:443 -cipher 'ECDHE-RSA-AES256-GCM-SHA384'

# List supported ciphers
openssl ciphers -v 'ALL'
openssl ciphers -v 'HIGH:!aNULL'

# Check which ciphers server supports
for cipher in $(openssl ciphers 'ALL:eNULL' | tr ':' ' '); do
  echo -n "Testing $cipher..."
  result=$(openssl s_client -cipher "$cipher" -connect example.com:443 </dev/null 2>&1)
  if echo "$result" | grep -q "Cipher is ${cipher}"; then
    echo " supported"
  else
    echo " not supported"
  fi
done
```

### Certificate Chain Validation

```bash
# Get certificate chain
openssl s_client -connect example.com:443 -showcerts </dev/null 2>/dev/null

# Verify server certificate with system CA
openssl s_client -connect example.com:443 -CApath /etc/ssl/certs/

# Check certificate expiration remotely
echo | openssl s_client -connect example.com:443 -servername example.com 2>/dev/null | \
  openssl x509 -noout -dates

# Get certificate expiration in days
echo $(( ($(date -d "$(echo | openssl s_client -connect example.com:443 \
  -servername example.com 2>/dev/null | openssl x509 -noout -enddate | \
  cut -d= -f2)" +%s) - $(date +%s)) / 86400 ))
```

### Security Testing

```bash
# Test for Heartbleed
openssl s_client -connect example.com:443 -tlsextdebug 2>&1 | grep "heartbeat"

# Check OCSP stapling
openssl s_client -connect example.com:443 -status -tlsextdebug

# Test session resumption
openssl s_client -connect example.com:443 -reconnect -no_ticket

# Test renegotiation
openssl s_client -connect example.com:443 -state -no_tls1_3 <<< "R"

# Check supported SSL/TLS versions
for version in ssl3 tls1 tls1_1 tls1_2 tls1_3; do
  echo -n "Testing $version: "
  if openssl s_client -connect example.com:443 -$version </dev/null 2>/dev/null | \
     grep -q "Protocol"; then
    echo "supported"
  else
    echo "not supported"
  fi
done
```

## Encryption & Decryption

### Symmetric Encryption

```bash
# Encrypt file with AES-256-CBC
openssl enc -aes-256-cbc -salt -in file.txt -out file.txt.enc

# Decrypt file
openssl enc -aes-256-cbc -d -in file.txt.enc -out file.txt

# Encrypt with password from command line (not recommended)
openssl enc -aes-256-cbc -salt -in file.txt -out file.txt.enc -k "password"

# Encrypt with key file
openssl enc -aes-256-cbc -salt -in file.txt -out file.txt.enc -kfile key.txt

# Base64 encode encrypted file
openssl enc -aes-256-cbc -salt -in file.txt -out file.txt.enc -a

# List available ciphers
openssl enc -list
```

### Asymmetric Encryption

```bash
# Encrypt with public key
openssl rsautl -encrypt -pubin -inkey public.key -in file.txt -out file.enc

# Decrypt with private key
openssl rsautl -decrypt -inkey private.key -in file.enc -out file.txt

# Encrypt large file (hybrid encryption)
# 1. Generate random key
openssl rand -base64 32 > key.bin
# 2. Encrypt file with symmetric key
openssl enc -aes-256-cbc -salt -in file.txt -out file.enc -pass file:key.bin
# 3. Encrypt symmetric key with public key
openssl rsautl -encrypt -pubin -inkey public.key -in key.bin -out key.enc
# 4. To decrypt: decrypt key first, then file
openssl rsautl -decrypt -inkey private.key -in key.enc -out key.bin
openssl enc -d -aes-256-cbc -in file.enc -out file.txt -pass file:key.bin
```

## Hashing & Signatures

### Generate Hashes

```bash
# MD5 (not recommended)
openssl md5 file.txt

# SHA-1 (not recommended for security)
openssl sha1 file.txt

# SHA-256
openssl sha256 file.txt
openssl dgst -sha256 file.txt

# SHA-512
openssl sha512 file.txt

# Multiple files
openssl sha256 *.txt

# Hash from stdin
echo "text" | openssl sha256
```

### Digital Signatures

```bash
# Sign file
openssl dgst -sha256 -sign private.key -out file.sig file.txt

# Verify signature
openssl dgst -sha256 -verify public.key -signature file.sig file.txt

# Sign with RSA (older method)
openssl rsautl -sign -inkey private.key -in file.txt -out file.sig

# Verify RSA signature
openssl rsautl -verify -pubin -inkey public.key -in file.sig

# Create detached signature (S/MIME)
openssl smime -sign -in file.txt -out file.txt.sig -signer cert.crt -inkey private.key

# Verify S/MIME signature
openssl smime -verify -in file.txt.sig -CAfile ca.crt -out file.txt
```

## Random Data Generation

```bash
# Generate random bytes
openssl rand -hex 16         # 16 bytes as hex
openssl rand -base64 32      # 32 bytes as base64
openssl rand 128 > random.bin # 128 bytes to file

# Generate random password
openssl rand -base64 12 | cut -c1-16

# Generate strong password
openssl rand -base64 32 | tr -d '/+=' | cut -c1-20
```

## OCSP (Online Certificate Status Protocol)

```bash
# Get OCSP URL from certificate
openssl x509 -in cert.crt -noout -ocsp_uri

# Make OCSP request
openssl ocsp -issuer ca.crt -cert cert.crt -url http://ocsp.example.com \
  -CAfile ca.crt

# OCSP with nonce
openssl ocsp -issuer ca.crt -cert cert.crt -url http://ocsp.example.com \
  -CAfile ca.crt -header "HOST" "ocsp.example.com"

# Save OCSP response
openssl ocsp -issuer ca.crt -cert cert.crt -url http://ocsp.example.com \
  -respout ocsp-response.der
```

## Certificate Revocation Lists (CRL)

```bash
# Download CRL
wget -O crl.der http://crl.example.com/crl.crl

# Convert CRL to PEM
openssl crl -inform DER -in crl.der -outform PEM -out crl.pem

# View CRL
openssl crl -in crl.pem -text -noout

# Verify certificate against CRL
openssl verify -CAfile ca.crt -CRLfile crl.pem -crl_check cert.crt

# Check if certificate is revoked
openssl crl -in crl.pem -noout -text | grep -A1 $(openssl x509 -in cert.crt -serial -noout | cut -d= -f2)
```

## Performance Benchmarking

```bash
# Benchmark RSA
openssl speed rsa

# Benchmark specific RSA key size
openssl speed rsa2048

# Benchmark AES
openssl speed aes-256-cbc

# Benchmark SHA
openssl speed sha256

# Benchmark all
openssl speed

# Multi-threaded benchmark
openssl speed -multi 4
```

## Common Tasks

### Generate Password Hash

```bash
# Generate bcrypt-style hash
openssl passwd -1 "mypassword"

# Generate SHA-512 crypt hash
openssl passwd -6 "mypassword"

# From file
openssl passwd -1 -in password.txt
```

### Create Diffie-Hellman Parameters

```bash
# Generate DH parameters (2048-bit)
openssl dhparam -out dhparam.pem 2048

# Generate DH parameters (4096-bit, slower)
openssl dhparam -out dhparam.pem 4096

# Check DH parameters
openssl dhparam -in dhparam.pem -check -text
```

### Nginx/Apache SSL Configuration

```bash
# Generate combined PEM (key + cert + chain)
cat private.key cert.crt intermediate.crt > combined.pem

# Generate cert chain only
cat cert.crt intermediate.crt ca.crt > fullchain.pem

# Verify Nginx configuration
openssl s_client -connect localhost:443 -servername example.com

# Check what certificate Nginx serves
openssl s_client -connect localhost:443 -servername example.com 2>/dev/null | \
  openssl x509 -noout -subject -issuer
```

## Tips & Best Practices

### Security Recommendations

```bash
# Minimum key sizes (2024+)
RSA: 2048 bits (prefer 4096)
ECDSA: P-256 (prime256v1) or P-384
Ed25519: 256 bits (default)

# Recommended hash algorithms
SHA-256 or SHA-512 (avoid SHA-1, MD5)

# Certificate validity
Max: 398 days (13 months) for public CAs
Recommended: 90 days or less (use automated renewal)

# Cipher suites (TLS 1.3 recommended)
TLS_AES_256_GCM_SHA384
TLS_CHACHA20_POLY1305_SHA256
TLS_AES_128_GCM_SHA256
```

### Common Errors

```bash
# "unable to load certificate"
# Fix: Check file format (PEM vs DER)
openssl x509 -in cert.crt -text -noout

# "bad decrypt"
# Fix: Wrong password or corrupted key
openssl rsa -in private.key -check

# "certificate verify failed"
# Fix: Missing intermediate certificates
openssl verify -CAfile ca.crt -untrusted intermediate.crt cert.crt

# "unable to get local issuer certificate"
# Fix: CA certificate not trusted
openssl verify -CApath /etc/ssl/certs/ cert.crt
```

### Useful One-Liners

```bash
# Check certificate expiry in days
echo $(( ($(date -d "$(openssl x509 -in cert.crt -noout -enddate | cut -d= -f2)" +%s) - $(date +%s)) / 86400 ))

# Find all certificates expiring in 30 days
find /etc/ssl -name "*.crt" -exec sh -c 'openssl x509 -in "$1" -noout -checkend 2592000 && echo "$1"' _ {} \;

# Extract domain names from certificate
openssl x509 -in cert.crt -noout -text | grep -oP '(?<=DNS:)[^,]+'

# Generate CSR from existing certificate
openssl x509 -x509toreq -in cert.crt -signkey private.key -out request.csr

# Compare two certificates
diff <(openssl x509 -in cert1.crt -noout -text) <(openssl x509 -in cert2.crt -noout -text)
```

## Resources

- [OpenSSL Documentation](https://www.openssl.org/docs/)
- [OpenSSL Cookbook](https://www.feistyduck.com/library/openssl-cookbook/)
- [SSL Labs Server Test](https://www.ssllabs.com/ssltest/)
- [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/)
- [Let's Encrypt](https://letsencrypt.org/)
