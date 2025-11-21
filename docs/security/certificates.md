# OpenSSL & Gestion du Cycle de Vie des Certificats

`#openssl` `#pki` `#anssi` `#secnumcloud`

Une référence complète pour gérer les certificats X.509 dans les environnements SecNumCloud.

---

## Vue d'ensemble du Cycle de Vie des Certificats

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

!!! danger "Sécurité Critique"
    La **Private Key** ne doit **JAMAIS** quitter le serveur sécurisé où elle a été générée.
    Ne transmettez jamais les clés privées par email, chat, ou canaux non chiffrés.
    Stockez les clés avec des permissions restrictives : `chmod 600`.

!!! info "Standards ANSSI"
    Selon les recommandations ANSSI pour SecNumCloud :

    - **RSA** : Minimum **3072 bits** (4096 recommandé)
    - **ECDSA** : Minimum courbe **P-256** (P-384 recommandé)
    - **Hash** : SHA-256 minimum (SHA-384/512 pour long terme)
    - **Validité** : Maximum 1 an pour les certificats publics

---

## Générer une Private Key

=== "Bash (Linux)"

    ```bash
    # RSA 4096 bits
    openssl genrsa -aes256 -out private.key 4096

    # ECDSA P-384 (recommandé)
    openssl ecparam -genkey -name secp384r1 | openssl ec -aes256 -out private-ec.key
    ```

=== "PowerShell (Windows)"

    ```powershell
    # Utiliser OpenSSL sur Windows
    openssl genrsa -aes256 -out private.key 4096

    # Utiliser certreq natif (générer avec fichier INF)
    certreq -new request.inf private.key
    ```

---

## Générer un CSR (Certificate Signing Request)

=== "Bash (Linux)"

    ```bash
    openssl req -new -key private.key -out request.csr \
        -subj "/C=FR/ST=IDF/L=Paris/O=MyCompany/OU=IT/CN=server.example.com"
    ```

=== "PowerShell (Windows)"

    ```powershell
    # Utiliser OpenSSL
    openssl req -new -key private.key -out request.csr `
        -subj "/C=FR/ST=IDF/L=Paris/O=MyCompany/OU=IT/CN=server.example.com"

    # Utiliser certreq avec template INF
    certreq -new csr_template.inf request.csr
    ```

??? note "Template CSR pour Windows (csr_template.inf)"
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

## Aide-mémoire OpenSSL

| Tâche | Commande |
|------|---------|
| Vérifier l'expiration du certificat | `openssl x509 -enddate -noout -in cert.pem` |
| Voir les détails du certificat | `openssl x509 -text -noout -in cert.pem` |
| Vérifier le contenu du CSR | `openssl req -text -noout -in request.csr` |
| Vérifier que la clé correspond au certificat | `openssl x509 -modulus -noout -in cert.pem \| md5sum` |
| Convertir PEM vers PFX/PKCS12 | `openssl pkcs12 -export -out cert.pfx -inkey key.pem -in cert.pem` |
| Convertir PFX vers PEM | `openssl pkcs12 -in cert.pfx -out cert.pem -nodes` |
| Vérifier le certificat distant | `openssl s_client -connect host:443 -servername host` |
| Vérifier la chaîne de certificats | `openssl verify -CAfile ca-bundle.crt cert.pem` |

---

## Script de Vérification Rapide

=== "Bash (Linux)"

    ```bash
    #!/bin/bash
    # Vérifier l'expiration du certificat
    CERT="$1"
    EXPIRY=$(openssl x509 -enddate -noout -in "$CERT" | cut -d= -f2)
    EXPIRY_EPOCH=$(date -d "$EXPIRY" +%s)
    NOW_EPOCH=$(date +%s)
    DAYS_LEFT=$(( (EXPIRY_EPOCH - NOW_EPOCH) / 86400 ))

    echo "Le certificat expire dans $DAYS_LEFT jours"
    [[ $DAYS_LEFT -lt 30 ]] && echo "⚠️  ATTENTION : Renouvellement requis bientôt !"
    ```

=== "PowerShell (Windows)"

    ```powershell
    # Vérifier l'expiration du certificat
    param([string]$CertPath)
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CertPath)
    $daysLeft = ($cert.NotAfter - (Get-Date)).Days

    Write-Host "Le certificat expire dans $daysLeft jours"
    if ($daysLeft -lt 30) { Write-Warning "Renouvellement requis bientôt !" }
    ```
