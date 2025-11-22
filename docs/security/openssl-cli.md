---
tags:
  - openssl
  - cli
  - commands
---

# Aide-Mémoire OpenSSL CLI

Commandes OpenSSL essentielles pour les opérations de sécurité quotidiennes.

---

## Encodage & Décodage

### Base64

```bash
# Encoder une chaîne
echo -n "Xavki" | openssl base64
# Sortie : WGF2a2k=

# Décoder
echo "WGF2a2k=" | openssl base64 -d
# Sortie : Xavki

# Encoder un fichier
openssl base64 -in file.bin -out file.b64

# Décoder un fichier
openssl base64 -d -in file.b64 -out file.bin
```

### Encodage Hexadécimal

```bash
# Chaîne vers hex
echo -n "Hello" | xxd -p
# Sortie : 48656c6c6f

# Hex vers chaîne
echo "48656c6c6f" | xxd -r -p
# Sortie : Hello
```

---

## Hachage (Checksums)

```bash
# SHA256 (recommandé)
echo -n "data" | openssl dgst -sha256
# Sortie : SHA2-256(stdin)= 3a6eb0790f39ac87...

# SHA512
echo -n "data" | openssl dgst -sha512

# MD5 (déprécié, mais toujours utilisé pour les checksums)
echo -n "data" | openssl dgst -md5

# Hacher un fichier
openssl dgst -sha256 file.txt

# Sortie binaire brute (pas hex)
openssl dgst -sha256 -binary file.txt > file.sha256

# Vérifier l'intégrité d'un fichier
sha256sum -c checksums.txt
```

### Algorithmes Disponibles

```bash
# Lister tous les algorithmes de digest
openssl list -digest-algorithms

# Courants :
# -md5        (128-bit, cassé, éviter pour la sécurité)
# -sha1       (160-bit, déprécié)
# -sha256     (256-bit, recommandé)
# -sha384     (384-bit)
# -sha512     (512-bit)
# -sha3-256   (famille SHA-3)
```

---

## Chiffrement Symétrique (Chiffrement de Fichiers)

### Chiffrer un Fichier

```bash
# AES-256-CBC avec mot de passe (invite interactive)
openssl enc -aes-256-cbc -salt -pbkdf2 -in secret.txt -out secret.enc

# Avec mot de passe en ligne de commande (moins sécurisé)
openssl enc -aes-256-cbc -salt -pbkdf2 -in secret.txt -out secret.enc -pass pass:MyPassword

# Avec mot de passe depuis un fichier
openssl enc -aes-256-cbc -salt -pbkdf2 -in secret.txt -out secret.enc -pass file:password.txt
```

### Déchiffrer un Fichier

```bash
# Déchiffrer (demandera le mot de passe)
openssl enc -d -aes-256-cbc -pbkdf2 -in secret.enc -out secret.txt

# Avec mot de passe
openssl enc -d -aes-256-cbc -pbkdf2 -in secret.enc -out secret.txt -pass pass:MyPassword
```

### Options Expliquées

| Option | Objectif |
|--------|---------|
| `-aes-256-cbc` | Algorithme (AES 256-bit, mode CBC) |
| `-salt` | Ajouter un salt aléatoire (empêche les rainbow tables) |
| `-pbkdf2` | Utiliser la dérivation de clé PBKDF2 (recommandé) |
| `-iter 100000` | Itérations pour PBKDF2 (plus lent = plus sécurisé) |
| `-in` | Fichier d'entrée |
| `-out` | Fichier de sortie |
| `-d` | Mode déchiffrement |
| `-pass` | Source du mot de passe |

### Lister les Ciphers Disponibles

```bash
openssl enc -list

# Ciphers recommandés :
# -aes-256-cbc     (AES 256-bit, mode CBC)
# -aes-256-gcm     (AES 256-bit, mode GCM - authentifié)
# -chacha20        (Cipher stream ChaCha20)
```

!!! tip "Toujours Utiliser Salt et PBKDF2"
    ```bash
    # Bon
    openssl enc -aes-256-cbc -salt -pbkdf2 -iter 100000 ...

    # Mauvais (vulnérable)
    openssl enc -aes-256-cbc ...
    ```

---

## Clés Asymétriques (RSA)

### Générer une Clé Privée RSA

```bash
# Générer une clé privée RSA 4096-bit
openssl genrsa -out private.pem 4096

# Avec protection par passphrase
openssl genrsa -aes256 -out private.pem 4096
```

### Extraire la Clé Publique

```bash
# Extraire la clé publique de la clé privée
openssl rsa -in private.pem -pubout -out public.pem

# Voir la clé publique
openssl rsa -in private.pem -pubout -text
```

### Voir les Détails de la Clé

```bash
# Voir les détails de la clé privée
openssl rsa -in private.pem -text -noout

# Voir les détails de la clé publique
openssl rsa -pubin -in public.pem -text -noout
```

!!! info "Fondation de SSH et HTTPS"
    Ces clés RSA sont au même format que celles utilisées par :

    - **SSH :** `~/.ssh/id_rsa` (privée) et `~/.ssh/id_rsa.pub` (publique)
    - **TLS/HTTPS :** Clé privée du serveur + certificat

---

## Chiffrement Asymétrique (RSA)

```bash
# Chiffrer un fichier avec la clé publique
openssl rsautl -encrypt -pubin -inkey public.pem -in secret.txt -out secret.enc

# Déchiffrer avec la clé privée
openssl rsautl -decrypt -inkey private.pem -in secret.enc -out secret.txt

# Utiliser pkeyutl (plus récent, recommandé)
openssl pkeyutl -encrypt -pubin -inkey public.pem -in secret.txt -out secret.enc
openssl pkeyutl -decrypt -inkey private.pem -in secret.enc -out secret.txt
```

!!! warning "Limitation de Taille RSA"
    RSA ne peut chiffrer que des données plus petites que la taille de la clé moins le padding.
    Pour une clé 4096-bit : max ~470 octets.

    **Pour les fichiers plus volumineux :** Chiffrer avec une clé symétrique, puis chiffrer la clé avec RSA.

---

## Signatures Numériques

### Signer un Fichier

```bash
# Créer une signature
openssl dgst -sha256 -sign private.pem -out signature.bin file.txt

# Créer une signature (encodée en base64)
openssl dgst -sha256 -sign private.pem file.txt | openssl base64 > signature.b64
```

### Vérifier une Signature

```bash
# Vérifier la signature
openssl dgst -sha256 -verify public.pem -signature signature.bin file.txt
# Sortie : Verified OK

# Vérifier une signature base64
openssl base64 -d -in signature.b64 -out signature.bin
openssl dgst -sha256 -verify public.pem -signature signature.bin file.txt
```

---

## Génération de Données Aléatoires

```bash
# Générer 32 octets aléatoires (hex)
openssl rand -hex 32

# Générer 32 octets aléatoires (base64)
openssl rand -base64 32

# Générer des octets aléatoires dans un fichier
openssl rand -out random.bin 256

# Générer une chaîne aléatoire sûre pour les mots de passe
openssl rand -base64 24 | tr -d '=/+' | cut -c1-16
```

---

## Tableau de Référence Rapide

| Tâche | Commande |
|------|---------|
| Encoder en Base64 | `echo -n "text" \| openssl base64` |
| Décoder Base64 | `echo "dGV4dA==" \| openssl base64 -d` |
| Hash SHA256 | `openssl dgst -sha256 file.txt` |
| Chiffrer un fichier (symétrique) | `openssl enc -aes-256-cbc -salt -pbkdf2 -in f.txt -out f.enc` |
| Déchiffrer un fichier | `openssl enc -d -aes-256-cbc -pbkdf2 -in f.enc -out f.txt` |
| Générer une clé RSA | `openssl genrsa -out private.pem 4096` |
| Extraire la clé publique | `openssl rsa -in private.pem -pubout -out public.pem` |
| Signer un fichier | `openssl dgst -sha256 -sign private.pem -out sig.bin file` |
| Vérifier une signature | `openssl dgst -sha256 -verify public.pem -signature sig.bin file` |
| Octets aléatoires | `openssl rand -hex 32` |

---

## Exemples Pratiques

### Transfert Sécurisé de Fichier

```bash
# Expéditeur : Chiffrer le fichier pour le destinataire
openssl rand -out session.key 32
openssl enc -aes-256-cbc -salt -pbkdf2 -in data.tar.gz -out data.enc -pass file:session.key
openssl pkeyutl -encrypt -pubin -inkey recipient_public.pem -in session.key -out session.key.enc

# Envoyer : data.enc + session.key.enc

# Destinataire : Déchiffrer
openssl pkeyutl -decrypt -inkey my_private.pem -in session.key.enc -out session.key
openssl enc -d -aes-256-cbc -pbkdf2 -in data.enc -out data.tar.gz -pass file:session.key
```

### Générateur Rapide de Mot de Passe

```bash
# Mot de passe alphanumérique de 16 caractères
openssl rand -base64 12

# Mot de passe hex de 32 caractères
openssl rand -hex 16
```
