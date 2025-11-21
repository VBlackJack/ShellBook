# Cryptography Fundamentals & Vocabulary

`#crypto` `#security` `#theory`

Master the concepts before the commands.

---

!!! important "Le Vocabulaire (Terminologie Française)"
    En français technique, les termes ont des sens précis :

    | Terme | Définition | Usage |
    |-------|------------|-------|
    | **Chiffrer** | Transformer des données avec une clé | ✅ Correct |
    | **Déchiffrer** | Inverser le chiffrement *avec* la clé | ✅ Légitime |
    | **Décrypter** | Inverser *sans* la clé (attaque) | ⚠️ Contexte sécurité |
    | **Crypter** | ❌ N'existe pas en français | ⛔ À éviter |
    | **Encrypter** | ❌ Anglicisme | ⛔ À éviter |

    **Correct :** "Je vais **chiffrer** ce fichier avec AES."

    **Incorrect :** "Je vais ~~crypter~~ ce fichier."

---

## The 3 Pillars

| Concept | Reversible | Uses Keys | Goal | Examples |
|---------|------------|-----------|------|----------|
| **Encryption** | ✅ Yes | ✅ Yes | Confidentiality | AES, RSA, ChaCha20 |
| **Hashing** | ❌ No | ❌ No | Integrity, Auth | SHA256, bcrypt, MD5 |
| **Encoding** | ✅ Yes | ❌ No | Transport, Format | Base64, Hex, URL |

### Encryption (Chiffrement)

Transform data so only authorized parties can read it.

```
Plaintext + Key → [Encryption] → Ciphertext
Ciphertext + Key → [Decryption] → Plaintext
```

**Use cases:**

- File protection
- Network traffic (TLS/HTTPS)
- Disk encryption
- Messaging (E2E)

---

### Hashing (Hachage)

One-way transformation producing a fixed-size "fingerprint."

```
Data → [Hash Function] → Fixed-size Digest

"Hello" → SHA256 → 2cf24dba5fb0a30e26e83b2ac5b9e29e...
"Hello!" → SHA256 → 33d7c290db4c... (completely different!)
```

**Properties:**

- **Deterministic:** Same input = same output
- **One-way:** Cannot reverse hash to get original
- **Avalanche effect:** Small change = completely different hash
- **Collision resistant:** Hard to find two inputs with same hash

**Use cases:**

- Password storage (with salt!)
- File integrity verification
- Digital signatures
- Blockchain

---

### Encoding (Encodage)

Format transformation for transport or compatibility. **NOT security!**

```
Binary → [Base64] → ASCII text
ASCII → [Hex] → Hexadecimal string
```

!!! warning "Encoding ≠ Security"
    Base64 is **not encryption**. It's just a format change.
    Anyone can decode it instantly.

    ```bash
    # "Secret" in Base64
    echo "U2VjcmV0" | base64 -d
    # Output: Secret
    ```

**Use cases:**

- Email attachments (MIME)
- URLs (URL encoding)
- JSON with binary data
- Certificates (PEM format)

---

## Symmetric vs Asymmetric

### Symmetric Encryption (Chiffrement Symétrique)

**One shared secret key** for both encryption and decryption.

```
        ┌─────────────┐
        │  Same Key   │
        └──────┬──────┘
               │
    ┌──────────┴──────────┐
    ▼                     ▼
[Encrypt]             [Decrypt]
    │                     │
Plaintext → Ciphertext → Plaintext
```

| Pros | Cons |
|------|------|
| Very fast | Key distribution problem |
| Efficient for large data | If key leaked, all compromised |
| Simple implementation | Need secure channel to share key |

**Algorithms:** AES-256, ChaCha20, 3DES (deprecated)

**Use cases:**

- File encryption
- Disk encryption (LUKS, BitLocker)
- VPN tunnels (after key exchange)

---

### Asymmetric Encryption (Chiffrement Asymétrique)

**Key pair:** Public key + Private key

```
┌─────────────────────────────────────────────────┐
│                  KEY PAIR                        │
├─────────────────────┬───────────────────────────┤
│    Public Key       │     Private Key           │
│    (shareable)      │     (SECRET!)             │
└─────────────────────┴───────────────────────────┘
```

#### For Encryption (Confidentiality)

**Public key encrypts → Private key decrypts**

```
Alice wants to send secret to Bob:

1. Bob shares his PUBLIC key with Alice
2. Alice encrypts message with Bob's PUBLIC key
3. Only Bob's PRIVATE key can decrypt it

    Alice                           Bob
      │                              │
      │ ◄── Bob's Public Key ───────┤
      │                              │
      ├─── Encrypted Message ──────► │
      │    (only Bob can read)       │
```

#### For Signatures (Authentication)

**Private key signs → Public key verifies**

```
Bob wants to prove he wrote a message:

1. Bob signs message with his PRIVATE key
2. Anyone with Bob's PUBLIC key can verify
3. Only Bob could have created that signature

    Bob                            Anyone
      │                              │
      ├─── Message + Signature ────► │
      │                              │
      │ ◄── Verify with Public Key ──┤
      │    "Yes, Bob signed this"    │
```

| Pros | Cons |
|------|------|
| No key distribution problem | Much slower than symmetric |
| Digital signatures | Limited data size |
| Non-repudiation | Complex mathematics |

**Algorithms:** RSA, ECDSA, Ed25519

---

## Hybrid Encryption (Real World)

Modern systems combine both: **asymmetric for key exchange, symmetric for data.**

```
TLS/HTTPS Handshake:

1. Client & Server use ASYMMETRIC crypto
   to securely exchange a session key

2. All further communication uses SYMMETRIC
   encryption with that session key (fast!)

┌──────────────────────────────────────────┐
│  Asymmetric (RSA/ECDH)                   │
│  └─► Exchange symmetric key              │
│                                          │
│  Symmetric (AES-256-GCM)                 │
│  └─► Encrypt all traffic (fast)          │
└──────────────────────────────────────────┘
```

---

## Quick Reference

| Question | Answer |
|----------|--------|
| Need confidentiality? | Encryption |
| Need to verify integrity? | Hashing |
| Need to prove identity? | Digital Signature |
| Need fast bulk encryption? | Symmetric (AES) |
| Need key exchange? | Asymmetric (RSA/ECDH) |
| Need password storage? | Hashing + Salt (bcrypt) |
| Need to transport binary? | Encoding (Base64) |
