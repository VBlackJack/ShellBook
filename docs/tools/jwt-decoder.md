---
tags:
  - tools
  - security
  - jwt
  - authentication
---

# JWT Decoder

Decodeur de tokens JWT (JSON Web Tokens).

<div class="tool-container">

<div class="input-group">
    <label for="jwt-input">Token JWT :</label>
    <textarea id="jwt-input" rows="4" placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"></textarea>
</div>

<div id="jwt-error" class="error-box" style="display:none;"></div>

<div class="jwt-parts">
    <div class="jwt-part header">
        <h4>Header</h4>
        <pre id="jwt-header"></pre>
    </div>
    <div class="jwt-part payload">
        <h4>Payload</h4>
        <pre id="jwt-payload"></pre>
    </div>
    <div class="jwt-part signature">
        <h4>Signature</h4>
        <code id="jwt-signature"></code>
        <div id="jwt-signature-info"></div>
    </div>
</div>

<div id="jwt-claims" class="claims-section">
    <h4>Claims standards</h4>
    <table>
        <tr><td><strong>iss</strong> (Issuer)</td><td id="claim-iss">-</td></tr>
        <tr><td><strong>sub</strong> (Subject)</td><td id="claim-sub">-</td></tr>
        <tr><td><strong>aud</strong> (Audience)</td><td id="claim-aud">-</td></tr>
        <tr><td><strong>exp</strong> (Expiration)</td><td id="claim-exp">-</td></tr>
        <tr><td><strong>nbf</strong> (Not Before)</td><td id="claim-nbf">-</td></tr>
        <tr><td><strong>iat</strong> (Issued At)</td><td id="claim-iat">-</td></tr>
        <tr><td><strong>jti</strong> (JWT ID)</td><td id="claim-jti">-</td></tr>
    </table>
</div>

<div id="jwt-status" class="status-box"></div>

</div>

## Structure JWT

### Format

```
header.payload.signature
```

Un JWT est compose de 3 parties separees par des points :

1. **Header** (Base64URL) - Algorithme et type
2. **Payload** (Base64URL) - Claims (donnees)
3. **Signature** - Verification d'integrite

### Algorithmes courants

| Algorithme | Type | Description |
|------------|------|-------------|
| `HS256` | Symetrique | HMAC + SHA-256 |
| `HS384` | Symetrique | HMAC + SHA-384 |
| `HS512` | Symetrique | HMAC + SHA-512 |
| `RS256` | Asymetrique | RSA + SHA-256 |
| `RS384` | Asymetrique | RSA + SHA-384 |
| `RS512` | Asymetrique | RSA + SHA-512 |
| `ES256` | Asymetrique | ECDSA + SHA-256 |
| `ES384` | Asymetrique | ECDSA + SHA-384 |
| `ES512` | Asymetrique | ECDSA + SHA-512 |

### Claims standards (RFC 7519)

| Claim | Description |
|-------|-------------|
| `iss` | Emetteur du token |
| `sub` | Sujet (utilisateur) |
| `aud` | Audience cible |
| `exp` | Date d'expiration (timestamp) |
| `nbf` | Pas valide avant (timestamp) |
| `iat` | Date d'emission (timestamp) |
| `jti` | Identifiant unique du token |

### Verification CLI

```bash
# Decoder un JWT (sans verification)
echo "TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq

# Avec jq (payload)
echo "TOKEN" | jq -R 'split(".")[1] | @base64d | fromjson'

# Verifier avec openssl (RS256)
echo -n "header.payload" | \
  openssl dgst -sha256 -verify public.pem -signature sig.bin
```

!!! warning "Securite"
    Le decodage d'un JWT **ne verifie pas sa signature**.
    Toujours valider les tokens cote serveur avec la cle secrete/publique.

<style>
.tool-container {
    background: var(--md-code-bg-color);
    padding: 20px;
    border-radius: 8px;
    margin: 20px 0;
}
.input-group {
    margin: 15px 0;
}
.input-group label {
    display: block;
    font-weight: bold;
    margin-bottom: 5px;
}
.input-group textarea {
    width: 100%;
    padding: 12px;
    font-family: monospace;
    font-size: 13px;
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    background: var(--md-default-bg-color);
    color: var(--md-default-fg-color);
    resize: vertical;
    word-break: break-all;
}
.error-box {
    padding: 10px 15px;
    background: #f8d7da;
    border: 1px solid #f5c6cb;
    border-radius: 4px;
    color: #721c24;
    margin: 10px 0;
}
.jwt-parts {
    display: flex;
    gap: 15px;
    flex-wrap: wrap;
    margin: 20px 0;
}
.jwt-part {
    flex: 1;
    min-width: 250px;
    padding: 15px;
    border-radius: 4px;
    background: var(--md-default-bg-color);
}
.jwt-part.header {
    border-left: 4px solid #e74c3c;
}
.jwt-part.payload {
    border-left: 4px solid #9b59b6;
}
.jwt-part.signature {
    border-left: 4px solid #3498db;
}
.jwt-part h4 {
    margin: 0 0 10px 0;
}
.jwt-part pre {
    margin: 0;
    white-space: pre-wrap;
    word-break: break-all;
    font-size: 12px;
    max-height: 200px;
    overflow-y: auto;
}
.jwt-part code {
    font-size: 11px;
    word-break: break-all;
}
#jwt-signature-info {
    margin-top: 10px;
    font-size: 12px;
    color: var(--md-default-fg-color--light);
}
.claims-section {
    background: var(--md-default-bg-color);
    padding: 15px;
    border-radius: 4px;
    margin: 20px 0;
}
.claims-section h4 {
    margin: 0 0 15px 0;
}
.claims-section table {
    width: 100%;
}
.claims-section td {
    padding: 8px;
    border-bottom: 1px solid var(--md-default-fg-color--lightest);
}
.claims-section td:first-child {
    width: 150px;
}
.status-box {
    padding: 15px;
    border-radius: 4px;
    margin-top: 15px;
    font-weight: bold;
}
.status-box.valid {
    background: #d4edda;
    color: #155724;
}
.status-box.expired {
    background: #f8d7da;
    color: #721c24;
}
.status-box.not-yet-valid {
    background: #fff3cd;
    color: #856404;
}
</style>

<script>
function base64UrlDecode(str) {
    // Add padding
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4) str += '=';
    return atob(str);
}

function formatTimestamp(ts) {
    if (!ts) return '-';
    const date = new Date(ts * 1000);
    const now = new Date();
    const diff = date - now;

    let status = '';
    if (diff < 0) {
        status = ' (expire)';
    } else if (diff < 3600000) {
        status = ` (dans ${Math.round(diff/60000)} min)`;
    } else if (diff < 86400000) {
        status = ` (dans ${Math.round(diff/3600000)} h)`;
    }

    return date.toLocaleString('fr-FR') + status;
}

function decodeJWT() {
    const token = document.getElementById('jwt-input').value.trim();
    const errorBox = document.getElementById('jwt-error');
    const statusBox = document.getElementById('jwt-status');

    errorBox.style.display = 'none';
    statusBox.textContent = '';
    statusBox.className = 'status-box';

    // Reset displays
    document.getElementById('jwt-header').textContent = '';
    document.getElementById('jwt-payload').textContent = '';
    document.getElementById('jwt-signature').textContent = '';
    document.getElementById('jwt-signature-info').textContent = '';

    ['iss', 'sub', 'aud', 'exp', 'nbf', 'iat', 'jti'].forEach(claim => {
        document.getElementById('claim-' + claim).textContent = '-';
    });

    if (!token) return;

    const parts = token.split('.');
    if (parts.length !== 3) {
        errorBox.textContent = 'Format invalide: un JWT doit avoir 3 parties separees par des points';
        errorBox.style.display = 'block';
        return;
    }

    try {
        // Decode header
        const headerJson = base64UrlDecode(parts[0]);
        const header = JSON.parse(headerJson);
        document.getElementById('jwt-header').textContent = JSON.stringify(header, null, 2);

        // Decode payload
        const payloadJson = base64UrlDecode(parts[1]);
        const payload = JSON.parse(payloadJson);
        document.getElementById('jwt-payload').textContent = JSON.stringify(payload, null, 2);

        // Signature
        document.getElementById('jwt-signature').textContent = parts[2];
        document.getElementById('jwt-signature-info').textContent = `Algorithme: ${header.alg || 'non specifie'}`;

        // Standard claims
        document.getElementById('claim-iss').textContent = payload.iss || '-';
        document.getElementById('claim-sub').textContent = payload.sub || '-';
        document.getElementById('claim-aud').textContent = Array.isArray(payload.aud) ? payload.aud.join(', ') : (payload.aud || '-');
        document.getElementById('claim-exp').textContent = formatTimestamp(payload.exp);
        document.getElementById('claim-nbf').textContent = formatTimestamp(payload.nbf);
        document.getElementById('claim-iat').textContent = formatTimestamp(payload.iat);
        document.getElementById('claim-jti').textContent = payload.jti || '-';

        // Check validity
        const now = Math.floor(Date.now() / 1000);

        if (payload.exp && payload.exp < now) {
            statusBox.textContent = 'Token expire';
            statusBox.className = 'status-box expired';
        } else if (payload.nbf && payload.nbf > now) {
            statusBox.textContent = 'Token pas encore valide';
            statusBox.className = 'status-box not-yet-valid';
        } else if (payload.exp) {
            const remaining = payload.exp - now;
            const hours = Math.floor(remaining / 3600);
            const minutes = Math.floor((remaining % 3600) / 60);
            statusBox.textContent = `Token valide (expire dans ${hours}h ${minutes}m)`;
            statusBox.className = 'status-box valid';
        } else {
            statusBox.textContent = 'Token decode (pas de date d\'expiration)';
            statusBox.className = 'status-box valid';
        }

    } catch (e) {
        errorBox.textContent = 'Erreur de decodage: ' + e.message;
        errorBox.style.display = 'block';
    }
}

// Event listener
document.getElementById('jwt-input').addEventListener('input', decodeJWT);

// Initial decode if placeholder has content
decodeJWT();
</script>
