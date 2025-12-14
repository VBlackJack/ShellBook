---
tags:
  - tools
  - security
  - ssl
  - certificates
---

# Certificate Decoder

Decodeur de certificats X.509 (PEM/Base64).

<div class="tool-container">

<div class="input-group">
    <label for="cert-input">Certificat PEM :</label>
    <textarea id="cert-input" rows="10" placeholder="-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAJC1HiIAZAiU...
-----END CERTIFICATE-----"></textarea>
</div>

<button onclick="decodeCert()" class="action-btn">Decoder</button>

<div id="cert-error" class="error-box" style="display:none;"></div>

<div id="cert-result" class="cert-result" style="display:none;">
    <div class="cert-section">
        <h4>Sujet</h4>
        <table>
            <tr><td>Common Name (CN)</td><td id="cert-cn">-</td></tr>
            <tr><td>Organisation (O)</td><td id="cert-org">-</td></tr>
            <tr><td>Unite (OU)</td><td id="cert-ou">-</td></tr>
            <tr><td>Localite (L)</td><td id="cert-loc">-</td></tr>
            <tr><td>Pays (C)</td><td id="cert-country">-</td></tr>
        </table>
    </div>

    <div class="cert-section">
        <h4>Emetteur</h4>
        <table>
            <tr><td>Common Name</td><td id="issuer-cn">-</td></tr>
            <tr><td>Organisation</td><td id="issuer-org">-</td></tr>
        </table>
    </div>

    <div class="cert-section">
        <h4>Validite</h4>
        <table>
            <tr><td>Debut</td><td id="cert-notbefore">-</td></tr>
            <tr><td>Fin</td><td id="cert-notafter">-</td></tr>
            <tr><td>Statut</td><td id="cert-status">-</td></tr>
        </table>
    </div>

    <div class="cert-section">
        <h4>Details techniques</h4>
        <table>
            <tr><td>Serial Number</td><td id="cert-serial">-</td></tr>
            <tr><td>Signature Algorithm</td><td id="cert-sigalg">-</td></tr>
            <tr><td>Public Key</td><td id="cert-pubkey">-</td></tr>
            <tr><td>Version</td><td id="cert-version">-</td></tr>
        </table>
    </div>

    <div class="cert-section">
        <h4>Subject Alternative Names (SAN)</h4>
        <div id="cert-san" class="san-list">-</div>
    </div>

    <div class="cert-section">
        <h4>Fingerprints</h4>
        <table>
            <tr><td>SHA-256</td><td id="cert-sha256">-</td></tr>
            <tr><td>SHA-1</td><td id="cert-sha1">-</td></tr>
        </table>
    </div>
</div>

</div>

## Commandes OpenSSL

### Decoder un certificat

```bash
# Afficher les informations
openssl x509 -in cert.pem -text -noout

# Afficher le sujet
openssl x509 -in cert.pem -subject -noout

# Afficher l'emetteur
openssl x509 -in cert.pem -issuer -noout

# Afficher les dates
openssl x509 -in cert.pem -dates -noout

# Afficher le fingerprint SHA-256
openssl x509 -in cert.pem -fingerprint -sha256 -noout
```

### Verifier un certificat

```bash
# Verifier la chaine
openssl verify -CAfile ca.pem cert.pem

# Verifier la correspondance cle/cert
openssl x509 -noout -modulus -in cert.pem | openssl md5
openssl rsa -noout -modulus -in key.pem | openssl md5

# Verifier l'expiration
openssl x509 -checkend 86400 -noout -in cert.pem
```

### Extraire depuis un serveur

```bash
# Telecharger le certificat
echo | openssl s_client -connect example.com:443 -servername example.com 2>/dev/null | openssl x509 -text

# Afficher la chaine complete
openssl s_client -connect example.com:443 -showcerts
```

## Types de certificats

| Type | Description |
|------|-------------|
| DV | Domain Validated - Verification domaine uniquement |
| OV | Organization Validated - Verification organisation |
| EV | Extended Validation - Verification etendue |
| Wildcard | Valide pour *.domaine.com |
| SAN/UCC | Multi-domaines (Subject Alternative Names) |

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
    font-size: 12px;
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    background: var(--md-default-bg-color);
    color: var(--md-default-fg-color);
    resize: vertical;
}
.action-btn {
    padding: 12px 24px;
    background: var(--md-primary-fg-color);
    color: white;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    font-size: 16px;
}
.action-btn:hover {
    opacity: 0.9;
}
.error-box {
    padding: 10px 15px;
    background: #f8d7da;
    border: 1px solid #f5c6cb;
    border-radius: 4px;
    color: #721c24;
    margin: 10px 0;
}
.cert-result {
    margin-top: 20px;
}
.cert-section {
    background: var(--md-default-bg-color);
    padding: 15px;
    border-radius: 4px;
    margin: 15px 0;
}
.cert-section h4 {
    margin: 0 0 10px 0;
    color: var(--md-primary-fg-color);
}
.cert-section table {
    width: 100%;
}
.cert-section td {
    padding: 6px;
    border-bottom: 1px solid var(--md-default-fg-color--lightest);
}
.cert-section td:first-child {
    font-weight: bold;
    width: 180px;
}
.cert-section td:last-child {
    font-family: monospace;
    word-break: break-all;
}
.san-list {
    font-family: monospace;
    background: var(--md-code-bg-color);
    padding: 10px;
    border-radius: 4px;
    word-break: break-all;
}
#cert-status.valid {
    color: #155724;
    font-weight: bold;
}
#cert-status.expired {
    color: #721c24;
    font-weight: bold;
}
#cert-status.expiring {
    color: #856404;
    font-weight: bold;
}
</style>

<script>
// Simple ASN.1/X.509 parser
function parseX509(pem) {
    // Remove PEM headers and decode base64
    const b64 = pem.replace(/-----BEGIN CERTIFICATE-----/g, '')
                   .replace(/-----END CERTIFICATE-----/g, '')
                   .replace(/\s/g, '');

    const der = Uint8Array.from(atob(b64), c => c.charCodeAt(0));

    // Parse ASN.1 structure (simplified)
    const result = {
        subject: {},
        issuer: {},
        validity: {},
        serialNumber: '',
        signatureAlgorithm: '',
        publicKey: '',
        version: 3,
        san: [],
        fingerprints: {}
    };

    // Extract OID-based fields from DER
    const derHex = Array.from(der).map(b => b.toString(16).padStart(2, '0')).join('');

    // Common OIDs
    const oids = {
        '550403': 'CN',
        '55040a': 'O',
        '55040b': 'OU',
        '550407': 'L',
        '550408': 'ST',
        '550406': 'C',
        '551d11': 'SAN'
    };

    // Find CN in subject (simplified extraction)
    const cnMatch = derHex.match(/550403.{2}(.{2})([0-9a-f]+?)(?=5504|2a86|300)/);
    if (cnMatch) {
        const len = parseInt(cnMatch[1], 16);
        result.subject.CN = hexToString(cnMatch[2].slice(0, len * 2));
    }

    // Find O in subject
    const oMatch = derHex.match(/55040a.{2}(.{2})([0-9a-f]+?)(?=5504|2a86|300)/);
    if (oMatch) {
        const len = parseInt(oMatch[1], 16);
        result.subject.O = hexToString(oMatch[2].slice(0, len * 2));
    }

    // Find serial number (first integer after version)
    const serialMatch = derHex.match(/0201.{2}02(.{2})([0-9a-f]+?)30/);
    if (serialMatch) {
        result.serialNumber = serialMatch[2].toUpperCase();
    }

    // Try to find dates (UTC Time format 17 bytes or Generalized Time 15 bytes)
    const dateMatches = derHex.matchAll(/17.{2}([0-9a-f]{26})/g);
    const dates = Array.from(dateMatches);
    if (dates.length >= 2) {
        result.validity.notBefore = parseUtcTime(hexToString(dates[0][1]));
        result.validity.notAfter = parseUtcTime(hexToString(dates[1][1]));
    }

    // Determine signature algorithm from common OIDs
    if (derHex.includes('2a864886f70d010105')) {
        result.signatureAlgorithm = 'SHA-1 with RSA';
    } else if (derHex.includes('2a864886f70d01010b')) {
        result.signatureAlgorithm = 'SHA-256 with RSA';
    } else if (derHex.includes('2a864886f70d01010c')) {
        result.signatureAlgorithm = 'SHA-384 with RSA';
    } else if (derHex.includes('2a864886f70d01010d')) {
        result.signatureAlgorithm = 'SHA-512 with RSA';
    } else if (derHex.includes('2a8648ce3d040302')) {
        result.signatureAlgorithm = 'ECDSA with SHA-256';
    }

    // RSA key size detection
    if (derHex.includes('2a864886f70d010101')) {
        result.publicKey = 'RSA';
        // Try to detect key size from modulus length
        const modulusMatch = derHex.match(/02820(.{3})00/);
        if (modulusMatch) {
            const keySize = parseInt(modulusMatch[1], 16) * 8;
            result.publicKey = `RSA ${keySize} bits`;
        }
    } else if (derHex.includes('2a8648ce3d0201')) {
        result.publicKey = 'ECDSA';
    }

    return result;
}

function hexToString(hex) {
    let str = '';
    for (let i = 0; i < hex.length; i += 2) {
        str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
    }
    return str;
}

function parseUtcTime(str) {
    // Format: YYMMDDHHMMSSZ
    if (str.length < 12) return null;
    let year = parseInt(str.substr(0, 2));
    year += year < 50 ? 2000 : 1900;
    const month = parseInt(str.substr(2, 2)) - 1;
    const day = parseInt(str.substr(4, 2));
    const hour = parseInt(str.substr(6, 2));
    const min = parseInt(str.substr(8, 2));
    const sec = parseInt(str.substr(10, 2));
    return new Date(Date.UTC(year, month, day, hour, min, sec));
}

async function computeFingerprint(der, algo) {
    const hashBuffer = await crypto.subtle.digest(algo, der);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).toUpperCase().padStart(2, '0')).join(':');
}

async function decodeCert() {
    const pem = document.getElementById('cert-input').value.trim();
    const errorBox = document.getElementById('cert-error');
    const resultDiv = document.getElementById('cert-result');

    errorBox.style.display = 'none';
    resultDiv.style.display = 'none';

    if (!pem) return;

    if (!pem.includes('-----BEGIN CERTIFICATE-----')) {
        errorBox.textContent = 'Format invalide: le certificat doit commencer par -----BEGIN CERTIFICATE-----';
        errorBox.style.display = 'block';
        return;
    }

    try {
        const cert = parseX509(pem);

        // Update display
        document.getElementById('cert-cn').textContent = cert.subject.CN || '-';
        document.getElementById('cert-org').textContent = cert.subject.O || '-';
        document.getElementById('cert-ou').textContent = cert.subject.OU || '-';
        document.getElementById('cert-loc').textContent = cert.subject.L || '-';
        document.getElementById('cert-country').textContent = cert.subject.C || '-';

        document.getElementById('issuer-cn').textContent = cert.issuer.CN || cert.subject.CN || '-';
        document.getElementById('issuer-org').textContent = cert.issuer.O || cert.subject.O || '-';

        if (cert.validity.notBefore) {
            document.getElementById('cert-notbefore').textContent = cert.validity.notBefore.toLocaleString('fr-FR');
        }
        if (cert.validity.notAfter) {
            document.getElementById('cert-notafter').textContent = cert.validity.notAfter.toLocaleString('fr-FR');

            // Check status
            const now = new Date();
            const statusEl = document.getElementById('cert-status');
            if (cert.validity.notAfter < now) {
                statusEl.textContent = 'EXPIRE';
                statusEl.className = 'expired';
            } else if (cert.validity.notAfter - now < 30 * 24 * 60 * 60 * 1000) {
                statusEl.textContent = 'Expire dans moins de 30 jours';
                statusEl.className = 'expiring';
            } else {
                const days = Math.floor((cert.validity.notAfter - now) / (24 * 60 * 60 * 1000));
                statusEl.textContent = `Valide (${days} jours restants)`;
                statusEl.className = 'valid';
            }
        }

        document.getElementById('cert-serial').textContent = cert.serialNumber || '-';
        document.getElementById('cert-sigalg').textContent = cert.signatureAlgorithm || '-';
        document.getElementById('cert-pubkey').textContent = cert.publicKey || '-';
        document.getElementById('cert-version').textContent = 'v' + cert.version;

        document.getElementById('cert-san').textContent = cert.san.length ? cert.san.join(', ') : 'Non specifie';

        // Compute fingerprints
        const b64 = pem.replace(/-----BEGIN CERTIFICATE-----/g, '')
                       .replace(/-----END CERTIFICATE-----/g, '')
                       .replace(/\s/g, '');
        const der = Uint8Array.from(atob(b64), c => c.charCodeAt(0));

        document.getElementById('cert-sha256').textContent = await computeFingerprint(der, 'SHA-256');
        document.getElementById('cert-sha1').textContent = await computeFingerprint(der, 'SHA-1');

        resultDiv.style.display = 'block';

    } catch (e) {
        errorBox.textContent = 'Erreur de decodage: ' + e.message;
        errorBox.style.display = 'block';
    }
}
</script>
