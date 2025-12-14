---
tags:
  - tools
  - jwt
  - security
  - token
  - auth
---

# JWT Builder & Decoder

Creation et decodage de JSON Web Tokens (JWT).

<div class="tool-container">

<div class="mode-selector">
    <button class="mode-btn active" onclick="selectMode('decode')">Decoder</button>
    <button class="mode-btn" onclick="selectMode('encode')">Encoder</button>
</div>

<div id="decode-section">
    <div class="input-section">
        <h3>Token JWT</h3>
        <textarea id="jwt-input" placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c" oninput="decodeJWT()"></textarea>
    </div>

    <div class="decoded-section" id="decoded-section">
        <div class="jwt-part">
            <h4>Header <span class="jwt-color header">Rouge</span></h4>
            <pre id="decoded-header">{}</pre>
        </div>
        <div class="jwt-part">
            <h4>Payload <span class="jwt-color payload">Violet</span></h4>
            <pre id="decoded-payload">{}</pre>
        </div>
        <div class="jwt-part">
            <h4>Signature <span class="jwt-color signature">Bleu</span></h4>
            <div id="decoded-signature">-</div>
        </div>
        <div class="jwt-part">
            <h4>Status</h4>
            <div id="jwt-status">-</div>
        </div>
    </div>
</div>

<div id="encode-section" style="display: none;">
    <div class="encode-grid">
        <div class="encode-column">
            <h4>Header</h4>
            <textarea id="encode-header">{
  "alg": "HS256",
  "typ": "JWT"
}</textarea>
        </div>
        <div class="encode-column">
            <h4>Payload</h4>
            <textarea id="encode-payload">{
  "sub": "1234567890",
  "name": "John Doe",
  "iat": 1516239022,
  "exp": 1893456000
}</textarea>
        </div>
    </div>
    <div class="secret-section">
        <label for="jwt-secret">Secret (pour signature HS256)</label>
        <input type="text" id="jwt-secret" value="your-256-bit-secret">
        <button onclick="encodeJWT()" class="encode-btn">Generer JWT</button>
    </div>
    <div class="output-section" id="encode-output-section" style="display: none;">
        <h4>Token genere</h4>
        <div class="jwt-display" id="encoded-jwt"></div>
        <button onclick="copyEncoded()" class="copy-btn">Copier</button>
    </div>
</div>

<div class="claims-section">
    <h3>Claims Standards (RFC 7519)</h3>
    <div class="claims-grid">
        <div class="claim-card">
            <code>iss</code>
            <span>Issuer - Emetteur du token</span>
        </div>
        <div class="claim-card">
            <code>sub</code>
            <span>Subject - Sujet du token</span>
        </div>
        <div class="claim-card">
            <code>aud</code>
            <span>Audience - Destinataire</span>
        </div>
        <div class="claim-card">
            <code>exp</code>
            <span>Expiration Time (Unix)</span>
        </div>
        <div class="claim-card">
            <code>nbf</code>
            <span>Not Before (Unix)</span>
        </div>
        <div class="claim-card">
            <code>iat</code>
            <span>Issued At (Unix)</span>
        </div>
        <div class="claim-card">
            <code>jti</code>
            <span>JWT ID - Identifiant unique</span>
        </div>
    </div>
</div>

<div class="examples-section">
    <h3>Exemples</h3>
    <div class="examples-grid">
        <button onclick="loadExample('basic')">JWT Simple</button>
        <button onclick="loadExample('expired')">JWT Expire</button>
        <button onclick="loadExample('rs256')">RS256</button>
    </div>
</div>

</div>

## Structure JWT

```
xxxxx.yyyyy.zzzzz
  |      |     |
  |      |     +-- Signature
  |      +-------- Payload (Base64URL)
  +--------------- Header (Base64URL)
```

## Verification en CLI

```bash
# Decoder sans verifier (jq)
echo "eyJhbG..." | cut -d. -f2 | base64 -d 2>/dev/null | jq

# Avec jwt-cli
jwt decode eyJhbGciOiJI...

# Python
python -c "import jwt; print(jwt.decode('token', options={'verify_signature': False}))"

# Verifier signature
jwt verify -S "secret" eyJhbGciOiJI...
```

<style>
.tool-container {
    background: var(--md-code-bg-color);
    padding: 20px;
    border-radius: 8px;
    margin: 20px 0;
}
.mode-selector {
    display: flex;
    gap: 10px;
    margin-bottom: 20px;
}
.mode-btn {
    padding: 10px 20px;
    background: var(--md-default-bg-color);
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    cursor: pointer;
}
.mode-btn.active {
    background: var(--md-primary-fg-color);
    color: white;
    border-color: var(--md-primary-fg-color);
}
.input-section, .decoded-section, .encode-grid, .secret-section, .output-section, .claims-section, .examples-section {
    background: var(--md-default-bg-color);
    padding: 20px;
    border-radius: 4px;
    margin-bottom: 20px;
}
.input-section h3, .claims-section h3, .examples-section h3 {
    margin: 0 0 15px 0;
}
.input-section textarea, .encode-column textarea {
    width: 100%;
    min-height: 100px;
    padding: 12px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 12px;
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    background: var(--md-code-bg-color);
    color: var(--md-default-fg-color);
    word-break: break-all;
}
.jwt-part {
    background: var(--md-code-bg-color);
    padding: 15px;
    border-radius: 4px;
    margin-bottom: 15px;
}
.jwt-part h4 {
    margin: 0 0 10px 0;
    display: flex;
    align-items: center;
    gap: 10px;
}
.jwt-color {
    font-size: 11px;
    padding: 2px 8px;
    border-radius: 10px;
    color: white;
}
.jwt-color.header { background: #e74c3c; }
.jwt-color.payload { background: #9b59b6; }
.jwt-color.signature { background: #3498db; }
.jwt-part pre {
    margin: 0;
    padding: 10px;
    background: var(--md-default-bg-color);
    border-radius: 4px;
    overflow-x: auto;
    font-size: 12px;
}
.encode-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 20px;
}
@media (max-width: 768px) {
    .encode-grid {
        grid-template-columns: 1fr;
    }
}
.encode-column h4 {
    margin: 0 0 10px 0;
}
.secret-section {
    display: flex;
    gap: 15px;
    align-items: center;
    flex-wrap: wrap;
}
.secret-section label {
    font-weight: bold;
    font-size: 14px;
}
.secret-section input {
    flex: 1;
    min-width: 200px;
    padding: 10px;
    font-family: monospace;
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    background: var(--md-code-bg-color);
    color: var(--md-default-fg-color);
}
.encode-btn, .copy-btn {
    padding: 10px 20px;
    background: var(--md-primary-fg-color);
    color: white;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    font-weight: bold;
}
.output-section h4 {
    margin: 0 0 10px 0;
}
.jwt-display {
    background: var(--md-code-bg-color);
    padding: 15px;
    border-radius: 4px;
    font-family: monospace;
    font-size: 12px;
    word-break: break-all;
    margin-bottom: 10px;
}
.claims-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
    gap: 10px;
}
.claim-card {
    background: var(--md-code-bg-color);
    padding: 10px 15px;
    border-radius: 4px;
    display: flex;
    flex-direction: column;
    gap: 5px;
}
.claim-card code {
    font-weight: bold;
    color: var(--md-primary-fg-color);
}
.claim-card span {
    font-size: 12px;
    color: var(--md-default-fg-color--light);
}
.examples-grid {
    display: flex;
    gap: 10px;
    flex-wrap: wrap;
}
.examples-grid button {
    padding: 8px 16px;
    background: var(--md-code-bg-color);
    color: var(--md-default-fg-color);
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    cursor: pointer;
}
.examples-grid button:hover {
    background: var(--md-primary-fg-color);
    color: white;
}
.status-valid {
    color: #4caf50;
    font-weight: bold;
}
.status-expired {
    color: #f44336;
    font-weight: bold;
}
.status-warning {
    color: #ff9800;
    font-weight: bold;
}
</style>

<script>
const EXAMPLES = {
    basic: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
    expired: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiZXhwIjoxNTE2MjM5MDIyfQ.4Adcj3UFYzPUVaVF43FmMab6RlaQD8A9V8wFzzht-KQ',
    rs256: 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.NHVaYe26MbtOYhSKkoKYdFVomg4i8ZJd8_-RU8VNbftc4TSMb4bXP3l3YlNWACwyXPGffz5aXHc6lty1Y2t4SWRqGteragsVdZufDn5BlnJl9pdR_kdVFUsra2rWKEofkZeIC4yWytE58sMIihvo9H1ScmmVwBcQP6XETqYd0aSHp1gOa9RdUPDvoXQ5oqygTqVtxaDr6wUFKrKItgBMzWIdNZ6y7O9E0DhEPTbE9rfBo6KTFsHAZnMg4k68CDp2woYIaXbmYTWcvbzIuHO7_37GT79XdIwkm95QJ7hYC9RiwrV7mesbY4PAahERJawntho0my942XheVLmGwLMBkQ'
};

function base64UrlDecode(str) {
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4) str += '=';
    return atob(str);
}

function base64UrlEncode(str) {
    return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function selectMode(mode) {
    document.querySelectorAll('.mode-btn').forEach(btn => btn.classList.remove('active'));
    event.target.classList.add('active');

    document.getElementById('decode-section').style.display = mode === 'decode' ? 'block' : 'none';
    document.getElementById('encode-section').style.display = mode === 'encode' ? 'block' : 'none';
}

function decodeJWT() {
    const token = document.getElementById('jwt-input').value.trim();
    const parts = token.split('.');

    if (parts.length !== 3) {
        document.getElementById('decoded-header').textContent = 'Token invalide';
        document.getElementById('decoded-payload').textContent = 'Token invalide';
        document.getElementById('decoded-signature').textContent = '-';
        document.getElementById('jwt-status').innerHTML = '<span class="status-warning">Format JWT invalide (doit avoir 3 parties)</span>';
        return;
    }

    try {
        const header = JSON.parse(base64UrlDecode(parts[0]));
        const payload = JSON.parse(base64UrlDecode(parts[1]));

        document.getElementById('decoded-header').textContent = JSON.stringify(header, null, 2);
        document.getElementById('decoded-payload').textContent = JSON.stringify(payload, null, 2);
        document.getElementById('decoded-signature').textContent = parts[2];

        // Check expiration
        let status = '';
        const now = Math.floor(Date.now() / 1000);

        if (payload.exp) {
            const expDate = new Date(payload.exp * 1000);
            if (payload.exp < now) {
                status = `<span class="status-expired">EXPIRE</span> le ${expDate.toLocaleString()}`;
            } else {
                status = `<span class="status-valid">VALIDE</span> jusqu'au ${expDate.toLocaleString()}`;
            }
        } else {
            status = '<span class="status-warning">Pas d\'expiration definie</span>';
        }

        if (payload.iat) {
            const iatDate = new Date(payload.iat * 1000);
            status += `<br>Emis le: ${iatDate.toLocaleString()}`;
        }

        status += `<br>Algorithme: <strong>${header.alg}</strong>`;

        document.getElementById('jwt-status').innerHTML = status;

    } catch (e) {
        document.getElementById('decoded-header').textContent = 'Erreur de decodage';
        document.getElementById('decoded-payload').textContent = e.message;
        document.getElementById('jwt-status').innerHTML = '<span class="status-warning">Erreur de parsing</span>';
    }
}

async function encodeJWT() {
    try {
        const header = JSON.parse(document.getElementById('encode-header').value);
        const payload = JSON.parse(document.getElementById('encode-payload').value);
        const secret = document.getElementById('jwt-secret').value;

        const encodedHeader = base64UrlEncode(JSON.stringify(header));
        const encodedPayload = base64UrlEncode(JSON.stringify(payload));
        const message = `${encodedHeader}.${encodedPayload}`;

        // Create signature using HMAC-SHA256
        const encoder = new TextEncoder();
        const keyData = encoder.encode(secret);
        const messageData = encoder.encode(message);

        const key = await crypto.subtle.importKey(
            'raw',
            keyData,
            { name: 'HMAC', hash: 'SHA-256' },
            false,
            ['sign']
        );

        const signature = await crypto.subtle.sign('HMAC', key, messageData);
        const encodedSignature = base64UrlEncode(String.fromCharCode(...new Uint8Array(signature)));

        const jwt = `${message}.${encodedSignature}`;

        document.getElementById('encoded-jwt').textContent = jwt;
        document.getElementById('encode-output-section').style.display = 'block';

    } catch (e) {
        alert('Erreur: ' + e.message);
    }
}

function copyEncoded() {
    const jwt = document.getElementById('encoded-jwt').textContent;
    navigator.clipboard.writeText(jwt);

    const btn = event.target;
    btn.textContent = 'Copie!';
    setTimeout(() => { btn.textContent = 'Copier'; }, 1000);
}

function loadExample(type) {
    document.getElementById('jwt-input').value = EXAMPLES[type];
    decodeJWT();
    selectMode('decode');
    document.querySelectorAll('.mode-btn')[0].classList.add('active');
    document.querySelectorAll('.mode-btn')[1].classList.remove('active');
}

// Initialize with example
document.getElementById('jwt-input').value = EXAMPLES.basic;
decodeJWT();
</script>
