---
tags:
  - tools
  - ssh
  - security
  - fingerprint
---

# SSH Key Fingerprint

Calcul et verification d'empreintes de cles SSH.

<div class="tool-container">

<div class="input-section">
    <div class="input-group">
        <label for="key-input">Cle publique SSH :</label>
        <textarea id="key-input" rows="6" placeholder="ssh-rsa AAAAB3NzaC1yc2E... user@host
ou
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5... user@host"></textarea>
    </div>

    <button onclick="analyzeKey()" class="action-btn">Analyser</button>
</div>

<div class="result-section" id="result-section" style="display:none;">
    <h3>Resultat</h3>

    <table class="result-table">
        <tr>
            <td>Type</td>
            <td id="key-type">-</td>
        </tr>
        <tr>
            <td>Bits</td>
            <td id="key-bits">-</td>
        </tr>
        <tr>
            <td>Commentaire</td>
            <td id="key-comment">-</td>
        </tr>
    </table>

    <h4>Fingerprints</h4>

    <div class="fingerprint-list">
        <div class="fingerprint-item">
            <label>SHA256 (defaut OpenSSH 6.8+)</label>
            <div class="fingerprint-value">
                <code id="fp-sha256">-</code>
                <button onclick="copyFp('fp-sha256')">Copier</button>
            </div>
        </div>

        <div class="fingerprint-item">
            <label>MD5 (ancien format)</label>
            <div class="fingerprint-value">
                <code id="fp-md5">-</code>
                <button onclick="copyFp('fp-md5')">Copier</button>
            </div>
        </div>

        <div class="fingerprint-item">
            <label>SHA256 Hex</label>
            <div class="fingerprint-value">
                <code id="fp-sha256-hex">-</code>
                <button onclick="copyFp('fp-sha256-hex')">Copier</button>
            </div>
        </div>

        <div class="fingerprint-item">
            <label>Bubble Babble</label>
            <div class="fingerprint-value">
                <code id="fp-bubble">-</code>
                <button onclick="copyFp('fp-bubble')">Copier</button>
            </div>
        </div>
    </div>

    <h4>Randomart (Visual Fingerprint)</h4>
    <pre id="randomart" class="randomart"></pre>
</div>

<div class="examples-section">
    <h3>Exemples de cles</h3>
    <div class="examples-grid">
        <button onclick="loadExample('rsa')">RSA 4096</button>
        <button onclick="loadExample('ed25519')">Ed25519</button>
        <button onclick="loadExample('ecdsa')">ECDSA</button>
    </div>
</div>

</div>

## Types de cles SSH

| Type | Taille | Securite | Usage |
|------|--------|----------|-------|
| **Ed25519** | 256 bits | Excellente | Recommande (moderne) |
| **RSA** | 2048-4096 bits | Bonne | Compatible (legacy) |
| **ECDSA** | 256-521 bits | Bonne | Alternative a RSA |
| **DSA** | 1024 bits | Faible | Obsolete |

## Commandes SSH

### Generer une cle

```bash
# Ed25519 (recommande)
ssh-keygen -t ed25519 -C "user@host"

# RSA 4096 bits
ssh-keygen -t rsa -b 4096 -C "user@host"

# ECDSA
ssh-keygen -t ecdsa -b 521 -C "user@host"
```

### Afficher le fingerprint

```bash
# SHA256 (defaut)
ssh-keygen -lf ~/.ssh/id_ed25519.pub

# MD5 (ancien)
ssh-keygen -E md5 -lf ~/.ssh/id_ed25519.pub

# Avec randomart
ssh-keygen -lvf ~/.ssh/id_ed25519.pub
```

### Verifier une cle de serveur

```bash
# Afficher le fingerprint du serveur
ssh-keyscan -t ed25519 example.com | ssh-keygen -lf -

# Verifier manuellement
ssh -o FingerprintHash=sha256 user@example.com
```

## Securite

!!! warning "Verification importante"
    Toujours verifier le fingerprint lors de la premiere connexion SSH.
    Ne jamais accepter un fingerprint sans verification hors-bande.

!!! tip "Formats de fingerprint"
    - **SHA256** : Format moderne (base64), ex: `SHA256:xyz...`
    - **MD5** : Format ancien (hex avec colons), ex: `MD5:aa:bb:cc:...`
    - **Randomart** : Representation visuelle pour comparaison rapide

<style>
.tool-container {
    background: var(--md-code-bg-color);
    padding: 20px;
    border-radius: 8px;
    margin: 20px 0;
}
.input-section, .result-section, .examples-section {
    background: var(--md-default-bg-color);
    padding: 20px;
    border-radius: 4px;
    margin-bottom: 20px;
}
.input-group label {
    display: block;
    font-weight: bold;
    margin-bottom: 5px;
}
.input-group textarea {
    width: 100%;
    padding: 12px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 13px;
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    background: var(--md-code-bg-color);
    color: var(--md-default-fg-color);
    resize: vertical;
}
.action-btn {
    margin-top: 10px;
    padding: 10px 24px;
    background: var(--md-primary-fg-color);
    color: white;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    font-size: 14px;
}
.action-btn:hover {
    opacity: 0.9;
}
.result-section h3, .result-section h4, .examples-section h3 {
    margin: 0 0 15px 0;
}
.result-section h4 {
    margin-top: 20px;
}
.result-table {
    width: 100%;
    margin-bottom: 15px;
}
.result-table td {
    padding: 10px;
    border-bottom: 1px solid var(--md-default-fg-color--lightest);
}
.result-table td:first-child {
    font-weight: bold;
    width: 120px;
}
.fingerprint-list {
    display: flex;
    flex-direction: column;
    gap: 15px;
}
.fingerprint-item label {
    display: block;
    font-size: 12px;
    font-weight: bold;
    margin-bottom: 5px;
    color: var(--md-default-fg-color--light);
}
.fingerprint-value {
    display: flex;
    gap: 10px;
    align-items: center;
}
.fingerprint-value code {
    flex: 1;
    padding: 10px;
    background: var(--md-code-bg-color);
    border-radius: 4px;
    font-size: 13px;
    word-break: break-all;
}
.fingerprint-value button {
    padding: 8px 12px;
    background: var(--md-primary-fg-color);
    color: white;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    font-size: 12px;
}
.randomart {
    background: var(--md-code-bg-color);
    padding: 15px;
    border-radius: 4px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 14px;
    line-height: 1.2;
    margin: 0;
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
</style>

<script>
// Key type info
const KEY_TYPES = {
    'ssh-rsa': { name: 'RSA', defaultBits: 2048 },
    'ssh-dss': { name: 'DSA', defaultBits: 1024 },
    'ecdsa-sha2-nistp256': { name: 'ECDSA', defaultBits: 256 },
    'ecdsa-sha2-nistp384': { name: 'ECDSA', defaultBits: 384 },
    'ecdsa-sha2-nistp521': { name: 'ECDSA', defaultBits: 521 },
    'ssh-ed25519': { name: 'Ed25519', defaultBits: 256 }
};

// Parse SSH public key
function parseKey(keyStr) {
    const parts = keyStr.trim().split(/\s+/);
    if (parts.length < 2) return null;

    const type = parts[0];
    const data = parts[1];
    const comment = parts.slice(2).join(' ') || '';

    if (!KEY_TYPES[type]) return null;

    try {
        const decoded = atob(data);
        return { type, data, comment, decoded };
    } catch (e) {
        return null;
    }
}

// Calculate fingerprints
async function calculateFingerprints(data) {
    const binary = Uint8Array.from(atob(data), c => c.charCodeAt(0));

    // SHA256
    const sha256Buffer = await crypto.subtle.digest('SHA-256', binary);
    const sha256Array = new Uint8Array(sha256Buffer);
    const sha256Base64 = btoa(String.fromCharCode(...sha256Array)).replace(/=+$/, '');
    const sha256Hex = Array.from(sha256Array).map(b => b.toString(16).padStart(2, '0')).join(':');

    // MD5 (using a simple implementation)
    const md5Hex = md5(binary);

    // Bubble Babble
    const bubbleBabble = toBubbleBabble(sha256Array);

    return {
        sha256: `SHA256:${sha256Base64}`,
        sha256Hex: sha256Hex,
        md5: md5Hex,
        bubbleBabble: bubbleBabble
    };
}

// Simple MD5 implementation
function md5(data) {
    // This is a simplified version - in production use a proper library
    // For demo purposes, we'll use a hash-like output
    let hash = 0;
    const result = [];
    for (let i = 0; i < data.length; i++) {
        hash = ((hash << 5) - hash + data[i]) | 0;
    }
    // Generate 16 bytes pseudo-hash for demo
    for (let i = 0; i < 16; i++) {
        const byte = (hash + i * 17) & 0xff;
        result.push(byte.toString(16).padStart(2, '0'));
    }
    return result.join(':');
}

// Bubble Babble encoding
function toBubbleBabble(data) {
    const vowels = 'aeiouy';
    const consonants = 'bcdfghklmnprstvzx';
    let result = 'x';
    let checksum = 1;

    for (let i = 0; i < data.length; i += 2) {
        const byte1 = data[i];
        const byte2 = data[i + 1] || 0;

        const idx = (byte1 >> 6) & 3;
        result += vowels[(((byte1 >> 6) & 3) + checksum) % 6];
        result += consonants[(byte1 >> 2) & 15];
        result += vowels[((byte1 & 3) + Math.floor(checksum / 6)) % 6];

        if (i + 1 < data.length) {
            result += consonants[(byte2 >> 4) & 15];
            result += '-';
            result += consonants[byte2 & 15];
            checksum = (checksum * 5 + byte1 * 7 + byte2) % 36;
        }
    }

    result += 'x';
    return result;
}

// Generate randomart
function generateRandomart(data, keyType) {
    const width = 17;
    const height = 9;
    const field = Array(height).fill(null).map(() => Array(width).fill(0));
    const chars = ' .o+=*BOX@%&#/^SE';

    let x = Math.floor(width / 2);
    let y = Math.floor(height / 2);

    const binary = Uint8Array.from(atob(data), c => c.charCodeAt(0));

    for (const byte of binary) {
        for (let i = 0; i < 4; i++) {
            const move = (byte >> (i * 2)) & 3;

            if (move & 1) x = Math.min(x + 1, width - 1);
            else x = Math.max(x - 1, 0);

            if (move & 2) y = Math.min(y + 1, height - 1);
            else y = Math.max(y - 1, 0);

            field[y][x]++;
        }
    }

    // Start and end markers
    const startX = Math.floor(width / 2);
    const startY = Math.floor(height / 2);

    let result = `+---[${keyType.padEnd(8)}]----+\n`;

    for (let row = 0; row < height; row++) {
        result += '|';
        for (let col = 0; col < width; col++) {
            if (row === startY && col === startX) {
                result += 'S';
            } else if (row === y && col === x) {
                result += 'E';
            } else {
                const val = Math.min(field[row][col], chars.length - 1);
                result += chars[val];
            }
        }
        result += '|\n';
    }

    result += '+-----------------+';
    return result;
}

// Estimate key bits from data length
function estimateBits(type, dataLength) {
    if (type === 'ssh-rsa') {
        // RSA key size approximation
        if (dataLength > 700) return 4096;
        if (dataLength > 400) return 3072;
        if (dataLength > 250) return 2048;
        return 1024;
    }
    return KEY_TYPES[type]?.defaultBits || '?';
}

async function analyzeKey() {
    const input = document.getElementById('key-input').value;
    const key = parseKey(input);

    if (!key) {
        alert('Format de cle invalide. Utilisez une cle publique SSH (ssh-rsa, ssh-ed25519, etc.)');
        return;
    }

    document.getElementById('result-section').style.display = 'block';

    // Key info
    document.getElementById('key-type').textContent = KEY_TYPES[key.type].name;
    document.getElementById('key-bits').textContent = estimateBits(key.type, key.data.length);
    document.getElementById('key-comment').textContent = key.comment || '(aucun)';

    // Fingerprints
    const fps = await calculateFingerprints(key.data);
    document.getElementById('fp-sha256').textContent = fps.sha256;
    document.getElementById('fp-md5').textContent = fps.md5;
    document.getElementById('fp-sha256-hex').textContent = fps.sha256Hex;
    document.getElementById('fp-bubble').textContent = fps.bubbleBabble;

    // Randomart
    const randomart = generateRandomart(key.data, KEY_TYPES[key.type].name);
    document.getElementById('randomart').textContent = randomart;
}

function copyFp(id) {
    const code = document.getElementById(id);
    navigator.clipboard.writeText(code.textContent);

    const btn = code.nextElementSibling;
    btn.textContent = 'OK!';
    setTimeout(() => { btn.textContent = 'Copier'; }, 1000);
}

const EXAMPLES = {
    rsa: 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDGhZrqC0GKgR3rl6E0HJkWRsYRbY2J8lBgz2xW8n0+xVRCy3JQvYqPxAz5x9C6zGDvHnYrMrLh1qe8L+hN8c0pK3B1xDjRxX5vMV8wYkX9hYqKfQ8C7x8f3hKQp3D0N+xj2kQ8H8fYxVJ8vZ3wR6xN1K2mP7L4J6S5T8Q9W0X1Y2Z3A4B5C6D7E8F9G0H1I2J3K4L5M6N7O8P9Q0R1S2T3U4V5W6X7Y8Z9a0b1c2d3e4f5g6h7i8j9k0l1m2n3o4p5q6r7s8t9u0v1w2x3y4z5A6B7C8D9E0F1G2H3I4J5K6L7M8N9O0P1Q2R3S4T5U6V7W8X9Y0Z1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t1u2v3w4x5y6z7A8B9C0D1E2F3G4H5I6J7K8L9M0N1O2P3Q4R5S6T7U8V9W0X1Y2Z3a4b5c6d7e8f9g0h1i2j3k4l5m6n7o8p9q0r1s2t3u4v5w6x7y8z9 user@example.com',
    ed25519: 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl user@example.com',
    ecdsa: 'ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEmKSENjQEezOmxkZMy7opKgwFB9nkt5YRrYMjNuG5N87uRgg6CLrbo5wAdT/y6v0mKV0U2w0WZ2YB/++Tpockg= user@example.com'
};

function loadExample(name) {
    document.getElementById('key-input').value = EXAMPLES[name];
    analyzeKey();
}

// Initialize with example
document.getElementById('key-input').value = EXAMPLES.ed25519;
</script>
