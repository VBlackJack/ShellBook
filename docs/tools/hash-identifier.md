---
tags:
  - tools
  - hash
  - security
  - crypto
  - identifier
---

# Hash Identifier

Identification automatique du type de hash et informations sur les algorithmes.

<div class="tool-container">

<div class="input-section">
    <h3>Identifier un Hash</h3>
    <div class="input-group">
        <label for="hash-input">Hash a identifier</label>
        <input type="text" id="hash-input" placeholder="Entrez un hash..." oninput="identifyHash()">
    </div>
    <div class="hash-info">
        <span>Longueur: <strong id="hash-length">0</strong> caracteres</span>
        <span>Type: <strong id="hash-charset">-</strong></span>
    </div>
</div>

<div class="results-section" id="results-section" style="display: none;">
    <h3>Resultats de l'identification</h3>
    <div id="hash-results"></div>
</div>

<div class="generate-section">
    <h3>Generateur de Hash</h3>
    <div class="generate-grid">
        <div class="form-group">
            <label for="gen-input">Texte a hasher</label>
            <input type="text" id="gen-input" placeholder="Entrez du texte..." value="password123">
        </div>
        <div class="form-group">
            <label for="gen-algo">Algorithme</label>
            <select id="gen-algo">
                <option value="MD5">MD5</option>
                <option value="SHA-1">SHA-1</option>
                <option value="SHA-256" selected>SHA-256</option>
                <option value="SHA-384">SHA-384</option>
                <option value="SHA-512">SHA-512</option>
            </select>
        </div>
        <button onclick="generateHash()" class="generate-btn">Generer</button>
    </div>
    <div class="output-group" id="gen-output-group" style="display: none;">
        <label>Resultat</label>
        <div class="output-row">
            <input type="text" id="gen-output" readonly>
            <button onclick="copyGenerated()" class="copy-btn">Copier</button>
        </div>
    </div>
</div>

<div class="reference-section">
    <h3>Reference des Algorithmes</h3>
    <div class="algo-grid" id="algo-grid"></div>
</div>

<div class="examples-section">
    <h3>Exemples de Hash</h3>
    <div class="examples-grid">
        <button onclick="loadExample('md5')">MD5</button>
        <button onclick="loadExample('sha1')">SHA-1</button>
        <button onclick="loadExample('sha256')">SHA-256</button>
        <button onclick="loadExample('sha512')">SHA-512</button>
        <button onclick="loadExample('bcrypt')">Bcrypt</button>
        <button onclick="loadExample('ntlm')">NTLM</button>
    </div>
</div>

</div>

## Types de Hash Courants

| Algorithme | Longueur | Usage |
|------------|----------|-------|
| **MD5** | 32 hex | Legacy, checksums |
| **SHA-1** | 40 hex | Git, legacy |
| **SHA-256** | 64 hex | Securite moderne |
| **SHA-512** | 128 hex | Haute securite |
| **Bcrypt** | 60 chars | Mots de passe |
| **NTLM** | 32 hex | Windows auth |

## Verification en CLI

```bash
# Generer des hash
echo -n "password" | md5sum
echo -n "password" | sha1sum
echo -n "password" | sha256sum
echo -n "password" | sha512sum

# Verifier un fichier
sha256sum fichier.iso
sha256sum -c checksums.txt

# Hashcat - identifier
hashcat --identify hash.txt

# John the Ripper
john --list=formats | grep -i sha
```

<style>
.tool-container {
    background: var(--md-code-bg-color);
    padding: 20px;
    border-radius: 8px;
    margin: 20px 0;
}
.input-section, .results-section, .generate-section, .reference-section, .examples-section {
    background: var(--md-default-bg-color);
    padding: 20px;
    border-radius: 4px;
    margin-bottom: 20px;
}
.input-section h3, .results-section h3, .generate-section h3, .reference-section h3, .examples-section h3 {
    margin: 0 0 15px 0;
}
.input-group {
    margin-bottom: 15px;
}
.input-group label, .form-group label {
    display: block;
    font-size: 12px;
    font-weight: bold;
    margin-bottom: 5px;
}
.input-group input {
    width: 100%;
    padding: 12px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 14px;
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    background: var(--md-code-bg-color);
    color: var(--md-default-fg-color);
}
.hash-info {
    display: flex;
    gap: 20px;
    padding: 10px;
    background: var(--md-code-bg-color);
    border-radius: 4px;
    font-size: 13px;
}
.hash-result {
    background: var(--md-code-bg-color);
    padding: 15px;
    border-radius: 4px;
    margin-bottom: 10px;
    border-left: 4px solid var(--md-primary-fg-color);
}
.hash-result.likely {
    border-left-color: #4caf50;
}
.hash-result.possible {
    border-left-color: #ff9800;
}
.hash-result .algo-name {
    font-weight: bold;
    font-size: 16px;
    margin-bottom: 5px;
}
.hash-result .algo-details {
    font-size: 12px;
    color: var(--md-default-fg-color--light);
}
.hash-result .confidence {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 10px;
    font-size: 11px;
    font-weight: bold;
    margin-left: 10px;
}
.confidence.high {
    background: #4caf50;
    color: white;
}
.confidence.medium {
    background: #ff9800;
    color: white;
}
.confidence.low {
    background: #9e9e9e;
    color: white;
}
.generate-grid {
    display: grid;
    grid-template-columns: 1fr auto auto;
    gap: 15px;
    align-items: end;
}
@media (max-width: 600px) {
    .generate-grid {
        grid-template-columns: 1fr;
    }
}
.form-group input, .form-group select {
    width: 100%;
    padding: 10px;
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    background: var(--md-code-bg-color);
    color: var(--md-default-fg-color);
    font-family: monospace;
}
.generate-btn {
    padding: 10px 20px;
    background: var(--md-primary-fg-color);
    color: white;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    font-weight: bold;
}
.output-group {
    margin-top: 15px;
}
.output-group label {
    display: block;
    font-size: 12px;
    font-weight: bold;
    margin-bottom: 5px;
}
.output-row {
    display: flex;
    gap: 10px;
}
.output-row input {
    flex: 1;
    padding: 10px;
    font-family: 'JetBrains Mono', monospace;
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    background: var(--md-code-bg-color);
    color: var(--md-default-fg-color);
}
.copy-btn {
    padding: 10px 15px;
    background: var(--md-primary-fg-color);
    color: white;
    border: none;
    border-radius: 4px;
    cursor: pointer;
}
.algo-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
    gap: 15px;
}
.algo-card {
    background: var(--md-code-bg-color);
    padding: 15px;
    border-radius: 4px;
}
.algo-card h4 {
    margin: 0 0 10px 0;
    display: flex;
    align-items: center;
    gap: 10px;
}
.algo-card .status {
    font-size: 10px;
    padding: 2px 6px;
    border-radius: 3px;
}
.status.secure {
    background: #4caf50;
    color: white;
}
.status.weak {
    background: #f44336;
    color: white;
}
.status.deprecated {
    background: #ff9800;
    color: white;
}
.algo-card table {
    width: 100%;
    font-size: 12px;
}
.algo-card td {
    padding: 3px 0;
}
.algo-card td:first-child {
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
</style>

<script>
const HASH_PATTERNS = [
    { name: 'MD5', regex: /^[a-f0-9]{32}$/i, length: 32, hashcat: 0, john: 'Raw-MD5' },
    { name: 'SHA-1', regex: /^[a-f0-9]{40}$/i, length: 40, hashcat: 100, john: 'Raw-SHA1' },
    { name: 'SHA-224', regex: /^[a-f0-9]{56}$/i, length: 56, hashcat: 1300, john: 'Raw-SHA224' },
    { name: 'SHA-256', regex: /^[a-f0-9]{64}$/i, length: 64, hashcat: 1400, john: 'Raw-SHA256' },
    { name: 'SHA-384', regex: /^[a-f0-9]{96}$/i, length: 96, hashcat: 10800, john: 'Raw-SHA384' },
    { name: 'SHA-512', regex: /^[a-f0-9]{128}$/i, length: 128, hashcat: 1700, john: 'Raw-SHA512' },
    { name: 'NTLM', regex: /^[a-f0-9]{32}$/i, length: 32, hashcat: 1000, john: 'NT' },
    { name: 'LM', regex: /^[a-f0-9]{32}$/i, length: 32, hashcat: 3000, john: 'LM' },
    { name: 'MySQL 4.1+', regex: /^\*[a-f0-9]{40}$/i, length: 41, hashcat: 300, john: 'mysql-sha1' },
    { name: 'MySQL 3.x', regex: /^[a-f0-9]{16}$/i, length: 16, hashcat: 200, john: 'mysql' },
    { name: 'Bcrypt', regex: /^\$2[ayb]\$\d{2}\$[./A-Za-z0-9]{53}$/, length: 60, hashcat: 3200, john: 'bcrypt' },
    { name: 'MD5 Crypt', regex: /^\$1\$[./0-9A-Za-z]{8}\$[./0-9A-Za-z]{22}$/, length: null, hashcat: 500, john: 'md5crypt' },
    { name: 'SHA-256 Crypt', regex: /^\$5\$[./0-9A-Za-z]{16}\$[./0-9A-Za-z]{43}$/, length: null, hashcat: 7400, john: 'sha256crypt' },
    { name: 'SHA-512 Crypt', regex: /^\$6\$[./0-9A-Za-z]{16}\$[./0-9A-Za-z]{86}$/, length: null, hashcat: 1800, john: 'sha512crypt' },
    { name: 'APR1 (Apache)', regex: /^\$apr1\$[./0-9A-Za-z]{8}\$[./0-9A-Za-z]{22}$/, length: null, hashcat: 1600, john: 'md5apr1' },
    { name: 'RIPEMD-160', regex: /^[a-f0-9]{40}$/i, length: 40, hashcat: 6000, john: 'ripemd-160' },
    { name: 'Whirlpool', regex: /^[a-f0-9]{128}$/i, length: 128, hashcat: 6100, john: 'whirlpool' },
    { name: 'CRC32', regex: /^[a-f0-9]{8}$/i, length: 8, hashcat: null, john: 'CRC32' },
    { name: 'Argon2', regex: /^\$argon2(i|d|id)\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$/, length: null, hashcat: null, john: 'argon2' },
    { name: 'PBKDF2-SHA256', regex: /^pbkdf2_sha256\$\d+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+=*$/, length: null, hashcat: 10900, john: 'PBKDF2-HMAC-SHA256' }
];

const ALGORITHMS = [
    { name: 'MD5', bits: 128, hex: 32, status: 'weak', usage: 'Checksums legacy, NE PAS utiliser pour securite' },
    { name: 'SHA-1', bits: 160, hex: 40, status: 'deprecated', usage: 'Git commits, certificats legacy' },
    { name: 'SHA-256', bits: 256, hex: 64, status: 'secure', usage: 'Standard moderne, Bitcoin, TLS' },
    { name: 'SHA-384', bits: 384, hex: 96, status: 'secure', usage: 'Haute securite, TLS' },
    { name: 'SHA-512', bits: 512, hex: 128, status: 'secure', usage: 'Haute securite, Linux passwords' },
    { name: 'Bcrypt', bits: null, hex: null, status: 'secure', usage: 'Mots de passe (recommande)' },
    { name: 'Argon2', bits: null, hex: null, status: 'secure', usage: 'Mots de passe (moderne)' },
    { name: 'NTLM', bits: 128, hex: 32, status: 'weak', usage: 'Windows authentication legacy' }
];

const EXAMPLES = {
    md5: '5f4dcc3b5aa765d61d8327deb882cf99',
    sha1: '5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8',
    sha256: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
    sha512: 'b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86',
    bcrypt: '$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X.VF.GQmELdF4Kz8a',
    ntlm: 'a4f49c406510bdcab6824ee7c30fd852'
};

function identifyHash() {
    const input = document.getElementById('hash-input').value.trim();
    const resultsSection = document.getElementById('results-section');
    const resultsDiv = document.getElementById('hash-results');

    document.getElementById('hash-length').textContent = input.length;

    // Detect charset
    let charset = '-';
    if (/^[a-f0-9]+$/i.test(input)) charset = 'Hexadecimal';
    else if (/^[A-Za-z0-9+/]+=*$/.test(input)) charset = 'Base64';
    else if (/^\$/.test(input)) charset = 'Crypt format';
    document.getElementById('hash-charset').textContent = charset;

    if (input.length < 4) {
        resultsSection.style.display = 'none';
        return;
    }

    const matches = [];

    for (const pattern of HASH_PATTERNS) {
        if (pattern.regex.test(input)) {
            let confidence = 'medium';

            // Increase confidence for unique lengths
            if (pattern.length && pattern.length === input.length) {
                const sameLength = HASH_PATTERNS.filter(p => p.length === input.length);
                if (sameLength.length === 1) confidence = 'high';
            }

            // High confidence for specific prefixes
            if (input.startsWith('$2') || input.startsWith('$1$') ||
                input.startsWith('$5$') || input.startsWith('$6$') ||
                input.startsWith('$apr1$') || input.startsWith('$argon2') ||
                input.startsWith('*') || input.startsWith('pbkdf2_')) {
                confidence = 'high';
            }

            matches.push({ ...pattern, confidence });
        }
    }

    if (matches.length === 0) {
        resultsSection.style.display = 'block';
        resultsDiv.innerHTML = '<div class="hash-result"><div class="algo-name">Type inconnu</div><div class="algo-details">Aucun algorithme reconnu pour ce hash</div></div>';
        return;
    }

    // Sort by confidence
    matches.sort((a, b) => {
        const order = { high: 0, medium: 1, low: 2 };
        return order[a.confidence] - order[b.confidence];
    });

    resultsSection.style.display = 'block';
    resultsDiv.innerHTML = matches.map(m => `
        <div class="hash-result ${m.confidence === 'high' ? 'likely' : 'possible'}">
            <div class="algo-name">
                ${m.name}
                <span class="confidence ${m.confidence}">${m.confidence === 'high' ? 'Probable' : m.confidence === 'medium' ? 'Possible' : 'Peu probable'}</span>
            </div>
            <div class="algo-details">
                ${m.length ? `Longueur: ${m.length} chars` : 'Variable'} |
                ${m.hashcat !== null ? `Hashcat: -m ${m.hashcat}` : 'Hashcat: N/A'} |
                John: ${m.john}
            </div>
        </div>
    `).join('');
}

async function generateHash() {
    const input = document.getElementById('gen-input').value;
    const algo = document.getElementById('gen-algo').value;

    const encoder = new TextEncoder();
    const data = encoder.encode(input);

    let hashBuffer;

    if (algo === 'MD5') {
        // MD5 not in SubtleCrypto, use simple implementation
        hashBuffer = md5(input);
        document.getElementById('gen-output').value = hashBuffer;
    } else {
        hashBuffer = await crypto.subtle.digest(algo.replace('-', ''), data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        document.getElementById('gen-output').value = hashHex;
    }

    document.getElementById('gen-output-group').style.display = 'block';
}

// Simple MD5 implementation
function md5(string) {
    function rotateLeft(x, n) { return (x << n) | (x >>> (32 - n)); }
    function addUnsigned(x, y) {
        const x4 = (x & 0x40000000), y4 = (y & 0x40000000);
        const x8 = (x & 0x80000000), y8 = (y & 0x80000000);
        const result = (x & 0x3FFFFFFF) + (y & 0x3FFFFFFF);
        if (x4 & y4) return (result ^ 0x80000000 ^ x8 ^ y8);
        if (x4 | y4) {
            if (result & 0x40000000) return (result ^ 0xC0000000 ^ x8 ^ y8);
            else return (result ^ 0x40000000 ^ x8 ^ y8);
        } else return (result ^ x8 ^ y8);
    }
    function F(x, y, z) { return (x & y) | ((~x) & z); }
    function G(x, y, z) { return (x & z) | (y & (~z)); }
    function H(x, y, z) { return (x ^ y ^ z); }
    function I(x, y, z) { return (y ^ (x | (~z))); }
    function FF(a, b, c, d, x, s, ac) { a = addUnsigned(a, addUnsigned(addUnsigned(F(b, c, d), x), ac)); return addUnsigned(rotateLeft(a, s), b); }
    function GG(a, b, c, d, x, s, ac) { a = addUnsigned(a, addUnsigned(addUnsigned(G(b, c, d), x), ac)); return addUnsigned(rotateLeft(a, s), b); }
    function HH(a, b, c, d, x, s, ac) { a = addUnsigned(a, addUnsigned(addUnsigned(H(b, c, d), x), ac)); return addUnsigned(rotateLeft(a, s), b); }
    function II(a, b, c, d, x, s, ac) { a = addUnsigned(a, addUnsigned(addUnsigned(I(b, c, d), x), ac)); return addUnsigned(rotateLeft(a, s), b); }
    function convertToWordArray(string) {
        let messageLength = string.length;
        let numberOfWords_temp1 = messageLength + 8;
        let numberOfWords_temp2 = (numberOfWords_temp1 - (numberOfWords_temp1 % 64)) / 64;
        let numberOfWords = (numberOfWords_temp2 + 1) * 16;
        let wordArray = Array(numberOfWords - 1);
        let wordCount, bytePosition = 0, byteCount = 0;
        while (byteCount < messageLength) {
            wordCount = (byteCount - (byteCount % 4)) / 4;
            bytePosition = (byteCount % 4) * 8;
            wordArray[wordCount] = (wordArray[wordCount] || 0) | (string.charCodeAt(byteCount) << bytePosition);
            byteCount++;
        }
        wordCount = (byteCount - (byteCount % 4)) / 4;
        bytePosition = (byteCount % 4) * 8;
        wordArray[wordCount] = (wordArray[wordCount] || 0) | (0x80 << bytePosition);
        wordArray[numberOfWords - 2] = messageLength << 3;
        wordArray[numberOfWords - 1] = messageLength >>> 29;
        return wordArray;
    }
    function wordToHex(value) {
        let hex = '', temp, byte;
        for (byte = 0; byte <= 3; byte++) {
            temp = (value >>> (byte * 8)) & 255;
            hex += ('0' + temp.toString(16)).slice(-2);
        }
        return hex;
    }

    let x = convertToWordArray(string);
    let a = 0x67452301, b = 0xEFCDAB89, c = 0x98BADCFE, d = 0x10325476;
    const S = [7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21];
    const K = [
        0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE, 0xF57C0FAF, 0x4787C62A, 0xA8304613, 0xFD469501,
        0x698098D8, 0x8B44F7AF, 0xFFFF5BB1, 0x895CD7BE, 0x6B901122, 0xFD987193, 0xA679438E, 0x49B40821,
        0xF61E2562, 0xC040B340, 0x265E5A51, 0xE9B6C7AA, 0xD62F105D, 0x02441453, 0xD8A1E681, 0xE7D3FBC8,
        0x21E1CDE6, 0xC33707D6, 0xF4D50D87, 0x455A14ED, 0xA9E3E905, 0xFCEFA3F8, 0x676F02D9, 0x8D2A4C8A,
        0xFFFA3942, 0x8771F681, 0x6D9D6122, 0xFDE5380C, 0xA4BEEA44, 0x4BDECFA9, 0xF6BB4B60, 0xBEBFBC70,
        0x289B7EC6, 0xEAA127FA, 0xD4EF3085, 0x04881D05, 0xD9D4D039, 0xE6DB99E5, 0x1FA27CF8, 0xC4AC5665,
        0xF4292244, 0x432AFF97, 0xAB9423A7, 0xFC93A039, 0x655B59C3, 0x8F0CCC92, 0xFFEFF47D, 0x85845DD1,
        0x6FA87E4F, 0xFE2CE6E0, 0xA3014314, 0x4E0811A1, 0xF7537E82, 0xBD3AF235, 0x2AD7D2BB, 0xEB86D391
    ];

    for (let k = 0; k < x.length; k += 16) {
        let AA = a, BB = b, CC = c, DD = d;
        for (let i = 0; i < 64; i++) {
            let f, g;
            if (i < 16) { f = F(b, c, d); g = i; }
            else if (i < 32) { f = G(b, c, d); g = (5 * i + 1) % 16; }
            else if (i < 48) { f = H(b, c, d); g = (3 * i + 5) % 16; }
            else { f = I(b, c, d); g = (7 * i) % 16; }
            let temp = d;
            d = c;
            c = b;
            b = addUnsigned(b, rotateLeft(addUnsigned(a, addUnsigned(addUnsigned(f, K[i]), x[k + g] || 0)), S[Math.floor(i / 16) * 4 + (i % 4)]));
            a = temp;
        }
        a = addUnsigned(a, AA);
        b = addUnsigned(b, BB);
        c = addUnsigned(c, CC);
        d = addUnsigned(d, DD);
    }
    return (wordToHex(a) + wordToHex(b) + wordToHex(c) + wordToHex(d)).toLowerCase();
}

function copyGenerated() {
    const output = document.getElementById('gen-output');
    output.select();
    document.execCommand('copy');

    const btn = event.target;
    btn.textContent = 'Copie!';
    setTimeout(() => { btn.textContent = 'Copier'; }, 1000);
}

function loadExample(type) {
    document.getElementById('hash-input').value = EXAMPLES[type];
    identifyHash();
}

function buildAlgoGrid() {
    const grid = document.getElementById('algo-grid');
    grid.innerHTML = ALGORITHMS.map(algo => `
        <div class="algo-card">
            <h4>
                ${algo.name}
                <span class="status ${algo.status}">${algo.status === 'secure' ? 'Sur' : algo.status === 'weak' ? 'Faible' : 'Obsolete'}</span>
            </h4>
            <table>
                <tr><td>Bits:</td><td>${algo.bits || 'Variable'}</td></tr>
                <tr><td>Hex:</td><td>${algo.hex || 'Variable'} chars</td></tr>
                <tr><td>Usage:</td><td>${algo.usage}</td></tr>
            </table>
        </div>
    `).join('');
}

// Initialize
buildAlgoGrid();
</script>
