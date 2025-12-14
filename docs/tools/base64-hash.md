---
tags:
  - tools
  - encoding
  - hash
  - security
---

# Base64 & Hash Tool

Encodage Base64 et calcul de hash (MD5, SHA-256, etc.).

<div class="tool-container">

<h3>Encodage Base64</h3>

<div class="dual-panel">
    <div class="panel">
        <label>Texte clair :</label>
        <textarea id="b64-plain" rows="4" placeholder="Texte a encoder..."></textarea>
        <button onclick="encodeBase64()" class="action-btn">Encoder &rarr;</button>
    </div>
    <div class="panel">
        <label>Base64 :</label>
        <textarea id="b64-encoded" rows="4" placeholder="Texte encode..."></textarea>
        <button onclick="decodeBase64()" class="action-btn">&larr; Decoder</button>
    </div>
</div>

<div class="options-row">
    <label><input type="checkbox" id="b64-url"> URL-safe (- _ au lieu de + /)</label>
    <label><input type="checkbox" id="b64-nowrap"> Sans retours ligne</label>
</div>

<h3>Calcul de Hash</h3>

<div class="input-group">
    <label for="hash-input">Texte a hasher :</label>
    <textarea id="hash-input" rows="3" placeholder="Entrez le texte..."></textarea>
</div>

<div class="hash-results">
    <div class="hash-row">
        <span class="hash-label">MD5</span>
        <input type="text" id="hash-md5" readonly>
        <button onclick="copyHash('hash-md5')" class="copy-btn">&#128203;</button>
    </div>
    <div class="hash-row">
        <span class="hash-label">SHA-1</span>
        <input type="text" id="hash-sha1" readonly>
        <button onclick="copyHash('hash-sha1')" class="copy-btn">&#128203;</button>
    </div>
    <div class="hash-row">
        <span class="hash-label">SHA-256</span>
        <input type="text" id="hash-sha256" readonly>
        <button onclick="copyHash('hash-sha256')" class="copy-btn">&#128203;</button>
    </div>
    <div class="hash-row">
        <span class="hash-label">SHA-384</span>
        <input type="text" id="hash-sha384" readonly>
        <button onclick="copyHash('hash-sha384')" class="copy-btn">&#128203;</button>
    </div>
    <div class="hash-row">
        <span class="hash-label">SHA-512</span>
        <input type="text" id="hash-sha512" readonly>
        <button onclick="copyHash('hash-sha512')" class="copy-btn">&#128203;</button>
    </div>
</div>

<h3>Verification de Hash</h3>

<div class="verify-section">
    <div class="input-group">
        <label>Hash a verifier :</label>
        <input type="text" id="verify-hash" placeholder="Collez un hash MD5, SHA-1, SHA-256...">
    </div>
    <div id="verify-result" class="verify-result"></div>
</div>

</div>

## Reference

### Base64

| Commande | Description |
|----------|-------------|
| `echo -n "text" \| base64` | Encoder |
| `echo "dGV4dA==" \| base64 -d` | Decoder |
| `openssl base64 -in file` | Encoder fichier |
| `openssl base64 -d -in file` | Decoder fichier |

### Hash en ligne de commande

```bash
# MD5
echo -n "text" | md5sum
md5sum fichier.txt

# SHA-256
echo -n "text" | sha256sum
sha256sum fichier.txt

# SHA-512
echo -n "text" | sha512sum

# OpenSSL (tous les algos)
openssl dgst -md5 fichier.txt
openssl dgst -sha256 fichier.txt
```

### Tailles de hash

| Algorithme | Bits | Caracteres hex |
|------------|------|----------------|
| MD5 | 128 | 32 |
| SHA-1 | 160 | 40 |
| SHA-256 | 256 | 64 |
| SHA-384 | 384 | 96 |
| SHA-512 | 512 | 128 |

!!! warning "MD5 et SHA-1"
    MD5 et SHA-1 sont considered **cryptographiquement faibles**.
    Utilisez SHA-256 ou superieur pour la securite.

<style>
.tool-container {
    background: var(--md-code-bg-color);
    padding: 20px;
    border-radius: 8px;
    margin: 20px 0;
}
.dual-panel {
    display: flex;
    gap: 20px;
    flex-wrap: wrap;
}
.panel {
    flex: 1;
    min-width: 280px;
}
.panel label {
    display: block;
    font-weight: bold;
    margin-bottom: 5px;
}
.panel textarea {
    width: 100%;
    padding: 10px;
    font-family: monospace;
    font-size: 14px;
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    background: var(--md-default-bg-color);
    color: var(--md-default-fg-color);
    resize: vertical;
}
.action-btn {
    margin-top: 10px;
    padding: 8px 16px;
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
.options-row {
    margin: 15px 0;
    padding: 10px;
    background: var(--md-default-bg-color);
    border-radius: 4px;
}
.options-row label {
    margin-right: 20px;
    cursor: pointer;
}
.input-group {
    margin: 15px 0;
}
.input-group label {
    display: block;
    font-weight: bold;
    margin-bottom: 5px;
}
.input-group textarea, .input-group input {
    width: 100%;
    padding: 10px;
    font-family: monospace;
    font-size: 14px;
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    background: var(--md-default-bg-color);
    color: var(--md-default-fg-color);
}
.hash-results {
    background: var(--md-default-bg-color);
    padding: 15px;
    border-radius: 4px;
    margin-top: 15px;
}
.hash-row {
    display: flex;
    align-items: center;
    gap: 10px;
    margin: 10px 0;
}
.hash-label {
    min-width: 80px;
    font-weight: bold;
    font-size: 13px;
}
.hash-row input {
    flex: 1;
    padding: 8px;
    font-family: monospace;
    font-size: 12px;
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    background: var(--md-code-bg-color);
    color: var(--md-default-fg-color);
}
.copy-btn {
    padding: 8px 12px;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    background: var(--md-primary-fg-color);
    color: white;
}
.verify-section {
    background: var(--md-default-bg-color);
    padding: 15px;
    border-radius: 4px;
    margin-top: 15px;
}
.verify-result {
    margin-top: 10px;
    padding: 10px;
    border-radius: 4px;
    font-weight: bold;
}
.verify-result.match {
    background: #d4edda;
    color: #155724;
}
.verify-result.no-match {
    background: #f8d7da;
    color: #721c24;
}
</style>

<script>
function encodeBase64() {
    const plain = document.getElementById('b64-plain').value;
    const urlSafe = document.getElementById('b64-url').checked;

    try {
        let encoded = btoa(unescape(encodeURIComponent(plain)));
        if (urlSafe) {
            encoded = encoded.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
        }
        document.getElementById('b64-encoded').value = encoded;
    } catch (e) {
        alert('Erreur encodage: ' + e.message);
    }
}

function decodeBase64() {
    let encoded = document.getElementById('b64-encoded').value;
    const urlSafe = document.getElementById('b64-url').checked;

    try {
        if (urlSafe) {
            encoded = encoded.replace(/-/g, '+').replace(/_/g, '/');
            // Add padding if needed
            while (encoded.length % 4) encoded += '=';
        }
        const plain = decodeURIComponent(escape(atob(encoded)));
        document.getElementById('b64-plain').value = plain;
    } catch (e) {
        alert('Erreur decodage: ' + e.message);
    }
}

async function computeHash(text, algo) {
    const encoder = new TextEncoder();
    const data = encoder.encode(text);
    const hashBuffer = await crypto.subtle.digest(algo, data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// MD5 implementation (not in Web Crypto API)
function md5(string) {
    function rotateLeft(x, n) {
        return (x << n) | (x >>> (32 - n));
    }

    function addUnsigned(x, y) {
        const x4 = (x & 0x40000000);
        const y4 = (y & 0x40000000);
        const x8 = (x & 0x80000000);
        const y8 = (y & 0x80000000);
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

    function FF(a, b, c, d, x, s, ac) {
        a = addUnsigned(a, addUnsigned(addUnsigned(F(b, c, d), x), ac));
        return addUnsigned(rotateLeft(a, s), b);
    }
    function GG(a, b, c, d, x, s, ac) {
        a = addUnsigned(a, addUnsigned(addUnsigned(G(b, c, d), x), ac));
        return addUnsigned(rotateLeft(a, s), b);
    }
    function HH(a, b, c, d, x, s, ac) {
        a = addUnsigned(a, addUnsigned(addUnsigned(H(b, c, d), x), ac));
        return addUnsigned(rotateLeft(a, s), b);
    }
    function II(a, b, c, d, x, s, ac) {
        a = addUnsigned(a, addUnsigned(addUnsigned(I(b, c, d), x), ac));
        return addUnsigned(rotateLeft(a, s), b);
    }

    function convertToWordArray(str) {
        let wordCount;
        const messageLength = str.length;
        const temp1 = messageLength + 8;
        const temp2 = (temp1 - (temp1 % 64)) / 64;
        const numberOfWords = (temp2 + 1) * 16;
        const wordArray = Array(numberOfWords - 1);
        let bytePosition = 0;
        let byteCount = 0;
        while (byteCount < messageLength) {
            wordCount = (byteCount - (byteCount % 4)) / 4;
            bytePosition = (byteCount % 4) * 8;
            wordArray[wordCount] = (wordArray[wordCount] | (str.charCodeAt(byteCount) << bytePosition));
            byteCount++;
        }
        wordCount = (byteCount - (byteCount % 4)) / 4;
        bytePosition = (byteCount % 4) * 8;
        wordArray[wordCount] = wordArray[wordCount] | (0x80 << bytePosition);
        wordArray[numberOfWords - 2] = messageLength << 3;
        wordArray[numberOfWords - 1] = messageLength >>> 29;
        return wordArray;
    }

    function wordToHex(value) {
        let hex = "", temp, byte;
        for (let count = 0; count <= 3; count++) {
            byte = (value >>> (count * 8)) & 255;
            temp = "0" + byte.toString(16);
            hex = hex + temp.substr(temp.length - 2, 2);
        }
        return hex;
    }

    const x = convertToWordArray(unescape(encodeURIComponent(string)));
    let a = 0x67452301, b = 0xEFCDAB89, c = 0x98BADCFE, d = 0x10325476;

    const S11 = 7, S12 = 12, S13 = 17, S14 = 22;
    const S21 = 5, S22 = 9, S23 = 14, S24 = 20;
    const S31 = 4, S32 = 11, S33 = 16, S34 = 23;
    const S41 = 6, S42 = 10, S43 = 15, S44 = 21;

    for (let k = 0; k < x.length; k += 16) {
        const AA = a, BB = b, CC = c, DD = d;
        a = FF(a, b, c, d, x[k], S11, 0xD76AA478);
        d = FF(d, a, b, c, x[k + 1], S12, 0xE8C7B756);
        c = FF(c, d, a, b, x[k + 2], S13, 0x242070DB);
        b = FF(b, c, d, a, x[k + 3], S14, 0xC1BDCEEE);
        a = FF(a, b, c, d, x[k + 4], S11, 0xF57C0FAF);
        d = FF(d, a, b, c, x[k + 5], S12, 0x4787C62A);
        c = FF(c, d, a, b, x[k + 6], S13, 0xA8304613);
        b = FF(b, c, d, a, x[k + 7], S14, 0xFD469501);
        a = FF(a, b, c, d, x[k + 8], S11, 0x698098D8);
        d = FF(d, a, b, c, x[k + 9], S12, 0x8B44F7AF);
        c = FF(c, d, a, b, x[k + 10], S13, 0xFFFF5BB1);
        b = FF(b, c, d, a, x[k + 11], S14, 0x895CD7BE);
        a = FF(a, b, c, d, x[k + 12], S11, 0x6B901122);
        d = FF(d, a, b, c, x[k + 13], S12, 0xFD987193);
        c = FF(c, d, a, b, x[k + 14], S13, 0xA679438E);
        b = FF(b, c, d, a, x[k + 15], S14, 0x49B40821);
        a = GG(a, b, c, d, x[k + 1], S21, 0xF61E2562);
        d = GG(d, a, b, c, x[k + 6], S22, 0xC040B340);
        c = GG(c, d, a, b, x[k + 11], S23, 0x265E5A51);
        b = GG(b, c, d, a, x[k], S24, 0xE9B6C7AA);
        a = GG(a, b, c, d, x[k + 5], S21, 0xD62F105D);
        d = GG(d, a, b, c, x[k + 10], S22, 0x2441453);
        c = GG(c, d, a, b, x[k + 15], S23, 0xD8A1E681);
        b = GG(b, c, d, a, x[k + 4], S24, 0xE7D3FBC8);
        a = GG(a, b, c, d, x[k + 9], S21, 0x21E1CDE6);
        d = GG(d, a, b, c, x[k + 14], S22, 0xC33707D6);
        c = GG(c, d, a, b, x[k + 3], S23, 0xF4D50D87);
        b = GG(b, c, d, a, x[k + 8], S24, 0x455A14ED);
        a = GG(a, b, c, d, x[k + 13], S21, 0xA9E3E905);
        d = GG(d, a, b, c, x[k + 2], S22, 0xFCEFA3F8);
        c = GG(c, d, a, b, x[k + 7], S23, 0x676F02D9);
        b = GG(b, c, d, a, x[k + 12], S24, 0x8D2A4C8A);
        a = HH(a, b, c, d, x[k + 5], S31, 0xFFFA3942);
        d = HH(d, a, b, c, x[k + 8], S32, 0x8771F681);
        c = HH(c, d, a, b, x[k + 11], S33, 0x6D9D6122);
        b = HH(b, c, d, a, x[k + 14], S34, 0xFDE5380C);
        a = HH(a, b, c, d, x[k + 1], S31, 0xA4BEEA44);
        d = HH(d, a, b, c, x[k + 4], S32, 0x4BDECFA9);
        c = HH(c, d, a, b, x[k + 7], S33, 0xF6BB4B60);
        b = HH(b, c, d, a, x[k + 10], S34, 0xBEBFBC70);
        a = HH(a, b, c, d, x[k + 13], S31, 0x289B7EC6);
        d = HH(d, a, b, c, x[k], S32, 0xEAA127FA);
        c = HH(c, d, a, b, x[k + 3], S33, 0xD4EF3085);
        b = HH(b, c, d, a, x[k + 6], S34, 0x4881D05);
        a = HH(a, b, c, d, x[k + 9], S31, 0xD9D4D039);
        d = HH(d, a, b, c, x[k + 12], S32, 0xE6DB99E5);
        c = HH(c, d, a, b, x[k + 15], S33, 0x1FA27CF8);
        b = HH(b, c, d, a, x[k + 2], S34, 0xC4AC5665);
        a = II(a, b, c, d, x[k], S41, 0xF4292244);
        d = II(d, a, b, c, x[k + 7], S42, 0x432AFF97);
        c = II(c, d, a, b, x[k + 14], S43, 0xAB9423A7);
        b = II(b, c, d, a, x[k + 5], S44, 0xFC93A039);
        a = II(a, b, c, d, x[k + 12], S41, 0x655B59C3);
        d = II(d, a, b, c, x[k + 3], S42, 0x8F0CCC92);
        c = II(c, d, a, b, x[k + 10], S43, 0xFFEFF47D);
        b = II(b, c, d, a, x[k + 1], S44, 0x85845DD1);
        a = II(a, b, c, d, x[k + 8], S41, 0x6FA87E4F);
        d = II(d, a, b, c, x[k + 15], S42, 0xFE2CE6E0);
        c = II(c, d, a, b, x[k + 6], S43, 0xA3014314);
        b = II(b, c, d, a, x[k + 13], S44, 0x4E0811A1);
        a = II(a, b, c, d, x[k + 4], S41, 0xF7537E82);
        d = II(d, a, b, c, x[k + 11], S42, 0xBD3AF235);
        c = II(c, d, a, b, x[k + 2], S43, 0x2AD7D2BB);
        b = II(b, c, d, a, x[k + 9], S44, 0xEB86D391);
        a = addUnsigned(a, AA);
        b = addUnsigned(b, BB);
        c = addUnsigned(c, CC);
        d = addUnsigned(d, DD);
    }

    return (wordToHex(a) + wordToHex(b) + wordToHex(c) + wordToHex(d)).toLowerCase();
}

async function updateHashes() {
    const text = document.getElementById('hash-input').value;

    if (!text) {
        document.querySelectorAll('.hash-row input').forEach(input => input.value = '');
        return;
    }

    document.getElementById('hash-md5').value = md5(text);
    document.getElementById('hash-sha1').value = await computeHash(text, 'SHA-1');
    document.getElementById('hash-sha256').value = await computeHash(text, 'SHA-256');
    document.getElementById('hash-sha384').value = await computeHash(text, 'SHA-384');
    document.getElementById('hash-sha512').value = await computeHash(text, 'SHA-512');

    verifyHash();
}

function verifyHash() {
    const inputHash = document.getElementById('verify-hash').value.toLowerCase().trim();
    const resultDiv = document.getElementById('verify-result');

    if (!inputHash) {
        resultDiv.textContent = '';
        resultDiv.className = 'verify-result';
        return;
    }

    const hashes = {
        'MD5': document.getElementById('hash-md5').value,
        'SHA-1': document.getElementById('hash-sha1').value,
        'SHA-256': document.getElementById('hash-sha256').value,
        'SHA-384': document.getElementById('hash-sha384').value,
        'SHA-512': document.getElementById('hash-sha512').value
    };

    for (const [name, hash] of Object.entries(hashes)) {
        if (hash && hash === inputHash) {
            resultDiv.textContent = `Correspondance ${name}`;
            resultDiv.className = 'verify-result match';
            return;
        }
    }

    resultDiv.textContent = 'Aucune correspondance';
    resultDiv.className = 'verify-result no-match';
}

function copyHash(id) {
    const input = document.getElementById(id);
    input.select();
    document.execCommand('copy');
}

// Event listeners
document.getElementById('hash-input').addEventListener('input', updateHashes);
document.getElementById('verify-hash').addEventListener('input', verifyHash);

// Initial
updateHashes();
</script>
