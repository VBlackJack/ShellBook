---
tags:
  - tools
  - uuid
  - guid
---

# UUID Generator

Generateur d'identifiants uniques universels (UUID/GUID).

<div class="tool-container">

<div class="generator-section">
    <h3>Generer des UUIDs</h3>

    <div class="options-row">
        <div class="input-group">
            <label for="uuid-version">Version :</label>
            <select id="uuid-version">
                <option value="4" selected>v4 (Aleatoire)</option>
                <option value="1">v1 (Timestamp + MAC)</option>
            </select>
        </div>
        <div class="input-group">
            <label for="uuid-count">Quantite :</label>
            <input type="number" id="uuid-count" value="1" min="1" max="100">
        </div>
        <div class="input-group">
            <label for="uuid-format">Format :</label>
            <select id="uuid-format">
                <option value="lower">minuscules</option>
                <option value="upper">MAJUSCULES</option>
                <option value="nodash">Sans tirets</option>
                <option value="braces">{Avec accolades}</option>
            </select>
        </div>
    </div>

    <button onclick="generateUUIDs()" class="action-btn">Generer</button>

    <div class="uuid-output">
        <textarea id="uuid-result" rows="6" readonly></textarea>
        <button onclick="copyUUIDs()" class="copy-btn">Copier tout</button>
    </div>
</div>

<div class="parser-section">
    <h3>Analyser un UUID</h3>

    <div class="input-group">
        <label for="uuid-input">UUID a analyser :</label>
        <input type="text" id="uuid-input" placeholder="550e8400-e29b-41d4-a716-446655440000">
    </div>

    <div id="uuid-analysis" class="analysis-box" style="display:none;">
        <table>
            <tr><td>Valide</td><td id="uuid-valid">-</td></tr>
            <tr><td>Version</td><td id="uuid-ver">-</td></tr>
            <tr><td>Variante</td><td id="uuid-variant">-</td></tr>
            <tr><td>Timestamp (v1)</td><td id="uuid-timestamp">-</td></tr>
        </table>
    </div>
</div>

<div class="nil-section">
    <h3>UUIDs speciaux</h3>
    <table class="special-uuids">
        <tr>
            <td><strong>Nil UUID</strong></td>
            <td><code>00000000-0000-0000-0000-000000000000</code></td>
            <td><button onclick="copySpecial('00000000-0000-0000-0000-000000000000')">Copier</button></td>
        </tr>
        <tr>
            <td><strong>Max UUID</strong></td>
            <td><code>ffffffff-ffff-ffff-ffff-ffffffffffff</code></td>
            <td><button onclick="copySpecial('ffffffff-ffff-ffff-ffff-ffffffffffff')">Copier</button></td>
        </tr>
    </table>
</div>

</div>

## Versions UUID

| Version | Nom | Description |
|---------|-----|-------------|
| **v1** | Time-based | Timestamp 100ns + adresse MAC |
| **v2** | DCE Security | Comme v1 + identifiants POSIX |
| **v3** | Name-based MD5 | Hash MD5 d'un namespace + nom |
| **v4** | Random | 122 bits aleatoires |
| **v5** | Name-based SHA-1 | Hash SHA-1 d'un namespace + nom |
| **v6** | Reordered Time | v1 reordonne (tri lexicographique) |
| **v7** | Unix Timestamp | Timestamp Unix + aleatoire |

## Structure

```
550e8400-e29b-41d4-a716-446655440000
    |       |    |    |       |
    |       |    |    |       +-- Node (48 bits)
    |       |    |    +---------- Clock Seq (14 bits) + Variant (2 bits)
    |       |    +--------------- Version (4 bits)
    |       +-------------------- Time High (16 bits)
    +---------------------------- Time Low (32 bits) + Time Mid (16 bits)
```

### Bits de version et variante

```
xxxxxxxx-xxxx-Mxxx-Nxxx-xxxxxxxxxxxx
              |    |
              |    +-- N = Variante (8, 9, a, b pour RFC 4122)
              +------- M = Version (1, 2, 3, 4, 5)
```

## Generation en CLI

```bash
# Linux (uuidgen)
uuidgen
uuidgen -r  # Random (v4)
uuidgen -t  # Time-based (v1)

# Python
python -c "import uuid; print(uuid.uuid4())"

# PowerShell
[guid]::NewGuid()
New-Guid

# Node.js
node -e "console.log(require('crypto').randomUUID())"
```

<style>
.tool-container {
    background: var(--md-code-bg-color);
    padding: 20px;
    border-radius: 8px;
    margin: 20px 0;
}
.generator-section, .parser-section, .nil-section {
    background: var(--md-default-bg-color);
    padding: 20px;
    border-radius: 4px;
    margin-bottom: 20px;
}
.generator-section h3, .parser-section h3, .nil-section h3 {
    margin: 0 0 15px 0;
}
.options-row {
    display: flex;
    gap: 20px;
    flex-wrap: wrap;
    margin-bottom: 15px;
}
.input-group {
    min-width: 150px;
}
.input-group label {
    display: block;
    font-size: 12px;
    margin-bottom: 5px;
    font-weight: bold;
}
.input-group input, .input-group select {
    padding: 8px;
    font-size: 14px;
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    background: var(--md-code-bg-color);
    color: var(--md-default-fg-color);
}
.input-group input[type="number"] {
    width: 80px;
}
.input-group input[type="text"] {
    width: 100%;
    max-width: 400px;
    font-family: monospace;
}
.action-btn {
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
.uuid-output {
    position: relative;
    margin-top: 15px;
}
.uuid-output textarea {
    width: 100%;
    padding: 12px;
    font-family: monospace;
    font-size: 14px;
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    background: var(--md-code-bg-color);
    color: var(--md-default-fg-color);
    resize: vertical;
}
.copy-btn {
    position: absolute;
    right: 10px;
    top: 10px;
    padding: 5px 10px;
    background: var(--md-primary-fg-color);
    color: white;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    font-size: 12px;
}
.analysis-box {
    margin-top: 15px;
    padding: 15px;
    background: var(--md-code-bg-color);
    border-radius: 4px;
}
.analysis-box table {
    width: 100%;
}
.analysis-box td {
    padding: 8px;
    border-bottom: 1px solid var(--md-default-fg-color--lightest);
}
.analysis-box td:first-child {
    font-weight: bold;
    width: 120px;
}
.special-uuids {
    width: 100%;
}
.special-uuids td {
    padding: 10px;
    border-bottom: 1px solid var(--md-default-fg-color--lightest);
}
.special-uuids code {
    font-size: 13px;
}
.special-uuids button {
    padding: 5px 10px;
    background: var(--md-primary-fg-color);
    color: white;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    font-size: 12px;
}
#uuid-valid.valid {
    color: #155724;
}
#uuid-valid.invalid {
    color: #721c24;
}
</style>

<script>
function generateUUIDv4() {
    // Use crypto API for secure random
    const array = new Uint8Array(16);
    crypto.getRandomValues(array);

    // Set version (4) and variant (RFC 4122)
    array[6] = (array[6] & 0x0f) | 0x40;
    array[8] = (array[8] & 0x3f) | 0x80;

    const hex = Array.from(array).map(b => b.toString(16).padStart(2, '0')).join('');

    return `${hex.slice(0,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}-${hex.slice(16,20)}-${hex.slice(20)}`;
}

function generateUUIDv1() {
    // Simplified v1 UUID (uses random instead of real MAC)
    const now = Date.now();
    const gregorianOffset = 122192928000000000n; // 100ns intervals from 1582 to 1970
    const timestamp = BigInt(now) * 10000n + gregorianOffset;

    const timeLow = Number(timestamp & 0xffffffffn);
    const timeMid = Number((timestamp >> 32n) & 0xffffn);
    const timeHi = Number((timestamp >> 48n) & 0x0fffn) | 0x1000;

    const clockSeq = (crypto.getRandomValues(new Uint16Array(1))[0] & 0x3fff) | 0x8000;

    const node = crypto.getRandomValues(new Uint8Array(6));
    node[0] |= 0x01; // Multicast bit to indicate random

    const nodeHex = Array.from(node).map(b => b.toString(16).padStart(2, '0')).join('');

    return `${timeLow.toString(16).padStart(8, '0')}-${timeMid.toString(16).padStart(4, '0')}-${timeHi.toString(16).padStart(4, '0')}-${clockSeq.toString(16).padStart(4, '0')}-${nodeHex}`;
}

function formatUUID(uuid, format) {
    switch (format) {
        case 'upper':
            return uuid.toUpperCase();
        case 'nodash':
            return uuid.replace(/-/g, '');
        case 'braces':
            return '{' + uuid + '}';
        default:
            return uuid.toLowerCase();
    }
}

function generateUUIDs() {
    const version = document.getElementById('uuid-version').value;
    const count = parseInt(document.getElementById('uuid-count').value) || 1;
    const format = document.getElementById('uuid-format').value;

    const uuids = [];
    for (let i = 0; i < Math.min(count, 100); i++) {
        let uuid = version === '1' ? generateUUIDv1() : generateUUIDv4();
        uuids.push(formatUUID(uuid, format));
    }

    document.getElementById('uuid-result').value = uuids.join('\n');
}

function copyUUIDs() {
    const textarea = document.getElementById('uuid-result');
    textarea.select();
    document.execCommand('copy');

    const btn = document.querySelector('.uuid-output .copy-btn');
    btn.textContent = 'Copie!';
    setTimeout(() => { btn.textContent = 'Copier tout'; }, 1000);
}

function copySpecial(uuid) {
    navigator.clipboard.writeText(uuid);
}

function analyzeUUID() {
    const input = document.getElementById('uuid-input').value.trim();
    const analysisBox = document.getElementById('uuid-analysis');

    if (!input) {
        analysisBox.style.display = 'none';
        return;
    }

    analysisBox.style.display = 'block';

    // Normalize input
    const normalized = input.replace(/[{}-]/g, '').toLowerCase();
    const uuidRegex = /^[0-9a-f]{32}$/;

    const validEl = document.getElementById('uuid-valid');
    if (!uuidRegex.test(normalized)) {
        validEl.textContent = 'Non';
        validEl.className = 'invalid';
        document.getElementById('uuid-ver').textContent = '-';
        document.getElementById('uuid-variant').textContent = '-';
        document.getElementById('uuid-timestamp').textContent = '-';
        return;
    }

    validEl.textContent = 'Oui';
    validEl.className = 'valid';

    // Extract version (13th character)
    const version = parseInt(normalized[12], 16);
    document.getElementById('uuid-ver').textContent = 'v' + version;

    // Extract variant (17th character)
    const variantBits = parseInt(normalized[16], 16);
    let variant;
    if ((variantBits & 0x8) === 0) {
        variant = 'NCS (backward compatibility)';
    } else if ((variantBits & 0xc) === 0x8) {
        variant = 'RFC 4122';
    } else if ((variantBits & 0xe) === 0xc) {
        variant = 'Microsoft (backward compatibility)';
    } else {
        variant = 'Reserved';
    }
    document.getElementById('uuid-variant').textContent = variant;

    // Timestamp for v1
    if (version === 1) {
        try {
            const timeLow = parseInt(normalized.slice(0, 8), 16);
            const timeMid = parseInt(normalized.slice(8, 12), 16);
            const timeHi = parseInt(normalized.slice(12, 16), 16) & 0x0fff;

            const timestamp = BigInt(timeLow) + (BigInt(timeMid) << 32n) + (BigInt(timeHi) << 48n);
            const gregorianOffset = 122192928000000000n;
            const unixNs = (timestamp - gregorianOffset) / 10000n;
            const date = new Date(Number(unixNs));

            document.getElementById('uuid-timestamp').textContent = date.toLocaleString('fr-FR');
        } catch (e) {
            document.getElementById('uuid-timestamp').textContent = 'Erreur de parsing';
        }
    } else {
        document.getElementById('uuid-timestamp').textContent = 'N/A (v' + version + ')';
    }
}

// Event listeners
document.getElementById('uuid-input').addEventListener('input', analyzeUUID);

// Initial generation
generateUUIDs();
</script>
