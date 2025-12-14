---
tags:
  - tools
  - converter
  - binary
  - hex
  - decimal
---

# Number Base Converter

Conversion entre bases numeriques : binaire, octal, decimal, hexadecimal.

<div class="tool-container">

<div class="converter-section">
    <h3>Convertisseur</h3>

    <div class="input-grid">
        <div class="input-group">
            <label for="bin-input">Binaire (base 2)</label>
            <input type="text" id="bin-input" placeholder="1010 1100">
            <span class="prefix">0b</span>
        </div>

        <div class="input-group">
            <label for="oct-input">Octal (base 8)</label>
            <input type="text" id="oct-input" placeholder="254">
            <span class="prefix">0o</span>
        </div>

        <div class="input-group">
            <label for="dec-input">Decimal (base 10)</label>
            <input type="text" id="dec-input" placeholder="172">
        </div>

        <div class="input-group">
            <label for="hex-input">Hexadecimal (base 16)</label>
            <input type="text" id="hex-input" placeholder="AC">
            <span class="prefix">0x</span>
        </div>
    </div>

    <div class="info-row">
        <span>Bits: <strong id="bit-count">0</strong></span>
        <span>Bytes: <strong id="byte-count">0</strong></span>
        <span>ASCII: <strong id="ascii-char">-</strong></span>
    </div>
</div>

<div class="bitwise-section">
    <h3>Operations bit a bit</h3>

    <div class="bitwise-grid">
        <div class="form-group">
            <label for="op-a">Operande A (decimal)</label>
            <input type="number" id="op-a" value="170">
        </div>

        <div class="form-group">
            <label for="op-type">Operation</label>
            <select id="op-type">
                <option value="and">AND (&)</option>
                <option value="or">OR (|)</option>
                <option value="xor">XOR (^)</option>
                <option value="not">NOT (~)</option>
                <option value="shl">Shift Left (<<)</option>
                <option value="shr">Shift Right (>>)</option>
            </select>
        </div>

        <div class="form-group">
            <label for="op-b">Operande B</label>
            <input type="number" id="op-b" value="15">
        </div>
    </div>

    <div class="bitwise-result">
        <div class="result-row">
            <span>A:</span>
            <code id="op-a-bin">10101010</code>
            <span>=</span>
            <code id="op-a-dec">170</code>
        </div>
        <div class="result-row">
            <span>B:</span>
            <code id="op-b-bin">00001111</code>
            <span>=</span>
            <code id="op-b-dec">15</code>
        </div>
        <div class="result-row result">
            <span>=</span>
            <code id="op-result-bin">00001010</code>
            <span>=</span>
            <code id="op-result-dec">10</code>
            <span>=</span>
            <code id="op-result-hex">0x0A</code>
        </div>
    </div>
</div>

<div class="visual-section">
    <h3>Representation binaire (8 bits)</h3>
    <div class="bit-visual" id="bit-visual">
        <div class="bit-row">
            <span class="bit-label">128</span>
            <span class="bit-label">64</span>
            <span class="bit-label">32</span>
            <span class="bit-label">16</span>
            <span class="bit-label">8</span>
            <span class="bit-label">4</span>
            <span class="bit-label">2</span>
            <span class="bit-label">1</span>
        </div>
        <div class="bit-row bits" id="bit-display">
            <span class="bit" onclick="toggleBit(7)">0</span>
            <span class="bit" onclick="toggleBit(6)">0</span>
            <span class="bit" onclick="toggleBit(5)">0</span>
            <span class="bit" onclick="toggleBit(4)">0</span>
            <span class="bit" onclick="toggleBit(3)">0</span>
            <span class="bit" onclick="toggleBit(2)">0</span>
            <span class="bit" onclick="toggleBit(1)">0</span>
            <span class="bit" onclick="toggleBit(0)">0</span>
        </div>
    </div>
    <p class="hint">Cliquez sur les bits pour les basculer</p>
</div>

<div class="table-section">
    <h3>Table de reference</h3>
    <div class="reference-table">
        <table>
            <thead>
                <tr>
                    <th>Dec</th>
                    <th>Hex</th>
                    <th>Oct</th>
                    <th>Bin</th>
                    <th>Char</th>
                </tr>
            </thead>
            <tbody id="ref-table-body">
            </tbody>
        </table>
    </div>
</div>

</div>

## Prefixes de base

| Base | Prefixe | Exemple |
|------|---------|---------|
| **Binaire** | 0b | `0b1010` |
| **Octal** | 0o ou 0 | `0o12` ou `012` |
| **Decimal** | (aucun) | `10` |
| **Hexadecimal** | 0x | `0xA` |

## Conversion en CLI

```bash
# Bash - decimal vers autres bases
echo "obase=2; 255" | bc      # Binaire: 11111111
echo "obase=16; 255" | bc     # Hex: FF
printf '%x\n' 255             # Hex: ff

# Bash - hex vers decimal
echo $((0xFF))                # 255
printf '%d\n' 0xFF            # 255

# Python
bin(255)    # '0b11111111'
oct(255)    # '0o377'
hex(255)    # '0xff'
int('FF', 16)  # 255
```

<style>
.tool-container {
    background: var(--md-code-bg-color);
    padding: 20px;
    border-radius: 8px;
    margin: 20px 0;
}
.converter-section, .bitwise-section, .visual-section, .table-section {
    background: var(--md-default-bg-color);
    padding: 20px;
    border-radius: 4px;
    margin-bottom: 20px;
}
.converter-section h3, .bitwise-section h3, .visual-section h3, .table-section h3 {
    margin: 0 0 15px 0;
}
.input-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 15px;
}
.input-group {
    position: relative;
}
.input-group label {
    display: block;
    font-size: 12px;
    font-weight: bold;
    margin-bottom: 5px;
}
.input-group input {
    width: 100%;
    padding: 12px;
    padding-left: 35px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 16px;
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    background: var(--md-code-bg-color);
    color: var(--md-default-fg-color);
}
.input-group .prefix {
    position: absolute;
    left: 10px;
    bottom: 12px;
    font-family: monospace;
    color: var(--md-default-fg-color--light);
}
.info-row {
    display: flex;
    gap: 20px;
    margin-top: 15px;
    padding: 10px;
    background: var(--md-code-bg-color);
    border-radius: 4px;
}
.bitwise-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 15px;
    margin-bottom: 15px;
}
.form-group label {
    display: block;
    font-size: 12px;
    font-weight: bold;
    margin-bottom: 5px;
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
.bitwise-result {
    background: var(--md-code-bg-color);
    padding: 15px;
    border-radius: 4px;
    font-family: monospace;
}
.result-row {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 5px 0;
}
.result-row.result {
    border-top: 1px solid var(--md-default-fg-color--lighter);
    margin-top: 10px;
    padding-top: 10px;
    font-weight: bold;
}
.result-row code {
    background: var(--md-default-bg-color);
    padding: 4px 8px;
    border-radius: 3px;
}
.bit-visual {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 5px;
}
.bit-row {
    display: flex;
    gap: 5px;
}
.bit-label {
    width: 40px;
    text-align: center;
    font-size: 12px;
    color: var(--md-default-fg-color--light);
}
.bit {
    width: 40px;
    height: 40px;
    display: flex;
    align-items: center;
    justify-content: center;
    background: var(--md-code-bg-color);
    border: 2px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    font-family: monospace;
    font-size: 18px;
    font-weight: bold;
    cursor: pointer;
    transition: all 0.1s;
}
.bit.active {
    background: var(--md-primary-fg-color);
    color: white;
    border-color: var(--md-primary-fg-color);
}
.hint {
    text-align: center;
    font-size: 12px;
    color: var(--md-default-fg-color--light);
    margin-top: 10px;
}
.reference-table {
    max-height: 300px;
    overflow-y: auto;
}
.reference-table table {
    width: 100%;
    border-collapse: collapse;
    font-family: monospace;
}
.reference-table th, .reference-table td {
    padding: 8px 12px;
    text-align: center;
    border-bottom: 1px solid var(--md-default-fg-color--lightest);
}
.reference-table th {
    background: var(--md-code-bg-color);
    position: sticky;
    top: 0;
}
</style>

<script>
let currentValue = 0;

function updateFromValue(value, source) {
    currentValue = value;

    if (source !== 'bin') {
        document.getElementById('bin-input').value = value.toString(2);
    }
    if (source !== 'oct') {
        document.getElementById('oct-input').value = value.toString(8);
    }
    if (source !== 'dec') {
        document.getElementById('dec-input').value = value.toString(10);
    }
    if (source !== 'hex') {
        document.getElementById('hex-input').value = value.toString(16).toUpperCase();
    }

    // Update info
    const bits = value.toString(2).length;
    const bytes = Math.ceil(bits / 8);
    document.getElementById('bit-count').textContent = bits;
    document.getElementById('byte-count').textContent = bytes;
    document.getElementById('ascii-char').textContent = value >= 32 && value < 127 ? String.fromCharCode(value) : '-';

    // Update visual
    updateBitVisual(value);
}

function updateBitVisual(value) {
    const bits = document.querySelectorAll('#bit-display .bit');
    for (let i = 0; i < 8; i++) {
        const bitValue = (value >> i) & 1;
        bits[7 - i].textContent = bitValue;
        bits[7 - i].classList.toggle('active', bitValue === 1);
    }
}

function toggleBit(position) {
    currentValue ^= (1 << position);
    updateFromValue(currentValue, 'visual');
}

// Input event listeners
document.getElementById('bin-input').addEventListener('input', (e) => {
    const val = parseInt(e.target.value.replace(/\s/g, ''), 2);
    if (!isNaN(val)) updateFromValue(val, 'bin');
});

document.getElementById('oct-input').addEventListener('input', (e) => {
    const val = parseInt(e.target.value, 8);
    if (!isNaN(val)) updateFromValue(val, 'oct');
});

document.getElementById('dec-input').addEventListener('input', (e) => {
    const val = parseInt(e.target.value, 10);
    if (!isNaN(val)) updateFromValue(val, 'dec');
});

document.getElementById('hex-input').addEventListener('input', (e) => {
    const val = parseInt(e.target.value, 16);
    if (!isNaN(val)) updateFromValue(val, 'hex');
});

// Bitwise operations
function updateBitwise() {
    const a = parseInt(document.getElementById('op-a').value) || 0;
    const b = parseInt(document.getElementById('op-b').value) || 0;
    const op = document.getElementById('op-type').value;

    let result;
    switch (op) {
        case 'and': result = a & b; break;
        case 'or': result = a | b; break;
        case 'xor': result = a ^ b; break;
        case 'not': result = ~a & 0xFF; break;
        case 'shl': result = a << b; break;
        case 'shr': result = a >>> b; break;
    }

    document.getElementById('op-a-bin').textContent = (a >>> 0).toString(2).padStart(8, '0');
    document.getElementById('op-a-dec').textContent = a;
    document.getElementById('op-b-bin').textContent = (b >>> 0).toString(2).padStart(8, '0');
    document.getElementById('op-b-dec').textContent = b;
    document.getElementById('op-result-bin').textContent = (result >>> 0).toString(2).padStart(8, '0');
    document.getElementById('op-result-dec').textContent = result;
    document.getElementById('op-result-hex').textContent = '0x' + (result >>> 0).toString(16).toUpperCase();
}

document.getElementById('op-a').addEventListener('input', updateBitwise);
document.getElementById('op-b').addEventListener('input', updateBitwise);
document.getElementById('op-type').addEventListener('change', updateBitwise);

// Reference table
function buildReferenceTable() {
    const tbody = document.getElementById('ref-table-body');
    let html = '';

    for (let i = 0; i <= 255; i++) {
        const char = i >= 32 && i < 127 ? String.fromCharCode(i) : '';
        html += `<tr>
            <td>${i}</td>
            <td>${i.toString(16).toUpperCase().padStart(2, '0')}</td>
            <td>${i.toString(8).padStart(3, '0')}</td>
            <td>${i.toString(2).padStart(8, '0')}</td>
            <td>${char}</td>
        </tr>`;
    }

    tbody.innerHTML = html;
}

// Initialize
updateFromValue(172, null);
updateBitwise();
buildReferenceTable();
</script>
