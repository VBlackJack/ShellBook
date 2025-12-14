---
tags:
  - tools
  - ascii
  - encoding
  - reference
---

# ASCII Table

Table de reference ASCII avec recherche et conversion.

<div class="tool-container">

<div class="converter-section">
    <h3>Convertisseur</h3>

    <div class="converter-grid">
        <div class="input-group">
            <label for="char-input">Caractere</label>
            <input type="text" id="char-input" maxlength="1" placeholder="A">
        </div>
        <div class="input-group">
            <label for="dec-input">Decimal</label>
            <input type="number" id="dec-input" min="0" max="127" placeholder="65">
        </div>
        <div class="input-group">
            <label for="hex-input">Hexadecimal</label>
            <input type="text" id="hex-input" maxlength="2" placeholder="41">
        </div>
        <div class="input-group">
            <label for="oct-input">Octal</label>
            <input type="text" id="oct-input" maxlength="3" placeholder="101">
        </div>
        <div class="input-group">
            <label for="bin-input">Binaire</label>
            <input type="text" id="bin-input" maxlength="8" placeholder="01000001">
        </div>
    </div>
</div>

<div class="string-section">
    <h3>Conversion de texte</h3>

    <div class="input-group">
        <label for="text-input">Texte</label>
        <input type="text" id="text-input" placeholder="Hello World">
    </div>

    <div class="string-outputs">
        <div class="output-item">
            <label>Decimal</label>
            <code id="text-dec">-</code>
        </div>
        <div class="output-item">
            <label>Hexadecimal</label>
            <code id="text-hex">-</code>
        </div>
        <div class="output-item">
            <label>Binaire</label>
            <code id="text-bin">-</code>
        </div>
    </div>
</div>

<div class="search-section">
    <input type="text" id="ascii-search" placeholder="Rechercher (caractere, code, nom...)">
</div>

<div class="table-section">
    <h3>Table ASCII (0-127)</h3>

    <div class="table-tabs">
        <button class="tab-btn active" onclick="showTable('all')">Tous</button>
        <button class="tab-btn" onclick="showTable('control')">Controle (0-31)</button>
        <button class="tab-btn" onclick="showTable('printable')">Imprimables (32-126)</button>
        <button class="tab-btn" onclick="showTable('extended')">Etendus (128-255)</button>
    </div>

    <div class="ascii-table-wrapper">
        <table class="ascii-table" id="ascii-table">
            <thead>
                <tr>
                    <th>Dec</th>
                    <th>Hex</th>
                    <th>Oct</th>
                    <th>Bin</th>
                    <th>Char</th>
                    <th>Description</th>
                </tr>
            </thead>
            <tbody id="ascii-tbody">
            </tbody>
        </table>
    </div>
</div>

</div>

## Categories ASCII

### Caracteres de controle (0-31, 127)

| Code | Abbr | Description | Usage |
|------|------|-------------|-------|
| 0 | NUL | Null | Fin de chaine (C) |
| 7 | BEL | Bell | Bip sonore |
| 8 | BS | Backspace | Retour arriere |
| 9 | HT | Horizontal Tab | Tabulation |
| 10 | LF | Line Feed | Nouvelle ligne (Unix) |
| 13 | CR | Carriage Return | Retour chariot (Windows: CR+LF) |
| 27 | ESC | Escape | Sequences d'echappement |
| 127 | DEL | Delete | Suppression |

### Caracteres speciaux courants

| Char | Dec | Hex | Nom |
|------|-----|-----|-----|
| ` ` | 32 | 20 | Espace |
| `!` | 33 | 21 | Point d'exclamation |
| `"` | 34 | 22 | Guillemet double |
| `#` | 35 | 23 | Diese |
| `$` | 36 | 24 | Dollar |
| `%` | 37 | 25 | Pourcent |
| `&` | 38 | 26 | Esperluette |
| `'` | 39 | 27 | Apostrophe |
| `*` | 42 | 2A | Asterisque |
| `@` | 64 | 40 | Arobase |
| `\` | 92 | 5C | Backslash |
| `^` | 94 | 5E | Accent circonflexe |
| `` ` `` | 96 | 60 | Accent grave |
| `~` | 126 | 7E | Tilde |

## Commandes utiles

```bash
# Afficher la table ASCII
man ascii

# Convertir caractere en code
printf '%d\n' "'A"     # 65

# Convertir code en caractere
printf "\\$(printf '%03o' 65)"   # A

# Python
python -c "print(ord('A'))"      # 65
python -c "print(chr(65))"       # A

# PowerShell
[int][char]'A'                   # 65
[char]65                         # A
```

<style>
.tool-container {
    background: var(--md-code-bg-color);
    padding: 20px;
    border-radius: 8px;
    margin: 20px 0;
}
.converter-section, .string-section, .search-section, .table-section {
    background: var(--md-default-bg-color);
    padding: 20px;
    border-radius: 4px;
    margin-bottom: 20px;
}
.converter-section h3, .string-section h3, .table-section h3 {
    margin: 0 0 15px 0;
}
.converter-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
    gap: 15px;
}
.input-group label {
    display: block;
    font-size: 12px;
    font-weight: bold;
    margin-bottom: 5px;
}
.input-group input {
    width: 100%;
    padding: 10px;
    font-family: monospace;
    font-size: 16px;
    text-align: center;
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    background: var(--md-code-bg-color);
    color: var(--md-default-fg-color);
}
.string-section .input-group input {
    text-align: left;
}
.string-outputs {
    display: flex;
    flex-direction: column;
    gap: 10px;
    margin-top: 15px;
}
.output-item {
    display: flex;
    align-items: center;
    gap: 10px;
}
.output-item label {
    min-width: 100px;
    font-weight: bold;
    font-size: 12px;
}
.output-item code {
    flex: 1;
    padding: 8px;
    background: var(--md-code-bg-color);
    border-radius: 4px;
    font-size: 13px;
    word-break: break-all;
}
.search-section {
    padding: 15px 20px;
}
.search-section input {
    width: 100%;
    max-width: 400px;
    padding: 12px;
    font-size: 16px;
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    background: var(--md-code-bg-color);
    color: var(--md-default-fg-color);
}
.table-tabs {
    display: flex;
    gap: 10px;
    flex-wrap: wrap;
    margin-bottom: 15px;
}
.tab-btn {
    padding: 8px 16px;
    background: var(--md-code-bg-color);
    color: var(--md-default-fg-color);
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    cursor: pointer;
    font-size: 13px;
}
.tab-btn.active {
    background: var(--md-primary-fg-color);
    color: white;
    border-color: var(--md-primary-fg-color);
}
.ascii-table-wrapper {
    overflow-x: auto;
    max-height: 500px;
    overflow-y: auto;
}
.ascii-table {
    width: 100%;
    border-collapse: collapse;
    font-family: monospace;
}
.ascii-table th, .ascii-table td {
    padding: 8px 12px;
    border-bottom: 1px solid var(--md-default-fg-color--lightest);
    text-align: left;
}
.ascii-table th {
    background: var(--md-code-bg-color);
    position: sticky;
    top: 0;
    font-weight: bold;
}
.ascii-table td:first-child {
    color: var(--md-primary-fg-color);
    font-weight: bold;
}
.ascii-table tr:hover {
    background: var(--md-code-bg-color);
}
.ascii-table .char-cell {
    font-size: 18px;
    font-weight: bold;
}
.ascii-table .control {
    color: var(--md-default-fg-color--light);
    font-style: italic;
}
</style>

<script>
// Control character names
const CONTROL_CHARS = {
    0: 'NUL (Null)', 1: 'SOH (Start of Heading)', 2: 'STX (Start of Text)',
    3: 'ETX (End of Text)', 4: 'EOT (End of Transmission)', 5: 'ENQ (Enquiry)',
    6: 'ACK (Acknowledge)', 7: 'BEL (Bell)', 8: 'BS (Backspace)',
    9: 'HT (Horizontal Tab)', 10: 'LF (Line Feed)', 11: 'VT (Vertical Tab)',
    12: 'FF (Form Feed)', 13: 'CR (Carriage Return)', 14: 'SO (Shift Out)',
    15: 'SI (Shift In)', 16: 'DLE (Data Link Escape)', 17: 'DC1 (Device Control 1)',
    18: 'DC2 (Device Control 2)', 19: 'DC3 (Device Control 3)', 20: 'DC4 (Device Control 4)',
    21: 'NAK (Negative Ack)', 22: 'SYN (Synchronous Idle)', 23: 'ETB (End Trans Block)',
    24: 'CAN (Cancel)', 25: 'EM (End of Medium)', 26: 'SUB (Substitute)',
    27: 'ESC (Escape)', 28: 'FS (File Separator)', 29: 'GS (Group Separator)',
    30: 'RS (Record Separator)', 31: 'US (Unit Separator)', 32: 'Space',
    127: 'DEL (Delete)'
};

// Character descriptions
function getDescription(code) {
    if (CONTROL_CHARS[code]) return CONTROL_CHARS[code];
    if (code >= 48 && code <= 57) return `Digit ${code - 48}`;
    if (code >= 65 && code <= 90) return `Uppercase ${String.fromCharCode(code)}`;
    if (code >= 97 && code <= 122) return `Lowercase ${String.fromCharCode(code)}`;
    return String.fromCharCode(code);
}

// Display character
function displayChar(code) {
    if (code < 32 || code === 127) {
        return `<span class="control">^${String.fromCharCode(code < 32 ? code + 64 : 63)}</span>`;
    }
    return String.fromCharCode(code);
}

// Build table
function buildTable(start = 0, end = 127) {
    const tbody = document.getElementById('ascii-tbody');
    tbody.innerHTML = '';

    const search = document.getElementById('ascii-search').value.toLowerCase();

    for (let i = start; i <= end; i++) {
        const char = String.fromCharCode(i);
        const desc = getDescription(i);

        // Filter by search
        if (search) {
            const matches =
                i.toString().includes(search) ||
                i.toString(16).includes(search) ||
                char.toLowerCase().includes(search) ||
                desc.toLowerCase().includes(search);
            if (!matches) continue;
        }

        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${i}</td>
            <td>${i.toString(16).toUpperCase().padStart(2, '0')}</td>
            <td>${i.toString(8).padStart(3, '0')}</td>
            <td>${i.toString(2).padStart(8, '0')}</td>
            <td class="char-cell">${displayChar(i)}</td>
            <td>${desc}</td>
        `;
        row.onclick = () => selectChar(i);
        row.style.cursor = 'pointer';
        tbody.appendChild(row);
    }
}

// Show table section
function showTable(section) {
    document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
    event.target.classList.add('active');

    switch (section) {
        case 'control': buildTable(0, 31); break;
        case 'printable': buildTable(32, 126); break;
        case 'extended': buildTable(128, 255); break;
        default: buildTable(0, 127);
    }
}

// Select character and update converter
function selectChar(code) {
    document.getElementById('char-input').value = code >= 32 && code < 127 ? String.fromCharCode(code) : '';
    document.getElementById('dec-input').value = code;
    document.getElementById('hex-input').value = code.toString(16).toUpperCase().padStart(2, '0');
    document.getElementById('oct-input').value = code.toString(8).padStart(3, '0');
    document.getElementById('bin-input').value = code.toString(2).padStart(8, '0');
}

// Converter event listeners
document.getElementById('char-input').addEventListener('input', (e) => {
    const char = e.target.value;
    if (char) selectChar(char.charCodeAt(0));
});

document.getElementById('dec-input').addEventListener('input', (e) => {
    const val = parseInt(e.target.value);
    if (!isNaN(val) && val >= 0 && val <= 255) selectChar(val);
});

document.getElementById('hex-input').addEventListener('input', (e) => {
    const val = parseInt(e.target.value, 16);
    if (!isNaN(val) && val >= 0 && val <= 255) selectChar(val);
});

document.getElementById('oct-input').addEventListener('input', (e) => {
    const val = parseInt(e.target.value, 8);
    if (!isNaN(val) && val >= 0 && val <= 255) selectChar(val);
});

document.getElementById('bin-input').addEventListener('input', (e) => {
    const val = parseInt(e.target.value, 2);
    if (!isNaN(val) && val >= 0 && val <= 255) selectChar(val);
});

// String conversion
document.getElementById('text-input').addEventListener('input', (e) => {
    const text = e.target.value;

    const dec = Array.from(text).map(c => c.charCodeAt(0)).join(' ');
    const hex = Array.from(text).map(c => c.charCodeAt(0).toString(16).toUpperCase().padStart(2, '0')).join(' ');
    const bin = Array.from(text).map(c => c.charCodeAt(0).toString(2).padStart(8, '0')).join(' ');

    document.getElementById('text-dec').textContent = dec || '-';
    document.getElementById('text-hex').textContent = hex || '-';
    document.getElementById('text-bin').textContent = bin || '-';
});

// Search
document.getElementById('ascii-search').addEventListener('input', () => {
    const activeTab = document.querySelector('.tab-btn.active').textContent;
    if (activeTab.includes('Controle')) buildTable(0, 31);
    else if (activeTab.includes('Imprimables')) buildTable(32, 126);
    else if (activeTab.includes('Etendus')) buildTable(128, 255);
    else buildTable(0, 127);
});

// Initialize
buildTable();
selectChar(65);
</script>
