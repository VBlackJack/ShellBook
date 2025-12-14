---
tags:
  - tools
  - unicode
  - characters
---

# Unicode Lookup

Recherche et information sur les caracteres Unicode.

<div class="tool-container">

<div class="input-group">
    <label for="char-input">Caractere ou code :</label>
    <input type="text" id="char-input" placeholder="Entrez un caractere, U+xxxx, ou recherchez...">
</div>

<div id="char-result" class="char-result" style="display:none;">
    <div class="char-display" id="char-display"></div>
    <table>
        <tr><td>Caractere</td><td id="result-char">-</td></tr>
        <tr><td>Code Point</td><td id="result-codepoint">-</td></tr>
        <tr><td>Decimal</td><td id="result-decimal">-</td></tr>
        <tr><td>HTML Entity</td><td id="result-html">-</td></tr>
        <tr><td>CSS</td><td id="result-css">-</td></tr>
        <tr><td>JavaScript</td><td id="result-js">-</td></tr>
        <tr><td>UTF-8 Bytes</td><td id="result-utf8">-</td></tr>
        <tr><td>Nom</td><td id="result-name">-</td></tr>
    </table>
</div>

<h3>Caracteres courants</h3>

<div class="char-categories">
    <div class="char-category">
        <h4>Fleches</h4>
        <div class="char-grid">
            <span onclick="showChar(this)" title="U+2190">←</span>
            <span onclick="showChar(this)" title="U+2191">↑</span>
            <span onclick="showChar(this)" title="U+2192">→</span>
            <span onclick="showChar(this)" title="U+2193">↓</span>
            <span onclick="showChar(this)" title="U+21D0">⇐</span>
            <span onclick="showChar(this)" title="U+21D2">⇒</span>
            <span onclick="showChar(this)" title="U+21D4">⇔</span>
            <span onclick="showChar(this)" title="U+2794">➔</span>
            <span onclick="showChar(this)" title="U+27A1">➡</span>
            <span onclick="showChar(this)" title="U+2B06">⬆</span>
        </div>
    </div>
    <div class="char-category">
        <h4>Symboles</h4>
        <div class="char-grid">
            <span onclick="showChar(this)" title="U+2713">✓</span>
            <span onclick="showChar(this)" title="U+2717">✗</span>
            <span onclick="showChar(this)" title="U+2714">✔</span>
            <span onclick="showChar(this)" title="U+2718">✘</span>
            <span onclick="showChar(this)" title="U+2605">★</span>
            <span onclick="showChar(this)" title="U+2606">☆</span>
            <span onclick="showChar(this)" title="U+2665">♥</span>
            <span onclick="showChar(this)" title="U+266A">♪</span>
            <span onclick="showChar(this)" title="U+2600">☀</span>
            <span onclick="showChar(this)" title="U+2764">❤</span>
        </div>
    </div>
    <div class="char-category">
        <h4>Mathematiques</h4>
        <div class="char-grid">
            <span onclick="showChar(this)" title="U+00B1">±</span>
            <span onclick="showChar(this)" title="U+00D7">×</span>
            <span onclick="showChar(this)" title="U+00F7">÷</span>
            <span onclick="showChar(this)" title="U+2260">≠</span>
            <span onclick="showChar(this)" title="U+2264">≤</span>
            <span onclick="showChar(this)" title="U+2265">≥</span>
            <span onclick="showChar(this)" title="U+221E">∞</span>
            <span onclick="showChar(this)" title="U+221A">√</span>
            <span onclick="showChar(this)" title="U+03C0">π</span>
            <span onclick="showChar(this)" title="U+2211">∑</span>
        </div>
    </div>
    <div class="char-category">
        <h4>Devises</h4>
        <div class="char-grid">
            <span onclick="showChar(this)" title="U+20AC">€</span>
            <span onclick="showChar(this)" title="U+00A3">£</span>
            <span onclick="showChar(this)" title="U+00A5">¥</span>
            <span onclick="showChar(this)" title="U+20B9">₹</span>
            <span onclick="showChar(this)" title="U+20BD">₽</span>
            <span onclick="showChar(this)" title="U+0024">$</span>
            <span onclick="showChar(this)" title="U+20BF">₿</span>
            <span onclick="showChar(this)" title="U+00A2">¢</span>
        </div>
    </div>
    <div class="char-category">
        <h4>Box Drawing</h4>
        <div class="char-grid">
            <span onclick="showChar(this)" title="U+2500">─</span>
            <span onclick="showChar(this)" title="U+2502">│</span>
            <span onclick="showChar(this)" title="U+250C">┌</span>
            <span onclick="showChar(this)" title="U+2510">┐</span>
            <span onclick="showChar(this)" title="U+2514">└</span>
            <span onclick="showChar(this)" title="U+2518">┘</span>
            <span onclick="showChar(this)" title="U+251C">├</span>
            <span onclick="showChar(this)" title="U+2524">┤</span>
            <span onclick="showChar(this)" title="U+2550">═</span>
            <span onclick="showChar(this)" title="U+2551">║</span>
        </div>
    </div>
    <div class="char-category">
        <h4>Technique</h4>
        <div class="char-grid">
            <span onclick="showChar(this)" title="U+2318">⌘</span>
            <span onclick="showChar(this)" title="U+2325">⌥</span>
            <span onclick="showChar(this)" title="U+21E7">⇧</span>
            <span onclick="showChar(this)" title="U+2303">⌃</span>
            <span onclick="showChar(this)" title="U+232B">⌫</span>
            <span onclick="showChar(this)" title="U+21B5">↵</span>
            <span onclick="showChar(this)" title="U+2423">␣</span>
            <span onclick="showChar(this)" title="U+21B9">↹</span>
            <span onclick="showChar(this)" title="U+2026">…</span>
            <span onclick="showChar(this)" title="U+00B7">·</span>
        </div>
    </div>
</div>

</div>

## Reference

### Plages Unicode communes

| Bloc | Plage | Description |
|------|-------|-------------|
| ASCII | U+0000-007F | Caracteres de base |
| Latin-1 | U+0080-00FF | Caracteres latins etendus |
| Latin Extended-A | U+0100-017F | Caracteres europeens |
| Greek | U+0370-03FF | Alphabet grec |
| Cyrillic | U+0400-04FF | Alphabet cyrillique |
| Arabic | U+0600-06FF | Alphabet arabe |
| CJK | U+4E00-9FFF | Ideogrammes chinois |
| Emoji | U+1F600-1F64F | Emoticones |

### Encodages

| Caractere | UTF-8 | UTF-16 |
|-----------|-------|--------|
| A (U+0041) | 41 | 00 41 |
| e (U+00E9) | C3 A9 | 00 E9 |
| € (U+20AC) | E2 82 AC | 20 AC |
| 😀 (U+1F600) | F0 9F 98 80 | D8 3D DE 00 |

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
.input-group input {
    width: 100%;
    max-width: 400px;
    padding: 12px;
    font-size: 18px;
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    background: var(--md-default-bg-color);
    color: var(--md-default-fg-color);
}
.char-result {
    background: var(--md-default-bg-color);
    padding: 20px;
    border-radius: 4px;
    margin: 20px 0;
}
.char-display {
    font-size: 72px;
    text-align: center;
    padding: 20px;
    background: var(--md-code-bg-color);
    border-radius: 4px;
    margin-bottom: 15px;
}
.char-result table {
    width: 100%;
}
.char-result td {
    padding: 8px;
    border-bottom: 1px solid var(--md-default-fg-color--lightest);
}
.char-result td:first-child {
    font-weight: bold;
    width: 120px;
}
.char-result td:last-child {
    font-family: monospace;
}
.char-categories {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
    gap: 20px;
    margin-top: 20px;
}
.char-category {
    background: var(--md-default-bg-color);
    padding: 15px;
    border-radius: 4px;
}
.char-category h4 {
    margin: 0 0 10px 0;
    font-size: 14px;
}
.char-grid {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
}
.char-grid span {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 36px;
    height: 36px;
    font-size: 20px;
    background: var(--md-code-bg-color);
    border-radius: 4px;
    cursor: pointer;
    transition: transform 0.1s;
}
.char-grid span:hover {
    transform: scale(1.2);
    background: var(--md-primary-fg-color);
    color: white;
}
</style>

<script>
// Unicode character names (subset)
const charNames = {
    0x2190: 'LEFTWARDS ARROW',
    0x2191: 'UPWARDS ARROW',
    0x2192: 'RIGHTWARDS ARROW',
    0x2193: 'DOWNWARDS ARROW',
    0x2713: 'CHECK MARK',
    0x2717: 'BALLOT X',
    0x2714: 'HEAVY CHECK MARK',
    0x2718: 'HEAVY BALLOT X',
    0x2605: 'BLACK STAR',
    0x2606: 'WHITE STAR',
    0x20AC: 'EURO SIGN',
    0x00A3: 'POUND SIGN',
    0x00A5: 'YEN SIGN',
    0x221E: 'INFINITY',
    0x03C0: 'GREEK SMALL LETTER PI',
    0x2318: 'PLACE OF INTEREST SIGN (Command)',
    0x2325: 'OPTION KEY',
    0x21E7: 'UPWARDS WHITE ARROW (Shift)',
    0x2303: 'UP ARROWHEAD (Control)'
};

function getCharInfo(char) {
    const codePoint = char.codePointAt(0);
    const hex = codePoint.toString(16).toUpperCase().padStart(4, '0');

    // UTF-8 bytes
    const encoder = new TextEncoder();
    const bytes = encoder.encode(char);
    const utf8 = Array.from(bytes).map(b => b.toString(16).toUpperCase().padStart(2, '0')).join(' ');

    return {
        char: char,
        codePoint: 'U+' + hex,
        decimal: codePoint,
        html: '&#' + codePoint + ';',
        css: '\\' + hex,
        js: codePoint > 0xFFFF ? '\\u{' + hex + '}' : '\\u' + hex,
        utf8: utf8,
        name: charNames[codePoint] || 'Unknown'
    };
}

function displayChar(info) {
    document.getElementById('char-display').textContent = info.char;
    document.getElementById('result-char').textContent = info.char;
    document.getElementById('result-codepoint').textContent = info.codePoint;
    document.getElementById('result-decimal').textContent = info.decimal;
    document.getElementById('result-html').textContent = info.html;
    document.getElementById('result-css').textContent = info.css;
    document.getElementById('result-js').textContent = info.js;
    document.getElementById('result-utf8').textContent = info.utf8;
    document.getElementById('result-name').textContent = info.name;
    document.getElementById('char-result').style.display = 'block';
}

function showChar(el) {
    const char = el.textContent;
    const info = getCharInfo(char);
    displayChar(info);
    document.getElementById('char-input').value = char;
}

function processInput() {
    const input = document.getElementById('char-input').value.trim();

    if (!input) {
        document.getElementById('char-result').style.display = 'none';
        return;
    }

    let char;

    // Check if it's a U+xxxx format
    if (/^U\+[0-9A-Fa-f]{4,6}$/i.test(input)) {
        const codePoint = parseInt(input.slice(2), 16);
        char = String.fromCodePoint(codePoint);
    }
    // Check if it's a hex number
    else if (/^0x[0-9A-Fa-f]+$/i.test(input)) {
        const codePoint = parseInt(input, 16);
        char = String.fromCodePoint(codePoint);
    }
    // Check if it's a decimal number
    else if (/^\d+$/.test(input) && parseInt(input) > 127) {
        const codePoint = parseInt(input);
        char = String.fromCodePoint(codePoint);
    }
    // Otherwise treat as character
    else {
        char = input.charAt(0);
    }

    const info = getCharInfo(char);
    displayChar(info);
}

// Event listeners
document.getElementById('char-input').addEventListener('input', processInput);
</script>
