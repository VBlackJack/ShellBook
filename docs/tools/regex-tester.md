---
tags:
  - tools
  - regex
  - scripting
---

# Regex Tester

Testeur d'expressions regulieres en temps reel.

<div class="tool-container">

<div class="input-group">
    <label for="regex-pattern">Pattern :</label>
    <div class="pattern-input">
        <span class="delimiter">/</span>
        <input type="text" id="regex-pattern" placeholder="[a-z]+@[a-z]+\.[a-z]{2,}">
        <span class="delimiter">/</span>
        <input type="text" id="regex-flags" value="gm" maxlength="6" class="flags-input">
    </div>
</div>

<div class="flags-checkboxes">
    <label><input type="checkbox" id="flag-g" checked> g (global)</label>
    <label><input type="checkbox" id="flag-i"> i (insensible casse)</label>
    <label><input type="checkbox" id="flag-m" checked> m (multiline)</label>
    <label><input type="checkbox" id="flag-s"> s (dotAll)</label>
</div>

<div class="input-group">
    <label for="regex-text">Texte de test :</label>
    <textarea id="regex-text" rows="8" placeholder="Entrez le texte a tester...">user@example.com
admin@company.org
invalid-email
test.user@domain.co.uk
info@localhost</textarea>
</div>

<div id="regex-error" class="error-box" style="display:none;"></div>

<div class="results-section">
    <div class="result-box">
        <h4>Resultat</h4>
        <div id="regex-result" class="highlighted-text"></div>
    </div>
    <div class="matches-box">
        <h4>Correspondances (<span id="match-count">0</span>)</h4>
        <ul id="match-list"></ul>
    </div>
</div>

<h3>Presets utiles</h3>

<div class="presets-grid">
    <button onclick="setRegex('[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}', 'gi')">Email</button>
    <button onclick="setRegex('https?://[\\w\\-._~:/?#[\\]@!$&\\'()*+,;=%]+', 'gi')">URL</button>
    <button onclick="setRegex('\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b', 'g')">IPv4</button>
    <button onclick="setRegex('^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d).{8,}$', 'm')">Password fort</button>
    <button onclick="setRegex('\\b\\d{4}-\\d{2}-\\d{2}\\b', 'g')">Date ISO</button>
    <button onclick="setRegex('\\b\\d{2}/\\d{2}/\\d{4}\\b', 'g')">Date FR</button>
    <button onclick="setRegex('^#?([a-fA-F0-9]{6}|[a-fA-F0-9]{3})$', 'gm')">Hex Color</button>
    <button onclick="setRegex('\\b[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}\\b', 'gi')">MAC Address</button>
    <button onclick="setRegex('^\\+?[0-9]{10,14}$', 'gm')">Telephone</button>
    <button onclick="setRegex('<[^>]+>', 'g')">Tags HTML</button>
</div>

</div>

## Reference Regex

### Caracteres speciaux

| Pattern | Description |
|---------|-------------|
| `.` | N'importe quel caractere (sauf newline) |
| `\d` | Chiffre [0-9] |
| `\D` | Non-chiffre |
| `\w` | Mot [a-zA-Z0-9_] |
| `\W` | Non-mot |
| `\s` | Espace blanc |
| `\S` | Non-espace |
| `\b` | Limite de mot |

### Quantificateurs

| Pattern | Description |
|---------|-------------|
| `*` | 0 ou plus |
| `+` | 1 ou plus |
| `?` | 0 ou 1 |
| `{n}` | Exactement n |
| `{n,}` | n ou plus |
| `{n,m}` | Entre n et m |

### Ancres

| Pattern | Description |
|---------|-------------|
| `^` | Debut de ligne |
| `$` | Fin de ligne |
| `\b` | Limite de mot |
| `\B` | Non-limite |

### Groupes

| Pattern | Description |
|---------|-------------|
| `(abc)` | Groupe de capture |
| `(?:abc)` | Groupe non-capturant |
| `(?=abc)` | Lookahead positif |
| `(?!abc)` | Lookahead negatif |
| `(?<=abc)` | Lookbehind positif |
| `(?<!abc)` | Lookbehind negatif |

### Classes de caracteres

| Pattern | Description |
|---------|-------------|
| `[abc]` | a, b ou c |
| `[^abc]` | Pas a, b, c |
| `[a-z]` | a a z |
| `[A-Z]` | A a Z |
| `[0-9]` | 0 a 9 |

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
    margin-bottom: 5px;
    font-weight: bold;
}
.pattern-input {
    display: flex;
    align-items: center;
    background: var(--md-default-bg-color);
    border: 2px solid var(--md-primary-fg-color);
    border-radius: 4px;
    padding: 5px 10px;
}
.pattern-input .delimiter {
    font-family: monospace;
    font-size: 20px;
    color: var(--md-primary-fg-color);
}
.pattern-input input {
    flex: 1;
    padding: 10px;
    font-family: monospace;
    font-size: 16px;
    border: none;
    background: transparent;
    color: var(--md-default-fg-color);
    outline: none;
}
.flags-input {
    width: 50px !important;
    flex: none !important;
    text-align: center;
}
.flags-checkboxes {
    margin: 10px 0;
}
.flags-checkboxes label {
    margin-right: 15px;
    cursor: pointer;
}
.input-group textarea {
    width: 100%;
    padding: 12px;
    font-family: monospace;
    font-size: 14px;
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    background: var(--md-default-bg-color);
    color: var(--md-default-fg-color);
    resize: vertical;
}
.error-box {
    padding: 10px 15px;
    background: #f8d7da;
    border: 1px solid #f5c6cb;
    border-radius: 4px;
    color: #721c24;
    margin: 10px 0;
}
.results-section {
    display: flex;
    gap: 20px;
    flex-wrap: wrap;
    margin-top: 20px;
}
.result-box, .matches-box {
    flex: 1;
    min-width: 300px;
    background: var(--md-default-bg-color);
    padding: 15px;
    border-radius: 4px;
    border: 1px solid var(--md-default-fg-color--lighter);
}
.result-box h4, .matches-box h4 {
    margin: 0 0 10px 0;
}
.highlighted-text {
    font-family: monospace;
    white-space: pre-wrap;
    word-break: break-all;
    line-height: 1.8;
}
.highlighted-text .match {
    background: #ffeb3b;
    color: #000;
    padding: 2px 4px;
    border-radius: 2px;
}
.matches-box ul {
    margin: 0;
    padding-left: 20px;
    max-height: 200px;
    overflow-y: auto;
}
.matches-box li {
    font-family: monospace;
    margin: 5px 0;
    padding: 3px 6px;
    background: var(--md-code-bg-color);
    border-radius: 2px;
}
.presets-grid {
    display: flex;
    gap: 10px;
    flex-wrap: wrap;
    margin: 15px 0;
}
.presets-grid button {
    padding: 8px 16px;
    border: 1px solid var(--md-primary-fg-color);
    border-radius: 4px;
    background: var(--md-default-bg-color);
    color: var(--md-default-fg-color);
    cursor: pointer;
    font-size: 13px;
}
.presets-grid button:hover {
    background: var(--md-primary-fg-color);
    color: white;
}
</style>

<script>
function updateFlags() {
    let flags = '';
    if (document.getElementById('flag-g').checked) flags += 'g';
    if (document.getElementById('flag-i').checked) flags += 'i';
    if (document.getElementById('flag-m').checked) flags += 'm';
    if (document.getElementById('flag-s').checked) flags += 's';
    document.getElementById('regex-flags').value = flags;
    testRegex();
}

function syncFlags() {
    const flags = document.getElementById('regex-flags').value;
    document.getElementById('flag-g').checked = flags.includes('g');
    document.getElementById('flag-i').checked = flags.includes('i');
    document.getElementById('flag-m').checked = flags.includes('m');
    document.getElementById('flag-s').checked = flags.includes('s');
    testRegex();
}

function testRegex() {
    const pattern = document.getElementById('regex-pattern').value;
    const flags = document.getElementById('regex-flags').value;
    const text = document.getElementById('regex-text').value;
    const errorBox = document.getElementById('regex-error');
    const resultDiv = document.getElementById('regex-result');
    const matchList = document.getElementById('match-list');
    const matchCount = document.getElementById('match-count');

    errorBox.style.display = 'none';

    if (!pattern) {
        resultDiv.textContent = text;
        matchList.innerHTML = '';
        matchCount.textContent = '0';
        return;
    }

    try {
        const regex = new RegExp(pattern, flags);
        const matches = [];
        let match;

        // Collect all matches
        if (flags.includes('g')) {
            while ((match = regex.exec(text)) !== null) {
                matches.push({
                    value: match[0],
                    index: match.index,
                    groups: match.slice(1)
                });
                if (match.index === regex.lastIndex) regex.lastIndex++;
            }
        } else {
            match = regex.exec(text);
            if (match) {
                matches.push({
                    value: match[0],
                    index: match.index,
                    groups: match.slice(1)
                });
            }
        }

        // Highlight matches in text
        let highlighted = '';
        let lastIndex = 0;

        // Sort matches by index
        matches.sort((a, b) => a.index - b.index);

        for (const m of matches) {
            highlighted += escapeHtml(text.slice(lastIndex, m.index));
            highlighted += `<span class="match">${escapeHtml(m.value)}</span>`;
            lastIndex = m.index + m.value.length;
        }
        highlighted += escapeHtml(text.slice(lastIndex));

        resultDiv.innerHTML = highlighted;

        // Update match list
        matchList.innerHTML = matches.map((m, i) => {
            let html = `<li>${i + 1}. "${escapeHtml(m.value)}"`;
            if (m.groups.length > 0) {
                html += ` <small>[${m.groups.map(g => g || '').join(', ')}]</small>`;
            }
            html += '</li>';
            return html;
        }).join('');

        matchCount.textContent = matches.length;

    } catch (e) {
        errorBox.textContent = 'Erreur: ' + e.message;
        errorBox.style.display = 'block';
        resultDiv.textContent = text;
        matchList.innerHTML = '';
        matchCount.textContent = '0';
    }
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function setRegex(pattern, flags) {
    document.getElementById('regex-pattern').value = pattern;
    document.getElementById('regex-flags').value = flags;
    syncFlags();
}

// Event listeners
document.getElementById('regex-pattern').addEventListener('input', testRegex);
document.getElementById('regex-flags').addEventListener('input', syncFlags);
document.getElementById('regex-text').addEventListener('input', testRegex);

document.querySelectorAll('.flags-checkboxes input').forEach(cb => {
    cb.addEventListener('change', updateFlags);
});

// Initial test
testRegex();
</script>
