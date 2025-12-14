---
tags:
  - tools
  - url
  - encoding
  - web
---

# URL Encoder/Decoder

Encodage et decodage d'URLs et de parametres.

<div class="tool-container">

<div class="encoder-section">
    <h3>Encodage URL</h3>

    <div class="input-group">
        <label for="encode-input">Texte a encoder :</label>
        <textarea id="encode-input" rows="3" placeholder="Texte avec espaces & caractères spéciaux?"></textarea>
    </div>

    <div class="options-row">
        <label><input type="radio" name="encode-type" value="component" checked> encodeURIComponent (parametres)</label>
        <label><input type="radio" name="encode-type" value="uri"> encodeURI (URL complete)</label>
    </div>

    <button onclick="encodeURL()" class="action-btn">Encoder</button>

    <div class="input-group">
        <label>Resultat :</label>
        <textarea id="encode-output" rows="3" readonly></textarea>
        <button onclick="copyResult('encode-output')" class="copy-btn">Copier</button>
    </div>
</div>

<div class="decoder-section">
    <h3>Decodage URL</h3>

    <div class="input-group">
        <label for="decode-input">URL a decoder :</label>
        <textarea id="decode-input" rows="3" placeholder="Texte%20avec%20espaces%20%26%20caract%C3%A8res"></textarea>
    </div>

    <button onclick="decodeURL()" class="action-btn">Decoder</button>

    <div class="input-group">
        <label>Resultat :</label>
        <textarea id="decode-output" rows="3" readonly></textarea>
        <button onclick="copyResult('decode-output')" class="copy-btn">Copier</button>
    </div>
</div>

<div class="parser-section">
    <h3>Analyseur d'URL</h3>

    <div class="input-group">
        <label for="url-input">URL complete :</label>
        <input type="text" id="url-input" placeholder="https://user:pass@example.com:8080/path?query=value#hash">
    </div>

    <div id="url-parts" class="url-parts" style="display:none;">
        <table>
            <tr><td>Protocol</td><td id="part-protocol">-</td></tr>
            <tr><td>Username</td><td id="part-username">-</td></tr>
            <tr><td>Password</td><td id="part-password">-</td></tr>
            <tr><td>Hostname</td><td id="part-hostname">-</td></tr>
            <tr><td>Port</td><td id="part-port">-</td></tr>
            <tr><td>Pathname</td><td id="part-pathname">-</td></tr>
            <tr><td>Search</td><td id="part-search">-</td></tr>
            <tr><td>Hash</td><td id="part-hash">-</td></tr>
        </table>

        <h4>Parametres</h4>
        <div id="url-params"></div>
    </div>
</div>

</div>

## Reference encodage

### Caracteres reserves

| Caractere | Encode | Description |
|-----------|--------|-------------|
| ` ` (espace) | `%20` ou `+` | Espace |
| `!` | `%21` | Point d'exclamation |
| `#` | `%23` | Hash/Fragment |
| `$` | `%24` | Dollar |
| `%` | `%25` | Pourcent |
| `&` | `%26` | Esperluette |
| `'` | `%27` | Apostrophe |
| `(` | `%28` | Parenthese ouvrante |
| `)` | `%29` | Parenthese fermante |
| `*` | `%2A` | Asterisque |
| `+` | `%2B` | Plus |
| `,` | `%2C` | Virgule |
| `/` | `%2F` | Slash |
| `:` | `%3A` | Deux-points |
| `;` | `%3B` | Point-virgule |
| `=` | `%3D` | Egal |
| `?` | `%3F` | Point d'interrogation |
| `@` | `%40` | Arobase |
| `[` | `%5B` | Crochet ouvrant |
| `]` | `%5D` | Crochet fermant |

### Caracteres speciaux

| Caractere | Encode | Description |
|-----------|--------|-------------|
| `é` | `%C3%A9` | e accent aigu (UTF-8) |
| `è` | `%C3%A8` | e accent grave |
| `à` | `%C3%A0` | a accent grave |
| `ç` | `%C3%A7` | c cedille |
| `€` | `%E2%82%AC` | Euro |

### Difference encodeURI vs encodeURIComponent

```javascript
// encodeURI - preserve URL structure
encodeURI("https://example.com/path?q=hello world")
// "https://example.com/path?q=hello%20world"

// encodeURIComponent - encode everything
encodeURIComponent("https://example.com/path?q=hello world")
// "https%3A%2F%2Fexample.com%2Fpath%3Fq%3Dhello%20world"
```

!!! tip "Quand utiliser quoi"
    - **encodeURIComponent** : pour les valeurs de parametres
    - **encodeURI** : pour une URL complete (preserve :/?#)

### CLI

```bash
# Python
python -c "import urllib.parse; print(urllib.parse.quote('hello world'))"

# Curl (auto-encode)
curl -G --data-urlencode "q=hello world" https://example.com

# PowerShell
[System.Uri]::EscapeDataString("hello world")
```

<style>
.tool-container {
    background: var(--md-code-bg-color);
    padding: 20px;
    border-radius: 8px;
    margin: 20px 0;
}
.encoder-section, .decoder-section, .parser-section {
    background: var(--md-default-bg-color);
    padding: 20px;
    border-radius: 4px;
    margin-bottom: 20px;
}
.encoder-section h3, .decoder-section h3, .parser-section h3 {
    margin: 0 0 15px 0;
}
.input-group {
    margin: 15px 0;
    position: relative;
}
.input-group label {
    display: block;
    font-weight: bold;
    margin-bottom: 5px;
}
.input-group textarea, .input-group input[type="text"] {
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
.options-row {
    margin: 10px 0;
}
.options-row label {
    margin-right: 20px;
    cursor: pointer;
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
.copy-btn {
    position: absolute;
    right: 10px;
    bottom: 10px;
    padding: 5px 10px;
    background: var(--md-primary-fg-color);
    color: white;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    font-size: 12px;
}
.url-parts {
    margin-top: 15px;
    padding: 15px;
    background: var(--md-code-bg-color);
    border-radius: 4px;
}
.url-parts table {
    width: 100%;
    margin-bottom: 15px;
}
.url-parts td {
    padding: 8px;
    border-bottom: 1px solid var(--md-default-fg-color--lightest);
}
.url-parts td:first-child {
    font-weight: bold;
    width: 100px;
}
.url-parts td:last-child {
    font-family: monospace;
    word-break: break-all;
}
.url-parts h4 {
    margin: 15px 0 10px 0;
}
#url-params {
    font-family: monospace;
    font-size: 13px;
}
#url-params .param-row {
    display: flex;
    gap: 10px;
    padding: 5px 0;
    border-bottom: 1px solid var(--md-default-fg-color--lightest);
}
#url-params .param-key {
    font-weight: bold;
    min-width: 150px;
}
</style>

<script>
function encodeURL() {
    const input = document.getElementById('encode-input').value;
    const type = document.querySelector('input[name="encode-type"]:checked').value;

    let result;
    if (type === 'component') {
        result = encodeURIComponent(input);
    } else {
        result = encodeURI(input);
    }

    document.getElementById('encode-output').value = result;
}

function decodeURL() {
    const input = document.getElementById('decode-input').value;

    try {
        const result = decodeURIComponent(input.replace(/\+/g, ' '));
        document.getElementById('decode-output').value = result;
    } catch (e) {
        document.getElementById('decode-output').value = 'Erreur: ' + e.message;
    }
}

function parseURL() {
    const input = document.getElementById('url-input').value.trim();
    const partsDiv = document.getElementById('url-parts');

    if (!input) {
        partsDiv.style.display = 'none';
        return;
    }

    try {
        const url = new URL(input);

        document.getElementById('part-protocol').textContent = url.protocol || '-';
        document.getElementById('part-username').textContent = url.username || '-';
        document.getElementById('part-password').textContent = url.password || '-';
        document.getElementById('part-hostname').textContent = url.hostname || '-';
        document.getElementById('part-port').textContent = url.port || '(default)';
        document.getElementById('part-pathname').textContent = url.pathname || '-';
        document.getElementById('part-search').textContent = url.search || '-';
        document.getElementById('part-hash').textContent = url.hash || '-';

        // Parse query params
        const paramsDiv = document.getElementById('url-params');
        if (url.searchParams && url.search) {
            let html = '';
            for (const [key, value] of url.searchParams) {
                html += `<div class="param-row"><span class="param-key">${escapeHtml(key)}</span><span class="param-value">${escapeHtml(value)}</span></div>`;
            }
            paramsDiv.innerHTML = html || '<em>Aucun parametre</em>';
        } else {
            paramsDiv.innerHTML = '<em>Aucun parametre</em>';
        }

        partsDiv.style.display = 'block';

    } catch (e) {
        partsDiv.style.display = 'block';
        document.getElementById('part-protocol').textContent = 'URL invalide';
        ['username', 'password', 'hostname', 'port', 'pathname', 'search', 'hash'].forEach(part => {
            document.getElementById('part-' + part).textContent = '-';
        });
        document.getElementById('url-params').innerHTML = '';
    }
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function copyResult(id) {
    const textarea = document.getElementById(id);
    textarea.select();
    document.execCommand('copy');
}

// Event listener
document.getElementById('url-input').addEventListener('input', parseURL);
</script>
