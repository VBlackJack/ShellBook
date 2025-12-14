---
tags:
  - tools
  - html
  - entities
  - encoding
---

# HTML Entities

Reference et convertisseur d'entites HTML.

<div class="tool-container">

<h3>Convertisseur</h3>

<div class="converter-section">
    <div class="input-group">
        <label for="text-input">Texte :</label>
        <textarea id="text-input" rows="3" placeholder="Texte avec caractères spéciaux < > & é ç"></textarea>
    </div>
    <div class="button-row">
        <button onclick="encodeHtml()" class="action-btn">Encoder HTML</button>
        <button onclick="decodeHtml()" class="action-btn secondary">Decoder HTML</button>
    </div>
    <div class="input-group">
        <label>Resultat :</label>
        <textarea id="html-output" rows="3" readonly></textarea>
        <button onclick="copyResult()" class="copy-btn">Copier</button>
    </div>
</div>

<h3>Entites essentielles</h3>

<div class="entities-section">
    <table class="entities-table">
        <tr><th>Char</th><th>Entity</th><th>Code</th><th>Description</th></tr>
        <tr><td>&lt;</td><td>&amp;lt;</td><td>&amp;#60;</td><td>Inferieur a</td></tr>
        <tr><td>&gt;</td><td>&amp;gt;</td><td>&amp;#62;</td><td>Superieur a</td></tr>
        <tr><td>&amp;</td><td>&amp;amp;</td><td>&amp;#38;</td><td>Esperluette</td></tr>
        <tr><td>&quot;</td><td>&amp;quot;</td><td>&amp;#34;</td><td>Guillemet double</td></tr>
        <tr><td>&apos;</td><td>&amp;apos;</td><td>&amp;#39;</td><td>Apostrophe</td></tr>
        <tr><td>&nbsp;</td><td>&amp;nbsp;</td><td>&amp;#160;</td><td>Espace insecable</td></tr>
    </table>
</div>

<h3>Caracteres speciaux</h3>

<div class="char-tabs">
    <button class="tab-btn active" onclick="showTab('accents')">Accents</button>
    <button class="tab-btn" onclick="showTab('symbols')">Symboles</button>
    <button class="tab-btn" onclick="showTab('punctuation')">Ponctuation</button>
    <button class="tab-btn" onclick="showTab('currency')">Devises</button>
    <button class="tab-btn" onclick="showTab('arrows')">Fleches</button>
    <button class="tab-btn" onclick="showTab('math')">Maths</button>
</div>

<div id="tab-accents" class="char-tab-content active">
    <table class="entities-table">
        <tr><th>Char</th><th>Entity</th><th>Code</th></tr>
        <tr><td>à</td><td>&amp;agrave;</td><td>&amp;#224;</td></tr>
        <tr><td>á</td><td>&amp;aacute;</td><td>&amp;#225;</td></tr>
        <tr><td>â</td><td>&amp;acirc;</td><td>&amp;#226;</td></tr>
        <tr><td>ä</td><td>&amp;auml;</td><td>&amp;#228;</td></tr>
        <tr><td>è</td><td>&amp;egrave;</td><td>&amp;#232;</td></tr>
        <tr><td>é</td><td>&amp;eacute;</td><td>&amp;#233;</td></tr>
        <tr><td>ê</td><td>&amp;ecirc;</td><td>&amp;#234;</td></tr>
        <tr><td>ë</td><td>&amp;euml;</td><td>&amp;#235;</td></tr>
        <tr><td>ì</td><td>&amp;igrave;</td><td>&amp;#236;</td></tr>
        <tr><td>í</td><td>&amp;iacute;</td><td>&amp;#237;</td></tr>
        <tr><td>î</td><td>&amp;icirc;</td><td>&amp;#238;</td></tr>
        <tr><td>ï</td><td>&amp;iuml;</td><td>&amp;#239;</td></tr>
        <tr><td>ò</td><td>&amp;ograve;</td><td>&amp;#242;</td></tr>
        <tr><td>ó</td><td>&amp;oacute;</td><td>&amp;#243;</td></tr>
        <tr><td>ô</td><td>&amp;ocirc;</td><td>&amp;#244;</td></tr>
        <tr><td>ö</td><td>&amp;ouml;</td><td>&amp;#246;</td></tr>
        <tr><td>ù</td><td>&amp;ugrave;</td><td>&amp;#249;</td></tr>
        <tr><td>ú</td><td>&amp;uacute;</td><td>&amp;#250;</td></tr>
        <tr><td>û</td><td>&amp;ucirc;</td><td>&amp;#251;</td></tr>
        <tr><td>ü</td><td>&amp;uuml;</td><td>&amp;#252;</td></tr>
        <tr><td>ç</td><td>&amp;ccedil;</td><td>&amp;#231;</td></tr>
        <tr><td>ñ</td><td>&amp;ntilde;</td><td>&amp;#241;</td></tr>
    </table>
</div>

<div id="tab-symbols" class="char-tab-content">
    <table class="entities-table">
        <tr><th>Char</th><th>Entity</th><th>Code</th></tr>
        <tr><td>©</td><td>&amp;copy;</td><td>&amp;#169;</td></tr>
        <tr><td>®</td><td>&amp;reg;</td><td>&amp;#174;</td></tr>
        <tr><td>™</td><td>&amp;trade;</td><td>&amp;#8482;</td></tr>
        <tr><td>°</td><td>&amp;deg;</td><td>&amp;#176;</td></tr>
        <tr><td>§</td><td>&amp;sect;</td><td>&amp;#167;</td></tr>
        <tr><td>¶</td><td>&amp;para;</td><td>&amp;#182;</td></tr>
        <tr><td>†</td><td>&amp;dagger;</td><td>&amp;#8224;</td></tr>
        <tr><td>‡</td><td>&amp;Dagger;</td><td>&amp;#8225;</td></tr>
        <tr><td>•</td><td>&amp;bull;</td><td>&amp;#8226;</td></tr>
        <tr><td>…</td><td>&amp;hellip;</td><td>&amp;#8230;</td></tr>
    </table>
</div>

<div id="tab-punctuation" class="char-tab-content">
    <table class="entities-table">
        <tr><th>Char</th><th>Entity</th><th>Code</th></tr>
        <tr><td>'</td><td>&amp;lsquo;</td><td>&amp;#8216;</td></tr>
        <tr><td>'</td><td>&amp;rsquo;</td><td>&amp;#8217;</td></tr>
        <tr><td>"</td><td>&amp;ldquo;</td><td>&amp;#8220;</td></tr>
        <tr><td>"</td><td>&amp;rdquo;</td><td>&amp;#8221;</td></tr>
        <tr><td>«</td><td>&amp;laquo;</td><td>&amp;#171;</td></tr>
        <tr><td>»</td><td>&amp;raquo;</td><td>&amp;#187;</td></tr>
        <tr><td>–</td><td>&amp;ndash;</td><td>&amp;#8211;</td></tr>
        <tr><td>—</td><td>&amp;mdash;</td><td>&amp;#8212;</td></tr>
        <tr><td>¿</td><td>&amp;iquest;</td><td>&amp;#191;</td></tr>
        <tr><td>¡</td><td>&amp;iexcl;</td><td>&amp;#161;</td></tr>
    </table>
</div>

<div id="tab-currency" class="char-tab-content">
    <table class="entities-table">
        <tr><th>Char</th><th>Entity</th><th>Code</th></tr>
        <tr><td>€</td><td>&amp;euro;</td><td>&amp;#8364;</td></tr>
        <tr><td>£</td><td>&amp;pound;</td><td>&amp;#163;</td></tr>
        <tr><td>¥</td><td>&amp;yen;</td><td>&amp;#165;</td></tr>
        <tr><td>¢</td><td>&amp;cent;</td><td>&amp;#162;</td></tr>
        <tr><td>$</td><td>-</td><td>&amp;#36;</td></tr>
        <tr><td>¤</td><td>&amp;curren;</td><td>&amp;#164;</td></tr>
    </table>
</div>

<div id="tab-arrows" class="char-tab-content">
    <table class="entities-table">
        <tr><th>Char</th><th>Entity</th><th>Code</th></tr>
        <tr><td>←</td><td>&amp;larr;</td><td>&amp;#8592;</td></tr>
        <tr><td>→</td><td>&amp;rarr;</td><td>&amp;#8594;</td></tr>
        <tr><td>↑</td><td>&amp;uarr;</td><td>&amp;#8593;</td></tr>
        <tr><td>↓</td><td>&amp;darr;</td><td>&amp;#8595;</td></tr>
        <tr><td>↔</td><td>&amp;harr;</td><td>&amp;#8596;</td></tr>
        <tr><td>⇐</td><td>&amp;lArr;</td><td>&amp;#8656;</td></tr>
        <tr><td>⇒</td><td>&amp;rArr;</td><td>&amp;#8658;</td></tr>
        <tr><td>⇑</td><td>&amp;uArr;</td><td>&amp;#8657;</td></tr>
        <tr><td>⇓</td><td>&amp;dArr;</td><td>&amp;#8659;</td></tr>
        <tr><td>⇔</td><td>&amp;hArr;</td><td>&amp;#8660;</td></tr>
    </table>
</div>

<div id="tab-math" class="char-tab-content">
    <table class="entities-table">
        <tr><th>Char</th><th>Entity</th><th>Code</th></tr>
        <tr><td>±</td><td>&amp;plusmn;</td><td>&amp;#177;</td></tr>
        <tr><td>×</td><td>&amp;times;</td><td>&amp;#215;</td></tr>
        <tr><td>÷</td><td>&amp;divide;</td><td>&amp;#247;</td></tr>
        <tr><td>≠</td><td>&amp;ne;</td><td>&amp;#8800;</td></tr>
        <tr><td>≤</td><td>&amp;le;</td><td>&amp;#8804;</td></tr>
        <tr><td>≥</td><td>&amp;ge;</td><td>&amp;#8805;</td></tr>
        <tr><td>∞</td><td>&amp;infin;</td><td>&amp;#8734;</td></tr>
        <tr><td>√</td><td>&amp;radic;</td><td>&amp;#8730;</td></tr>
        <tr><td>∑</td><td>&amp;sum;</td><td>&amp;#8721;</td></tr>
        <tr><td>∏</td><td>&amp;prod;</td><td>&amp;#8719;</td></tr>
        <tr><td>π</td><td>&amp;pi;</td><td>&amp;#960;</td></tr>
        <tr><td>∈</td><td>&amp;isin;</td><td>&amp;#8712;</td></tr>
        <tr><td>∅</td><td>&amp;empty;</td><td>&amp;#8709;</td></tr>
    </table>
</div>

</div>

<style>
.tool-container {
    background: var(--md-code-bg-color);
    padding: 20px;
    border-radius: 8px;
    margin: 20px 0;
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
.button-row {
    display: flex;
    gap: 10px;
    flex-wrap: wrap;
}
.action-btn {
    padding: 10px 20px;
    background: var(--md-primary-fg-color);
    color: white;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    font-size: 14px;
}
.action-btn.secondary {
    background: var(--md-default-bg-color);
    color: var(--md-default-fg-color);
    border: 1px solid var(--md-default-fg-color--lighter);
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
.entities-section {
    margin: 20px 0;
}
.entities-table {
    width: 100%;
    background: var(--md-default-bg-color);
    border-collapse: collapse;
}
.entities-table th, .entities-table td {
    padding: 8px 12px;
    text-align: left;
    border-bottom: 1px solid var(--md-default-fg-color--lightest);
}
.entities-table th {
    background: var(--md-code-bg-color);
    font-weight: bold;
}
.entities-table td {
    font-family: monospace;
}
.entities-table td:first-child {
    font-size: 20px;
    width: 50px;
    text-align: center;
}
.char-tabs {
    display: flex;
    gap: 5px;
    flex-wrap: wrap;
    margin: 20px 0 10px;
}
.tab-btn {
    padding: 8px 16px;
    border: none;
    background: var(--md-default-bg-color);
    color: var(--md-default-fg-color);
    cursor: pointer;
    border-radius: 4px;
    font-size: 13px;
}
.tab-btn.active {
    background: var(--md-primary-fg-color);
    color: white;
}
.char-tab-content {
    display: none;
}
.char-tab-content.active {
    display: block;
}
</style>

<script>
function encodeHtml() {
    const input = document.getElementById('text-input').value;
    const output = input
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
    document.getElementById('html-output').value = output;
}

function decodeHtml() {
    const input = document.getElementById('text-input').value;
    const textarea = document.createElement('textarea');
    textarea.innerHTML = input;
    document.getElementById('html-output').value = textarea.value;
}

function copyResult() {
    const output = document.getElementById('html-output');
    output.select();
    document.execCommand('copy');
}

function showTab(tab) {
    document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
    document.querySelectorAll('.char-tab-content').forEach(content => content.classList.remove('active'));

    document.querySelector(`.tab-btn[onclick="showTab('${tab}')"]`).classList.add('active');
    document.getElementById('tab-' + tab).classList.add('active');
}
</script>
