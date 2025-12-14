---
tags:
  - tools
  - reference
  - ansi
  - terminal
  - colors
---

# ANSI Escape Codes

Reference interactive des codes ANSI pour la coloration et le formatage terminal.

<div class="tool-container">

<div class="preview-section">
    <h3>Apercu</h3>
    <div class="preview-box" id="preview-box">
        <span id="preview-text">Texte d'exemple</span>
    </div>
    <div class="preview-code">
        <code id="preview-code">\e[0m</code>
        <button onclick="copyCode()" class="copy-btn">Copier</button>
    </div>
</div>

<div class="builder-section">
    <h3>Constructeur de Code</h3>
    <div class="builder-grid">
        <div class="builder-group">
            <label>Style</label>
            <div class="style-buttons">
                <button class="style-btn" data-code="1" onclick="toggleStyle(1)">Gras</button>
                <button class="style-btn" data-code="2" onclick="toggleStyle(2)">Dim</button>
                <button class="style-btn" data-code="3" onclick="toggleStyle(3)">Italique</button>
                <button class="style-btn" data-code="4" onclick="toggleStyle(4)">Souligne</button>
                <button class="style-btn" data-code="5" onclick="toggleStyle(5)">Clignotant</button>
                <button class="style-btn" data-code="7" onclick="toggleStyle(7)">Inverse</button>
                <button class="style-btn" data-code="9" onclick="toggleStyle(9)">Barre</button>
            </div>
        </div>
        <div class="builder-group">
            <label>Couleur de texte (Foreground)</label>
            <div class="color-grid" id="fg-colors"></div>
        </div>
        <div class="builder-group">
            <label>Couleur de fond (Background)</label>
            <div class="color-grid" id="bg-colors"></div>
        </div>
    </div>
    <button onclick="resetStyles()" class="reset-btn">Reset</button>
</div>

<div class="colors-section">
    <h3>Palette 256 Couleurs</h3>
    <div class="palette-256" id="palette-256"></div>
    <div class="color-info">
        <span>Selectionnee: <strong id="selected-color">-</strong></span>
        <span>Code FG: <code id="fg-code">38;5;n</code></span>
        <span>Code BG: <code id="bg-code">48;5;n</code></span>
    </div>
</div>

<div class="reference-section">
    <h3>Reference Rapide</h3>

    <div class="ref-group">
        <h4>Styles</h4>
        <table class="ref-table">
            <tr><td><code>\e[0m</code></td><td>Reset</td><td>Reinitialiser tous les styles</td></tr>
            <tr><td><code>\e[1m</code></td><td>Bold</td><td>Gras</td></tr>
            <tr><td><code>\e[2m</code></td><td>Dim</td><td>Attenue</td></tr>
            <tr><td><code>\e[3m</code></td><td>Italic</td><td>Italique</td></tr>
            <tr><td><code>\e[4m</code></td><td>Underline</td><td>Souligne</td></tr>
            <tr><td><code>\e[5m</code></td><td>Blink</td><td>Clignotant</td></tr>
            <tr><td><code>\e[7m</code></td><td>Reverse</td><td>Inverse FG/BG</td></tr>
            <tr><td><code>\e[8m</code></td><td>Hidden</td><td>Cache</td></tr>
            <tr><td><code>\e[9m</code></td><td>Strike</td><td>Barre</td></tr>
        </table>
    </div>

    <div class="ref-group">
        <h4>Couleurs Standard (30-37 FG, 40-47 BG)</h4>
        <table class="ref-table colors-ref">
            <tr>
                <td><span class="color-sample" style="background:#000"></span><code>30/40</code> Black</td>
                <td><span class="color-sample" style="background:#c00"></span><code>31/41</code> Red</td>
                <td><span class="color-sample" style="background:#0c0"></span><code>32/42</code> Green</td>
                <td><span class="color-sample" style="background:#cc0"></span><code>33/43</code> Yellow</td>
            </tr>
            <tr>
                <td><span class="color-sample" style="background:#00c"></span><code>34/44</code> Blue</td>
                <td><span class="color-sample" style="background:#c0c"></span><code>35/45</code> Magenta</td>
                <td><span class="color-sample" style="background:#0cc"></span><code>36/46</code> Cyan</td>
                <td><span class="color-sample" style="background:#ccc"></span><code>37/47</code> White</td>
            </tr>
        </table>
    </div>

    <div class="ref-group">
        <h4>Couleurs Bright (90-97 FG, 100-107 BG)</h4>
        <table class="ref-table colors-ref">
            <tr>
                <td><span class="color-sample" style="background:#666"></span><code>90/100</code> Bright Black</td>
                <td><span class="color-sample" style="background:#f66"></span><code>91/101</code> Bright Red</td>
                <td><span class="color-sample" style="background:#6f6"></span><code>92/102</code> Bright Green</td>
                <td><span class="color-sample" style="background:#ff6"></span><code>93/103</code> Bright Yellow</td>
            </tr>
            <tr>
                <td><span class="color-sample" style="background:#66f"></span><code>94/104</code> Bright Blue</td>
                <td><span class="color-sample" style="background:#f6f"></span><code>95/105</code> Bright Magenta</td>
                <td><span class="color-sample" style="background:#6ff"></span><code>96/106</code> Bright Cyan</td>
                <td><span class="color-sample" style="background:#fff"></span><code>97/107</code> Bright White</td>
            </tr>
        </table>
    </div>

    <div class="ref-group">
        <h4>Cursor Control</h4>
        <table class="ref-table">
            <tr><td><code>\e[H</code></td><td>Cursor home (0,0)</td></tr>
            <tr><td><code>\e[{n}A</code></td><td>Cursor up n lines</td></tr>
            <tr><td><code>\e[{n}B</code></td><td>Cursor down n lines</td></tr>
            <tr><td><code>\e[{n}C</code></td><td>Cursor forward n chars</td></tr>
            <tr><td><code>\e[{n}D</code></td><td>Cursor back n chars</td></tr>
            <tr><td><code>\e[{r};{c}H</code></td><td>Move cursor to row r, col c</td></tr>
            <tr><td><code>\e[2J</code></td><td>Clear screen</td></tr>
            <tr><td><code>\e[K</code></td><td>Clear to end of line</td></tr>
        </table>
    </div>
</div>

<div class="examples-section">
    <h3>Exemples Bash</h3>
    <div class="examples-grid">
        <div class="example-card">
            <h4>Variables de couleur</h4>
            <pre>RED='\e[31m'
GREEN='\e[32m'
YELLOW='\e[33m'
BLUE='\e[34m'
NC='\e[0m' # No Color

echo -e "${RED}Error${NC}"
echo -e "${GREEN}Success${NC}"</pre>
        </div>
        <div class="example-card">
            <h4>Prompt colore</h4>
            <pre># ~/.bashrc
PS1='\[\e[32m\]\u@\h\[\e[0m\]:'
PS1+='\[\e[34m\]\w\[\e[0m\]\$ '

# Avec Git branch
PS1+='\[\e[33m\]$(git branch 2>/dev/null |
  grep "*" | cut -d" " -f2)\[\e[0m\]'</pre>
        </div>
        <div class="example-card">
            <h4>Barre de progression</h4>
            <pre>progress() {
    local width=50
    local percent=$1
    local filled=$((percent*width/100))
    local empty=$((width-filled))
    printf "\r\e[32m["
    printf "%${filled}s" | tr ' ' '='
    printf "%${empty}s" | tr ' ' ' '
    printf "] %3d%%\e[0m" $percent
}</pre>
        </div>
        <div class="example-card">
            <h4>Texte anime</h4>
            <pre>spinner() {
    local chars="⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
    while :; do
        for (( i=0; i<${#chars}; i++ )); do
            echo -en "\r\e[36m${chars:$i:1}\e[0m Loading..."
            sleep 0.1
        done
    done
}</pre>
        </div>
    </div>
</div>

</div>

## Format

```
\e[{codes}m    ou    \033[{codes}m    ou    \x1b[{codes}m
```

Codes multiples separes par `;` : `\e[1;31;44m` = gras + rouge + fond bleu

<style>
.tool-container {
    background: var(--md-code-bg-color);
    padding: 20px;
    border-radius: 8px;
    margin: 20px 0;
}
.preview-section, .builder-section, .colors-section, .reference-section, .examples-section {
    background: var(--md-default-bg-color);
    padding: 20px;
    border-radius: 4px;
    margin-bottom: 20px;
}
.preview-section h3, .builder-section h3, .colors-section h3, .reference-section h3, .examples-section h3 {
    margin: 0 0 15px 0;
}
.preview-box {
    background: #1e1e1e;
    color: #d4d4d4;
    padding: 30px;
    border-radius: 4px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 24px;
    text-align: center;
    margin-bottom: 15px;
}
.preview-code {
    display: flex;
    gap: 10px;
    align-items: center;
}
.preview-code code {
    flex: 1;
    padding: 10px 15px;
    background: var(--md-code-bg-color);
    border-radius: 4px;
    font-family: monospace;
}
.copy-btn, .reset-btn {
    padding: 10px 20px;
    background: var(--md-primary-fg-color);
    color: white;
    border: none;
    border-radius: 4px;
    cursor: pointer;
}
.builder-grid {
    display: flex;
    flex-direction: column;
    gap: 20px;
    margin-bottom: 15px;
}
.builder-group label {
    display: block;
    font-size: 12px;
    font-weight: bold;
    margin-bottom: 10px;
}
.style-buttons {
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
}
.style-btn {
    padding: 8px 12px;
    background: var(--md-code-bg-color);
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    cursor: pointer;
    color: var(--md-default-fg-color);
}
.style-btn.active {
    background: var(--md-primary-fg-color);
    color: white;
    border-color: var(--md-primary-fg-color);
}
.color-grid {
    display: flex;
    gap: 5px;
    flex-wrap: wrap;
}
.color-btn {
    width: 30px;
    height: 30px;
    border: 2px solid transparent;
    border-radius: 4px;
    cursor: pointer;
}
.color-btn.active {
    border-color: var(--md-primary-fg-color);
    box-shadow: 0 0 5px var(--md-primary-fg-color);
}
.palette-256 {
    display: grid;
    grid-template-columns: repeat(36, 1fr);
    gap: 2px;
    margin-bottom: 15px;
}
@media (max-width: 768px) {
    .palette-256 {
        grid-template-columns: repeat(18, 1fr);
    }
}
.palette-cell {
    aspect-ratio: 1;
    border-radius: 2px;
    cursor: pointer;
    min-width: 12px;
}
.palette-cell:hover {
    transform: scale(1.2);
    z-index: 1;
}
.color-info {
    display: flex;
    gap: 20px;
    flex-wrap: wrap;
    font-size: 13px;
}
.ref-group {
    margin-bottom: 20px;
}
.ref-group h4 {
    margin: 0 0 10px 0;
}
.ref-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
}
.ref-table td {
    padding: 8px;
    border-bottom: 1px solid var(--md-default-fg-color--lightest);
}
.ref-table code {
    background: var(--md-code-bg-color);
    padding: 2px 6px;
    border-radius: 3px;
}
.colors-ref td {
    width: 25%;
}
.color-sample {
    display: inline-block;
    width: 16px;
    height: 16px;
    border-radius: 3px;
    vertical-align: middle;
    margin-right: 5px;
}
.examples-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    gap: 15px;
}
.example-card {
    background: var(--md-code-bg-color);
    padding: 15px;
    border-radius: 4px;
}
.example-card h4 {
    margin: 0 0 10px 0;
    font-size: 14px;
}
.example-card pre {
    margin: 0;
    padding: 10px;
    background: #1e1e1e;
    color: #d4d4d4;
    border-radius: 4px;
    font-size: 11px;
    overflow-x: auto;
}
</style>

<script>
const COLORS = {
    standard: [
        { code: 30, bg: 40, name: 'Black', hex: '#000000' },
        { code: 31, bg: 41, name: 'Red', hex: '#cc0000' },
        { code: 32, bg: 42, name: 'Green', hex: '#00cc00' },
        { code: 33, bg: 43, name: 'Yellow', hex: '#cccc00' },
        { code: 34, bg: 44, name: 'Blue', hex: '#0000cc' },
        { code: 35, bg: 45, name: 'Magenta', hex: '#cc00cc' },
        { code: 36, bg: 46, name: 'Cyan', hex: '#00cccc' },
        { code: 37, bg: 47, name: 'White', hex: '#cccccc' }
    ],
    bright: [
        { code: 90, bg: 100, name: 'Bright Black', hex: '#666666' },
        { code: 91, bg: 101, name: 'Bright Red', hex: '#ff6666' },
        { code: 92, bg: 102, name: 'Bright Green', hex: '#66ff66' },
        { code: 93, bg: 103, name: 'Bright Yellow', hex: '#ffff66' },
        { code: 94, bg: 104, name: 'Bright Blue', hex: '#6666ff' },
        { code: 95, bg: 105, name: 'Bright Magenta', hex: '#ff66ff' },
        { code: 96, bg: 106, name: 'Bright Cyan', hex: '#66ffff' },
        { code: 97, bg: 107, name: 'Bright White', hex: '#ffffff' }
    ]
};

let currentStyles = [];
let currentFg = null;
let currentBg = null;

function get256Color(n) {
    if (n < 16) {
        const colors = [
            '#000000', '#800000', '#008000', '#808000', '#000080', '#800080', '#008080', '#c0c0c0',
            '#808080', '#ff0000', '#00ff00', '#ffff00', '#0000ff', '#ff00ff', '#00ffff', '#ffffff'
        ];
        return colors[n];
    } else if (n < 232) {
        n -= 16;
        const r = Math.floor(n / 36) * 51;
        const g = Math.floor((n % 36) / 6) * 51;
        const b = (n % 6) * 51;
        return `rgb(${r},${g},${b})`;
    } else {
        const gray = (n - 232) * 10 + 8;
        return `rgb(${gray},${gray},${gray})`;
    }
}

function renderColorButtons() {
    const fgGrid = document.getElementById('fg-colors');
    const bgGrid = document.getElementById('bg-colors');

    const allColors = [...COLORS.standard, ...COLORS.bright];

    fgGrid.innerHTML = allColors.map(c => `
        <button class="color-btn" style="background:${c.hex}" data-code="${c.code}"
                onclick="setFgColor(${c.code}, '${c.hex}')" title="${c.name}"></button>
    `).join('');

    bgGrid.innerHTML = allColors.map(c => `
        <button class="color-btn" style="background:${c.hex}" data-code="${c.bg}"
                onclick="setBgColor(${c.bg}, '${c.hex}')" title="${c.name}"></button>
    `).join('');
}

function render256Palette() {
    const palette = document.getElementById('palette-256');
    let html = '';

    for (let i = 0; i < 256; i++) {
        const color = get256Color(i);
        html += `<div class="palette-cell" style="background:${color}"
                      onclick="select256Color(${i})" title="Color ${i}"></div>`;
    }

    palette.innerHTML = html;
}

function toggleStyle(code) {
    const btn = event.target;
    const index = currentStyles.indexOf(code);

    if (index === -1) {
        currentStyles.push(code);
        btn.classList.add('active');
    } else {
        currentStyles.splice(index, 1);
        btn.classList.remove('active');
    }

    updatePreview();
}

function setFgColor(code, hex) {
    document.querySelectorAll('#fg-colors .color-btn').forEach(b => b.classList.remove('active'));
    event.target.classList.add('active');
    currentFg = { code, hex };
    updatePreview();
}

function setBgColor(code, hex) {
    document.querySelectorAll('#bg-colors .color-btn').forEach(b => b.classList.remove('active'));
    event.target.classList.add('active');
    currentBg = { code, hex };
    updatePreview();
}

function select256Color(n) {
    document.getElementById('selected-color').textContent = n;
    document.getElementById('fg-code').textContent = `38;5;${n}`;
    document.getElementById('bg-code').textContent = `48;5;${n}`;
}

function updatePreview() {
    const preview = document.getElementById('preview-text');
    const codeDisplay = document.getElementById('preview-code');

    let styles = [];
    let cssStyles = [];

    // Reset
    if (currentStyles.length === 0 && !currentFg && !currentBg) {
        styles.push('0');
    }

    // Styles
    currentStyles.forEach(s => {
        styles.push(s.toString());
        switch (s) {
            case 1: cssStyles.push('font-weight: bold'); break;
            case 2: cssStyles.push('opacity: 0.5'); break;
            case 3: cssStyles.push('font-style: italic'); break;
            case 4: cssStyles.push('text-decoration: underline'); break;
            case 5: cssStyles.push('animation: blink 1s infinite'); break;
            case 7: /* inverse handled separately */ break;
            case 9: cssStyles.push('text-decoration: line-through'); break;
        }
    });

    // Colors
    if (currentFg) {
        styles.push(currentFg.code.toString());
        cssStyles.push(`color: ${currentFg.hex}`);
    }

    if (currentBg) {
        styles.push(currentBg.code.toString());
        cssStyles.push(`background: ${currentBg.hex}`);
    }

    // Handle inverse
    if (currentStyles.includes(7) && currentFg && currentBg) {
        cssStyles = cssStyles.filter(s => !s.startsWith('color:') && !s.startsWith('background:'));
        cssStyles.push(`color: ${currentBg.hex}`);
        cssStyles.push(`background: ${currentFg.hex}`);
    }

    preview.style.cssText = cssStyles.join('; ');
    codeDisplay.textContent = `\\e[${styles.join(';')}m`;
}

function resetStyles() {
    currentStyles = [];
    currentFg = null;
    currentBg = null;

    document.querySelectorAll('.style-btn, .color-btn').forEach(b => b.classList.remove('active'));
    updatePreview();
}

function copyCode() {
    const code = document.getElementById('preview-code').textContent;
    navigator.clipboard.writeText(code);

    const btn = event.target;
    btn.textContent = 'Copie!';
    setTimeout(() => { btn.textContent = 'Copier'; }, 1000);
}

// Initialize
renderColorButtons();
render256Palette();
updatePreview();

// Add blink animation
const style = document.createElement('style');
style.textContent = '@keyframes blink { 50% { opacity: 0; } }';
document.head.appendChild(style);
</script>
