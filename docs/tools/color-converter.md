---
tags:
  - tools
  - color
  - css
  - design
---

# Color Converter

Conversion entre formats de couleurs : HEX, RGB, HSL, HSV.

<div class="tool-container">

<div class="color-section">
    <h3>Convertisseur de couleurs</h3>

    <div class="color-preview-row">
        <div class="color-preview" id="color-preview"></div>
        <input type="color" id="color-picker" value="#6200ee">
    </div>

    <div class="color-inputs">
        <div class="input-group">
            <label for="hex-input">HEX</label>
            <input type="text" id="hex-input" value="#6200ee" placeholder="#RRGGBB">
        </div>

        <div class="input-group rgb-group">
            <label>RGB</label>
            <div class="rgb-inputs">
                <input type="number" id="rgb-r" min="0" max="255" value="98" placeholder="R">
                <input type="number" id="rgb-g" min="0" max="255" value="0" placeholder="G">
                <input type="number" id="rgb-b" min="0" max="255" value="238" placeholder="B">
            </div>
        </div>

        <div class="input-group hsl-group">
            <label>HSL</label>
            <div class="hsl-inputs">
                <input type="number" id="hsl-h" min="0" max="360" value="265" placeholder="H">
                <input type="number" id="hsl-s" min="0" max="100" value="100" placeholder="S%">
                <input type="number" id="hsl-l" min="0" max="100" value="47" placeholder="L%">
            </div>
        </div>

        <div class="input-group hsv-group">
            <label>HSV/HSB</label>
            <div class="hsv-inputs">
                <input type="number" id="hsv-h" min="0" max="360" value="265" placeholder="H">
                <input type="number" id="hsv-s" min="0" max="100" value="100" placeholder="S%">
                <input type="number" id="hsv-v" min="0" max="100" value="93" placeholder="V%">
            </div>
        </div>
    </div>

    <div class="css-output">
        <h4>CSS</h4>
        <div class="css-values">
            <code id="css-hex">#6200ee</code>
            <code id="css-rgb">rgb(98, 0, 238)</code>
            <code id="css-hsl">hsl(265, 100%, 47%)</code>
        </div>
    </div>
</div>

<div class="palette-section">
    <h3>Palette generee</h3>

    <div class="palette-type">
        <label><input type="radio" name="palette-type" value="shades" checked> Nuances</label>
        <label><input type="radio" name="palette-type" value="complementary"> Complementaire</label>
        <label><input type="radio" name="palette-type" value="triadic"> Triadique</label>
        <label><input type="radio" name="palette-type" value="analogous"> Analogues</label>
    </div>

    <div class="palette-grid" id="palette-grid"></div>
</div>

<div class="contrast-section">
    <h3>Contraste WCAG</h3>

    <div class="contrast-inputs">
        <div class="contrast-color">
            <label>Texte</label>
            <input type="color" id="fg-color" value="#6200ee">
            <span id="fg-hex">#6200ee</span>
        </div>
        <div class="contrast-color">
            <label>Fond</label>
            <input type="color" id="bg-color" value="#ffffff">
            <span id="bg-hex">#ffffff</span>
        </div>
    </div>

    <div class="contrast-preview">
        <div id="contrast-demo" class="contrast-demo">
            <span class="large-text">Texte Large (18pt+)</span>
            <span class="normal-text">Texte normal (14pt)</span>
        </div>
    </div>

    <div class="contrast-result">
        <div class="ratio">Ratio: <strong id="contrast-ratio">8.59:1</strong></div>
        <div class="wcag-results">
            <span id="wcag-aa-normal" class="pass">AA Normal</span>
            <span id="wcag-aa-large" class="pass">AA Large</span>
            <span id="wcag-aaa-normal" class="pass">AAA Normal</span>
            <span id="wcag-aaa-large" class="pass">AAA Large</span>
        </div>
    </div>
</div>

</div>

## Formats de couleurs

| Format | Exemple | Description |
|--------|---------|-------------|
| **HEX** | `#FF5733` | Hexadecimal (web) |
| **RGB** | `rgb(255, 87, 51)` | Rouge, Vert, Bleu (0-255) |
| **HSL** | `hsl(14, 100%, 60%)` | Teinte, Saturation, Luminosite |
| **HSV/HSB** | `hsv(14, 80%, 100%)` | Teinte, Saturation, Valeur/Brillance |

## WCAG Accessibility

| Niveau | Normal Text | Large Text |
|--------|-------------|------------|
| **AA** | 4.5:1 minimum | 3:1 minimum |
| **AAA** | 7:1 minimum | 4.5:1 minimum |

!!! tip "Large Text"
    Texte de 18pt+ ou 14pt+ bold est considere "large text".

<style>
.tool-container {
    background: var(--md-code-bg-color);
    padding: 20px;
    border-radius: 8px;
    margin: 20px 0;
}
.color-section, .palette-section, .contrast-section {
    background: var(--md-default-bg-color);
    padding: 20px;
    border-radius: 4px;
    margin-bottom: 20px;
}
.color-section h3, .palette-section h3, .contrast-section h3 {
    margin: 0 0 15px 0;
}
.color-preview-row {
    display: flex;
    align-items: center;
    gap: 15px;
    margin-bottom: 20px;
}
.color-preview {
    width: 100px;
    height: 100px;
    border-radius: 8px;
    background: #6200ee;
    border: 2px solid var(--md-default-fg-color--lighter);
}
#color-picker {
    width: 60px;
    height: 60px;
    border: none;
    cursor: pointer;
    border-radius: 4px;
}
.color-inputs {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 15px;
    margin-bottom: 20px;
}
.input-group label {
    display: block;
    font-weight: bold;
    margin-bottom: 5px;
    font-size: 12px;
}
.input-group input[type="text"] {
    width: 100%;
    padding: 10px;
    font-family: monospace;
    font-size: 14px;
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    background: var(--md-code-bg-color);
    color: var(--md-default-fg-color);
}
.rgb-inputs, .hsl-inputs, .hsv-inputs {
    display: flex;
    gap: 5px;
}
.rgb-inputs input, .hsl-inputs input, .hsv-inputs input {
    width: 60px;
    padding: 10px;
    font-family: monospace;
    font-size: 14px;
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    background: var(--md-code-bg-color);
    color: var(--md-default-fg-color);
    text-align: center;
}
.css-output h4 {
    margin: 0 0 10px 0;
}
.css-values {
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
}
.css-values code {
    padding: 8px 12px;
    background: var(--md-code-bg-color);
    border-radius: 4px;
    cursor: pointer;
}
.css-values code:hover {
    background: var(--md-primary-fg-color);
    color: white;
}
.palette-type {
    display: flex;
    gap: 15px;
    flex-wrap: wrap;
    margin-bottom: 15px;
}
.palette-type label {
    cursor: pointer;
}
.palette-grid {
    display: flex;
    gap: 5px;
    flex-wrap: wrap;
}
.palette-color {
    width: 60px;
    height: 60px;
    border-radius: 4px;
    cursor: pointer;
    position: relative;
    border: 2px solid transparent;
}
.palette-color:hover {
    border-color: var(--md-default-fg-color);
}
.palette-color::after {
    content: attr(data-hex);
    position: absolute;
    bottom: -20px;
    left: 50%;
    transform: translateX(-50%);
    font-size: 10px;
    font-family: monospace;
    white-space: nowrap;
}
.contrast-inputs {
    display: flex;
    gap: 20px;
    flex-wrap: wrap;
    margin-bottom: 15px;
}
.contrast-color {
    display: flex;
    align-items: center;
    gap: 10px;
}
.contrast-color input[type="color"] {
    width: 40px;
    height: 40px;
    border: none;
    cursor: pointer;
    border-radius: 4px;
}
.contrast-color span {
    font-family: monospace;
}
.contrast-preview {
    margin: 15px 0;
}
.contrast-demo {
    padding: 20px;
    border-radius: 4px;
    display: flex;
    flex-direction: column;
    gap: 10px;
}
.contrast-demo .large-text {
    font-size: 18pt;
    font-weight: bold;
}
.contrast-demo .normal-text {
    font-size: 14px;
}
.contrast-result {
    display: flex;
    align-items: center;
    gap: 20px;
    flex-wrap: wrap;
}
.contrast-result .ratio {
    font-size: 18px;
}
.wcag-results {
    display: flex;
    gap: 10px;
    flex-wrap: wrap;
}
.wcag-results span {
    padding: 5px 10px;
    border-radius: 4px;
    font-size: 12px;
    font-weight: bold;
}
.wcag-results span.pass {
    background: #28a745;
    color: white;
}
.wcag-results span.fail {
    background: #dc3545;
    color: white;
}
</style>

<script>
// Color conversion functions
function hexToRgb(hex) {
    const result = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
    return result ? {
        r: parseInt(result[1], 16),
        g: parseInt(result[2], 16),
        b: parseInt(result[3], 16)
    } : null;
}

function rgbToHex(r, g, b) {
    return '#' + [r, g, b].map(x => {
        const hex = Math.round(x).toString(16);
        return hex.length === 1 ? '0' + hex : hex;
    }).join('');
}

function rgbToHsl(r, g, b) {
    r /= 255; g /= 255; b /= 255;
    const max = Math.max(r, g, b), min = Math.min(r, g, b);
    let h, s, l = (max + min) / 2;

    if (max === min) {
        h = s = 0;
    } else {
        const d = max - min;
        s = l > 0.5 ? d / (2 - max - min) : d / (max + min);
        switch (max) {
            case r: h = ((g - b) / d + (g < b ? 6 : 0)) / 6; break;
            case g: h = ((b - r) / d + 2) / 6; break;
            case b: h = ((r - g) / d + 4) / 6; break;
        }
    }
    return { h: Math.round(h * 360), s: Math.round(s * 100), l: Math.round(l * 100) };
}

function hslToRgb(h, s, l) {
    h /= 360; s /= 100; l /= 100;
    let r, g, b;

    if (s === 0) {
        r = g = b = l;
    } else {
        const hue2rgb = (p, q, t) => {
            if (t < 0) t += 1;
            if (t > 1) t -= 1;
            if (t < 1/6) return p + (q - p) * 6 * t;
            if (t < 1/2) return q;
            if (t < 2/3) return p + (q - p) * (2/3 - t) * 6;
            return p;
        };
        const q = l < 0.5 ? l * (1 + s) : l + s - l * s;
        const p = 2 * l - q;
        r = hue2rgb(p, q, h + 1/3);
        g = hue2rgb(p, q, h);
        b = hue2rgb(p, q, h - 1/3);
    }
    return { r: Math.round(r * 255), g: Math.round(g * 255), b: Math.round(b * 255) };
}

function rgbToHsv(r, g, b) {
    r /= 255; g /= 255; b /= 255;
    const max = Math.max(r, g, b), min = Math.min(r, g, b);
    let h, s, v = max;
    const d = max - min;
    s = max === 0 ? 0 : d / max;

    if (max === min) {
        h = 0;
    } else {
        switch (max) {
            case r: h = ((g - b) / d + (g < b ? 6 : 0)) / 6; break;
            case g: h = ((b - r) / d + 2) / 6; break;
            case b: h = ((r - g) / d + 4) / 6; break;
        }
    }
    return { h: Math.round(h * 360), s: Math.round(s * 100), v: Math.round(v * 100) };
}

function hsvToRgb(h, s, v) {
    h /= 360; s /= 100; v /= 100;
    let r, g, b;
    const i = Math.floor(h * 6);
    const f = h * 6 - i;
    const p = v * (1 - s);
    const q = v * (1 - f * s);
    const t = v * (1 - (1 - f) * s);

    switch (i % 6) {
        case 0: r = v; g = t; b = p; break;
        case 1: r = q; g = v; b = p; break;
        case 2: r = p; g = v; b = t; break;
        case 3: r = p; g = q; b = v; break;
        case 4: r = t; g = p; b = v; break;
        case 5: r = v; g = p; b = q; break;
    }
    return { r: Math.round(r * 255), g: Math.round(g * 255), b: Math.round(b * 255) };
}

// Update all fields from RGB
function updateFromRgb(r, g, b, source) {
    const hex = rgbToHex(r, g, b);
    const hsl = rgbToHsl(r, g, b);
    const hsv = rgbToHsv(r, g, b);

    if (source !== 'hex') document.getElementById('hex-input').value = hex;
    if (source !== 'rgb') {
        document.getElementById('rgb-r').value = r;
        document.getElementById('rgb-g').value = g;
        document.getElementById('rgb-b').value = b;
    }
    if (source !== 'hsl') {
        document.getElementById('hsl-h').value = hsl.h;
        document.getElementById('hsl-s').value = hsl.s;
        document.getElementById('hsl-l').value = hsl.l;
    }
    if (source !== 'hsv') {
        document.getElementById('hsv-h').value = hsv.h;
        document.getElementById('hsv-s').value = hsv.s;
        document.getElementById('hsv-v').value = hsv.v;
    }
    if (source !== 'picker') document.getElementById('color-picker').value = hex;

    // Update preview
    document.getElementById('color-preview').style.background = hex;

    // Update CSS values
    document.getElementById('css-hex').textContent = hex;
    document.getElementById('css-rgb').textContent = `rgb(${r}, ${g}, ${b})`;
    document.getElementById('css-hsl').textContent = `hsl(${hsl.h}, ${hsl.s}%, ${hsl.l}%)`;

    // Update palette
    generatePalette(hex);
}

// Event listeners
document.getElementById('color-picker').addEventListener('input', (e) => {
    const rgb = hexToRgb(e.target.value);
    if (rgb) updateFromRgb(rgb.r, rgb.g, rgb.b, 'picker');
});

document.getElementById('hex-input').addEventListener('input', (e) => {
    let hex = e.target.value;
    if (!hex.startsWith('#')) hex = '#' + hex;
    const rgb = hexToRgb(hex);
    if (rgb) updateFromRgb(rgb.r, rgb.g, rgb.b, 'hex');
});

['rgb-r', 'rgb-g', 'rgb-b'].forEach(id => {
    document.getElementById(id).addEventListener('input', () => {
        const r = parseInt(document.getElementById('rgb-r').value) || 0;
        const g = parseInt(document.getElementById('rgb-g').value) || 0;
        const b = parseInt(document.getElementById('rgb-b').value) || 0;
        updateFromRgb(r, g, b, 'rgb');
    });
});

['hsl-h', 'hsl-s', 'hsl-l'].forEach(id => {
    document.getElementById(id).addEventListener('input', () => {
        const h = parseInt(document.getElementById('hsl-h').value) || 0;
        const s = parseInt(document.getElementById('hsl-s').value) || 0;
        const l = parseInt(document.getElementById('hsl-l').value) || 0;
        const rgb = hslToRgb(h, s, l);
        updateFromRgb(rgb.r, rgb.g, rgb.b, 'hsl');
    });
});

['hsv-h', 'hsv-s', 'hsv-v'].forEach(id => {
    document.getElementById(id).addEventListener('input', () => {
        const h = parseInt(document.getElementById('hsv-h').value) || 0;
        const s = parseInt(document.getElementById('hsv-s').value) || 0;
        const v = parseInt(document.getElementById('hsv-v').value) || 0;
        const rgb = hsvToRgb(h, s, v);
        updateFromRgb(rgb.r, rgb.g, rgb.b, 'hsv');
    });
});

// Copy CSS values
document.querySelectorAll('.css-values code').forEach(el => {
    el.addEventListener('click', () => {
        navigator.clipboard.writeText(el.textContent);
        const orig = el.textContent;
        el.textContent = 'Copie!';
        setTimeout(() => { el.textContent = orig; }, 1000);
    });
});

// Palette generation
function generatePalette(baseHex) {
    const type = document.querySelector('input[name="palette-type"]:checked').value;
    const rgb = hexToRgb(baseHex);
    const hsl = rgbToHsl(rgb.r, rgb.g, rgb.b);
    const colors = [];

    switch (type) {
        case 'shades':
            for (let l = 95; l >= 5; l -= 10) {
                const c = hslToRgb(hsl.h, hsl.s, l);
                colors.push(rgbToHex(c.r, c.g, c.b));
            }
            break;
        case 'complementary':
            colors.push(baseHex);
            const comp = hslToRgb((hsl.h + 180) % 360, hsl.s, hsl.l);
            colors.push(rgbToHex(comp.r, comp.g, comp.b));
            break;
        case 'triadic':
            [0, 120, 240].forEach(offset => {
                const c = hslToRgb((hsl.h + offset) % 360, hsl.s, hsl.l);
                colors.push(rgbToHex(c.r, c.g, c.b));
            });
            break;
        case 'analogous':
            [-30, -15, 0, 15, 30].forEach(offset => {
                const c = hslToRgb((hsl.h + offset + 360) % 360, hsl.s, hsl.l);
                colors.push(rgbToHex(c.r, c.g, c.b));
            });
            break;
    }

    const grid = document.getElementById('palette-grid');
    grid.innerHTML = colors.map(hex => `
        <div class="palette-color" style="background:${hex}" data-hex="${hex}" onclick="navigator.clipboard.writeText('${hex}')"></div>
    `).join('');
}

document.querySelectorAll('input[name="palette-type"]').forEach(radio => {
    radio.addEventListener('change', () => {
        generatePalette(document.getElementById('hex-input').value);
    });
});

// Contrast checker
function getLuminance(r, g, b) {
    const [rs, gs, bs] = [r, g, b].map(c => {
        c /= 255;
        return c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4);
    });
    return 0.2126 * rs + 0.7152 * gs + 0.0722 * bs;
}

function getContrastRatio(rgb1, rgb2) {
    const l1 = getLuminance(rgb1.r, rgb1.g, rgb1.b);
    const l2 = getLuminance(rgb2.r, rgb2.g, rgb2.b);
    const lighter = Math.max(l1, l2);
    const darker = Math.min(l1, l2);
    return (lighter + 0.05) / (darker + 0.05);
}

function updateContrast() {
    const fgHex = document.getElementById('fg-color').value;
    const bgHex = document.getElementById('bg-color').value;
    const fgRgb = hexToRgb(fgHex);
    const bgRgb = hexToRgb(bgHex);

    document.getElementById('fg-hex').textContent = fgHex;
    document.getElementById('bg-hex').textContent = bgHex;

    const demo = document.getElementById('contrast-demo');
    demo.style.background = bgHex;
    demo.style.color = fgHex;

    const ratio = getContrastRatio(fgRgb, bgRgb);
    document.getElementById('contrast-ratio').textContent = ratio.toFixed(2) + ':1';

    // WCAG checks
    const aaNormal = ratio >= 4.5;
    const aaLarge = ratio >= 3;
    const aaaNormal = ratio >= 7;
    const aaaLarge = ratio >= 4.5;

    document.getElementById('wcag-aa-normal').className = aaNormal ? 'pass' : 'fail';
    document.getElementById('wcag-aa-large').className = aaLarge ? 'pass' : 'fail';
    document.getElementById('wcag-aaa-normal').className = aaaNormal ? 'pass' : 'fail';
    document.getElementById('wcag-aaa-large').className = aaaLarge ? 'pass' : 'fail';
}

document.getElementById('fg-color').addEventListener('input', updateContrast);
document.getElementById('bg-color').addEventListener('input', updateContrast);

// Initialize
updateFromRgb(98, 0, 238, null);
updateContrast();
</script>
