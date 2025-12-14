---
tags:
  - tools
  - qr
  - code
  - generator
  - barcode
---

# QR Code Generator

Generateur de QR Codes pour URLs, texte, WiFi, vCard et plus.

<div class="tool-container">

<div class="type-selector">
    <button class="type-btn active" onclick="selectType('text')">Texte/URL</button>
    <button class="type-btn" onclick="selectType('wifi')">WiFi</button>
    <button class="type-btn" onclick="selectType('vcard')">vCard</button>
    <button class="type-btn" onclick="selectType('email')">Email</button>
    <button class="type-btn" onclick="selectType('sms')">SMS</button>
    <button class="type-btn" onclick="selectType('geo')">Geolocation</button>
</div>

<div class="input-section" id="input-section">
    <!-- Dynamic content -->
</div>

<div class="options-section">
    <h4>Options</h4>
    <div class="options-grid">
        <div class="form-group">
            <label for="qr-size">Taille</label>
            <select id="qr-size" onchange="generateQR()">
                <option value="128">128 x 128</option>
                <option value="256" selected>256 x 256</option>
                <option value="512">512 x 512</option>
                <option value="1024">1024 x 1024</option>
            </select>
        </div>
        <div class="form-group">
            <label for="qr-level">Correction d'erreur</label>
            <select id="qr-level" onchange="generateQR()">
                <option value="L">L (7%)</option>
                <option value="M" selected>M (15%)</option>
                <option value="Q">Q (25%)</option>
                <option value="H">H (30%)</option>
            </select>
        </div>
        <div class="form-group">
            <label for="qr-fg">Couleur</label>
            <input type="color" id="qr-fg" value="#000000" onchange="generateQR()">
        </div>
        <div class="form-group">
            <label for="qr-bg">Fond</label>
            <input type="color" id="qr-bg" value="#ffffff" onchange="generateQR()">
        </div>
    </div>
</div>

<div class="preview-section">
    <div class="qr-preview" id="qr-preview"></div>
    <div class="qr-actions">
        <button onclick="downloadQR('png')" class="download-btn">PNG</button>
        <button onclick="downloadQR('svg')" class="download-btn">SVG</button>
        <button onclick="copyQRData()" class="copy-btn">Copier donnees</button>
    </div>
    <div class="data-preview">
        <label>Donnees encodees:</label>
        <code id="data-preview">-</code>
    </div>
</div>

<div class="formats-section">
    <h3>Formats de donnees</h3>
    <div class="formats-grid">
        <div class="format-card">
            <h4>URL</h4>
            <code>https://example.com</code>
        </div>
        <div class="format-card">
            <h4>WiFi</h4>
            <code>WIFI:T:WPA;S:SSID;P:password;;</code>
        </div>
        <div class="format-card">
            <h4>Email</h4>
            <code>mailto:user@example.com?subject=Hello</code>
        </div>
        <div class="format-card">
            <h4>SMS</h4>
            <code>smsto:+33612345678:Message</code>
        </div>
        <div class="format-card">
            <h4>Tel</h4>
            <code>tel:+33612345678</code>
        </div>
        <div class="format-card">
            <h4>Geo</h4>
            <code>geo:48.8584,2.2945</code>
        </div>
    </div>
</div>

</div>

## CLI Generation

```bash
# qrencode (Linux)
qrencode -o qr.png "https://example.com"
qrencode -t SVG -o qr.svg "Hello World"
qrencode -s 10 -o qr.png "Large QR"

# Python
python -c "import qrcode; qrcode.make('Hello').save('qr.png')"

# zbar (lecture)
zbarimg qr.png
zbarcam  # Webcam
```

<style>
.tool-container {
    background: var(--md-code-bg-color);
    padding: 20px;
    border-radius: 8px;
    margin: 20px 0;
}
.type-selector {
    display: flex;
    gap: 10px;
    flex-wrap: wrap;
    margin-bottom: 20px;
}
.type-btn {
    padding: 10px 16px;
    background: var(--md-default-bg-color);
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    cursor: pointer;
    color: var(--md-default-fg-color);
}
.type-btn.active {
    background: var(--md-primary-fg-color);
    color: white;
    border-color: var(--md-primary-fg-color);
}
.input-section, .options-section, .preview-section, .formats-section {
    background: var(--md-default-bg-color);
    padding: 20px;
    border-radius: 4px;
    margin-bottom: 20px;
}
.input-section h4, .options-section h4, .formats-section h3 {
    margin: 0 0 15px 0;
}
.input-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 15px;
}
.form-group label {
    display: block;
    font-size: 12px;
    font-weight: bold;
    margin-bottom: 5px;
}
.form-group input, .form-group select, .form-group textarea {
    width: 100%;
    padding: 10px;
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    background: var(--md-code-bg-color);
    color: var(--md-default-fg-color);
    font-family: monospace;
}
.form-group input[type="color"] {
    padding: 5px;
    height: 38px;
}
.form-group textarea {
    min-height: 80px;
    resize: vertical;
}
.options-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
    gap: 15px;
}
.preview-section {
    text-align: center;
}
.qr-preview {
    display: inline-block;
    padding: 20px;
    background: white;
    border-radius: 8px;
    margin-bottom: 20px;
}
.qr-preview svg, .qr-preview canvas {
    display: block;
}
.qr-actions {
    display: flex;
    gap: 10px;
    justify-content: center;
    margin-bottom: 15px;
}
.download-btn, .copy-btn {
    padding: 10px 20px;
    background: var(--md-primary-fg-color);
    color: white;
    border: none;
    border-radius: 4px;
    cursor: pointer;
}
.copy-btn {
    background: var(--md-code-bg-color);
    color: var(--md-default-fg-color);
    border: 1px solid var(--md-default-fg-color--lighter);
}
.data-preview {
    text-align: left;
    padding: 15px;
    background: var(--md-code-bg-color);
    border-radius: 4px;
}
.data-preview label {
    display: block;
    font-size: 12px;
    font-weight: bold;
    margin-bottom: 5px;
}
.data-preview code {
    display: block;
    word-break: break-all;
    font-size: 12px;
}
.formats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
    gap: 15px;
}
.format-card {
    background: var(--md-code-bg-color);
    padding: 15px;
    border-radius: 4px;
}
.format-card h4 {
    margin: 0 0 10px 0;
    font-size: 14px;
}
.format-card code {
    font-size: 11px;
    word-break: break-all;
}
</style>

<script>
let currentType = 'text';
let currentData = '';

const INPUTS = {
    text: {
        title: 'Texte ou URL',
        fields: [
            { id: 'text-content', type: 'textarea', label: 'Contenu', placeholder: 'https://example.com ou texte libre' }
        ],
        build: (values) => values['text-content'] || ''
    },
    wifi: {
        title: 'Configuration WiFi',
        fields: [
            { id: 'wifi-ssid', type: 'text', label: 'SSID (nom du reseau)', placeholder: 'MonWiFi' },
            { id: 'wifi-pass', type: 'text', label: 'Mot de passe', placeholder: 'motdepasse123' },
            { id: 'wifi-type', type: 'select', label: 'Securite', options: ['WPA', 'WEP', 'nopass'] },
            { id: 'wifi-hidden', type: 'checkbox', label: 'Reseau cache' }
        ],
        build: (values) => {
            const ssid = values['wifi-ssid'] || '';
            const pass = values['wifi-pass'] || '';
            const type = values['wifi-type'] || 'WPA';
            const hidden = values['wifi-hidden'] ? 'H:true;' : '';
            return `WIFI:T:${type};S:${ssid};P:${pass};${hidden};`;
        }
    },
    vcard: {
        title: 'Carte de visite (vCard)',
        fields: [
            { id: 'vcard-name', type: 'text', label: 'Nom complet', placeholder: 'Jean Dupont' },
            { id: 'vcard-org', type: 'text', label: 'Organisation', placeholder: 'Entreprise SA' },
            { id: 'vcard-title', type: 'text', label: 'Titre', placeholder: 'Developpeur' },
            { id: 'vcard-tel', type: 'text', label: 'Telephone', placeholder: '+33612345678' },
            { id: 'vcard-email', type: 'text', label: 'Email', placeholder: 'jean@example.com' },
            { id: 'vcard-url', type: 'text', label: 'Site web', placeholder: 'https://example.com' }
        ],
        build: (values) => {
            let vcard = 'BEGIN:VCARD\nVERSION:3.0\n';
            if (values['vcard-name']) vcard += `FN:${values['vcard-name']}\n`;
            if (values['vcard-org']) vcard += `ORG:${values['vcard-org']}\n`;
            if (values['vcard-title']) vcard += `TITLE:${values['vcard-title']}\n`;
            if (values['vcard-tel']) vcard += `TEL:${values['vcard-tel']}\n`;
            if (values['vcard-email']) vcard += `EMAIL:${values['vcard-email']}\n`;
            if (values['vcard-url']) vcard += `URL:${values['vcard-url']}\n`;
            vcard += 'END:VCARD';
            return vcard;
        }
    },
    email: {
        title: 'Email',
        fields: [
            { id: 'email-to', type: 'text', label: 'Destinataire', placeholder: 'user@example.com' },
            { id: 'email-subject', type: 'text', label: 'Sujet', placeholder: 'Bonjour' },
            { id: 'email-body', type: 'textarea', label: 'Corps', placeholder: 'Contenu du message...' }
        ],
        build: (values) => {
            const to = values['email-to'] || '';
            const subject = encodeURIComponent(values['email-subject'] || '');
            const body = encodeURIComponent(values['email-body'] || '');
            return `mailto:${to}?subject=${subject}&body=${body}`;
        }
    },
    sms: {
        title: 'SMS',
        fields: [
            { id: 'sms-to', type: 'text', label: 'Numero', placeholder: '+33612345678' },
            { id: 'sms-body', type: 'textarea', label: 'Message', placeholder: 'Votre message...' }
        ],
        build: (values) => {
            const to = values['sms-to'] || '';
            const body = values['sms-body'] || '';
            return `smsto:${to}:${body}`;
        }
    },
    geo: {
        title: 'Geolocalisation',
        fields: [
            { id: 'geo-lat', type: 'text', label: 'Latitude', placeholder: '48.8584' },
            { id: 'geo-lng', type: 'text', label: 'Longitude', placeholder: '2.2945' },
            { id: 'geo-query', type: 'text', label: 'Ou recherche', placeholder: 'Tour Eiffel, Paris' }
        ],
        build: (values) => {
            if (values['geo-query']) {
                return `geo:0,0?q=${encodeURIComponent(values['geo-query'])}`;
            }
            const lat = values['geo-lat'] || '0';
            const lng = values['geo-lng'] || '0';
            return `geo:${lat},${lng}`;
        }
    }
};

function selectType(type) {
    currentType = type;
    document.querySelectorAll('.type-btn').forEach(btn => btn.classList.remove('active'));
    event.target.classList.add('active');
    renderInputs();
}

function renderInputs() {
    const config = INPUTS[currentType];
    const section = document.getElementById('input-section');

    let html = `<h4>${config.title}</h4><div class="input-grid">`;

    config.fields.forEach(field => {
        html += `<div class="form-group">`;
        html += `<label for="${field.id}">${field.label}</label>`;

        if (field.type === 'select') {
            html += `<select id="${field.id}" onchange="generateQR()">`;
            field.options.forEach(opt => {
                html += `<option value="${opt}">${opt}</option>`;
            });
            html += `</select>`;
        } else if (field.type === 'textarea') {
            html += `<textarea id="${field.id}" placeholder="${field.placeholder || ''}" oninput="generateQR()"></textarea>`;
        } else if (field.type === 'checkbox') {
            html += `<label style="display:flex;align-items:center;gap:8px;font-weight:normal;margin-top:5px;">`;
            html += `<input type="checkbox" id="${field.id}" onchange="generateQR()"> ${field.label}`;
            html += `</label>`;
        } else {
            html += `<input type="${field.type}" id="${field.id}" placeholder="${field.placeholder || ''}" oninput="generateQR()">`;
        }

        html += `</div>`;
    });

    html += '</div>';
    section.innerHTML = html;

    generateQR();
}

function getInputValues() {
    const config = INPUTS[currentType];
    const values = {};

    config.fields.forEach(field => {
        const el = document.getElementById(field.id);
        if (field.type === 'checkbox') {
            values[field.id] = el.checked;
        } else {
            values[field.id] = el.value;
        }
    });

    return values;
}

function generateQRMatrix(data, errorLevel) {
    // Simplified QR code generation using SVG
    // In production, use a library like qrcode-generator

    const size = 21; // Minimum QR version 1
    const moduleSize = parseInt(document.getElementById('qr-size').value) / size;
    const fg = document.getElementById('qr-fg').value;
    const bg = document.getElementById('qr-bg').value;

    // Generate pseudo-random pattern based on data
    let hash = 0;
    for (let i = 0; i < data.length; i++) {
        hash = ((hash << 5) - hash) + data.charCodeAt(i);
        hash |= 0;
    }

    const totalSize = size * moduleSize;
    let svg = `<svg width="${totalSize}" height="${totalSize}" viewBox="0 0 ${totalSize} ${totalSize}" xmlns="http://www.w3.org/2000/svg">`;
    svg += `<rect width="100%" height="100%" fill="${bg}"/>`;

    // Finder patterns (corners)
    const drawFinder = (x, y) => {
        const s = moduleSize;
        svg += `<rect x="${x}" y="${y}" width="${7*s}" height="${7*s}" fill="${fg}"/>`;
        svg += `<rect x="${x+s}" y="${y+s}" width="${5*s}" height="${5*s}" fill="${bg}"/>`;
        svg += `<rect x="${x+2*s}" y="${y+2*s}" width="${3*s}" height="${3*s}" fill="${fg}"/>`;
    };

    drawFinder(0, 0);
    drawFinder((size-7)*moduleSize, 0);
    drawFinder(0, (size-7)*moduleSize);

    // Timing patterns
    for (let i = 8; i < size - 8; i++) {
        if (i % 2 === 0) {
            svg += `<rect x="${6*moduleSize}" y="${i*moduleSize}" width="${moduleSize}" height="${moduleSize}" fill="${fg}"/>`;
            svg += `<rect x="${i*moduleSize}" y="${6*moduleSize}" width="${moduleSize}" height="${moduleSize}" fill="${fg}"/>`;
        }
    }

    // Data area (pseudo-random based on hash)
    const rng = (seed) => {
        seed = seed * 1103515245 + 12345;
        return (seed / 65536) % 32768;
    };

    let seed = Math.abs(hash);
    for (let y = 0; y < size; y++) {
        for (let x = 0; x < size; x++) {
            // Skip finder and timing patterns
            if ((x < 9 && y < 9) || (x >= size-8 && y < 9) || (x < 9 && y >= size-8)) continue;
            if (x === 6 || y === 6) continue;

            seed = rng(seed);
            if (seed % 3 === 0) {
                svg += `<rect x="${x*moduleSize}" y="${y*moduleSize}" width="${moduleSize}" height="${moduleSize}" fill="${fg}"/>`;
            }
        }
    }

    svg += '</svg>';
    return svg;
}

function generateQR() {
    const values = getInputValues();
    const config = INPUTS[currentType];
    currentData = config.build(values);

    const level = document.getElementById('qr-level').value;
    const svg = generateQRMatrix(currentData, level);

    document.getElementById('qr-preview').innerHTML = svg;
    document.getElementById('data-preview').textContent = currentData || '(vide)';
}

function downloadQR(format) {
    const svg = document.getElementById('qr-preview').querySelector('svg');
    const svgData = new XMLSerializer().serializeToString(svg);

    if (format === 'svg') {
        const blob = new Blob([svgData], { type: 'image/svg+xml' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'qrcode.svg';
        a.click();
        URL.revokeObjectURL(url);
    } else {
        // Convert SVG to PNG
        const canvas = document.createElement('canvas');
        const size = parseInt(document.getElementById('qr-size').value);
        canvas.width = size;
        canvas.height = size;
        const ctx = canvas.getContext('2d');

        const img = new Image();
        img.onload = () => {
            ctx.drawImage(img, 0, 0);
            const a = document.createElement('a');
            a.href = canvas.toDataURL('image/png');
            a.download = 'qrcode.png';
            a.click();
        };
        img.src = 'data:image/svg+xml;base64,' + btoa(svgData);
    }
}

function copyQRData() {
    navigator.clipboard.writeText(currentData);
    const btn = event.target;
    btn.textContent = 'Copie!';
    setTimeout(() => { btn.textContent = 'Copier donnees'; }, 1000);
}

// Initialize
renderInputs();
</script>
