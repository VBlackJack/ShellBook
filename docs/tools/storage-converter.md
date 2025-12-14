---
tags:
  - tools
  - storage
  - converter
---

# Storage Converter

Convertisseur d'unités de stockage (décimal vs binaire).

<div class="tool-container">

<div class="input-row">
    <div class="input-group">
        <label for="storage-value">Valeur :</label>
        <input type="number" id="storage-value" value="1" min="0" step="0.01">
    </div>
    <div class="input-group">
        <label for="storage-unit">Unité source :</label>
        <select id="storage-unit">
            <optgroup label="Décimal (SI)">
                <option value="B">Bytes (B)</option>
                <option value="KB">Kilobytes (KB)</option>
                <option value="MB">Megabytes (MB)</option>
                <option value="GB">Gigabytes (GB)</option>
                <option value="TB" selected>Terabytes (TB)</option>
                <option value="PB">Petabytes (PB)</option>
            </optgroup>
            <optgroup label="Binaire (IEC)">
                <option value="Bi">Bytes (B)</option>
                <option value="KiB">Kibibytes (KiB)</option>
                <option value="MiB">Mebibytes (MiB)</option>
                <option value="GiB">Gibibytes (GiB)</option>
                <option value="TiB">Tebibytes (TiB)</option>
                <option value="PiB">Pebibytes (PiB)</option>
            </optgroup>
        </select>
    </div>
</div>

<div id="conversion-results" class="results-grid">
    <div class="result-section">
        <h4>Décimal (SI) - Base 1000</h4>
        <table>
            <tr><td>Bytes</td><td id="res-B">-</td></tr>
            <tr><td>Kilobytes (KB)</td><td id="res-KB">-</td></tr>
            <tr><td>Megabytes (MB)</td><td id="res-MB">-</td></tr>
            <tr><td>Gigabytes (GB)</td><td id="res-GB">-</td></tr>
            <tr><td>Terabytes (TB)</td><td id="res-TB">-</td></tr>
            <tr><td>Petabytes (PB)</td><td id="res-PB">-</td></tr>
        </table>
    </div>
    <div class="result-section">
        <h4>Binaire (IEC) - Base 1024</h4>
        <table>
            <tr><td>Bytes</td><td id="res-Bi">-</td></tr>
            <tr><td>Kibibytes (KiB)</td><td id="res-KiB">-</td></tr>
            <tr><td>Mebibytes (MiB)</td><td id="res-MiB">-</td></tr>
            <tr><td>Gibibytes (GiB)</td><td id="res-GiB">-</td></tr>
            <tr><td>Tebibytes (TiB)</td><td id="res-TiB">-</td></tr>
            <tr><td>Pebibytes (PiB)</td><td id="res-PiB">-</td></tr>
        </table>
    </div>
</div>

<div class="quick-convert">
    <h4>Conversions rapides</h4>
    <div id="quick-results">
        <p><strong>1 TB</strong> = <span id="tb-to-tib">0.909 TiB</span> (perte de ~9%)</p>
        <p><strong>1 TiB</strong> = <span id="tib-to-tb">1.100 TB</span> (gain de ~10%)</p>
    </div>
</div>

</div>

## Comprendre la différence

### Décimal (SI) vs Binaire (IEC)

| Unité SI | Valeur | Unité IEC | Valeur |
|----------|--------|-----------|--------|
| 1 KB | 1,000 B | 1 KiB | 1,024 B |
| 1 MB | 1,000,000 B | 1 MiB | 1,048,576 B |
| 1 GB | 1,000,000,000 B | 1 GiB | 1,073,741,824 B |
| 1 TB | 1,000,000,000,000 B | 1 TiB | 1,099,511,627,776 B |
| 1 PB | 10^15 B | 1 PiB | 2^50 B |

### Pourquoi cette confusion ?

!!! info "Fabricants de disques (SI)"
    Les fabricants utilisent le système **décimal** (1 TB = 1000 GB).
    Un disque vendu "1 TB" contient 1,000,000,000,000 bytes.

!!! info "Systèmes d'exploitation (IEC)"
    Windows, Linux et macOS affichent en **binaire** (1 TiB = 1024 GiB).
    Le même disque affiche environ **931 GiB** dans l'OS.

### Différence par taille

| Taille annoncée | Capacité réelle OS | Perte apparente |
|-----------------|-------------------|-----------------|
| 256 GB | 238 GiB | 7.0% |
| 512 GB | 477 GiB | 6.8% |
| 1 TB | 931 GiB | 6.9% |
| 2 TB | 1.82 TiB | 9.1% |
| 4 TB | 3.64 TiB | 9.1% |
| 8 TB | 7.28 TiB | 9.1% |
| 16 TB | 14.55 TiB | 9.1% |

<style>
.tool-container {
    background: var(--md-code-bg-color);
    padding: 20px;
    border-radius: 8px;
    margin: 20px 0;
}
.input-row {
    display: flex;
    gap: 20px;
    flex-wrap: wrap;
}
.input-group {
    margin: 15px 0;
}
.input-group label {
    display: block;
    margin-bottom: 5px;
    font-weight: bold;
}
.input-group input, .input-group select {
    padding: 10px;
    font-size: 16px;
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    background: var(--md-default-bg-color);
    color: var(--md-default-fg-color);
}
.input-group input[type="number"] {
    width: 150px;
}
.results-grid {
    display: flex;
    gap: 30px;
    flex-wrap: wrap;
    margin-top: 20px;
}
.result-section {
    flex: 1;
    min-width: 280px;
    background: var(--md-default-bg-color);
    padding: 15px;
    border-radius: 4px;
    border: 1px solid var(--md-default-fg-color--lighter);
}
.result-section h4 {
    margin: 0 0 15px 0;
    color: var(--md-primary-fg-color);
}
.result-section table {
    width: 100%;
}
.result-section td {
    padding: 6px;
    border-bottom: 1px solid var(--md-default-fg-color--lightest);
}
.result-section td:last-child {
    font-family: monospace;
    text-align: right;
}
.quick-convert {
    margin-top: 20px;
    padding: 15px;
    background: var(--md-default-bg-color);
    border-radius: 4px;
    border: 1px solid var(--md-default-fg-color--lighter);
}
.quick-convert h4 {
    margin: 0 0 10px 0;
}
.quick-convert p {
    margin: 5px 0;
}
</style>

<script>
const siUnits = {
    'B': 1,
    'KB': 1e3,
    'MB': 1e6,
    'GB': 1e9,
    'TB': 1e12,
    'PB': 1e15
};

const iecUnits = {
    'Bi': 1,
    'KiB': Math.pow(1024, 1),
    'MiB': Math.pow(1024, 2),
    'GiB': Math.pow(1024, 3),
    'TiB': Math.pow(1024, 4),
    'PiB': Math.pow(1024, 5)
};

function formatNumber(num) {
    if (num === 0) return '0';
    if (num >= 1e15) return num.toExponential(3);
    if (num >= 1000) return num.toLocaleString('fr-FR', { maximumFractionDigits: 2 });
    if (num >= 1) return num.toLocaleString('fr-FR', { maximumFractionDigits: 3 });
    if (num >= 0.001) return num.toLocaleString('fr-FR', { maximumFractionDigits: 6 });
    return num.toExponential(3);
}

function convert() {
    const value = parseFloat(document.getElementById('storage-value').value) || 0;
    const unit = document.getElementById('storage-unit').value;

    // Convert to bytes first
    let bytes;
    if (siUnits[unit]) {
        bytes = value * siUnits[unit];
    } else if (iecUnits[unit]) {
        bytes = value * iecUnits[unit];
    }

    // Convert to all SI units
    for (const [u, factor] of Object.entries(siUnits)) {
        document.getElementById('res-' + u).textContent = formatNumber(bytes / factor);
    }

    // Convert to all IEC units
    for (const [u, factor] of Object.entries(iecUnits)) {
        document.getElementById('res-' + u).textContent = formatNumber(bytes / factor);
    }

    // Update quick conversions based on input
    const tbInBytes = value * (siUnits[unit] || iecUnits[unit]);
    const inTB = tbInBytes / siUnits['TB'];
    const inTiB = tbInBytes / iecUnits['TiB'];

    document.getElementById('tb-to-tib').textContent = formatNumber(inTiB) + ' TiB';
    document.getElementById('tib-to-tb').textContent = formatNumber(inTB) + ' TB';
}

// Event listeners
document.getElementById('storage-value').addEventListener('input', convert);
document.getElementById('storage-unit').addEventListener('change', convert);

// Initial conversion
convert();
</script>
