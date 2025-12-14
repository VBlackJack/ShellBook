---
tags:
  - tools
  - network
  - bandwidth
  - transfer
---

# Bandwidth Calculator

Calculateur de temps de transfert et debit.

<div class="tool-container">

<h3>Temps de transfert</h3>

<div class="calc-grid">
    <div class="input-group">
        <label>Taille du fichier :</label>
        <div class="input-row">
            <input type="number" id="file-size" value="10" min="0" step="0.1">
            <select id="file-unit">
                <option value="1">B</option>
                <option value="1024">KB</option>
                <option value="1048576">MB</option>
                <option value="1073741824" selected>GB</option>
                <option value="1099511627776">TB</option>
            </select>
        </div>
    </div>
    <div class="input-group">
        <label>Debit :</label>
        <div class="input-row">
            <input type="number" id="bandwidth" value="100" min="0" step="1">
            <select id="bandwidth-unit">
                <option value="125">Kbps</option>
                <option value="125000" selected>Mbps</option>
                <option value="125000000">Gbps</option>
                <option value="1024">KB/s</option>
                <option value="1048576">MB/s</option>
                <option value="1073741824">GB/s</option>
            </select>
        </div>
    </div>
</div>

<div id="transfer-result" class="result-box">
    <div class="result-item">
        <span class="result-label">Temps de transfert :</span>
        <span class="result-value" id="transfer-time">-</span>
    </div>
    <div class="result-item">
        <span class="result-label">Debit effectif :</span>
        <span class="result-value" id="effective-rate">-</span>
    </div>
</div>

<h3>Comparaison des debits</h3>

<div class="comparison-grid" id="comparison-grid">
</div>

<h3>Presets connexions</h3>

<div class="presets-grid">
    <button onclick="setBandwidth(56, 125)">Modem 56k</button>
    <button onclick="setBandwidth(2, 125000)">ADSL 2 Mbps</button>
    <button onclick="setBandwidth(20, 125000)">ADSL 20 Mbps</button>
    <button onclick="setBandwidth(100, 125000)">Fibre 100 Mbps</button>
    <button onclick="setBandwidth(1000, 125000)">Fibre 1 Gbps</button>
    <button onclick="setBandwidth(10000, 125000)">10 Gbps</button>
    <button onclick="setBandwidth(100, 1048576)">USB 2.0</button>
    <button onclick="setBandwidth(500, 1048576)">USB 3.0</button>
    <button onclick="setBandwidth(1250, 1048576)">USB 3.1</button>
    <button onclick="setBandwidth(550, 1048576)">SATA III</button>
    <button onclick="setBandwidth(3500, 1048576)">NVMe</button>
</div>

</div>

## Reference debits

### Connexions reseau

| Type | Debit theorique | Debit reel |
|------|-----------------|------------|
| Modem 56k | 56 Kbps | ~5 KB/s |
| ADSL | 1-20 Mbps | 0.1-2 MB/s |
| VDSL | 50-100 Mbps | 5-10 MB/s |
| Fibre FTTH | 100-10000 Mbps | 10-1000 MB/s |
| 4G | 100-300 Mbps | 10-30 MB/s |
| 5G | 1-10 Gbps | 100-500 MB/s |
| WiFi 5 (802.11ac) | 433-6933 Mbps | 50-400 MB/s |
| WiFi 6 (802.11ax) | 600-9608 Mbps | 100-600 MB/s |
| Ethernet 1G | 1 Gbps | 100-120 MB/s |
| Ethernet 10G | 10 Gbps | 1-1.2 GB/s |

### Interfaces stockage

| Type | Debit theorique |
|------|-----------------|
| USB 2.0 | 480 Mbps (60 MB/s) |
| USB 3.0 | 5 Gbps (625 MB/s) |
| USB 3.1 Gen 2 | 10 Gbps (1.25 GB/s) |
| USB 3.2 Gen 2x2 | 20 Gbps (2.5 GB/s) |
| USB4 | 40 Gbps (5 GB/s) |
| SATA III | 6 Gbps (550 MB/s) |
| NVMe PCIe 3.0 x4 | 32 Gbps (4 GB/s) |
| NVMe PCIe 4.0 x4 | 64 Gbps (8 GB/s) |
| NVMe PCIe 5.0 x4 | 128 Gbps (16 GB/s) |

### Formules

```
Temps (s) = Taille (octets) / Debit (octets/s)

bits = octets × 8
Mbps = MB/s × 8
```

!!! tip "Overhead reseau"
    Le debit reel est generalement **10-20% inferieur** au debit theorique
    a cause des en-tetes de protocole (TCP/IP, Ethernet, etc.)

<style>
.tool-container {
    background: var(--md-code-bg-color);
    padding: 20px;
    border-radius: 8px;
    margin: 20px 0;
}
.calc-grid {
    display: flex;
    gap: 30px;
    flex-wrap: wrap;
    margin: 20px 0;
}
.input-group {
    flex: 1;
    min-width: 250px;
}
.input-group label {
    display: block;
    font-weight: bold;
    margin-bottom: 8px;
}
.input-row {
    display: flex;
    gap: 10px;
}
.input-row input {
    flex: 1;
    padding: 10px;
    font-size: 16px;
    font-family: monospace;
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    background: var(--md-default-bg-color);
    color: var(--md-default-fg-color);
}
.input-row select {
    padding: 10px;
    font-size: 14px;
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    background: var(--md-default-bg-color);
    color: var(--md-default-fg-color);
}
.result-box {
    background: var(--md-default-bg-color);
    padding: 20px;
    border-radius: 4px;
    margin: 20px 0;
}
.result-item {
    display: flex;
    justify-content: space-between;
    padding: 10px 0;
    border-bottom: 1px solid var(--md-default-fg-color--lightest);
}
.result-item:last-child {
    border-bottom: none;
}
.result-label {
    font-weight: bold;
}
.result-value {
    font-family: monospace;
    font-size: 18px;
    color: var(--md-primary-fg-color);
}
.comparison-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
    gap: 10px;
    margin: 20px 0;
}
.comparison-item {
    background: var(--md-default-bg-color);
    padding: 15px;
    border-radius: 4px;
    text-align: center;
}
.comparison-item .name {
    font-weight: bold;
    margin-bottom: 5px;
}
.comparison-item .time {
    font-family: monospace;
    font-size: 16px;
    color: var(--md-primary-fg-color);
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
const commonSpeeds = [
    { name: 'ADSL 2 Mbps', bytesPerSec: 2 * 125000 },
    { name: 'ADSL 20 Mbps', bytesPerSec: 20 * 125000 },
    { name: 'Fibre 100 Mbps', bytesPerSec: 100 * 125000 },
    { name: 'Fibre 1 Gbps', bytesPerSec: 1000 * 125000 },
    { name: 'USB 2.0', bytesPerSec: 60 * 1048576 },
    { name: 'USB 3.0', bytesPerSec: 500 * 1048576 }
];

function formatDuration(seconds) {
    if (seconds < 1) {
        return (seconds * 1000).toFixed(0) + ' ms';
    }
    if (seconds < 60) {
        return seconds.toFixed(1) + ' s';
    }
    if (seconds < 3600) {
        const min = Math.floor(seconds / 60);
        const sec = Math.floor(seconds % 60);
        return min + ' min ' + sec + ' s';
    }
    if (seconds < 86400) {
        const hours = Math.floor(seconds / 3600);
        const min = Math.floor((seconds % 3600) / 60);
        return hours + ' h ' + min + ' min';
    }
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    return days + ' jour' + (days > 1 ? 's' : '') + ' ' + hours + ' h';
}

function formatRate(bytesPerSec) {
    if (bytesPerSec >= 1073741824) {
        return (bytesPerSec / 1073741824).toFixed(2) + ' GB/s';
    }
    if (bytesPerSec >= 1048576) {
        return (bytesPerSec / 1048576).toFixed(2) + ' MB/s';
    }
    if (bytesPerSec >= 1024) {
        return (bytesPerSec / 1024).toFixed(2) + ' KB/s';
    }
    return bytesPerSec.toFixed(0) + ' B/s';
}

function calculate() {
    const fileSize = parseFloat(document.getElementById('file-size').value) || 0;
    const fileUnit = parseInt(document.getElementById('file-unit').value);
    const bandwidth = parseFloat(document.getElementById('bandwidth').value) || 0;
    const bandwidthUnit = parseInt(document.getElementById('bandwidth-unit').value);

    const sizeBytes = fileSize * fileUnit;
    const bytesPerSec = bandwidth * bandwidthUnit;

    if (bytesPerSec === 0) {
        document.getElementById('transfer-time').textContent = '-';
        document.getElementById('effective-rate').textContent = '-';
        return;
    }

    const seconds = sizeBytes / bytesPerSec;

    document.getElementById('transfer-time').textContent = formatDuration(seconds);
    document.getElementById('effective-rate').textContent = formatRate(bytesPerSec);

    // Update comparison grid
    const grid = document.getElementById('comparison-grid');
    grid.innerHTML = commonSpeeds.map(speed => {
        const time = sizeBytes / speed.bytesPerSec;
        return `<div class="comparison-item">
            <div class="name">${speed.name}</div>
            <div class="time">${formatDuration(time)}</div>
        </div>`;
    }).join('');
}

function setBandwidth(value, unit) {
    document.getElementById('bandwidth').value = value;
    document.getElementById('bandwidth-unit').value = unit;
    calculate();
}

// Event listeners
document.querySelectorAll('#file-size, #file-unit, #bandwidth, #bandwidth-unit').forEach(el => {
    el.addEventListener('input', calculate);
    el.addEventListener('change', calculate);
});

// Initial calculation
calculate();
</script>
