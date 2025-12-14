---
tags:
  - tools
  - storage
  - raid
---

# RAID Calculator

Calculateur de capacité et performance RAID.

<div class="tool-container">

<div class="input-row">
    <div class="input-group">
        <label for="disk-count">Nombre de disques :</label>
        <input type="number" id="disk-count" value="4" min="1" max="64">
    </div>

    <div class="input-group">
        <label for="disk-size">Taille par disque :</label>
        <input type="number" id="disk-size" value="1" min="0.1" step="0.1">
        <select id="disk-unit">
            <option value="1000">TB</option>
            <option value="1024">TiB</option>
            <option value="1">GB</option>
        </select>
    </div>
</div>

<div class="input-group">
    <label for="raid-level">Niveau RAID :</label>
    <select id="raid-level">
        <option value="0">RAID 0 (Striping)</option>
        <option value="1">RAID 1 (Mirroring)</option>
        <option value="5" selected>RAID 5 (Single Parity)</option>
        <option value="6">RAID 6 (Double Parity)</option>
        <option value="10">RAID 10 (1+0)</option>
        <option value="50">RAID 50 (5+0)</option>
        <option value="60">RAID 60 (6+0)</option>
    </select>
</div>

<div class="input-group" id="spare-group">
    <label for="hot-spares">Hot Spares :</label>
    <input type="number" id="hot-spares" value="0" min="0" max="8">
</div>

<button onclick="calculateRaid()" class="calc-btn">Calculer</button>

<div id="raid-results" class="results-box">
    <h3>Résultats</h3>
    <table>
        <tr><td><strong>Capacité utilisable</strong></td><td id="usable-capacity">-</td></tr>
        <tr><td><strong>Capacité brute</strong></td><td id="raw-capacity">-</td></tr>
        <tr><td><strong>Efficacité</strong></td><td id="efficiency">-</td></tr>
        <tr><td><strong>Tolérance de panne</strong></td><td id="fault-tolerance">-</td></tr>
        <tr><td><strong>Disques minimum</strong></td><td id="min-disks">-</td></tr>
        <tr><td><strong>Performance lecture</strong></td><td id="read-perf">-</td></tr>
        <tr><td><strong>Performance écriture</strong></td><td id="write-perf">-</td></tr>
    </table>
</div>

<div id="raid-warning" class="warning-box" style="display:none;">
</div>

</div>

## Comparaison des niveaux RAID

| RAID | Min. disques | Tolérance panne | Efficacité | Lecture | Écriture | Usage |
|------|-------------|-----------------|------------|---------|----------|-------|
| **0** | 2 | 0 disque | 100% | Excellente | Excellente | Performance pure |
| **1** | 2 | 1 disque | 50% | Bonne | Normale | OS, critique |
| **5** | 3 | 1 disque | 67-94% | Bonne | Moyenne | Usage général |
| **6** | 4 | 2 disques | 50-88% | Bonne | Faible | Haute disponibilité |
| **10** | 4 | 1 par paire | 50% | Excellente | Bonne | Bases de données |
| **50** | 6 | 1 par groupe | 67-94% | Excellente | Moyenne | Grands volumes |
| **60** | 8 | 2 par groupe | 50-88% | Excellente | Faible | Très haute dispo |

## Recommandations

!!! success "RAID 10 pour les bases de données"
    Meilleur compromis performance/sécurité pour les workloads intensifs en I/O.

!!! info "RAID 6 pour le stockage critique"
    Recommandé pour les gros disques (>2TB) où le rebuild est long et risqué.

!!! warning "RAID 5 attention avec gros disques"
    Risque d'URE (Unrecoverable Read Error) pendant le rebuild sur disques >2TB.

!!! danger "RAID 0 = pas de redondance"
    Uniquement pour données non critiques ou si réplication externe.

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
    width: 100px;
}
.calc-btn {
    background: var(--md-primary-fg-color);
    color: white;
    border: none;
    padding: 12px 24px;
    font-size: 16px;
    border-radius: 4px;
    cursor: pointer;
    margin-top: 10px;
}
.calc-btn:hover {
    opacity: 0.9;
}
.results-box {
    margin-top: 20px;
    padding: 15px;
    background: var(--md-default-bg-color);
    border-radius: 4px;
    border: 1px solid var(--md-default-fg-color--lighter);
}
.results-box h3 {
    margin-top: 0;
}
.results-box table {
    width: 100%;
}
.results-box td {
    padding: 8px;
    border-bottom: 1px solid var(--md-default-fg-color--lightest);
}
.results-box td:last-child {
    font-family: monospace;
    text-align: right;
}
.warning-box {
    margin-top: 15px;
    padding: 15px;
    background: #fff3cd;
    border: 1px solid #ffc107;
    border-radius: 4px;
    color: #856404;
}
</style>

<script>
const raidConfig = {
    '0': { minDisks: 2, parity: 0, fault: 0, read: 'n×', write: 'n×', formula: (n) => n },
    '1': { minDisks: 2, parity: 0, fault: 1, read: 'n×', write: '1×', formula: (n) => Math.floor(n/2) },
    '5': { minDisks: 3, parity: 1, fault: 1, read: '(n-1)×', write: '(n-1)×', formula: (n) => n - 1 },
    '6': { minDisks: 4, parity: 2, fault: 2, read: '(n-2)×', write: '(n-2)×', formula: (n) => n - 2 },
    '10': { minDisks: 4, parity: 0, fault: 1, read: 'n×', write: '(n/2)×', formula: (n) => Math.floor(n/2) },
    '50': { minDisks: 6, parity: 1, fault: 1, read: '(n-g)×', write: '(n-g)×', formula: (n) => n - Math.ceil(n/3) },
    '60': { minDisks: 8, parity: 2, fault: 2, read: '(n-2g)×', write: '(n-2g)×', formula: (n) => n - 2*Math.ceil(n/4) }
};

function formatSize(sizeInGB) {
    if (sizeInGB >= 1000) {
        return (sizeInGB / 1000).toFixed(2) + ' TB';
    }
    return sizeInGB.toFixed(2) + ' GB';
}

function calculateRaid() {
    const diskCount = parseInt(document.getElementById('disk-count').value);
    const diskSize = parseFloat(document.getElementById('disk-size').value);
    const diskUnit = parseInt(document.getElementById('disk-unit').value);
    const raidLevel = document.getElementById('raid-level').value;
    const hotSpares = parseInt(document.getElementById('hot-spares').value);

    const config = raidConfig[raidLevel];
    const warningBox = document.getElementById('raid-warning');
    warningBox.style.display = 'none';

    // Validate
    const effectiveDisks = diskCount - hotSpares;
    if (effectiveDisks < config.minDisks) {
        warningBox.innerHTML = `⚠️ RAID ${raidLevel} nécessite au minimum ${config.minDisks} disques (${diskCount - hotSpares} disponibles après hot spares).`;
        warningBox.style.display = 'block';
        return;
    }

    // RAID 10 needs even number
    if (raidLevel === '10' && effectiveDisks % 2 !== 0) {
        warningBox.innerHTML = '⚠️ RAID 10 nécessite un nombre pair de disques.';
        warningBox.style.display = 'block';
        return;
    }

    const diskSizeGB = diskSize * diskUnit;
    const rawCapacity = diskCount * diskSizeGB;
    const usableDisks = config.formula(effectiveDisks);
    const usableCapacity = usableDisks * diskSizeGB;
    const efficiency = (usableCapacity / (effectiveDisks * diskSizeGB) * 100).toFixed(1);

    let faultTolerance = config.fault;
    if (raidLevel === '10') {
        faultTolerance = '1 par paire miroir';
    } else if (raidLevel === '50') {
        faultTolerance = '1 par groupe RAID 5';
    } else if (raidLevel === '60') {
        faultTolerance = '2 par groupe RAID 6';
    } else {
        faultTolerance = config.fault + ' disque(s)';
    }

    // Read/Write performance relative to single disk
    let readPerf = config.read.replace('n', effectiveDisks).replace('g', Math.ceil(effectiveDisks/3));
    let writePerf = config.write.replace('n', effectiveDisks).replace('g', Math.ceil(effectiveDisks/3));

    document.getElementById('usable-capacity').textContent = formatSize(usableCapacity);
    document.getElementById('raw-capacity').textContent = formatSize(rawCapacity);
    document.getElementById('efficiency').textContent = efficiency + '%';
    document.getElementById('fault-tolerance').textContent = faultTolerance;
    document.getElementById('min-disks').textContent = config.minDisks;
    document.getElementById('read-perf').textContent = readPerf;
    document.getElementById('write-perf').textContent = writePerf;

    // Warnings
    if (raidLevel === '0') {
        warningBox.innerHTML = '⚠️ RAID 0 n\'offre aucune protection contre la perte de données !';
        warningBox.style.display = 'block';
    } else if (raidLevel === '5' && diskSizeGB >= 2000) {
        warningBox.innerHTML = '⚠️ RAID 5 avec des disques ≥2TB : risque élevé d\'URE pendant le rebuild. Considérez RAID 6 ou RAID 10.';
        warningBox.style.display = 'block';
    }
}

// Event listeners
document.querySelectorAll('#disk-count, #disk-size, #disk-unit, #raid-level, #hot-spares').forEach(el => {
    el.addEventListener('change', calculateRaid);
    el.addEventListener('input', calculateRaid);
});

// Initial calculation
calculateRaid();
</script>
