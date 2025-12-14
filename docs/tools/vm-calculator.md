---
tags:
  - tools
  - virtualization
  - sizing
  - vmware
  - hyperv
---

# VM Sizing Calculator

Calculateur de dimensionnement pour environnements virtualisés.

<div class="tool-container">

<h3>Configuration de l'hôte</h3>

<div class="input-row">
    <div class="input-group">
        <label for="host-cpu">CPU physiques (cores) :</label>
        <input type="number" id="host-cpu" value="32" min="1" max="256">
    </div>
    <div class="input-group">
        <label for="host-ram">RAM totale (GB) :</label>
        <input type="number" id="host-ram" value="256" min="1" max="8192">
    </div>
    <div class="input-group">
        <label for="host-storage">Stockage (TB) :</label>
        <input type="number" id="host-storage" value="10" min="0.1" step="0.1">
    </div>
</div>

<h3>Configuration des VMs</h3>

<div class="input-row">
    <div class="input-group">
        <label for="vm-cpu">vCPU par VM :</label>
        <input type="number" id="vm-cpu" value="4" min="1" max="64">
    </div>
    <div class="input-group">
        <label for="vm-ram">RAM par VM (GB) :</label>
        <input type="number" id="vm-ram" value="8" min="1" max="1024">
    </div>
    <div class="input-group">
        <label for="vm-storage">Stockage par VM (GB) :</label>
        <input type="number" id="vm-storage" value="100" min="1">
    </div>
</div>

<h3>Paramètres avancés</h3>

<div class="input-row">
    <div class="input-group">
        <label for="cpu-ratio">Ratio vCPU:pCPU :</label>
        <select id="cpu-ratio">
            <option value="1">1:1 (Critique)</option>
            <option value="2">2:1 (Production)</option>
            <option value="3" selected>3:1 (Général)</option>
            <option value="4">4:1 (Dev/Test)</option>
            <option value="6">6:1 (VDI)</option>
            <option value="8">8:1 (Densité max)</option>
        </select>
    </div>
    <div class="input-group">
        <label for="ram-overhead">Overhead hyperviseur :</label>
        <select id="ram-overhead">
            <option value="0.02">2% (ESXi optimisé)</option>
            <option value="0.05" selected>5% (Standard)</option>
            <option value="0.10">10% (Hyper-V)</option>
            <option value="0.15">15% (Avec HA)</option>
        </select>
    </div>
    <div class="input-group">
        <label for="storage-overhead">Overhead stockage :</label>
        <select id="storage-overhead">
            <option value="0.10">10% (Thin provisioning)</option>
            <option value="0.20" selected>20% (Standard)</option>
            <option value="0.30">30% (Avec snapshots)</option>
            <option value="0.50">50% (Réplication)</option>
        </select>
    </div>
</div>

<button onclick="calculateVM()" class="calc-btn">Calculer</button>

<div id="vm-results" class="results-box">
    <h3>Résultats</h3>
    <div class="results-grid">
        <div class="result-card">
            <div class="result-value" id="max-vms">-</div>
            <div class="result-label">VMs maximum</div>
        </div>
        <div class="result-card">
            <div class="result-value" id="limiting-factor">-</div>
            <div class="result-label">Facteur limitant</div>
        </div>
    </div>
    <table>
        <tr><td><strong>Limite CPU</strong></td><td id="cpu-limit">-</td></tr>
        <tr><td><strong>Limite RAM</strong></td><td id="ram-limit">-</td></tr>
        <tr><td><strong>Limite Stockage</strong></td><td id="storage-limit">-</td></tr>
        <tr><td><strong>vCPU totaux alloués</strong></td><td id="total-vcpu">-</td></tr>
        <tr><td><strong>RAM totale allouée</strong></td><td id="total-ram">-</td></tr>
        <tr><td><strong>Stockage total alloué</strong></td><td id="total-storage">-</td></tr>
    </table>
</div>

<div id="vm-warning" class="warning-box" style="display:none;"></div>

</div>

## Recommandations de sizing

### Ratios vCPU:pCPU recommandés

| Workload | Ratio | Description |
|----------|-------|-------------|
| Critique | 1:1 | Base de données, temps réel |
| Production | 2:1 | Applications métier |
| Général | 3:1 | Serveurs standards |
| Dev/Test | 4:1 | Environnements non-prod |
| VDI | 6:1 | Postes virtuels |
| Densité max | 8:1 | Lab, démo |

### Dimensionnement RAM

!!! tip "Règle générale"
    Prévoir **10-15%** de la RAM totale pour l'hyperviseur et ses fonctionnalités (vMotion, HA, etc.)

| Hyperviseur | Overhead typique |
|-------------|------------------|
| VMware ESXi | 2-5% |
| Microsoft Hyper-V | 5-10% |
| Proxmox VE | 3-5% |
| KVM/libvirt | 2-4% |

### Stockage

!!! warning "Thin provisioning"
    Avec le thin provisioning, surveillez attentivement l'espace réellement utilisé.
    Prévoir 20-30% d'espace libre minimum.

| Scénario | Overhead recommandé |
|----------|---------------------|
| Thick provisioning | 10% |
| Thin provisioning | 20% |
| Avec snapshots | 30-50% |
| Avec réplication | 50-100% |

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
    margin: 10px 0;
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
    margin-top: 15px;
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
.results-grid {
    display: flex;
    gap: 20px;
    margin-bottom: 20px;
}
.result-card {
    flex: 1;
    text-align: center;
    padding: 20px;
    background: var(--md-code-bg-color);
    border-radius: 4px;
}
.result-value {
    font-size: 36px;
    font-weight: bold;
    color: var(--md-primary-fg-color);
}
.result-label {
    font-size: 14px;
    margin-top: 5px;
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
function calculateVM() {
    const hostCPU = parseInt(document.getElementById('host-cpu').value);
    const hostRAM = parseInt(document.getElementById('host-ram').value);
    const hostStorage = parseFloat(document.getElementById('host-storage').value) * 1000; // Convert to GB
    const vmCPU = parseInt(document.getElementById('vm-cpu').value);
    const vmRAM = parseInt(document.getElementById('vm-ram').value);
    const vmStorage = parseInt(document.getElementById('vm-storage').value);
    const cpuRatio = parseInt(document.getElementById('cpu-ratio').value);
    const ramOverhead = parseFloat(document.getElementById('ram-overhead').value);
    const storageOverhead = parseFloat(document.getElementById('storage-overhead').value);

    const warningBox = document.getElementById('vm-warning');
    warningBox.style.display = 'none';

    // Calculate available resources
    const availableVCPU = hostCPU * cpuRatio;
    const availableRAM = hostRAM * (1 - ramOverhead);
    const availableStorage = hostStorage * (1 - storageOverhead);

    // Calculate limits
    const cpuLimitVMs = Math.floor(availableVCPU / vmCPU);
    const ramLimitVMs = Math.floor(availableRAM / vmRAM);
    const storageLimitVMs = Math.floor(availableStorage / vmStorage);

    // Find minimum (limiting factor)
    const maxVMs = Math.min(cpuLimitVMs, ramLimitVMs, storageLimitVMs);
    let limitingFactor = 'CPU';
    if (maxVMs === ramLimitVMs) limitingFactor = 'RAM';
    if (maxVMs === storageLimitVMs) limitingFactor = 'Stockage';

    // Calculate totals
    const totalVCPU = maxVMs * vmCPU;
    const totalRAM = maxVMs * vmRAM;
    const totalStorage = maxVMs * vmStorage;

    // Update display
    document.getElementById('max-vms').textContent = maxVMs;
    document.getElementById('limiting-factor').textContent = limitingFactor;
    document.getElementById('cpu-limit').textContent = cpuLimitVMs + ' VMs (vCPU disponibles: ' + availableVCPU + ')';
    document.getElementById('ram-limit').textContent = ramLimitVMs + ' VMs (RAM disponible: ' + availableRAM.toFixed(1) + ' GB)';
    document.getElementById('storage-limit').textContent = storageLimitVMs + ' VMs (Stockage disponible: ' + availableStorage.toFixed(0) + ' GB)';
    document.getElementById('total-vcpu').textContent = totalVCPU + ' vCPU (' + (totalVCPU/hostCPU).toFixed(1) + ':1 effectif)';
    document.getElementById('total-ram').textContent = totalRAM + ' GB (' + ((totalRAM/hostRAM)*100).toFixed(1) + '% de la RAM)';
    document.getElementById('total-storage').textContent = (totalStorage/1000).toFixed(2) + ' TB (' + ((totalStorage/hostStorage)*100).toFixed(1) + '% du stockage)';

    // Warnings
    let warnings = [];
    if (cpuRatio > 4 && vmCPU > 2) {
        warnings.push('Ratio CPU élevé avec VMs multi-core : risque de contention CPU.');
    }
    if ((totalRAM / hostRAM) > 0.9) {
        warnings.push('Utilisation RAM > 90% : considérez la mémoire partagée ou l\'overcommit.');
    }
    if (maxVMs < 1) {
        warnings.push('Configuration impossible : ressources insuffisantes pour une seule VM.');
    }

    if (warnings.length > 0) {
        warningBox.innerHTML = '⚠️ ' + warnings.join('<br>⚠️ ');
        warningBox.style.display = 'block';
    }
}

// Event listeners
document.querySelectorAll('input, select').forEach(el => {
    el.addEventListener('change', calculateVM);
    el.addEventListener('input', calculateVM);
});

// Initial calculation
calculateVM();
</script>
