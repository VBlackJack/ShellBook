---
tags:
  - tools
  - windows
  - licensing
  - virtualization
---

# Windows Licensing Calculator

Calculateur de licences Windows Server pour environnements virtualises.

<div class="tool-container">

<h3>Infrastructure physique</h3>

<div class="input-row">
    <div class="input-group">
        <label for="host-count">Nombre d'hotes physiques :</label>
        <input type="number" id="host-count" value="3" min="1" max="100">
    </div>
    <div class="input-group">
        <label for="cores-per-host">Cores par hote :</label>
        <input type="number" id="cores-per-host" value="32" min="8" max="256">
    </div>
    <div class="input-group">
        <label for="sockets-per-host">Sockets par hote :</label>
        <input type="number" id="sockets-per-host" value="2" min="1" max="8">
    </div>
</div>

<h3>Machines virtuelles Windows</h3>

<div class="input-row">
    <div class="input-group">
        <label for="vm-count">Nombre de VMs Windows :</label>
        <input type="number" id="vm-count" value="20" min="0" max="1000">
    </div>
    <div class="input-group">
        <label for="edition">Edition Windows Server :</label>
        <select id="edition">
            <option value="datacenter">Datacenter (VMs illimitees)</option>
            <option value="standard">Standard (2 VMs / licence)</option>
        </select>
    </div>
</div>

<h3>Options</h3>

<div class="options-row">
    <label><input type="checkbox" id="sa-coverage" checked> Software Assurance (SA)</label>
    <label><input type="checkbox" id="high-availability"> Haute disponibilite (licence tous les hotes)</label>
</div>

<button onclick="calculateLicenses()" class="calc-btn">Calculer</button>

<div id="license-results" class="results-box">
    <h3>Licences requises</h3>
    <table>
        <tr><td><strong>Total cores a licencier</strong></td><td id="total-cores">-</td></tr>
        <tr><td><strong>Licences 2-core packs</strong></td><td id="core-packs">-</td></tr>
        <tr><td><strong>Licences 16-core packs</strong></td><td id="sixteen-packs">-</td></tr>
        <tr><td><strong>Stacking requis (Standard)</strong></td><td id="stacking">-</td></tr>
        <tr><td><strong>Edition recommandee</strong></td><td id="recommended">-</td></tr>
    </table>

    <div class="comparison-section">
        <h4>Comparaison des couts (estimation)</h4>
        <table>
            <tr>
                <th>Edition</th>
                <th>Licences</th>
                <th>Cout estime</th>
            </tr>
            <tr>
                <td>Datacenter</td>
                <td id="dc-licenses">-</td>
                <td id="dc-cost">-</td>
            </tr>
            <tr>
                <td>Standard</td>
                <td id="std-licenses">-</td>
                <td id="std-cost">-</td>
            </tr>
        </table>
    </div>
</div>

<div id="license-warning" class="warning-box" style="display:none;"></div>
<div id="license-info" class="info-box" style="display:none;"></div>

</div>

## Regles de licence Windows Server 2022

### Minimum par hote

!!! warning "Minimums obligatoires"
    - **16 cores minimum** par serveur physique
    - **8 cores minimum** par processeur
    - Licence au **core physique** (pas vCPU)

### Editions et droits de virtualisation

| Edition | VMs Windows incluses | Usage |
|---------|---------------------|-------|
| **Datacenter** | Illimitees | Virtualisation dense |
| **Standard** | 2 VMs par licence | Virtualisation legere |

### Stacking Standard

Pour plus de 2 VMs avec Standard, il faut "stacker" les licences :

| VMs souhaitees | Licences Standard requises |
|----------------|---------------------------|
| 1-2 | 1x |
| 3-4 | 2x |
| 5-6 | 3x |
| 7-8 | 4x |
| ... | ... |

### Seuil de rentabilite

!!! tip "Datacenter vs Standard"
    **Datacenter devient rentable** quand le nombre de VMs depasse le seuil ou le cout
    du stacking Standard depasse celui d'une licence Datacenter.

    Typiquement: **8-10+ VMs par hote** = Datacenter preferable

### Haute disponibilite et mobilite

!!! info "Software Assurance requis pour"
    - **Live Migration** entre hotes
    - **Failover clustering**
    - **License Mobility** dans les fermes de serveurs

Sans SA, chaque hote potentiel doit etre licence individuellement.

## Prix indicatifs (2024)

| Produit | Prix indicatif |
|---------|----------------|
| Windows Server 2022 Standard 16-core | ~$1,070 |
| Windows Server 2022 Datacenter 16-core | ~$6,950 |
| Windows Server 2022 Standard 2-core | ~$134 |
| Windows Server 2022 Datacenter 2-core | ~$868 |

!!! warning "Prix variables"
    Les prix varient selon le canal d'achat (OEM, Volume, CSP) et les remises.
    Consultez votre revendeur Microsoft.

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
.options-row {
    margin: 15px 0;
}
.options-row label {
    margin-right: 20px;
    cursor: pointer;
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
.results-box h3, .results-box h4 {
    margin-top: 0;
}
.results-box table {
    width: 100%;
    margin-bottom: 15px;
}
.results-box td, .results-box th {
    padding: 8px;
    border-bottom: 1px solid var(--md-default-fg-color--lightest);
    text-align: left;
}
.results-box td:last-child, .results-box th:last-child {
    font-family: monospace;
    text-align: right;
}
.comparison-section {
    margin-top: 20px;
    padding-top: 15px;
    border-top: 1px solid var(--md-default-fg-color--lighter);
}
.warning-box {
    margin-top: 15px;
    padding: 15px;
    background: #fff3cd;
    border: 1px solid #ffc107;
    border-radius: 4px;
    color: #856404;
}
.info-box {
    margin-top: 15px;
    padding: 15px;
    background: #d1ecf1;
    border: 1px solid #bee5eb;
    border-radius: 4px;
    color: #0c5460;
}
</style>

<script>
// Approximate pricing (USD)
const pricing = {
    datacenter: { twoCore: 868, sixteenCore: 6950 },
    standard: { twoCore: 134, sixteenCore: 1070 }
};

function calculateLicenses() {
    const hostCount = parseInt(document.getElementById('host-count').value);
    const coresPerHost = parseInt(document.getElementById('cores-per-host').value);
    const socketsPerHost = parseInt(document.getElementById('sockets-per-host').value);
    const vmCount = parseInt(document.getElementById('vm-count').value);
    const edition = document.getElementById('edition').value;
    const hasSA = document.getElementById('sa-coverage').checked;
    const highAvail = document.getElementById('high-availability').checked;

    const warningBox = document.getElementById('license-warning');
    const infoBox = document.getElementById('license-info');
    warningBox.style.display = 'none';
    infoBox.style.display = 'none';

    // Calculate cores to license per host
    // Minimum 16 cores per server, minimum 8 per socket
    const minCoresPerSocket = Math.max(8, Math.ceil(coresPerHost / socketsPerHost));
    const coresPerHostToLicense = Math.max(16, coresPerHost);

    // For HA, all hosts need to be licensed
    const hostsToLicense = highAvail ? hostCount : Math.ceil(vmCount / (edition === 'datacenter' ? 1000 : 2));
    const effectiveHosts = Math.min(hostsToLicense, hostCount);

    const totalCores = effectiveHosts * coresPerHostToLicense;

    // Calculate 2-core packs needed
    const twoCorePacks = Math.ceil(totalCores / 2);

    // Calculate 16-core packs (more economical for full coverage)
    const sixteenCorePacks = Math.ceil(totalCores / 16);

    // Standard stacking calculation
    const vmsPerHost = Math.ceil(vmCount / hostCount);
    const stackingNeeded = edition === 'standard' ? Math.ceil(vmsPerHost / 2) : 1;

    // Cost calculations
    // For Standard, multiply by stacking factor
    const stdTotalCores = totalCores * stackingNeeded;
    const stdSixteenPacks = Math.ceil(stdTotalCores / 16);
    const stdCost = stdSixteenPacks * pricing.standard.sixteenCore;

    // For Datacenter, no stacking needed
    const dcSixteenPacks = Math.ceil(totalCores / 16);
    const dcCost = dcSixteenPacks * pricing.datacenter.sixteenCore;

    // Update display
    document.getElementById('total-cores').textContent = totalCores + ' cores (' + effectiveHosts + ' hotes x ' + coresPerHostToLicense + ' cores)';
    document.getElementById('core-packs').textContent = twoCorePacks + ' packs de 2 cores';
    document.getElementById('sixteen-packs').textContent = sixteenCorePacks + ' packs de 16 cores (recommande)';
    document.getElementById('stacking').textContent = edition === 'standard' ? stackingNeeded + 'x (pour ' + vmsPerHost + ' VMs/hote)' : 'N/A (Datacenter)';

    // Cost comparison
    document.getElementById('dc-licenses').textContent = dcSixteenPacks + ' packs 16-core';
    document.getElementById('dc-cost').textContent = '$' + dcCost.toLocaleString();
    document.getElementById('std-licenses').textContent = stdSixteenPacks + ' packs 16-core (' + stackingNeeded + 'x stack)';
    document.getElementById('std-cost').textContent = '$' + stdCost.toLocaleString();

    // Recommendation
    let recommended;
    if (dcCost < stdCost) {
        recommended = 'Datacenter (moins cher)';
    } else if (vmsPerHost > 6) {
        recommended = 'Datacenter (flexibilite)';
    } else {
        recommended = 'Standard (economique)';
    }
    document.getElementById('recommended').textContent = recommended;

    // Warnings
    let warnings = [];
    if (coresPerHost < 16) {
        warnings.push('Minimum 16 cores par hote requis - vous serez facture pour 16.');
    }
    if (!hasSA && highAvail) {
        warnings.push('Sans Software Assurance, la haute disponibilite necessite une licence sur chaque hote potentiel.');
    }
    if (edition === 'standard' && vmsPerHost > 8) {
        warnings.push('Avec ' + vmsPerHost + ' VMs/hote, Datacenter est probablement plus economique.');
    }

    if (warnings.length > 0) {
        warningBox.innerHTML = warnings.join('<br>');
        warningBox.style.display = 'block';
    }

    // Info
    if (hasSA) {
        infoBox.innerHTML = 'Avec Software Assurance: License Mobility et droits de failover inclus.';
        infoBox.style.display = 'block';
    }
}

// Event listeners
document.querySelectorAll('input, select').forEach(el => {
    el.addEventListener('change', calculateLicenses);
    el.addEventListener('input', calculateLicenses);
});

// Initial calculation
calculateLicenses();
</script>
