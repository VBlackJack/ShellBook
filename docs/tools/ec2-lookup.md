---
tags:
  - tools
  - aws
  - ec2
  - cloud
---

# AWS EC2 Instance Lookup

Reference des types d'instances EC2 AWS.

<div class="tool-container">

<div class="search-section">
    <div class="input-group">
        <label for="instance-search">Rechercher :</label>
        <input type="text" id="instance-search" placeholder="t3.micro, m5.large, etc.">
    </div>
    <div class="filters">
        <select id="filter-family">
            <option value="">Toutes familles</option>
            <option value="t">t - General Purpose (Burstable)</option>
            <option value="m">m - General Purpose</option>
            <option value="c">c - Compute Optimized</option>
            <option value="r">r - Memory Optimized</option>
            <option value="i">i - Storage Optimized</option>
            <option value="g">g - GPU Instances</option>
        </select>
    </div>
</div>

<div id="instance-results" class="results-table">
    <table>
        <thead>
            <tr>
                <th>Instance</th>
                <th>vCPU</th>
                <th>RAM</th>
                <th>Stockage</th>
                <th>Reseau</th>
                <th>Prix/h (us-east-1)</th>
            </tr>
        </thead>
        <tbody id="instance-tbody">
        </tbody>
    </table>
</div>

<div id="instance-detail" class="detail-box" style="display:none;">
    <h4 id="detail-name">-</h4>
    <table>
        <tr><td>Famille</td><td id="detail-family">-</td></tr>
        <tr><td>vCPU</td><td id="detail-vcpu">-</td></tr>
        <tr><td>Memoire</td><td id="detail-memory">-</td></tr>
        <tr><td>Stockage</td><td id="detail-storage">-</td></tr>
        <tr><td>Reseau</td><td id="detail-network">-</td></tr>
        <tr><td>EBS Optimized</td><td id="detail-ebs">-</td></tr>
        <tr><td>Prix On-Demand</td><td id="detail-price">-</td></tr>
        <tr><td>Prix/mois (730h)</td><td id="detail-monthly">-</td></tr>
    </table>
</div>

</div>

## Familles d'instances EC2

### General Purpose

| Famille | Usage | Caracteristiques |
|---------|-------|------------------|
| **t3/t3a** | Dev, test, petites apps | Burstable, credits CPU |
| **t4g** | Comme t3 mais ARM (Graviton) | Meilleur rapport qualite/prix |
| **m5/m5a** | Applications generales | Equilibre CPU/RAM |
| **m6i/m6a** | Derniere generation Intel/AMD | Meilleur perf/$ |
| **m7g** | ARM Graviton3 | Meilleur perf/$ |

### Compute Optimized

| Famille | Usage | Caracteristiques |
|---------|-------|------------------|
| **c5/c5a** | Calcul intensif | Ratio CPU/RAM eleve |
| **c6i/c6a** | HPC, gaming, encoding | Derniere gen |
| **c7g** | ARM Graviton3 | Meilleur perf/$ |

### Memory Optimized

| Famille | Usage | Caracteristiques |
|---------|-------|------------------|
| **r5/r5a** | Bases de donnees | Ratio RAM/CPU eleve |
| **r6i/r6a** | In-memory caching | Derniere gen |
| **x2idn** | SAP HANA, grandes DBs | Jusqu'a 3 TB RAM |

### Storage Optimized

| Famille | Usage | Caracteristiques |
|---------|-------|------------------|
| **i3** | Bases NoSQL | NVMe local haute perf |
| **i4i** | Transactionnel | Derniere gen NVMe |
| **d3** | Data warehousing | HDD haute densite |

### GPU Instances

| Famille | Usage | GPU |
|---------|-------|-----|
| **g4dn** | ML inference, graphics | NVIDIA T4 |
| **g5** | ML training/inference | NVIDIA A10G |
| **p4d** | Deep learning | NVIDIA A100 |

## Conventions de nommage

```
m5.xlarge
│ │  │
│ │  └── Taille (nano, micro, small, medium, large, xlarge, 2xlarge...)
│ └───── Generation (plus recent = mieux)
└─────── Famille (m = general purpose)

Suffixes:
a = AMD processor
n = Network optimized
d = Local NVMe storage
g = Graviton (ARM)
```

## Comparaison de prix

!!! tip "Economiser sur EC2"
    - **Spot Instances**: jusqu'a 90% moins cher
    - **Reserved Instances**: 30-60% de reduction
    - **Savings Plans**: Flexibilite + economies
    - **Graviton (ARM)**: ~20% moins cher

<style>
.tool-container {
    background: var(--md-code-bg-color);
    padding: 20px;
    border-radius: 8px;
    margin: 20px 0;
}
.search-section {
    display: flex;
    gap: 20px;
    flex-wrap: wrap;
    margin-bottom: 20px;
}
.input-group {
    flex: 1;
    min-width: 200px;
}
.input-group label {
    display: block;
    font-weight: bold;
    margin-bottom: 5px;
}
.input-group input {
    width: 100%;
    padding: 10px;
    font-size: 16px;
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    background: var(--md-default-bg-color);
    color: var(--md-default-fg-color);
}
.filters select {
    padding: 10px;
    font-size: 14px;
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    background: var(--md-default-bg-color);
    color: var(--md-default-fg-color);
}
.results-table {
    overflow-x: auto;
}
.results-table table {
    width: 100%;
    background: var(--md-default-bg-color);
    border-collapse: collapse;
}
.results-table th, .results-table td {
    padding: 10px;
    text-align: left;
    border-bottom: 1px solid var(--md-default-fg-color--lightest);
}
.results-table th {
    background: var(--md-code-bg-color);
    font-weight: bold;
    position: sticky;
    top: 0;
}
.results-table tr {
    cursor: pointer;
}
.results-table tr:hover {
    background: var(--md-code-bg-color);
}
.results-table td:first-child {
    font-family: monospace;
    font-weight: bold;
    color: var(--md-primary-fg-color);
}
.detail-box {
    margin-top: 20px;
    padding: 20px;
    background: var(--md-default-bg-color);
    border-radius: 4px;
    border: 2px solid var(--md-primary-fg-color);
}
.detail-box h4 {
    margin: 0 0 15px 0;
    font-size: 20px;
    color: var(--md-primary-fg-color);
}
.detail-box table {
    width: 100%;
}
.detail-box td {
    padding: 8px;
    border-bottom: 1px solid var(--md-default-fg-color--lightest);
}
.detail-box td:first-child {
    font-weight: bold;
    width: 150px;
}
</style>

<script>
// EC2 instance database (subset of common instances)
const ec2Instances = [
    // t3 family
    { name: 't3.nano', family: 't', vcpu: 2, memory: 0.5, storage: 'EBS', network: 'Low', price: 0.0052 },
    { name: 't3.micro', family: 't', vcpu: 2, memory: 1, storage: 'EBS', network: 'Low', price: 0.0104 },
    { name: 't3.small', family: 't', vcpu: 2, memory: 2, storage: 'EBS', network: 'Low-Mod', price: 0.0208 },
    { name: 't3.medium', family: 't', vcpu: 2, memory: 4, storage: 'EBS', network: 'Low-Mod', price: 0.0416 },
    { name: 't3.large', family: 't', vcpu: 2, memory: 8, storage: 'EBS', network: 'Low-Mod', price: 0.0832 },
    { name: 't3.xlarge', family: 't', vcpu: 4, memory: 16, storage: 'EBS', network: 'Moderate', price: 0.1664 },
    { name: 't3.2xlarge', family: 't', vcpu: 8, memory: 32, storage: 'EBS', network: 'Moderate', price: 0.3328 },

    // m5 family
    { name: 'm5.large', family: 'm', vcpu: 2, memory: 8, storage: 'EBS', network: 'Up to 10 Gbps', price: 0.096 },
    { name: 'm5.xlarge', family: 'm', vcpu: 4, memory: 16, storage: 'EBS', network: 'Up to 10 Gbps', price: 0.192 },
    { name: 'm5.2xlarge', family: 'm', vcpu: 8, memory: 32, storage: 'EBS', network: 'Up to 10 Gbps', price: 0.384 },
    { name: 'm5.4xlarge', family: 'm', vcpu: 16, memory: 64, storage: 'EBS', network: 'Up to 10 Gbps', price: 0.768 },
    { name: 'm5.8xlarge', family: 'm', vcpu: 32, memory: 128, storage: 'EBS', network: '10 Gbps', price: 1.536 },
    { name: 'm5.12xlarge', family: 'm', vcpu: 48, memory: 192, storage: 'EBS', network: '12 Gbps', price: 2.304 },
    { name: 'm5.16xlarge', family: 'm', vcpu: 64, memory: 256, storage: 'EBS', network: '20 Gbps', price: 3.072 },
    { name: 'm5.24xlarge', family: 'm', vcpu: 96, memory: 384, storage: 'EBS', network: '25 Gbps', price: 4.608 },

    // m6i family
    { name: 'm6i.large', family: 'm', vcpu: 2, memory: 8, storage: 'EBS', network: 'Up to 12.5 Gbps', price: 0.096 },
    { name: 'm6i.xlarge', family: 'm', vcpu: 4, memory: 16, storage: 'EBS', network: 'Up to 12.5 Gbps', price: 0.192 },
    { name: 'm6i.2xlarge', family: 'm', vcpu: 8, memory: 32, storage: 'EBS', network: 'Up to 12.5 Gbps', price: 0.384 },
    { name: 'm6i.4xlarge', family: 'm', vcpu: 16, memory: 64, storage: 'EBS', network: 'Up to 12.5 Gbps', price: 0.768 },

    // c5 family
    { name: 'c5.large', family: 'c', vcpu: 2, memory: 4, storage: 'EBS', network: 'Up to 10 Gbps', price: 0.085 },
    { name: 'c5.xlarge', family: 'c', vcpu: 4, memory: 8, storage: 'EBS', network: 'Up to 10 Gbps', price: 0.17 },
    { name: 'c5.2xlarge', family: 'c', vcpu: 8, memory: 16, storage: 'EBS', network: 'Up to 10 Gbps', price: 0.34 },
    { name: 'c5.4xlarge', family: 'c', vcpu: 16, memory: 32, storage: 'EBS', network: 'Up to 10 Gbps', price: 0.68 },
    { name: 'c5.9xlarge', family: 'c', vcpu: 36, memory: 72, storage: 'EBS', network: '10 Gbps', price: 1.53 },
    { name: 'c5.12xlarge', family: 'c', vcpu: 48, memory: 96, storage: 'EBS', network: '12 Gbps', price: 2.04 },
    { name: 'c5.18xlarge', family: 'c', vcpu: 72, memory: 144, storage: 'EBS', network: '25 Gbps', price: 3.06 },

    // r5 family
    { name: 'r5.large', family: 'r', vcpu: 2, memory: 16, storage: 'EBS', network: 'Up to 10 Gbps', price: 0.126 },
    { name: 'r5.xlarge', family: 'r', vcpu: 4, memory: 32, storage: 'EBS', network: 'Up to 10 Gbps', price: 0.252 },
    { name: 'r5.2xlarge', family: 'r', vcpu: 8, memory: 64, storage: 'EBS', network: 'Up to 10 Gbps', price: 0.504 },
    { name: 'r5.4xlarge', family: 'r', vcpu: 16, memory: 128, storage: 'EBS', network: 'Up to 10 Gbps', price: 1.008 },
    { name: 'r5.8xlarge', family: 'r', vcpu: 32, memory: 256, storage: 'EBS', network: '10 Gbps', price: 2.016 },
    { name: 'r5.12xlarge', family: 'r', vcpu: 48, memory: 384, storage: 'EBS', network: '10 Gbps', price: 3.024 },

    // i3 family
    { name: 'i3.large', family: 'i', vcpu: 2, memory: 15.25, storage: '475 GB NVMe', network: 'Up to 10 Gbps', price: 0.156 },
    { name: 'i3.xlarge', family: 'i', vcpu: 4, memory: 30.5, storage: '950 GB NVMe', network: 'Up to 10 Gbps', price: 0.312 },
    { name: 'i3.2xlarge', family: 'i', vcpu: 8, memory: 61, storage: '1.9 TB NVMe', network: 'Up to 10 Gbps', price: 0.624 },
    { name: 'i3.4xlarge', family: 'i', vcpu: 16, memory: 122, storage: '3.8 TB NVMe', network: 'Up to 10 Gbps', price: 1.248 },

    // g4dn family
    { name: 'g4dn.xlarge', family: 'g', vcpu: 4, memory: 16, storage: '125 GB NVMe', network: 'Up to 25 Gbps', price: 0.526, gpu: '1x T4' },
    { name: 'g4dn.2xlarge', family: 'g', vcpu: 8, memory: 32, storage: '225 GB NVMe', network: 'Up to 25 Gbps', price: 0.752, gpu: '1x T4' },
    { name: 'g4dn.4xlarge', family: 'g', vcpu: 16, memory: 64, storage: '225 GB NVMe', network: 'Up to 25 Gbps', price: 1.204, gpu: '1x T4' },
    { name: 'g4dn.8xlarge', family: 'g', vcpu: 32, memory: 128, storage: '900 GB NVMe', network: '50 Gbps', price: 2.176, gpu: '1x T4' },
    { name: 'g4dn.12xlarge', family: 'g', vcpu: 48, memory: 192, storage: '900 GB NVMe', network: '50 Gbps', price: 3.912, gpu: '4x T4' }
];

function filterInstances() {
    const search = document.getElementById('instance-search').value.toLowerCase();
    const family = document.getElementById('filter-family').value;

    const filtered = ec2Instances.filter(instance => {
        const matchSearch = !search || instance.name.toLowerCase().includes(search);
        const matchFamily = !family || instance.family === family;
        return matchSearch && matchFamily;
    });

    renderTable(filtered);
}

function renderTable(instances) {
    const tbody = document.getElementById('instance-tbody');
    tbody.innerHTML = instances.map(instance => `
        <tr onclick="showDetail('${instance.name}')">
            <td>${instance.name}</td>
            <td>${instance.vcpu}</td>
            <td>${instance.memory} GB</td>
            <td>${instance.storage}</td>
            <td>${instance.network}</td>
            <td>$${instance.price.toFixed(4)}</td>
        </tr>
    `).join('');
}

function showDetail(name) {
    const instance = ec2Instances.find(i => i.name === name);
    if (!instance) return;

    document.getElementById('detail-name').textContent = instance.name;
    document.getElementById('detail-family').textContent = getFamilyName(instance.family);
    document.getElementById('detail-vcpu').textContent = instance.vcpu + ' vCPU';
    document.getElementById('detail-memory').textContent = instance.memory + ' GB';
    document.getElementById('detail-storage').textContent = instance.storage;
    document.getElementById('detail-network').textContent = instance.network;
    document.getElementById('detail-ebs').textContent = instance.storage === 'EBS' ? 'Oui' : 'Avec stockage local';
    document.getElementById('detail-price').textContent = '$' + instance.price.toFixed(4) + '/heure';
    document.getElementById('detail-monthly').textContent = '$' + (instance.price * 730).toFixed(2) + '/mois';

    document.getElementById('instance-detail').style.display = 'block';
}

function getFamilyName(family) {
    const names = {
        't': 'General Purpose (Burstable)',
        'm': 'General Purpose',
        'c': 'Compute Optimized',
        'r': 'Memory Optimized',
        'i': 'Storage Optimized',
        'g': 'GPU Instances'
    };
    return names[family] || family;
}

// Event listeners
document.getElementById('instance-search').addEventListener('input', filterInstances);
document.getElementById('filter-family').addEventListener('change', filterInstances);

// Initial render
filterInstances();
</script>
