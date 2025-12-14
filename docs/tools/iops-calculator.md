---
tags:
  - tools
  - system
  - storage
  - iops
---

# IOPS Calculator

Calculateur d'IOPS et de throughput pour le dimensionnement du stockage.

<div id="iops-app">
  <div class="iops-container">
    <div class="iops-section">
      <h3>Parametres du workload</h3>

      <div class="form-group">
        <label>Type de stockage</label>
        <select id="storageType" onchange="updateStorageDefaults(); calculate()">
          <option value="ssd-nvme">SSD NVMe</option>
          <option value="ssd-sata">SSD SATA</option>
          <option value="hdd-sas">HDD SAS 15K</option>
          <option value="hdd-sata">HDD SATA 7.2K</option>
          <option value="cloud-ssd">Cloud SSD (gp3/Premium)</option>
          <option value="cloud-io">Cloud IO Optimized</option>
          <option value="custom">Personnalise</option>
        </select>
      </div>

      <div class="form-group">
        <label>IOPS par disque</label>
        <input type="number" id="iopsPerDisk" value="100000" oninput="onManualStorageInput()">
      </div>

      <div class="form-group">
        <label>Throughput par disque (MB/s)</label>
        <input type="number" id="throughputPerDisk" value="3500" oninput="onManualStorageInput()">
      </div>

      <div class="form-group">
        <label>Nombre de disques</label>
        <input type="number" id="diskCount" value="1" min="1" oninput="calculate()">
      </div>

      <div class="form-group">
        <label>Configuration RAID</label>
        <select id="raidLevel" onchange="calculate()">
          <option value="none">Aucun (JBOD)</option>
          <option value="raid0">RAID 0 (stripe)</option>
          <option value="raid1">RAID 1 (mirror)</option>
          <option value="raid5">RAID 5</option>
          <option value="raid6">RAID 6</option>
          <option value="raid10">RAID 10</option>
        </select>
      </div>

      <div class="form-group">
        <label>Ratio Read/Write</label>
        <div class="slider-row">
          <span>Read</span>
          <input type="range" id="readRatio" min="0" max="100" value="70" oninput="calculate()">
          <span>Write</span>
        </div>
        <div class="ratio-display">
          <span id="readPct">70%</span> / <span id="writePct">30%</span>
        </div>
      </div>
    </div>

    <div class="iops-section">
      <h3>Resultats</h3>

      <div class="results-grid">
        <div class="result-card">
          <div class="result-label">IOPS theoriques</div>
          <div class="result-value" id="rawIops">0</div>
        </div>

        <div class="result-card">
          <div class="result-label">IOPS effectifs</div>
          <div class="result-value" id="effectiveIops">0</div>
        </div>

        <div class="result-card primary">
          <div class="result-label">Throughput total</div>
          <div class="result-value" id="totalThroughput">0</div>
          <div class="result-unit">MB/s</div>
        </div>

        <div class="result-card">
          <div class="result-label">Latence estimee</div>
          <div class="result-value" id="latency">0</div>
          <div class="result-unit">ms</div>
        </div>
      </div>

      <div class="breakdown">
        <h4>Details</h4>
        <div id="breakdown" class="breakdown-content"></div>
      </div>
    </div>
  </div>

  <div class="workload-section">
    <h3>Estimation par workload</h3>

    <div class="workload-grid">
      <div class="workload-card" onclick="setWorkload('oltp')">
        <h4>💾 OLTP Database</h4>
        <p>Random I/O, 8K blocks</p>
        <span>~5000 IOPS</span>
      </div>

      <div class="workload-card" onclick="setWorkload('olap')">
        <h4>📊 OLAP/Analytics</h4>
        <p>Sequential reads, large blocks</p>
        <span>~500 MB/s</span>
      </div>

      <div class="workload-card" onclick="setWorkload('vm')">
        <h4>🖥️ VM Hosting</h4>
        <p>Mixed random/sequential</p>
        <span>~100 IOPS/VM</span>
      </div>

      <div class="workload-card" onclick="setWorkload('web')">
        <h4>🌐 Web Server</h4>
        <p>Read-heavy, cacheable</p>
        <span>~500 IOPS</span>
      </div>

      <div class="workload-card" onclick="setWorkload('video')">
        <h4>🎬 Video Streaming</h4>
        <p>Sequential read, high throughput</p>
        <span>~1 GB/s</span>
      </div>

      <div class="workload-card" onclick="setWorkload('backup')">
        <h4>💿 Backup</h4>
        <p>Sequential write, bulk</p>
        <span>~500 MB/s</span>
      </div>
    </div>
  </div>

  <div class="reference-section">
    <h3>Reference performances stockage</h3>

    <table class="ref-table">
      <thead>
        <tr>
          <th>Type</th>
          <th>IOPS (4K)</th>
          <th>Throughput</th>
          <th>Latence</th>
          <th>Prix relatif</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td>NVMe PCIe 4.0</td>
          <td>500K-1M</td>
          <td>5-7 GB/s</td>
          <td>&lt;0.1ms</td>
          <td>$$$$</td>
        </tr>
        <tr>
          <td>NVMe PCIe 3.0</td>
          <td>100K-500K</td>
          <td>2-3.5 GB/s</td>
          <td>&lt;0.1ms</td>
          <td>$$$</td>
        </tr>
        <tr>
          <td>SSD SATA</td>
          <td>50K-100K</td>
          <td>500-550 MB/s</td>
          <td>0.1-0.5ms</td>
          <td>$$</td>
        </tr>
        <tr>
          <td>HDD SAS 15K</td>
          <td>150-200</td>
          <td>150-200 MB/s</td>
          <td>3-5ms</td>
          <td>$$</td>
        </tr>
        <tr>
          <td>HDD SATA 7.2K</td>
          <td>75-100</td>
          <td>100-150 MB/s</td>
          <td>8-15ms</td>
          <td>$</td>
        </tr>
        <tr>
          <td>AWS gp3</td>
          <td>3K-16K</td>
          <td>125-1000 MB/s</td>
          <td>1-2ms</td>
          <td>$$</td>
        </tr>
        <tr>
          <td>AWS io2</td>
          <td>64K</td>
          <td>1000 MB/s</td>
          <td>&lt;1ms</td>
          <td>$$$$</td>
        </tr>
        <tr>
          <td>Azure Premium P30</td>
          <td>5K</td>
          <td>200 MB/s</td>
          <td>1-2ms</td>
          <td>$$$</td>
        </tr>
      </tbody>
    </table>
  </div>
</div>

<style>
.iops-container {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 20px;
}

@media (max-width: 800px) {
  .iops-container {
    grid-template-columns: 1fr;
  }
}

.iops-section, .workload-section, .reference-section {
  background: var(--md-code-bg-color);
  padding: 20px;
  border-radius: 8px;
  margin-bottom: 20px;
}

.form-group {
  margin-bottom: 15px;
}

.form-group label {
  display: block;
  font-size: 0.85em;
  margin-bottom: 5px;
  color: var(--md-default-fg-color--light);
}

.form-group select,
.form-group input[type="number"] {
  width: 100%;
  padding: 10px;
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  background: var(--md-default-bg-color);
  color: var(--md-default-fg-color);
  font-family: monospace;
}

.slider-row {
  display: flex;
  align-items: center;
  gap: 10px;
}

.slider-row input[type="range"] {
  flex: 1;
}

.ratio-display {
  text-align: center;
  margin-top: 5px;
  font-family: monospace;
}

.results-grid {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 12px;
  margin-bottom: 20px;
}

.result-card {
  background: var(--md-default-bg-color);
  padding: 15px;
  border-radius: 6px;
  text-align: center;
}

.result-card.primary {
  grid-column: span 2;
  background: var(--md-primary-fg-color);
  color: white;
}

.result-label {
  font-size: 0.8em;
  opacity: 0.8;
  margin-bottom: 5px;
}

.result-value {
  font-size: 1.8em;
  font-weight: 700;
  font-family: monospace;
}

.result-unit {
  font-size: 0.75em;
  opacity: 0.7;
}

.breakdown {
  background: var(--md-default-bg-color);
  padding: 15px;
  border-radius: 6px;
}

.breakdown h4 {
  margin: 0 0 10px 0;
}

.breakdown-content {
  font-size: 0.85em;
  font-family: monospace;
}

.breakdown-item {
  display: flex;
  justify-content: space-between;
  padding: 5px 0;
  border-bottom: 1px solid var(--md-default-fg-color--lightest);
}

.workload-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 12px;
}

.workload-card {
  background: var(--md-default-bg-color);
  padding: 15px;
  border-radius: 6px;
  cursor: pointer;
  transition: transform 0.2s;
}

.workload-card:hover {
  transform: scale(1.02);
}

.workload-card h4 {
  margin: 0 0 5px 0;
}

.workload-card p {
  font-size: 0.8em;
  color: var(--md-default-fg-color--light);
  margin: 0 0 8px 0;
}

.workload-card span {
  font-family: monospace;
  font-weight: 600;
  color: var(--md-primary-fg-color);
}

.ref-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.85em;
}

.ref-table th, .ref-table td {
  padding: 10px;
  text-align: left;
  border-bottom: 1px solid var(--md-default-fg-color--lightest);
}

.ref-table th {
  background: var(--md-default-bg-color);
}
</style>

<script>
const storageSpecs = {
  'ssd-nvme': { iops: 100000, throughput: 3500, latency: 0.1 },
  'ssd-sata': { iops: 75000, throughput: 550, latency: 0.3 },
  'hdd-sas': { iops: 180, throughput: 180, latency: 4 },
  'hdd-sata': { iops: 80, throughput: 120, latency: 10 },
  'cloud-ssd': { iops: 3000, throughput: 125, latency: 1.5 },
  'cloud-io': { iops: 16000, throughput: 500, latency: 0.8 },
  'custom': { iops: 10000, throughput: 500, latency: 1 }
};

const raidFactors = {
  'none': { iopsRead: 1, iopsWrite: 1, capacity: 1 },
  'raid0': { iopsRead: 1, iopsWrite: 1, capacity: 1 },
  'raid1': { iopsRead: 1, iopsWrite: 0.5, capacity: 0.5 },
  'raid5': { iopsRead: 1, iopsWrite: 0.25, capacity: 0.75 },
  'raid6': { iopsRead: 1, iopsWrite: 0.17, capacity: 0.67 },
  'raid10': { iopsRead: 1, iopsWrite: 0.5, capacity: 0.5 }
};

// Appelé quand l'utilisateur modifie manuellement IOPS ou throughput
function onManualStorageInput() {
  document.getElementById('storageType').value = 'custom';
  calculate();
}

function updateStorageDefaults() {
  const type = document.getElementById('storageType').value;
  // Ne pas écraser les valeurs en mode custom
  if (type === 'custom') {
    calculate();
    return;
  }
  const spec = storageSpecs[type];
  document.getElementById('iopsPerDisk').value = spec.iops;
  document.getElementById('throughputPerDisk').value = spec.throughput;
}

function calculate() {
  const iopsPerDisk = parseInt(document.getElementById('iopsPerDisk').value) || 10000;
  const throughputPerDisk = parseInt(document.getElementById('throughputPerDisk').value) || 500;
  const diskCount = parseInt(document.getElementById('diskCount').value) || 1;
  const raidLevel = document.getElementById('raidLevel').value;
  const readRatio = parseInt(document.getElementById('readRatio').value);
  const writeRatio = 100 - readRatio;

  document.getElementById('readPct').textContent = readRatio + '%';
  document.getElementById('writePct').textContent = writeRatio + '%';

  const raid = raidFactors[raidLevel];
  const type = document.getElementById('storageType').value;
  const latency = storageSpecs[type]?.latency || 1;

  // Raw IOPS (all disks)
  const rawIops = iopsPerDisk * diskCount;

  // Effective IOPS considering RAID and read/write ratio
  const readIops = rawIops * raid.iopsRead * (readRatio / 100);
  const writeIops = rawIops * raid.iopsWrite * (writeRatio / 100);
  const effectiveIops = Math.round(readIops + writeIops);

  // Throughput (RAID 0 and 10 scale, others limited by parity)
  let totalThroughput;
  if (raidLevel === 'raid0' || raidLevel === 'none') {
    totalThroughput = throughputPerDisk * diskCount;
  } else if (raidLevel === 'raid10') {
    totalThroughput = throughputPerDisk * (diskCount / 2);
  } else {
    totalThroughput = throughputPerDisk * (diskCount - (raidLevel === 'raid6' ? 2 : 1));
  }

  // Update display
  document.getElementById('rawIops').textContent = rawIops.toLocaleString();
  document.getElementById('effectiveIops').textContent = effectiveIops.toLocaleString();
  document.getElementById('totalThroughput').textContent = Math.round(totalThroughput).toLocaleString();
  document.getElementById('latency').textContent = latency.toFixed(2);

  // Breakdown
  document.getElementById('breakdown').innerHTML = `
    <div class="breakdown-item">
      <span>IOPS par disque</span>
      <span>${iopsPerDisk.toLocaleString()}</span>
    </div>
    <div class="breakdown-item">
      <span>Nombre de disques</span>
      <span>${diskCount}</span>
    </div>
    <div class="breakdown-item">
      <span>RAID penalty (write)</span>
      <span>×${raid.iopsWrite}</span>
    </div>
    <div class="breakdown-item">
      <span>Read IOPS</span>
      <span>${Math.round(readIops).toLocaleString()}</span>
    </div>
    <div class="breakdown-item">
      <span>Write IOPS</span>
      <span>${Math.round(writeIops).toLocaleString()}</span>
    </div>
    <div class="breakdown-item">
      <span>Capacite utilisable</span>
      <span>${Math.round(raid.capacity * 100)}%</span>
    </div>
  `;
}

function setWorkload(type) {
  const workloads = {
    'oltp': { read: 70, type: 'ssd-nvme' },
    'olap': { read: 95, type: 'ssd-nvme' },
    'vm': { read: 60, type: 'ssd-sata' },
    'web': { read: 90, type: 'ssd-sata' },
    'video': { read: 95, type: 'ssd-nvme' },
    'backup': { read: 10, type: 'hdd-sata' }
  };

  const w = workloads[type];
  if (w) {
    document.getElementById('readRatio').value = w.read;
    document.getElementById('storageType').value = w.type;
    updateStorageDefaults();
    calculate();
  }
}

// Initialize
calculate();
</script>

---

## Formules

```
IOPS effectifs = (Read IOPS × Read%) + (Write IOPS × Write% × RAID penalty)
Latence = 1000 / IOPS (approximation simplifiee)
Queue Depth optimal = IOPS × Latence(s)
```

---

!!! tip "Conseils"
    - Pour les bases de donnees OLTP, priorisez les IOPS
    - Pour l'analytics/streaming, priorisez le throughput
    - NVMe > SATA SSD > SAS HDD > SATA HDD
