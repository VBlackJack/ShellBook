---
tags:
  - tools
  - network
  - cidr
  - ip
---

# CIDR Overlap Checker

Detecte les chevauchements entre plusieurs plages CIDR pour eviter les conflits reseau.

<div id="cidr-overlap-app">
  <div class="cidr-container">
    <div class="cidr-input-section">
      <h3>Plages CIDR</h3>
      <div class="cidr-form">
        <div class="form-row">
          <input type="text" id="newCidr" placeholder="Ex: 10.0.0.0/16, 192.168.1.0/24">
          <button onclick="addCidr()" class="btn-add">➕ Ajouter</button>
        </div>
        <div class="form-hint">Entrez un bloc CIDR ou plusieurs separes par des virgules</div>
      </div>

      <div class="presets">
        <button onclick="loadPreset('aws')">☁️ AWS VPC</button>
        <button onclick="loadPreset('azure')">🔷 Azure VNet</button>
        <button onclick="loadPreset('private')">🏠 RFC1918</button>
        <button onclick="loadPreset('docker')">🐳 Docker</button>
        <button onclick="loadPreset('k8s')">☸️ Kubernetes</button>
      </div>

      <h4>Blocs ajoutes (<span id="cidrCount">0</span>)</h4>
      <div id="cidrList" class="cidr-list"></div>

      <div class="actions">
        <button onclick="checkOverlaps()" class="btn-check">🔍 Verifier chevauchements</button>
        <button onclick="clearAll()" class="btn-clear">🗑️ Tout effacer</button>
      </div>
    </div>

    <div class="cidr-results-section">
      <h3>Resultats</h3>
      <div id="overlapResults" class="results">
        <p class="no-results">Ajoutez des blocs CIDR et cliquez sur "Verifier"</p>
      </div>

      <div id="networkDetails" class="network-details"></div>
    </div>
  </div>
</div>

<style>
.cidr-container {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 20px;
}

@media (max-width: 800px) {
  .cidr-container {
    grid-template-columns: 1fr;
  }
}

.cidr-input-section, .cidr-results-section {
  background: var(--md-code-bg-color);
  padding: 20px;
  border-radius: 8px;
}

.cidr-form .form-row {
  display: flex;
  gap: 10px;
}

.cidr-form input {
  flex: 1;
  padding: 10px 15px;
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  background: var(--md-default-bg-color);
  color: var(--md-default-fg-color);
  font-family: monospace;
  font-size: 1em;
}

.btn-add {
  padding: 10px 20px;
  background: var(--md-primary-fg-color);
  color: white;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  white-space: nowrap;
}

.form-hint {
  font-size: 0.8em;
  color: var(--md-default-fg-color--light);
  margin-top: 5px;
}

.presets {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin: 15px 0;
}

.presets button {
  padding: 6px 12px;
  background: var(--md-default-bg-color);
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  cursor: pointer;
  font-size: 0.85em;
}

.presets button:hover {
  border-color: var(--md-primary-fg-color);
}

.cidr-list {
  max-height: 250px;
  overflow-y: auto;
  overflow-x: hidden;
  margin-bottom: 15px;
}

.cidr-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 10px 12px;
  margin-bottom: 6px;
  background: var(--md-default-bg-color);
  border-radius: 4px;
  border-left: 3px solid var(--md-primary-fg-color);
}

.cidr-item.overlap {
  border-left-color: #e74c3c;
  background: rgba(231, 76, 60, 0.1);
}

.cidr-item-info {
  font-family: monospace;
  font-weight: 500;
}

.cidr-item-range {
  font-size: 0.8em;
  color: var(--md-default-fg-color--light);
}

.cidr-item button {
  padding: 4px 8px;
  background: transparent;
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  cursor: pointer;
}

.actions {
  display: flex;
  gap: 10px;
}

.btn-check {
  flex: 1;
  padding: 12px;
  background: var(--md-primary-fg-color);
  color: white;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  font-weight: 500;
}

.btn-clear {
  padding: 12px 20px;
  background: var(--md-default-fg-color--lightest);
  border: none;
  border-radius: 4px;
  cursor: pointer;
}

.results {
  min-height: 150px;
}

.no-results {
  color: var(--md-default-fg-color--light);
  font-style: italic;
}

.result-ok {
  padding: 15px;
  background: rgba(39, 174, 96, 0.1);
  border: 1px solid #27ae60;
  border-radius: 6px;
  color: #27ae60;
}

.result-ok h4 {
  margin: 0 0 5px 0;
  color: #27ae60;
}

.result-warning {
  padding: 15px;
  background: rgba(231, 76, 60, 0.1);
  border: 1px solid #e74c3c;
  border-radius: 6px;
  margin-bottom: 10px;
}

.result-warning h4 {
  margin: 0 0 10px 0;
  color: #e74c3c;
}

.overlap-item {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 8px;
  background: var(--md-default-bg-color);
  border-radius: 4px;
  margin-bottom: 6px;
  font-family: monospace;
  font-size: 0.9em;
}

.overlap-icon {
  color: #e74c3c;
}

.network-details {
  margin-top: 20px;
}

.network-details h4 {
  margin-bottom: 10px;
}

.detail-item {
  padding: 12px;
  background: var(--md-default-bg-color);
  border-radius: 4px;
  margin-bottom: 8px;
}

.detail-header {
  font-family: monospace;
  font-weight: 600;
  margin-bottom: 8px;
  color: var(--md-primary-fg-color);
}

.detail-grid {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 5px;
  font-size: 0.85em;
}

.detail-label {
  color: var(--md-default-fg-color--light);
}

.detail-value {
  font-family: monospace;
}
</style>

<script>
let cidrs = [];

function parseCIDR(cidr) {
  const parts = cidr.trim().split('/');
  if (parts.length !== 2) return null;

  const ip = parts[0];
  const prefix = parseInt(parts[1]);

  if (isNaN(prefix) || prefix < 0 || prefix > 32) return null;

  const ipParts = ip.split('.');
  if (ipParts.length !== 4) return null;

  let ipNum = 0;
  for (let i = 0; i < 4; i++) {
    const octet = parseInt(ipParts[i]);
    if (isNaN(octet) || octet < 0 || octet > 255) return null;
    ipNum = (ipNum << 8) + octet;
  }

  const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
  const network = (ipNum & mask) >>> 0;
  const broadcast = (network | (~mask >>> 0)) >>> 0;
  const hostCount = prefix === 32 ? 1 : Math.pow(2, 32 - prefix) - 2;

  return {
    cidr: cidr.trim(),
    ip,
    prefix,
    network,
    broadcast,
    mask,
    hostCount,
    networkStr: numToIP(network),
    broadcastStr: numToIP(broadcast),
    firstHost: numToIP(network + 1),
    lastHost: numToIP(broadcast - 1)
  };
}

function numToIP(num) {
  return [
    (num >>> 24) & 255,
    (num >>> 16) & 255,
    (num >>> 8) & 255,
    num & 255
  ].join('.');
}

function checkOverlap(cidr1, cidr2) {
  // Two CIDRs overlap if either contains the other's network or broadcast
  return (cidr1.network <= cidr2.broadcast && cidr1.broadcast >= cidr2.network);
}

function addCidr() {
  const input = document.getElementById('newCidr').value;
  const blocks = input.split(',').map(s => s.trim()).filter(s => s);

  let added = 0;
  blocks.forEach(block => {
    const parsed = parseCIDR(block);
    if (parsed) {
      // Check for duplicates
      if (!cidrs.some(c => c.cidr === parsed.cidr)) {
        cidrs.push(parsed);
        added++;
      }
    }
  });

  if (added > 0) {
    document.getElementById('newCidr').value = '';
    updateUI();
  } else if (blocks.length > 0) {
    alert('Format CIDR invalide. Utilisez le format: 10.0.0.0/16');
  }
}

function removeCidr(index) {
  cidrs.splice(index, 1);
  updateUI();
}

function clearAll() {
  cidrs = [];
  updateUI();
  document.getElementById('overlapResults').innerHTML = '<p class="no-results">Ajoutez des blocs CIDR et cliquez sur "Verifier"</p>';
  document.getElementById('networkDetails').innerHTML = '';
}

function loadPreset(type) {
  const presets = {
    'aws': ['10.0.0.0/16', '10.1.0.0/16', '10.2.0.0/16'],
    'azure': ['10.0.0.0/8', '172.16.0.0/12'],
    'private': ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'],
    'docker': ['172.17.0.0/16', '172.18.0.0/16', '172.19.0.0/16'],
    'k8s': ['10.244.0.0/16', '10.96.0.0/12', '10.0.0.0/16']
  };

  if (presets[type]) {
    presets[type].forEach(cidr => {
      const parsed = parseCIDR(cidr);
      if (parsed && !cidrs.some(c => c.cidr === parsed.cidr)) {
        cidrs.push(parsed);
      }
    });
    updateUI();
  }
}

function updateUI() {
  document.getElementById('cidrCount').textContent = cidrs.length;

  const listEl = document.getElementById('cidrList');
  if (cidrs.length === 0) {
    listEl.innerHTML = '<p style="color: var(--md-default-fg-color--light); font-size: 0.9em;">Aucun bloc CIDR ajoute</p>';
  } else {
    listEl.innerHTML = cidrs.map((c, i) => `
      <div class="cidr-item" id="cidr-${i}">
        <div>
          <div class="cidr-item-info">${c.cidr}</div>
          <div class="cidr-item-range">${c.networkStr} - ${c.broadcastStr}</div>
        </div>
        <button onclick="removeCidr(${i})">🗑️</button>
      </div>
    `).join('');
  }
}

function checkOverlaps() {
  if (cidrs.length < 2) {
    document.getElementById('overlapResults').innerHTML = '<p class="no-results">Ajoutez au moins 2 blocs CIDR pour verifier</p>';
    return;
  }

  const overlaps = [];

  // Reset visual state
  cidrs.forEach((_, i) => {
    const el = document.getElementById(`cidr-${i}`);
    if (el) el.classList.remove('overlap');
  });

  // Check all pairs
  for (let i = 0; i < cidrs.length; i++) {
    for (let j = i + 1; j < cidrs.length; j++) {
      if (checkOverlap(cidrs[i], cidrs[j])) {
        overlaps.push({ a: cidrs[i], b: cidrs[j], indexA: i, indexB: j });

        // Mark overlapping items
        const elA = document.getElementById(`cidr-${i}`);
        const elB = document.getElementById(`cidr-${j}`);
        if (elA) elA.classList.add('overlap');
        if (elB) elB.classList.add('overlap');
      }
    }
  }

  const resultsEl = document.getElementById('overlapResults');

  if (overlaps.length === 0) {
    resultsEl.innerHTML = `
      <div class="result-ok">
        <h4>✅ Aucun chevauchement detecte</h4>
        <p>Les ${cidrs.length} blocs CIDR sont tous distincts.</p>
      </div>
    `;
  } else {
    resultsEl.innerHTML = `
      <div class="result-warning">
        <h4>⚠️ ${overlaps.length} chevauchement(s) detecte(s)</h4>
        ${overlaps.map(o => `
          <div class="overlap-item">
            <span class="overlap-icon">⚡</span>
            <span>${o.a.cidr}</span>
            <span>↔</span>
            <span>${o.b.cidr}</span>
          </div>
        `).join('')}
      </div>
    `;
  }

  // Show network details
  showNetworkDetails();
}

function showNetworkDetails() {
  const detailsEl = document.getElementById('networkDetails');

  detailsEl.innerHTML = `
    <h4>Details des reseaux</h4>
    ${cidrs.map(c => `
      <div class="detail-item">
        <div class="detail-header">${c.cidr}</div>
        <div class="detail-grid">
          <span class="detail-label">Reseau:</span>
          <span class="detail-value">${c.networkStr}</span>
          <span class="detail-label">Broadcast:</span>
          <span class="detail-value">${c.broadcastStr}</span>
          <span class="detail-label">Premier host:</span>
          <span class="detail-value">${c.firstHost}</span>
          <span class="detail-label">Dernier host:</span>
          <span class="detail-value">${c.lastHost}</span>
          <span class="detail-label">Hosts disponibles:</span>
          <span class="detail-value">${c.hostCount.toLocaleString()}</span>
          <span class="detail-label">Masque:</span>
          <span class="detail-value">/${c.prefix}</span>
        </div>
      </div>
    `).join('')}
  `;
}

// Handle Enter key
document.getElementById('newCidr').addEventListener('keypress', function(e) {
  if (e.key === 'Enter') addCidr();
});

// Initialize
updateUI();
</script>

---

## Cas d'usage

| Scenario | Description |
|----------|-------------|
| **Migration cloud** | Verifier que les nouveaux VPC ne conflitent pas |
| **VPN site-to-site** | S'assurer que les reseaux distants sont distincts |
| **Multi-cluster K8s** | Eviter les conflits entre Pod CIDRs |
| **Fusion reseau** | Planifier l'integration de deux infrastructures |

---

!!! warning "Plages reservees"
    Attention aux plages speciales RFC1918 (privees), RFC6598 (CGNAT: 100.64.0.0/10), et link-local (169.254.0.0/16).
