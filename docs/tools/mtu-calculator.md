---
tags:
  - tools
  - network
  - mtu
  - performance
---

# MTU Calculator

Calculez le MTU optimal pour eviter la fragmentation et optimiser les performances reseau.

<div id="mtu-app">
  <div class="mtu-container">
    <div class="mtu-left">
      <h3>Configuration</h3>

      <div class="mtu-form">
        <div class="form-group">
          <label>Type de connexion</label>
          <select id="connType" onchange="updateMTU()">
            <option value="ethernet">Ethernet standard</option>
            <option value="jumbo">Jumbo frames</option>
            <option value="pppoe">PPPoE (DSL)</option>
            <option value="vpn-ipsec">VPN IPSec</option>
            <option value="vpn-wireguard">VPN WireGuard</option>
            <option value="vpn-openvpn">VPN OpenVPN</option>
            <option value="gre">GRE Tunnel</option>
            <option value="vxlan">VXLAN</option>
            <option value="geneve">Geneve</option>
            <option value="custom">Personnalise</option>
          </select>
        </div>

        <div class="form-group">
          <label>MTU de base (bytes)</label>
          <input type="number" id="baseMtu" value="1500" min="68" max="9216" oninput="onManualInput()">
        </div>

        <div class="form-group">
          <label>Overhead supplementaire (bytes)</label>
          <input type="number" id="overhead" value="0" min="0" max="500" oninput="onManualInput()">
          <span class="hint">Pour encapsulations multiples</span>
        </div>

        <div class="options-section">
          <h4>Options d'encapsulation</h4>
          <label class="checkbox-option">
            <input type="checkbox" id="opt8021q" onchange="calculateMTU()">
            <span>802.1Q VLAN tag (+4 bytes)</span>
          </label>
          <label class="checkbox-option">
            <input type="checkbox" id="optQinQ" onchange="calculateMTU()">
            <span>QinQ double tag (+8 bytes)</span>
          </label>
          <label class="checkbox-option">
            <input type="checkbox" id="optMpls" onchange="calculateMTU()">
            <span>MPLS label (+4 bytes/label)</span>
          </label>
          <div id="mplsLabels" style="display:none; margin-left: 25px;">
            <label>Nombre de labels MPLS:</label>
            <input type="number" id="mplsCount" value="1" min="1" max="7" onchange="calculateMTU()">
          </div>
        </div>
      </div>
    </div>

    <div class="mtu-right">
      <h3>Resultats</h3>

      <div class="result-cards">
        <div class="result-card primary">
          <div class="result-label">MTU recommande</div>
          <div class="result-value" id="recMtu">1500</div>
          <div class="result-unit">bytes</div>
        </div>

        <div class="result-card">
          <div class="result-label">MSS TCP</div>
          <div class="result-value" id="recMss">1460</div>
          <div class="result-unit">bytes</div>
        </div>

        <div class="result-card">
          <div class="result-label">Overhead total</div>
          <div class="result-value" id="totalOverhead">0</div>
          <div class="result-unit">bytes</div>
        </div>

        <div class="result-card">
          <div class="result-label">Efficacite</div>
          <div class="result-value" id="efficiency">97.3</div>
          <div class="result-unit">%</div>
        </div>
      </div>

      <div class="breakdown-section">
        <h4>Decomposition</h4>
        <div id="breakdown" class="breakdown"></div>
      </div>

      <div class="commands-section">
        <h4>Commandes</h4>
        <div class="command-tabs">
          <button class="tab active" onclick="showTab('linux')">Linux</button>
          <button class="tab" onclick="showTab('windows')">Windows</button>
          <button class="tab" onclick="showTab('macos')">macOS</button>
        </div>
        <div id="commands" class="commands-output">
          <pre id="cmd-linux"># Verifier MTU actuel
ip link show eth0

# Definir MTU temporairement
sudo ip link set eth0 mtu 1500

# Test MTU avec ping (ICMP)
ping -M do -s 1472 host.example.com</pre>
          <pre id="cmd-windows" style="display:none;"># Verifier MTU actuel
netsh interface ipv4 show subinterfaces

# Definir MTU
netsh interface ipv4 set subinterface "Ethernet" mtu=1500 store=persistent

# Test MTU avec ping
ping -f -l 1472 host.example.com</pre>
          <pre id="cmd-macos" style="display:none;"># Verifier MTU actuel
ifconfig en0

# Definir MTU
sudo ifconfig en0 mtu 1500

# Test MTU avec ping
ping -D -s 1472 host.example.com</pre>
        </div>
        <button onclick="copyCommands()" class="btn-copy">📋 Copier</button>
      </div>
    </div>
  </div>

  <div class="reference-section">
    <h3>Reference MTU</h3>
    <table class="mtu-table">
      <thead>
        <tr>
          <th>Type</th>
          <th>MTU</th>
          <th>Overhead</th>
          <th>Notes</th>
        </tr>
      </thead>
      <tbody>
        <tr><td>Ethernet</td><td>1500</td><td>-</td><td>Standard IEEE 802.3</td></tr>
        <tr><td>Jumbo</td><td>9000</td><td>-</td><td>Pour datacenter/SAN</td></tr>
        <tr><td>PPPoE</td><td>1492</td><td>8</td><td>DSL/Fibre grand public</td></tr>
        <tr><td>IPSec ESP</td><td>~1400</td><td>50-100</td><td>Varie selon algo</td></tr>
        <tr><td>WireGuard</td><td>1420</td><td>80</td><td>UDP + crypto</td></tr>
        <tr><td>OpenVPN UDP</td><td>1400</td><td>100</td><td>Avec compression</td></tr>
        <tr><td>GRE</td><td>1476</td><td>24</td><td>Tunnel IP-over-IP</td></tr>
        <tr><td>VXLAN</td><td>1450</td><td>50</td><td>Overlay datacenter</td></tr>
        <tr><td>Geneve</td><td>1450</td><td>50+</td><td>Extensible overlay</td></tr>
      </tbody>
    </table>
  </div>
</div>

<style>
.mtu-container {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 20px;
}

@media (max-width: 800px) {
  .mtu-container {
    grid-template-columns: 1fr;
  }
}

.mtu-left, .mtu-right {
  background: var(--md-code-bg-color);
  padding: 20px;
  border-radius: 8px;
}

.mtu-form {
  background: var(--md-default-bg-color);
  padding: 15px;
  border-radius: 6px;
}

.form-group {
  margin-bottom: 15px;
}

.form-group label {
  display: block;
  margin-bottom: 5px;
  font-size: 0.9em;
}

.form-group select,
.form-group input {
  width: 100%;
  padding: 10px;
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  background: var(--md-code-bg-color);
  color: var(--md-default-fg-color);
}

.form-group .hint {
  font-size: 0.8em;
  color: var(--md-default-fg-color--light);
  margin-top: 4px;
  display: block;
}

.options-section {
  margin-top: 20px;
  padding-top: 15px;
  border-top: 1px solid var(--md-default-fg-color--lightest);
}

.options-section h4 {
  margin-bottom: 10px;
  font-size: 0.95em;
}

.checkbox-option {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 8px;
  cursor: pointer;
  font-size: 0.9em;
}

.checkbox-option input {
  width: 16px;
  height: 16px;
}

.result-cards {
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

.breakdown-section, .commands-section {
  margin-top: 20px;
}

.breakdown {
  background: var(--md-default-bg-color);
  padding: 15px;
  border-radius: 6px;
}

.breakdown-item {
  display: flex;
  justify-content: space-between;
  padding: 6px 0;
  font-size: 0.9em;
  border-bottom: 1px solid var(--md-default-fg-color--lightest);
}

.breakdown-item:last-child {
  border-bottom: none;
  font-weight: 600;
}

.command-tabs {
  display: flex;
  gap: 5px;
  margin-bottom: 10px;
}

.tab {
  padding: 6px 12px;
  background: var(--md-default-bg-color);
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  cursor: pointer;
  font-size: 0.85em;
}

.tab.active {
  background: var(--md-primary-fg-color);
  color: white;
  border-color: var(--md-primary-fg-color);
}

.commands-output {
  background: #1e1e1e;
  border-radius: 6px;
  margin-bottom: 10px;
}

.commands-output pre {
  margin: 0;
  padding: 15px;
  color: #d4d4d4;
  font-size: 0.85em;
  overflow-x: auto;
}

.btn-copy {
  padding: 8px 16px;
  background: var(--md-default-bg-color);
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  cursor: pointer;
}

.reference-section {
  margin-top: 20px;
  background: var(--md-code-bg-color);
  padding: 20px;
  border-radius: 8px;
}

.mtu-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.9em;
}

.mtu-table th, .mtu-table td {
  padding: 10px;
  text-align: left;
  border-bottom: 1px solid var(--md-default-fg-color--lightest);
}

.mtu-table th {
  background: var(--md-default-bg-color);
}

.mtu-table td:nth-child(2),
.mtu-table td:nth-child(3) {
  font-family: monospace;
}
</style>

<script>
const mtuPresets = {
  'ethernet': { mtu: 1500, overhead: 0, desc: 'Ethernet standard' },
  'jumbo': { mtu: 9000, overhead: 0, desc: 'Jumbo frames' },
  'pppoe': { mtu: 1492, overhead: 8, desc: 'PPPoE encapsulation' },
  'vpn-ipsec': { mtu: 1400, overhead: 100, desc: 'IPSec ESP + AH' },
  'vpn-wireguard': { mtu: 1420, overhead: 80, desc: 'WireGuard UDP' },
  'vpn-openvpn': { mtu: 1400, overhead: 100, desc: 'OpenVPN UDP' },
  'gre': { mtu: 1476, overhead: 24, desc: 'GRE tunnel' },
  'vxlan': { mtu: 1450, overhead: 50, desc: 'VXLAN overlay' },
  'geneve': { mtu: 1450, overhead: 50, desc: 'Geneve overlay' },
  'custom': { mtu: 1500, overhead: 0, desc: 'Custom' }
};

let currentTab = 'linux';

// Appelé quand l'utilisateur change manuellement MTU ou overhead
function onManualInput() {
  // Basculer en mode custom pour ne pas écraser les valeurs
  document.getElementById('connType').value = 'custom';
  calculateMTU();
}

// Appelé quand le type de connexion change
function updateMTU() {
  const connType = document.getElementById('connType').value;
  const preset = mtuPresets[connType];

  // Appliquer les presets seulement si ce n'est pas custom
  if (connType !== 'custom') {
    document.getElementById('baseMtu').value = preset.mtu + preset.overhead;
    document.getElementById('overhead').value = preset.overhead;
  }

  calculateMTU();
}

// Calcul des valeurs MTU
function calculateMTU() {
  let baseMtu = parseInt(document.getElementById('baseMtu').value) || 1500;
  let overhead = parseInt(document.getElementById('overhead').value) || 0;

  // Additional encapsulation
  let addOverhead = 0;
  const breakdown = [];

  breakdown.push({ name: 'MTU de base', value: baseMtu });

  if (document.getElementById('opt8021q').checked) {
    addOverhead += 4;
    breakdown.push({ name: '802.1Q VLAN tag', value: -4 });
  }

  if (document.getElementById('optQinQ').checked) {
    addOverhead += 8;
    breakdown.push({ name: 'QinQ double tag', value: -8 });
  }

  if (document.getElementById('optMpls').checked) {
    document.getElementById('mplsLabels').style.display = 'block';
    const labels = parseInt(document.getElementById('mplsCount').value) || 1;
    addOverhead += labels * 4;
    breakdown.push({ name: `MPLS (${labels} labels)`, value: -(labels * 4) });
  } else {
    document.getElementById('mplsLabels').style.display = 'none';
  }

  if (overhead > 0) {
    breakdown.push({ name: 'Overhead initial', value: -overhead });
  }

  const totalOverhead = overhead + addOverhead;
  const recMtu = baseMtu - addOverhead;
  const mss = recMtu - 40; // IP header (20) + TCP header (20)
  const efficiency = ((mss / recMtu) * 100).toFixed(1);

  breakdown.push({ name: 'MTU final', value: recMtu, final: true });

  // Update display
  document.getElementById('recMtu').textContent = recMtu;
  document.getElementById('recMss').textContent = mss;
  document.getElementById('totalOverhead').textContent = totalOverhead;
  document.getElementById('efficiency').textContent = efficiency;

  // Breakdown
  document.getElementById('breakdown').innerHTML = breakdown.map(b => `
    <div class="breakdown-item" ${b.final ? 'style="font-weight:600"' : ''}>
      <span>${b.name}</span>
      <span>${b.value > 0 ? b.value : b.value} bytes</span>
    </div>
  `).join('');

  // Update commands
  updateCommands(recMtu, mss);
}

function updateCommands(mtu, mss) {
  const pingSize = mtu - 28; // MTU - IP header (20) - ICMP header (8)

  document.getElementById('cmd-linux').textContent = `# Verifier MTU actuel
ip link show eth0

# Definir MTU temporairement
sudo ip link set eth0 mtu ${mtu}

# Test MTU avec ping (ICMP)
ping -M do -s ${pingSize} host.example.com

# Voir la route et MTU
ip route get 8.8.8.8`;

  document.getElementById('cmd-windows').textContent = `# Verifier MTU actuel
netsh interface ipv4 show subinterfaces

# Definir MTU
netsh interface ipv4 set subinterface "Ethernet" mtu=${mtu} store=persistent

# Test MTU avec ping (Don't Fragment)
ping -f -l ${pingSize} host.example.com`;

  document.getElementById('cmd-macos').textContent = `# Verifier MTU actuel
ifconfig en0

# Definir MTU
sudo ifconfig en0 mtu ${mtu}

# Test MTU avec ping (Don't Fragment)
ping -D -s ${pingSize} host.example.com

# Route MTU Discovery
route get host.example.com`;
}

function showTab(tab) {
  currentTab = tab;
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  event.target.classList.add('active');

  document.querySelectorAll('.commands-output pre').forEach(p => p.style.display = 'none');
  document.getElementById(`cmd-${tab}`).style.display = 'block';
}

function copyCommands() {
  const cmd = document.getElementById(`cmd-${currentTab}`).textContent;
  navigator.clipboard.writeText(cmd).then(() => {
    const btn = event.target;
    const orig = btn.textContent;
    btn.textContent = '✓ Copie!';
    setTimeout(() => btn.textContent = orig, 1500);
  });
}

// Initialize
updateMTU();
</script>

---

## Formule MSS

```
MSS = MTU - IP Header (20 bytes) - TCP Header (20 bytes)
MSS = MTU - 40 bytes

Exemple: MTU 1500 → MSS 1460
```

---

!!! tip "Path MTU Discovery"
    Activez PMTUD pour detecter automatiquement le MTU optimal sur le chemin reseau. Assurez-vous que les messages ICMP "Fragmentation Needed" ne sont pas bloques.
