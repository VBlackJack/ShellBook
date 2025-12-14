---
tags:
  - tools
  - network
  - netplan
  - ubuntu
---

# Netplan Config Generator

Generateur de configuration Netplan pour Ubuntu 18.04+.

<div id="netplan-app">
  <div class="netplan-container">
    <div class="netplan-section">
      <h3>Configuration reseau</h3>

      <div class="form-group">
        <label>Nom de l'interface</label>
        <input type="text" id="ifaceName" value="eth0" oninput="generate()">
        <span class="hint">ens160, eth0, enp0s3, etc.</span>
      </div>

      <div class="form-group">
        <label>Type de configuration</label>
        <select id="configType" onchange="generate()">
          <option value="dhcp" selected>DHCP</option>
          <option value="static">IP statique</option>
          <option value="disabled">Desactive</option>
        </select>
      </div>

      <div id="staticOptions" style="display:none">
        <div class="form-group">
          <label>Adresses IP (CIDR)</label>
          <textarea id="addresses" rows="2" oninput="generate()">192.168.1.100/24</textarea>
          <span class="hint">Une adresse par ligne, format CIDR</span>
        </div>

        <div class="form-group">
          <label>Gateway</label>
          <input type="text" id="gateway" value="192.168.1.1" oninput="generate()">
        </div>

        <div class="form-group">
          <label>Serveurs DNS</label>
          <input type="text" id="nameservers" value="8.8.8.8, 8.8.4.4" oninput="generate()">
          <span class="hint">Separes par des virgules</span>
        </div>

        <div class="form-group">
          <label>Domaines de recherche (optionnel)</label>
          <input type="text" id="searchDomains" value="" placeholder="example.com, internal.local" oninput="generate()">
        </div>
      </div>

      <div class="form-group">
        <label>Renderer</label>
        <select id="renderer" onchange="generate()">
          <option value="networkd" selected>networkd (systemd)</option>
          <option value="NetworkManager">NetworkManager</option>
        </select>
      </div>

      <h4>Options avancees</h4>

      <div class="form-group">
        <label>
          <input type="checkbox" id="setMtu" onchange="generate()">
          Definir MTU
        </label>
      </div>

      <div class="form-group" id="mtuGroup" style="display:none">
        <label>MTU</label>
        <input type="number" id="mtu" value="1500" oninput="generate()">
      </div>

      <div class="form-group">
        <label>
          <input type="checkbox" id="setMac" onchange="generate()">
          Definir MAC address
        </label>
      </div>

      <div class="form-group" id="macGroup" style="display:none">
        <label>MAC Address</label>
        <input type="text" id="macAddress" value="00:11:22:33:44:55" oninput="generate()">
      </div>

      <div class="form-group">
        <label>
          <input type="checkbox" id="optional" onchange="generate()">
          Interface optionnelle
        </label>
        <span class="hint">N'attend pas cette interface au boot</span>
      </div>

      <h4>Configuration additionnelle</h4>

      <div class="form-group">
        <label>
          <input type="checkbox" id="addBond" onchange="generate()">
          Ajouter interface Bond
        </label>
      </div>

      <div id="bondGroup" style="display:none">
        <div class="form-group">
          <label>Interfaces membres (espaces)</label>
          <input type="text" id="bondMembers" value="eth0 eth1" oninput="generate()">
        </div>
        <div class="form-group">
          <label>Mode bond</label>
          <select id="bondMode" onchange="generate()">
            <option value="balance-rr">balance-rr (0)</option>
            <option value="active-backup" selected>active-backup (1)</option>
            <option value="balance-xor">balance-xor (2)</option>
            <option value="broadcast">broadcast (3)</option>
            <option value="802.3ad">802.3ad (4) - LACP</option>
            <option value="balance-tlb">balance-tlb (5)</option>
            <option value="balance-alb">balance-alb (6)</option>
          </select>
        </div>
      </div>

      <div class="form-group">
        <label>
          <input type="checkbox" id="addVlan" onchange="generate()">
          Ajouter VLAN
        </label>
      </div>

      <div id="vlanGroup" style="display:none">
        <div class="form-group">
          <label>VLAN ID</label>
          <input type="number" id="vlanId" value="100" min="1" max="4094" oninput="generate()">
        </div>
        <div class="form-group">
          <label>Interface parente</label>
          <input type="text" id="vlanParent" value="eth0" oninput="generate()">
        </div>
      </div>

      <div class="form-group">
        <label>
          <input type="checkbox" id="addBridge" onchange="generate()">
          Ajouter Bridge
        </label>
      </div>

      <div id="bridgeGroup" style="display:none">
        <div class="form-group">
          <label>Interfaces membres</label>
          <input type="text" id="bridgeMembers" value="eth0 eth1" oninput="generate()">
        </div>
      </div>
    </div>

    <div class="netplan-section">
      <h3>Configuration generee</h3>
      <pre id="configOutput"># netplan config</pre>
      <button onclick="copyConfig()">Copier</button>

      <div class="install-info">
        <h4>Application</h4>
        <pre id="installCmd"># Commandes</pre>
        <button onclick="copyInstall()">Copier</button>
      </div>
    </div>
  </div>

  <div class="presets-section">
    <h3>Presets courants</h3>
    <div class="presets-grid">
      <div class="preset-card" onclick="loadPreset('dhcp')">
        <h4>DHCP Simple</h4>
        <p>Config automatique</p>
      </div>
      <div class="preset-card" onclick="loadPreset('static')">
        <h4>IP Statique</h4>
        <p>Serveur classique</p>
      </div>
      <div class="preset-card" onclick="loadPreset('dual')">
        <h4>Dual Stack</h4>
        <p>IPv4 + IPv6</p>
      </div>
      <div class="preset-card" onclick="loadPreset('bond')">
        <h4>Bond Active-Backup</h4>
        <p>HA reseau</p>
      </div>
      <div class="preset-card" onclick="loadPreset('bridge')">
        <h4>Bridge KVM</h4>
        <p>Pour VMs</p>
      </div>
      <div class="preset-card" onclick="loadPreset('vlan')">
        <h4>VLAN</h4>
        <p>Interface tagguee</p>
      </div>
    </div>
  </div>
</div>

<style>
.netplan-container {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 20px;
}

@media (max-width: 900px) {
  .netplan-container { grid-template-columns: 1fr; }
}

.netplan-section, .presets-section {
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

.form-group h4 {
  margin: 20px 0 10px 0;
  padding-top: 15px;
  border-top: 1px solid var(--md-default-fg-color--lightest);
}

.form-group select,
.form-group input[type="text"],
.form-group input[type="number"],
.form-group textarea {
  width: 100%;
  padding: 10px;
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  background: var(--md-default-bg-color);
  color: var(--md-default-fg-color);
  font-family: monospace;
}

.form-group input[type="checkbox"] { margin-right: 8px; }

.hint {
  font-size: 0.8em;
  color: var(--md-default-fg-color--light);
  display: block;
  margin-top: 4px;
}

#configOutput, #installCmd {
  background: #1e1e1e;
  color: #d4d4d4;
  padding: 15px;
  border-radius: 4px;
  font-size: 0.85em;
  overflow-x: auto;
  white-space: pre-wrap;
}

#configOutput { min-height: 300px; }

.netplan-section button {
  margin-top: 10px;
  margin-right: 10px;
  padding: 8px 16px;
  background: var(--md-primary-fg-color);
  color: white;
  border: none;
  border-radius: 4px;
  cursor: pointer;
}

.install-info {
  margin-top: 20px;
  padding-top: 20px;
  border-top: 1px solid var(--md-default-fg-color--lightest);
}

.presets-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
  gap: 12px;
}

.preset-card {
  background: var(--md-default-bg-color);
  padding: 15px;
  border-radius: 6px;
  cursor: pointer;
  transition: transform 0.2s;
}

.preset-card:hover { transform: scale(1.02); }
.preset-card h4 { margin: 0 0 5px 0; font-size: 0.95em; }
.preset-card p { margin: 0; font-size: 0.8em; color: var(--md-default-fg-color--light); }
</style>

<script>
function generate() {
  const ifaceName = document.getElementById('ifaceName').value;
  const configType = document.getElementById('configType').value;
  const renderer = document.getElementById('renderer').value;
  const setMtu = document.getElementById('setMtu').checked;
  const mtu = document.getElementById('mtu').value;
  const setMac = document.getElementById('setMac').checked;
  const macAddress = document.getElementById('macAddress').value;
  const optional = document.getElementById('optional').checked;
  const addBond = document.getElementById('addBond').checked;
  const addVlan = document.getElementById('addVlan').checked;
  const addBridge = document.getElementById('addBridge').checked;

  // Visibility
  document.getElementById('staticOptions').style.display =
    configType === 'static' ? 'block' : 'none';
  document.getElementById('mtuGroup').style.display = setMtu ? 'block' : 'none';
  document.getElementById('macGroup').style.display = setMac ? 'block' : 'none';
  document.getElementById('bondGroup').style.display = addBond ? 'block' : 'none';
  document.getElementById('vlanGroup').style.display = addVlan ? 'block' : 'none';
  document.getElementById('bridgeGroup').style.display = addBridge ? 'block' : 'none';

  let config = `# Netplan configuration
# File: /etc/netplan/01-netcfg.yaml

network:
  version: 2
  renderer: ${renderer}
`;

  // Ethernets
  config += `  ethernets:\n`;

  if (!addBond && !addBridge) {
    config += `    ${ifaceName}:\n`;

    if (configType === 'dhcp') {
      config += `      dhcp4: true\n`;
    } else if (configType === 'static') {
      config += `      dhcp4: false\n`;

      const addresses = document.getElementById('addresses').value
        .split('\n').filter(a => a.trim());
      if (addresses.length > 0) {
        config += `      addresses:\n`;
        addresses.forEach(addr => {
          config += `        - ${addr.trim()}\n`;
        });
      }

      const gateway = document.getElementById('gateway').value;
      if (gateway) {
        config += `      routes:\n`;
        config += `        - to: default\n`;
        config += `          via: ${gateway}\n`;
      }

      const nameservers = document.getElementById('nameservers').value;
      const searchDomains = document.getElementById('searchDomains').value;
      if (nameservers || searchDomains) {
        config += `      nameservers:\n`;
        if (nameservers) {
          const servers = nameservers.split(',').map(s => s.trim());
          config += `        addresses: [${servers.join(', ')}]\n`;
        }
        if (searchDomains) {
          const domains = searchDomains.split(',').map(s => s.trim());
          config += `        search: [${domains.join(', ')}]\n`;
        }
      }
    } else if (configType === 'disabled') {
      config += `      dhcp4: false\n`;
      config += `      dhcp6: false\n`;
    }

    if (setMtu) {
      config += `      mtu: ${mtu}\n`;
    }
    if (setMac) {
      config += `      macaddress: ${macAddress}\n`;
    }
    if (optional) {
      config += `      optional: true\n`;
    }
  }

  // Bond members
  if (addBond) {
    const bondMembers = document.getElementById('bondMembers').value.split(/\s+/);
    bondMembers.forEach(member => {
      config += `    ${member}:\n`;
      config += `      dhcp4: false\n`;
      config += `      dhcp6: false\n`;
    });

    config += `  bonds:\n`;
    config += `    bond0:\n`;
    config += `      interfaces: [${bondMembers.join(', ')}]\n`;
    config += `      parameters:\n`;
    config += `        mode: ${document.getElementById('bondMode').value}\n`;
    config += `        mii-monitor-interval: 100\n`;
    config += `      dhcp4: true\n`;
  }

  // VLAN
  if (addVlan) {
    const vlanId = document.getElementById('vlanId').value;
    const vlanParent = document.getElementById('vlanParent').value;

    config += `  vlans:\n`;
    config += `    vlan${vlanId}:\n`;
    config += `      id: ${vlanId}\n`;
    config += `      link: ${vlanParent}\n`;
    config += `      dhcp4: true\n`;
  }

  // Bridge
  if (addBridge) {
    const bridgeMembers = document.getElementById('bridgeMembers').value.split(/\s+/);
    bridgeMembers.forEach(member => {
      config += `    ${member}:\n`;
      config += `      dhcp4: false\n`;
    });

    config += `  bridges:\n`;
    config += `    br0:\n`;
    config += `      interfaces: [${bridgeMembers.join(', ')}]\n`;
    config += `      dhcp4: true\n`;
    config += `      parameters:\n`;
    config += `        stp: false\n`;
    config += `        forward-delay: 0\n`;
  }

  document.getElementById('configOutput').textContent = config;

  // Install commands
  const installCmd = `# Sauvegarder la configuration actuelle
sudo cp /etc/netplan/*.yaml /etc/netplan/backup/

# Ecrire la nouvelle configuration
sudo tee /etc/netplan/01-netcfg.yaml << 'EOF'
${config}
EOF

# Valider la syntaxe
sudo netplan generate

# Tester (rollback auto apres 120s si pas de confirmation)
sudo netplan try

# Appliquer definitivement
sudo netplan apply

# Debug
networkctl status ${ifaceName}`;

  document.getElementById('installCmd').textContent = installCmd;
}

function loadPreset(name) {
  // Reset checkboxes
  document.getElementById('addBond').checked = false;
  document.getElementById('addVlan').checked = false;
  document.getElementById('addBridge').checked = false;
  document.getElementById('setMtu').checked = false;
  document.getElementById('setMac').checked = false;
  document.getElementById('optional').checked = false;

  switch(name) {
    case 'dhcp':
      document.getElementById('configType').value = 'dhcp';
      break;
    case 'static':
      document.getElementById('configType').value = 'static';
      document.getElementById('addresses').value = '192.168.1.100/24';
      document.getElementById('gateway').value = '192.168.1.1';
      document.getElementById('nameservers').value = '8.8.8.8, 8.8.4.4';
      break;
    case 'dual':
      document.getElementById('configType').value = 'static';
      document.getElementById('addresses').value = '192.168.1.100/24\n2001:db8::100/64';
      break;
    case 'bond':
      document.getElementById('addBond').checked = true;
      document.getElementById('bondMembers').value = 'eth0 eth1';
      document.getElementById('bondMode').value = 'active-backup';
      break;
    case 'bridge':
      document.getElementById('addBridge').checked = true;
      document.getElementById('bridgeMembers').value = 'eth0';
      break;
    case 'vlan':
      document.getElementById('addVlan').checked = true;
      document.getElementById('vlanId').value = '100';
      document.getElementById('vlanParent').value = 'eth0';
      break;
  }
  generate();
}

function copyConfig() {
  const config = document.getElementById('configOutput').textContent;
  navigator.clipboard.writeText(config).then(() => {
    event.target.textContent = 'Copie!';
    setTimeout(() => event.target.textContent = 'Copier', 1500);
  });
}

function copyInstall() {
  const cmd = document.getElementById('installCmd').textContent;
  navigator.clipboard.writeText(cmd).then(() => {
    event.target.textContent = 'Copie!';
    setTimeout(() => event.target.textContent = 'Copier', 1500);
  });
}

generate();
</script>

---

## Commandes utiles

```bash
# Valider la syntaxe
sudo netplan generate

# Tester (rollback auto 120s)
sudo netplan try --timeout 120

# Appliquer
sudo netplan apply

# Debug
sudo netplan --debug apply

# Statut interface
networkctl status
ip addr
```

---

## Voir aussi

- [MTU Calculator](mtu-calculator.md)
- [Subnet Calculator](subnet-calculator.md)
