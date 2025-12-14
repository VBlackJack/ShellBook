---
tags:
  - tools
  - firewall
  - nftables
  - security
---

# nftables Rules Generator

Generateur de regles nftables, le successeur moderne d'iptables.

<div id="nftables-app">
  <div class="nftables-container">
    <div class="nftables-section">
      <h3>Configuration</h3>

      <div class="config-tabs">
        <button class="tab-btn active" onclick="switchTab('basic')">Basique</button>
        <button class="tab-btn" onclick="switchTab('nat')">NAT</button>
        <button class="tab-btn" onclick="switchTab('sets')">Sets</button>
        <button class="tab-btn" onclick="switchTab('advanced')">Avance</button>
      </div>

      <!-- BASIC TAB -->
      <div id="basic-tab" class="tab-content active">
        <div class="form-group">
          <label>Nom de la table</label>
          <input type="text" id="tableName" value="firewall" oninput="generate()">
        </div>

        <div class="form-group">
          <label>Famille</label>
          <select id="tableFamily" onchange="generate()">
            <option value="inet" selected>inet (IPv4 + IPv6)</option>
            <option value="ip">ip (IPv4 only)</option>
            <option value="ip6">ip6 (IPv6 only)</option>
          </select>
        </div>

        <div class="form-group">
          <label>Politique par defaut (input)</label>
          <select id="inputPolicy" onchange="generate()">
            <option value="drop" selected>drop (securise)</option>
            <option value="accept">accept</option>
          </select>
        </div>

        <div class="form-group">
          <label>Politique par defaut (forward)</label>
          <select id="forwardPolicy" onchange="generate()">
            <option value="drop" selected>drop</option>
            <option value="accept">accept</option>
          </select>
        </div>

        <h4>Services autorises (input)</h4>

        <div class="services-grid">
          <label><input type="checkbox" id="allowSsh" onchange="generate()" checked> SSH (22)</label>
          <label><input type="checkbox" id="allowHttp" onchange="generate()"> HTTP (80)</label>
          <label><input type="checkbox" id="allowHttps" onchange="generate()"> HTTPS (443)</label>
          <label><input type="checkbox" id="allowDns" onchange="generate()"> DNS (53)</label>
          <label><input type="checkbox" id="allowSmtp" onchange="generate()"> SMTP (25)</label>
          <label><input type="checkbox" id="allowSmtps" onchange="generate()"> SMTPS (587)</label>
          <label><input type="checkbox" id="allowImap" onchange="generate()"> IMAP (143,993)</label>
          <label><input type="checkbox" id="allowMysql" onchange="generate()"> MySQL (3306)</label>
          <label><input type="checkbox" id="allowPgsql" onchange="generate()"> PostgreSQL (5432)</label>
          <label><input type="checkbox" id="allowRedis" onchange="generate()"> Redis (6379)</label>
        </div>

        <div class="form-group">
          <label>Ports supplementaires (TCP)</label>
          <input type="text" id="extraPorts" placeholder="8080, 3000, 9000" oninput="generate()">
        </div>

        <div class="form-group">
          <label>Ports UDP</label>
          <input type="text" id="udpPorts" placeholder="51820" oninput="generate()">
          <span class="hint">Ex: 51820 pour WireGuard</span>
        </div>

        <h4>Options</h4>

        <div class="form-group">
          <label>
            <input type="checkbox" id="allowEstablished" onchange="generate()" checked>
            Autoriser connexions etablies
          </label>
        </div>

        <div class="form-group">
          <label>
            <input type="checkbox" id="allowIcmp" onchange="generate()" checked>
            Autoriser ICMP (ping)
          </label>
        </div>

        <div class="form-group">
          <label>
            <input type="checkbox" id="allowLoopback" onchange="generate()" checked>
            Autoriser loopback
          </label>
        </div>

        <div class="form-group">
          <label>
            <input type="checkbox" id="logDropped" onchange="generate()">
            Logger les paquets droppes
          </label>
        </div>

        <div class="form-group">
          <label>
            <input type="checkbox" id="rateLimitSsh" onchange="generate()" checked>
            Rate limit SSH (anti brute-force)
          </label>
        </div>
      </div>

      <!-- NAT TAB -->
      <div id="nat-tab" class="tab-content">
        <div class="form-group">
          <label>
            <input type="checkbox" id="enableNat" onchange="generate()">
            Activer NAT/Masquerade
          </label>
        </div>

        <div id="natOptions" style="display:none">
          <div class="form-group">
            <label>Interface sortante</label>
            <input type="text" id="natOutIface" value="eth0" oninput="generate()">
          </div>

          <div class="form-group">
            <label>Reseau source a NATer</label>
            <input type="text" id="natSource" value="192.168.1.0/24" oninput="generate()">
          </div>
        </div>

        <h4>Port Forwarding (DNAT)</h4>

        <div class="form-group">
          <label>
            <input type="checkbox" id="enableDnat" onchange="generate()">
            Activer port forwarding
          </label>
        </div>

        <div id="dnatOptions" style="display:none">
          <div class="form-group">
            <label>Port externe</label>
            <input type="number" id="dnatExtPort" value="8080" oninput="generate()">
          </div>
          <div class="form-group">
            <label>IP interne</label>
            <input type="text" id="dnatIntIp" value="192.168.1.100" oninput="generate()">
          </div>
          <div class="form-group">
            <label>Port interne</label>
            <input type="number" id="dnatIntPort" value="80" oninput="generate()">
          </div>
        </div>
      </div>

      <!-- SETS TAB -->
      <div id="sets-tab" class="tab-content">
        <div class="form-group">
          <label>
            <input type="checkbox" id="useBlacklist" onchange="generate()">
            Creer set blacklist
          </label>
        </div>

        <div class="form-group" id="blacklistGroup" style="display:none">
          <label>IPs a bloquer (une par ligne)</label>
          <textarea id="blacklistIps" rows="4" oninput="generate()">192.168.1.100
10.0.0.50</textarea>
        </div>

        <div class="form-group">
          <label>
            <input type="checkbox" id="useWhitelist" onchange="generate()">
            Creer set whitelist
          </label>
        </div>

        <div class="form-group" id="whitelistGroup" style="display:none">
          <label>IPs autorisees (une par ligne)</label>
          <textarea id="whitelistIps" rows="4" oninput="generate()">192.168.1.0/24
10.0.0.0/8</textarea>
        </div>

        <div class="form-group">
          <label>
            <input type="checkbox" id="usePortSet" onchange="generate()">
            Creer set de ports
          </label>
        </div>

        <div class="form-group" id="portSetGroup" style="display:none">
          <label>Ports (separes par virgules)</label>
          <input type="text" id="portSetPorts" value="22, 80, 443, 8080" oninput="generate()">
        </div>
      </div>

      <!-- ADVANCED TAB -->
      <div id="advanced-tab" class="tab-content">
        <h4>Protection contre les attaques</h4>

        <div class="form-group">
          <label>
            <input type="checkbox" id="synFloodProtect" onchange="generate()" checked>
            Protection SYN flood
          </label>
        </div>

        <div class="form-group">
          <label>
            <input type="checkbox" id="invalidDrop" onchange="generate()" checked>
            Drop paquets invalides
          </label>
        </div>

        <div class="form-group">
          <label>
            <input type="checkbox" id="xmasTreeDrop" onchange="generate()">
            Drop paquets XMAS tree
          </label>
        </div>

        <div class="form-group">
          <label>
            <input type="checkbox" id="nullScanDrop" onchange="generate()">
            Drop null scans
          </label>
        </div>

        <h4>Rate Limiting</h4>

        <div class="form-group">
          <label>Limite connexions/seconde (0 = desactive)</label>
          <input type="number" id="connLimit" value="0" min="0" oninput="generate()">
        </div>

        <div class="form-group">
          <label>Limite ICMP/seconde</label>
          <input type="number" id="icmpLimit" value="10" min="1" oninput="generate()">
        </div>

        <h4>Interfaces</h4>

        <div class="form-group">
          <label>Interface(s) a proteger</label>
          <input type="text" id="protectedIface" placeholder="eth0, eth1" oninput="generate()">
          <span class="hint">Laissez vide pour toutes les interfaces</span>
        </div>
      </div>
    </div>

    <div class="nftables-section">
      <h3>Configuration generee</h3>
      <pre id="configOutput"># nftables.conf</pre>
      <button onclick="copyConfig()">Copier</button>

      <div class="install-info">
        <h4>Installation</h4>
        <pre id="installCmd"># Commandes</pre>
        <button onclick="copyInstall()">Copier</button>
      </div>
    </div>
  </div>

  <div class="presets-section">
    <h3>Presets courants</h3>
    <div class="presets-grid">
      <div class="preset-card" onclick="loadPreset('webserver')">
        <h4>Web Server</h4>
        <p>HTTP/HTTPS + SSH</p>
      </div>
      <div class="preset-card" onclick="loadPreset('database')">
        <h4>Database Server</h4>
        <p>MySQL/PgSQL depuis LAN</p>
      </div>
      <div class="preset-card" onclick="loadPreset('router')">
        <h4>Router/NAT</h4>
        <p>Masquerade + forwarding</p>
      </div>
      <div class="preset-card" onclick="loadPreset('docker')">
        <h4>Docker Host</h4>
        <p>Ports dynamiques</p>
      </div>
      <div class="preset-card" onclick="loadPreset('vpn')">
        <h4>VPN Server</h4>
        <p>WireGuard/OpenVPN</p>
      </div>
      <div class="preset-card" onclick="loadPreset('minimal')">
        <h4>Minimal</h4>
        <p>SSH seulement</p>
      </div>
    </div>
  </div>

  <div class="reference-section">
    <h3>Reference rapide</h3>
    <table class="ref-table">
      <tr><td><code>nft list ruleset</code></td><td>Afficher toutes les regles</td></tr>
      <tr><td><code>nft flush ruleset</code></td><td>Supprimer toutes les regles</td></tr>
      <tr><td><code>nft -f /etc/nftables.conf</code></td><td>Charger config</td></tr>
      <tr><td><code>nft add element inet firewall blacklist { 1.2.3.4 }</code></td><td>Ajouter a un set</td></tr>
      <tr><td><code>nft delete element inet firewall blacklist { 1.2.3.4 }</code></td><td>Supprimer d'un set</td></tr>
    </table>
  </div>
</div>

<style>
.nftables-container {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 20px;
}

@media (max-width: 900px) {
  .nftables-container { grid-template-columns: 1fr; }
}

.nftables-section, .presets-section, .reference-section {
  background: var(--md-code-bg-color);
  padding: 20px;
  border-radius: 8px;
  margin-bottom: 20px;
}

.config-tabs {
  display: flex;
  gap: 5px;
  margin-bottom: 20px;
  flex-wrap: wrap;
}

.tab-btn {
  padding: 8px 16px;
  border: 1px solid var(--md-default-fg-color--lightest);
  background: transparent;
  border-radius: 4px;
  cursor: pointer;
  color: var(--md-default-fg-color);
}

.tab-btn.active {
  background: var(--md-primary-fg-color);
  color: white;
}

.tab-content { display: none; }
.tab-content.active { display: block; }

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

.services-grid {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 8px;
  margin-bottom: 15px;
}

.services-grid label {
  display: flex;
  align-items: center;
  font-size: 0.9em;
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

#configOutput { min-height: 350px; }

.nftables-section button {
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
  grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
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

.ref-table {
  width: 100%;
  font-size: 0.85em;
  border-collapse: collapse;
}

.ref-table td {
  padding: 8px;
  border-bottom: 1px solid var(--md-default-fg-color--lightest);
}

.ref-table code {
  background: var(--md-default-bg-color);
  padding: 2px 6px;
  border-radius: 3px;
}
</style>

<script>
let currentTab = 'basic';

function switchTab(tab) {
  currentTab = tab;
  document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
  event.target.classList.add('active');
  document.getElementById(tab + '-tab').classList.add('active');
}

function generate() {
  // Visibility updates
  document.getElementById('natOptions').style.display =
    document.getElementById('enableNat').checked ? 'block' : 'none';
  document.getElementById('dnatOptions').style.display =
    document.getElementById('enableDnat').checked ? 'block' : 'none';
  document.getElementById('blacklistGroup').style.display =
    document.getElementById('useBlacklist').checked ? 'block' : 'none';
  document.getElementById('whitelistGroup').style.display =
    document.getElementById('useWhitelist').checked ? 'block' : 'none';
  document.getElementById('portSetGroup').style.display =
    document.getElementById('usePortSet').checked ? 'block' : 'none';

  const tableName = document.getElementById('tableName').value;
  const tableFamily = document.getElementById('tableFamily').value;
  const inputPolicy = document.getElementById('inputPolicy').value;
  const forwardPolicy = document.getElementById('forwardPolicy').value;

  // Services
  const allowSsh = document.getElementById('allowSsh').checked;
  const allowHttp = document.getElementById('allowHttp').checked;
  const allowHttps = document.getElementById('allowHttps').checked;
  const allowDns = document.getElementById('allowDns').checked;
  const allowSmtp = document.getElementById('allowSmtp').checked;
  const allowSmtps = document.getElementById('allowSmtps').checked;
  const allowImap = document.getElementById('allowImap').checked;
  const allowMysql = document.getElementById('allowMysql').checked;
  const allowPgsql = document.getElementById('allowPgsql').checked;
  const allowRedis = document.getElementById('allowRedis').checked;
  const extraPorts = document.getElementById('extraPorts').value;
  const udpPorts = document.getElementById('udpPorts').value;

  // Options
  const allowEstablished = document.getElementById('allowEstablished').checked;
  const allowIcmp = document.getElementById('allowIcmp').checked;
  const allowLoopback = document.getElementById('allowLoopback').checked;
  const logDropped = document.getElementById('logDropped').checked;
  const rateLimitSsh = document.getElementById('rateLimitSsh').checked;

  // NAT
  const enableNat = document.getElementById('enableNat').checked;
  const natOutIface = document.getElementById('natOutIface').value;
  const natSource = document.getElementById('natSource').value;
  const enableDnat = document.getElementById('enableDnat').checked;

  // Sets
  const useBlacklist = document.getElementById('useBlacklist').checked;
  const blacklistIps = document.getElementById('blacklistIps').value;
  const useWhitelist = document.getElementById('useWhitelist').checked;
  const whitelistIps = document.getElementById('whitelistIps').value;
  const usePortSet = document.getElementById('usePortSet').checked;
  const portSetPorts = document.getElementById('portSetPorts').value;

  // Advanced
  const synFloodProtect = document.getElementById('synFloodProtect').checked;
  const invalidDrop = document.getElementById('invalidDrop').checked;
  const xmasTreeDrop = document.getElementById('xmasTreeDrop').checked;
  const nullScanDrop = document.getElementById('nullScanDrop').checked;
  const connLimit = parseInt(document.getElementById('connLimit').value) || 0;
  const icmpLimit = document.getElementById('icmpLimit').value;
  const protectedIface = document.getElementById('protectedIface').value;

  let config = `#!/usr/sbin/nft -f
# nftables configuration
# Generated by ShellBook nftables Generator

flush ruleset

table ${tableFamily} ${tableName} {
`;

  // Sets
  if (useBlacklist) {
    const ips = blacklistIps.split('\n').filter(ip => ip.trim()).map(ip => ip.trim());
    config += `    # Blacklist set
    set blacklist {
        type ipv4_addr
        flags interval
        elements = { ${ips.join(', ')} }
    }

`;
  }

  if (useWhitelist) {
    const ips = whitelistIps.split('\n').filter(ip => ip.trim()).map(ip => ip.trim());
    config += `    # Whitelist set
    set whitelist {
        type ipv4_addr
        flags interval
        elements = { ${ips.join(', ')} }
    }

`;
  }

  if (usePortSet) {
    const ports = portSetPorts.split(',').map(p => p.trim()).filter(p => p);
    config += `    # Allowed ports set
    set allowed_ports {
        type inet_service
        elements = { ${ports.join(', ')} }
    }

`;
  }

  // Input chain
  config += `    chain input {
        type filter hook input priority 0; policy ${inputPolicy};

`;

  if (allowLoopback) {
    config += `        # Loopback
        iif lo accept

`;
  }

  if (allowEstablished) {
    config += `        # Established/related connections
        ct state established,related accept

`;
  }

  if (invalidDrop) {
    config += `        # Drop invalid
        ct state invalid drop

`;
  }

  if (useBlacklist) {
    config += `        # Blacklist
        ip saddr @blacklist drop

`;
  }

  if (synFloodProtect) {
    config += `        # SYN flood protection
        tcp flags syn limit rate 100/second burst 150 packets accept

`;
  }

  if (xmasTreeDrop) {
    config += `        # XMAS tree packets
        tcp flags & (fin|syn|rst|psh|ack|urg) == fin|syn|rst|psh|ack|urg drop

`;
  }

  if (nullScanDrop) {
    config += `        # Null scan
        tcp flags & (fin|syn|rst|psh|ack|urg) == 0x0 drop

`;
  }

  if (allowIcmp) {
    config += `        # ICMP
        ip protocol icmp icmp type { echo-request, echo-reply, destination-unreachable } limit rate ${icmpLimit}/second accept
`;
    if (tableFamily === 'inet') {
      config += `        ip6 nexthdr icmpv6 icmpv6 type { echo-request, echo-reply, nd-neighbor-solicit, nd-neighbor-advert } accept
`;
    }
    config += `
`;
  }

  // TCP Services
  let tcpPorts = [];
  if (allowSsh) tcpPorts.push('22');
  if (allowHttp) tcpPorts.push('80');
  if (allowHttps) tcpPorts.push('443');
  if (allowDns) tcpPorts.push('53');
  if (allowSmtp) tcpPorts.push('25');
  if (allowSmtps) tcpPorts.push('587');
  if (allowImap) tcpPorts.push('143', '993');
  if (allowMysql) tcpPorts.push('3306');
  if (allowPgsql) tcpPorts.push('5432');
  if (allowRedis) tcpPorts.push('6379');
  if (extraPorts) {
    extraPorts.split(',').forEach(p => {
      const port = p.trim();
      if (port) tcpPorts.push(port);
    });
  }

  if (rateLimitSsh && allowSsh) {
    config += `        # SSH with rate limit
        tcp dport 22 ct state new limit rate 4/minute burst 20 packets accept

`;
    tcpPorts = tcpPorts.filter(p => p !== '22');
  }

  if (usePortSet) {
    config += `        # Services from port set
        tcp dport @allowed_ports accept

`;
  } else if (tcpPorts.length > 0) {
    config += `        # TCP services
        tcp dport { ${tcpPorts.join(', ')} } accept

`;
  }

  // UDP
  let udpPortsList = [];
  if (allowDns) udpPortsList.push('53');
  if (udpPorts) {
    udpPorts.split(',').forEach(p => {
      const port = p.trim();
      if (port) udpPortsList.push(port);
    });
  }

  if (udpPortsList.length > 0) {
    config += `        # UDP services
        udp dport { ${udpPortsList.join(', ')} } accept

`;
  }

  if (connLimit > 0) {
    config += `        # Connection limit
        ct count over ${connLimit} drop

`;
  }

  if (logDropped) {
    config += `        # Log dropped packets
        log prefix "nftables-dropped: " flags all

`;
  }

  config += `    }

`;

  // Forward chain
  config += `    chain forward {
        type filter hook forward priority 0; policy ${forwardPolicy};

`;

  if (allowEstablished) {
    config += `        ct state established,related accept
`;
  }

  if (enableNat) {
    config += `        ip saddr ${natSource} accept
`;
  }

  config += `    }

`;

  // Output chain
  config += `    chain output {
        type filter hook output priority 0; policy accept;
    }
`;

  // NAT chains
  if (enableNat || enableDnat) {
    config += `
    chain prerouting {
        type nat hook prerouting priority -100;
`;

    if (enableDnat) {
      const extPort = document.getElementById('dnatExtPort').value;
      const intIp = document.getElementById('dnatIntIp').value;
      const intPort = document.getElementById('dnatIntPort').value;
      config += `        tcp dport ${extPort} dnat to ${intIp}:${intPort}
`;
    }

    config += `    }

    chain postrouting {
        type nat hook postrouting priority 100;
`;

    if (enableNat) {
      config += `        oifname "${natOutIface}" ip saddr ${natSource} masquerade
`;
    }

    config += `    }
`;
  }

  config += `}
`;

  document.getElementById('configOutput').textContent = config;

  // Install commands
  const installCmd = `# Sauvegarder la configuration actuelle
sudo nft list ruleset > /etc/nftables.backup

# Appliquer la nouvelle configuration
sudo tee /etc/nftables.conf << 'EOF'
${config}
EOF

# Tester la syntaxe
sudo nft -c -f /etc/nftables.conf

# Appliquer
sudo nft -f /etc/nftables.conf

# Activer au demarrage
sudo systemctl enable nftables

# Verifier
sudo nft list ruleset`;

  document.getElementById('installCmd').textContent = installCmd;
}

function loadPreset(name) {
  // Reset all
  document.querySelectorAll('input[type="checkbox"]').forEach(cb => {
    if (['allowEstablished', 'allowIcmp', 'allowLoopback', 'allowSsh', 'synFloodProtect', 'invalidDrop', 'rateLimitSsh'].includes(cb.id)) {
      cb.checked = true;
    } else {
      cb.checked = false;
    }
  });

  switch(name) {
    case 'webserver':
      document.getElementById('allowHttp').checked = true;
      document.getElementById('allowHttps').checked = true;
      break;
    case 'database':
      document.getElementById('allowMysql').checked = true;
      document.getElementById('allowPgsql').checked = true;
      document.getElementById('useWhitelist').checked = true;
      document.getElementById('whitelistIps').value = '192.168.1.0/24\n10.0.0.0/8';
      break;
    case 'router':
      document.getElementById('enableNat').checked = true;
      document.getElementById('forwardPolicy').value = 'accept';
      break;
    case 'docker':
      document.getElementById('allowHttp').checked = true;
      document.getElementById('allowHttps').checked = true;
      document.getElementById('extraPorts').value = '8080, 3000, 9000';
      document.getElementById('forwardPolicy').value = 'accept';
      break;
    case 'vpn':
      document.getElementById('udpPorts').value = '51820';
      document.getElementById('enableNat').checked = true;
      document.getElementById('forwardPolicy').value = 'accept';
      break;
    case 'minimal':
      // Default is already minimal with SSH
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

## Migration iptables vers nftables

```bash
# Exporter regles iptables
iptables-save > iptables-rules.txt

# Convertir en nftables
iptables-restore-translate -f iptables-rules.txt > nftables.conf

# Ou utiliser iptables-nft (compatibilite)
update-alternatives --set iptables /usr/sbin/iptables-nft
```

---

## Voir aussi

- [Iptables Generator](iptables-generator.md)
- [Fail2Ban Generator](fail2ban-generator.md)
- [Firewall Best Practices](../security/firewall-best-practices.md)
