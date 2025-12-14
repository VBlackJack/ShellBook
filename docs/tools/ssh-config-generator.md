---
tags:
  - tools
  - ssh
  - generator
  - network
---

# SSH Config Generator

Generateur de fichier `~/.ssh/config` pour simplifier vos connexions SSH.

<div id="ssh-config-app">
  <div class="ssh-container">
    <div class="ssh-left">
      <h3>Hosts SSH</h3>

      <div class="host-form">
        <div class="form-row">
          <label>Alias (Host)</label>
          <input type="text" id="hostAlias" placeholder="mon-serveur">
        </div>

        <div class="form-row">
          <label>HostName (IP/DNS)</label>
          <input type="text" id="hostName" placeholder="192.168.1.100 ou server.example.com">
        </div>

        <div class="form-row">
          <label>User</label>
          <input type="text" id="hostUser" placeholder="root">
        </div>

        <div class="form-row">
          <label>Port</label>
          <input type="number" id="hostPort" value="22" min="1" max="65535">
        </div>

        <div class="form-row">
          <label>IdentityFile (cle privee)</label>
          <input type="text" id="hostKey" placeholder="~/.ssh/id_rsa">
        </div>

        <details class="advanced-options">
          <summary>Options avancees</summary>

          <div class="form-row">
            <label>ProxyJump (bastion)</label>
            <input type="text" id="proxyJump" placeholder="bastion-host">
          </div>

          <div class="form-row">
            <label>LocalForward</label>
            <input type="text" id="localForward" placeholder="8080:localhost:80">
          </div>

          <div class="form-row">
            <label>RemoteForward</label>
            <input type="text" id="remoteForward" placeholder="9090:localhost:3000">
          </div>

          <div class="form-row">
            <label>DynamicForward (SOCKS)</label>
            <input type="text" id="dynamicForward" placeholder="1080">
          </div>

          <div class="form-row checkbox-row">
            <label><input type="checkbox" id="forwardAgent"> ForwardAgent</label>
          </div>

          <div class="form-row checkbox-row">
            <label><input type="checkbox" id="forwardX11"> ForwardX11</label>
          </div>

          <div class="form-row">
            <label>ServerAliveInterval (sec)</label>
            <input type="number" id="serverAlive" placeholder="60">
          </div>

          <div class="form-row">
            <label>ServerAliveCountMax</label>
            <input type="number" id="serverAliveCount" placeholder="3">
          </div>

          <div class="form-row">
            <label>Compression</label>
            <select id="compression">
              <option value="">Default</option>
              <option value="yes">Yes</option>
              <option value="no">No</option>
            </select>
          </div>

          <div class="form-row">
            <label>StrictHostKeyChecking</label>
            <select id="strictHost">
              <option value="">Default</option>
              <option value="yes">Yes</option>
              <option value="no">No</option>
              <option value="ask">Ask</option>
              <option value="accept-new">Accept-new</option>
            </select>
          </div>

          <div class="form-row">
            <label>AddKeysToAgent</label>
            <select id="addKeysAgent">
              <option value="">Default</option>
              <option value="yes">Yes</option>
              <option value="no">No</option>
              <option value="confirm">Confirm</option>
            </select>
          </div>
        </details>

        <div class="form-actions">
          <button onclick="addHost()" class="btn-add">➕ Ajouter Host</button>
          <button onclick="clearForm()" class="btn-clear">🔄 Reset</button>
        </div>
      </div>

      <h4>Presets</h4>
      <div class="presets">
        <button onclick="loadPreset('bastion')">🏰 Bastion Jump</button>
        <button onclick="loadPreset('tunnel')">🚇 Local Tunnel</button>
        <button onclick="loadPreset('github')">🐙 GitHub</button>
        <button onclick="loadPreset('gitlab')">🦊 GitLab</button>
        <button onclick="loadPreset('aws')">☁️ AWS EC2</button>
      </div>

      <h4>Hosts configures (<span id="hostCount">0</span>)</h4>
      <div id="hostList" class="host-list"></div>
    </div>

    <div class="ssh-right">
      <div class="output-header">
        <h3>~/.ssh/config</h3>
        <div class="output-actions">
          <button onclick="copyConfig()">📋 Copier</button>
          <button onclick="downloadConfig()">💾 Telecharger</button>
        </div>
      </div>
      <pre id="configOutput" class="config-output"># Ajoutez des hosts pour generer la configuration</pre>

      <div class="usage-section">
        <h4>Utilisation</h4>
        <div class="usage-example">
          <code>ssh mon-serveur</code>
          <span class="usage-desc">Connexion directe via alias</span>
        </div>
        <div class="usage-example">
          <code>scp fichier.txt mon-serveur:/path/</code>
          <span class="usage-desc">Copie de fichier</span>
        </div>
        <div class="usage-example">
          <code>rsync -avz ./local/ mon-serveur:/remote/</code>
          <span class="usage-desc">Synchronisation</span>
        </div>
      </div>
    </div>
  </div>
</div>

<style>
.ssh-container {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 20px;
}

@media (max-width: 900px) {
  .ssh-container {
    grid-template-columns: 1fr;
  }
}

.ssh-left, .ssh-right {
  background: var(--md-code-bg-color);
  padding: 20px;
  border-radius: 8px;
}

.host-form {
  background: var(--md-default-bg-color);
  padding: 15px;
  border-radius: 6px;
  margin-bottom: 20px;
}

.form-row {
  margin-bottom: 12px;
}

.form-row label {
  display: block;
  font-size: 0.85em;
  margin-bottom: 4px;
  color: var(--md-default-fg-color--light);
}

.form-row input[type="text"],
.form-row input[type="number"],
.form-row select {
  width: 100%;
  padding: 8px 12px;
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  background: var(--md-code-bg-color);
  color: var(--md-default-fg-color);
  font-family: monospace;
}

.checkbox-row label {
  display: flex;
  align-items: center;
  gap: 8px;
  cursor: pointer;
}

.checkbox-row input[type="checkbox"] {
  width: 16px;
  height: 16px;
}

.advanced-options {
  margin: 15px 0;
  padding: 10px;
  background: var(--md-code-bg-color);
  border-radius: 4px;
}

.advanced-options summary {
  cursor: pointer;
  font-weight: 500;
  color: var(--md-primary-fg-color);
}

.advanced-options[open] summary {
  margin-bottom: 15px;
}

.form-actions {
  display: flex;
  gap: 10px;
  margin-top: 15px;
}

.btn-add {
  flex: 1;
  padding: 10px;
  background: var(--md-primary-fg-color);
  color: white;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  font-weight: 500;
}

.btn-add:hover {
  opacity: 0.9;
}

.btn-clear {
  padding: 10px 15px;
  background: var(--md-default-fg-color--lightest);
  border: none;
  border-radius: 4px;
  cursor: pointer;
}

.presets {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-bottom: 20px;
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

.host-list {
  max-height: 300px;
  overflow-y: auto;
}

.host-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 10px;
  margin-bottom: 8px;
  background: var(--md-default-bg-color);
  border-radius: 4px;
  border-left: 3px solid var(--md-primary-fg-color);
}

.host-item-info {
  flex: 1;
}

.host-item-alias {
  font-weight: 600;
  font-family: monospace;
}

.host-item-details {
  font-size: 0.8em;
  color: var(--md-default-fg-color--light);
}

.host-item-actions button {
  padding: 4px 8px;
  margin-left: 5px;
  background: transparent;
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  cursor: pointer;
  font-size: 0.8em;
}

.host-item-actions button:hover {
  background: var(--md-default-fg-color--lightest);
}

.output-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 15px;
}

.output-header h3 {
  margin: 0;
}

.output-actions {
  display: flex;
  gap: 8px;
}

.output-actions button {
  padding: 6px 12px;
  background: var(--md-default-bg-color);
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  cursor: pointer;
  font-size: 0.85em;
}

.output-actions button:hover {
  border-color: var(--md-primary-fg-color);
}

.config-output {
  background: #1e1e1e;
  color: #d4d4d4;
  padding: 15px;
  border-radius: 6px;
  font-size: 0.85em;
  overflow-x: auto;
  white-space: pre;
  min-height: 200px;
  max-height: 400px;
  overflow-y: auto;
}

.usage-section {
  margin-top: 20px;
  padding-top: 20px;
  border-top: 1px solid var(--md-default-fg-color--lightest);
}

.usage-section h4 {
  margin-bottom: 10px;
}

.usage-example {
  display: flex;
  align-items: center;
  gap: 15px;
  margin-bottom: 8px;
}

.usage-example code {
  background: var(--md-default-bg-color);
  padding: 4px 10px;
  border-radius: 4px;
  font-size: 0.85em;
  min-width: 280px;
}

.usage-desc {
  font-size: 0.85em;
  color: var(--md-default-fg-color--light);
}
</style>

<script>
let hosts = [];

function addHost() {
  const alias = document.getElementById('hostAlias').value.trim();
  const hostname = document.getElementById('hostName').value.trim();

  if (!alias || !hostname) {
    alert('Alias et HostName sont requis');
    return;
  }

  const host = {
    id: Date.now(),
    alias,
    hostname,
    user: document.getElementById('hostUser').value.trim(),
    port: document.getElementById('hostPort').value,
    identityFile: document.getElementById('hostKey').value.trim(),
    proxyJump: document.getElementById('proxyJump').value.trim(),
    localForward: document.getElementById('localForward').value.trim(),
    remoteForward: document.getElementById('remoteForward').value.trim(),
    dynamicForward: document.getElementById('dynamicForward').value.trim(),
    forwardAgent: document.getElementById('forwardAgent').checked,
    forwardX11: document.getElementById('forwardX11').checked,
    serverAliveInterval: document.getElementById('serverAlive').value,
    serverAliveCountMax: document.getElementById('serverAliveCount').value,
    compression: document.getElementById('compression').value,
    strictHostKeyChecking: document.getElementById('strictHost').value,
    addKeysToAgent: document.getElementById('addKeysAgent').value
  };

  hosts.push(host);
  clearForm();
  updateUI();
}

function removeHost(id) {
  hosts = hosts.filter(h => h.id !== id);
  updateUI();
}

function clearForm() {
  document.getElementById('hostAlias').value = '';
  document.getElementById('hostName').value = '';
  document.getElementById('hostUser').value = '';
  document.getElementById('hostPort').value = '22';
  document.getElementById('hostKey').value = '';
  document.getElementById('proxyJump').value = '';
  document.getElementById('localForward').value = '';
  document.getElementById('remoteForward').value = '';
  document.getElementById('dynamicForward').value = '';
  document.getElementById('forwardAgent').checked = false;
  document.getElementById('forwardX11').checked = false;
  document.getElementById('serverAlive').value = '';
  document.getElementById('serverAliveCount').value = '';
  document.getElementById('compression').value = '';
  document.getElementById('strictHost').value = '';
  document.getElementById('addKeysAgent').value = '';
}

function loadPreset(type) {
  clearForm();

  switch(type) {
    case 'bastion':
      document.getElementById('hostAlias').value = 'prod-server';
      document.getElementById('hostName').value = '10.0.1.100';
      document.getElementById('hostUser').value = 'admin';
      document.getElementById('hostKey').value = '~/.ssh/id_ed25519';
      document.getElementById('proxyJump').value = 'bastion';
      // Add bastion host first
      hosts.push({
        id: Date.now(),
        alias: 'bastion',
        hostname: 'bastion.example.com',
        user: 'admin',
        port: '22',
        identityFile: '~/.ssh/id_ed25519'
      });
      updateUI();
      break;

    case 'tunnel':
      document.getElementById('hostAlias').value = 'db-tunnel';
      document.getElementById('hostName').value = 'db-server.internal';
      document.getElementById('hostUser').value = 'tunnel';
      document.getElementById('hostKey').value = '~/.ssh/tunnel_key';
      document.getElementById('localForward').value = '3306:localhost:3306';
      document.getElementById('serverAlive').value = '60';
      document.getElementById('serverAliveCount').value = '3';
      break;

    case 'github':
      document.getElementById('hostAlias').value = 'github.com';
      document.getElementById('hostName').value = 'github.com';
      document.getElementById('hostUser').value = 'git';
      document.getElementById('hostKey').value = '~/.ssh/github_key';
      document.getElementById('addKeysAgent').value = 'yes';
      break;

    case 'gitlab':
      document.getElementById('hostAlias').value = 'gitlab.com';
      document.getElementById('hostName').value = 'gitlab.com';
      document.getElementById('hostUser').value = 'git';
      document.getElementById('hostKey').value = '~/.ssh/gitlab_key';
      document.getElementById('addKeysAgent').value = 'yes';
      break;

    case 'aws':
      document.getElementById('hostAlias').value = 'aws-ec2';
      document.getElementById('hostName').value = 'ec2-xxx-xxx-xxx-xxx.compute-1.amazonaws.com';
      document.getElementById('hostUser').value = 'ec2-user';
      document.getElementById('hostKey').value = '~/.ssh/aws-keypair.pem';
      document.getElementById('strictHost').value = 'accept-new';
      break;
  }
}

function updateUI() {
  // Update host count
  document.getElementById('hostCount').textContent = hosts.length;

  // Update host list
  const listEl = document.getElementById('hostList');
  if (hosts.length === 0) {
    listEl.innerHTML = '<p style="color: var(--md-default-fg-color--light); font-size: 0.9em;">Aucun host configure</p>';
  } else {
    listEl.innerHTML = hosts.map(h => `
      <div class="host-item">
        <div class="host-item-info">
          <div class="host-item-alias">${h.alias}</div>
          <div class="host-item-details">${h.user ? h.user + '@' : ''}${h.hostname}${h.port !== '22' ? ':' + h.port : ''}</div>
        </div>
        <div class="host-item-actions">
          <button onclick="removeHost(${h.id})">🗑️</button>
        </div>
      </div>
    `).join('');
  }

  // Generate config
  generateConfig();
}

function generateConfig() {
  const outputEl = document.getElementById('configOutput');

  if (hosts.length === 0) {
    outputEl.textContent = '# Ajoutez des hosts pour generer la configuration';
    return;
  }

  let config = '# SSH Config - Generated by ShellBook\n';
  config += '# Copy to ~/.ssh/config\n\n';

  hosts.forEach(h => {
    config += `Host ${h.alias}\n`;
    config += `    HostName ${h.hostname}\n`;

    if (h.user) config += `    User ${h.user}\n`;
    if (h.port && h.port !== '22') config += `    Port ${h.port}\n`;
    if (h.identityFile) config += `    IdentityFile ${h.identityFile}\n`;
    if (h.proxyJump) config += `    ProxyJump ${h.proxyJump}\n`;
    if (h.localForward) config += `    LocalForward ${h.localForward}\n`;
    if (h.remoteForward) config += `    RemoteForward ${h.remoteForward}\n`;
    if (h.dynamicForward) config += `    DynamicForward ${h.dynamicForward}\n`;
    if (h.forwardAgent) config += `    ForwardAgent yes\n`;
    if (h.forwardX11) config += `    ForwardX11 yes\n`;
    if (h.serverAliveInterval) config += `    ServerAliveInterval ${h.serverAliveInterval}\n`;
    if (h.serverAliveCountMax) config += `    ServerAliveCountMax ${h.serverAliveCountMax}\n`;
    if (h.compression) config += `    Compression ${h.compression}\n`;
    if (h.strictHostKeyChecking) config += `    StrictHostKeyChecking ${h.strictHostKeyChecking}\n`;
    if (h.addKeysToAgent) config += `    AddKeysToAgent ${h.addKeysToAgent}\n`;

    config += '\n';
  });

  outputEl.textContent = config;
}

function copyConfig() {
  const config = document.getElementById('configOutput').textContent;
  navigator.clipboard.writeText(config).then(() => {
    const btn = event.target;
    const orig = btn.textContent;
    btn.textContent = '✓ Copie!';
    setTimeout(() => btn.textContent = orig, 1500);
  });
}

function downloadConfig() {
  const config = document.getElementById('configOutput').textContent;
  const blob = new Blob([config], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'config';
  a.click();
  URL.revokeObjectURL(url);
}

// Initialize
updateUI();
</script>

---

## Reference des Options

| Option | Description |
|--------|-------------|
| `Host` | Alias pour la connexion |
| `HostName` | Adresse IP ou nom DNS reel |
| `User` | Utilisateur par defaut |
| `Port` | Port SSH (defaut: 22) |
| `IdentityFile` | Chemin vers la cle privee |
| `ProxyJump` | Host intermediaire (bastion) |
| `LocalForward` | Tunnel local (port:host:hostport) |
| `RemoteForward` | Tunnel distant |
| `DynamicForward` | Proxy SOCKS |
| `ForwardAgent` | Transfert de l'agent SSH |
| `ForwardX11` | Transfert X11 |
| `ServerAliveInterval` | Keepalive interval (secondes) |
| `Compression` | Activer compression |

---

!!! tip "Securite"
    - Utilisez `chmod 600 ~/.ssh/config` pour securiser le fichier
    - Preferez les cles Ed25519 (`ssh-keygen -t ed25519`)
    - N'activez `ForwardAgent` que si necessaire
