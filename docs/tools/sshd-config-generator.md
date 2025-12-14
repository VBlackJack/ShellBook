---
tags:
  - tools
  - ssh
  - security
  - hardening
---

# SSHD Config Generator

Generateur de configuration sshd_config avec options de hardening.

<div id="sshd-app">
  <div class="sshd-container">
    <div class="sshd-section">
      <h3>Configuration SSH Server</h3>

      <div class="security-level">
        <label>Niveau de securite</label>
        <div class="level-buttons">
          <button class="level-btn" onclick="setLevel('basic')">Basique</button>
          <button class="level-btn active" onclick="setLevel('moderate')">Modere</button>
          <button class="level-btn" onclick="setLevel('hardened')">Durci</button>
          <button class="level-btn" onclick="setLevel('paranoid')">Paranoiaque</button>
        </div>
      </div>

      <h4>Reseau</h4>

      <div class="form-group">
        <label>Port SSH</label>
        <input type="number" id="port" value="22" min="1" max="65535" oninput="generate()">
        <span class="hint">Changer le port peut reduire le bruit des scans</span>
      </div>

      <div class="form-group">
        <label>Adresse d'ecoute</label>
        <input type="text" id="listenAddress" value="0.0.0.0" oninput="generate()">
        <span class="hint">0.0.0.0 = toutes interfaces, ou IP specifique</span>
      </div>

      <div class="form-group">
        <label>Address Family</label>
        <select id="addressFamily" onchange="generate()">
          <option value="any" selected>any (IPv4 + IPv6)</option>
          <option value="inet">inet (IPv4 only)</option>
          <option value="inet6">inet6 (IPv6 only)</option>
        </select>
      </div>

      <h4>Authentification</h4>

      <div class="form-group">
        <label>
          <input type="checkbox" id="permitRootLogin" onchange="generate()">
          Autoriser root login
        </label>
        <span class="hint">Fortement deconseille en production</span>
      </div>

      <div class="form-group" id="rootLoginType" style="display:none">
        <label>Type de root login</label>
        <select id="rootLoginValue" onchange="generate()">
          <option value="prohibit-password">prohibit-password (cles seulement)</option>
          <option value="forced-commands-only">forced-commands-only</option>
          <option value="yes">yes (tout)</option>
        </select>
      </div>

      <div class="form-group">
        <label>
          <input type="checkbox" id="passwordAuth" onchange="generate()">
          Autoriser authentification par mot de passe
        </label>
      </div>

      <div class="form-group">
        <label>
          <input type="checkbox" id="pubkeyAuth" onchange="generate()" checked>
          Autoriser authentification par cle publique
        </label>
      </div>

      <div class="form-group">
        <label>
          <input type="checkbox" id="kbdInteractive" onchange="generate()">
          Keyboard-interactive (2FA, etc.)
        </label>
      </div>

      <div class="form-group">
        <label>
          <input type="checkbox" id="challengeResponse" onchange="generate()">
          Challenge-response (PAM)
        </label>
      </div>

      <div class="form-group">
        <label>
          <input type="checkbox" id="usePam" onchange="generate()" checked>
          Utiliser PAM
        </label>
      </div>

      <h4>Restrictions d'acces</h4>

      <div class="form-group">
        <label>
          <input type="checkbox" id="allowUsers" onchange="generate()">
          Restreindre aux utilisateurs specifiques
        </label>
      </div>

      <div class="form-group" id="allowUsersGroup" style="display:none">
        <label>Utilisateurs autorises (separes par espaces)</label>
        <input type="text" id="allowUsersList" value="admin deploy" oninput="generate()">
      </div>

      <div class="form-group">
        <label>
          <input type="checkbox" id="allowGroups" onchange="generate()">
          Restreindre aux groupes specifiques
        </label>
      </div>

      <div class="form-group" id="allowGroupsGroup" style="display:none">
        <label>Groupes autorises (separes par espaces)</label>
        <input type="text" id="allowGroupsList" value="ssh-users wheel" oninput="generate()">
      </div>

      <div class="form-group">
        <label>Max tentatives d'auth</label>
        <input type="number" id="maxAuthTries" value="3" min="1" max="10" oninput="generate()">
      </div>

      <div class="form-group">
        <label>Max sessions</label>
        <input type="number" id="maxSessions" value="2" min="1" max="100" oninput="generate()">
      </div>

      <div class="form-group">
        <label>Login grace time (secondes)</label>
        <input type="number" id="loginGraceTime" value="60" min="10" max="300" oninput="generate()">
      </div>

      <h4>Fonctionnalites</h4>

      <div class="form-group">
        <label>
          <input type="checkbox" id="x11Forwarding" onchange="generate()">
          X11 Forwarding
        </label>
      </div>

      <div class="form-group">
        <label>
          <input type="checkbox" id="tcpForwarding" onchange="generate()" checked>
          TCP Forwarding (tunnels)
        </label>
      </div>

      <div class="form-group">
        <label>
          <input type="checkbox" id="agentForwarding" onchange="generate()">
          Agent Forwarding
        </label>
      </div>

      <div class="form-group">
        <label>
          <input type="checkbox" id="gatewayPorts" onchange="generate()">
          Gateway Ports
        </label>
      </div>

      <div class="form-group">
        <label>
          <input type="checkbox" id="permitTunnel" onchange="generate()">
          Permit Tunnel (VPN)
        </label>
      </div>

      <h4>Cryptographie</h4>

      <div class="form-group">
        <label>Algorithmes de cle d'hote</label>
        <select id="hostKeyAlgo" onchange="generate()">
          <option value="modern" selected>Modern (ed25519, rsa-sha2)</option>
          <option value="compatible">Compatible (+ ecdsa)</option>
          <option value="legacy">Legacy (tous)</option>
        </select>
      </div>

      <div class="form-group">
        <label>Ciphers</label>
        <select id="ciphers" onchange="generate()">
          <option value="modern" selected>Modern (chacha20, aes-gcm)</option>
          <option value="compatible">Compatible (+ aes-ctr)</option>
          <option value="legacy">Legacy (tous)</option>
        </select>
      </div>

      <div class="form-group">
        <label>MACs</label>
        <select id="macs" onchange="generate()">
          <option value="modern" selected>Modern (umac, hmac-sha2-etm)</option>
          <option value="compatible">Compatible</option>
        </select>
      </div>

      <div class="form-group">
        <label>Key Exchange</label>
        <select id="kex" onchange="generate()">
          <option value="modern" selected>Modern (curve25519, ecdh)</option>
          <option value="compatible">Compatible (+ diffie-hellman)</option>
        </select>
      </div>

      <h4>Divers</h4>

      <div class="form-group">
        <label>Client alive interval (secondes)</label>
        <input type="number" id="clientAliveInterval" value="300" min="0" oninput="generate()">
        <span class="hint">0 = desactive</span>
      </div>

      <div class="form-group">
        <label>Client alive count max</label>
        <input type="number" id="clientAliveCountMax" value="2" min="0" oninput="generate()">
      </div>

      <div class="form-group">
        <label>
          <input type="checkbox" id="printMotd" onchange="generate()">
          Afficher MOTD
        </label>
      </div>

      <div class="form-group">
        <label>
          <input type="checkbox" id="printLastLog" onchange="generate()" checked>
          Afficher derniere connexion
        </label>
      </div>

      <div class="form-group">
        <label>Banner</label>
        <input type="text" id="banner" value="" placeholder="/etc/ssh/banner.txt" oninput="generate()">
      </div>
    </div>

    <div class="sshd-section">
      <h3>Configuration generee</h3>
      <pre id="configOutput"># sshd_config</pre>
      <button onclick="copyConfig()">Copier</button>

      <div class="warnings" id="warningsBox"></div>

      <div class="install-info">
        <h4>Installation</h4>
        <pre id="installCmd"># Commandes</pre>
        <button onclick="copyInstall()">Copier</button>
      </div>
    </div>
  </div>

  <div class="presets-section">
    <h3>Presets par cas d'usage</h3>
    <div class="presets-grid">
      <div class="preset-card" onclick="loadPreset('bastion')">
        <h4>Bastion/Jump Host</h4>
        <p>Agent forwarding, pas de shell</p>
      </div>
      <div class="preset-card" onclick="loadPreset('webserver')">
        <h4>Web Server</h4>
        <p>Acces restreint, pas de forward</p>
      </div>
      <div class="preset-card" onclick="loadPreset('git')">
        <h4>Git Server</h4>
        <p>Cles uniquement, utilisateur git</p>
      </div>
      <div class="preset-card" onclick="loadPreset('container')">
        <h4>Container/CI</h4>
        <p>Port alternatif, deploy user</p>
      </div>
      <div class="preset-card" onclick="loadPreset('anssi')">
        <h4>ANSSI/SecNumCloud</h4>
        <p>Conformite recommandations ANSSI</p>
      </div>
      <div class="preset-card" onclick="loadPreset('dev')">
        <h4>Dev/Home</h4>
        <p>Plus permissif pour dev local</p>
      </div>
    </div>
  </div>
</div>

<style>
.sshd-container {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 20px;
}

@media (max-width: 900px) {
  .sshd-container { grid-template-columns: 1fr; }
}

.sshd-section, .presets-section {
  background: var(--md-code-bg-color);
  padding: 20px;
  border-radius: 8px;
  margin-bottom: 20px;
}

.security-level {
  margin-bottom: 20px;
  padding: 15px;
  background: var(--md-default-bg-color);
  border-radius: 6px;
}

.level-buttons {
  display: flex;
  gap: 10px;
  margin-top: 10px;
  flex-wrap: wrap;
}

.level-btn {
  padding: 8px 16px;
  border: 1px solid var(--md-default-fg-color--lightest);
  background: transparent;
  border-radius: 4px;
  cursor: pointer;
  color: var(--md-default-fg-color);
}

.level-btn.active {
  background: var(--md-primary-fg-color);
  color: white;
  border-color: var(--md-primary-fg-color);
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
.form-group input[type="number"] {
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

#configOutput { min-height: 350px; }

.sshd-section button {
  margin-top: 10px;
  margin-right: 10px;
  padding: 8px 16px;
  background: var(--md-primary-fg-color);
  color: white;
  border: none;
  border-radius: 4px;
  cursor: pointer;
}

.warnings {
  margin-top: 15px;
  padding: 10px;
  border-radius: 4px;
}

.warnings.has-warnings {
  background: #fff3cd;
  color: #856404;
}

.warnings.secure {
  background: #d4edda;
  color: #155724;
}

.install-info {
  margin-top: 20px;
  padding-top: 20px;
  border-top: 1px solid var(--md-default-fg-color--lightest);
}

.presets-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
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
const cryptoPresets = {
  modern: {
    hostKey: 'ssh-ed25519,rsa-sha2-512,rsa-sha2-256',
    ciphers: 'chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com',
    macs: 'hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com',
    kex: 'curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256'
  },
  compatible: {
    hostKey: 'ssh-ed25519,ecdsa-sha2-nistp521,ecdsa-sha2-nistp384,ecdsa-sha2-nistp256,rsa-sha2-512,rsa-sha2-256',
    ciphers: 'chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr',
    macs: 'hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256',
    kex: 'curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group18-sha512,diffie-hellman-group16-sha512'
  },
  legacy: {
    hostKey: '',
    ciphers: '',
    macs: '',
    kex: ''
  }
};

function setLevel(level) {
  document.querySelectorAll('.level-btn').forEach(btn => btn.classList.remove('active'));
  event.target.classList.add('active');

  switch(level) {
    case 'basic':
      document.getElementById('port').value = '22';
      document.getElementById('permitRootLogin').checked = true;
      document.getElementById('rootLoginValue').value = 'prohibit-password';
      document.getElementById('passwordAuth').checked = true;
      document.getElementById('pubkeyAuth').checked = true;
      document.getElementById('maxAuthTries').value = '6';
      document.getElementById('hostKeyAlgo').value = 'compatible';
      document.getElementById('ciphers').value = 'compatible';
      break;
    case 'moderate':
      document.getElementById('port').value = '22';
      document.getElementById('permitRootLogin').checked = false;
      document.getElementById('passwordAuth').checked = false;
      document.getElementById('pubkeyAuth').checked = true;
      document.getElementById('maxAuthTries').value = '3';
      document.getElementById('hostKeyAlgo').value = 'modern';
      document.getElementById('ciphers').value = 'modern';
      break;
    case 'hardened':
      document.getElementById('port').value = '2222';
      document.getElementById('permitRootLogin').checked = false;
      document.getElementById('passwordAuth').checked = false;
      document.getElementById('pubkeyAuth').checked = true;
      document.getElementById('allowUsers').checked = true;
      document.getElementById('maxAuthTries').value = '2';
      document.getElementById('x11Forwarding').checked = false;
      document.getElementById('tcpForwarding').checked = false;
      document.getElementById('hostKeyAlgo').value = 'modern';
      document.getElementById('ciphers').value = 'modern';
      break;
    case 'paranoid':
      document.getElementById('port').value = '2222';
      document.getElementById('permitRootLogin').checked = false;
      document.getElementById('passwordAuth').checked = false;
      document.getElementById('pubkeyAuth').checked = true;
      document.getElementById('allowUsers').checked = true;
      document.getElementById('allowGroups').checked = true;
      document.getElementById('maxAuthTries').value = '2';
      document.getElementById('maxSessions').value = '1';
      document.getElementById('loginGraceTime').value = '30';
      document.getElementById('x11Forwarding').checked = false;
      document.getElementById('tcpForwarding').checked = false;
      document.getElementById('agentForwarding').checked = false;
      document.getElementById('hostKeyAlgo').value = 'modern';
      document.getElementById('ciphers').value = 'modern';
      document.getElementById('clientAliveInterval').value = '120';
      document.getElementById('clientAliveCountMax').value = '2';
      break;
  }
  generate();
}

function generate() {
  // Update visibility
  document.getElementById('rootLoginType').style.display =
    document.getElementById('permitRootLogin').checked ? 'block' : 'none';
  document.getElementById('allowUsersGroup').style.display =
    document.getElementById('allowUsers').checked ? 'block' : 'none';
  document.getElementById('allowGroupsGroup').style.display =
    document.getElementById('allowGroups').checked ? 'block' : 'none';

  const port = document.getElementById('port').value;
  const listenAddress = document.getElementById('listenAddress').value;
  const addressFamily = document.getElementById('addressFamily').value;

  const permitRootLogin = document.getElementById('permitRootLogin').checked;
  const rootLoginValue = document.getElementById('rootLoginValue').value;
  const passwordAuth = document.getElementById('passwordAuth').checked;
  const pubkeyAuth = document.getElementById('pubkeyAuth').checked;
  const kbdInteractive = document.getElementById('kbdInteractive').checked;
  const challengeResponse = document.getElementById('challengeResponse').checked;
  const usePam = document.getElementById('usePam').checked;

  const allowUsers = document.getElementById('allowUsers').checked;
  const allowUsersList = document.getElementById('allowUsersList').value;
  const allowGroups = document.getElementById('allowGroups').checked;
  const allowGroupsList = document.getElementById('allowGroupsList').value;

  const maxAuthTries = document.getElementById('maxAuthTries').value;
  const maxSessions = document.getElementById('maxSessions').value;
  const loginGraceTime = document.getElementById('loginGraceTime').value;

  const x11Forwarding = document.getElementById('x11Forwarding').checked;
  const tcpForwarding = document.getElementById('tcpForwarding').checked;
  const agentForwarding = document.getElementById('agentForwarding').checked;
  const gatewayPorts = document.getElementById('gatewayPorts').checked;
  const permitTunnel = document.getElementById('permitTunnel').checked;

  const hostKeyAlgo = document.getElementById('hostKeyAlgo').value;
  const ciphersLevel = document.getElementById('ciphers').value;
  const macsLevel = document.getElementById('macs').value;
  const kexLevel = document.getElementById('kex').value;

  const clientAliveInterval = document.getElementById('clientAliveInterval').value;
  const clientAliveCountMax = document.getElementById('clientAliveCountMax').value;
  const printMotd = document.getElementById('printMotd').checked;
  const printLastLog = document.getElementById('printLastLog').checked;
  const banner = document.getElementById('banner').value;

  let config = `# sshd_config - Generated by ShellBook
# OpenSSH Server Configuration

# ============================================================================
# NETWORK
# ============================================================================
Port ${port}
ListenAddress ${listenAddress}
AddressFamily ${addressFamily}

# ============================================================================
# HOST KEYS
# ============================================================================
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key
#HostKey /etc/ssh/ssh_host_ecdsa_key

# ============================================================================
# AUTHENTICATION
# ============================================================================
PermitRootLogin ${permitRootLogin ? rootLoginValue : 'no'}
PubkeyAuthentication ${pubkeyAuth ? 'yes' : 'no'}
PasswordAuthentication ${passwordAuth ? 'yes' : 'no'}
PermitEmptyPasswords no
ChallengeResponseAuthentication ${challengeResponse ? 'yes' : 'no'}
KbdInteractiveAuthentication ${kbdInteractive ? 'yes' : 'no'}
UsePAM ${usePam ? 'yes' : 'no'}

# Disable other authentication methods
GSSAPIAuthentication no
HostbasedAuthentication no

`;

  if (allowUsers) {
    config += `# Restrict to specific users
AllowUsers ${allowUsersList}

`;
  }

  if (allowGroups) {
    config += `# Restrict to specific groups
AllowGroups ${allowGroupsList}

`;
  }

  config += `# ============================================================================
# SECURITY LIMITS
# ============================================================================
MaxAuthTries ${maxAuthTries}
MaxSessions ${maxSessions}
LoginGraceTime ${loginGraceTime}
MaxStartups 10:30:60

# ============================================================================
# FEATURES
# ============================================================================
X11Forwarding ${x11Forwarding ? 'yes' : 'no'}
AllowTcpForwarding ${tcpForwarding ? 'yes' : 'no'}
AllowAgentForwarding ${agentForwarding ? 'yes' : 'no'}
GatewayPorts ${gatewayPorts ? 'yes' : 'no'}
PermitTunnel ${permitTunnel ? 'yes' : 'no'}
PermitUserEnvironment no
AllowStreamLocalForwarding no
DisableForwarding no

# ============================================================================
# CRYPTOGRAPHY
# ============================================================================
`;

  const crypto = cryptoPresets[ciphersLevel] || cryptoPresets.modern;
  if (crypto.hostKey) {
    config += `HostKeyAlgorithms ${cryptoPresets[hostKeyAlgo]?.hostKey || crypto.hostKey}\n`;
  }
  if (crypto.ciphers) {
    config += `Ciphers ${crypto.ciphers}\n`;
  }
  if (crypto.macs) {
    config += `MACs ${cryptoPresets[macsLevel]?.macs || crypto.macs}\n`;
  }
  if (crypto.kex) {
    config += `KexAlgorithms ${cryptoPresets[kexLevel]?.kex || crypto.kex}\n`;
  }

  config += `
# ============================================================================
# KEEPALIVE & TIMEOUT
# ============================================================================
ClientAliveInterval ${clientAliveInterval}
ClientAliveCountMax ${clientAliveCountMax}
TCPKeepAlive yes

# ============================================================================
# LOGGING
# ============================================================================
SyslogFacility AUTH
LogLevel VERBOSE

# ============================================================================
# MISC
# ============================================================================
PrintMotd ${printMotd ? 'yes' : 'no'}
PrintLastLog ${printLastLog ? 'yes' : 'no'}
${banner ? `Banner ${banner}` : '#Banner none'}
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
`;

  document.getElementById('configOutput').textContent = config;

  // Warnings
  let warnings = [];
  if (permitRootLogin && rootLoginValue === 'yes') {
    warnings.push('⚠️ Root login avec mot de passe active - risque eleve');
  }
  if (passwordAuth) {
    warnings.push('⚠️ Authentification par mot de passe active - preferer les cles');
  }
  if (port === '22') {
    warnings.push('ℹ️ Port 22 par defaut - considerer un port alternatif');
  }
  if (!allowUsers && !allowGroups) {
    warnings.push('ℹ️ Pas de restriction d\'utilisateurs - considerer AllowUsers/AllowGroups');
  }
  if (agentForwarding) {
    warnings.push('⚠️ Agent forwarding active - risque si serveur compromis');
  }

  const warningsBox = document.getElementById('warningsBox');
  if (warnings.length > 0) {
    warningsBox.className = 'warnings has-warnings';
    warningsBox.innerHTML = warnings.join('<br>');
  } else {
    warningsBox.className = 'warnings secure';
    warningsBox.innerHTML = '✓ Configuration securisee';
  }

  // Install commands
  const installCmd = `# Sauvegarder la config actuelle
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

# Ecrire la nouvelle configuration
sudo tee /etc/ssh/sshd_config << 'EOF'
${config}
EOF

# Verifier la syntaxe
sudo sshd -t

# Si OK, recharger SSH
sudo systemctl reload sshd

# IMPORTANT: Garder une session ouverte pour tester !`;

  document.getElementById('installCmd').textContent = installCmd;
}

function loadPreset(name) {
  switch(name) {
    case 'bastion':
      setLevel('hardened');
      document.getElementById('agentForwarding').checked = true;
      document.getElementById('tcpForwarding').checked = true;
      document.getElementById('maxSessions').value = '10';
      break;
    case 'webserver':
      setLevel('hardened');
      document.getElementById('tcpForwarding').checked = false;
      document.getElementById('agentForwarding').checked = false;
      document.getElementById('allowUsers').checked = true;
      document.getElementById('allowUsersList').value = 'deploy admin';
      break;
    case 'git':
      setLevel('hardened');
      document.getElementById('allowUsers').checked = true;
      document.getElementById('allowUsersList').value = 'git';
      document.getElementById('tcpForwarding').checked = false;
      break;
    case 'container':
      setLevel('moderate');
      document.getElementById('port').value = '2222';
      document.getElementById('allowUsers').checked = true;
      document.getElementById('allowUsersList').value = 'deploy';
      break;
    case 'anssi':
      setLevel('paranoid');
      document.getElementById('hostKeyAlgo').value = 'modern';
      document.getElementById('ciphers').value = 'modern';
      document.getElementById('macs').value = 'modern';
      document.getElementById('kex').value = 'modern';
      document.getElementById('loginGraceTime').value = '30';
      break;
    case 'dev':
      setLevel('basic');
      document.getElementById('tcpForwarding').checked = true;
      document.getElementById('agentForwarding').checked = true;
      document.getElementById('x11Forwarding').checked = true;
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
# Tester la configuration
sshd -t

# Voir la config effective
sshd -T

# Regenerer les cles d'hote
ssh-keygen -A

# Voir les connexions actives
ss -tnp | grep sshd
```

---

## Voir aussi

- [SSH Config Generator](ssh-config-generator.md) - Configuration client
- [SSH Hardening](../linux/ssh-hardening.md)
- [Fail2Ban Generator](fail2ban-generator.md)
