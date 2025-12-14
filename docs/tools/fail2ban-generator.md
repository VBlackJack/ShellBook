---
tags:
  - tools
  - security
  - fail2ban
  - firewall
---

# Fail2Ban Jail Generator

Generateur de configuration Fail2Ban pour la protection contre les attaques brute-force.

<div id="fail2ban-app">
  <div class="fail2ban-container">
    <div class="fail2ban-section">
      <h3>Configuration Jail</h3>

      <div class="form-group">
        <label>Nom du jail</label>
        <input type="text" id="jailName" value="custom-service" oninput="generate()">
      </div>

      <div class="form-group">
        <label>Service/Application</label>
        <select id="serviceType" onchange="updateService(); generate()">
          <option value="custom">Personnalise</option>
          <option value="sshd" selected>SSH (sshd)</option>
          <option value="nginx-http-auth">Nginx HTTP Auth</option>
          <option value="nginx-botsearch">Nginx Bot Search</option>
          <option value="nginx-limit-req">Nginx Limit Req</option>
          <option value="apache-auth">Apache Auth</option>
          <option value="apache-badbots">Apache Bad Bots</option>
          <option value="postfix">Postfix SMTP</option>
          <option value="dovecot">Dovecot IMAP/POP3</option>
          <option value="vsftpd">vsFTPd</option>
          <option value="mysql">MySQL/MariaDB</option>
          <option value="wordpress">WordPress</option>
        </select>
      </div>

      <div class="form-group">
        <label>
          <input type="checkbox" id="enabled" onchange="generate()" checked>
          Activer le jail
        </label>
      </div>

      <h4>Detection</h4>

      <div class="form-group">
        <label>Fichier de log a surveiller</label>
        <input type="text" id="logpath" value="/var/log/auth.log" oninput="generate()">
        <span class="hint">Variables: %(syslog_authpriv)s, %(nginx_access_log)s</span>
      </div>

      <div class="form-group">
        <label>Backend</label>
        <select id="backend" onchange="generate()">
          <option value="auto" selected>auto (recommande)</option>
          <option value="systemd">systemd (journald)</option>
          <option value="pyinotify">pyinotify</option>
          <option value="polling">polling</option>
        </select>
      </div>

      <div class="form-group" id="journalGroup" style="display:none">
        <label>Journalmatch (pour systemd)</label>
        <input type="text" id="journalmatch" value="_SYSTEMD_UNIT=sshd.service" oninput="generate()">
      </div>

      <h4>Seuils</h4>

      <div class="form-group">
        <label>Nombre de tentatives avant ban (maxretry)</label>
        <input type="number" id="maxretry" value="5" min="1" max="100" oninput="generate()">
      </div>

      <div class="form-group">
        <label>Fenetre de detection (findtime)</label>
        <div class="time-input">
          <input type="number" id="findtime" value="10" min="1" oninput="generate()">
          <select id="findtimeUnit" onchange="generate()">
            <option value="s">secondes</option>
            <option value="m" selected>minutes</option>
            <option value="h">heures</option>
            <option value="d">jours</option>
          </select>
        </div>
        <span class="hint">Periode pendant laquelle les echecs sont comptes</span>
      </div>

      <div class="form-group">
        <label>Duree du ban (bantime)</label>
        <div class="time-input">
          <input type="number" id="bantime" value="1" min="-1" oninput="generate()">
          <select id="bantimeUnit" onchange="generate()">
            <option value="s">secondes</option>
            <option value="m">minutes</option>
            <option value="h" selected>heures</option>
            <option value="d">jours</option>
            <option value="-1">permanent</option>
          </select>
        </div>
        <span class="hint">-1 = ban permanent</span>
      </div>

      <h4>Action</h4>

      <div class="form-group">
        <label>Type d'action</label>
        <select id="actionType" onchange="generate()">
          <option value="default">Ban simple (iptables/nftables)</option>
          <option value="action_mw">Ban + Email warning</option>
          <option value="action_mwl">Ban + Email + Logs</option>
          <option value="custom">Personnalise</option>
        </select>
      </div>

      <div class="form-group" id="emailGroup" style="display:none">
        <label>Email destinataire</label>
        <input type="email" id="destemail" value="admin@example.com" oninput="generate()">
      </div>

      <div class="form-group" id="customActionGroup" style="display:none">
        <label>Action personnalisee</label>
        <input type="text" id="customAction" value="iptables-multiport[name=%(__name__)s, port=\"%(port)s\"]" oninput="generate()">
      </div>

      <div class="form-group">
        <label>Port(s) a bloquer</label>
        <input type="text" id="port" value="ssh" oninput="generate()">
        <span class="hint">Nom (ssh, http) ou numero (22, 80,443)</span>
      </div>

      <h4>Options avancees</h4>

      <div class="form-group">
        <label>
          <input type="checkbox" id="ignoreself" onchange="generate()" checked>
          Ignorer localhost (ignoreself)
        </label>
      </div>

      <div class="form-group">
        <label>IPs a ignorer (whitelist)</label>
        <input type="text" id="ignoreip" value="127.0.0.1/8 ::1" oninput="generate()">
        <span class="hint">Separees par espaces. Ex: 192.168.1.0/24 10.0.0.0/8</span>
      </div>

      <div class="form-group" id="filterGroup">
        <label>Filtre (regex)</label>
        <select id="filterType" onchange="generate()">
          <option value="builtin" selected>Filtre integre</option>
          <option value="custom">Filtre personnalise</option>
        </select>
      </div>

      <div class="form-group" id="customFilterGroup" style="display:none">
        <label>Regex failregex</label>
        <textarea id="failregex" rows="3" oninput="generate()">^<HOST> - - \[.*\] ".*" 401</textarea>
        <span class="hint">&lt;HOST&gt; capture l'IP de l'attaquant</span>
      </div>
    </div>

    <div class="fail2ban-section">
      <h3>Configuration generee</h3>

      <div class="output-tabs">
        <button class="output-tab active" onclick="switchOutput('jail')">jail.local</button>
        <button class="output-tab" onclick="switchOutput('filter')">filter.d</button>
      </div>

      <pre id="jailOutput"># jail.local</pre>
      <pre id="filterOutput" style="display:none"># filter.d</pre>
      <button onclick="copyConfig()">Copier</button>

      <div class="install-info">
        <h4>Installation</h4>
        <pre id="installCmd"># Commandes d'installation</pre>
        <button onclick="copyInstall()">Copier</button>
      </div>
    </div>
  </div>

  <div class="presets-section">
    <h3>Presets courants</h3>
    <div class="presets-grid">
      <div class="preset-card" onclick="loadPreset('ssh-aggressive')">
        <h4>SSH Agressif</h4>
        <p>3 echecs, ban 24h</p>
      </div>
      <div class="preset-card" onclick="loadPreset('ssh-moderate')">
        <h4>SSH Modere</h4>
        <p>5 echecs, ban 1h</p>
      </div>
      <div class="preset-card" onclick="loadPreset('nginx-ddos')">
        <h4>Nginx Anti-DDoS</h4>
        <p>Rate limiting agressif</p>
      </div>
      <div class="preset-card" onclick="loadPreset('wordpress')">
        <h4>WordPress</h4>
        <p>Protection wp-login</p>
      </div>
      <div class="preset-card" onclick="loadPreset('recidive')">
        <h4>Recidive</h4>
        <p>Ban long pour recidivistes</p>
      </div>
      <div class="preset-card" onclick="loadPreset('postfix')">
        <h4>Postfix SASL</h4>
        <p>Protection SMTP auth</p>
      </div>
    </div>
  </div>

  <div class="reference-section">
    <h3>Commandes utiles</h3>
    <table class="ref-table">
      <tr><td><code>fail2ban-client status</code></td><td>Voir tous les jails actifs</td></tr>
      <tr><td><code>fail2ban-client status sshd</code></td><td>Details d'un jail</td></tr>
      <tr><td><code>fail2ban-client set sshd unbanip IP</code></td><td>Debannir une IP</td></tr>
      <tr><td><code>fail2ban-client set sshd banip IP</code></td><td>Bannir manuellement</td></tr>
      <tr><td><code>fail2ban-regex /var/log/auth.log /etc/fail2ban/filter.d/sshd.conf</code></td><td>Tester un filtre</td></tr>
      <tr><td><code>fail2ban-client reload</code></td><td>Recharger la config</td></tr>
    </table>
  </div>
</div>

<style>
.fail2ban-container {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 20px;
}

@media (max-width: 900px) {
  .fail2ban-container {
    grid-template-columns: 1fr;
  }
}

.fail2ban-section, .presets-section, .reference-section {
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
.form-group input[type="email"],
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

.form-group textarea {
  resize: vertical;
}

.form-group input[type="checkbox"] {
  margin-right: 8px;
}

.hint {
  font-size: 0.8em;
  color: var(--md-default-fg-color--light);
  display: block;
  margin-top: 4px;
}

.time-input {
  display: flex;
  gap: 10px;
}

.time-input input {
  flex: 1;
}

.time-input select {
  width: 120px;
}

.output-tabs {
  display: flex;
  gap: 5px;
  margin-bottom: 10px;
}

.output-tab {
  padding: 6px 12px;
  border: 1px solid var(--md-default-fg-color--lightest);
  background: transparent;
  border-radius: 4px;
  cursor: pointer;
  color: var(--md-default-fg-color);
  font-size: 0.85em;
}

.output-tab.active {
  background: var(--md-primary-fg-color);
  color: white;
  border-color: var(--md-primary-fg-color);
}

#jailOutput, #filterOutput, #installCmd {
  background: #1e1e1e;
  color: #d4d4d4;
  padding: 15px;
  border-radius: 4px;
  font-size: 0.85em;
  overflow-x: auto;
  white-space: pre-wrap;
}

#jailOutput, #filterOutput {
  min-height: 200px;
}

.fail2ban-section button {
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

.install-info h4 {
  margin: 0 0 10px 0;
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

.preset-card:hover {
  transform: scale(1.02);
}

.preset-card h4 {
  margin: 0 0 5px 0;
  font-size: 0.95em;
}

.preset-card p {
  margin: 0;
  font-size: 0.8em;
  color: var(--md-default-fg-color--light);
}

.ref-table {
  width: 100%;
  font-size: 0.85em;
  border-collapse: collapse;
}

.ref-table td {
  padding: 8px;
  border-bottom: 1px solid var(--md-default-fg-color--lightest);
  vertical-align: top;
}

.ref-table code {
  background: var(--md-default-bg-color);
  padding: 2px 6px;
  border-radius: 3px;
  white-space: nowrap;
}
</style>

<script>
let currentOutput = 'jail';

const serviceDefaults = {
  sshd: { logpath: '/var/log/auth.log', port: 'ssh', filter: 'sshd', journal: '_SYSTEMD_UNIT=sshd.service' },
  'nginx-http-auth': { logpath: '/var/log/nginx/error.log', port: 'http,https', filter: 'nginx-http-auth', journal: '' },
  'nginx-botsearch': { logpath: '/var/log/nginx/access.log', port: 'http,https', filter: 'nginx-botsearch', journal: '' },
  'nginx-limit-req': { logpath: '/var/log/nginx/error.log', port: 'http,https', filter: 'nginx-limit-req', journal: '' },
  'apache-auth': { logpath: '/var/log/apache2/error.log', port: 'http,https', filter: 'apache-auth', journal: '' },
  'apache-badbots': { logpath: '/var/log/apache2/access.log', port: 'http,https', filter: 'apache-badbots', journal: '' },
  postfix: { logpath: '/var/log/mail.log', port: 'smtp,465,submission', filter: 'postfix', journal: '_SYSTEMD_UNIT=postfix.service' },
  dovecot: { logpath: '/var/log/mail.log', port: 'pop3,pop3s,imap,imaps', filter: 'dovecot', journal: '_SYSTEMD_UNIT=dovecot.service' },
  vsftpd: { logpath: '/var/log/vsftpd.log', port: 'ftp,ftp-data,ftps,ftps-data', filter: 'vsftpd', journal: '' },
  mysql: { logpath: '/var/log/mysql/error.log', port: '3306', filter: 'mysqld-auth', journal: '' },
  wordpress: { logpath: '/var/log/nginx/access.log', port: 'http,https', filter: 'wordpress', journal: '' },
  custom: { logpath: '/var/log/myapp.log', port: '8080', filter: 'custom', journal: '' }
};

function updateService() {
  const service = document.getElementById('serviceType').value;
  const defaults = serviceDefaults[service];

  if (defaults) {
    document.getElementById('logpath').value = defaults.logpath;
    document.getElementById('port').value = defaults.port;
    document.getElementById('journalmatch').value = defaults.journal;
    if (service !== 'custom') {
      document.getElementById('jailName').value = service;
    }
  }
}

function switchOutput(type) {
  currentOutput = type;
  document.querySelectorAll('.output-tab').forEach(btn => btn.classList.remove('active'));
  event.target.classList.add('active');

  document.getElementById('jailOutput').style.display = type === 'jail' ? 'block' : 'none';
  document.getElementById('filterOutput').style.display = type === 'filter' ? 'block' : 'none';
}

function generate() {
  const jailName = document.getElementById('jailName').value;
  const serviceType = document.getElementById('serviceType').value;
  const enabled = document.getElementById('enabled').checked;
  const logpath = document.getElementById('logpath').value;
  const backend = document.getElementById('backend').value;
  const journalmatch = document.getElementById('journalmatch').value;
  const maxretry = document.getElementById('maxretry').value;
  const findtime = document.getElementById('findtime').value;
  const findtimeUnit = document.getElementById('findtimeUnit').value;
  const bantime = document.getElementById('bantime').value;
  const bantimeUnit = document.getElementById('bantimeUnit').value;
  const actionType = document.getElementById('actionType').value;
  const destemail = document.getElementById('destemail').value;
  const customAction = document.getElementById('customAction').value;
  const port = document.getElementById('port').value;
  const ignoreself = document.getElementById('ignoreself').checked;
  const ignoreip = document.getElementById('ignoreip').value;
  const filterType = document.getElementById('filterType').value;
  const failregex = document.getElementById('failregex').value;

  // Update visibility
  document.getElementById('journalGroup').style.display = backend === 'systemd' ? 'block' : 'none';
  document.getElementById('emailGroup').style.display =
    (actionType === 'action_mw' || actionType === 'action_mwl') ? 'block' : 'none';
  document.getElementById('customActionGroup').style.display = actionType === 'custom' ? 'block' : 'none';
  document.getElementById('customFilterGroup').style.display = filterType === 'custom' ? 'block' : 'none';

  // Generate jail.local
  let jail = `# /etc/fail2ban/jail.local
# Configuration generee pour ${jailName}

[${jailName}]
enabled = ${enabled ? 'true' : 'false'}
`;

  if (filterType === 'custom') {
    jail += `filter = ${jailName}\n`;
  } else if (serviceType !== 'custom') {
    jail += `filter = ${serviceDefaults[serviceType].filter}\n`;
  }

  jail += `port = ${port}
logpath = ${logpath}
backend = ${backend}
`;

  if (backend === 'systemd' && journalmatch) {
    jail += `journalmatch = ${journalmatch}\n`;
  }

  jail += `
maxretry = ${maxretry}
findtime = ${findtime}${findtimeUnit}
`;

  if (bantimeUnit === '-1') {
    jail += `bantime = -1\n`;
  } else {
    jail += `bantime = ${bantime}${bantimeUnit}\n`;
  }

  if (ignoreself) {
    jail += `ignoreself = true\n`;
  }
  if (ignoreip) {
    jail += `ignoreip = ${ignoreip}\n`;
  }

  switch(actionType) {
    case 'action_mw':
      jail += `\naction = %(action_mw)s\ndestemail = ${destemail}\n`;
      break;
    case 'action_mwl':
      jail += `\naction = %(action_mwl)s\ndestemail = ${destemail}\n`;
      break;
    case 'custom':
      jail += `\naction = ${customAction}\n`;
      break;
  }

  document.getElementById('jailOutput').textContent = jail;

  // Generate filter.d if custom
  let filter = '';
  if (filterType === 'custom') {
    filter = `# /etc/fail2ban/filter.d/${jailName}.conf
# Filtre personnalise pour ${jailName}

[Definition]
failregex = ${failregex}

ignoreregex =

# Notes:
# - <HOST> capture l'adresse IP de l'attaquant
# - Les regex sont au format Python
# - Testez avec: fail2ban-regex /path/to/log /etc/fail2ban/filter.d/${jailName}.conf
`;
  } else {
    filter = `# Utilise le filtre integre: ${serviceDefaults[serviceType]?.filter || 'N/A'}
# Emplacement: /etc/fail2ban/filter.d/${serviceDefaults[serviceType]?.filter || 'custom'}.conf

# Pour personnaliser, copiez le filtre existant:
# cp /etc/fail2ban/filter.d/${serviceDefaults[serviceType]?.filter || 'template'}.conf /etc/fail2ban/filter.d/${jailName}.conf
# Puis editez selon vos besoins
`;
  }
  document.getElementById('filterOutput').textContent = filter;

  // Generate install commands
  const installCmd = `# Installation Fail2Ban
sudo apt install fail2ban  # Debian/Ubuntu
# sudo dnf install fail2ban  # RHEL/Fedora

# Sauvegarder la configuration jail
sudo tee -a /etc/fail2ban/jail.local << 'EOF'
${jail}
EOF
${filterType === 'custom' ? `
# Sauvegarder le filtre personnalise
sudo tee /etc/fail2ban/filter.d/${jailName}.conf << 'EOF'
${filter}
EOF
` : ''}
# Tester la configuration
sudo fail2ban-client -t

# Recharger
sudo fail2ban-client reload

# Verifier le statut
sudo fail2ban-client status ${jailName}`;

  document.getElementById('installCmd').textContent = installCmd;
}

function loadPreset(name) {
  switch(name) {
    case 'ssh-aggressive':
      document.getElementById('serviceType').value = 'sshd';
      document.getElementById('jailName').value = 'sshd';
      document.getElementById('maxretry').value = '3';
      document.getElementById('findtime').value = '10';
      document.getElementById('findtimeUnit').value = 'm';
      document.getElementById('bantime').value = '24';
      document.getElementById('bantimeUnit').value = 'h';
      document.getElementById('actionType').value = 'action_mw';
      updateService();
      break;

    case 'ssh-moderate':
      document.getElementById('serviceType').value = 'sshd';
      document.getElementById('jailName').value = 'sshd';
      document.getElementById('maxretry').value = '5';
      document.getElementById('findtime').value = '10';
      document.getElementById('findtimeUnit').value = 'm';
      document.getElementById('bantime').value = '1';
      document.getElementById('bantimeUnit').value = 'h';
      document.getElementById('actionType').value = 'default';
      updateService();
      break;

    case 'nginx-ddos':
      document.getElementById('serviceType').value = 'nginx-limit-req';
      document.getElementById('jailName').value = 'nginx-limit-req';
      document.getElementById('maxretry').value = '10';
      document.getElementById('findtime').value = '1';
      document.getElementById('findtimeUnit').value = 'm';
      document.getElementById('bantime').value = '1';
      document.getElementById('bantimeUnit').value = 'h';
      document.getElementById('actionType').value = 'default';
      updateService();
      break;

    case 'wordpress':
      document.getElementById('serviceType').value = 'custom';
      document.getElementById('jailName').value = 'wordpress';
      document.getElementById('logpath').value = '/var/log/nginx/access.log';
      document.getElementById('port').value = 'http,https';
      document.getElementById('maxretry').value = '5';
      document.getElementById('findtime').value = '5';
      document.getElementById('findtimeUnit').value = 'm';
      document.getElementById('bantime').value = '1';
      document.getElementById('bantimeUnit').value = 'h';
      document.getElementById('filterType').value = 'custom';
      document.getElementById('failregex').value = '^<HOST> .* "POST /wp-login.php';
      break;

    case 'recidive':
      document.getElementById('serviceType').value = 'custom';
      document.getElementById('jailName').value = 'recidive';
      document.getElementById('logpath').value = '/var/log/fail2ban.log';
      document.getElementById('port').value = 'all';
      document.getElementById('maxretry').value = '3';
      document.getElementById('findtime').value = '1';
      document.getElementById('findtimeUnit').value = 'd';
      document.getElementById('bantime').value = '7';
      document.getElementById('bantimeUnit').value = 'd';
      document.getElementById('filterType').value = 'builtin';
      break;

    case 'postfix':
      document.getElementById('serviceType').value = 'postfix';
      document.getElementById('jailName').value = 'postfix-sasl';
      document.getElementById('maxretry').value = '3';
      document.getElementById('findtime').value = '10';
      document.getElementById('findtimeUnit').value = 'm';
      document.getElementById('bantime').value = '12';
      document.getElementById('bantimeUnit').value = 'h';
      document.getElementById('actionType').value = 'default';
      updateService();
      break;
  }
  generate();
}

function copyConfig() {
  const output = currentOutput === 'jail'
    ? document.getElementById('jailOutput').textContent
    : document.getElementById('filterOutput').textContent;
  navigator.clipboard.writeText(output).then(() => {
    const btn = event.target;
    const orig = btn.textContent;
    btn.textContent = 'Copie!';
    setTimeout(() => btn.textContent = orig, 1500);
  });
}

function copyInstall() {
  const cmd = document.getElementById('installCmd').textContent;
  navigator.clipboard.writeText(cmd).then(() => {
    const btn = event.target;
    const orig = btn.textContent;
    btn.textContent = 'Copie!';
    setTimeout(() => btn.textContent = orig, 1500);
  });
}

// Init
generate();
</script>

---

## Architecture Fail2Ban

```
/etc/fail2ban/
├── fail2ban.conf      # Config globale (ne pas modifier)
├── fail2ban.local     # Surcharges globales
├── jail.conf          # Jails par defaut (ne pas modifier)
├── jail.local         # Vos jails personnalises
├── jail.d/            # Configs additionnelles
├── filter.d/          # Definitions de filtres (regex)
└── action.d/          # Actions (iptables, mail, etc.)
```

---

## Voir aussi

- [SSH Hardening](../linux/ssh-hardening.md)
- [Iptables Generator](iptables-generator.md)
- [nftables Generator](nftables-generator.md)
