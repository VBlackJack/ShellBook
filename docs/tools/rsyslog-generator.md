---
tags:
  - tools
  - logging
  - rsyslog
  - syslog
---

# Rsyslog Config Generator

Generateur de configuration rsyslog avec filtres, templates et forwarding.

<div id="rsyslog-app">
  <div class="rsyslog-container">
    <div class="rsyslog-section">
      <h3>Type de configuration</h3>

      <div class="config-tabs">
        <button class="tab-btn active" onclick="switchTab('filter')">Filtres</button>
        <button class="tab-btn" onclick="switchTab('template')">Templates</button>
        <button class="tab-btn" onclick="switchTab('forward')">Forwarding</button>
        <button class="tab-btn" onclick="switchTab('input')">Inputs</button>
      </div>

      <!-- FILTER TAB -->
      <div id="filter-tab" class="tab-content active">
        <div class="form-group">
          <label>Facility</label>
          <select id="facility" onchange="generate()">
            <option value="*">* (toutes)</option>
            <option value="auth">auth</option>
            <option value="authpriv" selected>authpriv</option>
            <option value="cron">cron</option>
            <option value="daemon">daemon</option>
            <option value="kern">kern</option>
            <option value="lpr">lpr</option>
            <option value="mail">mail</option>
            <option value="news">news</option>
            <option value="syslog">syslog</option>
            <option value="user">user</option>
            <option value="uucp">uucp</option>
            <option value="local0">local0</option>
            <option value="local1">local1</option>
            <option value="local2">local2</option>
            <option value="local3">local3</option>
            <option value="local4">local4</option>
            <option value="local5">local5</option>
            <option value="local6">local6</option>
            <option value="local7">local7</option>
          </select>
        </div>

        <div class="form-group">
          <label>Severity</label>
          <select id="severity" onchange="generate()">
            <option value="*">* (toutes)</option>
            <option value="emerg">emerg (0)</option>
            <option value="alert">alert (1)</option>
            <option value="crit">crit (2)</option>
            <option value="err">err (3)</option>
            <option value="warning">warning (4)</option>
            <option value="notice">notice (5)</option>
            <option value="info" selected>info (6)</option>
            <option value="debug">debug (7)</option>
            <option value="none">none (desactiver)</option>
          </select>
        </div>

        <div class="form-group">
          <label>Comparaison severity</label>
          <select id="severityOp" onchange="generate()">
            <option value="." selected>. (cette severity et plus grave)</option>
            <option value=".=">.= (exactement cette severity)</option>
            <option value=".!">.! (sauf cette severity)</option>
          </select>
        </div>

        <div class="form-group">
          <label>Destination</label>
          <select id="destType" onchange="generate()">
            <option value="file" selected>Fichier</option>
            <option value="remote">Serveur distant</option>
            <option value="pipe">Pipe/Programme</option>
            <option value="discard">Discard (ignorer)</option>
          </select>
        </div>

        <div class="form-group" id="fileDestGroup">
          <label>Chemin fichier</label>
          <input type="text" id="fileDest" value="/var/log/auth.log" oninput="generate()">
        </div>

        <div class="form-group">
          <label>
            <input type="checkbox" id="syncWrite" onchange="generate()">
            Ecriture synchrone (prefixe -)
          </label>
          <span class="hint">Desactive le buffering pour les logs critiques</span>
        </div>
      </div>

      <!-- TEMPLATE TAB -->
      <div id="template-tab" class="tab-content">
        <div class="form-group">
          <label>Nom du template</label>
          <input type="text" id="templateName" value="CustomFormat" oninput="generate()">
        </div>

        <div class="form-group">
          <label>Format</label>
          <select id="templateFormat" onchange="generate()">
            <option value="traditional">Traditional (like syslog)</option>
            <option value="json" selected>JSON</option>
            <option value="cef">CEF (Common Event Format)</option>
            <option value="custom">Personnalise</option>
          </select>
        </div>

        <div class="form-group" id="customTemplateGroup" style="display:none">
          <label>Template personnalise</label>
          <input type="text" id="customTemplate" value="%timestamp% %hostname% %syslogtag%%msg%\n" oninput="generate()">
        </div>

        <div class="form-group">
          <h4>Variables disponibles</h4>
          <div class="variables-grid">
            <code>%timestamp%</code>
            <code>%hostname%</code>
            <code>%syslogtag%</code>
            <code>%msg%</code>
            <code>%pri%</code>
            <code>%syslogfacility%</code>
            <code>%syslogseverity%</code>
            <code>%programname%</code>
            <code>%procid%</code>
            <code>%fromhost-ip%</code>
          </div>
        </div>
      </div>

      <!-- FORWARD TAB -->
      <div id="forward-tab" class="tab-content">
        <div class="form-group">
          <label>Protocole</label>
          <select id="forwardProto" onchange="generate()">
            <option value="udp">UDP (@@)</option>
            <option value="tcp" selected>TCP (@)</option>
            <option value="relp">RELP (reliable)</option>
          </select>
        </div>

        <div class="form-group">
          <label>Serveur distant</label>
          <input type="text" id="forwardHost" value="logserver.example.com" oninput="generate()">
        </div>

        <div class="form-group">
          <label>Port</label>
          <input type="number" id="forwardPort" value="514" oninput="generate()">
        </div>

        <div class="form-group">
          <label>
            <input type="checkbox" id="forwardTls" onchange="generate()">
            Activer TLS/SSL
          </label>
        </div>

        <div class="form-group" id="tlsGroup" style="display:none">
          <label>CA Certificate</label>
          <input type="text" id="tlsCa" value="/etc/rsyslog.d/ca.pem" oninput="generate()">
        </div>

        <div class="form-group">
          <label>
            <input type="checkbox" id="forwardQueue" onchange="generate()" checked>
            Queue pour resilience
          </label>
          <span class="hint">Buffer local si serveur indisponible</span>
        </div>

        <div class="form-group" id="queueGroup">
          <label>Taille queue (messages)</label>
          <input type="number" id="queueSize" value="10000" oninput="generate()">
        </div>
      </div>

      <!-- INPUT TAB -->
      <div id="input-tab" class="tab-content">
        <div class="form-group">
          <label>Type d'input</label>
          <select id="inputType" onchange="generate()">
            <option value="imudp">UDP (imudp)</option>
            <option value="imtcp" selected>TCP (imtcp)</option>
            <option value="imfile">Fichier (imfile)</option>
            <option value="imjournal">Journald (imjournal)</option>
          </select>
        </div>

        <div class="form-group" id="inputPortGroup">
          <label>Port d'ecoute</label>
          <input type="number" id="inputPort" value="514" oninput="generate()">
        </div>

        <div class="form-group" id="inputFileGroup" style="display:none">
          <label>Chemin fichier a surveiller</label>
          <input type="text" id="inputFile" value="/var/log/app/*.log" oninput="generate()">
        </div>

        <div class="form-group" id="inputTagGroup" style="display:none">
          <label>Tag</label>
          <input type="text" id="inputTag" value="myapp" oninput="generate()">
        </div>

        <div class="form-group" id="inputFacilityGroup" style="display:none">
          <label>Facility</label>
          <select id="inputFacility" onchange="generate()">
            <option value="local0" selected>local0</option>
            <option value="local1">local1</option>
            <option value="local2">local2</option>
            <option value="local3">local3</option>
            <option value="local4">local4</option>
            <option value="local5">local5</option>
            <option value="local6">local6</option>
            <option value="local7">local7</option>
          </select>
        </div>
      </div>
    </div>

    <div class="rsyslog-section">
      <h3>Configuration generee</h3>
      <pre id="configOutput"># Configuration rsyslog</pre>
      <button onclick="copyConfig()">Copier</button>
    </div>
  </div>

  <div class="presets-section">
    <h3>Presets courants</h3>
    <div class="presets-grid">
      <div class="preset-card" onclick="loadPreset('authlog')">
        <h4>Auth Logs</h4>
        <p>Logs authentification separes</p>
      </div>
      <div class="preset-card" onclick="loadPreset('remotesyslog')">
        <h4>Remote Syslog</h4>
        <p>Forwarding TCP vers SIEM</p>
      </div>
      <div class="preset-card" onclick="loadPreset('jsonlog')">
        <h4>JSON Logging</h4>
        <p>Format JSON pour ELK</p>
      </div>
      <div class="preset-card" onclick="loadPreset('filewatch')">
        <h4>File Watch</h4>
        <p>Surveiller fichiers applicatifs</p>
      </div>
      <div class="preset-card" onclick="loadPreset('syslogserver')">
        <h4>Syslog Server</h4>
        <p>Recevoir logs distants</p>
      </div>
      <div class="preset-card" onclick="loadPreset('securityaudit')">
        <h4>Security Audit</h4>
        <p>Logs securite complets</p>
      </div>
    </div>
  </div>

  <div class="reference-section">
    <h3>Reference Facilities & Severities</h3>
    <div class="ref-grid">
      <div>
        <h4>Facilities</h4>
        <table class="ref-table">
          <tr><td>0</td><td>kern</td><td>Messages kernel</td></tr>
          <tr><td>1</td><td>user</td><td>User-level</td></tr>
          <tr><td>2</td><td>mail</td><td>Systeme mail</td></tr>
          <tr><td>3</td><td>daemon</td><td>Daemons systeme</td></tr>
          <tr><td>4</td><td>auth</td><td>Securite/auth</td></tr>
          <tr><td>5</td><td>syslog</td><td>Syslogd interne</td></tr>
          <tr><td>10</td><td>authpriv</td><td>Auth prive</td></tr>
          <tr><td>16-23</td><td>local0-7</td><td>Usage local</td></tr>
        </table>
      </div>
      <div>
        <h4>Severities</h4>
        <table class="ref-table">
          <tr><td>0</td><td>emerg</td><td>Systeme inutilisable</td></tr>
          <tr><td>1</td><td>alert</td><td>Action immediate</td></tr>
          <tr><td>2</td><td>crit</td><td>Conditions critiques</td></tr>
          <tr><td>3</td><td>err</td><td>Erreurs</td></tr>
          <tr><td>4</td><td>warning</td><td>Avertissements</td></tr>
          <tr><td>5</td><td>notice</td><td>Normal significatif</td></tr>
          <tr><td>6</td><td>info</td><td>Informationnel</td></tr>
          <tr><td>7</td><td>debug</td><td>Debug</td></tr>
        </table>
      </div>
    </div>
  </div>
</div>

<style>
.rsyslog-container {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 20px;
}

@media (max-width: 900px) {
  .rsyslog-container {
    grid-template-columns: 1fr;
  }
}

.rsyslog-section, .presets-section, .reference-section {
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
  border-color: var(--md-primary-fg-color);
}

.tab-content {
  display: none;
}

.tab-content.active {
  display: block;
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

.form-group input[type="checkbox"] {
  margin-right: 8px;
}

.hint {
  font-size: 0.8em;
  color: var(--md-default-fg-color--light);
  display: block;
  margin-top: 4px;
}

.variables-grid {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.variables-grid code {
  padding: 4px 8px;
  background: var(--md-default-bg-color);
  border-radius: 4px;
  font-size: 0.85em;
}

#configOutput {
  background: #1e1e1e;
  color: #d4d4d4;
  padding: 15px;
  border-radius: 4px;
  font-size: 0.85em;
  overflow-x: auto;
  white-space: pre-wrap;
  min-height: 200px;
}

.rsyslog-section button {
  margin-top: 10px;
  padding: 8px 16px;
  background: var(--md-primary-fg-color);
  color: white;
  border: none;
  border-radius: 4px;
  cursor: pointer;
}

.presets-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
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

.ref-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 20px;
}

@media (max-width: 600px) {
  .ref-grid {
    grid-template-columns: 1fr;
  }
}

.ref-table {
  width: 100%;
  font-size: 0.85em;
  border-collapse: collapse;
}

.ref-table td {
  padding: 6px 8px;
  border-bottom: 1px solid var(--md-default-fg-color--lightest);
}

.ref-table td:first-child {
  font-family: monospace;
  width: 40px;
}

.ref-table td:nth-child(2) {
  font-family: monospace;
  font-weight: 500;
}
</style>

<script>
let currentTab = 'filter';

function switchTab(tab) {
  currentTab = tab;
  document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));

  event.target.classList.add('active');
  document.getElementById(tab + '-tab').classList.add('active');

  generate();
}

function generate() {
  let config = '';

  // Update visibility
  const inputType = document.getElementById('inputType').value;
  document.getElementById('inputPortGroup').style.display =
    (inputType === 'imudp' || inputType === 'imtcp') ? 'block' : 'none';
  document.getElementById('inputFileGroup').style.display =
    inputType === 'imfile' ? 'block' : 'none';
  document.getElementById('inputTagGroup').style.display =
    inputType === 'imfile' ? 'block' : 'none';
  document.getElementById('inputFacilityGroup').style.display =
    inputType === 'imfile' ? 'block' : 'none';

  const templateFormat = document.getElementById('templateFormat').value;
  document.getElementById('customTemplateGroup').style.display =
    templateFormat === 'custom' ? 'block' : 'none';

  const forwardTls = document.getElementById('forwardTls').checked;
  document.getElementById('tlsGroup').style.display = forwardTls ? 'block' : 'none';

  const forwardQueue = document.getElementById('forwardQueue').checked;
  document.getElementById('queueGroup').style.display = forwardQueue ? 'block' : 'none';

  const destType = document.getElementById('destType').value;
  document.getElementById('fileDestGroup').style.display =
    destType === 'file' ? 'block' : 'none';

  switch(currentTab) {
    case 'filter':
      config = generateFilter();
      break;
    case 'template':
      config = generateTemplate();
      break;
    case 'forward':
      config = generateForward();
      break;
    case 'input':
      config = generateInput();
      break;
  }

  document.getElementById('configOutput').textContent = config;
}

function generateFilter() {
  const facility = document.getElementById('facility').value;
  const severity = document.getElementById('severity').value;
  const severityOp = document.getElementById('severityOp').value;
  const destType = document.getElementById('destType').value;
  const syncWrite = document.getElementById('syncWrite').checked;

  let config = `# Rsyslog Filter Rule
# Fichier: /etc/rsyslog.d/50-custom.conf

`;

  const selector = `${facility}${severityOp}${severity}`;
  let action = '';

  switch(destType) {
    case 'file':
      const fileDest = document.getElementById('fileDest').value;
      action = syncWrite ? fileDest : `-${fileDest}`;
      break;
    case 'remote':
      action = '@logserver:514';
      break;
    case 'pipe':
      action = '|/usr/bin/logger-script';
      break;
    case 'discard':
      action = '~';
      break;
  }

  config += `${selector}    ${action}

# Syntaxe: facility.severity    action
#
# Operateurs severity:
#   .info    = info et plus grave (info, notice, warning, err, crit, alert, emerg)
#   .=info   = exactement info
#   .!info   = tout sauf info
#
# Actions:
#   /path/to/file     = ecrire dans fichier (avec sync)
#   -/path/to/file    = ecrire dans fichier (sans sync, plus rapide)
#   @host:port        = UDP vers serveur distant
#   @@host:port       = TCP vers serveur distant
#   |/path/to/prog    = pipe vers programme
#   ~                 = discard (ignorer)
`;

  return config;
}

function generateTemplate() {
  const name = document.getElementById('templateName').value;
  const format = document.getElementById('templateFormat').value;

  let config = `# Rsyslog Template
# Fichier: /etc/rsyslog.d/10-templates.conf

`;

  let templateContent = '';

  switch(format) {
    case 'traditional':
      templateContent = `"%timestamp% %hostname% %syslogtag%%msg%\\n"`;
      break;
    case 'json':
      templateContent = `"{\\\"@timestamp\\\":\\\"%timestamp:::date-rfc3339%\\\",\\\"host\\\":\\\"%hostname%\\\",\\\"severity\\\":\\\"%syslogseverity-text%\\\",\\\"facility\\\":\\\"%syslogfacility-text%\\\",\\\"tag\\\":\\\"%syslogtag%\\\",\\\"message\\\":\\\"%msg:::json%\\\"}\\n"`;
      break;
    case 'cef':
      templateContent = `"CEF:0|%hostname%|syslog|1.0|%syslogfacility%|%msg%|%syslogseverity%|src=%fromhost-ip% spt=%source% dst=%hostname%\\n"`;
      break;
    case 'custom':
      const custom = document.getElementById('customTemplate').value;
      templateContent = `"${custom.replace(/"/g, '\\"')}"`;
      break;
  }

  config += `template(name="${name}" type="string"
  string=${templateContent}
)

# Utilisation du template:
# *.* action(type="omfile" file="/var/log/custom.log" template="${name}")

# Ou syntaxe legacy:
# $template ${name}, ${templateContent}
# *.* /var/log/custom.log;${name}
`;

  if (format === 'json') {
    config += `
# Pour ELK Stack, ajoutez aussi:
# module(load="mmjsonparse")
# action(type="mmjsonparse")
`;
  }

  return config;
}

function generateForward() {
  const proto = document.getElementById('forwardProto').value;
  const host = document.getElementById('forwardHost').value;
  const port = document.getElementById('forwardPort').value;
  const tls = document.getElementById('forwardTls').checked;
  const queue = document.getElementById('forwardQueue').checked;
  const queueSize = document.getElementById('queueSize').value;

  let config = `# Rsyslog Forwarding Configuration
# Fichier: /etc/rsyslog.d/60-forward.conf

`;

  if (proto === 'relp') {
    config += `# Charger le module RELP
module(load="omrelp")

`;
  }

  if (tls) {
    const ca = document.getElementById('tlsCa').value;
    config += `# Configuration TLS
global(
  defaultNetstreamDriver="gtls"
  defaultNetstreamDriverCAFile="${ca}"
)

`;
  }

  config += `# Action de forwarding
*.* action(type="om${proto === 'relp' ? 'relp' : 'fwd'}"
  target="${host}"
  port="${port}"
  protocol="${proto === 'relp' ? 'relp' : proto}"`;

  if (tls && proto !== 'relp') {
    config += `
  streamDriver="gtls"
  streamDriverMode="1"
  streamDriverAuthMode="x509/name"`;
  }

  if (queue) {
    config += `

  # Queue pour resilience
  queue.type="LinkedList"
  queue.size="${queueSize}"
  queue.filename="fwd_queue"
  queue.saveonshutdown="on"
  action.resumeRetryCount="-1"
  action.resumeInterval="30"`;
  }

  config += `
)

# Syntaxe legacy equivalente:
# *.* ${proto === 'tcp' ? '@@' : '@'}${host}:${port}
`;

  return config;
}

function generateInput() {
  const inputType = document.getElementById('inputType').value;
  const port = document.getElementById('inputPort').value;
  const file = document.getElementById('inputFile').value;
  const tag = document.getElementById('inputTag').value;
  const facility = document.getElementById('inputFacility').value;

  let config = `# Rsyslog Input Configuration
# Fichier: /etc/rsyslog.d/20-inputs.conf

`;

  switch(inputType) {
    case 'imudp':
      config += `# Module UDP
module(load="imudp")
input(type="imudp" port="${port}")

# Pour plusieurs ports:
# input(type="imudp" port="514")
# input(type="imudp" port="1514")
`;
      break;

    case 'imtcp':
      config += `# Module TCP
module(load="imtcp")
input(type="imtcp" port="${port}")

# Avec rate limiting:
# input(type="imtcp" port="${port}" maxSessions="500" rateLimit.interval="1" rateLimit.burst="10000")
`;
      break;

    case 'imfile':
      config += `# Module File Monitoring
module(load="imfile")

input(type="imfile"
  file="${file}"
  tag="${tag}:"
  facility="${facility}"
  severity="info"
  freshStartTail="on"
  reopenOnTruncate="on"
)

# freshStartTail=on : commence a la fin du fichier au demarrage
# reopenOnTruncate=on : gere la rotation de logs
`;
      break;

    case 'imjournal':
      config += `# Module Journald
module(load="imjournal"
  StateFile="imjournal.state"
  ratelimit.interval="600"
  ratelimit.burst="20000"
)

# Filtrer par unite systemd:
# if $!_SYSTEMD_UNIT == "nginx.service" then /var/log/nginx-journal.log
`;
      break;
  }

  return config;
}

function loadPreset(name) {
  switch(name) {
    case 'authlog':
      switchTabDirect('filter');
      document.getElementById('facility').value = 'authpriv';
      document.getElementById('severity').value = 'info';
      document.getElementById('destType').value = 'file';
      document.getElementById('fileDest').value = '/var/log/auth.log';
      break;

    case 'remotesyslog':
      switchTabDirect('forward');
      document.getElementById('forwardProto').value = 'tcp';
      document.getElementById('forwardHost').value = 'siem.example.com';
      document.getElementById('forwardPort').value = '514';
      document.getElementById('forwardQueue').checked = true;
      break;

    case 'jsonlog':
      switchTabDirect('template');
      document.getElementById('templateName').value = 'JsonFormat';
      document.getElementById('templateFormat').value = 'json';
      break;

    case 'filewatch':
      switchTabDirect('input');
      document.getElementById('inputType').value = 'imfile';
      document.getElementById('inputFile').value = '/var/log/app/*.log';
      document.getElementById('inputTag').value = 'myapp';
      break;

    case 'syslogserver':
      switchTabDirect('input');
      document.getElementById('inputType').value = 'imtcp';
      document.getElementById('inputPort').value = '514';
      break;

    case 'securityaudit':
      switchTabDirect('filter');
      document.getElementById('facility').value = 'authpriv';
      document.getElementById('severity').value = '*';
      document.getElementById('destType').value = 'file';
      document.getElementById('fileDest').value = '/var/log/security/audit.log';
      document.getElementById('syncWrite').checked = true;
      break;
  }
  generate();
}

function switchTabDirect(tab) {
  currentTab = tab;
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.classList.toggle('active', btn.textContent.toLowerCase().includes(tab));
  });
  document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
  document.getElementById(tab + '-tab').classList.add('active');
}

function copyConfig() {
  const config = document.getElementById('configOutput').textContent;
  navigator.clipboard.writeText(config).then(() => {
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

## Installation

```bash
# Verifier la syntaxe
rsyslogd -N1

# Recharger la configuration
systemctl restart rsyslog

# Tester
logger -p local0.info "Test message"
```

---

## Voir aussi

- [Logrotate Config Generator](logrotate-generator.md)
- [Log Levels Reference](log-levels.md)
- [Fail2Ban Jail Generator](fail2ban-generator.md)
