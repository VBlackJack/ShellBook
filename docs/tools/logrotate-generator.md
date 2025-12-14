---
tags:
  - tools
  - logging
  - logrotate
  - maintenance
---

# Logrotate Config Generator

Generateur de configuration logrotate pour la rotation automatique des logs.

<div id="logrotate-app">
  <div class="logrotate-container">
    <div class="logrotate-section">
      <h3>Configuration</h3>

      <div class="form-group">
        <label>Chemin des logs</label>
        <input type="text" id="logPath" value="/var/log/myapp/*.log" oninput="generate()">
        <span class="hint">Supporte les wildcards: *.log, app-*.log</span>
      </div>

      <div class="form-group">
        <label>Frequence de rotation</label>
        <select id="frequency" onchange="generate()">
          <option value="hourly">Horaire</option>
          <option value="daily" selected>Journaliere</option>
          <option value="weekly">Hebdomadaire</option>
          <option value="monthly">Mensuelle</option>
          <option value="yearly">Annuelle</option>
        </select>
      </div>

      <div class="form-group">
        <label>Nombre de rotations a conserver</label>
        <input type="number" id="rotate" value="7" min="1" max="365" oninput="generate()">
      </div>

      <div class="form-group">
        <label>Taille max avant rotation (optionnel)</label>
        <div class="size-input">
          <input type="number" id="sizeValue" value="" placeholder="Ex: 100" oninput="generate()">
          <select id="sizeUnit" onchange="generate()">
            <option value="k">KB</option>
            <option value="M" selected>MB</option>
            <option value="G">GB</option>
          </select>
        </div>
        <span class="hint">Laissez vide pour rotation basee uniquement sur la frequence</span>
      </div>

      <h4>Options de compression</h4>

      <div class="form-group">
        <label>
          <input type="checkbox" id="compress" onchange="generate()" checked>
          Compresser les logs rotates
        </label>
      </div>

      <div class="form-group" id="compressOptions">
        <label>
          <input type="checkbox" id="delaycompress" onchange="generate()" checked>
          Delayer la compression (delaycompress)
        </label>
        <span class="hint">Ne compresse pas le log le plus recent (utile si l'app ecrit encore dedans)</span>
      </div>

      <div class="form-group" id="compressCmd">
        <label>Programme de compression</label>
        <select id="compresscmd" onchange="generate()">
          <option value="gzip" selected>gzip (.gz)</option>
          <option value="bzip2">bzip2 (.bz2)</option>
          <option value="xz">xz (.xz)</option>
          <option value="zstd">zstd (.zst)</option>
        </select>
      </div>

      <h4>Options de fichier</h4>

      <div class="form-group">
        <label>
          <input type="checkbox" id="missingok" onchange="generate()" checked>
          missingok - Ne pas generer d'erreur si le fichier manque
        </label>
      </div>

      <div class="form-group">
        <label>
          <input type="checkbox" id="notifempty" onchange="generate()" checked>
          notifempty - Ne pas rotater si le fichier est vide
        </label>
      </div>

      <div class="form-group">
        <label>
          <input type="checkbox" id="copytruncate" onchange="generate()">
          copytruncate - Copier puis tronquer (au lieu de rename)
        </label>
        <span class="hint">Pour les apps qui gardent le fichier ouvert</span>
      </div>

      <div class="form-group">
        <label>
          <input type="checkbox" id="create" onchange="generate()" checked>
          Creer un nouveau fichier apres rotation
        </label>
      </div>

      <div class="form-group" id="createOptions">
        <label>Permissions du nouveau fichier</label>
        <div class="create-input">
          <input type="text" id="createMode" value="0640" size="5" oninput="generate()">
          <input type="text" id="createOwner" value="root" placeholder="owner" oninput="generate()">
          <input type="text" id="createGroup" value="adm" placeholder="group" oninput="generate()">
        </div>
      </div>

      <div class="form-group">
        <label>
          <input type="checkbox" id="dateext" onchange="generate()" checked>
          dateext - Utiliser la date dans le nom (au lieu de .1, .2...)
        </label>
      </div>

      <div class="form-group" id="dateFormatGroup">
        <label>Format de date</label>
        <select id="dateformat" onchange="generate()">
          <option value="-%Y%m%d" selected>-YYYYMMDD</option>
          <option value="-%Y-%m-%d">-YYYY-MM-DD</option>
          <option value="-%Y%m%d%H">-YYYYMMDDHH</option>
          <option value=".%Y%m%d">.YYYYMMDD</option>
        </select>
      </div>

      <h4>Scripts (optionnel)</h4>

      <div class="form-group">
        <label>
          <input type="checkbox" id="usePostrotate" onchange="generate()">
          Ajouter un script postrotate
        </label>
      </div>

      <div class="form-group" id="postrotateGroup" style="display:none">
        <label>Commande postrotate</label>
        <select id="postrotatePreset" onchange="updatePostrotate()">
          <option value="custom">Personnalise</option>
          <option value="nginx">Nginx reload</option>
          <option value="apache">Apache reload</option>
          <option value="rsyslog">Rsyslog restart</option>
          <option value="systemd">Systemd service</option>
        </select>
        <textarea id="postrotate" rows="3" oninput="generate()">/usr/bin/systemctl reload myapp</textarea>
      </div>

      <div class="form-group">
        <label>
          <input type="checkbox" id="sharedscripts" onchange="generate()">
          sharedscripts - Executer le script une seule fois pour tous les fichiers
        </label>
      </div>
    </div>

    <div class="logrotate-section">
      <h3>Configuration generee</h3>
      <pre id="configOutput"># logrotate config</pre>
      <button onclick="copyConfig()">Copier</button>

      <div class="install-info">
        <h4>Installation</h4>
        <pre id="installCmd"># Sauvegarder dans /etc/logrotate.d/myapp</pre>
        <button onclick="copyInstall()">Copier</button>
      </div>
    </div>
  </div>

  <div class="presets-section">
    <h3>Presets courants</h3>
    <div class="presets-grid">
      <div class="preset-card" onclick="loadPreset('nginx')">
        <h4>Nginx</h4>
        <p>Logs Nginx avec reload</p>
      </div>
      <div class="preset-card" onclick="loadPreset('apache')">
        <h4>Apache</h4>
        <p>Logs Apache avec graceful</p>
      </div>
      <div class="preset-card" onclick="loadPreset('syslog')">
        <h4>Syslog</h4>
        <p>Logs systeme standards</p>
      </div>
      <div class="preset-card" onclick="loadPreset('docker')">
        <h4>Docker</h4>
        <p>Logs containers Docker</p>
      </div>
      <div class="preset-card" onclick="loadPreset('app')">
        <h4>Application</h4>
        <p>Logs applicatifs generiques</p>
      </div>
      <div class="preset-card" onclick="loadPreset('audit')">
        <h4>Audit/Securite</h4>
        <p>Retention longue, pas de compression</p>
      </div>
    </div>
  </div>

  <div class="reference-section">
    <h3>Reference rapide</h3>
    <table class="ref-table">
      <tr><td><code>daily/weekly/monthly</code></td><td>Frequence de rotation</td></tr>
      <tr><td><code>rotate N</code></td><td>Garder N fichiers rotates</td></tr>
      <tr><td><code>size 100M</code></td><td>Rotater si > 100MB</td></tr>
      <tr><td><code>maxsize 100M</code></td><td>Rotater si > 100MB meme si pas l'heure</td></tr>
      <tr><td><code>minsize 100M</code></td><td>Ne pas rotater si < 100MB</td></tr>
      <tr><td><code>compress</code></td><td>Compresser avec gzip</td></tr>
      <tr><td><code>delaycompress</code></td><td>Ne pas compresser le plus recent</td></tr>
      <tr><td><code>copytruncate</code></td><td>Copier puis tronquer</td></tr>
      <tr><td><code>create 0640 user group</code></td><td>Creer nouveau fichier</td></tr>
      <tr><td><code>dateext</code></td><td>Suffixe date au lieu de numero</td></tr>
      <tr><td><code>olddir /path</code></td><td>Deplacer les rotates ailleurs</td></tr>
      <tr><td><code>postrotate...endscript</code></td><td>Script apres rotation</td></tr>
    </table>
  </div>
</div>

<style>
.logrotate-container {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 20px;
}

@media (max-width: 900px) {
  .logrotate-container {
    grid-template-columns: 1fr;
  }
}

.logrotate-section, .presets-section, .reference-section {
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

.size-input, .create-input {
  display: flex;
  gap: 10px;
}

.size-input input {
  flex: 1;
}

.size-input select {
  width: 80px;
}

.create-input input {
  flex: 1;
}

.create-input input:first-child {
  width: 80px;
  flex: none;
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

#configOutput {
  min-height: 250px;
}

.logrotate-section button {
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
}

.ref-table td:first-child {
  width: 40%;
}

.ref-table code {
  background: var(--md-default-bg-color);
  padding: 2px 6px;
  border-radius: 3px;
}
</style>

<script>
function generate() {
  const logPath = document.getElementById('logPath').value;
  const frequency = document.getElementById('frequency').value;
  const rotate = document.getElementById('rotate').value;
  const sizeValue = document.getElementById('sizeValue').value;
  const sizeUnit = document.getElementById('sizeUnit').value;

  const compress = document.getElementById('compress').checked;
  const delaycompress = document.getElementById('delaycompress').checked;
  const compresscmd = document.getElementById('compresscmd').value;

  const missingok = document.getElementById('missingok').checked;
  const notifempty = document.getElementById('notifempty').checked;
  const copytruncate = document.getElementById('copytruncate').checked;
  const create = document.getElementById('create').checked;
  const createMode = document.getElementById('createMode').value;
  const createOwner = document.getElementById('createOwner').value;
  const createGroup = document.getElementById('createGroup').value;

  const dateext = document.getElementById('dateext').checked;
  const dateformat = document.getElementById('dateformat').value;

  const usePostrotate = document.getElementById('usePostrotate').checked;
  const postrotate = document.getElementById('postrotate').value;
  const sharedscripts = document.getElementById('sharedscripts').checked;

  // Update visibility
  document.getElementById('compressOptions').style.display = compress ? 'block' : 'none';
  document.getElementById('compressCmd').style.display = compress ? 'block' : 'none';
  document.getElementById('createOptions').style.display = create ? 'block' : 'none';
  document.getElementById('dateFormatGroup').style.display = dateext ? 'block' : 'none';
  document.getElementById('postrotateGroup').style.display = usePostrotate ? 'block' : 'none';

  let config = `${logPath} {\n`;
  config += `    ${frequency}\n`;
  config += `    rotate ${rotate}\n`;

  if (sizeValue) {
    config += `    size ${sizeValue}${sizeUnit}\n`;
  }

  if (missingok) config += `    missingok\n`;
  if (notifempty) config += `    notifempty\n`;

  if (compress) {
    config += `    compress\n`;
    if (delaycompress) config += `    delaycompress\n`;
    if (compresscmd !== 'gzip') {
      config += `    compresscmd /usr/bin/${compresscmd}\n`;
      const ext = {bzip2: '.bz2', xz: '.xz', zstd: '.zst'}[compresscmd];
      config += `    compressext ${ext}\n`;
    }
  } else {
    config += `    nocompress\n`;
  }

  if (copytruncate) {
    config += `    copytruncate\n`;
  } else if (create) {
    config += `    create ${createMode} ${createOwner} ${createGroup}\n`;
  }

  if (dateext) {
    config += `    dateext\n`;
    config += `    dateformat ${dateformat}\n`;
  }

  if (usePostrotate) {
    if (sharedscripts) config += `    sharedscripts\n`;
    config += `    postrotate\n`;
    config += `        ${postrotate}\n`;
    config += `    endscript\n`;
  }

  config += `}`;

  document.getElementById('configOutput').textContent = config;

  // Extract app name from path for install command
  const appName = logPath.split('/').pop().replace(/[*?.]/g, '').replace('.log', '') || 'myapp';
  const installCmd = `# Sauvegarder la configuration
sudo tee /etc/logrotate.d/${appName} << 'EOF'
${config}
EOF

# Tester la configuration
sudo logrotate -d /etc/logrotate.d/${appName}

# Forcer une rotation (test)
sudo logrotate -f /etc/logrotate.d/${appName}`;

  document.getElementById('installCmd').textContent = installCmd;
}

function updatePostrotate() {
  const preset = document.getElementById('postrotatePreset').value;
  const postrotate = document.getElementById('postrotate');

  switch(preset) {
    case 'nginx':
      postrotate.value = '/usr/sbin/nginx -s reopen';
      break;
    case 'apache':
      postrotate.value = '/usr/sbin/apachectl graceful';
      break;
    case 'rsyslog':
      postrotate.value = '/usr/bin/systemctl kill -s HUP rsyslog.service';
      break;
    case 'systemd':
      postrotate.value = '/usr/bin/systemctl reload myapp.service';
      break;
    case 'custom':
      postrotate.value = '';
      break;
  }
  generate();
}

function loadPreset(name) {
  switch(name) {
    case 'nginx':
      document.getElementById('logPath').value = '/var/log/nginx/*.log';
      document.getElementById('frequency').value = 'daily';
      document.getElementById('rotate').value = '14';
      document.getElementById('compress').checked = true;
      document.getElementById('delaycompress').checked = true;
      document.getElementById('missingok').checked = true;
      document.getElementById('notifempty').checked = true;
      document.getElementById('copytruncate').checked = false;
      document.getElementById('create').checked = true;
      document.getElementById('createMode').value = '0640';
      document.getElementById('createOwner').value = 'www-data';
      document.getElementById('createGroup').value = 'adm';
      document.getElementById('dateext').checked = true;
      document.getElementById('usePostrotate').checked = true;
      document.getElementById('postrotatePreset').value = 'nginx';
      document.getElementById('postrotate').value = '/usr/sbin/nginx -s reopen';
      document.getElementById('sharedscripts').checked = true;
      break;

    case 'apache':
      document.getElementById('logPath').value = '/var/log/apache2/*.log';
      document.getElementById('frequency').value = 'daily';
      document.getElementById('rotate').value = '14';
      document.getElementById('compress').checked = true;
      document.getElementById('delaycompress').checked = true;
      document.getElementById('missingok').checked = true;
      document.getElementById('notifempty').checked = true;
      document.getElementById('copytruncate').checked = false;
      document.getElementById('create').checked = true;
      document.getElementById('createMode').value = '0640';
      document.getElementById('createOwner').value = 'root';
      document.getElementById('createGroup').value = 'adm';
      document.getElementById('dateext').checked = true;
      document.getElementById('usePostrotate').checked = true;
      document.getElementById('postrotatePreset').value = 'apache';
      document.getElementById('postrotate').value = '/usr/sbin/apachectl graceful';
      document.getElementById('sharedscripts').checked = true;
      break;

    case 'syslog':
      document.getElementById('logPath').value = '/var/log/syslog';
      document.getElementById('frequency').value = 'daily';
      document.getElementById('rotate').value = '7';
      document.getElementById('compress').checked = true;
      document.getElementById('delaycompress').checked = true;
      document.getElementById('missingok').checked = false;
      document.getElementById('notifempty').checked = true;
      document.getElementById('copytruncate').checked = false;
      document.getElementById('create').checked = true;
      document.getElementById('createMode').value = '0640';
      document.getElementById('createOwner').value = 'syslog';
      document.getElementById('createGroup').value = 'adm';
      document.getElementById('dateext').checked = true;
      document.getElementById('usePostrotate').checked = true;
      document.getElementById('postrotatePreset').value = 'rsyslog';
      document.getElementById('postrotate').value = '/usr/bin/systemctl kill -s HUP rsyslog.service';
      document.getElementById('sharedscripts').checked = true;
      break;

    case 'docker':
      document.getElementById('logPath').value = '/var/lib/docker/containers/*/*.log';
      document.getElementById('frequency').value = 'daily';
      document.getElementById('rotate').value = '7';
      document.getElementById('sizeValue').value = '100';
      document.getElementById('sizeUnit').value = 'M';
      document.getElementById('compress').checked = true;
      document.getElementById('delaycompress').checked = false;
      document.getElementById('missingok').checked = true;
      document.getElementById('notifempty').checked = true;
      document.getElementById('copytruncate').checked = true;
      document.getElementById('create').checked = false;
      document.getElementById('dateext').checked = true;
      document.getElementById('usePostrotate').checked = false;
      break;

    case 'app':
      document.getElementById('logPath').value = '/var/log/myapp/*.log';
      document.getElementById('frequency').value = 'daily';
      document.getElementById('rotate').value = '30';
      document.getElementById('sizeValue').value = '50';
      document.getElementById('sizeUnit').value = 'M';
      document.getElementById('compress').checked = true;
      document.getElementById('delaycompress').checked = true;
      document.getElementById('missingok').checked = true;
      document.getElementById('notifempty').checked = true;
      document.getElementById('copytruncate').checked = true;
      document.getElementById('create').checked = false;
      document.getElementById('dateext').checked = true;
      document.getElementById('usePostrotate').checked = false;
      break;

    case 'audit':
      document.getElementById('logPath').value = '/var/log/audit/*.log';
      document.getElementById('frequency').value = 'monthly';
      document.getElementById('rotate').value = '12';
      document.getElementById('sizeValue').value = '';
      document.getElementById('compress').checked = false;
      document.getElementById('missingok').checked = false;
      document.getElementById('notifempty').checked = false;
      document.getElementById('copytruncate').checked = false;
      document.getElementById('create').checked = true;
      document.getElementById('createMode').value = '0600';
      document.getElementById('createOwner').value = 'root';
      document.getElementById('createGroup').value = 'root';
      document.getElementById('dateext').checked = true;
      document.getElementById('usePostrotate').checked = false;
      break;
  }
  generate();
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

## Commandes utiles

```bash
# Tester une config sans executer
logrotate -d /etc/logrotate.d/myapp

# Forcer la rotation
logrotate -f /etc/logrotate.d/myapp

# Voir le statut des rotations
cat /var/lib/logrotate/status

# Debug verbose
logrotate -v /etc/logrotate.conf
```

---

## Voir aussi

- [Rsyslog Config Generator](rsyslog-generator.md)
- [Log Levels Reference](log-levels.md)
- [Systemd Unit Generator](systemd-generator.md)
