---
tags:
  - tools
  - linux
  - security
  - sudoers
  - permissions
---

# Sudoers Builder

Generateur de regles sudoers avec validation de syntaxe.

<div id="sudoers-app">
  <div class="sudoers-container">
    <div class="builder-section">
      <h3>Configuration de la regle</h3>

      <div class="form-group">
        <label>Type d'identite</label>
        <div class="radio-group">
          <label><input type="radio" name="identityType" value="user" checked onchange="updateRule()"> Utilisateur</label>
          <label><input type="radio" name="identityType" value="group" onchange="updateRule()"> Groupe (%)</label>
          <label><input type="radio" name="identityType" value="alias" onchange="updateRule()"> User_Alias</label>
        </div>
      </div>

      <div class="form-group">
        <label>Nom (utilisateur/groupe/alias)</label>
        <input type="text" id="identity" value="admin" placeholder="admin, %wheel, ADMINS" oninput="updateRule()">
      </div>

      <div class="form-group">
        <label>Hotes</label>
        <input type="text" id="hosts" value="ALL" placeholder="ALL, localhost, 192.168.1.0/24" oninput="updateRule()">
        <span class="hint">ALL = tous les hotes</span>
      </div>

      <div class="form-group">
        <label>Executer en tant que (RunAs)</label>
        <div class="runas-inputs">
          <input type="text" id="runasUser" value="ALL" placeholder="root, ALL" oninput="updateRule()">
          <span>:</span>
          <input type="text" id="runasGroup" value="" placeholder="groupe (optionnel)" oninput="updateRule()">
        </div>
        <span class="hint">Utilisateur : Groupe (ex: root:wheel)</span>
      </div>

      <div class="form-group">
        <label>Commandes</label>
        <textarea id="commands" placeholder="/usr/bin/systemctl, /usr/bin/apt, ALL" oninput="updateRule()">ALL</textarea>
        <span class="hint">Une commande par ligne ou separees par virgules</span>
      </div>

      <div class="form-group">
        <label>Options</label>
        <div class="options-grid">
          <label class="option-item">
            <input type="checkbox" id="optNopasswd" onchange="updateRule()">
            <span>NOPASSWD</span>
            <small>Pas de mot de passe</small>
          </label>
          <label class="option-item">
            <input type="checkbox" id="optNoexec" onchange="updateRule()">
            <span>NOEXEC</span>
            <small>Empeche l'execution de sous-commandes</small>
          </label>
          <label class="option-item">
            <input type="checkbox" id="optSetenv" onchange="updateRule()">
            <span>SETENV</span>
            <small>Permet de definir des variables d'env</small>
          </label>
          <label class="option-item">
            <input type="checkbox" id="optNosetenv" onchange="updateRule()">
            <span>NOSETENV</span>
            <small>Interdit les variables d'env</small>
          </label>
          <label class="option-item">
            <input type="checkbox" id="optLog" onchange="updateRule()">
            <span>LOG_INPUT</span>
            <small>Log les entrees</small>
          </label>
          <label class="option-item">
            <input type="checkbox" id="optLogOutput" onchange="updateRule()">
            <span>LOG_OUTPUT</span>
            <small>Log les sorties</small>
          </label>
        </div>
      </div>

      <h3>Presets courants</h3>
      <div class="presets-grid">
        <button onclick="loadPreset('admin')">Admin complet</button>
        <button onclick="loadPreset('wheel')">Groupe wheel</button>
        <button onclick="loadPreset('deploy')">Deploiement</button>
        <button onclick="loadPreset('docker')">Docker</button>
        <button onclick="loadPreset('systemd')">Systemd</button>
        <button onclick="loadPreset('network')">Reseau</button>
        <button onclick="loadPreset('backup')">Backup</button>
        <button onclick="loadPreset('monitoring')">Monitoring</button>
      </div>
    </div>

    <div class="output-section">
      <h3>Regle generee</h3>
      <div class="rule-output">
        <pre id="ruleOutput">admin ALL=(ALL) ALL</pre>
        <button onclick="copyRule()" class="btn-copy">Copier</button>
      </div>

      <div id="validation" class="validation-box valid">
        <span class="icon">✓</span>
        <span class="message">Syntaxe valide</span>
      </div>

      <h3>Fichier complet</h3>
      <div class="file-output">
        <pre id="fileOutput"># /etc/sudoers.d/custom-rules
# Genere par ShellBook Sudoers Builder

admin ALL=(ALL) ALL</pre>
        <button onclick="copyFile()" class="btn-copy">Copier</button>
      </div>

      <h3>Commandes d'installation</h3>
      <div class="install-commands">
        <pre id="installCmd"># Creer le fichier (TOUJOURS utiliser visudo!)
sudo visudo -f /etc/sudoers.d/custom-rules

# Ou via echo (risque)
echo 'admin ALL=(ALL) ALL' | sudo tee /etc/sudoers.d/custom-rules
sudo chmod 440 /etc/sudoers.d/custom-rules

# Verifier la syntaxe
sudo visudo -c -f /etc/sudoers.d/custom-rules</pre>
      </div>
    </div>
  </div>

  <div class="aliases-section">
    <h3>Generateur d'Alias</h3>
    <div class="alias-tabs">
      <button class="alias-tab active" onclick="showAliasTab('user')">User_Alias</button>
      <button class="alias-tab" onclick="showAliasTab('host')">Host_Alias</button>
      <button class="alias-tab" onclick="showAliasTab('cmnd')">Cmnd_Alias</button>
      <button class="alias-tab" onclick="showAliasTab('runas')">Runas_Alias</button>
    </div>

    <div id="aliasContent" class="alias-content">
      <div class="alias-form">
        <div class="form-group">
          <label>Nom de l'alias</label>
          <input type="text" id="aliasName" placeholder="ADMINS, WEBSERVERS, NETWORK_CMDS" oninput="updateAlias()">
        </div>
        <div class="form-group">
          <label>Membres (separes par virgules)</label>
          <textarea id="aliasMembers" placeholder="user1, user2, user3" oninput="updateAlias()"></textarea>
        </div>
        <div class="alias-output">
          <pre id="aliasOutput">User_Alias ADMINS = user1, user2, user3</pre>
          <button onclick="copyAlias()" class="btn-copy">Copier</button>
        </div>
      </div>
    </div>
  </div>

  <div class="reference-section">
    <h3>Reference Syntaxe</h3>
    <table class="ref-table">
      <tr>
        <th>Element</th>
        <th>Description</th>
        <th>Exemples</th>
      </tr>
      <tr>
        <td><code>ALL</code></td>
        <td>Wildcard universel</td>
        <td>Tous les hotes, users, commandes</td>
      </tr>
      <tr>
        <td><code>%groupe</code></td>
        <td>Groupe systeme</td>
        <td>%wheel, %sudo, %admin</td>
      </tr>
      <tr>
        <td><code>!</code></td>
        <td>Negation</td>
        <td>ALL, !/bin/su</td>
      </tr>
      <tr>
        <td><code>NOPASSWD:</code></td>
        <td>Sans mot de passe</td>
        <td>NOPASSWD: /usr/bin/apt</td>
      </tr>
      <tr>
        <td><code>sha256:</code></td>
        <td>Verification hash</td>
        <td>sha256:abc123... /path/cmd</td>
      </tr>
    </table>
  </div>
</div>

<style>
.sudoers-container {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 20px;
}

@media (max-width: 900px) {
  .sudoers-container {
    grid-template-columns: 1fr;
  }
}

.builder-section, .output-section {
  background: var(--md-code-bg-color);
  padding: 20px;
  border-radius: 8px;
}

.form-group {
  margin-bottom: 15px;
}

.form-group label {
  display: block;
  font-weight: 500;
  margin-bottom: 5px;
  font-size: 0.9em;
}

.form-group input[type="text"],
.form-group textarea,
.form-group select {
  width: 100%;
  padding: 10px;
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  background: var(--md-default-bg-color);
  color: var(--md-default-fg-color);
  font-family: monospace;
}

.form-group textarea {
  min-height: 80px;
  resize: vertical;
}

.form-group .hint {
  font-size: 0.8em;
  color: var(--md-default-fg-color--light);
  margin-top: 4px;
  display: block;
}

.radio-group {
  display: flex;
  gap: 20px;
  flex-wrap: wrap;
}

.radio-group label {
  display: flex;
  align-items: center;
  gap: 5px;
  font-weight: normal;
  cursor: pointer;
}

.runas-inputs {
  display: flex;
  gap: 10px;
  align-items: center;
}

.runas-inputs input {
  flex: 1;
}

.runas-inputs span {
  font-weight: bold;
  color: var(--md-default-fg-color--light);
}

.options-grid {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 10px;
}

@media (max-width: 600px) {
  .options-grid {
    grid-template-columns: 1fr;
  }
}

.option-item {
  display: flex;
  flex-direction: column;
  padding: 10px;
  background: var(--md-default-bg-color);
  border-radius: 4px;
  cursor: pointer;
}

.option-item input {
  margin-bottom: 5px;
}

.option-item span {
  font-family: monospace;
  font-weight: 600;
  font-size: 0.9em;
}

.option-item small {
  font-size: 0.75em;
  color: var(--md-default-fg-color--light);
}

.presets-grid {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 8px;
}

@media (max-width: 600px) {
  .presets-grid {
    grid-template-columns: repeat(2, 1fr);
  }
}

.presets-grid button {
  padding: 8px 12px;
  border: 1px solid var(--md-primary-fg-color);
  background: transparent;
  color: var(--md-primary-fg-color);
  border-radius: 4px;
  cursor: pointer;
  font-size: 0.85em;
}

.presets-grid button:hover {
  background: var(--md-primary-fg-color);
  color: white;
}

.rule-output, .file-output, .install-commands {
  position: relative;
  margin-bottom: 15px;
}

.rule-output pre, .file-output pre, .install-commands pre {
  background: #1e1e1e;
  color: #d4d4d4;
  padding: 15px;
  border-radius: 4px;
  overflow-x: auto;
  font-size: 0.9em;
  margin: 0;
}

.btn-copy {
  position: absolute;
  top: 10px;
  right: 10px;
  padding: 5px 10px;
  background: #333;
  border: 1px solid #555;
  color: #d4d4d4;
  border-radius: 4px;
  cursor: pointer;
  font-size: 0.8em;
}

.btn-copy:hover {
  background: #444;
}

.validation-box {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 12px 15px;
  border-radius: 4px;
  margin-bottom: 15px;
}

.validation-box.valid {
  background: #d4edda;
  color: #155724;
}

.validation-box.warning {
  background: #fff3cd;
  color: #856404;
}

.validation-box.error {
  background: #f8d7da;
  color: #721c24;
}

.validation-box .icon {
  font-size: 1.2em;
}

.aliases-section {
  margin-top: 20px;
  background: var(--md-code-bg-color);
  padding: 20px;
  border-radius: 8px;
}

.alias-tabs {
  display: flex;
  gap: 5px;
  margin-bottom: 15px;
}

.alias-tab {
  padding: 8px 16px;
  border: 1px solid var(--md-default-fg-color--lightest);
  background: var(--md-default-bg-color);
  color: var(--md-default-fg-color);
  border-radius: 4px;
  cursor: pointer;
}

.alias-tab.active {
  background: var(--md-primary-fg-color);
  color: white;
  border-color: var(--md-primary-fg-color);
}

.alias-content {
  background: var(--md-default-bg-color);
  padding: 15px;
  border-radius: 4px;
}

.alias-output {
  position: relative;
  margin-top: 15px;
}

.alias-output pre {
  background: #1e1e1e;
  color: #d4d4d4;
  padding: 15px;
  border-radius: 4px;
  margin: 0;
}

.reference-section {
  margin-top: 20px;
  background: var(--md-code-bg-color);
  padding: 20px;
  border-radius: 8px;
}

.ref-table {
  width: 100%;
  border-collapse: collapse;
}

.ref-table th, .ref-table td {
  padding: 10px;
  text-align: left;
  border-bottom: 1px solid var(--md-default-fg-color--lightest);
}

.ref-table th {
  background: var(--md-default-bg-color);
}

.ref-table code {
  background: var(--md-default-bg-color);
  padding: 2px 6px;
  border-radius: 3px;
}
</style>

<script>
const presets = {
  admin: {
    identityType: 'user',
    identity: 'admin',
    hosts: 'ALL',
    runasUser: 'ALL',
    runasGroup: '',
    commands: 'ALL',
    options: { nopasswd: false }
  },
  wheel: {
    identityType: 'group',
    identity: 'wheel',
    hosts: 'ALL',
    runasUser: 'ALL',
    runasGroup: 'ALL',
    commands: 'ALL',
    options: { nopasswd: false }
  },
  deploy: {
    identityType: 'user',
    identity: 'deploy',
    hosts: 'ALL',
    runasUser: 'root',
    runasGroup: '',
    commands: '/usr/bin/systemctl restart *, /usr/bin/systemctl reload *, /usr/bin/docker *, /usr/local/bin/deploy.sh',
    options: { nopasswd: true }
  },
  docker: {
    identityType: 'group',
    identity: 'docker-users',
    hosts: 'ALL',
    runasUser: 'root',
    runasGroup: '',
    commands: '/usr/bin/docker, /usr/bin/docker-compose, /usr/local/bin/docker-compose',
    options: { nopasswd: true, noexec: false }
  },
  systemd: {
    identityType: 'user',
    identity: 'svc-account',
    hosts: 'ALL',
    runasUser: 'root',
    runasGroup: '',
    commands: '/usr/bin/systemctl start *, /usr/bin/systemctl stop *, /usr/bin/systemctl restart *, /usr/bin/systemctl status *, /usr/bin/journalctl',
    options: { nopasswd: true }
  },
  network: {
    identityType: 'group',
    identity: 'netadmins',
    hosts: 'ALL',
    runasUser: 'root',
    runasGroup: '',
    commands: '/usr/sbin/ip, /usr/sbin/iptables, /usr/sbin/nft, /usr/bin/ss, /usr/sbin/tcpdump, /usr/bin/firewall-cmd',
    options: { nopasswd: false }
  },
  backup: {
    identityType: 'user',
    identity: 'backup',
    hosts: 'ALL',
    runasUser: 'root',
    runasGroup: '',
    commands: '/usr/bin/rsync, /usr/bin/tar, /usr/bin/restic, /usr/bin/borgbackup, /usr/bin/rclone',
    options: { nopasswd: true, log: true }
  },
  monitoring: {
    identityType: 'user',
    identity: 'nagios',
    hosts: 'ALL',
    runasUser: 'root',
    runasGroup: '',
    commands: '/usr/lib/nagios/plugins/*, /usr/bin/systemctl status *, /usr/bin/journalctl -n *',
    options: { nopasswd: true, noexec: true }
  }
};

let currentAliasType = 'user';

function updateRule() {
  const identityType = document.querySelector('input[name="identityType"]:checked').value;
  let identity = document.getElementById('identity').value.trim() || 'user';
  const hosts = document.getElementById('hosts').value.trim() || 'ALL';
  const runasUser = document.getElementById('runasUser').value.trim() || 'ALL';
  const runasGroup = document.getElementById('runasGroup').value.trim();
  const commands = document.getElementById('commands').value.trim() || 'ALL';

  // Format identity
  if (identityType === 'group' && !identity.startsWith('%')) {
    identity = '%' + identity;
  }

  // Build RunAs
  let runas = runasUser;
  if (runasGroup) {
    runas += ':' + runasGroup;
  }

  // Build options
  const opts = [];
  if (document.getElementById('optNopasswd').checked) opts.push('NOPASSWD:');
  if (document.getElementById('optNoexec').checked) opts.push('NOEXEC:');
  if (document.getElementById('optSetenv').checked) opts.push('SETENV:');
  if (document.getElementById('optNosetenv').checked) opts.push('NOSETENV:');
  if (document.getElementById('optLog').checked) opts.push('LOG_INPUT:');
  if (document.getElementById('optLogOutput').checked) opts.push('LOG_OUTPUT:');

  const optStr = opts.join(' ');

  // Format commands
  const cmdList = commands.split(/[,\n]/).map(c => c.trim()).filter(c => c).join(', ');

  // Build rule
  let rule = `${identity} ${hosts}=(${runas}) `;
  if (optStr) rule += optStr + ' ';
  rule += cmdList;

  document.getElementById('ruleOutput').textContent = rule;

  // Update file output
  const filename = identity.replace('%', '').toLowerCase().replace(/[^a-z0-9]/g, '-');
  document.getElementById('fileOutput').textContent =
`# /etc/sudoers.d/${filename}
# Genere par ShellBook Sudoers Builder
# Verifier avec: sudo visudo -c -f /etc/sudoers.d/${filename}

${rule}`;

  // Update install commands
  document.getElementById('installCmd').textContent =
`# Methode recommandee: utiliser visudo
sudo visudo -f /etc/sudoers.d/${filename}

# Copier-coller cette ligne:
${rule}

# Alternative (attention aux erreurs de syntaxe!)
echo '${rule}' | sudo tee /etc/sudoers.d/${filename}
sudo chmod 440 /etc/sudoers.d/${filename}

# Verifier la syntaxe AVANT de fermer la session!
sudo visudo -c -f /etc/sudoers.d/${filename}
sudo visudo -c`;

  // Validate
  validateRule(rule);
}

function validateRule(rule) {
  const validationBox = document.getElementById('validation');
  let isValid = true;
  let message = 'Syntaxe valide';
  let level = 'valid';

  // Basic validation
  if (!rule.includes('=')) {
    isValid = false;
    message = 'Format invalide: manque le signe =';
    level = 'error';
  } else if (rule.includes('  ')) {
    level = 'warning';
    message = 'Attention: espaces multiples detectes';
  } else if (rule.includes('ALL') && rule.includes('NOPASSWD')) {
    level = 'warning';
    message = 'Attention: NOPASSWD avec ALL est risque';
  }

  validationBox.className = 'validation-box ' + level;
  validationBox.innerHTML = `
    <span class="icon">${level === 'valid' ? '✓' : level === 'warning' ? '⚠' : '✗'}</span>
    <span class="message">${message}</span>
  `;
}

function loadPreset(name) {
  const preset = presets[name];
  if (!preset) return;

  document.querySelector(`input[name="identityType"][value="${preset.identityType}"]`).checked = true;
  document.getElementById('identity').value = preset.identity;
  document.getElementById('hosts').value = preset.hosts;
  document.getElementById('runasUser').value = preset.runasUser;
  document.getElementById('runasGroup').value = preset.runasGroup || '';
  document.getElementById('commands').value = preset.commands;

  // Reset options
  document.getElementById('optNopasswd').checked = preset.options?.nopasswd || false;
  document.getElementById('optNoexec').checked = preset.options?.noexec || false;
  document.getElementById('optSetenv').checked = preset.options?.setenv || false;
  document.getElementById('optNosetenv').checked = preset.options?.nosetenv || false;
  document.getElementById('optLog').checked = preset.options?.log || false;
  document.getElementById('optLogOutput').checked = preset.options?.logOutput || false;

  updateRule();
}

function showAliasTab(type) {
  currentAliasType = type;
  document.querySelectorAll('.alias-tab').forEach(t => t.classList.remove('active'));
  event.target.classList.add('active');

  const placeholders = {
    user: { name: 'ADMINS', members: 'alice, bob, charlie' },
    host: { name: 'WEBSERVERS', members: 'web1, web2, 192.168.1.0/24' },
    cmnd: { name: 'SERVICES', members: '/usr/bin/systemctl, /usr/bin/journalctl' },
    runas: { name: 'OPERATORS', members: 'root, operator' }
  };

  document.getElementById('aliasName').placeholder = placeholders[type].name;
  document.getElementById('aliasMembers').placeholder = placeholders[type].members;
  updateAlias();
}

function updateAlias() {
  const typeMap = {
    user: 'User_Alias',
    host: 'Host_Alias',
    cmnd: 'Cmnd_Alias',
    runas: 'Runas_Alias'
  };

  const name = document.getElementById('aliasName').value.trim() || 'ALIAS_NAME';
  const members = document.getElementById('aliasMembers').value.trim() || 'member1, member2';

  const memberList = members.split(/[,\n]/).map(m => m.trim()).filter(m => m).join(', ');
  const alias = `${typeMap[currentAliasType]} ${name.toUpperCase()} = ${memberList}`;

  document.getElementById('aliasOutput').textContent = alias;
}

function copyRule() {
  const rule = document.getElementById('ruleOutput').textContent;
  navigator.clipboard.writeText(rule).then(() => {
    showCopyFeedback(event.target);
  });
}

function copyFile() {
  const file = document.getElementById('fileOutput').textContent;
  navigator.clipboard.writeText(file).then(() => {
    showCopyFeedback(event.target);
  });
}

function copyAlias() {
  const alias = document.getElementById('aliasOutput').textContent;
  navigator.clipboard.writeText(alias).then(() => {
    showCopyFeedback(event.target);
  });
}

function showCopyFeedback(btn) {
  const orig = btn.textContent;
  btn.textContent = '✓ Copie!';
  setTimeout(() => btn.textContent = orig, 1500);
}

// Initialize
updateRule();
updateAlias();
</script>

---

## Bonnes pratiques sudoers

!!! danger "Toujours utiliser visudo"
    Ne jamais editer `/etc/sudoers` directement. Utiliser `visudo` qui valide la syntaxe avant de sauvegarder.

### Structure recommandee

```bash
/etc/sudoers           # Fichier principal (ne pas modifier)
/etc/sudoers.d/        # Fichiers supplementaires
  ├── 10-admins        # Regles admin
  ├── 20-developers    # Regles dev
  ├── 30-services      # Comptes de service
  └── 90-monitoring    # Monitoring
```

### Exemples courants

```bash
# Admin complet
admin ALL=(ALL:ALL) ALL

# Groupe wheel sans mot de passe
%wheel ALL=(ALL:ALL) NOPASSWD: ALL

# Commandes specifiques
deploy ALL=(root) NOPASSWD: /usr/bin/systemctl restart myapp

# Exclusion de commandes dangereuses
operator ALL=(ALL) ALL, !/bin/su, !/bin/bash, !/usr/bin/passwd root

# Avec logging
auditor ALL=(ALL) LOG_INPUT: LOG_OUTPUT: ALL
```

---

## Securite

| Pratique | Recommandation |
|----------|----------------|
| NOPASSWD | Limiter aux commandes specifiques |
| ALL | Eviter sauf pour admins |
| Wildcards | Attention aux injections de commandes |
| Chemins | Toujours utiliser des chemins absolus |
| Logging | Activer LOG_INPUT/LOG_OUTPUT pour audit |
