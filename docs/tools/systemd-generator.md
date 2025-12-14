---
tags:
  - tools
  - systemd
  - linux
  - service
---

# Systemd Unit Generator

Generateur de fichiers unit systemd (.service, .timer, .socket).

<div class="tool-container">

<div class="type-selector">
    <button class="type-btn active" onclick="selectType('service')">Service</button>
    <button class="type-btn" onclick="selectType('timer')">Timer</button>
    <button class="type-btn" onclick="selectType('socket')">Socket</button>
</div>

<div class="generator-section" id="service-section">
    <h3>Configuration du Service</h3>

    <div class="form-grid">
        <div class="form-group">
            <label for="svc-description">Description</label>
            <input type="text" id="svc-description" placeholder="My Application Service">
        </div>

        <div class="form-group">
            <label for="svc-type">Type</label>
            <select id="svc-type">
                <option value="simple">simple (defaut)</option>
                <option value="exec">exec</option>
                <option value="forking">forking (daemon)</option>
                <option value="oneshot">oneshot (script)</option>
                <option value="notify">notify (sd_notify)</option>
                <option value="idle">idle</option>
            </select>
        </div>

        <div class="form-group">
            <label for="svc-user">User</label>
            <input type="text" id="svc-user" placeholder="www-data">
        </div>

        <div class="form-group">
            <label for="svc-group">Group</label>
            <input type="text" id="svc-group" placeholder="www-data">
        </div>

        <div class="form-group">
            <label for="svc-workdir">WorkingDirectory</label>
            <input type="text" id="svc-workdir" placeholder="/opt/myapp">
        </div>

        <div class="form-group">
            <label for="svc-execstart">ExecStart</label>
            <input type="text" id="svc-execstart" placeholder="/opt/myapp/bin/start.sh">
        </div>

        <div class="form-group">
            <label for="svc-execstop">ExecStop (optionnel)</label>
            <input type="text" id="svc-execstop" placeholder="/opt/myapp/bin/stop.sh">
        </div>

        <div class="form-group">
            <label for="svc-restart">Restart</label>
            <select id="svc-restart">
                <option value="">no (defaut)</option>
                <option value="always" selected>always</option>
                <option value="on-success">on-success</option>
                <option value="on-failure">on-failure</option>
                <option value="on-abnormal">on-abnormal</option>
                <option value="on-abort">on-abort</option>
                <option value="on-watchdog">on-watchdog</option>
            </select>
        </div>

        <div class="form-group">
            <label for="svc-restartsec">RestartSec</label>
            <input type="text" id="svc-restartsec" placeholder="5">
        </div>

        <div class="form-group">
            <label for="svc-after">After</label>
            <input type="text" id="svc-after" placeholder="network.target">
        </div>

        <div class="form-group">
            <label for="svc-wantedby">WantedBy</label>
            <input type="text" id="svc-wantedby" value="multi-user.target">
        </div>

        <div class="form-group">
            <label for="svc-env">Environment (key=value)</label>
            <input type="text" id="svc-env" placeholder="NODE_ENV=production">
        </div>

        <div class="form-group full-width">
            <label>Options de securite</label>
            <div class="checkbox-group">
                <label><input type="checkbox" id="svc-privatetmp"> PrivateTmp</label>
                <label><input type="checkbox" id="svc-protectsystem"> ProtectSystem=strict</label>
                <label><input type="checkbox" id="svc-protecthome"> ProtectHome</label>
                <label><input type="checkbox" id="svc-noexec"> NoNewPrivileges</label>
                <label><input type="checkbox" id="svc-readonly"> ReadOnlyPaths=/</label>
            </div>
        </div>
    </div>
</div>

<div class="generator-section" id="timer-section" style="display:none;">
    <h3>Configuration du Timer</h3>

    <div class="form-grid">
        <div class="form-group">
            <label for="timer-description">Description</label>
            <input type="text" id="timer-description" placeholder="Run backup daily">
        </div>

        <div class="form-group">
            <label for="timer-oncalendar">OnCalendar</label>
            <input type="text" id="timer-oncalendar" placeholder="*-*-* 02:00:00">
        </div>

        <div class="form-group">
            <label for="timer-onboot">OnBootSec</label>
            <input type="text" id="timer-onboot" placeholder="5min">
        </div>

        <div class="form-group">
            <label for="timer-onunitactive">OnUnitActiveSec</label>
            <input type="text" id="timer-onunitactive" placeholder="1h">
        </div>

        <div class="form-group">
            <label for="timer-unit">Unit (service a lancer)</label>
            <input type="text" id="timer-unit" placeholder="backup.service">
        </div>

        <div class="form-group">
            <label><input type="checkbox" id="timer-persistent"> Persistent</label>
        </div>
    </div>

    <div class="calendar-help">
        <h4>Exemples OnCalendar</h4>
        <table>
            <tr><td><code>*-*-* 00:00:00</code></td><td>Tous les jours a minuit</td></tr>
            <tr><td><code>Mon *-*-* 00:00:00</code></td><td>Chaque lundi</td></tr>
            <tr><td><code>*-*-01 00:00:00</code></td><td>Premier du mois</td></tr>
            <tr><td><code>hourly</code></td><td>Chaque heure</td></tr>
            <tr><td><code>daily</code></td><td>Chaque jour</td></tr>
            <tr><td><code>weekly</code></td><td>Chaque semaine</td></tr>
        </table>
    </div>
</div>

<div class="generator-section" id="socket-section" style="display:none;">
    <h3>Configuration du Socket</h3>

    <div class="form-grid">
        <div class="form-group">
            <label for="socket-description">Description</label>
            <input type="text" id="socket-description" placeholder="My App Socket">
        </div>

        <div class="form-group">
            <label for="socket-listensream">ListenStream (TCP)</label>
            <input type="text" id="socket-listenstream" placeholder="8080">
        </div>

        <div class="form-group">
            <label for="socket-listendgram">ListenDatagram (UDP)</label>
            <input type="text" id="socket-listendgram" placeholder="">
        </div>

        <div class="form-group">
            <label for="socket-listenunix">ListenStream (Unix Socket)</label>
            <input type="text" id="socket-listenunix" placeholder="/run/myapp.sock">
        </div>

        <div class="form-group">
            <label><input type="checkbox" id="socket-accept"> Accept (inetd-style)</label>
        </div>
    </div>
</div>

<div class="output-section">
    <div class="output-header">
        <h3>Fichier genere</h3>
        <button onclick="copyOutput()" class="copy-btn">Copier</button>
    </div>
    <pre id="unit-output" class="unit-output"></pre>
</div>

<div class="install-section">
    <h3>Installation</h3>
    <pre id="install-commands"></pre>
</div>

</div>

## Types de services

| Type | Description | Usage |
|------|-------------|-------|
| **simple** | Demarre immediatement | Applications foreground |
| **exec** | Comme simple, attend exec() | Plus precis que simple |
| **forking** | Daemon qui fork | Services traditionnels |
| **oneshot** | Execute et termine | Scripts, init tasks |
| **notify** | Notifie systemd via sd_notify | Apps systemd-aware |

## Commandes systemd

```bash
# Recharger la configuration
sudo systemctl daemon-reload

# Gestion du service
sudo systemctl start myapp
sudo systemctl stop myapp
sudo systemctl restart myapp
sudo systemctl status myapp

# Activation au boot
sudo systemctl enable myapp
sudo systemctl disable myapp

# Logs
journalctl -u myapp -f
journalctl -u myapp --since "1 hour ago"
```

<style>
.tool-container {
    background: var(--md-code-bg-color);
    padding: 20px;
    border-radius: 8px;
    margin: 20px 0;
}
.type-selector {
    display: flex;
    gap: 10px;
    margin-bottom: 20px;
}
.type-btn {
    padding: 10px 20px;
    background: var(--md-default-bg-color);
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    cursor: pointer;
    font-size: 14px;
}
.type-btn.active {
    background: var(--md-primary-fg-color);
    color: white;
    border-color: var(--md-primary-fg-color);
}
.generator-section {
    background: var(--md-default-bg-color);
    padding: 20px;
    border-radius: 4px;
    margin-bottom: 20px;
}
.generator-section h3 {
    margin: 0 0 15px 0;
}
.form-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    gap: 15px;
}
.form-group {
    display: flex;
    flex-direction: column;
}
.form-group.full-width {
    grid-column: 1 / -1;
}
.form-group label {
    font-size: 12px;
    font-weight: bold;
    margin-bottom: 5px;
}
.form-group input, .form-group select {
    padding: 10px;
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    background: var(--md-code-bg-color);
    color: var(--md-default-fg-color);
    font-family: monospace;
}
.checkbox-group {
    display: flex;
    flex-wrap: wrap;
    gap: 15px;
}
.checkbox-group label {
    font-weight: normal;
    display: flex;
    align-items: center;
    gap: 5px;
    cursor: pointer;
}
.calendar-help {
    margin-top: 15px;
    padding: 15px;
    background: var(--md-code-bg-color);
    border-radius: 4px;
}
.calendar-help h4 {
    margin: 0 0 10px 0;
}
.calendar-help table {
    width: 100%;
}
.calendar-help td {
    padding: 5px 10px;
}
.calendar-help code {
    background: var(--md-default-bg-color);
    padding: 2px 6px;
    border-radius: 3px;
}
.output-section, .install-section {
    background: var(--md-default-bg-color);
    padding: 20px;
    border-radius: 4px;
    margin-bottom: 20px;
}
.output-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 10px;
}
.output-header h3 {
    margin: 0;
}
.copy-btn {
    padding: 8px 16px;
    background: var(--md-primary-fg-color);
    color: white;
    border: none;
    border-radius: 4px;
    cursor: pointer;
}
.unit-output {
    background: var(--md-code-bg-color);
    padding: 15px;
    border-radius: 4px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 13px;
    overflow-x: auto;
    margin: 0;
    white-space: pre-wrap;
}
.install-section h3 {
    margin: 0 0 10px 0;
}
.install-section pre {
    background: var(--md-code-bg-color);
    padding: 15px;
    border-radius: 4px;
    font-size: 13px;
    margin: 0;
}
</style>

<script>
let currentType = 'service';

function selectType(type) {
    currentType = type;
    document.querySelectorAll('.type-btn').forEach(btn => btn.classList.remove('active'));
    event.target.classList.add('active');

    document.getElementById('service-section').style.display = type === 'service' ? 'block' : 'none';
    document.getElementById('timer-section').style.display = type === 'timer' ? 'block' : 'none';
    document.getElementById('socket-section').style.display = type === 'socket' ? 'block' : 'none';

    generateUnit();
}

function generateService() {
    const desc = document.getElementById('svc-description').value || 'My Service';
    const type = document.getElementById('svc-type').value;
    const user = document.getElementById('svc-user').value;
    const group = document.getElementById('svc-group').value;
    const workdir = document.getElementById('svc-workdir').value;
    const execstart = document.getElementById('svc-execstart').value || '/usr/bin/myapp';
    const execstop = document.getElementById('svc-execstop').value;
    const restart = document.getElementById('svc-restart').value;
    const restartsec = document.getElementById('svc-restartsec').value;
    const after = document.getElementById('svc-after').value;
    const wantedby = document.getElementById('svc-wantedby').value || 'multi-user.target';
    const env = document.getElementById('svc-env').value;

    const privatetmp = document.getElementById('svc-privatetmp').checked;
    const protectsystem = document.getElementById('svc-protectsystem').checked;
    const protecthome = document.getElementById('svc-protecthome').checked;
    const noexec = document.getElementById('svc-noexec').checked;
    const readonly = document.getElementById('svc-readonly').checked;

    let unit = `[Unit]
Description=${desc}
`;
    if (after) unit += `After=${after}\n`;

    unit += `
[Service]
Type=${type}
ExecStart=${execstart}
`;
    if (execstop) unit += `ExecStop=${execstop}\n`;
    if (user) unit += `User=${user}\n`;
    if (group) unit += `Group=${group}\n`;
    if (workdir) unit += `WorkingDirectory=${workdir}\n`;
    if (env) unit += `Environment=${env}\n`;
    if (restart) unit += `Restart=${restart}\n`;
    if (restartsec) unit += `RestartSec=${restartsec}\n`;

    if (privatetmp || protectsystem || protecthome || noexec || readonly) {
        unit += `\n# Security hardening\n`;
        if (privatetmp) unit += `PrivateTmp=true\n`;
        if (protectsystem) unit += `ProtectSystem=strict\n`;
        if (protecthome) unit += `ProtectHome=true\n`;
        if (noexec) unit += `NoNewPrivileges=true\n`;
        if (readonly) unit += `ReadOnlyPaths=/\n`;
    }

    unit += `
[Install]
WantedBy=${wantedby}
`;

    return unit;
}

function generateTimer() {
    const desc = document.getElementById('timer-description').value || 'My Timer';
    const oncalendar = document.getElementById('timer-oncalendar').value;
    const onboot = document.getElementById('timer-onboot').value;
    const onunitactive = document.getElementById('timer-onunitactive').value;
    const timerunit = document.getElementById('timer-unit').value;
    const persistent = document.getElementById('timer-persistent').checked;

    let unit = `[Unit]
Description=${desc}

[Timer]
`;
    if (oncalendar) unit += `OnCalendar=${oncalendar}\n`;
    if (onboot) unit += `OnBootSec=${onboot}\n`;
    if (onunitactive) unit += `OnUnitActiveSec=${onunitactive}\n`;
    if (persistent) unit += `Persistent=true\n`;
    if (timerunit) unit += `Unit=${timerunit}\n`;

    unit += `
[Install]
WantedBy=timers.target
`;

    return unit;
}

function generateSocket() {
    const desc = document.getElementById('socket-description').value || 'My Socket';
    const listenstream = document.getElementById('socket-listenstream').value;
    const listendgram = document.getElementById('socket-listendgram').value;
    const listenunix = document.getElementById('socket-listenunix').value;
    const accept = document.getElementById('socket-accept').checked;

    let unit = `[Unit]
Description=${desc}

[Socket]
`;
    if (listenstream) unit += `ListenStream=${listenstream}\n`;
    if (listendgram) unit += `ListenDatagram=${listendgram}\n`;
    if (listenunix) unit += `ListenStream=${listenunix}\n`;
    if (accept) unit += `Accept=yes\n`;

    unit += `
[Install]
WantedBy=sockets.target
`;

    return unit;
}

function generateUnit() {
    let output;
    let filename;
    let commands;

    switch (currentType) {
        case 'service':
            output = generateService();
            filename = 'myapp.service';
            commands = `# Copier le fichier
sudo cp ${filename} /etc/systemd/system/

# Recharger systemd
sudo systemctl daemon-reload

# Demarrer et activer
sudo systemctl start myapp
sudo systemctl enable myapp

# Verifier le statut
sudo systemctl status myapp`;
            break;
        case 'timer':
            output = generateTimer();
            filename = 'mytimer.timer';
            commands = `# Copier le fichier
sudo cp ${filename} /etc/systemd/system/

# Recharger systemd
sudo systemctl daemon-reload

# Demarrer et activer le timer
sudo systemctl start mytimer.timer
sudo systemctl enable mytimer.timer

# Lister les timers
systemctl list-timers`;
            break;
        case 'socket':
            output = generateSocket();
            filename = 'myapp.socket';
            commands = `# Copier le fichier
sudo cp ${filename} /etc/systemd/system/

# Recharger systemd
sudo systemctl daemon-reload

# Demarrer et activer
sudo systemctl start myapp.socket
sudo systemctl enable myapp.socket`;
            break;
    }

    document.getElementById('unit-output').textContent = output;
    document.getElementById('install-commands').textContent = commands;
}

function copyOutput() {
    const output = document.getElementById('unit-output').textContent;
    navigator.clipboard.writeText(output);

    const btn = document.querySelector('.copy-btn');
    btn.textContent = 'Copie!';
    setTimeout(() => { btn.textContent = 'Copier'; }, 1000);
}

// Event listeners
document.querySelectorAll('.generator-section input, .generator-section select').forEach(el => {
    el.addEventListener('input', generateUnit);
    el.addEventListener('change', generateUnit);
});

// Initial generation
generateUnit();
</script>
