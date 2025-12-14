---
tags:
  - tools
  - iptables
  - firewall
  - security
  - linux
---

# Iptables Rule Generator

Generateur de regles iptables/nftables pour Linux.

<div class="tool-container">

<div class="type-selector">
    <button class="type-btn active" onclick="selectType('iptables')">iptables</button>
    <button class="type-btn" onclick="selectType('nftables')">nftables</button>
    <button class="type-btn" onclick="selectType('firewalld')">firewalld</button>
    <button class="type-btn" onclick="selectType('ufw')">ufw</button>
</div>

<div class="generator-section">
    <h3>Nouvelle regle</h3>

    <div class="form-grid">
        <div class="form-group">
            <label for="rule-chain">Chain</label>
            <select id="rule-chain">
                <option value="INPUT">INPUT (entrant)</option>
                <option value="OUTPUT">OUTPUT (sortant)</option>
                <option value="FORWARD">FORWARD (transit)</option>
            </select>
        </div>

        <div class="form-group">
            <label for="rule-action">Action</label>
            <select id="rule-action">
                <option value="ACCEPT">ACCEPT (autoriser)</option>
                <option value="DROP">DROP (bloquer silencieux)</option>
                <option value="REJECT">REJECT (bloquer avec reponse)</option>
                <option value="LOG">LOG (journaliser)</option>
            </select>
        </div>

        <div class="form-group">
            <label for="rule-protocol">Protocole</label>
            <select id="rule-protocol">
                <option value="">Tous</option>
                <option value="tcp">TCP</option>
                <option value="udp">UDP</option>
                <option value="icmp">ICMP</option>
            </select>
        </div>

        <div class="form-group">
            <label for="rule-source">Source IP/CIDR</label>
            <input type="text" id="rule-source" placeholder="192.168.1.0/24 ou any">
        </div>

        <div class="form-group">
            <label for="rule-dest">Destination IP/CIDR</label>
            <input type="text" id="rule-dest" placeholder="10.0.0.1 ou any">
        </div>

        <div class="form-group">
            <label for="rule-sport">Port source</label>
            <input type="text" id="rule-sport" placeholder="1024:65535 ou any">
        </div>

        <div class="form-group">
            <label for="rule-dport">Port destination</label>
            <input type="text" id="rule-dport" placeholder="22, 80, 443 ou 8000:8100">
        </div>

        <div class="form-group">
            <label for="rule-interface">Interface</label>
            <input type="text" id="rule-interface" placeholder="eth0, ens192">
        </div>

        <div class="form-group">
            <label for="rule-state">Etat connexion</label>
            <select id="rule-state">
                <option value="">Aucun</option>
                <option value="NEW">NEW</option>
                <option value="ESTABLISHED">ESTABLISHED</option>
                <option value="RELATED">RELATED</option>
                <option value="ESTABLISHED,RELATED">ESTABLISHED,RELATED</option>
                <option value="NEW,ESTABLISHED">NEW,ESTABLISHED</option>
            </select>
        </div>

        <div class="form-group">
            <label for="rule-comment">Commentaire</label>
            <input type="text" id="rule-comment" placeholder="Allow SSH">
        </div>
    </div>

    <button onclick="addRule()" class="action-btn">Ajouter la regle</button>
</div>

<div class="presets-section">
    <h3>Presets courants</h3>
    <div class="preset-buttons">
        <button onclick="addPreset('ssh')">SSH (22)</button>
        <button onclick="addPreset('http')">HTTP (80)</button>
        <button onclick="addPreset('https')">HTTPS (443)</button>
        <button onclick="addPreset('mysql')">MySQL (3306)</button>
        <button onclick="addPreset('postgres')">PostgreSQL (5432)</button>
        <button onclick="addPreset('dns')">DNS (53)</button>
        <button onclick="addPreset('ping')">ICMP Ping</button>
        <button onclick="addPreset('established')">Established</button>
        <button onclick="addPreset('loopback')">Loopback</button>
        <button onclick="addPreset('dropall')">Drop All (defaut)</button>
    </div>
</div>

<div class="rules-list-section" id="rules-section">
    <h3>Regles configurees</h3>
    <div id="rules-list"></div>
</div>

<div class="output-section">
    <div class="output-header">
        <h3>Script genere</h3>
        <button onclick="copyOutput()" class="copy-btn">Copier</button>
    </div>
    <pre id="rules-output" class="rules-output"></pre>
</div>

</div>

## Chaines iptables

| Chain | Description |
|-------|-------------|
| **INPUT** | Paquets destines a la machine locale |
| **OUTPUT** | Paquets emis par la machine locale |
| **FORWARD** | Paquets transitant (routage) |

## Commandes utiles

```bash
# Lister les regles
iptables -L -n -v --line-numbers

# Sauvegarder les regles
iptables-save > /etc/iptables.rules

# Restaurer les regles
iptables-restore < /etc/iptables.rules

# Supprimer une regle par numero
iptables -D INPUT 3

# Vider toutes les regles
iptables -F
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
    flex-wrap: wrap;
}
.type-btn {
    padding: 10px 20px;
    background: var(--md-default-bg-color);
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    cursor: pointer;
}
.type-btn.active {
    background: var(--md-primary-fg-color);
    color: white;
    border-color: var(--md-primary-fg-color);
}
.generator-section, .presets-section, .rules-list-section, .output-section {
    background: var(--md-default-bg-color);
    padding: 20px;
    border-radius: 4px;
    margin-bottom: 20px;
}
.generator-section h3, .presets-section h3, .rules-list-section h3 {
    margin: 0 0 15px 0;
}
.form-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 15px;
    margin-bottom: 15px;
}
.form-group {
    display: flex;
    flex-direction: column;
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
.action-btn {
    padding: 10px 24px;
    background: var(--md-primary-fg-color);
    color: white;
    border: none;
    border-radius: 4px;
    cursor: pointer;
}
.preset-buttons {
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
}
.preset-buttons button {
    padding: 8px 16px;
    background: var(--md-code-bg-color);
    color: var(--md-default-fg-color);
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    cursor: pointer;
    font-size: 13px;
}
.preset-buttons button:hover {
    background: var(--md-primary-fg-color);
    color: white;
}
#rules-list {
    display: flex;
    flex-direction: column;
    gap: 10px;
}
.rule-item {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 10px 15px;
    background: var(--md-code-bg-color);
    border-radius: 4px;
    font-family: monospace;
    font-size: 13px;
}
.rule-item.accept { border-left: 4px solid #28a745; }
.rule-item.drop { border-left: 4px solid #dc3545; }
.rule-item.reject { border-left: 4px solid #ffc107; }
.rule-item.log { border-left: 4px solid #17a2b8; }
.rule-item button {
    padding: 5px 10px;
    background: #dc3545;
    color: white;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    font-size: 11px;
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
.rules-output {
    background: var(--md-code-bg-color);
    padding: 15px;
    border-radius: 4px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 13px;
    overflow-x: auto;
    margin: 0;
    white-space: pre-wrap;
    min-height: 150px;
}
</style>

<script>
let currentType = 'iptables';
let rules = [];

function selectType(type) {
    currentType = type;
    document.querySelectorAll('.type-btn').forEach(btn => btn.classList.remove('active'));
    event.target.classList.add('active');
    generateOutput();
}

function addRule() {
    const rule = {
        id: Date.now(),
        chain: document.getElementById('rule-chain').value,
        action: document.getElementById('rule-action').value,
        protocol: document.getElementById('rule-protocol').value,
        source: document.getElementById('rule-source').value,
        dest: document.getElementById('rule-dest').value,
        sport: document.getElementById('rule-sport').value,
        dport: document.getElementById('rule-dport').value,
        interface: document.getElementById('rule-interface').value,
        state: document.getElementById('rule-state').value,
        comment: document.getElementById('rule-comment').value
    };

    rules.push(rule);
    renderRules();
    generateOutput();
}

function removeRule(id) {
    rules = rules.filter(r => r.id !== id);
    renderRules();
    generateOutput();
}

function addPreset(preset) {
    const presets = {
        ssh: { chain: 'INPUT', action: 'ACCEPT', protocol: 'tcp', dport: '22', comment: 'Allow SSH' },
        http: { chain: 'INPUT', action: 'ACCEPT', protocol: 'tcp', dport: '80', comment: 'Allow HTTP' },
        https: { chain: 'INPUT', action: 'ACCEPT', protocol: 'tcp', dport: '443', comment: 'Allow HTTPS' },
        mysql: { chain: 'INPUT', action: 'ACCEPT', protocol: 'tcp', dport: '3306', comment: 'Allow MySQL' },
        postgres: { chain: 'INPUT', action: 'ACCEPT', protocol: 'tcp', dport: '5432', comment: 'Allow PostgreSQL' },
        dns: { chain: 'INPUT', action: 'ACCEPT', protocol: 'udp', dport: '53', comment: 'Allow DNS' },
        ping: { chain: 'INPUT', action: 'ACCEPT', protocol: 'icmp', comment: 'Allow ICMP' },
        established: { chain: 'INPUT', action: 'ACCEPT', state: 'ESTABLISHED,RELATED', comment: 'Allow established' },
        loopback: { chain: 'INPUT', action: 'ACCEPT', interface: 'lo', comment: 'Allow loopback' },
        dropall: { chain: 'INPUT', action: 'DROP', comment: 'Drop all (default policy)' }
    };

    const p = presets[preset];
    rules.push({
        id: Date.now(),
        chain: p.chain || 'INPUT',
        action: p.action || 'ACCEPT',
        protocol: p.protocol || '',
        source: p.source || '',
        dest: p.dest || '',
        sport: p.sport || '',
        dport: p.dport || '',
        interface: p.interface || '',
        state: p.state || '',
        comment: p.comment || ''
    });

    renderRules();
    generateOutput();
}

function renderRules() {
    const list = document.getElementById('rules-list');

    if (rules.length === 0) {
        list.innerHTML = '<p style="color: var(--md-default-fg-color--light)">Aucune regle. Ajoutez des regles ci-dessus ou utilisez les presets.</p>';
        return;
    }

    list.innerHTML = rules.map(rule => {
        let desc = `${rule.chain} ${rule.action}`;
        if (rule.protocol) desc += ` ${rule.protocol}`;
        if (rule.source) desc += ` src:${rule.source}`;
        if (rule.dest) desc += ` dst:${rule.dest}`;
        if (rule.dport) desc += ` dport:${rule.dport}`;
        if (rule.interface) desc += ` if:${rule.interface}`;
        if (rule.state) desc += ` state:${rule.state}`;
        if (rule.comment) desc += ` # ${rule.comment}`;

        return `<div class="rule-item ${rule.action.toLowerCase()}">
            <span>${desc}</span>
            <button onclick="removeRule(${rule.id})">X</button>
        </div>`;
    }).join('');
}

function generateOutput() {
    let output = '';

    switch (currentType) {
        case 'iptables':
            output = generateIptables();
            break;
        case 'nftables':
            output = generateNftables();
            break;
        case 'firewalld':
            output = generateFirewalld();
            break;
        case 'ufw':
            output = generateUfw();
            break;
    }

    document.getElementById('rules-output').textContent = output;
}

function generateIptables() {
    if (rules.length === 0) return '# Ajoutez des regles pour generer le script';

    let script = `#!/bin/bash
# iptables firewall rules
# Generated by ShellBook

# Flush existing rules
iptables -F
iptables -X

# Default policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

`;

    rules.forEach(rule => {
        let cmd = `iptables -A ${rule.chain}`;

        if (rule.interface) {
            cmd += rule.chain === 'OUTPUT' ? ` -o ${rule.interface}` : ` -i ${rule.interface}`;
        }
        if (rule.protocol) cmd += ` -p ${rule.protocol}`;
        if (rule.source) cmd += ` -s ${rule.source}`;
        if (rule.dest) cmd += ` -d ${rule.dest}`;
        if (rule.sport) cmd += ` --sport ${rule.sport}`;
        if (rule.dport) cmd += ` --dport ${rule.dport}`;
        if (rule.state) cmd += ` -m state --state ${rule.state}`;
        if (rule.comment) cmd += ` -m comment --comment "${rule.comment}"`;
        cmd += ` -j ${rule.action}`;

        script += cmd + '\n';
    });

    script += `
# Save rules
iptables-save > /etc/iptables.rules

echo "Firewall rules applied successfully"`;

    return script;
}

function generateNftables() {
    if (rules.length === 0) return '# Ajoutez des regles pour generer le script';

    let script = `#!/usr/sbin/nft -f
# nftables firewall rules
# Generated by ShellBook

flush ruleset

table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;

`;

    rules.filter(r => r.chain === 'INPUT').forEach(rule => {
        let cmd = '        ';
        if (rule.interface) cmd += `iifname "${rule.interface}" `;
        if (rule.protocol) cmd += `${rule.protocol} `;
        if (rule.source) cmd += `ip saddr ${rule.source} `;
        if (rule.dest) cmd += `ip daddr ${rule.dest} `;
        if (rule.dport) cmd += `dport ${rule.dport} `;
        if (rule.state) cmd += `ct state ${rule.state.toLowerCase()} `;
        cmd += rule.action.toLowerCase();
        if (rule.comment) cmd += ` comment "${rule.comment}"`;

        script += cmd + '\n';
    });

    script += `    }

    chain forward {
        type filter hook forward priority 0; policy drop;
    }

    chain output {
        type filter hook output priority 0; policy accept;
    }
}`;

    return script;
}

function generateFirewalld() {
    if (rules.length === 0) return '# Ajoutez des regles pour generer le script';

    let script = `#!/bin/bash
# firewalld rules
# Generated by ShellBook

`;

    rules.forEach(rule => {
        if (rule.dport && rule.protocol) {
            if (rule.action === 'ACCEPT') {
                script += `firewall-cmd --permanent --add-port=${rule.dport}/${rule.protocol}\n`;
            } else {
                script += `firewall-cmd --permanent --remove-port=${rule.dport}/${rule.protocol}\n`;
            }
        }
        if (rule.source && rule.action === 'ACCEPT') {
            script += `firewall-cmd --permanent --add-source=${rule.source}\n`;
        }
    });

    script += `
# Reload firewalld
firewall-cmd --reload

echo "Firewalld rules applied successfully"`;

    return script;
}

function generateUfw() {
    if (rules.length === 0) return '# Ajoutez des regles pour generer le script';

    let script = `#!/bin/bash
# ufw rules
# Generated by ShellBook

# Reset ufw
ufw --force reset

# Default policies
ufw default deny incoming
ufw default allow outgoing

`;

    rules.forEach(rule => {
        if (rule.chain !== 'INPUT') return;

        let cmd = 'ufw ';
        cmd += rule.action === 'ACCEPT' ? 'allow' : 'deny';

        if (rule.source) cmd += ` from ${rule.source}`;
        if (rule.dest) cmd += ` to ${rule.dest}`;
        if (rule.dport) {
            cmd += ` port ${rule.dport}`;
            if (rule.protocol) cmd += `/${rule.protocol}`;
        } else if (rule.protocol === 'icmp') {
            cmd = 'ufw allow icmp';
        }

        if (rule.comment) cmd += ` comment "${rule.comment}"`;

        script += cmd + '\n';
    });

    script += `
# Enable ufw
ufw --force enable

echo "UFW rules applied successfully"`;

    return script;
}

function copyOutput() {
    const output = document.getElementById('rules-output').textContent;
    navigator.clipboard.writeText(output);

    const btn = document.querySelector('.copy-btn');
    btn.textContent = 'Copie!';
    setTimeout(() => { btn.textContent = 'Copier'; }, 1000);
}

// Initial render
renderRules();
generateOutput();
</script>
