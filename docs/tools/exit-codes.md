---
tags:
  - tools
  - reference
  - shell
  - exit-codes
  - bash
---

# Exit Codes Reference

Reference des codes de sortie standards Unix/Linux et leurs significations.

<div class="tool-container">

<div class="search-section">
    <input type="text" id="search-input" placeholder="Rechercher un code ou description..." oninput="filterCodes()">
</div>

<div class="quick-lookup">
    <h3>Lookup Rapide</h3>
    <div class="lookup-grid">
        <input type="number" id="code-input" placeholder="Code" min="0" max="255" oninput="lookupCode()">
        <div class="lookup-result" id="lookup-result">Entrez un code (0-255)</div>
    </div>
</div>

<div class="categories-section">
    <h3>Categories</h3>
    <div class="category-tabs">
        <button class="cat-btn active" onclick="filterCategory('all')">Tous</button>
        <button class="cat-btn" onclick="filterCategory('success')">Succes</button>
        <button class="cat-btn" onclick="filterCategory('error')">Erreurs</button>
        <button class="cat-btn" onclick="filterCategory('signal')">Signaux</button>
        <button class="cat-btn" onclick="filterCategory('reserved')">Reserves</button>
    </div>
</div>

<div class="codes-section">
    <table class="codes-table" id="codes-table">
        <thead>
            <tr>
                <th>Code</th>
                <th>Signification</th>
                <th>Description</th>
                <th>Exemple</th>
            </tr>
        </thead>
        <tbody id="codes-body">
        </tbody>
    </table>
</div>

<div class="signal-section">
    <h3>Signaux Unix (128 + signal)</h3>
    <table class="signals-table">
        <thead>
            <tr>
                <th>Signal</th>
                <th>Num</th>
                <th>Exit Code</th>
                <th>Description</th>
            </tr>
        </thead>
        <tbody id="signals-body">
        </tbody>
    </table>
</div>

<div class="tips-section">
    <h3>Bonnes Pratiques</h3>
    <div class="tips-grid">
        <div class="tip-card">
            <h4>Scripts Bash</h4>
            <pre>#!/bin/bash
set -e  # Exit on error
trap 'echo "Error $?" >&2' ERR

# Custom exit codes
readonly E_SUCCESS=0
readonly E_ARGS=64
readonly E_NOINPUT=66

[ $# -eq 0 ] && exit $E_ARGS</pre>
        </div>
        <div class="tip-card">
            <h4>Verifier le code</h4>
            <pre># Dernier code de sortie
echo $?

# Dans un script
command
if [ $? -ne 0 ]; then
    echo "Erreur"
    exit 1
fi

# Forme courte
command || exit 1</pre>
        </div>
    </div>
</div>

</div>

## Conventions

| Plage | Usage |
|-------|-------|
| **0** | Succes |
| **1** | Erreur generale |
| **2** | Mauvaise utilisation de commande shell |
| **64-78** | Codes sysexits.h (BSD) |
| **126** | Commande non executable |
| **127** | Commande non trouvee |
| **128+N** | Signal fatal N |
| **130** | Script termine par Ctrl+C |
| **255** | Code de sortie hors plage |

## CLI Usage

```bash
# Voir le dernier code de sortie
echo $?

# Exit avec un code specifique
exit 1

# Executer si succes/echec
command && echo "OK" || echo "FAIL"

# Ignorer le code de sortie
command || true

# Propager le code
command; exit $?
```

<style>
.tool-container {
    background: var(--md-code-bg-color);
    padding: 20px;
    border-radius: 8px;
    margin: 20px 0;
}
.search-section {
    margin-bottom: 20px;
}
.search-section input {
    width: 100%;
    padding: 12px 15px;
    font-size: 14px;
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    background: var(--md-default-bg-color);
    color: var(--md-default-fg-color);
}
.quick-lookup, .categories-section, .codes-section, .signal-section, .tips-section {
    background: var(--md-default-bg-color);
    padding: 20px;
    border-radius: 4px;
    margin-bottom: 20px;
}
.quick-lookup h3, .categories-section h3, .signal-section h3, .tips-section h3 {
    margin: 0 0 15px 0;
}
.lookup-grid {
    display: flex;
    gap: 15px;
    align-items: center;
}
.lookup-grid input {
    width: 100px;
    padding: 10px;
    font-size: 18px;
    text-align: center;
    font-family: monospace;
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    background: var(--md-code-bg-color);
    color: var(--md-default-fg-color);
}
.lookup-result {
    flex: 1;
    padding: 10px 15px;
    background: var(--md-code-bg-color);
    border-radius: 4px;
    font-family: monospace;
}
.category-tabs {
    display: flex;
    gap: 10px;
    flex-wrap: wrap;
}
.cat-btn {
    padding: 8px 16px;
    background: var(--md-code-bg-color);
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    cursor: pointer;
    color: var(--md-default-fg-color);
}
.cat-btn.active {
    background: var(--md-primary-fg-color);
    color: white;
    border-color: var(--md-primary-fg-color);
}
.codes-table, .signals-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
}
.codes-table th, .codes-table td,
.signals-table th, .signals-table td {
    padding: 10px 12px;
    text-align: left;
    border-bottom: 1px solid var(--md-default-fg-color--lightest);
}
.codes-table th, .signals-table th {
    background: var(--md-code-bg-color);
    font-weight: bold;
    position: sticky;
    top: 0;
}
.codes-table tr:hover, .signals-table tr:hover {
    background: var(--md-code-bg-color);
}
.code-badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 3px;
    font-family: monospace;
    font-weight: bold;
}
.code-badge.success { background: #4caf50; color: white; }
.code-badge.error { background: #f44336; color: white; }
.code-badge.signal { background: #ff9800; color: white; }
.code-badge.reserved { background: #9c27b0; color: white; }
.tips-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 20px;
}
.tip-card {
    background: var(--md-code-bg-color);
    padding: 15px;
    border-radius: 4px;
}
.tip-card h4 {
    margin: 0 0 10px 0;
}
.tip-card pre {
    margin: 0;
    padding: 10px;
    background: var(--md-default-bg-color);
    border-radius: 4px;
    font-size: 12px;
    overflow-x: auto;
}
</style>

<script>
const EXIT_CODES = [
    { code: 0, meaning: 'Success', desc: 'Commande executee avec succes', example: 'true', category: 'success' },
    { code: 1, meaning: 'General error', desc: 'Erreur generale ou non specifiee', example: 'false', category: 'error' },
    { code: 2, meaning: 'Misuse of shell', desc: 'Mauvaise utilisation de commande shell ou builtin', example: 'empty_function() {}', category: 'error' },
    { code: 64, meaning: 'EX_USAGE', desc: 'Usage incorrect de la commande', example: 'command --invalid', category: 'reserved' },
    { code: 65, meaning: 'EX_DATAERR', desc: 'Donnees d\'entree incorrectes', example: 'Invalid input format', category: 'reserved' },
    { code: 66, meaning: 'EX_NOINPUT', desc: 'Fichier d\'entree inexistant ou illisible', example: 'cat nonexistent', category: 'reserved' },
    { code: 67, meaning: 'EX_NOUSER', desc: 'Utilisateur inexistant', example: 'Unknown user', category: 'reserved' },
    { code: 68, meaning: 'EX_NOHOST', desc: 'Hote inexistant', example: 'Unknown host', category: 'reserved' },
    { code: 69, meaning: 'EX_UNAVAILABLE', desc: 'Service indisponible', example: 'Service unavailable', category: 'reserved' },
    { code: 70, meaning: 'EX_SOFTWARE', desc: 'Erreur logicielle interne', example: 'Internal error', category: 'reserved' },
    { code: 71, meaning: 'EX_OSERR', desc: 'Erreur systeme (fork, pipe)', example: 'OS error', category: 'reserved' },
    { code: 72, meaning: 'EX_OSFILE', desc: 'Fichier systeme critique manquant', example: '/etc/passwd missing', category: 'reserved' },
    { code: 73, meaning: 'EX_CANTCREAT', desc: 'Impossible de creer un fichier', example: 'Cannot create file', category: 'reserved' },
    { code: 74, meaning: 'EX_IOERR', desc: 'Erreur I/O', example: 'I/O error', category: 'reserved' },
    { code: 75, meaning: 'EX_TEMPFAIL', desc: 'Echec temporaire', example: 'Temp failure, retry', category: 'reserved' },
    { code: 76, meaning: 'EX_PROTOCOL', desc: 'Erreur de protocole', example: 'Protocol error', category: 'reserved' },
    { code: 77, meaning: 'EX_NOPERM', desc: 'Permission insuffisante', example: 'Permission denied', category: 'reserved' },
    { code: 78, meaning: 'EX_CONFIG', desc: 'Erreur de configuration', example: 'Config error', category: 'reserved' },
    { code: 126, meaning: 'Not executable', desc: 'Commande trouvee mais non executable', example: './script (no +x)', category: 'error' },
    { code: 127, meaning: 'Command not found', desc: 'Commande introuvable', example: 'nonexistentcmd', category: 'error' },
    { code: 128, meaning: 'Invalid exit argument', desc: 'Argument exit invalide', example: 'exit 3.14', category: 'error' },
    { code: 129, meaning: 'SIGHUP (128+1)', desc: 'Hangup - Terminal ferme', example: 'kill -1 $$', category: 'signal' },
    { code: 130, meaning: 'SIGINT (128+2)', desc: 'Interrupt - Ctrl+C', example: 'Ctrl+C', category: 'signal' },
    { code: 131, meaning: 'SIGQUIT (128+3)', desc: 'Quit - Ctrl+\\', example: 'Ctrl+\\', category: 'signal' },
    { code: 132, meaning: 'SIGILL (128+4)', desc: 'Illegal instruction', example: 'Invalid CPU instruction', category: 'signal' },
    { code: 133, meaning: 'SIGTRAP (128+5)', desc: 'Trace trap', example: 'Debugger trap', category: 'signal' },
    { code: 134, meaning: 'SIGABRT (128+6)', desc: 'Abort', example: 'abort()', category: 'signal' },
    { code: 135, meaning: 'SIGBUS (128+7)', desc: 'Bus error', example: 'Memory alignment error', category: 'signal' },
    { code: 136, meaning: 'SIGFPE (128+8)', desc: 'Floating point exception', example: 'Division by zero', category: 'signal' },
    { code: 137, meaning: 'SIGKILL (128+9)', desc: 'Kill - Non interceptable', example: 'kill -9 $$', category: 'signal' },
    { code: 139, meaning: 'SIGSEGV (128+11)', desc: 'Segmentation fault', example: 'Invalid memory access', category: 'signal' },
    { code: 141, meaning: 'SIGPIPE (128+13)', desc: 'Broken pipe', example: 'yes | head', category: 'signal' },
    { code: 143, meaning: 'SIGTERM (128+15)', desc: 'Terminate', example: 'kill $$', category: 'signal' },
    { code: 255, meaning: 'Exit status out of range', desc: 'Code de sortie hors plage (0-255)', example: 'exit -1', category: 'error' }
];

const SIGNALS = [
    { name: 'SIGHUP', num: 1, desc: 'Hangup detected on controlling terminal' },
    { name: 'SIGINT', num: 2, desc: 'Interrupt from keyboard (Ctrl+C)' },
    { name: 'SIGQUIT', num: 3, desc: 'Quit from keyboard (Ctrl+\\)' },
    { name: 'SIGILL', num: 4, desc: 'Illegal instruction' },
    { name: 'SIGTRAP', num: 5, desc: 'Trace/breakpoint trap' },
    { name: 'SIGABRT', num: 6, desc: 'Abort signal from abort()' },
    { name: 'SIGBUS', num: 7, desc: 'Bus error (bad memory access)' },
    { name: 'SIGFPE', num: 8, desc: 'Floating-point exception' },
    { name: 'SIGKILL', num: 9, desc: 'Kill signal (cannot be caught)' },
    { name: 'SIGUSR1', num: 10, desc: 'User-defined signal 1' },
    { name: 'SIGSEGV', num: 11, desc: 'Invalid memory reference' },
    { name: 'SIGUSR2', num: 12, desc: 'User-defined signal 2' },
    { name: 'SIGPIPE', num: 13, desc: 'Broken pipe: write to pipe with no readers' },
    { name: 'SIGALRM', num: 14, desc: 'Timer signal from alarm()' },
    { name: 'SIGTERM', num: 15, desc: 'Termination signal' },
    { name: 'SIGCHLD', num: 17, desc: 'Child stopped or terminated' },
    { name: 'SIGCONT', num: 18, desc: 'Continue if stopped' },
    { name: 'SIGSTOP', num: 19, desc: 'Stop process (cannot be caught)' },
    { name: 'SIGTSTP', num: 20, desc: 'Stop typed at terminal (Ctrl+Z)' }
];

let currentCategory = 'all';

function renderCodes(codes) {
    const tbody = document.getElementById('codes-body');
    tbody.innerHTML = codes.map(c => `
        <tr data-category="${c.category}">
            <td><span class="code-badge ${c.category}">${c.code}</span></td>
            <td><strong>${c.meaning}</strong></td>
            <td>${c.desc}</td>
            <td><code>${c.example}</code></td>
        </tr>
    `).join('');
}

function renderSignals() {
    const tbody = document.getElementById('signals-body');
    tbody.innerHTML = SIGNALS.map(s => `
        <tr>
            <td><strong>${s.name}</strong></td>
            <td>${s.num}</td>
            <td><span class="code-badge signal">${128 + s.num}</span></td>
            <td>${s.desc}</td>
        </tr>
    `).join('');
}

function filterCodes() {
    const search = document.getElementById('search-input').value.toLowerCase();
    let filtered = EXIT_CODES;

    if (currentCategory !== 'all') {
        filtered = filtered.filter(c => c.category === currentCategory);
    }

    if (search) {
        filtered = filtered.filter(c =>
            c.code.toString().includes(search) ||
            c.meaning.toLowerCase().includes(search) ||
            c.desc.toLowerCase().includes(search)
        );
    }

    renderCodes(filtered);
}

function filterCategory(category) {
    currentCategory = category;
    document.querySelectorAll('.cat-btn').forEach(btn => btn.classList.remove('active'));
    event.target.classList.add('active');
    filterCodes();
}

function lookupCode() {
    const code = parseInt(document.getElementById('code-input').value);
    const resultDiv = document.getElementById('lookup-result');

    if (isNaN(code) || code < 0 || code > 255) {
        resultDiv.textContent = 'Entrez un code (0-255)';
        return;
    }

    const found = EXIT_CODES.find(c => c.code === code);

    if (found) {
        resultDiv.innerHTML = `<strong>${found.meaning}</strong>: ${found.desc}`;
    } else if (code > 128 && code < 192) {
        const signal = SIGNALS.find(s => s.num === code - 128);
        if (signal) {
            resultDiv.innerHTML = `<strong>${signal.name}</strong> (128+${signal.num}): ${signal.desc}`;
        } else {
            resultDiv.innerHTML = `Signal ${code - 128}: Process terminated by signal`;
        }
    } else {
        resultDiv.textContent = 'Code non standard - verifiez la documentation du programme';
    }
}

// Initialize
renderCodes(EXIT_CODES);
renderSignals();
</script>
