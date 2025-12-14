---
tags:
  - tools
  - sla
  - uptime
  - availability
  - calculator
---

# SLA Calculator

Calculateur de disponibilite SLA et temps d'indisponibilite autorise.

<div class="tool-container">

<div class="calculator-section">
    <h3>Calculateur SLA</h3>
    <div class="calc-grid">
        <div class="form-group">
            <label for="sla-percent">SLA (%)</label>
            <input type="number" id="sla-percent" value="99.9" min="0" max="100" step="0.001" oninput="calculateSLA()">
        </div>
        <div class="form-group">
            <label>Presets</label>
            <div class="preset-buttons">
                <button onclick="setSLA(99)">99%</button>
                <button onclick="setSLA(99.9)" class="active">99.9%</button>
                <button onclick="setSLA(99.95)">99.95%</button>
                <button onclick="setSLA(99.99)">99.99%</button>
                <button onclick="setSLA(99.999)">99.999%</button>
            </div>
        </div>
    </div>

    <div class="results-grid">
        <div class="result-card">
            <div class="result-label">Par Jour</div>
            <div class="result-value" id="downtime-day">1m 26s</div>
            <div class="result-sub">Uptime: <span id="uptime-day">23h 58m</span></div>
        </div>
        <div class="result-card">
            <div class="result-label">Par Semaine</div>
            <div class="result-value" id="downtime-week">10m 5s</div>
            <div class="result-sub">Uptime: <span id="uptime-week">6j 23h 50m</span></div>
        </div>
        <div class="result-card">
            <div class="result-label">Par Mois (30j)</div>
            <div class="result-value" id="downtime-month">43m 12s</div>
            <div class="result-sub">Uptime: <span id="uptime-month">29j 23h 17m</span></div>
        </div>
        <div class="result-card highlight">
            <div class="result-label">Par An</div>
            <div class="result-value" id="downtime-year">8h 45m 36s</div>
            <div class="result-sub">Uptime: <span id="uptime-year">364j 15h 14m</span></div>
        </div>
    </div>
</div>

<div class="reverse-section">
    <h3>Calcul Inverse</h3>
    <p class="hint">Calculez le SLA a partir du temps d'indisponibilite</p>
    <div class="reverse-grid">
        <div class="form-group">
            <label for="downtime-input">Temps d'indisponibilite</label>
            <input type="number" id="downtime-input" value="8" min="0" oninput="calculateReverse()">
        </div>
        <div class="form-group">
            <label for="downtime-unit">Unite</label>
            <select id="downtime-unit" onchange="calculateReverse()">
                <option value="minutes">Minutes / mois</option>
                <option value="hours" selected>Heures / an</option>
                <option value="days">Jours / an</option>
            </select>
        </div>
        <div class="form-group">
            <label>SLA Equivalent</label>
            <div class="reverse-result" id="reverse-result">99.91%</div>
        </div>
    </div>
</div>

<div class="nines-section">
    <h3>Table des "Nines"</h3>
    <table class="nines-table">
        <thead>
            <tr>
                <th>Nines</th>
                <th>SLA</th>
                <th>Downtime/An</th>
                <th>Downtime/Mois</th>
                <th>Downtime/Jour</th>
            </tr>
        </thead>
        <tbody id="nines-table-body">
        </tbody>
    </table>
</div>

<div class="composite-section">
    <h3>SLA Composite</h3>
    <p class="hint">Calculez le SLA global d'un systeme avec plusieurs composants en serie</p>
    <div class="composite-inputs" id="composite-inputs">
        <div class="composite-row">
            <input type="text" placeholder="Composant" value="Load Balancer">
            <input type="number" placeholder="SLA %" value="99.99" step="0.01">
            <button onclick="removeComponent(this)" class="remove-btn">×</button>
        </div>
        <div class="composite-row">
            <input type="text" placeholder="Composant" value="Web Server">
            <input type="number" placeholder="SLA %" value="99.9" step="0.01">
            <button onclick="removeComponent(this)" class="remove-btn">×</button>
        </div>
        <div class="composite-row">
            <input type="text" placeholder="Composant" value="Database">
            <input type="number" placeholder="SLA %" value="99.95" step="0.01">
            <button onclick="removeComponent(this)" class="remove-btn">×</button>
        </div>
    </div>
    <button onclick="addComponent()" class="add-btn">+ Ajouter composant</button>
    <div class="composite-result">
        <span>SLA Global:</span>
        <strong id="composite-sla">99.84%</strong>
        <span class="composite-downtime">≈ <span id="composite-downtime">14h/an</span></span>
    </div>
</div>

</div>

## Formules

$$SLA\% = \frac{Uptime}{Uptime + Downtime} \times 100$$

$$Downtime_{autorise} = Periode \times (1 - \frac{SLA}{100})$$

$$SLA_{composite} = SLA_1 \times SLA_2 \times ... \times SLA_n$$

## Bonnes Pratiques

| SLA | Use Case | Exigences |
|-----|----------|-----------|
| **99%** | Services internes | Monitoring basique |
| **99.9%** | Applications business | Redondance, alerting |
| **99.95%** | E-commerce | Multi-AZ, failover auto |
| **99.99%** | Services critiques | Multi-region, chaos testing |
| **99.999%** | Telecom, finance | Architecture distribuee globale |

<style>
.tool-container {
    background: var(--md-code-bg-color);
    padding: 20px;
    border-radius: 8px;
    margin: 20px 0;
}
.calculator-section, .reverse-section, .nines-section, .composite-section {
    background: var(--md-default-bg-color);
    padding: 20px;
    border-radius: 4px;
    margin-bottom: 20px;
}
.calculator-section h3, .reverse-section h3, .nines-section h3, .composite-section h3 {
    margin: 0 0 15px 0;
}
.calc-grid {
    display: grid;
    grid-template-columns: 200px 1fr;
    gap: 20px;
    align-items: end;
    margin-bottom: 20px;
}
@media (max-width: 600px) {
    .calc-grid {
        grid-template-columns: 1fr;
    }
}
.form-group label {
    display: block;
    font-size: 12px;
    font-weight: bold;
    margin-bottom: 5px;
}
.form-group input, .form-group select {
    width: 100%;
    padding: 12px;
    font-size: 18px;
    font-family: monospace;
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    background: var(--md-code-bg-color);
    color: var(--md-default-fg-color);
}
.preset-buttons {
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
}
.preset-buttons button {
    padding: 10px 15px;
    background: var(--md-code-bg-color);
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    cursor: pointer;
    color: var(--md-default-fg-color);
    font-family: monospace;
}
.preset-buttons button.active, .preset-buttons button:hover {
    background: var(--md-primary-fg-color);
    color: white;
    border-color: var(--md-primary-fg-color);
}
.results-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 15px;
}
.result-card {
    background: var(--md-code-bg-color);
    padding: 20px;
    border-radius: 4px;
    text-align: center;
}
.result-card.highlight {
    background: var(--md-primary-fg-color);
    color: white;
}
.result-label {
    font-size: 12px;
    opacity: 0.8;
    margin-bottom: 5px;
}
.result-value {
    font-size: 24px;
    font-weight: bold;
    font-family: 'JetBrains Mono', monospace;
}
.result-sub {
    font-size: 11px;
    opacity: 0.7;
    margin-top: 10px;
}
.hint {
    font-size: 12px;
    color: var(--md-default-fg-color--light);
    margin-bottom: 15px;
}
.reverse-grid {
    display: grid;
    grid-template-columns: 1fr 1fr 1fr;
    gap: 20px;
    align-items: end;
}
@media (max-width: 768px) {
    .reverse-grid {
        grid-template-columns: 1fr;
    }
}
.reverse-result {
    padding: 12px;
    background: var(--md-code-bg-color);
    border-radius: 4px;
    font-size: 24px;
    font-weight: bold;
    font-family: monospace;
    text-align: center;
    color: var(--md-primary-fg-color);
}
.nines-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
}
.nines-table th, .nines-table td {
    padding: 12px;
    text-align: center;
    border-bottom: 1px solid var(--md-default-fg-color--lightest);
}
.nines-table th {
    background: var(--md-code-bg-color);
}
.nines-table tr:hover {
    background: var(--md-code-bg-color);
}
.nines-table .highlight-row {
    background: rgba(var(--md-primary-fg-color--rgb), 0.1);
}
.composite-inputs {
    margin-bottom: 15px;
}
.composite-row {
    display: grid;
    grid-template-columns: 1fr 120px auto;
    gap: 10px;
    margin-bottom: 10px;
}
.composite-row input {
    padding: 10px;
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    background: var(--md-code-bg-color);
    color: var(--md-default-fg-color);
}
.remove-btn {
    padding: 10px 15px;
    background: #f44336;
    color: white;
    border: none;
    border-radius: 4px;
    cursor: pointer;
}
.add-btn {
    padding: 10px 20px;
    background: var(--md-primary-fg-color);
    color: white;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    margin-bottom: 15px;
}
.composite-result {
    display: flex;
    align-items: center;
    gap: 15px;
    padding: 15px;
    background: var(--md-code-bg-color);
    border-radius: 4px;
}
.composite-result strong {
    font-size: 28px;
    font-family: monospace;
    color: var(--md-primary-fg-color);
}
.composite-downtime {
    color: var(--md-default-fg-color--light);
    font-size: 14px;
}
</style>

<script>
const MINUTES_PER_DAY = 24 * 60;
const MINUTES_PER_WEEK = 7 * MINUTES_PER_DAY;
const MINUTES_PER_MONTH = 30 * MINUTES_PER_DAY;
const MINUTES_PER_YEAR = 365 * MINUTES_PER_DAY;

function formatDuration(minutes) {
    if (minutes < 1) {
        return `${Math.round(minutes * 60)}s`;
    }
    if (minutes < 60) {
        const m = Math.floor(minutes);
        const s = Math.round((minutes - m) * 60);
        return s > 0 ? `${m}m ${s}s` : `${m}m`;
    }
    if (minutes < MINUTES_PER_DAY) {
        const h = Math.floor(minutes / 60);
        const m = Math.round(minutes % 60);
        return m > 0 ? `${h}h ${m}m` : `${h}h`;
    }
    const d = Math.floor(minutes / MINUTES_PER_DAY);
    const h = Math.floor((minutes % MINUTES_PER_DAY) / 60);
    const m = Math.round(minutes % 60);
    let result = `${d}j`;
    if (h > 0) result += ` ${h}h`;
    if (m > 0) result += ` ${m}m`;
    return result;
}

function calculateSLA() {
    const sla = parseFloat(document.getElementById('sla-percent').value) || 0;
    const downtimePercent = (100 - sla) / 100;

    // Calculate downtime
    const dayDown = MINUTES_PER_DAY * downtimePercent;
    const weekDown = MINUTES_PER_WEEK * downtimePercent;
    const monthDown = MINUTES_PER_MONTH * downtimePercent;
    const yearDown = MINUTES_PER_YEAR * downtimePercent;

    // Calculate uptime
    const dayUp = MINUTES_PER_DAY - dayDown;
    const weekUp = MINUTES_PER_WEEK - weekDown;
    const monthUp = MINUTES_PER_MONTH - monthDown;
    const yearUp = MINUTES_PER_YEAR - yearDown;

    // Update display
    document.getElementById('downtime-day').textContent = formatDuration(dayDown);
    document.getElementById('downtime-week').textContent = formatDuration(weekDown);
    document.getElementById('downtime-month').textContent = formatDuration(monthDown);
    document.getElementById('downtime-year').textContent = formatDuration(yearDown);

    document.getElementById('uptime-day').textContent = formatDuration(dayUp);
    document.getElementById('uptime-week').textContent = formatDuration(weekUp);
    document.getElementById('uptime-month').textContent = formatDuration(monthUp);
    document.getElementById('uptime-year').textContent = formatDuration(yearUp);

    // Update preset buttons
    document.querySelectorAll('.preset-buttons button').forEach(btn => {
        btn.classList.remove('active');
        if (parseFloat(btn.textContent) === sla) {
            btn.classList.add('active');
        }
    });
}

function setSLA(value) {
    document.getElementById('sla-percent').value = value;
    calculateSLA();
}

function calculateReverse() {
    const downtime = parseFloat(document.getElementById('downtime-input').value) || 0;
    const unit = document.getElementById('downtime-unit').value;

    let downtimeMinutes;
    let totalMinutes;

    switch (unit) {
        case 'minutes':
            downtimeMinutes = downtime;
            totalMinutes = MINUTES_PER_MONTH;
            break;
        case 'hours':
            downtimeMinutes = downtime * 60;
            totalMinutes = MINUTES_PER_YEAR;
            break;
        case 'days':
            downtimeMinutes = downtime * MINUTES_PER_DAY;
            totalMinutes = MINUTES_PER_YEAR;
            break;
    }

    const sla = ((totalMinutes - downtimeMinutes) / totalMinutes) * 100;
    document.getElementById('reverse-result').textContent = sla.toFixed(4) + '%';
}

function buildNinesTable() {
    const nines = [
        { label: 'Two nines', sla: 99 },
        { label: 'Three nines', sla: 99.9 },
        { label: 'Three and a half', sla: 99.95 },
        { label: 'Four nines', sla: 99.99 },
        { label: 'Five nines', sla: 99.999 },
        { label: 'Six nines', sla: 99.9999 }
    ];

    const tbody = document.getElementById('nines-table-body');
    tbody.innerHTML = nines.map(n => {
        const downtimePercent = (100 - n.sla) / 100;
        const yearDown = MINUTES_PER_YEAR * downtimePercent;
        const monthDown = MINUTES_PER_MONTH * downtimePercent;
        const dayDown = MINUTES_PER_DAY * downtimePercent;

        const highlight = n.sla === 99.9 ? 'highlight-row' : '';

        return `
            <tr class="${highlight}">
                <td><strong>${n.label}</strong></td>
                <td>${n.sla}%</td>
                <td>${formatDuration(yearDown)}</td>
                <td>${formatDuration(monthDown)}</td>
                <td>${formatDuration(dayDown)}</td>
            </tr>
        `;
    }).join('');
}

function addComponent() {
    const container = document.getElementById('composite-inputs');
    const row = document.createElement('div');
    row.className = 'composite-row';
    row.innerHTML = `
        <input type="text" placeholder="Composant" value="New Component">
        <input type="number" placeholder="SLA %" value="99.9" step="0.01">
        <button onclick="removeComponent(this)" class="remove-btn">×</button>
    `;
    container.appendChild(row);
    calculateComposite();
}

function removeComponent(btn) {
    const rows = document.querySelectorAll('.composite-row');
    if (rows.length > 1) {
        btn.parentElement.remove();
        calculateComposite();
    }
}

function calculateComposite() {
    const rows = document.querySelectorAll('.composite-row');
    let compositeSLA = 1;

    rows.forEach(row => {
        const slaInput = row.querySelectorAll('input')[1];
        const sla = parseFloat(slaInput.value) || 100;
        compositeSLA *= sla / 100;
    });

    const finalSLA = compositeSLA * 100;
    const downtimeMinutes = MINUTES_PER_YEAR * (1 - compositeSLA);

    document.getElementById('composite-sla').textContent = finalSLA.toFixed(2) + '%';
    document.getElementById('composite-downtime').textContent = formatDuration(downtimeMinutes) + '/an';
}

// Event listeners for composite inputs
document.getElementById('composite-inputs').addEventListener('input', calculateComposite);

// Initialize
calculateSLA();
calculateReverse();
buildNinesTable();
calculateComposite();
</script>
