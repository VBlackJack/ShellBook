---
tags:
  - tools
  - timezone
  - time
  - converter
  - utc
---

# Timezone Converter

Conversion entre fuseaux horaires avec affichage temps reel.

<div class="tool-container">

<div class="current-time-section">
    <h3>Heure Actuelle</h3>
    <div class="current-time-grid" id="current-times"></div>
</div>

<div class="converter-section">
    <h3>Convertisseur</h3>
    <div class="converter-grid">
        <div class="input-column">
            <div class="form-group">
                <label for="source-tz">Fuseau source</label>
                <select id="source-tz" onchange="convert()"></select>
            </div>
            <div class="form-group">
                <label for="source-date">Date</label>
                <input type="date" id="source-date" onchange="convert()">
            </div>
            <div class="form-group">
                <label for="source-time">Heure</label>
                <input type="time" id="source-time" onchange="convert()">
            </div>
            <button onclick="setNow()" class="now-btn">Maintenant</button>
        </div>
        <div class="arrow">→</div>
        <div class="output-column">
            <div class="form-group">
                <label for="target-tz">Fuseau cible</label>
                <select id="target-tz" onchange="convert()"></select>
            </div>
            <div class="result-display">
                <div class="result-date" id="result-date">-</div>
                <div class="result-time" id="result-time">--:--</div>
                <div class="result-diff" id="result-diff">-</div>
            </div>
        </div>
    </div>
</div>

<div class="multi-tz-section">
    <h3>Comparaison Multi-Fuseaux</h3>
    <div class="tz-selector">
        <label>Ajouter un fuseau:</label>
        <select id="add-tz-select"></select>
        <button onclick="addTimezone()" class="add-btn">+</button>
    </div>
    <div class="multi-tz-grid" id="multi-tz-grid"></div>
</div>

<div class="meeting-section">
    <h3>Planificateur de Meeting</h3>
    <p class="hint">Trouvez le meilleur horaire pour une reunion multi-fuseaux</p>
    <div class="meeting-grid" id="meeting-grid"></div>
</div>

</div>

## Abbreviations Courantes

| Abbrev | Nom | UTC Offset |
|--------|-----|------------|
| **UTC** | Coordinated Universal Time | +00:00 |
| **CET** | Central European Time | +01:00 |
| **CEST** | Central European Summer Time | +02:00 |
| **EST** | Eastern Standard Time | -05:00 |
| **PST** | Pacific Standard Time | -08:00 |
| **JST** | Japan Standard Time | +09:00 |

## CLI Conversion

```bash
# Date actuelle en UTC
date -u

# Convertir vers un fuseau
TZ="America/New_York" date

# Afficher plusieurs fuseaux
for tz in UTC Europe/Paris America/New_York Asia/Tokyo; do
    echo "$tz: $(TZ=$tz date '+%Y-%m-%d %H:%M:%S')"
done

# Timestamp vers date locale
date -d @1700000000
```

<style>
.tool-container {
    background: var(--md-code-bg-color);
    padding: 20px;
    border-radius: 8px;
    margin: 20px 0;
}
.current-time-section, .converter-section, .multi-tz-section, .meeting-section {
    background: var(--md-default-bg-color);
    padding: 20px;
    border-radius: 4px;
    margin-bottom: 20px;
}
.current-time-section h3, .converter-section h3, .multi-tz-section h3, .meeting-section h3 {
    margin: 0 0 15px 0;
}
.current-time-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 15px;
}
.time-card {
    background: var(--md-code-bg-color);
    padding: 15px;
    border-radius: 4px;
    text-align: center;
}
.time-card .tz-name {
    font-size: 12px;
    color: var(--md-default-fg-color--light);
    margin-bottom: 5px;
}
.time-card .tz-time {
    font-size: 28px;
    font-weight: bold;
    font-family: 'JetBrains Mono', monospace;
}
.time-card .tz-date {
    font-size: 12px;
    color: var(--md-default-fg-color--light);
}
.time-card .tz-offset {
    font-size: 11px;
    color: var(--md-primary-fg-color);
    margin-top: 5px;
}
.converter-grid {
    display: grid;
    grid-template-columns: 1fr auto 1fr;
    gap: 20px;
    align-items: center;
}
@media (max-width: 768px) {
    .converter-grid {
        grid-template-columns: 1fr;
    }
    .arrow {
        transform: rotate(90deg);
    }
}
.form-group {
    margin-bottom: 15px;
}
.form-group label {
    display: block;
    font-size: 12px;
    font-weight: bold;
    margin-bottom: 5px;
}
.form-group input, .form-group select {
    width: 100%;
    padding: 10px;
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    background: var(--md-code-bg-color);
    color: var(--md-default-fg-color);
    font-family: monospace;
}
.now-btn, .add-btn {
    padding: 10px 20px;
    background: var(--md-primary-fg-color);
    color: white;
    border: none;
    border-radius: 4px;
    cursor: pointer;
}
.arrow {
    font-size: 24px;
    color: var(--md-primary-fg-color);
    text-align: center;
}
.result-display {
    background: var(--md-code-bg-color);
    padding: 20px;
    border-radius: 4px;
    text-align: center;
}
.result-date {
    font-size: 14px;
    color: var(--md-default-fg-color--light);
}
.result-time {
    font-size: 36px;
    font-weight: bold;
    font-family: 'JetBrains Mono', monospace;
    color: var(--md-primary-fg-color);
}
.result-diff {
    font-size: 12px;
    color: var(--md-default-fg-color--light);
    margin-top: 10px;
}
.tz-selector {
    display: flex;
    gap: 10px;
    align-items: center;
    margin-bottom: 15px;
}
.tz-selector select {
    flex: 1;
    padding: 8px;
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    background: var(--md-code-bg-color);
    color: var(--md-default-fg-color);
}
.multi-tz-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 10px;
}
.multi-tz-card {
    background: var(--md-code-bg-color);
    padding: 15px;
    border-radius: 4px;
    position: relative;
}
.multi-tz-card .remove-btn {
    position: absolute;
    top: 5px;
    right: 5px;
    background: none;
    border: none;
    color: var(--md-default-fg-color--light);
    cursor: pointer;
    font-size: 16px;
}
.multi-tz-card .tz-label {
    font-size: 11px;
    color: var(--md-default-fg-color--light);
}
.multi-tz-card .tz-city {
    font-weight: bold;
    margin-bottom: 5px;
}
.multi-tz-card .tz-current {
    font-size: 20px;
    font-family: monospace;
}
.meeting-grid {
    overflow-x: auto;
}
.meeting-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 12px;
}
.meeting-table th, .meeting-table td {
    padding: 8px;
    text-align: center;
    border: 1px solid var(--md-default-fg-color--lightest);
}
.meeting-table th {
    background: var(--md-code-bg-color);
}
.meeting-table .good {
    background: #4caf50;
    color: white;
}
.meeting-table .ok {
    background: #ff9800;
    color: white;
}
.meeting-table .bad {
    background: #f44336;
    color: white;
}
.hint {
    font-size: 12px;
    color: var(--md-default-fg-color--light);
    margin-bottom: 15px;
}
</style>

<script>
const TIMEZONES = [
    { id: 'UTC', name: 'UTC', city: 'UTC', offset: 0 },
    { id: 'Europe/London', name: 'GMT/BST', city: 'Londres', offset: 0 },
    { id: 'Europe/Paris', name: 'CET/CEST', city: 'Paris', offset: 1 },
    { id: 'Europe/Berlin', name: 'CET/CEST', city: 'Berlin', offset: 1 },
    { id: 'Europe/Moscow', name: 'MSK', city: 'Moscou', offset: 3 },
    { id: 'Asia/Dubai', name: 'GST', city: 'Dubai', offset: 4 },
    { id: 'Asia/Kolkata', name: 'IST', city: 'Mumbai', offset: 5.5 },
    { id: 'Asia/Singapore', name: 'SGT', city: 'Singapour', offset: 8 },
    { id: 'Asia/Tokyo', name: 'JST', city: 'Tokyo', offset: 9 },
    { id: 'Australia/Sydney', name: 'AEST/AEDT', city: 'Sydney', offset: 10 },
    { id: 'Pacific/Auckland', name: 'NZST/NZDT', city: 'Auckland', offset: 12 },
    { id: 'America/New_York', name: 'EST/EDT', city: 'New York', offset: -5 },
    { id: 'America/Chicago', name: 'CST/CDT', city: 'Chicago', offset: -6 },
    { id: 'America/Denver', name: 'MST/MDT', city: 'Denver', offset: -7 },
    { id: 'America/Los_Angeles', name: 'PST/PDT', city: 'Los Angeles', offset: -8 },
    { id: 'America/Sao_Paulo', name: 'BRT', city: 'Sao Paulo', offset: -3 }
];

const DEFAULT_DISPLAY = ['UTC', 'Europe/Paris', 'America/New_York', 'Asia/Tokyo'];
let selectedTimezones = [...DEFAULT_DISPLAY];

function getTimezoneOffset(tzId) {
    const now = new Date();
    const utc = new Date(now.toLocaleString('en-US', { timeZone: 'UTC' }));
    const tz = new Date(now.toLocaleString('en-US', { timeZone: tzId }));
    return (tz - utc) / (1000 * 60 * 60);
}

function formatTime(date, tzId) {
    return date.toLocaleTimeString('fr-FR', {
        timeZone: tzId,
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
    });
}

function formatDate(date, tzId) {
    return date.toLocaleDateString('fr-FR', {
        timeZone: tzId,
        weekday: 'short',
        day: 'numeric',
        month: 'short'
    });
}

function populateSelects() {
    const selects = ['source-tz', 'target-tz', 'add-tz-select'];
    selects.forEach(id => {
        const select = document.getElementById(id);
        select.innerHTML = TIMEZONES.map(tz =>
            `<option value="${tz.id}">${tz.city} (${tz.name})</option>`
        ).join('');
    });

    document.getElementById('source-tz').value = 'Europe/Paris';
    document.getElementById('target-tz').value = 'America/New_York';
}

function updateCurrentTimes() {
    const now = new Date();
    const grid = document.getElementById('current-times');

    grid.innerHTML = DEFAULT_DISPLAY.map(tzId => {
        const tz = TIMEZONES.find(t => t.id === tzId);
        const offset = getTimezoneOffset(tzId);
        const sign = offset >= 0 ? '+' : '';
        return `
            <div class="time-card">
                <div class="tz-name">${tz.city}</div>
                <div class="tz-time">${formatTime(now, tzId)}</div>
                <div class="tz-date">${formatDate(now, tzId)}</div>
                <div class="tz-offset">UTC${sign}${offset}</div>
            </div>
        `;
    }).join('');
}

function setNow() {
    const now = new Date();
    const sourceTz = document.getElementById('source-tz').value;

    document.getElementById('source-date').value = now.toLocaleDateString('en-CA', { timeZone: sourceTz });
    document.getElementById('source-time').value = now.toLocaleTimeString('en-GB', {
        timeZone: sourceTz,
        hour: '2-digit',
        minute: '2-digit'
    });

    convert();
}

function convert() {
    const sourceTz = document.getElementById('source-tz').value;
    const targetTz = document.getElementById('target-tz').value;
    const dateStr = document.getElementById('source-date').value;
    const timeStr = document.getElementById('source-time').value;

    if (!dateStr || !timeStr) return;

    // Create date in source timezone
    const sourceDate = new Date(`${dateStr}T${timeStr}:00`);

    // Get offset difference
    const sourceOffset = getTimezoneOffset(sourceTz);
    const targetOffset = getTimezoneOffset(targetTz);
    const diff = targetOffset - sourceOffset;

    // Display results
    document.getElementById('result-date').textContent = formatDate(sourceDate, targetTz);
    document.getElementById('result-time').textContent = formatTime(sourceDate, targetTz).substring(0, 5);

    const sign = diff >= 0 ? '+' : '';
    document.getElementById('result-diff').textContent = `Difference: ${sign}${diff}h`;

    updateMultiTz();
    updateMeetingGrid();
}

function addTimezone() {
    const tzId = document.getElementById('add-tz-select').value;
    if (!selectedTimezones.includes(tzId)) {
        selectedTimezones.push(tzId);
        updateMultiTz();
    }
}

function removeTimezone(tzId) {
    selectedTimezones = selectedTimezones.filter(t => t !== tzId);
    updateMultiTz();
}

function updateMultiTz() {
    const now = new Date();
    const grid = document.getElementById('multi-tz-grid');

    grid.innerHTML = selectedTimezones.map(tzId => {
        const tz = TIMEZONES.find(t => t.id === tzId);
        const offset = getTimezoneOffset(tzId);
        const sign = offset >= 0 ? '+' : '';
        return `
            <div class="multi-tz-card">
                <button class="remove-btn" onclick="removeTimezone('${tzId}')">×</button>
                <div class="tz-label">${tz.name} (UTC${sign}${offset})</div>
                <div class="tz-city">${tz.city}</div>
                <div class="tz-current">${formatTime(now, tzId).substring(0, 5)}</div>
            </div>
        `;
    }).join('');

    updateMeetingGrid();
}

function updateMeetingGrid() {
    if (selectedTimezones.length < 2) {
        document.getElementById('meeting-grid').innerHTML = '<p>Ajoutez au moins 2 fuseaux horaires</p>';
        return;
    }

    const hours = Array.from({ length: 24 }, (_, i) => i);

    let html = '<table class="meeting-table"><thead><tr><th>UTC</th>';
    selectedTimezones.forEach(tzId => {
        const tz = TIMEZONES.find(t => t.id === tzId);
        html += `<th>${tz.city}</th>`;
    });
    html += '</tr></thead><tbody>';

    hours.forEach(utcHour => {
        html += `<tr><td>${utcHour.toString().padStart(2, '0')}:00</td>`;

        selectedTimezones.forEach(tzId => {
            const offset = getTimezoneOffset(tzId);
            let localHour = (utcHour + offset + 24) % 24;
            const hourStr = Math.floor(localHour).toString().padStart(2, '0');

            let cls = '';
            if (localHour >= 9 && localHour < 18) cls = 'good';
            else if (localHour >= 7 && localHour < 21) cls = 'ok';
            else cls = 'bad';

            html += `<td class="${cls}">${hourStr}:00</td>`;
        });

        html += '</tr>';
    });

    html += '</tbody></table>';
    document.getElementById('meeting-grid').innerHTML = html;
}

// Initialize
populateSelects();
setNow();
updateCurrentTimes();
updateMultiTz();

// Update every second
setInterval(updateCurrentTimes, 1000);
</script>
