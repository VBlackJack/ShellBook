---
tags:
  - tools
  - time
  - unix
  - timestamp
---

# Unix Timestamp Converter

Conversion entre timestamps Unix et dates lisibles.

<div class="tool-container">

<div class="current-time">
    <h3>Heure actuelle</h3>
    <div class="time-display">
        <div class="time-box">
            <span id="current-ts" class="big-number">-</span>
            <small>Unix Timestamp</small>
        </div>
        <div class="time-box">
            <span id="current-date" class="big-number">-</span>
            <small>Date/Heure locale</small>
        </div>
    </div>
</div>

<div class="converter-section">
    <h3>Timestamp &rarr; Date</h3>
    <div class="input-row">
        <input type="text" id="ts-input" placeholder="1702569600">
        <select id="ts-unit">
            <option value="s">Secondes</option>
            <option value="ms">Millisecondes</option>
        </select>
        <button onclick="tsToDate()" class="action-btn">Convertir</button>
    </div>
    <div id="ts-result" class="result-display">
        <table>
            <tr><td>UTC</td><td id="res-utc">-</td></tr>
            <tr><td>Local</td><td id="res-local">-</td></tr>
            <tr><td>ISO 8601</td><td id="res-iso">-</td></tr>
            <tr><td>RFC 2822</td><td id="res-rfc">-</td></tr>
            <tr><td>Relatif</td><td id="res-relative">-</td></tr>
        </table>
    </div>
</div>

<div class="converter-section">
    <h3>Date &rarr; Timestamp</h3>
    <div class="date-inputs">
        <div class="input-group">
            <label>Date :</label>
            <input type="date" id="date-input">
        </div>
        <div class="input-group">
            <label>Heure :</label>
            <input type="time" id="time-input" value="00:00">
        </div>
        <div class="input-group">
            <label>Fuseau :</label>
            <select id="tz-select">
                <option value="local">Local</option>
                <option value="utc">UTC</option>
            </select>
        </div>
        <button onclick="dateToTs()" class="action-btn">Convertir</button>
    </div>
    <div id="date-result" class="result-display">
        <table>
            <tr><td>Secondes</td><td id="res-ts-s">-</td></tr>
            <tr><td>Millisecondes</td><td id="res-ts-ms">-</td></tr>
        </table>
    </div>
</div>

<div class="presets-section">
    <h3>Dates courantes</h3>
    <div class="presets-grid">
        <button onclick="setTs(0)">Epoch (1970)</button>
        <button onclick="setTs(Date.now()/1000)">Maintenant</button>
        <button onclick="setTs(Date.now()/1000 + 86400)">Demain</button>
        <button onclick="setTs(Date.now()/1000 - 86400)">Hier</button>
        <button onclick="setTs(Date.now()/1000 + 604800)">+1 semaine</button>
        <button onclick="setTs(Date.now()/1000 + 2592000)">+30 jours</button>
        <button onclick="setTs(2147483647)">Y2K38 (max 32-bit)</button>
        <button onclick="setTs(253402300799)">31 Dec 9999</button>
    </div>
</div>

</div>

## Reference

### Conversions courantes

| Periode | Secondes |
|---------|----------|
| 1 minute | 60 |
| 1 heure | 3,600 |
| 1 jour | 86,400 |
| 1 semaine | 604,800 |
| 30 jours | 2,592,000 |
| 365 jours | 31,536,000 |

### Formats de date

| Format | Exemple |
|--------|---------|
| Unix (s) | `1702569600` |
| Unix (ms) | `1702569600000` |
| ISO 8601 | `2023-12-14T16:00:00.000Z` |
| RFC 2822 | `Thu, 14 Dec 2023 16:00:00 +0000` |

### CLI

```bash
# Timestamp actuel
date +%s

# Timestamp en milliseconds
date +%s%3N

# Timestamp vers date
date -d @1702569600

# Date vers timestamp
date -d "2023-12-14 16:00:00" +%s

# Date ISO
date -u +"%Y-%m-%dT%H:%M:%SZ"
```

### Langages

```python
# Python
import time
time.time()                    # Timestamp actuel
datetime.fromtimestamp(ts)     # Vers datetime
datetime.now().timestamp()     # Depuis datetime
```

```javascript
// JavaScript
Date.now()                     // Timestamp ms
Math.floor(Date.now()/1000)    // Timestamp s
new Date(ts * 1000)            // Vers Date
```

```bash
# PowerShell
[DateTimeOffset]::Now.ToUnixTimeSeconds()
[DateTimeOffset]::FromUnixTimeSeconds(1702569600)
```

!!! warning "Probleme Y2K38"
    Les systemes 32-bit ont un timestamp max de **2147483647**
    (19 janvier 2038 a 03:14:07 UTC). Utilisez des entiers 64-bit.

<style>
.tool-container {
    background: var(--md-code-bg-color);
    padding: 20px;
    border-radius: 8px;
    margin: 20px 0;
}
.current-time {
    background: var(--md-default-bg-color);
    padding: 20px;
    border-radius: 4px;
    margin-bottom: 20px;
}
.current-time h3 {
    margin: 0 0 15px 0;
}
.time-display {
    display: flex;
    gap: 20px;
    flex-wrap: wrap;
}
.time-box {
    flex: 1;
    min-width: 200px;
    text-align: center;
    padding: 15px;
    background: var(--md-code-bg-color);
    border-radius: 4px;
}
.big-number {
    display: block;
    font-family: monospace;
    font-size: 24px;
    font-weight: bold;
    color: var(--md-primary-fg-color);
    margin-bottom: 5px;
}
.time-box small {
    color: var(--md-default-fg-color--light);
}
.converter-section {
    background: var(--md-default-bg-color);
    padding: 20px;
    border-radius: 4px;
    margin-bottom: 20px;
}
.converter-section h3 {
    margin: 0 0 15px 0;
}
.input-row {
    display: flex;
    gap: 10px;
    flex-wrap: wrap;
    align-items: center;
}
.input-row input, .input-row select {
    padding: 10px;
    font-size: 16px;
    font-family: monospace;
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    background: var(--md-code-bg-color);
    color: var(--md-default-fg-color);
}
.input-row input[type="text"] {
    flex: 1;
    min-width: 200px;
}
.date-inputs {
    display: flex;
    gap: 15px;
    flex-wrap: wrap;
    align-items: flex-end;
}
.date-inputs .input-group {
    margin: 0;
}
.date-inputs .input-group label {
    display: block;
    font-size: 12px;
    margin-bottom: 5px;
}
.date-inputs input, .date-inputs select {
    padding: 10px;
    font-size: 14px;
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    background: var(--md-code-bg-color);
    color: var(--md-default-fg-color);
}
.action-btn {
    padding: 10px 20px;
    background: var(--md-primary-fg-color);
    color: white;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    font-size: 14px;
}
.action-btn:hover {
    opacity: 0.9;
}
.result-display {
    margin-top: 15px;
    padding: 15px;
    background: var(--md-code-bg-color);
    border-radius: 4px;
}
.result-display table {
    width: 100%;
}
.result-display td {
    padding: 8px;
    border-bottom: 1px solid var(--md-default-fg-color--lightest);
}
.result-display td:first-child {
    font-weight: bold;
    width: 120px;
}
.result-display td:last-child {
    font-family: monospace;
}
.presets-section {
    background: var(--md-default-bg-color);
    padding: 20px;
    border-radius: 4px;
}
.presets-section h3 {
    margin: 0 0 15px 0;
}
.presets-grid {
    display: flex;
    gap: 10px;
    flex-wrap: wrap;
}
.presets-grid button {
    padding: 8px 16px;
    border: 1px solid var(--md-primary-fg-color);
    border-radius: 4px;
    background: var(--md-code-bg-color);
    color: var(--md-default-fg-color);
    cursor: pointer;
    font-size: 13px;
}
.presets-grid button:hover {
    background: var(--md-primary-fg-color);
    color: white;
}
</style>

<script>
function updateCurrentTime() {
    const now = new Date();
    const ts = Math.floor(now.getTime() / 1000);

    document.getElementById('current-ts').textContent = ts;
    document.getElementById('current-date').textContent = now.toLocaleString('fr-FR');
}

function getRelativeTime(date) {
    const now = new Date();
    const diff = date - now;
    const absDiff = Math.abs(diff);

    const seconds = Math.floor(absDiff / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);
    const months = Math.floor(days / 30);
    const years = Math.floor(days / 365);

    let result;
    if (years > 0) result = years + ' an' + (years > 1 ? 's' : '');
    else if (months > 0) result = months + ' mois';
    else if (days > 0) result = days + ' jour' + (days > 1 ? 's' : '');
    else if (hours > 0) result = hours + ' heure' + (hours > 1 ? 's' : '');
    else if (minutes > 0) result = minutes + ' minute' + (minutes > 1 ? 's' : '');
    else result = seconds + ' seconde' + (seconds > 1 ? 's' : '');

    return diff > 0 ? 'dans ' + result : 'il y a ' + result;
}

function tsToDate() {
    const input = document.getElementById('ts-input').value;
    const unit = document.getElementById('ts-unit').value;

    let ts = parseInt(input);
    if (isNaN(ts)) return;

    if (unit === 'ms') ts = ts / 1000;

    const date = new Date(ts * 1000);

    document.getElementById('res-utc').textContent = date.toUTCString();
    document.getElementById('res-local').textContent = date.toLocaleString('fr-FR');
    document.getElementById('res-iso').textContent = date.toISOString();
    document.getElementById('res-rfc').textContent = date.toUTCString();
    document.getElementById('res-relative').textContent = getRelativeTime(date);
}

function dateToTs() {
    const dateVal = document.getElementById('date-input').value;
    const timeVal = document.getElementById('time-input').value;
    const tz = document.getElementById('tz-select').value;

    if (!dateVal) return;

    let date;
    if (tz === 'utc') {
        date = new Date(dateVal + 'T' + timeVal + ':00Z');
    } else {
        date = new Date(dateVal + 'T' + timeVal + ':00');
    }

    const ts = Math.floor(date.getTime() / 1000);

    document.getElementById('res-ts-s').textContent = ts;
    document.getElementById('res-ts-ms').textContent = ts * 1000;
}

function setTs(ts) {
    document.getElementById('ts-input').value = Math.floor(ts);
    tsToDate();
}

// Initialize
updateCurrentTime();
setInterval(updateCurrentTime, 1000);

// Set default date to today
const today = new Date().toISOString().split('T')[0];
document.getElementById('date-input').value = today;

// Event listeners
document.getElementById('ts-input').addEventListener('input', tsToDate);
document.getElementById('ts-unit').addEventListener('change', tsToDate);
</script>
