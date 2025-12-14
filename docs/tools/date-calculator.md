---
tags:
  - tools
  - date
  - time
  - calculator
  - duration
---

# Date Calculator

Calculateur de dates : difference entre dates, ajout/soustraction de jours.

<div class="tool-container">

<div class="diff-section">
    <h3>Difference entre Dates</h3>
    <div class="diff-grid">
        <div class="form-group">
            <label for="date-start">Date de debut</label>
            <input type="date" id="date-start" onchange="calculateDiff()">
        </div>
        <div class="form-group">
            <label for="date-end">Date de fin</label>
            <input type="date" id="date-end" onchange="calculateDiff()">
        </div>
        <button onclick="swapDates()" class="swap-btn">⇄</button>
    </div>
    <div class="diff-results">
        <div class="diff-card main">
            <div class="diff-value" id="diff-days">0</div>
            <div class="diff-label">jours</div>
        </div>
        <div class="diff-card">
            <div class="diff-value" id="diff-weeks">0</div>
            <div class="diff-label">semaines</div>
        </div>
        <div class="diff-card">
            <div class="diff-value" id="diff-months">0</div>
            <div class="diff-label">mois</div>
        </div>
        <div class="diff-card">
            <div class="diff-value" id="diff-years">0</div>
            <div class="diff-label">annees</div>
        </div>
    </div>
    <div class="diff-details" id="diff-details"></div>
</div>

<div class="add-section">
    <h3>Ajouter / Soustraire</h3>
    <div class="add-grid">
        <div class="form-group">
            <label for="add-date">Date de reference</label>
            <input type="date" id="add-date" onchange="calculateAdd()">
        </div>
        <div class="form-group">
            <label for="add-operation">Operation</label>
            <select id="add-operation" onchange="calculateAdd()">
                <option value="add">Ajouter (+)</option>
                <option value="sub">Soustraire (-)</option>
            </select>
        </div>
        <div class="form-group">
            <label for="add-value">Valeur</label>
            <input type="number" id="add-value" value="30" min="0" onchange="calculateAdd()">
        </div>
        <div class="form-group">
            <label for="add-unit">Unite</label>
            <select id="add-unit" onchange="calculateAdd()">
                <option value="days" selected>Jours</option>
                <option value="weeks">Semaines</option>
                <option value="months">Mois</option>
                <option value="years">Annees</option>
                <option value="business">Jours ouvres</option>
            </select>
        </div>
    </div>
    <div class="add-result">
        <div class="result-label">Resultat</div>
        <div class="result-date" id="add-result-date">-</div>
        <div class="result-day" id="add-result-day">-</div>
    </div>
    <div class="quick-adds">
        <button onclick="quickAdd(7, 'days')">+7 jours</button>
        <button onclick="quickAdd(14, 'days')">+14 jours</button>
        <button onclick="quickAdd(30, 'days')">+30 jours</button>
        <button onclick="quickAdd(90, 'days')">+90 jours</button>
        <button onclick="quickAdd(1, 'months')">+1 mois</button>
        <button onclick="quickAdd(3, 'months')">+3 mois</button>
        <button onclick="quickAdd(6, 'months')">+6 mois</button>
        <button onclick="quickAdd(1, 'years')">+1 an</button>
    </div>
</div>

<div class="workdays-section">
    <h3>Jours Ouvres</h3>
    <div class="workdays-grid">
        <div class="form-group">
            <label for="work-start">Date debut</label>
            <input type="date" id="work-start" onchange="calculateWorkdays()">
        </div>
        <div class="form-group">
            <label for="work-end">Date fin</label>
            <input type="date" id="work-end" onchange="calculateWorkdays()">
        </div>
    </div>
    <div class="workdays-results">
        <div class="work-card">
            <div class="work-value" id="work-total">0</div>
            <div class="work-label">jours ouvres</div>
        </div>
        <div class="work-card">
            <div class="work-value" id="work-weekends">0</div>
            <div class="work-label">weekends</div>
        </div>
        <div class="work-card">
            <div class="work-value" id="work-weeks">0</div>
            <div class="work-label">semaines</div>
        </div>
    </div>
</div>

<div class="special-section">
    <h3>Dates Speciales</h3>
    <div class="special-grid" id="special-dates"></div>
</div>

</div>

## Formules

```
Jours entre dates = Date2 - Date1

Jours ouvres = Total jours - Weekends - Feries

Date future = Date + (N * Unite)
```

## CLI Usage

```bash
# Date actuelle
date +%Y-%m-%d

# Ajouter des jours
date -d "+30 days" +%Y-%m-%d

# Difference entre dates
echo $(( ($(date -d "2024-12-31" +%s) - $(date +%s)) / 86400 )) jours

# Jour de la semaine
date -d "2024-07-14" +%A

# Timestamp vers date
date -d @1700000000
```

<style>
.tool-container {
    background: var(--md-code-bg-color);
    padding: 20px;
    border-radius: 8px;
    margin: 20px 0;
}
.diff-section, .add-section, .workdays-section, .special-section {
    background: var(--md-default-bg-color);
    padding: 20px;
    border-radius: 4px;
    margin-bottom: 20px;
}
.diff-section h3, .add-section h3, .workdays-section h3, .special-section h3 {
    margin: 0 0 15px 0;
}
.diff-grid, .workdays-grid {
    display: grid;
    grid-template-columns: 1fr 1fr auto;
    gap: 15px;
    align-items: end;
    margin-bottom: 20px;
}
.add-grid {
    display: grid;
    grid-template-columns: 1fr 1fr 100px 1fr;
    gap: 15px;
    align-items: end;
    margin-bottom: 20px;
}
@media (max-width: 768px) {
    .diff-grid, .add-grid, .workdays-grid {
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
    font-size: 14px;
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    background: var(--md-code-bg-color);
    color: var(--md-default-fg-color);
}
.swap-btn {
    padding: 12px 20px;
    background: var(--md-primary-fg-color);
    color: white;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    font-size: 18px;
}
.diff-results, .workdays-results {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
    gap: 15px;
    margin-bottom: 15px;
}
.diff-card, .work-card {
    background: var(--md-code-bg-color);
    padding: 20px;
    border-radius: 4px;
    text-align: center;
}
.diff-card.main {
    background: var(--md-primary-fg-color);
    color: white;
}
.diff-value, .work-value {
    font-size: 32px;
    font-weight: bold;
    font-family: 'JetBrains Mono', monospace;
}
.diff-label, .work-label {
    font-size: 12px;
    opacity: 0.8;
    margin-top: 5px;
}
.diff-details {
    font-size: 13px;
    color: var(--md-default-fg-color--light);
    padding: 10px;
    background: var(--md-code-bg-color);
    border-radius: 4px;
}
.add-result {
    background: var(--md-code-bg-color);
    padding: 20px;
    border-radius: 4px;
    text-align: center;
    margin-bottom: 15px;
}
.result-label {
    font-size: 12px;
    opacity: 0.7;
    margin-bottom: 5px;
}
.result-date {
    font-size: 28px;
    font-weight: bold;
    font-family: 'JetBrains Mono', monospace;
    color: var(--md-primary-fg-color);
}
.result-day {
    font-size: 14px;
    color: var(--md-default-fg-color--light);
    margin-top: 5px;
}
.quick-adds {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
}
.quick-adds button {
    padding: 8px 12px;
    background: var(--md-code-bg-color);
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    cursor: pointer;
    font-size: 12px;
    color: var(--md-default-fg-color);
}
.quick-adds button:hover {
    background: var(--md-primary-fg-color);
    color: white;
}
.special-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 15px;
}
.special-card {
    background: var(--md-code-bg-color);
    padding: 15px;
    border-radius: 4px;
}
.special-card .event-name {
    font-weight: bold;
    margin-bottom: 5px;
}
.special-card .event-date {
    font-family: monospace;
    color: var(--md-primary-fg-color);
}
.special-card .event-countdown {
    font-size: 12px;
    color: var(--md-default-fg-color--light);
    margin-top: 5px;
}
</style>

<script>
const DAYS_FR = ['Dimanche', 'Lundi', 'Mardi', 'Mercredi', 'Jeudi', 'Vendredi', 'Samedi'];
const MONTHS_FR = ['Janvier', 'Fevrier', 'Mars', 'Avril', 'Mai', 'Juin', 'Juillet', 'Aout', 'Septembre', 'Octobre', 'Novembre', 'Decembre'];

function formatDate(date) {
    return date.toLocaleDateString('fr-FR', {
        weekday: 'long',
        day: 'numeric',
        month: 'long',
        year: 'numeric'
    });
}

function formatDateShort(date) {
    return date.toISOString().split('T')[0];
}

function initDates() {
    const today = new Date();
    const endOfYear = new Date(today.getFullYear(), 11, 31);

    document.getElementById('date-start').value = formatDateShort(today);
    document.getElementById('date-end').value = formatDateShort(endOfYear);
    document.getElementById('add-date').value = formatDateShort(today);
    document.getElementById('work-start').value = formatDateShort(today);
    document.getElementById('work-end').value = formatDateShort(endOfYear);
}

function calculateDiff() {
    const start = new Date(document.getElementById('date-start').value);
    const end = new Date(document.getElementById('date-end').value);

    if (isNaN(start) || isNaN(end)) return;

    const diffMs = end - start;
    const diffDays = Math.round(diffMs / (1000 * 60 * 60 * 24));
    const diffWeeks = (diffDays / 7).toFixed(1);

    // Calculate months and years
    let months = (end.getFullYear() - start.getFullYear()) * 12;
    months += end.getMonth() - start.getMonth();
    const years = (months / 12).toFixed(1);

    document.getElementById('diff-days').textContent = Math.abs(diffDays);
    document.getElementById('diff-weeks').textContent = Math.abs(diffWeeks);
    document.getElementById('diff-months').textContent = Math.abs(months);
    document.getElementById('diff-years').textContent = Math.abs(years);

    // Details
    const absDays = Math.abs(diffDays);
    const y = Math.floor(absDays / 365);
    const m = Math.floor((absDays % 365) / 30);
    const d = absDays % 30;

    let details = '';
    if (y > 0) details += `${y} an${y > 1 ? 's' : ''} `;
    if (m > 0) details += `${m} mois `;
    if (d > 0) details += `${d} jour${d > 1 ? 's' : ''}`;

    const direction = diffDays >= 0 ? 'apres' : 'avant';
    document.getElementById('diff-details').innerHTML = `
        <strong>${details.trim()}</strong><br>
        ${absDays} jours = ${Math.round(absDays * 24)} heures = ${Math.round(absDays * 24 * 60)} minutes
    `;
}

function swapDates() {
    const start = document.getElementById('date-start').value;
    const end = document.getElementById('date-end').value;
    document.getElementById('date-start').value = end;
    document.getElementById('date-end').value = start;
    calculateDiff();
}

function calculateAdd() {
    const dateStr = document.getElementById('add-date').value;
    const operation = document.getElementById('add-operation').value;
    const value = parseInt(document.getElementById('add-value').value) || 0;
    const unit = document.getElementById('add-unit').value;

    if (!dateStr) return;

    const date = new Date(dateStr);
    const multiplier = operation === 'add' ? 1 : -1;
    let result;

    switch (unit) {
        case 'days':
            result = new Date(date);
            result.setDate(result.getDate() + (value * multiplier));
            break;
        case 'weeks':
            result = new Date(date);
            result.setDate(result.getDate() + (value * 7 * multiplier));
            break;
        case 'months':
            result = new Date(date);
            result.setMonth(result.getMonth() + (value * multiplier));
            break;
        case 'years':
            result = new Date(date);
            result.setFullYear(result.getFullYear() + (value * multiplier));
            break;
        case 'business':
            result = addBusinessDays(date, value * multiplier);
            break;
    }

    document.getElementById('add-result-date').textContent = formatDateShort(result);
    document.getElementById('add-result-day').textContent = formatDate(result);
}

function addBusinessDays(date, days) {
    const result = new Date(date);
    let count = 0;
    const step = days >= 0 ? 1 : -1;

    while (count < Math.abs(days)) {
        result.setDate(result.getDate() + step);
        const dayOfWeek = result.getDay();
        if (dayOfWeek !== 0 && dayOfWeek !== 6) {
            count++;
        }
    }

    return result;
}

function quickAdd(value, unit) {
    document.getElementById('add-value').value = value;
    document.getElementById('add-unit').value = unit;
    document.getElementById('add-operation').value = 'add';
    calculateAdd();
}

function calculateWorkdays() {
    const start = new Date(document.getElementById('work-start').value);
    const end = new Date(document.getElementById('work-end').value);

    if (isNaN(start) || isNaN(end)) return;

    let workdays = 0;
    let weekends = 0;
    const current = new Date(start);

    while (current <= end) {
        const dayOfWeek = current.getDay();
        if (dayOfWeek === 0 || dayOfWeek === 6) {
            weekends++;
        } else {
            workdays++;
        }
        current.setDate(current.getDate() + 1);
    }

    const totalDays = Math.round((end - start) / (1000 * 60 * 60 * 24)) + 1;
    const weeks = (totalDays / 7).toFixed(1);

    document.getElementById('work-total').textContent = workdays;
    document.getElementById('work-weekends').textContent = weekends;
    document.getElementById('work-weeks').textContent = weeks;
}

function updateSpecialDates() {
    const today = new Date();
    const year = today.getFullYear();

    const events = [
        { name: 'Nouvel An', date: new Date(year + 1, 0, 1) },
        { name: 'Saint-Valentin', date: new Date(year, 1, 14) },
        { name: 'Fete du Travail', date: new Date(year, 4, 1) },
        { name: 'Fete Nationale', date: new Date(year, 6, 14) },
        { name: 'Toussaint', date: new Date(year, 10, 1) },
        { name: 'Noel', date: new Date(year, 11, 25) },
        { name: 'Fin d\'annee', date: new Date(year, 11, 31) }
    ];

    // Fix dates that have passed
    events.forEach(e => {
        if (e.date < today && e.name !== 'Nouvel An') {
            e.date.setFullYear(year + 1);
        }
    });

    const grid = document.getElementById('special-dates');
    grid.innerHTML = events.map(e => {
        const diff = Math.ceil((e.date - today) / (1000 * 60 * 60 * 24));
        const countdown = diff === 0 ? "Aujourd'hui!" : diff === 1 ? 'Demain' : `Dans ${diff} jours`;

        return `
            <div class="special-card">
                <div class="event-name">${e.name}</div>
                <div class="event-date">${formatDateShort(e.date)}</div>
                <div class="event-countdown">${countdown}</div>
            </div>
        `;
    }).join('');
}

// Initialize
initDates();
calculateDiff();
calculateAdd();
calculateWorkdays();
updateSpecialDates();
</script>
