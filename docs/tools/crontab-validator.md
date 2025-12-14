---
tags:
  - tools
  - linux
  - cron
  - scheduler
---

# Crontab Validator

Validateur et interpreteur d'expressions cron avec previsualisation des executions.

<div id="cron-app">
  <div class="cron-container">
    <div class="cron-section">
      <h3>Expression Cron</h3>

      <div class="cron-input">
        <div class="cron-fields">
          <div class="cron-field">
            <label>Min</label>
            <input type="text" id="cronMin" value="0" oninput="validateCron()">
            <span class="field-range">0-59</span>
          </div>
          <div class="cron-field">
            <label>Heure</label>
            <input type="text" id="cronHour" value="9" oninput="validateCron()">
            <span class="field-range">0-23</span>
          </div>
          <div class="cron-field">
            <label>Jour</label>
            <input type="text" id="cronDom" value="*" oninput="validateCron()">
            <span class="field-range">1-31</span>
          </div>
          <div class="cron-field">
            <label>Mois</label>
            <input type="text" id="cronMonth" value="*" oninput="validateCron()">
            <span class="field-range">1-12</span>
          </div>
          <div class="cron-field">
            <label>Jour sem.</label>
            <input type="text" id="cronDow" value="1-5" oninput="validateCron()">
            <span class="field-range">0-7</span>
          </div>
        </div>
      </div>

      <div class="full-expression">
        <label>Expression complete</label>
        <input type="text" id="cronFull" value="0 9 * * 1-5" oninput="parseFullCron()">
      </div>

      <div class="presets">
        <h4>Presets</h4>
        <div class="presets-grid">
          <button onclick="setPreset('0 * * * *')">Chaque heure</button>
          <button onclick="setPreset('0 0 * * *')">Minuit</button>
          <button onclick="setPreset('0 9 * * 1-5')">9h lun-ven</button>
          <button onclick="setPreset('0 0 * * 0')">Dimanche minuit</button>
          <button onclick="setPreset('0 0 1 * *')">1er du mois</button>
          <button onclick="setPreset('*/15 * * * *')">Toutes les 15min</button>
          <button onclick="setPreset('0 */2 * * *')">Toutes les 2h</button>
          <button onclick="setPreset('0 0 * * 1')">Lundi minuit</button>
        </div>
      </div>
    </div>

    <div class="cron-section">
      <h3>Interpretation</h3>

      <div class="validation-status" id="validationStatus">
        <span class="status-icon">✅</span>
        <span class="status-text">Expression valide</span>
      </div>

      <div class="human-readable" id="humanReadable">
        A 09:00, du lundi au vendredi
      </div>

      <div class="next-runs">
        <h4>Prochaines executions</h4>
        <div id="nextRuns" class="runs-list"></div>
      </div>
    </div>
  </div>

  <div class="syntax-section">
    <h3>Reference syntaxe</h3>

    <div class="syntax-grid">
      <div class="syntax-card">
        <h4>Caracteres speciaux</h4>
        <table>
          <tr><td><code>*</code></td><td>Toutes les valeurs</td></tr>
          <tr><td><code>,</code></td><td>Liste (1,3,5)</td></tr>
          <tr><td><code>-</code></td><td>Plage (1-5)</td></tr>
          <tr><td><code>/</code></td><td>Step (*/15)</td></tr>
        </table>
      </div>

      <div class="syntax-card">
        <h4>Jours de la semaine</h4>
        <table>
          <tr><td>0 ou 7</td><td>Dimanche</td></tr>
          <tr><td>1</td><td>Lundi</td></tr>
          <tr><td>2</td><td>Mardi</td></tr>
          <tr><td>3</td><td>Mercredi</td></tr>
          <tr><td>4</td><td>Jeudi</td></tr>
          <tr><td>5</td><td>Vendredi</td></tr>
          <tr><td>6</td><td>Samedi</td></tr>
        </table>
      </div>

      <div class="syntax-card">
        <h4>Mois</h4>
        <table>
          <tr><td>1</td><td>Janvier</td><td>7</td><td>Juillet</td></tr>
          <tr><td>2</td><td>Fevrier</td><td>8</td><td>Aout</td></tr>
          <tr><td>3</td><td>Mars</td><td>9</td><td>Septembre</td></tr>
          <tr><td>4</td><td>Avril</td><td>10</td><td>Octobre</td></tr>
          <tr><td>5</td><td>Mai</td><td>11</td><td>Novembre</td></tr>
          <tr><td>6</td><td>Juin</td><td>12</td><td>Decembre</td></tr>
        </table>
      </div>

      <div class="syntax-card">
        <h4>Extensions (non-standard)</h4>
        <table>
          <tr><td><code>@yearly</code></td><td>0 0 1 1 *</td></tr>
          <tr><td><code>@monthly</code></td><td>0 0 1 * *</td></tr>
          <tr><td><code>@weekly</code></td><td>0 0 * * 0</td></tr>
          <tr><td><code>@daily</code></td><td>0 0 * * *</td></tr>
          <tr><td><code>@hourly</code></td><td>0 * * * *</td></tr>
          <tr><td><code>@reboot</code></td><td>Au demarrage</td></tr>
        </table>
      </div>
    </div>
  </div>

  <div class="commands-section">
    <h3>Commandes crontab</h3>

    <div class="commands-grid">
      <div class="cmd-card">
        <h4>📋 Voir crontab</h4>
        <pre>crontab -l
crontab -l -u username</pre>
      </div>

      <div class="cmd-card">
        <h4>✏️ Editer crontab</h4>
        <pre>crontab -e
EDITOR=nano crontab -e</pre>
      </div>

      <div class="cmd-card">
        <h4>🗑️ Supprimer crontab</h4>
        <pre>crontab -r
crontab -r -u username</pre>
      </div>

      <div class="cmd-card">
        <h4>📁 Fichiers systeme</h4>
        <pre>/etc/crontab
/etc/cron.d/
/etc/cron.{hourly,daily,weekly,monthly}/</pre>
      </div>
    </div>
  </div>

  <div class="examples-section">
    <h3>Exemples courants</h3>

    <div class="examples-grid">
      <div class="example-card" onclick="setPreset('0 2 * * *')">
        <div class="example-cron">0 2 * * *</div>
        <div class="example-desc">Backup quotidien a 2h</div>
      </div>

      <div class="example-card" onclick="setPreset('*/5 * * * *')">
        <div class="example-cron">*/5 * * * *</div>
        <div class="example-desc">Health check toutes les 5min</div>
      </div>

      <div class="example-card" onclick="setPreset('0 0 * * 0')">
        <div class="example-cron">0 0 * * 0</div>
        <div class="example-desc">Rapport hebdo dimanche</div>
      </div>

      <div class="example-card" onclick="setPreset('0 9,18 * * 1-5')">
        <div class="example-cron">0 9,18 * * 1-5</div>
        <div class="example-desc">9h et 18h en semaine</div>
      </div>

      <div class="example-card" onclick="setPreset('0 0 1 1 *')">
        <div class="example-cron">0 0 1 1 *</div>
        <div class="example-desc">1er janvier a minuit</div>
      </div>

      <div class="example-card" onclick="setPreset('30 4 1,15 * *')">
        <div class="example-cron">30 4 1,15 * *</div>
        <div class="example-desc">4h30 le 1er et 15 du mois</div>
      </div>
    </div>
  </div>
</div>

<style>
.cron-container {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 20px;
}

@media (max-width: 800px) {
  .cron-container {
    grid-template-columns: 1fr;
  }
}

.cron-section, .syntax-section, .commands-section, .examples-section {
  background: var(--md-code-bg-color);
  padding: 20px;
  border-radius: 8px;
  margin-bottom: 20px;
}

.cron-fields {
  display: flex;
  gap: 10px;
  justify-content: center;
  margin-bottom: 20px;
}

.cron-field {
  text-align: center;
}

.cron-field label {
  display: block;
  font-size: 0.8em;
  color: var(--md-default-fg-color--light);
  margin-bottom: 5px;
}

.cron-field input {
  width: 50px;
  padding: 10px;
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  background: var(--md-default-bg-color);
  color: var(--md-default-fg-color);
  font-family: monospace;
  font-size: 1.2em;
  text-align: center;
}

.field-range {
  display: block;
  font-size: 0.7em;
  color: var(--md-default-fg-color--light);
  margin-top: 3px;
}

.full-expression {
  margin-bottom: 20px;
}

.full-expression label {
  display: block;
  font-size: 0.85em;
  margin-bottom: 5px;
  color: var(--md-default-fg-color--light);
}

.full-expression input {
  width: 100%;
  padding: 12px;
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  background: var(--md-default-bg-color);
  color: var(--md-default-fg-color);
  font-family: monospace;
  font-size: 1.2em;
  text-align: center;
}

.presets h4 {
  margin-bottom: 10px;
}

.presets-grid {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.presets-grid button {
  padding: 6px 12px;
  background: var(--md-default-bg-color);
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  cursor: pointer;
  font-size: 0.85em;
}

.presets-grid button:hover {
  border-color: var(--md-primary-fg-color);
}

.validation-status {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 12px 15px;
  border-radius: 6px;
  margin-bottom: 15px;
  font-weight: 500;
}

.validation-status.valid {
  background: rgba(39, 174, 96, 0.1);
  color: #27ae60;
}

.validation-status.invalid {
  background: rgba(231, 76, 60, 0.1);
  color: #e74c3c;
}

.human-readable {
  background: var(--md-default-bg-color);
  padding: 20px;
  border-radius: 6px;
  text-align: center;
  font-size: 1.1em;
  margin-bottom: 20px;
}

.next-runs h4 {
  margin-bottom: 10px;
}

.runs-list {
  background: var(--md-default-bg-color);
  padding: 15px;
  border-radius: 6px;
}

.run-item {
  display: flex;
  justify-content: space-between;
  padding: 8px 0;
  border-bottom: 1px solid var(--md-default-fg-color--lightest);
  font-family: monospace;
  font-size: 0.9em;
}

.run-item:last-child {
  border-bottom: none;
}

.run-date {
  color: var(--md-default-fg-color--light);
}

.syntax-grid, .examples-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 15px;
}

.syntax-card {
  background: var(--md-default-bg-color);
  padding: 15px;
  border-radius: 6px;
}

.syntax-card h4 {
  margin: 0 0 10px 0;
}

.syntax-card table {
  width: 100%;
  font-size: 0.85em;
}

.syntax-card td {
  padding: 4px;
}

.syntax-card code {
  background: var(--md-code-bg-color);
  padding: 2px 5px;
  border-radius: 3px;
}

.commands-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 15px;
}

.cmd-card {
  background: var(--md-default-bg-color);
  padding: 15px;
  border-radius: 6px;
}

.cmd-card h4 {
  margin: 0 0 10px 0;
}

.cmd-card pre {
  margin: 0;
  padding: 10px;
  background: #1e1e1e;
  color: #d4d4d4;
  border-radius: 4px;
  font-size: 0.8em;
}

.example-card {
  background: var(--md-default-bg-color);
  padding: 15px;
  border-radius: 6px;
  cursor: pointer;
  transition: transform 0.2s;
}

.example-card:hover {
  transform: scale(1.02);
}

.example-cron {
  font-family: monospace;
  font-size: 1.1em;
  font-weight: 600;
  margin-bottom: 5px;
}

.example-desc {
  font-size: 0.85em;
  color: var(--md-default-fg-color--light);
}
</style>

<script>
const dayNames = ['Dimanche', 'Lundi', 'Mardi', 'Mercredi', 'Jeudi', 'Vendredi', 'Samedi'];
const monthNames = ['Janvier', 'Fevrier', 'Mars', 'Avril', 'Mai', 'Juin', 'Juillet', 'Aout', 'Septembre', 'Octobre', 'Novembre', 'Decembre'];

function validateCron() {
  const min = document.getElementById('cronMin').value;
  const hour = document.getElementById('cronHour').value;
  const dom = document.getElementById('cronDom').value;
  const month = document.getElementById('cronMonth').value;
  const dow = document.getElementById('cronDow').value;

  const expr = `${min} ${hour} ${dom} ${month} ${dow}`;
  document.getElementById('cronFull').value = expr;

  validateExpression(expr);
}

function parseFullCron() {
  const expr = document.getElementById('cronFull').value.trim();
  const parts = expr.split(/\s+/);

  if (parts.length === 5) {
    document.getElementById('cronMin').value = parts[0];
    document.getElementById('cronHour').value = parts[1];
    document.getElementById('cronDom').value = parts[2];
    document.getElementById('cronMonth').value = parts[3];
    document.getElementById('cronDow').value = parts[4];
  }

  validateExpression(expr);
}

function validateExpression(expr) {
  const statusEl = document.getElementById('validationStatus');
  const humanEl = document.getElementById('humanReadable');

  const parts = expr.split(/\s+/);

  if (parts.length !== 5) {
    statusEl.className = 'validation-status invalid';
    statusEl.innerHTML = '<span class="status-icon">❌</span><span class="status-text">Expression invalide (5 champs requis)</span>';
    humanEl.textContent = '-';
    return;
  }

  // Simple validation
  const fieldRanges = [
    { name: 'minute', min: 0, max: 59 },
    { name: 'hour', min: 0, max: 23 },
    { name: 'day', min: 1, max: 31 },
    { name: 'month', min: 1, max: 12 },
    { name: 'dow', min: 0, max: 7 }
  ];

  let valid = true;
  parts.forEach((part, i) => {
    if (!isValidField(part, fieldRanges[i])) {
      valid = false;
    }
  });

  if (valid) {
    statusEl.className = 'validation-status valid';
    statusEl.innerHTML = '<span class="status-icon">✅</span><span class="status-text">Expression valide</span>';
    humanEl.textContent = toHumanReadable(parts);
    calculateNextRuns(parts);
  } else {
    statusEl.className = 'validation-status invalid';
    statusEl.innerHTML = '<span class="status-icon">❌</span><span class="status-text">Expression invalide</span>';
    humanEl.textContent = '-';
  }
}

function isValidField(field, range) {
  if (field === '*') return true;

  // Step (*/n or n/m)
  if (field.includes('/')) {
    const [base, step] = field.split('/');
    if (base !== '*' && !isValidField(base, range)) return false;
    if (isNaN(parseInt(step))) return false;
    return true;
  }

  // Range (n-m)
  if (field.includes('-') && !field.includes(',')) {
    const [start, end] = field.split('-').map(Number);
    return start >= range.min && end <= range.max && start <= end;
  }

  // List (n,m,o)
  if (field.includes(',')) {
    return field.split(',').every(part => isValidField(part, range));
  }

  // Single value
  const num = parseInt(field);
  return !isNaN(num) && num >= range.min && num <= range.max;
}

function toHumanReadable(parts) {
  const [min, hour, dom, month, dow] = parts;

  let result = '';

  // Time
  if (min === '*' && hour === '*') {
    result = 'Chaque minute';
  } else if (min.startsWith('*/')) {
    result = `Toutes les ${min.slice(2)} minutes`;
  } else if (hour === '*') {
    result = `A la minute ${min} de chaque heure`;
  } else if (hour.startsWith('*/')) {
    result = `Toutes les ${hour.slice(2)} heures, a la minute ${min}`;
  } else {
    const hours = hour.includes(',') ? hour.split(',').join('h, ') + 'h' : hour.padStart(2, '0') + ':' + min.padStart(2, '0');
    result = `A ${hours}`;
  }

  // Day of week
  if (dow !== '*') {
    if (dow === '1-5') {
      result += ', du lundi au vendredi';
    } else if (dow === '0' || dow === '7') {
      result += ', le dimanche';
    } else if (dow === '6') {
      result += ', le samedi';
    } else {
      result += `, jour(s) ${dow}`;
    }
  }

  // Day of month
  if (dom !== '*') {
    result += `, le ${dom} du mois`;
  }

  // Month
  if (month !== '*') {
    if (month.includes(',')) {
      result += `, en ${month.split(',').map(m => monthNames[parseInt(m)-1]).join(', ')}`;
    } else {
      result += `, en ${monthNames[parseInt(month)-1]}`;
    }
  }

  return result;
}

function calculateNextRuns(parts) {
  const container = document.getElementById('nextRuns');
  const runs = [];
  let date = new Date();

  // Simple implementation - just show next 5 matching dates
  for (let i = 0; i < 1000 && runs.length < 5; i++) {
    date = new Date(date.getTime() + 60000); // Add 1 minute

    if (matchesCron(date, parts)) {
      runs.push(new Date(date));
    }
  }

  container.innerHTML = runs.map(d => {
    const dateStr = d.toLocaleDateString('fr-FR', { weekday: 'short', day: 'numeric', month: 'short' });
    const timeStr = d.toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' });
    return `
      <div class="run-item">
        <span class="run-date">${dateStr}</span>
        <span class="run-time">${timeStr}</span>
      </div>
    `;
  }).join('');
}

function matchesCron(date, parts) {
  const [min, hour, dom, month, dow] = parts;

  if (!matchesField(date.getMinutes(), min)) return false;
  if (!matchesField(date.getHours(), hour)) return false;
  if (!matchesField(date.getDate(), dom)) return false;
  if (!matchesField(date.getMonth() + 1, month)) return false;
  if (!matchesField(date.getDay(), dow)) return false;

  return true;
}

function matchesField(value, field) {
  if (field === '*') return true;

  if (field.includes('/')) {
    const [base, step] = field.split('/');
    const stepNum = parseInt(step);
    if (base === '*') return value % stepNum === 0;
    // Handle range/step
  }

  if (field.includes('-')) {
    const [start, end] = field.split('-').map(Number);
    return value >= start && value <= end;
  }

  if (field.includes(',')) {
    return field.split(',').map(Number).includes(value);
  }

  return parseInt(field) === value;
}

function setPreset(expr) {
  document.getElementById('cronFull').value = expr;
  parseFullCron();
}

// Initialize
validateCron();
</script>

---

## Format crontab

```
┌───────────── minute (0 - 59)
│ ┌───────────── heure (0 - 23)
│ │ ┌───────────── jour du mois (1 - 31)
│ │ │ ┌───────────── mois (1 - 12)
│ │ │ │ ┌───────────── jour de la semaine (0 - 7)
│ │ │ │ │
* * * * * commande
```
