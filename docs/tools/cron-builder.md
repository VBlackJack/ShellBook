---
tags:
  - tools
  - linux
  - cron
  - scheduling
---

# Cron Builder

Generateur et validateur d'expressions cron.

<div class="tool-container">

<h3>Mode interactif</h3>

<div class="cron-grid">
    <div class="cron-field">
        <label>Minute</label>
        <input type="text" id="cron-min" value="0" maxlength="10">
        <small>0-59</small>
    </div>
    <div class="cron-field">
        <label>Heure</label>
        <input type="text" id="cron-hour" value="*" maxlength="10">
        <small>0-23</small>
    </div>
    <div class="cron-field">
        <label>Jour (mois)</label>
        <input type="text" id="cron-dom" value="*" maxlength="10">
        <small>1-31</small>
    </div>
    <div class="cron-field">
        <label>Mois</label>
        <input type="text" id="cron-month" value="*" maxlength="10">
        <small>1-12</small>
    </div>
    <div class="cron-field">
        <label>Jour (semaine)</label>
        <input type="text" id="cron-dow" value="*" maxlength="10">
        <small>0-6 (0=Dim)</small>
    </div>
</div>

<div class="cron-output">
    <div class="cron-expression">
        <label>Expression cron :</label>
        <input type="text" id="cron-result" value="0 * * * *" readonly>
        <button onclick="copyCron()" class="copy-btn" title="Copier">&#128203;</button>
    </div>
    <div class="cron-description" id="cron-desc">
        Toutes les heures, a la minute 0
    </div>
</div>

<h3>Presets courants</h3>

<div class="presets-grid">
    <button onclick="setPreset('0 * * * *')">Toutes les heures</button>
    <button onclick="setPreset('*/5 * * * *')">Toutes les 5 min</button>
    <button onclick="setPreset('*/15 * * * *')">Toutes les 15 min</button>
    <button onclick="setPreset('0 0 * * *')">Minuit</button>
    <button onclick="setPreset('0 6 * * *')">6h du matin</button>
    <button onclick="setPreset('0 0 * * 0')">Dimanche minuit</button>
    <button onclick="setPreset('0 0 1 * *')">1er du mois</button>
    <button onclick="setPreset('0 0 1 1 *')">1er janvier</button>
    <button onclick="setPreset('0 */2 * * *')">Toutes les 2h</button>
    <button onclick="setPreset('0 9-17 * * 1-5')">9h-17h semaine</button>
    <button onclick="setPreset('0 0 * * 1-5')">Minuit semaine</button>
    <button onclick="setPreset('30 4 * * *')">4h30</button>
</div>

<h3>Prochaines executions</h3>

<div id="next-runs" class="next-runs">
    <ul></ul>
</div>

</div>

## Syntaxe Cron

### Format standard (5 champs)

```
┌───────────── minute (0-59)
│ ┌───────────── heure (0-23)
│ │ ┌───────────── jour du mois (1-31)
│ │ │ ┌───────────── mois (1-12)
│ │ │ │ ┌───────────── jour de la semaine (0-6, 0=Dimanche)
│ │ │ │ │
* * * * *
```

### Caracteres speciaux

| Caractere | Signification | Exemple |
|-----------|---------------|---------|
| `*` | Toutes les valeurs | `* * * * *` = chaque minute |
| `,` | Liste de valeurs | `1,15 * * * *` = minute 1 et 15 |
| `-` | Plage | `0 9-17 * * *` = 9h a 17h |
| `/` | Increment | `*/15 * * * *` = toutes les 15 min |

### Exemples communs

| Expression | Description |
|------------|-------------|
| `0 * * * *` | Toutes les heures (minute 0) |
| `*/5 * * * *` | Toutes les 5 minutes |
| `0 0 * * *` | Tous les jours a minuit |
| `0 0 * * 0` | Tous les dimanches a minuit |
| `0 0 1 * *` | Le 1er de chaque mois |
| `0 6 * * 1-5` | 6h du lundi au vendredi |
| `0 0 1 1 *` | Le 1er janvier a minuit |
| `30 4 1,15 * *` | 4h30 le 1er et 15 du mois |

### Noms symboliques

| Mois | Valeur | Jour | Valeur |
|------|--------|------|--------|
| JAN | 1 | SUN | 0 |
| FEB | 2 | MON | 1 |
| MAR | 3 | TUE | 2 |
| APR | 4 | WED | 3 |
| MAY | 5 | THU | 4 |
| JUN | 6 | FRI | 5 |
| JUL | 7 | SAT | 6 |
| AUG-DEC | 8-12 | | |

<style>
.tool-container {
    background: var(--md-code-bg-color);
    padding: 20px;
    border-radius: 8px;
    margin: 20px 0;
}
.cron-grid {
    display: flex;
    gap: 15px;
    flex-wrap: wrap;
    margin: 20px 0;
}
.cron-field {
    text-align: center;
    background: var(--md-default-bg-color);
    padding: 15px;
    border-radius: 4px;
    min-width: 80px;
}
.cron-field label {
    display: block;
    font-weight: bold;
    margin-bottom: 8px;
    font-size: 14px;
}
.cron-field input {
    width: 60px;
    padding: 10px;
    font-family: monospace;
    font-size: 18px;
    text-align: center;
    border: 2px solid var(--md-primary-fg-color);
    border-radius: 4px;
    background: var(--md-code-bg-color);
    color: var(--md-default-fg-color);
}
.cron-field small {
    display: block;
    margin-top: 5px;
    color: var(--md-default-fg-color--light);
}
.cron-output {
    margin: 20px 0;
    padding: 20px;
    background: var(--md-default-bg-color);
    border-radius: 4px;
}
.cron-expression {
    display: flex;
    align-items: center;
    gap: 10px;
    flex-wrap: wrap;
}
.cron-expression label {
    font-weight: bold;
}
.cron-expression input {
    flex: 1;
    min-width: 200px;
    padding: 12px;
    font-family: monospace;
    font-size: 20px;
    border: 2px solid var(--md-primary-fg-color);
    border-radius: 4px;
    background: var(--md-code-bg-color);
    color: var(--md-primary-fg-color);
}
.copy-btn {
    padding: 12px 16px;
    font-size: 18px;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    background: var(--md-primary-fg-color);
    color: white;
}
.cron-description {
    margin-top: 15px;
    padding: 10px;
    background: var(--md-code-bg-color);
    border-radius: 4px;
    font-style: italic;
}
.presets-grid {
    display: flex;
    gap: 10px;
    flex-wrap: wrap;
    margin: 15px 0;
}
.presets-grid button {
    padding: 8px 16px;
    border: 1px solid var(--md-primary-fg-color);
    border-radius: 4px;
    background: var(--md-default-bg-color);
    color: var(--md-default-fg-color);
    cursor: pointer;
    font-size: 13px;
}
.presets-grid button:hover {
    background: var(--md-primary-fg-color);
    color: white;
}
.next-runs {
    background: var(--md-default-bg-color);
    padding: 15px;
    border-radius: 4px;
    margin-top: 15px;
}
.next-runs ul {
    margin: 0;
    padding-left: 20px;
}
.next-runs li {
    margin: 5px 0;
    font-family: monospace;
}
</style>

<script>
const dayNames = ['Dimanche', 'Lundi', 'Mardi', 'Mercredi', 'Jeudi', 'Vendredi', 'Samedi'];
const monthNames = ['Janvier', 'Fevrier', 'Mars', 'Avril', 'Mai', 'Juin', 'Juillet', 'Aout', 'Septembre', 'Octobre', 'Novembre', 'Decembre'];

function updateCron() {
    const min = document.getElementById('cron-min').value || '*';
    const hour = document.getElementById('cron-hour').value || '*';
    const dom = document.getElementById('cron-dom').value || '*';
    const month = document.getElementById('cron-month').value || '*';
    const dow = document.getElementById('cron-dow').value || '*';

    const expr = `${min} ${hour} ${dom} ${month} ${dow}`;
    document.getElementById('cron-result').value = expr;

    // Generate description
    const desc = describeCron(min, hour, dom, month, dow);
    document.getElementById('cron-desc').textContent = desc;

    // Calculate next runs
    calculateNextRuns(expr);
}

function describeCron(min, hour, dom, month, dow) {
    let parts = [];

    // Minute
    if (min === '*') {
        parts.push('Chaque minute');
    } else if (min.startsWith('*/')) {
        parts.push(`Toutes les ${min.slice(2)} minutes`);
    } else if (min.includes(',')) {
        parts.push(`Aux minutes ${min}`);
    } else if (min.includes('-')) {
        parts.push(`De la minute ${min.replace('-', ' a ')}`);
    } else {
        parts.push(`A la minute ${min}`);
    }

    // Hour
    if (hour === '*') {
        parts.push('de chaque heure');
    } else if (hour.startsWith('*/')) {
        parts.push(`toutes les ${hour.slice(2)} heures`);
    } else if (hour.includes(',')) {
        parts.push(`a ${hour}h`);
    } else if (hour.includes('-')) {
        parts.push(`entre ${hour.replace('-', 'h et ')}h`);
    } else {
        parts.push(`a ${hour}h`);
    }

    // Day of month
    if (dom !== '*') {
        if (dom.includes(',')) {
            parts.push(`les jours ${dom}`);
        } else if (dom.includes('-')) {
            parts.push(`du ${dom.replace('-', ' au ')}`);
        } else {
            parts.push(`le ${dom}`);
        }
    }

    // Month
    if (month !== '*') {
        if (month.includes('-')) {
            const [start, end] = month.split('-');
            parts.push(`de ${monthNames[parseInt(start)-1]} a ${monthNames[parseInt(end)-1]}`);
        } else {
            parts.push(`en ${monthNames[parseInt(month)-1]}`);
        }
    }

    // Day of week
    if (dow !== '*') {
        if (dow.includes('-')) {
            const [start, end] = dow.split('-');
            parts.push(`du ${dayNames[parseInt(start)]} au ${dayNames[parseInt(end)]}`);
        } else if (dow.includes(',')) {
            const days = dow.split(',').map(d => dayNames[parseInt(d)]).join(', ');
            parts.push(`les ${days}`);
        } else {
            parts.push(`le ${dayNames[parseInt(dow)]}`);
        }
    }

    return parts.join(' ');
}

function parseField(field, min, max) {
    if (field === '*') {
        return Array.from({length: max - min + 1}, (_, i) => i + min);
    }
    if (field.startsWith('*/')) {
        const step = parseInt(field.slice(2));
        return Array.from({length: Math.ceil((max - min + 1) / step)}, (_, i) => min + i * step);
    }
    if (field.includes(',')) {
        return field.split(',').map(v => parseInt(v));
    }
    if (field.includes('-')) {
        const [start, end] = field.split('-').map(v => parseInt(v));
        return Array.from({length: end - start + 1}, (_, i) => start + i);
    }
    return [parseInt(field)];
}

function calculateNextRuns(expr) {
    const [minF, hourF, domF, monthF, dowF] = expr.split(' ');
    const now = new Date();
    const runs = [];
    let date = new Date(now);

    // Find next 5 runs
    for (let i = 0; i < 10000 && runs.length < 5; i++) {
        date = new Date(date.getTime() + 60000); // Add 1 minute

        const min = date.getMinutes();
        const hour = date.getHours();
        const dom = date.getDate();
        const month = date.getMonth() + 1;
        const dow = date.getDay();

        const minMatch = parseField(minF, 0, 59).includes(min);
        const hourMatch = parseField(hourF, 0, 23).includes(hour);
        const domMatch = parseField(domF, 1, 31).includes(dom);
        const monthMatch = parseField(monthF, 1, 12).includes(month);
        const dowMatch = parseField(dowF, 0, 6).includes(dow);

        if (minMatch && hourMatch && domMatch && monthMatch && dowMatch) {
            runs.push(date.toLocaleString('fr-FR', {
                weekday: 'short',
                year: 'numeric',
                month: 'short',
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit'
            }));
        }
    }

    const ul = document.querySelector('#next-runs ul');
    ul.innerHTML = runs.map(r => `<li>${r}</li>`).join('');
}

function setPreset(expr) {
    const [min, hour, dom, month, dow] = expr.split(' ');
    document.getElementById('cron-min').value = min;
    document.getElementById('cron-hour').value = hour;
    document.getElementById('cron-dom').value = dom;
    document.getElementById('cron-month').value = month;
    document.getElementById('cron-dow').value = dow;
    updateCron();
}

function copyCron() {
    const input = document.getElementById('cron-result');
    input.select();
    document.execCommand('copy');

    const btn = document.querySelector('.copy-btn');
    btn.textContent = '\u2713';
    setTimeout(() => { btn.innerHTML = '&#128203;'; }, 1000);
}

// Event listeners
document.querySelectorAll('.cron-field input').forEach(input => {
    input.addEventListener('input', updateCron);
});

// Initial update
updateCron();
</script>
