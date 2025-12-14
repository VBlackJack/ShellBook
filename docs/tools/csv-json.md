---
tags:
  - tools
  - csv
  - json
  - converter
  - data
---

# CSV / JSON Converter

Conversion bidirectionnelle entre CSV et JSON.

<div class="tool-container">

<div class="type-selector">
    <button class="type-btn active" onclick="selectType('csv2json')">CSV → JSON</button>
    <button class="type-btn" onclick="selectType('json2csv')">JSON → CSV</button>
</div>

<div class="converter-section">
    <div class="input-pane">
        <div class="pane-header">
            <span id="input-label">CSV</span>
            <div class="options">
                <label id="delimiter-option">
                    Delimiteur:
                    <select id="delimiter">
                        <option value=",">Virgule (,)</option>
                        <option value=";">Point-virgule (;)</option>
                        <option value="\t">Tabulation</option>
                        <option value="|">Pipe (|)</option>
                    </select>
                </label>
                <label>
                    <input type="checkbox" id="has-header" checked> Premiere ligne = en-tetes
                </label>
            </div>
        </div>
        <textarea id="input-data" placeholder="col1,col2,col3
value1,value2,value3
value4,value5,value6"></textarea>
    </div>

    <div class="convert-btn-container">
        <button onclick="convert()" class="convert-btn">Convertir →</button>
    </div>

    <div class="output-pane">
        <div class="pane-header">
            <span id="output-label">JSON</span>
            <button onclick="copyOutput()" class="copy-btn">Copier</button>
        </div>
        <textarea id="output-data" readonly></textarea>
    </div>
</div>

<div class="options-section">
    <h3>Options JSON</h3>
    <div class="options-grid">
        <label>
            <input type="checkbox" id="pretty-print" checked> Formatage (pretty print)
        </label>
        <label>
            <input type="checkbox" id="array-of-arrays"> Tableau de tableaux (sans cles)
        </label>
        <label>
            <input type="checkbox" id="minify"> Minifier
        </label>
    </div>
</div>

<div class="examples-section">
    <h3>Exemples</h3>
    <div class="examples-grid">
        <button onclick="loadExample('simple')">CSV Simple</button>
        <button onclick="loadExample('quoted')">CSV avec guillemets</button>
        <button onclick="loadExample('json')">JSON Array</button>
    </div>
</div>

</div>

## Formats supportes

### CSV (Comma-Separated Values)

```csv
name,age,city
Alice,30,Paris
Bob,25,Lyon
```

### JSON Array of Objects

```json
[
  {"name": "Alice", "age": 30, "city": "Paris"},
  {"name": "Bob", "age": 25, "city": "Lyon"}
]
```

### JSON Array of Arrays

```json
[
  ["name", "age", "city"],
  ["Alice", 30, "Paris"],
  ["Bob", 25, "Lyon"]
]
```

## CLI Conversion

```bash
# CSV vers JSON (jq)
cat data.csv | python -c "import csv,json,sys; print(json.dumps(list(csv.DictReader(sys.stdin))))"

# JSON vers CSV (jq + miller)
cat data.json | mlr --json --ocsv cat

# Python
python -c "import pandas as pd; pd.read_csv('data.csv').to_json('data.json', orient='records')"
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
}
.type-btn.active {
    background: var(--md-primary-fg-color);
    color: white;
    border-color: var(--md-primary-fg-color);
}
.converter-section {
    display: grid;
    grid-template-columns: 1fr auto 1fr;
    gap: 15px;
    align-items: stretch;
}
@media (max-width: 900px) {
    .converter-section {
        grid-template-columns: 1fr;
    }
}
.input-pane, .output-pane {
    background: var(--md-default-bg-color);
    border-radius: 4px;
    display: flex;
    flex-direction: column;
}
.pane-header {
    padding: 10px 15px;
    background: var(--md-code-bg-color);
    border-radius: 4px 4px 0 0;
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 10px;
}
.pane-header span {
    font-weight: bold;
}
.pane-header .options {
    display: flex;
    gap: 15px;
    flex-wrap: wrap;
    font-size: 12px;
}
.pane-header select {
    padding: 4px;
    font-size: 12px;
    background: var(--md-default-bg-color);
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 3px;
    color: var(--md-default-fg-color);
}
.input-pane textarea, .output-pane textarea {
    flex: 1;
    min-height: 300px;
    padding: 15px;
    border: none;
    border-radius: 0 0 4px 4px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 13px;
    resize: vertical;
    background: var(--md-default-bg-color);
    color: var(--md-default-fg-color);
}
.convert-btn-container {
    display: flex;
    align-items: center;
    justify-content: center;
}
.convert-btn {
    padding: 15px 25px;
    background: var(--md-primary-fg-color);
    color: white;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    font-size: 14px;
    font-weight: bold;
}
.copy-btn {
    padding: 5px 10px;
    background: var(--md-primary-fg-color);
    color: white;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    font-size: 12px;
}
.options-section, .examples-section {
    background: var(--md-default-bg-color);
    padding: 20px;
    border-radius: 4px;
    margin-top: 20px;
}
.options-section h3, .examples-section h3 {
    margin: 0 0 15px 0;
}
.options-grid {
    display: flex;
    gap: 20px;
    flex-wrap: wrap;
}
.options-grid label {
    display: flex;
    align-items: center;
    gap: 5px;
    cursor: pointer;
}
.examples-grid {
    display: flex;
    gap: 10px;
    flex-wrap: wrap;
}
.examples-grid button {
    padding: 8px 16px;
    background: var(--md-code-bg-color);
    color: var(--md-default-fg-color);
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    cursor: pointer;
}
.examples-grid button:hover {
    background: var(--md-primary-fg-color);
    color: white;
}
</style>

<script>
let currentType = 'csv2json';

function selectType(type) {
    currentType = type;
    document.querySelectorAll('.type-btn').forEach(btn => btn.classList.remove('active'));
    event.target.classList.add('active');

    if (type === 'csv2json') {
        document.getElementById('input-label').textContent = 'CSV';
        document.getElementById('output-label').textContent = 'JSON';
        document.getElementById('delimiter-option').style.display = 'inline';
        document.getElementById('has-header').parentElement.style.display = 'inline';
    } else {
        document.getElementById('input-label').textContent = 'JSON';
        document.getElementById('output-label').textContent = 'CSV';
        document.getElementById('delimiter-option').style.display = 'none';
        document.getElementById('has-header').parentElement.style.display = 'none';
    }
}

function parseCSV(text, delimiter, hasHeader) {
    const lines = [];
    let currentLine = [];
    let currentField = '';
    let inQuotes = false;

    for (let i = 0; i < text.length; i++) {
        const char = text[i];
        const nextChar = text[i + 1];

        if (inQuotes) {
            if (char === '"' && nextChar === '"') {
                currentField += '"';
                i++;
            } else if (char === '"') {
                inQuotes = false;
            } else {
                currentField += char;
            }
        } else {
            if (char === '"') {
                inQuotes = true;
            } else if (char === delimiter) {
                currentLine.push(currentField);
                currentField = '';
            } else if (char === '\n' || (char === '\r' && nextChar === '\n')) {
                currentLine.push(currentField);
                if (currentLine.some(f => f !== '')) {
                    lines.push(currentLine);
                }
                currentLine = [];
                currentField = '';
                if (char === '\r') i++;
            } else if (char !== '\r') {
                currentField += char;
            }
        }
    }

    if (currentField || currentLine.length > 0) {
        currentLine.push(currentField);
        if (currentLine.some(f => f !== '')) {
            lines.push(currentLine);
        }
    }

    return lines;
}

function csvToJson(csv, delimiter, hasHeader, arrayOfArrays) {
    const lines = parseCSV(csv, delimiter, hasHeader);

    if (lines.length === 0) return [];

    if (arrayOfArrays || !hasHeader) {
        return lines.map(row => row.map(cell => {
            if (cell === '') return null;
            if (!isNaN(cell) && cell !== '') return Number(cell);
            if (cell.toLowerCase() === 'true') return true;
            if (cell.toLowerCase() === 'false') return false;
            return cell;
        }));
    }

    const headers = lines[0];
    const data = lines.slice(1);

    return data.map(row => {
        const obj = {};
        headers.forEach((header, i) => {
            let value = row[i] || '';
            if (value === '') {
                obj[header] = null;
            } else if (!isNaN(value) && value !== '') {
                obj[header] = Number(value);
            } else if (value.toLowerCase() === 'true') {
                obj[header] = true;
            } else if (value.toLowerCase() === 'false') {
                obj[header] = false;
            } else {
                obj[header] = value;
            }
        });
        return obj;
    });
}

function jsonToCsv(json, delimiter) {
    let data;
    try {
        data = JSON.parse(json);
    } catch (e) {
        return 'Erreur: JSON invalide';
    }

    if (!Array.isArray(data)) {
        return 'Erreur: Le JSON doit etre un tableau';
    }

    if (data.length === 0) return '';

    // Array of arrays
    if (Array.isArray(data[0])) {
        return data.map(row => row.map(cell => {
            if (cell === null || cell === undefined) return '';
            const str = String(cell);
            if (str.includes(delimiter) || str.includes('"') || str.includes('\n')) {
                return '"' + str.replace(/"/g, '""') + '"';
            }
            return str;
        }).join(delimiter)).join('\n');
    }

    // Array of objects
    const headers = [...new Set(data.flatMap(obj => Object.keys(obj)))];

    const csvRows = [headers.join(delimiter)];

    data.forEach(obj => {
        const row = headers.map(header => {
            const value = obj[header];
            if (value === null || value === undefined) return '';
            const str = String(value);
            if (str.includes(delimiter) || str.includes('"') || str.includes('\n')) {
                return '"' + str.replace(/"/g, '""') + '"';
            }
            return str;
        });
        csvRows.push(row.join(delimiter));
    });

    return csvRows.join('\n');
}

function convert() {
    const input = document.getElementById('input-data').value;
    const delimiter = document.getElementById('delimiter').value === '\\t' ? '\t' : document.getElementById('delimiter').value;
    const hasHeader = document.getElementById('has-header').checked;
    const prettyPrint = document.getElementById('pretty-print').checked;
    const arrayOfArrays = document.getElementById('array-of-arrays').checked;
    const minify = document.getElementById('minify').checked;

    let output;

    if (currentType === 'csv2json') {
        const result = csvToJson(input, delimiter, hasHeader, arrayOfArrays);
        if (minify) {
            output = JSON.stringify(result);
        } else if (prettyPrint) {
            output = JSON.stringify(result, null, 2);
        } else {
            output = JSON.stringify(result);
        }
    } else {
        output = jsonToCsv(input, delimiter);
    }

    document.getElementById('output-data').value = output;
}

function copyOutput() {
    const output = document.getElementById('output-data');
    output.select();
    document.execCommand('copy');

    const btn = document.querySelector('.copy-btn');
    btn.textContent = 'Copie!';
    setTimeout(() => { btn.textContent = 'Copier'; }, 1000);
}

const EXAMPLES = {
    simple: `name,age,city,active
Alice,30,Paris,true
Bob,25,Lyon,false
Charlie,35,Marseille,true`,

    quoted: `name,description,price
"Product A","A great product, with features",29.99
"Product B","Contains ""special"" characters",49.99
"Product C","Multi-line
description here",19.99`,

    json: `[
  {"name": "Alice", "age": 30, "city": "Paris"},
  {"name": "Bob", "age": 25, "city": "Lyon"},
  {"name": "Charlie", "age": 35, "city": "Marseille"}
]`
};

function loadExample(name) {
    const example = EXAMPLES[name];
    document.getElementById('input-data').value = example;

    if (name === 'json') {
        selectType('json2csv');
        document.querySelectorAll('.type-btn')[1].classList.add('active');
        document.querySelectorAll('.type-btn')[0].classList.remove('active');
    } else {
        selectType('csv2json');
        document.querySelectorAll('.type-btn')[0].classList.add('active');
        document.querySelectorAll('.type-btn')[1].classList.remove('active');
    }

    convert();
}

// Event listeners for auto-convert
document.querySelectorAll('.options-section input').forEach(el => {
    el.addEventListener('change', convert);
});

// Initialize with example
loadExample('simple');
</script>
