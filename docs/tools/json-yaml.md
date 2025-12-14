---
tags:
  - tools
  - json
  - yaml
  - formatting
---

# JSON / YAML Formatter

Formatage, validation et conversion JSON/YAML.

<div class="tool-container">

<div class="tabs">
    <button class="tab-btn active" onclick="switchTab('json')">JSON</button>
    <button class="tab-btn" onclick="switchTab('yaml')">YAML</button>
    <button class="tab-btn" onclick="switchTab('convert')">Convertir</button>
</div>

<div id="tab-json" class="tab-content active">
    <div class="input-group">
        <label>JSON brut :</label>
        <textarea id="json-input" rows="10" placeholder='{"name":"John","age":30,"city":"Paris"}'></textarea>
    </div>
    <div class="button-row">
        <button onclick="formatJSON()" class="action-btn">Formater</button>
        <button onclick="minifyJSON()" class="action-btn secondary">Minifier</button>
        <button onclick="validateJSON()" class="action-btn secondary">Valider</button>
        <button onclick="copyOutput('json-output')" class="action-btn secondary">Copier</button>
    </div>
    <div id="json-error" class="error-box" style="display:none;"></div>
    <div id="json-success" class="success-box" style="display:none;"></div>
    <div class="input-group">
        <label>Resultat :</label>
        <textarea id="json-output" rows="10" readonly></textarea>
    </div>
</div>

<div id="tab-yaml" class="tab-content">
    <div class="input-group">
        <label>YAML brut :</label>
        <textarea id="yaml-input" rows="10" placeholder="name: John
age: 30
city: Paris"></textarea>
    </div>
    <div class="button-row">
        <button onclick="formatYAML()" class="action-btn">Formater</button>
        <button onclick="validateYAML()" class="action-btn secondary">Valider</button>
        <button onclick="copyOutput('yaml-output')" class="action-btn secondary">Copier</button>
    </div>
    <div id="yaml-error" class="error-box" style="display:none;"></div>
    <div id="yaml-success" class="success-box" style="display:none;"></div>
    <div class="input-group">
        <label>Resultat :</label>
        <textarea id="yaml-output" rows="10" readonly></textarea>
    </div>
</div>

<div id="tab-convert" class="tab-content">
    <div class="convert-grid">
        <div class="convert-panel">
            <label>JSON :</label>
            <textarea id="convert-json" rows="12" placeholder='{"key": "value"}'></textarea>
            <button onclick="jsonToYaml()" class="action-btn">JSON &rarr; YAML</button>
        </div>
        <div class="convert-panel">
            <label>YAML :</label>
            <textarea id="convert-yaml" rows="12" placeholder="key: value"></textarea>
            <button onclick="yamlToJson()" class="action-btn">YAML &rarr; JSON</button>
        </div>
    </div>
    <div id="convert-error" class="error-box" style="display:none;"></div>
</div>

</div>

## Reference

### JSON

```json
{
  "string": "Hello",
  "number": 42,
  "float": 3.14,
  "boolean": true,
  "null": null,
  "array": [1, 2, 3],
  "object": {
    "nested": "value"
  }
}
```

### YAML

```yaml
string: Hello
number: 42
float: 3.14
boolean: true
null_value: null
array:
  - 1
  - 2
  - 3
object:
  nested: value

# Syntaxe alternative pour arrays
inline_array: [1, 2, 3]

# Multi-ligne
description: |
  Premiere ligne
  Deuxieme ligne

# Multi-ligne sans newlines finaux
compact: >
  Cette phrase sera
  sur une seule ligne
```

### Outils CLI

```bash
# Valider JSON
cat file.json | jq .

# Formater JSON
cat file.json | jq '.' > formatted.json

# Minifier JSON
cat file.json | jq -c '.'

# YAML vers JSON (avec yq)
yq -o=json file.yaml

# JSON vers YAML (avec yq)
yq -P file.json

# Valider YAML
python -c "import yaml; yaml.safe_load(open('file.yaml'))"
```

<style>
.tool-container {
    background: var(--md-code-bg-color);
    padding: 20px;
    border-radius: 8px;
    margin: 20px 0;
}
.tabs {
    display: flex;
    gap: 5px;
    margin-bottom: 20px;
    border-bottom: 2px solid var(--md-default-fg-color--lighter);
    padding-bottom: 10px;
}
.tab-btn {
    padding: 10px 20px;
    border: none;
    background: transparent;
    color: var(--md-default-fg-color);
    cursor: pointer;
    font-size: 14px;
    font-weight: bold;
    border-radius: 4px 4px 0 0;
}
.tab-btn.active {
    background: var(--md-primary-fg-color);
    color: white;
}
.tab-btn:hover:not(.active) {
    background: var(--md-default-fg-color--lightest);
}
.tab-content {
    display: none;
}
.tab-content.active {
    display: block;
}
.input-group {
    margin: 15px 0;
}
.input-group label {
    display: block;
    font-weight: bold;
    margin-bottom: 5px;
}
.input-group textarea {
    width: 100%;
    padding: 12px;
    font-family: monospace;
    font-size: 13px;
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    background: var(--md-default-bg-color);
    color: var(--md-default-fg-color);
    resize: vertical;
}
.button-row {
    display: flex;
    gap: 10px;
    flex-wrap: wrap;
}
.action-btn {
    padding: 10px 20px;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    font-size: 14px;
    background: var(--md-primary-fg-color);
    color: white;
}
.action-btn.secondary {
    background: var(--md-default-bg-color);
    color: var(--md-default-fg-color);
    border: 1px solid var(--md-default-fg-color--lighter);
}
.action-btn:hover {
    opacity: 0.9;
}
.error-box {
    padding: 10px 15px;
    background: #f8d7da;
    border: 1px solid #f5c6cb;
    border-radius: 4px;
    color: #721c24;
    margin: 10px 0;
}
.success-box {
    padding: 10px 15px;
    background: #d4edda;
    border: 1px solid #c3e6cb;
    border-radius: 4px;
    color: #155724;
    margin: 10px 0;
}
.convert-grid {
    display: flex;
    gap: 20px;
    flex-wrap: wrap;
}
.convert-panel {
    flex: 1;
    min-width: 300px;
}
.convert-panel label {
    display: block;
    font-weight: bold;
    margin-bottom: 5px;
}
.convert-panel textarea {
    width: 100%;
    padding: 12px;
    font-family: monospace;
    font-size: 13px;
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    background: var(--md-default-bg-color);
    color: var(--md-default-fg-color);
    resize: vertical;
    margin-bottom: 10px;
}
</style>

<script>
function switchTab(tab) {
    document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));

    document.querySelector(`.tab-btn[onclick="switchTab('${tab}')"]`).classList.add('active');
    document.getElementById('tab-' + tab).classList.add('active');
}

function formatJSON() {
    const input = document.getElementById('json-input').value;
    const errorBox = document.getElementById('json-error');
    const successBox = document.getElementById('json-success');

    errorBox.style.display = 'none';
    successBox.style.display = 'none';

    try {
        const parsed = JSON.parse(input);
        document.getElementById('json-output').value = JSON.stringify(parsed, null, 2);
        successBox.textContent = 'JSON formate avec succes';
        successBox.style.display = 'block';
    } catch (e) {
        errorBox.textContent = 'Erreur: ' + e.message;
        errorBox.style.display = 'block';
    }
}

function minifyJSON() {
    const input = document.getElementById('json-input').value;
    const errorBox = document.getElementById('json-error');
    const successBox = document.getElementById('json-success');

    errorBox.style.display = 'none';
    successBox.style.display = 'none';

    try {
        const parsed = JSON.parse(input);
        document.getElementById('json-output').value = JSON.stringify(parsed);
        successBox.textContent = 'JSON minifie avec succes';
        successBox.style.display = 'block';
    } catch (e) {
        errorBox.textContent = 'Erreur: ' + e.message;
        errorBox.style.display = 'block';
    }
}

function validateJSON() {
    const input = document.getElementById('json-input').value;
    const errorBox = document.getElementById('json-error');
    const successBox = document.getElementById('json-success');

    errorBox.style.display = 'none';
    successBox.style.display = 'none';

    try {
        JSON.parse(input);
        successBox.textContent = 'JSON valide';
        successBox.style.display = 'block';
    } catch (e) {
        errorBox.textContent = 'JSON invalide: ' + e.message;
        errorBox.style.display = 'block';
    }
}

// Simple YAML parser (basic implementation)
function parseYAML(yaml) {
    const lines = yaml.split('\n');
    const result = {};
    const stack = [{ obj: result, indent: -1 }];
    let currentArray = null;

    for (let line of lines) {
        // Skip comments and empty lines
        if (line.trim().startsWith('#') || line.trim() === '') continue;

        const indent = line.search(/\S/);
        const trimmed = line.trim();

        // Array item
        if (trimmed.startsWith('- ')) {
            const value = trimmed.slice(2).trim();
            const parent = stack[stack.length - 1];

            if (currentArray === null) {
                // Find the key for this array
                const keys = Object.keys(parent.obj);
                const lastKey = keys[keys.length - 1];
                if (parent.obj[lastKey] === null) {
                    parent.obj[lastKey] = [];
                    currentArray = parent.obj[lastKey];
                }
            }

            if (currentArray) {
                currentArray.push(parseValue(value));
            }
            continue;
        }

        currentArray = null;

        // Key-value pair
        const colonIndex = trimmed.indexOf(':');
        if (colonIndex === -1) continue;

        const key = trimmed.slice(0, colonIndex).trim();
        const value = trimmed.slice(colonIndex + 1).trim();

        // Adjust stack based on indentation
        while (stack.length > 1 && stack[stack.length - 1].indent >= indent) {
            stack.pop();
        }

        const parent = stack[stack.length - 1].obj;

        if (value === '' || value === '|' || value === '>') {
            // Nested object or multiline
            parent[key] = {};
            stack.push({ obj: parent[key], indent: indent });
        } else {
            parent[key] = parseValue(value);
        }
    }

    return result;
}

function parseValue(str) {
    if (str === '' || str === 'null' || str === '~') return null;
    if (str === 'true') return true;
    if (str === 'false') return false;
    if (/^-?\d+$/.test(str)) return parseInt(str);
    if (/^-?\d*\.\d+$/.test(str)) return parseFloat(str);
    // Remove quotes
    if ((str.startsWith('"') && str.endsWith('"')) ||
        (str.startsWith("'") && str.endsWith("'"))) {
        return str.slice(1, -1);
    }
    return str;
}

function toYAML(obj, indent = 0) {
    const spaces = '  '.repeat(indent);
    let result = '';

    if (Array.isArray(obj)) {
        for (const item of obj) {
            if (typeof item === 'object' && item !== null) {
                result += spaces + '-\n' + toYAML(item, indent + 1);
            } else {
                result += spaces + '- ' + formatYAMLValue(item) + '\n';
            }
        }
    } else if (typeof obj === 'object' && obj !== null) {
        for (const [key, value] of Object.entries(obj)) {
            if (typeof value === 'object' && value !== null) {
                result += spaces + key + ':\n' + toYAML(value, indent + 1);
            } else {
                result += spaces + key + ': ' + formatYAMLValue(value) + '\n';
            }
        }
    }

    return result;
}

function formatYAMLValue(val) {
    if (val === null) return 'null';
    if (typeof val === 'boolean') return val ? 'true' : 'false';
    if (typeof val === 'number') return String(val);
    if (typeof val === 'string') {
        if (val.includes('\n') || val.includes(':') || val.includes('#')) {
            return '"' + val.replace(/"/g, '\\"') + '"';
        }
        return val;
    }
    return String(val);
}

function formatYAML() {
    const input = document.getElementById('yaml-input').value;
    const errorBox = document.getElementById('yaml-error');
    const successBox = document.getElementById('yaml-success');

    errorBox.style.display = 'none';
    successBox.style.display = 'none';

    try {
        const parsed = parseYAML(input);
        document.getElementById('yaml-output').value = toYAML(parsed);
        successBox.textContent = 'YAML formate avec succes';
        successBox.style.display = 'block';
    } catch (e) {
        errorBox.textContent = 'Erreur: ' + e.message;
        errorBox.style.display = 'block';
    }
}

function validateYAML() {
    const input = document.getElementById('yaml-input').value;
    const errorBox = document.getElementById('yaml-error');
    const successBox = document.getElementById('yaml-success');

    errorBox.style.display = 'none';
    successBox.style.display = 'none';

    try {
        parseYAML(input);
        successBox.textContent = 'YAML valide';
        successBox.style.display = 'block';
    } catch (e) {
        errorBox.textContent = 'YAML invalide: ' + e.message;
        errorBox.style.display = 'block';
    }
}

function jsonToYaml() {
    const input = document.getElementById('convert-json').value;
    const errorBox = document.getElementById('convert-error');
    errorBox.style.display = 'none';

    try {
        const parsed = JSON.parse(input);
        document.getElementById('convert-yaml').value = toYAML(parsed);
    } catch (e) {
        errorBox.textContent = 'Erreur JSON: ' + e.message;
        errorBox.style.display = 'block';
    }
}

function yamlToJson() {
    const input = document.getElementById('convert-yaml').value;
    const errorBox = document.getElementById('convert-error');
    errorBox.style.display = 'none';

    try {
        const parsed = parseYAML(input);
        document.getElementById('convert-json').value = JSON.stringify(parsed, null, 2);
    } catch (e) {
        errorBox.textContent = 'Erreur YAML: ' + e.message;
        errorBox.style.display = 'block';
    }
}

function copyOutput(id) {
    const textarea = document.getElementById(id);
    textarea.select();
    document.execCommand('copy');
}
</script>
