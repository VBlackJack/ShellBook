---
tags:
  - tools
  - string
  - text
  - case
  - naming
---

# String Case Converter

Conversion entre conventions de nommage : camelCase, snake_case, kebab-case, etc.

<div class="tool-container">

<div class="input-section">
    <div class="input-group">
        <label for="string-input">Texte a convertir :</label>
        <textarea id="string-input" rows="3" placeholder="hello world, HelloWorld, hello_world, hello-world..."></textarea>
    </div>

    <div class="detect-row">
        <span>Format detecte : <strong id="detected-format">-</strong></span>
    </div>
</div>

<div class="output-section">
    <h3>Conversions</h3>

    <div class="case-grid">
        <div class="case-item">
            <label>camelCase</label>
            <div class="case-output">
                <input type="text" id="camel-case" readonly>
                <button onclick="copyCase('camel-case')">Copier</button>
            </div>
        </div>

        <div class="case-item">
            <label>PascalCase</label>
            <div class="case-output">
                <input type="text" id="pascal-case" readonly>
                <button onclick="copyCase('pascal-case')">Copier</button>
            </div>
        </div>

        <div class="case-item">
            <label>snake_case</label>
            <div class="case-output">
                <input type="text" id="snake-case" readonly>
                <button onclick="copyCase('snake-case')">Copier</button>
            </div>
        </div>

        <div class="case-item">
            <label>SCREAMING_SNAKE_CASE</label>
            <div class="case-output">
                <input type="text" id="screaming-snake" readonly>
                <button onclick="copyCase('screaming-snake')">Copier</button>
            </div>
        </div>

        <div class="case-item">
            <label>kebab-case</label>
            <div class="case-output">
                <input type="text" id="kebab-case" readonly>
                <button onclick="copyCase('kebab-case')">Copier</button>
            </div>
        </div>

        <div class="case-item">
            <label>COBOL-CASE</label>
            <div class="case-output">
                <input type="text" id="cobol-case" readonly>
                <button onclick="copyCase('cobol-case')">Copier</button>
            </div>
        </div>

        <div class="case-item">
            <label>Train-Case</label>
            <div class="case-output">
                <input type="text" id="train-case" readonly>
                <button onclick="copyCase('train-case')">Copier</button>
            </div>
        </div>

        <div class="case-item">
            <label>flatcase</label>
            <div class="case-output">
                <input type="text" id="flat-case" readonly>
                <button onclick="copyCase('flat-case')">Copier</button>
            </div>
        </div>

        <div class="case-item">
            <label>UPPERFLATCASE</label>
            <div class="case-output">
                <input type="text" id="upper-flat" readonly>
                <button onclick="copyCase('upper-flat')">Copier</button>
            </div>
        </div>

        <div class="case-item">
            <label>Title Case</label>
            <div class="case-output">
                <input type="text" id="title-case" readonly>
                <button onclick="copyCase('title-case')">Copier</button>
            </div>
        </div>

        <div class="case-item">
            <label>Sentence case</label>
            <div class="case-output">
                <input type="text" id="sentence-case" readonly>
                <button onclick="copyCase('sentence-case')">Copier</button>
            </div>
        </div>

        <div class="case-item">
            <label>dot.case</label>
            <div class="case-output">
                <input type="text" id="dot-case" readonly>
                <button onclick="copyCase('dot-case')">Copier</button>
            </div>
        </div>

        <div class="case-item">
            <label>path/case</label>
            <div class="case-output">
                <input type="text" id="path-case" readonly>
                <button onclick="copyCase('path-case')">Copier</button>
            </div>
        </div>
    </div>
</div>

</div>

## Conventions de nommage

| Convention | Exemple | Usage |
|------------|---------|-------|
| **camelCase** | `myVariableName` | JavaScript, Java variables |
| **PascalCase** | `MyClassName` | Classes, composants React |
| **snake_case** | `my_variable_name` | Python, Ruby, SQL |
| **SCREAMING_SNAKE** | `MY_CONSTANT` | Constantes |
| **kebab-case** | `my-component-name` | CSS, URLs, CLI |
| **COBOL-CASE** | `MY-VARIABLE-NAME` | COBOL, anciens systemes |
| **Train-Case** | `My-Variable-Name` | HTTP headers |
| **flatcase** | `myvariablename` | Packages Java |
| **Title Case** | `My Variable Name` | Titres |
| **dot.case** | `my.variable.name` | Proprietes Java, configs |
| **path/case** | `my/variable/name` | Chemins fichiers |

## Conventions par langage

| Langage | Variables | Constantes | Classes | Fonctions |
|---------|-----------|------------|---------|-----------|
| **JavaScript** | camelCase | SCREAMING_SNAKE | PascalCase | camelCase |
| **Python** | snake_case | SCREAMING_SNAKE | PascalCase | snake_case |
| **Java** | camelCase | SCREAMING_SNAKE | PascalCase | camelCase |
| **C#** | camelCase | PascalCase | PascalCase | PascalCase |
| **Go** | camelCase | camelCase | PascalCase | camelCase |
| **Rust** | snake_case | SCREAMING_SNAKE | PascalCase | snake_case |
| **Ruby** | snake_case | SCREAMING_SNAKE | PascalCase | snake_case |
| **PHP** | camelCase | SCREAMING_SNAKE | PascalCase | camelCase |
| **CSS** | kebab-case | - | - | - |
| **SQL** | snake_case | - | - | snake_case |

<style>
.tool-container {
    background: var(--md-code-bg-color);
    padding: 20px;
    border-radius: 8px;
    margin: 20px 0;
}
.input-section {
    background: var(--md-default-bg-color);
    padding: 20px;
    border-radius: 4px;
    margin-bottom: 20px;
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
    font-size: 16px;
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    background: var(--md-code-bg-color);
    color: var(--md-default-fg-color);
    resize: vertical;
}
.detect-row {
    margin-top: 10px;
    font-size: 14px;
}
.output-section {
    background: var(--md-default-bg-color);
    padding: 20px;
    border-radius: 4px;
}
.output-section h3 {
    margin: 0 0 15px 0;
}
.case-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 15px;
}
.case-item {
    background: var(--md-code-bg-color);
    padding: 15px;
    border-radius: 4px;
}
.case-item label {
    display: block;
    font-size: 12px;
    font-weight: bold;
    margin-bottom: 8px;
    color: var(--md-default-fg-color--light);
}
.case-output {
    display: flex;
    gap: 10px;
}
.case-output input {
    flex: 1;
    padding: 10px;
    font-family: monospace;
    font-size: 14px;
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    background: var(--md-default-bg-color);
    color: var(--md-default-fg-color);
}
.case-output button {
    padding: 10px 15px;
    background: var(--md-primary-fg-color);
    color: white;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    font-size: 12px;
}
.case-output button:hover {
    opacity: 0.9;
}
</style>

<script>
// Split string into words
function splitIntoWords(str) {
    if (!str) return [];

    // Replace common separators with spaces
    str = str.replace(/[-_./\\]/g, ' ');

    // Add space before uppercase letters (for camelCase/PascalCase)
    str = str.replace(/([a-z])([A-Z])/g, '$1 $2');
    str = str.replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2');

    // Split by spaces and filter empty
    return str.split(/\s+/).filter(w => w.length > 0);
}

// Detect current format
function detectFormat(str) {
    if (!str) return '-';

    if (/^[a-z]+$/.test(str)) return 'flatcase';
    if (/^[A-Z]+$/.test(str)) return 'UPPERFLATCASE';
    if (/^[a-z]+[A-Z]/.test(str) && !str.includes('_') && !str.includes('-')) return 'camelCase';
    if (/^[A-Z][a-z]+[A-Z]/.test(str) && !str.includes('_') && !str.includes('-')) return 'PascalCase';
    if (/^[a-z]+(_[a-z]+)+$/.test(str)) return 'snake_case';
    if (/^[A-Z]+(_[A-Z]+)+$/.test(str)) return 'SCREAMING_SNAKE_CASE';
    if (/^[a-z]+(-[a-z]+)+$/.test(str)) return 'kebab-case';
    if (/^[A-Z]+(-[A-Z]+)+$/.test(str)) return 'COBOL-CASE';
    if (/^[A-Z][a-z]+(-[A-Z][a-z]+)+$/.test(str)) return 'Train-Case';
    if (/^[a-z]+(\\.[a-z]+)+$/.test(str)) return 'dot.case';
    if (/^[a-z]+(\/[a-z]+)+$/.test(str)) return 'path/case';
    if (/^[A-Z][a-z]+( [A-Z][a-z]+)+$/.test(str)) return 'Title Case';

    return 'Mixed';
}

// Conversion functions
function toCamelCase(words) {
    return words.map((w, i) =>
        i === 0 ? w.toLowerCase() : w.charAt(0).toUpperCase() + w.slice(1).toLowerCase()
    ).join('');
}

function toPascalCase(words) {
    return words.map(w => w.charAt(0).toUpperCase() + w.slice(1).toLowerCase()).join('');
}

function toSnakeCase(words) {
    return words.map(w => w.toLowerCase()).join('_');
}

function toScreamingSnake(words) {
    return words.map(w => w.toUpperCase()).join('_');
}

function toKebabCase(words) {
    return words.map(w => w.toLowerCase()).join('-');
}

function toCobolCase(words) {
    return words.map(w => w.toUpperCase()).join('-');
}

function toTrainCase(words) {
    return words.map(w => w.charAt(0).toUpperCase() + w.slice(1).toLowerCase()).join('-');
}

function toFlatCase(words) {
    return words.map(w => w.toLowerCase()).join('');
}

function toUpperFlat(words) {
    return words.map(w => w.toUpperCase()).join('');
}

function toTitleCase(words) {
    return words.map(w => w.charAt(0).toUpperCase() + w.slice(1).toLowerCase()).join(' ');
}

function toSentenceCase(words) {
    return words.map((w, i) =>
        i === 0 ? w.charAt(0).toUpperCase() + w.slice(1).toLowerCase() : w.toLowerCase()
    ).join(' ');
}

function toDotCase(words) {
    return words.map(w => w.toLowerCase()).join('.');
}

function toPathCase(words) {
    return words.map(w => w.toLowerCase()).join('/');
}

// Convert and update all outputs
function convertAll() {
    const input = document.getElementById('string-input').value.trim();
    const words = splitIntoWords(input);

    document.getElementById('detected-format').textContent = detectFormat(input);

    if (words.length === 0) {
        document.querySelectorAll('.case-output input').forEach(el => el.value = '');
        return;
    }

    document.getElementById('camel-case').value = toCamelCase(words);
    document.getElementById('pascal-case').value = toPascalCase(words);
    document.getElementById('snake-case').value = toSnakeCase(words);
    document.getElementById('screaming-snake').value = toScreamingSnake(words);
    document.getElementById('kebab-case').value = toKebabCase(words);
    document.getElementById('cobol-case').value = toCobolCase(words);
    document.getElementById('train-case').value = toTrainCase(words);
    document.getElementById('flat-case').value = toFlatCase(words);
    document.getElementById('upper-flat').value = toUpperFlat(words);
    document.getElementById('title-case').value = toTitleCase(words);
    document.getElementById('sentence-case').value = toSentenceCase(words);
    document.getElementById('dot-case').value = toDotCase(words);
    document.getElementById('path-case').value = toPathCase(words);
}

function copyCase(id) {
    const input = document.getElementById(id);
    input.select();
    document.execCommand('copy');

    const btn = input.nextElementSibling;
    const orig = btn.textContent;
    btn.textContent = 'OK!';
    setTimeout(() => { btn.textContent = orig; }, 1000);
}

// Event listener
document.getElementById('string-input').addEventListener('input', convertAll);

// Initial example
document.getElementById('string-input').value = 'hello world example';
convertAll();
</script>
