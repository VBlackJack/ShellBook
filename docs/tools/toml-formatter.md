---
tags:
  - tools
  - toml
  - formatter
  - config
---

# TOML Formatter

Validateur et formateur TOML avec conversion JSON.

<div id="toml-app">
  <div class="toml-container">
    <div class="toml-section">
      <div class="section-header">
        <h3>TOML Input</h3>
        <div class="header-actions">
          <button onclick="formatToml()">🎨 Formater</button>
          <button onclick="clearInput()">🗑️ Effacer</button>
        </div>
      </div>
      <textarea id="tomlInput" placeholder="Collez votre TOML ici..." oninput="validateToml()"># Configuration exemple
[server]
host = "localhost"
port = 8080
debug = true

[database]
driver = "postgresql"
host = "db.example.com"
port = 5432
name = "myapp"

[database.pool]
min = 5
max = 20
timeout = 30

[[users]]
name = "admin"
email = "admin@example.com"
roles = ["admin", "user"]

[[users]]
name = "guest"
email = "guest@example.com"
roles = ["user"]

[logging]
level = "info"
format = "json"
output = "/var/log/app.log"</textarea>

      <div class="examples-bar">
        <span>Exemples:</span>
        <button onclick="loadExample('cargo')">Cargo.toml</button>
        <button onclick="loadExample('pyproject')">pyproject.toml</button>
        <button onclick="loadExample('config')">App Config</button>
        <button onclick="loadExample('hugo')">Hugo</button>
      </div>
    </div>

    <div class="toml-section">
      <div class="validation-status" id="validationStatus">
        <span class="status-icon">⏳</span>
        <span class="status-text">En attente...</span>
      </div>

      <div class="tabs">
        <button class="tab active" onclick="showTab('json')">JSON</button>
        <button class="tab" onclick="showTab('tree')">Tree View</button>
        <button class="tab" onclick="showTab('env')">Env Vars</button>
      </div>

      <div id="tab-json" class="tab-content active">
        <div class="output-header">
          <span>Conversion JSON</span>
          <button onclick="copyJson()">📋 Copier</button>
        </div>
        <pre id="jsonOutput" class="output-code"></pre>
      </div>

      <div id="tab-tree" class="tab-content">
        <div id="treeOutput" class="tree-view"></div>
      </div>

      <div id="tab-env" class="tab-content">
        <div class="output-header">
          <span>Variables d'environnement</span>
          <button onclick="copyEnv()">📋 Copier</button>
        </div>
        <pre id="envOutput" class="output-code"></pre>
      </div>

      <div id="errorDetails" class="error-details" style="display:none;"></div>
    </div>
  </div>

  <div class="reference-section">
    <h3>Reference TOML</h3>

    <div class="ref-grid">
      <div class="ref-card">
        <h4>Types de base</h4>
        <pre>string = "hello"
integer = 42
float = 3.14
boolean = true
datetime = 2024-01-15T10:30:00Z</pre>
      </div>

      <div class="ref-card">
        <h4>Strings</h4>
        <pre># Basic string
str1 = "Hello\nWorld"

# Literal string (no escape)
str2 = 'C:\path\to\file'

# Multi-line
str3 = """
  Multi-line
  string
"""</pre>
      </div>

      <div class="ref-card">
        <h4>Tables</h4>
        <pre>[server]
host = "localhost"
port = 8080

# Nested (inline)
[server.ssl]
enabled = true
cert = "/path/to/cert"

# Inline table
point = { x = 1, y = 2 }</pre>
      </div>

      <div class="ref-card">
        <h4>Arrays</h4>
        <pre># Array of values
ports = [8080, 8081, 8082]

# Array of tables
[[products]]
name = "Widget"
price = 9.99

[[products]]
name = "Gadget"
price = 19.99</pre>
      </div>
    </div>
  </div>
</div>

<style>
.toml-container {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 20px;
}

@media (max-width: 800px) {
  .toml-container {
    grid-template-columns: 1fr;
  }
}

.toml-section, .reference-section {
  background: var(--md-code-bg-color);
  padding: 20px;
  border-radius: 8px;
  margin-bottom: 20px;
}

.section-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 15px;
}

.section-header h3 {
  margin: 0;
}

.header-actions {
  display: flex;
  gap: 8px;
}

.header-actions button {
  padding: 6px 12px;
  background: var(--md-default-bg-color);
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  cursor: pointer;
  font-size: 0.85em;
}

#tomlInput {
  width: 100%;
  min-height: 400px;
  padding: 15px;
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 6px;
  background: var(--md-default-bg-color);
  color: var(--md-default-fg-color);
  font-family: monospace;
  font-size: 0.9em;
  resize: vertical;
  line-height: 1.5;
}

.examples-bar {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
  margin-top: 12px;
  font-size: 0.85em;
}

.examples-bar button {
  padding: 4px 10px;
  background: var(--md-default-bg-color);
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  cursor: pointer;
}

.examples-bar button:hover {
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

.validation-status.pending {
  background: var(--md-default-bg-color);
  color: var(--md-default-fg-color--light);
}

.tabs {
  display: flex;
  gap: 5px;
  margin-bottom: 15px;
}

.tab {
  padding: 8px 15px;
  background: var(--md-default-bg-color);
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  cursor: pointer;
}

.tab.active {
  background: var(--md-primary-fg-color);
  color: white;
  border-color: var(--md-primary-fg-color);
}

.tab-content {
  display: none;
}

.tab-content.active {
  display: block;
}

.output-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 10px;
  font-size: 0.9em;
}

.output-header button {
  padding: 4px 10px;
  background: transparent;
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  cursor: pointer;
}

.output-code {
  background: #1e1e1e;
  color: #d4d4d4;
  padding: 15px;
  border-radius: 6px;
  font-size: 0.85em;
  overflow: auto;
  max-height: 350px;
  white-space: pre;
  margin: 0;
}

.tree-view {
  background: var(--md-default-bg-color);
  padding: 15px;
  border-radius: 6px;
  font-family: monospace;
  font-size: 0.85em;
  max-height: 350px;
  overflow: auto;
}

.tree-item {
  padding: 2px 0;
}

.tree-key {
  color: var(--md-primary-fg-color);
}

.tree-value {
  color: #27ae60;
}

.error-details {
  margin-top: 15px;
  padding: 15px;
  background: rgba(231, 76, 60, 0.1);
  border: 1px solid #e74c3c;
  border-radius: 6px;
  color: #e74c3c;
}

.ref-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 15px;
}

.ref-card {
  background: var(--md-default-bg-color);
  padding: 15px;
  border-radius: 6px;
}

.ref-card h4 {
  margin: 0 0 10px 0;
}

.ref-card pre {
  margin: 0;
  padding: 10px;
  background: #1e1e1e;
  color: #d4d4d4;
  border-radius: 4px;
  font-size: 0.8em;
  overflow-x: auto;
}
</style>

<script>
// Simple TOML parser
function parseToml(toml) {
  const result = {};
  let currentSection = result;
  let currentPath = [];
  let arrayTable = null;

  const lines = toml.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();

    // Skip empty lines and comments
    if (!line || line.startsWith('#')) continue;

    // Array of tables [[section]]
    const arrayMatch = line.match(/^\[\[([^\]]+)\]\]$/);
    if (arrayMatch) {
      const path = arrayMatch[1].split('.');
      let obj = result;
      for (let j = 0; j < path.length - 1; j++) {
        if (!obj[path[j]]) obj[path[j]] = {};
        obj = obj[path[j]];
      }
      const key = path[path.length - 1];
      if (!obj[key]) obj[key] = [];
      const newItem = {};
      obj[key].push(newItem);
      currentSection = newItem;
      currentPath = path;
      continue;
    }

    // Table [section]
    const tableMatch = line.match(/^\[([^\]]+)\]$/);
    if (tableMatch) {
      const path = tableMatch[1].split('.');
      currentSection = result;
      for (const key of path) {
        if (!currentSection[key]) currentSection[key] = {};
        currentSection = currentSection[key];
      }
      currentPath = path;
      continue;
    }

    // Key-value pair
    const kvMatch = line.match(/^([^=]+)=(.*)$/);
    if (kvMatch) {
      const key = kvMatch[1].trim();
      const value = parseTomlValue(kvMatch[2].trim());
      currentSection[key] = value;
    }
  }

  return result;
}

function parseTomlValue(val) {
  val = val.trim();

  // String (basic or literal)
  if ((val.startsWith('"') && val.endsWith('"')) ||
      (val.startsWith("'") && val.endsWith("'"))) {
    return val.slice(1, -1);
  }

  // Multi-line string
  if (val.startsWith('"""') || val.startsWith("'''")) {
    return val.slice(3, -3);
  }

  // Boolean
  if (val === 'true') return true;
  if (val === 'false') return false;

  // Integer
  if (/^-?\d+$/.test(val)) return parseInt(val);

  // Float
  if (/^-?\d*\.\d+$/.test(val)) return parseFloat(val);

  // Array
  if (val.startsWith('[') && val.endsWith(']')) {
    const inner = val.slice(1, -1);
    if (!inner.trim()) return [];
    return inner.split(',').map(v => parseTomlValue(v.trim()));
  }

  // Inline table
  if (val.startsWith('{') && val.endsWith('}')) {
    const inner = val.slice(1, -1);
    const obj = {};
    inner.split(',').forEach(pair => {
      const [k, v] = pair.split('=').map(s => s.trim());
      if (k && v) obj[k] = parseTomlValue(v);
    });
    return obj;
  }

  // Datetime (basic check)
  if (/^\d{4}-\d{2}-\d{2}/.test(val)) {
    return val;
  }

  return val;
}

function validateToml() {
  const input = document.getElementById('tomlInput').value;
  const statusEl = document.getElementById('validationStatus');
  const errorEl = document.getElementById('errorDetails');

  if (!input.trim()) {
    statusEl.className = 'validation-status pending';
    statusEl.innerHTML = '<span class="status-icon">⏳</span><span class="status-text">En attente...</span>';
    document.getElementById('jsonOutput').textContent = '';
    errorEl.style.display = 'none';
    return;
  }

  try {
    const parsed = parseToml(input);

    statusEl.className = 'validation-status valid';
    statusEl.innerHTML = '<span class="status-icon">✅</span><span class="status-text">TOML valide</span>';

    document.getElementById('jsonOutput').textContent = JSON.stringify(parsed, null, 2);
    renderTree(parsed);
    renderEnvVars(parsed);
    errorEl.style.display = 'none';

  } catch (e) {
    statusEl.className = 'validation-status invalid';
    statusEl.innerHTML = '<span class="status-icon">❌</span><span class="status-text">TOML invalide</span>';

    errorEl.style.display = 'block';
    errorEl.innerHTML = `<h4>Erreur de syntaxe</h4><p>${e.message || e}</p>`;

    document.getElementById('jsonOutput').textContent = '';
  }
}

function renderTree(obj, indent = 0) {
  const container = document.getElementById('treeOutput');
  container.innerHTML = buildTreeHTML(obj, indent);
}

function buildTreeHTML(obj, indent) {
  let html = '';
  const spaces = '&nbsp;'.repeat(indent * 2);

  if (Array.isArray(obj)) {
    obj.forEach((item, i) => {
      if (typeof item === 'object' && item !== null) {
        html += `<div class="tree-item">${spaces}<span class="tree-key">[${i}]</span></div>`;
        html += buildTreeHTML(item, indent + 1);
      } else {
        html += `<div class="tree-item">${spaces}<span class="tree-key">[${i}]</span>: <span class="tree-value">${escapeHtml(String(item))}</span></div>`;
      }
    });
  } else if (typeof obj === 'object' && obj !== null) {
    for (const [key, value] of Object.entries(obj)) {
      if (typeof value === 'object' && value !== null) {
        html += `<div class="tree-item">${spaces}<span class="tree-key">${escapeHtml(key)}</span>:</div>`;
        html += buildTreeHTML(value, indent + 1);
      } else {
        html += `<div class="tree-item">${spaces}<span class="tree-key">${escapeHtml(key)}</span>: <span class="tree-value">${escapeHtml(String(value))}</span></div>`;
      }
    }
  }

  return html;
}

function renderEnvVars(obj, prefix = '') {
  const envVars = [];
  flattenToEnv(obj, prefix, envVars);
  document.getElementById('envOutput').textContent = envVars.join('\n');
}

function flattenToEnv(obj, prefix, result) {
  for (const [key, value] of Object.entries(obj)) {
    const envKey = (prefix ? prefix + '_' + key : key).toUpperCase().replace(/[^A-Z0-9_]/g, '_');

    if (Array.isArray(value)) {
      result.push(`${envKey}="${value.join(',')}"`);
    } else if (typeof value === 'object' && value !== null) {
      flattenToEnv(value, envKey, result);
    } else {
      result.push(`${envKey}="${value}"`);
    }
  }
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

function showTab(tab) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
  event.target.classList.add('active');
  document.getElementById(`tab-${tab}`).classList.add('active');
}

function formatToml() {
  validateToml();
}

function clearInput() {
  document.getElementById('tomlInput').value = '';
  validateToml();
}

function copyJson() {
  const json = document.getElementById('jsonOutput').textContent;
  navigator.clipboard.writeText(json);
}

function copyEnv() {
  const env = document.getElementById('envOutput').textContent;
  navigator.clipboard.writeText(env);
}

function loadExample(type) {
  const examples = {
    cargo: `[package]
name = "myapp"
version = "0.1.0"
edition = "2021"
authors = ["Dev <dev@example.com>"]
description = "My awesome Rust app"

[dependencies]
serde = { version = "1.0", features = ["derive"] }
tokio = { version = "1", features = ["full"] }

[dev-dependencies]
criterion = "0.4"

[[bin]]
name = "myapp"
path = "src/main.rs"`,

    pyproject: `[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "mypackage"
version = "0.1.0"
description = "My Python package"
requires-python = ">=3.8"
dependencies = [
    "requests>=2.28",
    "pydantic>=2.0"
]

[project.optional-dependencies]
dev = ["pytest", "black", "mypy"]

[tool.black]
line-length = 100

[tool.pytest.ini_options]
testpaths = ["tests"]`,

    config: `[server]
host = "0.0.0.0"
port = 8080
workers = 4

[database]
url = "postgresql://user:pass@localhost/db"
pool_size = 10

[cache]
driver = "redis"
url = "redis://localhost:6379"
ttl = 3600

[logging]
level = "info"
format = "json"

[features]
enable_signup = true
maintenance_mode = false`,

    hugo: `baseURL = "https://example.org/"
languageCode = "en-us"
title = "My Hugo Site"
theme = "ananke"

[params]
  author = "Your Name"
  description = "My site description"
  featured_image = "/images/hero.jpg"

[menu]
  [[menu.main]]
    name = "Home"
    url = "/"
    weight = 1
  [[menu.main]]
    name = "Blog"
    url = "/blog/"
    weight = 2

[markup]
  [markup.goldmark]
    [markup.goldmark.renderer]
      unsafe = true`
  };

  if (examples[type]) {
    document.getElementById('tomlInput').value = examples[type];
    validateToml();
  }
}

// Initialize
validateToml();
</script>

---

## Cas d'usage TOML

| Fichier | Usage |
|---------|-------|
| `Cargo.toml` | Configuration Rust |
| `pyproject.toml` | Configuration Python |
| `Hugo.toml` | Site statique Hugo |
| `Netlify.toml` | Deploiement Netlify |
| `deno.json(c)` | Configuration Deno |
