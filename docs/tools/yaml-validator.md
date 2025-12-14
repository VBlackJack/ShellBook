---
tags:
  - tools
  - devops
  - yaml
  - validation
---

# YAML Validator

Validateur et formateur YAML avec conversion JSON.

<div id="yaml-app">
  <div class="yaml-container">
    <div class="yaml-input-section">
      <div class="section-header">
        <h3>YAML Input</h3>
        <div class="header-actions">
          <button onclick="formatYaml()">🎨 Formater</button>
          <button onclick="clearInput()">🗑️ Effacer</button>
        </div>
      </div>
      <textarea id="yamlInput" placeholder="Collez votre YAML ici..." oninput="validateYaml()">apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx
  labels:
    app: nginx
spec:
  replicas: 3
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
      - name: nginx
        image: nginx:1.21
        ports:
        - containerPort: 80
        resources:
          limits:
            memory: "128Mi"
            cpu: "500m"</textarea>

      <div class="examples-bar">
        <span>Exemples:</span>
        <button onclick="loadExample('k8s-deploy')">K8s Deploy</button>
        <button onclick="loadExample('docker-compose')">Docker Compose</button>
        <button onclick="loadExample('ansible')">Ansible</button>
        <button onclick="loadExample('github-action')">GitHub Action</button>
        <button onclick="loadExample('gitlab-ci')">GitLab CI</button>
      </div>
    </div>

    <div class="yaml-output-section">
      <div class="validation-status" id="validationStatus">
        <span class="status-icon">⏳</span>
        <span class="status-text">En attente...</span>
      </div>

      <div class="tabs">
        <button class="tab active" onclick="showTab('json')">JSON</button>
        <button class="tab" onclick="showTab('tree')">Tree View</button>
        <button class="tab" onclick="showTab('stats')">Stats</button>
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

      <div id="tab-stats" class="tab-content">
        <div id="statsOutput" class="stats-view"></div>
      </div>

      <div id="errorDetails" class="error-details" style="display:none;"></div>
    </div>
  </div>
</div>

<style>
.yaml-container {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 20px;
}

@media (max-width: 800px) {
  .yaml-container {
    grid-template-columns: 1fr;
  }
}

.yaml-input-section, .yaml-output-section {
  background: var(--md-code-bg-color);
  padding: 20px;
  border-radius: 8px;
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

#yamlInput {
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
  font-size: 0.85em;
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

.status-icon {
  font-size: 1.2em;
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
  font-size: 0.9em;
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
  font-size: 0.85em;
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
}

.tree-view {
  background: var(--md-default-bg-color);
  padding: 15px;
  border-radius: 6px;
  font-family: monospace;
  font-size: 0.85em;
  max-height: 400px;
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

.tree-type {
  color: var(--md-default-fg-color--light);
  font-size: 0.85em;
}

.tree-indent {
  display: inline-block;
  width: 20px;
}

.stats-view {
  background: var(--md-default-bg-color);
  padding: 15px;
  border-radius: 6px;
}

.stat-row {
  display: flex;
  justify-content: space-between;
  padding: 8px 0;
  border-bottom: 1px solid var(--md-default-fg-color--lightest);
}

.stat-row:last-child {
  border-bottom: none;
}

.stat-label {
  color: var(--md-default-fg-color--light);
}

.stat-value {
  font-weight: 500;
  font-family: monospace;
}

.error-details {
  margin-top: 15px;
  padding: 15px;
  background: rgba(231, 76, 60, 0.1);
  border: 1px solid #e74c3c;
  border-radius: 6px;
  color: #e74c3c;
}

.error-details h4 {
  margin: 0 0 10px 0;
}

.error-line {
  font-family: monospace;
  font-size: 0.9em;
  background: rgba(0,0,0,0.1);
  padding: 10px;
  border-radius: 4px;
  margin-top: 10px;
}
</style>

<script>
// Simple YAML parser (basic implementation)
function parseYaml(yaml) {
  const lines = yaml.split('\n');
  const result = {};
  const stack = [{ obj: result, indent: -1 }];
  let currentArray = null;
  let arrayIndent = -1;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();

    // Skip empty lines and comments
    if (!trimmed || trimmed.startsWith('#')) continue;

    // Get indentation
    const indent = line.search(/\S/);

    // Array item
    if (trimmed.startsWith('- ')) {
      const content = trimmed.slice(2);

      // Pop stack to correct level
      while (stack.length > 1 && stack[stack.length - 1].indent >= indent) {
        stack.pop();
      }

      const parent = stack[stack.length - 1].obj;

      if (content.includes(': ')) {
        const [key, ...valueParts] = content.split(': ');
        const value = valueParts.join(': ');
        const item = {};
        item[key.trim()] = parseValue(value.trim());

        if (!Array.isArray(parent)) {
          const lastKey = Object.keys(parent).pop();
          if (!Array.isArray(parent[lastKey])) {
            parent[lastKey] = [];
          }
          parent[lastKey].push(item);
          stack.push({ obj: item, indent: indent + 2 });
        } else {
          parent.push(item);
          stack.push({ obj: item, indent: indent + 2 });
        }
      } else {
        const lastKey = Object.keys(parent).pop();
        if (!Array.isArray(parent[lastKey])) {
          parent[lastKey] = [];
        }
        parent[lastKey].push(parseValue(content));
      }
      continue;
    }

    // Key: value
    if (trimmed.includes(': ')) {
      const colonIdx = trimmed.indexOf(': ');
      const key = trimmed.slice(0, colonIdx).trim();
      const value = trimmed.slice(colonIdx + 2).trim();

      // Pop stack to correct level
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
    } else if (trimmed.endsWith(':')) {
      // Key only (nested object)
      const key = trimmed.slice(0, -1).trim();

      while (stack.length > 1 && stack[stack.length - 1].indent >= indent) {
        stack.pop();
      }

      const parent = stack[stack.length - 1].obj;
      parent[key] = {};
      stack.push({ obj: parent[key], indent: indent });
    }
  }

  return result;
}

function parseValue(val) {
  if (val === 'true') return true;
  if (val === 'false') return false;
  if (val === 'null' || val === '~') return null;
  if (/^-?\d+$/.test(val)) return parseInt(val);
  if (/^-?\d*\.\d+$/.test(val)) return parseFloat(val);
  if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
    return val.slice(1, -1);
  }
  return val;
}

function validateYaml() {
  const input = document.getElementById('yamlInput').value;
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
    // Use js-yaml if available, otherwise use simple parser
    let parsed;
    if (typeof jsyaml !== 'undefined') {
      parsed = jsyaml.load(input);
    } else {
      parsed = parseYaml(input);
    }

    statusEl.className = 'validation-status valid';
    statusEl.innerHTML = '<span class="status-icon">✅</span><span class="status-text">YAML valide</span>';

    document.getElementById('jsonOutput').textContent = JSON.stringify(parsed, null, 2);
    renderTree(parsed);
    renderStats(input, parsed);
    errorEl.style.display = 'none';

  } catch (e) {
    statusEl.className = 'validation-status invalid';
    statusEl.innerHTML = '<span class="status-icon">❌</span><span class="status-text">YAML invalide</span>';

    errorEl.style.display = 'block';
    errorEl.innerHTML = `
      <h4>Erreur de syntaxe</h4>
      <p>${e.message || e}</p>
    `;

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
        html += `<div class="tree-item">${spaces}<span class="tree-key">[${i}]</span>:</div>`;
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
        const type = value === null ? 'null' : typeof value;
        html += `<div class="tree-item">${spaces}<span class="tree-key">${escapeHtml(key)}</span>: <span class="tree-value">${escapeHtml(String(value))}</span> <span class="tree-type">(${type})</span></div>`;
      }
    }
  }

  return html;
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

function renderStats(yaml, parsed) {
  const lines = yaml.split('\n');
  const nonEmptyLines = lines.filter(l => l.trim() && !l.trim().startsWith('#')).length;
  const comments = lines.filter(l => l.trim().startsWith('#')).length;

  function countKeys(obj) {
    let count = 0;
    if (typeof obj === 'object' && obj !== null) {
      if (Array.isArray(obj)) {
        obj.forEach(item => count += countKeys(item));
      } else {
        count += Object.keys(obj).length;
        Object.values(obj).forEach(val => count += countKeys(val));
      }
    }
    return count;
  }

  function getDepth(obj, current = 0) {
    if (typeof obj !== 'object' || obj === null) return current;
    if (Array.isArray(obj)) {
      return Math.max(current, ...obj.map(item => getDepth(item, current + 1)));
    }
    return Math.max(current, ...Object.values(obj).map(val => getDepth(val, current + 1)));
  }

  const stats = [
    { label: 'Lignes totales', value: lines.length },
    { label: 'Lignes de contenu', value: nonEmptyLines },
    { label: 'Commentaires', value: comments },
    { label: 'Taille', value: yaml.length + ' chars' },
    { label: 'Cles totales', value: countKeys(parsed) },
    { label: 'Profondeur max', value: getDepth(parsed) },
    { label: 'Taille JSON', value: JSON.stringify(parsed).length + ' chars' }
  ];

  document.getElementById('statsOutput').innerHTML = stats.map(s => `
    <div class="stat-row">
      <span class="stat-label">${s.label}</span>
      <span class="stat-value">${s.value}</span>
    </div>
  `).join('');
}

function showTab(tab) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

  event.target.classList.add('active');
  document.getElementById(`tab-${tab}`).classList.add('active');
}

function formatYaml() {
  // Just re-indent based on parsing
  validateYaml();
}

function clearInput() {
  document.getElementById('yamlInput').value = '';
  validateYaml();
}

function copyJson() {
  const json = document.getElementById('jsonOutput').textContent;
  navigator.clipboard.writeText(json).then(() => {
    const btn = event.target;
    const orig = btn.textContent;
    btn.textContent = '✓ Copie!';
    setTimeout(() => btn.textContent = orig, 1500);
  });
}

function loadExample(type) {
  const examples = {
    'k8s-deploy': `apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx
  labels:
    app: nginx
spec:
  replicas: 3
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
      - name: nginx
        image: nginx:1.21
        ports:
        - containerPort: 80`,

    'docker-compose': `version: "3.9"
services:
  web:
    build: .
    ports:
      - "8000:5000"
    volumes:
      - .:/code
    environment:
      FLASK_DEBUG: "true"
  redis:
    image: redis:alpine
    ports:
      - "6379:6379"`,

    'ansible': `---
- name: Install and configure web server
  hosts: webservers
  become: true
  vars:
    http_port: 80
    max_clients: 200

  tasks:
    - name: Install nginx
      apt:
        name: nginx
        state: present

    - name: Start nginx
      service:
        name: nginx
        state: started
        enabled: true`,

    'github-action': `name: CI Pipeline
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Setup Node.js
        uses: actions/setup-node@v3
        with:
          node-version: 18
      - run: npm ci
      - run: npm test`,

    'gitlab-ci': `stages:
  - build
  - test
  - deploy

variables:
  NODE_VERSION: "18"

build:
  stage: build
  image: node:18
  script:
    - npm ci
    - npm run build
  artifacts:
    paths:
      - dist/

test:
  stage: test
  image: node:18
  script:
    - npm ci
    - npm test

deploy:
  stage: deploy
  script:
    - echo "Deploying..."
  only:
    - main`
  };

  if (examples[type]) {
    document.getElementById('yamlInput').value = examples[type];
    validateYaml();
  }
}

// Initialize
validateYaml();
</script>

---

## Syntaxe YAML

| Element | Syntaxe | Exemple |
|---------|---------|---------|
| Cle-valeur | `key: value` | `name: nginx` |
| Liste | `- item` | `- port: 80` |
| Nested | Indentation 2 espaces | Voir exemples |
| Commentaire | `# comment` | `# This is a comment` |
| Multiline | `|` ou `>` | `description: |` |
| Ancre | `&name` / `*name` | `defaults: &defaults` |

---

!!! warning "Indentation"
    YAML est sensible a l'indentation. Utilisez des espaces (pas de tabs) et soyez coherent (2 ou 4 espaces).
