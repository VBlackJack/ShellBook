---
tags:
  - tools
  - markdown
  - table
  - generator
---

# Markdown Table Generator

Generateur de tableaux Markdown avec import CSV et formatage automatique.

<div id="table-app">
  <div class="table-container">
    <div class="table-section">
      <h3>Editeur de tableau</h3>

      <div class="controls">
        <div class="control-group">
          <label>Colonnes</label>
          <input type="number" id="colCount" value="3" min="1" max="20" onchange="updateGrid()">
        </div>
        <div class="control-group">
          <label>Lignes</label>
          <input type="number" id="rowCount" value="3" min="1" max="50" onchange="updateGrid()">
        </div>
        <button onclick="addRow()">➕ Ligne</button>
        <button onclick="addColumn()">➕ Colonne</button>
      </div>

      <div id="tableGrid" class="table-grid"></div>

      <div class="alignment-controls">
        <span>Alignement:</span>
        <button onclick="setAlignment('left')">⬅️ Gauche</button>
        <button onclick="setAlignment('center')">↔️ Centre</button>
        <button onclick="setAlignment('right')">➡️ Droite</button>
      </div>
    </div>

    <div class="table-section">
      <h3>Markdown</h3>
      <div class="output-actions">
        <button onclick="copyMarkdown()">📋 Copier</button>
        <button onclick="clearTable()">🗑️ Effacer</button>
      </div>
      <pre id="markdownOutput" class="markdown-output">| Col 1 | Col 2 | Col 3 |
|-------|-------|-------|
|       |       |       |</pre>

      <h4>Apercu</h4>
      <div id="preview" class="table-preview"></div>
    </div>
  </div>

  <div class="import-section">
    <h3>Import</h3>

    <div class="import-tabs">
      <button class="tab active" onclick="showImportTab('csv')">CSV</button>
      <button class="tab" onclick="showImportTab('tsv')">TSV</button>
      <button class="tab" onclick="showImportTab('json')">JSON</button>
    </div>

    <div id="import-csv" class="import-content active">
      <textarea id="csvInput" placeholder="Collez vos donnees CSV ici...
nom,age,ville
Alice,25,Paris
Bob,30,Lyon"></textarea>
      <div class="import-options">
        <label><input type="checkbox" id="csvHeader" checked> Premiere ligne = en-tetes</label>
        <label>Separateur: <input type="text" id="csvSep" value="," style="width:30px"></label>
      </div>
      <button onclick="importCSV()">📥 Importer CSV</button>
    </div>

    <div id="import-tsv" class="import-content">
      <textarea id="tsvInput" placeholder="Collez vos donnees TSV (tab-separated)..."></textarea>
      <button onclick="importTSV()">📥 Importer TSV</button>
    </div>

    <div id="import-json" class="import-content">
      <textarea id="jsonInput" placeholder='[{"nom": "Alice", "age": 25}, {"nom": "Bob", "age": 30}]'></textarea>
      <button onclick="importJSON()">📥 Importer JSON</button>
    </div>
  </div>

  <div class="templates-section">
    <h3>Templates</h3>
    <div class="templates-grid">
      <button onclick="loadTemplate('comparison')">📊 Comparaison</button>
      <button onclick="loadTemplate('pricing')">💰 Pricing</button>
      <button onclick="loadTemplate('features')">✅ Features</button>
      <button onclick="loadTemplate('schedule')">📅 Planning</button>
      <button onclick="loadTemplate('api')">🔌 API Reference</button>
      <button onclick="loadTemplate('changelog')">📝 Changelog</button>
    </div>
  </div>
</div>

<style>
.table-container {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 20px;
}

@media (max-width: 900px) {
  .table-container {
    grid-template-columns: 1fr;
  }
}

.table-section, .import-section, .templates-section {
  background: var(--md-code-bg-color);
  padding: 20px;
  border-radius: 8px;
  margin-bottom: 20px;
}

.controls {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  margin-bottom: 15px;
  align-items: flex-end;
}

.control-group {
  display: flex;
  flex-direction: column;
  gap: 5px;
}

.control-group label {
  font-size: 0.8em;
  color: var(--md-default-fg-color--light);
}

.control-group input {
  width: 60px;
  padding: 8px;
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  background: var(--md-default-bg-color);
  color: var(--md-default-fg-color);
}

.controls button {
  padding: 8px 12px;
  background: var(--md-default-bg-color);
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  cursor: pointer;
}

.table-grid {
  overflow-x: auto;
  margin-bottom: 15px;
}

.table-grid table {
  border-collapse: collapse;
  width: 100%;
}

.table-grid th, .table-grid td {
  border: 1px solid var(--md-default-fg-color--lightest);
  padding: 0;
}

.table-grid input {
  width: 100%;
  padding: 8px;
  border: none;
  background: var(--md-default-bg-color);
  color: var(--md-default-fg-color);
  font-family: inherit;
}

.table-grid th input {
  font-weight: 600;
  background: var(--md-code-bg-color);
}

.alignment-controls {
  display: flex;
  gap: 10px;
  align-items: center;
  font-size: 0.9em;
}

.alignment-controls button {
  padding: 5px 10px;
  background: var(--md-default-bg-color);
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  cursor: pointer;
  font-size: 0.85em;
}

.output-actions {
  display: flex;
  gap: 10px;
  margin-bottom: 10px;
}

.output-actions button {
  padding: 6px 12px;
  background: var(--md-default-bg-color);
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  cursor: pointer;
}

.markdown-output {
  background: #1e1e1e;
  color: #d4d4d4;
  padding: 15px;
  border-radius: 6px;
  font-size: 0.85em;
  overflow-x: auto;
  white-space: pre;
  min-height: 100px;
}

.table-preview {
  background: var(--md-default-bg-color);
  padding: 15px;
  border-radius: 6px;
  overflow-x: auto;
}

.table-preview table {
  border-collapse: collapse;
  width: 100%;
}

.table-preview th, .table-preview td {
  border: 1px solid var(--md-default-fg-color--lightest);
  padding: 8px 12px;
  text-align: left;
}

.table-preview th {
  background: var(--md-code-bg-color);
  font-weight: 600;
}

.import-tabs {
  display: flex;
  gap: 5px;
  margin-bottom: 15px;
}

.import-tabs .tab {
  padding: 8px 15px;
  background: var(--md-default-bg-color);
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  cursor: pointer;
}

.import-tabs .tab.active {
  background: var(--md-primary-fg-color);
  color: white;
  border-color: var(--md-primary-fg-color);
}

.import-content {
  display: none;
}

.import-content.active {
  display: block;
}

.import-content textarea {
  width: 100%;
  min-height: 100px;
  padding: 10px;
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  background: var(--md-default-bg-color);
  color: var(--md-default-fg-color);
  font-family: monospace;
  font-size: 0.9em;
  margin-bottom: 10px;
}

.import-options {
  display: flex;
  gap: 20px;
  margin-bottom: 10px;
  font-size: 0.9em;
}

.import-options label {
  display: flex;
  align-items: center;
  gap: 5px;
}

.import-content button {
  padding: 10px 20px;
  background: var(--md-primary-fg-color);
  color: white;
  border: none;
  border-radius: 4px;
  cursor: pointer;
}

.templates-grid {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
}

.templates-grid button {
  padding: 8px 15px;
  background: var(--md-default-bg-color);
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  cursor: pointer;
}

.templates-grid button:hover {
  border-color: var(--md-primary-fg-color);
}
</style>

<script>
let tableData = {
  headers: ['Col 1', 'Col 2', 'Col 3'],
  rows: [['', '', ''], ['', '', ''], ['', '', '']],
  alignments: ['left', 'left', 'left']
};

function updateGrid() {
  const cols = parseInt(document.getElementById('colCount').value) || 3;
  const rows = parseInt(document.getElementById('rowCount').value) || 3;

  // Adjust headers
  while (tableData.headers.length < cols) {
    tableData.headers.push('Col ' + (tableData.headers.length + 1));
    tableData.alignments.push('left');
  }
  tableData.headers = tableData.headers.slice(0, cols);
  tableData.alignments = tableData.alignments.slice(0, cols);

  // Adjust rows
  while (tableData.rows.length < rows) {
    tableData.rows.push(new Array(cols).fill(''));
  }
  tableData.rows = tableData.rows.slice(0, rows);
  tableData.rows = tableData.rows.map(row => {
    while (row.length < cols) row.push('');
    return row.slice(0, cols);
  });

  renderGrid();
}

function renderGrid() {
  const grid = document.getElementById('tableGrid');
  let html = '<table>';

  // Headers
  html += '<tr>';
  tableData.headers.forEach((h, i) => {
    html += `<th><input type="text" value="${escapeHtml(h)}" onchange="updateHeader(${i}, this.value)"></th>`;
  });
  html += '</tr>';

  // Rows
  tableData.rows.forEach((row, ri) => {
    html += '<tr>';
    row.forEach((cell, ci) => {
      html += `<td><input type="text" value="${escapeHtml(cell)}" onchange="updateCell(${ri}, ${ci}, this.value)"></td>`;
    });
    html += '</tr>';
  });

  html += '</table>';
  grid.innerHTML = html;

  generateMarkdown();
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

function updateHeader(index, value) {
  tableData.headers[index] = value;
  generateMarkdown();
}

function updateCell(row, col, value) {
  tableData.rows[row][col] = value;
  generateMarkdown();
}

function addRow() {
  tableData.rows.push(new Array(tableData.headers.length).fill(''));
  document.getElementById('rowCount').value = tableData.rows.length;
  renderGrid();
}

function addColumn() {
  tableData.headers.push('Col ' + (tableData.headers.length + 1));
  tableData.alignments.push('left');
  tableData.rows.forEach(row => row.push(''));
  document.getElementById('colCount').value = tableData.headers.length;
  renderGrid();
}

function setAlignment(align) {
  tableData.alignments = tableData.alignments.map(() => align);
  generateMarkdown();
}

function generateMarkdown() {
  const colWidths = tableData.headers.map((h, i) => {
    const cells = [h, ...tableData.rows.map(r => r[i] || '')];
    return Math.max(...cells.map(c => c.length), 3);
  });

  // Header row
  let md = '| ' + tableData.headers.map((h, i) => h.padEnd(colWidths[i])).join(' | ') + ' |\n';

  // Separator row
  md += '|' + tableData.alignments.map((a, i) => {
    const w = colWidths[i];
    if (a === 'center') return ':' + '-'.repeat(w) + ':';
    if (a === 'right') return '-'.repeat(w) + ':';
    return '-'.repeat(w + 1) + '';
  }).join('|') + '|\n';

  // Data rows
  tableData.rows.forEach(row => {
    md += '| ' + row.map((c, i) => (c || '').padEnd(colWidths[i])).join(' | ') + ' |\n';
  });

  document.getElementById('markdownOutput').textContent = md;
  renderPreview(md);
}

function renderPreview(md) {
  const lines = md.trim().split('\n');
  if (lines.length < 2) return;

  const headers = lines[0].split('|').filter(c => c.trim()).map(c => c.trim());
  const rows = lines.slice(2).map(line =>
    line.split('|').filter(c => c.trim()).map(c => c.trim())
  );

  let html = '<table><thead><tr>';
  headers.forEach(h => html += `<th>${escapeHtml(h)}</th>`);
  html += '</tr></thead><tbody>';
  rows.forEach(row => {
    html += '<tr>';
    row.forEach(c => html += `<td>${escapeHtml(c)}</td>`);
    html += '</tr>';
  });
  html += '</tbody></table>';

  document.getElementById('preview').innerHTML = html;
}

function copyMarkdown() {
  const md = document.getElementById('markdownOutput').textContent;
  navigator.clipboard.writeText(md).then(() => {
    const btn = event.target;
    const orig = btn.textContent;
    btn.textContent = '✓ Copie!';
    setTimeout(() => btn.textContent = orig, 1500);
  });
}

function clearTable() {
  tableData = {
    headers: ['Col 1', 'Col 2', 'Col 3'],
    rows: [['', '', '']],
    alignments: ['left', 'left', 'left']
  };
  document.getElementById('colCount').value = 3;
  document.getElementById('rowCount').value = 1;
  renderGrid();
}

function showImportTab(tab) {
  document.querySelectorAll('.import-tabs .tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.import-content').forEach(c => c.classList.remove('active'));
  event.target.classList.add('active');
  document.getElementById(`import-${tab}`).classList.add('active');
}

function importCSV() {
  const csv = document.getElementById('csvInput').value;
  const hasHeader = document.getElementById('csvHeader').checked;
  const sep = document.getElementById('csvSep').value || ',';

  const lines = csv.trim().split('\n').map(l => l.split(sep).map(c => c.trim()));
  if (lines.length === 0) return;

  if (hasHeader) {
    tableData.headers = lines[0];
    tableData.rows = lines.slice(1);
  } else {
    tableData.headers = lines[0].map((_, i) => 'Col ' + (i + 1));
    tableData.rows = lines;
  }

  tableData.alignments = tableData.headers.map(() => 'left');
  document.getElementById('colCount').value = tableData.headers.length;
  document.getElementById('rowCount').value = tableData.rows.length;
  renderGrid();
}

function importTSV() {
  const tsv = document.getElementById('tsvInput').value;
  const lines = tsv.trim().split('\n').map(l => l.split('\t').map(c => c.trim()));
  if (lines.length === 0) return;

  tableData.headers = lines[0];
  tableData.rows = lines.slice(1);
  tableData.alignments = tableData.headers.map(() => 'left');
  document.getElementById('colCount').value = tableData.headers.length;
  document.getElementById('rowCount').value = tableData.rows.length;
  renderGrid();
}

function importJSON() {
  try {
    const json = JSON.parse(document.getElementById('jsonInput').value);
    if (!Array.isArray(json) || json.length === 0) return;

    tableData.headers = Object.keys(json[0]);
    tableData.rows = json.map(obj => tableData.headers.map(h => String(obj[h] ?? '')));
    tableData.alignments = tableData.headers.map(() => 'left');
    document.getElementById('colCount').value = tableData.headers.length;
    document.getElementById('rowCount').value = tableData.rows.length;
    renderGrid();
  } catch (e) {
    alert('JSON invalide');
  }
}

function loadTemplate(type) {
  const templates = {
    comparison: {
      headers: ['Fonctionnalite', 'Plan Gratuit', 'Plan Pro', 'Plan Enterprise'],
      rows: [
        ['Utilisateurs', '1', '10', 'Illimite'],
        ['Stockage', '1 GB', '100 GB', 'Illimite'],
        ['Support', 'Community', 'Email', '24/7 Phone'],
        ['API Access', '❌', '✅', '✅']
      ]
    },
    pricing: {
      headers: ['Plan', 'Prix/mois', 'Fonctionnalites'],
      rows: [
        ['Starter', '9€', 'Basic features'],
        ['Pro', '29€', 'Advanced features'],
        ['Enterprise', 'Contact', 'Custom solutions']
      ]
    },
    features: {
      headers: ['Feature', 'Status', 'Notes'],
      rows: [
        ['Authentication', '✅', 'OAuth2 support'],
        ['API Rate Limiting', '✅', '100 req/min'],
        ['Webhooks', '🔄', 'In progress'],
        ['Custom Domains', '❌', 'Planned Q2']
      ]
    },
    schedule: {
      headers: ['Jour', 'Tache', 'Responsable', 'Status'],
      rows: [
        ['Lundi', 'Sprint Planning', 'Team Lead', '✅'],
        ['Mercredi', 'Code Review', 'Senior Dev', '🔄'],
        ['Vendredi', 'Demo', 'PM', '📅']
      ]
    },
    api: {
      headers: ['Method', 'Endpoint', 'Description'],
      rows: [
        ['GET', '/api/users', 'List all users'],
        ['POST', '/api/users', 'Create user'],
        ['GET', '/api/users/:id', 'Get user by ID'],
        ['DELETE', '/api/users/:id', 'Delete user']
      ]
    },
    changelog: {
      headers: ['Version', 'Date', 'Changes'],
      rows: [
        ['1.2.0', '2024-01-15', 'New dashboard'],
        ['1.1.0', '2024-01-01', 'Bug fixes'],
        ['1.0.0', '2023-12-15', 'Initial release']
      ]
    }
  };

  const t = templates[type];
  if (t) {
    tableData.headers = t.headers;
    tableData.rows = t.rows;
    tableData.alignments = t.headers.map(() => 'left');
    document.getElementById('colCount').value = t.headers.length;
    document.getElementById('rowCount').value = t.rows.length;
    renderGrid();
  }
}

// Initialize
renderGrid();
</script>

---

## Syntaxe Markdown

```markdown
| Gauche | Centre | Droite |
|:-------|:------:|-------:|
| texte  | texte  | texte  |
```

| Alignement | Syntaxe |
|------------|---------|
| Gauche (defaut) | `|---|` ou `|:---|` |
| Centre | `|:---:|` |
| Droite | `|---:|` |
