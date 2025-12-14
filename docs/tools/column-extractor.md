---
tags:
  - tools
  - data
  - csv
  - parsing
---

# Column Extractor

Extracteur de colonnes pour fichiers CSV, TSV et texte délimité.

<div id="column-extractor">
  <style>
    #column-extractor {
      font-family: inherit;
    }
    #column-extractor .extractor-container {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 20px;
    }
    @media (max-width: 900px) {
      #column-extractor .extractor-container {
        grid-template-columns: 1fr;
      }
    }
    #column-extractor .input-section,
    #column-extractor .output-section {
      background: var(--md-code-bg-color);
      border-radius: 8px;
      padding: 20px;
    }
    #column-extractor .section-title {
      font-size: 14px;
      font-weight: 600;
      margin: 15px 0 10px 0;
      padding-bottom: 5px;
      border-bottom: 1px solid var(--md-default-fg-color--lighter);
    }
    #column-extractor .section-title:first-child {
      margin-top: 0;
    }
    #column-extractor .form-group {
      margin-bottom: 15px;
    }
    #column-extractor label {
      display: block;
      margin-bottom: 5px;
      font-weight: 500;
      font-size: 13px;
    }
    #column-extractor select,
    #column-extractor input[type="text"] {
      width: 100%;
      padding: 8px 12px;
      border: 1px solid var(--md-default-fg-color--lighter);
      border-radius: 4px;
      background: var(--md-default-bg-color);
      color: var(--md-default-fg-color);
      font-size: 14px;
      box-sizing: border-box;
    }
    #column-extractor textarea {
      width: 100%;
      min-height: 200px;
      padding: 12px;
      border: 1px solid var(--md-default-fg-color--lighter);
      border-radius: 4px;
      background: var(--md-default-bg-color);
      color: var(--md-default-fg-color);
      font-family: 'Consolas', 'Monaco', monospace;
      font-size: 12px;
      resize: vertical;
      box-sizing: border-box;
    }
    #column-extractor .output-box {
      background: var(--md-default-bg-color);
      border: 1px solid var(--md-default-fg-color--lighter);
      border-radius: 4px;
      padding: 15px;
      font-family: monospace;
      font-size: 12px;
      white-space: pre-wrap;
      min-height: 200px;
      max-height: 400px;
      overflow: auto;
    }
    #column-extractor .columns-selector {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin: 10px 0;
    }
    #column-extractor .column-chip {
      display: inline-flex;
      align-items: center;
      gap: 5px;
      padding: 6px 12px;
      background: var(--md-default-bg-color);
      border: 1px solid var(--md-default-fg-color--lighter);
      border-radius: 20px;
      cursor: pointer;
      font-size: 12px;
      transition: all 0.2s;
    }
    #column-extractor .column-chip:hover {
      border-color: var(--md-primary-fg-color);
    }
    #column-extractor .column-chip.selected {
      background: var(--md-primary-fg-color);
      border-color: var(--md-primary-fg-color);
      color: white;
    }
    #column-extractor .column-chip .col-index {
      font-size: 10px;
      opacity: 0.7;
    }
    #column-extractor .presets {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-bottom: 15px;
    }
    #column-extractor .preset-btn {
      padding: 5px 10px;
      border: 1px solid var(--md-primary-fg-color);
      background: transparent;
      color: var(--md-primary-fg-color);
      border-radius: 4px;
      cursor: pointer;
      font-size: 11px;
    }
    #column-extractor .preset-btn:hover {
      background: var(--md-primary-fg-color);
      color: white;
    }
    #column-extractor .actions {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      margin-top: 15px;
    }
    #column-extractor .btn {
      padding: 8px 16px;
      border: none;
      border-radius: 4px;
      cursor: pointer;
      font-size: 13px;
    }
    #column-extractor .btn-primary {
      background: var(--md-primary-fg-color);
      color: white;
    }
    #column-extractor .btn-secondary {
      background: var(--md-default-fg-color--lighter);
      color: var(--md-default-fg-color);
    }
    #column-extractor .stats {
      font-size: 12px;
      color: var(--md-default-fg-color--light);
      margin-top: 10px;
    }
    #column-extractor .inline-options {
      display: flex;
      flex-wrap: wrap;
      gap: 15px;
      margin-top: 10px;
    }
    #column-extractor .inline-option {
      display: flex;
      align-items: center;
      gap: 5px;
      font-size: 13px;
    }
    #column-extractor .preview-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 11px;
      margin-top: 10px;
    }
    #column-extractor .preview-table th,
    #column-extractor .preview-table td {
      padding: 6px 8px;
      border: 1px solid var(--md-default-fg-color--lighter);
      text-align: left;
      max-width: 150px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    #column-extractor .preview-table th {
      background: var(--md-code-bg-color);
      font-weight: 600;
    }
    #column-extractor .preview-table tr:nth-child(even) {
      background: var(--md-code-bg-color);
    }
    #column-extractor .drag-handle {
      cursor: grab;
      opacity: 0.5;
    }
  </style>

  <div class="presets">
    <button class="preset-btn" onclick="loadCSVExample('csv')">📊 CSV</button>
    <button class="preset-btn" onclick="loadCSVExample('tsv')">📋 TSV</button>
    <button class="preset-btn" onclick="loadCSVExample('logs')">📝 Logs</button>
    <button class="preset-btn" onclick="loadCSVExample('passwd')">🔐 /etc/passwd</button>
  </div>

  <div class="extractor-container">
    <div class="input-section">
      <div class="section-title">📥 Données d'entrée</div>
      <textarea id="col-input" oninput="parseInput()" placeholder="Collez vos données CSV, TSV ou texte délimité...">name,email,department,salary
Alice Martin,alice@company.com,Engineering,75000
Bob Johnson,bob@company.com,Marketing,65000
Carol Williams,carol@company.com,Engineering,80000
David Brown,david@company.com,Sales,70000
Eva Davis,eva@company.com,HR,60000</textarea>

      <div class="form-group">
        <label for="delimiter">Délimiteur</label>
        <select id="delimiter" onchange="parseInput()">
          <option value=",">Virgule (,)</option>
          <option value=";">Point-virgule (;)</option>
          <option value="\t">Tabulation</option>
          <option value="|">Pipe (|)</option>
          <option value=" ">Espace</option>
          <option value=":">Deux-points (:)</option>
          <option value="custom">Personnalisé...</option>
        </select>
      </div>

      <div class="form-group" id="custom-delimiter-group" style="display: none;">
        <label for="custom-delimiter">Délimiteur personnalisé</label>
        <input type="text" id="custom-delimiter" placeholder="Entrez le délimiteur" oninput="parseInput()">
      </div>

      <div class="inline-options">
        <label class="inline-option">
          <input type="checkbox" id="has-header" checked onchange="parseInput()"> Première ligne = en-têtes
        </label>
        <label class="inline-option">
          <input type="checkbox" id="trim-spaces" checked onchange="extractColumns()"> Supprimer espaces
        </label>
        <label class="inline-option">
          <input type="checkbox" id="skip-empty" onchange="extractColumns()"> Ignorer lignes vides
        </label>
      </div>

      <div class="section-title">📋 Colonnes détectées</div>
      <div class="columns-selector" id="columns-selector"></div>
      <div class="stats" id="input-stats"></div>
    </div>

    <div class="output-section">
      <div class="section-title">👀 Aperçu</div>
      <div id="preview-container" style="overflow-x: auto;"></div>

      <div class="section-title">📤 Colonnes extraites</div>
      <div class="form-group">
        <label for="output-delimiter">Délimiteur de sortie</label>
        <select id="output-delimiter" onchange="extractColumns()">
          <option value=",">Virgule (,)</option>
          <option value=";">Point-virgule (;)</option>
          <option value="\t">Tabulation</option>
          <option value="|">Pipe (|)</option>
          <option value="\n">Nouvelle ligne</option>
        </select>
      </div>
      <div class="output-box" id="col-output"></div>
      <div class="stats" id="output-stats"></div>

      <div class="actions">
        <button class="btn btn-primary" onclick="copyOutput()">📋 Copier</button>
        <button class="btn btn-secondary" onclick="downloadOutput()">💾 Télécharger</button>
        <button class="btn btn-secondary" onclick="selectAll()">✅ Tout sélectionner</button>
        <button class="btn btn-secondary" onclick="selectNone()">❌ Tout désélectionner</button>
      </div>
    </div>
  </div>
</div>

<script>
(function() {
  let parsedData = [];
  let headers = [];
  let selectedColumns = new Set();

  const examples = {
    csv: {
      data: `name,email,department,salary
Alice Martin,alice@company.com,Engineering,75000
Bob Johnson,bob@company.com,Marketing,65000
Carol Williams,carol@company.com,Engineering,80000
David Brown,david@company.com,Sales,70000
Eva Davis,eva@company.com,HR,60000`,
      delimiter: ','
    },
    tsv: {
      data: `ID\tName\tCountry\tScore
1\tJohn Doe\tUSA\t95
2\tJane Smith\tUK\t88
3\tPierre Dupont\tFrance\t92
4\tMaria Garcia\tSpain\t87`,
      delimiter: '\t'
    },
    logs: {
      data: `192.168.1.100 - - [10/Dec/2024:10:15:32] "GET /api/users HTTP/1.1" 200 1234
192.168.1.101 - - [10/Dec/2024:10:15:33] "POST /api/login HTTP/1.1" 200 567
192.168.1.102 - - [10/Dec/2024:10:15:34] "GET /api/products HTTP/1.1" 404 89
192.168.1.100 - - [10/Dec/2024:10:15:35] "PUT /api/users/1 HTTP/1.1" 200 432`,
      delimiter: ' '
    },
    passwd: {
      data: `root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin`,
      delimiter: ':'
    }
  };

  window.loadCSVExample = function(example) {
    const ex = examples[example];
    document.getElementById('col-input').value = ex.data;
    document.getElementById('delimiter').value = ex.delimiter;
    if (ex.delimiter === '\t') {
      document.getElementById('delimiter').value = '\t';
    }
    parseInput();
  };

  document.getElementById('delimiter').addEventListener('change', function() {
    const customGroup = document.getElementById('custom-delimiter-group');
    customGroup.style.display = this.value === 'custom' ? 'block' : 'none';
  });

  window.parseInput = function() {
    const input = document.getElementById('col-input').value;
    const delimiterSelect = document.getElementById('delimiter').value;
    const delimiter = delimiterSelect === 'custom'
      ? document.getElementById('custom-delimiter').value
      : delimiterSelect;
    const hasHeader = document.getElementById('has-header').checked;

    if (!input.trim() || !delimiter) {
      parsedData = [];
      headers = [];
      renderColumnSelector();
      renderPreview();
      extractColumns();
      return;
    }

    const lines = input.split('\n').filter(line => line.trim());
    parsedData = lines.map(line => parseCSVLine(line, delimiter));

    if (hasHeader && parsedData.length > 0) {
      headers = parsedData[0];
      parsedData = parsedData.slice(1);
    } else {
      const maxCols = Math.max(...parsedData.map(row => row.length));
      headers = Array.from({ length: maxCols }, (_, i) => `Col ${i + 1}`);
    }

    // Initialize selected columns
    if (selectedColumns.size === 0) {
      headers.forEach((_, i) => selectedColumns.add(i));
    }

    renderColumnSelector();
    renderPreview();
    extractColumns();

    // Update stats
    document.getElementById('input-stats').textContent =
      `${parsedData.length} lignes × ${headers.length} colonnes`;
  };

  function parseCSVLine(line, delimiter) {
    const result = [];
    let current = '';
    let inQuotes = false;

    for (let i = 0; i < line.length; i++) {
      const char = line[i];

      if (char === '"') {
        if (inQuotes && line[i + 1] === '"') {
          current += '"';
          i++;
        } else {
          inQuotes = !inQuotes;
        }
      } else if (char === delimiter && !inQuotes) {
        result.push(current);
        current = '';
      } else {
        current += char;
      }
    }
    result.push(current);

    return result;
  }

  function renderColumnSelector() {
    const container = document.getElementById('columns-selector');

    if (headers.length === 0) {
      container.innerHTML = '<span style="color: var(--md-default-fg-color--light);">Aucune colonne détectée</span>';
      return;
    }

    container.innerHTML = headers.map((header, i) => `
      <div class="column-chip ${selectedColumns.has(i) ? 'selected' : ''}"
           onclick="toggleColumn(${i})">
        <span class="col-index">#${i + 1}</span>
        <span>${header}</span>
      </div>
    `).join('');
  }

  window.toggleColumn = function(index) {
    if (selectedColumns.has(index)) {
      selectedColumns.delete(index);
    } else {
      selectedColumns.add(index);
    }
    renderColumnSelector();
    extractColumns();
  };

  window.selectAll = function() {
    headers.forEach((_, i) => selectedColumns.add(i));
    renderColumnSelector();
    extractColumns();
  };

  window.selectNone = function() {
    selectedColumns.clear();
    renderColumnSelector();
    extractColumns();
  };

  function renderPreview() {
    const container = document.getElementById('preview-container');

    if (parsedData.length === 0) {
      container.innerHTML = '<div style="color: var(--md-default-fg-color--light); padding: 20px;">Aucune donnée</div>';
      return;
    }

    const previewRows = parsedData.slice(0, 5);

    container.innerHTML = `
      <table class="preview-table">
        <thead>
          <tr>
            ${headers.map((h, i) => `<th style="${selectedColumns.has(i) ? 'background: var(--md-primary-fg-color); color: white;' : ''}">${h}</th>`).join('')}
          </tr>
        </thead>
        <tbody>
          ${previewRows.map(row => `
            <tr>
              ${headers.map((_, i) => `<td style="${selectedColumns.has(i) ? 'background: var(--md-primary-fg-color--light);' : ''}">${row[i] || ''}</td>`).join('')}
            </tr>
          `).join('')}
        </tbody>
      </table>
      ${parsedData.length > 5 ? `<div style="text-align: center; padding: 5px; font-size: 11px; color: var(--md-default-fg-color--light);">... et ${parsedData.length - 5} lignes de plus</div>` : ''}
    `;
  }

  window.extractColumns = function() {
    const outputDelimiter = document.getElementById('output-delimiter').value;
    const trimSpaces = document.getElementById('trim-spaces').checked;
    const skipEmpty = document.getElementById('skip-empty').checked;

    if (parsedData.length === 0 || selectedColumns.size === 0) {
      document.getElementById('col-output').textContent = '';
      document.getElementById('output-stats').textContent = '';
      return;
    }

    const selectedIndices = Array.from(selectedColumns).sort((a, b) => a - b);

    // Include headers if present
    const hasHeader = document.getElementById('has-header').checked;
    let output = [];

    if (hasHeader) {
      const headerRow = selectedIndices.map(i => headers[i]);
      output.push(headerRow.join(outputDelimiter === '\n' ? outputDelimiter : outputDelimiter));
    }

    parsedData.forEach(row => {
      const selectedValues = selectedIndices.map(i => {
        let val = row[i] || '';
        if (trimSpaces) val = val.trim();
        return val;
      });

      if (skipEmpty && selectedValues.every(v => v === '')) return;

      output.push(selectedValues.join(outputDelimiter === '\n' ? outputDelimiter : outputDelimiter));
    });

    document.getElementById('col-output').textContent = output.join('\n');
    document.getElementById('output-stats').textContent =
      `${output.length} lignes × ${selectedIndices.length} colonnes`;
  };

  window.copyOutput = function() {
    const output = document.getElementById('col-output').textContent;
    navigator.clipboard.writeText(output).then(() => {
      const btn = event.target;
      btn.textContent = '✓ Copié!';
      setTimeout(() => btn.textContent = '📋 Copier', 2000);
    });
  };

  window.downloadOutput = function() {
    const output = document.getElementById('col-output').textContent;
    const blob = new Blob([output], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'extracted_columns.csv';
    a.click();
    URL.revokeObjectURL(url);
  };

  // Initialize
  parseInput();
})();
</script>

---

## Équivalents CLI

### cut

```bash
# Extraire colonnes 1 et 3 (CSV)
cut -d',' -f1,3 data.csv

# Extraire colonnes 1-3 (TSV)
cut -f1-3 data.tsv

# Extraire avec délimiteur personnalisé
cut -d':' -f1,7 /etc/passwd
```

### awk

```bash
# Extraire colonnes spécifiques
awk -F',' '{print $1, $3}' data.csv

# Avec reformatage
awk -F',' '{print $2 " - " $1}' data.csv

# Filtrer et extraire
awk -F',' '$3 > 100 {print $1, $3}' data.csv
```

### csvkit

```bash
# Extraire par nom de colonne
csvcut -c name,email data.csv

# Extraire par numéro
csvcut -c 1,3 data.csv
```

---

## Formats courants

| Format | Délimiteur | Extension |
|--------|------------|-----------|
| CSV | `,` | .csv |
| TSV | Tab | .tsv |
| PSV | `\|` | .psv |
| SSV | `;` | .csv (Europe) |
