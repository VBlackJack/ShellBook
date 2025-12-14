---
tags:
  - tools
  - json
  - jsonpath
  - development
---

# JSONPath Tester

Testeur interactif de requêtes JSONPath pour extraire des données JSON.

<div id="jsonpath-tester">
  <style>
    #jsonpath-tester {
      font-family: inherit;
    }
    #jsonpath-tester .tester-container {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 20px;
    }
    @media (max-width: 900px) {
      #jsonpath-tester .tester-container {
        grid-template-columns: 1fr;
      }
    }
    #jsonpath-tester .input-section,
    #jsonpath-tester .output-section {
      background: var(--md-code-bg-color);
      border-radius: 8px;
      padding: 20px;
    }
    #jsonpath-tester .section-title {
      font-size: 14px;
      font-weight: 600;
      margin: 0 0 15px 0;
      padding-bottom: 10px;
      border-bottom: 1px solid var(--md-default-fg-color--lighter);
    }
    #jsonpath-tester .query-input {
      width: 100%;
      padding: 12px 15px;
      font-family: monospace;
      font-size: 14px;
      border: 2px solid var(--md-default-fg-color--lighter);
      border-radius: 4px;
      background: var(--md-default-bg-color);
      color: var(--md-primary-fg-color);
      box-sizing: border-box;
      margin-bottom: 15px;
    }
    #jsonpath-tester .query-input:focus {
      border-color: var(--md-primary-fg-color);
      outline: none;
    }
    #jsonpath-tester textarea {
      width: 100%;
      min-height: 300px;
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
    #jsonpath-tester .output-box {
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
    #jsonpath-tester .presets {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-bottom: 15px;
    }
    #jsonpath-tester .preset-btn {
      padding: 5px 10px;
      border: 1px solid var(--md-primary-fg-color);
      background: transparent;
      color: var(--md-primary-fg-color);
      border-radius: 4px;
      cursor: pointer;
      font-size: 11px;
    }
    #jsonpath-tester .preset-btn:hover {
      background: var(--md-primary-fg-color);
      color: white;
    }
    #jsonpath-tester .stats {
      margin-top: 10px;
      font-size: 12px;
      color: var(--md-default-fg-color--light);
    }
    #jsonpath-tester .error-msg {
      color: #e74c3c;
      background: #e74c3c22;
      padding: 10px;
      border-radius: 4px;
      font-size: 13px;
    }
    #jsonpath-tester .actions {
      display: flex;
      gap: 10px;
      margin-top: 15px;
    }
    #jsonpath-tester .btn {
      padding: 8px 16px;
      border: none;
      border-radius: 4px;
      cursor: pointer;
      font-size: 13px;
    }
    #jsonpath-tester .btn-primary {
      background: var(--md-primary-fg-color);
      color: white;
    }
    #jsonpath-tester .btn-secondary {
      background: var(--md-default-fg-color--lighter);
      color: var(--md-default-fg-color);
    }
    #jsonpath-tester .reference-section {
      background: var(--md-code-bg-color);
      border-radius: 8px;
      padding: 20px;
      margin-top: 20px;
    }
    #jsonpath-tester .ref-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: 15px;
    }
    #jsonpath-tester .ref-item {
      background: var(--md-default-bg-color);
      border-radius: 4px;
      padding: 12px;
    }
    #jsonpath-tester .ref-syntax {
      font-family: monospace;
      color: var(--md-primary-fg-color);
      font-size: 13px;
      margin-bottom: 5px;
    }
    #jsonpath-tester .ref-desc {
      font-size: 12px;
      color: var(--md-default-fg-color--light);
    }
    #jsonpath-tester .try-btn {
      font-size: 10px;
      padding: 2px 6px;
      margin-left: 8px;
      background: var(--md-primary-fg-color);
      color: white;
      border: none;
      border-radius: 3px;
      cursor: pointer;
    }
  </style>

  <div class="presets">
    <button class="preset-btn" onclick="loadJSONExample('users')">👥 Users API</button>
    <button class="preset-btn" onclick="loadJSONExample('products')">🛍️ Products</button>
    <button class="preset-btn" onclick="loadJSONExample('kubernetes')">☸️ K8s Pod</button>
    <button class="preset-btn" onclick="loadJSONExample('github')">🐙 GitHub</button>
  </div>

  <div class="tester-container">
    <div class="input-section">
      <div class="section-title">📝 JSON Input</div>
      <textarea id="json-input" oninput="executeQuery()">{
  "store": {
    "name": "My Store",
    "books": [
      {"title": "The Great Gatsby", "author": "F. Scott Fitzgerald", "price": 9.99, "category": "fiction"},
      {"title": "1984", "author": "George Orwell", "price": 12.99, "category": "fiction"},
      {"title": "Clean Code", "author": "Robert Martin", "price": 34.99, "category": "programming"},
      {"title": "The Pragmatic Programmer", "author": "David Thomas", "price": 44.95, "category": "programming"}
    ],
    "electronics": [
      {"name": "Laptop", "price": 999.99, "brand": "TechCo"},
      {"name": "Phone", "price": 699.99, "brand": "MobileCorp"}
    ]
  }
}</textarea>
      <div class="actions">
        <button class="btn btn-secondary" onclick="formatJSON()">🎨 Formater</button>
        <button class="btn btn-secondary" onclick="minifyJSON()">📦 Minifier</button>
      </div>
    </div>

    <div class="output-section">
      <div class="section-title">🔍 JSONPath Query</div>
      <input type="text" class="query-input" id="jsonpath-query" value="$.store.books[*].title" placeholder="$.store.books[*].title" oninput="executeQuery()">

      <div class="section-title">📤 Résultat</div>
      <div class="output-box" id="jsonpath-output"></div>
      <div class="stats" id="query-stats"></div>

      <div class="actions">
        <button class="btn btn-primary" onclick="copyResult()">📋 Copier</button>
      </div>
    </div>
  </div>

  <div class="reference-section">
    <div class="section-title">📖 Syntaxe JSONPath</div>
    <div class="ref-grid">
      <div class="ref-item">
        <div class="ref-syntax">$ <button class="try-btn" onclick="tryQuery('$')">Essayer</button></div>
        <div class="ref-desc">Racine du document</div>
      </div>
      <div class="ref-item">
        <div class="ref-syntax">$.store <button class="try-btn" onclick="tryQuery('$.store')">Essayer</button></div>
        <div class="ref-desc">Accès à une propriété</div>
      </div>
      <div class="ref-item">
        <div class="ref-syntax">$.store.books[0] <button class="try-btn" onclick="tryQuery('$.store.books[0]')">Essayer</button></div>
        <div class="ref-desc">Premier élément du tableau</div>
      </div>
      <div class="ref-item">
        <div class="ref-syntax">$.store.books[-1] <button class="try-btn" onclick="tryQuery('$.store.books[-1]')">Essayer</button></div>
        <div class="ref-desc">Dernier élément du tableau</div>
      </div>
      <div class="ref-item">
        <div class="ref-syntax">$.store.books[*] <button class="try-btn" onclick="tryQuery('$.store.books[*]')">Essayer</button></div>
        <div class="ref-desc">Tous les éléments</div>
      </div>
      <div class="ref-item">
        <div class="ref-syntax">$.store.books[0:2] <button class="try-btn" onclick="tryQuery('$.store.books[0:2]')">Essayer</button></div>
        <div class="ref-desc">Slice (indices 0 et 1)</div>
      </div>
      <div class="ref-item">
        <div class="ref-syntax">$.store.books[*].title <button class="try-btn" onclick="tryQuery('$.store.books[*].title')">Essayer</button></div>
        <div class="ref-desc">Propriété de tous les éléments</div>
      </div>
      <div class="ref-item">
        <div class="ref-syntax">$..title <button class="try-btn" onclick="tryQuery('$..title')">Essayer</button></div>
        <div class="ref-desc">Recherche récursive</div>
      </div>
      <div class="ref-item">
        <div class="ref-syntax">$..price <button class="try-btn" onclick="tryQuery('$..price')">Essayer</button></div>
        <div class="ref-desc">Tous les prix (récursif)</div>
      </div>
      <div class="ref-item">
        <div class="ref-syntax">$.store.books[?(@.price<15)] <button class="try-btn" onclick="tryQuery('$.store.books[?(@.price<15)]')">Essayer</button></div>
        <div class="ref-desc">Filtre: prix < 15</div>
      </div>
      <div class="ref-item">
        <div class="ref-syntax">$.store.books[?(@.category=="fiction")] <button class="try-btn" onclick="tryQuery('$.store.books[?(@.category==\"fiction\")]')">Essayer</button></div>
        <div class="ref-desc">Filtre par catégorie</div>
      </div>
      <div class="ref-item">
        <div class="ref-syntax">$.store.books.length <button class="try-btn" onclick="tryQuery('$.store.books.length')">Essayer</button></div>
        <div class="ref-desc">Nombre d'éléments</div>
      </div>
    </div>
  </div>
</div>

<script>
(function() {
  const examples = {
    users: {
      json: {
        users: [
          { id: 1, name: "Alice", email: "alice@example.com", role: "admin", active: true },
          { id: 2, name: "Bob", email: "bob@example.com", role: "user", active: true },
          { id: 3, name: "Charlie", email: "charlie@example.com", role: "user", active: false }
        ],
        total: 3,
        page: 1
      },
      query: '$.users[?(@.active==true)].name'
    },
    products: {
      json: {
        products: [
          { id: "P001", name: "Laptop", price: 999.99, stock: 50, category: "electronics" },
          { id: "P002", name: "Mouse", price: 29.99, stock: 200, category: "electronics" },
          { id: "P003", name: "Desk", price: 299.99, stock: 30, category: "furniture" }
        ],
        currency: "USD"
      },
      query: '$.products[?(@.price>100)].name'
    },
    kubernetes: {
      json: {
        apiVersion: "v1",
        kind: "Pod",
        metadata: {
          name: "nginx-pod",
          namespace: "default",
          labels: { app: "nginx", env: "production" }
        },
        spec: {
          containers: [
            { name: "nginx", image: "nginx:1.25", ports: [{ containerPort: 80 }] },
            { name: "sidecar", image: "busybox:latest", command: ["sleep", "3600"] }
          ]
        },
        status: { phase: "Running" }
      },
      query: '$.spec.containers[*].image'
    },
    github: {
      json: {
        repository: {
          name: "awesome-project",
          owner: { login: "developer", id: 12345 },
          stargazers_count: 1234,
          forks_count: 567,
          issues: [
            { number: 1, title: "Bug fix needed", state: "open", labels: ["bug"] },
            { number: 2, title: "Feature request", state: "open", labels: ["enhancement"] },
            { number: 3, title: "Documentation update", state: "closed", labels: ["docs"] }
          ]
        }
      },
      query: '$.repository.issues[?(@.state=="open")].title'
    }
  };

  window.loadJSONExample = function(example) {
    const ex = examples[example];
    document.getElementById('json-input').value = JSON.stringify(ex.json, null, 2);
    document.getElementById('jsonpath-query').value = ex.query;
    executeQuery();
  };

  window.tryQuery = function(query) {
    document.getElementById('jsonpath-query').value = query;
    executeQuery();
  };

  window.executeQuery = function() {
    const jsonInput = document.getElementById('json-input').value;
    const query = document.getElementById('jsonpath-query').value;
    const output = document.getElementById('jsonpath-output');
    const stats = document.getElementById('query-stats');

    if (!jsonInput.trim()) {
      output.textContent = '';
      stats.textContent = '';
      return;
    }

    let data;
    try {
      data = JSON.parse(jsonInput);
    } catch (e) {
      output.innerHTML = `<span class="error-msg">❌ JSON invalide: ${e.message}</span>`;
      stats.textContent = '';
      return;
    }

    if (!query.trim()) {
      output.textContent = JSON.stringify(data, null, 2);
      stats.textContent = '';
      return;
    }

    try {
      const result = evaluateJSONPath(data, query);
      if (result === undefined) {
        output.textContent = 'null';
        stats.textContent = 'Aucun résultat';
      } else if (Array.isArray(result)) {
        output.textContent = JSON.stringify(result, null, 2);
        stats.textContent = `${result.length} résultat(s)`;
      } else {
        output.textContent = JSON.stringify(result, null, 2);
        stats.textContent = '1 résultat';
      }
    } catch (e) {
      output.innerHTML = `<span class="error-msg">❌ Erreur: ${e.message}</span>`;
      stats.textContent = '';
    }
  };

  // Simple JSONPath implementation
  function evaluateJSONPath(data, path) {
    if (path === '$') return data;

    // Handle length
    if (path.endsWith('.length')) {
      const basePath = path.slice(0, -7);
      const base = evaluateJSONPath(data, basePath);
      return Array.isArray(base) ? base.length : undefined;
    }

    // Handle recursive descent
    if (path.includes('..')) {
      const parts = path.split('..');
      let current = evaluateJSONPath(data, parts[0]);
      const prop = parts[1].replace(/\[\*\]/g, '');
      return findAllDeep(current || data, prop);
    }

    // Parse path
    const tokens = tokenizePath(path);
    let current = data;

    for (const token of tokens) {
      if (current === undefined || current === null) return undefined;

      if (token.type === 'root') {
        continue;
      } else if (token.type === 'property') {
        current = current[token.value];
      } else if (token.type === 'index') {
        if (token.value < 0) {
          current = current[current.length + token.value];
        } else {
          current = current[token.value];
        }
      } else if (token.type === 'wildcard') {
        if (Array.isArray(current)) {
          current = current;
        } else {
          current = Object.values(current);
        }
      } else if (token.type === 'slice') {
        current = current.slice(token.start, token.end);
      } else if (token.type === 'filter') {
        current = current.filter(item => evaluateFilter(item, token.expression));
      } else if (token.type === 'propertyOfAll') {
        if (Array.isArray(current)) {
          current = current.map(item => item[token.value]).filter(v => v !== undefined);
        }
      }
    }

    return current;
  }

  function tokenizePath(path) {
    const tokens = [];
    let remaining = path;

    while (remaining.length > 0) {
      if (remaining.startsWith('$')) {
        tokens.push({ type: 'root' });
        remaining = remaining.slice(1);
      } else if (remaining.startsWith('.')) {
        remaining = remaining.slice(1);
      } else if (remaining.startsWith('[*]')) {
        tokens.push({ type: 'wildcard' });
        remaining = remaining.slice(3);
      } else if (remaining.startsWith('[?')) {
        const end = findMatchingBracket(remaining, 0);
        const expr = remaining.slice(3, end - 1);
        tokens.push({ type: 'filter', expression: expr });
        remaining = remaining.slice(end + 1);
      } else if (remaining.match(/^\[\d+:\d*\]/)) {
        const match = remaining.match(/^\[(\d+):(\d*)\]/);
        tokens.push({
          type: 'slice',
          start: parseInt(match[1]),
          end: match[2] ? parseInt(match[2]) : undefined
        });
        remaining = remaining.slice(match[0].length);
      } else if (remaining.match(/^\[-?\d+\]/)) {
        const match = remaining.match(/^\[(-?\d+)\]/);
        tokens.push({ type: 'index', value: parseInt(match[1]) });
        remaining = remaining.slice(match[0].length);
      } else if (remaining.match(/^[a-zA-Z_][a-zA-Z0-9_]*/)) {
        const match = remaining.match(/^([a-zA-Z_][a-zA-Z0-9_]*)/);
        const lastToken = tokens[tokens.length - 1];
        if (lastToken && lastToken.type === 'wildcard') {
          tokens.push({ type: 'propertyOfAll', value: match[1] });
        } else {
          tokens.push({ type: 'property', value: match[1] });
        }
        remaining = remaining.slice(match[0].length);
      } else {
        remaining = remaining.slice(1);
      }
    }

    return tokens;
  }

  function findMatchingBracket(str, start) {
    let depth = 0;
    for (let i = start; i < str.length; i++) {
      if (str[i] === '[') depth++;
      if (str[i] === ']') {
        depth--;
        if (depth === 0) return i;
      }
    }
    return str.length;
  }

  function evaluateFilter(item, expr) {
    // Simple filter evaluation
    expr = expr.replace(/@/g, 'item');
    expr = expr.replace(/==/g, '===');
    try {
      return eval(expr);
    } catch {
      return false;
    }
  }

  function findAllDeep(obj, prop) {
    const results = [];

    function search(current) {
      if (current === null || current === undefined) return;

      if (typeof current === 'object') {
        if (prop in current) {
          results.push(current[prop]);
        }
        for (const key in current) {
          search(current[key]);
        }
      }
    }

    search(obj);
    return results;
  }

  window.formatJSON = function() {
    const input = document.getElementById('json-input');
    try {
      const data = JSON.parse(input.value);
      input.value = JSON.stringify(data, null, 2);
    } catch (e) {
      alert('JSON invalide: ' + e.message);
    }
  };

  window.minifyJSON = function() {
    const input = document.getElementById('json-input');
    try {
      const data = JSON.parse(input.value);
      input.value = JSON.stringify(data);
    } catch (e) {
      alert('JSON invalide: ' + e.message);
    }
  };

  window.copyResult = function() {
    const output = document.getElementById('jsonpath-output').textContent;
    navigator.clipboard.writeText(output).then(() => {
      const btn = event.target;
      btn.textContent = '✓ Copié!';
      setTimeout(() => btn.textContent = '📋 Copier', 2000);
    });
  };

  // Initialize
  executeQuery();
})();
</script>

---

## Syntaxe JSONPath

| Expression | Description |
|------------|-------------|
| `$` | Racine du document |
| `.` ou `[]` | Accès enfant |
| `..` | Descente récursive |
| `*` | Wildcard (tous les éléments) |
| `[n]` | Index du tableau (0-based) |
| `[-n]` | Index depuis la fin |
| `[start:end]` | Slice du tableau |
| `[?(expr)]` | Filtre avec expression |
| `@` | Élément courant (dans les filtres) |

## Filtres courants

```jsonpath
# Prix inférieur à 20
$.products[?(@.price < 20)]

# Statut actif
$.users[?(@.active == true)]

# Catégorie spécifique
$.items[?(@.category == "electronics")]

# Contient une propriété
$.objects[?(@.name)]

# Combinaison
$.products[?(@.price < 100 && @.stock > 0)]
```

## Comparaison avec jq

| JSONPath | jq |
|----------|-----|
| `$.users[0].name` | `.users[0].name` |
| `$.users[*].name` | `.users[].name` |
| `$..name` | `.. \| .name?` |
| `$.users[?(@.active)]` | `.users[] \| select(.active)` |
