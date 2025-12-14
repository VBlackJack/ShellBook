---
tags:
  - tools
  - system
  - memory
  - sizing
---

# Memory Sizing Calculator

Calculateur de dimensionnement memoire pour applications et services.

<div id="memory-app">
  <div class="memory-container">
    <div class="memory-section">
      <h3>Dimensionnement application</h3>

      <div class="form-group">
        <label>Type d'application</label>
        <select id="appType" onchange="updateDefaults(); calculate()">
          <option value="web">Application Web (Node.js/Python)</option>
          <option value="java">Application Java/JVM</option>
          <option value="database">Base de donnees</option>
          <option value="cache">Cache (Redis/Memcached)</option>
          <option value="container">Container generique</option>
          <option value="custom">Personnalise</option>
        </select>
      </div>

      <div class="form-group">
        <label>Memoire de base (MB)</label>
        <input type="number" id="baseMem" value="256" min="32" oninput="onManualMemInput()">
        <span class="hint">Empreinte memoire de base de l'application</span>
      </div>

      <div class="form-group">
        <label>Connexions/workers concurrents</label>
        <input type="number" id="connections" value="100" min="1" oninput="calculate()">
      </div>

      <div class="form-group">
        <label>Memoire par connexion (MB)</label>
        <input type="number" id="memPerConn" value="2" min="0.1" step="0.1" oninput="onManualMemInput()">
      </div>

      <div class="form-group">
        <label>Nombre d'instances/replicas</label>
        <input type="number" id="instances" value="3" min="1" oninput="calculate()">
      </div>

      <div class="form-group">
        <label>Marge de securite (%)</label>
        <input type="range" id="margin" min="10" max="50" value="20" oninput="calculate()">
        <span id="marginValue">20%</span>
      </div>
    </div>

    <div class="memory-section">
      <h3>Resultats</h3>

      <div class="results-grid">
        <div class="result-card">
          <div class="result-label">Par instance</div>
          <div class="result-value" id="perInstance">0</div>
          <div class="result-unit">MB</div>
        </div>

        <div class="result-card">
          <div class="result-label">Avec marge</div>
          <div class="result-value" id="withMargin">0</div>
          <div class="result-unit">MB</div>
        </div>

        <div class="result-card primary">
          <div class="result-label">Total cluster</div>
          <div class="result-value" id="totalCluster">0</div>
          <div class="result-unit">GB</div>
        </div>

        <div class="result-card">
          <div class="result-label">Request K8s</div>
          <div class="result-value" id="k8sRequest">0</div>
          <div class="result-unit">Mi</div>
        </div>

        <div class="result-card">
          <div class="result-label">Limit K8s</div>
          <div class="result-value" id="k8sLimit">0</div>
          <div class="result-unit">Mi</div>
        </div>
      </div>

      <div class="k8s-yaml">
        <h4>Kubernetes Resources</h4>
        <pre id="k8sYaml">resources:
  requests:
    memory: "256Mi"
  limits:
    memory: "512Mi"</pre>
        <button onclick="copyYaml()">📋 Copier</button>
      </div>
    </div>
  </div>

  <div class="presets-section">
    <h3>Presets courants</h3>

    <div class="presets-grid">
      <div class="preset-card" onclick="loadPreset('nginx')">
        <h4>🌐 Nginx</h4>
        <p>50MB base, 2MB/worker</p>
        <span class="preset-total">~128MB</span>
      </div>

      <div class="preset-card" onclick="loadPreset('nodejs')">
        <h4>📦 Node.js</h4>
        <p>256MB base, 4MB/conn</p>
        <span class="preset-total">~512MB</span>
      </div>

      <div class="preset-card" onclick="loadPreset('java')">
        <h4>☕ Java/Spring</h4>
        <p>512MB heap, overhead JVM</p>
        <span class="preset-total">~1GB</span>
      </div>

      <div class="preset-card" onclick="loadPreset('postgres')">
        <h4>🐘 PostgreSQL</h4>
        <p>shared_buffers + connections</p>
        <span class="preset-total">~2GB</span>
      </div>

      <div class="preset-card" onclick="loadPreset('mysql')">
        <h4>🐬 MySQL</h4>
        <p>buffer_pool + connections</p>
        <span class="preset-total">~2GB</span>
      </div>

      <div class="preset-card" onclick="loadPreset('redis')">
        <h4>🔴 Redis</h4>
        <p>maxmemory + overhead</p>
        <span class="preset-total">~512MB</span>
      </div>

      <div class="preset-card" onclick="loadPreset('elasticsearch')">
        <h4>🔍 Elasticsearch</h4>
        <p>Heap 50% RAM</p>
        <span class="preset-total">~4GB</span>
      </div>

      <div class="preset-card" onclick="loadPreset('kafka')">
        <h4>📨 Kafka</h4>
        <p>Heap + page cache</p>
        <span class="preset-total">~6GB</span>
      </div>
    </div>
  </div>

  <div class="reference-section">
    <h3>Reference dimensionnement</h3>

    <table class="ref-table">
      <thead>
        <tr>
          <th>Service</th>
          <th>Minimum</th>
          <th>Recommande</th>
          <th>Production</th>
          <th>Notes</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td>Nginx</td>
          <td>64MB</td>
          <td>128MB</td>
          <td>256MB</td>
          <td>worker_connections</td>
        </tr>
        <tr>
          <td>Node.js</td>
          <td>256MB</td>
          <td>512MB</td>
          <td>1GB</td>
          <td>--max-old-space-size</td>
        </tr>
        <tr>
          <td>Python/Django</td>
          <td>128MB</td>
          <td>256MB</td>
          <td>512MB</td>
          <td>Par worker Gunicorn</td>
        </tr>
        <tr>
          <td>Java/JVM</td>
          <td>512MB</td>
          <td>1GB</td>
          <td>2-4GB</td>
          <td>-Xmx + overhead</td>
        </tr>
        <tr>
          <td>PostgreSQL</td>
          <td>256MB</td>
          <td>1GB</td>
          <td>4-8GB</td>
          <td>shared_buffers=25% RAM</td>
        </tr>
        <tr>
          <td>MySQL</td>
          <td>512MB</td>
          <td>2GB</td>
          <td>8GB+</td>
          <td>innodb_buffer_pool</td>
        </tr>
        <tr>
          <td>Redis</td>
          <td>64MB</td>
          <td>256MB</td>
          <td>1-4GB</td>
          <td>maxmemory</td>
        </tr>
        <tr>
          <td>MongoDB</td>
          <td>1GB</td>
          <td>4GB</td>
          <td>16GB+</td>
          <td>WiredTiger cache</td>
        </tr>
        <tr>
          <td>Elasticsearch</td>
          <td>2GB</td>
          <td>4GB</td>
          <td>32GB</td>
          <td>Heap max 50% RAM, 32GB max</td>
        </tr>
      </tbody>
    </table>
  </div>
</div>

<style>
.memory-container {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 20px;
}

@media (max-width: 800px) {
  .memory-container {
    grid-template-columns: 1fr;
  }
}

.memory-section, .presets-section, .reference-section {
  background: var(--md-code-bg-color);
  padding: 20px;
  border-radius: 8px;
  margin-bottom: 20px;
}

.form-group {
  margin-bottom: 15px;
}

.form-group label {
  display: block;
  font-size: 0.85em;
  margin-bottom: 5px;
  color: var(--md-default-fg-color--light);
}

.form-group select,
.form-group input[type="number"] {
  width: 100%;
  padding: 10px;
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  background: var(--md-default-bg-color);
  color: var(--md-default-fg-color);
  font-family: monospace;
}

.form-group input[type="range"] {
  width: calc(100% - 50px);
}

.form-group #marginValue {
  margin-left: 10px;
  font-weight: 500;
}

.hint {
  font-size: 0.8em;
  color: var(--md-default-fg-color--light);
  margin-top: 4px;
  display: block;
}

.results-grid {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 12px;
  margin-bottom: 20px;
}

.result-card {
  background: var(--md-default-bg-color);
  padding: 15px;
  border-radius: 6px;
  text-align: center;
}

.result-card.primary {
  grid-column: span 2;
  background: var(--md-primary-fg-color);
  color: white;
}

.result-label {
  font-size: 0.8em;
  opacity: 0.8;
  margin-bottom: 5px;
}

.result-value {
  font-size: 1.8em;
  font-weight: 700;
  font-family: monospace;
}

.result-unit {
  font-size: 0.75em;
  opacity: 0.7;
}

.k8s-yaml {
  background: var(--md-default-bg-color);
  padding: 15px;
  border-radius: 6px;
}

.k8s-yaml h4 {
  margin: 0 0 10px 0;
}

.k8s-yaml pre {
  background: #1e1e1e;
  color: #d4d4d4;
  padding: 15px;
  border-radius: 4px;
  font-size: 0.85em;
  margin: 0 0 10px 0;
}

.k8s-yaml button {
  padding: 6px 12px;
  background: transparent;
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  cursor: pointer;
}

.presets-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 12px;
}

.preset-card {
  background: var(--md-default-bg-color);
  padding: 15px;
  border-radius: 6px;
  cursor: pointer;
  transition: transform 0.2s;
}

.preset-card:hover {
  transform: scale(1.02);
}

.preset-card h4 {
  margin: 0 0 5px 0;
}

.preset-card p {
  font-size: 0.8em;
  color: var(--md-default-fg-color--light);
  margin: 0 0 8px 0;
}

.preset-total {
  font-family: monospace;
  font-weight: 600;
  color: var(--md-primary-fg-color);
}

.ref-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.85em;
}

.ref-table th, .ref-table td {
  padding: 10px;
  text-align: left;
  border-bottom: 1px solid var(--md-default-fg-color--lightest);
}

.ref-table th {
  background: var(--md-default-bg-color);
}
</style>

<script>
const presets = {
  nginx: { base: 50, conn: 100, memPerConn: 0.5, type: 'web' },
  nodejs: { base: 256, conn: 100, memPerConn: 4, type: 'web' },
  java: { base: 512, conn: 50, memPerConn: 8, type: 'java' },
  postgres: { base: 512, conn: 100, memPerConn: 10, type: 'database' },
  mysql: { base: 512, conn: 100, memPerConn: 8, type: 'database' },
  redis: { base: 256, conn: 1000, memPerConn: 0.1, type: 'cache' },
  elasticsearch: { base: 2048, conn: 50, memPerConn: 10, type: 'database' },
  kafka: { base: 4096, conn: 100, memPerConn: 5, type: 'container' }
};

// Appelé quand l'utilisateur modifie manuellement la mémoire
function onManualMemInput() {
  document.getElementById('appType').value = 'custom';
  calculate();
}

function updateDefaults() {
  const appType = document.getElementById('appType').value;
  // Ne pas écraser les valeurs en mode custom
  if (appType === 'custom') {
    return;
  }
  const defaults = {
    web: { base: 256, memPerConn: 2 },
    java: { base: 512, memPerConn: 8 },
    database: { base: 512, memPerConn: 10 },
    cache: { base: 128, memPerConn: 0.1 },
    container: { base: 256, memPerConn: 2 }
  };

  if (defaults[appType]) {
    document.getElementById('baseMem').value = defaults[appType].base;
    document.getElementById('memPerConn').value = defaults[appType].memPerConn;
  }
}

function loadPreset(name) {
  const preset = presets[name];
  if (preset) {
    document.getElementById('appType').value = preset.type;
    document.getElementById('baseMem').value = preset.base;
    document.getElementById('connections').value = preset.conn;
    document.getElementById('memPerConn').value = preset.memPerConn;
    calculate();
  }
}

function calculate() {
  const baseMem = parseInt(document.getElementById('baseMem').value) || 256;
  const connections = parseInt(document.getElementById('connections').value) || 100;
  const memPerConn = parseFloat(document.getElementById('memPerConn').value) || 2;
  const instances = parseInt(document.getElementById('instances').value) || 1;
  const margin = parseInt(document.getElementById('margin').value) || 20;

  document.getElementById('marginValue').textContent = margin + '%';

  // Calculate per instance
  const perInstance = baseMem + (connections * memPerConn);
  const withMargin = Math.ceil(perInstance * (1 + margin / 100));
  const totalCluster = (withMargin * instances) / 1024; // GB

  // K8s resources (request = base, limit = with margin)
  const k8sRequest = Math.ceil(perInstance);
  const k8sLimit = withMargin;

  // Update display
  document.getElementById('perInstance').textContent = Math.round(perInstance);
  document.getElementById('withMargin').textContent = withMargin;
  document.getElementById('totalCluster').textContent = totalCluster.toFixed(2);
  document.getElementById('k8sRequest').textContent = k8sRequest;
  document.getElementById('k8sLimit').textContent = k8sLimit;

  // Update K8s YAML
  document.getElementById('k8sYaml').textContent = `resources:
  requests:
    memory: "${k8sRequest}Mi"
  limits:
    memory: "${k8sLimit}Mi"`;
}

function copyYaml() {
  const yaml = document.getElementById('k8sYaml').textContent;
  navigator.clipboard.writeText(yaml).then(() => {
    const btn = event.target;
    const orig = btn.textContent;
    btn.textContent = '✓ Copie!';
    setTimeout(() => btn.textContent = orig, 1500);
  });
}

// Initialize
calculate();
</script>

---

## Formules de calcul

```
Memory par instance = Base + (Connexions × Memory/connexion)
Memory avec marge = Memory par instance × (1 + marge%)
Total cluster = Memory avec marge × Nombre d'instances
```

---

!!! tip "Bonnes pratiques"
    - **Request** = memoire normale d'utilisation
    - **Limit** = memoire maximale acceptable
    - Ratio Limit/Request entre 1.2 et 2.0
    - Surveillez les OOM kills pour ajuster
