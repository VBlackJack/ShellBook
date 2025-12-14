---
tags:
  - tools
  - devops
  - prometheus
  - monitoring
---

# Prometheus Query Builder

Constructeur visuel de requetes PromQL pour Prometheus et Grafana.

<div id="promql-app">
  <div class="promql-container">
    <div class="promql-builder">
      <h3>Constructeur de requete</h3>

      <div class="builder-section">
        <label>Metrique</label>
        <div class="metric-input">
          <input type="text" id="metric" placeholder="http_requests_total" list="metricSuggestions" oninput="updateQuery()">
          <datalist id="metricSuggestions">
            <option value="http_requests_total">
            <option value="http_request_duration_seconds">
            <option value="node_cpu_seconds_total">
            <option value="node_memory_MemAvailable_bytes">
            <option value="node_disk_io_time_seconds_total">
            <option value="container_cpu_usage_seconds_total">
            <option value="container_memory_usage_bytes">
            <option value="up">
            <option value="process_resident_memory_bytes">
            <option value="go_goroutines">
          </datalist>
        </div>
      </div>

      <div class="builder-section">
        <label>Labels (filtres)</label>
        <div id="labels" class="labels-list">
          <div class="label-row">
            <input type="text" placeholder="label" value="job" oninput="updateQuery()">
            <select onchange="updateQuery()">
              <option value="=">=</option>
              <option value="!=">!=</option>
              <option value="=~">=~</option>
              <option value="!~">!~</option>
            </select>
            <input type="text" placeholder="value" value="api-server" oninput="updateQuery()">
            <button onclick="removeLabel(this)">🗑️</button>
          </div>
        </div>
        <button onclick="addLabel()" class="btn-add">➕ Ajouter label</button>
      </div>

      <div class="builder-section">
        <label>Fonction</label>
        <select id="function" onchange="updateFunctionParams(); updateQuery()">
          <option value="">Aucune</option>
          <optgroup label="Aggregation">
            <option value="sum">sum - Somme</option>
            <option value="avg">avg - Moyenne</option>
            <option value="min">min - Minimum</option>
            <option value="max">max - Maximum</option>
            <option value="count">count - Comptage</option>
            <option value="stddev">stddev - Ecart-type</option>
            <option value="topk">topk - Top K</option>
            <option value="bottomk">bottomk - Bottom K</option>
          </optgroup>
          <optgroup label="Rate/Counter">
            <option value="rate">rate - Taux/sec (counter)</option>
            <option value="irate">irate - Taux instantane</option>
            <option value="increase">increase - Augmentation</option>
            <option value="delta">delta - Delta (gauge)</option>
            <option value="deriv">deriv - Derivee</option>
          </optgroup>
          <optgroup label="Over Time">
            <option value="avg_over_time">avg_over_time</option>
            <option value="max_over_time">max_over_time</option>
            <option value="min_over_time">min_over_time</option>
            <option value="sum_over_time">sum_over_time</option>
            <option value="quantile_over_time">quantile_over_time</option>
          </optgroup>
          <optgroup label="Math">
            <option value="abs">abs - Valeur absolue</option>
            <option value="ceil">ceil - Arrondi sup</option>
            <option value="floor">floor - Arrondi inf</option>
            <option value="round">round - Arrondi</option>
            <option value="ln">ln - Log naturel</option>
            <option value="log2">log2</option>
            <option value="log10">log10</option>
          </optgroup>
          <optgroup label="Time">
            <option value="time">time - Timestamp actuel</option>
            <option value="timestamp">timestamp - Timestamp sample</option>
            <option value="day_of_week">day_of_week</option>
            <option value="hour">hour</option>
          </optgroup>
        </select>
      </div>

      <div id="functionParams" class="builder-section" style="display:none;">
        <div id="rangeParam" style="display:none;">
          <label>Range</label>
          <select id="range" onchange="updateQuery()">
            <option value="1m">1 minute</option>
            <option value="5m" selected>5 minutes</option>
            <option value="15m">15 minutes</option>
            <option value="30m">30 minutes</option>
            <option value="1h">1 heure</option>
            <option value="6h">6 heures</option>
            <option value="24h">24 heures</option>
            <option value="7d">7 jours</option>
          </select>
        </div>
        <div id="kParam" style="display:none;">
          <label>K (nombre)</label>
          <input type="number" id="kValue" value="10" min="1" onchange="updateQuery()">
        </div>
        <div id="quantileParam" style="display:none;">
          <label>Quantile</label>
          <select id="quantileValue" onchange="updateQuery()">
            <option value="0.5">50% (median)</option>
            <option value="0.75">75%</option>
            <option value="0.9">90%</option>
            <option value="0.95">95%</option>
            <option value="0.99">99%</option>
            <option value="0.999">99.9%</option>
          </select>
        </div>
      </div>

      <div class="builder-section">
        <label>Group by</label>
        <input type="text" id="groupBy" placeholder="job, instance" oninput="updateQuery()">
        <span class="hint">Labels pour aggregation (separes par virgule)</span>
      </div>

      <div class="builder-section">
        <label>Operateurs</label>
        <div class="operators">
          <button onclick="addOperator('* 100')">× 100</button>
          <button onclick="addOperator('/ 1024 / 1024')">→ MB</button>
          <button onclick="addOperator('/ 1024 / 1024 / 1024')">→ GB</button>
          <button onclick="addOperator('> 0')"> > 0</button>
          <button onclick="addOperator('!= 0')">!= 0</button>
        </div>
        <input type="text" id="customOp" placeholder="Operateur personnalise (ex: / 1000)" oninput="updateQuery()">
      </div>
    </div>

    <div class="promql-output">
      <div class="output-header">
        <h3>Requete PromQL</h3>
        <button onclick="copyQuery()">📋 Copier</button>
      </div>
      <pre id="queryOutput" class="query-code">http_requests_total</pre>

      <div class="presets-section">
        <h4>Requetes courantes</h4>
        <div class="preset-grid">
          <button onclick="loadPreset('cpu')">CPU Usage %</button>
          <button onclick="loadPreset('memory')">Memory Usage</button>
          <button onclick="loadPreset('disk')">Disk I/O</button>
          <button onclick="loadPreset('http-rate')">HTTP Rate</button>
          <button onclick="loadPreset('http-errors')">HTTP Errors</button>
          <button onclick="loadPreset('latency')">Latency P99</button>
          <button onclick="loadPreset('saturation')">Saturation</button>
          <button onclick="loadPreset('availability')">Availability</button>
        </div>
      </div>

      <div class="examples-section">
        <h4>Exemples</h4>
        <div class="example-list">
          <div class="example-item" onclick="setQuery(this.querySelector('code').textContent)">
            <code>rate(http_requests_total[5m])</code>
            <span>Requetes/sec sur 5min</span>
          </div>
          <div class="example-item" onclick="setQuery(this.querySelector('code').textContent)">
            <code>sum by (status_code) (rate(http_requests_total[5m]))</code>
            <span>Requetes/sec par status</span>
          </div>
          <div class="example-item" onclick="setQuery(this.querySelector('code').textContent)">
            <code>histogram_quantile(0.99, rate(http_request_duration_seconds_bucket[5m]))</code>
            <span>Latence P99</span>
          </div>
          <div class="example-item" onclick="setQuery(this.querySelector('code').textContent)">
            <code>100 - (avg by (instance) (irate(node_cpu_seconds_total{mode="idle"}[5m])) * 100)</code>
            <span>CPU usage %</span>
          </div>
          <div class="example-item" onclick="setQuery(this.querySelector('code').textContent)">
            <code>node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes * 100</code>
            <span>Memory available %</span>
          </div>
          <div class="example-item" onclick="setQuery(this.querySelector('code').textContent)">
            <code>sum(rate(container_cpu_usage_seconds_total{container!=""}[5m])) by (pod)</code>
            <span>CPU par pod K8s</span>
          </div>
        </div>
      </div>
    </div>
  </div>
</div>

<style>
.promql-container {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 20px;
}

@media (max-width: 900px) {
  .promql-container {
    grid-template-columns: 1fr;
  }
}

.promql-builder, .promql-output {
  background: var(--md-code-bg-color);
  padding: 20px;
  border-radius: 8px;
}

.builder-section {
  margin-bottom: 20px;
}

.builder-section > label {
  display: block;
  font-size: 0.9em;
  font-weight: 500;
  margin-bottom: 8px;
}

.builder-section input[type="text"],
.builder-section select {
  width: 100%;
  padding: 10px;
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  background: var(--md-default-bg-color);
  color: var(--md-default-fg-color);
  font-family: monospace;
}

.hint {
  font-size: 0.8em;
  color: var(--md-default-fg-color--light);
  margin-top: 4px;
  display: block;
}

.labels-list {
  margin-bottom: 10px;
}

.label-row {
  display: flex;
  gap: 8px;
  margin-bottom: 8px;
}

.label-row input {
  flex: 1;
  padding: 8px;
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  background: var(--md-default-bg-color);
  color: var(--md-default-fg-color);
  font-family: monospace;
}

.label-row select {
  width: 60px;
  padding: 8px;
}

.label-row button {
  padding: 8px;
  background: transparent;
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  cursor: pointer;
}

.btn-add {
  padding: 6px 12px;
  background: var(--md-default-bg-color);
  border: 1px dashed var(--md-default-fg-color--lightest);
  border-radius: 4px;
  cursor: pointer;
  font-size: 0.85em;
}

.operators {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-bottom: 10px;
}

.operators button {
  padding: 6px 10px;
  background: var(--md-default-bg-color);
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  cursor: pointer;
  font-family: monospace;
  font-size: 0.85em;
}

.operators button:hover {
  border-color: var(--md-primary-fg-color);
}

.output-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 15px;
}

.output-header h3 {
  margin: 0;
}

.output-header button {
  padding: 6px 12px;
  background: var(--md-default-bg-color);
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  cursor: pointer;
}

.query-code {
  background: #1e1e1e;
  color: #d4d4d4;
  padding: 15px;
  border-radius: 6px;
  font-size: 0.9em;
  overflow-x: auto;
  white-space: pre-wrap;
  word-break: break-all;
  min-height: 60px;
}

.presets-section, .examples-section {
  margin-top: 20px;
}

.presets-section h4, .examples-section h4 {
  margin-bottom: 10px;
}

.preset-grid {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.preset-grid button {
  padding: 6px 12px;
  background: var(--md-default-bg-color);
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  cursor: pointer;
  font-size: 0.85em;
}

.preset-grid button:hover {
  border-color: var(--md-primary-fg-color);
}

.example-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.example-item {
  padding: 10px;
  background: var(--md-default-bg-color);
  border-radius: 4px;
  cursor: pointer;
}

.example-item:hover {
  outline: 1px solid var(--md-primary-fg-color);
}

.example-item code {
  display: block;
  font-size: 0.85em;
  margin-bottom: 4px;
  word-break: break-all;
}

.example-item span {
  font-size: 0.8em;
  color: var(--md-default-fg-color--light);
}
</style>

<script>
let customOperator = '';

function updateQuery() {
  const metric = document.getElementById('metric').value || 'metric_name';
  const fn = document.getElementById('function').value;
  const groupBy = document.getElementById('groupBy').value.trim();
  const customOp = document.getElementById('customOp').value.trim();

  // Build labels
  const labels = [];
  document.querySelectorAll('#labels .label-row').forEach(row => {
    const inputs = row.querySelectorAll('input');
    const select = row.querySelector('select');
    const key = inputs[0].value.trim();
    const op = select.value;
    const val = inputs[1].value.trim();
    if (key && val) {
      labels.push(`${key}${op}"${val}"`);
    }
  });

  let labelStr = labels.length > 0 ? `{${labels.join(', ')}}` : '';

  // Build base query
  let query = metric + labelStr;

  // Add function with range if needed
  const needsRange = ['rate', 'irate', 'increase', 'delta', 'deriv', 'avg_over_time', 'max_over_time', 'min_over_time', 'sum_over_time', 'quantile_over_time'].includes(fn);

  if (fn) {
    const range = document.getElementById('range').value;
    const kValue = document.getElementById('kValue').value;
    const quantile = document.getElementById('quantileValue').value;

    if (needsRange) {
      query = `${query}[${range}]`;
    }

    if (fn === 'topk' || fn === 'bottomk') {
      query = `${fn}(${kValue}, ${query})`;
    } else if (fn === 'quantile_over_time') {
      query = `${fn}(${quantile}, ${query})`;
    } else if (['sum', 'avg', 'min', 'max', 'count', 'stddev'].includes(fn)) {
      if (groupBy) {
        query = `${fn} by (${groupBy}) (${fn === 'sum' || fn === 'avg' ? 'rate(' + query + ')' : query})`;
      } else {
        query = `${fn}(${query})`;
      }
    } else {
      query = `${fn}(${query})`;
    }
  }

  // Add custom operator
  if (customOp || customOperator) {
    query = query + ' ' + (customOp || customOperator);
  }

  document.getElementById('queryOutput').textContent = query;
}

function updateFunctionParams() {
  const fn = document.getElementById('function').value;
  const paramsDiv = document.getElementById('functionParams');
  const rangeDiv = document.getElementById('rangeParam');
  const kDiv = document.getElementById('kParam');
  const quantileDiv = document.getElementById('quantileParam');

  const needsRange = ['rate', 'irate', 'increase', 'delta', 'deriv', 'avg_over_time', 'max_over_time', 'min_over_time', 'sum_over_time', 'quantile_over_time'].includes(fn);
  const needsK = ['topk', 'bottomk'].includes(fn);
  const needsQuantile = fn === 'quantile_over_time';

  paramsDiv.style.display = (needsRange || needsK || needsQuantile) ? 'block' : 'none';
  rangeDiv.style.display = needsRange ? 'block' : 'none';
  kDiv.style.display = needsK ? 'block' : 'none';
  quantileDiv.style.display = needsQuantile ? 'block' : 'none';
}

function addLabel() {
  const container = document.getElementById('labels');
  const row = document.createElement('div');
  row.className = 'label-row';
  row.innerHTML = `
    <input type="text" placeholder="label" oninput="updateQuery()">
    <select onchange="updateQuery()">
      <option value="=">=</option>
      <option value="!=">!=</option>
      <option value="=~">=~</option>
      <option value="!~">!~</option>
    </select>
    <input type="text" placeholder="value" oninput="updateQuery()">
    <button onclick="removeLabel(this)">🗑️</button>
  `;
  container.appendChild(row);
}

function removeLabel(btn) {
  btn.parentElement.remove();
  updateQuery();
}

function addOperator(op) {
  customOperator = op;
  document.getElementById('customOp').value = op;
  updateQuery();
}

function copyQuery() {
  const query = document.getElementById('queryOutput').textContent;
  navigator.clipboard.writeText(query).then(() => {
    const btn = event.target;
    const orig = btn.textContent;
    btn.textContent = '✓ Copie!';
    setTimeout(() => btn.textContent = orig, 1500);
  });
}

function setQuery(q) {
  document.getElementById('queryOutput').textContent = q;
}

function loadPreset(type) {
  const presets = {
    'cpu': '100 - (avg by (instance) (irate(node_cpu_seconds_total{mode="idle"}[5m])) * 100)',
    'memory': '(1 - node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes) * 100',
    'disk': 'rate(node_disk_io_time_seconds_total[5m])',
    'http-rate': 'sum by (status_code) (rate(http_requests_total[5m]))',
    'http-errors': 'sum(rate(http_requests_total{status_code=~"5.."}[5m])) / sum(rate(http_requests_total[5m])) * 100',
    'latency': 'histogram_quantile(0.99, sum by (le) (rate(http_request_duration_seconds_bucket[5m])))',
    'saturation': 'avg by (instance) (node_load1) / count by (instance) (node_cpu_seconds_total{mode="idle"})',
    'availability': 'avg_over_time(up[24h]) * 100'
  };

  if (presets[type]) {
    setQuery(presets[type]);
  }
}

// Initialize
updateQuery();
</script>

---

## Reference PromQL

| Fonction | Description | Exemple |
|----------|-------------|---------|
| `rate()` | Taux/sec (counters) | `rate(requests[5m])` |
| `irate()` | Taux instantane | `irate(requests[5m])` |
| `increase()` | Augmentation totale | `increase(requests[1h])` |
| `sum()` | Somme | `sum by (job) (up)` |
| `avg()` | Moyenne | `avg(cpu_usage)` |
| `histogram_quantile()` | Percentile | `histogram_quantile(0.95, ...)` |
| `topk()` | Top K series | `topk(10, requests)` |
| `absent()` | Alerte si absent | `absent(up{job="x"})` |

---

!!! tip "Bonnes pratiques"
    - Utilisez `rate()` pour les counters, jamais sur des gauges
    - Choisissez un range >= 4x l'intervalle de scrape
    - Agregez avec `by()` pour reduire la cardinalite
