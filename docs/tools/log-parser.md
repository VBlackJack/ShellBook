---
tags:
  - tools
  - logs
  - parser
  - devops
---

# Log Parser

Analyseur de logs avec extraction de patterns et statistiques.

<div id="log-app">
  <div class="log-container">
    <div class="log-section">
      <h3>Logs</h3>
      <textarea id="logInput" placeholder="Collez vos logs ici..." oninput="parseLogInput()">192.168.1.1 - - [10/Oct/2024:13:55:36 +0200] "GET /api/users HTTP/1.1" 200 1234
192.168.1.2 - - [10/Oct/2024:13:55:37 +0200] "POST /api/login HTTP/1.1" 401 89
192.168.1.1 - - [10/Oct/2024:13:55:38 +0200] "GET /api/products HTTP/1.1" 200 5678
10.0.0.5 - - [10/Oct/2024:13:55:39 +0200] "GET /api/users/123 HTTP/1.1" 404 45
192.168.1.3 - - [10/Oct/2024:13:55:40 +0200] "DELETE /api/users/456 HTTP/1.1" 500 123
192.168.1.1 - - [10/Oct/2024:13:55:41 +0200] "GET /static/app.js HTTP/1.1" 200 89012</textarea>

      <div class="format-select">
        <label>Format:</label>
        <select id="logFormat" onchange="parseLogInput()">
          <option value="apache">Apache/Nginx Combined</option>
          <option value="json">JSON (un objet par ligne)</option>
          <option value="syslog">Syslog</option>
          <option value="custom">Pattern personnalise</option>
        </select>
      </div>

      <div id="customPattern" class="custom-pattern" style="display:none;">
        <label>Pattern regex:</label>
        <input type="text" id="patternInput" placeholder="^(\S+) - - \[([^\]]+)\] &quot;(\w+) ([^&quot;]+)&quot; (\d+) (\d+)">
        <label>Groupes (separes par virgule):</label>
        <input type="text" id="patternGroups" placeholder="ip,timestamp,method,path,status,size">
      </div>
    </div>

    <div class="log-section">
      <h3>Statistiques</h3>

      <div class="stats-grid">
        <div class="stat-card">
          <div class="stat-value" id="totalLines">0</div>
          <div class="stat-label">Lignes</div>
        </div>
        <div class="stat-card">
          <div class="stat-value" id="uniqueIps">0</div>
          <div class="stat-label">IPs uniques</div>
        </div>
        <div class="stat-card error">
          <div class="stat-value" id="errorCount">0</div>
          <div class="stat-label">Erreurs (4xx/5xx)</div>
        </div>
        <div class="stat-card success">
          <div class="stat-value" id="successCount">0</div>
          <div class="stat-label">Succes (2xx)</div>
        </div>
      </div>
    </div>
  </div>

  <div class="analysis-section">
    <div class="analysis-tabs">
      <button class="tab active" onclick="showTab('status')">📊 Status Codes</button>
      <button class="tab" onclick="showTab('ips')">🌐 IPs</button>
      <button class="tab" onclick="showTab('paths')">📁 Paths</button>
      <button class="tab" onclick="showTab('methods')">🔧 Methods</button>
      <button class="tab" onclick="showTab('timeline')">⏱️ Timeline</button>
    </div>

    <div id="tab-status" class="tab-content active">
      <div id="statusChart" class="chart"></div>
    </div>

    <div id="tab-ips" class="tab-content">
      <div id="ipsChart" class="chart"></div>
    </div>

    <div id="tab-paths" class="tab-content">
      <div id="pathsChart" class="chart"></div>
    </div>

    <div id="tab-methods" class="tab-content">
      <div id="methodsChart" class="chart"></div>
    </div>

    <div id="tab-timeline" class="tab-content">
      <div id="timelineChart" class="chart"></div>
    </div>
  </div>

  <div class="filter-section">
    <h3>Filtres</h3>

    <div class="filters">
      <div class="filter-group">
        <label>Status Code</label>
        <select id="filterStatus" onchange="applyFilters()">
          <option value="">Tous</option>
          <option value="2xx">2xx (Success)</option>
          <option value="3xx">3xx (Redirect)</option>
          <option value="4xx">4xx (Client Error)</option>
          <option value="5xx">5xx (Server Error)</option>
        </select>
      </div>

      <div class="filter-group">
        <label>IP contient</label>
        <input type="text" id="filterIp" placeholder="192.168" oninput="applyFilters()">
      </div>

      <div class="filter-group">
        <label>Path contient</label>
        <input type="text" id="filterPath" placeholder="/api" oninput="applyFilters()">
      </div>

      <div class="filter-group">
        <label>Method</label>
        <select id="filterMethod" onchange="applyFilters()">
          <option value="">Tous</option>
          <option value="GET">GET</option>
          <option value="POST">POST</option>
          <option value="PUT">PUT</option>
          <option value="DELETE">DELETE</option>
          <option value="PATCH">PATCH</option>
        </select>
      </div>
    </div>
  </div>

  <div class="results-section">
    <h3>Logs filtres (<span id="filteredCount">0</span>)</h3>
    <div class="results-actions">
      <button onclick="copyFiltered()">📋 Copier</button>
      <button onclick="exportCSV()">📥 Export CSV</button>
    </div>
    <div id="filteredResults" class="filtered-results"></div>
  </div>
</div>

<style>
.log-container {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 20px;
}

@media (max-width: 800px) {
  .log-container {
    grid-template-columns: 1fr;
  }
}

.log-section, .analysis-section, .filter-section, .results-section {
  background: var(--md-code-bg-color);
  padding: 20px;
  border-radius: 8px;
  margin-bottom: 20px;
}

.log-section textarea {
  width: 100%;
  min-height: 200px;
  padding: 12px;
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  background: var(--md-default-bg-color);
  color: var(--md-default-fg-color);
  font-family: monospace;
  font-size: 0.85em;
  margin-bottom: 10px;
}

.format-select {
  display: flex;
  align-items: center;
  gap: 10px;
}

.format-select select {
  padding: 8px;
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  background: var(--md-default-bg-color);
  color: var(--md-default-fg-color);
}

.custom-pattern {
  margin-top: 15px;
  padding: 15px;
  background: var(--md-default-bg-color);
  border-radius: 6px;
}

.custom-pattern label {
  display: block;
  font-size: 0.85em;
  margin-bottom: 5px;
  color: var(--md-default-fg-color--light);
}

.custom-pattern input {
  width: 100%;
  padding: 8px;
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  background: var(--md-code-bg-color);
  color: var(--md-default-fg-color);
  font-family: monospace;
  margin-bottom: 10px;
}

.stats-grid {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 12px;
}

.stat-card {
  background: var(--md-default-bg-color);
  padding: 15px;
  border-radius: 6px;
  text-align: center;
}

.stat-card.error { border-left: 4px solid #e74c3c; }
.stat-card.success { border-left: 4px solid #27ae60; }

.stat-value {
  font-size: 2em;
  font-weight: 700;
  font-family: monospace;
}

.stat-label {
  font-size: 0.8em;
  color: var(--md-default-fg-color--light);
}

.analysis-tabs {
  display: flex;
  flex-wrap: wrap;
  gap: 5px;
  margin-bottom: 15px;
}

.analysis-tabs .tab {
  padding: 8px 15px;
  background: var(--md-default-bg-color);
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  cursor: pointer;
}

.analysis-tabs .tab.active {
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

.chart {
  background: var(--md-default-bg-color);
  padding: 15px;
  border-radius: 6px;
  min-height: 200px;
}

.chart-bar {
  display: flex;
  align-items: center;
  margin-bottom: 10px;
}

.chart-label {
  width: 150px;
  font-size: 0.85em;
  font-family: monospace;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.chart-bar-container {
  flex: 1;
  height: 24px;
  background: var(--md-code-bg-color);
  border-radius: 4px;
  overflow: hidden;
  margin: 0 10px;
}

.chart-bar-fill {
  height: 100%;
  background: var(--md-primary-fg-color);
  border-radius: 4px;
  transition: width 0.3s;
}

.chart-bar-fill.error { background: #e74c3c; }
.chart-bar-fill.warning { background: #f39c12; }
.chart-bar-fill.success { background: #27ae60; }

.chart-count {
  width: 50px;
  text-align: right;
  font-family: monospace;
  font-size: 0.85em;
}

.filters {
  display: flex;
  flex-wrap: wrap;
  gap: 15px;
}

.filter-group {
  flex: 1;
  min-width: 150px;
}

.filter-group label {
  display: block;
  font-size: 0.85em;
  margin-bottom: 5px;
  color: var(--md-default-fg-color--light);
}

.filter-group select,
.filter-group input {
  width: 100%;
  padding: 8px;
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  background: var(--md-default-bg-color);
  color: var(--md-default-fg-color);
}

.results-actions {
  display: flex;
  gap: 10px;
  margin-bottom: 10px;
}

.results-actions button {
  padding: 6px 12px;
  background: var(--md-default-bg-color);
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  cursor: pointer;
}

.filtered-results {
  max-height: 300px;
  overflow-y: auto;
  overflow-x: hidden;
  font-family: monospace;
  font-size: 0.8em;
}

.log-line {
  padding: 5px 10px;
  border-bottom: 1px solid var(--md-default-fg-color--lightest);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.log-line.error { background: rgba(231, 76, 60, 0.1); }
.log-line.warning { background: rgba(243, 156, 18, 0.1); }
</style>

<script>
let parsedLogs = [];
let filteredLogs = [];

const patterns = {
  apache: /^(\S+) - - \[([^\]]+)\] "(\w+) ([^"]+)" (\d+) (\d+)/,
  syslog: /^(\w+\s+\d+\s+[\d:]+)\s+(\S+)\s+(\S+):\s+(.+)$/
};

function parseLogInput() {
  const input = document.getElementById('logInput').value;
  const format = document.getElementById('logFormat').value;

  // Show/hide custom pattern
  document.getElementById('customPattern').style.display = format === 'custom' ? 'block' : 'none';

  const lines = input.trim().split('\n').filter(l => l.trim());
  parsedLogs = [];

  lines.forEach(line => {
    let parsed = null;

    if (format === 'apache') {
      const match = line.match(patterns.apache);
      if (match) {
        parsed = {
          ip: match[1],
          timestamp: match[2],
          method: match[3],
          path: match[4].split(' ')[0],
          status: parseInt(match[5]),
          size: parseInt(match[6]),
          raw: line
        };
      }
    } else if (format === 'json') {
      try {
        const obj = JSON.parse(line);
        parsed = {
          ip: obj.ip || obj.remote_addr || obj.client_ip || '-',
          timestamp: obj.timestamp || obj.time || obj['@timestamp'] || '-',
          method: obj.method || obj.request_method || '-',
          path: obj.path || obj.uri || obj.request_uri || '-',
          status: parseInt(obj.status || obj.status_code || 0),
          size: parseInt(obj.size || obj.bytes || obj.body_bytes_sent || 0),
          raw: line
        };
      } catch (e) {}
    } else if (format === 'syslog') {
      const match = line.match(patterns.syslog);
      if (match) {
        parsed = {
          ip: '-',
          timestamp: match[1],
          method: '-',
          path: match[3],
          status: 0,
          size: 0,
          message: match[4],
          raw: line
        };
      }
    }

    if (parsed) {
      parsedLogs.push(parsed);
    }
  });

  updateStats();
  applyFilters();
  updateCharts();
}

function updateStats() {
  const ips = new Set(parsedLogs.map(l => l.ip));
  const errors = parsedLogs.filter(l => l.status >= 400).length;
  const success = parsedLogs.filter(l => l.status >= 200 && l.status < 300).length;

  document.getElementById('totalLines').textContent = parsedLogs.length;
  document.getElementById('uniqueIps').textContent = ips.size;
  document.getElementById('errorCount').textContent = errors;
  document.getElementById('successCount').textContent = success;
}

function applyFilters() {
  const statusFilter = document.getElementById('filterStatus').value;
  const ipFilter = document.getElementById('filterIp').value.toLowerCase();
  const pathFilter = document.getElementById('filterPath').value.toLowerCase();
  const methodFilter = document.getElementById('filterMethod').value;

  filteredLogs = parsedLogs.filter(log => {
    if (statusFilter) {
      const statusRange = statusFilter.charAt(0);
      if (Math.floor(log.status / 100) !== parseInt(statusRange)) return false;
    }
    if (ipFilter && !log.ip.toLowerCase().includes(ipFilter)) return false;
    if (pathFilter && !log.path.toLowerCase().includes(pathFilter)) return false;
    if (methodFilter && log.method !== methodFilter) return false;
    return true;
  });

  document.getElementById('filteredCount').textContent = filteredLogs.length;
  renderFilteredResults();
}

function renderFilteredResults() {
  const container = document.getElementById('filteredResults');
  container.innerHTML = filteredLogs.slice(0, 100).map(log => {
    let cls = '';
    if (log.status >= 500) cls = 'error';
    else if (log.status >= 400) cls = 'warning';
    return `<div class="log-line ${cls}">${escapeHtml(log.raw)}</div>`;
  }).join('');

  if (filteredLogs.length > 100) {
    container.innerHTML += `<div class="log-line">... et ${filteredLogs.length - 100} de plus</div>`;
  }
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

function updateCharts() {
  renderStatusChart();
  renderIpsChart();
  renderPathsChart();
  renderMethodsChart();
  renderTimelineChart();
}

function renderBarChart(containerId, data, colorFn) {
  const container = document.getElementById(containerId);
  const max = Math.max(...data.map(d => d.count));

  container.innerHTML = data.slice(0, 10).map(d => {
    const pct = (d.count / max) * 100;
    const colorClass = colorFn ? colorFn(d.label) : '';
    return `
      <div class="chart-bar">
        <div class="chart-label" title="${escapeHtml(d.label)}">${escapeHtml(d.label)}</div>
        <div class="chart-bar-container">
          <div class="chart-bar-fill ${colorClass}" style="width: ${pct}%"></div>
        </div>
        <div class="chart-count">${d.count}</div>
      </div>
    `;
  }).join('');
}

function renderStatusChart() {
  const counts = {};
  parsedLogs.forEach(l => {
    counts[l.status] = (counts[l.status] || 0) + 1;
  });
  const data = Object.entries(counts).map(([label, count]) => ({ label, count }))
    .sort((a, b) => b.count - a.count);

  renderBarChart('statusChart', data, label => {
    const status = parseInt(label);
    if (status >= 500) return 'error';
    if (status >= 400) return 'warning';
    if (status >= 200 && status < 300) return 'success';
    return '';
  });
}

function renderIpsChart() {
  const counts = {};
  parsedLogs.forEach(l => {
    counts[l.ip] = (counts[l.ip] || 0) + 1;
  });
  const data = Object.entries(counts).map(([label, count]) => ({ label, count }))
    .sort((a, b) => b.count - a.count);
  renderBarChart('ipsChart', data);
}

function renderPathsChart() {
  const counts = {};
  parsedLogs.forEach(l => {
    const path = l.path.split('?')[0]; // Remove query string
    counts[path] = (counts[path] || 0) + 1;
  });
  const data = Object.entries(counts).map(([label, count]) => ({ label, count }))
    .sort((a, b) => b.count - a.count);
  renderBarChart('pathsChart', data);
}

function renderMethodsChart() {
  const counts = {};
  parsedLogs.forEach(l => {
    counts[l.method] = (counts[l.method] || 0) + 1;
  });
  const data = Object.entries(counts).map(([label, count]) => ({ label, count }))
    .sort((a, b) => b.count - a.count);
  renderBarChart('methodsChart', data);
}

function renderTimelineChart() {
  document.getElementById('timelineChart').innerHTML =
    '<p style="color: var(--md-default-fg-color--light)">Timeline requires timestamp parsing (non implemente dans cette version)</p>';
}

function showTab(tab) {
  document.querySelectorAll('.analysis-tabs .tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
  event.target.classList.add('active');
  document.getElementById(`tab-${tab}`).classList.add('active');
}

function copyFiltered() {
  const text = filteredLogs.map(l => l.raw).join('\n');
  navigator.clipboard.writeText(text);
}

function exportCSV() {
  const headers = ['ip', 'timestamp', 'method', 'path', 'status', 'size'];
  let csv = headers.join(',') + '\n';
  filteredLogs.forEach(l => {
    csv += headers.map(h => `"${String(l[h] || '').replace(/"/g, '""')}"`).join(',') + '\n';
  });

  const blob = new Blob([csv], { type: 'text/csv' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'logs_export.csv';
  a.click();
  URL.revokeObjectURL(url);
}

// Initialize
parseLogInput();
</script>

---

## Formats supportes

| Format | Pattern |
|--------|---------|
| Apache Combined | `%h %l %u %t "%r" %>s %b` |
| JSON | Un objet JSON par ligne |
| Syslog | `MMM DD HH:MM:SS host service: message` |
