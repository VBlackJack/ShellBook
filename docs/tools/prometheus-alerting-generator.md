---
tags:
  - tools
  - monitoring
  - prometheus
  - alerting
---

# Prometheus Alerting Rules Generator

Generateur de regles d'alerte Prometheus.

<div id="prom-app">
  <div class="prom-container">
    <div class="prom-section">
      <h3>Configuration alerte</h3>

      <div class="form-group">
        <label>Nom de l'alerte</label>
        <input type="text" id="alertName" value="HighCpuUsage" oninput="generate()">
      </div>

      <div class="form-group">
        <label>Expression PromQL</label>
        <textarea id="expr" rows="3" oninput="generate()">100 - (avg by(instance) (rate(node_cpu_seconds_total{mode="idle"}[5m])) * 100) > 80</textarea>
      </div>

      <div class="form-group">
        <label>Duree avant declenchement (for)</label>
        <div class="time-input">
          <input type="number" id="forDuration" value="5" min="1" oninput="generate()">
          <select id="forUnit" onchange="generate()">
            <option value="s">secondes</option>
            <option value="m" selected>minutes</option>
            <option value="h">heures</option>
          </select>
        </div>
        <span class="hint">Temps pendant lequel la condition doit etre vraie</span>
      </div>

      <div class="form-group">
        <label>Severite</label>
        <select id="severity" onchange="generate()">
          <option value="info">info</option>
          <option value="warning" selected>warning</option>
          <option value="critical">critical</option>
          <option value="page">page (PagerDuty)</option>
        </select>
      </div>

      <div class="form-group">
        <label>Groupe d'alerte</label>
        <input type="text" id="alertGroup" value="node-alerts" oninput="generate()">
      </div>

      <h4>Labels</h4>

      <div class="form-group">
        <label>Team</label>
        <input type="text" id="team" value="infrastructure" oninput="generate()">
      </div>

      <div class="form-group">
        <label>Service</label>
        <input type="text" id="service" value="compute" oninput="generate()">
      </div>

      <h4>Annotations</h4>

      <div class="form-group">
        <label>Summary</label>
        <input type="text" id="summary" value="High CPU usage detected on {{ $labels.instance }}" oninput="generate()">
      </div>

      <div class="form-group">
        <label>Description</label>
        <textarea id="description" rows="2" oninput="generate()">CPU usage is above 80% (current value: {{ $value | printf "%.1f" }}%) on instance {{ $labels.instance }}</textarea>
      </div>

      <div class="form-group">
        <label>Runbook URL (optionnel)</label>
        <input type="text" id="runbook" value="" placeholder="https://wiki.example.com/runbooks/high-cpu" oninput="generate()">
      </div>
    </div>

    <div class="prom-section">
      <h3>Regle generee</h3>
      <pre id="configOutput"># alert rules</pre>
      <button onclick="copyConfig()">Copier</button>
    </div>
  </div>

  <div class="presets-section">
    <h3>Presets par categorie</h3>
    <div class="presets-grid">
      <div class="preset-card" onclick="loadPreset('cpu')">
        <h4>High CPU</h4>
        <p>CPU > 80%</p>
      </div>
      <div class="preset-card" onclick="loadPreset('memory')">
        <h4>High Memory</h4>
        <p>RAM > 90%</p>
      </div>
      <div class="preset-card" onclick="loadPreset('disk')">
        <h4>Disk Full</h4>
        <p>Disk > 85%</p>
      </div>
      <div class="preset-card" onclick="loadPreset('down')">
        <h4>Instance Down</h4>
        <p>Target unreachable</p>
      </div>
      <div class="preset-card" onclick="loadPreset('http5xx')">
        <h4>HTTP 5xx</h4>
        <p>Error rate > 5%</p>
      </div>
      <div class="preset-card" onclick="loadPreset('latency')">
        <h4>High Latency</h4>
        <p>P99 > 500ms</p>
      </div>
      <div class="preset-card" onclick="loadPreset('pod')">
        <h4>K8s Pod</h4>
        <p>Pod not ready</p>
      </div>
      <div class="preset-card" onclick="loadPreset('cert')">
        <h4>Cert Expiry</h4>
        <p>SSL < 30 days</p>
      </div>
    </div>
  </div>

  <div class="reference-section">
    <h3>Variables disponibles</h3>
    <table class="ref-table">
      <tr><td><code>{{ $labels }}</code></td><td>Tous les labels de la serie</td></tr>
      <tr><td><code>{{ $labels.instance }}</code></td><td>Label specifique</td></tr>
      <tr><td><code>{{ $value }}</code></td><td>Valeur courante</td></tr>
      <tr><td><code>{{ $value | printf "%.2f" }}</code></td><td>Valeur formatee</td></tr>
      <tr><td><code>{{ $externalLabels }}</code></td><td>Labels externes Prometheus</td></tr>
    </table>
  </div>
</div>

<style>
.prom-container {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 20px;
}

@media (max-width: 900px) {
  .prom-container { grid-template-columns: 1fr; }
}

.prom-section, .presets-section, .reference-section {
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

.form-group h4 {
  margin: 20px 0 10px 0;
  padding-top: 15px;
  border-top: 1px solid var(--md-default-fg-color--lightest);
}

.form-group select,
.form-group input[type="text"],
.form-group input[type="number"],
.form-group textarea {
  width: 100%;
  padding: 10px;
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  background: var(--md-default-bg-color);
  color: var(--md-default-fg-color);
  font-family: monospace;
}

.time-input {
  display: flex;
  gap: 10px;
}

.time-input input { flex: 1; }
.time-input select { width: 120px; }

.hint {
  font-size: 0.8em;
  color: var(--md-default-fg-color--light);
  display: block;
  margin-top: 4px;
}

#configOutput {
  background: #1e1e1e;
  color: #d4d4d4;
  padding: 15px;
  border-radius: 4px;
  font-size: 0.85em;
  overflow-x: auto;
  white-space: pre-wrap;
  min-height: 300px;
}

.prom-section button {
  margin-top: 10px;
  padding: 8px 16px;
  background: var(--md-primary-fg-color);
  color: white;
  border: none;
  border-radius: 4px;
  cursor: pointer;
}

.presets-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(110px, 1fr));
  gap: 12px;
}

.preset-card {
  background: var(--md-default-bg-color);
  padding: 15px;
  border-radius: 6px;
  cursor: pointer;
  transition: transform 0.2s;
}

.preset-card:hover { transform: scale(1.02); }
.preset-card h4 { margin: 0 0 5px 0; font-size: 0.95em; }
.preset-card p { margin: 0; font-size: 0.8em; color: var(--md-default-fg-color--light); }

.ref-table {
  width: 100%;
  font-size: 0.85em;
  border-collapse: collapse;
}

.ref-table td {
  padding: 8px;
  border-bottom: 1px solid var(--md-default-fg-color--lightest);
}

.ref-table code {
  background: var(--md-default-bg-color);
  padding: 2px 6px;
  border-radius: 3px;
}
</style>

<script>
function generate() {
  const alertName = document.getElementById('alertName').value;
  const expr = document.getElementById('expr').value;
  const forDuration = document.getElementById('forDuration').value;
  const forUnit = document.getElementById('forUnit').value;
  const severity = document.getElementById('severity').value;
  const alertGroup = document.getElementById('alertGroup').value;
  const team = document.getElementById('team').value;
  const service = document.getElementById('service').value;
  const summary = document.getElementById('summary').value;
  const description = document.getElementById('description').value;
  const runbook = document.getElementById('runbook').value;

  let config = `# Prometheus Alerting Rules
# File: /etc/prometheus/rules/${alertGroup}.yml

groups:
  - name: ${alertGroup}
    rules:
      - alert: ${alertName}
        expr: ${expr}
        for: ${forDuration}${forUnit}
        labels:
          severity: ${severity}
          team: ${team}
          service: ${service}
        annotations:
          summary: "${summary}"
          description: "${description}"`;

  if (runbook) {
    config += `
          runbook_url: "${runbook}"`;
  }

  config += `

# To test this alert:
# promtool check rules ${alertGroup}.yml

# Example alertmanager.yml receiver:
# receivers:
#   - name: '${team}-${severity}'
#     slack_configs:
#       - channel: '#alerts-${team}'
#         send_resolved: true
`;

  document.getElementById('configOutput').textContent = config;
}

function loadPreset(name) {
  const presets = {
    cpu: {
      name: 'HighCpuUsage',
      expr: '100 - (avg by(instance) (rate(node_cpu_seconds_total{mode="idle"}[5m])) * 100) > 80',
      for: 5,
      unit: 'm',
      severity: 'warning',
      summary: 'High CPU usage on {{ $labels.instance }}',
      description: 'CPU usage is {{ $value | printf "%.1f" }}% on {{ $labels.instance }}'
    },
    memory: {
      name: 'HighMemoryUsage',
      expr: '(1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)) * 100 > 90',
      for: 5,
      unit: 'm',
      severity: 'critical',
      summary: 'High memory usage on {{ $labels.instance }}',
      description: 'Memory usage is {{ $value | printf "%.1f" }}% on {{ $labels.instance }}'
    },
    disk: {
      name: 'DiskSpaceLow',
      expr: '(1 - (node_filesystem_avail_bytes{fstype!~"tmpfs|overlay"} / node_filesystem_size_bytes)) * 100 > 85',
      for: 15,
      unit: 'm',
      severity: 'warning',
      summary: 'Low disk space on {{ $labels.instance }}',
      description: 'Disk {{ $labels.mountpoint }} is {{ $value | printf "%.1f" }}% full on {{ $labels.instance }}'
    },
    down: {
      name: 'InstanceDown',
      expr: 'up == 0',
      for: 2,
      unit: 'm',
      severity: 'critical',
      summary: 'Instance {{ $labels.instance }} is down',
      description: 'Instance {{ $labels.instance }} (job {{ $labels.job }}) has been down for more than 2 minutes'
    },
    http5xx: {
      name: 'HighHttp5xxRate',
      expr: 'sum(rate(http_requests_total{status=~"5.."}[5m])) by (service) / sum(rate(http_requests_total[5m])) by (service) * 100 > 5',
      for: 5,
      unit: 'm',
      severity: 'critical',
      summary: 'High HTTP 5xx rate for {{ $labels.service }}',
      description: '5xx error rate is {{ $value | printf "%.2f" }}% for service {{ $labels.service }}'
    },
    latency: {
      name: 'HighLatency',
      expr: 'histogram_quantile(0.99, sum(rate(http_request_duration_seconds_bucket[5m])) by (le, service)) > 0.5',
      for: 5,
      unit: 'm',
      severity: 'warning',
      summary: 'High P99 latency for {{ $labels.service }}',
      description: 'P99 latency is {{ $value | printf "%.3f" }}s for service {{ $labels.service }}'
    },
    pod: {
      name: 'KubePodNotReady',
      expr: 'kube_pod_status_ready{condition="true"} == 0',
      for: 5,
      unit: 'm',
      severity: 'warning',
      summary: 'Pod {{ $labels.namespace }}/{{ $labels.pod }} not ready',
      description: 'Pod {{ $labels.pod }} in namespace {{ $labels.namespace }} has been not ready for 5 minutes'
    },
    cert: {
      name: 'SSLCertExpiringSoon',
      expr: 'probe_ssl_earliest_cert_expiry - time() < 86400 * 30',
      for: 1,
      unit: 'h',
      severity: 'warning',
      summary: 'SSL certificate expiring soon for {{ $labels.instance }}',
      description: 'SSL certificate for {{ $labels.instance }} expires in {{ $value | humanizeDuration }}'
    }
  };

  const p = presets[name];
  if (p) {
    document.getElementById('alertName').value = p.name;
    document.getElementById('expr').value = p.expr;
    document.getElementById('forDuration').value = p.for;
    document.getElementById('forUnit').value = p.unit;
    document.getElementById('severity').value = p.severity;
    document.getElementById('summary').value = p.summary;
    document.getElementById('description').value = p.description;
    generate();
  }
}

function copyConfig() {
  const config = document.getElementById('configOutput').textContent;
  navigator.clipboard.writeText(config).then(() => {
    event.target.textContent = 'Copie!';
    setTimeout(() => event.target.textContent = 'Copier', 1500);
  });
}

generate();
</script>

---

## Commandes utiles

```bash
# Valider les regles
promtool check rules /etc/prometheus/rules/*.yml

# Tester une expression
curl -g 'http://localhost:9090/api/v1/query?query=up==0'

# Voir les alertes actives
curl http://localhost:9090/api/v1/alerts

# Recharger Prometheus
curl -X POST http://localhost:9090/-/reload
```

---

## Voir aussi

- [PromQL Builder](promql-builder.md)
- [Telegraf Config Generator](telegraf-generator.md)
