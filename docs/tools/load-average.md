---
tags:
  - tools
  - system
  - linux
  - monitoring
---

# Load Average Interpreter

Interpreteur de load average Linux avec diagnostic et recommandations.

<div id="load-app">
  <div class="load-container">
    <div class="load-section">
      <h3>Entrez le load average</h3>

      <div class="load-input">
        <div class="input-group">
          <label>1 min</label>
          <input type="number" id="load1" value="2.5" step="0.1" min="0" oninput="analyze()">
        </div>
        <div class="input-group">
          <label>5 min</label>
          <input type="number" id="load5" value="3.2" step="0.1" min="0" oninput="analyze()">
        </div>
        <div class="input-group">
          <label>15 min</label>
          <input type="number" id="load15" value="2.8" step="0.1" min="0" oninput="analyze()">
        </div>
      </div>

      <div class="cpu-input">
        <label>Nombre de CPUs/Cores</label>
        <input type="number" id="cpuCount" value="4" min="1" oninput="analyze()">
        <span class="hint">Obtenez avec: <code>nproc</code> ou <code>grep -c processor /proc/cpuinfo</code></span>
      </div>

      <div class="parse-section">
        <label>Ou collez la sortie de <code>uptime</code></label>
        <input type="text" id="uptimeOutput" placeholder="10:30:45 up 5 days, 3:22, 2 users, load average: 2.50, 3.20, 2.80" oninput="parseUptime()">
      </div>
    </div>

    <div class="load-section">
      <h3>Analyse</h3>

      <div class="gauge-container">
        <div class="gauge">
          <div class="gauge-fill" id="gaugeFill"></div>
          <div class="gauge-label" id="gaugeLabel">0%</div>
        </div>
        <div class="gauge-legend">
          <span class="legend-ok">0-70%: OK</span>
          <span class="legend-warn">70-100%: Attention</span>
          <span class="legend-crit">>100%: Critique</span>
        </div>
      </div>

      <div class="status-card" id="statusCard">
        <div class="status-icon" id="statusIcon">✅</div>
        <div class="status-text" id="statusText">Charge normale</div>
      </div>

      <div class="metrics-grid">
        <div class="metric-card">
          <div class="metric-label">Load/CPU (1min)</div>
          <div class="metric-value" id="loadPerCpu1">0.00</div>
        </div>
        <div class="metric-card">
          <div class="metric-label">Load/CPU (5min)</div>
          <div class="metric-value" id="loadPerCpu5">0.00</div>
        </div>
        <div class="metric-card">
          <div class="metric-label">Load/CPU (15min)</div>
          <div class="metric-value" id="loadPerCpu15">0.00</div>
        </div>
        <div class="metric-card">
          <div class="metric-label">Utilisation estimee</div>
          <div class="metric-value" id="utilization">0%</div>
        </div>
      </div>

      <div class="trend-section">
        <h4>Tendance</h4>
        <div id="trend" class="trend"></div>
      </div>
    </div>
  </div>

  <div class="recommendations-section">
    <h3>Recommandations</h3>
    <div id="recommendations" class="recommendations"></div>
  </div>

  <div class="commands-section">
    <h3>Commandes de diagnostic</h3>

    <div class="commands-grid">
      <div class="cmd-card">
        <h4>📊 Vue generale</h4>
        <pre>uptime
cat /proc/loadavg
top -bn1 | head -5</pre>
      </div>

      <div class="cmd-card">
        <h4>🔍 Processus CPU</h4>
        <pre>ps aux --sort=-%cpu | head -10
top -bn1 -o %CPU | head -15</pre>
      </div>

      <div class="cmd-card">
        <h4>💾 Processus en attente I/O</h4>
        <pre># Processes en D state (uninterruptible)
ps aux | awk '$8 ~ /D/'
iostat -x 1 5</pre>
      </div>

      <div class="cmd-card">
        <h4>🔢 Info CPU</h4>
        <pre>nproc
lscpu | grep -E "^CPU\(s\)|Thread|Core"
cat /proc/cpuinfo | grep "model name" | head -1</pre>
      </div>

      <div class="cmd-card">
        <h4>📈 Historique</h4>
        <pre># Si sar est installe
sar -q 1 10
sar -q -f /var/log/sa/sa$(date +%d)</pre>
      </div>

      <div class="cmd-card">
        <h4>🐳 Containers</h4>
        <pre>docker stats --no-stream
kubectl top pods
crictl stats</pre>
      </div>
    </div>
  </div>

  <div class="reference-section">
    <h3>Comprendre le load average</h3>

    <div class="info-grid">
      <div class="info-card">
        <h4>Qu'est-ce que le load average?</h4>
        <p>Le load average represente le nombre moyen de processus:</p>
        <ul>
          <li>En cours d'execution (R state)</li>
          <li>En attente de CPU</li>
          <li>En attente d'I/O (D state) sous Linux</li>
        </ul>
      </div>

      <div class="info-card">
        <h4>Interpretation</h4>
        <table>
          <tr><td><strong>Load = CPUs</strong></td><td>Utilisation 100%, pas de queue</td></tr>
          <tr><td><strong>Load < CPUs</strong></td><td>Ressources disponibles</td></tr>
          <tr><td><strong>Load > CPUs</strong></td><td>Processus en attente (queue)</td></tr>
        </table>
      </div>

      <div class="info-card">
        <h4>Moyennes temporelles</h4>
        <ul>
          <li><strong>1 min:</strong> Charge actuelle (spike detection)</li>
          <li><strong>5 min:</strong> Tendance recente</li>
          <li><strong>15 min:</strong> Charge moyenne long terme</li>
        </ul>
      </div>

      <div class="info-card">
        <h4>Seuils recommandes</h4>
        <ul>
          <li><strong>< 0.7 × CPUs:</strong> OK</li>
          <li><strong>0.7-1.0 × CPUs:</strong> Attention</li>
          <li><strong>> 1.0 × CPUs:</strong> Investigation requise</li>
          <li><strong>> 5.0 × CPUs:</strong> Critique</li>
        </ul>
      </div>
    </div>
  </div>
</div>

<style>
.load-container {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 20px;
}

@media (max-width: 800px) {
  .load-container {
    grid-template-columns: 1fr;
  }
}

.load-section, .recommendations-section, .commands-section, .reference-section {
  background: var(--md-code-bg-color);
  padding: 20px;
  border-radius: 8px;
  margin-bottom: 20px;
}

.load-input {
  display: flex;
  gap: 15px;
  margin-bottom: 20px;
}

.input-group {
  flex: 1;
}

.input-group label {
  display: block;
  font-size: 0.85em;
  margin-bottom: 5px;
  color: var(--md-default-fg-color--light);
}

.input-group input {
  width: 100%;
  padding: 12px;
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  background: var(--md-default-bg-color);
  color: var(--md-default-fg-color);
  font-family: monospace;
  font-size: 1.2em;
  text-align: center;
}

.cpu-input {
  margin-bottom: 20px;
}

.cpu-input label {
  display: block;
  font-size: 0.85em;
  margin-bottom: 5px;
}

.cpu-input input {
  width: 100px;
  padding: 10px;
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  background: var(--md-default-bg-color);
  color: var(--md-default-fg-color);
  font-family: monospace;
}

.cpu-input .hint {
  display: block;
  font-size: 0.8em;
  color: var(--md-default-fg-color--light);
  margin-top: 5px;
}

.parse-section {
  padding-top: 15px;
  border-top: 1px solid var(--md-default-fg-color--lightest);
}

.parse-section label {
  display: block;
  font-size: 0.85em;
  margin-bottom: 5px;
}

.parse-section input {
  width: 100%;
  padding: 10px;
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  background: var(--md-default-bg-color);
  color: var(--md-default-fg-color);
  font-family: monospace;
  font-size: 0.85em;
}

.gauge-container {
  text-align: center;
  margin-bottom: 20px;
}

.gauge {
  width: 150px;
  height: 150px;
  border-radius: 50%;
  background: conic-gradient(
    #27ae60 0deg 90deg,
    #f39c12 90deg 180deg,
    #e74c3c 180deg 360deg
  );
  margin: 0 auto 10px;
  position: relative;
  display: flex;
  align-items: center;
  justify-content: center;
}

.gauge::before {
  content: '';
  width: 110px;
  height: 110px;
  border-radius: 50%;
  background: var(--md-code-bg-color);
  position: absolute;
}

.gauge-fill {
  width: 100px;
  height: 100px;
  border-radius: 50%;
  background: var(--md-default-bg-color);
  position: absolute;
  z-index: 1;
}

.gauge-label {
  position: relative;
  z-index: 2;
  font-size: 1.5em;
  font-weight: 700;
  font-family: monospace;
}

.gauge-legend {
  display: flex;
  justify-content: center;
  gap: 15px;
  font-size: 0.75em;
}

.legend-ok { color: #27ae60; }
.legend-warn { color: #f39c12; }
.legend-crit { color: #e74c3c; }

.status-card {
  display: flex;
  align-items: center;
  gap: 15px;
  padding: 15px;
  border-radius: 6px;
  margin-bottom: 20px;
}

.status-card.ok { background: rgba(39, 174, 96, 0.1); }
.status-card.warn { background: rgba(243, 156, 18, 0.1); }
.status-card.crit { background: rgba(231, 76, 60, 0.1); }

.status-icon { font-size: 2em; }
.status-text { font-weight: 500; }

.metrics-grid {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 10px;
  margin-bottom: 20px;
}

.metric-card {
  background: var(--md-default-bg-color);
  padding: 12px;
  border-radius: 6px;
  text-align: center;
}

.metric-label {
  font-size: 0.75em;
  color: var(--md-default-fg-color--light);
  margin-bottom: 5px;
}

.metric-value {
  font-size: 1.2em;
  font-weight: 600;
  font-family: monospace;
}

.trend-section h4 {
  margin: 0 0 10px 0;
}

.trend {
  padding: 15px;
  background: var(--md-default-bg-color);
  border-radius: 6px;
  font-size: 0.9em;
}

.recommendations {
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.rec-item {
  padding: 12px;
  border-radius: 6px;
  border-left: 4px solid;
}

.rec-item.info { background: rgba(52, 152, 219, 0.1); border-left-color: #3498db; }
.rec-item.warn { background: rgba(243, 156, 18, 0.1); border-left-color: #f39c12; }
.rec-item.error { background: rgba(231, 76, 60, 0.1); border-left-color: #e74c3c; }

.commands-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 15px;
}

.cmd-card {
  background: var(--md-default-bg-color);
  padding: 15px;
  border-radius: 6px;
}

.cmd-card h4 {
  margin: 0 0 10px 0;
}

.cmd-card pre {
  margin: 0;
  padding: 10px;
  background: #1e1e1e;
  color: #d4d4d4;
  border-radius: 4px;
  font-size: 0.8em;
  overflow-x: auto;
}

.info-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 15px;
}

.info-card {
  background: var(--md-default-bg-color);
  padding: 15px;
  border-radius: 6px;
}

.info-card h4 {
  margin: 0 0 10px 0;
}

.info-card ul, .info-card p {
  margin: 0;
  font-size: 0.9em;
}

.info-card ul {
  padding-left: 20px;
}

.info-card table {
  width: 100%;
  font-size: 0.85em;
}

.info-card td {
  padding: 5px;
}
</style>

<script>
function analyze() {
  const load1 = parseFloat(document.getElementById('load1').value) || 0;
  const load5 = parseFloat(document.getElementById('load5').value) || 0;
  const load15 = parseFloat(document.getElementById('load15').value) || 0;
  const cpus = parseInt(document.getElementById('cpuCount').value) || 1;

  // Calculate load per CPU
  const lpc1 = load1 / cpus;
  const lpc5 = load5 / cpus;
  const lpc15 = load15 / cpus;

  document.getElementById('loadPerCpu1').textContent = lpc1.toFixed(2);
  document.getElementById('loadPerCpu5').textContent = lpc5.toFixed(2);
  document.getElementById('loadPerCpu15').textContent = lpc15.toFixed(2);

  // Utilization (capped at 100% for display)
  const utilization = Math.min(lpc5 * 100, 999);
  document.getElementById('utilization').textContent = Math.round(utilization) + '%';

  // Gauge
  document.getElementById('gaugeLabel').textContent = Math.round(Math.min(utilization, 200)) + '%';

  // Status
  const statusCard = document.getElementById('statusCard');
  const statusIcon = document.getElementById('statusIcon');
  const statusText = document.getElementById('statusText');

  if (lpc5 < 0.7) {
    statusCard.className = 'status-card ok';
    statusIcon.textContent = '✅';
    statusText.textContent = 'Charge normale - Ressources disponibles';
  } else if (lpc5 < 1.0) {
    statusCard.className = 'status-card warn';
    statusIcon.textContent = '⚠️';
    statusText.textContent = 'Charge elevee - Surveillance recommandee';
  } else if (lpc5 < 5.0) {
    statusCard.className = 'status-card crit';
    statusIcon.textContent = '🔴';
    statusText.textContent = 'Charge critique - Investigation requise';
  } else {
    statusCard.className = 'status-card crit';
    statusIcon.textContent = '🚨';
    statusText.textContent = 'Surcharge severe - Action immediate';
  }

  // Trend analysis
  let trendText = '';
  if (load1 > load5 && load5 > load15) {
    trendText = '📈 <strong>Tendance haussiere</strong> - La charge augmente, surveillez l\'evolution';
  } else if (load1 < load5 && load5 < load15) {
    trendText = '📉 <strong>Tendance baissiere</strong> - La charge diminue, situation en amelioration';
  } else if (load1 > load15 * 1.5) {
    trendText = '⚡ <strong>Pic de charge</strong> - Spike recent detecte, probablement temporaire';
  } else {
    trendText = '➡️ <strong>Charge stable</strong> - Les valeurs sont relativement constantes';
  }
  document.getElementById('trend').innerHTML = trendText;

  // Recommendations
  const recs = [];

  if (lpc5 >= 1.0) {
    recs.push({ type: 'error', text: 'La charge depasse le nombre de CPUs. Des processus sont en file d\'attente.' });
  }

  if (load1 > load5 * 1.5) {
    recs.push({ type: 'warn', text: 'Spike recent detecte. Verifiez les processus actifs avec `top` ou `htop`.' });
  }

  if (lpc5 > 0.7 && lpc5 < 1.0) {
    recs.push({ type: 'warn', text: 'Approche de la saturation. Considerez l\'ajout de ressources ou l\'optimisation.' });
  }

  if (lpc5 >= 5.0) {
    recs.push({ type: 'error', text: 'Surcharge severe! Verifiez les processus bloques en I/O (D state) avec `ps aux | awk \'$8 ~ /D/\'`' });
  }

  if (recs.length === 0) {
    recs.push({ type: 'info', text: 'Le systeme fonctionne dans les parametres normaux.' });
  }

  // Check for I/O wait hint
  if (lpc5 > 1.0) {
    recs.push({ type: 'info', text: 'Verifiez si la charge est due au CPU ou a l\'I/O avec `iostat -x 1 5` et `vmstat 1 5`' });
  }

  document.getElementById('recommendations').innerHTML = recs.map(r =>
    `<div class="rec-item ${r.type}">${r.text}</div>`
  ).join('');
}

function parseUptime() {
  const output = document.getElementById('uptimeOutput').value;
  const match = output.match(/load average[s]?:\s*([\d.]+)[,\s]+([\d.]+)[,\s]+([\d.]+)/i);

  if (match) {
    document.getElementById('load1').value = parseFloat(match[1]);
    document.getElementById('load5').value = parseFloat(match[2]);
    document.getElementById('load15').value = parseFloat(match[3]);
    analyze();
  }
}

// Initialize
analyze();
</script>

---

## Resume rapide

| Load/CPU | Status | Action |
|----------|--------|--------|
| < 0.7 | ✅ OK | Aucune |
| 0.7 - 1.0 | ⚠️ Attention | Surveiller |
| 1.0 - 5.0 | 🔴 Critique | Investiguer |
| > 5.0 | 🚨 Severe | Action immediate |
