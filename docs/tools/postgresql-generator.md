---
tags:
  - tools
  - database
  - postgresql
  - tuning
---

# PostgreSQL Config Generator

Generateur de configuration postgresql.conf optimisee selon vos ressources.

<div id="pgsql-app">
  <div class="pgsql-container">
    <div class="pgsql-section">
      <h3>Ressources systeme</h3>

      <div class="form-group">
        <label>RAM totale du serveur</label>
        <div class="input-with-unit">
          <input type="number" id="totalRam" value="16" min="1" oninput="generate()">
          <select id="ramUnit" onchange="generate()">
            <option value="GB" selected>GB</option>
            <option value="MB">MB</option>
          </select>
        </div>
      </div>

      <div class="form-group">
        <label>Nombre de CPUs</label>
        <input type="number" id="cpuCount" value="4" min="1" max="256" oninput="generate()">
      </div>

      <div class="form-group">
        <label>Type de stockage</label>
        <select id="storageType" onchange="generate()">
          <option value="ssd" selected>SSD / NVMe</option>
          <option value="hdd">HDD</option>
          <option value="san">SAN</option>
        </select>
      </div>

      <div class="form-group">
        <label>Type d'utilisation</label>
        <select id="workloadType" onchange="generate()">
          <option value="web">Web Application (OLTP)</option>
          <option value="olap">Data Warehouse (OLAP)</option>
          <option value="mixed" selected>Mixed</option>
          <option value="desktop">Desktop/Dev</option>
        </select>
      </div>

      <div class="form-group">
        <label>Connexions max attendues</label>
        <input type="number" id="maxConnections" value="100" min="10" max="10000" oninput="generate()">
      </div>

      <div class="form-group">
        <label>Version PostgreSQL</label>
        <select id="pgVersion" onchange="generate()">
          <option value="16">PostgreSQL 16</option>
          <option value="15" selected>PostgreSQL 15</option>
          <option value="14">PostgreSQL 14</option>
          <option value="13">PostgreSQL 13</option>
          <option value="12">PostgreSQL 12</option>
        </select>
      </div>

      <h4>Options avancees</h4>

      <div class="form-group">
        <label>
          <input type="checkbox" id="dedicated" onchange="generate()" checked>
          Serveur dedie a PostgreSQL
        </label>
        <span class="hint">Si non coche, reserves moins de RAM</span>
      </div>

      <div class="form-group">
        <label>
          <input type="checkbox" id="replication" onchange="generate()">
          Configuration replication
        </label>
      </div>

      <div class="form-group">
        <label>
          <input type="checkbox" id="logging" onchange="generate()" checked>
          Logging detaille
        </label>
      </div>

      <div class="form-group">
        <label>
          <input type="checkbox" id="autovacuum" onchange="generate()" checked>
          Autovacuum agressif
        </label>
      </div>
    </div>

    <div class="pgsql-section">
      <h3>Configuration generee</h3>
      <pre id="configOutput"># postgresql.conf</pre>
      <button onclick="copyConfig()">Copier</button>

      <div class="calc-details">
        <h4>Calculs</h4>
        <div id="calcDetails"></div>
      </div>
    </div>
  </div>

  <div class="presets-section">
    <h3>Presets par taille</h3>
    <div class="presets-grid">
      <div class="preset-card" onclick="loadPreset('small')">
        <h4>Small</h4>
        <p>2GB RAM, 2 CPU</p>
      </div>
      <div class="preset-card" onclick="loadPreset('medium')">
        <h4>Medium</h4>
        <p>8GB RAM, 4 CPU</p>
      </div>
      <div class="preset-card" onclick="loadPreset('large')">
        <h4>Large</h4>
        <p>32GB RAM, 8 CPU</p>
      </div>
      <div class="preset-card" onclick="loadPreset('xlarge')">
        <h4>X-Large</h4>
        <p>64GB RAM, 16 CPU</p>
      </div>
      <div class="preset-card" onclick="loadPreset('rds-small')">
        <h4>RDS db.t3.medium</h4>
        <p>4GB RAM, 2 vCPU</p>
      </div>
      <div class="preset-card" onclick="loadPreset('rds-large')">
        <h4>RDS db.r5.large</h4>
        <p>16GB RAM, 2 vCPU</p>
      </div>
    </div>
  </div>

  <div class="reference-section">
    <h3>Parametres cles</h3>
    <table class="ref-table">
      <tr><td><code>shared_buffers</code></td><td>Cache de donnees en RAM (25% RAM)</td></tr>
      <tr><td><code>effective_cache_size</code></td><td>Estimation cache OS (50-75% RAM)</td></tr>
      <tr><td><code>work_mem</code></td><td>Memoire par operation de tri</td></tr>
      <tr><td><code>maintenance_work_mem</code></td><td>Memoire pour VACUUM, CREATE INDEX</td></tr>
      <tr><td><code>wal_buffers</code></td><td>Buffers pour Write-Ahead Log</td></tr>
      <tr><td><code>checkpoint_completion_target</code></td><td>Etaler les ecritures checkpoint</td></tr>
    </table>
  </div>
</div>

<style>
.pgsql-container {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 20px;
}

@media (max-width: 900px) {
  .pgsql-container { grid-template-columns: 1fr; }
}

.pgsql-section, .presets-section, .reference-section {
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
.form-group input[type="number"] {
  width: 100%;
  padding: 10px;
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  background: var(--md-default-bg-color);
  color: var(--md-default-fg-color);
  font-family: monospace;
}

.form-group input[type="checkbox"] { margin-right: 8px; }

.input-with-unit {
  display: flex;
  gap: 10px;
}

.input-with-unit input { flex: 1; }
.input-with-unit select { width: 80px; }

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
  min-height: 400px;
}

.pgsql-section button {
  margin-top: 10px;
  padding: 8px 16px;
  background: var(--md-primary-fg-color);
  color: white;
  border: none;
  border-radius: 4px;
  cursor: pointer;
}

.calc-details {
  margin-top: 20px;
  padding: 15px;
  background: var(--md-default-bg-color);
  border-radius: 6px;
  font-size: 0.85em;
}

.calc-details h4 { margin: 0 0 10px 0; }

.presets-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
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
function formatSize(mb) {
  if (mb >= 1024) {
    return Math.round(mb / 1024) + 'GB';
  }
  return Math.round(mb) + 'MB';
}

function generate() {
  let ramMB = parseInt(document.getElementById('totalRam').value);
  const ramUnit = document.getElementById('ramUnit').value;
  if (ramUnit === 'GB') ramMB *= 1024;

  const cpuCount = parseInt(document.getElementById('cpuCount').value);
  const storageType = document.getElementById('storageType').value;
  const workloadType = document.getElementById('workloadType').value;
  const maxConnections = parseInt(document.getElementById('maxConnections').value);
  const pgVersion = document.getElementById('pgVersion').value;
  const dedicated = document.getElementById('dedicated').checked;
  const replication = document.getElementById('replication').checked;
  const logging = document.getElementById('logging').checked;
  const autovacuum = document.getElementById('autovacuum').checked;

  // Calculate values
  const ramFactor = dedicated ? 1 : 0.7;
  const availableRam = ramMB * ramFactor;

  // shared_buffers: 25% of RAM, max 8GB for most workloads
  let sharedBuffers = Math.min(availableRam * 0.25, 8192);
  if (workloadType === 'olap') sharedBuffers = Math.min(availableRam * 0.4, 16384);

  // effective_cache_size: 50-75% of RAM
  const effectiveCacheSize = availableRam * 0.75;

  // work_mem: depends on connections and workload
  let workMem = Math.max(4, Math.floor((availableRam - sharedBuffers) / (maxConnections * 3)));
  if (workloadType === 'olap') workMem = Math.min(workMem * 4, 2048);
  if (workloadType === 'web') workMem = Math.min(workMem, 64);

  // maintenance_work_mem: 5% of RAM, max 2GB
  const maintenanceWorkMem = Math.min(availableRam * 0.05, 2048);

  // wal_buffers: 3% of shared_buffers, min 64KB, max 64MB
  const walBuffers = Math.min(Math.max(sharedBuffers * 0.03, 0.0625), 64);

  // random_page_cost
  const randomPageCost = storageType === 'ssd' ? 1.1 : (storageType === 'san' ? 1.5 : 4.0);

  // effective_io_concurrency
  const effectiveIoConcurrency = storageType === 'ssd' ? 200 : (storageType === 'san' ? 100 : 2);

  // parallel workers
  const maxParallelWorkers = Math.min(cpuCount, 8);
  const maxParallelWorkersPerGather = Math.min(Math.floor(cpuCount / 2), 4);
  const maxParallelMaintenanceWorkers = Math.min(Math.floor(cpuCount / 2), 4);

  // WAL settings
  const minWalSize = workloadType === 'olap' ? '2GB' : '1GB';
  const maxWalSize = workloadType === 'olap' ? '8GB' : '4GB';

  let config = `# PostgreSQL ${pgVersion} Configuration
# Generated by ShellBook PostgreSQL Generator
# RAM: ${formatSize(ramMB)} | CPUs: ${cpuCount} | Storage: ${storageType}
# Workload: ${workloadType}

# =============================================================================
# CONNECTIONS
# =============================================================================
listen_addresses = '*'
port = 5432
max_connections = ${maxConnections}
superuser_reserved_connections = 3

# =============================================================================
# MEMORY
# =============================================================================
shared_buffers = ${formatSize(sharedBuffers)}
effective_cache_size = ${formatSize(effectiveCacheSize)}
work_mem = ${formatSize(workMem)}
maintenance_work_mem = ${formatSize(maintenanceWorkMem)}
huge_pages = try

# =============================================================================
# WAL
# =============================================================================
wal_buffers = ${formatSize(walBuffers)}
min_wal_size = ${minWalSize}
max_wal_size = ${maxWalSize}
checkpoint_completion_target = 0.9
wal_compression = on
`;

  if (replication) {
    config += `
# Replication
wal_level = replica
max_wal_senders = 10
max_replication_slots = 10
hot_standby = on
`;
  }

  config += `
# =============================================================================
# QUERY PLANNING
# =============================================================================
random_page_cost = ${randomPageCost}
effective_io_concurrency = ${effectiveIoConcurrency}
default_statistics_target = ${workloadType === 'olap' ? 500 : 100}

# =============================================================================
# PARALLELISM
# =============================================================================
max_worker_processes = ${cpuCount}
max_parallel_workers = ${maxParallelWorkers}
max_parallel_workers_per_gather = ${maxParallelWorkersPerGather}
max_parallel_maintenance_workers = ${maxParallelMaintenanceWorkers}
`;

  if (autovacuum) {
    config += `
# =============================================================================
# AUTOVACUUM
# =============================================================================
autovacuum = on
autovacuum_max_workers = ${Math.min(Math.floor(cpuCount / 2), 4)}
autovacuum_naptime = 10s
autovacuum_vacuum_threshold = 50
autovacuum_vacuum_scale_factor = 0.05
autovacuum_analyze_threshold = 50
autovacuum_analyze_scale_factor = 0.05
autovacuum_vacuum_cost_delay = 2ms
autovacuum_vacuum_cost_limit = 1000
`;
  }

  if (logging) {
    config += `
# =============================================================================
# LOGGING
# =============================================================================
logging_collector = on
log_directory = 'log'
log_filename = 'postgresql-%Y-%m-%d_%H%M%S.log'
log_rotation_age = 1d
log_rotation_size = 100MB
log_min_duration_statement = 1000
log_checkpoints = on
log_connections = on
log_disconnections = on
log_lock_waits = on
log_temp_files = 0
log_autovacuum_min_duration = 0
log_line_prefix = '%t [%p]: [%l-1] user=%u,db=%d,app=%a,client=%h '
`;
  }

  config += `
# =============================================================================
# MISC
# =============================================================================
timezone = 'UTC'
lc_messages = 'en_US.UTF-8'
`;

  document.getElementById('configOutput').textContent = config;

  // Calculation details
  const details = `
<strong>shared_buffers:</strong> ${formatSize(sharedBuffers)} (25% of ${formatSize(availableRam)} available RAM)<br>
<strong>effective_cache_size:</strong> ${formatSize(effectiveCacheSize)} (75% RAM - cache OS inclus)<br>
<strong>work_mem:</strong> ${formatSize(workMem)} (par operation de tri)<br>
<strong>maintenance_work_mem:</strong> ${formatSize(maintenanceWorkMem)} (pour VACUUM/INDEX)<br>
<strong>random_page_cost:</strong> ${randomPageCost} (${storageType})<br>
<strong>parallel workers:</strong> ${maxParallelWorkersPerGather} per query, ${maxParallelWorkers} total
`;
  document.getElementById('calcDetails').innerHTML = details;
}

function loadPreset(name) {
  const presets = {
    'small': { ram: 2, cpu: 2, unit: 'GB' },
    'medium': { ram: 8, cpu: 4, unit: 'GB' },
    'large': { ram: 32, cpu: 8, unit: 'GB' },
    'xlarge': { ram: 64, cpu: 16, unit: 'GB' },
    'rds-small': { ram: 4, cpu: 2, unit: 'GB', dedicated: false },
    'rds-large': { ram: 16, cpu: 2, unit: 'GB', dedicated: false }
  };

  const p = presets[name];
  if (p) {
    document.getElementById('totalRam').value = p.ram;
    document.getElementById('cpuCount').value = p.cpu;
    document.getElementById('ramUnit').value = p.unit;
    document.getElementById('dedicated').checked = p.dedicated !== false;
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

## Application

```bash
# Trouver le fichier de config
psql -c "SHOW config_file"

# Appliquer (necessite restart pour shared_buffers)
sudo systemctl restart postgresql

# Recharger sans restart (params dynamiques)
sudo systemctl reload postgresql
# ou
SELECT pg_reload_conf();

# Verifier une valeur
SHOW shared_buffers;
SHOW ALL;
```

---

## Voir aussi

- [MySQL Config Generator](mysql-generator.md)
- [Memory Sizing Calculator](memory-calculator.md)
- [IOPS Calculator](iops-calculator.md)
