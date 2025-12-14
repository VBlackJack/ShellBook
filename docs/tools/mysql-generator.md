---
tags:
  - tools
  - database
  - mysql
  - mariadb
  - tuning
---

# MySQL/MariaDB Config Generator

Generateur de configuration my.cnf optimisee selon vos ressources.

<div id="mysql-app">
  <div class="mysql-container">
    <div class="mysql-section">
      <h3>Ressources systeme</h3>

      <div class="form-group">
        <label>Type de serveur</label>
        <select id="serverType" onchange="generate()">
          <option value="mysql8" selected>MySQL 8.x</option>
          <option value="mysql57">MySQL 5.7</option>
          <option value="mariadb">MariaDB 10.x</option>
        </select>
      </div>

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
        </select>
      </div>

      <div class="form-group">
        <label>Type d'utilisation</label>
        <select id="workloadType" onchange="generate()">
          <option value="oltp" selected>OLTP (transactions)</option>
          <option value="olap">OLAP (analytique)</option>
          <option value="mixed">Mixed</option>
        </select>
      </div>

      <div class="form-group">
        <label>Connexions max attendues</label>
        <input type="number" id="maxConnections" value="150" min="10" max="10000" oninput="generate()">
      </div>

      <h4>Options</h4>

      <div class="form-group">
        <label>
          <input type="checkbox" id="dedicated" onchange="generate()" checked>
          Serveur dedie a MySQL
        </label>
      </div>

      <div class="form-group">
        <label>
          <input type="checkbox" id="replication" onchange="generate()">
          Configuration replication
        </label>
      </div>

      <div class="form-group" id="replRole" style="display:none">
        <label>Role replication</label>
        <select id="replicationRole" onchange="generate()">
          <option value="master">Master/Primary</option>
          <option value="slave">Slave/Replica</option>
        </select>
      </div>

      <div class="form-group">
        <label>
          <input type="checkbox" id="slowLog" onchange="generate()" checked>
          Slow query log
        </label>
      </div>

      <div class="form-group">
        <label>
          <input type="checkbox" id="ssl" onchange="generate()">
          Forcer SSL
        </label>
      </div>
    </div>

    <div class="mysql-section">
      <h3>Configuration generee</h3>
      <pre id="configOutput"># my.cnf</pre>
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
      <div class="preset-card" onclick="loadPreset('micro')">
        <h4>Micro</h4>
        <p>1GB RAM, 1 CPU</p>
      </div>
      <div class="preset-card" onclick="loadPreset('small')">
        <h4>Small</h4>
        <p>4GB RAM, 2 CPU</p>
      </div>
      <div class="preset-card" onclick="loadPreset('medium')">
        <h4>Medium</h4>
        <p>16GB RAM, 4 CPU</p>
      </div>
      <div class="preset-card" onclick="loadPreset('large')">
        <h4>Large</h4>
        <p>64GB RAM, 16 CPU</p>
      </div>
      <div class="preset-card" onclick="loadPreset('xlarge')">
        <h4>X-Large</h4>
        <p>128GB RAM, 32 CPU</p>
      </div>
      <div class="preset-card" onclick="loadPreset('galera')">
        <h4>Galera Cluster</h4>
        <p>Config cluster sync</p>
      </div>
    </div>
  </div>

  <div class="reference-section">
    <h3>Parametres cles InnoDB</h3>
    <table class="ref-table">
      <tr><td><code>innodb_buffer_pool_size</code></td><td>Cache principal (50-80% RAM)</td></tr>
      <tr><td><code>innodb_log_file_size</code></td><td>Taille redo log (1-2GB)</td></tr>
      <tr><td><code>innodb_flush_log_at_trx_commit</code></td><td>1=ACID, 2=perf, 0=risque</td></tr>
      <tr><td><code>innodb_io_capacity</code></td><td>IOPS disponibles (SSD: 2000+)</td></tr>
      <tr><td><code>innodb_read_io_threads</code></td><td>Threads lecture async</td></tr>
      <tr><td><code>innodb_write_io_threads</code></td><td>Threads ecriture async</td></tr>
    </table>
  </div>
</div>

<style>
.mysql-container {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 20px;
}

@media (max-width: 900px) {
  .mysql-container { grid-template-columns: 1fr; }
}

.mysql-section, .presets-section, .reference-section {
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

.mysql-section button {
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

.presets-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
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
    const gb = mb / 1024;
    return gb >= 1 ? Math.round(gb) + 'G' : gb.toFixed(1) + 'G';
  }
  return Math.round(mb) + 'M';
}

function generate() {
  let ramMB = parseInt(document.getElementById('totalRam').value);
  const ramUnit = document.getElementById('ramUnit').value;
  if (ramUnit === 'GB') ramMB *= 1024;

  const serverType = document.getElementById('serverType').value;
  const cpuCount = parseInt(document.getElementById('cpuCount').value);
  const storageType = document.getElementById('storageType').value;
  const workloadType = document.getElementById('workloadType').value;
  const maxConnections = parseInt(document.getElementById('maxConnections').value);
  const dedicated = document.getElementById('dedicated').checked;
  const replication = document.getElementById('replication').checked;
  const replicationRole = document.getElementById('replicationRole').value;
  const slowLog = document.getElementById('slowLog').checked;
  const ssl = document.getElementById('ssl').checked;

  document.getElementById('replRole').style.display = replication ? 'block' : 'none';

  const ramFactor = dedicated ? 1 : 0.7;
  const availableRam = ramMB * ramFactor;

  // InnoDB buffer pool: 50-80% of available RAM
  let bufferPoolPct = dedicated ? 0.75 : 0.5;
  if (workloadType === 'olap') bufferPoolPct = 0.8;
  const bufferPoolSize = Math.floor(availableRam * bufferPoolPct);

  // Buffer pool instances (1 per GB, max 64)
  const bufferPoolInstances = Math.min(Math.max(Math.floor(bufferPoolSize / 1024), 1), 64);

  // Log file size
  let logFileSize = Math.min(Math.floor(bufferPoolSize / 4), 2048);
  if (logFileSize < 256) logFileSize = 256;

  // IO capacity
  const ioCapacity = storageType === 'ssd' ? 2000 : 200;
  const ioCapacityMax = storageType === 'ssd' ? 4000 : 400;

  // Thread counts
  const readThreads = Math.min(cpuCount, 64);
  const writeThreads = Math.min(cpuCount, 64);

  // tmp_table_size / max_heap_table_size
  const tmpTableSize = Math.min(Math.floor(availableRam * 0.02), 256);

  // join_buffer_size, sort_buffer_size
  const joinBufferSize = workloadType === 'olap' ? 4 : 1;
  const sortBufferSize = workloadType === 'olap' ? 4 : 2;

  let config = `# MySQL/MariaDB Configuration
# Generated by ShellBook MySQL Generator
# Server: ${serverType} | RAM: ${formatSize(ramMB)} | CPUs: ${cpuCount}
# Workload: ${workloadType} | Storage: ${storageType}

[mysqld]
# =============================================================================
# GENERAL
# =============================================================================
user = mysql
datadir = /var/lib/mysql
socket = /var/run/mysqld/mysqld.sock
pid-file = /var/run/mysqld/mysqld.pid
bind-address = 0.0.0.0
port = 3306

# =============================================================================
# CONNECTIONS
# =============================================================================
max_connections = ${maxConnections}
max_connect_errors = 1000000
wait_timeout = 28800
interactive_timeout = 28800

# =============================================================================
# INNODB
# =============================================================================
default_storage_engine = InnoDB
innodb_buffer_pool_size = ${formatSize(bufferPoolSize)}
innodb_buffer_pool_instances = ${bufferPoolInstances}
innodb_log_file_size = ${formatSize(logFileSize)}
innodb_log_buffer_size = 64M
innodb_flush_log_at_trx_commit = ${workloadType === 'oltp' ? 1 : 2}
innodb_flush_method = O_DIRECT
innodb_file_per_table = 1
innodb_stats_on_metadata = 0
innodb_lock_wait_timeout = 50

# IO Settings
innodb_io_capacity = ${ioCapacity}
innodb_io_capacity_max = ${ioCapacityMax}
innodb_read_io_threads = ${readThreads}
innodb_write_io_threads = ${writeThreads}
`;

  if (serverType === 'mysql8') {
    config += `innodb_redo_log_capacity = ${formatSize(logFileSize * 2)}
innodb_dedicated_server = ${dedicated ? 'ON' : 'OFF'}
`;
  }

  config += `
# =============================================================================
# QUERY CACHE / BUFFERS
# =============================================================================
`;

  if (serverType !== 'mysql8') {
    config += `query_cache_type = 0
query_cache_size = 0
`;
  }

  config += `tmp_table_size = ${formatSize(tmpTableSize)}
max_heap_table_size = ${formatSize(tmpTableSize)}
join_buffer_size = ${joinBufferSize}M
sort_buffer_size = ${sortBufferSize}M
read_buffer_size = 1M
read_rnd_buffer_size = 1M

# =============================================================================
# TABLE CACHE
# =============================================================================
table_open_cache = ${Math.min(maxConnections * 2, 4000)}
table_definition_cache = ${Math.min(maxConnections * 2, 2000)}
open_files_limit = 65535
`;

  if (replication) {
    config += `
# =============================================================================
# REPLICATION
# =============================================================================
server-id = ${replicationRole === 'master' ? 1 : 2}
log_bin = mysql-bin
binlog_format = ROW
sync_binlog = 1
expire_logs_days = 7
`;

    if (replicationRole === 'slave') {
      config += `read_only = ON
relay_log = relay-bin
log_slave_updates = ON
`;
    }

    if (serverType === 'mysql8') {
      config += `gtid_mode = ON
enforce_gtid_consistency = ON
`;
    }
  }

  if (slowLog) {
    config += `
# =============================================================================
# LOGGING
# =============================================================================
slow_query_log = 1
slow_query_log_file = /var/log/mysql/mysql-slow.log
long_query_time = 2
log_queries_not_using_indexes = 1
`;
  }

  if (ssl) {
    config += `
# =============================================================================
# SSL
# =============================================================================
require_secure_transport = ON
ssl-ca = /etc/mysql/certs/ca.pem
ssl-cert = /etc/mysql/certs/server-cert.pem
ssl-key = /etc/mysql/certs/server-key.pem
`;
  }

  config += `
# =============================================================================
# CHARACTER SET
# =============================================================================
character_set_server = utf8mb4
collation_server = utf8mb4_unicode_ci

[client]
socket = /var/run/mysqld/mysqld.sock
default-character-set = utf8mb4
`;

  document.getElementById('configOutput').textContent = config;

  // Calculation details
  const details = `
<strong>innodb_buffer_pool_size:</strong> ${formatSize(bufferPoolSize)} (${Math.round(bufferPoolPct * 100)}% of ${formatSize(availableRam)})<br>
<strong>innodb_buffer_pool_instances:</strong> ${bufferPoolInstances}<br>
<strong>innodb_log_file_size:</strong> ${formatSize(logFileSize)}<br>
<strong>innodb_io_capacity:</strong> ${ioCapacity} (${storageType})<br>
<strong>Memory per connection:</strong> ~${joinBufferSize + sortBufferSize + 2}MB
`;
  document.getElementById('calcDetails').innerHTML = details;
}

function loadPreset(name) {
  const presets = {
    'micro': { ram: 1, cpu: 1, unit: 'GB' },
    'small': { ram: 4, cpu: 2, unit: 'GB' },
    'medium': { ram: 16, cpu: 4, unit: 'GB' },
    'large': { ram: 64, cpu: 16, unit: 'GB' },
    'xlarge': { ram: 128, cpu: 32, unit: 'GB' },
    'galera': { ram: 16, cpu: 4, unit: 'GB', replication: true }
  };

  const p = presets[name];
  if (p) {
    document.getElementById('totalRam').value = p.ram;
    document.getElementById('cpuCount').value = p.cpu;
    document.getElementById('ramUnit').value = p.unit;
    document.getElementById('replication').checked = p.replication || false;
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
# Emplacement du fichier
# Debian/Ubuntu: /etc/mysql/mysql.conf.d/mysqld.cnf
# RHEL/CentOS: /etc/my.cnf ou /etc/my.cnf.d/

# Verifier la syntaxe
mysqld --validate-config

# Redemarrer
sudo systemctl restart mysql  # ou mariadb

# Verifier une valeur
mysql -e "SHOW VARIABLES LIKE 'innodb_buffer_pool_size'"
```

---

## Voir aussi

- [PostgreSQL Config Generator](postgresql-generator.md)
- [Memory Sizing Calculator](memory-calculator.md)
- [Galera Cluster Guide](../databases/galera-cluster.md)
