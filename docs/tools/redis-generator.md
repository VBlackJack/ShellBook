---
tags:
  - tools
  - database
  - redis
  - cache
---

# Redis Config Generator

Generateur de configuration redis.conf optimisee.

<div id="redis-app">
  <div class="redis-container">
    <div class="redis-section">
      <h3>Configuration</h3>

      <div class="form-group">
        <label>Memoire max allouee</label>
        <div class="input-with-unit">
          <input type="number" id="maxMemory" value="1" min="0.1" step="0.1" oninput="generate()">
          <select id="memUnit" onchange="generate()">
            <option value="gb" selected>GB</option>
            <option value="mb">MB</option>
          </select>
        </div>
        <span class="hint">0 = illimite (non recommande en production)</span>
      </div>

      <div class="form-group">
        <label>Politique d'eviction</label>
        <select id="evictionPolicy" onchange="generate()">
          <option value="noeviction">noeviction (erreur si plein)</option>
          <option value="allkeys-lru" selected>allkeys-lru (LRU sur toutes les cles)</option>
          <option value="volatile-lru">volatile-lru (LRU sur cles avec TTL)</option>
          <option value="allkeys-lfu">allkeys-lfu (LFU sur toutes les cles)</option>
          <option value="volatile-lfu">volatile-lfu (LFU sur cles avec TTL)</option>
          <option value="allkeys-random">allkeys-random</option>
          <option value="volatile-random">volatile-random</option>
          <option value="volatile-ttl">volatile-ttl (plus court TTL)</option>
        </select>
      </div>

      <div class="form-group">
        <label>Port</label>
        <input type="number" id="port" value="6379" oninput="generate()">
      </div>

      <div class="form-group">
        <label>Bind address</label>
        <input type="text" id="bind" value="127.0.0.1" oninput="generate()">
        <span class="hint">127.0.0.1 = local only, 0.0.0.0 = toutes interfaces</span>
      </div>

      <h4>Persistance</h4>

      <div class="form-group">
        <label>Type de persistance</label>
        <select id="persistence" onchange="generate()">
          <option value="none">Aucune (cache pur)</option>
          <option value="rdb" selected>RDB (snapshots)</option>
          <option value="aof">AOF (append-only)</option>
          <option value="both">RDB + AOF</option>
        </select>
      </div>

      <div class="form-group" id="rdbOptions">
        <label>Frequence snapshots RDB</label>
        <select id="rdbFrequency" onchange="generate()">
          <option value="high">Haute (3600 1, 300 100, 60 10000)</option>
          <option value="medium" selected>Moyenne (900 1, 300 10, 60 10000)</option>
          <option value="low">Basse (3600 1)</option>
        </select>
      </div>

      <div class="form-group" id="aofOptions" style="display:none">
        <label>AOF fsync</label>
        <select id="aofFsync" onchange="generate()">
          <option value="everysec" selected>everysec (recommande)</option>
          <option value="always">always (lent mais sur)</option>
          <option value="no">no (OS decide)</option>
        </select>
      </div>

      <h4>Securite</h4>

      <div class="form-group">
        <label>
          <input type="checkbox" id="requireAuth" onchange="generate()" checked>
          Mot de passe requis
        </label>
      </div>

      <div class="form-group" id="passwordGroup">
        <label>Mot de passe</label>
        <input type="text" id="password" value="your_secure_password_here" oninput="generate()">
      </div>

      <div class="form-group">
        <label>
          <input type="checkbox" id="protectedMode" onchange="generate()" checked>
          Protected mode
        </label>
      </div>

      <div class="form-group">
        <label>
          <input type="checkbox" id="disableDangerousCommands" onchange="generate()" checked>
          Desactiver commandes dangereuses
        </label>
        <span class="hint">FLUSHALL, FLUSHDB, CONFIG, DEBUG, KEYS</span>
      </div>

      <h4>Performance</h4>

      <div class="form-group">
        <label>TCP backlog</label>
        <input type="number" id="tcpBacklog" value="511" oninput="generate()">
      </div>

      <div class="form-group">
        <label>Timeout client (secondes, 0=desactive)</label>
        <input type="number" id="timeout" value="0" oninput="generate()">
      </div>

      <div class="form-group">
        <label>Max clients</label>
        <input type="number" id="maxClients" value="10000" oninput="generate()">
      </div>

      <div class="form-group">
        <label>
          <input type="checkbox" id="ioThreads" onchange="generate()">
          IO threads (Redis 6+)
        </label>
      </div>

      <div class="form-group" id="ioThreadsCount" style="display:none">
        <label>Nombre IO threads</label>
        <input type="number" id="ioThreadsNum" value="4" min="1" max="128" oninput="generate()">
      </div>
    </div>

    <div class="redis-section">
      <h3>Configuration generee</h3>
      <pre id="configOutput"># redis.conf</pre>
      <button onclick="copyConfig()">Copier</button>
    </div>
  </div>

  <div class="presets-section">
    <h3>Presets par usage</h3>
    <div class="presets-grid">
      <div class="preset-card" onclick="loadPreset('cache')">
        <h4>Cache</h4>
        <p>LRU, pas de persistance</p>
      </div>
      <div class="preset-card" onclick="loadPreset('session')">
        <h4>Sessions</h4>
        <p>RDB, volatile-lru</p>
      </div>
      <div class="preset-card" onclick="loadPreset('queue')">
        <h4>Queue/Pub-Sub</h4>
        <p>AOF everysec</p>
      </div>
      <div class="preset-card" onclick="loadPreset('database')">
        <h4>Database</h4>
        <p>RDB + AOF, noeviction</p>
      </div>
      <div class="preset-card" onclick="loadPreset('dev')">
        <h4>Dev/Local</h4>
        <p>Pas de persistance, pas de auth</p>
      </div>
      <div class="preset-card" onclick="loadPreset('highperf')">
        <h4>High Performance</h4>
        <p>IO threads, cache only</p>
      </div>
    </div>
  </div>

  <div class="reference-section">
    <h3>Politiques d'eviction</h3>
    <table class="ref-table">
      <tr><td><code>noeviction</code></td><td>Erreur OOM si maxmemory atteint</td></tr>
      <tr><td><code>allkeys-lru</code></td><td>Supprime les moins recemment utilisees</td></tr>
      <tr><td><code>volatile-lru</code></td><td>LRU uniquement sur cles avec expire</td></tr>
      <tr><td><code>allkeys-lfu</code></td><td>Supprime les moins frequemment utilisees</td></tr>
      <tr><td><code>volatile-ttl</code></td><td>Supprime cles avec le plus court TTL</td></tr>
    </table>
  </div>
</div>

<style>
.redis-container {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 20px;
}

@media (max-width: 900px) {
  .redis-container { grid-template-columns: 1fr; }
}

.redis-section, .presets-section, .reference-section {
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

.redis-section button {
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
function generate() {
  let maxMem = parseFloat(document.getElementById('maxMemory').value);
  const memUnit = document.getElementById('memUnit').value;
  const maxMemStr = memUnit === 'gb' ? maxMem + 'gb' : maxMem + 'mb';

  const evictionPolicy = document.getElementById('evictionPolicy').value;
  const port = document.getElementById('port').value;
  const bind = document.getElementById('bind').value;
  const persistence = document.getElementById('persistence').value;
  const rdbFrequency = document.getElementById('rdbFrequency').value;
  const aofFsync = document.getElementById('aofFsync').value;
  const requireAuth = document.getElementById('requireAuth').checked;
  const password = document.getElementById('password').value;
  const protectedMode = document.getElementById('protectedMode').checked;
  const disableDangerous = document.getElementById('disableDangerousCommands').checked;
  const tcpBacklog = document.getElementById('tcpBacklog').value;
  const timeout = document.getElementById('timeout').value;
  const maxClients = document.getElementById('maxClients').value;
  const ioThreads = document.getElementById('ioThreads').checked;
  const ioThreadsNum = document.getElementById('ioThreadsNum').value;

  // Visibility
  document.getElementById('passwordGroup').style.display = requireAuth ? 'block' : 'none';
  document.getElementById('rdbOptions').style.display =
    (persistence === 'rdb' || persistence === 'both') ? 'block' : 'none';
  document.getElementById('aofOptions').style.display =
    (persistence === 'aof' || persistence === 'both') ? 'block' : 'none';
  document.getElementById('ioThreadsCount').style.display = ioThreads ? 'block' : 'none';

  let config = `# Redis Configuration
# Generated by ShellBook Redis Generator

################################## NETWORK ##################################

bind ${bind}
port ${port}
protected-mode ${protectedMode ? 'yes' : 'no'}
tcp-backlog ${tcpBacklog}
timeout ${timeout}

################################## GENERAL ##################################

daemonize yes
pidfile /var/run/redis/redis-server.pid
loglevel notice
logfile /var/log/redis/redis-server.log
databases 16

################################## SECURITY #################################

`;

  if (requireAuth) {
    config += `requirepass ${password}
`;
  }

  if (disableDangerous) {
    config += `
# Disable dangerous commands
rename-command FLUSHALL ""
rename-command FLUSHDB ""
rename-command CONFIG ""
rename-command DEBUG ""
rename-command KEYS ""
`;
  }

  config += `
################################## MEMORY ###################################

maxmemory ${maxMemStr}
maxmemory-policy ${evictionPolicy}
maxmemory-samples 5

################################## CLIENTS ##################################

maxclients ${maxClients}

`;

  // Persistence
  if (persistence === 'none') {
    config += `################################# SNAPSHOTTING ##############################

# Persistence disabled
save ""
`;
  } else if (persistence === 'rdb' || persistence === 'both') {
    config += `################################# SNAPSHOTTING ##############################

`;
    switch(rdbFrequency) {
      case 'high':
        config += `save 3600 1
save 300 100
save 60 10000
`;
        break;
      case 'medium':
        config += `save 900 1
save 300 10
save 60 10000
`;
        break;
      case 'low':
        config += `save 3600 1
`;
        break;
    }
    config += `
stop-writes-on-bgsave-error yes
rdbcompression yes
rdbchecksum yes
dbfilename dump.rdb
dir /var/lib/redis
`;
  }

  if (persistence === 'aof' || persistence === 'both') {
    config += `
############################## APPEND ONLY MODE #############################

appendonly yes
appendfilename "appendonly.aof"
appendfsync ${aofFsync}
no-appendfsync-on-rewrite no
auto-aof-rewrite-percentage 100
auto-aof-rewrite-min-size 64mb
aof-load-truncated yes
aof-use-rdb-preamble yes
`;
  } else {
    config += `
############################## APPEND ONLY MODE #############################

appendonly no
`;
  }

  config += `
################################## SLOW LOG #################################

slowlog-log-slower-than 10000
slowlog-max-len 128

################################ LATENCY MONITOR ############################

latency-monitor-threshold 0

`;

  if (ioThreads) {
    config += `############################ THREADED I/O #################################

io-threads ${ioThreadsNum}
io-threads-do-reads yes
`;
  }

  config += `
############################### ADVANCED CONFIG #############################

hash-max-ziplist-entries 512
hash-max-ziplist-value 64
list-max-ziplist-size -2
set-max-intset-entries 512
zset-max-ziplist-entries 128
zset-max-ziplist-value 64
activerehashing yes
client-output-buffer-limit normal 0 0 0
client-output-buffer-limit replica 256mb 64mb 60
client-output-buffer-limit pubsub 32mb 8mb 60
hz 10
dynamic-hz yes
`;

  document.getElementById('configOutput').textContent = config;
}

function loadPreset(name) {
  switch(name) {
    case 'cache':
      document.getElementById('maxMemory').value = '1';
      document.getElementById('evictionPolicy').value = 'allkeys-lru';
      document.getElementById('persistence').value = 'none';
      document.getElementById('requireAuth').checked = true;
      break;
    case 'session':
      document.getElementById('maxMemory').value = '512';
      document.getElementById('memUnit').value = 'mb';
      document.getElementById('evictionPolicy').value = 'volatile-lru';
      document.getElementById('persistence').value = 'rdb';
      document.getElementById('rdbFrequency').value = 'medium';
      break;
    case 'queue':
      document.getElementById('maxMemory').value = '1';
      document.getElementById('evictionPolicy').value = 'noeviction';
      document.getElementById('persistence').value = 'aof';
      document.getElementById('aofFsync').value = 'everysec';
      break;
    case 'database':
      document.getElementById('maxMemory').value = '4';
      document.getElementById('evictionPolicy').value = 'noeviction';
      document.getElementById('persistence').value = 'both';
      break;
    case 'dev':
      document.getElementById('maxMemory').value = '256';
      document.getElementById('memUnit').value = 'mb';
      document.getElementById('persistence').value = 'none';
      document.getElementById('requireAuth').checked = false;
      document.getElementById('protectedMode').checked = false;
      document.getElementById('disableDangerousCommands').checked = false;
      break;
    case 'highperf':
      document.getElementById('maxMemory').value = '4';
      document.getElementById('evictionPolicy').value = 'allkeys-lfu';
      document.getElementById('persistence').value = 'none';
      document.getElementById('ioThreads').checked = true;
      document.getElementById('ioThreadsNum').value = '4';
      break;
  }
  generate();
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
# Tester la config
redis-server /etc/redis/redis.conf --test-memory 1024

# Verifier une valeur
redis-cli CONFIG GET maxmemory

# Changer a chaud
redis-cli CONFIG SET maxmemory 2gb

# Info memoire
redis-cli INFO memory

# Monitorer
redis-cli MONITOR
```

---

## Voir aussi

- [Memory Sizing Calculator](memory-calculator.md)
- [Redis Sentinel Setup](../databases/redis-sentinel.md)
