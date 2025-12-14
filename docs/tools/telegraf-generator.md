---
tags:
  - tools
  - monitoring
  - telegraf
  - metrics
---

# Telegraf Config Generator

Generateur de configuration Telegraf pour la collecte de metriques.

<div id="telegraf-app">
  <div class="telegraf-container">
    <div class="telegraf-section">
      <h3>Configuration</h3>

      <h4>Output (destination)</h4>

      <div class="form-group">
        <label>Type de sortie</label>
        <select id="outputType" onchange="generate()">
          <option value="influxdb2" selected>InfluxDB 2.x</option>
          <option value="influxdb">InfluxDB 1.x</option>
          <option value="prometheus">Prometheus Remote Write</option>
          <option value="elasticsearch">Elasticsearch</option>
          <option value="file">File (debug)</option>
        </select>
      </div>

      <div class="form-group" id="influx2Group">
        <label>URL InfluxDB</label>
        <input type="text" id="influxUrl" value="http://localhost:8086" oninput="generate()">
        <label>Token</label>
        <input type="text" id="influxToken" value="your-token" oninput="generate()">
        <label>Organization</label>
        <input type="text" id="influxOrg" value="myorg" oninput="generate()">
        <label>Bucket</label>
        <input type="text" id="influxBucket" value="telegraf" oninput="generate()">
      </div>

      <div class="form-group" id="promGroup" style="display:none">
        <label>URL Prometheus</label>
        <input type="text" id="promUrl" value="http://localhost:9090/api/v1/write" oninput="generate()">
      </div>

      <h4>Inputs (sources de metriques)</h4>

      <div class="inputs-grid">
        <label><input type="checkbox" id="inputCpu" onchange="generate()" checked> CPU</label>
        <label><input type="checkbox" id="inputMem" onchange="generate()" checked> Memory</label>
        <label><input type="checkbox" id="inputDisk" onchange="generate()" checked> Disk</label>
        <label><input type="checkbox" id="inputDiskio" onchange="generate()" checked> Disk I/O</label>
        <label><input type="checkbox" id="inputNet" onchange="generate()" checked> Network</label>
        <label><input type="checkbox" id="inputSystem" onchange="generate()" checked> System</label>
        <label><input type="checkbox" id="inputProcesses" onchange="generate()"> Processes</label>
        <label><input type="checkbox" id="inputDocker" onchange="generate()"> Docker</label>
        <label><input type="checkbox" id="inputNginx" onchange="generate()"> Nginx</label>
        <label><input type="checkbox" id="inputMysql" onchange="generate()"> MySQL</label>
        <label><input type="checkbox" id="inputPostgresql" onchange="generate()"> PostgreSQL</label>
        <label><input type="checkbox" id="inputRedis" onchange="generate()"> Redis</label>
        <label><input type="checkbox" id="inputMongodb" onchange="generate()"> MongoDB</label>
        <label><input type="checkbox" id="inputKubernetes" onchange="generate()"> Kubernetes</label>
      </div>

      <div class="form-group" id="dockerGroup" style="display:none">
        <label>Docker endpoint</label>
        <input type="text" id="dockerEndpoint" value="unix:///var/run/docker.sock" oninput="generate()">
      </div>

      <div class="form-group" id="nginxGroup" style="display:none">
        <label>Nginx status URL</label>
        <input type="text" id="nginxUrl" value="http://localhost/nginx_status" oninput="generate()">
      </div>

      <div class="form-group" id="mysqlGroup" style="display:none">
        <label>MySQL connection string</label>
        <input type="text" id="mysqlConn" value="root:password@tcp(localhost:3306)/" oninput="generate()">
      </div>

      <div class="form-group" id="pgsqlGroup" style="display:none">
        <label>PostgreSQL connection</label>
        <input type="text" id="pgsqlConn" value="host=localhost user=postgres dbname=postgres" oninput="generate()">
      </div>

      <div class="form-group" id="redisGroup" style="display:none">
        <label>Redis servers</label>
        <input type="text" id="redisServers" value="tcp://localhost:6379" oninput="generate()">
      </div>

      <h4>Options</h4>

      <div class="form-group">
        <label>Intervalle de collecte</label>
        <select id="interval" onchange="generate()">
          <option value="10s" selected>10 secondes</option>
          <option value="30s">30 secondes</option>
          <option value="1m">1 minute</option>
          <option value="5m">5 minutes</option>
        </select>
      </div>

      <div class="form-group">
        <label>Hostname (tag)</label>
        <input type="text" id="hostname" placeholder="auto-detect" oninput="generate()">
      </div>

      <div class="form-group">
        <label>Tags globaux (key=value, un par ligne)</label>
        <textarea id="globalTags" rows="2" oninput="generate()">env=production
dc=eu-west-1</textarea>
      </div>
    </div>

    <div class="telegraf-section">
      <h3>Configuration generee</h3>
      <pre id="configOutput"># telegraf.conf</pre>
      <button onclick="copyConfig()">Copier</button>
    </div>
  </div>

  <div class="presets-section">
    <h3>Presets par cas d'usage</h3>
    <div class="presets-grid">
      <div class="preset-card" onclick="loadPreset('basic')">
        <h4>Basic</h4>
        <p>CPU, RAM, Disk</p>
      </div>
      <div class="preset-card" onclick="loadPreset('webserver')">
        <h4>Web Server</h4>
        <p>+ Nginx</p>
      </div>
      <div class="preset-card" onclick="loadPreset('database')">
        <h4>Database</h4>
        <p>MySQL + PostgreSQL</p>
      </div>
      <div class="preset-card" onclick="loadPreset('docker')">
        <h4>Docker Host</h4>
        <p>Docker + containers</p>
      </div>
      <div class="preset-card" onclick="loadPreset('k8s')">
        <h4>Kubernetes</h4>
        <p>K8s metrics</p>
      </div>
      <div class="preset-card" onclick="loadPreset('full')">
        <h4>Full Stack</h4>
        <p>Tout actif</p>
      </div>
    </div>
  </div>
</div>

<style>
.telegraf-container {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 20px;
}

@media (max-width: 900px) {
  .telegraf-container { grid-template-columns: 1fr; }
}

.telegraf-section, .presets-section {
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
.form-group textarea {
  width: 100%;
  padding: 10px;
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  background: var(--md-default-bg-color);
  color: var(--md-default-fg-color);
  font-family: monospace;
  margin-bottom: 10px;
}

.inputs-grid {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 8px;
  margin-bottom: 15px;
}

.inputs-grid label {
  display: flex;
  align-items: center;
  font-size: 0.9em;
}

.inputs-grid input { margin-right: 8px; }

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

.telegraf-section button {
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
</style>

<script>
function generate() {
  const outputType = document.getElementById('outputType').value;
  const interval = document.getElementById('interval').value;
  const hostname = document.getElementById('hostname').value;
  const globalTags = document.getElementById('globalTags').value;

  // Visibility
  document.getElementById('influx2Group').style.display =
    (outputType === 'influxdb2' || outputType === 'influxdb') ? 'block' : 'none';
  document.getElementById('promGroup').style.display =
    outputType === 'prometheus' ? 'block' : 'none';
  document.getElementById('dockerGroup').style.display =
    document.getElementById('inputDocker').checked ? 'block' : 'none';
  document.getElementById('nginxGroup').style.display =
    document.getElementById('inputNginx').checked ? 'block' : 'none';
  document.getElementById('mysqlGroup').style.display =
    document.getElementById('inputMysql').checked ? 'block' : 'none';
  document.getElementById('pgsqlGroup').style.display =
    document.getElementById('inputPostgresql').checked ? 'block' : 'none';
  document.getElementById('redisGroup').style.display =
    document.getElementById('inputRedis').checked ? 'block' : 'none';

  let config = `# Telegraf Configuration
# Generated by ShellBook Telegraf Generator

[global_tags]
`;

  globalTags.split('\n').forEach(line => {
    const trimmed = line.trim();
    if (trimmed && trimmed.includes('=')) {
      config += `  ${trimmed}\n`;
    }
  });

  config += `
[agent]
  interval = "${interval}"
  round_interval = true
  metric_batch_size = 1000
  metric_buffer_limit = 10000
  collection_jitter = "0s"
  flush_interval = "10s"
  flush_jitter = "0s"
  precision = ""
`;

  if (hostname) {
    config += `  hostname = "${hostname}"\n`;
  }

  config += `  omit_hostname = false

###############################################################################
#                            OUTPUT PLUGINS                                   #
###############################################################################

`;

  // Output
  switch(outputType) {
    case 'influxdb2':
      const influxUrl = document.getElementById('influxUrl').value;
      const influxToken = document.getElementById('influxToken').value;
      const influxOrg = document.getElementById('influxOrg').value;
      const influxBucket = document.getElementById('influxBucket').value;
      config += `[[outputs.influxdb_v2]]
  urls = ["${influxUrl}"]
  token = "${influxToken}"
  organization = "${influxOrg}"
  bucket = "${influxBucket}"
`;
      break;
    case 'influxdb':
      config += `[[outputs.influxdb]]
  urls = ["${document.getElementById('influxUrl').value}"]
  database = "${document.getElementById('influxBucket').value}"
`;
      break;
    case 'prometheus':
      config += `[[outputs.prometheus_client]]
  listen = ":9273"
  path = "/metrics"

[[outputs.http]]
  url = "${document.getElementById('promUrl').value}"
  data_format = "prometheusremotewrite"
`;
      break;
    case 'elasticsearch':
      config += `[[outputs.elasticsearch]]
  urls = ["http://localhost:9200"]
  index_name = "telegraf-%Y.%m.%d"
`;
      break;
    case 'file':
      config += `[[outputs.file]]
  files = ["stdout", "/tmp/metrics.out"]
  data_format = "influx"
`;
      break;
  }

  config += `
###############################################################################
#                            INPUT PLUGINS                                    #
###############################################################################

`;

  // Inputs
  if (document.getElementById('inputCpu').checked) {
    config += `[[inputs.cpu]]
  percpu = true
  totalcpu = true
  collect_cpu_time = false
  report_active = false

`;
  }

  if (document.getElementById('inputMem').checked) {
    config += `[[inputs.mem]]

`;
  }

  if (document.getElementById('inputDisk').checked) {
    config += `[[inputs.disk]]
  ignore_fs = ["tmpfs", "devtmpfs", "devfs", "iso9660", "overlay", "aufs", "squashfs"]

`;
  }

  if (document.getElementById('inputDiskio').checked) {
    config += `[[inputs.diskio]]

`;
  }

  if (document.getElementById('inputNet').checked) {
    config += `[[inputs.net]]
  ignore_protocol_stats = true

`;
  }

  if (document.getElementById('inputSystem').checked) {
    config += `[[inputs.system]]

`;
  }

  if (document.getElementById('inputProcesses').checked) {
    config += `[[inputs.processes]]

`;
  }

  if (document.getElementById('inputDocker').checked) {
    config += `[[inputs.docker]]
  endpoint = "${document.getElementById('dockerEndpoint').value}"
  gather_services = false
  container_names = []
  source_tag = false
  container_name_include = []
  container_name_exclude = []
  timeout = "5s"
  perdevice = true
  total = false

`;
  }

  if (document.getElementById('inputNginx').checked) {
    config += `[[inputs.nginx]]
  urls = ["${document.getElementById('nginxUrl').value}"]
  response_timeout = "5s"

`;
  }

  if (document.getElementById('inputMysql').checked) {
    config += `[[inputs.mysql]]
  servers = ["${document.getElementById('mysqlConn').value}"]
  gather_process_list = true
  gather_user_statistics = true
  gather_info_schema_auto_inc = true
  gather_innodb_metrics = true
  gather_slave_status = true

`;
  }

  if (document.getElementById('inputPostgresql').checked) {
    config += `[[inputs.postgresql]]
  address = "${document.getElementById('pgsqlConn').value}"
  databases = ["*"]

`;
  }

  if (document.getElementById('inputRedis').checked) {
    config += `[[inputs.redis]]
  servers = ["${document.getElementById('redisServers').value}"]

`;
  }

  if (document.getElementById('inputMongodb').checked) {
    config += `[[inputs.mongodb]]
  servers = ["mongodb://localhost:27017"]
  gather_perdb_stats = true

`;
  }

  if (document.getElementById('inputKubernetes').checked) {
    config += `[[inputs.kubernetes]]
  url = "https://kubernetes.default.svc:443"
  bearer_token = "/var/run/secrets/kubernetes.io/serviceaccount/token"
  insecure_skip_verify = true

`;
  }

  document.getElementById('configOutput').textContent = config;
}

function loadPreset(name) {
  // Reset all inputs
  document.querySelectorAll('.inputs-grid input[type="checkbox"]').forEach(cb => cb.checked = false);

  const basic = ['inputCpu', 'inputMem', 'inputDisk', 'inputDiskio', 'inputNet', 'inputSystem'];

  switch(name) {
    case 'basic':
      basic.forEach(id => document.getElementById(id).checked = true);
      break;
    case 'webserver':
      basic.forEach(id => document.getElementById(id).checked = true);
      document.getElementById('inputNginx').checked = true;
      break;
    case 'database':
      basic.forEach(id => document.getElementById(id).checked = true);
      document.getElementById('inputMysql').checked = true;
      document.getElementById('inputPostgresql').checked = true;
      break;
    case 'docker':
      basic.forEach(id => document.getElementById(id).checked = true);
      document.getElementById('inputDocker').checked = true;
      break;
    case 'k8s':
      basic.forEach(id => document.getElementById(id).checked = true);
      document.getElementById('inputKubernetes').checked = true;
      document.getElementById('inputDocker').checked = true;
      break;
    case 'full':
      document.querySelectorAll('.inputs-grid input[type="checkbox"]').forEach(cb => cb.checked = true);
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
# Tester la configuration
telegraf --config telegraf.conf --test

# Lancer en debug
telegraf --config telegraf.conf --debug

# Lister les plugins
telegraf --input-list
telegraf --output-list

# Verifier un input specifique
telegraf --config telegraf.conf --input-filter cpu --test
```

---

## Voir aussi

- [Prometheus Query Builder](promql-builder.md)
- [Prometheus Alerting Rules](prometheus-alerting-generator.md)
