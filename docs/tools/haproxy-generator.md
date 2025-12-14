---
tags:
  - tools
  - haproxy
  - load-balancing
  - proxy
---

# HAProxy Config Generator

Generateur de configuration HAProxy pour le load balancing et reverse proxy.

<div id="haproxy-app">
  <div class="haproxy-container">
    <div class="haproxy-section">
      <h3>Configuration</h3>

      <div class="config-tabs">
        <button class="tab-btn active" onclick="switchTab('frontend')">Frontend</button>
        <button class="tab-btn" onclick="switchTab('backend')">Backend</button>
        <button class="tab-btn" onclick="switchTab('global')">Global</button>
        <button class="tab-btn" onclick="switchTab('ssl')">SSL/TLS</button>
      </div>

      <!-- FRONTEND TAB -->
      <div id="frontend-tab" class="tab-content active">
        <div class="form-group">
          <label>Nom du frontend</label>
          <input type="text" id="frontendName" value="http_front" oninput="generate()">
        </div>

        <div class="form-group">
          <label>Bind (adresse:port)</label>
          <input type="text" id="frontendBind" value="*:80" oninput="generate()">
          <span class="hint">Ex: *:80, 0.0.0.0:443 ssl crt /etc/ssl/cert.pem</span>
        </div>

        <div class="form-group">
          <label>Mode</label>
          <select id="frontendMode" onchange="generate()">
            <option value="http" selected>HTTP (Layer 7)</option>
            <option value="tcp">TCP (Layer 4)</option>
          </select>
        </div>

        <div class="form-group" id="httpOptionsGroup">
          <label>
            <input type="checkbox" id="httpLog" onchange="generate()" checked>
            Activer HTTP logging
          </label>
        </div>

        <div class="form-group">
          <label>
            <input type="checkbox" id="forwardFor" onchange="generate()" checked>
            Ajouter X-Forwarded-For
          </label>
        </div>

        <div class="form-group">
          <label>Default backend</label>
          <input type="text" id="defaultBackend" value="web_servers" oninput="generate()">
        </div>

        <h4>ACLs & Routing</h4>

        <div class="form-group">
          <label>
            <input type="checkbox" id="useAcl" onchange="generate()">
            Ajouter des regles ACL
          </label>
        </div>

        <div id="aclGroup" style="display:none">
          <div class="form-group">
            <label>ACL 1 - Condition</label>
            <select id="acl1Type" onchange="generate()">
              <option value="path_beg">Path commence par</option>
              <option value="path_end">Path termine par</option>
              <option value="hdr(host)">Host header</option>
              <option value="src">Source IP</option>
            </select>
            <input type="text" id="acl1Value" value="/api" oninput="generate()">
            <label>Backend cible</label>
            <input type="text" id="acl1Backend" value="api_servers" oninput="generate()">
          </div>

          <div class="form-group">
            <label>
              <input type="checkbox" id="useAcl2" onchange="generate()">
              ACL 2
            </label>
          </div>

          <div id="acl2Group" style="display:none">
            <select id="acl2Type" onchange="generate()">
              <option value="path_beg">Path commence par</option>
              <option value="hdr(host)" selected>Host header</option>
            </select>
            <input type="text" id="acl2Value" value="api.example.com" oninput="generate()">
            <label>Backend</label>
            <input type="text" id="acl2Backend" value="api_servers" oninput="generate()">
          </div>
        </div>
      </div>

      <!-- BACKEND TAB -->
      <div id="backend-tab" class="tab-content">
        <div class="form-group">
          <label>Nom du backend</label>
          <input type="text" id="backendName" value="web_servers" oninput="generate()">
        </div>

        <div class="form-group">
          <label>Mode</label>
          <select id="backendMode" onchange="generate()">
            <option value="http" selected>HTTP</option>
            <option value="tcp">TCP</option>
          </select>
        </div>

        <div class="form-group">
          <label>Algorithme de load balancing</label>
          <select id="balance" onchange="generate()">
            <option value="roundrobin" selected>Round Robin</option>
            <option value="leastconn">Least Connections</option>
            <option value="source">Source IP Hash</option>
            <option value="uri">URI Hash</option>
            <option value="first">First Available</option>
          </select>
        </div>

        <h4>Serveurs</h4>

        <div id="serversContainer">
          <div class="server-row">
            <input type="text" placeholder="Nom" value="server1" class="server-name" oninput="generate()">
            <input type="text" placeholder="IP:Port" value="192.168.1.10:8080" class="server-addr" oninput="generate()">
            <input type="text" placeholder="Options" value="check" class="server-opts" oninput="generate()">
          </div>
          <div class="server-row">
            <input type="text" placeholder="Nom" value="server2" class="server-name" oninput="generate()">
            <input type="text" placeholder="IP:Port" value="192.168.1.11:8080" class="server-addr" oninput="generate()">
            <input type="text" placeholder="Options" value="check" class="server-opts" oninput="generate()">
          </div>
          <div class="server-row">
            <input type="text" placeholder="Nom" value="server3" class="server-name" oninput="generate()">
            <input type="text" placeholder="IP:Port" value="192.168.1.12:8080" class="server-addr" oninput="generate()">
            <input type="text" placeholder="Options" value="check backup" class="server-opts" oninput="generate()">
          </div>
        </div>
        <button type="button" onclick="addServer()">+ Ajouter serveur</button>

        <h4>Health Check</h4>

        <div class="form-group">
          <label>Type de check</label>
          <select id="checkType" onchange="generate()">
            <option value="tcp">TCP Connect</option>
            <option value="http" selected>HTTP Request</option>
            <option value="mysql">MySQL</option>
            <option value="pgsql">PostgreSQL</option>
          </select>
        </div>

        <div class="form-group" id="httpCheckGroup">
          <label>HTTP check path</label>
          <input type="text" id="httpCheckPath" value="/health" oninput="generate()">
        </div>

        <div class="form-group">
          <label>Intervalle (secondes)</label>
          <input type="number" id="checkInterval" value="5" min="1" oninput="generate()">
        </div>

        <div class="form-group">
          <label>
            <input type="checkbox" id="cookieSticky" onchange="generate()">
            Session stickiness (cookie)
          </label>
        </div>

        <div class="form-group" id="cookieGroup" style="display:none">
          <label>Nom du cookie</label>
          <input type="text" id="cookieName" value="SERVERID" oninput="generate()">
        </div>
      </div>

      <!-- GLOBAL TAB -->
      <div id="global-tab" class="tab-content">
        <div class="form-group">
          <label>Max connections</label>
          <input type="number" id="maxconn" value="4096" oninput="generate()">
        </div>

        <div class="form-group">
          <label>Timeout connect (secondes)</label>
          <input type="number" id="timeoutConnect" value="5" oninput="generate()">
        </div>

        <div class="form-group">
          <label>Timeout client (secondes)</label>
          <input type="number" id="timeoutClient" value="50" oninput="generate()">
        </div>

        <div class="form-group">
          <label>Timeout server (secondes)</label>
          <input type="number" id="timeoutServer" value="50" oninput="generate()">
        </div>

        <div class="form-group">
          <label>
            <input type="checkbox" id="enableStats" onchange="generate()" checked>
            Activer page de stats
          </label>
        </div>

        <div id="statsGroup">
          <div class="form-group">
            <label>Stats URI</label>
            <input type="text" id="statsUri" value="/haproxy-stats" oninput="generate()">
          </div>
          <div class="form-group">
            <label>Stats auth (user:pass)</label>
            <input type="text" id="statsAuth" value="admin:secret" oninput="generate()">
          </div>
        </div>

        <div class="form-group">
          <label>Log facility</label>
          <select id="logFacility" onchange="generate()">
            <option value="local0" selected>local0</option>
            <option value="local1">local1</option>
            <option value="local2">local2</option>
          </select>
        </div>
      </div>

      <!-- SSL TAB -->
      <div id="ssl-tab" class="tab-content">
        <div class="form-group">
          <label>
            <input type="checkbox" id="enableSsl" onchange="generate()">
            Activer HTTPS frontend
          </label>
        </div>

        <div id="sslOptions" style="display:none">
          <div class="form-group">
            <label>Certificat (PEM)</label>
            <input type="text" id="sslCert" value="/etc/haproxy/certs/site.pem" oninput="generate()">
            <span class="hint">Fichier PEM contenant cert + key + chain</span>
          </div>

          <div class="form-group">
            <label>
              <input type="checkbox" id="httpRedirect" onchange="generate()" checked>
              Rediriger HTTP vers HTTPS
            </label>
          </div>

          <div class="form-group">
            <label>
              <input type="checkbox" id="hsts" onchange="generate()" checked>
              Activer HSTS
            </label>
          </div>

          <div class="form-group">
            <label>SSL Min Version</label>
            <select id="sslMinVer" onchange="generate()">
              <option value="TLSv1.2" selected>TLS 1.2</option>
              <option value="TLSv1.3">TLS 1.3</option>
            </select>
          </div>

          <div class="form-group">
            <label>Ciphers</label>
            <select id="sslCiphers" onchange="generate()">
              <option value="modern" selected>Modern (TLS 1.3 only)</option>
              <option value="intermediate">Intermediate</option>
              <option value="old">Old (legacy)</option>
            </select>
          </div>
        </div>

        <div class="form-group">
          <label>
            <input type="checkbox" id="backendSsl" onchange="generate()">
            SSL vers backend
          </label>
        </div>
      </div>
    </div>

    <div class="haproxy-section">
      <h3>Configuration generee</h3>
      <pre id="configOutput"># HAProxy config</pre>
      <button onclick="copyConfig()">Copier</button>
    </div>
  </div>

  <div class="presets-section">
    <h3>Presets courants</h3>
    <div class="presets-grid">
      <div class="preset-card" onclick="loadPreset('webhttp')">
        <h4>Web HTTP</h4>
        <p>Load balancer HTTP simple</p>
      </div>
      <div class="preset-card" onclick="loadPreset('webhttps')">
        <h4>Web HTTPS</h4>
        <p>SSL termination + redirect</p>
      </div>
      <div class="preset-card" onclick="loadPreset('api')">
        <h4>API Gateway</h4>
        <p>Routing par path/host</p>
      </div>
      <div class="preset-card" onclick="loadPreset('tcp')">
        <h4>TCP Proxy</h4>
        <p>Layer 4 (MySQL, etc.)</p>
      </div>
      <div class="preset-card" onclick="loadPreset('sticky')">
        <h4>Sticky Sessions</h4>
        <p>Affinite par cookie</p>
      </div>
      <div class="preset-card" onclick="loadPreset('k8s')">
        <h4>K8s Ingress</h4>
        <p>Multi-backend routing</p>
      </div>
    </div>
  </div>
</div>

<style>
.haproxy-container {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 20px;
}

@media (max-width: 900px) {
  .haproxy-container { grid-template-columns: 1fr; }
}

.haproxy-section, .presets-section {
  background: var(--md-code-bg-color);
  padding: 20px;
  border-radius: 8px;
  margin-bottom: 20px;
}

.config-tabs {
  display: flex;
  gap: 5px;
  margin-bottom: 20px;
  flex-wrap: wrap;
}

.tab-btn {
  padding: 8px 16px;
  border: 1px solid var(--md-default-fg-color--lightest);
  background: transparent;
  border-radius: 4px;
  cursor: pointer;
  color: var(--md-default-fg-color);
}

.tab-btn.active {
  background: var(--md-primary-fg-color);
  color: white;
}

.tab-content { display: none; }
.tab-content.active { display: block; }

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

.hint {
  font-size: 0.8em;
  color: var(--md-default-fg-color--light);
  display: block;
  margin-top: 4px;
}

.server-row {
  display: grid;
  grid-template-columns: 1fr 2fr 1fr;
  gap: 10px;
  margin-bottom: 10px;
}

.server-row input {
  padding: 8px;
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  background: var(--md-default-bg-color);
  color: var(--md-default-fg-color);
  font-family: monospace;
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

.haproxy-section button {
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
  grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
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
let currentTab = 'frontend';

function switchTab(tab) {
  currentTab = tab;
  document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
  event.target.classList.add('active');
  document.getElementById(tab + '-tab').classList.add('active');
}

function addServer() {
  const container = document.getElementById('serversContainer');
  const count = container.children.length + 1;
  const row = document.createElement('div');
  row.className = 'server-row';
  row.innerHTML = `
    <input type="text" placeholder="Nom" value="server${count}" class="server-name" oninput="generate()">
    <input type="text" placeholder="IP:Port" value="192.168.1.${10+count}:8080" class="server-addr" oninput="generate()">
    <input type="text" placeholder="Options" value="check" class="server-opts" oninput="generate()">
  `;
  container.appendChild(row);
  generate();
}

function generate() {
  // Visibility
  document.getElementById('aclGroup').style.display =
    document.getElementById('useAcl').checked ? 'block' : 'none';
  document.getElementById('acl2Group').style.display =
    document.getElementById('useAcl2').checked ? 'block' : 'none';
  document.getElementById('httpCheckGroup').style.display =
    document.getElementById('checkType').value === 'http' ? 'block' : 'none';
  document.getElementById('cookieGroup').style.display =
    document.getElementById('cookieSticky').checked ? 'block' : 'none';
  document.getElementById('statsGroup').style.display =
    document.getElementById('enableStats').checked ? 'block' : 'none';
  document.getElementById('sslOptions').style.display =
    document.getElementById('enableSsl').checked ? 'block' : 'none';
  document.getElementById('httpOptionsGroup').style.display =
    document.getElementById('frontendMode').value === 'http' ? 'block' : 'none';

  // Values
  const maxconn = document.getElementById('maxconn').value;
  const timeoutConnect = document.getElementById('timeoutConnect').value;
  const timeoutClient = document.getElementById('timeoutClient').value;
  const timeoutServer = document.getElementById('timeoutServer').value;
  const logFacility = document.getElementById('logFacility').value;

  const frontendName = document.getElementById('frontendName').value;
  const frontendBind = document.getElementById('frontendBind').value;
  const frontendMode = document.getElementById('frontendMode').value;
  const httpLog = document.getElementById('httpLog').checked;
  const forwardFor = document.getElementById('forwardFor').checked;
  const defaultBackend = document.getElementById('defaultBackend').value;

  const useAcl = document.getElementById('useAcl').checked;
  const acl1Type = document.getElementById('acl1Type').value;
  const acl1Value = document.getElementById('acl1Value').value;
  const acl1Backend = document.getElementById('acl1Backend').value;

  const backendName = document.getElementById('backendName').value;
  const backendMode = document.getElementById('backendMode').value;
  const balance = document.getElementById('balance').value;
  const checkType = document.getElementById('checkType').value;
  const httpCheckPath = document.getElementById('httpCheckPath').value;
  const checkInterval = document.getElementById('checkInterval').value;
  const cookieSticky = document.getElementById('cookieSticky').checked;
  const cookieName = document.getElementById('cookieName').value;

  const enableStats = document.getElementById('enableStats').checked;
  const statsUri = document.getElementById('statsUri').value;
  const statsAuth = document.getElementById('statsAuth').value;

  const enableSsl = document.getElementById('enableSsl').checked;
  const sslCert = document.getElementById('sslCert').value;
  const httpRedirect = document.getElementById('httpRedirect').checked;
  const hsts = document.getElementById('hsts').checked;
  const sslMinVer = document.getElementById('sslMinVer').value;
  const backendSsl = document.getElementById('backendSsl').checked;

  let config = `# HAProxy Configuration
# Genere par ShellBook HAProxy Generator

global
    log /dev/log ${logFacility}
    chroot /var/lib/haproxy
    stats socket /run/haproxy/admin.sock mode 660 level admin
    stats timeout 30s
    user haproxy
    group haproxy
    daemon
    maxconn ${maxconn}

defaults
    log     global
    mode    http
    option  httplog
    option  dontlognull
    timeout connect ${timeoutConnect}s
    timeout client  ${timeoutClient}s
    timeout server  ${timeoutServer}s
    errorfile 400 /etc/haproxy/errors/400.http
    errorfile 403 /etc/haproxy/errors/403.http
    errorfile 408 /etc/haproxy/errors/408.http
    errorfile 500 /etc/haproxy/errors/500.http
    errorfile 502 /etc/haproxy/errors/502.http
    errorfile 503 /etc/haproxy/errors/503.http
    errorfile 504 /etc/haproxy/errors/504.http

`;

  // Stats
  if (enableStats) {
    config += `# Stats page
listen stats
    bind *:8404
    stats enable
    stats uri ${statsUri}
    stats refresh 10s
    stats auth ${statsAuth}

`;
  }

  // HTTP redirect frontend if SSL enabled
  if (enableSsl && httpRedirect) {
    config += `# HTTP to HTTPS redirect
frontend http_redirect
    bind *:80
    mode http
    redirect scheme https code 301

`;
  }

  // Main frontend
  config += `# Frontend
frontend ${frontendName}
`;

  if (enableSsl) {
    config += `    bind *:443 ssl crt ${sslCert} alpn h2,http/1.1`;
    if (sslMinVer === 'TLSv1.3') {
      config += ` ssl-min-ver TLSv1.3`;
    }
    config += `\n`;
  } else {
    config += `    bind ${frontendBind}\n`;
  }

  config += `    mode ${frontendMode}\n`;

  if (frontendMode === 'http') {
    if (httpLog) config += `    option httplog\n`;
    if (forwardFor) config += `    option forwardfor\n`;
    if (enableSsl && hsts) {
      config += `    http-response set-header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"\n`;
    }
  }

  if (useAcl) {
    config += `\n    # ACL rules\n`;
    config += `    acl is_acl1 ${acl1Type} ${acl1Value}\n`;
    config += `    use_backend ${acl1Backend} if is_acl1\n`;

    if (document.getElementById('useAcl2').checked) {
      const acl2Type = document.getElementById('acl2Type').value;
      const acl2Value = document.getElementById('acl2Value').value;
      const acl2Backend = document.getElementById('acl2Backend').value;
      config += `    acl is_acl2 ${acl2Type} ${acl2Value}\n`;
      config += `    use_backend ${acl2Backend} if is_acl2\n`;
    }
  }

  config += `\n    default_backend ${defaultBackend}\n`;

  // Backend
  config += `
# Backend
backend ${backendName}
    mode ${backendMode}
    balance ${balance}
`;

  if (checkType === 'http' && backendMode === 'http') {
    config += `    option httpchk GET ${httpCheckPath}\n`;
  }

  if (cookieSticky && backendMode === 'http') {
    config += `    cookie ${cookieName} insert indirect nocache\n`;
  }

  // Servers
  const serverRows = document.querySelectorAll('.server-row');
  serverRows.forEach(row => {
    const name = row.querySelector('.server-name').value;
    const addr = row.querySelector('.server-addr').value;
    let opts = row.querySelector('.server-opts').value;

    if (name && addr) {
      if (checkType === 'http') {
        opts = opts.replace('check', `check inter ${checkInterval}s`);
      }
      if (cookieSticky) {
        opts += ` cookie ${name}`;
      }
      if (backendSsl) {
        opts += ` ssl verify none`;
      }
      config += `    server ${name} ${addr} ${opts}\n`;
    }
  });

  document.getElementById('configOutput').textContent = config;
}

function loadPreset(name) {
  switch(name) {
    case 'webhttp':
      document.getElementById('frontendMode').value = 'http';
      document.getElementById('enableSsl').checked = false;
      document.getElementById('useAcl').checked = false;
      document.getElementById('cookieSticky').checked = false;
      break;
    case 'webhttps':
      document.getElementById('frontendMode').value = 'http';
      document.getElementById('enableSsl').checked = true;
      document.getElementById('httpRedirect').checked = true;
      document.getElementById('hsts').checked = true;
      break;
    case 'api':
      document.getElementById('frontendMode').value = 'http';
      document.getElementById('useAcl').checked = true;
      document.getElementById('acl1Type').value = 'path_beg';
      document.getElementById('acl1Value').value = '/api';
      break;
    case 'tcp':
      document.getElementById('frontendMode').value = 'tcp';
      document.getElementById('backendMode').value = 'tcp';
      document.getElementById('checkType').value = 'tcp';
      document.getElementById('frontendBind').value = '*:3306';
      break;
    case 'sticky':
      document.getElementById('cookieSticky').checked = true;
      document.getElementById('balance').value = 'roundrobin';
      break;
    case 'k8s':
      document.getElementById('useAcl').checked = true;
      document.getElementById('acl1Type').value = 'hdr(host)';
      document.getElementById('acl1Value').value = 'app1.example.com';
      document.getElementById('useAcl2').checked = true;
      document.getElementById('acl2Type').value = 'hdr(host)';
      document.getElementById('acl2Value').value = 'app2.example.com';
      break;
  }
  generate();
}

function copyConfig() {
  const config = document.getElementById('configOutput').textContent;
  navigator.clipboard.writeText(config).then(() => {
    const btn = event.target;
    btn.textContent = 'Copie!';
    setTimeout(() => btn.textContent = 'Copier', 1500);
  });
}

generate();
</script>

---

## Commandes utiles

```bash
# Tester la configuration
haproxy -c -f /etc/haproxy/haproxy.cfg

# Recharger sans interruption
systemctl reload haproxy

# Stats en ligne de commande
echo "show stat" | socat stdio /run/haproxy/admin.sock

# Desactiver un serveur
echo "disable server backend/server1" | socat stdio /run/haproxy/admin.sock
```

---

## Voir aussi

- [Nginx Config Generator](nginx-generator.md)
- [SSL Certificate Checker](ssl-checker.md)
- [Systemd Unit Generator](systemd-generator.md)
