---
tags:
  - tools
  - proxy
  - squid
  - network
  - security
---

# Squid Proxy Config Generator

Generateur de configuration Squid Proxy avec ACLs, authentification et SSL Bump.

<div id="squid-app">
  <div class="squid-container">
    <div class="squid-section">
      <h3>Configuration de base</h3>

      <div class="form-group">
        <label>Port HTTP</label>
        <input type="number" id="httpPort" value="3128" min="1" max="65535" oninput="generate()">
      </div>

      <div class="form-group">
        <label>Mode proxy</label>
        <select id="proxyMode" onchange="updateMode(); generate()">
          <option value="forward">Forward Proxy (explicite)</option>
          <option value="transparent">Transparent Proxy (intercept)</option>
          <option value="intercept-ssl">SSL Intercepting (bump)</option>
        </select>
        <span class="hint" id="modeHint">Les clients doivent configurer le proxy manuellement</span>
      </div>

      <div class="form-group">
        <label>Hostname visible</label>
        <input type="text" id="visibleHostname" value="proxy.example.com" oninput="generate()">
      </div>

      <div class="form-group">
        <label>Email administrateur</label>
        <input type="text" id="adminEmail" value="admin@example.com" oninput="generate()">
      </div>

      <h4>Cache</h4>

      <div class="form-group">
        <label>Activer le cache disque</label>
        <select id="cacheEnabled" onchange="toggleCache(); generate()">
          <option value="yes">Oui</option>
          <option value="no">Non</option>
        </select>
      </div>

      <div id="cacheOptions">
        <div class="form-group">
          <label>Type de cache</label>
          <select id="cacheType" onchange="generate()">
            <option value="ufs">ufs (standard)</option>
            <option value="aufs" selected>aufs (async, recommande)</option>
            <option value="rock">rock (SSD optimise)</option>
          </select>
        </div>

        <div class="form-group">
          <label>Repertoire cache</label>
          <input type="text" id="cacheDir" value="/var/spool/squid" oninput="generate()">
        </div>

        <div class="form-row">
          <div class="form-group">
            <label>Taille cache (MB)</label>
            <input type="number" id="cacheSize" value="10000" min="100" oninput="generate()">
          </div>
          <div class="form-group">
            <label>Memory cache (MB)</label>
            <input type="number" id="memCache" value="256" min="8" oninput="generate()">
          </div>
        </div>

        <div class="form-row">
          <div class="form-group">
            <label>Max object size (MB)</label>
            <input type="number" id="maxObjSize" value="100" min="1" oninput="generate()">
          </div>
          <div class="form-group">
            <label>Min object size (KB)</label>
            <input type="number" id="minObjSize" value="0" min="0" oninput="generate()">
          </div>
        </div>
      </div>

      <h4>Reseaux autorises (ACL localnet)</h4>

      <div class="form-group">
        <label>Reseaux sources (un par ligne, CIDR)</label>
        <textarea id="allowedNetworks" rows="3" oninput="generate()">192.168.1.0/24
10.0.0.0/8</textarea>
      </div>

      <h4>Authentification</h4>

      <div class="form-group">
        <label>Type d'authentification</label>
        <select id="authType" onchange="updateAuth(); generate()">
          <option value="none">Aucune</option>
          <option value="basic">Basic (htpasswd)</option>
          <option value="ldap">LDAP</option>
          <option value="ntlm">NTLM (Active Directory)</option>
        </select>
      </div>

      <div id="authBasicOptions" class="auth-options" style="display:none;">
        <div class="form-group">
          <label>Fichier htpasswd</label>
          <input type="text" id="htpasswdFile" value="/etc/squid/passwd" oninput="generate()">
        </div>
        <div class="form-group">
          <label>Realm (message login)</label>
          <input type="text" id="authRealm" value="Squid Proxy Authentication" oninput="generate()">
        </div>
      </div>

      <div id="authLdapOptions" class="auth-options" style="display:none;">
        <div class="form-group">
          <label>Serveur LDAP</label>
          <input type="text" id="ldapServer" value="ldap://dc.example.com:389" oninput="generate()">
        </div>
        <div class="form-group">
          <label>Base DN</label>
          <input type="text" id="ldapBaseDn" value="ou=Users,dc=example,dc=com" oninput="generate()">
        </div>
        <div class="form-group">
          <label>Bind DN</label>
          <input type="text" id="ldapBindDn" value="cn=squid,ou=Services,dc=example,dc=com" oninput="generate()">
        </div>
        <div class="form-group">
          <label>Attribut utilisateur</label>
          <input type="text" id="ldapUserAttr" value="sAMAccountName" oninput="generate()">
        </div>
      </div>

      <div id="authNtlmOptions" class="auth-options" style="display:none;">
        <div class="form-group">
          <label>Domaine AD</label>
          <input type="text" id="ntlmDomain" value="EXAMPLE" oninput="generate()">
        </div>
        <div class="form-group">
          <label>Controleur de domaine</label>
          <input type="text" id="ntlmDc" value="dc.example.com" oninput="generate()">
        </div>
      </div>
    </div>

    <div class="squid-section">
      <h3>Filtrage & Securite</h3>

      <div class="form-group">
        <label>Ports autorises (Safe_ports)</label>
        <textarea id="safePorts" rows="2" oninput="generate()">80 21 443 70 210 280 488 591 777 1025-65535</textarea>
      </div>

      <div class="form-group">
        <label>Ports SSL autorises</label>
        <input type="text" id="sslPorts" value="443" oninput="generate()">
      </div>

      <h4>Filtrage de contenu</h4>

      <div class="form-group">
        <label>Domaines bloques (un par ligne)</label>
        <textarea id="blockedDomains" rows="3" placeholder="facebook.com&#10;youtube.com&#10;tiktok.com" oninput="generate()"></textarea>
      </div>

      <div class="form-group">
        <label>Domaines autorises uniquement (whitelist, vide = tout)</label>
        <textarea id="allowedDomains" rows="2" placeholder="example.com&#10;company.com" oninput="generate()"></textarea>
      </div>

      <div class="form-group">
        <label>Mots-cles bloques dans URL (un par ligne)</label>
        <textarea id="blockedKeywords" rows="2" placeholder="porn&#10;gambling&#10;torrent" oninput="generate()"></textarea>
      </div>

      <div id="sslBumpOptions" style="display:none;">
        <h4>SSL Bump (Interception HTTPS)</h4>

        <div class="form-group">
          <label>Certificat CA</label>
          <input type="text" id="sslCert" value="/etc/squid/ssl/squid-ca.pem" oninput="generate()">
        </div>

        <div class="form-group">
          <label>Mode SSL Bump</label>
          <select id="sslBumpMode" onchange="generate()">
            <option value="bump-all">Bump all (tout intercepter)</option>
            <option value="peek-splice" selected>Peek and splice (intelligent)</option>
            <option value="bump-server-first">Bump server-first</option>
          </select>
          <span class="hint">peek-splice: intercepte seulement si necessaire</span>
        </div>

        <div class="form-group">
          <label>Domaines a NE PAS intercepter (un par ligne)</label>
          <textarea id="sslNoBump" rows="2" placeholder="banking.com&#10;healthcare.gov" oninput="generate()"></textarea>
        </div>
      </div>

      <h4>Limites & Performance</h4>

      <div class="form-row">
        <div class="form-group">
          <label>Max connexions client</label>
          <input type="number" id="maxConn" value="1000" min="10" oninput="generate()">
        </div>
        <div class="form-group">
          <label>Timeout connexion (sec)</label>
          <input type="number" id="connTimeout" value="60" min="10" oninput="generate()">
        </div>
      </div>

      <div class="form-group">
        <label>Limite bande passante par client (0 = illimite, KB/s)</label>
        <input type="number" id="delayPool" value="0" min="0" oninput="generate()">
      </div>

      <h4>Logging</h4>

      <div class="form-group">
        <label>Format de log</label>
        <select id="logFormat" onchange="generate()">
          <option value="squid">squid (natif)</option>
          <option value="combined" selected>combined (Apache-like)</option>
          <option value="common">common</option>
          <option value="none">Desactive</option>
        </select>
      </div>

      <div class="form-group">
        <label>Fichier access.log</label>
        <input type="text" id="accessLog" value="/var/log/squid/access.log" oninput="generate()">
      </div>
    </div>
  </div>

  <div class="squid-section output-section">
    <h3>Configuration generee</h3>
    <div class="tabs">
      <button class="tab active" onclick="showTab('squid')">squid.conf</button>
      <button class="tab" onclick="showTab('commands')">Commandes</button>
      <button class="tab" onclick="showTab('client')">Config Client</button>
    </div>
    <pre id="configOutput"># squid.conf</pre>
    <button onclick="copyConfig()">Copier</button>
  </div>

  <div class="presets-section">
    <h3>Presets</h3>
    <div class="presets-grid">
      <div class="preset-card" onclick="loadPreset('basic')">
        <h4>Basic Forward</h4>
        <p>Proxy simple pour LAN</p>
      </div>
      <div class="preset-card" onclick="loadPreset('transparent')">
        <h4>Transparent</h4>
        <p>Sans config client</p>
      </div>
      <div class="preset-card" onclick="loadPreset('authenticated')">
        <h4>Authenticated</h4>
        <p>Avec login/password</p>
      </div>
      <div class="preset-card" onclick="loadPreset('filter')">
        <h4>Content Filter</h4>
        <p>Blocage sites</p>
      </div>
      <div class="preset-card" onclick="loadPreset('cache')">
        <h4>Caching Proxy</h4>
        <p>Cache agressif</p>
      </div>
      <div class="preset-card" onclick="loadPreset('sslbump')">
        <h4>SSL Intercept</h4>
        <p>Inspection HTTPS</p>
      </div>
    </div>
  </div>
</div>

<style>
.squid-container {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 20px;
}

@media (max-width: 1000px) {
  .squid-container { grid-template-columns: 1fr; }
}

.squid-section, .presets-section {
  background: var(--md-code-bg-color);
  padding: 20px;
  border-radius: 8px;
  margin-bottom: 20px;
}

.output-section {
  grid-column: 1 / -1;
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
  margin: 25px 0 15px 0;
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
  font-size: 0.9em;
}

.form-row {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 15px;
}

.hint {
  font-size: 0.8em;
  color: var(--md-default-fg-color--light);
  display: block;
  margin-top: 4px;
}

.tabs {
  display: flex;
  gap: 5px;
  margin-bottom: 15px;
}

.tab {
  padding: 8px 16px;
  border: none;
  background: var(--md-default-bg-color);
  color: var(--md-default-fg-color);
  border-radius: 4px 4px 0 0;
  cursor: pointer;
}

.tab.active {
  background: #1e1e1e;
  color: #d4d4d4;
}

#configOutput {
  background: #1e1e1e;
  color: #d4d4d4;
  padding: 15px;
  border-radius: 0 4px 4px 4px;
  font-size: 0.85em;
  overflow-x: auto;
  white-space: pre-wrap;
  min-height: 400px;
  max-height: 600px;
  overflow-y: auto;
}

.squid-section button {
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
  grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
  gap: 12px;
}

.preset-card {
  background: var(--md-default-bg-color);
  padding: 15px;
  border-radius: 6px;
  cursor: pointer;
  text-align: center;
  transition: transform 0.2s;
}

.preset-card:hover { transform: scale(1.03); }
.preset-card h4 { margin: 0 0 5px 0; font-size: 0.95em; }
.preset-card p { margin: 0; font-size: 0.8em; color: var(--md-default-fg-color--light); }

.auth-options {
  background: var(--md-default-bg-color);
  padding: 15px;
  border-radius: 4px;
  margin-top: 10px;
}
</style>

<script>
let currentTab = 'squid';

function updateMode() {
  const mode = document.getElementById('proxyMode').value;
  const hint = document.getElementById('modeHint');
  const sslOpts = document.getElementById('sslBumpOptions');

  switch(mode) {
    case 'forward':
      hint.textContent = 'Les clients doivent configurer le proxy manuellement';
      sslOpts.style.display = 'none';
      break;
    case 'transparent':
      hint.textContent = 'Necessite regles iptables pour rediriger le trafic';
      sslOpts.style.display = 'none';
      break;
    case 'intercept-ssl':
      hint.textContent = 'Intercepte HTTPS - necessite certificat CA sur les clients';
      sslOpts.style.display = 'block';
      break;
  }
}

function toggleCache() {
  const enabled = document.getElementById('cacheEnabled').value === 'yes';
  document.getElementById('cacheOptions').style.display = enabled ? 'block' : 'none';
}

function updateAuth() {
  const authType = document.getElementById('authType').value;
  document.querySelectorAll('.auth-options').forEach(el => el.style.display = 'none');

  if (authType === 'basic') {
    document.getElementById('authBasicOptions').style.display = 'block';
  } else if (authType === 'ldap') {
    document.getElementById('authLdapOptions').style.display = 'block';
  } else if (authType === 'ntlm') {
    document.getElementById('authNtlmOptions').style.display = 'block';
  }
}

function generate() {
  const config = generateSquidConf();
  const commands = generateCommands();
  const client = generateClientConfig();

  if (currentTab === 'squid') {
    document.getElementById('configOutput').textContent = config;
  } else if (currentTab === 'commands') {
    document.getElementById('configOutput').textContent = commands;
  } else {
    document.getElementById('configOutput').textContent = client;
  }
}

function generateSquidConf() {
  const httpPort = document.getElementById('httpPort').value;
  const proxyMode = document.getElementById('proxyMode').value;
  const visibleHostname = document.getElementById('visibleHostname').value;
  const adminEmail = document.getElementById('adminEmail').value;
  const cacheEnabled = document.getElementById('cacheEnabled').value === 'yes';
  const cacheType = document.getElementById('cacheType').value;
  const cacheDir = document.getElementById('cacheDir').value;
  const cacheSize = document.getElementById('cacheSize').value;
  const memCache = document.getElementById('memCache').value;
  const maxObjSize = document.getElementById('maxObjSize').value;
  const minObjSize = document.getElementById('minObjSize').value;
  const networks = document.getElementById('allowedNetworks').value.trim().split('\n').filter(n => n);
  const authType = document.getElementById('authType').value;
  const safePorts = document.getElementById('safePorts').value;
  const sslPorts = document.getElementById('sslPorts').value;
  const blockedDomains = document.getElementById('blockedDomains').value.trim().split('\n').filter(d => d);
  const allowedDomains = document.getElementById('allowedDomains').value.trim().split('\n').filter(d => d);
  const blockedKeywords = document.getElementById('blockedKeywords').value.trim().split('\n').filter(k => k);
  const maxConn = document.getElementById('maxConn').value;
  const connTimeout = document.getElementById('connTimeout').value;
  const delayPool = document.getElementById('delayPool').value;
  const logFormat = document.getElementById('logFormat').value;
  const accessLog = document.getElementById('accessLog').value;

  let conf = `# Squid Proxy Configuration
# Generated for Squid 5.x / 6.x
# File: /etc/squid/squid.conf

# ============================================
# NETWORK OPTIONS
# ============================================
`;

  // Port configuration based on mode
  if (proxyMode === 'forward') {
    conf += `http_port ${httpPort}\n`;
  } else if (proxyMode === 'transparent') {
    conf += `http_port ${httpPort} intercept\n`;
  } else if (proxyMode === 'intercept-ssl') {
    const sslCert = document.getElementById('sslCert').value;
    conf += `http_port ${httpPort} intercept\n`;
    conf += `https_port 3129 intercept ssl-bump \\
  cert=${sslCert} \\
  generate-host-certificates=on \\
  dynamic_cert_mem_cache_size=4MB\n`;
  }

  conf += `
visible_hostname ${visibleHostname}
cache_mgr ${adminEmail}

# ============================================
# CACHE OPTIONS
# ============================================
`;

  if (cacheEnabled) {
    conf += `cache_dir ${cacheType} ${cacheDir} ${cacheSize} 16 256
cache_mem ${memCache} MB
maximum_object_size ${maxObjSize} MB
minimum_object_size ${minObjSize} KB
cache_swap_low 90
cache_swap_high 95

# Refresh patterns
refresh_pattern ^ftp:           1440    20%     10080
refresh_pattern ^gopher:        1440    0%      1440
refresh_pattern -i (/cgi-bin/|\\?) 0     0%      0
refresh_pattern .               0       20%     4320
`;
  } else {
    conf += `cache deny all
`;
  }

  conf += `
# ============================================
# ACL DEFINITIONS
# ============================================
`;

  // Safe ports
  conf += `acl Safe_ports port ${safePorts}\n`;
  conf += `acl SSL_ports port ${sslPorts}\n`;
  conf += `acl CONNECT method CONNECT\n\n`;

  // Local networks
  networks.forEach((net, i) => {
    conf += `acl localnet src ${net}\n`;
  });
  conf += '\n';

  // Blocked domains
  if (blockedDomains.length > 0) {
    conf += `# Blocked domains\n`;
    blockedDomains.forEach((domain, i) => {
      conf += `acl blocked_domains dstdomain .${domain.replace(/^\./, '')}\n`;
    });
    conf += '\n';
  }

  // Allowed domains (whitelist)
  if (allowedDomains.length > 0) {
    conf += `# Allowed domains (whitelist mode)\n`;
    allowedDomains.forEach((domain, i) => {
      conf += `acl allowed_domains dstdomain .${domain.replace(/^\./, '')}\n`;
    });
    conf += '\n';
  }

  // Blocked keywords
  if (blockedKeywords.length > 0) {
    conf += `# Blocked URL keywords\n`;
    blockedKeywords.forEach((kw, i) => {
      conf += `acl blocked_keywords url_regex -i ${kw}\n`;
    });
    conf += '\n';
  }

  // Authentication
  if (authType !== 'none') {
    conf += `# ============================================
# AUTHENTICATION
# ============================================
`;
    if (authType === 'basic') {
      const htpasswdFile = document.getElementById('htpasswdFile').value;
      const authRealm = document.getElementById('authRealm').value;
      conf += `auth_param basic program /usr/lib/squid/basic_ncsa_auth ${htpasswdFile}
auth_param basic realm ${authRealm}
auth_param basic credentialsttl 2 hours
auth_param basic casesensitive on
acl authenticated proxy_auth REQUIRED
`;
    } else if (authType === 'ldap') {
      const ldapServer = document.getElementById('ldapServer').value;
      const ldapBaseDn = document.getElementById('ldapBaseDn').value;
      const ldapBindDn = document.getElementById('ldapBindDn').value;
      const ldapUserAttr = document.getElementById('ldapUserAttr').value;
      conf += `auth_param basic program /usr/lib/squid/basic_ldap_auth -v 3 \\
  -H ${ldapServer} \\
  -b "${ldapBaseDn}" \\
  -D "${ldapBindDn}" \\
  -W /etc/squid/ldap_password \\
  -f "(${ldapUserAttr}=%s)"
auth_param basic realm LDAP Authentication
auth_param basic credentialsttl 1 hour
acl authenticated proxy_auth REQUIRED
`;
    } else if (authType === 'ntlm') {
      const ntlmDomain = document.getElementById('ntlmDomain').value;
      const ntlmDc = document.getElementById('ntlmDc').value;
      conf += `auth_param ntlm program /usr/lib/squid/ntlm_smb_lm_auth \\
  ${ntlmDomain}/${ntlmDc}
auth_param ntlm children 10
auth_param ntlm keep_alive on
acl authenticated proxy_auth REQUIRED
`;
    }
    conf += '\n';
  }

  // SSL Bump
  if (proxyMode === 'intercept-ssl') {
    const sslBumpMode = document.getElementById('sslBumpMode').value;
    const sslNoBump = document.getElementById('sslNoBump').value.trim().split('\n').filter(d => d);

    conf += `# ============================================
# SSL BUMP (HTTPS INTERCEPTION)
# ============================================
acl step1 at_step SslBump1
acl step2 at_step SslBump2
acl step3 at_step SslBump3

`;
    if (sslNoBump.length > 0) {
      sslNoBump.forEach(domain => {
        conf += `acl no_ssl_bump ssl::server_name .${domain.replace(/^\./, '')}\n`;
      });
      conf += '\n';
    }

    if (sslBumpMode === 'bump-all') {
      conf += `ssl_bump bump all\n`;
    } else if (sslBumpMode === 'peek-splice') {
      conf += `ssl_bump peek step1 all\n`;
      if (sslNoBump.length > 0) {
        conf += `ssl_bump splice no_ssl_bump\n`;
      }
      conf += `ssl_bump bump all\n`;
    } else {
      conf += `ssl_bump server-first all\n`;
    }
    conf += `
sslcrtd_program /usr/lib/squid/security_file_certgen \\
  -s /var/lib/squid/ssl_db -M 4MB
sslcrtd_children 5
ssl_bump stare step2 all
`;
  }

  conf += `
# ============================================
# ACCESS RULES
# ============================================
# Deny requests to non-safe ports
http_access deny !Safe_ports

# Deny CONNECT to non-SSL ports
http_access deny CONNECT !SSL_ports

# Allow localhost
http_access allow localhost manager
http_access deny manager

# Allow localhost
http_access allow localhost

`;

  // Blocked content
  if (blockedDomains.length > 0) {
    conf += `# Block specific domains\nhttp_access deny blocked_domains\n\n`;
  }
  if (blockedKeywords.length > 0) {
    conf += `# Block URLs with keywords\nhttp_access deny blocked_keywords\n\n`;
  }

  // Whitelist mode
  if (allowedDomains.length > 0) {
    conf += `# Whitelist mode - only allow specific domains\n`;
    if (authType !== 'none') {
      conf += `http_access allow authenticated allowed_domains\n`;
    } else {
      conf += `http_access allow localnet allowed_domains\n`;
    }
    conf += `http_access deny all\n`;
  } else {
    // Normal mode
    if (authType !== 'none') {
      conf += `# Require authentication for local networks\nhttp_access allow authenticated\n`;
    } else {
      conf += `# Allow local networks\nhttp_access allow localnet\n`;
    }
    conf += `\n# Deny everything else\nhttp_access deny all\n`;
  }

  // Performance
  conf += `
# ============================================
# PERFORMANCE & LIMITS
# ============================================
max_filedescriptors ${maxConn}
client_lifetime ${connTimeout} seconds
connect_timeout 30 seconds
read_timeout 15 minutes
request_timeout 5 minutes
`;

  // Delay pools (bandwidth limiting)
  if (parseInt(delayPool) > 0) {
    conf += `
# Bandwidth limiting
delay_pools 1
delay_class 1 2
delay_parameters 1 -1/-1 ${delayPool * 1024}/${delayPool * 2048}
delay_access 1 allow localnet
`;
  }

  // Logging
  conf += `
# ============================================
# LOGGING
# ============================================
`;
  if (logFormat === 'none') {
    conf += `access_log none\n`;
  } else {
    conf += `access_log daemon:${accessLog} ${logFormat}\n`;
  }
  conf += `cache_log /var/log/squid/cache.log
cache_store_log none

# Log rotation
logfile_rotate 7

# ============================================
# PRIVACY & SECURITY
# ============================================
forwarded_for delete
via off
request_header_access X-Forwarded-For deny all
request_header_access Via deny all

# Disable ICP
icp_port 0

# Disable HTCP
htcp_port 0

# Error pages
error_directory /usr/share/squid/errors/en
`;

  return conf;
}

function generateCommands() {
  const proxyMode = document.getElementById('proxyMode').value;
  const httpPort = document.getElementById('httpPort').value;
  const cacheDir = document.getElementById('cacheDir').value;
  const authType = document.getElementById('authType').value;

  let cmd = `# ============================================
# INSTALLATION
# ============================================

# Debian/Ubuntu
apt update && apt install -y squid

# RHEL/Rocky/AlmaLinux
dnf install -y squid

# ============================================
# CONFIGURATION
# ============================================

# Backup original config
cp /etc/squid/squid.conf /etc/squid/squid.conf.bak

# Copy generated config
# (paste generated config to /etc/squid/squid.conf)

# Verify configuration syntax
squid -k parse

# Initialize cache directory
squid -z

# ============================================
# SERVICE MANAGEMENT
# ============================================

# Start service
systemctl start squid
systemctl enable squid

# Check status
systemctl status squid

# Reload configuration (without restart)
squid -k reconfigure

# Graceful shutdown
squid -k shutdown

# ============================================
# LOGS & DEBUGGING
# ============================================

# Watch access log
tail -f /var/log/squid/access.log

# Watch cache log
tail -f /var/log/squid/cache.log

# Check cache stats
squidclient -h localhost mgr:info

# List active connections
squidclient -h localhost mgr:active_requests
`;

  if (proxyMode === 'transparent') {
    cmd += `
# ============================================
# IPTABLES RULES (Transparent Proxy)
# ============================================

# Redirect HTTP traffic to Squid
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j REDIRECT --to-port ${httpPort}

# Allow forwarding
iptables -A FORWARD -p tcp --dport 80 -j ACCEPT

# Save rules
iptables-save > /etc/iptables.rules

# Enable IP forwarding
echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
sysctl -p
`;
  }

  if (proxyMode === 'intercept-ssl') {
    const sslCert = document.getElementById('sslCert').value;
    const certDir = sslCert.substring(0, sslCert.lastIndexOf('/'));
    cmd += `
# ============================================
# SSL BUMP SETUP
# ============================================

# Create SSL directory
mkdir -p ${certDir}

# Generate CA certificate
openssl req -new -newkey rsa:2048 -sha256 -days 3650 -nodes -x509 \\
  -keyout ${certDir}/squid-ca-key.pem \\
  -out ${certDir}/squid-ca-cert.pem \\
  -subj "/C=FR/ST=IDF/L=Paris/O=Company/CN=Squid CA"

# Combine key and cert
cat ${certDir}/squid-ca-key.pem ${certDir}/squid-ca-cert.pem > ${sslCert}

# Set permissions
chown squid:squid ${certDir}/*
chmod 400 ${certDir}/*.pem

# Initialize SSL certificate database
/usr/lib/squid/security_file_certgen -c -s /var/lib/squid/ssl_db -M 4MB
chown -R squid:squid /var/lib/squid/ssl_db

# Convert CA cert for client distribution (DER format)
openssl x509 -in ${certDir}/squid-ca-cert.pem -outform DER -out ${certDir}/squid-ca.crt

# IPTABLES for HTTPS interception
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 443 -j REDIRECT --to-port 3129
`;
  }

  if (authType === 'basic') {
    const htpasswdFile = document.getElementById('htpasswdFile').value;
    cmd += `
# ============================================
# BASIC AUTHENTICATION SETUP
# ============================================

# Install apache2-utils for htpasswd
apt install -y apache2-utils   # Debian/Ubuntu
# dnf install -y httpd-tools   # RHEL/Rocky

# Create password file and first user
htpasswd -c ${htpasswdFile} admin

# Add additional users
htpasswd ${htpasswdFile} user2

# Set permissions
chown squid:squid ${htpasswdFile}
chmod 640 ${htpasswdFile}
`;
  }

  cmd += `
# ============================================
# FIREWALL
# ============================================

# UFW
ufw allow ${httpPort}/tcp comment "Squid Proxy"

# firewalld
firewall-cmd --permanent --add-port=${httpPort}/tcp
firewall-cmd --reload

# ============================================
# TROUBLESHOOTING
# ============================================

# Test connectivity
curl -x http://localhost:${httpPort} http://example.com

# Check listening ports
ss -tlnp | grep squid

# Check open file descriptors
ls -la /proc/$(pidof squid)/fd | wc -l

# Analyze access log
cat /var/log/squid/access.log | awk '{print $4}' | sort | uniq -c | sort -rn | head
`;

  return cmd;
}

function generateClientConfig() {
  const httpPort = document.getElementById('httpPort').value;
  const visibleHostname = document.getElementById('visibleHostname').value;
  const proxyMode = document.getElementById('proxyMode').value;
  const authType = document.getElementById('authType').value;

  let conf = `# ============================================
# CLIENT CONFIGURATION
# ============================================
`;

  if (proxyMode === 'transparent') {
    conf += `
# Transparent proxy - NO client configuration needed
# Traffic is automatically redirected via iptables/firewall rules
# Ensure clients use the proxy server as their default gateway
`;
  } else {
    conf += `
# Proxy Server: ${visibleHostname}
# Proxy Port: ${httpPort}

# ============================================
# LINUX - Environment Variables
# ============================================

# Add to ~/.bashrc or /etc/environment
export http_proxy="http://${visibleHostname}:${httpPort}"
export https_proxy="http://${visibleHostname}:${httpPort}"
export ftp_proxy="http://${visibleHostname}:${httpPort}"
export no_proxy="localhost,127.0.0.1,::1,.local"

# For sudo to keep proxy settings
# Add to /etc/sudoers.d/proxy:
Defaults env_keep += "http_proxy https_proxy ftp_proxy no_proxy"
`;

    if (authType !== 'none') {
      conf += `
# With authentication
export http_proxy="http://username:password@${visibleHostname}:${httpPort}"
export https_proxy="http://username:password@${visibleHostname}:${httpPort}"
`;
    }

    conf += `
# ============================================
# APT (Debian/Ubuntu)
# ============================================

# /etc/apt/apt.conf.d/proxy.conf
Acquire::http::Proxy "http://${visibleHostname}:${httpPort}";
Acquire::https::Proxy "http://${visibleHostname}:${httpPort}";

# ============================================
# YUM/DNF (RHEL/Rocky)
# ============================================

# /etc/yum.conf or /etc/dnf/dnf.conf
proxy=http://${visibleHostname}:${httpPort}
`;

    if (authType !== 'none') {
      conf += `proxy_username=username
proxy_password=password
`;
    }

    conf += `
# ============================================
# WGET
# ============================================

# ~/.wgetrc
http_proxy = http://${visibleHostname}:${httpPort}
https_proxy = http://${visibleHostname}:${httpPort}
use_proxy = on

# ============================================
# CURL
# ============================================

# ~/.curlrc
proxy = "http://${visibleHostname}:${httpPort}"

# Or command line
curl -x http://${visibleHostname}:${httpPort} https://example.com

# ============================================
# GIT
# ============================================

git config --global http.proxy http://${visibleHostname}:${httpPort}
git config --global https.proxy http://${visibleHostname}:${httpPort}

# Remove proxy
git config --global --unset http.proxy
git config --global --unset https.proxy

# ============================================
# NPM
# ============================================

npm config set proxy http://${visibleHostname}:${httpPort}
npm config set https-proxy http://${visibleHostname}:${httpPort}

# ============================================
# DOCKER
# ============================================

# /etc/systemd/system/docker.service.d/http-proxy.conf
[Service]
Environment="HTTP_PROXY=http://${visibleHostname}:${httpPort}"
Environment="HTTPS_PROXY=http://${visibleHostname}:${httpPort}"
Environment="NO_PROXY=localhost,127.0.0.1"

# Then reload
systemctl daemon-reload
systemctl restart docker

# ============================================
# WINDOWS - PowerShell
# ============================================

# Set proxy for current session
$env:HTTP_PROXY = "http://${visibleHostname}:${httpPort}"
$env:HTTPS_PROXY = "http://${visibleHostname}:${httpPort}"

# Set system proxy via netsh
netsh winhttp set proxy ${visibleHostname}:${httpPort}

# Set IE/Edge proxy (affects many apps)
Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -Name ProxyEnable -Value 1
Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -Name ProxyServer -Value "${visibleHostname}:${httpPort}"

# ============================================
# WINDOWS - GPO (Group Policy)
# ============================================

# User Configuration > Preferences > Windows Settings > Registry
# HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings
# ProxyEnable = 1 (DWORD)
# ProxyServer = ${visibleHostname}:${httpPort} (String)

# Or use PAC file
# ProxyEnable = 1
# AutoConfigURL = http://${visibleHostname}/proxy.pac
`;
  }

  if (proxyMode === 'intercept-ssl') {
    conf += `
# ============================================
# SSL CA CERTIFICATE INSTALLATION
# ============================================

# Download CA certificate from proxy server
# File: squid-ca.crt (DER format) or squid-ca-cert.pem (PEM format)

# LINUX - System-wide (Debian/Ubuntu)
cp squid-ca.crt /usr/local/share/ca-certificates/squid-ca.crt
update-ca-certificates

# LINUX - System-wide (RHEL/Rocky)
cp squid-ca.crt /etc/pki/ca-trust/source/anchors/
update-ca-trust

# WINDOWS - certutil
certutil -addstore -f "ROOT" squid-ca.crt

# WINDOWS - PowerShell
Import-Certificate -FilePath squid-ca.crt -CertStoreLocation Cert:\\LocalMachine\\Root

# FIREFOX (uses its own cert store)
# Settings > Privacy & Security > Certificates > View Certificates > Import

# CHROME (uses system store on Windows/Mac, NSS on Linux)
# Linux: certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n "Squid CA" -i squid-ca.crt
`;
  }

  return conf;
}

function showTab(tab) {
  currentTab = tab;
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  event.target.classList.add('active');
  generate();
}

function loadPreset(name) {
  const presets = {
    basic: {
      httpPort: 3128,
      proxyMode: 'forward',
      cacheEnabled: 'yes',
      cacheSize: 5000,
      memCache: 256,
      authType: 'none',
      blockedDomains: '',
      allowedDomains: '',
      delayPool: 0
    },
    transparent: {
      httpPort: 3128,
      proxyMode: 'transparent',
      cacheEnabled: 'yes',
      cacheSize: 10000,
      memCache: 512,
      authType: 'none',
      blockedDomains: '',
      allowedDomains: '',
      delayPool: 0
    },
    authenticated: {
      httpPort: 3128,
      proxyMode: 'forward',
      cacheEnabled: 'yes',
      cacheSize: 5000,
      memCache: 256,
      authType: 'basic',
      blockedDomains: '',
      allowedDomains: '',
      delayPool: 0
    },
    filter: {
      httpPort: 3128,
      proxyMode: 'forward',
      cacheEnabled: 'no',
      cacheSize: 1000,
      memCache: 64,
      authType: 'none',
      blockedDomains: 'facebook.com\nyoutube.com\ntiktok.com\ntwitter.com\ninstagram.com',
      blockedKeywords: 'porn\ngambling\ntorrent\nwarez',
      allowedDomains: '',
      delayPool: 0
    },
    cache: {
      httpPort: 3128,
      proxyMode: 'forward',
      cacheEnabled: 'yes',
      cacheSize: 50000,
      memCache: 1024,
      maxObjSize: 500,
      authType: 'none',
      blockedDomains: '',
      allowedDomains: '',
      delayPool: 0
    },
    sslbump: {
      httpPort: 3128,
      proxyMode: 'intercept-ssl',
      cacheEnabled: 'yes',
      cacheSize: 10000,
      memCache: 512,
      authType: 'none',
      blockedDomains: '',
      allowedDomains: '',
      sslBumpMode: 'peek-splice',
      sslNoBump: 'banking.com\nhealthcare.gov\npaypal.com',
      delayPool: 0
    }
  };

  const p = presets[name];
  if (p) {
    document.getElementById('httpPort').value = p.httpPort;
    document.getElementById('proxyMode').value = p.proxyMode;
    document.getElementById('cacheEnabled').value = p.cacheEnabled;
    document.getElementById('cacheSize').value = p.cacheSize;
    document.getElementById('memCache').value = p.memCache;
    if (p.maxObjSize) document.getElementById('maxObjSize').value = p.maxObjSize;
    document.getElementById('authType').value = p.authType;
    document.getElementById('blockedDomains').value = p.blockedDomains || '';
    if (p.blockedKeywords) document.getElementById('blockedKeywords').value = p.blockedKeywords;
    document.getElementById('allowedDomains').value = p.allowedDomains || '';
    document.getElementById('delayPool').value = p.delayPool;
    if (p.sslBumpMode) document.getElementById('sslBumpMode').value = p.sslBumpMode;
    if (p.sslNoBump) document.getElementById('sslNoBump').value = p.sslNoBump;

    updateMode();
    toggleCache();
    updateAuth();
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

// Initialize
document.addEventListener('DOMContentLoaded', function() {
  updateMode();
  toggleCache();
  updateAuth();
  generate();
});

generate();
</script>

---

## Architecture Squid

```
                    ┌─────────────────────────────────────┐
                    │           SQUID PROXY               │
                    │                                     │
  Clients           │  ┌─────────┐    ┌──────────────┐   │    Internet
  ───────────────►  │  │  ACLs   │───►│    Cache     │   │  ───────────►
  HTTP/HTTPS        │  └─────────┘    └──────────────┘   │
                    │       │                │            │
                    │       ▼                ▼            │
                    │  ┌─────────┐    ┌──────────────┐   │
                    │  │  Auth   │    │   Logging    │   │
                    │  └─────────┘    └──────────────┘   │
                    └─────────────────────────────────────┘
```

## Modes de fonctionnement

| Mode | Description | Config client |
|------|-------------|---------------|
| **Forward** | Proxy explicite | Oui (manuel ou PAC) |
| **Transparent** | Interception HTTP | Non (iptables) |
| **SSL Bump** | Interception HTTPS | Cert CA requis |

---

## Voir aussi

- [HAProxy Config Generator](haproxy-generator.md)
- [Nginx Config Generator](nginx-generator.md)
- [Iptables Generator](iptables-generator.md)
- [nftables Generator](nftables-generator.md)
