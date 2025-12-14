---
tags:
  - tools
  - nginx
  - web
  - config
---

# Nginx Config Generator

Generateur de configurations Nginx pour sites web et reverse proxy.

<div class="tool-container">

<div class="type-selector">
    <button class="type-btn active" onclick="selectType('static')">Site Statique</button>
    <button class="type-btn" onclick="selectType('proxy')">Reverse Proxy</button>
    <button class="type-btn" onclick="selectType('php')">PHP-FPM</button>
    <button class="type-btn" onclick="selectType('redirect')">Redirection</button>
</div>

<div class="generator-section">
    <h3>Configuration generale</h3>

    <div class="form-grid">
        <div class="form-group">
            <label for="server-name">Server Name (domaine)</label>
            <input type="text" id="server-name" placeholder="example.com www.example.com">
        </div>

        <div class="form-group">
            <label for="listen-port">Port</label>
            <input type="number" id="listen-port" value="80">
        </div>

        <div class="form-group">
            <label><input type="checkbox" id="enable-ssl"> Activer SSL/TLS</label>
        </div>

        <div class="form-group">
            <label><input type="checkbox" id="enable-http2"> HTTP/2</label>
        </div>
    </div>

    <div class="ssl-options" id="ssl-options" style="display:none;">
        <div class="form-grid">
            <div class="form-group">
                <label for="ssl-cert">Certificat SSL</label>
                <input type="text" id="ssl-cert" placeholder="/etc/letsencrypt/live/example.com/fullchain.pem">
            </div>
            <div class="form-group">
                <label for="ssl-key">Cle privee SSL</label>
                <input type="text" id="ssl-key" placeholder="/etc/letsencrypt/live/example.com/privkey.pem">
            </div>
            <div class="form-group">
                <label><input type="checkbox" id="ssl-redirect" checked> Rediriger HTTP vers HTTPS</label>
            </div>
            <div class="form-group">
                <label><input type="checkbox" id="ssl-hsts"> HSTS</label>
            </div>
        </div>
    </div>
</div>

<div class="generator-section" id="static-options">
    <h3>Site Statique</h3>
    <div class="form-grid">
        <div class="form-group">
            <label for="root-path">Document Root</label>
            <input type="text" id="root-path" placeholder="/var/www/html">
        </div>
        <div class="form-group">
            <label for="index-files">Index files</label>
            <input type="text" id="index-files" value="index.html index.htm">
        </div>
        <div class="form-group">
            <label><input type="checkbox" id="enable-gzip" checked> Compression Gzip</label>
        </div>
        <div class="form-group">
            <label><input type="checkbox" id="enable-cache"> Cache navigateur</label>
        </div>
    </div>
</div>

<div class="generator-section" id="proxy-options" style="display:none;">
    <h3>Reverse Proxy</h3>
    <div class="form-grid">
        <div class="form-group">
            <label for="proxy-pass">Backend URL</label>
            <input type="text" id="proxy-pass" placeholder="http://localhost:3000">
        </div>
        <div class="form-group">
            <label><input type="checkbox" id="proxy-websocket"> WebSocket support</label>
        </div>
        <div class="form-group">
            <label><input type="checkbox" id="proxy-headers" checked> Transmettre headers</label>
        </div>
        <div class="form-group">
            <label for="proxy-timeout">Timeout (secondes)</label>
            <input type="number" id="proxy-timeout" value="60">
        </div>
    </div>
</div>

<div class="generator-section" id="php-options" style="display:none;">
    <h3>PHP-FPM</h3>
    <div class="form-grid">
        <div class="form-group">
            <label for="php-root">Document Root</label>
            <input type="text" id="php-root" placeholder="/var/www/html">
        </div>
        <div class="form-group">
            <label for="php-socket">PHP-FPM Socket</label>
            <input type="text" id="php-socket" placeholder="unix:/run/php/php8.2-fpm.sock">
        </div>
        <div class="form-group">
            <label for="php-index">Index file</label>
            <input type="text" id="php-index" value="index.php">
        </div>
    </div>
</div>

<div class="generator-section" id="redirect-options" style="display:none;">
    <h3>Redirection</h3>
    <div class="form-grid">
        <div class="form-group">
            <label for="redirect-url">URL de destination</label>
            <input type="text" id="redirect-url" placeholder="https://www.example.com$request_uri">
        </div>
        <div class="form-group">
            <label for="redirect-code">Code HTTP</label>
            <select id="redirect-code">
                <option value="301">301 (Permanent)</option>
                <option value="302">302 (Temporaire)</option>
                <option value="307">307 (Temporaire, preserve methode)</option>
                <option value="308">308 (Permanent, preserve methode)</option>
            </select>
        </div>
    </div>
</div>

<div class="generator-section">
    <h3>Options supplementaires</h3>
    <div class="form-grid">
        <div class="form-group">
            <label><input type="checkbox" id="enable-logs" checked> Access/Error logs</label>
        </div>
        <div class="form-group">
            <label><input type="checkbox" id="security-headers"> Headers de securite</label>
        </div>
        <div class="form-group">
            <label><input type="checkbox" id="rate-limit"> Rate limiting</label>
        </div>
        <div class="form-group">
            <label for="client-max-body">Client Max Body Size</label>
            <input type="text" id="client-max-body" placeholder="10M">
        </div>
    </div>
</div>

<div class="output-section">
    <div class="output-header">
        <h3>Configuration generee</h3>
        <button onclick="copyOutput()" class="copy-btn">Copier</button>
    </div>
    <pre id="nginx-output" class="config-output"></pre>
</div>

<div class="install-section">
    <h3>Installation</h3>
    <pre id="install-commands"></pre>
</div>

</div>

## Emplacements fichiers

| Distro | Sites disponibles | Sites actives |
|--------|-------------------|---------------|
| **Debian/Ubuntu** | `/etc/nginx/sites-available/` | `/etc/nginx/sites-enabled/` |
| **RHEL/Rocky** | `/etc/nginx/conf.d/` | (meme dossier) |

## Commandes utiles

```bash
# Tester la configuration
sudo nginx -t

# Recharger nginx
sudo systemctl reload nginx

# Logs
tail -f /var/log/nginx/access.log
tail -f /var/log/nginx/error.log
```

<style>
.tool-container {
    background: var(--md-code-bg-color);
    padding: 20px;
    border-radius: 8px;
    margin: 20px 0;
}
.type-selector {
    display: flex;
    gap: 10px;
    margin-bottom: 20px;
    flex-wrap: wrap;
}
.type-btn {
    padding: 10px 20px;
    background: var(--md-default-bg-color);
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    cursor: pointer;
    font-size: 14px;
}
.type-btn.active {
    background: var(--md-primary-fg-color);
    color: white;
    border-color: var(--md-primary-fg-color);
}
.generator-section {
    background: var(--md-default-bg-color);
    padding: 20px;
    border-radius: 4px;
    margin-bottom: 20px;
}
.generator-section h3 {
    margin: 0 0 15px 0;
}
.form-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 15px;
}
.form-group {
    display: flex;
    flex-direction: column;
}
.form-group label {
    font-size: 12px;
    font-weight: bold;
    margin-bottom: 5px;
}
.form-group input[type="text"],
.form-group input[type="number"],
.form-group select {
    padding: 10px;
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    background: var(--md-code-bg-color);
    color: var(--md-default-fg-color);
    font-family: monospace;
}
.ssl-options {
    margin-top: 15px;
    padding: 15px;
    background: var(--md-code-bg-color);
    border-radius: 4px;
}
.output-section, .install-section {
    background: var(--md-default-bg-color);
    padding: 20px;
    border-radius: 4px;
    margin-bottom: 20px;
}
.output-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 10px;
}
.output-header h3 {
    margin: 0;
}
.copy-btn {
    padding: 8px 16px;
    background: var(--md-primary-fg-color);
    color: white;
    border: none;
    border-radius: 4px;
    cursor: pointer;
}
.config-output {
    background: var(--md-code-bg-color);
    padding: 15px;
    border-radius: 4px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 13px;
    overflow-x: auto;
    margin: 0;
    white-space: pre-wrap;
}
.install-section h3 {
    margin: 0 0 10px 0;
}
.install-section pre {
    background: var(--md-code-bg-color);
    padding: 15px;
    border-radius: 4px;
    font-size: 13px;
    margin: 0;
}
</style>

<script>
let currentType = 'static';

function selectType(type) {
    currentType = type;
    document.querySelectorAll('.type-btn').forEach(btn => btn.classList.remove('active'));
    event.target.classList.add('active');

    document.getElementById('static-options').style.display = type === 'static' ? 'block' : 'none';
    document.getElementById('proxy-options').style.display = type === 'proxy' ? 'block' : 'none';
    document.getElementById('php-options').style.display = type === 'php' ? 'block' : 'none';
    document.getElementById('redirect-options').style.display = type === 'redirect' ? 'block' : 'none';

    generateConfig();
}

function generateConfig() {
    const serverName = document.getElementById('server-name').value || 'example.com';
    const listenPort = document.getElementById('listen-port').value || '80';
    const enableSsl = document.getElementById('enable-ssl').checked;
    const enableHttp2 = document.getElementById('enable-http2').checked;
    const sslCert = document.getElementById('ssl-cert').value;
    const sslKey = document.getElementById('ssl-key').value;
    const sslRedirect = document.getElementById('ssl-redirect').checked;
    const sslHsts = document.getElementById('ssl-hsts').checked;
    const enableLogs = document.getElementById('enable-logs').checked;
    const securityHeaders = document.getElementById('security-headers').checked;
    const rateLimit = document.getElementById('rate-limit').checked;
    const clientMaxBody = document.getElementById('client-max-body').value;

    let config = '';

    // Rate limit zone (if enabled)
    if (rateLimit) {
        config += `# Rate limiting (add to http block)
limit_req_zone $binary_remote_addr zone=mylimit:10m rate=10r/s;

`;
    }

    // HTTP to HTTPS redirect
    if (enableSsl && sslRedirect) {
        config += `server {
    listen 80;
    listen [::]:80;
    server_name ${serverName};
    return 301 https://$server_name$request_uri;
}

`;
    }

    // Main server block
    config += `server {
    listen ${enableSsl ? '443 ssl' : listenPort}${enableHttp2 ? ' http2' : ''};
    listen [::]:${enableSsl ? '443 ssl' : listenPort}${enableHttp2 ? ' http2' : ''};
    server_name ${serverName};

`;

    // SSL configuration
    if (enableSsl) {
        config += `    # SSL Configuration
    ssl_certificate ${sslCert || '/etc/letsencrypt/live/' + serverName.split(' ')[0] + '/fullchain.pem'};
    ssl_certificate_key ${sslKey || '/etc/letsencrypt/live/' + serverName.split(' ')[0] + '/privkey.pem'};
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;

`;
        if (sslHsts) {
            config += `    # HSTS
    add_header Strict-Transport-Security "max-age=63072000" always;

`;
        }
    }

    // Logs
    if (enableLogs) {
        config += `    # Logs
    access_log /var/log/nginx/${serverName.split(' ')[0]}.access.log;
    error_log /var/log/nginx/${serverName.split(' ')[0]}.error.log;

`;
    }

    // Client max body
    if (clientMaxBody) {
        config += `    client_max_body_size ${clientMaxBody};

`;
    }

    // Security headers
    if (securityHeaders) {
        config += `    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

`;
    }

    // Rate limiting
    if (rateLimit) {
        config += `    # Rate limiting
    limit_req zone=mylimit burst=20 nodelay;

`;
    }

    // Type-specific configuration
    switch (currentType) {
        case 'static':
            const rootPath = document.getElementById('root-path').value || '/var/www/html';
            const indexFiles = document.getElementById('index-files').value || 'index.html';
            const enableGzip = document.getElementById('enable-gzip').checked;
            const enableCache = document.getElementById('enable-cache').checked;

            config += `    root ${rootPath};
    index ${indexFiles};

    location / {
        try_files $uri $uri/ =404;
    }

`;
            if (enableGzip) {
                config += `    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml;

`;
            }
            if (enableCache) {
                config += `    # Browser cache
    location ~* \\.(jpg|jpeg|png|gif|ico|css|js|woff2?)$ {
        expires 30d;
        add_header Cache-Control "public, immutable";
    }

`;
            }
            break;

        case 'proxy':
            const proxyPass = document.getElementById('proxy-pass').value || 'http://localhost:3000';
            const proxyWebsocket = document.getElementById('proxy-websocket').checked;
            const proxyHeaders = document.getElementById('proxy-headers').checked;
            const proxyTimeout = document.getElementById('proxy-timeout').value || '60';

            config += `    location / {
        proxy_pass ${proxyPass};
`;
            if (proxyHeaders) {
                config += `        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
`;
            }
            if (proxyWebsocket) {
                config += `        # WebSocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
`;
            }
            config += `        proxy_connect_timeout ${proxyTimeout}s;
        proxy_send_timeout ${proxyTimeout}s;
        proxy_read_timeout ${proxyTimeout}s;
    }

`;
            break;

        case 'php':
            const phpRoot = document.getElementById('php-root').value || '/var/www/html';
            const phpSocket = document.getElementById('php-socket').value || 'unix:/run/php/php8.2-fpm.sock';
            const phpIndex = document.getElementById('php-index').value || 'index.php';

            config += `    root ${phpRoot};
    index ${phpIndex};

    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }

    location ~ \\.php$ {
        fastcgi_pass ${phpSocket};
        fastcgi_param SCRIPT_FILENAME $realpath_root$fastcgi_script_name;
        include fastcgi_params;
        fastcgi_hide_header X-Powered-By;
    }

    location ~ /\\.(?!well-known).* {
        deny all;
    }

`;
            break;

        case 'redirect':
            const redirectUrl = document.getElementById('redirect-url').value || 'https://www.example.com$request_uri';
            const redirectCode = document.getElementById('redirect-code').value || '301';

            config += `    return ${redirectCode} ${redirectUrl};

`;
            break;
    }

    config += `}`;

    document.getElementById('nginx-output').textContent = config;

    // Install commands
    const domain = serverName.split(' ')[0];
    document.getElementById('install-commands').textContent = `# Sauvegarder la configuration
sudo nano /etc/nginx/sites-available/${domain}

# Activer le site (Debian/Ubuntu)
sudo ln -s /etc/nginx/sites-available/${domain} /etc/nginx/sites-enabled/

# Tester la configuration
sudo nginx -t

# Recharger nginx
sudo systemctl reload nginx`;
}

function copyOutput() {
    const output = document.getElementById('nginx-output').textContent;
    navigator.clipboard.writeText(output);

    const btn = document.querySelector('.copy-btn');
    btn.textContent = 'Copie!';
    setTimeout(() => { btn.textContent = 'Copier'; }, 1000);
}

// Toggle SSL options
document.getElementById('enable-ssl').addEventListener('change', function() {
    document.getElementById('ssl-options').style.display = this.checked ? 'block' : 'none';
    generateConfig();
});

// Event listeners for all inputs
document.querySelectorAll('.generator-section input, .generator-section select').forEach(el => {
    el.addEventListener('input', generateConfig);
    el.addEventListener('change', generateConfig);
});

// Initial generation
generateConfig();
</script>
