---
tags:
  - tools
  - security
  - cors
  - web
---

# CORS Builder

Générateur de configuration CORS (Cross-Origin Resource Sharing) pour vos APIs.

<div id="cors-builder">
  <style>
    #cors-builder {
      font-family: inherit;
    }
    #cors-builder .builder-container {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 20px;
    }
    @media (max-width: 900px) {
      #cors-builder .builder-container {
        grid-template-columns: 1fr;
      }
    }
    #cors-builder .config-section {
      background: var(--md-code-bg-color);
      border-radius: 8px;
      padding: 20px;
    }
    #cors-builder .output-section {
      background: var(--md-code-bg-color);
      border-radius: 8px;
      padding: 20px;
    }
    #cors-builder .section-title {
      font-size: 14px;
      font-weight: 600;
      margin: 20px 0 10px 0;
      padding-bottom: 5px;
      border-bottom: 1px solid var(--md-default-fg-color--lighter);
    }
    #cors-builder .section-title:first-child {
      margin-top: 0;
    }
    #cors-builder .form-group {
      margin-bottom: 15px;
    }
    #cors-builder label {
      display: block;
      margin-bottom: 5px;
      font-weight: 500;
      font-size: 13px;
    }
    #cors-builder input[type="text"],
    #cors-builder input[type="number"],
    #cors-builder select {
      width: 100%;
      padding: 8px 12px;
      border: 1px solid var(--md-default-fg-color--lighter);
      border-radius: 4px;
      background: var(--md-default-bg-color);
      color: var(--md-default-fg-color);
      font-size: 14px;
      box-sizing: border-box;
    }
    #cors-builder .checkbox-group {
      display: grid;
      grid-template-columns: repeat(2, 1fr);
      gap: 8px;
    }
    #cors-builder .checkbox-item {
      display: flex;
      align-items: center;
      gap: 8px;
    }
    #cors-builder .checkbox-item input {
      margin: 0;
    }
    #cors-builder .presets {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-bottom: 20px;
    }
    #cors-builder .preset-btn {
      padding: 6px 12px;
      border: 1px solid var(--md-primary-fg-color);
      background: transparent;
      color: var(--md-primary-fg-color);
      border-radius: 4px;
      cursor: pointer;
      font-size: 12px;
    }
    #cors-builder .preset-btn:hover {
      background: var(--md-primary-fg-color);
      color: white;
    }
    #cors-builder .origin-list {
      margin-top: 10px;
    }
    #cors-builder .origin-item {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 6px 10px;
      background: var(--md-default-bg-color);
      border-radius: 4px;
      margin-bottom: 5px;
      font-family: monospace;
      font-size: 12px;
    }
    #cors-builder .origin-item button {
      background: #e74c3c;
      color: white;
      border: none;
      border-radius: 4px;
      padding: 2px 8px;
      cursor: pointer;
      font-size: 11px;
    }
    #cors-builder .add-input {
      display: flex;
      gap: 8px;
    }
    #cors-builder .add-input input {
      flex: 1;
    }
    #cors-builder .add-input button {
      padding: 8px 16px;
      background: var(--md-primary-fg-color);
      color: white;
      border: none;
      border-radius: 4px;
      cursor: pointer;
    }
    #cors-builder .format-tabs {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-bottom: 15px;
    }
    #cors-builder .format-tab {
      padding: 6px 12px;
      border: 1px solid var(--md-default-fg-color--lighter);
      background: var(--md-default-bg-color);
      color: var(--md-default-fg-color);
      border-radius: 4px;
      cursor: pointer;
      font-size: 12px;
    }
    #cors-builder .format-tab.active {
      background: var(--md-primary-fg-color);
      border-color: var(--md-primary-fg-color);
      color: white;
    }
    #cors-builder .output-box {
      background: var(--md-default-bg-color);
      border: 1px solid var(--md-default-fg-color--lighter);
      border-radius: 4px;
      padding: 15px;
      font-family: 'Consolas', 'Monaco', monospace;
      font-size: 12px;
      white-space: pre-wrap;
      overflow-x: auto;
      min-height: 200px;
      max-height: 400px;
      overflow-y: auto;
    }
    #cors-builder .actions {
      display: flex;
      gap: 10px;
      margin-top: 15px;
    }
    #cors-builder .btn {
      padding: 8px 16px;
      border: none;
      border-radius: 4px;
      cursor: pointer;
      font-size: 14px;
    }
    #cors-builder .btn-primary {
      background: var(--md-primary-fg-color);
      color: white;
    }
    #cors-builder .warning-box {
      background: #fff3cd;
      border: 1px solid #ffc107;
      border-radius: 4px;
      padding: 10px;
      margin-top: 15px;
      font-size: 12px;
      color: #856404;
    }
    #cors-builder .info-box {
      background: var(--md-admonition-bg-color);
      border-left: 3px solid var(--md-primary-fg-color);
      padding: 10px;
      margin-top: 15px;
      font-size: 12px;
    }
  </style>

  <div class="presets">
    <button class="preset-btn" onclick="loadCORSPreset('dev')">🔧 Développement</button>
    <button class="preset-btn" onclick="loadCORSPreset('strict')">🔒 Strict</button>
    <button class="preset-btn" onclick="loadCORSPreset('public-api')">🌐 API Publique</button>
    <button class="preset-btn" onclick="loadCORSPreset('spa')">⚛️ SPA</button>
    <button class="preset-btn" onclick="loadCORSPreset('microservices')">🔗 Microservices</button>
  </div>

  <div class="builder-container">
    <div class="config-section">
      <div class="section-title">🌍 Origins autorisées</div>

      <div class="form-group">
        <label>
          <input type="checkbox" id="cors-allow-all" onchange="toggleAllOrigins()">
          Autoriser toutes les origines (*)
        </label>
      </div>

      <div id="origins-config">
        <div class="add-input">
          <input type="text" id="new-origin" placeholder="https://example.com">
          <button onclick="addOrigin()">Ajouter</button>
        </div>
        <div class="origin-list" id="origins-list"></div>
      </div>

      <div class="section-title">📨 Méthodes HTTP</div>
      <div class="checkbox-group">
        <label class="checkbox-item"><input type="checkbox" id="method-GET" checked> GET</label>
        <label class="checkbox-item"><input type="checkbox" id="method-POST" checked> POST</label>
        <label class="checkbox-item"><input type="checkbox" id="method-PUT" checked> PUT</label>
        <label class="checkbox-item"><input type="checkbox" id="method-DELETE" checked> DELETE</label>
        <label class="checkbox-item"><input type="checkbox" id="method-PATCH"> PATCH</label>
        <label class="checkbox-item"><input type="checkbox" id="method-OPTIONS" checked> OPTIONS</label>
        <label class="checkbox-item"><input type="checkbox" id="method-HEAD"> HEAD</label>
      </div>

      <div class="section-title">📋 Headers autorisés</div>
      <div class="checkbox-group">
        <label class="checkbox-item"><input type="checkbox" id="header-content-type" checked> Content-Type</label>
        <label class="checkbox-item"><input type="checkbox" id="header-authorization" checked> Authorization</label>
        <label class="checkbox-item"><input type="checkbox" id="header-accept" checked> Accept</label>
        <label class="checkbox-item"><input type="checkbox" id="header-origin"> Origin</label>
        <label class="checkbox-item"><input type="checkbox" id="header-x-requested-with"> X-Requested-With</label>
        <label class="checkbox-item"><input type="checkbox" id="header-x-api-key"> X-API-Key</label>
      </div>

      <div class="form-group" style="margin-top: 10px;">
        <label for="custom-headers">Headers personnalisés (séparés par virgule)</label>
        <input type="text" id="custom-headers" placeholder="X-Custom-Header, X-Another-Header">
      </div>

      <div class="section-title">📤 Headers exposés</div>
      <div class="form-group">
        <label for="exposed-headers">Headers visibles par le client</label>
        <input type="text" id="exposed-headers" placeholder="X-Total-Count, X-Page, Link">
      </div>

      <div class="section-title">⚙️ Options avancées</div>

      <div class="form-group">
        <label>
          <input type="checkbox" id="cors-credentials">
          Autoriser credentials (cookies, auth headers)
        </label>
      </div>

      <div class="form-group">
        <label for="cors-max-age">Max-Age (secondes) - Cache preflight</label>
        <input type="number" id="cors-max-age" value="86400" min="0">
      </div>
    </div>

    <div class="output-section">
      <div class="section-title">Configuration générée</div>

      <div class="format-tabs">
        <button class="format-tab active" onclick="setOutputFormat('headers')">Headers</button>
        <button class="format-tab" onclick="setOutputFormat('nginx')">Nginx</button>
        <button class="format-tab" onclick="setOutputFormat('apache')">Apache</button>
        <button class="format-tab" onclick="setOutputFormat('express')">Express</button>
        <button class="format-tab" onclick="setOutputFormat('fastapi')">FastAPI</button>
        <button class="format-tab" onclick="setOutputFormat('spring')">Spring</button>
      </div>

      <div class="output-box" id="cors-output"></div>

      <div id="cors-warnings"></div>

      <div class="actions">
        <button class="btn btn-primary" onclick="copyCORS()">📋 Copier</button>
      </div>

      <div class="info-box">
        <strong>💡 Astuce:</strong> Les requêtes simples (GET, POST avec Content-Type standard) n'ont pas besoin de preflight. Les requêtes avec headers personnalisés ou méthodes PUT/DELETE déclenchent un preflight OPTIONS.
      </div>
    </div>
  </div>
</div>

<script>
(function() {
  let origins = [];
  let outputFormat = 'headers';

  const presets = {
    dev: {
      allowAll: false,
      origins: ['http://localhost:3000', 'http://localhost:5173', 'http://127.0.0.1:3000'],
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
      headers: ['content-type', 'authorization', 'accept', 'x-requested-with'],
      customHeaders: '',
      exposedHeaders: '',
      credentials: true,
      maxAge: 3600
    },
    strict: {
      allowAll: false,
      origins: ['https://app.example.com'],
      methods: ['GET', 'POST', 'OPTIONS'],
      headers: ['content-type', 'authorization'],
      customHeaders: '',
      exposedHeaders: '',
      credentials: true,
      maxAge: 86400
    },
    'public-api': {
      allowAll: true,
      origins: [],
      methods: ['GET', 'POST', 'OPTIONS'],
      headers: ['content-type', 'accept', 'x-api-key'],
      customHeaders: '',
      exposedHeaders: 'X-RateLimit-Limit, X-RateLimit-Remaining',
      credentials: false,
      maxAge: 86400
    },
    spa: {
      allowAll: false,
      origins: ['https://app.example.com', 'https://www.example.com'],
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
      headers: ['content-type', 'authorization', 'accept'],
      customHeaders: '',
      exposedHeaders: '',
      credentials: true,
      maxAge: 86400
    },
    microservices: {
      allowAll: false,
      origins: ['https://service1.internal', 'https://service2.internal', 'https://gateway.internal'],
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
      headers: ['content-type', 'authorization', 'x-request-id', 'x-correlation-id'],
      customHeaders: 'X-Trace-ID',
      exposedHeaders: 'X-Request-ID',
      credentials: true,
      maxAge: 3600
    }
  };

  window.loadCORSPreset = function(preset) {
    const p = presets[preset];

    document.getElementById('cors-allow-all').checked = p.allowAll;
    origins = [...p.origins];
    renderOrigins();
    toggleAllOrigins();

    // Methods
    ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'].forEach(m => {
      const cb = document.getElementById(`method-${m}`);
      if (cb) cb.checked = p.methods.includes(m);
    });

    // Headers
    ['content-type', 'authorization', 'accept', 'origin', 'x-requested-with', 'x-api-key'].forEach(h => {
      const cb = document.getElementById(`header-${h}`);
      if (cb) cb.checked = p.headers.includes(h);
    });

    document.getElementById('custom-headers').value = p.customHeaders;
    document.getElementById('exposed-headers').value = p.exposedHeaders;
    document.getElementById('cors-credentials').checked = p.credentials;
    document.getElementById('cors-max-age').value = p.maxAge;

    generateCORS();
  };

  window.toggleAllOrigins = function() {
    const allowAll = document.getElementById('cors-allow-all').checked;
    document.getElementById('origins-config').style.display = allowAll ? 'none' : 'block';
    generateCORS();
  };

  window.addOrigin = function() {
    const input = document.getElementById('new-origin');
    const value = input.value.trim();

    if (value && !origins.includes(value)) {
      origins.push(value);
      input.value = '';
      renderOrigins();
      generateCORS();
    }
  };

  window.removeOrigin = function(origin) {
    origins = origins.filter(o => o !== origin);
    renderOrigins();
    generateCORS();
  };

  function renderOrigins() {
    const container = document.getElementById('origins-list');
    container.innerHTML = origins.map(o =>
      `<div class="origin-item">${o}<button onclick="removeOrigin('${o}')">×</button></div>`
    ).join('');
  }

  window.setOutputFormat = function(format) {
    outputFormat = format;
    document.querySelectorAll('.format-tab').forEach(tab => {
      tab.classList.toggle('active', tab.textContent.toLowerCase().includes(format) ||
        (format === 'headers' && tab.textContent === 'Headers'));
    });
    generateCORS();
  };

  function getSelectedMethods() {
    const methods = [];
    ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'].forEach(m => {
      const cb = document.getElementById(`method-${m}`);
      if (cb && cb.checked) methods.push(m);
    });
    return methods;
  }

  function getSelectedHeaders() {
    const headers = [];
    const headerMap = {
      'content-type': 'Content-Type',
      'authorization': 'Authorization',
      'accept': 'Accept',
      'origin': 'Origin',
      'x-requested-with': 'X-Requested-With',
      'x-api-key': 'X-API-Key'
    };

    Object.entries(headerMap).forEach(([id, name]) => {
      const cb = document.getElementById(`header-${id}`);
      if (cb && cb.checked) headers.push(name);
    });

    const custom = document.getElementById('custom-headers').value.trim();
    if (custom) {
      custom.split(',').forEach(h => {
        const trimmed = h.trim();
        if (trimmed) headers.push(trimmed);
      });
    }

    return headers;
  }

  function generateCORS() {
    const allowAll = document.getElementById('cors-allow-all').checked;
    const methods = getSelectedMethods();
    const headers = getSelectedHeaders();
    const exposedHeaders = document.getElementById('exposed-headers').value.trim();
    const credentials = document.getElementById('cors-credentials').checked;
    const maxAge = document.getElementById('cors-max-age').value;

    const originsValue = allowAll ? '*' : origins.join(', ');
    let output = '';

    switch (outputFormat) {
      case 'headers':
        output = generateHeaders(originsValue, methods, headers, exposedHeaders, credentials, maxAge, allowAll);
        break;
      case 'nginx':
        output = generateNginx(origins, methods, headers, exposedHeaders, credentials, maxAge, allowAll);
        break;
      case 'apache':
        output = generateApache(originsValue, methods, headers, exposedHeaders, credentials, maxAge);
        break;
      case 'express':
        output = generateExpress(origins, methods, headers, exposedHeaders, credentials, maxAge, allowAll);
        break;
      case 'fastapi':
        output = generateFastAPI(origins, methods, headers, exposedHeaders, credentials, maxAge, allowAll);
        break;
      case 'spring':
        output = generateSpring(origins, methods, headers, exposedHeaders, credentials, maxAge, allowAll);
        break;
    }

    document.getElementById('cors-output').textContent = output;
    showWarnings(allowAll, credentials);
  }

  function generateHeaders(origins, methods, headers, exposed, credentials, maxAge, allowAll) {
    let output = [];
    output.push(`Access-Control-Allow-Origin: ${allowAll ? '*' : origins}`);
    output.push(`Access-Control-Allow-Methods: ${methods.join(', ')}`);
    output.push(`Access-Control-Allow-Headers: ${headers.join(', ')}`);
    if (exposed) output.push(`Access-Control-Expose-Headers: ${exposed}`);
    if (credentials && !allowAll) output.push(`Access-Control-Allow-Credentials: true`);
    output.push(`Access-Control-Max-Age: ${maxAge}`);
    return output.join('\n');
  }

  function generateNginx(originsList, methods, headers, exposed, credentials, maxAge, allowAll) {
    let output = [];
    output.push('# CORS Configuration for Nginx');
    output.push('');

    if (allowAll) {
      output.push("add_header 'Access-Control-Allow-Origin' '*' always;");
    } else if (originsList.length > 0) {
      output.push('# Dynamic origin check');
      output.push(`set $cors_origin "";`);
      output.push(`if ($http_origin ~* "^(${originsList.map(o => o.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|')})$") {`);
      output.push(`    set $cors_origin $http_origin;`);
      output.push(`}`);
      output.push(`add_header 'Access-Control-Allow-Origin' $cors_origin always;`);
    }

    output.push(`add_header 'Access-Control-Allow-Methods' '${methods.join(', ')}' always;`);
    output.push(`add_header 'Access-Control-Allow-Headers' '${headers.join(', ')}' always;`);
    if (exposed) output.push(`add_header 'Access-Control-Expose-Headers' '${exposed}' always;`);
    if (credentials && !allowAll) output.push(`add_header 'Access-Control-Allow-Credentials' 'true' always;`);
    output.push(`add_header 'Access-Control-Max-Age' ${maxAge} always;`);
    output.push('');
    output.push('# Handle preflight');
    output.push('if ($request_method = OPTIONS) {');
    output.push('    return 204;');
    output.push('}');

    return output.join('\n');
  }

  function generateApache(origins, methods, headers, exposed, credentials, maxAge) {
    let output = [];
    output.push('# CORS Configuration for Apache');
    output.push('<IfModule mod_headers.c>');
    output.push(`    Header set Access-Control-Allow-Origin "${origins}"`);
    output.push(`    Header set Access-Control-Allow-Methods "${methods.join(', ')}"`);
    output.push(`    Header set Access-Control-Allow-Headers "${headers.join(', ')}"`);
    if (exposed) output.push(`    Header set Access-Control-Expose-Headers "${exposed}"`);
    if (credentials) output.push(`    Header set Access-Control-Allow-Credentials "true"`);
    output.push(`    Header set Access-Control-Max-Age "${maxAge}"`);
    output.push('</IfModule>');
    output.push('');
    output.push('# Handle preflight');
    output.push('RewriteEngine On');
    output.push('RewriteCond %{REQUEST_METHOD} OPTIONS');
    output.push('RewriteRule ^(.*)$ $1 [R=204,L]');

    return output.join('\n');
  }

  function generateExpress(originsList, methods, headers, exposed, credentials, maxAge, allowAll) {
    let output = [];
    output.push('// npm install cors');
    output.push("const cors = require('cors');");
    output.push('');
    output.push('const corsOptions = {');
    if (allowAll) {
      output.push("  origin: '*',");
    } else if (originsList.length === 1) {
      output.push(`  origin: '${originsList[0]}',`);
    } else {
      output.push(`  origin: [${originsList.map(o => `'${o}'`).join(', ')}],`);
    }
    output.push(`  methods: [${methods.map(m => `'${m}'`).join(', ')}],`);
    output.push(`  allowedHeaders: [${headers.map(h => `'${h}'`).join(', ')}],`);
    if (exposed) output.push(`  exposedHeaders: [${exposed.split(',').map(h => `'${h.trim()}'`).join(', ')}],`);
    if (credentials && !allowAll) output.push(`  credentials: true,`);
    output.push(`  maxAge: ${maxAge},`);
    output.push('};');
    output.push('');
    output.push('app.use(cors(corsOptions));');

    return output.join('\n');
  }

  function generateFastAPI(originsList, methods, headers, exposed, credentials, maxAge, allowAll) {
    let output = [];
    output.push('from fastapi.middleware.cors import CORSMiddleware');
    output.push('');
    output.push('app.add_middleware(');
    output.push('    CORSMiddleware,');
    if (allowAll) {
      output.push('    allow_origins=["*"],');
    } else {
      output.push(`    allow_origins=[${originsList.map(o => `"${o}"`).join(', ')}],`);
    }
    if (credentials && !allowAll) output.push('    allow_credentials=True,');
    output.push(`    allow_methods=[${methods.map(m => `"${m}"`).join(', ')}],`);
    output.push(`    allow_headers=[${headers.map(h => `"${h}"`).join(', ')}],`);
    if (exposed) output.push(`    expose_headers=[${exposed.split(',').map(h => `"${h.trim()}"`).join(', ')}],`);
    output.push(`    max_age=${maxAge},`);
    output.push(')');

    return output.join('\n');
  }

  function generateSpring(originsList, methods, headers, exposed, credentials, maxAge, allowAll) {
    let output = [];
    output.push('@Configuration');
    output.push('public class CorsConfig implements WebMvcConfigurer {');
    output.push('');
    output.push('    @Override');
    output.push('    public void addCorsMappings(CorsRegistry registry) {');
    output.push('        registry.addMapping("/**")');
    if (allowAll) {
      output.push('            .allowedOrigins("*")');
    } else {
      output.push(`            .allowedOrigins(${originsList.map(o => `"${o}"`).join(', ')})`);
    }
    output.push(`            .allowedMethods(${methods.map(m => `"${m}"`).join(', ')})`);
    output.push(`            .allowedHeaders(${headers.map(h => `"${h}"`).join(', ')})`);
    if (exposed) output.push(`            .exposedHeaders(${exposed.split(',').map(h => `"${h.trim()}"`).join(', ')})`);
    if (credentials && !allowAll) output.push('            .allowCredentials(true)');
    output.push(`            .maxAge(${maxAge});`);
    output.push('    }');
    output.push('}');

    return output.join('\n');
  }

  function showWarnings(allowAll, credentials) {
    const warnings = [];

    if (allowAll && credentials) {
      warnings.push("⚠️ Impossible d'utiliser credentials avec origin '*'. Le navigateur bloquera.");
    }
    if (allowAll) {
      warnings.push("⚠️ Origin '*' est très permissif. À éviter en production.");
    }
    if (origins.length === 0 && !allowAll) {
      warnings.push("⚠️ Aucune origine configurée. CORS bloquera toutes les requêtes cross-origin.");
    }

    const container = document.getElementById('cors-warnings');
    if (warnings.length > 0) {
      container.innerHTML = `<div class="warning-box">${warnings.join('<br>')}</div>`;
    } else {
      container.innerHTML = '';
    }
  }

  window.copyCORS = function() {
    const content = document.getElementById('cors-output').textContent;
    navigator.clipboard.writeText(content).then(() => {
      const btn = event.target;
      btn.textContent = '✓ Copié!';
      setTimeout(() => btn.textContent = '📋 Copier', 2000);
    });
  };

  // Event listeners
  document.querySelectorAll('#cors-builder input, #cors-builder select').forEach(el => {
    el.addEventListener('change', generateCORS);
    el.addEventListener('input', generateCORS);
  });

  document.getElementById('new-origin').addEventListener('keypress', function(e) {
    if (e.key === 'Enter') {
      e.preventDefault();
      addOrigin();
    }
  });

  // Initialize
  loadCORSPreset('dev');
})();
</script>

---

## Comment fonctionne CORS

### Requêtes simples (pas de preflight)

```
GET /api/data HTTP/1.1
Origin: https://app.example.com

HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://app.example.com
```

### Requêtes avec preflight

```
OPTIONS /api/data HTTP/1.1
Origin: https://app.example.com
Access-Control-Request-Method: PUT
Access-Control-Request-Headers: Content-Type, Authorization

HTTP/1.1 204 No Content
Access-Control-Allow-Origin: https://app.example.com
Access-Control-Allow-Methods: GET, POST, PUT, DELETE
Access-Control-Allow-Headers: Content-Type, Authorization
Access-Control-Max-Age: 86400
```

---

## Headers CORS

| Header | Direction | Description |
|--------|-----------|-------------|
| `Access-Control-Allow-Origin` | Réponse | Origins autorisées |
| `Access-Control-Allow-Methods` | Réponse | Méthodes autorisées |
| `Access-Control-Allow-Headers` | Réponse | Headers autorisés |
| `Access-Control-Expose-Headers` | Réponse | Headers lisibles par JS |
| `Access-Control-Allow-Credentials` | Réponse | Autorise cookies/auth |
| `Access-Control-Max-Age` | Réponse | Cache du preflight (sec) |
| `Origin` | Requête | Origine de la requête |
| `Access-Control-Request-Method` | Requête (preflight) | Méthode demandée |
| `Access-Control-Request-Headers` | Requête (preflight) | Headers demandés |

---

## Bonnes pratiques

1. **Ne jamais utiliser `*` avec credentials** - Le navigateur refuse
2. **Lister explicitement les origines** en production
3. **Limiter les méthodes** au nécessaire
4. **Utiliser Max-Age** pour réduire les preflight
5. **Exposer uniquement les headers nécessaires** au client
