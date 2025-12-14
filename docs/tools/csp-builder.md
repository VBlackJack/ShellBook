---
tags:
  - tools
  - security
  - csp
  - web
---

# CSP Builder

Générateur interactif de Content Security Policy (CSP) pour sécuriser vos applications web.

<div id="csp-builder">
  <style>
    #csp-builder {
      font-family: inherit;
    }
    #csp-builder .builder-container {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 20px;
    }
    @media (max-width: 900px) {
      #csp-builder .builder-container {
        grid-template-columns: 1fr;
      }
    }
    #csp-builder .config-section {
      background: var(--md-code-bg-color);
      border-radius: 8px;
      padding: 20px;
    }
    #csp-builder .output-section {
      background: var(--md-code-bg-color);
      border-radius: 8px;
      padding: 20px;
    }
    #csp-builder .section-title {
      font-size: 14px;
      font-weight: 600;
      margin: 20px 0 10px 0;
      padding-bottom: 5px;
      border-bottom: 1px solid var(--md-default-fg-color--lighter);
    }
    #csp-builder .section-title:first-child {
      margin-top: 0;
    }
    #csp-builder .directive-group {
      margin-bottom: 15px;
    }
    #csp-builder .directive-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 8px;
    }
    #csp-builder .directive-name {
      font-weight: 500;
      font-family: monospace;
      font-size: 13px;
    }
    #csp-builder .directive-toggle {
      font-size: 12px;
      color: var(--md-primary-fg-color);
      cursor: pointer;
    }
    #csp-builder .source-options {
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      margin-bottom: 8px;
    }
    #csp-builder .source-chip {
      display: inline-flex;
      align-items: center;
      gap: 4px;
      padding: 4px 10px;
      border: 1px solid var(--md-default-fg-color--lighter);
      border-radius: 15px;
      font-size: 12px;
      cursor: pointer;
      transition: all 0.2s;
      background: var(--md-default-bg-color);
    }
    #csp-builder .source-chip:hover {
      border-color: var(--md-primary-fg-color);
    }
    #csp-builder .source-chip.selected {
      background: var(--md-primary-fg-color);
      border-color: var(--md-primary-fg-color);
      color: white;
    }
    #csp-builder .custom-sources {
      display: flex;
      gap: 8px;
    }
    #csp-builder .custom-sources input {
      flex: 1;
      padding: 6px 10px;
      border: 1px solid var(--md-default-fg-color--lighter);
      border-radius: 4px;
      background: var(--md-default-bg-color);
      color: var(--md-default-fg-color);
      font-size: 12px;
    }
    #csp-builder .custom-sources button {
      padding: 6px 12px;
      border: none;
      background: var(--md-primary-fg-color);
      color: white;
      border-radius: 4px;
      cursor: pointer;
      font-size: 12px;
    }
    #csp-builder .added-sources {
      display: flex;
      flex-wrap: wrap;
      gap: 5px;
      margin-top: 8px;
    }
    #csp-builder .added-source {
      display: inline-flex;
      align-items: center;
      gap: 4px;
      padding: 3px 8px;
      background: var(--md-accent-fg-color--transparent);
      border-radius: 4px;
      font-size: 11px;
      font-family: monospace;
    }
    #csp-builder .added-source button {
      background: none;
      border: none;
      cursor: pointer;
      color: var(--md-default-fg-color);
      font-size: 12px;
      padding: 0;
    }
    #csp-builder .presets {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-bottom: 20px;
    }
    #csp-builder .preset-btn {
      padding: 6px 12px;
      border: 1px solid var(--md-primary-fg-color);
      background: transparent;
      color: var(--md-primary-fg-color);
      border-radius: 4px;
      cursor: pointer;
      font-size: 12px;
    }
    #csp-builder .preset-btn:hover {
      background: var(--md-primary-fg-color);
      color: white;
    }
    #csp-builder .output-box {
      background: var(--md-default-bg-color);
      border: 1px solid var(--md-default-fg-color--lighter);
      border-radius: 4px;
      padding: 15px;
      font-family: 'Consolas', 'Monaco', monospace;
      font-size: 12px;
      word-break: break-all;
      min-height: 100px;
    }
    #csp-builder .format-tabs {
      display: flex;
      gap: 10px;
      margin-bottom: 15px;
    }
    #csp-builder .format-tab {
      padding: 8px 16px;
      border: 1px solid var(--md-default-fg-color--lighter);
      background: var(--md-default-bg-color);
      color: var(--md-default-fg-color);
      border-radius: 4px;
      cursor: pointer;
      font-size: 13px;
    }
    #csp-builder .format-tab.active {
      background: var(--md-primary-fg-color);
      border-color: var(--md-primary-fg-color);
      color: white;
    }
    #csp-builder .actions {
      display: flex;
      gap: 10px;
      margin-top: 15px;
    }
    #csp-builder .btn {
      padding: 8px 16px;
      border: none;
      border-radius: 4px;
      cursor: pointer;
      font-size: 14px;
    }
    #csp-builder .btn-primary {
      background: var(--md-primary-fg-color);
      color: white;
    }
    #csp-builder .btn-secondary {
      background: var(--md-default-fg-color--lighter);
      color: var(--md-default-fg-color);
    }
    #csp-builder .warning-box {
      background: #fff3cd;
      border: 1px solid #ffc107;
      border-radius: 4px;
      padding: 10px;
      margin-top: 15px;
      font-size: 12px;
      color: #856404;
    }
    #csp-builder .info-icon {
      display: inline-block;
      width: 14px;
      height: 14px;
      line-height: 14px;
      text-align: center;
      border-radius: 50%;
      background: var(--md-default-fg-color--lighter);
      color: var(--md-default-bg-color);
      font-size: 10px;
      cursor: help;
      margin-left: 5px;
    }
  </style>

  <div class="presets">
    <button class="preset-btn" onclick="loadCSPPreset('strict')">🔒 Strict</button>
    <button class="preset-btn" onclick="loadCSPPreset('moderate')">⚖️ Modéré</button>
    <button class="preset-btn" onclick="loadCSPPreset('permissive')">🔓 Permissif</button>
    <button class="preset-btn" onclick="loadCSPPreset('spa')">⚛️ SPA</button>
    <button class="preset-btn" onclick="loadCSPPreset('wordpress')">📝 WordPress</button>
    <button class="preset-btn" onclick="loadCSPPreset('reset')">🗑️ Reset</button>
  </div>

  <div class="builder-container">
    <div class="config-section">
      <div class="section-title">📜 Fetch Directives</div>
      <div id="fetch-directives"></div>

      <div class="section-title">📄 Document Directives</div>
      <div id="document-directives"></div>

      <div class="section-title">🧭 Navigation Directives</div>
      <div id="navigation-directives"></div>

      <div class="section-title">📊 Reporting</div>
      <div id="reporting-directives"></div>
    </div>

    <div class="output-section">
      <div class="section-title">CSP généré</div>

      <div class="format-tabs">
        <button class="format-tab active" onclick="setFormat('header')">HTTP Header</button>
        <button class="format-tab" onclick="setFormat('meta')">Meta Tag</button>
        <button class="format-tab" onclick="setFormat('nginx')">Nginx</button>
        <button class="format-tab" onclick="setFormat('apache')">Apache</button>
      </div>

      <div class="output-box" id="csp-output"></div>

      <div id="csp-warnings"></div>

      <div class="actions">
        <button class="btn btn-primary" onclick="copyCSP()">📋 Copier</button>
        <button class="btn btn-secondary" onclick="testCSP()">🧪 Tester</button>
      </div>

      <div class="section-title" style="margin-top: 30px;">Analyse</div>
      <div id="csp-analysis"></div>
    </div>
  </div>
</div>

<script>
(function() {
  let currentFormat = 'header';

  const directives = {
    fetch: [
      { name: 'default-src', desc: 'Fallback pour toutes les directives *-src' },
      { name: 'script-src', desc: 'Sources JavaScript' },
      { name: 'style-src', desc: 'Sources CSS' },
      { name: 'img-src', desc: 'Sources images' },
      { name: 'font-src', desc: 'Sources polices' },
      { name: 'connect-src', desc: 'URLs pour fetch, XHR, WebSocket' },
      { name: 'media-src', desc: 'Sources audio/video' },
      { name: 'object-src', desc: 'Sources pour <object>, <embed>' },
      { name: 'frame-src', desc: 'Sources pour <iframe>' },
      { name: 'worker-src', desc: 'Sources pour workers' },
      { name: 'manifest-src', desc: 'Sources manifeste' }
    ],
    document: [
      { name: 'base-uri', desc: 'URLs autorisées pour <base>' },
      { name: 'sandbox', desc: 'Restrictions sandbox', special: true }
    ],
    navigation: [
      { name: 'form-action', desc: 'URLs pour soumission formulaires' },
      { name: 'frame-ancestors', desc: 'Parents autorisés (anti-clickjacking)' }
    ],
    reporting: [
      { name: 'report-uri', desc: 'URL pour rapports (déprécié)', custom: true },
      { name: 'report-to', desc: 'Groupe de rapport', custom: true }
    ]
  };

  const sources = {
    keywords: ["'self'", "'none'", "'unsafe-inline'", "'unsafe-eval'", "'strict-dynamic'", "'unsafe-hashes'"],
    schemes: ['https:', 'data:', 'blob:', 'wss:'],
    common: ['*.googleapis.com', '*.gstatic.com', '*.cloudflare.com', '*.jsdelivr.net', '*.unpkg.com']
  };

  const state = {};

  const presets = {
    strict: {
      'default-src': { keywords: ["'none'"], custom: [] },
      'script-src': { keywords: ["'self'"], custom: [] },
      'style-src': { keywords: ["'self'"], custom: [] },
      'img-src': { keywords: ["'self'"], custom: [] },
      'font-src': { keywords: ["'self'"], custom: [] },
      'connect-src': { keywords: ["'self'"], custom: [] },
      'base-uri': { keywords: ["'self'"], custom: [] },
      'form-action': { keywords: ["'self'"], custom: [] },
      'frame-ancestors': { keywords: ["'none'"], custom: [] },
      'object-src': { keywords: ["'none'"], custom: [] }
    },
    moderate: {
      'default-src': { keywords: ["'self'"], custom: [] },
      'script-src': { keywords: ["'self'"], custom: ['https:'] },
      'style-src': { keywords: ["'self'", "'unsafe-inline'"], custom: [] },
      'img-src': { keywords: ["'self'"], custom: ['https:', 'data:'] },
      'font-src': { keywords: ["'self'"], custom: ['https:'] },
      'connect-src': { keywords: ["'self'"], custom: ['https:'] },
      'base-uri': { keywords: ["'self'"], custom: [] },
      'form-action': { keywords: ["'self'"], custom: [] },
      'frame-ancestors': { keywords: ["'self'"], custom: [] }
    },
    permissive: {
      'default-src': { keywords: ["'self'"], custom: ['https:'] },
      'script-src': { keywords: ["'self'", "'unsafe-inline'", "'unsafe-eval'"], custom: ['https:'] },
      'style-src': { keywords: ["'self'", "'unsafe-inline'"], custom: ['https:'] },
      'img-src': { keywords: [], custom: ['*', 'data:', 'blob:'] },
      'font-src': { keywords: ["'self'"], custom: ['https:', 'data:'] },
      'connect-src': { keywords: ["'self'"], custom: ['https:', 'wss:'] }
    },
    spa: {
      'default-src': { keywords: ["'self'"], custom: [] },
      'script-src': { keywords: ["'self'", "'unsafe-inline'"], custom: [] },
      'style-src': { keywords: ["'self'", "'unsafe-inline'"], custom: [] },
      'img-src': { keywords: ["'self'"], custom: ['data:', 'blob:'] },
      'font-src': { keywords: ["'self'"], custom: ['data:'] },
      'connect-src': { keywords: ["'self'"], custom: ['https:', 'wss:'] },
      'worker-src': { keywords: ["'self'"], custom: ['blob:'] },
      'base-uri': { keywords: ["'self'"], custom: [] },
      'form-action': { keywords: ["'self'"], custom: [] }
    },
    wordpress: {
      'default-src': { keywords: ["'self'"], custom: [] },
      'script-src': { keywords: ["'self'", "'unsafe-inline'", "'unsafe-eval'"], custom: ['*.googleapis.com', '*.gstatic.com'] },
      'style-src': { keywords: ["'self'", "'unsafe-inline'"], custom: ['*.googleapis.com'] },
      'img-src': { keywords: ["'self'"], custom: ['data:', 'https:'] },
      'font-src': { keywords: ["'self'"], custom: ['*.googleapis.com', '*.gstatic.com', 'data:'] },
      'connect-src': { keywords: ["'self'"], custom: [] },
      'frame-src': { keywords: ["'self'"], custom: ['*.youtube.com', '*.vimeo.com'] }
    },
    reset: {}
  };

  function initDirectives() {
    const fetchContainer = document.getElementById('fetch-directives');
    const docContainer = document.getElementById('document-directives');
    const navContainer = document.getElementById('navigation-directives');
    const reportContainer = document.getElementById('reporting-directives');

    directives.fetch.forEach(d => {
      state[d.name] = { keywords: [], custom: [] };
      fetchContainer.appendChild(createDirectiveUI(d));
    });

    directives.document.forEach(d => {
      state[d.name] = { keywords: [], custom: [] };
      docContainer.appendChild(createDirectiveUI(d));
    });

    directives.navigation.forEach(d => {
      state[d.name] = { keywords: [], custom: [] };
      navContainer.appendChild(createDirectiveUI(d));
    });

    directives.reporting.forEach(d => {
      state[d.name] = { keywords: [], custom: [] };
      reportContainer.appendChild(createDirectiveUI(d, true));
    });
  }

  function createDirectiveUI(directive, customOnly = false) {
    const div = document.createElement('div');
    div.className = 'directive-group';
    div.id = `group-${directive.name}`;

    let html = `
      <div class="directive-header">
        <span class="directive-name">${directive.name}</span>
        <span class="info-icon" title="${directive.desc}">?</span>
      </div>
    `;

    if (!customOnly) {
      html += `<div class="source-options">`;
      sources.keywords.forEach(kw => {
        html += `<span class="source-chip" data-directive="${directive.name}" data-value="${kw}" onclick="toggleSource(this)">${kw}</span>`;
      });
      html += `</div>`;
      html += `<div class="source-options">`;
      sources.schemes.forEach(scheme => {
        html += `<span class="source-chip" data-directive="${directive.name}" data-value="${scheme}" onclick="toggleSource(this)">${scheme}</span>`;
      });
      html += `</div>`;
    }

    html += `
      <div class="custom-sources">
        <input type="text" id="custom-${directive.name}" placeholder="Domaine personnalisé (ex: *.example.com)">
        <button onclick="addCustomSource('${directive.name}')">+</button>
      </div>
      <div class="added-sources" id="added-${directive.name}"></div>
    `;

    div.innerHTML = html;
    return div;
  }

  window.toggleSource = function(chip) {
    const directive = chip.dataset.directive;
    const value = chip.dataset.value;

    chip.classList.toggle('selected');

    if (chip.classList.contains('selected')) {
      if (!state[directive].keywords.includes(value)) {
        state[directive].keywords.push(value);
      }
    } else {
      state[directive].keywords = state[directive].keywords.filter(k => k !== value);
    }

    generateCSP();
  };

  window.addCustomSource = function(directive) {
    const input = document.getElementById(`custom-${directive}`);
    const value = input.value.trim();

    if (value && !state[directive].custom.includes(value)) {
      state[directive].custom.push(value);
      input.value = '';
      renderCustomSources(directive);
      generateCSP();
    }
  };

  window.removeCustomSource = function(directive, value) {
    state[directive].custom = state[directive].custom.filter(v => v !== value);
    renderCustomSources(directive);
    generateCSP();
  };

  function renderCustomSources(directive) {
    const container = document.getElementById(`added-${directive}`);
    container.innerHTML = state[directive].custom.map(v =>
      `<span class="added-source">${v}<button onclick="removeCustomSource('${directive}', '${v}')">&times;</button></span>`
    ).join('');
  }

  window.loadCSPPreset = function(preset) {
    const p = presets[preset];

    // Reset all
    Object.keys(state).forEach(directive => {
      state[directive] = { keywords: [], custom: [] };
    });

    // Apply preset
    Object.entries(p).forEach(([directive, values]) => {
      if (state[directive]) {
        state[directive] = { ...values };
      }
    });

    // Update UI
    document.querySelectorAll('.source-chip').forEach(chip => {
      const directive = chip.dataset.directive;
      const value = chip.dataset.value;
      chip.classList.toggle('selected', state[directive]?.keywords.includes(value));
    });

    Object.keys(state).forEach(d => renderCustomSources(d));
    generateCSP();
  };

  window.setFormat = function(format) {
    currentFormat = format;
    document.querySelectorAll('.format-tab').forEach(tab => {
      tab.classList.toggle('active', tab.textContent.toLowerCase().includes(format));
    });
    generateCSP();
  };

  function generateCSP() {
    const parts = [];

    Object.entries(state).forEach(([directive, values]) => {
      const allSources = [...values.keywords, ...values.custom];
      if (allSources.length > 0) {
        parts.push(`${directive} ${allSources.join(' ')}`);
      }
    });

    const csp = parts.join('; ');
    let output = '';

    switch (currentFormat) {
      case 'header':
        output = `Content-Security-Policy: ${csp}`;
        break;
      case 'meta':
        output = `<meta http-equiv="Content-Security-Policy" content="${csp}">`;
        break;
      case 'nginx':
        output = `add_header Content-Security-Policy "${csp}" always;`;
        break;
      case 'apache':
        output = `Header always set Content-Security-Policy "${csp}"`;
        break;
    }

    document.getElementById('csp-output').textContent = output || '(aucune directive configurée)';
    analyzeCSP();
  }

  function analyzeCSP() {
    const warnings = [];
    const analysis = [];

    // Check for unsafe directives
    if (state['script-src']?.keywords.includes("'unsafe-inline'")) {
      warnings.push("⚠️ 'unsafe-inline' dans script-src permet les scripts inline et réduit la protection XSS");
    }
    if (state['script-src']?.keywords.includes("'unsafe-eval'")) {
      warnings.push("⚠️ 'unsafe-eval' permet eval() et les fonctions similaires - risque de sécurité");
    }
    if (state['style-src']?.keywords.includes("'unsafe-inline'")) {
      analysis.push("ℹ️ 'unsafe-inline' dans style-src - acceptable mais préférer nonce/hash");
    }

    // Check for missing important directives
    if (!hasDirective('default-src')) {
      warnings.push("⚠️ default-src manquant - définissez une politique par défaut");
    }
    if (!hasDirective('object-src')) {
      analysis.push("ℹ️ object-src non défini - ajoutez 'none' pour bloquer les plugins");
    }
    if (!hasDirective('base-uri')) {
      analysis.push("ℹ️ base-uri non défini - ajoutez 'self' pour prévenir les injections de <base>");
    }
    if (!hasDirective('frame-ancestors')) {
      analysis.push("ℹ️ frame-ancestors non défini - protège contre le clickjacking");
    }

    // Wildcard check
    Object.entries(state).forEach(([directive, values]) => {
      if (values.custom.includes('*')) {
        warnings.push(`⚠️ Wildcard '*' dans ${directive} - très permissif`);
      }
    });

    // Display warnings
    const warningContainer = document.getElementById('csp-warnings');
    if (warnings.length > 0) {
      warningContainer.innerHTML = `<div class="warning-box">${warnings.join('<br>')}</div>`;
    } else {
      warningContainer.innerHTML = '';
    }

    // Display analysis
    const analysisContainer = document.getElementById('csp-analysis');
    const score = calculateScore();
    analysisContainer.innerHTML = `
      <div style="margin-bottom: 10px;">
        <strong>Score de sécurité:</strong>
        <span style="color: ${score >= 80 ? '#27ae60' : score >= 50 ? '#f39c12' : '#e74c3c'}">
          ${score}/100
        </span>
      </div>
      ${analysis.length > 0 ? `<div style="font-size: 12px; color: var(--md-default-fg-color--light);">${analysis.join('<br>')}</div>` : ''}
    `;
  }

  function hasDirective(name) {
    return state[name] && (state[name].keywords.length > 0 || state[name].custom.length > 0);
  }

  function calculateScore() {
    let score = 0;

    if (hasDirective('default-src')) score += 15;
    if (hasDirective('script-src')) score += 15;
    if (hasDirective('style-src')) score += 10;
    if (hasDirective('img-src')) score += 5;
    if (hasDirective('object-src') && state['object-src'].keywords.includes("'none'")) score += 10;
    if (hasDirective('base-uri')) score += 10;
    if (hasDirective('frame-ancestors')) score += 10;
    if (hasDirective('form-action')) score += 5;

    // Penalties
    if (state['script-src']?.keywords.includes("'unsafe-inline'")) score -= 15;
    if (state['script-src']?.keywords.includes("'unsafe-eval'")) score -= 10;
    if (state['default-src']?.custom.includes('*')) score -= 20;

    // Bonus for strict
    if (state['script-src']?.keywords.includes("'strict-dynamic'")) score += 10;
    if (state['default-src']?.keywords.includes("'none'")) score += 10;

    return Math.max(0, Math.min(100, score));
  }

  window.copyCSP = function() {
    const content = document.getElementById('csp-output').textContent;
    navigator.clipboard.writeText(content).then(() => {
      const btn = event.target;
      btn.textContent = '✓ Copié!';
      setTimeout(() => btn.textContent = '📋 Copier', 2000);
    });
  };

  window.testCSP = function() {
    window.open('https://csp-evaluator.withgoogle.com/', '_blank');
  };

  // Initialize
  initDirectives();
  generateCSP();
})();
</script>

---

## Référence CSP

### Valeurs sources

| Valeur | Description |
|--------|-------------|
| `'self'` | Même origine |
| `'none'` | Bloque tout |
| `'unsafe-inline'` | Autorise inline (scripts, styles) |
| `'unsafe-eval'` | Autorise eval() |
| `'strict-dynamic'` | Fait confiance aux scripts chargés dynamiquement |
| `'nonce-xxx'` | Script avec nonce spécifique |
| `'sha256-xxx'` | Script avec hash spécifique |
| `https:` | Tout en HTTPS |
| `data:` | URLs data: |
| `blob:` | URLs blob: |
| `*.example.com` | Wildcard domaine |

### Directives principales

| Directive | Contrôle |
|-----------|----------|
| `default-src` | Fallback pour tout |
| `script-src` | JavaScript |
| `style-src` | CSS |
| `img-src` | Images |
| `font-src` | Polices |
| `connect-src` | XHR, fetch, WebSocket |
| `frame-src` | iframes |
| `object-src` | Plugins (Flash, etc.) |
| `base-uri` | Element `<base>` |
| `form-action` | Soumission formulaires |
| `frame-ancestors` | Qui peut nous embed |

---

## Exemples

### CSP Strict (recommandé)

```http
Content-Security-Policy:
  default-src 'none';
  script-src 'self' 'nonce-xyz123';
  style-src 'self';
  img-src 'self';
  font-src 'self';
  connect-src 'self';
  base-uri 'self';
  form-action 'self';
  frame-ancestors 'none';
  object-src 'none';
```

### Mode Report-Only (test)

```http
Content-Security-Policy-Report-Only: default-src 'self'; report-uri /csp-report
```
