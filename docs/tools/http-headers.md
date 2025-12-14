---
tags:
  - tools
  - http
  - web
  - reference
---

# HTTP Headers Reference

Référence complète des headers HTTP avec recherche et exemples.

<div id="http-headers">
  <style>
    #http-headers {
      font-family: inherit;
    }
    #http-headers .search-section {
      background: var(--md-code-bg-color);
      border-radius: 8px;
      padding: 20px;
      margin-bottom: 20px;
    }
    #http-headers .search-input {
      width: 100%;
      padding: 12px 15px;
      font-size: 16px;
      border: 2px solid var(--md-default-fg-color--lighter);
      border-radius: 8px;
      background: var(--md-default-bg-color);
      color: var(--md-default-fg-color);
      box-sizing: border-box;
    }
    #http-headers .filter-tabs {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-top: 15px;
    }
    #http-headers .filter-tab {
      padding: 6px 12px;
      border: 1px solid var(--md-default-fg-color--lighter);
      background: var(--md-default-bg-color);
      color: var(--md-default-fg-color);
      border-radius: 20px;
      cursor: pointer;
      font-size: 12px;
    }
    #http-headers .filter-tab.active {
      background: var(--md-primary-fg-color);
      border-color: var(--md-primary-fg-color);
      color: white;
    }
    #http-headers .results-section {
      background: var(--md-code-bg-color);
      border-radius: 8px;
      padding: 20px;
    }
    #http-headers .header-card {
      background: var(--md-default-bg-color);
      border: 1px solid var(--md-default-fg-color--lighter);
      border-radius: 8px;
      margin-bottom: 15px;
      overflow: hidden;
    }
    #http-headers .header-card-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 12px 15px;
      background: var(--md-code-bg-color);
      cursor: pointer;
    }
    #http-headers .header-name {
      font-family: monospace;
      font-weight: 600;
      color: var(--md-primary-fg-color);
      font-size: 15px;
    }
    #http-headers .header-badges {
      display: flex;
      gap: 5px;
    }
    #http-headers .badge {
      padding: 3px 8px;
      border-radius: 4px;
      font-size: 10px;
      font-weight: 500;
    }
    #http-headers .badge-request { background: #3498db22; color: #3498db; }
    #http-headers .badge-response { background: #27ae6022; color: #27ae60; }
    #http-headers .badge-both { background: #9b59b622; color: #9b59b6; }
    #http-headers .badge-security { background: #e74c3c22; color: #e74c3c; }
    #http-headers .badge-caching { background: #f39c1222; color: #f39c12; }
    #http-headers .badge-cors { background: #1abc9c22; color: #1abc9c; }
    #http-headers .header-card-body {
      padding: 15px;
      display: none;
      border-top: 1px solid var(--md-default-fg-color--lighter);
    }
    #http-headers .header-card.expanded .header-card-body {
      display: block;
    }
    #http-headers .header-desc {
      margin-bottom: 15px;
      line-height: 1.6;
    }
    #http-headers .example-box {
      background: var(--md-code-bg-color);
      border-radius: 4px;
      padding: 10px 15px;
      font-family: monospace;
      font-size: 12px;
      margin-bottom: 10px;
      overflow-x: auto;
    }
    #http-headers .example-label {
      font-size: 11px;
      color: var(--md-default-fg-color--light);
      margin-bottom: 5px;
    }
    #http-headers .results-count {
      font-size: 14px;
      color: var(--md-default-fg-color--light);
      margin-bottom: 15px;
    }
    #http-headers .copy-btn {
      padding: 4px 10px;
      background: var(--md-primary-fg-color);
      color: white;
      border: none;
      border-radius: 4px;
      cursor: pointer;
      font-size: 11px;
      margin-left: 10px;
    }
    #http-headers .values-table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 10px;
      font-size: 12px;
    }
    #http-headers .values-table th,
    #http-headers .values-table td {
      padding: 8px;
      text-align: left;
      border-bottom: 1px solid var(--md-default-fg-color--lighter);
    }
    #http-headers .values-table th {
      background: var(--md-code-bg-color);
      font-weight: 600;
    }
    #http-headers .values-table code {
      background: var(--md-code-bg-color);
      padding: 2px 6px;
      border-radius: 3px;
      font-size: 11px;
    }
  </style>

  <div class="search-section">
    <input type="text" class="search-input" id="header-search" placeholder="Rechercher un header HTTP..." oninput="filterHeaders()">
    <div class="filter-tabs">
      <button class="filter-tab active" data-filter="all" onclick="setHeaderFilter('all')">Tous</button>
      <button class="filter-tab" data-filter="request" onclick="setHeaderFilter('request')">📤 Request</button>
      <button class="filter-tab" data-filter="response" onclick="setHeaderFilter('response')">📥 Response</button>
      <button class="filter-tab" data-filter="security" onclick="setHeaderFilter('security')">🔒 Sécurité</button>
      <button class="filter-tab" data-filter="caching" onclick="setHeaderFilter('caching')">💾 Cache</button>
      <button class="filter-tab" data-filter="cors" onclick="setHeaderFilter('cors')">🌐 CORS</button>
    </div>
  </div>

  <div class="results-section">
    <div class="results-count" id="header-count">0 headers</div>
    <div id="headers-container"></div>
  </div>
</div>

<script>
(function() {
  const headers = [
    // Request Headers
    {
      name: 'Accept',
      type: 'request',
      tags: [],
      desc: 'Indique les types de contenu que le client peut traiter.',
      examples: ['Accept: text/html, application/json', 'Accept: image/webp, image/*', 'Accept: */*'],
      values: [
        { val: 'text/html', desc: 'Documents HTML' },
        { val: 'application/json', desc: 'Données JSON' },
        { val: '*/*', desc: 'Tout type de contenu' }
      ]
    },
    {
      name: 'Accept-Encoding',
      type: 'request',
      tags: [],
      desc: 'Algorithmes de compression acceptés par le client.',
      examples: ['Accept-Encoding: gzip, deflate, br'],
      values: [
        { val: 'gzip', desc: 'Compression GZIP' },
        { val: 'deflate', desc: 'Compression Deflate' },
        { val: 'br', desc: 'Compression Brotli' }
      ]
    },
    {
      name: 'Accept-Language',
      type: 'request',
      tags: [],
      desc: 'Langues préférées pour la réponse.',
      examples: ['Accept-Language: fr-FR, fr;q=0.9, en;q=0.8']
    },
    {
      name: 'Authorization',
      type: 'request',
      tags: ['security'],
      desc: 'Credentials pour authentifier le client.',
      examples: ['Authorization: Bearer eyJhbGciOiJIUzI1NiIs...', 'Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQ='],
      values: [
        { val: 'Bearer <token>', desc: 'Token JWT ou OAuth' },
        { val: 'Basic <base64>', desc: 'Auth basique (user:pass en base64)' },
        { val: 'Digest', desc: 'Authentification Digest' }
      ]
    },
    {
      name: 'Content-Type',
      type: 'both',
      tags: [],
      desc: 'Type MIME du corps de la requête/réponse.',
      examples: ['Content-Type: application/json; charset=utf-8', 'Content-Type: multipart/form-data; boundary=----WebKitFormBoundary'],
      values: [
        { val: 'application/json', desc: 'Données JSON' },
        { val: 'application/x-www-form-urlencoded', desc: 'Formulaire simple' },
        { val: 'multipart/form-data', desc: 'Formulaire avec fichiers' },
        { val: 'text/html', desc: 'Document HTML' }
      ]
    },
    {
      name: 'Cookie',
      type: 'request',
      tags: [],
      desc: 'Envoie les cookies stockés au serveur.',
      examples: ['Cookie: session_id=abc123; user_pref=dark']
    },
    {
      name: 'Host',
      type: 'request',
      tags: [],
      desc: 'Nom de domaine du serveur (obligatoire en HTTP/1.1).',
      examples: ['Host: www.example.com', 'Host: api.example.com:8080']
    },
    {
      name: 'Origin',
      type: 'request',
      tags: ['cors'],
      desc: 'Origine de la requête (protocole + domaine + port).',
      examples: ['Origin: https://www.example.com']
    },
    {
      name: 'Referer',
      type: 'request',
      tags: [],
      desc: 'URL de la page d\'où provient la requête.',
      examples: ['Referer: https://www.example.com/page.html']
    },
    {
      name: 'User-Agent',
      type: 'request',
      tags: [],
      desc: 'Identifie le client (navigateur, bot, etc.).',
      examples: ['User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36']
    },
    {
      name: 'X-Requested-With',
      type: 'request',
      tags: [],
      desc: 'Indique une requête AJAX (header non standard mais courant).',
      examples: ['X-Requested-With: XMLHttpRequest']
    },

    // Response Headers
    {
      name: 'Cache-Control',
      type: 'both',
      tags: ['caching'],
      desc: 'Directives de mise en cache.',
      examples: ['Cache-Control: public, max-age=31536000', 'Cache-Control: no-store, no-cache, must-revalidate', 'Cache-Control: private, max-age=3600'],
      values: [
        { val: 'public', desc: 'Peut être mis en cache par tous' },
        { val: 'private', desc: 'Cache uniquement pour l\'utilisateur' },
        { val: 'no-cache', desc: 'Revalider avant utilisation' },
        { val: 'no-store', desc: 'Ne jamais mettre en cache' },
        { val: 'max-age=N', desc: 'Durée de vie en secondes' },
        { val: 'immutable', desc: 'Ne changera jamais' }
      ]
    },
    {
      name: 'ETag',
      type: 'response',
      tags: ['caching'],
      desc: 'Identifiant unique de la version de la ressource.',
      examples: ['ETag: "33a64df551425fcc55e4d42a148795d9f25f89d4"', 'ETag: W/"0815"']
    },
    {
      name: 'Expires',
      type: 'response',
      tags: ['caching'],
      desc: 'Date d\'expiration de la ressource en cache.',
      examples: ['Expires: Wed, 21 Oct 2025 07:28:00 GMT']
    },
    {
      name: 'Last-Modified',
      type: 'response',
      tags: ['caching'],
      desc: 'Date de dernière modification de la ressource.',
      examples: ['Last-Modified: Tue, 15 Nov 2024 12:45:26 GMT']
    },
    {
      name: 'Set-Cookie',
      type: 'response',
      tags: ['security'],
      desc: 'Définit un cookie à stocker côté client.',
      examples: ['Set-Cookie: session=abc123; Path=/; HttpOnly; Secure; SameSite=Strict'],
      values: [
        { val: 'HttpOnly', desc: 'Inaccessible via JavaScript' },
        { val: 'Secure', desc: 'Uniquement sur HTTPS' },
        { val: 'SameSite=Strict', desc: 'Pas envoyé cross-site' },
        { val: 'SameSite=Lax', desc: 'Envoyé sur navigation top-level' },
        { val: 'Max-Age=N', desc: 'Durée de vie en secondes' }
      ]
    },
    {
      name: 'Location',
      type: 'response',
      tags: [],
      desc: 'URL de redirection (avec status 3xx ou 201).',
      examples: ['Location: https://www.example.com/new-page', 'Location: /api/resource/123']
    },
    {
      name: 'Content-Length',
      type: 'both',
      tags: [],
      desc: 'Taille du corps en octets.',
      examples: ['Content-Length: 348']
    },
    {
      name: 'Content-Encoding',
      type: 'response',
      tags: [],
      desc: 'Algorithme de compression utilisé.',
      examples: ['Content-Encoding: gzip', 'Content-Encoding: br']
    },

    // Security Headers
    {
      name: 'Content-Security-Policy',
      type: 'response',
      tags: ['security'],
      desc: 'Politique de sécurité du contenu (CSP) pour prévenir XSS.',
      examples: ["Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'"]
    },
    {
      name: 'Strict-Transport-Security',
      type: 'response',
      tags: ['security'],
      desc: 'Force l\'utilisation de HTTPS (HSTS).',
      examples: ['Strict-Transport-Security: max-age=31536000; includeSubDomains; preload']
    },
    {
      name: 'X-Content-Type-Options',
      type: 'response',
      tags: ['security'],
      desc: 'Empêche le sniffing MIME.',
      examples: ['X-Content-Type-Options: nosniff']
    },
    {
      name: 'X-Frame-Options',
      type: 'response',
      tags: ['security'],
      desc: 'Contrôle l\'affichage dans un iframe (anti-clickjacking).',
      examples: ['X-Frame-Options: DENY', 'X-Frame-Options: SAMEORIGIN'],
      values: [
        { val: 'DENY', desc: 'Jamais dans un iframe' },
        { val: 'SAMEORIGIN', desc: 'Uniquement même origine' }
      ]
    },
    {
      name: 'X-XSS-Protection',
      type: 'response',
      tags: ['security'],
      desc: 'Active le filtre XSS du navigateur (déprécié, utiliser CSP).',
      examples: ['X-XSS-Protection: 1; mode=block']
    },
    {
      name: 'Referrer-Policy',
      type: 'response',
      tags: ['security'],
      desc: 'Contrôle les informations envoyées dans le header Referer.',
      examples: ['Referrer-Policy: strict-origin-when-cross-origin', 'Referrer-Policy: no-referrer'],
      values: [
        { val: 'no-referrer', desc: 'Jamais de Referer' },
        { val: 'same-origin', desc: 'Uniquement même origine' },
        { val: 'strict-origin', desc: 'Origine seulement (pas le path)' }
      ]
    },
    {
      name: 'Permissions-Policy',
      type: 'response',
      tags: ['security'],
      desc: 'Contrôle les fonctionnalités du navigateur (remplace Feature-Policy).',
      examples: ['Permissions-Policy: geolocation=(), camera=(), microphone=()']
    },

    // CORS Headers
    {
      name: 'Access-Control-Allow-Origin',
      type: 'response',
      tags: ['cors'],
      desc: 'Origines autorisées à accéder à la ressource.',
      examples: ['Access-Control-Allow-Origin: https://www.example.com', 'Access-Control-Allow-Origin: *']
    },
    {
      name: 'Access-Control-Allow-Methods',
      type: 'response',
      tags: ['cors'],
      desc: 'Méthodes HTTP autorisées pour CORS.',
      examples: ['Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS']
    },
    {
      name: 'Access-Control-Allow-Headers',
      type: 'response',
      tags: ['cors'],
      desc: 'Headers autorisés dans les requêtes CORS.',
      examples: ['Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With']
    },
    {
      name: 'Access-Control-Allow-Credentials',
      type: 'response',
      tags: ['cors'],
      desc: 'Autorise l\'envoi de credentials (cookies, auth) en CORS.',
      examples: ['Access-Control-Allow-Credentials: true']
    },
    {
      name: 'Access-Control-Max-Age',
      type: 'response',
      tags: ['cors'],
      desc: 'Durée de cache du preflight en secondes.',
      examples: ['Access-Control-Max-Age: 86400']
    },
    {
      name: 'Access-Control-Expose-Headers',
      type: 'response',
      tags: ['cors'],
      desc: 'Headers lisibles par JavaScript côté client.',
      examples: ['Access-Control-Expose-Headers: X-Total-Count, X-Page']
    }
  ];

  let currentFilter = 'all';

  function renderHeaders(data) {
    const container = document.getElementById('headers-container');

    container.innerHTML = data.map((h, i) => {
      const typeClass = h.type === 'request' ? 'badge-request' :
                        h.type === 'response' ? 'badge-response' : 'badge-both';
      const typeLabel = h.type === 'request' ? 'Request' :
                        h.type === 'response' ? 'Response' : 'Both';

      let badges = `<span class="badge ${typeClass}">${typeLabel}</span>`;
      h.tags.forEach(tag => {
        badges += `<span class="badge badge-${tag}">${tag}</span>`;
      });

      let valuesHtml = '';
      if (h.values && h.values.length > 0) {
        valuesHtml = `
          <div class="example-label">Valeurs possibles:</div>
          <table class="values-table">
            <tr><th>Valeur</th><th>Description</th></tr>
            ${h.values.map(v => `<tr><td><code>${v.val}</code></td><td>${v.desc}</td></tr>`).join('')}
          </table>
        `;
      }

      return `
        <div class="header-card" onclick="toggleCard(this)">
          <div class="header-card-header">
            <span class="header-name">${h.name}</span>
            <div class="header-badges">${badges}</div>
          </div>
          <div class="header-card-body">
            <div class="header-desc">${h.desc}</div>
            <div class="example-label">Exemples:</div>
            ${h.examples.map(ex => `
              <div class="example-box">
                ${ex}
                <button class="copy-btn" onclick="event.stopPropagation(); copyHeader('${ex.replace(/'/g, "\\'")}')">Copier</button>
              </div>
            `).join('')}
            ${valuesHtml}
          </div>
        </div>
      `;
    }).join('');

    document.getElementById('header-count').textContent = `${data.length} header${data.length > 1 ? 's' : ''}`;
  }

  window.toggleCard = function(card) {
    card.classList.toggle('expanded');
  };

  window.filterHeaders = function() {
    const query = document.getElementById('header-search').value.toLowerCase();

    let filtered = headers;

    // Apply type/tag filter
    if (currentFilter !== 'all') {
      filtered = filtered.filter(h =>
        h.type === currentFilter || h.tags.includes(currentFilter)
      );
    }

    // Apply search
    if (query) {
      filtered = filtered.filter(h =>
        h.name.toLowerCase().includes(query) ||
        h.desc.toLowerCase().includes(query)
      );
    }

    renderHeaders(filtered);
  };

  window.setHeaderFilter = function(filter) {
    currentFilter = filter;
    document.querySelectorAll('.filter-tab').forEach(tab => {
      tab.classList.toggle('active', tab.dataset.filter === filter);
    });
    filterHeaders();
  };

  window.copyHeader = function(text) {
    navigator.clipboard.writeText(text);
  };

  // Initialize
  renderHeaders(headers);
})();
</script>

---

## Headers essentiels

### Sécurité (OWASP recommandés)

```http
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src 'self'
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), camera=()
```

### Caching

```http
# Ressources statiques (1 an)
Cache-Control: public, max-age=31536000, immutable

# API dynamique (pas de cache)
Cache-Control: no-store, no-cache, must-revalidate

# Avec revalidation
Cache-Control: private, max-age=0, must-revalidate
ETag: "abc123"
```

### API JSON

```http
Content-Type: application/json; charset=utf-8
Accept: application/json
Authorization: Bearer <token>
```
