---
tags:
  - tools
  - http
  - web
  - reference
---

# HTTP Status Codes

Reference complete des codes de statut HTTP.

<div class="tool-container">

<div class="search-section">
    <input type="text" id="status-search" placeholder="Rechercher par code ou description...">
</div>

<div class="status-grid" id="status-grid">
</div>

</div>

## Categories

| Plage | Categorie | Description |
|-------|-----------|-------------|
| **1xx** | Informational | Requete recue, processus continue |
| **2xx** | Success | Requete recue, comprise et acceptee |
| **3xx** | Redirection | Action supplementaire necessaire |
| **4xx** | Client Error | Erreur cote client |
| **5xx** | Server Error | Erreur cote serveur |

## Codes les plus courants

### Success (2xx)

| Code | Nom | Usage |
|------|-----|-------|
| **200** | OK | Succes standard |
| **201** | Created | Ressource creee (POST) |
| **204** | No Content | Succes sans corps (DELETE) |

### Redirection (3xx)

| Code | Nom | Usage |
|------|-----|-------|
| **301** | Moved Permanently | Redirection permanente (SEO) |
| **302** | Found | Redirection temporaire |
| **304** | Not Modified | Cache valide |
| **307** | Temporary Redirect | Comme 302, preserve la methode |
| **308** | Permanent Redirect | Comme 301, preserve la methode |

### Client Errors (4xx)

| Code | Nom | Usage |
|------|-----|-------|
| **400** | Bad Request | Requete malformee |
| **401** | Unauthorized | Authentification requise |
| **403** | Forbidden | Acces refuse |
| **404** | Not Found | Ressource introuvable |
| **405** | Method Not Allowed | Methode HTTP non supportee |
| **409** | Conflict | Conflit (ex: doublon) |
| **429** | Too Many Requests | Rate limiting |

### Server Errors (5xx)

| Code | Nom | Usage |
|------|-----|-------|
| **500** | Internal Server Error | Erreur generique serveur |
| **502** | Bad Gateway | Erreur proxy/gateway |
| **503** | Service Unavailable | Maintenance/surcharge |
| **504** | Gateway Timeout | Timeout proxy |

## API REST - Bonnes pratiques

| Operation | Methode | Succes | Erreur typique |
|-----------|---------|--------|----------------|
| Lister | GET | 200 | 404 |
| Obtenir | GET | 200 | 404 |
| Creer | POST | 201 | 400, 409 |
| Modifier | PUT/PATCH | 200 | 400, 404 |
| Supprimer | DELETE | 204 | 404 |

<style>
.tool-container {
    background: var(--md-code-bg-color);
    padding: 20px;
    border-radius: 8px;
    margin: 20px 0;
}
.search-section {
    margin-bottom: 20px;
}
.search-section input {
    width: 100%;
    max-width: 400px;
    padding: 12px;
    font-size: 16px;
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    background: var(--md-default-bg-color);
    color: var(--md-default-fg-color);
}
.status-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
    gap: 10px;
}
.status-card {
    background: var(--md-default-bg-color);
    padding: 15px;
    border-radius: 4px;
    border-left: 4px solid;
    cursor: pointer;
    transition: transform 0.1s;
}
.status-card:hover {
    transform: translateX(5px);
}
.status-card.info { border-color: #17a2b8; }
.status-card.success { border-color: #28a745; }
.status-card.redirect { border-color: #ffc107; }
.status-card.client-error { border-color: #dc3545; }
.status-card.server-error { border-color: #6f42c1; }
.status-card .code {
    font-size: 24px;
    font-weight: bold;
    font-family: monospace;
}
.status-card.info .code { color: #17a2b8; }
.status-card.success .code { color: #28a745; }
.status-card.redirect .code { color: #ffc107; }
.status-card.client-error .code { color: #dc3545; }
.status-card.server-error .code { color: #6f42c1; }
.status-card .name {
    font-weight: bold;
    margin: 5px 0;
}
.status-card .desc {
    font-size: 13px;
    color: var(--md-default-fg-color--light);
}
</style>

<script>
const httpCodes = [
    // 1xx Informational
    { code: 100, name: 'Continue', desc: 'Le client peut continuer sa requete', category: 'info' },
    { code: 101, name: 'Switching Protocols', desc: 'Changement de protocole accepte (ex: WebSocket)', category: 'info' },
    { code: 102, name: 'Processing', desc: 'Requete en cours de traitement (WebDAV)', category: 'info' },
    { code: 103, name: 'Early Hints', desc: 'Headers preliminaires (preload)', category: 'info' },

    // 2xx Success
    { code: 200, name: 'OK', desc: 'Requete reussie', category: 'success' },
    { code: 201, name: 'Created', desc: 'Ressource creee avec succes', category: 'success' },
    { code: 202, name: 'Accepted', desc: 'Requete acceptee, traitement en cours', category: 'success' },
    { code: 203, name: 'Non-Authoritative Information', desc: 'Informations modifiees par proxy', category: 'success' },
    { code: 204, name: 'No Content', desc: 'Succes sans contenu a retourner', category: 'success' },
    { code: 205, name: 'Reset Content', desc: 'Reinitialiser le document', category: 'success' },
    { code: 206, name: 'Partial Content', desc: 'Contenu partiel (Range requests)', category: 'success' },
    { code: 207, name: 'Multi-Status', desc: 'Plusieurs statuts (WebDAV)', category: 'success' },

    // 3xx Redirection
    { code: 300, name: 'Multiple Choices', desc: 'Plusieurs representations disponibles', category: 'redirect' },
    { code: 301, name: 'Moved Permanently', desc: 'Ressource deplacee definitivement', category: 'redirect' },
    { code: 302, name: 'Found', desc: 'Ressource temporairement ailleurs', category: 'redirect' },
    { code: 303, name: 'See Other', desc: 'Voir autre ressource (GET)', category: 'redirect' },
    { code: 304, name: 'Not Modified', desc: 'Ressource non modifiee (cache)', category: 'redirect' },
    { code: 305, name: 'Use Proxy', desc: 'Utiliser le proxy specifie (obsolete)', category: 'redirect' },
    { code: 307, name: 'Temporary Redirect', desc: 'Redirection temporaire (meme methode)', category: 'redirect' },
    { code: 308, name: 'Permanent Redirect', desc: 'Redirection permanente (meme methode)', category: 'redirect' },

    // 4xx Client Errors
    { code: 400, name: 'Bad Request', desc: 'Requete malformee ou invalide', category: 'client-error' },
    { code: 401, name: 'Unauthorized', desc: 'Authentification requise', category: 'client-error' },
    { code: 402, name: 'Payment Required', desc: 'Paiement requis (reserve)', category: 'client-error' },
    { code: 403, name: 'Forbidden', desc: 'Acces refuse meme avec authentification', category: 'client-error' },
    { code: 404, name: 'Not Found', desc: 'Ressource introuvable', category: 'client-error' },
    { code: 405, name: 'Method Not Allowed', desc: 'Methode HTTP non autorisee', category: 'client-error' },
    { code: 406, name: 'Not Acceptable', desc: 'Contenu non acceptable (Accept headers)', category: 'client-error' },
    { code: 407, name: 'Proxy Authentication Required', desc: 'Authentification proxy requise', category: 'client-error' },
    { code: 408, name: 'Request Timeout', desc: 'Timeout de la requete', category: 'client-error' },
    { code: 409, name: 'Conflict', desc: 'Conflit avec etat actuel (ex: doublon)', category: 'client-error' },
    { code: 410, name: 'Gone', desc: 'Ressource definitivement supprimee', category: 'client-error' },
    { code: 411, name: 'Length Required', desc: 'Content-Length requis', category: 'client-error' },
    { code: 412, name: 'Precondition Failed', desc: 'Precondition non satisfaite', category: 'client-error' },
    { code: 413, name: 'Payload Too Large', desc: 'Corps de requete trop grand', category: 'client-error' },
    { code: 414, name: 'URI Too Long', desc: 'URL trop longue', category: 'client-error' },
    { code: 415, name: 'Unsupported Media Type', desc: 'Type de contenu non supporte', category: 'client-error' },
    { code: 416, name: 'Range Not Satisfiable', desc: 'Plage demandee non satisfaisable', category: 'client-error' },
    { code: 417, name: 'Expectation Failed', desc: 'Attente Expect non satisfaite', category: 'client-error' },
    { code: 418, name: "I'm a teapot", desc: 'Je suis une theiere (April Fools)', category: 'client-error' },
    { code: 421, name: 'Misdirected Request', desc: 'Requete mal dirigee', category: 'client-error' },
    { code: 422, name: 'Unprocessable Entity', desc: 'Entite non traitable (validation)', category: 'client-error' },
    { code: 423, name: 'Locked', desc: 'Ressource verrouillee (WebDAV)', category: 'client-error' },
    { code: 424, name: 'Failed Dependency', desc: 'Echec dependance (WebDAV)', category: 'client-error' },
    { code: 425, name: 'Too Early', desc: 'Trop tot (replay attack)', category: 'client-error' },
    { code: 426, name: 'Upgrade Required', desc: 'Mise a jour protocole requise', category: 'client-error' },
    { code: 428, name: 'Precondition Required', desc: 'Precondition requise', category: 'client-error' },
    { code: 429, name: 'Too Many Requests', desc: 'Trop de requetes (rate limiting)', category: 'client-error' },
    { code: 431, name: 'Request Header Fields Too Large', desc: 'Headers trop grands', category: 'client-error' },
    { code: 451, name: 'Unavailable For Legal Reasons', desc: 'Indisponible pour raisons legales', category: 'client-error' },

    // 5xx Server Errors
    { code: 500, name: 'Internal Server Error', desc: 'Erreur interne du serveur', category: 'server-error' },
    { code: 501, name: 'Not Implemented', desc: 'Fonctionnalite non implementee', category: 'server-error' },
    { code: 502, name: 'Bad Gateway', desc: 'Reponse invalide du serveur amont', category: 'server-error' },
    { code: 503, name: 'Service Unavailable', desc: 'Service indisponible (maintenance)', category: 'server-error' },
    { code: 504, name: 'Gateway Timeout', desc: 'Timeout du serveur amont', category: 'server-error' },
    { code: 505, name: 'HTTP Version Not Supported', desc: 'Version HTTP non supportee', category: 'server-error' },
    { code: 506, name: 'Variant Also Negotiates', desc: 'Negociation circulaire', category: 'server-error' },
    { code: 507, name: 'Insufficient Storage', desc: 'Stockage insuffisant (WebDAV)', category: 'server-error' },
    { code: 508, name: 'Loop Detected', desc: 'Boucle detectee (WebDAV)', category: 'server-error' },
    { code: 510, name: 'Not Extended', desc: 'Extension requise', category: 'server-error' },
    { code: 511, name: 'Network Authentication Required', desc: 'Authentification reseau requise', category: 'server-error' }
];

function renderCodes(codes) {
    const grid = document.getElementById('status-grid');
    grid.innerHTML = codes.map(code => `
        <div class="status-card ${code.category}">
            <div class="code">${code.code}</div>
            <div class="name">${code.name}</div>
            <div class="desc">${code.desc}</div>
        </div>
    `).join('');
}

function filterCodes() {
    const search = document.getElementById('status-search').value.toLowerCase();

    if (!search) {
        renderCodes(httpCodes);
        return;
    }

    const filtered = httpCodes.filter(code =>
        code.code.toString().includes(search) ||
        code.name.toLowerCase().includes(search) ||
        code.desc.toLowerCase().includes(search)
    );

    renderCodes(filtered);
}

// Event listener
document.getElementById('status-search').addEventListener('input', filterCodes);

// Initial render
renderCodes(httpCodes);
</script>
