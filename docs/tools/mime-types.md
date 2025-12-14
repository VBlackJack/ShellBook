---
tags:
  - tools
  - mime
  - web
  - reference
---

# MIME Types Reference

Référence complète des types MIME avec recherche interactive.

<div id="mime-types">
  <style>
    #mime-types {
      font-family: inherit;
    }
    #mime-types .search-section {
      background: var(--md-code-bg-color);
      border-radius: 8px;
      padding: 20px;
      margin-bottom: 20px;
    }
    #mime-types .search-input {
      width: 100%;
      padding: 12px 15px;
      font-size: 16px;
      border: 2px solid var(--md-default-fg-color--lighter);
      border-radius: 8px;
      background: var(--md-default-bg-color);
      color: var(--md-default-fg-color);
      box-sizing: border-box;
    }
    #mime-types .search-input:focus {
      border-color: var(--md-primary-fg-color);
      outline: none;
    }
    #mime-types .filter-tabs {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-top: 15px;
    }
    #mime-types .filter-tab {
      padding: 6px 12px;
      border: 1px solid var(--md-default-fg-color--lighter);
      background: var(--md-default-bg-color);
      color: var(--md-default-fg-color);
      border-radius: 20px;
      cursor: pointer;
      font-size: 12px;
      transition: all 0.2s;
    }
    #mime-types .filter-tab:hover {
      border-color: var(--md-primary-fg-color);
    }
    #mime-types .filter-tab.active {
      background: var(--md-primary-fg-color);
      border-color: var(--md-primary-fg-color);
      color: white;
    }
    #mime-types .results-section {
      background: var(--md-code-bg-color);
      border-radius: 8px;
      padding: 20px;
    }
    #mime-types .results-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 15px;
      padding-bottom: 10px;
      border-bottom: 1px solid var(--md-default-fg-color--lighter);
    }
    #mime-types .results-count {
      font-size: 14px;
      color: var(--md-default-fg-color--light);
    }
    #mime-types .mime-table {
      width: 100%;
      border-collapse: collapse;
    }
    #mime-types .mime-table th {
      text-align: left;
      padding: 12px 10px;
      background: var(--md-default-bg-color);
      font-weight: 600;
      font-size: 13px;
      position: sticky;
      top: 0;
    }
    #mime-types .mime-table td {
      padding: 10px;
      border-bottom: 1px solid var(--md-default-fg-color--lighter);
      font-size: 13px;
    }
    #mime-types .mime-table tr:hover td {
      background: var(--md-default-bg-color);
    }
    #mime-types .mime-type {
      font-family: monospace;
      color: var(--md-primary-fg-color);
      cursor: pointer;
    }
    #mime-types .mime-type:hover {
      text-decoration: underline;
    }
    #mime-types .extension {
      font-family: monospace;
      background: var(--md-primary-fg-color--light);
      padding: 2px 6px;
      border-radius: 4px;
      font-size: 11px;
      margin-right: 4px;
    }
    #mime-types .category-badge {
      display: inline-block;
      padding: 3px 8px;
      border-radius: 4px;
      font-size: 10px;
      font-weight: 500;
    }
    #mime-types .category-text { background: #3498db22; color: #3498db; }
    #mime-types .category-image { background: #9b59b622; color: #9b59b6; }
    #mime-types .category-audio { background: #e74c3c22; color: #e74c3c; }
    #mime-types .category-video { background: #e67e2222; color: #e67e22; }
    #mime-types .category-application { background: #27ae6022; color: #27ae60; }
    #mime-types .category-font { background: #1abc9c22; color: #1abc9c; }
    #mime-types .category-multipart { background: #f39c1222; color: #f39c12; }
    #mime-types .table-container {
      max-height: 500px;
      overflow-y: auto;
      overflow-x: hidden;
    }
    #mime-types .copy-toast {
      position: fixed;
      bottom: 20px;
      right: 20px;
      background: var(--md-primary-fg-color);
      color: white;
      padding: 10px 20px;
      border-radius: 4px;
      display: none;
      z-index: 1000;
    }
  </style>

  <div class="search-section">
    <input type="text" class="search-input" id="mime-search" placeholder="Rechercher par extension, type MIME ou description..." oninput="filterMimeTypes()">
    <div class="filter-tabs">
      <button class="filter-tab active" data-filter="all" onclick="setFilter('all')">Tous</button>
      <button class="filter-tab" data-filter="text" onclick="setFilter('text')">📄 Text</button>
      <button class="filter-tab" data-filter="image" onclick="setFilter('image')">🖼️ Image</button>
      <button class="filter-tab" data-filter="audio" onclick="setFilter('audio')">🎵 Audio</button>
      <button class="filter-tab" data-filter="video" onclick="setFilter('video')">🎬 Video</button>
      <button class="filter-tab" data-filter="application" onclick="setFilter('application')">📦 Application</button>
      <button class="filter-tab" data-filter="font" onclick="setFilter('font')">🔤 Font</button>
    </div>
  </div>

  <div class="results-section">
    <div class="results-header">
      <span class="results-count" id="results-count">0 résultats</span>
    </div>
    <div class="table-container">
      <table class="mime-table">
        <thead>
          <tr>
            <th>Type MIME</th>
            <th>Extensions</th>
            <th>Description</th>
            <th>Catégorie</th>
          </tr>
        </thead>
        <tbody id="mime-tbody"></tbody>
      </table>
    </div>
  </div>

  <div class="copy-toast" id="copy-toast">Copié!</div>
</div>

<script>
(function() {
  const mimeTypes = [
    // Text
    { type: 'text/plain', ext: ['.txt'], desc: 'Texte brut', cat: 'text' },
    { type: 'text/html', ext: ['.html', '.htm'], desc: 'Document HTML', cat: 'text' },
    { type: 'text/css', ext: ['.css'], desc: 'Feuille de style CSS', cat: 'text' },
    { type: 'text/javascript', ext: ['.js', '.mjs'], desc: 'JavaScript', cat: 'text' },
    { type: 'text/csv', ext: ['.csv'], desc: 'Données CSV', cat: 'text' },
    { type: 'text/xml', ext: ['.xml'], desc: 'Document XML', cat: 'text' },
    { type: 'text/markdown', ext: ['.md', '.markdown'], desc: 'Document Markdown', cat: 'text' },
    { type: 'text/calendar', ext: ['.ics'], desc: 'Calendrier iCalendar', cat: 'text' },
    { type: 'text/x-python', ext: ['.py'], desc: 'Script Python', cat: 'text' },
    { type: 'text/x-java-source', ext: ['.java'], desc: 'Code source Java', cat: 'text' },
    { type: 'text/x-c', ext: ['.c', '.h'], desc: 'Code source C', cat: 'text' },
    { type: 'text/x-shellscript', ext: ['.sh'], desc: 'Script Shell', cat: 'text' },
    { type: 'text/yaml', ext: ['.yaml', '.yml'], desc: 'Document YAML', cat: 'text' },

    // Images
    { type: 'image/jpeg', ext: ['.jpg', '.jpeg'], desc: 'Image JPEG', cat: 'image' },
    { type: 'image/png', ext: ['.png'], desc: 'Image PNG', cat: 'image' },
    { type: 'image/gif', ext: ['.gif'], desc: 'Image GIF', cat: 'image' },
    { type: 'image/webp', ext: ['.webp'], desc: 'Image WebP', cat: 'image' },
    { type: 'image/svg+xml', ext: ['.svg'], desc: 'Image SVG', cat: 'image' },
    { type: 'image/x-icon', ext: ['.ico'], desc: 'Icône', cat: 'image' },
    { type: 'image/avif', ext: ['.avif'], desc: 'Image AVIF', cat: 'image' },
    { type: 'image/bmp', ext: ['.bmp'], desc: 'Image Bitmap', cat: 'image' },
    { type: 'image/tiff', ext: ['.tiff', '.tif'], desc: 'Image TIFF', cat: 'image' },
    { type: 'image/heic', ext: ['.heic'], desc: 'Image HEIC (Apple)', cat: 'image' },
    { type: 'image/heif', ext: ['.heif'], desc: 'Image HEIF', cat: 'image' },

    // Audio
    { type: 'audio/mpeg', ext: ['.mp3'], desc: 'Audio MP3', cat: 'audio' },
    { type: 'audio/ogg', ext: ['.ogg', '.oga'], desc: 'Audio Ogg', cat: 'audio' },
    { type: 'audio/wav', ext: ['.wav'], desc: 'Audio WAV', cat: 'audio' },
    { type: 'audio/webm', ext: ['.weba'], desc: 'Audio WebM', cat: 'audio' },
    { type: 'audio/aac', ext: ['.aac'], desc: 'Audio AAC', cat: 'audio' },
    { type: 'audio/flac', ext: ['.flac'], desc: 'Audio FLAC', cat: 'audio' },
    { type: 'audio/midi', ext: ['.mid', '.midi'], desc: 'Audio MIDI', cat: 'audio' },
    { type: 'audio/mp4', ext: ['.m4a'], desc: 'Audio M4A', cat: 'audio' },

    // Video
    { type: 'video/mp4', ext: ['.mp4'], desc: 'Vidéo MP4', cat: 'video' },
    { type: 'video/webm', ext: ['.webm'], desc: 'Vidéo WebM', cat: 'video' },
    { type: 'video/ogg', ext: ['.ogv'], desc: 'Vidéo Ogg', cat: 'video' },
    { type: 'video/quicktime', ext: ['.mov'], desc: 'Vidéo QuickTime', cat: 'video' },
    { type: 'video/x-msvideo', ext: ['.avi'], desc: 'Vidéo AVI', cat: 'video' },
    { type: 'video/mpeg', ext: ['.mpeg', '.mpg'], desc: 'Vidéo MPEG', cat: 'video' },
    { type: 'video/x-matroska', ext: ['.mkv'], desc: 'Vidéo Matroska', cat: 'video' },
    { type: 'video/x-flv', ext: ['.flv'], desc: 'Vidéo Flash', cat: 'video' },

    // Applications - Documents
    { type: 'application/pdf', ext: ['.pdf'], desc: 'Document PDF', cat: 'application' },
    { type: 'application/json', ext: ['.json'], desc: 'Données JSON', cat: 'application' },
    { type: 'application/xml', ext: ['.xml'], desc: 'Données XML', cat: 'application' },
    { type: 'application/zip', ext: ['.zip'], desc: 'Archive ZIP', cat: 'application' },
    { type: 'application/gzip', ext: ['.gz'], desc: 'Archive GZIP', cat: 'application' },
    { type: 'application/x-tar', ext: ['.tar'], desc: 'Archive TAR', cat: 'application' },
    { type: 'application/x-rar-compressed', ext: ['.rar'], desc: 'Archive RAR', cat: 'application' },
    { type: 'application/x-7z-compressed', ext: ['.7z'], desc: 'Archive 7-Zip', cat: 'application' },
    { type: 'application/x-bzip2', ext: ['.bz2'], desc: 'Archive BZIP2', cat: 'application' },

    // Applications - MS Office
    { type: 'application/msword', ext: ['.doc'], desc: 'Microsoft Word', cat: 'application' },
    { type: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', ext: ['.docx'], desc: 'Microsoft Word (OpenXML)', cat: 'application' },
    { type: 'application/vnd.ms-excel', ext: ['.xls'], desc: 'Microsoft Excel', cat: 'application' },
    { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', ext: ['.xlsx'], desc: 'Microsoft Excel (OpenXML)', cat: 'application' },
    { type: 'application/vnd.ms-powerpoint', ext: ['.ppt'], desc: 'Microsoft PowerPoint', cat: 'application' },
    { type: 'application/vnd.openxmlformats-officedocument.presentationml.presentation', ext: ['.pptx'], desc: 'Microsoft PowerPoint (OpenXML)', cat: 'application' },

    // Applications - OpenDocument
    { type: 'application/vnd.oasis.opendocument.text', ext: ['.odt'], desc: 'OpenDocument Text', cat: 'application' },
    { type: 'application/vnd.oasis.opendocument.spreadsheet', ext: ['.ods'], desc: 'OpenDocument Spreadsheet', cat: 'application' },
    { type: 'application/vnd.oasis.opendocument.presentation', ext: ['.odp'], desc: 'OpenDocument Presentation', cat: 'application' },

    // Applications - Code/Dev
    { type: 'application/javascript', ext: ['.js'], desc: 'JavaScript', cat: 'application' },
    { type: 'application/typescript', ext: ['.ts'], desc: 'TypeScript', cat: 'application' },
    { type: 'application/x-httpd-php', ext: ['.php'], desc: 'Script PHP', cat: 'application' },
    { type: 'application/wasm', ext: ['.wasm'], desc: 'WebAssembly', cat: 'application' },
    { type: 'application/x-sh', ext: ['.sh'], desc: 'Script Shell', cat: 'application' },
    { type: 'application/sql', ext: ['.sql'], desc: 'Script SQL', cat: 'application' },

    // Applications - Binary
    { type: 'application/octet-stream', ext: ['.bin', '.exe', '.dll'], desc: 'Données binaires', cat: 'application' },
    { type: 'application/x-executable', ext: ['.exe'], desc: 'Exécutable', cat: 'application' },
    { type: 'application/vnd.apple.installer+xml', ext: ['.mpkg'], desc: 'Installer macOS', cat: 'application' },
    { type: 'application/x-deb', ext: ['.deb'], desc: 'Package Debian', cat: 'application' },
    { type: 'application/x-rpm', ext: ['.rpm'], desc: 'Package RPM', cat: 'application' },
    { type: 'application/vnd.android.package-archive', ext: ['.apk'], desc: 'Application Android', cat: 'application' },
    { type: 'application/java-archive', ext: ['.jar'], desc: 'Archive Java', cat: 'application' },

    // Applications - Web
    { type: 'application/x-www-form-urlencoded', ext: [], desc: 'Formulaire URL-encodé', cat: 'application' },
    { type: 'application/ld+json', ext: ['.jsonld'], desc: 'JSON-LD', cat: 'application' },
    { type: 'application/manifest+json', ext: ['.webmanifest'], desc: 'Web App Manifest', cat: 'application' },
    { type: 'application/rss+xml', ext: ['.rss'], desc: 'Flux RSS', cat: 'application' },
    { type: 'application/atom+xml', ext: ['.atom'], desc: 'Flux Atom', cat: 'application' },
    { type: 'application/graphql', ext: ['.graphql'], desc: 'GraphQL', cat: 'application' },

    // Fonts
    { type: 'font/woff', ext: ['.woff'], desc: 'Web Open Font Format', cat: 'font' },
    { type: 'font/woff2', ext: ['.woff2'], desc: 'WOFF 2.0', cat: 'font' },
    { type: 'font/ttf', ext: ['.ttf'], desc: 'TrueType Font', cat: 'font' },
    { type: 'font/otf', ext: ['.otf'], desc: 'OpenType Font', cat: 'font' },
    { type: 'font/eot', ext: ['.eot'], desc: 'Embedded OpenType', cat: 'font' },

    // Multipart
    { type: 'multipart/form-data', ext: [], desc: 'Formulaire multipart', cat: 'multipart' },
    { type: 'multipart/byteranges', ext: [], desc: 'Réponse partielle', cat: 'multipart' }
  ];

  let currentFilter = 'all';

  function renderTable(data) {
    const tbody = document.getElementById('mime-tbody');
    tbody.innerHTML = data.map(m => `
      <tr>
        <td><span class="mime-type" onclick="copyMimeType('${m.type}')">${m.type}</span></td>
        <td>${m.ext.map(e => `<span class="extension">${e}</span>`).join('')}</td>
        <td>${m.desc}</td>
        <td><span class="category-badge category-${m.cat}">${m.cat}</span></td>
      </tr>
    `).join('');

    document.getElementById('results-count').textContent = `${data.length} résultat${data.length > 1 ? 's' : ''}`;
  }

  window.filterMimeTypes = function() {
    const query = document.getElementById('mime-search').value.toLowerCase();

    let filtered = mimeTypes;

    // Apply category filter
    if (currentFilter !== 'all') {
      filtered = filtered.filter(m => m.cat === currentFilter);
    }

    // Apply search
    if (query) {
      filtered = filtered.filter(m =>
        m.type.toLowerCase().includes(query) ||
        m.ext.some(e => e.toLowerCase().includes(query)) ||
        m.desc.toLowerCase().includes(query)
      );
    }

    renderTable(filtered);
  };

  window.setFilter = function(filter) {
    currentFilter = filter;
    document.querySelectorAll('.filter-tab').forEach(tab => {
      tab.classList.toggle('active', tab.dataset.filter === filter);
    });
    filterMimeTypes();
  };

  window.copyMimeType = function(type) {
    navigator.clipboard.writeText(type).then(() => {
      const toast = document.getElementById('copy-toast');
      toast.style.display = 'block';
      setTimeout(() => toast.style.display = 'none', 1500);
    });
  };

  // Initialize
  renderTable(mimeTypes);
})();
</script>

---

## Types MIME courants

### Web

| Extension | Type MIME | Usage |
|-----------|-----------|-------|
| `.html` | `text/html` | Pages web |
| `.css` | `text/css` | Styles |
| `.js` | `text/javascript` | Scripts |
| `.json` | `application/json` | API, Config |
| `.xml` | `application/xml` | Données |

### Images

| Extension | Type MIME | Support navigateur |
|-----------|-----------|-------------------|
| `.jpg` | `image/jpeg` | Universel |
| `.png` | `image/png` | Universel |
| `.gif` | `image/gif` | Universel |
| `.webp` | `image/webp` | Moderne |
| `.avif` | `image/avif` | Récent |
| `.svg` | `image/svg+xml` | Universel |

### Documents

| Extension | Type MIME |
|-----------|-----------|
| `.pdf` | `application/pdf` |
| `.docx` | `application/vnd.openxmlformats-officedocument.wordprocessingml.document` |
| `.xlsx` | `application/vnd.openxmlformats-officedocument.spreadsheetml.sheet` |

---

## Configuration serveur

### Nginx

```nginx
types {
    text/html                             html htm;
    text/css                              css;
    text/javascript                       js mjs;
    application/json                      json;
    image/webp                            webp;
    font/woff2                            woff2;
}
```

### Apache (.htaccess)

```apache
AddType text/javascript .js .mjs
AddType application/json .json
AddType image/webp .webp
AddType font/woff2 .woff2
```
