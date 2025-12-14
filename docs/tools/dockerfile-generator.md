---
tags:
  - tools
  - docker
  - containers
  - devops
---

# Dockerfile Generator

Générateur interactif de Dockerfile avec bonnes pratiques et optimisations.

<div id="dockerfile-generator">
  <style>
    #dockerfile-generator {
      font-family: inherit;
    }
    #dockerfile-generator .generator-container {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 20px;
    }
    @media (max-width: 900px) {
      #dockerfile-generator .generator-container {
        grid-template-columns: 1fr;
      }
    }
    #dockerfile-generator .config-section {
      background: var(--md-code-bg-color);
      border-radius: 8px;
      padding: 20px;
    }
    #dockerfile-generator .output-section {
      background: var(--md-code-bg-color);
      border-radius: 8px;
      padding: 20px;
    }
    #dockerfile-generator .form-group {
      margin-bottom: 15px;
    }
    #dockerfile-generator label {
      display: block;
      margin-bottom: 5px;
      font-weight: 500;
    }
    #dockerfile-generator input[type="text"],
    #dockerfile-generator select,
    #dockerfile-generator textarea {
      width: 100%;
      padding: 8px 12px;
      border: 1px solid var(--md-default-fg-color--lighter);
      border-radius: 4px;
      background: var(--md-default-bg-color);
      color: var(--md-default-fg-color);
      font-size: 14px;
      box-sizing: border-box;
    }
    #dockerfile-generator .checkbox-group {
      display: grid;
      grid-template-columns: repeat(2, 1fr);
      gap: 8px;
    }
    #dockerfile-generator .checkbox-item {
      display: flex;
      align-items: center;
      gap: 8px;
    }
    #dockerfile-generator .checkbox-item input {
      margin: 0;
    }
    #dockerfile-generator .presets {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-bottom: 20px;
    }
    #dockerfile-generator .preset-btn {
      padding: 6px 12px;
      border: 1px solid var(--md-primary-fg-color);
      background: transparent;
      color: var(--md-primary-fg-color);
      border-radius: 4px;
      cursor: pointer;
      font-size: 12px;
    }
    #dockerfile-generator .preset-btn:hover {
      background: var(--md-primary-fg-color);
      color: white;
    }
    #dockerfile-generator .output-box {
      background: var(--md-default-bg-color);
      border: 1px solid var(--md-default-fg-color--lighter);
      border-radius: 4px;
      padding: 15px;
      font-family: 'Consolas', 'Monaco', monospace;
      font-size: 12px;
      white-space: pre-wrap;
      overflow-x: auto;
      min-height: 400px;
      max-height: 600px;
      overflow-y: auto;
    }
    #dockerfile-generator .actions {
      display: flex;
      gap: 10px;
      margin-top: 15px;
    }
    #dockerfile-generator .btn {
      padding: 8px 16px;
      border: none;
      border-radius: 4px;
      cursor: pointer;
      font-size: 14px;
    }
    #dockerfile-generator .btn-primary {
      background: var(--md-primary-fg-color);
      color: white;
    }
    #dockerfile-generator .btn-secondary {
      background: var(--md-default-fg-color--lighter);
      color: var(--md-default-fg-color);
    }
    #dockerfile-generator .section-title {
      font-size: 14px;
      font-weight: 600;
      margin: 20px 0 10px 0;
      padding-bottom: 5px;
      border-bottom: 1px solid var(--md-default-fg-color--lighter);
    }
    #dockerfile-generator .section-title:first-child {
      margin-top: 0;
    }
    #dockerfile-generator .deps-list {
      display: flex;
      flex-wrap: wrap;
      gap: 5px;
      margin-top: 8px;
    }
    #dockerfile-generator .dep-tag {
      display: inline-flex;
      align-items: center;
      gap: 5px;
      padding: 4px 8px;
      background: var(--md-primary-fg-color--light);
      border-radius: 4px;
      font-size: 12px;
    }
    #dockerfile-generator .dep-tag button {
      background: none;
      border: none;
      color: var(--md-default-fg-color);
      cursor: pointer;
      padding: 0;
      font-size: 14px;
    }
  </style>

  <div class="presets">
    <button class="preset-btn" onclick="loadPreset('node')">Node.js</button>
    <button class="preset-btn" onclick="loadPreset('python')">Python</button>
    <button class="preset-btn" onclick="loadPreset('go')">Go</button>
    <button class="preset-btn" onclick="loadPreset('java')">Java</button>
    <button class="preset-btn" onclick="loadPreset('rust')">Rust</button>
    <button class="preset-btn" onclick="loadPreset('nginx')">Nginx</button>
    <button class="preset-btn" onclick="loadPreset('php')">PHP</button>
  </div>

  <div class="generator-container">
    <div class="config-section">
      <div class="section-title">Base Image</div>

      <div class="form-group">
        <label for="df-base">Image de base</label>
        <input type="text" id="df-base" value="node:20-alpine" placeholder="node:20-alpine">
      </div>

      <div class="form-group">
        <label for="df-workdir">Working Directory</label>
        <input type="text" id="df-workdir" value="/app" placeholder="/app">
      </div>

      <div class="section-title">Build Configuration</div>

      <div class="form-group">
        <label for="df-build-deps">Dépendances système (apt/apk)</label>
        <div style="display: flex; gap: 8px;">
          <input type="text" id="df-dep-input" placeholder="curl, git, build-base...">
          <button class="btn btn-secondary" onclick="addDep()">+</button>
        </div>
        <div class="deps-list" id="deps-list"></div>
      </div>

      <div class="form-group">
        <label for="df-copy-files">Fichiers à copier (un par ligne)</label>
        <textarea id="df-copy-files" rows="3" placeholder="package*.json&#10;src/&#10;.">package*.json
.</textarea>
      </div>

      <div class="form-group">
        <label for="df-run-commands">Commandes RUN (une par ligne)</label>
        <textarea id="df-run-commands" rows="4" placeholder="npm install&#10;npm run build">npm ci --only=production</textarea>
      </div>

      <div class="section-title">Runtime</div>

      <div class="form-group">
        <label for="df-port">Port exposé</label>
        <input type="text" id="df-port" value="3000" placeholder="3000">
      </div>

      <div class="form-group">
        <label for="df-user">Utilisateur non-root</label>
        <input type="text" id="df-user" value="node" placeholder="node, appuser...">
      </div>

      <div class="form-group">
        <label for="df-entrypoint">Entrypoint</label>
        <input type="text" id="df-entrypoint" value="" placeholder='["node"]'>
      </div>

      <div class="form-group">
        <label for="df-cmd">CMD</label>
        <input type="text" id="df-cmd" value='["node", "index.js"]' placeholder='["node", "index.js"]'>
      </div>

      <div class="section-title">Options</div>

      <div class="checkbox-group">
        <label class="checkbox-item">
          <input type="checkbox" id="df-multistage"> Multi-stage build
        </label>
        <label class="checkbox-item">
          <input type="checkbox" id="df-healthcheck" checked> Healthcheck
        </label>
        <label class="checkbox-item">
          <input type="checkbox" id="df-labels" checked> Labels OCI
        </label>
        <label class="checkbox-item">
          <input type="checkbox" id="df-security" checked> Security best practices
        </label>
      </div>

      <div id="multistage-options" style="display: none; margin-top: 15px;">
        <div class="form-group">
          <label for="df-builder-image">Image builder</label>
          <input type="text" id="df-builder-image" value="node:20" placeholder="node:20">
        </div>
        <div class="form-group">
          <label for="df-build-cmd">Commande build</label>
          <input type="text" id="df-build-cmd" value="npm run build" placeholder="npm run build">
        </div>
        <div class="form-group">
          <label for="df-build-output">Dossier output</label>
          <input type="text" id="df-build-output" value="dist" placeholder="dist, build, out...">
        </div>
      </div>

      <div id="healthcheck-options" style="margin-top: 15px;">
        <div class="form-group">
          <label for="df-health-cmd">Commande healthcheck</label>
          <input type="text" id="df-health-cmd" value="wget --quiet --tries=1 --spider http://localhost:3000/health || exit 1" placeholder="curl -f http://localhost:3000/health">
        </div>
      </div>
    </div>

    <div class="output-section">
      <div class="section-title">Dockerfile généré</div>
      <div class="output-box" id="dockerfile-output"></div>
      <div class="actions">
        <button class="btn btn-primary" onclick="copyDockerfile()">📋 Copier</button>
        <button class="btn btn-secondary" onclick="downloadDockerfile()">💾 Télécharger</button>
      </div>
    </div>
  </div>
</div>

<script>
(function() {
  const deps = [];

  const presets = {
    node: {
      base: 'node:20-alpine',
      workdir: '/app',
      deps: [],
      copyFiles: 'package*.json\n.',
      runCommands: 'npm ci --only=production',
      port: '3000',
      user: 'node',
      entrypoint: '',
      cmd: '["node", "index.js"]',
      multistage: false,
      healthcheck: true,
      healthCmd: 'wget --quiet --tries=1 --spider http://localhost:3000/health || exit 1',
      builderImage: 'node:20',
      buildCmd: 'npm run build',
      buildOutput: 'dist'
    },
    python: {
      base: 'python:3.12-slim',
      workdir: '/app',
      deps: ['gcc', 'libpq-dev'],
      copyFiles: 'requirements.txt\n.',
      runCommands: 'pip install --no-cache-dir -r requirements.txt',
      port: '8000',
      user: 'appuser',
      entrypoint: '',
      cmd: '["python", "app.py"]',
      multistage: false,
      healthcheck: true,
      healthCmd: 'curl -f http://localhost:8000/health || exit 1',
      builderImage: 'python:3.12',
      buildCmd: 'pip wheel -r requirements.txt -w /wheels',
      buildOutput: '/wheels'
    },
    go: {
      base: 'gcr.io/distroless/static-debian12',
      workdir: '/app',
      deps: [],
      copyFiles: 'go.mod\ngo.sum\n.',
      runCommands: 'go mod download\nCGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main .',
      port: '8080',
      user: 'nonroot',
      entrypoint: '',
      cmd: '["/app/main"]',
      multistage: true,
      healthcheck: false,
      healthCmd: '',
      builderImage: 'golang:1.22-alpine',
      buildCmd: 'CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main .',
      buildOutput: 'main'
    },
    java: {
      base: 'eclipse-temurin:21-jre-alpine',
      workdir: '/app',
      deps: [],
      copyFiles: 'pom.xml\nsrc/',
      runCommands: './mvnw package -DskipTests',
      port: '8080',
      user: 'appuser',
      entrypoint: '',
      cmd: '["java", "-jar", "app.jar"]',
      multistage: true,
      healthcheck: true,
      healthCmd: 'wget --quiet --tries=1 --spider http://localhost:8080/actuator/health || exit 1',
      builderImage: 'eclipse-temurin:21-jdk-alpine',
      buildCmd: './mvnw package -DskipTests',
      buildOutput: 'target/*.jar'
    },
    rust: {
      base: 'gcr.io/distroless/cc-debian12',
      workdir: '/app',
      deps: [],
      copyFiles: 'Cargo.toml\nCargo.lock\nsrc/',
      runCommands: 'cargo build --release',
      port: '8080',
      user: 'nonroot',
      entrypoint: '',
      cmd: '["/app/myapp"]',
      multistage: true,
      healthcheck: false,
      healthCmd: '',
      builderImage: 'rust:1.75-alpine',
      buildCmd: 'cargo build --release',
      buildOutput: 'target/release/myapp'
    },
    nginx: {
      base: 'nginx:alpine',
      workdir: '/usr/share/nginx/html',
      deps: [],
      copyFiles: 'dist/\nnginx.conf:/etc/nginx/nginx.conf',
      runCommands: '',
      port: '80',
      user: 'nginx',
      entrypoint: '',
      cmd: '["nginx", "-g", "daemon off;"]',
      multistage: false,
      healthcheck: true,
      healthCmd: 'wget --quiet --tries=1 --spider http://localhost:80/ || exit 1',
      builderImage: 'node:20',
      buildCmd: 'npm run build',
      buildOutput: 'dist'
    },
    php: {
      base: 'php:8.3-fpm-alpine',
      workdir: '/var/www/html',
      deps: ['libpng-dev', 'libzip-dev'],
      copyFiles: 'composer.json\ncomposer.lock\n.',
      runCommands: 'docker-php-ext-install pdo pdo_mysql gd zip\ncurl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer\ncomposer install --no-dev --optimize-autoloader',
      port: '9000',
      user: 'www-data',
      entrypoint: '',
      cmd: '["php-fpm"]',
      multistage: false,
      healthcheck: true,
      healthCmd: 'php-fpm-healthcheck || exit 1',
      builderImage: 'composer:2',
      buildCmd: 'composer install --no-dev --optimize-autoloader',
      buildOutput: 'vendor'
    }
  };

  window.loadPreset = function(preset) {
    const p = presets[preset];
    document.getElementById('df-base').value = p.base;
    document.getElementById('df-workdir').value = p.workdir;
    document.getElementById('df-copy-files').value = p.copyFiles;
    document.getElementById('df-run-commands').value = p.runCommands;
    document.getElementById('df-port').value = p.port;
    document.getElementById('df-user').value = p.user;
    document.getElementById('df-entrypoint').value = p.entrypoint;
    document.getElementById('df-cmd').value = p.cmd;
    document.getElementById('df-multistage').checked = p.multistage;
    document.getElementById('df-healthcheck').checked = p.healthcheck;
    document.getElementById('df-health-cmd').value = p.healthCmd;
    document.getElementById('df-builder-image').value = p.builderImage;
    document.getElementById('df-build-cmd').value = p.buildCmd;
    document.getElementById('df-build-output').value = p.buildOutput;

    deps.length = 0;
    p.deps.forEach(d => deps.push(d));
    renderDeps();
    toggleMultistage();
    generateDockerfile();
  };

  window.addDep = function() {
    const input = document.getElementById('df-dep-input');
    const val = input.value.trim();
    if (val && !deps.includes(val)) {
      deps.push(val);
      input.value = '';
      renderDeps();
      generateDockerfile();
    }
  };

  window.removeDep = function(dep) {
    const idx = deps.indexOf(dep);
    if (idx > -1) {
      deps.splice(idx, 1);
      renderDeps();
      generateDockerfile();
    }
  };

  function renderDeps() {
    const container = document.getElementById('deps-list');
    container.innerHTML = deps.map(d =>
      `<span class="dep-tag">${d}<button onclick="removeDep('${d}')">&times;</button></span>`
    ).join('');
  }

  function toggleMultistage() {
    const checked = document.getElementById('df-multistage').checked;
    document.getElementById('multistage-options').style.display = checked ? 'block' : 'none';
  }

  function toggleHealthcheck() {
    const checked = document.getElementById('df-healthcheck').checked;
    document.getElementById('healthcheck-options').style.display = checked ? 'block' : 'none';
  }

  function generateDockerfile() {
    const base = document.getElementById('df-base').value || 'alpine';
    const workdir = document.getElementById('df-workdir').value || '/app';
    const copyFiles = document.getElementById('df-copy-files').value.split('\n').filter(f => f.trim());
    const runCommands = document.getElementById('df-run-commands').value.split('\n').filter(c => c.trim());
    const port = document.getElementById('df-port').value;
    const user = document.getElementById('df-user').value;
    const entrypoint = document.getElementById('df-entrypoint').value;
    const cmd = document.getElementById('df-cmd').value;
    const multistage = document.getElementById('df-multistage').checked;
    const healthcheck = document.getElementById('df-healthcheck').checked;
    const healthCmd = document.getElementById('df-health-cmd').value;
    const labels = document.getElementById('df-labels').checked;
    const security = document.getElementById('df-security').checked;
    const builderImage = document.getElementById('df-builder-image').value;
    const buildCmd = document.getElementById('df-build-cmd').value;
    const buildOutput = document.getElementById('df-build-output').value;

    let dockerfile = [];

    // Header comment
    dockerfile.push('# syntax=docker/dockerfile:1');
    dockerfile.push('');

    if (multistage) {
      // Builder stage
      dockerfile.push(`# ==================== BUILD STAGE ====================`);
      dockerfile.push(`FROM ${builderImage} AS builder`);
      dockerfile.push('');
      dockerfile.push(`WORKDIR ${workdir}`);
      dockerfile.push('');

      // Copy files for builder
      copyFiles.forEach(f => {
        if (f.includes(':')) {
          const [src, dest] = f.split(':');
          dockerfile.push(`COPY ${src} ${dest}`);
        } else {
          dockerfile.push(`COPY ${f} .`);
        }
      });
      dockerfile.push('');

      // Build commands
      if (buildCmd) {
        dockerfile.push(`RUN ${buildCmd}`);
      }
      dockerfile.push('');

      // Runtime stage
      dockerfile.push(`# ==================== RUNTIME STAGE ====================`);
      dockerfile.push(`FROM ${base} AS runtime`);
    } else {
      dockerfile.push(`FROM ${base}`);
    }
    dockerfile.push('');

    // Labels
    if (labels) {
      dockerfile.push('# OCI Labels');
      dockerfile.push('LABEL org.opencontainers.image.source="https://github.com/your-org/your-repo"');
      dockerfile.push('LABEL org.opencontainers.image.description="Your application description"');
      dockerfile.push('LABEL org.opencontainers.image.licenses="MIT"');
      dockerfile.push('');
    }

    // Install system dependencies
    if (deps.length > 0) {
      const isAlpine = base.includes('alpine');
      const pkgManager = isAlpine ? 'apk add --no-cache' : 'apt-get update && apt-get install -y --no-install-recommends';
      const cleanup = isAlpine ? '' : ' && rm -rf /var/lib/apt/lists/*';
      dockerfile.push('# Install system dependencies');
      dockerfile.push(`RUN ${pkgManager} ${deps.join(' ')}${cleanup}`);
      dockerfile.push('');
    }

    // Security: create non-root user (if not using distroless)
    if (security && user && !base.includes('distroless')) {
      const isAlpine = base.includes('alpine');
      if (user !== 'node' && user !== 'nginx' && user !== 'www-data') {
        dockerfile.push('# Create non-root user');
        if (isAlpine) {
          dockerfile.push(`RUN addgroup -g 1001 -S ${user} && adduser -S -u 1001 ${user} -G ${user}`);
        } else {
          dockerfile.push(`RUN groupadd -r ${user} && useradd --no-log-init -r -g ${user} ${user}`);
        }
        dockerfile.push('');
      }
    }

    dockerfile.push(`WORKDIR ${workdir}`);
    dockerfile.push('');

    if (multistage) {
      // Copy from builder
      dockerfile.push('# Copy built artifacts from builder');
      dockerfile.push(`COPY --from=builder ${workdir}/${buildOutput} ./${buildOutput}`);
      dockerfile.push('');
    } else {
      // Copy files
      if (copyFiles.length > 0) {
        dockerfile.push('# Copy application files');
        copyFiles.forEach(f => {
          if (f.includes(':')) {
            const [src, dest] = f.split(':');
            dockerfile.push(`COPY ${src} ${dest}`);
          } else {
            dockerfile.push(`COPY ${f} .`);
          }
        });
        dockerfile.push('');
      }

      // Run commands
      if (runCommands.length > 0) {
        dockerfile.push('# Build/install dependencies');
        if (runCommands.length === 1) {
          dockerfile.push(`RUN ${runCommands[0]}`);
        } else {
          dockerfile.push('RUN ' + runCommands.join(' && \\\n    '));
        }
        dockerfile.push('');
      }
    }

    // Change ownership and switch user
    if (security && user) {
      dockerfile.push('# Set ownership and permissions');
      dockerfile.push(`RUN chown -R ${user}:${user} ${workdir}`);
      dockerfile.push('');
      dockerfile.push(`USER ${user}`);
      dockerfile.push('');
    }

    // Expose port
    if (port) {
      dockerfile.push(`EXPOSE ${port}`);
      dockerfile.push('');
    }

    // Healthcheck
    if (healthcheck && healthCmd) {
      dockerfile.push('HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \\');
      dockerfile.push(`    CMD ${healthCmd}`);
      dockerfile.push('');
    }

    // Entrypoint
    if (entrypoint) {
      dockerfile.push(`ENTRYPOINT ${entrypoint}`);
    }

    // CMD
    if (cmd) {
      dockerfile.push(`CMD ${cmd}`);
    }

    document.getElementById('dockerfile-output').textContent = dockerfile.join('\n');
  }

  window.copyDockerfile = function() {
    const content = document.getElementById('dockerfile-output').textContent;
    navigator.clipboard.writeText(content).then(() => {
      const btn = event.target;
      btn.textContent = '✓ Copié!';
      setTimeout(() => btn.textContent = '📋 Copier', 2000);
    });
  };

  window.downloadDockerfile = function() {
    const content = document.getElementById('dockerfile-output').textContent;
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'Dockerfile';
    a.click();
    URL.revokeObjectURL(url);
  };

  // Event listeners
  document.getElementById('df-multistage').addEventListener('change', function() {
    toggleMultistage();
    generateDockerfile();
  });
  document.getElementById('df-healthcheck').addEventListener('change', function() {
    toggleHealthcheck();
    generateDockerfile();
  });

  // Auto-generate on input change
  const inputs = document.querySelectorAll('#dockerfile-generator input, #dockerfile-generator textarea, #dockerfile-generator select');
  inputs.forEach(input => {
    input.addEventListener('input', generateDockerfile);
    input.addEventListener('change', generateDockerfile);
  });

  // Add dep on Enter
  document.getElementById('df-dep-input').addEventListener('keypress', function(e) {
    if (e.key === 'Enter') {
      e.preventDefault();
      addDep();
    }
  });

  // Initialize
  generateDockerfile();
})();
</script>

---

## Bonnes pratiques

### Images de base recommandées

| Langage | Image Production | Image Build |
|---------|-----------------|-------------|
| Node.js | `node:20-alpine` | `node:20` |
| Python | `python:3.12-slim` | `python:3.12` |
| Go | `gcr.io/distroless/static` | `golang:1.22-alpine` |
| Java | `eclipse-temurin:21-jre-alpine` | `eclipse-temurin:21-jdk` |
| Rust | `gcr.io/distroless/cc` | `rust:1.75-alpine` |

### Optimisations

```dockerfile
# Utiliser les build caches
RUN --mount=type=cache,target=/root/.npm npm ci

# Copier les fichiers de dépendances d'abord (meilleur cache)
COPY package*.json ./
RUN npm install
COPY . .

# Multi-stage pour réduire la taille
FROM node:20 AS builder
# ... build
FROM node:20-alpine AS runtime
COPY --from=builder /app/dist ./dist
```

### Sécurité

```dockerfile
# Ne jamais faire
RUN curl http://example.com/script.sh | sh  # Dangereux!
USER root  # Éviter

# Bonnes pratiques
USER node  # Utilisateur non-root
RUN chmod 755 /app  # Permissions minimales
```

---

## Référence rapide

| Instruction | Description |
|------------|-------------|
| `FROM` | Image de base |
| `WORKDIR` | Répertoire de travail |
| `COPY` | Copie fichiers (contexte → image) |
| `ADD` | Comme COPY + extraction tar/URL |
| `RUN` | Exécute commandes |
| `ENV` | Variables d'environnement |
| `ARG` | Arguments de build |
| `EXPOSE` | Documente le port |
| `USER` | Change l'utilisateur |
| `CMD` | Commande par défaut |
| `ENTRYPOINT` | Point d'entrée |
| `HEALTHCHECK` | Vérification santé |
| `LABEL` | Métadonnées |
