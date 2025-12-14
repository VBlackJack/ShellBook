---
tags:
  - tools
  - makefile
  - build
  - automation
---

# Makefile Generator

Générateur de Makefile pour automatiser vos tâches de développement.

<div id="makefile-generator">
  <style>
    #makefile-generator {
      font-family: inherit;
    }
    #makefile-generator .generator-container {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 20px;
    }
    @media (max-width: 900px) {
      #makefile-generator .generator-container {
        grid-template-columns: 1fr;
      }
    }
    #makefile-generator .config-section {
      background: var(--md-code-bg-color);
      border-radius: 8px;
      padding: 20px;
    }
    #makefile-generator .output-section {
      background: var(--md-code-bg-color);
      border-radius: 8px;
      padding: 20px;
    }
    #makefile-generator .form-group {
      margin-bottom: 15px;
    }
    #makefile-generator label {
      display: block;
      margin-bottom: 5px;
      font-weight: 500;
    }
    #makefile-generator input[type="text"],
    #makefile-generator select,
    #makefile-generator textarea {
      width: 100%;
      padding: 8px 12px;
      border: 1px solid var(--md-default-fg-color--lighter);
      border-radius: 4px;
      background: var(--md-default-bg-color);
      color: var(--md-default-fg-color);
      font-size: 14px;
      box-sizing: border-box;
    }
    #makefile-generator .presets {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-bottom: 20px;
    }
    #makefile-generator .preset-btn {
      padding: 6px 12px;
      border: 1px solid var(--md-primary-fg-color);
      background: transparent;
      color: var(--md-primary-fg-color);
      border-radius: 4px;
      cursor: pointer;
      font-size: 12px;
    }
    #makefile-generator .preset-btn:hover {
      background: var(--md-primary-fg-color);
      color: white;
    }
    #makefile-generator .section-title {
      font-size: 14px;
      font-weight: 600;
      margin: 20px 0 10px 0;
      padding-bottom: 5px;
      border-bottom: 1px solid var(--md-default-fg-color--lighter);
    }
    #makefile-generator .section-title:first-child {
      margin-top: 0;
    }
    #makefile-generator .targets-list {
      margin-top: 15px;
    }
    #makefile-generator .target-item {
      background: var(--md-default-bg-color);
      border: 1px solid var(--md-default-fg-color--lighter);
      border-radius: 4px;
      padding: 12px;
      margin-bottom: 10px;
    }
    #makefile-generator .target-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 10px;
    }
    #makefile-generator .target-name {
      font-weight: 600;
      font-family: monospace;
    }
    #makefile-generator .remove-target {
      background: #e74c3c;
      color: white;
      border: none;
      border-radius: 4px;
      padding: 4px 8px;
      cursor: pointer;
      font-size: 12px;
    }
    #makefile-generator .output-box {
      background: var(--md-default-bg-color);
      border: 1px solid var(--md-default-fg-color--lighter);
      border-radius: 4px;
      padding: 15px;
      font-family: 'Consolas', 'Monaco', monospace;
      font-size: 12px;
      white-space: pre;
      overflow-x: auto;
      min-height: 400px;
      max-height: 600px;
      overflow-y: auto;
      tab-size: 4;
    }
    #makefile-generator .actions {
      display: flex;
      gap: 10px;
      margin-top: 15px;
    }
    #makefile-generator .btn {
      padding: 8px 16px;
      border: none;
      border-radius: 4px;
      cursor: pointer;
      font-size: 14px;
    }
    #makefile-generator .btn-primary {
      background: var(--md-primary-fg-color);
      color: white;
    }
    #makefile-generator .btn-secondary {
      background: var(--md-default-fg-color--lighter);
      color: var(--md-default-fg-color);
    }
    #makefile-generator .checkbox-group {
      display: flex;
      flex-wrap: wrap;
      gap: 15px;
    }
    #makefile-generator .checkbox-item {
      display: flex;
      align-items: center;
      gap: 5px;
    }
    #makefile-generator .add-target-form {
      background: var(--md-default-bg-color);
      border: 1px dashed var(--md-primary-fg-color);
      border-radius: 4px;
      padding: 12px;
      margin-top: 10px;
    }
    #makefile-generator .mini-input {
      padding: 6px 10px;
      font-size: 13px;
    }
    #makefile-generator .inline-form {
      display: flex;
      gap: 8px;
      margin-bottom: 8px;
    }
  </style>

  <div class="presets">
    <button class="preset-btn" onclick="loadMakePreset('node')">Node.js</button>
    <button class="preset-btn" onclick="loadMakePreset('python')">Python</button>
    <button class="preset-btn" onclick="loadMakePreset('go')">Go</button>
    <button class="preset-btn" onclick="loadMakePreset('docker')">Docker</button>
    <button class="preset-btn" onclick="loadMakePreset('terraform')">Terraform</button>
    <button class="preset-btn" onclick="loadMakePreset('c')">C/C++</button>
  </div>

  <div class="generator-container">
    <div class="config-section">
      <div class="section-title">Configuration générale</div>

      <div class="form-group">
        <label for="mk-project">Nom du projet</label>
        <input type="text" id="mk-project" value="myproject" placeholder="myproject">
      </div>

      <div class="form-group">
        <label for="mk-shell">Shell</label>
        <select id="mk-shell">
          <option value="/bin/bash">Bash</option>
          <option value="/bin/sh">POSIX sh</option>
          <option value="/usr/bin/env bash">env bash</option>
        </select>
      </div>

      <div class="form-group">
        <label for="mk-default">Target par défaut</label>
        <input type="text" id="mk-default" value="help" placeholder="help, build, all...">
      </div>

      <div class="checkbox-group">
        <label class="checkbox-item">
          <input type="checkbox" id="mk-phony" checked> .PHONY
        </label>
        <label class="checkbox-item">
          <input type="checkbox" id="mk-colors" checked> Couleurs
        </label>
        <label class="checkbox-item">
          <input type="checkbox" id="mk-help" checked> Target help
        </label>
      </div>

      <div class="section-title">Variables</div>
      <div id="variables-container">
        <div class="inline-form">
          <input type="text" class="mini-input" id="var-name" placeholder="Nom" style="width: 30%;">
          <input type="text" class="mini-input" id="var-value" placeholder="Valeur" style="flex: 1;">
          <button class="btn btn-secondary" onclick="addVariable()">+</button>
        </div>
        <div id="vars-list"></div>
      </div>

      <div class="section-title">Targets</div>
      <div class="targets-list" id="targets-list"></div>

      <div class="add-target-form">
        <div class="inline-form">
          <input type="text" class="mini-input" id="new-target-name" placeholder="Nom du target" style="width: 40%;">
          <input type="text" class="mini-input" id="new-target-deps" placeholder="Dépendances" style="flex: 1;">
        </div>
        <div class="inline-form">
          <input type="text" class="mini-input" id="new-target-desc" placeholder="Description (pour help)" style="flex: 1;">
        </div>
        <textarea id="new-target-cmds" rows="2" placeholder="Commandes (une par ligne)"></textarea>
        <button class="btn btn-primary" onclick="addTarget()" style="margin-top: 8px;">Ajouter target</button>
      </div>
    </div>

    <div class="output-section">
      <div class="section-title">Makefile généré</div>
      <div class="output-box" id="makefile-output"></div>
      <div class="actions">
        <button class="btn btn-primary" onclick="copyMakefile()">📋 Copier</button>
        <button class="btn btn-secondary" onclick="downloadMakefile()">💾 Télécharger</button>
      </div>
    </div>
  </div>
</div>

<script>
(function() {
  let targets = [];
  let variables = [];

  const presets = {
    node: {
      project: 'node-app',
      variables: [
        { name: 'NODE_ENV', value: 'development' },
        { name: 'PORT', value: '3000' }
      ],
      targets: [
        { name: 'install', deps: '', desc: 'Install dependencies', cmds: ['npm ci'] },
        { name: 'dev', deps: 'install', desc: 'Start development server', cmds: ['npm run dev'] },
        { name: 'build', deps: 'install', desc: 'Build for production', cmds: ['NODE_ENV=production npm run build'] },
        { name: 'test', deps: '', desc: 'Run tests', cmds: ['npm test'] },
        { name: 'lint', deps: '', desc: 'Run linter', cmds: ['npm run lint'] },
        { name: 'clean', deps: '', desc: 'Clean build artifacts', cmds: ['rm -rf node_modules dist coverage'] }
      ]
    },
    python: {
      project: 'python-app',
      variables: [
        { name: 'PYTHON', value: 'python3' },
        { name: 'VENV', value: '.venv' },
        { name: 'PIP', value: '$(VENV)/bin/pip' }
      ],
      targets: [
        { name: 'venv', deps: '', desc: 'Create virtual environment', cmds: ['$(PYTHON) -m venv $(VENV)'] },
        { name: 'install', deps: 'venv', desc: 'Install dependencies', cmds: ['$(PIP) install -r requirements.txt'] },
        { name: 'install-dev', deps: 'install', desc: 'Install dev dependencies', cmds: ['$(PIP) install -r requirements-dev.txt'] },
        { name: 'run', deps: '', desc: 'Run application', cmds: ['$(VENV)/bin/python app.py'] },
        { name: 'test', deps: '', desc: 'Run tests', cmds: ['$(VENV)/bin/pytest'] },
        { name: 'lint', deps: '', desc: 'Run linter', cmds: ['$(VENV)/bin/ruff check .'] },
        { name: 'clean', deps: '', desc: 'Clean artifacts', cmds: ['rm -rf $(VENV) __pycache__ .pytest_cache .ruff_cache'] }
      ]
    },
    go: {
      project: 'go-app',
      variables: [
        { name: 'BINARY', value: 'app' },
        { name: 'GO', value: 'go' },
        { name: 'GOFLAGS', value: '-ldflags="-s -w"' }
      ],
      targets: [
        { name: 'build', deps: '', desc: 'Build binary', cmds: ['$(GO) build $(GOFLAGS) -o $(BINARY) .'] },
        { name: 'run', deps: 'build', desc: 'Run application', cmds: ['./$(BINARY)'] },
        { name: 'test', deps: '', desc: 'Run tests', cmds: ['$(GO) test -v ./...'] },
        { name: 'test-coverage', deps: '', desc: 'Run tests with coverage', cmds: ['$(GO) test -coverprofile=coverage.out ./...', '$(GO) tool cover -html=coverage.out'] },
        { name: 'lint', deps: '', desc: 'Run linter', cmds: ['golangci-lint run'] },
        { name: 'fmt', deps: '', desc: 'Format code', cmds: ['$(GO) fmt ./...'] },
        { name: 'clean', deps: '', desc: 'Clean artifacts', cmds: ['rm -f $(BINARY) coverage.out'] }
      ]
    },
    docker: {
      project: 'docker-app',
      variables: [
        { name: 'IMAGE', value: 'myapp' },
        { name: 'TAG', value: 'latest' },
        { name: 'REGISTRY', value: 'docker.io' }
      ],
      targets: [
        { name: 'build', deps: '', desc: 'Build Docker image', cmds: ['docker build -t $(IMAGE):$(TAG) .'] },
        { name: 'run', deps: '', desc: 'Run container', cmds: ['docker run --rm -it -p 8080:8080 $(IMAGE):$(TAG)'] },
        { name: 'push', deps: 'build', desc: 'Push to registry', cmds: ['docker tag $(IMAGE):$(TAG) $(REGISTRY)/$(IMAGE):$(TAG)', 'docker push $(REGISTRY)/$(IMAGE):$(TAG)'] },
        { name: 'compose-up', deps: '', desc: 'Start with compose', cmds: ['docker compose up -d'] },
        { name: 'compose-down', deps: '', desc: 'Stop compose', cmds: ['docker compose down'] },
        { name: 'compose-logs', deps: '', desc: 'View compose logs', cmds: ['docker compose logs -f'] },
        { name: 'clean', deps: '', desc: 'Clean images', cmds: ['docker rmi $(IMAGE):$(TAG) || true'] }
      ]
    },
    terraform: {
      project: 'infra',
      variables: [
        { name: 'TF', value: 'terraform' },
        { name: 'ENV', value: 'dev' }
      ],
      targets: [
        { name: 'init', deps: '', desc: 'Initialize Terraform', cmds: ['$(TF) init'] },
        { name: 'plan', deps: '', desc: 'Plan changes', cmds: ['$(TF) plan -var-file=$(ENV).tfvars'] },
        { name: 'apply', deps: '', desc: 'Apply changes', cmds: ['$(TF) apply -var-file=$(ENV).tfvars -auto-approve'] },
        { name: 'destroy', deps: '', desc: 'Destroy infrastructure', cmds: ['$(TF) destroy -var-file=$(ENV).tfvars'] },
        { name: 'fmt', deps: '', desc: 'Format files', cmds: ['$(TF) fmt -recursive'] },
        { name: 'validate', deps: '', desc: 'Validate configuration', cmds: ['$(TF) validate'] },
        { name: 'clean', deps: '', desc: 'Clean Terraform files', cmds: ['rm -rf .terraform .terraform.lock.hcl'] }
      ]
    },
    c: {
      project: 'c-app',
      variables: [
        { name: 'CC', value: 'gcc' },
        { name: 'CFLAGS', value: '-Wall -Wextra -O2' },
        { name: 'LDFLAGS', value: '' },
        { name: 'SRC', value: '$(wildcard src/*.c)' },
        { name: 'OBJ', value: '$(SRC:.c=.o)' },
        { name: 'TARGET', value: 'app' }
      ],
      targets: [
        { name: 'all', deps: '$(TARGET)', desc: 'Build all', cmds: [] },
        { name: '$(TARGET)', deps: '$(OBJ)', desc: '', cmds: ['$(CC) $(LDFLAGS) -o $@ $^'] },
        { name: '%.o', deps: '%.c', desc: '', cmds: ['$(CC) $(CFLAGS) -c -o $@ $<'] },
        { name: 'debug', deps: '', desc: 'Build with debug symbols', cmds: ['$(MAKE) CFLAGS="$(CFLAGS) -g -DDEBUG"'] },
        { name: 'clean', deps: '', desc: 'Clean build files', cmds: ['rm -f $(OBJ) $(TARGET)'] },
        { name: 'install', deps: '$(TARGET)', desc: 'Install binary', cmds: ['install -m 755 $(TARGET) /usr/local/bin/'] }
      ]
    }
  };

  window.loadMakePreset = function(preset) {
    const p = presets[preset];
    document.getElementById('mk-project').value = p.project;
    variables = [...p.variables];
    targets = [...p.targets];
    renderVariables();
    renderTargets();
    generateMakefile();
  };

  window.addVariable = function() {
    const name = document.getElementById('var-name').value.trim();
    const value = document.getElementById('var-value').value.trim();
    if (name) {
      variables.push({ name, value });
      document.getElementById('var-name').value = '';
      document.getElementById('var-value').value = '';
      renderVariables();
      generateMakefile();
    }
  };

  window.removeVariable = function(idx) {
    variables.splice(idx, 1);
    renderVariables();
    generateMakefile();
  };

  function renderVariables() {
    const container = document.getElementById('vars-list');
    container.innerHTML = variables.map((v, i) => `
      <div style="display: flex; gap: 8px; margin-top: 5px; align-items: center;">
        <code style="flex: 1;">${v.name} = ${v.value}</code>
        <button class="btn btn-secondary" onclick="removeVariable(${i})" style="padding: 2px 8px;">×</button>
      </div>
    `).join('');
  }

  window.addTarget = function() {
    const name = document.getElementById('new-target-name').value.trim();
    const deps = document.getElementById('new-target-deps').value.trim();
    const desc = document.getElementById('new-target-desc').value.trim();
    const cmds = document.getElementById('new-target-cmds').value.split('\n').filter(c => c.trim());

    if (name) {
      targets.push({ name, deps, desc, cmds });
      document.getElementById('new-target-name').value = '';
      document.getElementById('new-target-deps').value = '';
      document.getElementById('new-target-desc').value = '';
      document.getElementById('new-target-cmds').value = '';
      renderTargets();
      generateMakefile();
    }
  };

  window.removeTarget = function(idx) {
    targets.splice(idx, 1);
    renderTargets();
    generateMakefile();
  };

  function renderTargets() {
    const container = document.getElementById('targets-list');
    container.innerHTML = targets.map((t, i) => `
      <div class="target-item">
        <div class="target-header">
          <span class="target-name">${t.name}${t.deps ? ': ' + t.deps : ''}</span>
          <button class="remove-target" onclick="removeTarget(${i})">×</button>
        </div>
        ${t.desc ? `<div style="font-size: 12px; color: var(--md-default-fg-color--light); margin-bottom: 5px;">## ${t.desc}</div>` : ''}
        <code style="font-size: 11px;">${t.cmds.join(' && ') || '(no commands)'}</code>
      </div>
    `).join('');
  }

  function generateMakefile() {
    const project = document.getElementById('mk-project').value || 'myproject';
    const shell = document.getElementById('mk-shell').value;
    const defaultTarget = document.getElementById('mk-default').value || 'help';
    const usePhony = document.getElementById('mk-phony').checked;
    const useColors = document.getElementById('mk-colors').checked;
    const useHelp = document.getElementById('mk-help').checked;

    let output = [];

    // Header
    output.push(`# Makefile for ${project}`);
    output.push(`# Generated by ShellBook Makefile Generator`);
    output.push('');

    // Shell
    output.push(`SHELL := ${shell}`);
    output.push('.DEFAULT_GOAL := ' + defaultTarget);
    output.push('');

    // Variables
    if (variables.length > 0) {
      output.push('# Variables');
      variables.forEach(v => {
        output.push(`${v.name} ?= ${v.value}`);
      });
      output.push('');
    }

    // Colors
    if (useColors) {
      output.push('# Colors');
      output.push('GREEN  := $(shell tput setaf 2)');
      output.push('YELLOW := $(shell tput setaf 3)');
      output.push('BLUE   := $(shell tput setaf 4)');
      output.push('RESET  := $(shell tput sgr0)');
      output.push('');
    }

    // PHONY
    if (usePhony) {
      const phonyTargets = targets.filter(t => !t.name.includes('%') && !t.name.includes('$')).map(t => t.name);
      if (useHelp) phonyTargets.unshift('help');
      output.push('.PHONY: ' + phonyTargets.join(' '));
      output.push('');
    }

    // Help target
    if (useHelp) {
      output.push('## help: Show this help message');
      output.push('help:');
      if (useColors) {
        output.push('\t@echo "$(BLUE)Usage:$(RESET)"');
        output.push('\t@echo "  make $(GREEN)<target>$(RESET)"');
        output.push('\t@echo ""');
        output.push('\t@echo "$(BLUE)Targets:$(RESET)"');
        output.push('\t@grep -E \'^## \' $(MAKEFILE_LIST) | sed -e \'s/## //\' | awk -F\': \' \'{printf "  $(GREEN)%-15s$(RESET) %s\\n", $$1, $$2}\'');
      } else {
        output.push('\t@echo "Usage: make <target>"');
        output.push('\t@echo ""');
        output.push('\t@echo "Targets:"');
        output.push('\t@grep -E \'^## \' $(MAKEFILE_LIST) | sed -e \'s/## //\' | awk -F\': \' \'{printf "  %-15s %s\\n", $$1, $$2}\'');
      }
      output.push('');
    }

    // Targets
    targets.forEach(t => {
      if (t.desc) {
        output.push(`## ${t.name}: ${t.desc}`);
      }
      output.push(`${t.name}:${t.deps ? ' ' + t.deps : ''}`);
      t.cmds.forEach(cmd => {
        output.push(`\t${cmd}`);
      });
      output.push('');
    });

    document.getElementById('makefile-output').textContent = output.join('\n');
  }

  window.copyMakefile = function() {
    const content = document.getElementById('makefile-output').textContent;
    navigator.clipboard.writeText(content).then(() => {
      const btn = event.target;
      btn.textContent = '✓ Copié!';
      setTimeout(() => btn.textContent = '📋 Copier', 2000);
    });
  };

  window.downloadMakefile = function() {
    const content = document.getElementById('makefile-output').textContent;
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'Makefile';
    a.click();
    URL.revokeObjectURL(url);
  };

  // Event listeners
  const inputs = document.querySelectorAll('#makefile-generator input, #makefile-generator select');
  inputs.forEach(input => {
    input.addEventListener('input', generateMakefile);
    input.addEventListener('change', generateMakefile);
  });

  // Initialize with Node.js preset
  loadMakePreset('node');
})();
</script>

---

## Syntaxe Makefile

### Variables

```makefile
# Définition
VAR = value        # Expansion récursive
VAR := value       # Expansion simple (immédiate)
VAR ?= value       # Seulement si non défini
VAR += value       # Append

# Utilisation
$(VAR) ou ${VAR}

# Variables automatiques
$@   # Target
$<   # Première dépendance
$^   # Toutes les dépendances
$*   # Stem (dans les patterns)
```

### Targets

```makefile
target: dependencies
	command1
	command2

# Pattern rules
%.o: %.c
	$(CC) -c $< -o $@

# Commandes silencieuses
target:
	@echo "Pas affiché"

# Ignorer erreurs
target:
	-rm file.txt  # Continue même si échoue
```

### Conditionnels

```makefile
ifeq ($(VAR),value)
    # si égal
else
    # sinon
endif

ifdef VAR
    # si défini
endif
```

---

## Commandes utiles

```bash
make              # Target par défaut
make target       # Target spécifique
make -n           # Dry-run (affiche sans exécuter)
make -j4          # Parallèle (4 jobs)
make VAR=value    # Override variable
make -f file.mk   # Fichier alternatif
make -C dir       # Changer de répertoire
```
