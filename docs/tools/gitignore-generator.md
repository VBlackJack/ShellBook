---
tags:
  - tools
  - git
  - development
---

# .gitignore Generator

Générateur de fichiers `.gitignore` adapté à votre stack technologique.

<div id="gitignore-generator">
  <style>
    #gitignore-generator {
      font-family: inherit;
    }
    #gitignore-generator .generator-container {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 20px;
    }
    @media (max-width: 900px) {
      #gitignore-generator .generator-container {
        grid-template-columns: 1fr;
      }
    }
    #gitignore-generator .config-section {
      background: var(--md-code-bg-color);
      border-radius: 8px;
      padding: 20px;
    }
    #gitignore-generator .output-section {
      background: var(--md-code-bg-color);
      border-radius: 8px;
      padding: 20px;
    }
    #gitignore-generator .section-title {
      font-size: 14px;
      font-weight: 600;
      margin: 15px 0 10px 0;
      padding-bottom: 5px;
      border-bottom: 1px solid var(--md-default-fg-color--lighter);
    }
    #gitignore-generator .section-title:first-child {
      margin-top: 0;
    }
    #gitignore-generator .category-grid {
      display: grid;
      grid-template-columns: repeat(2, 1fr);
      gap: 8px;
    }
    #gitignore-generator .category-item {
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 6px 10px;
      background: var(--md-default-bg-color);
      border-radius: 4px;
      cursor: pointer;
      transition: background 0.2s;
    }
    #gitignore-generator .category-item:hover {
      background: var(--md-primary-fg-color--light);
    }
    #gitignore-generator .category-item input {
      margin: 0;
    }
    #gitignore-generator .category-item label {
      cursor: pointer;
      font-size: 13px;
    }
    #gitignore-generator .quick-presets {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-bottom: 15px;
    }
    #gitignore-generator .preset-btn {
      padding: 6px 12px;
      border: 1px solid var(--md-primary-fg-color);
      background: transparent;
      color: var(--md-primary-fg-color);
      border-radius: 4px;
      cursor: pointer;
      font-size: 12px;
    }
    #gitignore-generator .preset-btn:hover {
      background: var(--md-primary-fg-color);
      color: white;
    }
    #gitignore-generator .preset-btn.active {
      background: var(--md-primary-fg-color);
      color: white;
    }
    #gitignore-generator .output-box {
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
    #gitignore-generator .actions {
      display: flex;
      gap: 10px;
      margin-top: 15px;
    }
    #gitignore-generator .btn {
      padding: 8px 16px;
      border: none;
      border-radius: 4px;
      cursor: pointer;
      font-size: 14px;
    }
    #gitignore-generator .btn-primary {
      background: var(--md-primary-fg-color);
      color: white;
    }
    #gitignore-generator .btn-secondary {
      background: var(--md-default-fg-color--lighter);
      color: var(--md-default-fg-color);
    }
    #gitignore-generator .custom-rules {
      margin-top: 15px;
    }
    #gitignore-generator textarea {
      width: 100%;
      padding: 10px;
      border: 1px solid var(--md-default-fg-color--lighter);
      border-radius: 4px;
      background: var(--md-default-bg-color);
      color: var(--md-default-fg-color);
      font-family: 'Consolas', 'Monaco', monospace;
      font-size: 12px;
      resize: vertical;
      box-sizing: border-box;
    }
    #gitignore-generator .stats {
      font-size: 12px;
      color: var(--md-default-fg-color--light);
      margin-top: 10px;
    }
  </style>

  <div class="quick-presets">
    <button class="preset-btn" onclick="selectStack('frontend')">🌐 Frontend</button>
    <button class="preset-btn" onclick="selectStack('backend-node')">📦 Node.js</button>
    <button class="preset-btn" onclick="selectStack('backend-python')">🐍 Python</button>
    <button class="preset-btn" onclick="selectStack('backend-go')">🔷 Go</button>
    <button class="preset-btn" onclick="selectStack('backend-java')">☕ Java</button>
    <button class="preset-btn" onclick="selectStack('mobile')">📱 Mobile</button>
    <button class="preset-btn" onclick="selectStack('devops')">🐳 DevOps</button>
    <button class="preset-btn" onclick="selectStack('all')">✅ Tout</button>
    <button class="preset-btn" onclick="selectStack('none')">❌ Reset</button>
  </div>

  <div class="generator-container">
    <div class="config-section">
      <div class="section-title">📁 Langages & Frameworks</div>
      <div class="category-grid" id="languages-grid"></div>

      <div class="section-title">🛠️ IDE & Éditeurs</div>
      <div class="category-grid" id="ide-grid"></div>

      <div class="section-title">💻 OS & Système</div>
      <div class="category-grid" id="os-grid"></div>

      <div class="section-title">⚙️ Build & CI</div>
      <div class="category-grid" id="build-grid"></div>

      <div class="custom-rules">
        <div class="section-title">📝 Règles personnalisées</div>
        <textarea id="custom-rules" rows="4" placeholder="# Ajouter vos règles personnalisées&#10;*.custom&#10;/local-config/"></textarea>
      </div>
    </div>

    <div class="output-section">
      <div class="section-title">.gitignore généré</div>
      <div class="output-box" id="gitignore-output"></div>
      <div class="stats" id="gitignore-stats"></div>
      <div class="actions">
        <button class="btn btn-primary" onclick="copyGitignore()">📋 Copier</button>
        <button class="btn btn-secondary" onclick="downloadGitignore()">💾 Télécharger</button>
      </div>
    </div>
  </div>
</div>

<script>
(function() {
  const templates = {
    // Languages & Frameworks
    node: {
      name: 'Node.js',
      category: 'languages',
      rules: `# Node.js
node_modules/
npm-debug.log*
yarn-debug.log*
yarn-error.log*
.pnpm-debug.log*
lerna-debug.log*
.npm
.yarn/cache
.yarn/unplugged
.yarn/install-state.gz
.pnp.*`
    },
    python: {
      name: 'Python',
      category: 'languages',
      rules: `# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg
.venv/
venv/
ENV/
env/
.pytest_cache/
.mypy_cache/
.ruff_cache/`
    },
    go: {
      name: 'Go',
      category: 'languages',
      rules: `# Go
*.exe
*.exe~
*.dll
*.so
*.dylib
*.test
*.out
go.work
vendor/`
    },
    java: {
      name: 'Java',
      category: 'languages',
      rules: `# Java
*.class
*.jar
*.war
*.ear
*.zip
*.tar.gz
*.rar
hs_err_pid*
replay_pid*
target/
.gradle/
build/
!gradle-wrapper.jar`
    },
    rust: {
      name: 'Rust',
      category: 'languages',
      rules: `# Rust
/target/
Cargo.lock
**/*.rs.bk
*.pdb`
    },
    csharp: {
      name: 'C#/.NET',
      category: 'languages',
      rules: `# C#/.NET
bin/
obj/
*.user
*.suo
*.userosscache
*.sln.docstates
.vs/
packages/
*.nupkg
*.snupkg
*.nuget.props
*.nuget.targets`
    },
    php: {
      name: 'PHP',
      category: 'languages',
      rules: `# PHP
/vendor/
composer.phar
composer.lock
.phpunit.result.cache
.php-cs-fixer.cache
*.log`
    },
    ruby: {
      name: 'Ruby',
      category: 'languages',
      rules: `# Ruby
*.gem
*.rbc
/.config
/coverage/
/InstalledFiles
/pkg/
/spec/reports/
/tmp/
.bundle/
vendor/bundle
.byebug_history`
    },
    react: {
      name: 'React',
      category: 'languages',
      rules: `# React
.next/
out/
build/
.vercel
.turbo`
    },
    vue: {
      name: 'Vue.js',
      category: 'languages',
      rules: `# Vue.js
.nuxt/
dist/
.output/
.nitro/
.cache/`
    },
    angular: {
      name: 'Angular',
      category: 'languages',
      rules: `# Angular
dist/
tmp/
.angular/
.sass-cache/`
    },
    // IDEs
    vscode: {
      name: 'VS Code',
      category: 'ide',
      rules: `# VS Code
.vscode/*
!.vscode/settings.json
!.vscode/tasks.json
!.vscode/launch.json
!.vscode/extensions.json
*.code-workspace
.history/`
    },
    intellij: {
      name: 'IntelliJ/JetBrains',
      category: 'ide',
      rules: `# JetBrains
.idea/
*.iml
*.iws
*.ipr
out/
.idea_modules/`
    },
    vim: {
      name: 'Vim',
      category: 'ide',
      rules: `# Vim
[._]*.s[a-v][a-z]
[._]*.sw[a-p]
[._]s[a-rt-v][a-z]
[._]ss[a-gi-z]
[._]sw[a-p]
Session.vim
Sessionx.vim
.netrwhist
*~
tags`
    },
    emacs: {
      name: 'Emacs',
      category: 'ide',
      rules: `# Emacs
*~
\\#*\\#
/.emacs.desktop
/.emacs.desktop.lock
*.elc
auto-save-list
tramp
.\\#*
.org-id-locations
*_archive
*.org_archive`
    },
    sublime: {
      name: 'Sublime Text',
      category: 'ide',
      rules: `# Sublime Text
*.tmlanguage.cache
*.tmPreferences.cache
*.stTheme.cache
*.sublime-workspace
*.sublime-project`
    },
    // OS
    macos: {
      name: 'macOS',
      category: 'os',
      rules: `# macOS
.DS_Store
.AppleDouble
.LSOverride
._*
.DocumentRevisions-V100
.fseventsd
.Spotlight-V100
.TemporaryItems
.Trashes
.VolumeIcon.icns
.com.apple.timemachine.donotpresent
.AppleDB
.AppleDesktop
Network Trash Folder
Temporary Items
.apdisk`
    },
    windows: {
      name: 'Windows',
      category: 'os',
      rules: `# Windows
Thumbs.db
Thumbs.db:encryptable
ehthumbs.db
ehthumbs_vista.db
*.stackdump
[Dd]esktop.ini
$RECYCLE.BIN/
*.lnk`
    },
    linux: {
      name: 'Linux',
      category: 'os',
      rules: `# Linux
*~
.fuse_hidden*
.directory
.Trash-*
.nfs*`
    },
    // Build & CI
    docker: {
      name: 'Docker',
      category: 'build',
      rules: `# Docker
.docker/
docker-compose*.override.yml`
    },
    terraform: {
      name: 'Terraform',
      category: 'build',
      rules: `# Terraform
.terraform/
*.tfstate
*.tfstate.*
crash.log
crash.*.log
*.tfvars
*.tfvars.json
override.tf
override.tf.json
*_override.tf
*_override.tf.json
.terraformrc
terraform.rc`
    },
    ansible: {
      name: 'Ansible',
      category: 'build',
      rules: `# Ansible
*.retry
inventory/*
!inventory/example`
    },
    kubernetes: {
      name: 'Kubernetes',
      category: 'build',
      rules: `# Kubernetes
kubeconfig
*.kubeconfig
.helm/`
    },
    ci: {
      name: 'CI/CD',
      category: 'build',
      rules: `# CI/CD
.github/
!.github/workflows/
.gitlab-ci-local/`
    },
    env: {
      name: 'Env & Secrets',
      category: 'build',
      rules: `# Environment & Secrets
.env
.env.*
!.env.example
!.env.template
*.pem
*.key
*.crt
secrets/
.secrets`
    },
    logs: {
      name: 'Logs & Cache',
      category: 'build',
      rules: `# Logs & Cache
logs/
*.log
.cache/
.temp/
.tmp/
tmp/
temp/`
    },
    coverage: {
      name: 'Tests & Coverage',
      category: 'build',
      rules: `# Tests & Coverage
coverage/
*.lcov
.nyc_output/
htmlcov/
.coverage
.coverage.*
nosetests.xml
coverage.xml`
    }
  };

  const stacks = {
    frontend: ['node', 'react', 'vue', 'angular', 'vscode', 'macos', 'windows', 'env', 'logs', 'coverage'],
    'backend-node': ['node', 'vscode', 'macos', 'windows', 'docker', 'env', 'logs', 'coverage'],
    'backend-python': ['python', 'vscode', 'macos', 'windows', 'docker', 'env', 'logs', 'coverage'],
    'backend-go': ['go', 'vscode', 'macos', 'windows', 'docker', 'env', 'logs'],
    'backend-java': ['java', 'intellij', 'macos', 'windows', 'docker', 'env', 'logs', 'coverage'],
    mobile: ['node', 'react', 'vscode', 'macos', 'windows', 'env'],
    devops: ['docker', 'terraform', 'ansible', 'kubernetes', 'ci', 'env', 'logs', 'vscode', 'macos', 'windows'],
    all: Object.keys(templates),
    none: []
  };

  function init() {
    const categories = {
      languages: document.getElementById('languages-grid'),
      ide: document.getElementById('ide-grid'),
      os: document.getElementById('os-grid'),
      build: document.getElementById('build-grid')
    };

    Object.entries(templates).forEach(([key, template]) => {
      const container = categories[template.category];
      if (container) {
        const item = document.createElement('div');
        item.className = 'category-item';
        item.innerHTML = `
          <input type="checkbox" id="gi-${key}" onchange="generateGitignore()">
          <label for="gi-${key}">${template.name}</label>
        `;
        item.onclick = (e) => {
          if (e.target.tagName !== 'INPUT') {
            const checkbox = item.querySelector('input');
            checkbox.checked = !checkbox.checked;
            generateGitignore();
          }
        };
        container.appendChild(item);
      }
    });

    document.getElementById('custom-rules').addEventListener('input', generateGitignore);

    // Default selection
    selectStack('backend-node');
  }

  window.selectStack = function(stack) {
    const selection = stacks[stack] || [];

    // Reset all
    Object.keys(templates).forEach(key => {
      const cb = document.getElementById(`gi-${key}`);
      if (cb) cb.checked = selection.includes(key);
    });

    generateGitignore();
  };

  window.generateGitignore = function() {
    const selected = [];
    Object.keys(templates).forEach(key => {
      const cb = document.getElementById(`gi-${key}`);
      if (cb && cb.checked) {
        selected.push(templates[key]);
      }
    });

    let output = [];
    output.push('# ===========================================');
    output.push('# .gitignore - Generated by ShellBook');
    output.push('# ===========================================');
    output.push('');

    selected.forEach(template => {
      output.push(template.rules);
      output.push('');
    });

    // Custom rules
    const custom = document.getElementById('custom-rules').value.trim();
    if (custom) {
      output.push('# Custom rules');
      output.push(custom);
      output.push('');
    }

    const result = output.join('\n');
    document.getElementById('gitignore-output').textContent = result;

    // Stats
    const lines = result.split('\n').filter(l => l.trim() && !l.startsWith('#')).length;
    document.getElementById('gitignore-stats').textContent =
      `${selected.length} catégorie(s) • ${lines} règle(s)`;
  };

  window.copyGitignore = function() {
    const content = document.getElementById('gitignore-output').textContent;
    navigator.clipboard.writeText(content).then(() => {
      const btn = event.target;
      btn.textContent = '✓ Copié!';
      setTimeout(() => btn.textContent = '📋 Copier', 2000);
    });
  };

  window.downloadGitignore = function() {
    const content = document.getElementById('gitignore-output').textContent;
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = '.gitignore';
    a.click();
    URL.revokeObjectURL(url);
  };

  init();
})();
</script>

---

## Syntaxe .gitignore

| Pattern | Description | Exemple |
|---------|-------------|---------|
| `*` | Wildcard (tout sauf `/`) | `*.log` |
| `**` | Wildcard récursif | `**/temp/` |
| `?` | Un caractère | `file?.txt` |
| `[abc]` | Un parmi a, b, c | `[Dd]ebug/` |
| `/` en début | Depuis la racine | `/build/` |
| `/` en fin | Dossier seulement | `logs/` |
| `!` | Négation (inclusion) | `!important.log` |
| `#` | Commentaire | `# Ignore logs` |

---

## Exemples avancés

```gitignore
# Ignorer tout sauf certains fichiers
*
!.gitignore
!src/
!src/**

# Ignorer dans tous les sous-dossiers
**/node_modules/
**/.cache/

# Ignorer sauf un fichier spécifique
*.env
!.env.example

# Ignorer par extension sauf un fichier
*.log
!important.log

# Ignorer dossier mais garder un sous-dossier
build/
!build/public/
```

---

## Ressources

- [gitignore.io](https://gitignore.io) - Générateur en ligne
- [GitHub gitignore templates](https://github.com/github/gitignore)
- [Documentation Git](https://git-scm.com/docs/gitignore)
