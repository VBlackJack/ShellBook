---
tags:
  - tools
  - git
  - vcs
  - command
  - builder
---

# Git Command Builder

Constructeur interactif de commandes Git pour les operations courantes.

<div class="tool-container">

<div class="category-selector">
    <button class="cat-btn active" onclick="selectCategory('branch')">Branches</button>
    <button class="cat-btn" onclick="selectCategory('commit')">Commits</button>
    <button class="cat-btn" onclick="selectCategory('remote')">Remote</button>
    <button class="cat-btn" onclick="selectCategory('undo')">Undo</button>
    <button class="cat-btn" onclick="selectCategory('stash')">Stash</button>
    <button class="cat-btn" onclick="selectCategory('log')">Log</button>
    <button class="cat-btn" onclick="selectCategory('diff')">Diff</button>
</div>

<div class="builder-section" id="builder-section">
    <!-- Dynamic content -->
</div>

<div class="output-section">
    <h4>Commande generee</h4>
    <div class="command-output">
        <code id="command-output">git status</code>
        <button onclick="copyCommand()" class="copy-btn">Copier</button>
    </div>
</div>

<div class="cheatsheet-section">
    <h3>Aide-memoire</h3>
    <div class="cheat-tabs">
        <button class="cheat-btn active" onclick="showCheat('basic')">Basique</button>
        <button class="cheat-btn" onclick="showCheat('branch')">Branches</button>
        <button class="cheat-btn" onclick="showCheat('advanced')">Avance</button>
    </div>

    <div class="cheat-content" id="basic-cheat">
        <table class="cheat-table">
            <tr><td><code>git init</code></td><td>Initialiser un depot</td></tr>
            <tr><td><code>git clone &lt;url&gt;</code></td><td>Cloner un depot</td></tr>
            <tr><td><code>git status</code></td><td>Voir l'etat actuel</td></tr>
            <tr><td><code>git add .</code></td><td>Ajouter tous les fichiers</td></tr>
            <tr><td><code>git commit -m "msg"</code></td><td>Creer un commit</td></tr>
            <tr><td><code>git push</code></td><td>Pousser vers remote</td></tr>
            <tr><td><code>git pull</code></td><td>Tirer depuis remote</td></tr>
            <tr><td><code>git log --oneline</code></td><td>Historique compact</td></tr>
        </table>
    </div>

    <div class="cheat-content" id="branch-cheat" style="display: none;">
        <table class="cheat-table">
            <tr><td><code>git branch</code></td><td>Lister les branches locales</td></tr>
            <tr><td><code>git branch -a</code></td><td>Lister toutes les branches</td></tr>
            <tr><td><code>git branch &lt;name&gt;</code></td><td>Creer une branche</td></tr>
            <tr><td><code>git checkout &lt;branch&gt;</code></td><td>Changer de branche</td></tr>
            <tr><td><code>git checkout -b &lt;name&gt;</code></td><td>Creer et changer</td></tr>
            <tr><td><code>git merge &lt;branch&gt;</code></td><td>Fusionner une branche</td></tr>
            <tr><td><code>git branch -d &lt;name&gt;</code></td><td>Supprimer une branche</td></tr>
            <tr><td><code>git rebase &lt;branch&gt;</code></td><td>Rebaser sur une branche</td></tr>
        </table>
    </div>

    <div class="cheat-content" id="advanced-cheat" style="display: none;">
        <table class="cheat-table">
            <tr><td><code>git cherry-pick &lt;hash&gt;</code></td><td>Appliquer un commit specifique</td></tr>
            <tr><td><code>git bisect start</code></td><td>Recherche dichotomique</td></tr>
            <tr><td><code>git reflog</code></td><td>Historique des refs</td></tr>
            <tr><td><code>git reset --hard HEAD~1</code></td><td>Annuler dernier commit</td></tr>
            <tr><td><code>git revert &lt;hash&gt;</code></td><td>Inverser un commit</td></tr>
            <tr><td><code>git stash</code></td><td>Mettre de cote les changements</td></tr>
            <tr><td><code>git clean -fd</code></td><td>Supprimer fichiers non-suivis</td></tr>
            <tr><td><code>git worktree add</code></td><td>Ajouter un worktree</td></tr>
        </table>
    </div>
</div>

</div>

## Aliases Utiles

```bash
# ~/.gitconfig
[alias]
    co = checkout
    br = branch
    ci = commit
    st = status
    lg = log --oneline --graph --decorate
    last = log -1 HEAD
    unstage = reset HEAD --
    amend = commit --amend --no-edit

# Voir tous les alias
git config --get-regexp alias
```

<style>
.tool-container {
    background: var(--md-code-bg-color);
    padding: 20px;
    border-radius: 8px;
    margin: 20px 0;
}
.category-selector {
    display: flex;
    gap: 10px;
    flex-wrap: wrap;
    margin-bottom: 20px;
}
.cat-btn {
    padding: 10px 16px;
    background: var(--md-default-bg-color);
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    cursor: pointer;
    color: var(--md-default-fg-color);
}
.cat-btn.active {
    background: var(--md-primary-fg-color);
    color: white;
    border-color: var(--md-primary-fg-color);
}
.builder-section, .output-section, .cheatsheet-section {
    background: var(--md-default-bg-color);
    padding: 20px;
    border-radius: 4px;
    margin-bottom: 20px;
}
.builder-section h4, .output-section h4, .cheatsheet-section h3 {
    margin: 0 0 15px 0;
}
.form-row {
    display: flex;
    gap: 15px;
    margin-bottom: 15px;
    flex-wrap: wrap;
}
.form-group {
    flex: 1;
    min-width: 200px;
}
.form-group label {
    display: block;
    font-size: 12px;
    font-weight: bold;
    margin-bottom: 5px;
}
.form-group input, .form-group select {
    width: 100%;
    padding: 10px;
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    background: var(--md-code-bg-color);
    color: var(--md-default-fg-color);
    font-family: monospace;
}
.form-group input[type="checkbox"] {
    width: auto;
    margin-right: 8px;
}
.checkbox-label {
    display: flex;
    align-items: center;
    padding: 10px 0;
    cursor: pointer;
}
.command-output {
    display: flex;
    gap: 15px;
    align-items: center;
}
.command-output code {
    flex: 1;
    padding: 15px;
    background: #1e1e1e;
    color: #4ec9b0;
    border-radius: 4px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 14px;
    word-break: break-all;
}
.copy-btn {
    padding: 10px 20px;
    background: var(--md-primary-fg-color);
    color: white;
    border: none;
    border-radius: 4px;
    cursor: pointer;
}
.cheat-tabs {
    display: flex;
    gap: 10px;
    margin-bottom: 15px;
}
.cheat-btn {
    padding: 8px 16px;
    background: var(--md-code-bg-color);
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    cursor: pointer;
    color: var(--md-default-fg-color);
}
.cheat-btn.active {
    background: var(--md-primary-fg-color);
    color: white;
}
.cheat-table {
    width: 100%;
    border-collapse: collapse;
}
.cheat-table td {
    padding: 10px;
    border-bottom: 1px solid var(--md-default-fg-color--lightest);
}
.cheat-table code {
    background: var(--md-code-bg-color);
    padding: 3px 8px;
    border-radius: 3px;
    white-space: nowrap;
}
.quick-actions {
    display: flex;
    gap: 10px;
    flex-wrap: wrap;
    margin-top: 15px;
}
.quick-btn {
    padding: 8px 12px;
    background: var(--md-code-bg-color);
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    cursor: pointer;
    font-size: 12px;
    color: var(--md-default-fg-color);
}
.quick-btn:hover {
    background: var(--md-primary-fg-color);
    color: white;
}
.warning-text {
    color: #f39c12;
    font-size: 12px;
    margin-top: 5px;
}
.danger-text {
    color: #e74c3c;
    font-size: 12px;
    margin-top: 5px;
}
</style>

<script>
const BUILDERS = {
    branch: {
        title: 'Operations sur les Branches',
        fields: [
            { id: 'branch-action', type: 'select', label: 'Action', options: [
                { value: 'list', label: 'Lister les branches' },
                { value: 'create', label: 'Creer une branche' },
                { value: 'checkout', label: 'Changer de branche' },
                { value: 'create-checkout', label: 'Creer et changer' },
                { value: 'delete', label: 'Supprimer une branche' },
                { value: 'rename', label: 'Renommer une branche' },
                { value: 'merge', label: 'Fusionner une branche' }
            ]},
            { id: 'branch-name', type: 'text', label: 'Nom de la branche', placeholder: 'feature/new-feature' },
            { id: 'branch-all', type: 'checkbox', label: 'Inclure branches distantes (-a)' },
            { id: 'branch-force', type: 'checkbox', label: 'Forcer (-f/-D)' }
        ],
        build: (values) => {
            const { 'branch-action': action, 'branch-name': name, 'branch-all': all, 'branch-force': force } = values;
            switch (action) {
                case 'list': return `git branch${all ? ' -a' : ''}`;
                case 'create': return `git branch ${name || '<branch-name>'}`;
                case 'checkout': return `git checkout ${name || '<branch-name>'}`;
                case 'create-checkout': return `git checkout -b ${name || '<branch-name>'}`;
                case 'delete': return `git branch ${force ? '-D' : '-d'} ${name || '<branch-name>'}`;
                case 'rename': return `git branch -m ${name || '<new-name>'}`;
                case 'merge': return `git merge ${name || '<branch-name>'}`;
                default: return 'git branch';
            }
        }
    },
    commit: {
        title: 'Operations de Commit',
        fields: [
            { id: 'commit-action', type: 'select', label: 'Action', options: [
                { value: 'commit', label: 'Creer un commit' },
                { value: 'amend', label: 'Modifier le dernier commit' },
                { value: 'add-commit', label: 'Add + Commit' },
                { value: 'fixup', label: 'Fixup commit' }
            ]},
            { id: 'commit-message', type: 'text', label: 'Message', placeholder: 'feat: add new feature' },
            { id: 'commit-all', type: 'checkbox', label: 'Inclure tous les fichiers modifies (-a)' },
            { id: 'commit-noedit', type: 'checkbox', label: 'Garder le message (--no-edit)' }
        ],
        build: (values) => {
            const { 'commit-action': action, 'commit-message': msg, 'commit-all': all, 'commit-noedit': noedit } = values;
            const message = msg || '<message>';
            switch (action) {
                case 'commit': return `git commit${all ? ' -a' : ''} -m "${message}"`;
                case 'amend': return `git commit --amend${noedit ? ' --no-edit' : ` -m "${message}"`}`;
                case 'add-commit': return `git add . && git commit -m "${message}"`;
                case 'fixup': return `git commit --fixup ${message}`;
                default: return 'git commit';
            }
        }
    },
    remote: {
        title: 'Operations Remote',
        fields: [
            { id: 'remote-action', type: 'select', label: 'Action', options: [
                { value: 'push', label: 'Push' },
                { value: 'pull', label: 'Pull' },
                { value: 'fetch', label: 'Fetch' },
                { value: 'add', label: 'Ajouter un remote' },
                { value: 'list', label: 'Lister les remotes' },
                { value: 'set-url', label: 'Modifier URL' }
            ]},
            { id: 'remote-name', type: 'text', label: 'Remote', placeholder: 'origin' },
            { id: 'remote-branch', type: 'text', label: 'Branche', placeholder: 'main' },
            { id: 'remote-url', type: 'text', label: 'URL', placeholder: 'git@github.com:user/repo.git' },
            { id: 'remote-force', type: 'checkbox', label: 'Forcer (--force)' },
            { id: 'remote-upstream', type: 'checkbox', label: 'Set upstream (-u)' }
        ],
        build: (values) => {
            const { 'remote-action': action, 'remote-name': name, 'remote-branch': branch, 'remote-url': url, 'remote-force': force, 'remote-upstream': upstream } = values;
            const remote = name || 'origin';
            const br = branch || '';
            switch (action) {
                case 'push': return `git push${force ? ' --force' : ''}${upstream ? ' -u' : ''} ${remote}${br ? ' ' + br : ''}`;
                case 'pull': return `git pull ${remote}${br ? ' ' + br : ''}`;
                case 'fetch': return `git fetch ${remote}${br ? ' ' + br : ''}`;
                case 'add': return `git remote add ${remote} ${url || '<url>'}`;
                case 'list': return 'git remote -v';
                case 'set-url': return `git remote set-url ${remote} ${url || '<url>'}`;
                default: return 'git remote';
            }
        }
    },
    undo: {
        title: 'Annuler des Changements',
        fields: [
            { id: 'undo-action', type: 'select', label: 'Action', options: [
                { value: 'unstage', label: 'Unstage fichiers' },
                { value: 'discard', label: 'Abandonner changements' },
                { value: 'reset-soft', label: 'Reset soft (garde changements)' },
                { value: 'reset-hard', label: 'Reset hard (supprime tout)' },
                { value: 'revert', label: 'Revert un commit' },
                { value: 'clean', label: 'Nettoyer fichiers non-suivis' }
            ]},
            { id: 'undo-ref', type: 'text', label: 'Reference/Fichier', placeholder: 'HEAD~1 ou fichier.txt' },
            { id: 'undo-force', type: 'checkbox', label: 'Forcer' }
        ],
        build: (values) => {
            const { 'undo-action': action, 'undo-ref': ref, 'undo-force': force } = values;
            const target = ref || 'HEAD~1';
            switch (action) {
                case 'unstage': return `git reset HEAD ${ref || '.'}`;
                case 'discard': return `git checkout -- ${ref || '.'}`;
                case 'reset-soft': return `git reset --soft ${target}`;
                case 'reset-hard': return `git reset --hard ${target}`;
                case 'revert': return `git revert ${ref || '<commit-hash>'}`;
                case 'clean': return `git clean -fd${force ? 'x' : ''}`;
                default: return 'git status';
            }
        }
    },
    stash: {
        title: 'Gestion du Stash',
        fields: [
            { id: 'stash-action', type: 'select', label: 'Action', options: [
                { value: 'save', label: 'Sauvegarder' },
                { value: 'list', label: 'Lister' },
                { value: 'apply', label: 'Appliquer' },
                { value: 'pop', label: 'Pop (appliquer et supprimer)' },
                { value: 'drop', label: 'Supprimer' },
                { value: 'clear', label: 'Tout supprimer' },
                { value: 'show', label: 'Voir le contenu' }
            ]},
            { id: 'stash-message', type: 'text', label: 'Message/Index', placeholder: 'WIP: feature' },
            { id: 'stash-include-untracked', type: 'checkbox', label: 'Inclure non-suivis (-u)' }
        ],
        build: (values) => {
            const { 'stash-action': action, 'stash-message': msg, 'stash-include-untracked': untracked } = values;
            switch (action) {
                case 'save': return `git stash${untracked ? ' -u' : ''}${msg ? ` -m "${msg}"` : ''}`;
                case 'list': return 'git stash list';
                case 'apply': return `git stash apply ${msg || 'stash@{0}'}`;
                case 'pop': return `git stash pop ${msg || ''}`.trim();
                case 'drop': return `git stash drop ${msg || 'stash@{0}'}`;
                case 'clear': return 'git stash clear';
                case 'show': return `git stash show -p ${msg || 'stash@{0}'}`;
                default: return 'git stash';
            }
        }
    },
    log: {
        title: 'Historique',
        fields: [
            { id: 'log-format', type: 'select', label: 'Format', options: [
                { value: 'default', label: 'Par defaut' },
                { value: 'oneline', label: 'Une ligne' },
                { value: 'graph', label: 'Graphique' },
                { value: 'pretty', label: 'Personnalise' }
            ]},
            { id: 'log-count', type: 'text', label: 'Nombre de commits', placeholder: '10' },
            { id: 'log-author', type: 'text', label: 'Auteur', placeholder: 'john' },
            { id: 'log-since', type: 'text', label: 'Depuis', placeholder: '2024-01-01' },
            { id: 'log-path', type: 'text', label: 'Fichier/Chemin', placeholder: 'src/' }
        ],
        build: (values) => {
            const { 'log-format': format, 'log-count': count, 'log-author': author, 'log-since': since, 'log-path': path } = values;
            let cmd = 'git log';

            switch (format) {
                case 'oneline': cmd += ' --oneline'; break;
                case 'graph': cmd += ' --oneline --graph --decorate --all'; break;
                case 'pretty': cmd += ' --pretty=format:"%h %ad | %s%d [%an]" --date=short'; break;
            }

            if (count) cmd += ` -${count}`;
            if (author) cmd += ` --author="${author}"`;
            if (since) cmd += ` --since="${since}"`;
            if (path) cmd += ` -- ${path}`;

            return cmd;
        }
    },
    diff: {
        title: 'Differences',
        fields: [
            { id: 'diff-type', type: 'select', label: 'Type', options: [
                { value: 'working', label: 'Working directory' },
                { value: 'staged', label: 'Staged (--cached)' },
                { value: 'commits', label: 'Entre commits' },
                { value: 'branches', label: 'Entre branches' }
            ]},
            { id: 'diff-ref1', type: 'text', label: 'Reference 1', placeholder: 'HEAD~1' },
            { id: 'diff-ref2', type: 'text', label: 'Reference 2', placeholder: 'HEAD' },
            { id: 'diff-stat', type: 'checkbox', label: 'Stats seulement (--stat)' },
            { id: 'diff-name', type: 'checkbox', label: 'Noms seulement (--name-only)' }
        ],
        build: (values) => {
            const { 'diff-type': type, 'diff-ref1': ref1, 'diff-ref2': ref2, 'diff-stat': stat, 'diff-name': nameOnly } = values;
            let cmd = 'git diff';

            switch (type) {
                case 'staged': cmd += ' --cached'; break;
                case 'commits': cmd += ` ${ref1 || 'HEAD~1'}..${ref2 || 'HEAD'}`; break;
                case 'branches': cmd += ` ${ref1 || 'main'}..${ref2 || 'feature'}`; break;
            }

            if (stat) cmd += ' --stat';
            if (nameOnly) cmd += ' --name-only';

            return cmd;
        }
    }
};

let currentCategory = 'branch';

function selectCategory(category) {
    currentCategory = category;
    document.querySelectorAll('.cat-btn').forEach(btn => btn.classList.remove('active'));
    event.target.classList.add('active');
    renderBuilder();
}

function renderBuilder() {
    const builder = BUILDERS[currentCategory];
    const section = document.getElementById('builder-section');

    let html = `<h4>${builder.title}</h4><div class="form-row">`;

    builder.fields.forEach(field => {
        if (field.type === 'select') {
            html += `
                <div class="form-group">
                    <label for="${field.id}">${field.label}</label>
                    <select id="${field.id}" onchange="updateCommand()">
                        ${field.options.map(o => `<option value="${o.value}">${o.label}</option>`).join('')}
                    </select>
                </div>
            `;
        } else if (field.type === 'checkbox') {
            html += `
                <div class="form-group">
                    <label class="checkbox-label">
                        <input type="checkbox" id="${field.id}" onchange="updateCommand()">
                        ${field.label}
                    </label>
                </div>
            `;
        } else {
            html += `
                <div class="form-group">
                    <label for="${field.id}">${field.label}</label>
                    <input type="text" id="${field.id}" placeholder="${field.placeholder || ''}" oninput="updateCommand()">
                </div>
            `;
        }
    });

    html += '</div>';
    section.innerHTML = html;

    updateCommand();
}

function updateCommand() {
    const builder = BUILDERS[currentCategory];
    const values = {};

    builder.fields.forEach(field => {
        const el = document.getElementById(field.id);
        if (field.type === 'checkbox') {
            values[field.id] = el.checked;
        } else {
            values[field.id] = el.value;
        }
    });

    const command = builder.build(values);
    document.getElementById('command-output').textContent = command;
}

function copyCommand() {
    const command = document.getElementById('command-output').textContent;
    navigator.clipboard.writeText(command);

    const btn = event.target;
    btn.textContent = 'Copie!';
    setTimeout(() => { btn.textContent = 'Copier'; }, 1000);
}

function showCheat(type) {
    document.querySelectorAll('.cheat-btn').forEach(btn => btn.classList.remove('active'));
    event.target.classList.add('active');

    document.querySelectorAll('.cheat-content').forEach(c => c.style.display = 'none');
    document.getElementById(`${type}-cheat`).style.display = 'block';
}

// Initialize
renderBuilder();
</script>
