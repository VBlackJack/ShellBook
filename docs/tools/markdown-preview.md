---
tags:
  - tools
  - markdown
  - preview
  - documentation
---

# Markdown Preview

Editeur Markdown avec apercu en temps reel.

<div class="tool-container">

<div class="editor-container">
    <div class="editor-pane">
        <div class="pane-header">
            <span>Markdown</span>
            <div class="toolbar">
                <button onclick="insertMd('**', '**')" title="Gras">B</button>
                <button onclick="insertMd('*', '*')" title="Italique"><em>I</em></button>
                <button onclick="insertMd('`', '`')" title="Code inline">`</button>
                <button onclick="insertMd('~~', '~~')" title="Barre">S</button>
                <button onclick="insertMd('[', '](url)')" title="Lien">🔗</button>
                <button onclick="insertMd('![alt](', ')')" title="Image">🖼️</button>
                <button onclick="insertLine('# ')" title="H1">H1</button>
                <button onclick="insertLine('## ')" title="H2">H2</button>
                <button onclick="insertLine('### ')" title="H3">H3</button>
                <button onclick="insertLine('- ')" title="Liste">•</button>
                <button onclick="insertLine('1. ')" title="Liste numerotee">1.</button>
                <button onclick="insertLine('> ')" title="Citation">"</button>
                <button onclick="insertBlock('```\\n', '\\n```')" title="Bloc code">{ }</button>
                <button onclick="insertLine('---')" title="Separateur">—</button>
            </div>
        </div>
        <textarea id="md-input" placeholder="Tapez votre Markdown ici..."></textarea>
    </div>

    <div class="preview-pane">
        <div class="pane-header">
            <span>Apercu</span>
            <button onclick="copyHtml()" class="copy-btn">Copier HTML</button>
        </div>
        <div id="md-preview" class="preview-content"></div>
    </div>
</div>

<div class="templates-section">
    <h3>Templates</h3>
    <div class="templates-grid">
        <button onclick="loadTemplate('readme')">README</button>
        <button onclick="loadTemplate('changelog')">CHANGELOG</button>
        <button onclick="loadTemplate('api')">API Doc</button>
        <button onclick="loadTemplate('issue')">Issue</button>
        <button onclick="loadTemplate('pr')">Pull Request</button>
    </div>
</div>

</div>

## Syntaxe Markdown

### Formatage de base

| Syntaxe | Resultat |
|---------|----------|
| `**gras**` | **gras** |
| `*italique*` | *italique* |
| `~~barre~~` | ~~barre~~ |
| `` `code` `` | `code` |
| `[lien](url)` | [lien](url) |
| `![image](url)` | Image |

### Titres

```markdown
# Titre 1
## Titre 2
### Titre 3
#### Titre 4
```

### Listes

```markdown
- Item 1
- Item 2
  - Sous-item

1. Premier
2. Deuxieme
3. Troisieme
```

### Code

````markdown
```python
def hello():
    print("Hello World")
```
````

### Tableaux

```markdown
| Colonne 1 | Colonne 2 |
|-----------|-----------|
| Valeur 1  | Valeur 2  |
```

### Citations et notes

```markdown
> Citation importante

!!! note "Titre"
    Contenu de la note (MkDocs)
```

<style>
.tool-container {
    background: var(--md-code-bg-color);
    padding: 20px;
    border-radius: 8px;
    margin: 20px 0;
}
.editor-container {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 15px;
    min-height: 500px;
}
@media (max-width: 900px) {
    .editor-container {
        grid-template-columns: 1fr;
    }
}
.editor-pane, .preview-pane {
    background: var(--md-default-bg-color);
    border-radius: 4px;
    display: flex;
    flex-direction: column;
    overflow: hidden;
}
.pane-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 10px 15px;
    background: var(--md-code-bg-color);
    border-bottom: 1px solid var(--md-default-fg-color--lightest);
    font-weight: bold;
}
.toolbar {
    display: flex;
    gap: 5px;
    flex-wrap: wrap;
}
.toolbar button {
    padding: 5px 10px;
    background: var(--md-default-bg-color);
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 3px;
    cursor: pointer;
    font-size: 12px;
    font-family: monospace;
}
.toolbar button:hover {
    background: var(--md-primary-fg-color);
    color: white;
}
#md-input {
    flex: 1;
    padding: 15px;
    border: none;
    resize: none;
    font-family: 'JetBrains Mono', monospace;
    font-size: 14px;
    line-height: 1.6;
    background: var(--md-default-bg-color);
    color: var(--md-default-fg-color);
}
#md-input:focus {
    outline: none;
}
.preview-content {
    flex: 1;
    padding: 15px;
    overflow: auto;
    line-height: 1.6;
}
.preview-content h1 { font-size: 2em; border-bottom: 1px solid var(--md-default-fg-color--lighter); padding-bottom: 0.3em; }
.preview-content h2 { font-size: 1.5em; border-bottom: 1px solid var(--md-default-fg-color--lightest); padding-bottom: 0.3em; }
.preview-content h3 { font-size: 1.25em; }
.preview-content code {
    background: var(--md-code-bg-color);
    padding: 2px 6px;
    border-radius: 3px;
    font-family: monospace;
}
.preview-content pre {
    background: var(--md-code-bg-color);
    padding: 15px;
    border-radius: 4px;
    overflow-x: auto;
}
.preview-content pre code {
    padding: 0;
    background: none;
}
.preview-content blockquote {
    margin: 0;
    padding: 10px 15px;
    border-left: 4px solid var(--md-primary-fg-color);
    background: var(--md-code-bg-color);
}
.preview-content table {
    border-collapse: collapse;
    width: 100%;
}
.preview-content th, .preview-content td {
    border: 1px solid var(--md-default-fg-color--lighter);
    padding: 8px 12px;
}
.preview-content th {
    background: var(--md-code-bg-color);
}
.preview-content img {
    max-width: 100%;
}
.preview-content hr {
    border: none;
    border-top: 2px solid var(--md-default-fg-color--lighter);
    margin: 20px 0;
}
.preview-content ul, .preview-content ol {
    padding-left: 25px;
}
.preview-content a {
    color: var(--md-primary-fg-color);
}
.copy-btn {
    padding: 5px 10px;
    background: var(--md-primary-fg-color);
    color: white;
    border: none;
    border-radius: 3px;
    cursor: pointer;
    font-size: 12px;
}
.templates-section {
    background: var(--md-default-bg-color);
    padding: 20px;
    border-radius: 4px;
    margin-top: 20px;
}
.templates-section h3 {
    margin: 0 0 15px 0;
}
.templates-grid {
    display: flex;
    gap: 10px;
    flex-wrap: wrap;
}
.templates-grid button {
    padding: 8px 16px;
    background: var(--md-code-bg-color);
    color: var(--md-default-fg-color);
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    cursor: pointer;
}
.templates-grid button:hover {
    background: var(--md-primary-fg-color);
    color: white;
}
</style>

<script>
// Simple Markdown parser
function parseMarkdown(md) {
    let html = md;

    // Escape HTML
    html = html.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

    // Code blocks (before other processing)
    html = html.replace(/```(\w*)\n([\s\S]*?)```/g, '<pre><code class="language-$1">$2</code></pre>');

    // Inline code
    html = html.replace(/`([^`]+)`/g, '<code>$1</code>');

    // Headers
    html = html.replace(/^#### (.+)$/gm, '<h4>$1</h4>');
    html = html.replace(/^### (.+)$/gm, '<h3>$1</h3>');
    html = html.replace(/^## (.+)$/gm, '<h2>$1</h2>');
    html = html.replace(/^# (.+)$/gm, '<h1>$1</h1>');

    // Bold and italic
    html = html.replace(/\*\*\*(.+?)\*\*\*/g, '<strong><em>$1</em></strong>');
    html = html.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
    html = html.replace(/\*(.+?)\*/g, '<em>$1</em>');
    html = html.replace(/~~(.+?)~~/g, '<del>$1</del>');

    // Links and images
    html = html.replace(/!\[([^\]]*)\]\(([^)]+)\)/g, '<img src="$2" alt="$1">');
    html = html.replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2">$1</a>');

    // Blockquotes
    html = html.replace(/^> (.+)$/gm, '<blockquote>$1</blockquote>');

    // Horizontal rules
    html = html.replace(/^---$/gm, '<hr>');
    html = html.replace(/^\*\*\*$/gm, '<hr>');

    // Lists
    html = html.replace(/^\d+\. (.+)$/gm, '<li>$1</li>');
    html = html.replace(/^- (.+)$/gm, '<li>$1</li>');
    html = html.replace(/(<li>.*<\/li>\n?)+/g, (match) => {
        if (match.includes('1.')) return '<ol>' + match + '</ol>';
        return '<ul>' + match + '</ul>';
    });

    // Tables
    html = html.replace(/^\|(.+)\|$/gm, (match, content) => {
        const cells = content.split('|').map(c => c.trim());
        if (cells.every(c => /^-+$/.test(c))) return '';
        const tag = match.includes('---') ? 'th' : 'td';
        return '<tr>' + cells.map(c => `<${tag}>${c}</${tag}>`).join('') + '</tr>';
    });
    html = html.replace(/(<tr>.*<\/tr>\n?)+/g, '<table>$&</table>');

    // Paragraphs
    html = html.replace(/\n\n/g, '</p><p>');
    html = '<p>' + html + '</p>';
    html = html.replace(/<p>(<h[1-6]>)/g, '$1');
    html = html.replace(/(<\/h[1-6]>)<\/p>/g, '$1');
    html = html.replace(/<p>(<pre>)/g, '$1');
    html = html.replace(/(<\/pre>)<\/p>/g, '$1');
    html = html.replace(/<p>(<ul>)/g, '$1');
    html = html.replace(/(<\/ul>)<\/p>/g, '$1');
    html = html.replace(/<p>(<ol>)/g, '$1');
    html = html.replace(/(<\/ol>)<\/p>/g, '$1');
    html = html.replace(/<p>(<table>)/g, '$1');
    html = html.replace(/(<\/table>)<\/p>/g, '$1');
    html = html.replace(/<p>(<hr>)<\/p>/g, '$1');
    html = html.replace(/<p>(<blockquote>)/g, '$1');
    html = html.replace(/(<\/blockquote>)<\/p>/g, '$1');
    html = html.replace(/<p>\s*<\/p>/g, '');

    return html;
}

// Update preview
function updatePreview() {
    const md = document.getElementById('md-input').value;
    const html = parseMarkdown(md);
    document.getElementById('md-preview').innerHTML = html;
}

// Toolbar functions
function insertMd(before, after) {
    const textarea = document.getElementById('md-input');
    const start = textarea.selectionStart;
    const end = textarea.selectionEnd;
    const text = textarea.value;
    const selected = text.substring(start, end) || 'text';

    textarea.value = text.substring(0, start) + before + selected + after + text.substring(end);
    textarea.focus();
    textarea.setSelectionRange(start + before.length, start + before.length + selected.length);
    updatePreview();
}

function insertLine(prefix) {
    const textarea = document.getElementById('md-input');
    const start = textarea.selectionStart;
    const text = textarea.value;

    // Find start of line
    let lineStart = start;
    while (lineStart > 0 && text[lineStart - 1] !== '\n') lineStart--;

    textarea.value = text.substring(0, lineStart) + prefix + text.substring(lineStart);
    textarea.focus();
    textarea.setSelectionRange(lineStart + prefix.length, lineStart + prefix.length);
    updatePreview();
}

function insertBlock(before, after) {
    const textarea = document.getElementById('md-input');
    const start = textarea.selectionStart;
    const end = textarea.selectionEnd;
    const text = textarea.value;
    const selected = text.substring(start, end) || 'code';

    before = before.replace(/\\n/g, '\n');
    after = after.replace(/\\n/g, '\n');

    textarea.value = text.substring(0, start) + before + selected + after + text.substring(end);
    textarea.focus();
    updatePreview();
}

function copyHtml() {
    const html = document.getElementById('md-preview').innerHTML;
    navigator.clipboard.writeText(html);

    const btn = document.querySelector('.copy-btn');
    btn.textContent = 'Copie!';
    setTimeout(() => { btn.textContent = 'Copier HTML'; }, 1000);
}

// Templates
const TEMPLATES = {
    readme: `# Project Name

Brief description of the project.

## Installation

\`\`\`bash
npm install my-project
\`\`\`

## Usage

\`\`\`javascript
const myProject = require('my-project');
myProject.doSomething();
\`\`\`

## Features

- Feature 1
- Feature 2
- Feature 3

## Contributing

Pull requests are welcome.

## License

MIT`,

    changelog: `# Changelog

All notable changes to this project will be documented in this file.

## [1.2.0] - 2024-01-15

### Added
- New feature X
- Support for Y

### Changed
- Improved performance of Z

### Fixed
- Bug in authentication flow
- Memory leak in cache

## [1.1.0] - 2024-01-01

### Added
- Initial release`,

    api: `# API Documentation

## Authentication

All API requests require an API key in the header:

\`\`\`
Authorization: Bearer YOUR_API_KEY
\`\`\`

## Endpoints

### GET /users

Returns a list of users.

**Response:**

| Field | Type | Description |
|-------|------|-------------|
| id | integer | User ID |
| name | string | User name |
| email | string | User email |

### POST /users

Creates a new user.

**Request Body:**

\`\`\`json
{
  "name": "John Doe",
  "email": "john@example.com"
}
\`\`\``,

    issue: `## Description

A clear description of the issue.

## Steps to Reproduce

1. Go to '...'
2. Click on '...'
3. See error

## Expected Behavior

What should happen.

## Actual Behavior

What actually happens.

## Environment

- OS: [e.g. Windows 11]
- Browser: [e.g. Chrome 120]
- Version: [e.g. 1.2.0]

## Screenshots

If applicable, add screenshots.`,

    pr: `## Summary

Brief description of changes.

## Changes

- Change 1
- Change 2
- Change 3

## Testing

- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Manual testing done

## Screenshots

If applicable, add screenshots.

## Related Issues

Fixes #123`
};

function loadTemplate(name) {
    document.getElementById('md-input').value = TEMPLATES[name];
    updatePreview();
}

// Event listener
document.getElementById('md-input').addEventListener('input', updatePreview);

// Initial content
document.getElementById('md-input').value = `# Bienvenue dans l'editeur Markdown

Ceci est un **apercu en temps reel** de votre *Markdown*.

## Fonctionnalites

- Formatage de base
- Listes
- \`Code inline\`
- [Liens](https://example.com)

### Bloc de code

\`\`\`python
def hello():
    print("Hello World!")
\`\`\`

> Citation importante

| Colonne 1 | Colonne 2 |
|-----------|-----------|
| Valeur A  | Valeur B  |

---

Commencez a taper!`;

updatePreview();
</script>
