---
tags:
  - tools
  - xml
  - formatter
  - validator
---

# XML Formatter

Formatage, validation et minification de documents XML.

<div class="tool-container">

<div class="editor-section">
    <div class="input-pane">
        <div class="pane-header">
            <span>XML</span>
            <div class="actions">
                <button onclick="formatXml()">Formater</button>
                <button onclick="minifyXml()">Minifier</button>
                <button onclick="validateXml()">Valider</button>
            </div>
        </div>
        <textarea id="xml-input" placeholder="<?xml version=&quot;1.0&quot;?>
<root>
  <element>content</element>
</root>"></textarea>
    </div>

    <div class="output-pane">
        <div class="pane-header">
            <span>Resultat</span>
            <button onclick="copyOutput()" class="copy-btn">Copier</button>
        </div>
        <pre id="xml-output" class="xml-output"></pre>
    </div>
</div>

<div class="status-section">
    <div id="validation-status" class="status"></div>
</div>

<div class="options-section">
    <h3>Options</h3>
    <div class="options-grid">
        <div class="form-group">
            <label for="indent-size">Indentation</label>
            <select id="indent-size">
                <option value="2">2 espaces</option>
                <option value="4" selected>4 espaces</option>
                <option value="tab">Tabulation</option>
            </select>
        </div>
        <label>
            <input type="checkbox" id="remove-comments"> Supprimer commentaires
        </label>
        <label>
            <input type="checkbox" id="sort-attrs"> Trier attributs
        </label>
    </div>
</div>

<div class="tree-section">
    <h3>Arborescence</h3>
    <div id="xml-tree" class="xml-tree"></div>
</div>

<div class="examples-section">
    <h3>Exemples</h3>
    <div class="examples-grid">
        <button onclick="loadExample('simple')">XML Simple</button>
        <button onclick="loadExample('rss')">RSS Feed</button>
        <button onclick="loadExample('config')">Configuration</button>
        <button onclick="loadExample('soap')">SOAP</button>
    </div>
</div>

</div>

## Syntaxe XML

### Structure de base

```xml
<?xml version="1.0" encoding="UTF-8"?>
<root>
    <element attribute="value">Content</element>
    <self-closing />
    <!-- Comment -->
    <![CDATA[Special <characters> here]]>
</root>
```

### Regles XML

- Un seul element racine
- Balises sensibles a la casse
- Attributs entre guillemets
- Caracteres speciaux echappes (`&lt;`, `&gt;`, `&amp;`)

## CLI Tools

```bash
# Formatter avec xmllint
xmllint --format input.xml > output.xml

# Valider
xmllint --noout --schema schema.xsd document.xml

# XPath query
xmllint --xpath "//element" document.xml

# Python
python -c "import xml.dom.minidom; print(xml.dom.minidom.parseString(open('file.xml').read()).toprettyxml())"
```

<style>
.tool-container {
    background: var(--md-code-bg-color);
    padding: 20px;
    border-radius: 8px;
    margin: 20px 0;
}
.editor-section {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 15px;
    margin-bottom: 20px;
}
@media (max-width: 900px) {
    .editor-section {
        grid-template-columns: 1fr;
    }
}
.input-pane, .output-pane {
    background: var(--md-default-bg-color);
    border-radius: 4px;
    display: flex;
    flex-direction: column;
}
.pane-header {
    padding: 10px 15px;
    background: var(--md-code-bg-color);
    border-radius: 4px 4px 0 0;
    display: flex;
    justify-content: space-between;
    align-items: center;
}
.pane-header span {
    font-weight: bold;
}
.pane-header .actions {
    display: flex;
    gap: 10px;
}
.pane-header button {
    padding: 5px 12px;
    background: var(--md-primary-fg-color);
    color: white;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    font-size: 12px;
}
.input-pane textarea {
    flex: 1;
    min-height: 300px;
    padding: 15px;
    border: none;
    border-radius: 0 0 4px 4px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 13px;
    resize: vertical;
    background: var(--md-default-bg-color);
    color: var(--md-default-fg-color);
}
.xml-output {
    flex: 1;
    min-height: 300px;
    padding: 15px;
    margin: 0;
    overflow: auto;
    font-family: 'JetBrains Mono', monospace;
    font-size: 13px;
    background: var(--md-default-bg-color);
    border-radius: 0 0 4px 4px;
    white-space: pre-wrap;
}
.copy-btn {
    padding: 5px 12px;
    background: var(--md-primary-fg-color);
    color: white;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    font-size: 12px;
}
.status-section {
    margin-bottom: 20px;
}
.status {
    padding: 15px;
    border-radius: 4px;
    font-family: monospace;
}
.status.valid {
    background: #d4edda;
    color: #155724;
    border: 1px solid #c3e6cb;
}
.status.invalid {
    background: #f8d7da;
    color: #721c24;
    border: 1px solid #f5c6cb;
}
.status:empty {
    display: none;
}
.options-section, .tree-section, .examples-section {
    background: var(--md-default-bg-color);
    padding: 20px;
    border-radius: 4px;
    margin-bottom: 20px;
}
.options-section h3, .tree-section h3, .examples-section h3 {
    margin: 0 0 15px 0;
}
.options-grid {
    display: flex;
    gap: 20px;
    flex-wrap: wrap;
    align-items: center;
}
.form-group {
    display: flex;
    align-items: center;
    gap: 10px;
}
.form-group select {
    padding: 8px;
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    background: var(--md-code-bg-color);
    color: var(--md-default-fg-color);
}
.xml-tree {
    max-height: 300px;
    overflow: auto;
    font-family: monospace;
    font-size: 13px;
}
.tree-node {
    margin-left: 20px;
}
.tree-tag {
    color: #c678dd;
}
.tree-attr {
    color: #e06c75;
}
.tree-value {
    color: #98c379;
}
.tree-text {
    color: var(--md-default-fg-color);
}
.tree-toggle {
    cursor: pointer;
    user-select: none;
}
.examples-grid {
    display: flex;
    gap: 10px;
    flex-wrap: wrap;
}
.examples-grid button {
    padding: 8px 16px;
    background: var(--md-code-bg-color);
    color: var(--md-default-fg-color);
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    cursor: pointer;
}
.examples-grid button:hover {
    background: var(--md-primary-fg-color);
    color: white;
}
/* Syntax highlighting */
.xml-output .tag { color: #c678dd; }
.xml-output .attr-name { color: #e06c75; }
.xml-output .attr-value { color: #98c379; }
.xml-output .comment { color: #5c6370; font-style: italic; }
.xml-output .cdata { color: #d19a66; }
</style>

<script>
function parseXml(xml) {
    const parser = new DOMParser();
    const doc = parser.parseFromString(xml, 'text/xml');
    const error = doc.querySelector('parsererror');
    if (error) {
        throw new Error(error.textContent);
    }
    return doc;
}

function formatXml() {
    const input = document.getElementById('xml-input').value;
    const indentSize = document.getElementById('indent-size').value;
    const removeComments = document.getElementById('remove-comments').checked;
    const sortAttrs = document.getElementById('sort-attrs').checked;

    const indent = indentSize === 'tab' ? '\t' : ' '.repeat(parseInt(indentSize));

    try {
        const doc = parseXml(input);

        function formatNode(node, level) {
            let result = '';
            const currentIndent = indent.repeat(level);

            if (node.nodeType === Node.TEXT_NODE) {
                const text = node.textContent.trim();
                if (text) {
                    return text;
                }
                return '';
            }

            if (node.nodeType === Node.COMMENT_NODE) {
                if (removeComments) return '';
                return currentIndent + '<!--' + node.textContent + '-->\n';
            }

            if (node.nodeType === Node.CDATA_SECTION_NODE) {
                return currentIndent + '<![CDATA[' + node.textContent + ']]>\n';
            }

            if (node.nodeType === Node.PROCESSING_INSTRUCTION_NODE) {
                return currentIndent + '<?' + node.target + ' ' + node.data + '?>\n';
            }

            if (node.nodeType === Node.ELEMENT_NODE) {
                result += currentIndent + '<' + node.tagName;

                // Attributes
                let attrs = Array.from(node.attributes);
                if (sortAttrs) {
                    attrs.sort((a, b) => a.name.localeCompare(b.name));
                }
                attrs.forEach(attr => {
                    result += ' ' + attr.name + '="' + escapeXml(attr.value) + '"';
                });

                // Children
                const children = Array.from(node.childNodes).filter(child => {
                    if (child.nodeType === Node.TEXT_NODE) {
                        return child.textContent.trim() !== '';
                    }
                    if (child.nodeType === Node.COMMENT_NODE && removeComments) {
                        return false;
                    }
                    return true;
                });

                if (children.length === 0) {
                    result += ' />\n';
                } else if (children.length === 1 && children[0].nodeType === Node.TEXT_NODE) {
                    result += '>' + escapeXml(children[0].textContent.trim()) + '</' + node.tagName + '>\n';
                } else {
                    result += '>\n';
                    children.forEach(child => {
                        result += formatNode(child, level + 1);
                    });
                    result += currentIndent + '</' + node.tagName + '>\n';
                }
            }

            return result;
        }

        let output = '';
        Array.from(doc.childNodes).forEach(child => {
            output += formatNode(child, 0);
        });

        document.getElementById('xml-output').innerHTML = highlightXml(output.trim());
        setStatus('valid', 'XML valide');
        buildTree(doc);

    } catch (e) {
        document.getElementById('xml-output').textContent = 'Erreur: ' + e.message;
        setStatus('invalid', 'XML invalide: ' + e.message);
    }
}

function minifyXml() {
    const input = document.getElementById('xml-input').value;

    try {
        const doc = parseXml(input);

        function minifyNode(node) {
            if (node.nodeType === Node.TEXT_NODE) {
                return node.textContent.trim();
            }
            if (node.nodeType === Node.COMMENT_NODE) {
                return '';
            }
            if (node.nodeType === Node.ELEMENT_NODE) {
                let result = '<' + node.tagName;
                Array.from(node.attributes).forEach(attr => {
                    result += ' ' + attr.name + '="' + escapeXml(attr.value) + '"';
                });

                const children = Array.from(node.childNodes);
                const hasContent = children.some(c =>
                    c.nodeType === Node.ELEMENT_NODE ||
                    (c.nodeType === Node.TEXT_NODE && c.textContent.trim())
                );

                if (!hasContent) {
                    return result + '/>';
                }

                result += '>';
                children.forEach(child => {
                    result += minifyNode(child);
                });
                result += '</' + node.tagName + '>';
                return result;
            }
            if (node.nodeType === Node.PROCESSING_INSTRUCTION_NODE) {
                return '<?' + node.target + ' ' + node.data + '?>';
            }
            return '';
        }

        let output = '';
        Array.from(doc.childNodes).forEach(child => {
            output += minifyNode(child);
        });

        document.getElementById('xml-output').textContent = output;
        setStatus('valid', 'XML minifie');

    } catch (e) {
        document.getElementById('xml-output').textContent = 'Erreur: ' + e.message;
        setStatus('invalid', e.message);
    }
}

function validateXml() {
    const input = document.getElementById('xml-input').value;

    try {
        parseXml(input);
        setStatus('valid', 'XML valide - bien forme');
        document.getElementById('xml-output').textContent = 'Le document XML est valide.';
    } catch (e) {
        setStatus('invalid', 'XML invalide: ' + e.message);
        document.getElementById('xml-output').textContent = 'Erreur de validation:\n' + e.message;
    }
}

function escapeXml(str) {
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&apos;');
}

function highlightXml(xml) {
    return xml
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/(&lt;\/?)([\w:-]+)/g, '$1<span class="tag">$2</span>')
        .replace(/([\w:-]+)(=)(".*?")/g, '<span class="attr-name">$1</span>$2<span class="attr-value">$3</span>')
        .replace(/(&lt;!--.*?--&gt;)/gs, '<span class="comment">$1</span>')
        .replace(/(&lt;!\[CDATA\[.*?\]\]&gt;)/gs, '<span class="cdata">$1</span>');
}

function setStatus(type, message) {
    const status = document.getElementById('validation-status');
    status.className = 'status ' + type;
    status.textContent = message;
}

function buildTree(doc) {
    const container = document.getElementById('xml-tree');

    function renderNode(node) {
        if (node.nodeType === Node.ELEMENT_NODE) {
            let html = '<div class="tree-node">';
            html += '<span class="tree-tag">&lt;' + node.tagName;

            Array.from(node.attributes).forEach(attr => {
                html += ' <span class="tree-attr">' + attr.name + '</span>=<span class="tree-value">"' + escapeXml(attr.value) + '"</span>';
            });

            html += '&gt;</span>';

            Array.from(node.childNodes).forEach(child => {
                if (child.nodeType === Node.TEXT_NODE && child.textContent.trim()) {
                    html += '<span class="tree-text">' + escapeXml(child.textContent.trim()) + '</span>';
                } else {
                    html += renderNode(child);
                }
            });

            html += '<span class="tree-tag">&lt;/' + node.tagName + '&gt;</span></div>';
            return html;
        }
        return '';
    }

    let html = '';
    Array.from(doc.childNodes).forEach(child => {
        if (child.nodeType === Node.ELEMENT_NODE) {
            html += renderNode(child);
        }
    });

    container.innerHTML = html || '<p>Parsez un XML valide pour voir l\'arborescence</p>';
}

function copyOutput() {
    const output = document.getElementById('xml-output').textContent;
    navigator.clipboard.writeText(output);

    const btn = document.querySelector('.copy-btn');
    btn.textContent = 'Copie!';
    setTimeout(() => { btn.textContent = 'Copier'; }, 1000);
}

const EXAMPLES = {
    simple: `<?xml version="1.0" encoding="UTF-8"?>
<bookstore><book category="fiction"><title lang="en">Harry Potter</title><author>J.K. Rowling</author><year>2005</year><price>29.99</price></book><book category="web"><title lang="en">Learning XML</title><author>Erik T. Ray</author><year>2003</year><price>39.95</price></book></bookstore>`,

    rss: `<?xml version="1.0" encoding="UTF-8"?><rss version="2.0"><channel><title>Example RSS Feed</title><link>https://example.com</link><description>This is an example RSS feed</description><item><title>First Article</title><link>https://example.com/first</link><description>Description of first article</description><pubDate>Mon, 01 Jan 2024 00:00:00 GMT</pubDate></item><item><title>Second Article</title><link>https://example.com/second</link><description>Description of second article</description><pubDate>Tue, 02 Jan 2024 00:00:00 GMT</pubDate></item></channel></rss>`,

    config: `<?xml version="1.0"?><configuration><appSettings><add key="Setting1" value="Value1"/><add key="Setting2" value="Value2"/></appSettings><connectionStrings><add name="DefaultConnection" connectionString="Server=localhost;Database=mydb;"/></connectionStrings><system.web><compilation debug="true" targetFramework="4.8"/><httpRuntime targetFramework="4.8"/></system.web></configuration>`,

    soap: `<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Header><auth:Credentials xmlns:auth="http://example.com/auth"><auth:Username>user</auth:Username><auth:Password>pass</auth:Password></auth:Credentials></soap:Header><soap:Body><m:GetUserRequest xmlns:m="http://example.com/users"><m:UserId>123</m:UserId></m:GetUserRequest></soap:Body></soap:Envelope>`
};

function loadExample(name) {
    document.getElementById('xml-input').value = EXAMPLES[name];
    formatXml();
}

// Initialize
loadExample('simple');
</script>
