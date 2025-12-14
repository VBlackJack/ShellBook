---
tags:
  - tools
  - sql
  - database
  - formatting
---

# SQL Formatter

Formatage et embellissement de requetes SQL.

<div class="tool-container">

<div class="input-section">
    <div class="input-group">
        <label for="sql-input">SQL a formater :</label>
        <textarea id="sql-input" rows="8" placeholder="SELECT * FROM users WHERE id = 1"></textarea>
    </div>

    <div class="options-row">
        <div class="option">
            <label for="indent-size">Indentation :</label>
            <select id="indent-size">
                <option value="2">2 espaces</option>
                <option value="4" selected>4 espaces</option>
                <option value="tab">Tab</option>
            </select>
        </div>
        <div class="option">
            <label for="keyword-case">Mots-cles :</label>
            <select id="keyword-case">
                <option value="upper" selected>MAJUSCULES</option>
                <option value="lower">minuscules</option>
                <option value="capitalize">Capitalize</option>
            </select>
        </div>
        <div class="option">
            <label>
                <input type="checkbox" id="trailing-comma" checked>
                Virgules en fin de ligne
            </label>
        </div>
    </div>

    <div class="button-row">
        <button onclick="formatSQL()" class="action-btn">Formater</button>
        <button onclick="minifySQL()" class="action-btn secondary">Minifier</button>
        <button onclick="clearSQL()" class="action-btn secondary">Effacer</button>
    </div>
</div>

<div class="output-section">
    <div class="output-header">
        <h3>Resultat</h3>
        <button onclick="copySQL()" class="copy-btn">Copier</button>
    </div>
    <pre id="sql-output" class="sql-output"></pre>
</div>

<div class="examples-section">
    <h3>Exemples</h3>
    <div class="examples-grid">
        <button onclick="loadExample('select')">SELECT simple</button>
        <button onclick="loadExample('join')">JOIN</button>
        <button onclick="loadExample('subquery')">Sous-requete</button>
        <button onclick="loadExample('insert')">INSERT</button>
        <button onclick="loadExample('update')">UPDATE</button>
        <button onclick="loadExample('create')">CREATE TABLE</button>
    </div>
</div>

</div>

## Bonnes pratiques SQL

### Formatage recommande

```sql
SELECT
    u.id,
    u.username,
    u.email,
    COUNT(o.id) AS order_count
FROM users u
LEFT JOIN orders o ON o.user_id = u.id
WHERE u.status = 'active'
    AND u.created_at > '2024-01-01'
GROUP BY u.id, u.username, u.email
HAVING COUNT(o.id) > 5
ORDER BY order_count DESC
LIMIT 10;
```

### Conventions

| Element | Convention | Exemple |
|---------|------------|---------|
| **Mots-cles** | MAJUSCULES | `SELECT`, `FROM`, `WHERE` |
| **Tables/Colonnes** | snake_case | `user_id`, `created_at` |
| **Alias** | Court et significatif | `u` pour users, `o` pour orders |
| **Indentation** | 4 espaces | Apres `SELECT`, `WHERE`, etc. |
| **Virgules** | En fin de ligne | Plus lisible pour le diff |

### Anti-patterns a eviter

```sql
-- MAL: SELECT *
SELECT * FROM users;

-- BIEN: Colonnes explicites
SELECT id, username, email FROM users;

-- MAL: Sans alias avec JOIN
SELECT users.id, orders.id FROM users JOIN orders ON orders.user_id = users.id;

-- BIEN: Avec alias
SELECT u.id, o.id FROM users u JOIN orders o ON o.user_id = u.id;
```

<style>
.tool-container {
    background: var(--md-code-bg-color);
    padding: 20px;
    border-radius: 8px;
    margin: 20px 0;
}
.input-section, .output-section, .examples-section {
    background: var(--md-default-bg-color);
    padding: 20px;
    border-radius: 4px;
    margin-bottom: 20px;
}
.input-group label {
    display: block;
    font-weight: bold;
    margin-bottom: 5px;
}
.input-group textarea {
    width: 100%;
    padding: 12px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 14px;
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    background: var(--md-code-bg-color);
    color: var(--md-default-fg-color);
    resize: vertical;
}
.options-row {
    display: flex;
    gap: 20px;
    flex-wrap: wrap;
    margin: 15px 0;
    align-items: center;
}
.option {
    display: flex;
    align-items: center;
    gap: 8px;
}
.option select {
    padding: 8px;
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    background: var(--md-code-bg-color);
    color: var(--md-default-fg-color);
}
.button-row {
    display: flex;
    gap: 10px;
    flex-wrap: wrap;
}
.action-btn {
    padding: 10px 24px;
    background: var(--md-primary-fg-color);
    color: white;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    font-size: 14px;
}
.action-btn.secondary {
    background: var(--md-default-fg-color--light);
}
.action-btn:hover {
    opacity: 0.9;
}
.output-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 10px;
}
.output-header h3 {
    margin: 0;
}
.copy-btn {
    padding: 8px 16px;
    background: var(--md-primary-fg-color);
    color: white;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    font-size: 12px;
}
.sql-output {
    padding: 15px;
    background: var(--md-code-bg-color);
    border-radius: 4px;
    overflow-x: auto;
    font-family: 'JetBrains Mono', monospace;
    font-size: 14px;
    min-height: 100px;
    margin: 0;
    white-space: pre-wrap;
}
.examples-section h3 {
    margin: 0 0 15px 0;
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
    font-size: 13px;
}
.examples-grid button:hover {
    background: var(--md-primary-fg-color);
    color: white;
    border-color: var(--md-primary-fg-color);
}
/* Syntax highlighting */
.sql-output .keyword { color: #c678dd; font-weight: bold; }
.sql-output .function { color: #61afef; }
.sql-output .string { color: #98c379; }
.sql-output .number { color: #d19a66; }
.sql-output .comment { color: #5c6370; font-style: italic; }
</style>

<script>
const SQL_KEYWORDS = [
    'SELECT', 'FROM', 'WHERE', 'AND', 'OR', 'NOT', 'IN', 'LIKE', 'BETWEEN',
    'JOIN', 'LEFT', 'RIGHT', 'INNER', 'OUTER', 'FULL', 'CROSS', 'ON',
    'GROUP', 'BY', 'HAVING', 'ORDER', 'ASC', 'DESC', 'LIMIT', 'OFFSET',
    'INSERT', 'INTO', 'VALUES', 'UPDATE', 'SET', 'DELETE',
    'CREATE', 'TABLE', 'INDEX', 'VIEW', 'DROP', 'ALTER', 'ADD', 'COLUMN',
    'PRIMARY', 'KEY', 'FOREIGN', 'REFERENCES', 'UNIQUE', 'DEFAULT', 'NULL',
    'AS', 'DISTINCT', 'ALL', 'UNION', 'INTERSECT', 'EXCEPT',
    'CASE', 'WHEN', 'THEN', 'ELSE', 'END', 'IF', 'EXISTS',
    'COUNT', 'SUM', 'AVG', 'MIN', 'MAX', 'COALESCE', 'CAST',
    'VARCHAR', 'INT', 'INTEGER', 'BIGINT', 'TEXT', 'BOOLEAN', 'DATE', 'TIMESTAMP',
    'WITH', 'RECURSIVE', 'OVER', 'PARTITION', 'WINDOW', 'ROW_NUMBER', 'RANK'
];

const CLAUSE_KEYWORDS = ['SELECT', 'FROM', 'WHERE', 'JOIN', 'LEFT JOIN', 'RIGHT JOIN',
    'INNER JOIN', 'OUTER JOIN', 'GROUP BY', 'HAVING', 'ORDER BY', 'LIMIT', 'OFFSET',
    'INSERT INTO', 'VALUES', 'UPDATE', 'SET', 'DELETE FROM', 'CREATE TABLE',
    'UNION', 'UNION ALL', 'WITH'];

function tokenize(sql) {
    const tokens = [];
    let current = '';
    let inString = false;
    let stringChar = '';
    let inComment = false;
    let commentType = '';

    for (let i = 0; i < sql.length; i++) {
        const char = sql[i];
        const next = sql[i + 1];

        // Handle strings
        if (!inComment && (char === "'" || char === '"') && sql[i-1] !== '\\') {
            if (!inString) {
                if (current) tokens.push(current);
                current = char;
                inString = true;
                stringChar = char;
            } else if (char === stringChar) {
                current += char;
                tokens.push(current);
                current = '';
                inString = false;
            } else {
                current += char;
            }
            continue;
        }

        if (inString) {
            current += char;
            continue;
        }

        // Handle comments
        if (!inComment && char === '-' && next === '-') {
            if (current) tokens.push(current);
            current = '--';
            inComment = true;
            commentType = 'line';
            i++;
            continue;
        }

        if (!inComment && char === '/' && next === '*') {
            if (current) tokens.push(current);
            current = '/*';
            inComment = true;
            commentType = 'block';
            i++;
            continue;
        }

        if (inComment) {
            current += char;
            if (commentType === 'line' && char === '\n') {
                tokens.push(current);
                current = '';
                inComment = false;
            } else if (commentType === 'block' && char === '/' && sql[i-1] === '*') {
                tokens.push(current);
                current = '';
                inComment = false;
            }
            continue;
        }

        // Handle operators and punctuation
        if (/[\s,;()=<>!+\-*\/]/.test(char)) {
            if (current) tokens.push(current);
            if (!/\s/.test(char)) tokens.push(char);
            current = '';
        } else {
            current += char;
        }
    }

    if (current) tokens.push(current);
    return tokens;
}

function formatSQL() {
    const input = document.getElementById('sql-input').value;
    const indentSize = document.getElementById('indent-size').value;
    const keywordCase = document.getElementById('keyword-case').value;
    const trailingComma = document.getElementById('trailing-comma').checked;

    const indent = indentSize === 'tab' ? '\t' : ' '.repeat(parseInt(indentSize));

    const tokens = tokenize(input);
    let result = '';
    let indentLevel = 0;
    let newline = true;
    let prevToken = '';

    function applyCase(token) {
        const upper = token.toUpperCase();
        if (SQL_KEYWORDS.includes(upper)) {
            switch (keywordCase) {
                case 'upper': return upper;
                case 'lower': return token.toLowerCase();
                case 'capitalize': return token.charAt(0).toUpperCase() + token.slice(1).toLowerCase();
            }
        }
        return token;
    }

    function isClauseKeyword(token) {
        return CLAUSE_KEYWORDS.includes(token.toUpperCase());
    }

    function addNewline() {
        result = result.trimEnd();
        result += '\n' + indent.repeat(indentLevel);
        newline = true;
    }

    for (let i = 0; i < tokens.length; i++) {
        const token = tokens[i];
        const nextToken = tokens[i + 1] || '';
        const upper = token.toUpperCase();

        // Handle clause keywords - new line before
        if (isClauseKeyword(upper) && i > 0) {
            if (['AND', 'OR'].includes(upper)) {
                addNewline();
                result += indent; // Extra indent for conditions
            } else if (['JOIN', 'LEFT', 'RIGHT', 'INNER', 'OUTER', 'FULL', 'CROSS'].includes(upper)) {
                addNewline();
            } else {
                indentLevel = 0;
                addNewline();
            }
        }

        // Add the token
        if (!newline && prevToken !== '(' && token !== ')' && token !== ',' && token !== ';') {
            result += ' ';
        }

        result += applyCase(token);
        newline = false;
        prevToken = token;

        // Handle after token
        if (['SELECT', 'SET'].includes(upper)) {
            indentLevel = 1;
            addNewline();
        } else if (token === ',') {
            if (trailingComma) {
                // Comma already added, just newline
            }
            if (['SELECT', 'SET', 'GROUP BY', 'ORDER BY'].some(k => result.toUpperCase().includes(k))) {
                addNewline();
            }
        } else if (token === '(') {
            indentLevel++;
        } else if (token === ')') {
            indentLevel = Math.max(0, indentLevel - 1);
        } else if (token === ';') {
            addNewline();
            result += '\n';
        }
    }

    document.getElementById('sql-output').textContent = result.trim();
    highlightSQL();
}

function minifySQL() {
    const input = document.getElementById('sql-input').value;
    const tokens = tokenize(input);
    let result = '';
    let prevToken = '';

    for (const token of tokens) {
        if (token.startsWith('--') || token.startsWith('/*')) continue; // Remove comments

        if (prevToken && !/[(),;]/.test(prevToken) && !/[(),;]/.test(token)) {
            result += ' ';
        }
        result += token;
        prevToken = token;
    }

    document.getElementById('sql-output').textContent = result.trim();
}

function highlightSQL() {
    const output = document.getElementById('sql-output');
    let html = output.textContent;

    // Escape HTML
    html = html.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

    // Keywords
    const keywordRegex = new RegExp('\\b(' + SQL_KEYWORDS.join('|') + ')\\b', 'gi');
    html = html.replace(keywordRegex, '<span class="keyword">$1</span>');

    // Strings
    html = html.replace(/'[^']*'/g, '<span class="string">$&</span>');

    // Numbers
    html = html.replace(/\b(\d+)\b/g, '<span class="number">$1</span>');

    // Comments
    html = html.replace(/(--.*$)/gm, '<span class="comment">$1</span>');
    html = html.replace(/(\/\*[\s\S]*?\*\/)/g, '<span class="comment">$1</span>');

    output.innerHTML = html;
}

function clearSQL() {
    document.getElementById('sql-input').value = '';
    document.getElementById('sql-output').textContent = '';
}

function copySQL() {
    const output = document.getElementById('sql-output').textContent;
    navigator.clipboard.writeText(output);

    const btn = document.querySelector('.copy-btn');
    btn.textContent = 'Copie!';
    setTimeout(() => { btn.textContent = 'Copier'; }, 1000);
}

const EXAMPLES = {
    select: `select u.id, u.username, u.email, count(o.id) as order_count from users u left join orders o on o.user_id = u.id where u.status = 'active' and u.created_at > '2024-01-01' group by u.id, u.username, u.email having count(o.id) > 5 order by order_count desc limit 10`,

    join: `select p.name, c.name as category, s.quantity from products p inner join categories c on c.id = p.category_id left join stock s on s.product_id = p.id where p.active = true and c.name in ('Electronics', 'Books')`,

    subquery: `select * from users where id in (select user_id from orders where total > 100 and created_at > '2024-01-01') and status = 'active'`,

    insert: `insert into users (username, email, password_hash, created_at) values ('john_doe', 'john@example.com', 'hash123', now())`,

    update: `update products set price = price * 1.1, updated_at = now() where category_id = 5 and stock > 0`,

    create: `create table orders (id serial primary key, user_id integer not null references users(id), total decimal(10,2) not null default 0, status varchar(50) default 'pending', created_at timestamp default current_timestamp)`
};

function loadExample(name) {
    document.getElementById('sql-input').value = EXAMPLES[name];
    formatSQL();
}

// Initial format on load
document.getElementById('sql-input').value = EXAMPLES.select;
formatSQL();
</script>
