---
tags:
  - tools
  - diff
  - comparison
  - text
---

# Diff Tool

Comparaison de texte cote a cote.

<div class="tool-container">

<div class="diff-options">
    <label><input type="checkbox" id="ignore-case"> Ignorer la casse</label>
    <label><input type="checkbox" id="ignore-whitespace"> Ignorer les espaces</label>
    <label><input type="checkbox" id="show-line-numbers" checked> Numeros de ligne</label>
</div>

<div class="diff-panels">
    <div class="diff-panel">
        <label>Texte original :</label>
        <textarea id="text-left" rows="15" placeholder="Collez le texte original ici..."></textarea>
    </div>
    <div class="diff-panel">
        <label>Texte modifie :</label>
        <textarea id="text-right" rows="15" placeholder="Collez le texte modifie ici..."></textarea>
    </div>
</div>

<button onclick="compareDiff()" class="action-btn">Comparer</button>

<div id="diff-stats" class="stats-box" style="display:none;">
    <span><strong>Lignes ajoutees :</strong> <span id="added-count">0</span></span>
    <span><strong>Lignes supprimees :</strong> <span id="removed-count">0</span></span>
    <span><strong>Lignes modifiees :</strong> <span id="changed-count">0</span></span>
</div>

<div id="diff-result" class="diff-result"></div>

</div>

## Outils diff en CLI

### Linux

```bash
# Diff standard
diff fichier1.txt fichier2.txt

# Diff unifie (plus lisible)
diff -u fichier1.txt fichier2.txt

# Diff cote a cote
diff -y fichier1.txt fichier2.txt

# Ignorer les espaces
diff -w fichier1.txt fichier2.txt

# Diff recursif (dossiers)
diff -r dossier1/ dossier2/

# Diff colore
diff --color fichier1.txt fichier2.txt
```

### Git

```bash
# Diff des modifications non commitees
git diff

# Diff entre commits
git diff commit1 commit2

# Diff d'un fichier specifique
git diff -- fichier.txt

# Diff avec stats
git diff --stat

# Diff mot a mot
git diff --word-diff
```

### Formats de sortie

| Format | Description |
|--------|-------------|
| Normal | `< ligne1` et `> ligne2` |
| Unifie (`-u`) | `+` ajouts, `-` suppressions |
| Context (`-c`) | Avec contexte environnant |
| Side-by-side (`-y`) | Cote a cote |

<style>
.tool-container {
    background: var(--md-code-bg-color);
    padding: 20px;
    border-radius: 8px;
    margin: 20px 0;
}
.diff-options {
    margin-bottom: 15px;
}
.diff-options label {
    margin-right: 20px;
    cursor: pointer;
}
.diff-panels {
    display: flex;
    gap: 20px;
    flex-wrap: wrap;
}
.diff-panel {
    flex: 1;
    min-width: 300px;
}
.diff-panel label {
    display: block;
    font-weight: bold;
    margin-bottom: 5px;
}
.diff-panel textarea {
    width: 100%;
    padding: 10px;
    font-family: monospace;
    font-size: 13px;
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    background: var(--md-default-bg-color);
    color: var(--md-default-fg-color);
    resize: vertical;
}
.action-btn {
    margin-top: 15px;
    padding: 12px 24px;
    background: var(--md-primary-fg-color);
    color: white;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    font-size: 16px;
}
.action-btn:hover {
    opacity: 0.9;
}
.stats-box {
    display: flex;
    gap: 30px;
    flex-wrap: wrap;
    margin: 20px 0;
    padding: 15px;
    background: var(--md-default-bg-color);
    border-radius: 4px;
}
.diff-result {
    margin-top: 20px;
    font-family: monospace;
    font-size: 13px;
    overflow-x: auto;
}
.diff-table {
    width: 100%;
    border-collapse: collapse;
}
.diff-table td {
    padding: 2px 8px;
    vertical-align: top;
    border-bottom: 1px solid var(--md-default-fg-color--lightest);
}
.diff-table .line-num {
    width: 40px;
    text-align: right;
    color: var(--md-default-fg-color--light);
    background: var(--md-default-bg-color);
    user-select: none;
}
.diff-table .line-content {
    white-space: pre-wrap;
    word-break: break-all;
}
.diff-table tr.added .line-content {
    background: #d4edda;
    color: #155724;
}
.diff-table tr.removed .line-content {
    background: #f8d7da;
    color: #721c24;
}
.diff-table tr.changed .line-content {
    background: #fff3cd;
    color: #856404;
}
.diff-table tr.unchanged .line-content {
    background: var(--md-default-bg-color);
}
.diff-separator {
    width: 20px;
    text-align: center;
    background: var(--md-code-bg-color);
}
</style>

<script>
function compareDiff() {
    const leftText = document.getElementById('text-left').value;
    const rightText = document.getElementById('text-right').value;
    const ignoreCase = document.getElementById('ignore-case').checked;
    const ignoreWhitespace = document.getElementById('ignore-whitespace').checked;
    const showLineNumbers = document.getElementById('show-line-numbers').checked;

    const leftLines = leftText.split('\n');
    const rightLines = rightText.split('\n');

    // Normalize lines for comparison
    function normalize(line) {
        let result = line;
        if (ignoreCase) result = result.toLowerCase();
        if (ignoreWhitespace) result = result.replace(/\s+/g, ' ').trim();
        return result;
    }

    // Simple LCS-based diff
    const diff = computeDiff(leftLines, rightLines, normalize);

    // Build result table
    let html = '<table class="diff-table">';

    let addedCount = 0, removedCount = 0, changedCount = 0;

    for (const item of diff) {
        const leftNum = showLineNumbers && item.leftNum ? item.leftNum : '';
        const rightNum = showLineNumbers && item.rightNum ? item.rightNum : '';
        const leftContent = escapeHtml(item.left || '');
        const rightContent = escapeHtml(item.right || '');

        let rowClass = 'unchanged';
        if (item.type === 'added') {
            rowClass = 'added';
            addedCount++;
        } else if (item.type === 'removed') {
            rowClass = 'removed';
            removedCount++;
        } else if (item.type === 'changed') {
            rowClass = 'changed';
            changedCount++;
        }

        html += `<tr class="${rowClass}">`;
        if (showLineNumbers) {
            html += `<td class="line-num">${leftNum}</td>`;
        }
        html += `<td class="line-content">${leftContent}</td>`;
        html += `<td class="diff-separator">|</td>`;
        if (showLineNumbers) {
            html += `<td class="line-num">${rightNum}</td>`;
        }
        html += `<td class="line-content">${rightContent}</td>`;
        html += '</tr>';
    }

    html += '</table>';

    document.getElementById('diff-result').innerHTML = html;

    // Update stats
    document.getElementById('added-count').textContent = addedCount;
    document.getElementById('removed-count').textContent = removedCount;
    document.getElementById('changed-count').textContent = changedCount;
    document.getElementById('diff-stats').style.display = 'flex';
}

function computeDiff(left, right, normalize) {
    const result = [];
    let leftIdx = 0, rightIdx = 0;
    let leftNum = 1, rightNum = 1;

    // Create normalized arrays for comparison
    const leftNorm = left.map(normalize);
    const rightNorm = right.map(normalize);

    while (leftIdx < left.length || rightIdx < right.length) {
        if (leftIdx >= left.length) {
            // Only right lines remain (added)
            result.push({
                type: 'added',
                left: '',
                right: right[rightIdx],
                leftNum: null,
                rightNum: rightNum++
            });
            rightIdx++;
        } else if (rightIdx >= right.length) {
            // Only left lines remain (removed)
            result.push({
                type: 'removed',
                left: left[leftIdx],
                right: '',
                leftNum: leftNum++,
                rightNum: null
            });
            leftIdx++;
        } else if (leftNorm[leftIdx] === rightNorm[rightIdx]) {
            // Lines match
            result.push({
                type: 'unchanged',
                left: left[leftIdx],
                right: right[rightIdx],
                leftNum: leftNum++,
                rightNum: rightNum++
            });
            leftIdx++;
            rightIdx++;
        } else {
            // Lines differ - look ahead for matches
            let foundInRight = rightNorm.indexOf(leftNorm[leftIdx], rightIdx);
            let foundInLeft = leftNorm.indexOf(rightNorm[rightIdx], leftIdx);

            if (foundInRight === -1 && foundInLeft === -1) {
                // Changed line
                result.push({
                    type: 'changed',
                    left: left[leftIdx],
                    right: right[rightIdx],
                    leftNum: leftNum++,
                    rightNum: rightNum++
                });
                leftIdx++;
                rightIdx++;
            } else if (foundInRight !== -1 && (foundInLeft === -1 || foundInRight - rightIdx <= foundInLeft - leftIdx)) {
                // Line was added in right
                result.push({
                    type: 'added',
                    left: '',
                    right: right[rightIdx],
                    leftNum: null,
                    rightNum: rightNum++
                });
                rightIdx++;
            } else {
                // Line was removed from left
                result.push({
                    type: 'removed',
                    left: left[leftIdx],
                    right: '',
                    leftNum: leftNum++,
                    rightNum: null
                });
                leftIdx++;
            }
        }
    }

    return result;
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}
</script>
