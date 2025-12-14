---
tags:
  - tools
  - regex
  - development
  - reference
---

# Regex Quick Reference

Testeur et référence rapide des expressions régulières.

<div id="regex-reference">
  <style>
    #regex-reference {
      font-family: inherit;
    }
    #regex-reference .tester-section {
      background: var(--md-code-bg-color);
      border-radius: 8px;
      padding: 20px;
      margin-bottom: 20px;
    }
    #regex-reference .form-group {
      margin-bottom: 15px;
    }
    #regex-reference label {
      display: block;
      margin-bottom: 5px;
      font-weight: 500;
      font-size: 14px;
    }
    #regex-reference .regex-input-wrapper {
      display: flex;
      align-items: center;
      background: var(--md-default-bg-color);
      border: 2px solid var(--md-default-fg-color--lighter);
      border-radius: 4px;
      padding: 0 10px;
    }
    #regex-reference .regex-input-wrapper:focus-within {
      border-color: var(--md-primary-fg-color);
    }
    #regex-reference .regex-delimiter {
      color: var(--md-default-fg-color--light);
      font-family: monospace;
      font-size: 18px;
    }
    #regex-reference .regex-input {
      flex: 1;
      padding: 10px 5px;
      border: none;
      background: transparent;
      font-family: monospace;
      font-size: 16px;
      color: var(--md-primary-fg-color);
      outline: none;
    }
    #regex-reference .flags-input {
      width: 50px;
      padding: 10px 5px;
      border: none;
      background: transparent;
      font-family: monospace;
      font-size: 16px;
      color: var(--md-accent-fg-color);
      outline: none;
    }
    #regex-reference textarea {
      width: 100%;
      padding: 12px;
      border: 1px solid var(--md-default-fg-color--lighter);
      border-radius: 4px;
      background: var(--md-default-bg-color);
      color: var(--md-default-fg-color);
      font-family: monospace;
      font-size: 14px;
      resize: vertical;
      box-sizing: border-box;
      min-height: 100px;
    }
    #regex-reference .test-output {
      min-height: 100px;
      white-space: pre-wrap;
      line-height: 1.8;
    }
    #regex-reference .match {
      background: #27ae6044;
      border-radius: 2px;
      padding: 2px 0;
    }
    #regex-reference .match-group {
      background: #3498db44;
      border-radius: 2px;
    }
    #regex-reference .stats {
      display: flex;
      gap: 20px;
      margin-top: 10px;
      font-size: 13px;
      color: var(--md-default-fg-color--light);
    }
    #regex-reference .presets {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-bottom: 15px;
    }
    #regex-reference .preset-btn {
      padding: 5px 10px;
      border: 1px solid var(--md-primary-fg-color);
      background: transparent;
      color: var(--md-primary-fg-color);
      border-radius: 4px;
      cursor: pointer;
      font-size: 11px;
    }
    #regex-reference .preset-btn:hover {
      background: var(--md-primary-fg-color);
      color: white;
    }
    #regex-reference .reference-section {
      background: var(--md-code-bg-color);
      border-radius: 8px;
      padding: 20px;
    }
    #regex-reference .ref-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
      gap: 20px;
    }
    #regex-reference .ref-category {
      background: var(--md-default-bg-color);
      border-radius: 8px;
      padding: 15px;
    }
    #regex-reference .ref-category h4 {
      margin: 0 0 10px 0;
      font-size: 14px;
      color: var(--md-primary-fg-color);
    }
    #regex-reference .ref-table {
      width: 100%;
      font-size: 12px;
    }
    #regex-reference .ref-table td {
      padding: 5px 8px;
      border-bottom: 1px solid var(--md-default-fg-color--lighter);
    }
    #regex-reference .ref-table td:first-child {
      font-family: monospace;
      color: var(--md-primary-fg-color);
      white-space: nowrap;
      width: 80px;
    }
    #regex-reference .error-msg {
      color: #e74c3c;
      padding: 10px;
      background: #e74c3c22;
      border-radius: 4px;
      font-size: 13px;
    }
    #regex-reference .matches-list {
      margin-top: 15px;
      font-size: 13px;
    }
    #regex-reference .match-item {
      display: flex;
      gap: 15px;
      padding: 8px 10px;
      background: var(--md-default-bg-color);
      border-radius: 4px;
      margin-bottom: 5px;
    }
    #regex-reference .match-index {
      color: var(--md-default-fg-color--light);
      min-width: 40px;
    }
    #regex-reference .match-value {
      font-family: monospace;
      color: var(--md-primary-fg-color);
    }
    #regex-reference .match-groups {
      color: var(--md-default-fg-color--light);
      font-size: 11px;
    }
  </style>

  <div class="tester-section">
    <div class="presets">
      <button class="preset-btn" onclick="loadRegex('email')">📧 Email</button>
      <button class="preset-btn" onclick="loadRegex('url')">🔗 URL</button>
      <button class="preset-btn" onclick="loadRegex('ip')">🌐 IP</button>
      <button class="preset-btn" onclick="loadRegex('phone')">📱 Téléphone</button>
      <button class="preset-btn" onclick="loadRegex('date')">📅 Date</button>
      <button class="preset-btn" onclick="loadRegex('password')">🔑 Password</button>
      <button class="preset-btn" onclick="loadRegex('hex')">🎨 Hex Color</button>
      <button class="preset-btn" onclick="loadRegex('uuid')">🆔 UUID</button>
    </div>

    <div class="form-group">
      <label>Expression régulière</label>
      <div class="regex-input-wrapper">
        <span class="regex-delimiter">/</span>
        <input type="text" class="regex-input" id="regex-pattern" placeholder="pattern" value="\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b" oninput="testRegex()">
        <span class="regex-delimiter">/</span>
        <input type="text" class="flags-input" id="regex-flags" placeholder="gi" value="gi" oninput="testRegex()">
      </div>
    </div>

    <div class="form-group">
      <label>Texte à tester</label>
      <textarea id="regex-input" oninput="testRegex()">Contactez-nous à support@example.com ou sales@company.org.
Vous pouvez aussi utiliser info@test.co.uk pour les questions générales.
Adresse invalide: not-an-email@</textarea>
    </div>

    <div class="form-group">
      <label>Résultat</label>
      <div class="test-output" id="regex-output"></div>
      <div class="stats" id="regex-stats"></div>
    </div>

    <div class="matches-list" id="matches-list"></div>
  </div>

  <div class="reference-section">
    <div class="ref-grid">
      <div class="ref-category">
        <h4>Caractères</h4>
        <table class="ref-table">
          <tr><td>.</td><td>Tout caractère (sauf newline)</td></tr>
          <tr><td>\d</td><td>Chiffre [0-9]</td></tr>
          <tr><td>\D</td><td>Non-chiffre [^0-9]</td></tr>
          <tr><td>\w</td><td>Mot [a-zA-Z0-9_]</td></tr>
          <tr><td>\W</td><td>Non-mot [^a-zA-Z0-9_]</td></tr>
          <tr><td>\s</td><td>Espace blanc</td></tr>
          <tr><td>\S</td><td>Non-espace</td></tr>
          <tr><td>\n</td><td>Nouvelle ligne</td></tr>
          <tr><td>\t</td><td>Tabulation</td></tr>
        </table>
      </div>

      <div class="ref-category">
        <h4>Ancres</h4>
        <table class="ref-table">
          <tr><td>^</td><td>Début de ligne</td></tr>
          <tr><td>$</td><td>Fin de ligne</td></tr>
          <tr><td>\b</td><td>Frontière de mot</td></tr>
          <tr><td>\B</td><td>Non-frontière de mot</td></tr>
          <tr><td>(?=...)</td><td>Lookahead positif</td></tr>
          <tr><td>(?!...)</td><td>Lookahead négatif</td></tr>
          <tr><td>(?<=...)</td><td>Lookbehind positif</td></tr>
          <tr><td>(?<!...)</td><td>Lookbehind négatif</td></tr>
        </table>
      </div>

      <div class="ref-category">
        <h4>Quantificateurs</h4>
        <table class="ref-table">
          <tr><td>*</td><td>0 ou plus</td></tr>
          <tr><td>+</td><td>1 ou plus</td></tr>
          <tr><td>?</td><td>0 ou 1</td></tr>
          <tr><td>{n}</td><td>Exactement n</td></tr>
          <tr><td>{n,}</td><td>n ou plus</td></tr>
          <tr><td>{n,m}</td><td>Entre n et m</td></tr>
          <tr><td>*?</td><td>0+ (lazy)</td></tr>
          <tr><td>+?</td><td>1+ (lazy)</td></tr>
        </table>
      </div>

      <div class="ref-category">
        <h4>Groupes & Classes</h4>
        <table class="ref-table">
          <tr><td>[abc]</td><td>a, b ou c</td></tr>
          <tr><td>[^abc]</td><td>Pas a, b, c</td></tr>
          <tr><td>[a-z]</td><td>Plage a à z</td></tr>
          <tr><td>(abc)</td><td>Groupe capturant</td></tr>
          <tr><td>(?:abc)</td><td>Groupe non-capturant</td></tr>
          <tr><td>(?&lt;name&gt;)</td><td>Groupe nommé</td></tr>
          <tr><td>\1</td><td>Référence au groupe 1</td></tr>
          <tr><td>a|b</td><td>a ou b</td></tr>
        </table>
      </div>

      <div class="ref-category">
        <h4>Flags</h4>
        <table class="ref-table">
          <tr><td>g</td><td>Global (toutes les occurrences)</td></tr>
          <tr><td>i</td><td>Insensible à la casse</td></tr>
          <tr><td>m</td><td>Multiline (^ et $ par ligne)</td></tr>
          <tr><td>s</td><td>Dotall (. inclut \n)</td></tr>
          <tr><td>u</td><td>Unicode</td></tr>
          <tr><td>y</td><td>Sticky</td></tr>
        </table>
      </div>

      <div class="ref-category">
        <h4>Caractères spéciaux</h4>
        <table class="ref-table">
          <tr><td>\\</td><td>Échapper caractère spécial</td></tr>
          <tr><td>\.</td><td>Point littéral</td></tr>
          <tr><td>\*</td><td>Astérisque littéral</td></tr>
          <tr><td>\+</td><td>Plus littéral</td></tr>
          <tr><td>\?</td><td>Question littéral</td></tr>
          <tr><td>\[</td><td>Crochet littéral</td></tr>
          <tr><td>\(</td><td>Parenthèse littérale</td></tr>
        </table>
      </div>
    </div>
  </div>
</div>

<script>
(function() {
  const presets = {
    email: {
      pattern: '\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b',
      flags: 'gi',
      text: 'Emails: support@example.com, john.doe@company.org, invalid@'
    },
    url: {
      pattern: 'https?:\\/\\/[\\w\\-._~:/?#[\\]@!$&\'()*+,;=]+',
      flags: 'gi',
      text: 'Visit https://example.com or http://test.org/path?query=1'
    },
    ip: {
      pattern: '\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b',
      flags: 'g',
      text: 'IPs: 192.168.1.1, 10.0.0.255, 256.1.1.1 (invalid), 8.8.8.8'
    },
    phone: {
      pattern: '(?:\\+33|0)\\s?[1-9](?:[\\s.-]?\\d{2}){4}',
      flags: 'g',
      text: 'Tél: +33 6 12 34 56 78, 01 23 45 67 89, 06.12.34.56.78'
    },
    date: {
      pattern: '\\b(0?[1-9]|[12][0-9]|3[01])[\\/\\-](0?[1-9]|1[012])[\\/\\-](19|20)?\\d{2}\\b',
      flags: 'g',
      text: 'Dates: 15/03/2024, 01-12-2023, 31/12/99'
    },
    password: {
      pattern: '^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$',
      flags: '',
      text: 'Test123!@\nweak\nStrong1!'
    },
    hex: {
      pattern: '#(?:[0-9a-fA-F]{3}){1,2}\\b',
      flags: 'g',
      text: 'Colors: #fff, #FF5733, #123456, #xyz (invalid)'
    },
    uuid: {
      pattern: '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
      flags: 'gi',
      text: 'UUID: 123e4567-e89b-12d3-a456-426614174000'
    }
  };

  window.loadRegex = function(preset) {
    const p = presets[preset];
    document.getElementById('regex-pattern').value = p.pattern;
    document.getElementById('regex-flags').value = p.flags;
    document.getElementById('regex-input').value = p.text;
    testRegex();
  };

  window.testRegex = function() {
    const pattern = document.getElementById('regex-pattern').value;
    const flags = document.getElementById('regex-flags').value;
    const text = document.getElementById('regex-input').value;
    const output = document.getElementById('regex-output');
    const stats = document.getElementById('regex-stats');
    const matchesList = document.getElementById('matches-list');

    if (!pattern) {
      output.innerHTML = text;
      stats.innerHTML = '';
      matchesList.innerHTML = '';
      return;
    }

    try {
      const regex = new RegExp(pattern, flags);
      const matches = [];
      let match;
      let highlighted = text;
      let matchCount = 0;

      // Reset lastIndex for global regex
      regex.lastIndex = 0;

      if (flags.includes('g')) {
        // Collect all matches
        while ((match = regex.exec(text)) !== null) {
          matches.push({
            value: match[0],
            index: match.index,
            groups: match.slice(1)
          });
          matchCount++;
          if (matchCount > 100) break; // Safety limit
        }

        // Highlight matches (from end to start to preserve indices)
        for (let i = matches.length - 1; i >= 0; i--) {
          const m = matches[i];
          highlighted = highlighted.slice(0, m.index) +
                       '<span class="match">' + escapeHtml(m.value) + '</span>' +
                       highlighted.slice(m.index + m.value.length);
        }
      } else {
        match = regex.exec(text);
        if (match) {
          matches.push({
            value: match[0],
            index: match.index,
            groups: match.slice(1)
          });
          highlighted = text.slice(0, match.index) +
                       '<span class="match">' + escapeHtml(match[0]) + '</span>' +
                       text.slice(match.index + match[0].length);
          matchCount = 1;
        }
      }

      output.innerHTML = highlighted || escapeHtml(text);
      stats.innerHTML = `<span>✓ ${matchCount} correspondance${matchCount !== 1 ? 's' : ''}</span>`;

      // Show matches list
      if (matches.length > 0) {
        matchesList.innerHTML = matches.slice(0, 20).map((m, i) => `
          <div class="match-item">
            <span class="match-index">#${i + 1}</span>
            <span class="match-value">"${escapeHtml(m.value)}"</span>
            ${m.groups.length > 0 ? `<span class="match-groups">Groupes: ${m.groups.map((g, j) => `$${j+1}="${g || ''}"`).join(', ')}</span>` : ''}
          </div>
        `).join('') + (matches.length > 20 ? '<div style="padding: 10px; color: var(--md-default-fg-color--light);">... et ' + (matches.length - 20) + ' autres</div>' : '');
      } else {
        matchesList.innerHTML = '';
      }
    } catch (e) {
      output.innerHTML = `<div class="error-msg">⚠️ Erreur: ${e.message}</div>`;
      stats.innerHTML = '';
      matchesList.innerHTML = '';
    }
  };

  function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }

  // Initialize
  testRegex();
})();
</script>

---

## Patterns courants

### Validation

```regex
# Email
^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$

# URL
^https?:\/\/[\w\-._~:\/?#\[\]@!$&'()*+,;=]+$

# IP v4
^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$

# UUID
^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$

# Mot de passe fort (8+ chars, maj, min, chiffre, symbole)
^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$
```

### Extraction

```regex
# Extraire domaine d'URL
https?:\/\/([^\/\s]+)

# Extraire extension de fichier
\.([a-zA-Z0-9]+)$

# Extraire hashtags
#(\w+)

# Extraire mentions @user
@(\w+)
```

### Remplacement

```javascript
// Masquer email
text.replace(/([a-z])[a-z]+@/gi, '$1***@')

// Formater numéro de téléphone
phone.replace(/(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})/, '$1 $2 $3 $4 $5')

// Supprimer balises HTML
html.replace(/<[^>]*>/g, '')
```
