---
tags:
  - tools
  - security
  - password
---

# Password Strength Meter

Analyseur de robustesse de mot de passe avec suggestions d'amélioration.

<div id="password-strength">
  <style>
    #password-strength {
      font-family: inherit;
    }
    #password-strength .main-container {
      max-width: 700px;
    }
    #password-strength .input-section {
      background: var(--md-code-bg-color);
      border-radius: 8px;
      padding: 20px;
      margin-bottom: 20px;
    }
    #password-strength .password-input-wrapper {
      position: relative;
      display: flex;
      gap: 10px;
    }
    #password-strength .password-input {
      flex: 1;
      padding: 15px;
      font-size: 18px;
      font-family: monospace;
      border: 2px solid var(--md-default-fg-color--lighter);
      border-radius: 8px;
      background: var(--md-default-bg-color);
      color: var(--md-default-fg-color);
    }
    #password-strength .toggle-visibility {
      padding: 10px 15px;
      background: var(--md-default-fg-color--lighter);
      border: none;
      border-radius: 8px;
      cursor: pointer;
      font-size: 18px;
    }
    #password-strength .generate-btn {
      padding: 10px 20px;
      background: var(--md-primary-fg-color);
      color: white;
      border: none;
      border-radius: 8px;
      cursor: pointer;
      font-size: 14px;
    }
    #password-strength .strength-bar-container {
      margin-top: 15px;
    }
    #password-strength .strength-bar {
      height: 8px;
      background: var(--md-default-fg-color--lighter);
      border-radius: 4px;
      overflow: hidden;
    }
    #password-strength .strength-fill {
      height: 100%;
      transition: all 0.3s ease;
      border-radius: 4px;
    }
    #password-strength .strength-label {
      display: flex;
      justify-content: space-between;
      margin-top: 8px;
      font-size: 14px;
    }
    #password-strength .results-section {
      background: var(--md-code-bg-color);
      border-radius: 8px;
      padding: 20px;
    }
    #password-strength .section-title {
      font-size: 14px;
      font-weight: 600;
      margin: 20px 0 10px 0;
      padding-bottom: 5px;
      border-bottom: 1px solid var(--md-default-fg-color--lighter);
    }
    #password-strength .section-title:first-child {
      margin-top: 0;
    }
    #password-strength .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
      gap: 15px;
    }
    #password-strength .stat-card {
      background: var(--md-default-bg-color);
      border-radius: 8px;
      padding: 15px;
      text-align: center;
    }
    #password-strength .stat-value {
      font-size: 24px;
      font-weight: bold;
      color: var(--md-primary-fg-color);
    }
    #password-strength .stat-label {
      font-size: 12px;
      color: var(--md-default-fg-color--light);
      margin-top: 5px;
    }
    #password-strength .criteria-list {
      display: grid;
      gap: 8px;
    }
    #password-strength .criteria-item {
      display: flex;
      align-items: center;
      gap: 10px;
      padding: 10px;
      background: var(--md-default-bg-color);
      border-radius: 4px;
    }
    #password-strength .criteria-icon {
      width: 24px;
      height: 24px;
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 12px;
      color: white;
    }
    #password-strength .criteria-icon.pass {
      background: #27ae60;
    }
    #password-strength .criteria-icon.fail {
      background: #e74c3c;
    }
    #password-strength .suggestions-list {
      margin-top: 10px;
    }
    #password-strength .suggestion {
      display: flex;
      align-items: flex-start;
      gap: 10px;
      padding: 10px;
      background: var(--md-default-bg-color);
      border-radius: 4px;
      margin-bottom: 8px;
      font-size: 13px;
    }
    #password-strength .time-estimate {
      text-align: center;
      padding: 20px;
      background: var(--md-default-bg-color);
      border-radius: 8px;
      margin-top: 15px;
    }
    #password-strength .time-value {
      font-size: 28px;
      font-weight: bold;
      margin-bottom: 5px;
    }
    #password-strength .warning-box {
      background: #fff3cd;
      border: 1px solid #ffc107;
      border-radius: 4px;
      padding: 10px;
      margin-top: 15px;
      font-size: 12px;
      color: #856404;
    }
    #password-strength .generator-options {
      display: flex;
      flex-wrap: wrap;
      gap: 15px;
      margin-top: 15px;
      padding-top: 15px;
      border-top: 1px solid var(--md-default-fg-color--lighter);
    }
    #password-strength .option-group {
      display: flex;
      align-items: center;
      gap: 8px;
    }
    #password-strength .option-group label {
      font-size: 13px;
    }
    #password-strength input[type="number"] {
      width: 60px;
      padding: 5px;
      border: 1px solid var(--md-default-fg-color--lighter);
      border-radius: 4px;
      background: var(--md-default-bg-color);
      color: var(--md-default-fg-color);
    }
  </style>

  <div class="main-container">
    <div class="input-section">
      <div class="password-input-wrapper">
        <input type="password" class="password-input" id="pwd-input" placeholder="Entrez votre mot de passe..." oninput="analyzePassword()">
        <button class="toggle-visibility" onclick="toggleVisibility()">👁️</button>
        <button class="generate-btn" onclick="generatePassword()">🎲 Générer</button>
      </div>

      <div class="strength-bar-container">
        <div class="strength-bar">
          <div class="strength-fill" id="strength-fill"></div>
        </div>
        <div class="strength-label">
          <span id="strength-text">Entrez un mot de passe</span>
          <span id="strength-score">0/100</span>
        </div>
      </div>

      <div class="generator-options">
        <div class="option-group">
          <label for="gen-length">Longueur:</label>
          <input type="number" id="gen-length" value="16" min="8" max="64">
        </div>
        <label class="option-group">
          <input type="checkbox" id="gen-upper" checked> Majuscules
        </label>
        <label class="option-group">
          <input type="checkbox" id="gen-lower" checked> Minuscules
        </label>
        <label class="option-group">
          <input type="checkbox" id="gen-numbers" checked> Chiffres
        </label>
        <label class="option-group">
          <input type="checkbox" id="gen-symbols" checked> Symboles
        </label>
      </div>
    </div>

    <div class="results-section" id="results-section" style="display: none;">
      <div class="section-title">📊 Statistiques</div>
      <div class="stats-grid" id="stats-grid"></div>

      <div class="section-title">✅ Critères de sécurité</div>
      <div class="criteria-list" id="criteria-list"></div>

      <div class="time-estimate" id="time-estimate"></div>

      <div class="section-title">💡 Suggestions</div>
      <div class="suggestions-list" id="suggestions-list"></div>

      <div id="warnings-container"></div>
    </div>
  </div>
</div>

<script>
(function() {
  const commonPasswords = ['password', '123456', '12345678', 'qwerty', 'abc123', 'monkey', '1234567',
    'letmein', 'trustno1', 'dragon', 'baseball', 'iloveyou', 'master', 'sunshine', 'ashley',
    'bailey', 'passw0rd', 'shadow', '123123', '654321', 'superman', 'qazwsx', 'michael',
    'football', 'password1', 'password123', 'welcome', 'jesus', 'ninja', 'mustang'];

  const patterns = {
    keyboard: ['qwerty', 'azerty', 'qwertz', 'asdfgh', 'zxcvbn', '!@#$%', 'qweasd'],
    sequential: ['123456', 'abcdef', '987654', 'fedcba'],
    repeated: /(.)\1{2,}/
  };

  window.toggleVisibility = function() {
    const input = document.getElementById('pwd-input');
    const btn = event.target;
    if (input.type === 'password') {
      input.type = 'text';
      btn.textContent = '🙈';
    } else {
      input.type = 'password';
      btn.textContent = '👁️';
    }
  };

  window.generatePassword = function() {
    const length = parseInt(document.getElementById('gen-length').value) || 16;
    const useUpper = document.getElementById('gen-upper').checked;
    const useLower = document.getElementById('gen-lower').checked;
    const useNumbers = document.getElementById('gen-numbers').checked;
    const useSymbols = document.getElementById('gen-symbols').checked;

    let charset = '';
    if (useUpper) charset += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    if (useLower) charset += 'abcdefghijklmnopqrstuvwxyz';
    if (useNumbers) charset += '0123456789';
    if (useSymbols) charset += '!@#$%^&*()_+-=[]{}|;:,.<>?';

    if (!charset) charset = 'abcdefghijklmnopqrstuvwxyz';

    let password = '';
    const array = new Uint32Array(length);
    crypto.getRandomValues(array);
    for (let i = 0; i < length; i++) {
      password += charset[array[i] % charset.length];
    }

    document.getElementById('pwd-input').value = password;
    document.getElementById('pwd-input').type = 'text';
    document.querySelector('.toggle-visibility').textContent = '🙈';
    analyzePassword();
  };

  window.analyzePassword = function() {
    const password = document.getElementById('pwd-input').value;
    const resultsSection = document.getElementById('results-section');

    if (!password) {
      resultsSection.style.display = 'none';
      updateStrengthBar(0, 'Entrez un mot de passe');
      return;
    }

    resultsSection.style.display = 'block';

    // Calculate metrics
    const length = password.length;
    const hasLower = /[a-z]/.test(password);
    const hasUpper = /[A-Z]/.test(password);
    const hasNumbers = /[0-9]/.test(password);
    const hasSymbols = /[^a-zA-Z0-9]/.test(password);
    const uniqueChars = new Set(password).size;

    // Character pool size
    let poolSize = 0;
    if (hasLower) poolSize += 26;
    if (hasUpper) poolSize += 26;
    if (hasNumbers) poolSize += 10;
    if (hasSymbols) poolSize += 32;

    // Entropy calculation
    const entropy = length * Math.log2(poolSize || 1);

    // Check patterns
    const isCommon = commonPasswords.includes(password.toLowerCase());
    const hasKeyboardPattern = patterns.keyboard.some(p => password.toLowerCase().includes(p));
    const hasSequential = patterns.sequential.some(p => password.toLowerCase().includes(p));
    const hasRepeated = patterns.repeated.test(password);

    // Calculate score
    let score = 0;

    // Length score (max 30)
    score += Math.min(30, length * 2);

    // Character variety (max 20)
    if (hasLower) score += 5;
    if (hasUpper) score += 5;
    if (hasNumbers) score += 5;
    if (hasSymbols) score += 5;

    // Entropy bonus (max 30)
    score += Math.min(30, entropy / 3);

    // Unique chars bonus (max 10)
    score += Math.min(10, uniqueChars / 2);

    // Penalties
    if (isCommon) score -= 50;
    if (hasKeyboardPattern) score -= 15;
    if (hasSequential) score -= 15;
    if (hasRepeated) score -= 10;
    if (length < 8) score -= 20;

    score = Math.max(0, Math.min(100, Math.round(score)));

    // Crack time estimation
    const crackTime = calculateCrackTime(poolSize, length);

    // Update UI
    updateStrengthBar(score, getStrengthLabel(score));
    updateStats(length, uniqueChars, poolSize, entropy);
    updateCriteria(length, hasLower, hasUpper, hasNumbers, hasSymbols, uniqueChars);
    updateTimeEstimate(crackTime);
    updateSuggestions(length, hasLower, hasUpper, hasNumbers, hasSymbols, isCommon, hasKeyboardPattern, hasSequential, hasRepeated);
    updateWarnings(isCommon, password);
  };

  function updateStrengthBar(score, label) {
    const fill = document.getElementById('strength-fill');
    const text = document.getElementById('strength-text');
    const scoreEl = document.getElementById('strength-score');

    let color;
    if (score < 25) color = '#e74c3c';
    else if (score < 50) color = '#f39c12';
    else if (score < 75) color = '#f1c40f';
    else color = '#27ae60';

    fill.style.width = score + '%';
    fill.style.background = color;
    text.textContent = label;
    text.style.color = color;
    scoreEl.textContent = score + '/100';
  }

  function getStrengthLabel(score) {
    if (score < 25) return 'Très faible';
    if (score < 50) return 'Faible';
    if (score < 75) return 'Moyen';
    if (score < 90) return 'Fort';
    return 'Très fort';
  }

  function updateStats(length, unique, pool, entropy) {
    document.getElementById('stats-grid').innerHTML = `
      <div class="stat-card">
        <div class="stat-value">${length}</div>
        <div class="stat-label">Caractères</div>
      </div>
      <div class="stat-card">
        <div class="stat-value">${unique}</div>
        <div class="stat-label">Uniques</div>
      </div>
      <div class="stat-card">
        <div class="stat-value">${pool}</div>
        <div class="stat-label">Pool size</div>
      </div>
      <div class="stat-card">
        <div class="stat-value">${Math.round(entropy)}</div>
        <div class="stat-label">Bits d'entropie</div>
      </div>
    `;
  }

  function updateCriteria(length, lower, upper, numbers, symbols, unique) {
    const criteria = [
      { pass: length >= 8, text: 'Au moins 8 caractères' },
      { pass: length >= 12, text: 'Au moins 12 caractères (recommandé)' },
      { pass: lower, text: 'Contient des minuscules (a-z)' },
      { pass: upper, text: 'Contient des majuscules (A-Z)' },
      { pass: numbers, text: 'Contient des chiffres (0-9)' },
      { pass: symbols, text: 'Contient des symboles (!@#...)' },
      { pass: unique >= length * 0.6, text: 'Bonne diversité de caractères' }
    ];

    document.getElementById('criteria-list').innerHTML = criteria.map(c => `
      <div class="criteria-item">
        <div class="criteria-icon ${c.pass ? 'pass' : 'fail'}">${c.pass ? '✓' : '✗'}</div>
        <span>${c.text}</span>
      </div>
    `).join('');
  }

  function calculateCrackTime(poolSize, length) {
    // Assuming 10 billion guesses per second (modern GPU)
    const guessesPerSecond = 10e9;
    const combinations = Math.pow(poolSize, length);
    const seconds = combinations / guessesPerSecond / 2; // Average case

    return formatTime(seconds);
  }

  function formatTime(seconds) {
    if (seconds < 1) return 'Instantané';
    if (seconds < 60) return Math.round(seconds) + ' secondes';
    if (seconds < 3600) return Math.round(seconds / 60) + ' minutes';
    if (seconds < 86400) return Math.round(seconds / 3600) + ' heures';
    if (seconds < 2592000) return Math.round(seconds / 86400) + ' jours';
    if (seconds < 31536000) return Math.round(seconds / 2592000) + ' mois';
    if (seconds < 31536000 * 100) return Math.round(seconds / 31536000) + ' ans';
    if (seconds < 31536000 * 1000000) return Math.round(seconds / 31536000 / 1000) + ' milliers d\'années';
    return '∞ (pratiquement incassable)';
  }

  function updateTimeEstimate(time) {
    document.getElementById('time-estimate').innerHTML = `
      <div>Temps estimé pour craquer (10B essais/sec):</div>
      <div class="time-value">${time}</div>
    `;
  }

  function updateSuggestions(length, lower, upper, numbers, symbols, isCommon, keyboard, sequential, repeated) {
    const suggestions = [];

    if (isCommon) {
      suggestions.push({ icon: '🚨', text: 'Ce mot de passe est dans les listes de mots de passe courants. Changez-le immédiatement!' });
    }
    if (length < 12) {
      suggestions.push({ icon: '📏', text: 'Augmentez la longueur à au moins 12 caractères pour une meilleure sécurité.' });
    }
    if (!upper) {
      suggestions.push({ icon: '🔠', text: 'Ajoutez des lettres majuscules pour augmenter la complexité.' });
    }
    if (!lower) {
      suggestions.push({ icon: '🔡', text: 'Ajoutez des lettres minuscules.' });
    }
    if (!numbers) {
      suggestions.push({ icon: '🔢', text: 'Incluez des chiffres dans votre mot de passe.' });
    }
    if (!symbols) {
      suggestions.push({ icon: '🔣', text: 'Ajoutez des symboles spéciaux (!@#$%...) pour renforcer la sécurité.' });
    }
    if (keyboard) {
      suggestions.push({ icon: '⌨️', text: 'Évitez les patterns de clavier (qwerty, azerty...).' });
    }
    if (sequential) {
      suggestions.push({ icon: '🔢', text: 'Évitez les séquences (123456, abcdef...).' });
    }
    if (repeated) {
      suggestions.push({ icon: '🔁', text: 'Évitez les caractères répétés (aaa, 111...).' });
    }

    if (suggestions.length === 0) {
      suggestions.push({ icon: '✅', text: 'Excellent mot de passe! Continuez à utiliser des mots de passe uniques pour chaque service.' });
    }

    document.getElementById('suggestions-list').innerHTML = suggestions.map(s =>
      `<div class="suggestion"><span>${s.icon}</span><span>${s.text}</span></div>`
    ).join('');
  }

  function updateWarnings(isCommon, password) {
    const container = document.getElementById('warnings-container');

    if (isCommon) {
      container.innerHTML = `
        <div class="warning-box">
          <strong>⚠️ ATTENTION:</strong> Ce mot de passe figure dans les listes des mots de passe les plus utilisés.
          Il sera testé en premier lors d'une attaque par dictionnaire.
        </div>
      `;
    } else {
      container.innerHTML = '';
    }
  }

  // Initialize
  analyzePassword();
})();
</script>

---

## Recommandations

### Longueur vs Complexité

| Longueur | Entropie approximative | Niveau |
|----------|----------------------|--------|
| 8 caractères mixtes | ~52 bits | Minimum |
| 12 caractères mixtes | ~78 bits | Recommandé |
| 16 caractères mixtes | ~104 bits | Fort |
| 20+ caractères | ~130+ bits | Excellent |

### Bonnes pratiques

1. **Utilisez un gestionnaire de mots de passe** (Bitwarden, 1Password, KeePass)
2. **Un mot de passe unique par service**
3. **Activez la 2FA/MFA** quand disponible
4. **Préférez les passphrases** (ex: `correct-horse-battery-staple`)
5. **Évitez** les informations personnelles (dates, noms...)

---

## Entropie

L'entropie mesure l'imprévisibilité d'un mot de passe:

```
Entropie = longueur × log₂(taille_alphabet)

Exemple (12 caractères mixtes):
- Minuscules: 26
- Majuscules: 26
- Chiffres: 10
- Symboles: 32
Total: 94 caractères

Entropie = 12 × log₂(94) ≈ 78 bits
```

| Bits | Temps de crack (10B/s) |
|------|----------------------|
| 40 | ~2 minutes |
| 50 | ~30 heures |
| 60 | ~3 ans |
| 70 | ~3700 ans |
| 80 | ~4 millions d'années |
