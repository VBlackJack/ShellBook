---
tags:
  - tools
  - security
  - password
---

# Password Generator

Generateur de mots de passe securises (100% client-side).

<div class="tool-container">

<div class="input-row">
    <div class="input-group">
        <label for="pwd-length">Longueur :</label>
        <input type="range" id="pwd-length" min="8" max="128" value="20">
        <span id="length-display">20</span>
    </div>
</div>

<div class="options-grid">
    <div class="option-group">
        <h4>Caracteres</h4>
        <label><input type="checkbox" id="opt-upper" checked> Majuscules (A-Z)</label>
        <label><input type="checkbox" id="opt-lower" checked> Minuscules (a-z)</label>
        <label><input type="checkbox" id="opt-numbers" checked> Chiffres (0-9)</label>
        <label><input type="checkbox" id="opt-symbols" checked> Symboles (!@#$...)</label>
    </div>
    <div class="option-group">
        <h4>Options</h4>
        <label><input type="checkbox" id="opt-ambiguous"> Exclure ambigus (0O, 1lI)</label>
        <label><input type="checkbox" id="opt-brackets"> Inclure brackets ()[]{}</label>
        <label><input type="checkbox" id="opt-extended"> Symboles etendus</label>
    </div>
    <div class="option-group">
        <h4>Modes speciaux</h4>
        <label><input type="checkbox" id="opt-cvc"> <strong>CVC</strong> - Prononcable (Consonne-Voyelle)</label>
        <label><input type="checkbox" id="opt-layout-safe"> <strong>Layout Safe</strong> - Compatible AZERTY/QWERTY</label>
    </div>
</div>

<div id="cvc-info" class="info-box" style="display:none;">
    <strong>Mode CVC:</strong> Genere des mots de passe prononcables en alternant consonnes et voyelles.
    <br>Les options Chiffres et Symboles sont respectees (intercales dans le mot de passe).
    <br>Exemple: <code>Kavupobi</code>, <code>Taf3Kun9</code>, <code>Bel-Vop4</code>
</div>

<div id="layout-info" class="info-box" style="display:none;">
    <strong>Layout Safe:</strong> Utilise uniquement les caracteres identiques sur AZERTY et QWERTY.
    <br>Evite: Q, W, Z, A, M (positions differentes). Symboles limites a <code>. - _</code>
</div>

<div class="password-output">
    <input type="text" id="password-result" readonly>
    <button onclick="copyPassword()" class="copy-btn" title="Copier">&#128203;</button>
    <button onclick="generatePassword()" class="refresh-btn" title="Regenerer">&#8635;</button>
</div>

<div class="strength-meter">
    <div id="strength-bar"></div>
</div>
<div id="strength-text">-</div>

<div class="batch-section">
    <h4>Generation en lot</h4>
    <div class="input-row">
        <div class="input-group">
            <label for="batch-count">Nombre :</label>
            <input type="number" id="batch-count" value="5" min="1" max="100">
        </div>
        <button onclick="generateBatch()" class="calc-btn">Generer</button>
    </div>
    <textarea id="batch-output" readonly placeholder="Les mots de passe generes apparaitront ici..."></textarea>
</div>

</div>

## Recommandations

### Longueur minimale par usage

| Usage | Longueur min | Recommandation |
|-------|--------------|----------------|
| Wi-Fi WPA2/3 | 12 | 20+ caracteres |
| Compte utilisateur | 12 | 16+ caracteres |
| Compte admin | 16 | 20+ caracteres |
| Cle API / Token | 32 | 64+ caracteres |
| Cle de chiffrement | 32 | 128+ caracteres |
| Passphrase | 20 | 4+ mots |

### Entropie et force

| Entropie (bits) | Force | Temps de crack (10B/s) |
|-----------------|-------|------------------------|
| < 40 | Faible | Secondes |
| 40-60 | Moyen | Minutes a heures |
| 60-80 | Fort | Jours a annees |
| 80-100 | Tres fort | Siecles |
| > 100 | Extreme | Milliers d'annees |

!!! tip "Formule entropie"
    `Entropie = log2(nombre_caracteres_possibles) × longueur`

### Caracteres recommandes

```text
Majuscules: ABCDEFGHIJKLMNOPQRSTUVWXYZ (26)
Minuscules: abcdefghijklmnopqrstuvwxyz (26)
Chiffres:   0123456789 (10)
Symboles:   !@#$%^&*()_+-=[]{}|;:,.<>? (30+)

Total avec tout: ~92 caracteres
Entropie par caractere: ~6.5 bits
```

!!! warning "Ne jamais utiliser"
    - Mots du dictionnaire
    - Informations personnelles (dates, noms)
    - Sequences (123456, qwerty)
    - Mots de passe reutilises

<style>
.tool-container {
    background: var(--md-code-bg-color);
    padding: 20px;
    border-radius: 8px;
    margin: 20px 0;
}
.input-row {
    display: flex;
    gap: 20px;
    flex-wrap: wrap;
    align-items: center;
}
.input-group {
    margin: 10px 0;
}
.input-group label {
    display: block;
    margin-bottom: 5px;
    font-weight: bold;
}
#pwd-length {
    width: 200px;
    vertical-align: middle;
}
#length-display {
    font-family: monospace;
    font-size: 18px;
    font-weight: bold;
    margin-left: 10px;
}
.options-grid {
    display: flex;
    gap: 40px;
    flex-wrap: wrap;
    margin: 20px 0;
}
.option-group {
    background: var(--md-default-bg-color);
    padding: 15px;
    border-radius: 4px;
}
.option-group h4 {
    margin: 0 0 10px 0;
    color: var(--md-primary-fg-color);
}
.option-group label {
    display: block;
    margin: 8px 0;
    cursor: pointer;
}
.password-output {
    display: flex;
    gap: 10px;
    margin: 20px 0;
}
.password-output input {
    flex: 1;
    padding: 15px;
    font-family: monospace;
    font-size: 18px;
    border: 2px solid var(--md-primary-fg-color);
    border-radius: 4px;
    background: var(--md-default-bg-color);
    color: var(--md-default-fg-color);
}
.copy-btn, .refresh-btn {
    padding: 15px 20px;
    font-size: 20px;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    background: var(--md-primary-fg-color);
    color: white;
}
.copy-btn:hover, .refresh-btn:hover {
    opacity: 0.9;
}
.strength-meter {
    height: 8px;
    background: var(--md-default-fg-color--lightest);
    border-radius: 4px;
    overflow: hidden;
}
#strength-bar {
    height: 100%;
    width: 0%;
    transition: width 0.3s, background 0.3s;
}
#strength-text {
    margin-top: 5px;
    font-weight: bold;
}
.batch-section {
    margin-top: 30px;
    padding-top: 20px;
    border-top: 1px solid var(--md-default-fg-color--lighter);
}
.batch-section h4 {
    margin: 0 0 15px 0;
}
.calc-btn {
    background: var(--md-primary-fg-color);
    color: white;
    border: none;
    padding: 10px 20px;
    font-size: 14px;
    border-radius: 4px;
    cursor: pointer;
}
#batch-output {
    width: 100%;
    height: 150px;
    margin-top: 10px;
    padding: 10px;
    font-family: monospace;
    font-size: 14px;
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    background: var(--md-default-bg-color);
    color: var(--md-default-fg-color);
    resize: vertical;
}
.info-box {
    background: var(--md-primary-fg-color--light);
    color: var(--md-primary-bg-color);
    padding: 12px 15px;
    border-radius: 4px;
    margin: 10px 0;
    font-size: 0.9em;
    border-left: 4px solid var(--md-primary-fg-color);
}
.info-box code {
    background: rgba(255,255,255,0.2);
    padding: 2px 6px;
    border-radius: 3px;
}
.option-group strong {
    color: var(--md-primary-fg-color);
}
</style>

<script>
const charSets = {
    upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    lower: 'abcdefghijklmnopqrstuvwxyz',
    numbers: '0123456789',
    symbols: '!@#$%^&*_+-=|;:,.<>?',
    brackets: '()[]{}',
    extended: '~`\'"\\/',
    ambiguous: '0O1lI',
    // CVC mode character sets
    consonants_upper: 'BCDFGHJKLNPRSTVXY',
    consonants_lower: 'bcdfghjklnprstvxy',
    vowels_upper: 'AEIOU',
    vowels_lower: 'aeiou',
    // Layout Safe: caracteres identiques AZERTY/QWERTY (meme position physique)
    // Exclus: Q, W, Z, A, M (positions differentes entre layouts)
    layout_safe_upper: 'BCDEFGHIJKLNOPRSTUVXY',
    layout_safe_lower: 'bcdefghijklnoprstuvxy',
    layout_safe_numbers: '0123456789',  // attention: sur AZERTY necessite Shift
    layout_safe_symbols: '.-_',  // symboles surs sur les deux layouts
    // CVC Layout Safe (sans Q, W, Z, A, M)
    cvc_consonants_safe_upper: 'BCDFGHJKLNPRSTVXY',
    cvc_consonants_safe_lower: 'bcdfghjklnprstvxy',
    cvc_vowels_safe_upper: 'EIOU',  // A exclu pour layout safe
    cvc_vowels_safe_lower: 'eiou'
};

function getCharacterSet() {
    const isLayoutSafe = document.getElementById('opt-layout-safe').checked;
    const isCVC = document.getElementById('opt-cvc').checked;

    let chars = '';

    if (isCVC) {
        // En mode CVC, on n'utilise pas ce charset standard
        return chars;
    }

    if (isLayoutSafe) {
        if (document.getElementById('opt-upper').checked) chars += charSets.layout_safe_upper;
        if (document.getElementById('opt-lower').checked) chars += charSets.layout_safe_lower;
        if (document.getElementById('opt-numbers').checked) chars += charSets.layout_safe_numbers;
        if (document.getElementById('opt-symbols').checked) chars += charSets.layout_safe_symbols;
    } else {
        if (document.getElementById('opt-upper').checked) chars += charSets.upper;
        if (document.getElementById('opt-lower').checked) chars += charSets.lower;
        if (document.getElementById('opt-numbers').checked) chars += charSets.numbers;
        if (document.getElementById('opt-symbols').checked) chars += charSets.symbols;
        if (document.getElementById('opt-brackets').checked) chars += charSets.brackets;
        if (document.getElementById('opt-extended').checked) chars += charSets.extended;
    }

    if (document.getElementById('opt-ambiguous').checked) {
        for (const c of charSets.ambiguous) {
            chars = chars.replace(new RegExp(c, 'g'), '');
        }
    }

    return chars;
}

function generateCVCPassword(length, isLayoutSafe) {
    const consonantsUpper = isLayoutSafe ? charSets.cvc_consonants_safe_upper : charSets.consonants_upper;
    const consonantsLower = isLayoutSafe ? charSets.cvc_consonants_safe_lower : charSets.consonants_lower;
    const vowelsUpper = isLayoutSafe ? charSets.cvc_vowels_safe_upper : charSets.vowels_upper;
    const vowelsLower = isLayoutSafe ? charSets.cvc_vowels_safe_lower : charSets.vowels_lower;

    const useUpper = document.getElementById('opt-upper').checked;
    const useLower = document.getElementById('opt-lower').checked;
    const useNumbers = document.getElementById('opt-numbers').checked;
    const useSymbols = document.getElementById('opt-symbols').checked;

    let consonants = '';
    let vowels = '';

    if (useUpper) {
        consonants += consonantsUpper;
        vowels += vowelsUpper;
    }
    if (useLower) {
        consonants += consonantsLower;
        vowels += vowelsLower;
    }

    if (consonants.length === 0 || vowels.length === 0) {
        return { password: 'Activez majuscules et/ou minuscules pour le mode CVC', charsetSize: 0 };
    }

    // Chiffres compatibles layout safe (evite 0/O et 1/l ambigus)
    const numbers = '23456789';
    // Symboles compatibles layout safe
    const symbols = isLayoutSafe ? '.-_' : '.-_!@#';

    const array = new Uint32Array(length * 3);
    crypto.getRandomValues(array);

    let password = '';
    let arrayIdx = 0;
    let isConsonant = true;
    let charCount = 0;

    while (password.length < length) {
        // Insere un chiffre tous les 3-4 caracteres si option activee
        if (useNumbers && charCount > 0 && charCount % 3 === 0 && password.length < length - 1) {
            password += numbers[array[arrayIdx++] % numbers.length];
        }
        // Insere un symbole tous les 5-6 caracteres si option activee
        else if (useSymbols && charCount > 0 && charCount % 5 === 0 && password.length < length - 1) {
            password += symbols[array[arrayIdx++] % symbols.length];
        }
        else {
            if (isConsonant) {
                password += consonants[array[arrayIdx++] % consonants.length];
            } else {
                password += vowels[array[arrayIdx++] % vowels.length];
            }
            isConsonant = !isConsonant;
            charCount++;
        }
    }

    // Calcul du charset effectif pour l'entropie
    let effectiveCharset = consonants.length + vowels.length;
    if (useNumbers) effectiveCharset += numbers.length;
    if (useSymbols) effectiveCharset += symbols.length;

    return { password: password.substring(0, length), charsetSize: effectiveCharset };
}

function generatePassword() {
    const length = parseInt(document.getElementById('pwd-length').value);
    const isCVC = document.getElementById('opt-cvc').checked;
    const isLayoutSafe = document.getElementById('opt-layout-safe').checked;

    // Mode CVC
    if (isCVC) {
        const result = generateCVCPassword(length, isLayoutSafe);
        document.getElementById('password-result').value = result.password;
        if (result.charsetSize > 0) {
            updateStrength(result.password, result.charsetSize);
        }
        return;
    }

    // Mode standard
    const chars = getCharacterSet();

    if (chars.length === 0) {
        document.getElementById('password-result').value = 'Selectionnez au moins un type de caractere';
        return;
    }

    // Use crypto API for secure random
    const array = new Uint32Array(length);
    crypto.getRandomValues(array);

    let password = '';
    for (let i = 0; i < length; i++) {
        password += chars[array[i] % chars.length];
    }

    document.getElementById('password-result').value = password;
    updateStrength(password, chars.length);
}

function updateStrength(password, charsetSize) {
    const length = password.length;
    const entropy = Math.log2(charsetSize) * length;

    const bar = document.getElementById('strength-bar');
    const text = document.getElementById('strength-text');

    let strength, color, width;

    if (entropy < 40) {
        strength = 'Faible';
        color = '#dc3545';
        width = 20;
    } else if (entropy < 60) {
        strength = 'Moyen';
        color = '#ffc107';
        width = 40;
    } else if (entropy < 80) {
        strength = 'Fort';
        color = '#28a745';
        width = 60;
    } else if (entropy < 100) {
        strength = 'Tres fort';
        color = '#20c997';
        width = 80;
    } else {
        strength = 'Extreme';
        color = '#6f42c1';
        width = 100;
    }

    bar.style.width = width + '%';
    bar.style.background = color;
    text.textContent = `${strength} - Entropie: ${entropy.toFixed(1)} bits (${charsetSize} caracteres possibles)`;
    text.style.color = color;
}

function copyPassword() {
    const password = document.getElementById('password-result');
    password.select();
    document.execCommand('copy');

    // Visual feedback
    const btn = document.querySelector('.copy-btn');
    btn.textContent = '\u2713';
    setTimeout(() => { btn.innerHTML = '&#128203;'; }, 1000);
}

function generateBatch() {
    const count = parseInt(document.getElementById('batch-count').value);
    const length = parseInt(document.getElementById('pwd-length').value);
    const isCVC = document.getElementById('opt-cvc').checked;
    const isLayoutSafe = document.getElementById('opt-layout-safe').checked;

    let passwords = [];

    // Mode CVC
    if (isCVC) {
        for (let i = 0; i < count; i++) {
            const result = generateCVCPassword(length, isLayoutSafe);
            if (result.charsetSize === 0) {
                document.getElementById('batch-output').value = result.password;
                return;
            }
            passwords.push(result.password);
        }
        document.getElementById('batch-output').value = passwords.join('\n');
        return;
    }

    // Mode standard
    const chars = getCharacterSet();

    if (chars.length === 0) {
        document.getElementById('batch-output').value = 'Selectionnez au moins un type de caractere';
        return;
    }

    for (let i = 0; i < count; i++) {
        const array = new Uint32Array(length);
        crypto.getRandomValues(array);
        let password = '';
        for (let j = 0; j < length; j++) {
            password += chars[array[j] % chars.length];
        }
        passwords.push(password);
    }

    document.getElementById('batch-output').value = passwords.join('\n');
}

// Event listeners
document.getElementById('pwd-length').addEventListener('input', function() {
    document.getElementById('length-display').textContent = this.value;
    generatePassword();
});

document.querySelectorAll('.option-group input').forEach(el => {
    el.addEventListener('change', generatePassword);
});

// Toggle info boxes for special modes
document.getElementById('opt-cvc').addEventListener('change', function() {
    document.getElementById('cvc-info').style.display = this.checked ? 'block' : 'none';
});

document.getElementById('opt-layout-safe').addEventListener('change', function() {
    document.getElementById('layout-info').style.display = this.checked ? 'block' : 'none';
    // Disable incompatible options in layout safe mode
    if (this.checked) {
        document.getElementById('opt-brackets').checked = false;
        document.getElementById('opt-extended').checked = false;
    }
});

// Initial generation
generatePassword();
</script>
