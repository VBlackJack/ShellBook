---
tags:
  - tools
  - security
  - aes
  - crypto
---

# AES Encrypt/Decrypt

Outil de chiffrement/dechiffrement AES utilisant Web Crypto API (100% client-side).

<div id="aes-app">
  <div class="aes-container">
    <div class="aes-section">
      <h3>Configuration</h3>

      <div class="form-group">
        <label>Mode</label>
        <div class="mode-toggle">
          <button class="mode-btn active" onclick="setMode('encrypt')">🔒 Chiffrer</button>
          <button class="mode-btn" onclick="setMode('decrypt')">🔓 Dechiffrer</button>
        </div>
      </div>

      <div class="form-group">
        <label>Algorithme</label>
        <select id="algorithm" onchange="updateKeySize()">
          <option value="AES-GCM" selected>AES-GCM (recommande)</option>
          <option value="AES-CBC">AES-CBC</option>
          <option value="AES-CTR">AES-CTR</option>
        </select>
        <span class="hint">GCM fournit l'authentification integree</span>
      </div>

      <div class="form-group">
        <label>Taille de cle</label>
        <select id="keySize">
          <option value="128">128 bits</option>
          <option value="256" selected>256 bits</option>
        </select>
      </div>

      <div class="form-group">
        <label>Cle (hex ou passphrase)</label>
        <div class="key-input">
          <input type="text" id="key" placeholder="Entrez une cle ou passphrase">
          <button onclick="generateKey()">🎲 Generer</button>
        </div>
        <div class="radio-group">
          <label><input type="radio" name="keyType" value="passphrase" checked> Passphrase (PBKDF2)</label>
          <label><input type="radio" name="keyType" value="hex"> Cle Hex brute</label>
        </div>
      </div>

      <div class="form-group" id="ivGroup">
        <label>IV/Nonce (hex)</label>
        <div class="key-input">
          <input type="text" id="iv" placeholder="Sera genere automatiquement">
          <button onclick="generateIV()">🎲</button>
        </div>
        <span class="hint" id="ivHint">12 bytes pour GCM, 16 bytes pour CBC</span>
      </div>
    </div>

    <div class="aes-section">
      <h3 id="inputLabel">Texte a chiffrer</h3>
      <textarea id="inputText" placeholder="Entrez le texte..." oninput="clearOutput()"></textarea>

      <div class="input-format">
        <label><input type="radio" name="inputFormat" value="text" checked> Texte UTF-8</label>
        <label><input type="radio" name="inputFormat" value="hex"> Hex</label>
        <label><input type="radio" name="inputFormat" value="base64"> Base64</label>
      </div>

      <button onclick="process()" class="btn-process" id="processBtn">🔒 Chiffrer</button>
    </div>
  </div>

  <div class="result-section">
    <h3>Resultat</h3>

    <div class="result-tabs">
      <button class="tab active" onclick="showResultTab('hex')">Hex</button>
      <button class="tab" onclick="showResultTab('base64')">Base64</button>
      <button class="tab" onclick="showResultTab('combined')">Combined (IV+Data)</button>
    </div>

    <div class="result-output">
      <div id="resultHex" class="result-content active">
        <textarea id="outputHex" readonly placeholder="Le resultat apparaitra ici..."></textarea>
        <button onclick="copyOutput('outputHex')">📋 Copier</button>
      </div>
      <div id="resultBase64" class="result-content">
        <textarea id="outputBase64" readonly></textarea>
        <button onclick="copyOutput('outputBase64')">📋 Copier</button>
      </div>
      <div id="resultCombined" class="result-content">
        <textarea id="outputCombined" readonly placeholder="IV concatene avec les donnees chiffrees"></textarea>
        <button onclick="copyOutput('outputCombined')">📋 Copier</button>
      </div>
    </div>

    <div id="usedParams" class="used-params"></div>
  </div>

  <div class="info-section">
    <h3>A propos d'AES</h3>

    <div class="info-grid">
      <div class="info-card">
        <h4>AES-GCM</h4>
        <ul>
          <li>Mode authentifie (AEAD)</li>
          <li>Detecte les modifications</li>
          <li>IV unique obligatoire</li>
          <li>Recommande pour la plupart des cas</li>
        </ul>
      </div>
      <div class="info-card">
        <h4>AES-CBC</h4>
        <ul>
          <li>Mode classique avec padding</li>
          <li>IV aleatoire obligatoire</li>
          <li>Necessite HMAC separe</li>
          <li>Compatible legacy</li>
        </ul>
      </div>
      <div class="info-card">
        <h4>AES-CTR</h4>
        <ul>
          <li>Mode compteur (stream)</li>
          <li>Pas de padding</li>
          <li>Parallelisable</li>
          <li>Counter unique obligatoire</li>
        </ul>
      </div>
    </div>
  </div>

  <div class="warning-section">
    <h3>⚠️ Avertissements securite</h3>
    <ul>
      <li><strong>Ne reutilisez JAMAIS un IV</strong> avec la meme cle (surtout en GCM/CTR)</li>
      <li>Utilisez des cles generees aleatoirement, pas des mots de passe simples</li>
      <li>Pour des mots de passe, utilisez PBKDF2/Argon2 pour deriver la cle</li>
      <li>Stockez les IVs avec les donnees chiffrees (ils ne sont pas secrets)</li>
      <li>En production, utilisez des bibliotheques cryptographiques eprouvees</li>
    </ul>
  </div>
</div>

<style>
.aes-container {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 20px;
}

@media (max-width: 800px) {
  .aes-container {
    grid-template-columns: 1fr;
  }
}

.aes-section, .result-section, .info-section, .warning-section {
  background: var(--md-code-bg-color);
  padding: 20px;
  border-radius: 8px;
  margin-bottom: 20px;
}

.form-group {
  margin-bottom: 15px;
}

.form-group label {
  display: block;
  font-size: 0.85em;
  margin-bottom: 5px;
  color: var(--md-default-fg-color--light);
}

.form-group select,
.form-group input[type="text"] {
  width: 100%;
  padding: 10px;
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  background: var(--md-default-bg-color);
  color: var(--md-default-fg-color);
  font-family: monospace;
}

.hint {
  font-size: 0.8em;
  color: var(--md-default-fg-color--light);
  margin-top: 4px;
  display: block;
}

.mode-toggle {
  display: flex;
  gap: 10px;
}

.mode-btn {
  flex: 1;
  padding: 12px;
  border: 2px solid var(--md-default-fg-color--lightest);
  border-radius: 6px;
  background: var(--md-default-bg-color);
  cursor: pointer;
  font-weight: 500;
  transition: all 0.2s;
}

.mode-btn.active {
  border-color: var(--md-primary-fg-color);
  background: var(--md-primary-fg-color);
  color: white;
}

.key-input {
  display: flex;
  gap: 8px;
}

.key-input input {
  flex: 1;
}

.key-input button {
  padding: 10px 15px;
  background: var(--md-default-bg-color);
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  cursor: pointer;
}

.radio-group {
  display: flex;
  gap: 15px;
  margin-top: 8px;
}

.radio-group label {
  display: flex;
  align-items: center;
  gap: 5px;
  cursor: pointer;
  font-size: 0.85em;
  color: var(--md-default-fg-color);
}

textarea {
  width: 100%;
  min-height: 120px;
  padding: 12px;
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  background: var(--md-default-bg-color);
  color: var(--md-default-fg-color);
  font-family: monospace;
  font-size: 0.9em;
  resize: vertical;
}

.input-format {
  display: flex;
  gap: 15px;
  margin: 10px 0;
}

.input-format label {
  display: flex;
  align-items: center;
  gap: 5px;
  cursor: pointer;
  font-size: 0.85em;
}

.btn-process {
  width: 100%;
  padding: 15px;
  background: var(--md-primary-fg-color);
  color: white;
  border: none;
  border-radius: 6px;
  cursor: pointer;
  font-size: 1em;
  font-weight: 500;
  margin-top: 10px;
}

.result-tabs {
  display: flex;
  gap: 5px;
  margin-bottom: 15px;
}

.result-tabs .tab {
  padding: 8px 15px;
  background: var(--md-default-bg-color);
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  cursor: pointer;
}

.result-tabs .tab.active {
  background: var(--md-primary-fg-color);
  color: white;
  border-color: var(--md-primary-fg-color);
}

.result-content {
  display: none;
}

.result-content.active {
  display: block;
}

.result-content textarea {
  min-height: 100px;
  margin-bottom: 10px;
}

.result-content button {
  padding: 8px 15px;
  background: var(--md-default-bg-color);
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  cursor: pointer;
}

.used-params {
  margin-top: 15px;
  padding: 15px;
  background: var(--md-default-bg-color);
  border-radius: 6px;
  font-size: 0.85em;
  font-family: monospace;
}

.info-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 15px;
}

.info-card {
  background: var(--md-default-bg-color);
  padding: 15px;
  border-radius: 6px;
}

.info-card h4 {
  margin: 0 0 10px 0;
}

.info-card ul {
  margin: 0;
  padding-left: 20px;
  font-size: 0.85em;
}

.info-card li {
  margin-bottom: 5px;
}

.warning-section {
  background: rgba(243, 156, 18, 0.1);
  border-left: 4px solid #f39c12;
}

.warning-section ul {
  margin: 0;
  padding-left: 20px;
}

.warning-section li {
  margin-bottom: 8px;
  font-size: 0.9em;
}
</style>

<script>
let currentMode = 'encrypt';
let lastIV = null;

function setMode(mode) {
  currentMode = mode;
  document.querySelectorAll('.mode-btn').forEach(btn => btn.classList.remove('active'));
  event.target.classList.add('active');

  if (mode === 'encrypt') {
    document.getElementById('inputLabel').textContent = 'Texte a chiffrer';
    document.getElementById('processBtn').textContent = '🔒 Chiffrer';
  } else {
    document.getElementById('inputLabel').textContent = 'Donnees a dechiffrer';
    document.getElementById('processBtn').textContent = '🔓 Dechiffrer';
  }
}

function updateKeySize() {
  const algo = document.getElementById('algorithm').value;
  const ivHint = document.getElementById('ivHint');

  if (algo === 'AES-GCM') {
    ivHint.textContent = '12 bytes (96 bits) pour GCM';
  } else if (algo === 'AES-CBC') {
    ivHint.textContent = '16 bytes (128 bits) pour CBC';
  } else {
    ivHint.textContent = '16 bytes pour CTR counter';
  }
}

function generateKey() {
  const keySize = parseInt(document.getElementById('keySize').value);
  const bytes = new Uint8Array(keySize / 8);
  crypto.getRandomValues(bytes);
  document.getElementById('key').value = arrayToHex(bytes);
  document.querySelector('input[name="keyType"][value="hex"]').checked = true;
}

function generateIV() {
  const algo = document.getElementById('algorithm').value;
  const ivSize = algo === 'AES-GCM' ? 12 : 16;
  const bytes = new Uint8Array(ivSize);
  crypto.getRandomValues(bytes);
  document.getElementById('iv').value = arrayToHex(bytes);
}

function arrayToHex(arr) {
  return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
}

function hexToArray(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

async function deriveKey(passphrase, salt, keySize) {
  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(passphrase),
    'PBKDF2',
    false,
    ['deriveBits', 'deriveKey']
  );

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: 100000,
      hash: 'SHA-256'
    },
    keyMaterial,
    { name: document.getElementById('algorithm').value, length: keySize },
    true,
    ['encrypt', 'decrypt']
  );
}

async function process() {
  try {
    const algo = document.getElementById('algorithm').value;
    const keySize = parseInt(document.getElementById('keySize').value);
    const keyInput = document.getElementById('key').value;
    const keyType = document.querySelector('input[name="keyType"]:checked').value;
    const inputFormat = document.querySelector('input[name="inputFormat"]:checked').value;
    let ivInput = document.getElementById('iv').value;

    if (!keyInput) {
      alert('Veuillez entrer une cle');
      return;
    }

    // Get or generate IV
    const ivSize = algo === 'AES-GCM' ? 12 : 16;
    let iv;

    if (currentMode === 'encrypt') {
      if (!ivInput) {
        generateIV();
        ivInput = document.getElementById('iv').value;
      }
      iv = hexToArray(ivInput);
    } else {
      // For decryption, IV might be prepended to data
      if (!ivInput) {
        alert('IV requis pour le dechiffrement');
        return;
      }
      iv = hexToArray(ivInput);
    }

    // Import or derive key
    let cryptoKey;
    if (keyType === 'hex') {
      const keyBytes = hexToArray(keyInput);
      cryptoKey = await crypto.subtle.importKey(
        'raw',
        keyBytes,
        { name: algo },
        true,
        ['encrypt', 'decrypt']
      );
    } else {
      // Derive from passphrase
      const salt = new TextEncoder().encode('aes-tool-salt-v1');
      cryptoKey = await deriveKey(keyInput, salt, keySize);
    }

    // Get input data
    const inputText = document.getElementById('inputText').value;
    let inputData;

    if (currentMode === 'encrypt') {
      if (inputFormat === 'hex') {
        inputData = hexToArray(inputText);
      } else if (inputFormat === 'base64') {
        inputData = Uint8Array.from(atob(inputText), c => c.charCodeAt(0));
      } else {
        inputData = new TextEncoder().encode(inputText);
      }
    } else {
      // Decryption input is always hex or base64
      if (inputFormat === 'base64') {
        inputData = Uint8Array.from(atob(inputText), c => c.charCodeAt(0));
      } else {
        inputData = hexToArray(inputText.replace(/\s/g, ''));
      }
    }

    // Build algorithm params
    let algoParams;
    if (algo === 'AES-GCM') {
      algoParams = { name: algo, iv: iv };
    } else if (algo === 'AES-CBC') {
      algoParams = { name: algo, iv: iv };
    } else {
      algoParams = { name: algo, counter: iv, length: 64 };
    }

    // Process
    let result;
    if (currentMode === 'encrypt') {
      result = await crypto.subtle.encrypt(algoParams, cryptoKey, inputData);
    } else {
      result = await crypto.subtle.decrypt(algoParams, cryptoKey, inputData);
    }

    const resultArray = new Uint8Array(result);
    lastIV = iv;

    // Output
    const hexResult = arrayToHex(resultArray);
    const base64Result = btoa(String.fromCharCode(...resultArray));

    // Combined = IV + encrypted data
    const combined = new Uint8Array(iv.length + resultArray.length);
    combined.set(iv);
    combined.set(resultArray, iv.length);
    const combinedHex = arrayToHex(combined);

    document.getElementById('outputHex').value = hexResult;
    document.getElementById('outputBase64').value = base64Result;
    document.getElementById('outputCombined').value = combinedHex;

    // Show used params
    document.getElementById('usedParams').innerHTML = `
      <strong>Parametres utilises:</strong><br>
      Algorithme: ${algo}<br>
      Taille cle: ${keySize} bits<br>
      IV: ${arrayToHex(iv)}
    `;

  } catch (e) {
    console.error('Crypto error:', e);
    alert('Erreur: ' + e.message);
  }
}

function showResultTab(tab) {
  document.querySelectorAll('.result-tabs .tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.result-content').forEach(c => c.classList.remove('active'));

  event.target.classList.add('active');
  document.getElementById(`result${tab.charAt(0).toUpperCase() + tab.slice(1)}`).classList.add('active');
}

function copyOutput(id) {
  const text = document.getElementById(id).value;
  navigator.clipboard.writeText(text).then(() => {
    const btn = event.target;
    const orig = btn.textContent;
    btn.textContent = '✓ Copie!';
    setTimeout(() => btn.textContent = orig, 1500);
  });
}

function clearOutput() {
  document.getElementById('outputHex').value = '';
  document.getElementById('outputBase64').value = '';
  document.getElementById('outputCombined').value = '';
}

// Initialize
updateKeySize();
</script>

---

## Commandes OpenSSL equivalentes

```bash
# Chiffrer avec AES-256-GCM
openssl enc -aes-256-gcm -in file.txt -out file.enc -K <key_hex> -iv <iv_hex>

# Chiffrer avec mot de passe (PBKDF2)
openssl enc -aes-256-cbc -salt -pbkdf2 -in file.txt -out file.enc

# Dechiffrer
openssl enc -d -aes-256-cbc -pbkdf2 -in file.enc -out file.txt
```
