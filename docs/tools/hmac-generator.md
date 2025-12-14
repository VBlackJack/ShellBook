---
tags:
  - tools
  - security
  - hmac
  - crypto
---

# HMAC Generator

Generateur de codes d'authentification HMAC (Hash-based Message Authentication Code).

<div id="hmac-app">
  <div class="hmac-container">
    <div class="hmac-section">
      <h3>Configuration</h3>

      <div class="form-group">
        <label>Message</label>
        <textarea id="message" placeholder="Entrez le message a signer..." oninput="generateHMAC()">Hello, World!</textarea>
      </div>

      <div class="form-group">
        <label>Cle secrete</label>
        <div class="key-input">
          <input type="text" id="secretKey" placeholder="Votre cle secrete" value="my-secret-key" oninput="generateHMAC()">
          <button onclick="generateRandomKey()">🎲</button>
        </div>
      </div>

      <div class="form-group">
        <label>Format de la cle</label>
        <div class="radio-group">
          <label><input type="radio" name="keyFormat" value="utf8" checked onchange="generateHMAC()"> UTF-8</label>
          <label><input type="radio" name="keyFormat" value="hex" onchange="generateHMAC()"> Hex</label>
          <label><input type="radio" name="keyFormat" value="base64" onchange="generateHMAC()"> Base64</label>
        </div>
      </div>

      <div class="form-group">
        <label>Algorithme</label>
        <select id="algorithm" onchange="generateHMAC()">
          <option value="SHA-256" selected>HMAC-SHA256</option>
          <option value="SHA-384">HMAC-SHA384</option>
          <option value="SHA-512">HMAC-SHA512</option>
          <option value="SHA-1">HMAC-SHA1 (deprecie)</option>
        </select>
      </div>
    </div>

    <div class="hmac-section">
      <h3>Resultats HMAC</h3>

      <div class="result-group">
        <label>Hex (lowercase)</label>
        <div class="result-row">
          <input type="text" id="resultHex" readonly>
          <button onclick="copyResult('resultHex')">📋</button>
        </div>
      </div>

      <div class="result-group">
        <label>Hex (uppercase)</label>
        <div class="result-row">
          <input type="text" id="resultHexUpper" readonly>
          <button onclick="copyResult('resultHexUpper')">📋</button>
        </div>
      </div>

      <div class="result-group">
        <label>Base64</label>
        <div class="result-row">
          <input type="text" id="resultBase64" readonly>
          <button onclick="copyResult('resultBase64')">📋</button>
        </div>
      </div>

      <div class="result-group">
        <label>Base64 URL-safe</label>
        <div class="result-row">
          <input type="text" id="resultBase64Url" readonly>
          <button onclick="copyResult('resultBase64Url')">📋</button>
        </div>
      </div>
    </div>
  </div>

  <div class="verify-section">
    <h3>Verification</h3>

    <div class="verify-form">
      <div class="form-group">
        <label>HMAC a verifier</label>
        <input type="text" id="verifyHmac" placeholder="Collez le HMAC a verifier" oninput="verifyHMAC()">
      </div>

      <div id="verifyResult" class="verify-result"></div>
    </div>
  </div>

  <div class="examples-section">
    <h3>Exemples de code</h3>

    <div class="code-tabs">
      <button class="tab active" onclick="showCode('js')">JavaScript</button>
      <button class="tab" onclick="showCode('python')">Python</button>
      <button class="tab" onclick="showCode('php')">PHP</button>
      <button class="tab" onclick="showCode('bash')">Bash</button>
      <button class="tab" onclick="showCode('go')">Go</button>
    </div>

    <pre id="codeExample" class="code-block"></pre>
  </div>

  <div class="usecases-section">
    <h3>Cas d'usage</h3>

    <div class="usecase-grid">
      <div class="usecase-card">
        <h4>🔐 Webhooks</h4>
        <p>Verification d'integrite des payloads (GitHub, Stripe, Slack)</p>
        <code>X-Hub-Signature-256: sha256=...</code>
      </div>

      <div class="usecase-card">
        <h4>🎫 JWT</h4>
        <p>Signature des JSON Web Tokens avec HS256/HS384/HS512</p>
        <code>header.payload.signature</code>
      </div>

      <div class="usecase-card">
        <h4>☁️ AWS Signature</h4>
        <p>Authentification des requetes AWS (Signature Version 4)</p>
        <code>AWS4-HMAC-SHA256</code>
      </div>

      <div class="usecase-card">
        <h4>🔗 API Authentication</h4>
        <p>Signature des requetes API avec timestamp</p>
        <code>HMAC(timestamp + method + path + body)</code>
      </div>
    </div>
  </div>
</div>

<style>
.hmac-container {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 20px;
}

@media (max-width: 800px) {
  .hmac-container {
    grid-template-columns: 1fr;
  }
}

.hmac-section, .verify-section, .examples-section, .usecases-section {
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

.form-group textarea,
.form-group input[type="text"],
.form-group select {
  width: 100%;
  padding: 10px;
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  background: var(--md-default-bg-color);
  color: var(--md-default-fg-color);
  font-family: monospace;
}

.form-group textarea {
  min-height: 80px;
  resize: vertical;
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
  background: var(--md-primary-fg-color);
  color: white;
  border: none;
  border-radius: 4px;
  cursor: pointer;
}

.radio-group {
  display: flex;
  gap: 20px;
}

.radio-group label {
  display: flex;
  align-items: center;
  gap: 5px;
  cursor: pointer;
  font-size: 0.9em;
  color: var(--md-default-fg-color);
}

.result-group {
  margin-bottom: 15px;
}

.result-group label {
  display: block;
  font-size: 0.8em;
  margin-bottom: 5px;
  color: var(--md-default-fg-color--light);
}

.result-row {
  display: flex;
  gap: 8px;
}

.result-row input {
  flex: 1;
  padding: 10px;
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  background: var(--md-default-bg-color);
  color: var(--md-default-fg-color);
  font-family: monospace;
  font-size: 0.85em;
}

.result-row button {
  padding: 10px;
  background: var(--md-default-bg-color);
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  cursor: pointer;
}

.verify-form {
  background: var(--md-default-bg-color);
  padding: 15px;
  border-radius: 6px;
}

.verify-result {
  margin-top: 15px;
  padding: 12px;
  border-radius: 4px;
  text-align: center;
  font-weight: 500;
}

.verify-result.valid {
  background: rgba(39, 174, 96, 0.1);
  color: #27ae60;
}

.verify-result.invalid {
  background: rgba(231, 76, 60, 0.1);
  color: #e74c3c;
}

.code-tabs {
  display: flex;
  gap: 5px;
  margin-bottom: 10px;
}

.code-tabs .tab {
  padding: 6px 12px;
  background: var(--md-default-bg-color);
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  cursor: pointer;
  font-size: 0.85em;
}

.code-tabs .tab.active {
  background: var(--md-primary-fg-color);
  color: white;
  border-color: var(--md-primary-fg-color);
}

.code-block {
  background: #1e1e1e;
  color: #d4d4d4;
  padding: 15px;
  border-radius: 6px;
  font-size: 0.85em;
  overflow-x: auto;
  margin: 0;
}

.usecase-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: 15px;
}

.usecase-card {
  background: var(--md-default-bg-color);
  padding: 15px;
  border-radius: 6px;
}

.usecase-card h4 {
  margin: 0 0 8px 0;
}

.usecase-card p {
  font-size: 0.85em;
  color: var(--md-default-fg-color--light);
  margin: 0 0 10px 0;
}

.usecase-card code {
  display: block;
  font-size: 0.8em;
  padding: 8px;
  background: var(--md-code-bg-color);
  border-radius: 4px;
}
</style>

<script>
let currentCode = 'js';

async function generateHMAC() {
  const message = document.getElementById('message').value;
  const secretKey = document.getElementById('secretKey').value;
  const keyFormat = document.querySelector('input[name="keyFormat"]:checked').value;
  const algorithm = document.getElementById('algorithm').value;

  if (!message || !secretKey) {
    document.getElementById('resultHex').value = '';
    document.getElementById('resultHexUpper').value = '';
    document.getElementById('resultBase64').value = '';
    document.getElementById('resultBase64Url').value = '';
    return;
  }

  try {
    // Convert key based on format
    let keyData;
    if (keyFormat === 'hex') {
      keyData = hexToBytes(secretKey);
    } else if (keyFormat === 'base64') {
      keyData = Uint8Array.from(atob(secretKey), c => c.charCodeAt(0));
    } else {
      keyData = new TextEncoder().encode(secretKey);
    }

    const key = await crypto.subtle.importKey(
      'raw',
      keyData,
      { name: 'HMAC', hash: algorithm },
      false,
      ['sign']
    );

    const messageData = new TextEncoder().encode(message);
    const signature = await crypto.subtle.sign('HMAC', key, messageData);

    const hashArray = Array.from(new Uint8Array(signature));
    const hexLower = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    const base64 = btoa(String.fromCharCode(...hashArray));
    const base64Url = base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

    document.getElementById('resultHex').value = hexLower;
    document.getElementById('resultHexUpper').value = hexLower.toUpperCase();
    document.getElementById('resultBase64').value = base64;
    document.getElementById('resultBase64Url').value = base64Url;

    updateCodeExample();

  } catch (e) {
    console.error('HMAC error:', e);
    document.getElementById('resultHex').value = 'Erreur: ' + e.message;
  }
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

function generateRandomKey() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  const hex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  document.getElementById('secretKey').value = hex;
  document.querySelector('input[name="keyFormat"][value="hex"]').checked = true;
  generateHMAC();
}

function copyResult(id) {
  const input = document.getElementById(id);
  navigator.clipboard.writeText(input.value).then(() => {
    const btn = event.target;
    const orig = btn.textContent;
    btn.textContent = '✓';
    setTimeout(() => btn.textContent = orig, 1000);
  });
}

function verifyHMAC() {
  const toVerify = document.getElementById('verifyHmac').value.toLowerCase().trim();
  const resultEl = document.getElementById('verifyResult');

  if (!toVerify) {
    resultEl.className = 'verify-result';
    resultEl.textContent = '';
    return;
  }

  const currentHex = document.getElementById('resultHex').value;
  const currentBase64 = document.getElementById('resultBase64').value;
  const currentBase64Url = document.getElementById('resultBase64Url').value;

  const isValid = toVerify === currentHex ||
                  toVerify === currentHex.toUpperCase().toLowerCase() ||
                  toVerify === currentBase64 ||
                  toVerify === currentBase64Url;

  if (isValid) {
    resultEl.className = 'verify-result valid';
    resultEl.textContent = '✅ HMAC valide!';
  } else {
    resultEl.className = 'verify-result invalid';
    resultEl.textContent = '❌ HMAC invalide';
  }
}

function showCode(lang) {
  currentCode = lang;
  document.querySelectorAll('.code-tabs .tab').forEach(t => t.classList.remove('active'));
  event.target.classList.add('active');
  updateCodeExample();
}

function updateCodeExample() {
  const message = document.getElementById('message').value || 'Hello, World!';
  const key = document.getElementById('secretKey').value || 'secret-key';
  const algo = document.getElementById('algorithm').value;
  const algoName = algo.replace('-', '').toLowerCase();

  const examples = {
    js: `// Node.js
const crypto = require('crypto');

const hmac = crypto.createHmac('${algoName}', '${key}');
hmac.update('${message}');
const signature = hmac.digest('hex');
console.log(signature);

// Browser (Web Crypto API)
async function generateHMAC(message, key) {
  const encoder = new TextEncoder();
  const keyData = encoder.encode(key);
  const messageData = encoder.encode(message);

  const cryptoKey = await crypto.subtle.importKey(
    'raw', keyData, { name: 'HMAC', hash: '${algo}' }, false, ['sign']
  );

  const signature = await crypto.subtle.sign('HMAC', cryptoKey, messageData);
  return Array.from(new Uint8Array(signature))
    .map(b => b.toString(16).padStart(2, '0')).join('');
}`,

    python: `import hmac
import hashlib
import base64

message = b'${message}'
key = b'${key}'

# Generate HMAC
signature = hmac.new(key, message, hashlib.${algoName}).hexdigest()
print(f"Hex: {signature}")

# Base64
sig_bytes = hmac.new(key, message, hashlib.${algoName}).digest()
print(f"Base64: {base64.b64encode(sig_bytes).decode()}")

# Verify
def verify_hmac(message, signature, key):
    expected = hmac.new(key, message, hashlib.${algoName}).hexdigest()
    return hmac.compare_digest(expected, signature)`,

    php: `<?php
$message = '${message}';
$key = '${key}';

// Generate HMAC
$signature = hash_hmac('${algoName}', $message, $key);
echo "Hex: " . $signature . "\\n";

// Base64
$sig_binary = hash_hmac('${algoName}', $message, $key, true);
echo "Base64: " . base64_encode($sig_binary) . "\\n";

// Verify
function verify_hmac($message, $signature, $key) {
    $expected = hash_hmac('${algoName}', $message, $key);
    return hash_equals($expected, $signature);
}`,

    bash: `# Using OpenSSL
echo -n "${message}" | openssl dgst -${algoName} -hmac "${key}"

# Hex output only
echo -n "${message}" | openssl dgst -${algoName} -hmac "${key}" -hex | cut -d' ' -f2

# Base64 output
echo -n "${message}" | openssl dgst -${algoName} -hmac "${key}" -binary | base64`,

    go: `package main

import (
    "crypto/hmac"
    "crypto/${algoName.replace('sha', 'sha').replace('256', '256').replace('384', '384').replace('512', '512')}"
    "encoding/base64"
    "encoding/hex"
    "fmt"
)

func main() {
    message := []byte("${message}")
    key := []byte("${key}")

    h := hmac.New(sha256.New, key)
    h.Write(message)
    signature := h.Sum(nil)

    fmt.Printf("Hex: %s\\n", hex.EncodeToString(signature))
    fmt.Printf("Base64: %s\\n", base64.StdEncoding.EncodeToString(signature))
}`
  };

  document.getElementById('codeExample').textContent = examples[currentCode] || '';
}

// Initialize
generateHMAC();
updateCodeExample();
</script>

---

## Algorithmes HMAC

| Algorithme | Taille sortie | Securite | Usage |
|------------|---------------|----------|-------|
| HMAC-SHA256 | 256 bits | ⭐⭐⭐⭐⭐ | Recommande |
| HMAC-SHA384 | 384 bits | ⭐⭐⭐⭐⭐ | Haute securite |
| HMAC-SHA512 | 512 bits | ⭐⭐⭐⭐⭐ | Maximum |
| HMAC-SHA1 | 160 bits | ⭐⭐ | Legacy (deprecie) |

---

!!! warning "Securite"
    - Utilisez toujours une cle d'au moins 256 bits
    - Ne hardcodez jamais les cles dans le code
    - Utilisez `hmac.compare_digest()` pour eviter les timing attacks
