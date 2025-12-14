---
tags:
  - tools
  - devops
  - curl
  - api
---

# cURL Command Builder

Generateur visuel de commandes cURL pour tester des APIs.

<div id="curl-app">
  <div class="curl-container">
    <div class="curl-form">
      <div class="form-section">
        <h3>Requete</h3>

        <div class="form-row method-url">
          <select id="method" onchange="updateCurl()">
            <option value="GET">GET</option>
            <option value="POST">POST</option>
            <option value="PUT">PUT</option>
            <option value="PATCH">PATCH</option>
            <option value="DELETE">DELETE</option>
            <option value="HEAD">HEAD</option>
            <option value="OPTIONS">OPTIONS</option>
          </select>
          <input type="text" id="url" placeholder="https://api.example.com/endpoint" oninput="updateCurl()">
        </div>
      </div>

      <div class="form-section">
        <h3>Headers</h3>
        <div id="headers" class="headers-list">
          <div class="header-row">
            <input type="text" placeholder="Header" value="Content-Type" oninput="updateCurl()">
            <input type="text" placeholder="Value" value="application/json" oninput="updateCurl()">
            <button onclick="removeRow(this)">🗑️</button>
          </div>
        </div>
        <button onclick="addHeader()" class="btn-add-row">➕ Ajouter header</button>
      </div>

      <div class="form-section">
        <h3>Authentification</h3>
        <div class="auth-options">
          <select id="authType" onchange="updateAuthUI(); updateCurl()">
            <option value="none">Aucune</option>
            <option value="bearer">Bearer Token</option>
            <option value="basic">Basic Auth</option>
            <option value="apikey">API Key</option>
          </select>
        </div>
        <div id="authInputs" class="auth-inputs"></div>
      </div>

      <div class="form-section" id="bodySection">
        <h3>Body</h3>
        <div class="body-type">
          <label><input type="radio" name="bodyType" value="json" checked onchange="updateBodyUI(); updateCurl()"> JSON</label>
          <label><input type="radio" name="bodyType" value="form" onchange="updateBodyUI(); updateCurl()"> Form Data</label>
          <label><input type="radio" name="bodyType" value="raw" onchange="updateBodyUI(); updateCurl()"> Raw</label>
        </div>
        <div id="bodyInput">
          <textarea id="jsonBody" placeholder='{"key": "value"}' oninput="updateCurl()">{
  "name": "example",
  "value": 123
}</textarea>
        </div>
      </div>

      <div class="form-section">
        <h3>Options</h3>
        <div class="options-grid">
          <label><input type="checkbox" id="optVerbose" onchange="updateCurl()"> -v (verbose)</label>
          <label><input type="checkbox" id="optSilent" onchange="updateCurl()"> -s (silent)</label>
          <label><input type="checkbox" id="optInsecure" onchange="updateCurl()"> -k (insecure)</label>
          <label><input type="checkbox" id="optFollow" checked onchange="updateCurl()"> -L (follow redirects)</label>
          <label><input type="checkbox" id="optInclude" onchange="updateCurl()"> -i (include headers)</label>
          <label><input type="checkbox" id="optCompressed" onchange="updateCurl()"> --compressed</label>
        </div>
        <div class="timeout-row">
          <label>Timeout (sec):</label>
          <input type="number" id="timeout" placeholder="30" oninput="updateCurl()">
        </div>
      </div>
    </div>

    <div class="curl-output">
      <div class="output-header">
        <h3>Commande cURL</h3>
        <div class="output-actions">
          <button onclick="copyCurl()">📋 Copier</button>
          <button onclick="copyOneLine()">📋 Une ligne</button>
        </div>
      </div>
      <pre id="curlOutput" class="curl-code">curl https://api.example.com</pre>

      <div class="presets">
        <h4>Presets</h4>
        <div class="preset-buttons">
          <button onclick="loadPreset('get-json')">GET JSON</button>
          <button onclick="loadPreset('post-json')">POST JSON</button>
          <button onclick="loadPreset('upload-file')">Upload File</button>
          <button onclick="loadPreset('graphql')">GraphQL</button>
          <button onclick="loadPreset('oauth')">OAuth Token</button>
          <button onclick="loadPreset('webhook')">Webhook</button>
        </div>
      </div>

      <div class="equivalent-section">
        <h4>Equivalents</h4>
        <div class="equiv-tabs">
          <button class="tab active" onclick="showEquiv('fetch')">JavaScript</button>
          <button class="tab" onclick="showEquiv('python')">Python</button>
          <button class="tab" onclick="showEquiv('php')">PHP</button>
        </div>
        <pre id="equivCode" class="equiv-code"></pre>
      </div>
    </div>
  </div>
</div>

<style>
.curl-container {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 20px;
}

@media (max-width: 900px) {
  .curl-container {
    grid-template-columns: 1fr;
  }
}

.curl-form {
  background: var(--md-code-bg-color);
  padding: 20px;
  border-radius: 8px;
}

.form-section {
  margin-bottom: 20px;
  padding-bottom: 15px;
  border-bottom: 1px solid var(--md-default-fg-color--lightest);
}

.form-section:last-child {
  border-bottom: none;
  margin-bottom: 0;
}

.form-section h3 {
  margin-bottom: 12px;
  font-size: 0.95em;
}

.method-url {
  display: flex;
  gap: 10px;
}

.method-url select {
  width: 120px;
  padding: 10px;
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  background: var(--md-default-bg-color);
  color: var(--md-default-fg-color);
  font-weight: 600;
}

.method-url input {
  flex: 1;
  padding: 10px 15px;
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  background: var(--md-default-bg-color);
  color: var(--md-default-fg-color);
  font-family: monospace;
}

.headers-list {
  margin-bottom: 10px;
}

.header-row {
  display: flex;
  gap: 8px;
  margin-bottom: 8px;
}

.header-row input {
  flex: 1;
  padding: 8px 10px;
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  background: var(--md-default-bg-color);
  color: var(--md-default-fg-color);
  font-family: monospace;
  font-size: 0.9em;
}

.header-row button {
  padding: 8px;
  background: transparent;
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  cursor: pointer;
}

.btn-add-row {
  padding: 6px 12px;
  background: var(--md-default-bg-color);
  border: 1px dashed var(--md-default-fg-color--lightest);
  border-radius: 4px;
  cursor: pointer;
  font-size: 0.85em;
}

.auth-options select {
  width: 100%;
  padding: 10px;
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  background: var(--md-default-bg-color);
  color: var(--md-default-fg-color);
  margin-bottom: 10px;
}

.auth-inputs input {
  width: 100%;
  padding: 10px;
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  background: var(--md-default-bg-color);
  color: var(--md-default-fg-color);
  font-family: monospace;
  margin-bottom: 8px;
}

.body-type {
  display: flex;
  gap: 15px;
  margin-bottom: 10px;
}

.body-type label {
  display: flex;
  align-items: center;
  gap: 5px;
  cursor: pointer;
}

#bodyInput textarea {
  width: 100%;
  min-height: 120px;
  padding: 10px;
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  background: var(--md-default-bg-color);
  color: var(--md-default-fg-color);
  font-family: monospace;
  font-size: 0.9em;
  resize: vertical;
}

.options-grid {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 8px;
  margin-bottom: 12px;
}

.options-grid label {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 0.9em;
  cursor: pointer;
}

.timeout-row {
  display: flex;
  align-items: center;
  gap: 10px;
}

.timeout-row input {
  width: 80px;
  padding: 6px 10px;
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  background: var(--md-default-bg-color);
  color: var(--md-default-fg-color);
}

.curl-output {
  background: var(--md-code-bg-color);
  padding: 20px;
  border-radius: 8px;
}

.output-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 15px;
}

.output-header h3 {
  margin: 0;
}

.output-actions {
  display: flex;
  gap: 8px;
}

.output-actions button {
  padding: 6px 12px;
  background: var(--md-default-bg-color);
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  cursor: pointer;
  font-size: 0.85em;
}

.curl-code {
  background: #1e1e1e;
  color: #d4d4d4;
  padding: 15px;
  border-radius: 6px;
  font-size: 0.85em;
  overflow-x: auto;
  white-space: pre-wrap;
  word-break: break-all;
  min-height: 100px;
}

.presets {
  margin-top: 20px;
}

.presets h4 {
  margin-bottom: 10px;
}

.preset-buttons {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.preset-buttons button {
  padding: 6px 12px;
  background: var(--md-default-bg-color);
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  cursor: pointer;
  font-size: 0.85em;
}

.preset-buttons button:hover {
  border-color: var(--md-primary-fg-color);
}

.equivalent-section {
  margin-top: 20px;
}

.equiv-tabs {
  display: flex;
  gap: 5px;
  margin-bottom: 10px;
}

.equiv-tabs .tab {
  padding: 6px 12px;
  background: var(--md-default-bg-color);
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  cursor: pointer;
  font-size: 0.85em;
}

.equiv-tabs .tab.active {
  background: var(--md-primary-fg-color);
  color: white;
  border-color: var(--md-primary-fg-color);
}

.equiv-code {
  background: #1e1e1e;
  color: #d4d4d4;
  padding: 15px;
  border-radius: 6px;
  font-size: 0.8em;
  overflow-x: auto;
  min-height: 80px;
}
</style>

<script>
let currentEquiv = 'fetch';

function getFormData() {
  const method = document.getElementById('method').value;
  const url = document.getElementById('url').value || 'https://api.example.com';

  // Headers
  const headers = [];
  document.querySelectorAll('#headers .header-row').forEach(row => {
    const inputs = row.querySelectorAll('input');
    const key = inputs[0].value.trim();
    const val = inputs[1].value.trim();
    if (key && val) headers.push({ key, value: val });
  });

  // Auth
  const authType = document.getElementById('authType').value;
  let auth = null;
  if (authType === 'bearer') {
    const token = document.querySelector('#authInputs input')?.value || '';
    if (token) auth = { type: 'bearer', token };
  } else if (authType === 'basic') {
    const inputs = document.querySelectorAll('#authInputs input');
    const user = inputs[0]?.value || '';
    const pass = inputs[1]?.value || '';
    if (user) auth = { type: 'basic', user, pass };
  } else if (authType === 'apikey') {
    const inputs = document.querySelectorAll('#authInputs input');
    const key = inputs[0]?.value || 'X-API-Key';
    const val = inputs[1]?.value || '';
    if (val) auth = { type: 'apikey', key, value: val };
  }

  // Body
  const bodyType = document.querySelector('input[name="bodyType"]:checked')?.value || 'json';
  const bodyContent = document.getElementById('jsonBody')?.value || '';

  // Options
  const options = {
    verbose: document.getElementById('optVerbose').checked,
    silent: document.getElementById('optSilent').checked,
    insecure: document.getElementById('optInsecure').checked,
    follow: document.getElementById('optFollow').checked,
    include: document.getElementById('optInclude').checked,
    compressed: document.getElementById('optCompressed').checked,
    timeout: document.getElementById('timeout').value
  };

  return { method, url, headers, auth, bodyType, bodyContent, options };
}

function updateCurl() {
  const data = getFormData();
  let cmd = 'curl';

  // Options
  if (data.options.verbose) cmd += ' -v';
  if (data.options.silent) cmd += ' -s';
  if (data.options.insecure) cmd += ' -k';
  if (data.options.follow) cmd += ' -L';
  if (data.options.include) cmd += ' -i';
  if (data.options.compressed) cmd += ' --compressed';
  if (data.options.timeout) cmd += ` --max-time ${data.options.timeout}`;

  // Method
  if (data.method !== 'GET') {
    cmd += ` -X ${data.method}`;
  }

  // Headers
  data.headers.forEach(h => {
    cmd += ` \\\n  -H "${h.key}: ${h.value}"`;
  });

  // Auth
  if (data.auth) {
    if (data.auth.type === 'bearer') {
      cmd += ` \\\n  -H "Authorization: Bearer ${data.auth.token}"`;
    } else if (data.auth.type === 'basic') {
      cmd += ` \\\n  -u "${data.auth.user}:${data.auth.pass}"`;
    } else if (data.auth.type === 'apikey') {
      cmd += ` \\\n  -H "${data.auth.key}: ${data.auth.value}"`;
    }
  }

  // Body
  if (['POST', 'PUT', 'PATCH'].includes(data.method) && data.bodyContent.trim()) {
    if (data.bodyType === 'json') {
      cmd += ` \\\n  -d '${data.bodyContent.replace(/'/g, "'\\''")}'`;
    } else if (data.bodyType === 'form') {
      cmd += ` \\\n  --data-urlencode '${data.bodyContent}'`;
    } else {
      cmd += ` \\\n  -d '${data.bodyContent}'`;
    }
  }

  // URL
  cmd += ` \\\n  "${data.url}"`;

  document.getElementById('curlOutput').textContent = cmd;
  updateEquivalent();
}

function updateAuthUI() {
  const authType = document.getElementById('authType').value;
  const container = document.getElementById('authInputs');

  switch (authType) {
    case 'bearer':
      container.innerHTML = '<input type="text" placeholder="Token" oninput="updateCurl()">';
      break;
    case 'basic':
      container.innerHTML = `
        <input type="text" placeholder="Username" oninput="updateCurl()">
        <input type="password" placeholder="Password" oninput="updateCurl()">
      `;
      break;
    case 'apikey':
      container.innerHTML = `
        <input type="text" placeholder="Header name" value="X-API-Key" oninput="updateCurl()">
        <input type="text" placeholder="API Key value" oninput="updateCurl()">
      `;
      break;
    default:
      container.innerHTML = '';
  }
}

function updateBodyUI() {
  // Body section visibility based on method
  const method = document.getElementById('method').value;
  const bodySection = document.getElementById('bodySection');
  bodySection.style.display = ['POST', 'PUT', 'PATCH'].includes(method) ? 'block' : 'none';
}

function addHeader() {
  const container = document.getElementById('headers');
  const row = document.createElement('div');
  row.className = 'header-row';
  row.innerHTML = `
    <input type="text" placeholder="Header" oninput="updateCurl()">
    <input type="text" placeholder="Value" oninput="updateCurl()">
    <button onclick="removeRow(this)">🗑️</button>
  `;
  container.appendChild(row);
}

function removeRow(btn) {
  btn.parentElement.remove();
  updateCurl();
}

function copyCurl() {
  const cmd = document.getElementById('curlOutput').textContent;
  navigator.clipboard.writeText(cmd).then(() => {
    const btn = event.target;
    const orig = btn.textContent;
    btn.textContent = '✓ Copie!';
    setTimeout(() => btn.textContent = orig, 1500);
  });
}

function copyOneLine() {
  const cmd = document.getElementById('curlOutput').textContent.replace(/\\\n\s*/g, ' ');
  navigator.clipboard.writeText(cmd);
}

function loadPreset(type) {
  // Reset form first
  document.getElementById('url').value = '';
  document.getElementById('method').value = 'GET';
  document.getElementById('headers').innerHTML = `
    <div class="header-row">
      <input type="text" placeholder="Header" value="Content-Type" oninput="updateCurl()">
      <input type="text" placeholder="Value" value="application/json" oninput="updateCurl()">
      <button onclick="removeRow(this)">🗑️</button>
    </div>
  `;
  document.getElementById('authType').value = 'none';
  document.getElementById('authInputs').innerHTML = '';
  document.getElementById('jsonBody').value = '';

  switch (type) {
    case 'get-json':
      document.getElementById('url').value = 'https://api.example.com/users';
      document.getElementById('headers').innerHTML = `
        <div class="header-row">
          <input type="text" value="Accept" oninput="updateCurl()">
          <input type="text" value="application/json" oninput="updateCurl()">
          <button onclick="removeRow(this)">🗑️</button>
        </div>
      `;
      break;

    case 'post-json':
      document.getElementById('method').value = 'POST';
      document.getElementById('url').value = 'https://api.example.com/users';
      document.getElementById('jsonBody').value = '{\n  "name": "John Doe",\n  "email": "john@example.com"\n}';
      break;

    case 'upload-file':
      document.getElementById('method').value = 'POST';
      document.getElementById('url').value = 'https://api.example.com/upload';
      document.getElementById('headers').innerHTML = `
        <div class="header-row">
          <input type="text" value="Content-Type" oninput="updateCurl()">
          <input type="text" value="multipart/form-data" oninput="updateCurl()">
          <button onclick="removeRow(this)">🗑️</button>
        </div>
      `;
      document.querySelector('input[name="bodyType"][value="form"]').checked = true;
      document.getElementById('jsonBody').value = 'file=@/path/to/file.pdf';
      break;

    case 'graphql':
      document.getElementById('method').value = 'POST';
      document.getElementById('url').value = 'https://api.example.com/graphql';
      document.getElementById('jsonBody').value = '{\n  "query": "{ users { id name email } }",\n  "variables": {}\n}';
      break;

    case 'oauth':
      document.getElementById('method').value = 'POST';
      document.getElementById('url').value = 'https://auth.example.com/oauth/token';
      document.getElementById('headers').innerHTML = `
        <div class="header-row">
          <input type="text" value="Content-Type" oninput="updateCurl()">
          <input type="text" value="application/x-www-form-urlencoded" oninput="updateCurl()">
          <button onclick="removeRow(this)">🗑️</button>
        </div>
      `;
      document.querySelector('input[name="bodyType"][value="form"]').checked = true;
      document.getElementById('jsonBody').value = 'grant_type=client_credentials&client_id=xxx&client_secret=yyy';
      break;

    case 'webhook':
      document.getElementById('method').value = 'POST';
      document.getElementById('url').value = 'https://hooks.example.com/webhook';
      document.getElementById('jsonBody').value = '{\n  "event": "user.created",\n  "data": {\n    "id": 123,\n    "name": "John"\n  }\n}';
      break;
  }

  updateBodyUI();
  updateCurl();
}

function showEquiv(lang) {
  currentEquiv = lang;
  document.querySelectorAll('.equiv-tabs .tab').forEach(t => t.classList.remove('active'));
  event.target.classList.add('active');
  updateEquivalent();
}

function updateEquivalent() {
  const data = getFormData();
  let code = '';

  if (currentEquiv === 'fetch') {
    const fetchOpts = { method: data.method };
    const hdrs = {};
    data.headers.forEach(h => hdrs[h.key] = h.value);
    if (data.auth?.type === 'bearer') hdrs['Authorization'] = `Bearer ${data.auth.token}`;
    if (data.auth?.type === 'apikey') hdrs[data.auth.key] = data.auth.value;

    code = `fetch("${data.url}", {
  method: "${data.method}",
  headers: ${JSON.stringify(hdrs, null, 4)},${['POST', 'PUT', 'PATCH'].includes(data.method) ? `
  body: JSON.stringify(${data.bodyContent || '{}'})` : ''}
})
.then(res => res.json())
.then(data => console.log(data));`;
  }
  else if (currentEquiv === 'python') {
    code = `import requests

response = requests.${data.method.toLowerCase()}(
    "${data.url}",
    headers={
${data.headers.map(h => `        "${h.key}": "${h.value}"`).join(',\n')}
    }${['POST', 'PUT', 'PATCH'].includes(data.method) ? `,
    json=${data.bodyContent || '{}'}` : ''}
)
print(response.json())`;
  }
  else if (currentEquiv === 'php') {
    code = `<?php
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, "${data.url}");
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
${data.method !== 'GET' ? `curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "${data.method}");` : ''}
curl_setopt($ch, CURLOPT_HTTPHEADER, [
${data.headers.map(h => `    "${h.key}: ${h.value}"`).join(',\n')}
]);
${['POST', 'PUT', 'PATCH'].includes(data.method) ? `curl_setopt($ch, CURLOPT_POSTFIELDS, '${data.bodyContent}');` : ''}
$response = curl_exec($ch);
curl_close($ch);
echo $response;`;
  }

  document.getElementById('equivCode').textContent = code;
}

// Event listener for method change
document.getElementById('method').addEventListener('change', function() {
  updateBodyUI();
  updateCurl();
});

// Initialize
updateAuthUI();
updateBodyUI();
updateCurl();
</script>

---

## Options cURL courantes

| Option | Description |
|--------|-------------|
| `-X` | Methode HTTP (GET, POST, etc.) |
| `-H` | Header HTTP |
| `-d` | Data/Body de la requete |
| `-u` | Basic auth (user:pass) |
| `-o` | Output vers fichier |
| `-O` | Telecharger avec nom original |
| `-L` | Suivre redirections |
| `-v` | Mode verbose |
| `-s` | Mode silencieux |
| `-k` | Ignorer erreurs SSL |
| `-i` | Inclure headers reponse |
| `--compressed` | Compression gzip |
