---
tags:
  - tools
  - security
  - rsa
  - crypto
---

# RSA Key Generator

Reference des commandes pour generer des paires de cles RSA/ECDSA/Ed25519.

<div id="rsa-app">
  <div class="rsa-container">
    <div class="rsa-section">
      <h3>Generateur de commandes</h3>

      <div class="key-form">
        <div class="form-group">
          <label>Type de cle</label>
          <select id="keyType" onchange="updateCommands()">
            <option value="rsa">RSA</option>
            <option value="ecdsa">ECDSA</option>
            <option value="ed25519" selected>Ed25519 (recommande)</option>
          </select>
        </div>

        <div class="form-group" id="rsaSizeGroup">
          <label>Taille (bits)</label>
          <select id="rsaSize" onchange="updateCommands()">
            <option value="2048">2048 bits</option>
            <option value="3072">3072 bits</option>
            <option value="4096" selected>4096 bits</option>
          </select>
        </div>

        <div class="form-group" id="ecdsaCurveGroup" style="display:none;">
          <label>Courbe</label>
          <select id="ecdsaCurve" onchange="updateCommands()">
            <option value="prime256v1">P-256 (prime256v1)</option>
            <option value="secp384r1">P-384 (secp384r1)</option>
            <option value="secp521r1">P-521 (secp521r1)</option>
          </select>
        </div>

        <div class="form-group">
          <label>Nom du fichier</label>
          <input type="text" id="keyName" value="id_ed25519" oninput="updateCommands()">
        </div>

        <div class="form-group">
          <label>Commentaire</label>
          <input type="text" id="keyComment" placeholder="user@hostname" oninput="updateCommands()">
        </div>

        <div class="form-group">
          <label>Format de sortie</label>
          <select id="outputFormat" onchange="updateCommands()">
            <option value="openssh">OpenSSH</option>
            <option value="pem">PEM (PKCS#8)</option>
            <option value="pkcs1">PKCS#1 (RSA only)</option>
          </select>
        </div>
      </div>
    </div>

    <div class="rsa-section">
      <h3>Commandes</h3>

      <div class="cmd-card">
        <div class="cmd-header">
          <span>SSH-Keygen</span>
          <button onclick="copyCmd('sshKeygen')">📋</button>
        </div>
        <pre id="sshKeygen" class="cmd-code">ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519</pre>
      </div>

      <div class="cmd-card">
        <div class="cmd-header">
          <span>OpenSSL (cle privee)</span>
          <button onclick="copyCmd('opensslPriv')">📋</button>
        </div>
        <pre id="opensslPriv" class="cmd-code">openssl genpkey -algorithm ed25519 -out private.pem</pre>
      </div>

      <div class="cmd-card">
        <div class="cmd-header">
          <span>OpenSSL (cle publique)</span>
          <button onclick="copyCmd('opensslPub')">📋</button>
        </div>
        <pre id="opensslPub" class="cmd-code">openssl pkey -in private.pem -pubout -out public.pem</pre>
      </div>

      <div class="cmd-card">
        <div class="cmd-header">
          <span>Empreinte (fingerprint)</span>
          <button onclick="copyCmd('fingerprint')">📋</button>
        </div>
        <pre id="fingerprint" class="cmd-code">ssh-keygen -lf ~/.ssh/id_ed25519.pub</pre>
      </div>
    </div>
  </div>

  <div class="operations-section">
    <h3>Operations courantes</h3>

    <div class="ops-grid">
      <div class="op-card">
        <h4>🔄 Convertir PEM vers OpenSSH</h4>
        <pre>ssh-keygen -y -f private.pem > public.pub</pre>
      </div>

      <div class="op-card">
        <h4>🔐 Ajouter passphrase</h4>
        <pre>ssh-keygen -p -f ~/.ssh/id_ed25519</pre>
      </div>

      <div class="op-card">
        <h4>🔓 Supprimer passphrase</h4>
        <pre>ssh-keygen -p -N "" -f ~/.ssh/id_ed25519</pre>
      </div>

      <div class="op-card">
        <h4>📋 Copier cle publique</h4>
        <pre>ssh-copy-id -i ~/.ssh/id_ed25519.pub user@host</pre>
      </div>

      <div class="op-card">
        <h4>🔍 Voir cle publique</h4>
        <pre>ssh-keygen -y -f ~/.ssh/id_ed25519</pre>
      </div>

      <div class="op-card">
        <h4>📊 Infos cle</h4>
        <pre>openssl pkey -in private.pem -text -noout</pre>
      </div>
    </div>
  </div>

  <div class="reference-section">
    <h3>Comparaison des algorithmes</h3>
    <table class="algo-table">
      <thead>
        <tr>
          <th>Algorithme</th>
          <th>Taille cle</th>
          <th>Securite</th>
          <th>Performance</th>
          <th>Compatibilite</th>
        </tr>
      </thead>
      <tbody>
        <tr class="recommended">
          <td><strong>Ed25519</strong></td>
          <td>256 bits</td>
          <td>⭐⭐⭐⭐⭐</td>
          <td>⭐⭐⭐⭐⭐</td>
          <td>OpenSSH 6.5+</td>
        </tr>
        <tr>
          <td>ECDSA P-256</td>
          <td>256 bits</td>
          <td>⭐⭐⭐⭐</td>
          <td>⭐⭐⭐⭐</td>
          <td>OpenSSH 5.7+</td>
        </tr>
        <tr>
          <td>ECDSA P-384</td>
          <td>384 bits</td>
          <td>⭐⭐⭐⭐⭐</td>
          <td>⭐⭐⭐⭐</td>
          <td>OpenSSH 5.7+</td>
        </tr>
        <tr>
          <td>RSA 2048</td>
          <td>2048 bits</td>
          <td>⭐⭐⭐</td>
          <td>⭐⭐⭐</td>
          <td>Universal</td>
        </tr>
        <tr>
          <td>RSA 4096</td>
          <td>4096 bits</td>
          <td>⭐⭐⭐⭐</td>
          <td>⭐⭐</td>
          <td>Universal</td>
        </tr>
      </tbody>
    </table>
  </div>
</div>

<style>
.rsa-container {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 20px;
}

@media (max-width: 800px) {
  .rsa-container {
    grid-template-columns: 1fr;
  }
}

.rsa-section {
  background: var(--md-code-bg-color);
  padding: 20px;
  border-radius: 8px;
}

.key-form {
  background: var(--md-default-bg-color);
  padding: 15px;
  border-radius: 6px;
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
.form-group input {
  width: 100%;
  padding: 10px;
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  background: var(--md-code-bg-color);
  color: var(--md-default-fg-color);
  font-family: monospace;
}

.cmd-card {
  background: var(--md-default-bg-color);
  border-radius: 6px;
  margin-bottom: 12px;
  overflow: hidden;
}

.cmd-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 8px 12px;
  background: var(--md-code-bg-color);
  font-size: 0.85em;
}

.cmd-header button {
  padding: 4px 8px;
  background: transparent;
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  cursor: pointer;
  font-size: 0.85em;
}

.cmd-code {
  margin: 0;
  padding: 12px;
  background: #1e1e1e;
  color: #d4d4d4;
  font-size: 0.85em;
  overflow-x: auto;
}

.operations-section, .reference-section {
  margin-top: 20px;
  background: var(--md-code-bg-color);
  padding: 20px;
  border-radius: 8px;
}

.ops-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
  gap: 12px;
}

.op-card {
  background: var(--md-default-bg-color);
  padding: 15px;
  border-radius: 6px;
}

.op-card h4 {
  margin: 0 0 10px 0;
  font-size: 0.9em;
}

.op-card pre {
  margin: 0;
  padding: 10px;
  background: #1e1e1e;
  color: #d4d4d4;
  border-radius: 4px;
  font-size: 0.8em;
  overflow-x: auto;
}

.algo-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.9em;
}

.algo-table th, .algo-table td {
  padding: 12px;
  text-align: left;
  border-bottom: 1px solid var(--md-default-fg-color--lightest);
}

.algo-table th {
  background: var(--md-default-bg-color);
}

.algo-table tr.recommended {
  background: rgba(39, 174, 96, 0.1);
}
</style>

<script>
function updateCommands() {
  const keyType = document.getElementById('keyType').value;
  const rsaSize = document.getElementById('rsaSize').value;
  const ecdsaCurve = document.getElementById('ecdsaCurve').value;
  const keyName = document.getElementById('keyName').value || 'id_key';
  const comment = document.getElementById('keyComment').value;
  const format = document.getElementById('outputFormat').value;

  // Show/hide relevant options
  document.getElementById('rsaSizeGroup').style.display = keyType === 'rsa' ? 'block' : 'none';
  document.getElementById('ecdsaCurveGroup').style.display = keyType === 'ecdsa' ? 'block' : 'none';

  let sshKeygenCmd = 'ssh-keygen';
  let opensslPrivCmd = 'openssl genpkey';
  let opensslPubCmd = 'openssl pkey -in private.pem -pubout -out public.pem';
  let fingerprintCmd = `ssh-keygen -lf ~/.ssh/${keyName}.pub`;

  // SSH-keygen command
  if (keyType === 'rsa') {
    sshKeygenCmd += ` -t rsa -b ${rsaSize}`;
  } else if (keyType === 'ecdsa') {
    const bits = ecdsaCurve === 'prime256v1' ? '256' : ecdsaCurve === 'secp384r1' ? '384' : '521';
    sshKeygenCmd += ` -t ecdsa -b ${bits}`;
  } else {
    sshKeygenCmd += ' -t ed25519';
  }

  sshKeygenCmd += ` -f ~/.ssh/${keyName}`;
  if (comment) sshKeygenCmd += ` -C "${comment}"`;

  // OpenSSL commands
  if (keyType === 'rsa') {
    opensslPrivCmd = `openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:${rsaSize} -out private.pem`;
    if (format === 'pkcs1') {
      opensslPrivCmd = `openssl genrsa -out private.pem ${rsaSize}`;
    }
  } else if (keyType === 'ecdsa') {
    opensslPrivCmd = `openssl ecparam -name ${ecdsaCurve} -genkey -noout -out private.pem`;
  } else {
    opensslPrivCmd = 'openssl genpkey -algorithm ed25519 -out private.pem';
  }

  document.getElementById('sshKeygen').textContent = sshKeygenCmd;
  document.getElementById('opensslPriv').textContent = opensslPrivCmd;
  document.getElementById('opensslPub').textContent = opensslPubCmd;
  document.getElementById('fingerprint').textContent = fingerprintCmd;

  // Update default filename based on key type
  if (!document.getElementById('keyName').dataset.userModified) {
    document.getElementById('keyName').value = `id_${keyType === 'rsa' ? 'rsa' : keyType === 'ecdsa' ? 'ecdsa' : 'ed25519'}`;
  }
}

document.getElementById('keyName').addEventListener('input', function() {
  this.dataset.userModified = true;
});

function copyCmd(id) {
  const cmd = document.getElementById(id).textContent;
  navigator.clipboard.writeText(cmd).then(() => {
    const btn = event.target;
    const orig = btn.textContent;
    btn.textContent = '✓';
    setTimeout(() => btn.textContent = orig, 1000);
  });
}

// Initialize
updateCommands();
</script>

---

## Bonnes pratiques

!!! tip "Recommandations"
    - **Ed25519** est recommande pour les nouvelles installations
    - Utilisez toujours une passphrase forte
    - Stockez les cles privees avec permissions `600`
    - Utilisez `ssh-agent` pour eviter de retaper la passphrase
    - Faites une sauvegarde securisee de vos cles

---

## Fichiers SSH

| Fichier | Description |
|---------|-------------|
| `~/.ssh/id_ed25519` | Cle privee (secret!) |
| `~/.ssh/id_ed25519.pub` | Cle publique |
| `~/.ssh/authorized_keys` | Cles autorisees (serveur) |
| `~/.ssh/known_hosts` | Empreintes serveurs connus |
| `~/.ssh/config` | Configuration client |
