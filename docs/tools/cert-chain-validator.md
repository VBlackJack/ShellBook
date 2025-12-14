---
tags:
  - tools
  - security
  - ssl
  - certificates
---

# Certificate Chain Validator

Reference des commandes pour valider et analyser les chaines de certificats SSL/TLS.

<div id="cert-app">
  <div class="cert-container">
    <div class="cert-section">
      <h3>Commandes d'analyse</h3>

      <div class="cmd-input">
        <label>Domaine ou adresse</label>
        <input type="text" id="domain" value="google.com" oninput="updateCommands()">
      </div>

      <div class="cmd-card">
        <div class="cmd-header">
          <span>🔍 Recuperer la chaine complete</span>
          <button onclick="copyCmd('cmdChain')">📋</button>
        </div>
        <pre id="cmdChain" class="cmd-code">openssl s_client -connect google.com:443 -showcerts </dev/null 2>/dev/null</pre>
      </div>

      <div class="cmd-card">
        <div class="cmd-header">
          <span>📜 Info certificat</span>
          <button onclick="copyCmd('cmdInfo')">📋</button>
        </div>
        <pre id="cmdInfo" class="cmd-code">echo | openssl s_client -connect google.com:443 2>/dev/null | openssl x509 -noout -text</pre>
      </div>

      <div class="cmd-card">
        <div class="cmd-header">
          <span>📅 Dates de validite</span>
          <button onclick="copyCmd('cmdDates')">📋</button>
        </div>
        <pre id="cmdDates" class="cmd-code">echo | openssl s_client -connect google.com:443 2>/dev/null | openssl x509 -noout -dates</pre>
      </div>

      <div class="cmd-card">
        <div class="cmd-header">
          <span>🔗 Verifier la chaine</span>
          <button onclick="copyCmd('cmdVerify')">📋</button>
        </div>
        <pre id="cmdVerify" class="cmd-code">openssl s_client -connect google.com:443 -verify_return_error </dev/null 2>&1 | grep -E "Verify|depth"</pre>
      </div>

      <div class="cmd-card">
        <div class="cmd-header">
          <span>🖨️ Empreintes (fingerprints)</span>
          <button onclick="copyCmd('cmdFingerprint')">📋</button>
        </div>
        <pre id="cmdFingerprint" class="cmd-code">echo | openssl s_client -connect google.com:443 2>/dev/null | openssl x509 -noout -fingerprint -sha256</pre>
      </div>
    </div>

    <div class="cert-section">
      <h3>Analyse de fichier</h3>

      <div class="file-commands">
        <div class="cmd-card">
          <div class="cmd-header">
            <span>Lire certificat PEM</span>
          </div>
          <pre class="cmd-code">openssl x509 -in cert.pem -text -noout</pre>
        </div>

        <div class="cmd-card">
          <div class="cmd-header">
            <span>Lire certificat DER</span>
          </div>
          <pre class="cmd-code">openssl x509 -in cert.der -inform DER -text -noout</pre>
        </div>

        <div class="cmd-card">
          <div class="cmd-header">
            <span>Verifier correspondance cle/cert</span>
          </div>
          <pre class="cmd-code"># Les hash doivent etre identiques
openssl x509 -noout -modulus -in cert.pem | openssl md5
openssl rsa -noout -modulus -in key.pem | openssl md5</pre>
        </div>

        <div class="cmd-card">
          <div class="cmd-header">
            <span>Verifier chaine locale</span>
          </div>
          <pre class="cmd-code">openssl verify -CAfile ca-bundle.crt cert.pem</pre>
        </div>

        <div class="cmd-card">
          <div class="cmd-header">
            <span>Extraire certificats d'un bundle</span>
          </div>
          <pre class="cmd-code">csplit -f cert- bundle.pem '/-----BEGIN CERTIFICATE-----/' '{*}'</pre>
        </div>
      </div>
    </div>
  </div>

  <div class="chain-section">
    <h3>Structure d'une chaine de certificats</h3>

    <div class="chain-diagram">
      <div class="chain-item root">
        <div class="chain-icon">🏛️</div>
        <div class="chain-content">
          <h4>Root CA</h4>
          <p>Certificat racine (auto-signe)</p>
          <code>Issuer = Subject</code>
        </div>
      </div>
      <div class="chain-arrow">↓</div>
      <div class="chain-item intermediate">
        <div class="chain-icon">🔗</div>
        <div class="chain-content">
          <h4>Intermediate CA(s)</h4>
          <p>Certificat(s) intermediaire(s)</p>
          <code>Signe par Root CA</code>
        </div>
      </div>
      <div class="chain-arrow">↓</div>
      <div class="chain-item leaf">
        <div class="chain-icon">🌐</div>
        <div class="chain-content">
          <h4>End-Entity (Leaf)</h4>
          <p>Certificat du serveur</p>
          <code>Signe par Intermediate</code>
        </div>
      </div>
    </div>
  </div>

  <div class="issues-section">
    <h3>Problemes courants</h3>

    <div class="issues-grid">
      <div class="issue-card error">
        <h4>❌ Certificate has expired</h4>
        <p>Le certificat a depasse sa date de validite</p>
        <div class="solution">
          <strong>Solution:</strong> Renouveler le certificat
        </div>
      </div>

      <div class="issue-card error">
        <h4>❌ Unable to get local issuer certificate</h4>
        <p>Certificat intermediaire manquant</p>
        <div class="solution">
          <strong>Solution:</strong> Ajouter le(s) certificat(s) intermediaire(s) au bundle
        </div>
      </div>

      <div class="issue-card error">
        <h4>❌ Self-signed certificate in chain</h4>
        <p>CA non reconnue</p>
        <div class="solution">
          <strong>Solution:</strong> Installer le CA root ou utiliser -CAfile
        </div>
      </div>

      <div class="issue-card warning">
        <h4>⚠️ Certificate CN mismatch</h4>
        <p>Le domaine ne correspond pas au CN/SAN</p>
        <div class="solution">
          <strong>Solution:</strong> Verifier les Subject Alternative Names
        </div>
      </div>

      <div class="issue-card warning">
        <h4>⚠️ Chain order incorrect</h4>
        <p>Les certificats ne sont pas dans le bon ordre</p>
        <div class="solution">
          <strong>Solution:</strong> Leaf → Intermediate(s) → Root
        </div>
      </div>

      <div class="issue-card info">
        <h4>ℹ️ Certificate will expire soon</h4>
        <p>Expiration proche (< 30 jours)</p>
        <div class="solution">
          <strong>Solution:</strong> Planifier le renouvellement
        </div>
      </div>
    </div>
  </div>

  <div class="tools-section">
    <h3>Outils en ligne</h3>

    <div class="tools-grid">
      <a href="https://www.sslshopper.com/ssl-checker.html" target="_blank" class="tool-link">
        <strong>SSL Shopper</strong>
        <span>Analyse complete</span>
      </a>
      <a href="https://www.ssllabs.com/ssltest/" target="_blank" class="tool-link">
        <strong>SSL Labs</strong>
        <span>Test approfondi (A-F grade)</span>
      </a>
      <a href="https://crt.sh" target="_blank" class="tool-link">
        <strong>crt.sh</strong>
        <span>Certificate Transparency logs</span>
      </a>
      <a href="https://whatsmychaincert.com" target="_blank" class="tool-link">
        <strong>What's My Chain Cert</strong>
        <span>Generer le bundle intermediaire</span>
      </a>
    </div>
  </div>
</div>

<style>
.cert-container {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 20px;
}

@media (max-width: 900px) {
  .cert-container {
    grid-template-columns: 1fr;
  }
}

.cert-section, .chain-section, .issues-section, .tools-section {
  background: var(--md-code-bg-color);
  padding: 20px;
  border-radius: 8px;
  margin-bottom: 20px;
}

.cmd-input {
  margin-bottom: 15px;
}

.cmd-input label {
  display: block;
  font-size: 0.85em;
  margin-bottom: 5px;
  color: var(--md-default-fg-color--light);
}

.cmd-input input {
  width: 100%;
  padding: 10px;
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  background: var(--md-default-bg-color);
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
}

.cmd-code {
  margin: 0;
  padding: 12px;
  background: #1e1e1e;
  color: #d4d4d4;
  font-size: 0.8em;
  overflow-x: auto;
  white-space: pre-wrap;
}

.chain-diagram {
  display: flex;
  flex-direction: column;
  align-items: center;
  padding: 20px;
}

.chain-item {
  display: flex;
  align-items: center;
  gap: 15px;
  padding: 20px;
  background: var(--md-default-bg-color);
  border-radius: 8px;
  width: 100%;
  max-width: 400px;
  border-left: 4px solid;
}

.chain-item.root { border-left-color: #e74c3c; }
.chain-item.intermediate { border-left-color: #f39c12; }
.chain-item.leaf { border-left-color: #27ae60; }

.chain-icon {
  font-size: 2em;
}

.chain-content h4 {
  margin: 0 0 5px 0;
}

.chain-content p {
  margin: 0 0 5px 0;
  font-size: 0.85em;
  color: var(--md-default-fg-color--light);
}

.chain-content code {
  font-size: 0.8em;
}

.chain-arrow {
  font-size: 1.5em;
  margin: 10px 0;
  color: var(--md-default-fg-color--light);
}

.issues-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
  gap: 15px;
}

.issue-card {
  padding: 15px;
  border-radius: 6px;
  border-left: 4px solid;
}

.issue-card.error {
  background: rgba(231, 76, 60, 0.1);
  border-left-color: #e74c3c;
}

.issue-card.warning {
  background: rgba(243, 156, 18, 0.1);
  border-left-color: #f39c12;
}

.issue-card.info {
  background: rgba(52, 152, 219, 0.1);
  border-left-color: #3498db;
}

.issue-card h4 {
  margin: 0 0 8px 0;
  font-size: 0.95em;
}

.issue-card p {
  margin: 0 0 10px 0;
  font-size: 0.85em;
  color: var(--md-default-fg-color--light);
}

.issue-card .solution {
  font-size: 0.85em;
  padding: 8px;
  background: var(--md-default-bg-color);
  border-radius: 4px;
}

.tools-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 12px;
}

.tool-link {
  display: flex;
  flex-direction: column;
  padding: 15px;
  background: var(--md-default-bg-color);
  border-radius: 6px;
  text-decoration: none;
  color: var(--md-default-fg-color);
  border: 1px solid transparent;
}

.tool-link:hover {
  border-color: var(--md-primary-fg-color);
}

.tool-link span {
  font-size: 0.8em;
  color: var(--md-default-fg-color--light);
  margin-top: 4px;
}
</style>

<script>
function updateCommands() {
  const domain = document.getElementById('domain').value || 'example.com';

  document.getElementById('cmdChain').textContent =
    `openssl s_client -connect ${domain}:443 -showcerts </dev/null 2>/dev/null`;

  document.getElementById('cmdInfo').textContent =
    `echo | openssl s_client -connect ${domain}:443 2>/dev/null | openssl x509 -noout -text`;

  document.getElementById('cmdDates').textContent =
    `echo | openssl s_client -connect ${domain}:443 2>/dev/null | openssl x509 -noout -dates`;

  document.getElementById('cmdVerify').textContent =
    `openssl s_client -connect ${domain}:443 -verify_return_error </dev/null 2>&1 | grep -E "Verify|depth"`;

  document.getElementById('cmdFingerprint').textContent =
    `echo | openssl s_client -connect ${domain}:443 2>/dev/null | openssl x509 -noout -fingerprint -sha256`;
}

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

## Extensions X.509 importantes

| Extension | OID | Description |
|-----------|-----|-------------|
| Subject Alternative Name | 2.5.29.17 | Domaines/IP alternatifs |
| Basic Constraints | 2.5.29.19 | CA:TRUE/FALSE |
| Key Usage | 2.5.29.15 | Digital Signature, Key Encipherment |
| Extended Key Usage | 2.5.29.37 | Server Auth, Client Auth |
| Authority Key Identifier | 2.5.29.35 | ID de la cle de l'emetteur |
| CRL Distribution Points | 2.5.29.31 | URL de la CRL |
| OCSP | 1.3.6.1.5.5.7.1.1 | URL pour validation OCSP |
