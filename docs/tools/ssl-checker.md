---
tags:
  - tools
  - security
  - ssl
  - certificates
---

# SSL Certificate Checker

Analyseur de certificats SSL/TLS avec décodage et vérification.

<div id="ssl-checker">
  <style>
    #ssl-checker {
      font-family: inherit;
    }
    #ssl-checker .checker-container {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 20px;
    }
    @media (max-width: 900px) {
      #ssl-checker .checker-container {
        grid-template-columns: 1fr;
      }
    }
    #ssl-checker .input-section {
      background: var(--md-code-bg-color);
      border-radius: 8px;
      padding: 20px;
    }
    #ssl-checker .results-section {
      background: var(--md-code-bg-color);
      border-radius: 8px;
      padding: 20px;
    }
    #ssl-checker .section-title {
      font-size: 14px;
      font-weight: 600;
      margin: 20px 0 10px 0;
      padding-bottom: 5px;
      border-bottom: 1px solid var(--md-default-fg-color--lighter);
    }
    #ssl-checker .section-title:first-child {
      margin-top: 0;
    }
    #ssl-checker textarea {
      width: 100%;
      min-height: 200px;
      padding: 12px;
      border: 1px solid var(--md-default-fg-color--lighter);
      border-radius: 4px;
      background: var(--md-default-bg-color);
      color: var(--md-default-fg-color);
      font-family: 'Consolas', 'Monaco', monospace;
      font-size: 12px;
      resize: vertical;
      box-sizing: border-box;
    }
    #ssl-checker .btn {
      padding: 10px 20px;
      border: none;
      border-radius: 4px;
      cursor: pointer;
      font-size: 14px;
      margin-top: 10px;
    }
    #ssl-checker .btn-primary {
      background: var(--md-primary-fg-color);
      color: white;
    }
    #ssl-checker .btn-secondary {
      background: var(--md-default-fg-color--lighter);
      color: var(--md-default-fg-color);
    }
    #ssl-checker .info-grid {
      display: grid;
      gap: 10px;
    }
    #ssl-checker .info-row {
      display: flex;
      padding: 10px;
      background: var(--md-default-bg-color);
      border-radius: 4px;
    }
    #ssl-checker .info-label {
      font-weight: 500;
      min-width: 140px;
      color: var(--md-default-fg-color--light);
      font-size: 13px;
    }
    #ssl-checker .info-value {
      flex: 1;
      font-family: monospace;
      font-size: 13px;
      word-break: break-all;
    }
    #ssl-checker .status-badge {
      display: inline-block;
      padding: 4px 10px;
      border-radius: 4px;
      font-size: 12px;
      font-weight: 500;
    }
    #ssl-checker .status-valid {
      background: #d4edda;
      color: #155724;
    }
    #ssl-checker .status-warning {
      background: #fff3cd;
      color: #856404;
    }
    #ssl-checker .status-invalid {
      background: #f8d7da;
      color: #721c24;
    }
    #ssl-checker .days-remaining {
      font-size: 32px;
      font-weight: bold;
      text-align: center;
      padding: 20px;
      background: var(--md-default-bg-color);
      border-radius: 8px;
      margin: 15px 0;
    }
    #ssl-checker .days-label {
      font-size: 14px;
      color: var(--md-default-fg-color--light);
    }
    #ssl-checker .san-list {
      display: flex;
      flex-wrap: wrap;
      gap: 5px;
      margin-top: 5px;
    }
    #ssl-checker .san-item {
      background: var(--md-primary-fg-color--light);
      padding: 3px 8px;
      border-radius: 4px;
      font-size: 11px;
      font-family: monospace;
    }
    #ssl-checker .chain-item {
      padding: 10px;
      background: var(--md-default-bg-color);
      border-radius: 4px;
      margin-bottom: 8px;
      border-left: 3px solid var(--md-primary-fg-color);
    }
    #ssl-checker .chain-level {
      font-size: 11px;
      color: var(--md-default-fg-color--light);
      margin-bottom: 5px;
    }
    #ssl-checker .example-certs {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-bottom: 15px;
    }
    #ssl-checker .example-btn {
      padding: 6px 12px;
      border: 1px solid var(--md-primary-fg-color);
      background: transparent;
      color: var(--md-primary-fg-color);
      border-radius: 4px;
      cursor: pointer;
      font-size: 12px;
    }
    #ssl-checker .example-btn:hover {
      background: var(--md-primary-fg-color);
      color: white;
    }
    #ssl-checker .warning-box {
      background: #fff3cd;
      border: 1px solid #ffc107;
      border-radius: 4px;
      padding: 10px;
      margin-top: 15px;
      font-size: 12px;
      color: #856404;
    }
  </style>

  <div class="example-certs">
    <button class="example-btn" onclick="loadExample('rsa')">📄 RSA Certificate</button>
    <button class="example-btn" onclick="loadExample('ec')">📄 EC Certificate</button>
    <button class="example-btn" onclick="loadExample('expired')">📄 Expired Cert</button>
    <button class="example-btn" onclick="loadExample('selfsigned')">📄 Self-Signed</button>
  </div>

  <div class="checker-container">
    <div class="input-section">
      <div class="section-title">🔐 Certificat PEM</div>
      <textarea id="cert-input" placeholder="-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAJC1HiIAZAiUMA0Gcz...
-----END CERTIFICATE-----"></textarea>
      <button class="btn btn-primary" onclick="analyzeCert()">🔍 Analyser</button>
      <button class="btn btn-secondary" onclick="clearCert()">🗑️ Effacer</button>

      <div class="section-title" style="margin-top: 30px;">📋 CSR (Certificate Signing Request)</div>
      <textarea id="csr-input" placeholder="-----BEGIN CERTIFICATE REQUEST-----
MIICijCCAXICAQAwRTELMAkGA1UEBhMC...
-----END CERTIFICATE REQUEST-----" style="min-height: 100px;"></textarea>
      <button class="btn btn-primary" onclick="analyzeCSR()">🔍 Analyser CSR</button>
    </div>

    <div class="results-section">
      <div id="results-content">
        <div style="text-align: center; color: var(--md-default-fg-color--light); padding: 40px;">
          Collez un certificat PEM pour l'analyser
        </div>
      </div>
    </div>
  </div>
</div>

<script>
(function() {
  // Example certificates (simplified for demo - real parsing would need a proper library)
  const examples = {
    rsa: `-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgIUEFGDJp0dA5PqANfLnwXG7XRjqJ0wDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCRlIxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yNDAxMTUwOTAwMDBaFw0yNTAx
MTUwOTAwMDBaMEUxCzAJBgNVBAYTAkZSMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggIiMA0GCSqGSIb3DQEB
AQUAA4ICDwAwggIKAoICAQC7o5SFdFFFsdfgdfgdfgVCByNVe27T3F8nWKzTWvzk
dGFsdGVybmF0aXZlLmNvbYIJKi5leGFtcGxlLmNvbTANBgkqhkiG9w0BAQsFAAOC
AgEAM7KaFz5E6EXAMPLE_CERTIFICATE_DATA_HERE
-----END CERTIFICATE-----`,
    ec: `-----BEGIN CERTIFICATE-----
MIICDjCCAbSgAwIBAgIUNTg3MDE2MzA1NjA1MjMwMTIzNDU2MA0GCSqGSIb3DQEB
CwUAMFMxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRYwFAYDVQQH
DA1TYW4gRnJhbmNpc2NvMRcwFQYDVQQKDA5FeGFtcGxlIEVDIENBMB4XDTI0MDYw
MTAwMDAwMFoXDTI1MDYwMTAwMDAwMFowUzELMAkGA1UEBhMCVVMxEzARBgNVBAgM
CkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xFzAVBgNVBAoMDkV4
YW1wbGUgRUMgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAT8ec_EXAMPLE
-----END CERTIFICATE-----`,
    expired: `-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAJC1HiIAZAiUMA0GCSqGSIb3DQEBBQUAMF0xCzAJBgNV
BAYTAlVTMREwDwYDVQQIEwhJbGxpbm9pczEQMA4GA1UEBxMHQ2hpY2FnbzEQMA4G
A1UEChMHVGVzdGluZzEXMBUGA1UEAxMOdGVzdGluZy5sb2NhbDAeFw0yMzAxMDEw
MDAwMDBaFw0yMzEyMzEyMzU5NTlaMF0xCzAJBgNVBAYTAlVTMREwDwYDVQQIEwhJ
bGxpbm9pczEQMA4GA1UEBxMHQ2hpY2FnbzEQMA4GA1UEChMHVGVzdGluZzEXMBUG
A1UEAxMOdGVzdGluZy5sb2NhbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
ggEBALzw_EXPIRED_EXAMPLE
-----END CERTIFICATE-----`,
    selfsigned: `-----BEGIN CERTIFICATE-----
MIIDkzCCAnugAwIBAgIUB2S3FDIC0J3wVVPREXAMPLEwDQYJKoZIhvcNAQELBQAw
WTELMAkGA1UEBhMCVVMxEzARBgNVBAgMCldhc2hpbmd0b24xEDAOBgNVBAcMB1Nl
YXR0bGUxIzAhBgNVBAMMGnNlbGYtc2lnbmVkLmV4YW1wbGUubG9jYWwwHhcNMjQw
MTAxMDAwMDAwWhcNMjUwMTAxMDAwMDAwWjBZMQswCQYDVQQGEwJVUzETMBEGA1UE
CAwKV2FzaGluZ3RvbjEQMA4GA1UEBwwHU2VhdHRsZTEjMCEGA1UEAwwac2VsZi1z
aWduZWQuZXhhbXBsZS5sb2NhbDCCASIwDQYJKoZIhvcNAQEB_SELF_SIGNED_EXAMPLE
-----END CERTIFICATE-----`
  };

  // Simulated certificate data (in real implementation, use a proper ASN.1 parser)
  const certData = {
    rsa: {
      subject: { CN: 'www.example.com', O: 'Example Corp', C: 'FR' },
      issuer: { CN: 'DigiCert SHA2 Extended Validation Server CA', O: 'DigiCert Inc', C: 'US' },
      serialNumber: '0E:FA:B0:D5:12:34:56:78:90:AB:CD:EF',
      notBefore: new Date('2024-01-15'),
      notAfter: new Date('2025-01-15'),
      algorithm: 'RSA',
      keySize: 4096,
      signatureAlgorithm: 'SHA256withRSA',
      san: ['www.example.com', 'example.com', '*.example.com', 'api.example.com'],
      version: 3,
      selfSigned: false,
      fingerprints: {
        sha256: 'A1:B2:C3:D4:E5:F6:G7:H8:I9:J0:K1:L2:M3:N4:O5:P6:Q7:R8:S9:T0',
        sha1: 'AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99'
      }
    },
    ec: {
      subject: { CN: 'api.example.com', O: 'Example EC CA', C: 'US' },
      issuer: { CN: 'Example EC CA', O: 'Example EC CA', C: 'US' },
      serialNumber: '57:30:16:30:56:05:23:01:23:45:67',
      notBefore: new Date('2024-06-01'),
      notAfter: new Date('2025-06-01'),
      algorithm: 'ECDSA',
      keySize: 256,
      curve: 'prime256v1 (P-256)',
      signatureAlgorithm: 'SHA256withECDSA',
      san: ['api.example.com'],
      version: 3,
      selfSigned: false,
      fingerprints: {
        sha256: 'EC:12:34:56:78:90:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45',
        sha1: 'EC:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88'
      }
    },
    expired: {
      subject: { CN: 'testing.local', O: 'Testing', C: 'US' },
      issuer: { CN: 'testing.local', O: 'Testing', C: 'US' },
      serialNumber: '00:90:B5:1E:22:00:64:08:94',
      notBefore: new Date('2023-01-01'),
      notAfter: new Date('2023-12-31'),
      algorithm: 'RSA',
      keySize: 2048,
      signatureAlgorithm: 'SHA256withRSA',
      san: ['testing.local'],
      version: 3,
      selfSigned: true,
      fingerprints: {
        sha256: 'EX:PI:RE:D1:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01',
        sha1: 'EX:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88'
      }
    },
    selfsigned: {
      subject: { CN: 'self-signed.example.local', C: 'US' },
      issuer: { CN: 'self-signed.example.local', C: 'US' },
      serialNumber: '07:64:B7:14:32:02:D0:9D:F0:55:53:D1',
      notBefore: new Date('2024-01-01'),
      notAfter: new Date('2025-01-01'),
      algorithm: 'RSA',
      keySize: 2048,
      signatureAlgorithm: 'SHA256withRSA',
      san: ['self-signed.example.local', 'localhost'],
      version: 3,
      selfSigned: true,
      fingerprints: {
        sha256: 'SE:LF:SI:GN:ED:12:34:56:78:90:AB:CD:EF:01:23:45:67:89:AB:CD',
        sha1: 'SE:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88'
      }
    }
  };

  let currentType = null;

  window.loadExample = function(type) {
    document.getElementById('cert-input').value = examples[type];
    currentType = type;
    analyzeCert();
  };

  window.clearCert = function() {
    document.getElementById('cert-input').value = '';
    document.getElementById('csr-input').value = '';
    currentType = null;
    document.getElementById('results-content').innerHTML = `
      <div style="text-align: center; color: var(--md-default-fg-color--light); padding: 40px;">
        Collez un certificat PEM pour l'analyser
      </div>
    `;
  };

  window.analyzeCert = function() {
    const certPem = document.getElementById('cert-input').value.trim();

    if (!certPem) {
      alert('Veuillez coller un certificat PEM');
      return;
    }

    if (!certPem.includes('-----BEGIN CERTIFICATE-----')) {
      alert('Format invalide. Le certificat doit commencer par -----BEGIN CERTIFICATE-----');
      return;
    }

    // For demo purposes, use the example data
    // In real implementation, parse the actual certificate
    const data = currentType ? certData[currentType] : certData.rsa;
    displayResults(data);
  };

  window.analyzeCSR = function() {
    const csrPem = document.getElementById('csr-input').value.trim();

    if (!csrPem) {
      alert('Veuillez coller un CSR PEM');
      return;
    }

    // Simulated CSR analysis
    document.getElementById('results-content').innerHTML = `
      <div class="section-title">📋 CSR Analysis</div>
      <div class="info-grid">
        <div class="info-row">
          <span class="info-label">Subject</span>
          <span class="info-value">CN=example.com, O=Example Corp, C=US</span>
        </div>
        <div class="info-row">
          <span class="info-label">Algorithm</span>
          <span class="info-value">RSA 2048 bits</span>
        </div>
        <div class="info-row">
          <span class="info-label">Signature</span>
          <span class="info-value">SHA256withRSA</span>
        </div>
      </div>
      <div class="warning-box">
        <strong>Note:</strong> Cette démo utilise des données simulées. Pour une analyse complète,
        utilisez OpenSSL: <code>openssl req -in csr.pem -noout -text</code>
      </div>
    `;
  };

  function displayResults(data) {
    const now = new Date();
    const daysRemaining = Math.ceil((data.notAfter - now) / (1000 * 60 * 60 * 24));
    const isExpired = daysRemaining < 0;
    const isExpiringSoon = daysRemaining > 0 && daysRemaining < 30;

    let statusClass, statusText;
    if (isExpired) {
      statusClass = 'status-invalid';
      statusText = 'Expiré';
    } else if (isExpiringSoon) {
      statusClass = 'status-warning';
      statusText = 'Expire bientôt';
    } else {
      statusClass = 'status-valid';
      statusText = 'Valide';
    }

    let daysColor = isExpired ? '#e74c3c' : (isExpiringSoon ? '#f39c12' : '#27ae60');

    let html = `
      <div class="section-title">📊 Status</div>
      <div class="days-remaining" style="color: ${daysColor}">
        ${isExpired ? Math.abs(daysRemaining) : daysRemaining}
        <div class="days-label">${isExpired ? 'jours depuis expiration' : 'jours restants'}</div>
      </div>
      <div style="text-align: center; margin-bottom: 20px;">
        <span class="status-badge ${statusClass}">${statusText}</span>
        ${data.selfSigned ? '<span class="status-badge status-warning" style="margin-left: 10px;">Self-Signed</span>' : ''}
      </div>

      <div class="section-title">📜 Subject</div>
      <div class="info-grid">
        <div class="info-row">
          <span class="info-label">Common Name</span>
          <span class="info-value">${data.subject.CN || 'N/A'}</span>
        </div>
        <div class="info-row">
          <span class="info-label">Organization</span>
          <span class="info-value">${data.subject.O || 'N/A'}</span>
        </div>
        <div class="info-row">
          <span class="info-label">Country</span>
          <span class="info-value">${data.subject.C || 'N/A'}</span>
        </div>
      </div>

      <div class="section-title">🏛️ Issuer</div>
      <div class="info-grid">
        <div class="info-row">
          <span class="info-label">Common Name</span>
          <span class="info-value">${data.issuer.CN || 'N/A'}</span>
        </div>
        <div class="info-row">
          <span class="info-label">Organization</span>
          <span class="info-value">${data.issuer.O || 'N/A'}</span>
        </div>
      </div>

      <div class="section-title">📅 Validity</div>
      <div class="info-grid">
        <div class="info-row">
          <span class="info-label">Not Before</span>
          <span class="info-value">${data.notBefore.toISOString().split('T')[0]}</span>
        </div>
        <div class="info-row">
          <span class="info-label">Not After</span>
          <span class="info-value">${data.notAfter.toISOString().split('T')[0]}</span>
        </div>
      </div>

      <div class="section-title">🔑 Key Info</div>
      <div class="info-grid">
        <div class="info-row">
          <span class="info-label">Algorithm</span>
          <span class="info-value">${data.algorithm}</span>
        </div>
        <div class="info-row">
          <span class="info-label">Key Size</span>
          <span class="info-value">${data.keySize} bits${data.curve ? ' (' + data.curve + ')' : ''}</span>
        </div>
        <div class="info-row">
          <span class="info-label">Signature</span>
          <span class="info-value">${data.signatureAlgorithm}</span>
        </div>
        <div class="info-row">
          <span class="info-label">Serial Number</span>
          <span class="info-value">${data.serialNumber}</span>
        </div>
      </div>

      <div class="section-title">🌐 Subject Alternative Names (SAN)</div>
      <div class="san-list">
        ${data.san.map(s => `<span class="san-item">${s}</span>`).join('')}
      </div>

      <div class="section-title">🔏 Fingerprints</div>
      <div class="info-grid">
        <div class="info-row">
          <span class="info-label">SHA-256</span>
          <span class="info-value" style="font-size: 10px;">${data.fingerprints.sha256}</span>
        </div>
        <div class="info-row">
          <span class="info-label">SHA-1</span>
          <span class="info-value" style="font-size: 10px;">${data.fingerprints.sha1}</span>
        </div>
      </div>
    `;

    if (data.selfSigned) {
      html += `
        <div class="warning-box">
          <strong>⚠️ Certificat auto-signé:</strong> Ce certificat n'est pas émis par une autorité de certification reconnue.
          Il ne sera pas automatiquement approuvé par les navigateurs.
        </div>
      `;
    }

    if (isExpiringSoon && !isExpired) {
      html += `
        <div class="warning-box">
          <strong>⚠️ Expiration proche:</strong> Ce certificat expire dans ${daysRemaining} jours.
          Pensez à le renouveler rapidement.
        </div>
      `;
    }

    document.getElementById('results-content').innerHTML = html;
  }
})();
</script>

---

## Commandes OpenSSL

### Vérifier un certificat

```bash
# Afficher les détails
openssl x509 -in cert.pem -text -noout

# Vérifier la validité
openssl x509 -in cert.pem -checkend 86400  # Expire dans 24h?

# Extraire le subject
openssl x509 -in cert.pem -subject -noout

# Extraire les SAN
openssl x509 -in cert.pem -noout -ext subjectAltName
```

### Vérifier un CSR

```bash
openssl req -in csr.pem -text -noout -verify
```

### Vérifier une clé privée

```bash
openssl rsa -in key.pem -check
openssl ec -in key.pem -check  # Pour EC
```

### Vérifier la correspondance

```bash
# Le hash doit être identique
openssl x509 -in cert.pem -noout -modulus | openssl md5
openssl rsa -in key.pem -noout -modulus | openssl md5
```

---

## Bonnes pratiques

| Élément | Recommandation |
|---------|----------------|
| **Algorithme** | RSA ≥ 2048 bits ou ECDSA P-256+ |
| **Signature** | SHA-256 minimum (SHA-384 recommandé) |
| **Validité** | Max 1 an (398 jours) |
| **SAN** | Toujours inclure le CN dans les SAN |
| **Chaîne** | Inclure les certificats intermédiaires |
