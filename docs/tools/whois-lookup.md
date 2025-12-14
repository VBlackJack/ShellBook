---
tags:
  - tools
  - network
  - whois
  - dns
---

# Whois Lookup

Reference des commandes Whois et informations sur les registres Internet.

<div id="whois-app">
  <div class="whois-container">
    <div class="whois-section">
      <h3>Commandes Whois</h3>

      <div class="command-generator">
        <div class="form-row">
          <label>Cible</label>
          <input type="text" id="whoisTarget" placeholder="example.com ou 8.8.8.8">
        </div>

        <div class="form-row">
          <label>Type de requete</label>
          <select id="whoisType" onchange="updateWhoisCmd()">
            <option value="domain">Domaine</option>
            <option value="ip">Adresse IP</option>
            <option value="asn">ASN</option>
            <option value="netblock">Netblock</option>
          </select>
        </div>

        <div class="generated-cmd">
          <label>Commande</label>
          <div class="cmd-output">
            <code id="whoisCmd">whois example.com</code>
            <button onclick="copyCmd()">📋</button>
          </div>
        </div>
      </div>

      <div class="quick-commands">
        <h4>Commandes rapides</h4>
        <div class="cmd-grid">
          <div class="cmd-item">
            <code>whois -h whois.ripe.net 8.8.8.8</code>
            <span>IP via RIPE</span>
          </div>
          <div class="cmd-item">
            <code>whois -h whois.arin.net n 8.8.8.8</code>
            <span>IP via ARIN</span>
          </div>
          <div class="cmd-item">
            <code>whois -h whois.radb.net AS15169</code>
            <span>Info ASN</span>
          </div>
          <div class="cmd-item">
            <code>whois -h whois.verisign-grs.com example.com</code>
            <span>Domaine .com</span>
          </div>
          <div class="cmd-item">
            <code>whois -h whois.nic.fr example.fr</code>
            <span>Domaine .fr</span>
          </div>
          <div class="cmd-item">
            <code>dig +short TXT _dmarc.example.com</code>
            <span>DMARC record</span>
          </div>
        </div>
      </div>
    </div>

    <div class="whois-section">
      <h3>Registres RIR</h3>

      <div class="rir-table">
        <table>
          <thead>
            <tr>
              <th>RIR</th>
              <th>Region</th>
              <th>Serveur Whois</th>
              <th>Plages IP</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><strong>ARIN</strong></td>
              <td>🇺🇸 Amerique du Nord</td>
              <td><code>whois.arin.net</code></td>
              <td>3.0.0.0/8 - 76.0.0.0/8</td>
            </tr>
            <tr>
              <td><strong>RIPE NCC</strong></td>
              <td>🇪🇺 Europe, Moyen-Orient</td>
              <td><code>whois.ripe.net</code></td>
              <td>2.0.0.0/8 - 95.0.0.0/8</td>
            </tr>
            <tr>
              <td><strong>APNIC</strong></td>
              <td>🌏 Asie-Pacifique</td>
              <td><code>whois.apnic.net</code></td>
              <td>1.0.0.0/8 - 223.0.0.0/8</td>
            </tr>
            <tr>
              <td><strong>LACNIC</strong></td>
              <td>🌎 Amerique Latine</td>
              <td><code>whois.lacnic.net</code></td>
              <td>177.0.0.0/8 - 191.0.0.0/8</td>
            </tr>
            <tr>
              <td><strong>AFRINIC</strong></td>
              <td>🌍 Afrique</td>
              <td><code>whois.afrinic.net</code></td>
              <td>41.0.0.0/8 - 197.0.0.0/8</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <div class="tld-section">
    <h3>Registres par TLD</h3>
    <div class="tld-search">
      <input type="text" id="tldSearch" placeholder="Rechercher un TLD (.com, .fr, .io...)" oninput="filterTLDs()">
    </div>
    <div id="tldGrid" class="tld-grid"></div>
  </div>

  <div class="tools-section">
    <h3>Outils en ligne</h3>
    <div class="tools-grid">
      <a href="https://who.is" target="_blank" class="tool-card">
        <strong>who.is</strong>
        <span>Whois web simple</span>
      </a>
      <a href="https://www.whois.com/whois" target="_blank" class="tool-card">
        <strong>whois.com</strong>
        <span>Recherche domaine</span>
      </a>
      <a href="https://bgp.he.net" target="_blank" class="tool-card">
        <strong>HE BGP Toolkit</strong>
        <span>ASN et prefixes</span>
      </a>
      <a href="https://ipinfo.io" target="_blank" class="tool-card">
        <strong>ipinfo.io</strong>
        <span>Info IP + geoloc</span>
      </a>
      <a href="https://mxtoolbox.com" target="_blank" class="tool-card">
        <strong>MXToolbox</strong>
        <span>DNS, MX, blacklists</span>
      </a>
      <a href="https://securitytrails.com" target="_blank" class="tool-card">
        <strong>SecurityTrails</strong>
        <span>Historique DNS</span>
      </a>
    </div>
  </div>
</div>

<style>
.whois-container {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 20px;
}

@media (max-width: 800px) {
  .whois-container {
    grid-template-columns: 1fr;
  }
}

.whois-section {
  background: var(--md-code-bg-color);
  padding: 20px;
  border-radius: 8px;
}

.command-generator {
  background: var(--md-default-bg-color);
  padding: 15px;
  border-radius: 6px;
  margin-bottom: 20px;
}

.form-row {
  margin-bottom: 12px;
}

.form-row label {
  display: block;
  font-size: 0.85em;
  margin-bottom: 4px;
  color: var(--md-default-fg-color--light);
}

.form-row input,
.form-row select {
  width: 100%;
  padding: 10px;
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  background: var(--md-code-bg-color);
  color: var(--md-default-fg-color);
  font-family: monospace;
}

.generated-cmd {
  margin-top: 15px;
  padding-top: 15px;
  border-top: 1px solid var(--md-default-fg-color--lightest);
}

.cmd-output {
  display: flex;
  align-items: center;
  gap: 10px;
  background: #1e1e1e;
  padding: 10px 15px;
  border-radius: 4px;
}

.cmd-output code {
  flex: 1;
  color: #d4d4d4;
  font-size: 0.9em;
}

.cmd-output button {
  padding: 5px 10px;
  background: transparent;
  border: 1px solid #555;
  border-radius: 4px;
  color: #d4d4d4;
  cursor: pointer;
}

.quick-commands h4 {
  margin-bottom: 10px;
}

.cmd-grid {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.cmd-item {
  display: flex;
  flex-direction: column;
  padding: 10px;
  background: var(--md-default-bg-color);
  border-radius: 4px;
}

.cmd-item code {
  font-size: 0.85em;
  margin-bottom: 4px;
}

.cmd-item span {
  font-size: 0.75em;
  color: var(--md-default-fg-color--light);
}

.rir-table {
  overflow-x: auto;
}

.rir-table table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.85em;
}

.rir-table th, .rir-table td {
  padding: 10px;
  text-align: left;
  border-bottom: 1px solid var(--md-default-fg-color--lightest);
}

.rir-table th {
  background: var(--md-default-bg-color);
}

.rir-table code {
  font-size: 0.85em;
}

.tld-section, .tools-section {
  margin-top: 20px;
  background: var(--md-code-bg-color);
  padding: 20px;
  border-radius: 8px;
}

.tld-search {
  margin-bottom: 15px;
}

.tld-search input {
  width: 100%;
  padding: 10px 15px;
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  background: var(--md-default-bg-color);
  color: var(--md-default-fg-color);
}

.tld-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
  gap: 10px;
  max-height: 400px;
  overflow-y: auto;
}

.tld-item {
  display: flex;
  justify-content: space-between;
  padding: 10px 12px;
  background: var(--md-default-bg-color);
  border-radius: 4px;
  font-size: 0.85em;
}

.tld-name {
  font-family: monospace;
  font-weight: 600;
}

.tld-server {
  color: var(--md-default-fg-color--light);
  font-size: 0.85em;
}

.tools-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
  gap: 12px;
}

.tool-card {
  display: flex;
  flex-direction: column;
  padding: 15px;
  background: var(--md-default-bg-color);
  border-radius: 6px;
  text-decoration: none;
  color: var(--md-default-fg-color);
  border: 1px solid transparent;
  transition: border-color 0.2s;
}

.tool-card:hover {
  border-color: var(--md-primary-fg-color);
}

.tool-card strong {
  margin-bottom: 4px;
}

.tool-card span {
  font-size: 0.8em;
  color: var(--md-default-fg-color--light);
}
</style>

<script>
const tldData = [
  { tld: '.com', server: 'whois.verisign-grs.com' },
  { tld: '.net', server: 'whois.verisign-grs.com' },
  { tld: '.org', server: 'whois.pir.org' },
  { tld: '.info', server: 'whois.afilias.net' },
  { tld: '.io', server: 'whois.nic.io' },
  { tld: '.co', server: 'whois.nic.co' },
  { tld: '.dev', server: 'whois.nic.google' },
  { tld: '.app', server: 'whois.nic.google' },
  { tld: '.cloud', server: 'whois.nic.cloud' },
  { tld: '.fr', server: 'whois.nic.fr' },
  { tld: '.de', server: 'whois.denic.de' },
  { tld: '.uk', server: 'whois.nic.uk' },
  { tld: '.eu', server: 'whois.eu' },
  { tld: '.nl', server: 'whois.domain-registry.nl' },
  { tld: '.be', server: 'whois.dns.be' },
  { tld: '.ch', server: 'whois.nic.ch' },
  { tld: '.it', server: 'whois.nic.it' },
  { tld: '.es', server: 'whois.nic.es' },
  { tld: '.pl', server: 'whois.dns.pl' },
  { tld: '.ru', server: 'whois.tcinet.ru' },
  { tld: '.jp', server: 'whois.jprs.jp' },
  { tld: '.cn', server: 'whois.cnnic.cn' },
  { tld: '.au', server: 'whois.auda.org.au' },
  { tld: '.ca', server: 'whois.cira.ca' },
  { tld: '.br', server: 'whois.registro.br' },
  { tld: '.mx', server: 'whois.mx' },
  { tld: '.in', server: 'whois.registry.in' },
  { tld: '.kr', server: 'whois.kr' },
  { tld: '.se', server: 'whois.iis.se' },
  { tld: '.no', server: 'whois.norid.no' },
  { tld: '.fi', server: 'whois.fi' },
  { tld: '.dk', server: 'whois.dk-hostmaster.dk' },
  { tld: '.at', server: 'whois.nic.at' },
  { tld: '.nz', server: 'whois.srs.net.nz' },
  { tld: '.me', server: 'whois.nic.me' },
  { tld: '.tv', server: 'whois.nic.tv' },
  { tld: '.ai', server: 'whois.nic.ai' },
  { tld: '.gg', server: 'whois.gg' },
  { tld: '.xyz', server: 'whois.nic.xyz' },
  { tld: '.tech', server: 'whois.nic.tech' },
  { tld: '.online', server: 'whois.nic.online' },
  { tld: '.store', server: 'whois.nic.store' }
];

function updateWhoisCmd() {
  const target = document.getElementById('whoisTarget').value || 'example.com';
  const type = document.getElementById('whoisType').value;

  let cmd = 'whois ';

  switch(type) {
    case 'domain':
      cmd += target;
      break;
    case 'ip':
      cmd += target;
      break;
    case 'asn':
      cmd += `-h whois.radb.net ${target.toUpperCase().startsWith('AS') ? target : 'AS' + target}`;
      break;
    case 'netblock':
      cmd += `-h whois.ripe.net -B ${target}`;
      break;
  }

  document.getElementById('whoisCmd').textContent = cmd;
}

function copyCmd() {
  const cmd = document.getElementById('whoisCmd').textContent;
  navigator.clipboard.writeText(cmd).then(() => {
    const btn = event.target;
    const orig = btn.textContent;
    btn.textContent = '✓';
    setTimeout(() => btn.textContent = orig, 1000);
  });
}

function renderTLDs(data) {
  document.getElementById('tldGrid').innerHTML = data.map(t => `
    <div class="tld-item">
      <span class="tld-name">${t.tld}</span>
      <span class="tld-server">${t.server}</span>
    </div>
  `).join('');
}

function filterTLDs() {
  const search = document.getElementById('tldSearch').value.toLowerCase();
  const filtered = tldData.filter(t =>
    t.tld.toLowerCase().includes(search) ||
    t.server.toLowerCase().includes(search)
  );
  renderTLDs(filtered);
}

// Event listeners
document.getElementById('whoisTarget').addEventListener('input', updateWhoisCmd);

// Initialize
renderTLDs(tldData);
updateWhoisCmd();
</script>

---

## Champs Whois courants

| Champ | Description |
|-------|-------------|
| `Registrar` | Bureau d'enregistrement |
| `Creation Date` | Date de creation |
| `Expiry Date` | Date d'expiration |
| `Name Servers` | Serveurs DNS |
| `Status` | Statut du domaine |
| `DNSSEC` | Securisation DNS |
| `Registrant` | Proprietaire |
| `Admin Contact` | Contact administratif |
| `Tech Contact` | Contact technique |

---

!!! info "RDAP"
    RDAP (Registration Data Access Protocol) remplace progressivement Whois avec un format JSON standardise et HTTPS. Essayez: `curl https://rdap.org/domain/example.com`
