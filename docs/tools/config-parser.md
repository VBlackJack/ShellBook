---
tags:
  - tools
  - parser
  - config
  - analysis
  - documentation
---

# Config Parser & Explainer

Analyseur de fichiers de configuration avec explications visuelles et alertes de securite.

<div id="parser-app">
  <div class="parser-container">
    <div class="input-section">
      <div class="input-header">
        <h3>Configuration a analyser</h3>
        <div class="format-selector">
          <label>Format:</label>
          <select id="configFormat" onchange="parseConfig()">
            <option value="auto">Auto-detect</option>
            <optgroup label="Proxy & Web">
              <option value="squid">Squid (squid.conf)</option>
              <option value="nginx">Nginx (nginx.conf)</option>
              <option value="apache">Apache (httpd.conf)</option>
              <option value="haproxy">HAProxy</option>
            </optgroup>
            <optgroup label="SSH & Securite">
              <option value="sshd">SSHD (sshd_config)</option>
              <option value="ssh_config">SSH Client (ssh_config)</option>
              <option value="sudoers">Sudoers</option>
              <option value="iptables">iptables-save</option>
              <option value="nftables">nftables</option>
              <option value="fail2ban">Fail2Ban jail.conf</option>
            </optgroup>
            <optgroup label="Bases de donnees">
              <option value="postgresql">PostgreSQL (postgresql.conf)</option>
              <option value="mysql">MySQL (my.cnf)</option>
              <option value="redis">Redis (redis.conf)</option>
            </optgroup>
            <optgroup label="LDAP & Annuaires">
              <option value="ldap389">389 DS (dse.ldif / cn=config)</option>
              <option value="slapd">OpenLDAP (slapd.conf)</option>
              <option value="ldif">LDIF generique</option>
            </optgroup>
            <optgroup label="Systeme">
              <option value="systemd">Systemd Unit</option>
              <option value="crontab">Crontab</option>
              <option value="logrotate">Logrotate</option>
              <option value="rsyslog">Rsyslog</option>
              <option value="fstab">fstab</option>
            </optgroup>
            <optgroup label="Reseau">
              <option value="netplan">Netplan (YAML)</option>
              <option value="interfaces">interfaces (Debian)</option>
              <option value="resolv">resolv.conf</option>
              <option value="hosts">hosts</option>
            </optgroup>
            <optgroup label="Conteneurs">
              <option value="dockerfile">Dockerfile</option>
              <option value="compose">Docker Compose</option>
              <option value="kubernetes">Kubernetes YAML</option>
            </optgroup>
          </select>
        </div>
      </div>
      <textarea id="configInput" placeholder="Collez votre fichier de configuration ici..." oninput="parseConfig()"></textarea>
      <div class="examples-bar">
        <span>Exemples:</span>
        <button onclick="loadExample('squid')">Squid</button>
        <button onclick="loadExample('sshd')">SSHD</button>
        <button onclick="loadExample('nginx')">Nginx</button>
        <button onclick="loadExample('crontab')">Crontab</button>
        <button onclick="loadExample('sudoers')">Sudoers</button>
        <button onclick="loadExample('iptables')">iptables</button>
        <button onclick="loadExample('systemd')">Systemd</button>
        <button onclick="loadExample('postgresql')">PostgreSQL</button>
        <button onclick="loadExample('ldap389')">389 DS</button>
        <button onclick="loadExample('slapd')">OpenLDAP</button>
      </div>
    </div>

    <div class="output-section">
      <div class="output-header">
        <h3>Analyse</h3>
        <div class="detected-format">
          <span id="detectedFormat">-</span>
        </div>
        <button onclick="exportMarkdown()">Exporter MD</button>
      </div>
      <div id="analysisOutput">
        <div class="placeholder">
          <p>Collez une configuration pour voir l'analyse</p>
        </div>
      </div>
    </div>
  </div>

  <div class="legend-section">
    <h4>Legende</h4>
    <div class="legend-items">
      <span class="legend-item"><span class="icon security">🔒</span> Securite</span>
      <span class="legend-item"><span class="icon performance">⚡</span> Performance</span>
      <span class="legend-item"><span class="icon network">🌐</span> Reseau</span>
      <span class="legend-item"><span class="icon storage">💾</span> Stockage</span>
      <span class="legend-item"><span class="icon logging">📝</span> Logging</span>
      <span class="legend-item"><span class="icon warning">⚠️</span> Attention</span>
      <span class="legend-item"><span class="icon error">❌</span> Probleme</span>
      <span class="legend-item"><span class="icon good">✅</span> Bonne pratique</span>
      <span class="legend-item"><span class="icon info">ℹ️</span> Info</span>
    </div>
  </div>
</div>

<style>
.parser-container {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 20px;
  min-height: 600px;
}

@media (max-width: 1100px) {
  .parser-container { grid-template-columns: 1fr; }
}

.input-section, .output-section {
  background: var(--md-code-bg-color);
  border-radius: 8px;
  display: flex;
  flex-direction: column;
}

.input-header, .output-header {
  display: flex;
  align-items: center;
  gap: 15px;
  padding: 15px;
  border-bottom: 1px solid var(--md-default-fg-color--lightest);
}

.input-header h3, .output-header h3 {
  margin: 0;
  flex-shrink: 0;
}

.format-selector {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-left: auto;
}

.format-selector label {
  font-size: 0.85em;
  color: var(--md-default-fg-color--light);
}

.format-selector select {
  padding: 6px 10px;
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  background: var(--md-default-bg-color);
  color: var(--md-default-fg-color);
  font-size: 0.85em;
}

#configInput {
  flex: 1;
  width: 100%;
  padding: 15px;
  border: none;
  background: #1e1e1e;
  color: #d4d4d4;
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.85em;
  resize: none;
  min-height: 400px;
}

.examples-bar {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 10px 15px;
  border-top: 1px solid var(--md-default-fg-color--lightest);
  flex-wrap: wrap;
}

.examples-bar span {
  font-size: 0.8em;
  color: var(--md-default-fg-color--light);
}

.examples-bar button {
  padding: 4px 10px;
  font-size: 0.75em;
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 3px;
  background: var(--md-default-bg-color);
  color: var(--md-default-fg-color);
  cursor: pointer;
}

.examples-bar button:hover {
  background: var(--md-primary-fg-color);
  color: white;
  border-color: var(--md-primary-fg-color);
}

.detected-format {
  background: var(--md-primary-fg-color);
  color: white;
  padding: 4px 12px;
  border-radius: 12px;
  font-size: 0.8em;
  font-weight: 500;
}

.output-header button {
  margin-left: auto;
  padding: 6px 12px;
  background: var(--md-primary-fg-color);
  color: white;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  font-size: 0.85em;
}

#analysisOutput {
  flex: 1;
  padding: 15px;
  overflow-y: auto;
  max-height: 500px;
}

.placeholder {
  display: flex;
  align-items: center;
  justify-content: center;
  height: 100%;
  color: var(--md-default-fg-color--light);
}

.analysis-section {
  margin-bottom: 20px;
  background: var(--md-default-bg-color);
  border-radius: 6px;
  overflow: hidden;
}

.section-header {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 12px 15px;
  background: var(--md-code-bg-color);
  font-weight: 600;
  cursor: pointer;
}

.section-header:hover {
  background: var(--md-default-fg-color--lightest);
}

.section-icon {
  font-size: 1.2em;
}

.section-content {
  padding: 10px 15px;
}

.config-item {
  display: flex;
  flex-direction: column;
  padding: 10px 0;
  border-bottom: 1px solid var(--md-default-fg-color--lightest);
}

.config-item:last-child {
  border-bottom: none;
}

.item-header {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 5px;
}

.item-directive {
  font-family: 'JetBrains Mono', monospace;
  font-weight: 600;
  color: var(--md-primary-fg-color);
}

.item-value {
  font-family: 'JetBrains Mono', monospace;
  background: var(--md-code-bg-color);
  padding: 2px 8px;
  border-radius: 3px;
  font-size: 0.9em;
}

.item-badge {
  padding: 2px 8px;
  border-radius: 10px;
  font-size: 0.7em;
  font-weight: 600;
}

.badge-warning { background: #f59e0b; color: #000; }
.badge-error { background: #ef4444; color: #fff; }
.badge-good { background: #22c55e; color: #fff; }
.badge-info { background: #3b82f6; color: #fff; }
.badge-default { background: #6b7280; color: #fff; }

.item-description {
  font-size: 0.85em;
  color: var(--md-default-fg-color--light);
  margin-top: 5px;
  line-height: 1.5;
}

.item-alert {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  margin-top: 8px;
  padding: 8px 12px;
  border-radius: 4px;
  font-size: 0.85em;
}

.alert-warning {
  background: rgba(245, 158, 11, 0.15);
  border-left: 3px solid #f59e0b;
}

.alert-error {
  background: rgba(239, 68, 68, 0.15);
  border-left: 3px solid #ef4444;
}

.alert-good {
  background: rgba(34, 197, 94, 0.15);
  border-left: 3px solid #22c55e;
}

.alert-info {
  background: rgba(59, 130, 246, 0.15);
  border-left: 3px solid #3b82f6;
}

.summary-box {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
  gap: 10px;
  margin-bottom: 20px;
}

.summary-item {
  background: var(--md-default-bg-color);
  padding: 15px;
  border-radius: 6px;
  text-align: center;
}

.summary-value {
  font-size: 1.5em;
  font-weight: 700;
  color: var(--md-primary-fg-color);
}

.summary-label {
  font-size: 0.75em;
  color: var(--md-default-fg-color--light);
  margin-top: 5px;
}

.legend-section {
  background: var(--md-code-bg-color);
  padding: 15px 20px;
  border-radius: 8px;
  margin-top: 20px;
}

.legend-section h4 {
  margin: 0 0 10px 0;
  font-size: 0.9em;
}

.legend-items {
  display: flex;
  flex-wrap: wrap;
  gap: 15px;
}

.legend-item {
  display: flex;
  align-items: center;
  gap: 5px;
  font-size: 0.8em;
  color: var(--md-default-fg-color--light);
}

.cron-visual {
  display: grid;
  grid-template-columns: repeat(5, 1fr);
  gap: 10px;
  margin: 10px 0;
}

.cron-field {
  text-align: center;
  padding: 10px;
  background: var(--md-code-bg-color);
  border-radius: 4px;
}

.cron-field-value {
  font-family: 'JetBrains Mono', monospace;
  font-size: 1.2em;
  font-weight: 700;
  color: var(--md-primary-fg-color);
}

.cron-field-label {
  font-size: 0.7em;
  color: var(--md-default-fg-color--light);
  margin-top: 5px;
}

.cron-human {
  background: var(--md-primary-fg-color);
  color: white;
  padding: 10px 15px;
  border-radius: 4px;
  font-weight: 500;
  text-align: center;
}

.sudoers-visual {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin: 10px 0;
}

.sudoers-part {
  padding: 8px 12px;
  border-radius: 4px;
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.85em;
}

.sudoers-user { background: #3b82f6; color: white; }
.sudoers-host { background: #8b5cf6; color: white; }
.sudoers-runas { background: #ec4899; color: white; }
.sudoers-tag { background: #f59e0b; color: black; }
.sudoers-cmd { background: #22c55e; color: white; }

.tree-view {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.85em;
  line-height: 1.8;
}

.tree-item {
  display: flex;
  align-items: center;
  gap: 8px;
}

.tree-branch {
  color: var(--md-default-fg-color--light);
}

.tree-key {
  color: var(--md-primary-fg-color);
}

.tree-value {
  color: var(--md-default-fg-color);
}
</style>

<script>
// Parser definitions for each config format
const parsers = {

  // ==================== SQUID ====================
  squid: {
    name: 'Squid Proxy',
    detect: (text) => text.includes('http_port') || text.includes('cache_dir') || text.includes('acl ') && text.includes('http_access'),
    parse: (text) => {
      const lines = text.split('\n').filter(l => l.trim() && !l.trim().startsWith('#'));
      const result = {
        network: [], cache: [], acl: [], access: [], auth: [], security: [], logging: [], other: []
      };
      const directives = {
        'http_port': { cat: 'network', icon: '🌐', desc: 'Port d\'ecoute HTTP du proxy' },
        'https_port': { cat: 'network', icon: '🔒', desc: 'Port d\'ecoute HTTPS avec SSL bump' },
        'visible_hostname': { cat: 'network', icon: '🌐', desc: 'Nom d\'hote affiche dans les erreurs' },
        'cache_dir': { cat: 'cache', icon: '💾', desc: 'Repertoire et parametres du cache disque' },
        'cache_mem': { cat: 'cache', icon: '💾', desc: 'Memoire RAM allouee au cache' },
        'maximum_object_size': { cat: 'cache', icon: '💾', desc: 'Taille max des objets en cache' },
        'acl': { cat: 'acl', icon: '📋', desc: 'Definition d\'une liste de controle d\'acces' },
        'http_access': { cat: 'access', icon: '🚦', desc: 'Regle d\'autorisation/refus d\'acces' },
        'auth_param': { cat: 'auth', icon: '🔐', desc: 'Parametre d\'authentification' },
        'ssl_bump': { cat: 'security', icon: '🔒', desc: 'Interception SSL/TLS' },
        'access_log': { cat: 'logging', icon: '📝', desc: 'Configuration des logs d\'acces' },
        'cache_log': { cat: 'logging', icon: '📝', desc: 'Fichier de log du cache' },
        'forwarded_for': { cat: 'security', icon: '🔒', desc: 'Header X-Forwarded-For' },
        'via': { cat: 'security', icon: '🔒', desc: 'Header Via' },
        'refresh_pattern': { cat: 'cache', icon: '💾', desc: 'Regles de rafraichissement du cache' },
      };

      lines.forEach(line => {
        const parts = line.trim().split(/\s+/);
        const directive = parts[0];
        const value = parts.slice(1).join(' ');
        const info = directives[directive] || { cat: 'other', icon: 'ℹ️', desc: 'Directive Squid' };

        let alerts = [];
        if (directive === 'http_port' && value.includes('intercept')) {
          alerts.push({ type: 'info', text: 'Mode transparent - necessite regles iptables' });
        }
        if (directive === 'http_access' && value === 'allow all') {
          alerts.push({ type: 'error', text: 'Proxy ouvert a tous - risque de securite majeur!' });
        }
        if (directive === 'forwarded_for' && value === 'delete') {
          alerts.push({ type: 'good', text: 'Bonne pratique: IP client masquee' });
        }

        result[info.cat].push({
          directive, value, icon: info.icon, desc: info.desc, alerts, raw: line
        });
      });

      return result;
    },
    render: (data) => renderStandardConfig(data, 'Squid Proxy')
  },

  // ==================== SSHD ====================
  sshd: {
    name: 'SSHD Config',
    detect: (text) => text.includes('PermitRootLogin') || text.includes('PubkeyAuthentication') || text.includes('PasswordAuthentication'),
    parse: (text) => {
      const lines = text.split('\n').filter(l => l.trim() && !l.trim().startsWith('#'));
      const result = {
        auth: [], network: [], security: [], session: [], other: []
      };
      const directives = {
        'Port': { cat: 'network', icon: '🌐', desc: 'Port d\'ecoute SSH', secure: (v) => v !== '22' ? 'good' : 'info' },
        'ListenAddress': { cat: 'network', icon: '🌐', desc: 'Adresse d\'ecoute' },
        'PermitRootLogin': { cat: 'security', icon: '🔒', desc: 'Connexion root autorisee', secure: (v) => v === 'no' ? 'good' : v === 'yes' ? 'error' : 'warning' },
        'PubkeyAuthentication': { cat: 'auth', icon: '🔑', desc: 'Authentification par cle publique', secure: (v) => v === 'yes' ? 'good' : 'warning' },
        'PasswordAuthentication': { cat: 'auth', icon: '🔐', desc: 'Authentification par mot de passe', secure: (v) => v === 'no' ? 'good' : 'warning' },
        'PermitEmptyPasswords': { cat: 'security', icon: '🔒', desc: 'Mots de passe vides autorises', secure: (v) => v === 'no' ? 'good' : 'error' },
        'X11Forwarding': { cat: 'session', icon: '🖥️', desc: 'Redirection X11', secure: (v) => v === 'no' ? 'good' : 'info' },
        'AllowUsers': { cat: 'security', icon: '👥', desc: 'Utilisateurs autorises (whitelist)' },
        'AllowGroups': { cat: 'security', icon: '👥', desc: 'Groupes autorises (whitelist)' },
        'DenyUsers': { cat: 'security', icon: '🚫', desc: 'Utilisateurs refuses (blacklist)' },
        'MaxAuthTries': { cat: 'security', icon: '🔒', desc: 'Nombre max de tentatives', secure: (v) => parseInt(v) <= 3 ? 'good' : 'warning' },
        'ClientAliveInterval': { cat: 'session', icon: '⏱️', desc: 'Intervalle keepalive client' },
        'ClientAliveCountMax': { cat: 'session', icon: '⏱️', desc: 'Nombre max de keepalive sans reponse' },
        'LoginGraceTime': { cat: 'security', icon: '⏱️', desc: 'Temps max pour s\'authentifier' },
        'Protocol': { cat: 'security', icon: '🔒', desc: 'Version du protocole SSH', secure: (v) => v === '2' ? 'good' : 'error' },
        'Ciphers': { cat: 'security', icon: '🔐', desc: 'Algorithmes de chiffrement autorises' },
        'MACs': { cat: 'security', icon: '🔐', desc: 'Algorithmes MAC autorises' },
        'KexAlgorithms': { cat: 'security', icon: '🔐', desc: 'Algorithmes d\'echange de cles' },
        'UsePAM': { cat: 'auth', icon: '🔐', desc: 'Utilisation de PAM' },
        'Banner': { cat: 'session', icon: '📜', desc: 'Banniere affichee avant login' },
      };

      lines.forEach(line => {
        const match = line.match(/^(\w+)\s+(.+)$/);
        if (!match) return;
        const [, directive, value] = match;
        const info = directives[directive] || { cat: 'other', icon: 'ℹ️', desc: 'Directive SSHD' };

        let alerts = [];
        let badge = null;
        if (info.secure) {
          const level = info.secure(value);
          badge = level;
          if (level === 'error') alerts.push({ type: 'error', text: 'Configuration non securisee!' });
          if (level === 'good') alerts.push({ type: 'good', text: 'Bonne pratique de securite' });
        }

        result[info.cat].push({
          directive, value, icon: info.icon, desc: info.desc, alerts, badge, raw: line
        });
      });

      return result;
    },
    render: (data) => renderStandardConfig(data, 'SSHD Config')
  },

  // ==================== CRONTAB ====================
  crontab: {
    name: 'Crontab',
    detect: (text) => {
      const lines = text.split('\n').filter(l => l.trim() && !l.trim().startsWith('#'));
      return lines.some(l => /^[\d\*\/\-\,]+\s+[\d\*\/\-\,]+\s+[\d\*\/\-\,]+\s+[\d\*\/\-\,]+\s+[\d\*\/\-\,]+\s+/.test(l));
    },
    parse: (text) => {
      const lines = text.split('\n');
      const entries = [];
      const variables = [];

      lines.forEach((line, idx) => {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) return;

        // Variable (SHELL=, PATH=, MAILTO=)
        if (/^[A-Z_]+=/.test(trimmed)) {
          const [name, ...rest] = trimmed.split('=');
          variables.push({ name, value: rest.join('='), line: idx + 1 });
          return;
        }

        // Cron entry
        const match = trimmed.match(/^([\d\*\/\-\,]+)\s+([\d\*\/\-\,]+)\s+([\d\*\/\-\,]+)\s+([\d\*\/\-\,]+)\s+([\d\*\/\-\,]+)\s+(.+)$/);
        if (match) {
          const [, min, hour, dom, month, dow, cmd] = match;
          entries.push({
            minute: min, hour, dayOfMonth: dom, month, dayOfWeek: dow,
            command: cmd, line: idx + 1, raw: line,
            human: cronToHuman(min, hour, dom, month, dow)
          });
        }

        // Special syntax (@reboot, @daily, etc)
        const specialMatch = trimmed.match(/^@(reboot|yearly|annually|monthly|weekly|daily|midnight|hourly)\s+(.+)$/);
        if (specialMatch) {
          const [, special, cmd] = specialMatch;
          const specials = {
            reboot: 'Au demarrage du systeme',
            yearly: 'Une fois par an (1er janvier a minuit)',
            annually: 'Une fois par an (1er janvier a minuit)',
            monthly: 'Une fois par mois (1er du mois a minuit)',
            weekly: 'Une fois par semaine (dimanche a minuit)',
            daily: 'Une fois par jour (a minuit)',
            midnight: 'Une fois par jour (a minuit)',
            hourly: 'Une fois par heure'
          };
          entries.push({
            special, command: cmd, line: idx + 1, raw: line,
            human: specials[special] || special
          });
        }
      });

      return { entries, variables };
    },
    render: (data) => {
      let html = '<div class="summary-box">';
      html += `<div class="summary-item"><div class="summary-value">${data.entries.length}</div><div class="summary-label">Taches planifiees</div></div>`;
      html += `<div class="summary-item"><div class="summary-value">${data.variables.length}</div><div class="summary-label">Variables</div></div>`;
      html += '</div>';

      if (data.variables.length > 0) {
        html += '<div class="analysis-section"><div class="section-header"><span class="section-icon">⚙️</span> Variables d\'environnement</div>';
        html += '<div class="section-content">';
        data.variables.forEach(v => {
          html += `<div class="config-item">
            <div class="item-header">
              <span class="item-directive">${v.name}</span>
              <span class="item-value">${escapeHtml(v.value)}</span>
            </div>
          </div>`;
        });
        html += '</div></div>';
      }

      html += '<div class="analysis-section"><div class="section-header"><span class="section-icon">⏰</span> Taches planifiees</div>';
      html += '<div class="section-content">';

      data.entries.forEach(entry => {
        html += '<div class="config-item">';

        if (entry.special) {
          html += `<div class="item-header">
            <span class="item-badge badge-info">@${entry.special}</span>
          </div>`;
        } else {
          html += '<div class="cron-visual">';
          html += `<div class="cron-field"><div class="cron-field-value">${entry.minute}</div><div class="cron-field-label">Minute</div></div>`;
          html += `<div class="cron-field"><div class="cron-field-value">${entry.hour}</div><div class="cron-field-label">Heure</div></div>`;
          html += `<div class="cron-field"><div class="cron-field-value">${entry.dayOfMonth}</div><div class="cron-field-label">Jour (mois)</div></div>`;
          html += `<div class="cron-field"><div class="cron-field-value">${entry.month}</div><div class="cron-field-label">Mois</div></div>`;
          html += `<div class="cron-field"><div class="cron-field-value">${entry.dayOfWeek}</div><div class="cron-field-label">Jour (sem)</div></div>`;
          html += '</div>';
        }

        html += `<div class="cron-human">📅 ${entry.human}</div>`;
        html += `<div class="item-header" style="margin-top:10px;">
          <span class="section-icon">💻</span>
          <code class="item-value" style="flex:1;">${escapeHtml(entry.command)}</code>
        </div>`;

        // Alerts
        if (entry.command.includes('rm -rf')) {
          html += '<div class="item-alert alert-warning">⚠️ Commande de suppression recursive - verifiez le chemin!</div>';
        }
        if (entry.command.includes('> /dev/null')) {
          html += '<div class="item-alert alert-info">ℹ️ Sortie redirigee vers /dev/null - pas de logs</div>';
        }
        if (!entry.command.includes('2>&1') && !entry.command.includes('> /dev/null')) {
          html += '<div class="item-alert alert-info">ℹ️ stderr non redirige - les erreurs seront envoyees par mail</div>';
        }

        html += '</div>';
      });

      html += '</div></div>';
      return html;
    }
  },

  // ==================== SUDOERS ====================
  sudoers: {
    name: 'Sudoers',
    detect: (text) => text.includes('ALL=(ALL)') || text.includes('NOPASSWD') || /^\w+\s+ALL=/.test(text) || text.includes('Defaults'),
    parse: (text) => {
      const lines = text.split('\n').filter(l => l.trim() && !l.trim().startsWith('#'));
      const defaults = [];
      const aliases = { user: [], host: [], cmnd: [], runas: [] };
      const rules = [];

      lines.forEach((line, idx) => {
        const trimmed = line.trim();

        // Defaults
        if (trimmed.startsWith('Defaults')) {
          const value = trimmed.replace(/^Defaults\s*/, '');
          let desc = 'Option par defaut';
          let alert = null;

          if (value.includes('env_reset')) desc = 'Reinitialise les variables d\'environnement';
          if (value.includes('mail_badpass')) desc = 'Envoie un mail en cas de mauvais mot de passe';
          if (value.includes('secure_path')) desc = 'PATH securise pour les commandes sudo';
          if (value.includes('timestamp_timeout')) {
            desc = 'Duree de validite du mot de passe sudo (minutes)';
            const timeout = value.match(/timestamp_timeout=(\d+)/);
            if (timeout && parseInt(timeout[1]) > 15) {
              alert = { type: 'warning', text: 'Timeout eleve - le mot de passe reste en cache longtemps' };
            }
          }
          if (value.includes('!requiretty')) {
            alert = { type: 'info', text: 'Permet sudo sans terminal (scripts, cron)' };
          }

          defaults.push({ value, desc, alert, line: idx + 1 });
          return;
        }

        // Aliases
        const aliasMatch = trimmed.match(/^(User_Alias|Host_Alias|Cmnd_Alias|Runas_Alias)\s+(\w+)\s*=\s*(.+)$/);
        if (aliasMatch) {
          const [, type, name, members] = aliasMatch;
          const cat = type.split('_')[0].toLowerCase();
          aliases[cat].push({ name, members: members.split(',').map(m => m.trim()), line: idx + 1 });
          return;
        }

        // User rules
        const ruleMatch = trimmed.match(/^([%\w,\s]+)\s+([\w,\s]+)\s*=\s*(.+)$/);
        if (ruleMatch) {
          const [, users, hosts, rest] = ruleMatch;

          // Parse (runas) and commands
          const runasMatch = rest.match(/^\(([^)]+)\)\s*(.+)$/);
          let runas = 'root';
          let commands = rest;

          if (runasMatch) {
            runas = runasMatch[1];
            commands = runasMatch[2];
          }

          // Check for tags (NOPASSWD, NOEXEC, etc)
          const tags = [];
          const tagMatch = commands.match(/^((?:NOPASSWD|PASSWD|NOEXEC|EXEC|SETENV|NOSETENV):\s*)+/);
          if (tagMatch) {
            tagMatch[0].split(':').filter(t => t.trim()).forEach(t => tags.push(t.trim()));
            commands = commands.replace(tagMatch[0], '');
          }

          let alerts = [];
          if (tags.includes('NOPASSWD') && commands.includes('ALL')) {
            alerts.push({ type: 'error', text: 'NOPASSWD avec ALL - acces root complet sans mot de passe!' });
          } else if (tags.includes('NOPASSWD')) {
            alerts.push({ type: 'warning', text: 'NOPASSWD - pas de mot de passe requis pour ces commandes' });
          }
          if (commands.trim() === 'ALL') {
            alerts.push({ type: 'warning', text: 'Acces a TOUTES les commandes' });
          }
          if (users.includes('%')) {
            alerts.push({ type: 'info', text: 'Regle basee sur un groupe (%)' });
          }

          rules.push({
            users: users.split(',').map(u => u.trim()),
            hosts: hosts.split(',').map(h => h.trim()),
            runas,
            tags,
            commands: commands.split(',').map(c => c.trim()),
            alerts,
            line: idx + 1,
            raw: line
          });
        }
      });

      return { defaults, aliases, rules };
    },
    render: (data) => {
      let html = '<div class="summary-box">';
      html += `<div class="summary-item"><div class="summary-value">${data.rules.length}</div><div class="summary-label">Regles</div></div>`;
      html += `<div class="summary-item"><div class="summary-value">${data.defaults.length}</div><div class="summary-label">Defaults</div></div>`;
      const totalAliases = data.aliases.user.length + data.aliases.host.length + data.aliases.cmnd.length;
      html += `<div class="summary-item"><div class="summary-value">${totalAliases}</div><div class="summary-label">Aliases</div></div>`;
      const nopasswd = data.rules.filter(r => r.tags.includes('NOPASSWD')).length;
      html += `<div class="summary-item"><div class="summary-value" style="color:${nopasswd > 0 ? '#f59e0b' : '#22c55e'}">${nopasswd}</div><div class="summary-label">NOPASSWD</div></div>`;
      html += '</div>';

      // Defaults
      if (data.defaults.length > 0) {
        html += '<div class="analysis-section"><div class="section-header"><span class="section-icon">⚙️</span> Defaults</div>';
        html += '<div class="section-content">';
        data.defaults.forEach(d => {
          html += `<div class="config-item">
            <div class="item-header">
              <span class="item-directive">Defaults</span>
              <span class="item-value">${escapeHtml(d.value)}</span>
            </div>
            <div class="item-description">${d.desc}</div>
            ${d.alert ? `<div class="item-alert alert-${d.alert.type}">${d.alert.type === 'warning' ? '⚠️' : 'ℹ️'} ${d.alert.text}</div>` : ''}
          </div>`;
        });
        html += '</div></div>';
      }

      // Aliases
      const aliasTypes = [
        { key: 'user', name: 'User_Alias', icon: '👤' },
        { key: 'host', name: 'Host_Alias', icon: '🖥️' },
        { key: 'cmnd', name: 'Cmnd_Alias', icon: '💻' },
        { key: 'runas', name: 'Runas_Alias', icon: '👥' }
      ];

      aliasTypes.forEach(at => {
        if (data.aliases[at.key].length > 0) {
          html += `<div class="analysis-section"><div class="section-header"><span class="section-icon">${at.icon}</span> ${at.name}</div>`;
          html += '<div class="section-content">';
          data.aliases[at.key].forEach(a => {
            html += `<div class="config-item">
              <div class="item-header">
                <span class="item-directive">${a.name}</span>
                <span class="item-value">${escapeHtml(a.members.join(', '))}</span>
              </div>
            </div>`;
          });
          html += '</div></div>';
        }
      });

      // Rules
      html += '<div class="analysis-section"><div class="section-header"><span class="section-icon">📜</span> Regles d\'autorisation</div>';
      html += '<div class="section-content">';

      data.rules.forEach(rule => {
        html += '<div class="config-item">';
        html += '<div class="sudoers-visual">';
        rule.users.forEach(u => {
          html += `<span class="sudoers-part sudoers-user" title="Utilisateur/Groupe">${escapeHtml(u)}</span>`;
        });
        rule.hosts.forEach(h => {
          html += `<span class="sudoers-part sudoers-host" title="Hote">${escapeHtml(h)}</span>`;
        });
        html += `<span class="sudoers-part sudoers-runas" title="Executer en tant que">(${escapeHtml(rule.runas)})</span>`;
        rule.tags.forEach(t => {
          html += `<span class="sudoers-part sudoers-tag" title="Tag">${escapeHtml(t)}</span>`;
        });
        html += '</div>';

        html += '<div style="margin-top:10px;">';
        rule.commands.forEach(cmd => {
          html += `<div class="item-header">
            <span class="sudoers-part sudoers-cmd">${escapeHtml(cmd)}</span>
          </div>`;
        });
        html += '</div>';

        rule.alerts.forEach(a => {
          html += `<div class="item-alert alert-${a.type}">${a.type === 'error' ? '❌' : a.type === 'warning' ? '⚠️' : 'ℹ️'} ${a.text}</div>`;
        });

        html += '</div>';
      });

      html += '</div></div>';
      return html;
    }
  },

  // ==================== NGINX ====================
  nginx: {
    name: 'Nginx',
    detect: (text) => text.includes('server {') || text.includes('location ') || text.includes('upstream ') || text.includes('worker_processes'),
    parse: (text) => {
      const result = {
        global: [], http: [], servers: [], upstreams: [], security: []
      };

      // Simple line-by-line parsing for key directives
      const lines = text.split('\n');
      let currentServer = null;
      let braceCount = 0;
      let inServer = false;
      let inLocation = false;

      const globalDirectives = ['worker_processes', 'worker_connections', 'error_log', 'pid', 'user'];
      const securityDirectives = ['ssl_protocols', 'ssl_ciphers', 'ssl_certificate', 'add_header', 'server_tokens'];

      lines.forEach(line => {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) return;

        // Track braces
        braceCount += (trimmed.match(/{/g) || []).length;
        braceCount -= (trimmed.match(/}/g) || []).length;

        // Server block detection
        if (trimmed.startsWith('server {') || trimmed === 'server {') {
          inServer = true;
          currentServer = { listen: [], server_name: [], locations: [], ssl: false, root: '', alerts: [] };
          return;
        }

        if (inServer && braceCount === 1 && trimmed === '}') {
          result.servers.push(currentServer);
          inServer = false;
          currentServer = null;
          return;
        }

        // Inside server block
        if (inServer && currentServer) {
          if (trimmed.startsWith('listen ')) {
            const port = trimmed.replace('listen ', '').replace(';', '');
            currentServer.listen.push(port);
            if (port.includes('ssl') || port.includes('443')) currentServer.ssl = true;
          }
          if (trimmed.startsWith('server_name ')) {
            currentServer.server_name = trimmed.replace('server_name ', '').replace(';', '').split(/\s+/);
          }
          if (trimmed.startsWith('root ')) {
            currentServer.root = trimmed.replace('root ', '').replace(';', '');
          }
          if (trimmed.startsWith('location ')) {
            const loc = trimmed.match(/location\s+([^\s{]+)/);
            if (loc) currentServer.locations.push(loc[1]);
          }
          if (trimmed.includes('proxy_pass')) {
            currentServer.proxy = true;
          }
        }

        // Global directives
        globalDirectives.forEach(dir => {
          if (trimmed.startsWith(dir + ' ')) {
            result.global.push({
              directive: dir,
              value: trimmed.replace(dir + ' ', '').replace(';', ''),
              icon: dir === 'worker_processes' ? '⚙️' : dir.includes('log') ? '📝' : '🔧'
            });
          }
        });

        // Security
        securityDirectives.forEach(dir => {
          if (trimmed.startsWith(dir + ' ') || trimmed.includes(dir)) {
            const value = trimmed.replace(dir + ' ', '').replace(';', '');
            let alert = null;
            if (dir === 'server_tokens' && value === 'off') {
              alert = { type: 'good', text: 'Version Nginx masquee' };
            }
            if (dir === 'ssl_protocols' && value.includes('TLSv1 ') && !value.includes('TLSv1.')) {
              alert = { type: 'warning', text: 'TLSv1.0 est obsolete' };
            }
            result.security.push({ directive: dir, value, icon: '🔒', alert });
          }
        });
      });

      return result;
    },
    render: (data) => {
      let html = '<div class="summary-box">';
      html += `<div class="summary-item"><div class="summary-value">${data.servers.length}</div><div class="summary-label">Server blocks</div></div>`;
      html += `<div class="summary-item"><div class="summary-value">${data.servers.filter(s => s.ssl).length}</div><div class="summary-label">HTTPS</div></div>`;
      html += `<div class="summary-item"><div class="summary-value">${data.servers.filter(s => s.proxy).length}</div><div class="summary-label">Reverse Proxy</div></div>`;
      html += `<div class="summary-item"><div class="summary-value">${data.security.length}</div><div class="summary-label">Directives secu</div></div>`;
      html += '</div>';

      // Global
      if (data.global.length > 0) {
        html += '<div class="analysis-section"><div class="section-header"><span class="section-icon">⚙️</span> Configuration globale</div>';
        html += '<div class="section-content">';
        data.global.forEach(d => {
          html += `<div class="config-item"><div class="item-header">
            <span class="section-icon">${d.icon}</span>
            <span class="item-directive">${d.directive}</span>
            <span class="item-value">${escapeHtml(d.value)}</span>
          </div></div>`;
        });
        html += '</div></div>';
      }

      // Servers
      data.servers.forEach((server, idx) => {
        const names = server.server_name.join(', ') || 'default';
        const ports = server.listen.join(', ');
        html += `<div class="analysis-section"><div class="section-header">
          <span class="section-icon">${server.ssl ? '🔒' : '🌐'}</span>
          Server: ${escapeHtml(names)}
          <span class="item-badge badge-info">${ports}</span>
          ${server.proxy ? '<span class="item-badge badge-warning">Proxy</span>' : ''}
        </div>`;
        html += '<div class="section-content">';

        if (server.root) {
          html += `<div class="config-item"><div class="item-header">
            <span class="item-directive">root</span>
            <span class="item-value">${escapeHtml(server.root)}</span>
          </div></div>`;
        }

        if (server.locations.length > 0) {
          html += `<div class="config-item"><div class="item-header">
            <span class="item-directive">locations</span>
          </div>
          <div class="item-description">${server.locations.map(l => `<code>${escapeHtml(l)}</code>`).join(' ')}</div>
          </div>`;
        }

        html += '</div></div>';
      });

      // Security
      if (data.security.length > 0) {
        html += '<div class="analysis-section"><div class="section-header"><span class="section-icon">🔒</span> Securite</div>';
        html += '<div class="section-content">';
        data.security.forEach(d => {
          html += `<div class="config-item"><div class="item-header">
            <span class="item-directive">${d.directive}</span>
            <span class="item-value">${escapeHtml(d.value.substring(0, 60))}${d.value.length > 60 ? '...' : ''}</span>
          </div>
          ${d.alert ? `<div class="item-alert alert-${d.alert.type}">${d.alert.type === 'good' ? '✅' : '⚠️'} ${d.alert.text}</div>` : ''}
          </div>`;
        });
        html += '</div></div>';
      }

      return html;
    }
  },

  // ==================== IPTABLES ====================
  iptables: {
    name: 'iptables',
    detect: (text) => text.includes('-A INPUT') || text.includes('-A OUTPUT') || text.includes('-A FORWARD') || text.includes('*filter') || text.includes('-j ACCEPT') || text.includes('-j DROP'),
    parse: (text) => {
      const lines = text.split('\n').filter(l => l.trim() && !l.trim().startsWith('#'));
      const rules = { filter: { INPUT: [], OUTPUT: [], FORWARD: [] }, nat: { PREROUTING: [], POSTROUTING: [], OUTPUT: [] } };
      let currentTable = 'filter';

      lines.forEach(line => {
        const trimmed = line.trim();

        // Table switch
        if (trimmed.startsWith('*')) {
          currentTable = trimmed.substring(1);
          return;
        }

        // Chain policy
        if (trimmed.startsWith(':')) {
          const match = trimmed.match(/^:(\w+)\s+(\w+)/);
          if (match && rules[currentTable]) {
            const [, chain, policy] = match;
            if (!rules[currentTable][chain]) rules[currentTable][chain] = [];
            rules[currentTable][chain].policy = policy;
          }
          return;
        }

        // Rules
        if (trimmed.startsWith('-A ')) {
          const chainMatch = trimmed.match(/^-A\s+(\w+)\s+(.+)$/);
          if (chainMatch) {
            const [, chain, rest] = chainMatch;
            if (!rules[currentTable]) rules[currentTable] = {};
            if (!rules[currentTable][chain]) rules[currentTable][chain] = [];

            const rule = { raw: trimmed };

            // Parse common options
            const protoMatch = rest.match(/-p\s+(\w+)/);
            if (protoMatch) rule.protocol = protoMatch[1];

            const sportMatch = rest.match(/--sport\s+(\S+)/);
            if (sportMatch) rule.sport = sportMatch[1];

            const dportMatch = rest.match(/--dport\s+(\S+)/);
            if (dportMatch) rule.dport = dportMatch[1];

            const srcMatch = rest.match(/-s\s+(\S+)/);
            if (srcMatch) rule.source = srcMatch[1];

            const dstMatch = rest.match(/-d\s+(\S+)/);
            if (dstMatch) rule.dest = dstMatch[1];

            const ifaceInMatch = rest.match(/-i\s+(\S+)/);
            if (ifaceInMatch) rule.iface_in = ifaceInMatch[1];

            const ifaceOutMatch = rest.match(/-o\s+(\S+)/);
            if (ifaceOutMatch) rule.iface_out = ifaceOutMatch[1];

            const stateMatch = rest.match(/--state\s+(\S+)/);
            if (stateMatch) rule.state = stateMatch[1];

            const targetMatch = rest.match(/-j\s+(\w+)/);
            if (targetMatch) rule.target = targetMatch[1];

            const commentMatch = rest.match(/--comment\s+"([^"]+)"/);
            if (commentMatch) rule.comment = commentMatch[1];

            rules[currentTable][chain].push(rule);
          }
        }
      });

      return rules;
    },
    render: (data) => {
      let html = '';
      let totalRules = 0;
      let accepts = 0;
      let drops = 0;

      Object.values(data).forEach(table => {
        Object.values(table).forEach(chain => {
          if (Array.isArray(chain)) {
            totalRules += chain.length;
            chain.forEach(r => {
              if (r.target === 'ACCEPT') accepts++;
              if (r.target === 'DROP' || r.target === 'REJECT') drops++;
            });
          }
        });
      });

      html += '<div class="summary-box">';
      html += `<div class="summary-item"><div class="summary-value">${totalRules}</div><div class="summary-label">Regles</div></div>`;
      html += `<div class="summary-item"><div class="summary-value" style="color:#22c55e">${accepts}</div><div class="summary-label">ACCEPT</div></div>`;
      html += `<div class="summary-item"><div class="summary-value" style="color:#ef4444">${drops}</div><div class="summary-label">DROP/REJECT</div></div>`;
      html += '</div>';

      Object.entries(data).forEach(([tableName, table]) => {
        Object.entries(table).forEach(([chainName, chain]) => {
          if (!Array.isArray(chain) || chain.length === 0) return;

          const policy = chain.policy || 'ACCEPT';
          const policyClass = policy === 'DROP' ? 'badge-error' : policy === 'ACCEPT' ? 'badge-good' : 'badge-info';

          html += `<div class="analysis-section"><div class="section-header">
            <span class="section-icon">🔥</span>
            ${tableName} / ${chainName}
            <span class="item-badge ${policyClass}">Policy: ${policy}</span>
          </div>`;
          html += '<div class="section-content">';

          chain.forEach((rule, idx) => {
            if (typeof rule !== 'object') return;

            const targetClass = rule.target === 'ACCEPT' ? 'badge-good' :
                               rule.target === 'DROP' || rule.target === 'REJECT' ? 'badge-error' : 'badge-info';

            html += '<div class="config-item">';
            html += `<div class="item-header">
              <span style="color:var(--md-default-fg-color--light)">#${idx + 1}</span>
              ${rule.target ? `<span class="item-badge ${targetClass}">${rule.target}</span>` : ''}
              ${rule.protocol ? `<span class="item-badge badge-info">${rule.protocol}</span>` : ''}
              ${rule.dport ? `<span class="item-badge badge-warning">port ${rule.dport}</span>` : ''}
            </div>`;

            let details = [];
            if (rule.source) details.push(`Source: ${rule.source}`);
            if (rule.dest) details.push(`Dest: ${rule.dest}`);
            if (rule.iface_in) details.push(`In: ${rule.iface_in}`);
            if (rule.iface_out) details.push(`Out: ${rule.iface_out}`);
            if (rule.state) details.push(`State: ${rule.state}`);
            if (rule.comment) details.push(`"${rule.comment}"`);

            if (details.length > 0) {
              html += `<div class="item-description">${details.join(' | ')}</div>`;
            }

            html += `<code style="font-size:0.75em;color:var(--md-default-fg-color--light);display:block;margin-top:5px;">${escapeHtml(rule.raw)}</code>`;
            html += '</div>';
          });

          html += '</div></div>';
        });
      });

      return html;
    }
  },

  // ==================== SYSTEMD ====================
  systemd: {
    name: 'Systemd Unit',
    detect: (text) => text.includes('[Unit]') || text.includes('[Service]') || text.includes('[Install]') || text.includes('[Timer]'),
    parse: (text) => {
      const sections = {};
      let currentSection = null;

      text.split('\n').forEach(line => {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith(';')) return;

        const sectionMatch = trimmed.match(/^\[(\w+)\]$/);
        if (sectionMatch) {
          currentSection = sectionMatch[1];
          sections[currentSection] = [];
          return;
        }

        if (currentSection) {
          const kvMatch = trimmed.match(/^(\w+)=(.*)$/);
          if (kvMatch) {
            const [, key, value] = kvMatch;
            sections[currentSection].push({ key, value });
          }
        }
      });

      return sections;
    },
    render: (data) => {
      const sectionInfo = {
        Unit: { icon: '📦', desc: 'Metadonnees et dependances' },
        Service: { icon: '⚙️', desc: 'Configuration du service' },
        Install: { icon: '📥', desc: 'Installation et activation' },
        Timer: { icon: '⏱️', desc: 'Planification (timer unit)' },
        Socket: { icon: '🔌', desc: 'Configuration socket' },
        Mount: { icon: '💾', desc: 'Point de montage' },
        Path: { icon: '📁', desc: 'Surveillance de chemin' }
      };

      const keyInfo = {
        Description: 'Description du service',
        After: 'Demarre apres ces unites',
        Before: 'Demarre avant ces unites',
        Requires: 'Dependances obligatoires',
        Wants: 'Dependances optionnelles',
        ExecStart: 'Commande de demarrage',
        ExecStop: 'Commande d\'arret',
        ExecReload: 'Commande de rechargement',
        Restart: 'Politique de redemarrage',
        RestartSec: 'Delai avant redemarrage',
        User: 'Utilisateur d\'execution',
        Group: 'Groupe d\'execution',
        WorkingDirectory: 'Repertoire de travail',
        Environment: 'Variable d\'environnement',
        EnvironmentFile: 'Fichier de variables',
        Type: 'Type de service (simple, forking, oneshot...)',
        WantedBy: 'Cible d\'installation',
        RequiredBy: 'Requis par ces unites',
        OnCalendar: 'Planification calendaire',
        OnBootSec: 'Delai apres boot',
        Persistent: 'Rattraper les executions manquees'
      };

      let html = '<div class="summary-box">';
      html += `<div class="summary-item"><div class="summary-value">${Object.keys(data).length}</div><div class="summary-label">Sections</div></div>`;
      const totalKeys = Object.values(data).reduce((acc, arr) => acc + arr.length, 0);
      html += `<div class="summary-item"><div class="summary-value">${totalKeys}</div><div class="summary-label">Directives</div></div>`;
      const unitType = data.Timer ? 'Timer' : data.Socket ? 'Socket' : data.Mount ? 'Mount' : 'Service';
      html += `<div class="summary-item"><div class="summary-value">${unitType}</div><div class="summary-label">Type</div></div>`;
      html += '</div>';

      Object.entries(data).forEach(([section, items]) => {
        const info = sectionInfo[section] || { icon: '📄', desc: 'Section' };

        html += `<div class="analysis-section"><div class="section-header">
          <span class="section-icon">${info.icon}</span>
          [${section}]
        </div>`;
        html += '<div class="section-content">';

        items.forEach(item => {
          const desc = keyInfo[item.key] || 'Directive systemd';
          let alert = null;

          if (item.key === 'Restart' && item.value === 'always') {
            alert = { type: 'good', text: 'Le service redemarrera automatiquement en cas d\'echec' };
          }
          if (item.key === 'User' && item.value === 'root') {
            alert = { type: 'warning', text: 'Service execute en root - verifiez si necessaire' };
          }

          html += `<div class="config-item">
            <div class="item-header">
              <span class="item-directive">${item.key}</span>
              <span class="item-value">${escapeHtml(item.value.substring(0, 80))}${item.value.length > 80 ? '...' : ''}</span>
            </div>
            <div class="item-description">${desc}</div>
            ${alert ? `<div class="item-alert alert-${alert.type}">${alert.type === 'good' ? '✅' : '⚠️'} ${alert.text}</div>` : ''}
          </div>`;
        });

        html += '</div></div>';
      });

      return html;
    }
  },

  // ==================== POSTGRESQL ====================
  postgresql: {
    name: 'PostgreSQL',
    detect: (text) => text.includes('shared_buffers') || text.includes('work_mem') || text.includes('max_connections') || text.includes('wal_level'),
    parse: (text) => {
      const lines = text.split('\n').filter(l => l.trim() && !l.trim().startsWith('#'));
      const result = {
        connections: [], memory: [], wal: [], logging: [], security: [], performance: [], other: []
      };

      const directives = {
        'max_connections': { cat: 'connections', icon: '🔌', desc: 'Nombre maximum de connexions simultanees' },
        'listen_addresses': { cat: 'connections', icon: '🌐', desc: 'Adresses d\'ecoute' },
        'port': { cat: 'connections', icon: '🌐', desc: 'Port d\'ecoute' },
        'shared_buffers': { cat: 'memory', icon: '💾', desc: 'Memoire partagee pour le cache (25% RAM recommande)' },
        'work_mem': { cat: 'memory', icon: '💾', desc: 'Memoire par operation de tri/hash' },
        'maintenance_work_mem': { cat: 'memory', icon: '💾', desc: 'Memoire pour VACUUM, CREATE INDEX' },
        'effective_cache_size': { cat: 'memory', icon: '💾', desc: 'Estimation du cache OS disponible' },
        'wal_level': { cat: 'wal', icon: '📝', desc: 'Niveau de journalisation WAL' },
        'max_wal_size': { cat: 'wal', icon: '📝', desc: 'Taille max des fichiers WAL avant checkpoint' },
        'min_wal_size': { cat: 'wal', icon: '📝', desc: 'Taille min des fichiers WAL' },
        'checkpoint_completion_target': { cat: 'wal', icon: '📝', desc: 'Cible de completion des checkpoints' },
        'log_destination': { cat: 'logging', icon: '📋', desc: 'Destination des logs' },
        'logging_collector': { cat: 'logging', icon: '📋', desc: 'Collecteur de logs active' },
        'log_directory': { cat: 'logging', icon: '📋', desc: 'Repertoire des logs' },
        'log_statement': { cat: 'logging', icon: '📋', desc: 'Niveau de logging des requetes' },
        'ssl': { cat: 'security', icon: '🔒', desc: 'Chiffrement SSL active' },
        'password_encryption': { cat: 'security', icon: '🔒', desc: 'Methode de hashage des mots de passe' },
        'random_page_cost': { cat: 'performance', icon: '⚡', desc: 'Cout estime lecture aleatoire (SSD: 1.1, HDD: 4)' },
        'effective_io_concurrency': { cat: 'performance', icon: '⚡', desc: 'Concurrence I/O (SSD: 200, HDD: 2)' },
        'default_statistics_target': { cat: 'performance', icon: '⚡', desc: 'Precision des statistiques (100-500)' },
      };

      lines.forEach(line => {
        const match = line.match(/^(\w+)\s*=\s*(.+)$/);
        if (!match) return;
        let [, key, value] = match;
        value = value.replace(/\s*#.*$/, '').trim().replace(/^'|'$/g, '');

        const info = directives[key] || { cat: 'other', icon: 'ℹ️', desc: 'Parametre PostgreSQL' };
        let alerts = [];

        if (key === 'listen_addresses' && value === '*') {
          alerts.push({ type: 'warning', text: 'Ecoute sur toutes les interfaces - verifiez pg_hba.conf' });
        }
        if (key === 'ssl' && value === 'on') {
          alerts.push({ type: 'good', text: 'Connexions chiffrees activees' });
        }
        if (key === 'password_encryption' && value === 'scram-sha-256') {
          alerts.push({ type: 'good', text: 'Methode de hashage moderne et securisee' });
        }
        if (key === 'log_statement' && value === 'all') {
          alerts.push({ type: 'info', text: 'Toutes les requetes sont loguees - impact performance' });
        }

        result[info.cat].push({ key, value, icon: info.icon, desc: info.desc, alerts });
      });

      return result;
    },
    render: (data) => renderStandardConfig(data, 'PostgreSQL')
  },

  // ==================== 389 DIRECTORY SERVER ====================
  ldap389: {
    name: '389 Directory Server',
    detect: (text) => text.includes('nsslapd-') || text.includes('cn=config') || (text.includes('dn:') && text.includes('objectClass') && text.includes('nsDS')),
    parse: (text) => {
      const result = {
        network: [], database: [], security: [], replication: [], plugins: [], limits: [], logging: [], other: []
      };

      // Parse LDIF format
      const entries = [];
      let currentEntry = null;
      let currentAttr = null;

      text.split('\n').forEach(line => {
        // New entry
        if (line.startsWith('dn:')) {
          if (currentEntry) entries.push(currentEntry);
          currentEntry = { dn: line.substring(3).trim(), attrs: {} };
          currentAttr = null;
          return;
        }

        // Continuation line
        if (line.startsWith(' ') && currentEntry && currentAttr) {
          currentEntry.attrs[currentAttr] += line.substring(1);
          return;
        }

        // Attribute
        if (currentEntry && line.includes(':')) {
          const colonIdx = line.indexOf(':');
          const attr = line.substring(0, colonIdx);
          let value = line.substring(colonIdx + 1).trim();
          // Handle base64 (attr:: value)
          if (value.startsWith(':')) {
            value = '[base64]' + value.substring(1).trim();
          }
          currentEntry.attrs[attr] = value;
          currentAttr = attr;
        }
      });
      if (currentEntry) entries.push(currentEntry);

      // Categorize directives
      const directives = {
        'nsslapd-port': { cat: 'network', icon: '🌐', desc: 'Port LDAP (389 par defaut)' },
        'nsslapd-secureport': { cat: 'network', icon: '🔒', desc: 'Port LDAPS (636 par defaut)' },
        'nsslapd-listenhost': { cat: 'network', icon: '🌐', desc: 'Adresse d\'ecoute' },
        'nsslapd-localhost': { cat: 'network', icon: '🌐', desc: 'Hostname local' },
        'nsslapd-security': { cat: 'security', icon: '🔒', desc: 'SSL/TLS active' },
        'nsslapd-minssf': { cat: 'security', icon: '🔒', desc: 'Force de chiffrement minimum' },
        'nsslapd-require-secure-binds': { cat: 'security', icon: '🔒', desc: 'Binds securises obligatoires' },
        'nsslapd-allow-anonymous-access': { cat: 'security', icon: '🔒', desc: 'Acces anonyme autorise' },
        'nsslapd-rootdn': { cat: 'security', icon: '👤', desc: 'DN administrateur (Directory Manager)' },
        'nsslapd-rootpw': { cat: 'security', icon: '🔐', desc: 'Mot de passe administrateur (hashe)' },
        'nsslapd-suffix': { cat: 'database', icon: '🗄️', desc: 'Suffixe de la base (base DN)' },
        'nsslapd-backend': { cat: 'database', icon: '🗄️', desc: 'Nom du backend' },
        'nsslapd-directory': { cat: 'database', icon: '📁', desc: 'Repertoire des donnees' },
        'nsslapd-db-home-directory': { cat: 'database', icon: '📁', desc: 'Repertoire home BDB/LMDB' },
        'nsslapd-maxconnections': { cat: 'limits', icon: '⚙️', desc: 'Nombre max de connexions' },
        'nsslapd-timelimit': { cat: 'limits', icon: '⏱️', desc: 'Limite temps recherche (sec)' },
        'nsslapd-sizelimit': { cat: 'limits', icon: '📊', desc: 'Limite nombre resultats' },
        'nsslapd-idletimeout': { cat: 'limits', icon: '⏱️', desc: 'Timeout inactivite (sec)' },
        'nsslapd-maxbersize': { cat: 'limits', icon: '📏', desc: 'Taille max BER (octets)' },
        'nsslapd-maxdescriptors': { cat: 'limits', icon: '⚙️', desc: 'Max file descriptors' },
        'nsslapd-accesslog': { cat: 'logging', icon: '📝', desc: 'Fichier access log' },
        'nsslapd-errorlog': { cat: 'logging', icon: '📝', desc: 'Fichier error log' },
        'nsslapd-auditlog': { cat: 'logging', icon: '📝', desc: 'Fichier audit log' },
        'nsslapd-accesslog-logging-enabled': { cat: 'logging', icon: '📝', desc: 'Access log active' },
        'nsslapd-errorlog-level': { cat: 'logging', icon: '📝', desc: 'Niveau de log erreurs' },
        'nsds5replicahost': { cat: 'replication', icon: '🔄', desc: 'Hote replica' },
        'nsds5replicaport': { cat: 'replication', icon: '🔄', desc: 'Port replica' },
        'nsds5replicabinddn': { cat: 'replication', icon: '🔄', desc: 'DN de bind replication' },
        'nsds5replicaid': { cat: 'replication', icon: '🔄', desc: 'ID du replica' },
        'nsds5replicatype': { cat: 'replication', icon: '🔄', desc: 'Type (master/hub/consumer)' },
        'nsslapd-pluginpath': { cat: 'plugins', icon: '🔌', desc: 'Chemin du plugin' },
        'nsslapd-pluginenabled': { cat: 'plugins', icon: '🔌', desc: 'Plugin active' },
      };

      entries.forEach(entry => {
        Object.entries(entry.attrs).forEach(([attr, value]) => {
          const lowerAttr = attr.toLowerCase();
          const info = directives[lowerAttr] || null;

          if (info) {
            let alerts = [];

            // Security checks
            if (lowerAttr === 'nsslapd-allow-anonymous-access' && value === 'on') {
              alerts.push({ type: 'warning', text: 'Acces anonyme active - risque de fuite d\'informations' });
            }
            if (lowerAttr === 'nsslapd-security' && value === 'on') {
              alerts.push({ type: 'good', text: 'SSL/TLS active' });
            }
            if (lowerAttr === 'nsslapd-require-secure-binds' && value === 'on') {
              alerts.push({ type: 'good', text: 'Binds securises obligatoires' });
            }
            if (lowerAttr === 'nsslapd-minssf' && parseInt(value) >= 128) {
              alerts.push({ type: 'good', text: 'Chiffrement fort requis (SSF >= 128)' });
            }
            if (lowerAttr === 'nsslapd-rootpw' && !value.startsWith('{')) {
              alerts.push({ type: 'error', text: 'Mot de passe en clair! Utilisez un hash' });
            }

            result[info.cat].push({
              key: attr,
              value: value.length > 100 ? value.substring(0, 100) + '...' : value,
              icon: info.icon,
              desc: info.desc,
              alerts,
              dn: entry.dn
            });
          }
        });
      });

      // Also extract ACIs
      entries.forEach(entry => {
        if (entry.attrs.aci) {
          result.security.push({
            key: 'aci',
            value: entry.attrs.aci.substring(0, 80) + '...',
            icon: '🛡️',
            desc: 'Access Control Instruction',
            alerts: [],
            dn: entry.dn
          });
        }
      });

      return result;
    },
    render: (data) => {
      const categoryNames = {
        network: { name: 'Reseau', icon: '🌐' },
        database: { name: 'Base de donnees', icon: '🗄️' },
        security: { name: 'Securite & ACIs', icon: '🔒' },
        replication: { name: 'Replication', icon: '🔄' },
        plugins: { name: 'Plugins', icon: '🔌' },
        limits: { name: 'Limites & Performance', icon: '⚙️' },
        logging: { name: 'Logging', icon: '📝' },
        other: { name: 'Autres', icon: 'ℹ️' }
      };

      let totalItems = 0;
      let warnings = 0;
      let goods = 0;

      Object.values(data).forEach(items => {
        totalItems += items.length;
        items.forEach(item => {
          if (item.alerts) {
            item.alerts.forEach(a => {
              if (a.type === 'warning' || a.type === 'error') warnings++;
              if (a.type === 'good') goods++;
            });
          }
        });
      });

      let html = '<div class="summary-box">';
      html += `<div class="summary-item"><div class="summary-value">${totalItems}</div><div class="summary-label">Attributs</div></div>`;
      html += `<div class="summary-item"><div class="summary-value" style="color:#22c55e">${goods}</div><div class="summary-label">Bonnes pratiques</div></div>`;
      html += `<div class="summary-item"><div class="summary-value" style="color:#f59e0b">${warnings}</div><div class="summary-label">Alertes</div></div>`;
      html += `<div class="summary-item"><div class="summary-value">${data.replication.length > 0 ? 'Oui' : 'Non'}</div><div class="summary-label">Replication</div></div>`;
      html += '</div>';

      Object.entries(data).forEach(([cat, items]) => {
        if (items.length === 0) return;
        const info = categoryNames[cat] || { name: cat, icon: '📄' };

        html += `<div class="analysis-section"><div class="section-header">
          <span class="section-icon">${info.icon}</span>
          ${info.name}
          <span class="item-badge badge-info">${items.length}</span>
        </div>`;
        html += '<div class="section-content">';

        items.forEach(item => {
          html += `<div class="config-item">
            <div class="item-header">
              <span class="section-icon">${item.icon || 'ℹ️'}</span>
              <span class="item-directive">${item.key}</span>
              <span class="item-value">${escapeHtml(item.value)}</span>
            </div>
            <div class="item-description">${item.desc || ''}</div>`;

          if (item.alerts) {
            item.alerts.forEach(a => {
              const icon = a.type === 'error' ? '❌' : a.type === 'warning' ? '⚠️' : a.type === 'good' ? '✅' : 'ℹ️';
              html += `<div class="item-alert alert-${a.type}">${icon} ${a.text}</div>`;
            });
          }

          html += '</div>';
        });

        html += '</div></div>';
      });

      return html;
    }
  },

  // ==================== OPENLDAP SLAPD.CONF ====================
  slapd: {
    name: 'OpenLDAP (slapd.conf)',
    detect: (text) => text.includes('slapd') || text.includes('olcDatabase') || text.includes('olcSuffix') || (text.includes('database') && text.includes('suffix') && !text.includes('nsslapd')),
    parse: (text) => {
      const result = {
        global: [], database: [], security: [], acl: [], schema: [], modules: [], other: []
      };

      const directives = {
        'include': { cat: 'schema', icon: '📄', desc: 'Fichier schema inclus' },
        'pidfile': { cat: 'global', icon: '⚙️', desc: 'Fichier PID' },
        'argsfile': { cat: 'global', icon: '⚙️', desc: 'Fichier arguments' },
        'modulepath': { cat: 'modules', icon: '🔌', desc: 'Chemin des modules' },
        'moduleload': { cat: 'modules', icon: '🔌', desc: 'Module charge' },
        'database': { cat: 'database', icon: '🗄️', desc: 'Type de backend (mdb, hdb, bdb)' },
        'suffix': { cat: 'database', icon: '🗄️', desc: 'Suffixe de la base (base DN)' },
        'rootdn': { cat: 'security', icon: '👤', desc: 'DN administrateur' },
        'rootpw': { cat: 'security', icon: '🔐', desc: 'Mot de passe admin (hashe)' },
        'directory': { cat: 'database', icon: '📁', desc: 'Repertoire des donnees' },
        'index': { cat: 'database', icon: '⚡', desc: 'Index pour optimisation' },
        'access': { cat: 'acl', icon: '🛡️', desc: 'Regle de controle d\'acces' },
        'sizelimit': { cat: 'global', icon: '📊', desc: 'Limite nombre resultats' },
        'timelimit': { cat: 'global', icon: '⏱️', desc: 'Limite temps recherche' },
        'loglevel': { cat: 'global', icon: '📝', desc: 'Niveau de log' },
        'TLSCACertificateFile': { cat: 'security', icon: '🔒', desc: 'Certificat CA' },
        'TLSCertificateFile': { cat: 'security', icon: '🔒', desc: 'Certificat serveur' },
        'TLSCertificateKeyFile': { cat: 'security', icon: '🔒', desc: 'Cle privee' },
        'TLSCipherSuite': { cat: 'security', icon: '🔒', desc: 'Suites de chiffrement' },
        'security': { cat: 'security', icon: '🔒', desc: 'Exigences de securite (ssf)' },
        'syncrepl': { cat: 'database', icon: '🔄', desc: 'Configuration replication syncrepl' },
        'overlay': { cat: 'modules', icon: '🔌', desc: 'Overlay active (memberof, refint...)' },
      };

      const lines = text.split('\n');
      let currentDb = null;

      lines.forEach(line => {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) return;

        // Handle continuation lines
        const parts = trimmed.split(/\s+/);
        const directive = parts[0].toLowerCase();
        const value = parts.slice(1).join(' ');

        const info = directives[directive];
        if (!info) {
          if (trimmed.startsWith('access to')) {
            result.acl.push({
              key: 'access',
              value: trimmed,
              icon: '🛡️',
              desc: 'Regle ACL',
              alerts: []
            });
          }
          return;
        }

        let alerts = [];

        // Security checks
        if (directive === 'rootpw' && !value.startsWith('{')) {
          alerts.push({ type: 'error', text: 'Mot de passe en clair! Utilisez {SSHA} ou {ARGON2}' });
        }
        if (directive === 'rootpw' && value.startsWith('{SSHA}')) {
          alerts.push({ type: 'good', text: 'Mot de passe hashe avec SSHA' });
        }
        if (directive === 'database' && value === 'mdb') {
          alerts.push({ type: 'good', text: 'LMDB recommande pour les performances' });
        }
        if (directive === 'database' && (value === 'bdb' || value === 'hdb')) {
          alerts.push({ type: 'warning', text: 'BDB/HDB deprecie - migrez vers MDB' });
        }
        if (directive === 'tlscertificatefile') {
          alerts.push({ type: 'good', text: 'TLS configure' });
        }

        result[info.cat].push({
          key: directive,
          value: value.length > 80 ? value.substring(0, 80) + '...' : value,
          icon: info.icon,
          desc: info.desc,
          alerts
        });
      });

      return result;
    },
    render: (data) => renderStandardConfig(data, 'OpenLDAP slapd.conf')
  },

  // ==================== LDIF GENERIC ====================
  ldif: {
    name: 'LDIF',
    detect: (text) => text.includes('dn:') && text.includes('objectClass'),
    parse: (text) => {
      const entries = [];
      let currentEntry = null;
      let currentAttr = null;

      text.split('\n').forEach(line => {
        // Empty line = end of entry
        if (!line.trim()) {
          if (currentEntry && currentEntry.dn) {
            entries.push(currentEntry);
          }
          currentEntry = null;
          currentAttr = null;
          return;
        }

        // New entry
        if (line.startsWith('dn:')) {
          currentEntry = { dn: line.substring(3).trim(), attrs: {}, objectClasses: [] };
          return;
        }

        // Continuation line
        if (line.startsWith(' ') && currentEntry && currentAttr) {
          if (Array.isArray(currentEntry.attrs[currentAttr])) {
            const lastIdx = currentEntry.attrs[currentAttr].length - 1;
            currentEntry.attrs[currentAttr][lastIdx] += line.substring(1);
          } else {
            currentEntry.attrs[currentAttr] += line.substring(1);
          }
          return;
        }

        // Attribute
        if (currentEntry && line.includes(':')) {
          const colonIdx = line.indexOf(':');
          const attr = line.substring(0, colonIdx).toLowerCase();
          let value = line.substring(colonIdx + 1).trim();

          // Base64
          if (value.startsWith(':')) {
            value = '[base64] ' + value.substring(1).trim();
          }

          if (attr === 'objectclass') {
            currentEntry.objectClasses.push(value);
          }

          // Multi-valued
          if (currentEntry.attrs[attr]) {
            if (!Array.isArray(currentEntry.attrs[attr])) {
              currentEntry.attrs[attr] = [currentEntry.attrs[attr]];
            }
            currentEntry.attrs[attr].push(value);
          } else {
            currentEntry.attrs[attr] = value;
          }
          currentAttr = attr;
        }
      });

      if (currentEntry && currentEntry.dn) {
        entries.push(currentEntry);
      }

      return { entries };
    },
    render: (data) => {
      const entries = data.entries;

      let html = '<div class="summary-box">';
      html += `<div class="summary-item"><div class="summary-value">${entries.length}</div><div class="summary-label">Entrees</div></div>`;

      // Count entry types
      const types = {};
      entries.forEach(e => {
        e.objectClasses.forEach(oc => {
          types[oc] = (types[oc] || 0) + 1;
        });
      });
      const topTypes = Object.entries(types).sort((a, b) => b[1] - a[1]).slice(0, 3);
      topTypes.forEach(([type, count]) => {
        html += `<div class="summary-item"><div class="summary-value">${count}</div><div class="summary-label">${type}</div></div>`;
      });
      html += '</div>';

      // Display entries
      entries.forEach((entry, idx) => {
        const icon = entry.objectClasses.includes('organizationalUnit') ? '📁' :
                     entry.objectClasses.includes('inetOrgPerson') || entry.objectClasses.includes('person') ? '👤' :
                     entry.objectClasses.includes('groupOfNames') || entry.objectClasses.includes('posixGroup') ? '👥' :
                     entry.objectClasses.includes('organization') ? '🏢' :
                     entry.objectClasses.includes('domain') ? '🌐' : '📄';

        html += `<div class="analysis-section"><div class="section-header">
          <span class="section-icon">${icon}</span>
          ${escapeHtml(entry.dn)}
        </div>`;
        html += '<div class="section-content">';

        // ObjectClasses
        html += `<div class="config-item">
          <div class="item-header">
            <span class="item-directive">objectClass</span>
            <span class="item-value">${entry.objectClasses.join(', ')}</span>
          </div>
        </div>`;

        // Other attributes
        Object.entries(entry.attrs).forEach(([attr, value]) => {
          if (attr === 'objectclass') return;

          const displayValue = Array.isArray(value) ? value.join(', ') : value;
          const isSensitive = ['userpassword', 'userPKCS12'].includes(attr.toLowerCase());

          html += `<div class="config-item">
            <div class="item-header">
              <span class="item-directive">${attr}</span>
              <span class="item-value">${isSensitive ? '[SENSIBLE]' : escapeHtml(displayValue.substring(0, 60))}${displayValue.length > 60 ? '...' : ''}</span>
            </div>
          </div>`;
        });

        html += '</div></div>';
      });

      return html;
    }
  }
};

// Helper functions
function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

function cronToHuman(min, hour, dom, month, dow) {
  const parts = [];

  // Time
  if (min === '*' && hour === '*') {
    parts.push('Chaque minute');
  } else if (min === '0' && hour === '*') {
    parts.push('Chaque heure');
  } else if (min === '0' && hour === '0') {
    parts.push('A minuit');
  } else if (min !== '*' && hour !== '*') {
    parts.push(`A ${hour}:${min.padStart(2, '0')}`);
  } else if (min.includes('/')) {
    const interval = min.split('/')[1];
    parts.push(`Toutes les ${interval} minutes`);
  } else if (hour.includes('/')) {
    const interval = hour.split('/')[1];
    parts.push(`Toutes les ${interval} heures`);
  } else {
    parts.push(`Minute ${min}, heure ${hour}`);
  }

  // Day of month
  if (dom !== '*') {
    if (dom.includes(',')) {
      parts.push(`les ${dom}`);
    } else if (dom.includes('-')) {
      const [start, end] = dom.split('-');
      parts.push(`du ${start} au ${end}`);
    } else {
      parts.push(`le ${dom}`);
    }
  }

  // Month
  const months = ['', 'jan', 'fev', 'mar', 'avr', 'mai', 'jun', 'jul', 'aou', 'sep', 'oct', 'nov', 'dec'];
  if (month !== '*') {
    parts.push(`en ${months[parseInt(month)] || month}`);
  }

  // Day of week
  const days = ['dim', 'lun', 'mar', 'mer', 'jeu', 'ven', 'sam'];
  if (dow !== '*') {
    if (dow.includes(',')) {
      const dayNames = dow.split(',').map(d => days[parseInt(d)] || d).join(', ');
      parts.push(`(${dayNames})`);
    } else {
      parts.push(`(${days[parseInt(dow)] || dow})`);
    }
  }

  return parts.join(' ');
}

function renderStandardConfig(data, title) {
  const categoryNames = {
    network: { name: 'Reseau', icon: '🌐' },
    connections: { name: 'Connexions', icon: '🔌' },
    cache: { name: 'Cache', icon: '💾' },
    memory: { name: 'Memoire', icon: '💾' },
    acl: { name: 'ACLs', icon: '📋' },
    access: { name: 'Regles d\'acces', icon: '🚦' },
    auth: { name: 'Authentification', icon: '🔐' },
    security: { name: 'Securite', icon: '🔒' },
    session: { name: 'Session', icon: '🖥️' },
    logging: { name: 'Logging', icon: '📝' },
    wal: { name: 'WAL & Replication', icon: '📝' },
    performance: { name: 'Performance', icon: '⚡' },
    other: { name: 'Autres', icon: 'ℹ️' }
  };

  let totalItems = 0;
  let warnings = 0;
  let goods = 0;

  Object.values(data).forEach(items => {
    totalItems += items.length;
    items.forEach(item => {
      if (item.alerts) {
        item.alerts.forEach(a => {
          if (a.type === 'warning' || a.type === 'error') warnings++;
          if (a.type === 'good') goods++;
        });
      }
      if (item.badge === 'warning' || item.badge === 'error') warnings++;
      if (item.badge === 'good') goods++;
    });
  });

  let html = '<div class="summary-box">';
  html += `<div class="summary-item"><div class="summary-value">${totalItems}</div><div class="summary-label">Directives</div></div>`;
  html += `<div class="summary-item"><div class="summary-value" style="color:#22c55e">${goods}</div><div class="summary-label">Bonnes pratiques</div></div>`;
  html += `<div class="summary-item"><div class="summary-value" style="color:#f59e0b">${warnings}</div><div class="summary-label">Alertes</div></div>`;
  html += '</div>';

  Object.entries(data).forEach(([cat, items]) => {
    if (items.length === 0) return;
    const info = categoryNames[cat] || { name: cat, icon: '📄' };

    html += `<div class="analysis-section"><div class="section-header">
      <span class="section-icon">${info.icon}</span>
      ${info.name}
      <span class="item-badge badge-info">${items.length}</span>
    </div>`;
    html += '<div class="section-content">';

    items.forEach(item => {
      const badgeClass = item.badge ? `badge-${item.badge}` : '';
      html += `<div class="config-item">
        <div class="item-header">
          <span class="section-icon">${item.icon || 'ℹ️'}</span>
          <span class="item-directive">${item.directive || item.key}</span>
          <span class="item-value">${escapeHtml((item.value || '').substring(0, 60))}${(item.value || '').length > 60 ? '...' : ''}</span>
          ${item.badge ? `<span class="item-badge ${badgeClass}">${item.badge}</span>` : ''}
        </div>
        <div class="item-description">${item.desc || ''}</div>`;

      if (item.alerts) {
        item.alerts.forEach(a => {
          const icon = a.type === 'error' ? '❌' : a.type === 'warning' ? '⚠️' : a.type === 'good' ? '✅' : 'ℹ️';
          html += `<div class="item-alert alert-${a.type}">${icon} ${a.text}</div>`;
        });
      }

      html += '</div>';
    });

    html += '</div></div>';
  });

  return html;
}

function detectFormat(text) {
  for (const [format, parser] of Object.entries(parsers)) {
    if (parser.detect && parser.detect(text)) {
      return format;
    }
  }
  return null;
}

function parseConfig() {
  const text = document.getElementById('configInput').value;
  const formatSelect = document.getElementById('configFormat').value;
  const output = document.getElementById('analysisOutput');
  const detected = document.getElementById('detectedFormat');

  if (!text.trim()) {
    output.innerHTML = '<div class="placeholder"><p>Collez une configuration pour voir l\'analyse</p></div>';
    detected.textContent = '-';
    return;
  }

  let format = formatSelect;
  if (format === 'auto') {
    format = detectFormat(text);
    if (!format) {
      output.innerHTML = '<div class="placeholder"><p>Format non reconnu. Selectionnez le format manuellement.</p></div>';
      detected.textContent = 'Non reconnu';
      return;
    }
  }

  const parser = parsers[format];
  if (!parser) {
    output.innerHTML = '<div class="placeholder"><p>Parser non disponible pour ce format.</p></div>';
    detected.textContent = format;
    return;
  }

  detected.textContent = parser.name;

  try {
    const data = parser.parse(text);
    output.innerHTML = parser.render(data);
  } catch (e) {
    output.innerHTML = `<div class="placeholder"><p>Erreur de parsing: ${e.message}</p></div>`;
  }
}

function loadExample(type) {
  const examples = {
    squid: `http_port 3128 intercept
visible_hostname proxy.example.com
cache_dir aufs /var/spool/squid 10000 16 256
cache_mem 256 MB
maximum_object_size 100 MB

acl localnet src 192.168.1.0/24
acl SSL_ports port 443
acl Safe_ports port 80 443 21

http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports
http_access allow localhost
http_access allow localnet
http_access deny all

access_log daemon:/var/log/squid/access.log combined
forwarded_for delete
via off`,

    sshd: `Port 22
ListenAddress 0.0.0.0
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
X11Forwarding no
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
AllowUsers admin deploy
Protocol 2
UsePAM yes
Banner /etc/ssh/banner.txt`,

    nginx: `worker_processes auto;
error_log /var/log/nginx/error.log warn;

events {
    worker_connections 1024;
}

http {
    server_tokens off;

    server {
        listen 80;
        server_name example.com;
        return 301 https://$server_name$request_uri;
    }

    server {
        listen 443 ssl http2;
        server_name example.com;

        ssl_certificate /etc/ssl/certs/example.crt;
        ssl_certificate_key /etc/ssl/private/example.key;
        ssl_protocols TLSv1.2 TLSv1.3;

        root /var/www/html;

        location / {
            try_files $uri $uri/ =404;
        }

        location /api {
            proxy_pass http://localhost:3000;
        }
    }
}`,

    crontab: `SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
MAILTO=admin@example.com

# Backup quotidien a 2h du matin
0 2 * * * /usr/local/bin/backup.sh > /dev/null 2>&1

# Nettoyage des logs chaque dimanche
0 3 * * 0 /usr/local/bin/cleanup-logs.sh

# Verification disque toutes les 15 minutes
*/15 * * * * /usr/local/bin/check-disk.sh

# Mise a jour SSL le 1er de chaque mois
0 4 1 * * certbot renew --quiet

@reboot /usr/local/bin/startup.sh`,

    sudoers: `Defaults env_reset
Defaults mail_badpass
Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Defaults timestamp_timeout=5

# User aliases
User_Alias ADMINS = alice, bob, charlie
User_Alias DEVELOPERS = dev1, dev2, dev3

# Command aliases
Cmnd_Alias SERVICES = /usr/bin/systemctl restart *, /usr/bin/systemctl status *
Cmnd_Alias DOCKER = /usr/bin/docker, /usr/bin/docker-compose

# Rules
root ALL=(ALL:ALL) ALL
%sudo ALL=(ALL:ALL) ALL
%admin ALL=(ALL) NOPASSWD: ALL

ADMINS ALL=(ALL) ALL
DEVELOPERS ALL=(root) NOPASSWD: SERVICES, DOCKER
deploy ALL=(root) NOPASSWD: /usr/local/bin/deploy.sh`,

    iptables: `*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]

# Loopback
-A INPUT -i lo -j ACCEPT
-A OUTPUT -o lo -j ACCEPT

# Established connections
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# SSH
-A INPUT -p tcp --dport 22 -m state --state NEW -j ACCEPT

# HTTP/HTTPS
-A INPUT -p tcp --dport 80 -j ACCEPT
-A INPUT -p tcp --dport 443 -j ACCEPT

# ICMP
-A INPUT -p icmp --icmp-type echo-request -j ACCEPT

# Drop invalid
-A INPUT -m state --state INVALID -j DROP

COMMIT`,

    systemd: `[Unit]
Description=My Application Service
Documentation=https://example.com/docs
After=network.target postgresql.service
Requires=postgresql.service

[Service]
Type=simple
User=appuser
Group=appgroup
WorkingDirectory=/opt/myapp
Environment=NODE_ENV=production
EnvironmentFile=/opt/myapp/.env
ExecStart=/usr/bin/node /opt/myapp/server.js
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target`,

    postgresql: `# Connection settings
listen_addresses = '*'
port = 5432
max_connections = 200

# Memory
shared_buffers = 2GB
work_mem = 64MB
maintenance_work_mem = 512MB
effective_cache_size = 6GB

# WAL
wal_level = replica
max_wal_size = 2GB
min_wal_size = 1GB
checkpoint_completion_target = 0.9

# Logging
log_destination = 'stderr'
logging_collector = on
log_directory = 'log'
log_statement = 'ddl'

# Security
ssl = on
password_encryption = scram-sha-256

# Performance
random_page_cost = 1.1
effective_io_concurrency = 200
default_statistics_target = 200`,

    ldap389: `dn: cn=config
objectClass: top
objectClass: extensibleObject
objectClass: nsslapdConfig
nsslapd-port: 389
nsslapd-secureport: 636
nsslapd-security: on
nsslapd-localhost: ldap.example.com
nsslapd-rootdn: cn=Directory Manager
nsslapd-rootpw: {PBKDF2_SHA256}AAAgADfK...
nsslapd-maxconnections: 1000
nsslapd-timelimit: 3600
nsslapd-sizelimit: 2000
nsslapd-idletimeout: 3600
nsslapd-allow-anonymous-access: rootdse
nsslapd-require-secure-binds: on
nsslapd-minssf: 128
nsslapd-accesslog: /var/log/dirsrv/slapd-instance/access
nsslapd-errorlog: /var/log/dirsrv/slapd-instance/errors
nsslapd-accesslog-logging-enabled: on
nsslapd-errorlog-level: 16384

dn: cn=userRoot,cn=ldbm database,cn=plugins,cn=config
objectClass: top
objectClass: extensibleObject
objectClass: nsBackendInstance
nsslapd-suffix: dc=example,dc=com
nsslapd-backend: userRoot
nsslapd-directory: /var/lib/dirsrv/slapd-instance/db/userRoot

dn: cn=replica,cn=dc\\=example\\,dc\\=com,cn=mapping tree,cn=config
objectClass: top
objectClass: nsDS5Replica
nsDS5ReplicaId: 1
nsDS5ReplicaType: 3
nsDS5ReplicaBindDN: cn=replication manager,cn=config`,

    slapd: `# OpenLDAP slapd.conf
include /etc/openldap/schema/core.schema
include /etc/openldap/schema/cosine.schema
include /etc/openldap/schema/inetorgperson.schema

pidfile /var/run/openldap/slapd.pid
argsfile /var/run/openldap/slapd.args

modulepath /usr/lib64/openldap
moduleload back_mdb.la
moduleload memberof.la
moduleload refint.la

loglevel stats

TLSCACertificateFile /etc/pki/tls/certs/ca-bundle.crt
TLSCertificateFile /etc/pki/tls/certs/ldap.crt
TLSCertificateKeyFile /etc/pki/tls/private/ldap.key
TLSCipherSuite HIGH:!aNULL:!MD5

database mdb
suffix "dc=example,dc=com"
rootdn "cn=admin,dc=example,dc=com"
rootpw {SSHA}xxxxxxxxxxxxxxxxxxxxxxxxxx
directory /var/lib/openldap/openldap-data

index objectClass eq
index cn,sn,mail eq,sub
index uid eq
index memberOf eq

overlay memberof
overlay refint

sizelimit 500
timelimit 3600

access to attrs=userPassword
    by self write
    by anonymous auth
    by * none

access to *
    by self write
    by users read
    by * none`
  };

  if (examples[type]) {
    document.getElementById('configInput').value = examples[type];
    document.getElementById('configFormat').value = type;
    parseConfig();
  }
}

function exportMarkdown() {
  const output = document.getElementById('analysisOutput').innerText;
  const format = document.getElementById('detectedFormat').textContent;

  let md = `# Configuration Analysis: ${format}\n\n`;
  md += `Generated: ${new Date().toISOString()}\n\n`;
  md += '---\n\n';
  md += output;

  const blob = new Blob([md], { type: 'text/markdown' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `config-analysis-${format.toLowerCase().replace(/\s+/g, '-')}.md`;
  a.click();
  URL.revokeObjectURL(url);
}

// Initial state
document.addEventListener('DOMContentLoaded', parseConfig);
</script>

---

## Formats supportes

| Categorie | Formats |
|-----------|---------|
| **Proxy & Web** | Squid, Nginx, Apache, HAProxy |
| **SSH & Securite** | sshd_config, ssh_config, sudoers, iptables, nftables, Fail2Ban |
| **Bases de donnees** | PostgreSQL, MySQL, Redis |
| **LDAP & Annuaires** | 389 Directory Server, OpenLDAP (slapd.conf), LDIF |
| **Systeme** | Systemd, Crontab, Logrotate, Rsyslog, fstab |
| **Reseau** | Netplan, interfaces, resolv.conf, hosts |
| **Conteneurs** | Dockerfile, Docker Compose, Kubernetes YAML |

---

## Voir aussi

- [Squid Proxy Generator](squid-generator.md)
- [SSHD Config Generator](sshd-config-generator.md)
- [Sudoers Builder](sudoers-builder.md)
- [Cron Builder](cron-builder.md)
