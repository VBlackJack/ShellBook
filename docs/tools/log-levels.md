---
tags:
  - tools
  - reference
  - logging
  - syslog
  - debug
---

# Log Levels Reference

Reference des niveaux de log standards pour differents systemes.

<div class="tool-container">

<div class="comparison-section">
    <h3>Comparaison des Standards</h3>
    <div class="standards-table-container">
        <table class="standards-table">
            <thead>
                <tr>
                    <th>Severite</th>
                    <th>Syslog</th>
                    <th>Python</th>
                    <th>Log4j/SLF4J</th>
                    <th>JavaScript</th>
                    <th>RFC 5424</th>
                </tr>
            </thead>
            <tbody>
                <tr class="level-emerg">
                    <td><span class="level-badge emerg">EMERGENCY</span></td>
                    <td>0</td>
                    <td>-</td>
                    <td>-</td>
                    <td>-</td>
                    <td>0</td>
                </tr>
                <tr class="level-alert">
                    <td><span class="level-badge alert">ALERT</span></td>
                    <td>1</td>
                    <td>-</td>
                    <td>-</td>
                    <td>-</td>
                    <td>1</td>
                </tr>
                <tr class="level-crit">
                    <td><span class="level-badge critical">CRITICAL</span></td>
                    <td>2</td>
                    <td>50</td>
                    <td>FATAL</td>
                    <td>-</td>
                    <td>2</td>
                </tr>
                <tr class="level-error">
                    <td><span class="level-badge error">ERROR</span></td>
                    <td>3</td>
                    <td>40</td>
                    <td>ERROR</td>
                    <td>error</td>
                    <td>3</td>
                </tr>
                <tr class="level-warn">
                    <td><span class="level-badge warning">WARNING</span></td>
                    <td>4</td>
                    <td>30</td>
                    <td>WARN</td>
                    <td>warn</td>
                    <td>4</td>
                </tr>
                <tr class="level-notice">
                    <td><span class="level-badge notice">NOTICE</span></td>
                    <td>5</td>
                    <td>-</td>
                    <td>-</td>
                    <td>-</td>
                    <td>5</td>
                </tr>
                <tr class="level-info">
                    <td><span class="level-badge info">INFO</span></td>
                    <td>6</td>
                    <td>20</td>
                    <td>INFO</td>
                    <td>info/log</td>
                    <td>6</td>
                </tr>
                <tr class="level-debug">
                    <td><span class="level-badge debug">DEBUG</span></td>
                    <td>7</td>
                    <td>10</td>
                    <td>DEBUG</td>
                    <td>debug</td>
                    <td>7</td>
                </tr>
                <tr class="level-trace">
                    <td><span class="level-badge trace">TRACE</span></td>
                    <td>-</td>
                    <td>-</td>
                    <td>TRACE</td>
                    <td>trace</td>
                    <td>-</td>
                </tr>
            </tbody>
        </table>
    </div>
</div>

<div class="details-section">
    <h3>Description des Niveaux</h3>
    <div class="levels-grid" id="levels-grid"></div>
</div>

<div class="syslog-section">
    <h3>Syslog Facilities</h3>
    <div class="facilities-grid" id="facilities-grid"></div>
</div>

<div class="calculator-section">
    <h3>Calculateur Priority (Syslog)</h3>
    <p class="formula">Priority = Facility × 8 + Severity</p>
    <div class="calc-grid">
        <div class="calc-group">
            <label for="calc-facility">Facility</label>
            <select id="calc-facility" onchange="calculatePriority()">
                <option value="0">0 - kern</option>
                <option value="1" selected>1 - user</option>
                <option value="2">2 - mail</option>
                <option value="3">3 - daemon</option>
                <option value="4">4 - auth</option>
                <option value="5">5 - syslog</option>
                <option value="6">6 - lpr</option>
                <option value="7">7 - news</option>
                <option value="8">8 - uucp</option>
                <option value="9">9 - cron</option>
                <option value="10">10 - authpriv</option>
                <option value="11">11 - ftp</option>
                <option value="16">16 - local0</option>
                <option value="17">17 - local1</option>
                <option value="18">18 - local2</option>
                <option value="19">19 - local3</option>
                <option value="20">20 - local4</option>
                <option value="21">21 - local5</option>
                <option value="22">22 - local6</option>
                <option value="23">23 - local7</option>
            </select>
        </div>
        <div class="calc-group">
            <label for="calc-severity">Severity</label>
            <select id="calc-severity" onchange="calculatePriority()">
                <option value="0">0 - emerg</option>
                <option value="1">1 - alert</option>
                <option value="2">2 - crit</option>
                <option value="3">3 - err</option>
                <option value="4">4 - warning</option>
                <option value="5">5 - notice</option>
                <option value="6" selected>6 - info</option>
                <option value="7">7 - debug</option>
            </select>
        </div>
        <div class="calc-result">
            <span>Priority:</span>
            <strong id="priority-result">14</strong>
            <code id="priority-format">&lt;14&gt;</code>
        </div>
    </div>
</div>

<div class="examples-section">
    <h3>Exemples par Langage</h3>
    <div class="lang-tabs">
        <button class="lang-btn active" onclick="showLang('python')">Python</button>
        <button class="lang-btn" onclick="showLang('javascript')">JavaScript</button>
        <button class="lang-btn" onclick="showLang('java')">Java</button>
        <button class="lang-btn" onclick="showLang('bash')">Bash</button>
    </div>
    <div class="lang-content" id="python-code">
        <pre>import logging

# Configuration basique
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

logger.debug('Message de debug')
logger.info('Information')
logger.warning('Attention')
logger.error('Erreur')
logger.critical('Critique')</pre>
    </div>
    <div class="lang-content" id="javascript-code" style="display: none;">
        <pre>// Console native
console.debug('Debug message');
console.log('Log message');
console.info('Info message');
console.warn('Warning message');
console.error('Error message');

// Avec winston
const winston = require('winston');
const logger = winston.createLogger({
  level: 'debug',
  format: winston.format.json(),
  transports: [
    new winston.transports.Console()
  ]
});

logger.debug('Debug');
logger.info('Info');
logger.warn('Warning');
logger.error('Error');</pre>
    </div>
    <div class="lang-content" id="java-code" style="display: none;">
        <pre>import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class MyClass {
    private static final Logger logger =
        LoggerFactory.getLogger(MyClass.class);

    public void example() {
        logger.trace("Trace message");
        logger.debug("Debug message");
        logger.info("Info message");
        logger.warn("Warning message");
        logger.error("Error message");
    }
}</pre>
    </div>
    <div class="lang-content" id="bash-code" style="display: none;">
        <pre>#!/bin/bash

# Syslog via logger
logger -p user.info "Information message"
logger -p user.warning "Warning message"
logger -p user.err "Error message"

# Avec tag
logger -t myapp -p local0.info "Application message"

# Priority numerique
logger -p 14 "Priority 14 = user.info"

# Vers fichier specifique
logger -p local0.info -f /var/log/myapp.log "Message"</pre>
    </div>
</div>

</div>

## Bonnes Pratiques

| Niveau | Quand l'utiliser |
|--------|------------------|
| **ERROR** | Erreur necessitant une intervention |
| **WARN** | Comportement inattendu mais non bloquant |
| **INFO** | Evenements normaux importants |
| **DEBUG** | Details pour le debug (dev uniquement) |

<style>
.tool-container {
    background: var(--md-code-bg-color);
    padding: 20px;
    border-radius: 8px;
    margin: 20px 0;
}
.comparison-section, .details-section, .syslog-section, .calculator-section, .examples-section {
    background: var(--md-default-bg-color);
    padding: 20px;
    border-radius: 4px;
    margin-bottom: 20px;
}
.comparison-section h3, .details-section h3, .syslog-section h3, .calculator-section h3, .examples-section h3 {
    margin: 0 0 15px 0;
}
.standards-table-container {
    overflow-x: auto;
}
.standards-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
}
.standards-table th, .standards-table td {
    padding: 10px 12px;
    text-align: center;
    border-bottom: 1px solid var(--md-default-fg-color--lightest);
}
.standards-table th {
    background: var(--md-code-bg-color);
    font-weight: bold;
}
.level-badge {
    display: inline-block;
    padding: 3px 10px;
    border-radius: 3px;
    font-size: 11px;
    font-weight: bold;
    color: white;
}
.level-badge.emerg { background: #4a0000; }
.level-badge.alert { background: #8b0000; }
.level-badge.critical { background: #c0392b; }
.level-badge.error { background: #e74c3c; }
.level-badge.warning { background: #f39c12; }
.level-badge.notice { background: #3498db; }
.level-badge.info { background: #27ae60; }
.level-badge.debug { background: #95a5a6; }
.level-badge.trace { background: #bdc3c7; color: #333; }
.levels-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
    gap: 15px;
}
.level-card {
    background: var(--md-code-bg-color);
    padding: 15px;
    border-radius: 4px;
    border-left: 4px solid;
}
.level-card.emerg { border-color: #4a0000; }
.level-card.alert { border-color: #8b0000; }
.level-card.critical { border-color: #c0392b; }
.level-card.error { border-color: #e74c3c; }
.level-card.warning { border-color: #f39c12; }
.level-card.notice { border-color: #3498db; }
.level-card.info { border-color: #27ae60; }
.level-card.debug { border-color: #95a5a6; }
.level-card h4 {
    margin: 0 0 8px 0;
    display: flex;
    align-items: center;
    gap: 10px;
}
.level-card p {
    margin: 0;
    font-size: 13px;
    color: var(--md-default-fg-color--light);
}
.level-card code {
    font-size: 12px;
}
.facilities-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
    gap: 10px;
}
.facility-item {
    background: var(--md-code-bg-color);
    padding: 8px 12px;
    border-radius: 4px;
    display: flex;
    justify-content: space-between;
    font-size: 13px;
}
.facility-item code {
    color: var(--md-primary-fg-color);
}
.formula {
    background: var(--md-code-bg-color);
    padding: 10px 15px;
    border-radius: 4px;
    font-family: monospace;
    margin-bottom: 15px;
}
.calc-grid {
    display: flex;
    gap: 20px;
    align-items: end;
    flex-wrap: wrap;
}
.calc-group {
    flex: 1;
    min-width: 150px;
}
.calc-group label {
    display: block;
    font-size: 12px;
    font-weight: bold;
    margin-bottom: 5px;
}
.calc-group select {
    width: 100%;
    padding: 10px;
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    background: var(--md-code-bg-color);
    color: var(--md-default-fg-color);
}
.calc-result {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 10px 15px;
    background: var(--md-code-bg-color);
    border-radius: 4px;
}
.calc-result strong {
    font-size: 24px;
    color: var(--md-primary-fg-color);
}
.lang-tabs {
    display: flex;
    gap: 10px;
    margin-bottom: 15px;
    flex-wrap: wrap;
}
.lang-btn {
    padding: 8px 16px;
    background: var(--md-code-bg-color);
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    cursor: pointer;
    color: var(--md-default-fg-color);
}
.lang-btn.active {
    background: var(--md-primary-fg-color);
    color: white;
    border-color: var(--md-primary-fg-color);
}
.lang-content pre {
    margin: 0;
    padding: 15px;
    background: var(--md-code-bg-color);
    border-radius: 4px;
    overflow-x: auto;
    font-size: 12px;
}
</style>

<script>
const LEVELS = [
    { name: 'EMERGENCY', code: 'emerg', num: 0, desc: 'Systeme inutilisable', example: 'Kernel panic, panne materielle critique' },
    { name: 'ALERT', code: 'alert', num: 1, desc: 'Action immediate requise', example: 'Base de donnees corrompue, espace disque critique' },
    { name: 'CRITICAL', code: 'critical', num: 2, desc: 'Conditions critiques', example: 'Echec d\'un composant majeur, perte de connectivite' },
    { name: 'ERROR', code: 'error', num: 3, desc: 'Conditions d\'erreur', example: 'Echec d\'une operation, exception non geree' },
    { name: 'WARNING', code: 'warning', num: 4, desc: 'Conditions d\'avertissement', example: 'Ressource bientot epuisee, deprecation' },
    { name: 'NOTICE', code: 'notice', num: 5, desc: 'Normal mais significatif', example: 'Changement de configuration, connexion utilisateur' },
    { name: 'INFO', code: 'info', num: 6, desc: 'Messages informatifs', example: 'Demarrage service, requete traitee' },
    { name: 'DEBUG', code: 'debug', num: 7, desc: 'Messages de debug', example: 'Valeurs de variables, trace d\'execution' }
];

const FACILITIES = [
    { num: 0, name: 'kern', desc: 'Kernel messages' },
    { num: 1, name: 'user', desc: 'User-level messages' },
    { num: 2, name: 'mail', desc: 'Mail system' },
    { num: 3, name: 'daemon', desc: 'System daemons' },
    { num: 4, name: 'auth', desc: 'Security/auth' },
    { num: 5, name: 'syslog', desc: 'Syslog internal' },
    { num: 6, name: 'lpr', desc: 'Printer' },
    { num: 7, name: 'news', desc: 'News' },
    { num: 8, name: 'uucp', desc: 'UUCP' },
    { num: 9, name: 'cron', desc: 'Cron daemon' },
    { num: 10, name: 'authpriv', desc: 'Private auth' },
    { num: 11, name: 'ftp', desc: 'FTP daemon' },
    { num: 16, name: 'local0', desc: 'Local use 0' },
    { num: 17, name: 'local1', desc: 'Local use 1' },
    { num: 18, name: 'local2', desc: 'Local use 2' },
    { num: 19, name: 'local3', desc: 'Local use 3' },
    { num: 20, name: 'local4', desc: 'Local use 4' },
    { num: 21, name: 'local5', desc: 'Local use 5' },
    { num: 22, name: 'local6', desc: 'Local use 6' },
    { num: 23, name: 'local7', desc: 'Local use 7' }
];

function renderLevels() {
    const grid = document.getElementById('levels-grid');
    grid.innerHTML = LEVELS.map(l => `
        <div class="level-card ${l.code}">
            <h4>
                <span class="level-badge ${l.code}">${l.num}</span>
                ${l.name}
            </h4>
            <p>${l.desc}</p>
            <code>${l.example}</code>
        </div>
    `).join('');
}

function renderFacilities() {
    const grid = document.getElementById('facilities-grid');
    grid.innerHTML = FACILITIES.map(f => `
        <div class="facility-item">
            <span>${f.name}</span>
            <code>${f.num}</code>
        </div>
    `).join('');
}

function calculatePriority() {
    const facility = parseInt(document.getElementById('calc-facility').value);
    const severity = parseInt(document.getElementById('calc-severity').value);
    const priority = facility * 8 + severity;

    document.getElementById('priority-result').textContent = priority;
    document.getElementById('priority-format').textContent = `<${priority}>`;
}

function showLang(lang) {
    document.querySelectorAll('.lang-btn').forEach(btn => btn.classList.remove('active'));
    event.target.classList.add('active');

    document.querySelectorAll('.lang-content').forEach(content => content.style.display = 'none');
    document.getElementById(`${lang}-code`).style.display = 'block';
}

// Initialize
renderLevels();
renderFacilities();
calculatePriority();
</script>
