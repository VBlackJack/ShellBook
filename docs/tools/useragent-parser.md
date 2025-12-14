---
tags:
  - tools
  - useragent
  - browser
  - web
---

# User Agent Parser

Analyse des chaines User-Agent pour identifier navigateurs, OS et appareils.

<div class="tool-container">

<div class="input-section">
    <div class="input-group">
        <label for="ua-input">User-Agent</label>
        <input type="text" id="ua-input" placeholder="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36...">
        <button onclick="detectCurrentUA()" class="detect-btn">Mon navigateur</button>
    </div>
    <button onclick="parseUA()" class="action-btn">Analyser</button>
</div>

<div class="results-section" id="results-section">
    <div class="result-grid">
        <div class="result-card" id="browser-card">
            <div class="icon">🌐</div>
            <h4>Navigateur</h4>
            <div class="value" id="browser-name">-</div>
            <div class="version" id="browser-version">-</div>
        </div>

        <div class="result-card" id="os-card">
            <div class="icon">💻</div>
            <h4>Systeme</h4>
            <div class="value" id="os-name">-</div>
            <div class="version" id="os-version">-</div>
        </div>

        <div class="result-card" id="device-card">
            <div class="icon">📱</div>
            <h4>Appareil</h4>
            <div class="value" id="device-type">-</div>
            <div class="version" id="device-vendor">-</div>
        </div>

        <div class="result-card" id="engine-card">
            <div class="icon">⚙️</div>
            <h4>Moteur</h4>
            <div class="value" id="engine-name">-</div>
            <div class="version" id="engine-version">-</div>
        </div>
    </div>

    <div class="details-section">
        <h3>Details</h3>
        <table id="details-table">
            <tr><td>Mobile</td><td id="is-mobile">-</td></tr>
            <tr><td>Bot/Crawler</td><td id="is-bot">-</td></tr>
            <tr><td>Architecture</td><td id="arch">-</td></tr>
            <tr><td>Plateforme</td><td id="platform">-</td></tr>
        </table>
    </div>

    <div class="raw-section">
        <h3>Composants detectes</h3>
        <pre id="raw-output"></pre>
    </div>
</div>

<div class="examples-section">
    <h3>Exemples de User-Agents</h3>
    <div class="examples-grid">
        <button onclick="loadExample('chrome-win')">Chrome Windows</button>
        <button onclick="loadExample('firefox-mac')">Firefox Mac</button>
        <button onclick="loadExample('safari-ios')">Safari iOS</button>
        <button onclick="loadExample('edge')">Edge</button>
        <button onclick="loadExample('android')">Android</button>
        <button onclick="loadExample('googlebot')">Googlebot</button>
        <button onclick="loadExample('curl')">curl</button>
    </div>
</div>

</div>

## Structure User-Agent

```
Mozilla/5.0 (platform; security; OS; localization) engine/version (details) browser/version
```

### Exemple decode

```
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
         │           │          │              │                    │                │
         │           │          │              │                    │                └── Safari compat
         │           │          │              │                    └── Chrome 120
         │           │          │              └── Moteur WebKit/Blink
         │           │          └── Architecture 64-bit
         │           └── Windows 10
         └── Token historique
```

## Bots courants

| Bot | User-Agent contient |
|-----|---------------------|
| **Googlebot** | `Googlebot` |
| **Bingbot** | `bingbot` |
| **Facebookbot** | `facebookexternalhit` |
| **Twitterbot** | `Twitterbot` |
| **LinkedInBot** | `LinkedInBot` |

<style>
.tool-container {
    background: var(--md-code-bg-color);
    padding: 20px;
    border-radius: 8px;
    margin: 20px 0;
}
.input-section {
    background: var(--md-default-bg-color);
    padding: 20px;
    border-radius: 4px;
    margin-bottom: 20px;
}
.input-group {
    display: flex;
    gap: 10px;
    margin-bottom: 15px;
}
.input-group label {
    display: none;
}
.input-group input {
    flex: 1;
    padding: 12px;
    font-family: monospace;
    font-size: 13px;
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    background: var(--md-code-bg-color);
    color: var(--md-default-fg-color);
}
.detect-btn {
    padding: 12px 20px;
    background: var(--md-code-bg-color);
    color: var(--md-default-fg-color);
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    cursor: pointer;
    white-space: nowrap;
}
.action-btn {
    padding: 10px 24px;
    background: var(--md-primary-fg-color);
    color: white;
    border: none;
    border-radius: 4px;
    cursor: pointer;
}
.results-section {
    background: var(--md-default-bg-color);
    padding: 20px;
    border-radius: 4px;
    margin-bottom: 20px;
}
.result-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 15px;
    margin-bottom: 20px;
}
.result-card {
    background: var(--md-code-bg-color);
    padding: 20px;
    border-radius: 8px;
    text-align: center;
}
.result-card .icon {
    font-size: 32px;
    margin-bottom: 10px;
}
.result-card h4 {
    margin: 0 0 10px 0;
    color: var(--md-default-fg-color--light);
    font-size: 12px;
    text-transform: uppercase;
}
.result-card .value {
    font-size: 18px;
    font-weight: bold;
}
.result-card .version {
    font-size: 14px;
    color: var(--md-default-fg-color--light);
    margin-top: 5px;
}
.details-section, .raw-section {
    margin-top: 20px;
}
.details-section h3, .raw-section h3 {
    margin: 0 0 15px 0;
}
.details-section table {
    width: 100%;
    background: var(--md-code-bg-color);
    border-radius: 4px;
}
.details-section td {
    padding: 12px 15px;
    border-bottom: 1px solid var(--md-default-fg-color--lightest);
}
.details-section td:first-child {
    font-weight: bold;
    width: 150px;
}
.raw-section pre {
    background: var(--md-code-bg-color);
    padding: 15px;
    border-radius: 4px;
    font-size: 12px;
    overflow-x: auto;
    margin: 0;
}
.examples-section {
    background: var(--md-default-bg-color);
    padding: 20px;
    border-radius: 4px;
}
.examples-section h3 {
    margin: 0 0 15px 0;
}
.examples-grid {
    display: flex;
    gap: 10px;
    flex-wrap: wrap;
}
.examples-grid button {
    padding: 8px 16px;
    background: var(--md-code-bg-color);
    color: var(--md-default-fg-color);
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    cursor: pointer;
    font-size: 13px;
}
.examples-grid button:hover {
    background: var(--md-primary-fg-color);
    color: white;
}
</style>

<script>
const UA_PATTERNS = {
    browsers: [
        { name: 'Edge', pattern: /Edg(?:e|A|iOS)?\/(\d+[\d.]*)/ },
        { name: 'Opera', pattern: /(?:OPR|Opera)[\/\s](\d+[\d.]*)/ },
        { name: 'Chrome', pattern: /Chrome\/(\d+[\d.]*)/ },
        { name: 'Firefox', pattern: /Firefox\/(\d+[\d.]*)/ },
        { name: 'Safari', pattern: /Version\/(\d+[\d.]*).*Safari/ },
        { name: 'IE', pattern: /(?:MSIE |rv:)(\d+[\d.]*)/ },
        { name: 'Samsung Browser', pattern: /SamsungBrowser\/(\d+[\d.]*)/ },
        { name: 'UC Browser', pattern: /UCBrowser\/(\d+[\d.]*)/ },
        { name: 'Brave', pattern: /Brave\/(\d+[\d.]*)/ }
    ],
    engines: [
        { name: 'Blink', pattern: /Chrome\/(\d+[\d.]*)/ },
        { name: 'WebKit', pattern: /AppleWebKit\/(\d+[\d.]*)/ },
        { name: 'Gecko', pattern: /Gecko\/(\d+[\d.]*)/ },
        { name: 'Trident', pattern: /Trident\/(\d+[\d.]*)/ },
        { name: 'Presto', pattern: /Presto\/(\d+[\d.]*)/ }
    ],
    os: [
        { name: 'Windows 11', pattern: /Windows NT 10\.0.*Win64/ },
        { name: 'Windows 10', pattern: /Windows NT 10\.0/ },
        { name: 'Windows 8.1', pattern: /Windows NT 6\.3/ },
        { name: 'Windows 8', pattern: /Windows NT 6\.2/ },
        { name: 'Windows 7', pattern: /Windows NT 6\.1/ },
        { name: 'Windows Vista', pattern: /Windows NT 6\.0/ },
        { name: 'Windows XP', pattern: /Windows NT 5\.1/ },
        { name: 'macOS', pattern: /Mac OS X (\d+[._]\d+[._]?\d*)/ },
        { name: 'iOS', pattern: /(?:iPhone|iPad|iPod).*OS (\d+[._]\d+)/ },
        { name: 'Android', pattern: /Android (\d+[\d.]*)/ },
        { name: 'Chrome OS', pattern: /CrOS/ },
        { name: 'Linux', pattern: /Linux/ },
        { name: 'Ubuntu', pattern: /Ubuntu/ },
        { name: 'Fedora', pattern: /Fedora/ },
        { name: 'FreeBSD', pattern: /FreeBSD/ }
    ],
    devices: [
        { type: 'Mobile', pattern: /(?:Mobile|Android.*Mobile|iPhone|iPod)/ },
        { type: 'Tablet', pattern: /(?:iPad|Android(?!.*Mobile)|Tablet)/ },
        { type: 'Smart TV', pattern: /(?:SmartTV|TV|SMART-TV|NetCast)/ },
        { type: 'Console', pattern: /(?:PlayStation|Xbox|Nintendo)/ },
        { type: 'Bot', pattern: /(?:bot|crawler|spider|crawl|APIs-Google)/i },
        { type: 'Desktop', pattern: /.*/ }
    ],
    bots: [
        { name: 'Googlebot', pattern: /Googlebot/ },
        { name: 'Bingbot', pattern: /bingbot/ },
        { name: 'Yahoo Slurp', pattern: /Slurp/ },
        { name: 'DuckDuckBot', pattern: /DuckDuckBot/ },
        { name: 'Baiduspider', pattern: /Baiduspider/ },
        { name: 'YandexBot', pattern: /YandexBot/ },
        { name: 'Facebook', pattern: /facebookexternalhit/ },
        { name: 'Twitter', pattern: /Twitterbot/ },
        { name: 'LinkedIn', pattern: /LinkedInBot/ },
        { name: 'WhatsApp', pattern: /WhatsApp/ },
        { name: 'Slack', pattern: /Slackbot/ },
        { name: 'curl', pattern: /^curl\// },
        { name: 'wget', pattern: /^Wget\// },
        { name: 'Python Requests', pattern: /python-requests/ }
    ]
};

function parseUA() {
    const ua = document.getElementById('ua-input').value;
    if (!ua) {
        alert('Entrez un User-Agent');
        return;
    }

    const result = {
        browser: { name: 'Unknown', version: '' },
        engine: { name: 'Unknown', version: '' },
        os: { name: 'Unknown', version: '' },
        device: { type: 'Desktop', vendor: '' },
        isMobile: false,
        isBot: false,
        arch: '',
        raw: []
    };

    // Detect browser
    for (const b of UA_PATTERNS.browsers) {
        const match = ua.match(b.pattern);
        if (match) {
            result.browser.name = b.name;
            result.browser.version = match[1] || '';
            break;
        }
    }

    // Detect engine
    for (const e of UA_PATTERNS.engines) {
        const match = ua.match(e.pattern);
        if (match) {
            result.engine.name = e.name;
            result.engine.version = match[1] || '';
            break;
        }
    }

    // Detect OS
    for (const o of UA_PATTERNS.os) {
        const match = ua.match(o.pattern);
        if (match) {
            result.os.name = o.name;
            result.os.version = match[1] ? match[1].replace(/_/g, '.') : '';
            break;
        }
    }

    // Detect device type
    for (const d of UA_PATTERNS.devices) {
        if (d.pattern.test(ua)) {
            result.device.type = d.type;
            break;
        }
    }

    // Detect bot
    for (const b of UA_PATTERNS.bots) {
        if (b.pattern.test(ua)) {
            result.isBot = true;
            result.device.type = 'Bot';
            result.device.vendor = b.name;
            break;
        }
    }

    // Mobile detection
    result.isMobile = /Mobile|Android|iPhone|iPod/i.test(ua);

    // Architecture
    if (/Win64|x64|x86_64|amd64/i.test(ua)) {
        result.arch = '64-bit';
    } else if (/WOW64|i686|i386/i.test(ua)) {
        result.arch = '32-bit';
    } else if (/ARM64|aarch64/i.test(ua)) {
        result.arch = 'ARM64';
    } else if (/ARM/i.test(ua)) {
        result.arch = 'ARM';
    }

    // Extract tokens
    const tokens = ua.match(/[\w.]+\/[\d.]+/g) || [];
    result.raw = tokens;

    displayResults(result);
}

function displayResults(result) {
    // Browser
    document.getElementById('browser-name').textContent = result.browser.name;
    document.getElementById('browser-version').textContent = result.browser.version ? 'v' + result.browser.version : '';

    // OS
    document.getElementById('os-name').textContent = result.os.name;
    document.getElementById('os-version').textContent = result.os.version || '';

    // Device
    document.getElementById('device-type').textContent = result.device.type;
    document.getElementById('device-vendor').textContent = result.device.vendor || '';

    // Engine
    document.getElementById('engine-name').textContent = result.engine.name;
    document.getElementById('engine-version').textContent = result.engine.version ? 'v' + result.engine.version : '';

    // Details
    document.getElementById('is-mobile').textContent = result.isMobile ? 'Oui' : 'Non';
    document.getElementById('is-bot').textContent = result.isBot ? 'Oui' : 'Non';
    document.getElementById('arch').textContent = result.arch || 'Non detecte';
    document.getElementById('platform').textContent = result.os.name;

    // Raw
    document.getElementById('raw-output').textContent = result.raw.join('\n');
}

function detectCurrentUA() {
    document.getElementById('ua-input').value = navigator.userAgent;
    parseUA();
}

const EXAMPLES = {
    'chrome-win': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'firefox-mac': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0',
    'safari-ios': 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1',
    'edge': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0',
    'android': 'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.43 Mobile Safari/537.36',
    'googlebot': 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
    'curl': 'curl/8.4.0'
};

function loadExample(name) {
    document.getElementById('ua-input').value = EXAMPLES[name];
    parseUA();
}

// Initialize with current UA
detectCurrentUA();
</script>
