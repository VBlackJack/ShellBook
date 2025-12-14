---
tags:
  - tools
  - email
  - header
  - security
  - spam
---

# Email Header Analyzer

Analyse des en-tetes d'email pour le diagnostic et la securite.

<div class="tool-container">

<div class="input-section">
    <h3>En-tetes email</h3>
    <textarea id="header-input" placeholder="Collez les en-tetes complets de l'email ici...

Received: from mail.example.com (mail.example.com [192.168.1.1])
    by mx.google.com with ESMTPS id abc123
    for <user@gmail.com>
    (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384);
    Mon, 15 Jan 2024 10:30:00 -0800 (PST)
From: sender@example.com
To: recipient@example.com
Subject: Test Email
..."></textarea>
    <button onclick="analyzeHeaders()" class="action-btn">Analyser</button>
</div>

<div class="results-section" id="results-section" style="display:none;">

    <div class="summary-card" id="summary-card">
        <h3>Resume</h3>
        <div class="summary-grid" id="summary-grid"></div>
    </div>

    <div class="route-section">
        <h3>Chemin de l'email (Route)</h3>
        <div id="route-visual" class="route-visual"></div>
    </div>

    <div class="auth-section">
        <h3>Authentification</h3>
        <div id="auth-results" class="auth-results"></div>
    </div>

    <div class="headers-section">
        <h3>En-tetes detailles</h3>
        <div id="headers-list" class="headers-list"></div>
    </div>

    <div class="security-section">
        <h3>Analyse de securite</h3>
        <div id="security-alerts" class="security-alerts"></div>
    </div>

</div>

</div>

## En-tetes importants

| En-tete | Description |
|---------|-------------|
| **From** | Expediteur affiche |
| **Return-Path** | Adresse de rebond |
| **Received** | Serveurs de transit |
| **Message-ID** | Identifiant unique |
| **Date** | Date d'envoi |
| **X-Originating-IP** | IP d'origine |

## Authentification email

| Methode | Description |
|---------|-------------|
| **SPF** | Sender Policy Framework - verifie l'IP d'envoi |
| **DKIM** | DomainKeys - signature cryptographique |
| **DMARC** | Politique d'authentification du domaine |
| **ARC** | Authenticated Received Chain |

## Obtenir les en-tetes

**Gmail**: Menu ⋮ → "Afficher l'original"
**Outlook**: Fichier → Proprietes → En-tetes Internet
**Apple Mail**: Presentation → Message → En-tetes complets

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
.input-section h3 {
    margin: 0 0 15px 0;
}
.input-section textarea {
    width: 100%;
    min-height: 200px;
    padding: 15px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 12px;
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    background: var(--md-code-bg-color);
    color: var(--md-default-fg-color);
    resize: vertical;
    margin-bottom: 15px;
}
.action-btn {
    padding: 10px 24px;
    background: var(--md-primary-fg-color);
    color: white;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    font-size: 14px;
}
.summary-card, .route-section, .auth-section, .headers-section, .security-section {
    background: var(--md-default-bg-color);
    padding: 20px;
    border-radius: 4px;
    margin-bottom: 20px;
}
.summary-card h3, .route-section h3, .auth-section h3, .headers-section h3, .security-section h3 {
    margin: 0 0 15px 0;
}
.summary-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    gap: 15px;
}
.summary-item {
    background: var(--md-code-bg-color);
    padding: 15px;
    border-radius: 4px;
}
.summary-item label {
    font-size: 12px;
    color: var(--md-default-fg-color--light);
    display: block;
    margin-bottom: 5px;
}
.summary-item .value {
    font-family: monospace;
    word-break: break-all;
}
.route-visual {
    display: flex;
    flex-direction: column;
    gap: 10px;
}
.route-hop {
    display: flex;
    align-items: flex-start;
    gap: 15px;
}
.hop-number {
    width: 30px;
    height: 30px;
    background: var(--md-primary-fg-color);
    color: white;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-weight: bold;
    flex-shrink: 0;
}
.hop-details {
    flex: 1;
    background: var(--md-code-bg-color);
    padding: 15px;
    border-radius: 4px;
}
.hop-details .server {
    font-weight: bold;
    margin-bottom: 5px;
}
.hop-details .info {
    font-size: 12px;
    color: var(--md-default-fg-color--light);
}
.hop-arrow {
    width: 30px;
    text-align: center;
    color: var(--md-default-fg-color--light);
}
.auth-results {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 15px;
}
.auth-item {
    padding: 15px;
    border-radius: 4px;
    border-left: 4px solid;
}
.auth-item.pass {
    background: #d4edda;
    border-color: #28a745;
}
.auth-item.fail {
    background: #f8d7da;
    border-color: #dc3545;
}
.auth-item.none {
    background: var(--md-code-bg-color);
    border-color: var(--md-default-fg-color--light);
}
.auth-item .label {
    font-weight: bold;
    margin-bottom: 5px;
}
.auth-item .status {
    font-size: 12px;
}
.headers-list {
    max-height: 400px;
    overflow-y: auto;
}
.header-item {
    padding: 10px 15px;
    border-bottom: 1px solid var(--md-default-fg-color--lightest);
    display: flex;
    gap: 15px;
}
.header-item:hover {
    background: var(--md-code-bg-color);
}
.header-name {
    min-width: 150px;
    font-weight: bold;
    color: var(--md-primary-fg-color);
}
.header-value {
    flex: 1;
    font-family: monospace;
    font-size: 12px;
    word-break: break-all;
}
.security-alerts {
    display: flex;
    flex-direction: column;
    gap: 10px;
}
.alert {
    padding: 15px;
    border-radius: 4px;
    display: flex;
    align-items: flex-start;
    gap: 10px;
}
.alert.warning {
    background: #fff3cd;
    border: 1px solid #ffc107;
}
.alert.danger {
    background: #f8d7da;
    border: 1px solid #dc3545;
}
.alert.success {
    background: #d4edda;
    border: 1px solid #28a745;
}
.alert .icon {
    font-size: 20px;
}
.alert .message {
    flex: 1;
}
</style>

<script>
function parseHeaders(text) {
    const headers = {};
    const lines = text.split(/\r?\n/);
    let currentHeader = '';
    let currentValue = '';

    lines.forEach(line => {
        if (/^\s+/.test(line)) {
            // Continuation of previous header
            currentValue += ' ' + line.trim();
        } else {
            // Save previous header
            if (currentHeader) {
                if (headers[currentHeader]) {
                    if (!Array.isArray(headers[currentHeader])) {
                        headers[currentHeader] = [headers[currentHeader]];
                    }
                    headers[currentHeader].push(currentValue);
                } else {
                    headers[currentHeader] = currentValue;
                }
            }

            // Parse new header
            const match = line.match(/^([^:]+):\s*(.*)$/);
            if (match) {
                currentHeader = match[1];
                currentValue = match[2];
            } else {
                currentHeader = '';
                currentValue = '';
            }
        }
    });

    // Save last header
    if (currentHeader) {
        if (headers[currentHeader]) {
            if (!Array.isArray(headers[currentHeader])) {
                headers[currentHeader] = [headers[currentHeader]];
            }
            headers[currentHeader].push(currentValue);
        } else {
            headers[currentHeader] = currentValue;
        }
    }

    return headers;
}

function parseReceived(receivedHeaders) {
    if (!receivedHeaders) return [];

    const received = Array.isArray(receivedHeaders) ? receivedHeaders : [receivedHeaders];

    return received.map(header => {
        const hop = { raw: header };

        // Extract from
        const fromMatch = header.match(/from\s+([^\s(]+)(?:\s*\(([^)]+)\))?/i);
        if (fromMatch) {
            hop.from = fromMatch[1];
            hop.fromDetails = fromMatch[2];
        }

        // Extract by
        const byMatch = header.match(/by\s+([^\s(]+)/i);
        if (byMatch) {
            hop.by = byMatch[1];
        }

        // Extract date
        const dateMatch = header.match(/;\s*(.+)$/);
        if (dateMatch) {
            hop.date = dateMatch[1].trim();
            try {
                hop.timestamp = new Date(hop.date);
            } catch (e) {}
        }

        // Extract IP
        const ipMatch = header.match(/\[(\d+\.\d+\.\d+\.\d+)\]/);
        if (ipMatch) {
            hop.ip = ipMatch[1];
        }

        return hop;
    }).reverse(); // Reverse to show oldest first
}

function analyzeHeaders() {
    const input = document.getElementById('header-input').value;
    const headers = parseHeaders(input);

    if (Object.keys(headers).length === 0) {
        alert('Aucun en-tete valide trouve');
        return;
    }

    document.getElementById('results-section').style.display = 'block';

    // Summary
    const summaryGrid = document.getElementById('summary-grid');
    const summaryItems = [
        { label: 'From', value: headers['From'] || '-' },
        { label: 'To', value: headers['To'] || '-' },
        { label: 'Subject', value: headers['Subject'] || '-' },
        { label: 'Date', value: headers['Date'] || '-' },
        { label: 'Return-Path', value: headers['Return-Path'] || '-' },
        { label: 'Message-ID', value: headers['Message-ID'] || '-' }
    ];

    summaryGrid.innerHTML = summaryItems.map(item => `
        <div class="summary-item">
            <label>${item.label}</label>
            <div class="value">${escapeHtml(item.value)}</div>
        </div>
    `).join('');

    // Route
    const hops = parseReceived(headers['Received']);
    const routeVisual = document.getElementById('route-visual');

    if (hops.length > 0) {
        routeVisual.innerHTML = hops.map((hop, i) => `
            <div class="route-hop">
                <div class="hop-number">${i + 1}</div>
                <div class="hop-details">
                    <div class="server">${hop.by || 'Unknown server'}</div>
                    <div class="info">
                        ${hop.from ? `From: ${hop.from}` : ''}
                        ${hop.ip ? ` (${hop.ip})` : ''}
                        ${hop.date ? `<br>Date: ${hop.date}` : ''}
                    </div>
                </div>
            </div>
            ${i < hops.length - 1 ? '<div class="hop-arrow">↓</div>' : ''}
        `).join('');
    } else {
        routeVisual.innerHTML = '<p>Aucune information de routage trouvee</p>';
    }

    // Authentication
    const authResults = document.getElementById('auth-results');
    const authHeaders = headers['Authentication-Results'] || '';

    const spfMatch = authHeaders.match(/spf=(\w+)/i);
    const dkimMatch = authHeaders.match(/dkim=(\w+)/i);
    const dmarcMatch = authHeaders.match(/dmarc=(\w+)/i);

    authResults.innerHTML = `
        <div class="auth-item ${getAuthClass(spfMatch)}">
            <div class="label">SPF</div>
            <div class="status">${spfMatch ? spfMatch[1] : 'Non trouve'}</div>
        </div>
        <div class="auth-item ${getAuthClass(dkimMatch)}">
            <div class="label">DKIM</div>
            <div class="status">${dkimMatch ? dkimMatch[1] : 'Non trouve'}</div>
        </div>
        <div class="auth-item ${getAuthClass(dmarcMatch)}">
            <div class="label">DMARC</div>
            <div class="status">${dmarcMatch ? dmarcMatch[1] : 'Non trouve'}</div>
        </div>
    `;

    // All headers
    const headersList = document.getElementById('headers-list');
    headersList.innerHTML = Object.entries(headers).map(([name, value]) => {
        const values = Array.isArray(value) ? value : [value];
        return values.map(v => `
            <div class="header-item">
                <div class="header-name">${escapeHtml(name)}</div>
                <div class="header-value">${escapeHtml(v)}</div>
            </div>
        `).join('');
    }).join('');

    // Security analysis
    analyzeSecurityIssues(headers);
}

function getAuthClass(match) {
    if (!match) return 'none';
    const result = match[1].toLowerCase();
    if (result === 'pass') return 'pass';
    if (result === 'fail' || result === 'softfail') return 'fail';
    return 'none';
}

function analyzeSecurityIssues(headers) {
    const alerts = [];

    // Check SPF/DKIM/DMARC
    const authResults = headers['Authentication-Results'] || '';

    if (!authResults.includes('spf=pass')) {
        alerts.push({
            type: 'warning',
            icon: '⚠️',
            message: 'SPF n\'a pas reussi - l\'expediteur pourrait ne pas etre autorise'
        });
    }

    if (!authResults.includes('dkim=pass')) {
        alerts.push({
            type: 'warning',
            icon: '⚠️',
            message: 'DKIM non verifie - le message pourrait avoir ete modifie'
        });
    }

    // Check From vs Return-Path mismatch
    const from = headers['From'] || '';
    const returnPath = headers['Return-Path'] || '';

    if (from && returnPath) {
        const fromDomain = from.match(/@([^\s>]+)/);
        const returnDomain = returnPath.match(/@([^\s>]+)/);

        if (fromDomain && returnDomain && fromDomain[1] !== returnDomain[1]) {
            alerts.push({
                type: 'warning',
                icon: '⚠️',
                message: `Domaine From (${fromDomain[1]}) different du Return-Path (${returnDomain[1]})`
            });
        }
    }

    // Check for suspicious headers
    if (headers['X-Spam-Flag'] === 'YES' || headers['X-Spam-Status']?.includes('Yes')) {
        alerts.push({
            type: 'danger',
            icon: '🚨',
            message: 'Ce message a ete marque comme SPAM'
        });
    }

    if (alerts.length === 0) {
        alerts.push({
            type: 'success',
            icon: '✓',
            message: 'Aucun probleme de securite evident detecte'
        });
    }

    const securityAlerts = document.getElementById('security-alerts');
    securityAlerts.innerHTML = alerts.map(alert => `
        <div class="alert ${alert.type}">
            <span class="icon">${alert.icon}</span>
            <span class="message">${alert.message}</span>
        </div>
    `).join('');
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Example headers
document.getElementById('header-input').value = `Delivered-To: recipient@gmail.com
Received: by 2002:a17:90b:1234:0:0:0:0 with SMTP id abc123;
        Mon, 15 Jan 2024 10:30:00 -0800 (PST)
Received: from mail.example.com (mail.example.com. [192.168.1.100])
        by mx.google.com with ESMTPS id xyz789
        for <recipient@gmail.com>;
        Mon, 15 Jan 2024 10:29:55 -0800 (PST)
Received: from localhost (localhost [127.0.0.1])
        by mail.example.com (Postfix) with ESMTP id ABC123
        for <recipient@gmail.com>;
        Mon, 15 Jan 2024 18:29:50 +0000 (UTC)
Authentication-Results: mx.google.com;
       dkim=pass header.i=@example.com header.s=selector1;
       spf=pass (google.com: domain of sender@example.com designates 192.168.1.100 as permitted sender);
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=example.com
From: "John Doe" <sender@example.com>
To: recipient@gmail.com
Subject: Test Email Subject
Date: Mon, 15 Jan 2024 18:29:50 +0000
Message-ID: <abc123@mail.example.com>
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Return-Path: <sender@example.com>
X-Mailer: Custom Mailer 1.0`;
</script>
