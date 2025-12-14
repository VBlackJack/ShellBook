---
tags:
  - tools
  - network
  - subnet
  - cidr
---

# Subnet Calculator

Calculateur de sous-réseaux IPv4 avec support CIDR.

<div class="tool-container">

<div class="input-group">
    <label for="ip-input">Adresse IP :</label>
    <input type="text" id="ip-input" placeholder="192.168.1.0" value="192.168.1.0">
</div>

<div class="input-group">
    <label for="cidr-input">CIDR (préfixe) :</label>
    <input type="range" id="cidr-slider" min="1" max="32" value="24">
    <span id="cidr-display">/24</span>
</div>

<button onclick="calculateSubnet()" class="calc-btn">Calculer</button>

<div id="subnet-results" class="results-box">
    <table>
        <tr><td><strong>Adresse réseau</strong></td><td id="network-addr">-</td></tr>
        <tr><td><strong>Masque</strong></td><td id="subnet-mask">-</td></tr>
        <tr><td><strong>Wildcard</strong></td><td id="wildcard-mask">-</td></tr>
        <tr><td><strong>Broadcast</strong></td><td id="broadcast-addr">-</td></tr>
        <tr><td><strong>Première IP</strong></td><td id="first-ip">-</td></tr>
        <tr><td><strong>Dernière IP</strong></td><td id="last-ip">-</td></tr>
        <tr><td><strong>Nombre d'hôtes</strong></td><td id="host-count">-</td></tr>
        <tr><td><strong>Classe</strong></td><td id="ip-class">-</td></tr>
        <tr><td><strong>Type</strong></td><td id="ip-type">-</td></tr>
    </table>
</div>

</div>

## Tableau CIDR de référence

| CIDR | Masque | Hôtes | Usage typique |
|------|--------|-------|---------------|
| /32 | 255.255.255.255 | 1 | Host route |
| /31 | 255.255.255.254 | 2 | Point-to-point |
| /30 | 255.255.255.252 | 2 | Point-to-point |
| /29 | 255.255.255.248 | 6 | Petit segment |
| /28 | 255.255.255.240 | 14 | Petit LAN |
| /27 | 255.255.255.224 | 30 | Petit LAN |
| /26 | 255.255.255.192 | 62 | LAN moyen |
| /25 | 255.255.255.128 | 126 | LAN moyen |
| /24 | 255.255.255.0 | 254 | LAN standard |
| /23 | 255.255.254.0 | 510 | Grand LAN |
| /22 | 255.255.252.0 | 1022 | Grand LAN |
| /21 | 255.255.248.0 | 2046 | Campus |
| /20 | 255.255.240.0 | 4094 | Campus |
| /16 | 255.255.0.0 | 65534 | Classe B |
| /8 | 255.0.0.0 | 16M | Classe A |

## Plages privées (RFC 1918)

| Classe | Plage | CIDR |
|--------|-------|------|
| A | 10.0.0.0 - 10.255.255.255 | 10.0.0.0/8 |
| B | 172.16.0.0 - 172.31.255.255 | 172.16.0.0/12 |
| C | 192.168.0.0 - 192.168.255.255 | 192.168.0.0/16 |

<style>
.tool-container {
    background: var(--md-code-bg-color);
    padding: 20px;
    border-radius: 8px;
    margin: 20px 0;
}
.input-group {
    margin: 15px 0;
}
.input-group label {
    display: block;
    margin-bottom: 5px;
    font-weight: bold;
}
.input-group input[type="text"] {
    padding: 10px;
    font-size: 16px;
    width: 200px;
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    background: var(--md-default-bg-color);
    color: var(--md-default-fg-color);
}
.input-group input[type="range"] {
    width: 200px;
    vertical-align: middle;
}
#cidr-display {
    font-family: monospace;
    font-size: 18px;
    margin-left: 10px;
}
.calc-btn {
    background: var(--md-primary-fg-color);
    color: white;
    border: none;
    padding: 12px 24px;
    font-size: 16px;
    border-radius: 4px;
    cursor: pointer;
    margin-top: 10px;
}
.calc-btn:hover {
    opacity: 0.9;
}
.results-box {
    margin-top: 20px;
    padding: 15px;
    background: var(--md-default-bg-color);
    border-radius: 4px;
    border: 1px solid var(--md-default-fg-color--lighter);
}
.results-box table {
    width: 100%;
}
.results-box td {
    padding: 8px;
    border-bottom: 1px solid var(--md-default-fg-color--lightest);
}
.results-box td:last-child {
    font-family: monospace;
    text-align: right;
}
</style>

<script>
document.getElementById('cidr-slider').addEventListener('input', function() {
    document.getElementById('cidr-display').textContent = '/' + this.value;
    calculateSubnet();
});

document.getElementById('ip-input').addEventListener('input', calculateSubnet);

function ipToLong(ip) {
    const parts = ip.split('.');
    return ((parseInt(parts[0]) << 24) + (parseInt(parts[1]) << 16) +
            (parseInt(parts[2]) << 8) + parseInt(parts[3])) >>> 0;
}

function longToIp(long) {
    return [
        (long >>> 24) & 255,
        (long >>> 16) & 255,
        (long >>> 8) & 255,
        long & 255
    ].join('.');
}

function calculateSubnet() {
    const ip = document.getElementById('ip-input').value;
    const cidr = parseInt(document.getElementById('cidr-slider').value);

    // Validate IP
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (!ipRegex.test(ip)) return;

    const parts = ip.split('.').map(Number);
    if (parts.some(p => p > 255)) return;

    const ipLong = ipToLong(ip);
    const mask = cidr === 0 ? 0 : (0xFFFFFFFF << (32 - cidr)) >>> 0;
    const wildcard = ~mask >>> 0;
    const network = (ipLong & mask) >>> 0;
    const broadcast = (network | wildcard) >>> 0;
    const firstHost = cidr >= 31 ? network : network + 1;
    const lastHost = cidr >= 31 ? broadcast : broadcast - 1;
    const hostCount = cidr >= 31 ? (cidr === 32 ? 1 : 2) : Math.pow(2, 32 - cidr) - 2;

    // Determine class
    let ipClass = 'N/A';
    if (parts[0] < 128) ipClass = 'A';
    else if (parts[0] < 192) ipClass = 'B';
    else if (parts[0] < 224) ipClass = 'C';
    else if (parts[0] < 240) ipClass = 'D (Multicast)';
    else ipClass = 'E (Reserved)';

    // Determine type
    let ipType = 'Public';
    if (parts[0] === 10) ipType = 'Private (RFC 1918)';
    else if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ipType = 'Private (RFC 1918)';
    else if (parts[0] === 192 && parts[1] === 168) ipType = 'Private (RFC 1918)';
    else if (parts[0] === 127) ipType = 'Loopback';
    else if (parts[0] === 169 && parts[1] === 254) ipType = 'Link-local (APIPA)';

    document.getElementById('network-addr').textContent = longToIp(network) + '/' + cidr;
    document.getElementById('subnet-mask').textContent = longToIp(mask);
    document.getElementById('wildcard-mask').textContent = longToIp(wildcard);
    document.getElementById('broadcast-addr').textContent = longToIp(broadcast);
    document.getElementById('first-ip').textContent = longToIp(firstHost);
    document.getElementById('last-ip').textContent = longToIp(lastHost);
    document.getElementById('host-count').textContent = hostCount.toLocaleString();
    document.getElementById('ip-class').textContent = ipClass;
    document.getElementById('ip-type').textContent = ipType;
}

// Initial calculation
calculateSubnet();
</script>
