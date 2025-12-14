---
tags:
  - tools
  - network
  - mac
  - oui
---

# MAC Address Lookup

Recherche du fabricant par adresse MAC (OUI lookup).

<div class="tool-container">

<div class="input-group">
    <label for="mac-input">Adresse MAC :</label>
    <input type="text" id="mac-input" placeholder="00:1A:2B:3C:4D:5E" maxlength="17">
    <small>Formats acceptes: 00:1A:2B:3C:4D:5E, 00-1A-2B-3C-4D-5E, 001A2B3C4D5E</small>
</div>

<button onclick="lookupMAC()" class="calc-btn">Rechercher</button>

<div id="mac-results" class="results-box">
    <table>
        <tr><td><strong>Adresse MAC</strong></td><td id="mac-formatted">-</td></tr>
        <tr><td><strong>OUI (Prefixe)</strong></td><td id="mac-oui">-</td></tr>
        <tr><td><strong>Fabricant</strong></td><td id="mac-vendor">-</td></tr>
        <tr><td><strong>Type</strong></td><td id="mac-type">-</td></tr>
    </table>
</div>

<div class="batch-section">
    <h4>Recherche en lot</h4>
    <textarea id="mac-batch-input" placeholder="Une adresse MAC par ligne..."></textarea>
    <button onclick="batchLookup()" class="calc-btn">Rechercher tout</button>
    <div id="batch-results"></div>
</div>

</div>

## Comprendre les adresses MAC

### Structure

```
AA:BB:CC:DD:EE:FF
|-----|  |-----|
  OUI      NIC
(Vendor) (Unique)
```

- **OUI (Organizationally Unique Identifier)** : 3 premiers octets, identifies le fabricant
- **NIC (Network Interface Controller)** : 3 derniers octets, numero de serie unique

### Bits speciaux

| Bit | Position | Signification |
|-----|----------|---------------|
| U/L | bit 1 octet 1 | 0=UAA (universel), 1=LAA (local) |
| I/G | bit 0 octet 1 | 0=Unicast, 1=Multicast/Broadcast |

### Adresses speciales

| Adresse | Signification |
|---------|---------------|
| `FF:FF:FF:FF:FF:FF` | Broadcast |
| `01:00:5E:xx:xx:xx` | Multicast IPv4 |
| `33:33:xx:xx:xx:xx` | Multicast IPv6 |
| `00:00:00:00:00:00` | Non definie |

### Prefixes courants

| Prefixe | Fabricant |
|---------|-----------|
| `00:50:56` | VMware |
| `00:0C:29` | VMware |
| `52:54:00` | QEMU/KVM |
| `08:00:27` | VirtualBox |
| `00:15:5D` | Microsoft Hyper-V |
| `00:1C:42` | Parallels |
| `AC:DE:48` | Private (RFC 7042) |

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
.input-group input {
    padding: 12px;
    font-size: 18px;
    font-family: monospace;
    width: 300px;
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    background: var(--md-default-bg-color);
    color: var(--md-default-fg-color);
    text-transform: uppercase;
}
.input-group small {
    display: block;
    margin-top: 5px;
    color: var(--md-default-fg-color--light);
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
    padding: 10px;
    border-bottom: 1px solid var(--md-default-fg-color--lightest);
}
.results-box td:last-child {
    font-family: monospace;
}
.batch-section {
    margin-top: 30px;
    padding-top: 20px;
    border-top: 1px solid var(--md-default-fg-color--lighter);
}
.batch-section h4 {
    margin: 0 0 15px 0;
}
#mac-batch-input {
    width: 100%;
    height: 100px;
    padding: 10px;
    font-family: monospace;
    font-size: 14px;
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    background: var(--md-default-bg-color);
    color: var(--md-default-fg-color);
    margin-bottom: 10px;
}
#batch-results {
    margin-top: 15px;
}
#batch-results table {
    width: 100%;
    border-collapse: collapse;
}
#batch-results th, #batch-results td {
    padding: 8px;
    text-align: left;
    border-bottom: 1px solid var(--md-default-fg-color--lightest);
}
#batch-results th {
    background: var(--md-code-bg-color);
}
</style>

<script>
// Common OUI database (top manufacturers)
const ouiDatabase = {
    '000C29': 'VMware, Inc.',
    '005056': 'VMware, Inc.',
    '001C14': 'VMware, Inc.',
    '000569': 'VMware, Inc.',
    '080027': 'Oracle VirtualBox',
    '0A0027': 'Oracle VirtualBox',
    '525400': 'QEMU/KVM',
    '001C42': 'Parallels, Inc.',
    '00155D': 'Microsoft Hyper-V',
    '002248': 'Microsoft Corporation',
    '0050F2': 'Microsoft Corporation',
    'ACDE48': 'Private (RFC 7042)',
    '00000C': 'Cisco Systems',
    '000142': 'Cisco Systems',
    '000143': 'Cisco Systems',
    '000164': 'Cisco Systems',
    '0001C7': 'Cisco Systems',
    '0001C9': 'Cisco Systems',
    '000216': 'Cisco Systems',
    '000217': 'Cisco Systems',
    '0007B3': 'Cisco Systems',
    'D8B190': 'Cisco Systems',
    '001B17': 'Palo Alto Networks',
    'AABBCC': 'Private (Test)',
    'A4C494': 'Intel Corporate',
    '3C2EFF': 'Intel Corporate',
    '8C8590': 'Intel Corporate',
    '88B111': 'Intel Corporate',
    '001E67': 'Intel Corporate',
    '001E65': 'Intel Corporate',
    '0024D6': 'Intel Corporate',
    '4CCC6A': 'Intel Corporate',
    'F8B156': 'Dell Inc.',
    'F8BC12': 'Dell Inc.',
    '000874': 'Dell Inc.',
    '001A4B': 'Dell Inc.',
    '001C23': 'Dell Inc.',
    '001D09': 'Dell Inc.',
    '001E4F': 'Dell Inc.',
    '002219': 'Dell Inc.',
    'B8AEED': 'Dell Inc.',
    'B499BA': 'Hewlett Packard',
    '000D9D': 'Hewlett Packard',
    '001083': 'Hewlett Packard',
    '001185': 'Hewlett Packard',
    '0014C2': 'Hewlett Packard',
    '001560': 'Hewlett Packard',
    '0017A4': 'Hewlett Packard',
    '00188B': 'Hewlett Packard',
    '001A4B': 'Hewlett Packard',
    '001CC4': 'Hewlett Packard',
    '0021B7': 'Lexmark International',
    'AC1F6B': 'Super Micro Computer',
    '002590': 'Super Micro Computer',
    '0CC47A': 'Super Micro Computer',
    '7CC255': 'Super Micro Computer',
    '94C691': 'Lenovo',
    'E8E0B7': 'Lenovo',
    'F0DEF1': 'Lenovo',
    '28D244': 'Lenovo',
    '6C4B90': 'Lenovo',
    'E440E2': 'Samsung Electronics',
    'F8D0BD': 'Samsung Electronics',
    'CC07AB': 'Samsung Electronics',
    '5056BF': 'Samsung Electronics',
    '000D3A': 'Microsoft Corporation',
    '00125A': 'Microsoft Corporation',
    '0015C5': 'Microsoft Corporation',
    '0017FA': 'Microsoft Corporation',
    '001DD8': 'Microsoft Corporation',
    '002243': 'AzureWave Technology',
    '60C5AD': 'Samsung Electronics',
    '14DAE9': 'AsusTek Computer',
    '60A44C': 'AsusTek Computer',
    '74D02B': 'AsusTek Computer',
    'BCEE7B': 'AsusTek Computer',
    '00044B': 'NVIDIA Corporation',
    '043D98': 'NVIDIA Corporation',
    '48B02D': 'NVIDIA Corporation',
    '00E04C': 'Realtek Semiconductor',
    '52540B': 'Realtek Semiconductor',
    '001F1F': 'Edimax Technology',
    '001AEB': 'Edimax Technology',
    'B827EB': 'Raspberry Pi Foundation',
    'DC2632': 'Raspberry Pi Foundation',
    'E45F01': 'Raspberry Pi Foundation',
    '48E1E9': 'Ubiquiti Networks',
    'B4FBE4': 'Ubiquiti Networks',
    'DC9FDB': 'Ubiquiti Networks',
    '24A43C': 'Ubiquiti Networks',
    '802AA8': 'Ubiquiti Networks',
    'F09FC2': 'Ubiquiti Networks',
    '687251': 'Ubiquiti Networks',
    '00074D': 'Zebra Technologies',
    '001FEB': 'Zebra Technologies',
    '0023A4': 'Zebra Technologies',
    '0025DF': 'Zebra Technologies',
    '001BBA': 'Fortinet, Inc.',
    '70483E': 'Fortinet, Inc.',
    '907841': 'Fortinet, Inc.',
    '00249B': 'Fortinet, Inc.',
    '085B0E': 'Fortinet, Inc.',
    '000F5F': 'Cisco Systems',
    '0011BB': 'Cisco Systems',
    '0012D9': 'Cisco Systems',
    '001440': 'Cisco Systems',
    '001564': 'Cisco Systems',
    '0016C8': 'Cisco Systems',
    '0017E0': 'Cisco Systems',
    '00192F': 'Cisco Systems',
    '001A2F': 'Cisco Systems',
    '001A6C': 'Cisco Systems',
    '001B2A': 'Cisco Systems',
    '001BD4': 'Cisco Systems',
    '001CBD': 'Cisco Systems',
    '001D45': 'Cisco Systems',
    '001D70': 'Cisco Systems',
    '001E49': 'Cisco Systems',
    '001E4A': 'Cisco Systems',
    '001E79': 'Cisco Systems',
    '001EE5': 'Cisco Systems',
    '001F27': 'Cisco Systems',
    '001F6C': 'Cisco Systems',
    '001FE1': 'Cisco Systems',
    '0021D7': 'Cisco Systems',
    '0022CE': 'Cisco Systems',
    '002436': 'Cisco Systems',
    '002504': 'Cisco Systems',
    '00259C': 'Cisco Systems',
    '0025B4': 'Cisco Systems',
    '0026CB': 'Cisco Systems',
    '0CB6D2': 'Cisco Systems',
    '18E728': 'Cisco Systems',
    '1C6A7A': 'Cisco Systems',
    '241B7A': 'Cisco Systems',
    '286F7F': 'Cisco Systems',
    '2C542D': 'Cisco Systems',
    '2C5A0F': 'Cisco Systems',
    '2C86D2': 'Cisco Systems',
    '34A84E': 'Cisco Systems',
    '44AD52': 'Cisco Systems',
    '50064F': 'Cisco Systems',
    '54781A': 'Cisco Systems',
    '5C5015': 'Cisco Systems',
    '6400F1': 'Cisco Systems',
    '6C416A': 'Cisco Systems',
    '6C9989': 'Cisco Systems',
    '70CA9B': 'Cisco Systems',
    '7CC537': 'Cisco Systems',
    '847A88': 'Cisco Systems',
    '84802D': 'Cisco Systems',
    '885A92': 'Cisco Systems',
    '88F031': 'Cisco Systems',
    '8C604F': 'Cisco Systems',
    'A02BB8': 'Cisco Systems',
    'A0ECF9': 'Cisco Systems',
    'A434D9': 'Cisco Systems',
    'A4934C': 'Cisco Systems',
    'B07D47': 'Cisco Systems',
    'B0C53C': 'Cisco Systems',
    'B0FA47': 'Cisco Systems',
    'B4E9B0': 'Cisco Systems',
    'BC16F5': 'Cisco Systems',
    'C4F7D5': 'Cisco Systems',
    'D077CE': 'Cisco Systems',
    'D4D748': 'Cisco Systems',
    'D8B190': 'Cisco Systems',
    'E05D5E': 'Cisco Systems',
    'E4D3F1': 'Cisco Systems',
    'F0F7B3': 'Cisco Systems',
    'FC5B39': 'Cisco Systems',
    'D0D3E0': 'Aruba Networks',
    '001A1E': 'Aruba Networks',
    '00247C': 'Aruba Networks',
    '1CC1DE': 'Aruba Networks',
    '20A6CD': 'Aruba Networks',
    '24F27F': 'Aruba Networks',
    '40E3D6': 'Aruba Networks',
    '6C8BD5': 'Aruba Networks',
    '9C1C12': 'Aruba Networks',
    'B4F61C': 'Aruba Networks',
    'D8C7C8': 'Aruba Networks',
    '000FB5': 'Netgear',
    '0024B2': 'Netgear',
    '20E52A': 'Netgear',
    '4CF95D': 'Netgear',
    '6C70A3': 'Netgear',
    'C43DC7': 'Netgear',
    'E091F5': 'Netgear',
    '28C68E': 'Netgear',
    '30469A': 'Netgear',
    '44A56E': 'Netgear',
    '84681B': 'Netgear',
    '9CD643': 'Netgear',
    'A40E2B': 'Netgear',
    'B0B98A': 'Netgear',
    'C0FFD4': 'Netgear',
    'A42B8C': 'Synology Incorporated',
    '001132': 'Synology Incorporated',
    '0011BB': 'Cisco Systems',
    '382C4A': 'ASUSTek Computer',
    '50465D': 'ASUSTek Computer',
    '485B39': 'ASUSTek Computer'
};

function normalizeMAC(mac) {
    // Remove all separators and convert to uppercase
    return mac.replace(/[:\-\.]/g, '').toUpperCase();
}

function formatMAC(mac) {
    const normalized = normalizeMAC(mac);
    if (normalized.length !== 12) return null;
    return normalized.match(/.{2}/g).join(':');
}

function lookupMAC() {
    const macInput = document.getElementById('mac-input').value;
    const normalized = normalizeMAC(macInput);

    if (normalized.length < 6) {
        document.getElementById('mac-vendor').textContent = 'Adresse MAC invalide';
        return;
    }

    const formatted = formatMAC(macInput) || macInput.toUpperCase();
    const oui = normalized.substring(0, 6);

    document.getElementById('mac-formatted').textContent = formatted;
    document.getElementById('mac-oui').textContent = oui.match(/.{2}/g).join(':');

    // Check vendor
    const vendor = ouiDatabase[oui];
    document.getElementById('mac-vendor').textContent = vendor || 'Inconnu (non dans la base locale)';

    // Check type
    const firstByte = parseInt(normalized.substring(0, 2), 16);
    let macType = [];

    if (firstByte & 0x01) {
        macType.push('Multicast');
    } else {
        macType.push('Unicast');
    }

    if (firstByte & 0x02) {
        macType.push('LAA (Locally Administered)');
    } else {
        macType.push('UAA (Universally Administered)');
    }

    if (normalized === 'FFFFFFFFFFFF') {
        macType = ['Broadcast'];
    } else if (normalized.startsWith('01005E')) {
        macType.push('IPv4 Multicast');
    } else if (normalized.startsWith('3333')) {
        macType.push('IPv6 Multicast');
    }

    document.getElementById('mac-type').textContent = macType.join(', ');
}

function batchLookup() {
    const input = document.getElementById('mac-batch-input').value;
    const macs = input.split('\n').filter(m => m.trim());

    if (macs.length === 0) return;

    let html = '<table><tr><th>MAC</th><th>OUI</th><th>Fabricant</th></tr>';

    for (const mac of macs) {
        const normalized = normalizeMAC(mac);
        if (normalized.length < 6) continue;

        const formatted = formatMAC(mac) || mac.toUpperCase();
        const oui = normalized.substring(0, 6);
        const vendor = ouiDatabase[oui] || 'Inconnu';

        html += `<tr><td>${formatted}</td><td>${oui.match(/.{2}/g).join(':')}</td><td>${vendor}</td></tr>`;
    }

    html += '</table>';
    document.getElementById('batch-results').innerHTML = html;
}

// Event listener for Enter key
document.getElementById('mac-input').addEventListener('keypress', function(e) {
    if (e.key === 'Enter') lookupMAC();
});

// Auto-format as user types
document.getElementById('mac-input').addEventListener('input', function() {
    const val = this.value.replace(/[^0-9A-Fa-f]/g, '');
    if (val.length >= 6) {
        lookupMAC();
    }
});
</script>
