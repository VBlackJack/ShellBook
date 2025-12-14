---
tags:
  - tools
  - network
  - ports
  - firewall
---

# Port Reference

Reference des ports TCP/UDP courants.

<div class="tool-container">

<div class="search-section">
    <input type="text" id="port-search" placeholder="Rechercher par numero ou service...">
    <select id="port-filter">
        <option value="">Tous</option>
        <option value="web">Web & HTTP</option>
        <option value="mail">Email</option>
        <option value="database">Bases de donnees</option>
        <option value="file">Fichiers & Partage</option>
        <option value="remote">Acces distant</option>
        <option value="dns">DNS & Reseau</option>
        <option value="security">Securite</option>
        <option value="monitoring">Monitoring</option>
    </select>
</div>

<div class="port-table">
    <table id="port-table">
        <thead>
            <tr>
                <th>Port</th>
                <th>Protocol</th>
                <th>Service</th>
                <th>Description</th>
            </tr>
        </thead>
        <tbody id="port-tbody">
        </tbody>
    </table>
</div>

</div>

## Plages de ports

| Plage | Nom | Description |
|-------|-----|-------------|
| 0-1023 | Well-known | Ports systeme (root requis) |
| 1024-49151 | Registered | Ports enregistres IANA |
| 49152-65535 | Dynamic/Private | Ports ephemeres/prives |

## Regles firewall courantes

### Linux (firewalld)

```bash
# Autoriser un port
firewall-cmd --add-port=8080/tcp --permanent
firewall-cmd --add-service=https --permanent
firewall-cmd --reload

# Lister les ports ouverts
firewall-cmd --list-ports
firewall-cmd --list-services
```

### Linux (iptables)

```bash
# Autoriser un port
iptables -A INPUT -p tcp --dport 8080 -j ACCEPT
iptables -A INPUT -p udp --dport 53 -j ACCEPT

# Sauvegarder
iptables-save > /etc/iptables.rules
```

### Windows

```powershell
# Autoriser un port
New-NetFirewallRule -DisplayName "Allow 8080" -Direction Inbound -Port 8080 -Protocol TCP -Action Allow

# Lister les regles
Get-NetFirewallRule | Where-Object { $_.Enabled -eq 'True' }
```

## Verification des ports

```bash
# Linux - ports en ecoute
ss -tlnp
netstat -tlnp

# Test connexion
nc -zv host 80
telnet host 80

# Windows
netstat -an | findstr LISTENING
Test-NetConnection -ComputerName host -Port 80
```

<style>
.tool-container {
    background: var(--md-code-bg-color);
    padding: 20px;
    border-radius: 8px;
    margin: 20px 0;
}
.search-section {
    display: flex;
    gap: 15px;
    flex-wrap: wrap;
    margin-bottom: 20px;
}
.search-section input {
    flex: 1;
    min-width: 200px;
    padding: 10px;
    font-size: 16px;
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    background: var(--md-default-bg-color);
    color: var(--md-default-fg-color);
}
.search-section select {
    padding: 10px;
    font-size: 14px;
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    background: var(--md-default-bg-color);
    color: var(--md-default-fg-color);
}
.port-table {
    overflow-x: auto;
}
.port-table table {
    width: 100%;
    background: var(--md-default-bg-color);
    border-collapse: collapse;
}
.port-table th, .port-table td {
    padding: 10px;
    text-align: left;
    border-bottom: 1px solid var(--md-default-fg-color--lightest);
}
.port-table th {
    background: var(--md-code-bg-color);
    font-weight: bold;
    position: sticky;
    top: 0;
}
.port-table td:first-child {
    font-family: monospace;
    font-weight: bold;
    color: var(--md-primary-fg-color);
}
.port-table td:nth-child(2) {
    font-family: monospace;
}
.port-table tr:hover {
    background: var(--md-code-bg-color);
}
</style>

<script>
const ports = [
    // Web & HTTP
    { port: 80, protocol: 'TCP', service: 'HTTP', desc: 'Web non securise', category: 'web' },
    { port: 443, protocol: 'TCP', service: 'HTTPS', desc: 'Web securise (TLS)', category: 'web' },
    { port: 8080, protocol: 'TCP', service: 'HTTP-Alt', desc: 'HTTP alternatif / Proxy', category: 'web' },
    { port: 8443, protocol: 'TCP', service: 'HTTPS-Alt', desc: 'HTTPS alternatif', category: 'web' },
    { port: 3000, protocol: 'TCP', service: 'Node.js', desc: 'Dev Node.js / React', category: 'web' },
    { port: 5000, protocol: 'TCP', service: 'Flask/Dev', desc: 'Dev Python Flask', category: 'web' },
    { port: 8000, protocol: 'TCP', service: 'Django/Dev', desc: 'Dev Python Django', category: 'web' },

    // Email
    { port: 25, protocol: 'TCP', service: 'SMTP', desc: 'Email envoi (non securise)', category: 'mail' },
    { port: 465, protocol: 'TCP', service: 'SMTPS', desc: 'SMTP over SSL', category: 'mail' },
    { port: 587, protocol: 'TCP', service: 'SMTP-SUB', desc: 'SMTP submission (STARTTLS)', category: 'mail' },
    { port: 110, protocol: 'TCP', service: 'POP3', desc: 'Reception email POP3', category: 'mail' },
    { port: 995, protocol: 'TCP', service: 'POP3S', desc: 'POP3 over SSL', category: 'mail' },
    { port: 143, protocol: 'TCP', service: 'IMAP', desc: 'Reception email IMAP', category: 'mail' },
    { port: 993, protocol: 'TCP', service: 'IMAPS', desc: 'IMAP over SSL', category: 'mail' },

    // Databases
    { port: 3306, protocol: 'TCP', service: 'MySQL/MariaDB', desc: 'Base de donnees MySQL', category: 'database' },
    { port: 5432, protocol: 'TCP', service: 'PostgreSQL', desc: 'Base de donnees PostgreSQL', category: 'database' },
    { port: 1433, protocol: 'TCP', service: 'MSSQL', desc: 'Microsoft SQL Server', category: 'database' },
    { port: 1521, protocol: 'TCP', service: 'Oracle', desc: 'Oracle Database', category: 'database' },
    { port: 27017, protocol: 'TCP', service: 'MongoDB', desc: 'Base NoSQL MongoDB', category: 'database' },
    { port: 6379, protocol: 'TCP', service: 'Redis', desc: 'Cache Redis', category: 'database' },
    { port: 11211, protocol: 'TCP/UDP', service: 'Memcached', desc: 'Cache Memcached', category: 'database' },
    { port: 9200, protocol: 'TCP', service: 'Elasticsearch', desc: 'Moteur de recherche', category: 'database' },
    { port: 5984, protocol: 'TCP', service: 'CouchDB', desc: 'Base NoSQL CouchDB', category: 'database' },

    // File & Sharing
    { port: 20, protocol: 'TCP', service: 'FTP-DATA', desc: 'FTP transfert donnees', category: 'file' },
    { port: 21, protocol: 'TCP', service: 'FTP', desc: 'FTP controle', category: 'file' },
    { port: 22, protocol: 'TCP', service: 'SFTP/SSH', desc: 'Transfert securise via SSH', category: 'file' },
    { port: 69, protocol: 'UDP', service: 'TFTP', desc: 'Transfert trivial', category: 'file' },
    { port: 111, protocol: 'TCP/UDP', service: 'RPC', desc: 'Remote Procedure Call', category: 'file' },
    { port: 137, protocol: 'UDP', service: 'NetBIOS-NS', desc: 'NetBIOS Name Service', category: 'file' },
    { port: 138, protocol: 'UDP', service: 'NetBIOS-DGM', desc: 'NetBIOS Datagram', category: 'file' },
    { port: 139, protocol: 'TCP', service: 'NetBIOS-SSN', desc: 'NetBIOS Session (SMB)', category: 'file' },
    { port: 445, protocol: 'TCP', service: 'SMB', desc: 'Partage Windows/Samba', category: 'file' },
    { port: 2049, protocol: 'TCP/UDP', service: 'NFS', desc: 'Network File System', category: 'file' },
    { port: 873, protocol: 'TCP', service: 'rsync', desc: 'Synchronisation rsync', category: 'file' },

    // Remote Access
    { port: 22, protocol: 'TCP', service: 'SSH', desc: 'Secure Shell', category: 'remote' },
    { port: 23, protocol: 'TCP', service: 'Telnet', desc: 'Telnet (non securise)', category: 'remote' },
    { port: 3389, protocol: 'TCP', service: 'RDP', desc: 'Remote Desktop Windows', category: 'remote' },
    { port: 5900, protocol: 'TCP', service: 'VNC', desc: 'Virtual Network Computing', category: 'remote' },
    { port: 5901, protocol: 'TCP', service: 'VNC-1', desc: 'VNC Display 1', category: 'remote' },
    { port: 4899, protocol: 'TCP', service: 'Radmin', desc: 'Radmin Remote Control', category: 'remote' },

    // DNS & Network
    { port: 53, protocol: 'TCP/UDP', service: 'DNS', desc: 'Domain Name System', category: 'dns' },
    { port: 67, protocol: 'UDP', service: 'DHCP-Server', desc: 'DHCP serveur', category: 'dns' },
    { port: 68, protocol: 'UDP', service: 'DHCP-Client', desc: 'DHCP client', category: 'dns' },
    { port: 123, protocol: 'UDP', service: 'NTP', desc: 'Network Time Protocol', category: 'dns' },
    { port: 161, protocol: 'UDP', service: 'SNMP', desc: 'Simple Network Management', category: 'dns' },
    { port: 162, protocol: 'UDP', service: 'SNMP-Trap', desc: 'SNMP Trap', category: 'dns' },
    { port: 179, protocol: 'TCP', service: 'BGP', desc: 'Border Gateway Protocol', category: 'dns' },
    { port: 500, protocol: 'UDP', service: 'IKE', desc: 'IPsec Key Exchange', category: 'dns' },
    { port: 514, protocol: 'UDP', service: 'Syslog', desc: 'Journalisation systeme', category: 'dns' },
    { port: 1194, protocol: 'UDP', service: 'OpenVPN', desc: 'VPN OpenVPN', category: 'dns' },
    { port: 51820, protocol: 'UDP', service: 'WireGuard', desc: 'VPN WireGuard', category: 'dns' },

    // Security
    { port: 88, protocol: 'TCP/UDP', service: 'Kerberos', desc: 'Authentification Kerberos', category: 'security' },
    { port: 389, protocol: 'TCP', service: 'LDAP', desc: 'Annuaire LDAP', category: 'security' },
    { port: 636, protocol: 'TCP', service: 'LDAPS', desc: 'LDAP over SSL', category: 'security' },
    { port: 749, protocol: 'TCP', service: 'Kerberos-Admin', desc: 'Administration Kerberos', category: 'security' },
    { port: 464, protocol: 'TCP/UDP', service: 'Kpasswd', desc: 'Kerberos Password', category: 'security' },
    { port: 8140, protocol: 'TCP', service: 'Puppet', desc: 'Puppet Master', category: 'security' },
    { port: 8200, protocol: 'TCP', service: 'Vault', desc: 'HashiCorp Vault', category: 'security' },

    // Monitoring
    { port: 9090, protocol: 'TCP', service: 'Prometheus', desc: 'Prometheus Server', category: 'monitoring' },
    { port: 9100, protocol: 'TCP', service: 'Node Exporter', desc: 'Prometheus Node Exporter', category: 'monitoring' },
    { port: 9093, protocol: 'TCP', service: 'Alertmanager', desc: 'Prometheus Alertmanager', category: 'monitoring' },
    { port: 3000, protocol: 'TCP', service: 'Grafana', desc: 'Grafana Dashboard', category: 'monitoring' },
    { port: 5601, protocol: 'TCP', service: 'Kibana', desc: 'Kibana (ELK)', category: 'monitoring' },
    { port: 9200, protocol: 'TCP', service: 'Elasticsearch', desc: 'Elasticsearch API', category: 'monitoring' },
    { port: 5044, protocol: 'TCP', service: 'Logstash', desc: 'Logstash Beats', category: 'monitoring' },
    { port: 10050, protocol: 'TCP', service: 'Zabbix-Agent', desc: 'Zabbix Agent', category: 'monitoring' },
    { port: 10051, protocol: 'TCP', service: 'Zabbix-Server', desc: 'Zabbix Server', category: 'monitoring' },
    { port: 8086, protocol: 'TCP', service: 'InfluxDB', desc: 'InfluxDB HTTP', category: 'monitoring' },

    // Containers & K8s
    { port: 2375, protocol: 'TCP', service: 'Docker', desc: 'Docker API (non securise)', category: 'monitoring' },
    { port: 2376, protocol: 'TCP', service: 'Docker-TLS', desc: 'Docker API (TLS)', category: 'monitoring' },
    { port: 6443, protocol: 'TCP', service: 'K8s API', desc: 'Kubernetes API Server', category: 'monitoring' },
    { port: 10250, protocol: 'TCP', service: 'Kubelet', desc: 'Kubernetes Kubelet', category: 'monitoring' },
    { port: 2379, protocol: 'TCP', service: 'etcd-client', desc: 'etcd Client', category: 'monitoring' },
    { port: 2380, protocol: 'TCP', service: 'etcd-peer', desc: 'etcd Peer', category: 'monitoring' }
];

function renderPorts(portList) {
    const tbody = document.getElementById('port-tbody');
    tbody.innerHTML = portList.map(p => `
        <tr>
            <td>${p.port}</td>
            <td>${p.protocol}</td>
            <td>${p.service}</td>
            <td>${p.desc}</td>
        </tr>
    `).join('');
}

function filterPorts() {
    const search = document.getElementById('port-search').value.toLowerCase();
    const category = document.getElementById('port-filter').value;

    let filtered = ports;

    if (category) {
        filtered = filtered.filter(p => p.category === category);
    }

    if (search) {
        filtered = filtered.filter(p =>
            p.port.toString().includes(search) ||
            p.service.toLowerCase().includes(search) ||
            p.desc.toLowerCase().includes(search)
        );
    }

    renderPorts(filtered);
}

// Event listeners
document.getElementById('port-search').addEventListener('input', filterPorts);
document.getElementById('port-filter').addEventListener('change', filterPorts);

// Initial render
renderPorts(ports);
</script>
