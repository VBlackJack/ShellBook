---
tags:
  - tools
  - network
  - dns
---

# DNS Lookup

Outil de requetes DNS (simulation locale).

<div class="tool-container">

<div class="notice-box">
    <strong>Note :</strong> Cet outil fonctionne 100% cote client. Pour des requetes DNS reelles,
    utilisez les commandes CLI ci-dessous ou un service comme
    <a href="https://dns.google" target="_blank">dns.google</a>.
</div>

<h3>Reference DNS rapide</h3>

<div class="dns-types">
    <table>
        <tr><th>Type</th><th>Description</th><th>Exemple</th></tr>
        <tr><td><strong>A</strong></td><td>Adresse IPv4</td><td>93.184.216.34</td></tr>
        <tr><td><strong>AAAA</strong></td><td>Adresse IPv6</td><td>2606:2800:220:1:248:1893:25c8:1946</td></tr>
        <tr><td><strong>CNAME</strong></td><td>Alias vers un autre nom</td><td>www.example.com → example.com</td></tr>
        <tr><td><strong>MX</strong></td><td>Serveur mail</td><td>10 mail.example.com</td></tr>
        <tr><td><strong>TXT</strong></td><td>Texte (SPF, DKIM, verification)</td><td>v=spf1 include:...</td></tr>
        <tr><td><strong>NS</strong></td><td>Serveurs de noms</td><td>ns1.example.com</td></tr>
        <tr><td><strong>SOA</strong></td><td>Start of Authority</td><td>ns1.example.com admin.example.com</td></tr>
        <tr><td><strong>PTR</strong></td><td>Reverse DNS</td><td>host.example.com</td></tr>
        <tr><td><strong>SRV</strong></td><td>Service (LDAP, SIP, etc.)</td><td>_ldap._tcp.example.com</td></tr>
        <tr><td><strong>CAA</strong></td><td>Certification Authority Authorization</td><td>0 issue "letsencrypt.org"</td></tr>
    </table>
</div>

<h3>Serveurs DNS publics</h3>

<div class="dns-servers">
    <table>
        <tr><th>Fournisseur</th><th>IPv4 Principal</th><th>IPv4 Secondaire</th><th>IPv6</th></tr>
        <tr><td>Google</td><td>8.8.8.8</td><td>8.8.4.4</td><td>2001:4860:4860::8888</td></tr>
        <tr><td>Cloudflare</td><td>1.1.1.1</td><td>1.0.0.1</td><td>2606:4700:4700::1111</td></tr>
        <tr><td>Quad9</td><td>9.9.9.9</td><td>149.112.112.112</td><td>2620:fe::fe</td></tr>
        <tr><td>OpenDNS</td><td>208.67.222.222</td><td>208.67.220.220</td><td>2620:119:35::35</td></tr>
        <tr><td>Cloudflare (Malware)</td><td>1.1.1.2</td><td>1.0.0.2</td><td>2606:4700:4700::1112</td></tr>
        <tr><td>Cloudflare (Family)</td><td>1.1.1.3</td><td>1.0.0.3</td><td>2606:4700:4700::1113</td></tr>
    </table>
</div>

</div>

## Commandes DNS

### dig (Linux/macOS)

```bash
# Requete A
dig example.com

# Type specifique
dig example.com MX
dig example.com TXT
dig example.com AAAA
dig example.com NS

# Serveur DNS specifique
dig @8.8.8.8 example.com

# Reponse courte
dig +short example.com

# Trace complete
dig +trace example.com

# Reverse DNS
dig -x 93.184.216.34

# Tous les types
dig example.com ANY

# Format JSON
dig +json example.com | jq
```

### nslookup (Windows/Linux)

```bash
# Requete simple
nslookup example.com

# Type specifique
nslookup -type=MX example.com
nslookup -type=TXT example.com

# Serveur DNS specifique
nslookup example.com 8.8.8.8

# Mode interactif
nslookup
> set type=MX
> example.com
```

### host (Linux)

```bash
# Requete simple
host example.com

# Type specifique
host -t MX example.com
host -t TXT example.com

# Reverse DNS
host 93.184.216.34

# Verbose
host -v example.com
```

### PowerShell

```powershell
# Resolve-DnsName
Resolve-DnsName example.com

# Type specifique
Resolve-DnsName example.com -Type MX
Resolve-DnsName example.com -Type TXT

# Serveur specifique
Resolve-DnsName example.com -Server 8.8.8.8
```

## Records speciaux

### SPF (Sender Policy Framework)

```
v=spf1 ip4:192.168.1.0/24 include:_spf.google.com -all
```

| Mecanisme | Description |
|-----------|-------------|
| `ip4:` | Adresse IPv4 autorisee |
| `ip6:` | Adresse IPv6 autorisee |
| `include:` | Inclure la politique d'un domaine |
| `a` | Adresse A du domaine |
| `mx` | Serveurs MX du domaine |
| `all` | Tous les autres |

| Qualificateur | Signification |
|---------------|---------------|
| `+` | Pass (defaut) |
| `-` | Fail (rejeter) |
| `~` | SoftFail (marquer) |
| `?` | Neutral |

### DKIM (DomainKeys Identified Mail)

```
v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBA...
```

### DMARC (Domain-based Message Authentication)

```
v=DMARC1; p=reject; rua=mailto:dmarc@example.com; pct=100
```

| Tag | Description |
|-----|-------------|
| `p=` | Politique (none, quarantine, reject) |
| `rua=` | Adresse pour rapports agreges |
| `ruf=` | Adresse pour rapports forensiques |
| `pct=` | Pourcentage a appliquer |

<style>
.tool-container {
    background: var(--md-code-bg-color);
    padding: 20px;
    border-radius: 8px;
    margin: 20px 0;
}
.notice-box {
    background: #fff3cd;
    border: 1px solid #ffc107;
    padding: 15px;
    border-radius: 4px;
    color: #856404;
    margin-bottom: 20px;
}
.notice-box a {
    color: #533f03;
}
.dns-types, .dns-servers {
    margin: 20px 0;
}
.dns-types table, .dns-servers table {
    width: 100%;
    background: var(--md-default-bg-color);
    border-collapse: collapse;
}
.dns-types th, .dns-types td,
.dns-servers th, .dns-servers td {
    padding: 10px;
    text-align: left;
    border-bottom: 1px solid var(--md-default-fg-color--lightest);
}
.dns-types th, .dns-servers th {
    background: var(--md-code-bg-color);
    font-weight: bold;
}
.dns-types td:first-child {
    font-family: monospace;
    color: var(--md-primary-fg-color);
}
.dns-servers td {
    font-family: monospace;
}
</style>
