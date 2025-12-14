---
tags:
  - tools
  - openssl
  - ssl
  - certificates
  - security
---

# OpenSSL Command Builder

Generateur de commandes OpenSSL pour certificats et cryptographie.

<div class="tool-container">

<div class="type-selector">
    <button class="type-btn active" onclick="selectType('csr')">CSR</button>
    <button class="type-btn" onclick="selectType('selfsigned')">Self-Signed</button>
    <button class="type-btn" onclick="selectType('convert')">Conversion</button>
    <button class="type-btn" onclick="selectType('verify')">Verification</button>
    <button class="type-btn" onclick="selectType('encrypt')">Chiffrement</button>
</div>

<div class="generator-section" id="csr-section">
    <h3>Generer CSR + Cle privee</h3>

    <div class="form-grid">
        <div class="form-group">
            <label for="csr-cn">Common Name (CN)</label>
            <input type="text" id="csr-cn" placeholder="www.example.com">
        </div>
        <div class="form-group">
            <label for="csr-org">Organization (O)</label>
            <input type="text" id="csr-org" placeholder="My Company">
        </div>
        <div class="form-group">
            <label for="csr-ou">Organizational Unit (OU)</label>
            <input type="text" id="csr-ou" placeholder="IT Department">
        </div>
        <div class="form-group">
            <label for="csr-city">City (L)</label>
            <input type="text" id="csr-city" placeholder="Paris">
        </div>
        <div class="form-group">
            <label for="csr-state">State (ST)</label>
            <input type="text" id="csr-state" placeholder="Ile-de-France">
        </div>
        <div class="form-group">
            <label for="csr-country">Country (C)</label>
            <input type="text" id="csr-country" placeholder="FR" maxlength="2">
        </div>
        <div class="form-group">
            <label for="csr-keysize">Taille cle</label>
            <select id="csr-keysize">
                <option value="2048">RSA 2048 bits</option>
                <option value="4096" selected>RSA 4096 bits</option>
                <option value="ec256">ECDSA P-256</option>
                <option value="ec384">ECDSA P-384</option>
            </select>
        </div>
        <div class="form-group">
            <label for="csr-san">SANs (comma-separated)</label>
            <input type="text" id="csr-san" placeholder="www.example.com,example.com,api.example.com">
        </div>
    </div>
</div>

<div class="generator-section" id="selfsigned-section" style="display:none;">
    <h3>Certificat auto-signe</h3>

    <div class="form-grid">
        <div class="form-group">
            <label for="self-cn">Common Name (CN)</label>
            <input type="text" id="self-cn" placeholder="localhost">
        </div>
        <div class="form-group">
            <label for="self-days">Validite (jours)</label>
            <input type="number" id="self-days" value="365">
        </div>
        <div class="form-group">
            <label for="self-keysize">Taille cle</label>
            <select id="self-keysize">
                <option value="2048">RSA 2048 bits</option>
                <option value="4096" selected>RSA 4096 bits</option>
                <option value="ec256">ECDSA P-256</option>
            </select>
        </div>
        <div class="form-group">
            <label for="self-san">SANs</label>
            <input type="text" id="self-san" placeholder="localhost,127.0.0.1">
        </div>
    </div>
</div>

<div class="generator-section" id="convert-section" style="display:none;">
    <h3>Conversion de format</h3>

    <div class="form-grid">
        <div class="form-group">
            <label for="conv-from">Format source</label>
            <select id="conv-from">
                <option value="pem">PEM</option>
                <option value="der">DER</option>
                <option value="pfx">PFX/PKCS#12</option>
                <option value="p7b">P7B/PKCS#7</option>
            </select>
        </div>
        <div class="form-group">
            <label for="conv-to">Format destination</label>
            <select id="conv-to">
                <option value="pem">PEM</option>
                <option value="der">DER</option>
                <option value="pfx">PFX/PKCS#12</option>
            </select>
        </div>
        <div class="form-group">
            <label for="conv-input">Fichier source</label>
            <input type="text" id="conv-input" placeholder="certificate.crt">
        </div>
        <div class="form-group">
            <label for="conv-output">Fichier destination</label>
            <input type="text" id="conv-output" placeholder="certificate.pem">
        </div>
    </div>
</div>

<div class="generator-section" id="verify-section" style="display:none;">
    <h3>Verification</h3>

    <div class="form-grid">
        <div class="form-group">
            <label for="verify-type">Type</label>
            <select id="verify-type">
                <option value="cert">Afficher certificat</option>
                <option value="csr">Afficher CSR</option>
                <option value="key">Verifier cle privee</option>
                <option value="match">Verifier correspondance</option>
                <option value="chain">Verifier chaine</option>
                <option value="remote">Tester serveur distant</option>
            </select>
        </div>
        <div class="form-group">
            <label for="verify-file">Fichier</label>
            <input type="text" id="verify-file" placeholder="certificate.crt">
        </div>
        <div class="form-group">
            <label for="verify-file2">Fichier 2 (optionnel)</label>
            <input type="text" id="verify-file2" placeholder="private.key">
        </div>
        <div class="form-group">
            <label for="verify-host">Serveur:port (pour remote)</label>
            <input type="text" id="verify-host" placeholder="example.com:443">
        </div>
    </div>
</div>

<div class="generator-section" id="encrypt-section" style="display:none;">
    <h3>Chiffrement / Dechiffrement</h3>

    <div class="form-grid">
        <div class="form-group">
            <label for="enc-action">Action</label>
            <select id="enc-action">
                <option value="encrypt">Chiffrer</option>
                <option value="decrypt">Dechiffrer</option>
                <option value="hash">Hash</option>
                <option value="base64">Base64</option>
            </select>
        </div>
        <div class="form-group">
            <label for="enc-algo">Algorithme</label>
            <select id="enc-algo">
                <option value="aes-256-cbc">AES-256-CBC</option>
                <option value="aes-128-cbc">AES-128-CBC</option>
                <option value="aes-256-gcm">AES-256-GCM</option>
            </select>
        </div>
        <div class="form-group">
            <label for="enc-input">Fichier source</label>
            <input type="text" id="enc-input" placeholder="plaintext.txt">
        </div>
        <div class="form-group">
            <label for="enc-output">Fichier destination</label>
            <input type="text" id="enc-output" placeholder="encrypted.enc">
        </div>
    </div>
</div>

<div class="output-section">
    <div class="output-header">
        <h3>Commande</h3>
        <button onclick="copyOutput()" class="copy-btn">Copier</button>
    </div>
    <pre id="cmd-output" class="cmd-output"></pre>
</div>

</div>

## Formats de certificats

| Format | Extension | Description |
|--------|-----------|-------------|
| **PEM** | .pem, .crt, .cer | Base64, le plus courant |
| **DER** | .der, .cer | Binaire |
| **PFX/PKCS#12** | .pfx, .p12 | Cert + cle + chaine |
| **P7B/PKCS#7** | .p7b, .p7c | Chaine sans cle |

## Commandes courantes

```bash
# Generer cle privee RSA
openssl genrsa -out private.key 4096

# Generer cle privee ECDSA
openssl ecparam -genkey -name prime256v1 -out private.key

# Extraire cle publique
openssl rsa -in private.key -pubout -out public.key

# Verifier certificat
openssl x509 -in cert.crt -text -noout

# Verifier CSR
openssl req -in request.csr -text -noout
```

<style>
.tool-container {
    background: var(--md-code-bg-color);
    padding: 20px;
    border-radius: 8px;
    margin: 20px 0;
}
.type-selector {
    display: flex;
    gap: 10px;
    margin-bottom: 20px;
    flex-wrap: wrap;
}
.type-btn {
    padding: 10px 20px;
    background: var(--md-default-bg-color);
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    cursor: pointer;
}
.type-btn.active {
    background: var(--md-primary-fg-color);
    color: white;
    border-color: var(--md-primary-fg-color);
}
.generator-section {
    background: var(--md-default-bg-color);
    padding: 20px;
    border-radius: 4px;
    margin-bottom: 20px;
}
.generator-section h3 {
    margin: 0 0 15px 0;
}
.form-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 15px;
}
.form-group {
    display: flex;
    flex-direction: column;
}
.form-group label {
    font-size: 12px;
    font-weight: bold;
    margin-bottom: 5px;
}
.form-group input, .form-group select {
    padding: 10px;
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    background: var(--md-code-bg-color);
    color: var(--md-default-fg-color);
    font-family: monospace;
}
.output-section {
    background: var(--md-default-bg-color);
    padding: 20px;
    border-radius: 4px;
}
.output-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 10px;
}
.output-header h3 {
    margin: 0;
}
.copy-btn {
    padding: 8px 16px;
    background: var(--md-primary-fg-color);
    color: white;
    border: none;
    border-radius: 4px;
    cursor: pointer;
}
.cmd-output {
    background: var(--md-code-bg-color);
    padding: 15px;
    border-radius: 4px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 13px;
    overflow-x: auto;
    margin: 0;
    white-space: pre-wrap;
    min-height: 100px;
}
</style>

<script>
let currentType = 'csr';

function selectType(type) {
    currentType = type;
    document.querySelectorAll('.type-btn').forEach(btn => btn.classList.remove('active'));
    event.target.classList.add('active');

    document.getElementById('csr-section').style.display = type === 'csr' ? 'block' : 'none';
    document.getElementById('selfsigned-section').style.display = type === 'selfsigned' ? 'block' : 'none';
    document.getElementById('convert-section').style.display = type === 'convert' ? 'block' : 'none';
    document.getElementById('verify-section').style.display = type === 'verify' ? 'block' : 'none';
    document.getElementById('encrypt-section').style.display = type === 'encrypt' ? 'block' : 'none';

    generateCommand();
}

function generateCommand() {
    let cmd = '';

    switch (currentType) {
        case 'csr':
            cmd = generateCSR();
            break;
        case 'selfsigned':
            cmd = generateSelfSigned();
            break;
        case 'convert':
            cmd = generateConvert();
            break;
        case 'verify':
            cmd = generateVerify();
            break;
        case 'encrypt':
            cmd = generateEncrypt();
            break;
    }

    document.getElementById('cmd-output').textContent = cmd;
}

function generateCSR() {
    const cn = document.getElementById('csr-cn').value || 'www.example.com';
    const org = document.getElementById('csr-org').value || 'My Company';
    const ou = document.getElementById('csr-ou').value;
    const city = document.getElementById('csr-city').value;
    const state = document.getElementById('csr-state').value;
    const country = document.getElementById('csr-country').value || 'FR';
    const keysize = document.getElementById('csr-keysize').value;
    const san = document.getElementById('csr-san').value;

    let subject = `/CN=${cn}/O=${org}/C=${country}`;
    if (ou) subject += `/OU=${ou}`;
    if (city) subject += `/L=${city}`;
    if (state) subject += `/ST=${state}`;

    let cmd = '';

    if (keysize.startsWith('ec')) {
        const curve = keysize === 'ec256' ? 'prime256v1' : 'secp384r1';
        cmd = `# Generer cle privee ECDSA
openssl ecparam -genkey -name ${curve} -out ${cn}.key

`;
    } else {
        cmd = `# Generer cle privee RSA ${keysize} bits
openssl genrsa -out ${cn}.key ${keysize}

`;
    }

    if (san) {
        const sans = san.split(',').map(s => s.trim());
        const sanConfig = sans.map((s, i) => {
            if (/^\d+\.\d+\.\d+\.\d+$/.test(s)) {
                return `IP.${i + 1} = ${s}`;
            }
            return `DNS.${i + 1} = ${s}`;
        }).join('\n');

        cmd += `# Creer fichier de configuration SAN
cat > ${cn}.cnf << 'EOF'
[req]
distinguished_name = req_distinguished_name
req_extensions = req_ext
prompt = no

[req_distinguished_name]
CN = ${cn}
O = ${org}
C = ${country}
${ou ? `OU = ${ou}` : ''}
${city ? `L = ${city}` : ''}
${state ? `ST = ${state}` : ''}

[req_ext]
subjectAltName = @alt_names

[alt_names]
${sanConfig}
EOF

# Generer CSR avec SANs
openssl req -new -key ${cn}.key -out ${cn}.csr -config ${cn}.cnf
`;
    } else {
        cmd += `# Generer CSR
openssl req -new -key ${cn}.key -out ${cn}.csr -subj "${subject}"
`;
    }

    cmd += `
# Verifier le CSR
openssl req -in ${cn}.csr -text -noout`;

    return cmd;
}

function generateSelfSigned() {
    const cn = document.getElementById('self-cn').value || 'localhost';
    const days = document.getElementById('self-days').value || '365';
    const keysize = document.getElementById('self-keysize').value;
    const san = document.getElementById('self-san').value;

    let cmd = '';

    if (san) {
        const sans = san.split(',').map(s => s.trim());
        const sanConfig = sans.map((s, i) => {
            if (/^\d+\.\d+\.\d+\.\d+$/.test(s)) {
                return `IP.${i + 1} = ${s}`;
            }
            return `DNS.${i + 1} = ${s}`;
        }).join('\n');

        cmd = `# Certificat auto-signe avec SANs
openssl req -x509 -nodes -days ${days} -newkey rsa:${keysize === 'ec256' ? '2048' : keysize} \\
    -keyout ${cn}.key -out ${cn}.crt \\
    -subj "/CN=${cn}" \\
    -addext "subjectAltName=${sans.map(s => /^\d+\.\d+\.\d+\.\d+$/.test(s) ? `IP:${s}` : `DNS:${s}`).join(',')}"
`;
    } else {
        if (keysize.startsWith('ec')) {
            cmd = `# Certificat auto-signe ECDSA
openssl req -x509 -nodes -days ${days} \\
    -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \\
    -keyout ${cn}.key -out ${cn}.crt \\
    -subj "/CN=${cn}"
`;
        } else {
            cmd = `# Certificat auto-signe RSA ${keysize} bits
openssl req -x509 -nodes -days ${days} -newkey rsa:${keysize} \\
    -keyout ${cn}.key -out ${cn}.crt \\
    -subj "/CN=${cn}"
`;
        }
    }

    cmd += `
# Verifier le certificat
openssl x509 -in ${cn}.crt -text -noout`;

    return cmd;
}

function generateConvert() {
    const from = document.getElementById('conv-from').value;
    const to = document.getElementById('conv-to').value;
    const input = document.getElementById('conv-input').value || 'input.crt';
    const output = document.getElementById('conv-output').value || 'output.pem';

    let cmd = '';

    if (from === 'pem' && to === 'der') {
        cmd = `# PEM vers DER
openssl x509 -in ${input} -outform DER -out ${output}`;
    } else if (from === 'der' && to === 'pem') {
        cmd = `# DER vers PEM
openssl x509 -in ${input} -inform DER -outform PEM -out ${output}`;
    } else if (from === 'pem' && to === 'pfx') {
        cmd = `# PEM vers PFX (necessite la cle privee)
openssl pkcs12 -export -out ${output} -inkey private.key -in ${input}

# Avec chaine de certificats
openssl pkcs12 -export -out ${output} -inkey private.key -in ${input} -certfile chain.crt`;
    } else if (from === 'pfx' && to === 'pem') {
        cmd = `# Extraire certificat du PFX
openssl pkcs12 -in ${input} -clcerts -nokeys -out certificate.pem

# Extraire cle privee du PFX
openssl pkcs12 -in ${input} -nocerts -nodes -out private.key

# Extraire tout (cert + cle)
openssl pkcs12 -in ${input} -nodes -out ${output}`;
    } else if (from === 'p7b' && to === 'pem') {
        cmd = `# P7B vers PEM
openssl pkcs7 -in ${input} -print_certs -out ${output}`;
    } else {
        cmd = `# Conversion ${from.toUpperCase()} -> ${to.toUpperCase()}
# Voir la documentation OpenSSL pour cette conversion`;
    }

    return cmd;
}

function generateVerify() {
    const type = document.getElementById('verify-type').value;
    const file = document.getElementById('verify-file').value || 'certificate.crt';
    const file2 = document.getElementById('verify-file2').value || 'private.key';
    const host = document.getElementById('verify-host').value || 'example.com:443';

    let cmd = '';

    switch (type) {
        case 'cert':
            cmd = `# Afficher les details du certificat
openssl x509 -in ${file} -text -noout

# Afficher uniquement les dates
openssl x509 -in ${file} -noout -dates

# Afficher le subject et issuer
openssl x509 -in ${file} -noout -subject -issuer

# Afficher le fingerprint
openssl x509 -in ${file} -noout -fingerprint -sha256`;
            break;

        case 'csr':
            cmd = `# Afficher les details du CSR
openssl req -in ${file} -text -noout -verify`;
            break;

        case 'key':
            cmd = `# Verifier la cle privee RSA
openssl rsa -in ${file} -check -noout

# Verifier la cle privee ECDSA
openssl ec -in ${file} -check -noout

# Afficher les details de la cle
openssl rsa -in ${file} -text -noout`;
            break;

        case 'match':
            cmd = `# Verifier que la cle correspond au certificat
# Les hash doivent etre identiques

# Hash du certificat
openssl x509 -in ${file} -noout -modulus | openssl md5

# Hash de la cle privee
openssl rsa -in ${file2} -noout -modulus | openssl md5

# Hash du CSR (si applicable)
openssl req -in request.csr -noout -modulus | openssl md5`;
            break;

        case 'chain':
            cmd = `# Verifier la chaine de certificats
openssl verify -CAfile ca-bundle.crt ${file}

# Verifier avec chaine intermediaire
openssl verify -CAfile root.crt -untrusted intermediate.crt ${file}`;
            break;

        case 'remote':
            cmd = `# Tester le certificat d'un serveur distant
openssl s_client -connect ${host} -servername ${host.split(':')[0]} < /dev/null 2>/dev/null | openssl x509 -text -noout

# Afficher la chaine complete
openssl s_client -connect ${host} -servername ${host.split(':')[0]} -showcerts < /dev/null

# Verifier les dates d'expiration
echo | openssl s_client -connect ${host} -servername ${host.split(':')[0]} 2>/dev/null | openssl x509 -noout -dates`;
            break;
    }

    return cmd;
}

function generateEncrypt() {
    const action = document.getElementById('enc-action').value;
    const algo = document.getElementById('enc-algo').value;
    const input = document.getElementById('enc-input').value || 'input.txt';
    const output = document.getElementById('enc-output').value || 'output.enc';

    let cmd = '';

    switch (action) {
        case 'encrypt':
            cmd = `# Chiffrer un fichier avec ${algo.toUpperCase()}
openssl enc -${algo} -salt -pbkdf2 -in ${input} -out ${output}

# Chiffrer avec cle et IV specifiques
openssl enc -${algo} -K <hex_key> -iv <hex_iv> -in ${input} -out ${output}`;
            break;

        case 'decrypt':
            cmd = `# Dechiffrer un fichier
openssl enc -d -${algo} -pbkdf2 -in ${input} -out ${output}`;
            break;

        case 'hash':
            cmd = `# Calculer hash SHA-256
openssl dgst -sha256 ${input}

# Calculer hash SHA-512
openssl dgst -sha512 ${input}

# Calculer hash MD5 (obsolete)
openssl dgst -md5 ${input}

# Hash avec sortie binaire
openssl dgst -sha256 -binary ${input} > ${input}.sha256`;
            break;

        case 'base64':
            cmd = `# Encoder en Base64
openssl base64 -in ${input} -out ${output}

# Decoder du Base64
openssl base64 -d -in ${input} -out ${output}

# Encoder une chaine
echo -n "Hello World" | openssl base64`;
            break;
    }

    return cmd;
}

function copyOutput() {
    const output = document.getElementById('cmd-output').textContent;
    navigator.clipboard.writeText(output);

    const btn = document.querySelector('.copy-btn');
    btn.textContent = 'Copie!';
    setTimeout(() => { btn.textContent = 'Copier'; }, 1000);
}

// Event listeners
document.querySelectorAll('.generator-section input, .generator-section select').forEach(el => {
    el.addEventListener('input', generateCommand);
    el.addEventListener('change', generateCommand);
});

// Initial generation
generateCommand();
</script>
