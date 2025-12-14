---
tags:
  - tools
  - linux
  - permissions
  - chmod
---

# Permissions Calculator

Calculateur de permissions UNIX/Linux (chmod).

<div class="tool-container">

<h3>Mode interactif</h3>

<div class="perms-grid">
    <div class="perm-section">
        <h4>Owner (u)</h4>
        <label><input type="checkbox" id="owner-r" checked> Read (r)</label>
        <label><input type="checkbox" id="owner-w" checked> Write (w)</label>
        <label><input type="checkbox" id="owner-x" checked> Execute (x)</label>
    </div>
    <div class="perm-section">
        <h4>Group (g)</h4>
        <label><input type="checkbox" id="group-r" checked> Read (r)</label>
        <label><input type="checkbox" id="group-w"> Write (w)</label>
        <label><input type="checkbox" id="group-x" checked> Execute (x)</label>
    </div>
    <div class="perm-section">
        <h4>Others (o)</h4>
        <label><input type="checkbox" id="other-r" checked> Read (r)</label>
        <label><input type="checkbox" id="other-w"> Write (w)</label>
        <label><input type="checkbox" id="other-x" checked> Execute (x)</label>
    </div>
</div>

<div class="special-perms">
    <h4>Permissions spéciales</h4>
    <label><input type="checkbox" id="setuid"> SUID (Set User ID)</label>
    <label><input type="checkbox" id="setgid"> SGID (Set Group ID)</label>
    <label><input type="checkbox" id="sticky"> Sticky Bit</label>
</div>

<div class="results-section">
    <div class="result-box">
        <label>Octal :</label>
        <input type="text" id="octal-result" value="0755" readonly>
    </div>
    <div class="result-box">
        <label>Symbolique :</label>
        <input type="text" id="symbolic-result" value="rwxr-xr-x" readonly>
    </div>
    <div class="result-box">
        <label>Commande :</label>
        <input type="text" id="command-result" value="chmod 755 fichier" readonly>
    </div>
</div>

<h3>Conversion directe</h3>

<div class="convert-section">
    <div class="input-group">
        <label for="octal-input">Octal → Symbolique :</label>
        <input type="text" id="octal-input" placeholder="755" maxlength="4">
        <span id="octal-to-symbolic">-</span>
    </div>
    <div class="input-group">
        <label for="symbolic-input">Symbolique → Octal :</label>
        <input type="text" id="symbolic-input" placeholder="rwxr-xr-x" maxlength="10">
        <span id="symbolic-to-octal">-</span>
    </div>
</div>

</div>

## Référence rapide

### Valeurs octales

| Valeur | Binaire | Permissions |
|--------|---------|-------------|
| 0 | 000 | --- |
| 1 | 001 | --x |
| 2 | 010 | -w- |
| 3 | 011 | -wx |
| 4 | 100 | r-- |
| 5 | 101 | r-x |
| 6 | 110 | rw- |
| 7 | 111 | rwx |

### Permissions courantes

| Octal | Symbolique | Usage |
|-------|------------|-------|
| `644` | rw-r--r-- | Fichiers standards |
| `755` | rwxr-xr-x | Exécutables, dossiers |
| `600` | rw------- | Fichiers privés (clés SSH) |
| `700` | rwx------ | Dossiers privés |
| `664` | rw-rw-r-- | Fichiers partagés (groupe) |
| `775` | rwxrwxr-x | Dossiers partagés (groupe) |
| `777` | rwxrwxrwx | ⚠️ Tous les droits (éviter) |

### Permissions spéciales

| Bit | Octal | Effet sur fichier | Effet sur dossier |
|-----|-------|-------------------|-------------------|
| SUID | 4000 | Exécute avec UID owner | - |
| SGID | 2000 | Exécute avec GID group | Hérite du groupe |
| Sticky | 1000 | - | Seul owner peut supprimer |

### Exemples chmod

```bash
# Définir en octal
chmod 755 script.sh
chmod 644 config.txt
chmod 600 ~/.ssh/id_rsa

# Définir en symbolique
chmod u+x script.sh
chmod g+w,o-r file.txt
chmod a+r public.html

# Permissions spéciales
chmod 4755 /usr/bin/sudo    # SUID
chmod 2775 /var/shared      # SGID
chmod 1777 /tmp             # Sticky
```

<style>
.tool-container {
    background: var(--md-code-bg-color);
    padding: 20px;
    border-radius: 8px;
    margin: 20px 0;
}
.perms-grid {
    display: flex;
    gap: 30px;
    flex-wrap: wrap;
    margin: 20px 0;
}
.perm-section {
    background: var(--md-default-bg-color);
    padding: 15px;
    border-radius: 4px;
    min-width: 150px;
}
.perm-section h4 {
    margin: 0 0 10px 0;
    color: var(--md-primary-fg-color);
}
.perm-section label {
    display: block;
    margin: 8px 0;
    cursor: pointer;
}
.special-perms {
    margin: 20px 0;
    padding: 15px;
    background: var(--md-default-bg-color);
    border-radius: 4px;
}
.special-perms h4 {
    margin: 0 0 10px 0;
}
.special-perms label {
    display: inline-block;
    margin-right: 20px;
    cursor: pointer;
}
.results-section {
    display: flex;
    gap: 20px;
    flex-wrap: wrap;
    margin: 20px 0;
}
.result-box {
    background: var(--md-default-bg-color);
    padding: 15px;
    border-radius: 4px;
    flex: 1;
    min-width: 200px;
}
.result-box label {
    display: block;
    font-weight: bold;
    margin-bottom: 8px;
}
.result-box input {
    width: 100%;
    padding: 10px;
    font-family: monospace;
    font-size: 18px;
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    background: var(--md-code-bg-color);
    color: var(--md-primary-fg-color);
}
.convert-section {
    margin-top: 20px;
}
.input-group {
    margin: 15px 0;
    display: flex;
    align-items: center;
    gap: 15px;
    flex-wrap: wrap;
}
.input-group label {
    font-weight: bold;
    min-width: 180px;
}
.input-group input {
    padding: 10px;
    font-family: monospace;
    font-size: 16px;
    width: 120px;
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    background: var(--md-default-bg-color);
    color: var(--md-default-fg-color);
}
.input-group span {
    font-family: monospace;
    font-size: 16px;
    padding: 10px;
    background: var(--md-default-bg-color);
    border-radius: 4px;
}
</style>

<script>
function updateFromCheckboxes() {
    const perms = {
        owner: { r: document.getElementById('owner-r').checked,
                 w: document.getElementById('owner-w').checked,
                 x: document.getElementById('owner-x').checked },
        group: { r: document.getElementById('group-r').checked,
                 w: document.getElementById('group-w').checked,
                 x: document.getElementById('group-x').checked },
        other: { r: document.getElementById('other-r').checked,
                 w: document.getElementById('other-w').checked,
                 x: document.getElementById('other-x').checked }
    };

    const special = {
        suid: document.getElementById('setuid').checked,
        sgid: document.getElementById('setgid').checked,
        sticky: document.getElementById('sticky').checked
    };

    // Calculate octal
    const ownerOct = (perms.owner.r ? 4 : 0) + (perms.owner.w ? 2 : 0) + (perms.owner.x ? 1 : 0);
    const groupOct = (perms.group.r ? 4 : 0) + (perms.group.w ? 2 : 0) + (perms.group.x ? 1 : 0);
    const otherOct = (perms.other.r ? 4 : 0) + (perms.other.w ? 2 : 0) + (perms.other.x ? 1 : 0);
    const specialOct = (special.suid ? 4 : 0) + (special.sgid ? 2 : 0) + (special.sticky ? 1 : 0);

    let octal = specialOct > 0 ? `${specialOct}${ownerOct}${groupOct}${otherOct}` : `${ownerOct}${groupOct}${otherOct}`;

    // Calculate symbolic
    let symbolic = '';
    symbolic += perms.owner.r ? 'r' : '-';
    symbolic += perms.owner.w ? 'w' : '-';
    symbolic += special.suid ? (perms.owner.x ? 's' : 'S') : (perms.owner.x ? 'x' : '-');
    symbolic += perms.group.r ? 'r' : '-';
    symbolic += perms.group.w ? 'w' : '-';
    symbolic += special.sgid ? (perms.group.x ? 's' : 'S') : (perms.group.x ? 'x' : '-');
    symbolic += perms.other.r ? 'r' : '-';
    symbolic += perms.other.w ? 'w' : '-';
    symbolic += special.sticky ? (perms.other.x ? 't' : 'T') : (perms.other.x ? 'x' : '-');

    document.getElementById('octal-result').value = octal;
    document.getElementById('symbolic-result').value = symbolic;
    document.getElementById('command-result').value = `chmod ${octal} fichier`;
}

function octalToSymbolic(octal) {
    octal = octal.padStart(4, '0');
    const special = parseInt(octal[0]);
    const owner = parseInt(octal[1]);
    const group = parseInt(octal[2]);
    const other = parseInt(octal[3]);

    const permStr = (val, suid, sgid, sticky, pos) => {
        let str = '';
        str += (val & 4) ? 'r' : '-';
        str += (val & 2) ? 'w' : '-';
        if (pos === 'owner' && (special & 4)) {
            str += (val & 1) ? 's' : 'S';
        } else if (pos === 'group' && (special & 2)) {
            str += (val & 1) ? 's' : 'S';
        } else if (pos === 'other' && (special & 1)) {
            str += (val & 1) ? 't' : 'T';
        } else {
            str += (val & 1) ? 'x' : '-';
        }
        return str;
    };

    return permStr(owner, special, 0, 0, 'owner') +
           permStr(group, 0, special, 0, 'group') +
           permStr(other, 0, 0, special, 'other');
}

function symbolicToOctal(symbolic) {
    if (symbolic.length !== 9 && symbolic.length !== 10) return null;

    let s = symbolic.length === 10 ? symbolic.substring(1) : symbolic;

    let owner = 0, group = 0, other = 0, special = 0;

    if (s[0] === 'r') owner += 4;
    if (s[1] === 'w') owner += 2;
    if (s[2] === 'x') owner += 1;
    else if (s[2] === 's') { owner += 1; special += 4; }
    else if (s[2] === 'S') special += 4;

    if (s[3] === 'r') group += 4;
    if (s[4] === 'w') group += 2;
    if (s[5] === 'x') group += 1;
    else if (s[5] === 's') { group += 1; special += 2; }
    else if (s[5] === 'S') special += 2;

    if (s[6] === 'r') other += 4;
    if (s[7] === 'w') other += 2;
    if (s[8] === 'x') other += 1;
    else if (s[8] === 't') { other += 1; special += 1; }
    else if (s[8] === 'T') special += 1;

    return special > 0 ? `${special}${owner}${group}${other}` : `${owner}${group}${other}`;
}

// Event listeners for checkboxes
document.querySelectorAll('.perm-section input, .special-perms input').forEach(cb => {
    cb.addEventListener('change', updateFromCheckboxes);
});

// Event listener for octal input
document.getElementById('octal-input').addEventListener('input', function() {
    const val = this.value;
    if (/^[0-7]{3,4}$/.test(val)) {
        document.getElementById('octal-to-symbolic').textContent = octalToSymbolic(val);
    } else {
        document.getElementById('octal-to-symbolic').textContent = '-';
    }
});

// Event listener for symbolic input
document.getElementById('symbolic-input').addEventListener('input', function() {
    const val = this.value;
    const result = symbolicToOctal(val);
    document.getElementById('symbolic-to-octal').textContent = result || '-';
});

// Initial update
updateFromCheckboxes();
</script>
