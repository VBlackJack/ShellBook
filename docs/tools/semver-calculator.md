---
tags:
  - tools
  - devops
  - semver
  - versioning
---

# Semver Calculator

Analyseur et comparateur de versions semantiques (SemVer 2.0.0).

<div id="semver-app">
  <div class="semver-container">
    <div class="semver-section">
      <h3>Analyseur de version</h3>

      <div class="version-input">
        <input type="text" id="versionInput" placeholder="Ex: 1.2.3-beta.1+build.456" oninput="analyzeVersion()">
        <button onclick="analyzeVersion()">Analyser</button>
      </div>

      <div id="versionAnalysis" class="version-analysis"></div>

      <h4>Exemples rapides</h4>
      <div class="examples">
        <button onclick="setVersion('1.0.0')">1.0.0</button>
        <button onclick="setVersion('2.1.3-alpha')">2.1.3-alpha</button>
        <button onclick="setVersion('3.0.0-beta.2')">3.0.0-beta.2</button>
        <button onclick="setVersion('1.5.0-rc.1+build.123')">1.5.0-rc.1+build.123</button>
        <button onclick="setVersion('0.0.1-SNAPSHOT')">0.0.1-SNAPSHOT</button>
      </div>
    </div>

    <div class="semver-section">
      <h3>Comparateur</h3>

      <div class="compare-inputs">
        <div class="compare-row">
          <label>Version A</label>
          <input type="text" id="versionA" placeholder="1.0.0" oninput="compareVersions()">
        </div>
        <div class="compare-row">
          <label>Version B</label>
          <input type="text" id="versionB" placeholder="2.0.0" oninput="compareVersions()">
        </div>
      </div>

      <div id="compareResult" class="compare-result"></div>
    </div>
  </div>

  <div class="bump-section">
    <h3>Increment de version</h3>

    <div class="bump-container">
      <div class="bump-input">
        <label>Version actuelle</label>
        <input type="text" id="bumpVersion" value="1.2.3" oninput="calculateBumps()">
      </div>

      <div id="bumpResults" class="bump-results"></div>
    </div>
  </div>

  <div class="range-section">
    <h3>Plages de versions (npm/composer style)</h3>

    <div class="range-container">
      <div class="range-input">
        <label>Specification</label>
        <input type="text" id="rangeSpec" placeholder="^1.2.3 ou ~2.0.0 ou >=1.0.0 <2.0.0" oninput="parseRange()">
      </div>

      <div id="rangeResult" class="range-result"></div>

      <div class="range-examples">
        <h4>Syntaxes courantes</h4>
        <div class="range-grid">
          <div class="range-item" onclick="setRange('^1.2.3')">
            <code>^1.2.3</code>
            <span>>=1.2.3 <2.0.0</span>
          </div>
          <div class="range-item" onclick="setRange('~1.2.3')">
            <code>~1.2.3</code>
            <span>>=1.2.3 <1.3.0</span>
          </div>
          <div class="range-item" onclick="setRange('1.2.x')">
            <code>1.2.x</code>
            <span>>=1.2.0 <1.3.0</span>
          </div>
          <div class="range-item" onclick="setRange('1.x')">
            <code>1.x</code>
            <span>>=1.0.0 <2.0.0</span>
          </div>
          <div class="range-item" onclick="setRange('>=1.0.0')">
            <code>>=1.0.0</code>
            <span>Minimum version</span>
          </div>
          <div class="range-item" onclick="setRange('1.2.3 - 2.0.0')">
            <code>1.2.3 - 2.0.0</code>
            <span>Range inclusif</span>
          </div>
          <div class="range-item" onclick="setRange('1.2.3 || 2.x')">
            <code>1.2.3 || 2.x</code>
            <span>Union (OR)</span>
          </div>
          <div class="range-item" onclick="setRange('*')">
            <code>*</code>
            <span>Toutes versions</span>
          </div>
        </div>
      </div>
    </div>
  </div>

  <div class="reference-section">
    <h3>Reference SemVer</h3>
    <div class="ref-content">
      <div class="ref-format">
        <h4>Format</h4>
        <div class="format-diagram">
          <span class="major">MAJOR</span>.<span class="minor">MINOR</span>.<span class="patch">PATCH</span><span class="prerelease">-prerelease</span><span class="build">+build</span>
        </div>
      </div>

      <div class="ref-rules">
        <h4>Regles d'increment</h4>
        <table>
          <tr>
            <td><strong class="major">MAJOR</strong></td>
            <td>Changements incompatibles (breaking changes)</td>
          </tr>
          <tr>
            <td><strong class="minor">MINOR</strong></td>
            <td>Nouvelles fonctionnalites retrocompatibles</td>
          </tr>
          <tr>
            <td><strong class="patch">PATCH</strong></td>
            <td>Corrections de bugs retrocompatibles</td>
          </tr>
        </table>
      </div>

      <div class="ref-precedence">
        <h4>Precedence</h4>
        <code>1.0.0-alpha < 1.0.0-alpha.1 < 1.0.0-beta < 1.0.0-beta.2 < 1.0.0-rc.1 < 1.0.0</code>
      </div>
    </div>
  </div>
</div>

<style>
.semver-container {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 20px;
}

@media (max-width: 800px) {
  .semver-container {
    grid-template-columns: 1fr;
  }
}

.semver-section, .bump-section, .range-section, .reference-section {
  background: var(--md-code-bg-color);
  padding: 20px;
  border-radius: 8px;
  margin-bottom: 20px;
}

.version-input {
  display: flex;
  gap: 10px;
  margin-bottom: 15px;
}

.version-input input {
  flex: 1;
  padding: 12px 15px;
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  background: var(--md-default-bg-color);
  color: var(--md-default-fg-color);
  font-family: monospace;
  font-size: 1.1em;
}

.version-input button {
  padding: 12px 20px;
  background: var(--md-primary-fg-color);
  color: white;
  border: none;
  border-radius: 4px;
  cursor: pointer;
}

.version-analysis {
  background: var(--md-default-bg-color);
  padding: 15px;
  border-radius: 6px;
  min-height: 100px;
}

.analysis-parts {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  margin-bottom: 15px;
}

.part {
  padding: 8px 15px;
  border-radius: 4px;
  font-family: monospace;
}

.part.major { background: rgba(231, 76, 60, 0.2); color: #e74c3c; }
.part.minor { background: rgba(46, 204, 113, 0.2); color: #27ae60; }
.part.patch { background: rgba(52, 152, 219, 0.2); color: #3498db; }
.part.prerelease { background: rgba(155, 89, 182, 0.2); color: #9b59b6; }
.part.build { background: rgba(149, 165, 166, 0.2); color: #7f8c8d; }

.examples {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.examples button {
  padding: 6px 12px;
  background: var(--md-default-bg-color);
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  cursor: pointer;
  font-family: monospace;
  font-size: 0.85em;
}

.compare-inputs {
  margin-bottom: 15px;
}

.compare-row {
  margin-bottom: 10px;
}

.compare-row label {
  display: block;
  font-size: 0.85em;
  margin-bottom: 4px;
}

.compare-row input {
  width: 100%;
  padding: 10px;
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  background: var(--md-default-bg-color);
  color: var(--md-default-fg-color);
  font-family: monospace;
}

.compare-result {
  padding: 15px;
  background: var(--md-default-bg-color);
  border-radius: 6px;
  text-align: center;
  font-size: 1.2em;
}

.bump-container {
  display: grid;
  grid-template-columns: 200px 1fr;
  gap: 20px;
  align-items: start;
}

@media (max-width: 600px) {
  .bump-container {
    grid-template-columns: 1fr;
  }
}

.bump-input label {
  display: block;
  font-size: 0.85em;
  margin-bottom: 5px;
}

.bump-input input {
  width: 100%;
  padding: 12px;
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  background: var(--md-default-bg-color);
  color: var(--md-default-fg-color);
  font-family: monospace;
  font-size: 1.2em;
}

.bump-results {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 10px;
}

.bump-card {
  background: var(--md-default-bg-color);
  padding: 12px;
  border-radius: 6px;
  text-align: center;
  cursor: pointer;
  transition: transform 0.2s;
}

.bump-card:hover {
  transform: scale(1.02);
}

.bump-label {
  font-size: 0.8em;
  color: var(--md-default-fg-color--light);
  margin-bottom: 5px;
}

.bump-value {
  font-family: monospace;
  font-size: 1.1em;
  font-weight: 600;
}

.bump-card.major .bump-value { color: #e74c3c; }
.bump-card.minor .bump-value { color: #27ae60; }
.bump-card.patch .bump-value { color: #3498db; }
.bump-card.prerelease .bump-value { color: #9b59b6; }

.range-input {
  margin-bottom: 15px;
}

.range-input label {
  display: block;
  font-size: 0.85em;
  margin-bottom: 5px;
}

.range-input input {
  width: 100%;
  padding: 12px;
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  background: var(--md-default-bg-color);
  color: var(--md-default-fg-color);
  font-family: monospace;
}

.range-result {
  padding: 15px;
  background: var(--md-default-bg-color);
  border-radius: 6px;
  margin-bottom: 15px;
  font-family: monospace;
}

.range-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
  gap: 10px;
}

.range-item {
  display: flex;
  flex-direction: column;
  padding: 10px;
  background: var(--md-default-bg-color);
  border-radius: 4px;
  cursor: pointer;
}

.range-item:hover {
  outline: 1px solid var(--md-primary-fg-color);
}

.range-item code {
  font-size: 1em;
  margin-bottom: 4px;
}

.range-item span {
  font-size: 0.8em;
  color: var(--md-default-fg-color--light);
}

.ref-content {
  background: var(--md-default-bg-color);
  padding: 20px;
  border-radius: 6px;
}

.format-diagram {
  font-family: monospace;
  font-size: 1.3em;
  padding: 15px;
  background: var(--md-code-bg-color);
  border-radius: 4px;
  margin-bottom: 20px;
}

.format-diagram .major { color: #e74c3c; }
.format-diagram .minor { color: #27ae60; }
.format-diagram .patch { color: #3498db; }
.format-diagram .prerelease { color: #9b59b6; }
.format-diagram .build { color: #7f8c8d; }

.ref-rules table {
  width: 100%;
  margin-bottom: 20px;
}

.ref-rules td {
  padding: 8px;
  border-bottom: 1px solid var(--md-default-fg-color--lightest);
}

.ref-rules .major { color: #e74c3c; }
.ref-rules .minor { color: #27ae60; }
.ref-rules .patch { color: #3498db; }

.ref-precedence code {
  display: block;
  padding: 10px;
  background: var(--md-code-bg-color);
  border-radius: 4px;
  font-size: 0.9em;
  overflow-x: auto;
}
</style>

<script>
const semverRegex = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$/;

function parseSemver(version) {
  const match = version.trim().match(semverRegex);
  if (!match) return null;

  return {
    major: parseInt(match[1]),
    minor: parseInt(match[2]),
    patch: parseInt(match[3]),
    prerelease: match[4] || null,
    build: match[5] || null,
    raw: version.trim()
  };
}

function setVersion(v) {
  document.getElementById('versionInput').value = v;
  analyzeVersion();
}

function analyzeVersion() {
  const input = document.getElementById('versionInput').value;
  const el = document.getElementById('versionAnalysis');

  if (!input.trim()) {
    el.innerHTML = '<p style="color: var(--md-default-fg-color--light)">Entrez une version a analyser</p>';
    return;
  }

  const parsed = parseSemver(input);

  if (!parsed) {
    el.innerHTML = `<p style="color: #e74c3c">❌ Version invalide selon SemVer 2.0.0</p>
      <p style="font-size: 0.85em; color: var(--md-default-fg-color--light)">Format attendu: MAJOR.MINOR.PATCH[-prerelease][+build]</p>`;
    return;
  }

  let html = '<div class="analysis-parts">';
  html += `<div class="part major">Major: ${parsed.major}</div>`;
  html += `<div class="part minor">Minor: ${parsed.minor}</div>`;
  html += `<div class="part patch">Patch: ${parsed.patch}</div>`;
  if (parsed.prerelease) html += `<div class="part prerelease">Pre: ${parsed.prerelease}</div>`;
  if (parsed.build) html += `<div class="part build">Build: ${parsed.build}</div>`;
  html += '</div>';

  html += '<p style="color: #27ae60">✓ Version SemVer valide</p>';

  // Stability indicator
  if (parsed.major === 0) {
    html += '<p style="font-size: 0.85em; color: #f39c12">⚠️ Version 0.x.x - API instable</p>';
  } else if (parsed.prerelease) {
    html += '<p style="font-size: 0.85em; color: #9b59b6">🔬 Version pre-release</p>';
  } else {
    html += '<p style="font-size: 0.85em; color: #27ae60">✓ Version stable</p>';
  }

  el.innerHTML = html;
}

function compareVersions() {
  const a = document.getElementById('versionA').value;
  const b = document.getElementById('versionB').value;
  const el = document.getElementById('compareResult');

  if (!a || !b) {
    el.innerHTML = '<span style="color: var(--md-default-fg-color--light)">Entrez deux versions</span>';
    return;
  }

  const parsedA = parseSemver(a);
  const parsedB = parseSemver(b);

  if (!parsedA || !parsedB) {
    el.innerHTML = '<span style="color: #e74c3c">Version(s) invalide(s)</span>';
    return;
  }

  const cmp = compareSemver(parsedA, parsedB);

  if (cmp < 0) {
    el.innerHTML = `<span style="color: #3498db">${a}</span> < <span style="color: #e74c3c">${b}</span>`;
  } else if (cmp > 0) {
    el.innerHTML = `<span style="color: #e74c3c">${a}</span> > <span style="color: #3498db">${b}</span>`;
  } else {
    el.innerHTML = `<span style="color: #27ae60">${a} = ${b}</span>`;
  }
}

function compareSemver(a, b) {
  if (a.major !== b.major) return a.major - b.major;
  if (a.minor !== b.minor) return a.minor - b.minor;
  if (a.patch !== b.patch) return a.patch - b.patch;

  // Pre-release comparison
  if (a.prerelease && !b.prerelease) return -1;
  if (!a.prerelease && b.prerelease) return 1;
  if (a.prerelease && b.prerelease) {
    const aParts = a.prerelease.split('.');
    const bParts = b.prerelease.split('.');
    for (let i = 0; i < Math.max(aParts.length, bParts.length); i++) {
      if (i >= aParts.length) return -1;
      if (i >= bParts.length) return 1;
      const aNum = parseInt(aParts[i]);
      const bNum = parseInt(bParts[i]);
      if (!isNaN(aNum) && !isNaN(bNum)) {
        if (aNum !== bNum) return aNum - bNum;
      } else {
        const cmp = aParts[i].localeCompare(bParts[i]);
        if (cmp !== 0) return cmp;
      }
    }
  }

  return 0;
}

function calculateBumps() {
  const input = document.getElementById('bumpVersion').value;
  const parsed = parseSemver(input);
  const el = document.getElementById('bumpResults');

  if (!parsed) {
    el.innerHTML = '<p style="color: #e74c3c">Version invalide</p>';
    return;
  }

  const bumps = [
    { type: 'major', label: 'Major', version: `${parsed.major + 1}.0.0` },
    { type: 'minor', label: 'Minor', version: `${parsed.major}.${parsed.minor + 1}.0` },
    { type: 'patch', label: 'Patch', version: `${parsed.major}.${parsed.minor}.${parsed.patch + 1}` },
    { type: 'prerelease', label: 'Pre-alpha', version: `${parsed.major}.${parsed.minor}.${parsed.patch + 1}-alpha.1` },
    { type: 'prerelease', label: 'Pre-beta', version: `${parsed.major}.${parsed.minor}.${parsed.patch + 1}-beta.1` },
    { type: 'prerelease', label: 'Pre-RC', version: `${parsed.major}.${parsed.minor}.${parsed.patch + 1}-rc.1` }
  ];

  el.innerHTML = bumps.map(b => `
    <div class="bump-card ${b.type}" onclick="copyBump('${b.version}')">
      <div class="bump-label">${b.label}</div>
      <div class="bump-value">${b.version}</div>
    </div>
  `).join('');
}

function copyBump(version) {
  navigator.clipboard.writeText(version);
}

function setRange(spec) {
  document.getElementById('rangeSpec').value = spec;
  parseRange();
}

function parseRange() {
  const spec = document.getElementById('rangeSpec').value;
  const el = document.getElementById('rangeResult');

  if (!spec.trim()) {
    el.innerHTML = 'Entrez une specification de plage';
    return;
  }

  let explanation = '';

  // Caret range ^
  if (spec.startsWith('^')) {
    const v = parseSemver(spec.slice(1));
    if (v) {
      if (v.major === 0 && v.minor === 0) {
        explanation = `>=${v.major}.${v.minor}.${v.patch} <${v.major}.${v.minor}.${v.patch + 1}`;
      } else if (v.major === 0) {
        explanation = `>=${v.major}.${v.minor}.${v.patch} <${v.major}.${v.minor + 1}.0`;
      } else {
        explanation = `>=${v.major}.${v.minor}.${v.patch} <${v.major + 1}.0.0`;
      }
    }
  }
  // Tilde range ~
  else if (spec.startsWith('~')) {
    const v = parseSemver(spec.slice(1));
    if (v) {
      explanation = `>=${v.major}.${v.minor}.${v.patch} <${v.major}.${v.minor + 1}.0`;
    }
  }
  // X-range
  else if (spec.includes('x') || spec.includes('*')) {
    const parts = spec.replace(/\*/g, 'x').split('.');
    if (parts.length === 1 || (parts.length === 2 && parts[1] === 'x')) {
      const major = parts[0] === 'x' ? '*' : parseInt(parts[0]);
      if (major === '*') {
        explanation = '>=0.0.0 (toutes versions)';
      } else {
        explanation = `>=${major}.0.0 <${major + 1}.0.0`;
      }
    } else if (parts.length === 3 && parts[2] === 'x') {
      const major = parseInt(parts[0]);
      const minor = parseInt(parts[1]);
      explanation = `>=${major}.${minor}.0 <${major}.${minor + 1}.0`;
    }
  }
  // Comparators
  else if (spec.match(/^[<>=]/)) {
    explanation = spec + ' (comparateur direct)';
  }
  // Range with hyphen
  else if (spec.includes(' - ')) {
    const [a, b] = spec.split(' - ').map(s => s.trim());
    explanation = `>=${a} <=${b}`;
  }
  // OR
  else if (spec.includes('||')) {
    explanation = spec.split('||').map(s => s.trim()).join(' OU ');
  }

  el.innerHTML = explanation || 'Syntaxe non reconnue';
}

// Initialize
analyzeVersion();
calculateBumps();
</script>

---

## Liens utiles

- [Specification SemVer 2.0.0](https://semver.org/)
- [npm semver calculator](https://semver.npmjs.com/)
- [Conventional Commits](https://www.conventionalcommits.org/)
