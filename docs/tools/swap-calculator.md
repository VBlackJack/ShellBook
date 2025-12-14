---
tags:
  - tools
  - system
  - linux
  - memory
---

# Swap Size Calculator

Calculateur de taille de swap recommandee selon les bonnes pratiques.

<div id="swap-app">
  <div class="swap-container">
    <div class="swap-section">
      <h3>Configuration systeme</h3>

      <div class="form-group">
        <label>RAM totale</label>
        <div class="ram-input">
          <input type="number" id="ramSize" value="16" min="1" oninput="calculate()">
          <select id="ramUnit" onchange="calculate()">
            <option value="GB" selected>GB</option>
            <option value="MB">MB</option>
          </select>
        </div>
      </div>

      <div class="form-group">
        <label>Type de systeme</label>
        <select id="systemType" onchange="calculate()">
          <option value="desktop">Desktop / Laptop</option>
          <option value="server">Serveur</option>
          <option value="vm">Machine Virtuelle</option>
          <option value="container">Container Host</option>
          <option value="database">Serveur de base de donnees</option>
        </select>
      </div>

      <div class="form-group">
        <label>Hibernation</label>
        <select id="hibernate" onchange="calculate()">
          <option value="no" selected>Non utilisee</option>
          <option value="yes">Oui (laptop)</option>
        </select>
        <span class="hint">L'hibernation necessite swap >= RAM</span>
      </div>

      <div class="form-group">
        <label>Workload</label>
        <select id="workload" onchange="calculate()">
          <option value="light">Leger (bureautique, web)</option>
          <option value="normal" selected>Normal (developpement)</option>
          <option value="heavy">Lourd (compilation, VMs)</option>
          <option value="memory">Memory-intensive (DB, cache)</option>
        </select>
      </div>
    </div>

    <div class="swap-section">
      <h3>Recommandations</h3>

      <div class="results-grid">
        <div class="result-card primary">
          <div class="result-label">Swap recommande</div>
          <div class="result-value" id="recSwap">0</div>
          <div class="result-unit">GB</div>
        </div>

        <div class="result-card">
          <div class="result-label">Minimum</div>
          <div class="result-value" id="minSwap">0</div>
          <div class="result-unit">GB</div>
        </div>

        <div class="result-card">
          <div class="result-label">Maximum utile</div>
          <div class="result-value" id="maxSwap">0</div>
          <div class="result-unit">GB</div>
        </div>

        <div class="result-card">
          <div class="result-label">Ratio Swap/RAM</div>
          <div class="result-value" id="ratio">0</div>
          <div class="result-unit">×</div>
        </div>
      </div>

      <div class="guidelines" id="guidelines"></div>
    </div>
  </div>

  <div class="commands-section">
    <h3>Commandes</h3>

    <div class="commands-grid">
      <div class="cmd-card">
        <h4>📊 Verifier swap actuel</h4>
        <pre>free -h
swapon --show
cat /proc/swaps</pre>
      </div>

      <div class="cmd-card">
        <h4>📁 Creer fichier swap</h4>
        <pre id="createSwapCmd">sudo fallocate -l 8G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile</pre>
      </div>

      <div class="cmd-card">
        <h4>💾 Persistance (fstab)</h4>
        <pre>echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab</pre>
      </div>

      <div class="cmd-card">
        <h4>⚙️ Swappiness</h4>
        <pre># Verifier valeur actuelle
cat /proc/sys/vm/swappiness

# Modifier temporairement
sudo sysctl vm.swappiness=10

# Permanent (sysctl.conf)
echo 'vm.swappiness=10' | sudo tee -a /etc/sysctl.conf</pre>
      </div>

      <div class="cmd-card">
        <h4>🗑️ Supprimer swap</h4>
        <pre>sudo swapoff /swapfile
sudo rm /swapfile
# Retirer la ligne de /etc/fstab</pre>
      </div>

      <div class="cmd-card">
        <h4>📈 Monitoring</h4>
        <pre>vmstat 1 5
sar -S 1 5
watch -n 1 'free -h'</pre>
      </div>
    </div>
  </div>

  <div class="reference-section">
    <h3>Reference: Recommandations par RAM</h3>

    <table class="ref-table">
      <thead>
        <tr>
          <th>RAM</th>
          <th>Sans hibernation</th>
          <th>Avec hibernation</th>
          <th>Notes</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td>≤ 2 GB</td>
          <td>2× RAM</td>
          <td>3× RAM</td>
          <td>Systemes embarques/anciens</td>
        </tr>
        <tr>
          <td>2-8 GB</td>
          <td>= RAM</td>
          <td>2× RAM</td>
          <td>Desktops legers</td>
        </tr>
        <tr>
          <td>8-64 GB</td>
          <td>≥ 4 GB</td>
          <td>1.5× RAM</td>
          <td>Workstations</td>
        </tr>
        <tr>
          <td>> 64 GB</td>
          <td>≥ 4 GB</td>
          <td>= RAM</td>
          <td>Serveurs (hibernation rare)</td>
        </tr>
      </tbody>
    </table>

    <h4>Swappiness recommande</h4>
    <table class="ref-table">
      <thead>
        <tr>
          <th>Type</th>
          <th>Valeur</th>
          <th>Description</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td>Desktop</td>
          <td>60 (defaut)</td>
          <td>Balance equilibree</td>
        </tr>
        <tr>
          <td>Serveur web/app</td>
          <td>10-30</td>
          <td>Privilegier RAM</td>
        </tr>
        <tr>
          <td>Base de donnees</td>
          <td>1-10</td>
          <td>Eviter swap au maximum</td>
        </tr>
        <tr>
          <td>SSD</td>
          <td>10-20</td>
          <td>Reduire ecriture SSD</td>
        </tr>
      </tbody>
    </table>
  </div>
</div>

<style>
.swap-container {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 20px;
}

@media (max-width: 800px) {
  .swap-container {
    grid-template-columns: 1fr;
  }
}

.swap-section, .commands-section, .reference-section {
  background: var(--md-code-bg-color);
  padding: 20px;
  border-radius: 8px;
  margin-bottom: 20px;
}

.form-group {
  margin-bottom: 15px;
}

.form-group label {
  display: block;
  font-size: 0.85em;
  margin-bottom: 5px;
  color: var(--md-default-fg-color--light);
}

.form-group select {
  width: 100%;
  padding: 10px;
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  background: var(--md-default-bg-color);
  color: var(--md-default-fg-color);
}

.ram-input {
  display: flex;
  gap: 10px;
}

.ram-input input {
  flex: 1;
  padding: 10px;
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  background: var(--md-default-bg-color);
  color: var(--md-default-fg-color);
  font-family: monospace;
}

.ram-input select {
  width: 80px;
}

.hint {
  font-size: 0.8em;
  color: var(--md-default-fg-color--light);
  margin-top: 4px;
  display: block;
}

.results-grid {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 12px;
  margin-bottom: 20px;
}

.result-card {
  background: var(--md-default-bg-color);
  padding: 15px;
  border-radius: 6px;
  text-align: center;
}

.result-card.primary {
  grid-column: span 2;
  background: var(--md-primary-fg-color);
  color: white;
}

.result-label {
  font-size: 0.8em;
  opacity: 0.8;
  margin-bottom: 5px;
}

.result-value {
  font-size: 1.8em;
  font-weight: 700;
  font-family: monospace;
}

.result-unit {
  font-size: 0.75em;
  opacity: 0.7;
}

.guidelines {
  background: var(--md-default-bg-color);
  padding: 15px;
  border-radius: 6px;
  font-size: 0.9em;
}

.guideline-item {
  padding: 8px 0;
  border-bottom: 1px solid var(--md-default-fg-color--lightest);
}

.guideline-item:last-child {
  border-bottom: none;
}

.commands-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 15px;
}

.cmd-card {
  background: var(--md-default-bg-color);
  padding: 15px;
  border-radius: 6px;
}

.cmd-card h4 {
  margin: 0 0 10px 0;
}

.cmd-card pre {
  margin: 0;
  padding: 10px;
  background: #1e1e1e;
  color: #d4d4d4;
  border-radius: 4px;
  font-size: 0.8em;
  overflow-x: auto;
}

.ref-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.85em;
  margin-bottom: 20px;
}

.ref-table th, .ref-table td {
  padding: 10px;
  text-align: left;
  border-bottom: 1px solid var(--md-default-fg-color--lightest);
}

.ref-table th {
  background: var(--md-default-bg-color);
}
</style>

<script>
function calculate() {
  let ram = parseFloat(document.getElementById('ramSize').value) || 16;
  const ramUnit = document.getElementById('ramUnit').value;
  const systemType = document.getElementById('systemType').value;
  const hibernate = document.getElementById('hibernate').value === 'yes';
  const workload = document.getElementById('workload').value;

  // Convert to GB
  if (ramUnit === 'MB') {
    ram = ram / 1024;
  }

  let minSwap, recSwap, maxSwap;

  // Base calculation based on RAM
  if (ram <= 2) {
    minSwap = ram;
    recSwap = ram * 2;
    maxSwap = ram * 3;
  } else if (ram <= 8) {
    minSwap = ram;
    recSwap = ram;
    maxSwap = ram * 2;
  } else if (ram <= 64) {
    minSwap = 4;
    recSwap = Math.max(4, ram * 0.5);
    maxSwap = ram;
  } else {
    minSwap = 4;
    recSwap = 8;
    maxSwap = 32;
  }

  // Adjust for hibernation
  if (hibernate) {
    recSwap = Math.max(recSwap, ram);
    maxSwap = Math.max(maxSwap, ram * 1.5);
  }

  // Adjust for system type
  if (systemType === 'server' || systemType === 'database') {
    recSwap = Math.min(recSwap, 8);
    maxSwap = 16;
  } else if (systemType === 'container') {
    recSwap = Math.max(2, recSwap * 0.5);
    maxSwap = 8;
  } else if (systemType === 'vm') {
    recSwap = Math.min(recSwap, ram);
  }

  // Adjust for workload
  if (workload === 'heavy' || workload === 'memory') {
    recSwap = Math.max(recSwap, ram * 0.5);
  } else if (workload === 'light') {
    recSwap = Math.max(2, recSwap * 0.75);
  }

  // Round to nice values
  recSwap = Math.ceil(recSwap);
  minSwap = Math.ceil(minSwap);
  maxSwap = Math.ceil(maxSwap);

  // Update display
  document.getElementById('recSwap').textContent = recSwap;
  document.getElementById('minSwap').textContent = minSwap;
  document.getElementById('maxSwap').textContent = maxSwap;
  document.getElementById('ratio').textContent = (recSwap / ram).toFixed(2);

  // Update create swap command
  document.getElementById('createSwapCmd').textContent = `sudo fallocate -l ${recSwap}G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile`;

  // Guidelines
  const guidelines = [];

  if (hibernate) {
    guidelines.push('💤 Hibernation active: swap doit etre >= RAM');
  }

  if (systemType === 'database') {
    guidelines.push('🗄️ Base de donnees: reduisez swappiness a 1-10');
  }

  if (workload === 'memory') {
    guidelines.push('🧠 Workload memory-intensive: considerez plus de RAM plutot que plus de swap');
  }

  if (ram > 64) {
    guidelines.push('💾 Grande quantite de RAM: le swap est principalement pour les emergences');
  }

  if (systemType === 'container') {
    guidelines.push('🐳 Container host: limitez le swap, utilisez les limites de memoire par container');
  }

  // Swappiness recommendation
  let swappinessRec = 60;
  if (systemType === 'server' || systemType === 'database') {
    swappinessRec = 10;
  } else if (workload === 'memory') {
    swappinessRec = 1;
  }
  guidelines.push(`⚙️ Swappiness recommande: ${swappinessRec}`);

  document.getElementById('guidelines').innerHTML = guidelines.map(g =>
    `<div class="guideline-item">${g}</div>`
  ).join('');
}

// Initialize
calculate();
</script>

---

## Quand augmenter le swap?

- OOM killer tue des processus
- Utilisation swap constante > 50%
- Besoin d'hibernation
- Applications avec pics de memoire

## Quand reduire le swap?

- Serveur avec SSD (reduire usure)
- Base de donnees (latence critique)
- Beaucoup de RAM disponible
- Swap utilise pour mauvaises raisons (fuite memoire)
