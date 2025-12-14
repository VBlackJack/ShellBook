---
tags:
  - tools
  - ansible
  - automation
  - devops
---

# Ansible Playbook Generator

Generateur de playbooks Ansible avec bonnes pratiques.

<div id="ansible-app">
  <div class="ansible-container">
    <div class="ansible-section">
      <h3>Configuration Playbook</h3>

      <div class="form-group">
        <label>Nom du playbook</label>
        <input type="text" id="playbookName" value="deploy-app" oninput="generate()">
      </div>

      <div class="form-group">
        <label>Hosts cibles</label>
        <input type="text" id="hosts" value="webservers" oninput="generate()">
        <span class="hint">Groupe d'inventaire ou 'all'</span>
      </div>

      <div class="form-group">
        <label>
          <input type="checkbox" id="becomeRoot" onchange="generate()" checked>
          Devenir root (become)
        </label>
      </div>

      <div class="form-group">
        <label>
          <input type="checkbox" id="gatherFacts" onchange="generate()" checked>
          Collecter les facts
        </label>
      </div>

      <h4>Tasks</h4>

      <div class="tasks-container" id="tasksContainer">
        <div class="task-item">
          <select class="task-type" onchange="generate()">
            <option value="package">Installer package</option>
            <option value="service">Gerer service</option>
            <option value="copy">Copier fichier</option>
            <option value="template">Deployer template</option>
            <option value="command">Executer commande</option>
            <option value="file">Creer fichier/dir</option>
            <option value="user">Gerer utilisateur</option>
            <option value="lineinfile">Modifier ligne</option>
          </select>
          <input type="text" class="task-param1" placeholder="Parametre 1" value="nginx" oninput="generate()">
          <input type="text" class="task-param2" placeholder="Parametre 2" value="present" oninput="generate()">
        </div>
      </div>
      <button type="button" onclick="addTask()">+ Ajouter task</button>

      <h4>Variables</h4>

      <div class="form-group">
        <label>Variables (YAML)</label>
        <textarea id="vars" rows="4" oninput="generate()">app_name: myapp
app_port: 8080
app_user: www-data</textarea>
      </div>

      <h4>Handlers</h4>

      <div class="form-group">
        <label>
          <input type="checkbox" id="addHandlers" onchange="generate()" checked>
          Ajouter handlers
        </label>
      </div>

      <div id="handlersGroup">
        <div class="form-group">
          <label>Services a redemarrer (un par ligne)</label>
          <textarea id="handlers" rows="2" oninput="generate()">nginx
php-fpm</textarea>
        </div>
      </div>

      <h4>Options avancees</h4>

      <div class="form-group">
        <label>
          <input type="checkbox" id="addTags" onchange="generate()">
          Ajouter tags
        </label>
      </div>

      <div class="form-group">
        <label>
          <input type="checkbox" id="serialExec" onchange="generate()">
          Execution en serie
        </label>
      </div>

      <div class="form-group" id="serialGroup" style="display:none">
        <label>Nombre d'hotes simultanes</label>
        <input type="number" id="serialCount" value="2" min="1" oninput="generate()">
      </div>

      <div class="form-group">
        <label>
          <input type="checkbox" id="addRoles" onchange="generate()">
          Utiliser des roles
        </label>
      </div>

      <div class="form-group" id="rolesGroup" style="display:none">
        <label>Roles (un par ligne)</label>
        <textarea id="roles" rows="2" oninput="generate()">common
nginx
app</textarea>
      </div>
    </div>

    <div class="ansible-section">
      <h3>Playbook genere</h3>
      <pre id="configOutput"># playbook.yml</pre>
      <button onclick="copyConfig()">Copier</button>
    </div>
  </div>

  <div class="presets-section">
    <h3>Presets par cas d'usage</h3>
    <div class="presets-grid">
      <div class="preset-card" onclick="loadPreset('webserver')">
        <h4>Web Server</h4>
        <p>Nginx + config</p>
      </div>
      <div class="preset-card" onclick="loadPreset('docker')">
        <h4>Docker Host</h4>
        <p>Install Docker</p>
      </div>
      <div class="preset-card" onclick="loadPreset('user')">
        <h4>User Setup</h4>
        <p>Creer utilisateurs</p>
      </div>
      <div class="preset-card" onclick="loadPreset('security')">
        <h4>Security</h4>
        <p>Hardening basique</p>
      </div>
      <div class="preset-card" onclick="loadPreset('deploy')">
        <h4>App Deploy</h4>
        <p>Git + service</p>
      </div>
      <div class="preset-card" onclick="loadPreset('k8s')">
        <h4>K8s Node</h4>
        <p>Prep node K8s</p>
      </div>
    </div>
  </div>
</div>

<style>
.ansible-container {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 20px;
}

@media (max-width: 900px) {
  .ansible-container { grid-template-columns: 1fr; }
}

.ansible-section, .presets-section {
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

.form-group h4 {
  margin: 20px 0 10px 0;
  padding-top: 15px;
  border-top: 1px solid var(--md-default-fg-color--lightest);
}

.form-group select,
.form-group input[type="text"],
.form-group input[type="number"],
.form-group textarea {
  width: 100%;
  padding: 10px;
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  background: var(--md-default-bg-color);
  color: var(--md-default-fg-color);
  font-family: monospace;
}

.form-group input[type="checkbox"] { margin-right: 8px; }

.hint {
  font-size: 0.8em;
  color: var(--md-default-fg-color--light);
  display: block;
  margin-top: 4px;
}

.task-item {
  display: grid;
  grid-template-columns: 1fr 1fr 1fr;
  gap: 10px;
  margin-bottom: 10px;
}

.task-item select,
.task-item input {
  padding: 8px;
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 4px;
  background: var(--md-default-bg-color);
  color: var(--md-default-fg-color);
  font-family: monospace;
}

#configOutput {
  background: #1e1e1e;
  color: #d4d4d4;
  padding: 15px;
  border-radius: 4px;
  font-size: 0.85em;
  overflow-x: auto;
  white-space: pre-wrap;
  min-height: 400px;
}

.ansible-section button {
  margin-top: 10px;
  margin-right: 10px;
  padding: 8px 16px;
  background: var(--md-primary-fg-color);
  color: white;
  border: none;
  border-radius: 4px;
  cursor: pointer;
}

.presets-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
  gap: 12px;
}

.preset-card {
  background: var(--md-default-bg-color);
  padding: 15px;
  border-radius: 6px;
  cursor: pointer;
  transition: transform 0.2s;
}

.preset-card:hover { transform: scale(1.02); }
.preset-card h4 { margin: 0 0 5px 0; font-size: 0.95em; }
.preset-card p { margin: 0; font-size: 0.8em; color: var(--md-default-fg-color--light); }
</style>

<script>
function addTask() {
  const container = document.getElementById('tasksContainer');
  const task = document.createElement('div');
  task.className = 'task-item';
  task.innerHTML = `
    <select class="task-type" onchange="generate()">
      <option value="package">Installer package</option>
      <option value="service">Gerer service</option>
      <option value="copy">Copier fichier</option>
      <option value="template">Deployer template</option>
      <option value="command">Executer commande</option>
      <option value="file">Creer fichier/dir</option>
      <option value="user">Gerer utilisateur</option>
      <option value="lineinfile">Modifier ligne</option>
    </select>
    <input type="text" class="task-param1" placeholder="Parametre 1" oninput="generate()">
    <input type="text" class="task-param2" placeholder="Parametre 2" oninput="generate()">
  `;
  container.appendChild(task);
}

function generate() {
  const playbookName = document.getElementById('playbookName').value;
  const hosts = document.getElementById('hosts').value;
  const becomeRoot = document.getElementById('becomeRoot').checked;
  const gatherFacts = document.getElementById('gatherFacts').checked;
  const vars = document.getElementById('vars').value;
  const addHandlers = document.getElementById('addHandlers').checked;
  const handlers = document.getElementById('handlers').value;
  const addTags = document.getElementById('addTags').checked;
  const serialExec = document.getElementById('serialExec').checked;
  const serialCount = document.getElementById('serialCount').value;
  const addRoles = document.getElementById('addRoles').checked;
  const roles = document.getElementById('roles').value;

  // Visibility
  document.getElementById('handlersGroup').style.display = addHandlers ? 'block' : 'none';
  document.getElementById('serialGroup').style.display = serialExec ? 'block' : 'none';
  document.getElementById('rolesGroup').style.display = addRoles ? 'block' : 'none';

  let config = `---
# ${playbookName}.yml
# Generated by ShellBook Ansible Generator

- name: ${playbookName}
  hosts: ${hosts}
`;

  if (becomeRoot) {
    config += `  become: yes\n`;
  }

  config += `  gather_facts: ${gatherFacts ? 'yes' : 'no'}\n`;

  if (serialExec) {
    config += `  serial: ${serialCount}\n`;
  }

  // Variables
  if (vars.trim()) {
    config += `\n  vars:\n`;
    vars.split('\n').forEach(line => {
      if (line.trim()) {
        config += `    ${line.trim()}\n`;
      }
    });
  }

  // Roles
  if (addRoles) {
    config += `\n  roles:\n`;
    roles.split('\n').forEach(role => {
      if (role.trim()) {
        config += `    - ${role.trim()}\n`;
      }
    });
  }

  // Tasks
  config += `\n  tasks:\n`;

  const tasks = document.querySelectorAll('.task-item');
  tasks.forEach((task, index) => {
    const type = task.querySelector('.task-type').value;
    const param1 = task.querySelector('.task-param1').value;
    const param2 = task.querySelector('.task-param2').value;

    if (!param1) return;

    switch(type) {
      case 'package':
        config += `    - name: Install ${param1}
      ansible.builtin.package:
        name: ${param1}
        state: ${param2 || 'present'}
`;
        break;

      case 'service':
        config += `    - name: Manage ${param1} service
      ansible.builtin.service:
        name: ${param1}
        state: ${param2 || 'started'}
        enabled: yes
`;
        break;

      case 'copy':
        config += `    - name: Copy ${param1}
      ansible.builtin.copy:
        src: ${param1}
        dest: ${param2 || '/tmp/' + param1}
        mode: '0644'
`;
        break;

      case 'template':
        config += `    - name: Deploy ${param1} template
      ansible.builtin.template:
        src: ${param1}
        dest: ${param2 || '/etc/' + param1.replace('.j2', '')}
        mode: '0644'
`;
        if (addHandlers) {
          config += `      notify: Restart services\n`;
        }
        break;

      case 'command':
        config += `    - name: Run ${param1}
      ansible.builtin.command: ${param1}
      changed_when: false
`;
        break;

      case 'file':
        config += `    - name: Create ${param1}
      ansible.builtin.file:
        path: ${param1}
        state: ${param2 || 'directory'}
        mode: '0755'
`;
        break;

      case 'user':
        config += `    - name: Manage user ${param1}
      ansible.builtin.user:
        name: ${param1}
        state: ${param2 || 'present'}
        shell: /bin/bash
`;
        break;

      case 'lineinfile':
        config += `    - name: Ensure line in ${param1}
      ansible.builtin.lineinfile:
        path: ${param1}
        line: '${param2}'
        create: yes
`;
        break;
    }

    if (addTags) {
      // Remove last newline and add tags
      config = config.trimEnd() + `\n      tags:\n        - ${type}\n\n`;
    }
  });

  // Handlers
  if (addHandlers && handlers.trim()) {
    config += `\n  handlers:\n`;
    config += `    - name: Restart services\n`;
    config += `      ansible.builtin.service:\n`;
    config += `        name: "{{ item }}"\n`;
    config += `        state: restarted\n`;
    config += `      loop:\n`;
    handlers.split('\n').forEach(h => {
      if (h.trim()) {
        config += `        - ${h.trim()}\n`;
      }
    });
  }

  document.getElementById('configOutput').textContent = config;
}

function loadPreset(name) {
  // Clear tasks
  document.getElementById('tasksContainer').innerHTML = '';

  switch(name) {
    case 'webserver':
      document.getElementById('playbookName').value = 'setup-webserver';
      document.getElementById('hosts').value = 'webservers';
      document.getElementById('vars').value = 'server_name: example.com\ndocument_root: /var/www/html';
      document.getElementById('handlers').value = 'nginx';
      addTaskWithValues('package', 'nginx', 'present');
      addTaskWithValues('template', 'nginx.conf.j2', '/etc/nginx/nginx.conf');
      addTaskWithValues('service', 'nginx', 'started');
      break;

    case 'docker':
      document.getElementById('playbookName').value = 'install-docker';
      document.getElementById('hosts').value = 'docker_hosts';
      document.getElementById('vars').value = 'docker_users:\n  - deploy';
      addTaskWithValues('package', 'docker.io', 'present');
      addTaskWithValues('service', 'docker', 'started');
      addTaskWithValues('user', 'deploy', 'present');
      break;

    case 'user':
      document.getElementById('playbookName').value = 'manage-users';
      document.getElementById('hosts').value = 'all';
      document.getElementById('addHandlers').checked = false;
      addTaskWithValues('user', 'deploy', 'present');
      addTaskWithValues('file', '/home/deploy/.ssh', 'directory');
      addTaskWithValues('copy', 'authorized_keys', '/home/deploy/.ssh/authorized_keys');
      break;

    case 'security':
      document.getElementById('playbookName').value = 'security-hardening';
      document.getElementById('hosts').value = 'all';
      addTaskWithValues('package', 'fail2ban', 'present');
      addTaskWithValues('service', 'fail2ban', 'started');
      addTaskWithValues('lineinfile', '/etc/ssh/sshd_config', 'PermitRootLogin no');
      break;

    case 'deploy':
      document.getElementById('playbookName').value = 'deploy-app';
      document.getElementById('hosts').value = 'app_servers';
      document.getElementById('serialExec').checked = true;
      document.getElementById('serialCount').value = '1';
      document.getElementById('vars').value = 'app_repo: https://github.com/user/app.git\napp_branch: main';
      addTaskWithValues('command', 'git pull', '');
      addTaskWithValues('command', 'npm install', '');
      addTaskWithValues('service', 'myapp', 'restarted');
      break;

    case 'k8s':
      document.getElementById('playbookName').value = 'prep-k8s-node';
      document.getElementById('hosts').value = 'k8s_nodes';
      addTaskWithValues('package', 'containerd', 'present');
      addTaskWithValues('package', 'kubelet', 'present');
      addTaskWithValues('service', 'kubelet', 'started');
      break;
  }
  generate();
}

function addTaskWithValues(type, param1, param2) {
  const container = document.getElementById('tasksContainer');
  const task = document.createElement('div');
  task.className = 'task-item';
  task.innerHTML = `
    <select class="task-type" onchange="generate()">
      <option value="package" ${type === 'package' ? 'selected' : ''}>Installer package</option>
      <option value="service" ${type === 'service' ? 'selected' : ''}>Gerer service</option>
      <option value="copy" ${type === 'copy' ? 'selected' : ''}>Copier fichier</option>
      <option value="template" ${type === 'template' ? 'selected' : ''}>Deployer template</option>
      <option value="command" ${type === 'command' ? 'selected' : ''}>Executer commande</option>
      <option value="file" ${type === 'file' ? 'selected' : ''}>Creer fichier/dir</option>
      <option value="user" ${type === 'user' ? 'selected' : ''}>Gerer utilisateur</option>
      <option value="lineinfile" ${type === 'lineinfile' ? 'selected' : ''}>Modifier ligne</option>
    </select>
    <input type="text" class="task-param1" placeholder="Parametre 1" value="${param1}" oninput="generate()">
    <input type="text" class="task-param2" placeholder="Parametre 2" value="${param2}" oninput="generate()">
  `;
  container.appendChild(task);
}

function copyConfig() {
  const config = document.getElementById('configOutput').textContent;
  navigator.clipboard.writeText(config).then(() => {
    event.target.textContent = 'Copie!';
    setTimeout(() => event.target.textContent = 'Copier', 1500);
  });
}

generate();
</script>

---

## Commandes utiles

```bash
# Verifier la syntaxe
ansible-playbook --syntax-check playbook.yml

# Dry run
ansible-playbook -C playbook.yml

# Executer avec verbose
ansible-playbook -vvv playbook.yml

# Limiter a certains hosts
ansible-playbook -l webserver1 playbook.yml

# Executer certains tags
ansible-playbook --tags "install,config" playbook.yml
```

---

## Voir aussi

- [Terraform Module Generator](terraform-generator.md)
- [SSH Config Generator](ssh-config-generator.md)
