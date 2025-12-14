---
tags:
  - tools
  - docker
  - compose
  - containers
---

# Docker Compose Generator

Generateur de fichiers docker-compose.yml pour services courants.

<div class="tool-container">

<div class="services-section">
    <h3>Ajouter des services</h3>

    <div class="service-buttons">
        <button onclick="addService('nginx')">Nginx</button>
        <button onclick="addService('apache')">Apache</button>
        <button onclick="addService('node')">Node.js</button>
        <button onclick="addService('python')">Python</button>
        <button onclick="addService('mysql')">MySQL</button>
        <button onclick="addService('postgres')">PostgreSQL</button>
        <button onclick="addService('mariadb')">MariaDB</button>
        <button onclick="addService('mongodb')">MongoDB</button>
        <button onclick="addService('redis')">Redis</button>
        <button onclick="addService('rabbitmq')">RabbitMQ</button>
        <button onclick="addService('elasticsearch')">Elasticsearch</button>
        <button onclick="addService('traefik')">Traefik</button>
        <button onclick="addService('wordpress')">WordPress</button>
        <button onclick="addService('phpmyadmin')">phpMyAdmin</button>
        <button onclick="addService('adminer')">Adminer</button>
        <button onclick="addService('mailhog')">MailHog</button>
    </div>
</div>

<div class="active-services" id="active-services">
    <h3>Services actifs</h3>
    <div id="services-list"></div>
</div>

<div class="global-options">
    <h3>Options globales</h3>
    <div class="form-grid">
        <div class="form-group">
            <label for="project-name">Nom du projet</label>
            <input type="text" id="project-name" placeholder="myproject">
        </div>
        <div class="form-group">
            <label for="compose-version">Version Compose</label>
            <select id="compose-version">
                <option value="3.8">3.8 (recommande)</option>
                <option value="3.9">3.9</option>
                <option value="3.7">3.7</option>
            </select>
        </div>
        <div class="form-group">
            <label><input type="checkbox" id="create-network" checked> Creer un reseau</label>
        </div>
        <div class="form-group">
            <label><input type="checkbox" id="create-volumes" checked> Volumes persistants</label>
        </div>
    </div>
</div>

<div class="output-section">
    <div class="output-header">
        <h3>docker-compose.yml</h3>
        <div class="output-actions">
            <button onclick="copyOutput()" class="copy-btn">Copier</button>
            <button onclick="downloadOutput()" class="download-btn">Telecharger</button>
        </div>
    </div>
    <pre id="compose-output" class="compose-output"></pre>
</div>

<div class="commands-section">
    <h3>Commandes</h3>
    <pre id="commands-output"></pre>
</div>

</div>

## Commandes Docker Compose

```bash
# Demarrer les services
docker compose up -d

# Arreter les services
docker compose down

# Voir les logs
docker compose logs -f

# Reconstruire les images
docker compose build --no-cache

# Voir le statut
docker compose ps
```

<style>
.tool-container {
    background: var(--md-code-bg-color);
    padding: 20px;
    border-radius: 8px;
    margin: 20px 0;
}
.services-section, .active-services, .global-options, .output-section, .commands-section {
    background: var(--md-default-bg-color);
    padding: 20px;
    border-radius: 4px;
    margin-bottom: 20px;
}
.services-section h3, .active-services h3, .global-options h3, .commands-section h3 {
    margin: 0 0 15px 0;
}
.service-buttons {
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
}
.service-buttons button {
    padding: 8px 16px;
    background: var(--md-code-bg-color);
    color: var(--md-default-fg-color);
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    cursor: pointer;
    font-size: 13px;
}
.service-buttons button:hover {
    background: var(--md-primary-fg-color);
    color: white;
    border-color: var(--md-primary-fg-color);
}
#services-list {
    display: flex;
    flex-direction: column;
    gap: 15px;
}
.service-card {
    background: var(--md-code-bg-color);
    padding: 15px;
    border-radius: 4px;
    border-left: 4px solid var(--md-primary-fg-color);
}
.service-card-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 10px;
}
.service-card-header h4 {
    margin: 0;
}
.service-card-header button {
    padding: 5px 10px;
    background: #dc3545;
    color: white;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    font-size: 12px;
}
.service-options {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 10px;
}
.service-options input {
    padding: 8px;
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    background: var(--md-default-bg-color);
    color: var(--md-default-fg-color);
    font-size: 12px;
    font-family: monospace;
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
.output-actions {
    display: flex;
    gap: 10px;
}
.copy-btn, .download-btn {
    padding: 8px 16px;
    background: var(--md-primary-fg-color);
    color: white;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    font-size: 12px;
}
.compose-output {
    background: var(--md-code-bg-color);
    padding: 15px;
    border-radius: 4px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 13px;
    overflow-x: auto;
    margin: 0;
    white-space: pre;
    min-height: 200px;
}
.commands-section pre {
    background: var(--md-code-bg-color);
    padding: 15px;
    border-radius: 4px;
    font-size: 13px;
    margin: 0;
}
</style>

<script>
const SERVICE_TEMPLATES = {
    nginx: {
        name: 'nginx',
        image: 'nginx:alpine',
        ports: ['80:80'],
        volumes: ['./nginx.conf:/etc/nginx/nginx.conf:ro', './html:/usr/share/nginx/html:ro']
    },
    apache: {
        name: 'apache',
        image: 'httpd:alpine',
        ports: ['80:80'],
        volumes: ['./html:/usr/local/apache2/htdocs:ro']
    },
    node: {
        name: 'node',
        image: 'node:20-alpine',
        ports: ['3000:3000'],
        volumes: ['./app:/app'],
        working_dir: '/app',
        command: 'npm start'
    },
    python: {
        name: 'python',
        image: 'python:3.12-slim',
        ports: ['8000:8000'],
        volumes: ['./app:/app'],
        working_dir: '/app',
        command: 'python app.py'
    },
    mysql: {
        name: 'mysql',
        image: 'mysql:8',
        ports: ['3306:3306'],
        environment: {
            MYSQL_ROOT_PASSWORD: 'rootpassword',
            MYSQL_DATABASE: 'mydb',
            MYSQL_USER: 'user',
            MYSQL_PASSWORD: 'password'
        },
        volumes: ['mysql_data:/var/lib/mysql']
    },
    postgres: {
        name: 'postgres',
        image: 'postgres:16-alpine',
        ports: ['5432:5432'],
        environment: {
            POSTGRES_DB: 'mydb',
            POSTGRES_USER: 'user',
            POSTGRES_PASSWORD: 'password'
        },
        volumes: ['postgres_data:/var/lib/postgresql/data']
    },
    mariadb: {
        name: 'mariadb',
        image: 'mariadb:11',
        ports: ['3306:3306'],
        environment: {
            MARIADB_ROOT_PASSWORD: 'rootpassword',
            MARIADB_DATABASE: 'mydb',
            MARIADB_USER: 'user',
            MARIADB_PASSWORD: 'password'
        },
        volumes: ['mariadb_data:/var/lib/mysql']
    },
    mongodb: {
        name: 'mongodb',
        image: 'mongo:7',
        ports: ['27017:27017'],
        environment: {
            MONGO_INITDB_ROOT_USERNAME: 'root',
            MONGO_INITDB_ROOT_PASSWORD: 'password'
        },
        volumes: ['mongodb_data:/data/db']
    },
    redis: {
        name: 'redis',
        image: 'redis:alpine',
        ports: ['6379:6379'],
        volumes: ['redis_data:/data'],
        command: 'redis-server --appendonly yes'
    },
    rabbitmq: {
        name: 'rabbitmq',
        image: 'rabbitmq:3-management-alpine',
        ports: ['5672:5672', '15672:15672'],
        environment: {
            RABBITMQ_DEFAULT_USER: 'user',
            RABBITMQ_DEFAULT_PASS: 'password'
        },
        volumes: ['rabbitmq_data:/var/lib/rabbitmq']
    },
    elasticsearch: {
        name: 'elasticsearch',
        image: 'elasticsearch:8.11.0',
        ports: ['9200:9200'],
        environment: {
            'discovery.type': 'single-node',
            'xpack.security.enabled': 'false',
            'ES_JAVA_OPTS': '-Xms512m -Xmx512m'
        },
        volumes: ['elasticsearch_data:/usr/share/elasticsearch/data']
    },
    traefik: {
        name: 'traefik',
        image: 'traefik:v2.10',
        ports: ['80:80', '443:443', '8080:8080'],
        command: ['--api.insecure=true', '--providers.docker'],
        volumes: ['/var/run/docker.sock:/var/run/docker.sock:ro']
    },
    wordpress: {
        name: 'wordpress',
        image: 'wordpress:latest',
        ports: ['8080:80'],
        environment: {
            WORDPRESS_DB_HOST: 'mysql',
            WORDPRESS_DB_USER: 'user',
            WORDPRESS_DB_PASSWORD: 'password',
            WORDPRESS_DB_NAME: 'wordpress'
        },
        volumes: ['wordpress_data:/var/www/html'],
        depends_on: ['mysql']
    },
    phpmyadmin: {
        name: 'phpmyadmin',
        image: 'phpmyadmin:latest',
        ports: ['8081:80'],
        environment: {
            PMA_HOST: 'mysql',
            PMA_USER: 'root',
            PMA_PASSWORD: 'rootpassword'
        },
        depends_on: ['mysql']
    },
    adminer: {
        name: 'adminer',
        image: 'adminer:latest',
        ports: ['8081:8080'],
        depends_on: []
    },
    mailhog: {
        name: 'mailhog',
        image: 'mailhog/mailhog',
        ports: ['1025:1025', '8025:8025']
    }
};

let activeServices = [];

function addService(type) {
    const template = JSON.parse(JSON.stringify(SERVICE_TEMPLATES[type]));
    template.id = Date.now();
    activeServices.push(template);
    renderServices();
    generateCompose();
}

function removeService(id) {
    activeServices = activeServices.filter(s => s.id !== id);
    renderServices();
    generateCompose();
}

function renderServices() {
    const list = document.getElementById('services-list');

    if (activeServices.length === 0) {
        list.innerHTML = '<p style="color: var(--md-default-fg-color--light)">Aucun service. Cliquez sur un bouton ci-dessus pour ajouter un service.</p>';
        return;
    }

    list.innerHTML = activeServices.map(service => `
        <div class="service-card">
            <div class="service-card-header">
                <h4>${service.name}</h4>
                <button onclick="removeService(${service.id})">Supprimer</button>
            </div>
            <div class="service-options">
                <input type="text" value="${service.image}" placeholder="Image" onchange="updateService(${service.id}, 'image', this.value)">
                <input type="text" value="${service.ports ? service.ports.join(', ') : ''}" placeholder="Ports (ex: 80:80)" onchange="updateServicePorts(${service.id}, this.value)">
            </div>
        </div>
    `).join('');
}

function updateService(id, key, value) {
    const service = activeServices.find(s => s.id === id);
    if (service) {
        service[key] = value;
        generateCompose();
    }
}

function updateServicePorts(id, value) {
    const service = activeServices.find(s => s.id === id);
    if (service) {
        service.ports = value.split(',').map(p => p.trim()).filter(p => p);
        generateCompose();
    }
}

function generateCompose() {
    const version = document.getElementById('compose-version').value;
    const createNetwork = document.getElementById('create-network').checked;
    const createVolumes = document.getElementById('create-volumes').checked;
    const projectName = document.getElementById('project-name').value || 'myproject';

    if (activeServices.length === 0) {
        document.getElementById('compose-output').textContent = '# Ajoutez des services pour generer le fichier';
        return;
    }

    let yaml = `version: '${version}'

services:
`;

    // Collect volumes
    const volumes = new Set();

    activeServices.forEach(service => {
        yaml += `  ${service.name}:
    image: ${service.image}
    container_name: ${projectName}_${service.name}
`;

        if (service.ports && service.ports.length > 0) {
            yaml += `    ports:
`;
            service.ports.forEach(port => {
                yaml += `      - "${port}"
`;
            });
        }

        if (service.environment) {
            yaml += `    environment:
`;
            Object.entries(service.environment).forEach(([key, val]) => {
                yaml += `      ${key}: "${val}"
`;
            });
        }

        if (service.volumes && service.volumes.length > 0) {
            yaml += `    volumes:
`;
            service.volumes.forEach(vol => {
                yaml += `      - ${vol}
`;
                // Extract named volumes
                if (!vol.startsWith('./') && !vol.startsWith('/')) {
                    const volName = vol.split(':')[0];
                    volumes.add(volName);
                }
            });
        }

        if (service.working_dir) {
            yaml += `    working_dir: ${service.working_dir}
`;
        }

        if (service.command) {
            if (Array.isArray(service.command)) {
                yaml += `    command:
`;
                service.command.forEach(cmd => {
                    yaml += `      - ${cmd}
`;
                });
            } else {
                yaml += `    command: ${service.command}
`;
            }
        }

        if (service.depends_on && service.depends_on.length > 0) {
            yaml += `    depends_on:
`;
            service.depends_on.forEach(dep => {
                yaml += `      - ${dep}
`;
            });
        }

        if (createNetwork) {
            yaml += `    networks:
      - ${projectName}_network
`;
        }

        yaml += `    restart: unless-stopped

`;
    });

    // Networks
    if (createNetwork) {
        yaml += `networks:
  ${projectName}_network:
    driver: bridge

`;
    }

    // Volumes
    if (createVolumes && volumes.size > 0) {
        yaml += `volumes:
`;
        volumes.forEach(vol => {
            yaml += `  ${vol}:
`;
        });
    }

    document.getElementById('compose-output').textContent = yaml;

    // Commands
    document.getElementById('commands-output').textContent = `# Demarrer les services
docker compose up -d

# Voir les logs
docker compose logs -f

# Arreter les services
docker compose down

# Supprimer les volumes
docker compose down -v`;
}

function copyOutput() {
    const output = document.getElementById('compose-output').textContent;
    navigator.clipboard.writeText(output);

    const btn = document.querySelector('.copy-btn');
    btn.textContent = 'Copie!';
    setTimeout(() => { btn.textContent = 'Copier'; }, 1000);
}

function downloadOutput() {
    const output = document.getElementById('compose-output').textContent;
    const blob = new Blob([output], { type: 'text/yaml' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'docker-compose.yml';
    a.click();
    URL.revokeObjectURL(url);
}

// Event listeners
document.querySelectorAll('.global-options input, .global-options select').forEach(el => {
    el.addEventListener('input', generateCompose);
    el.addEventListener('change', generateCompose);
});

// Initial render
renderServices();
generateCompose();
</script>
