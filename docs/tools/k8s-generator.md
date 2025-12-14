---
tags:
  - tools
  - kubernetes
  - k8s
  - yaml
  - generator
---

# Kubernetes Manifest Generator

Generateur de manifests Kubernetes : Deployment, Service, Ingress, ConfigMap.

<div class="tool-container">

<div class="type-selector">
    <button class="type-btn active" onclick="selectType('deployment')">Deployment</button>
    <button class="type-btn" onclick="selectType('service')">Service</button>
    <button class="type-btn" onclick="selectType('ingress')">Ingress</button>
    <button class="type-btn" onclick="selectType('configmap')">ConfigMap</button>
    <button class="type-btn" onclick="selectType('secret')">Secret</button>
    <button class="type-btn" onclick="selectType('pvc')">PVC</button>
</div>

<div class="config-section" id="config-section">
    <!-- Dynamic content -->
</div>

<div class="output-section">
    <div class="output-header">
        <h4>Manifest YAML</h4>
        <div class="output-actions">
            <button onclick="copyYaml()" class="copy-btn">Copier</button>
            <button onclick="downloadYaml()" class="download-btn">Telecharger</button>
        </div>
    </div>
    <pre id="yaml-output" class="yaml-output"></pre>
</div>

<div class="tips-section">
    <h3>Commandes kubectl</h3>
    <div class="tips-grid">
        <div class="tip-card">
            <code>kubectl apply -f manifest.yaml</code>
            <span>Appliquer le manifest</span>
        </div>
        <div class="tip-card">
            <code>kubectl get pods -l app=myapp</code>
            <span>Lister les pods</span>
        </div>
        <div class="tip-card">
            <code>kubectl describe deployment myapp</code>
            <span>Details du deployment</span>
        </div>
        <div class="tip-card">
            <code>kubectl logs -l app=myapp</code>
            <span>Voir les logs</span>
        </div>
    </div>
</div>

</div>

## Ressources Utiles

| Ressource | Description |
|-----------|-------------|
| **Deployment** | Gestion du cycle de vie des Pods |
| **Service** | Exposition reseau des Pods |
| **Ingress** | Routage HTTP/HTTPS externe |
| **ConfigMap** | Configuration non-sensible |
| **Secret** | Donnees sensibles (base64) |
| **PVC** | Stockage persistant |

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
    flex-wrap: wrap;
    margin-bottom: 20px;
}
.type-btn {
    padding: 10px 16px;
    background: var(--md-default-bg-color);
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    cursor: pointer;
    color: var(--md-default-fg-color);
}
.type-btn.active {
    background: var(--md-primary-fg-color);
    color: white;
    border-color: var(--md-primary-fg-color);
}
.config-section, .output-section, .tips-section {
    background: var(--md-default-bg-color);
    padding: 20px;
    border-radius: 4px;
    margin-bottom: 20px;
}
.config-section h4, .tips-section h3 {
    margin: 0 0 15px 0;
}
.config-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 15px;
}
.form-group {
    margin-bottom: 15px;
}
.form-group label {
    display: block;
    font-size: 12px;
    font-weight: bold;
    margin-bottom: 5px;
}
.form-group input, .form-group select, .form-group textarea {
    width: 100%;
    padding: 10px;
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    background: var(--md-code-bg-color);
    color: var(--md-default-fg-color);
    font-family: monospace;
}
.form-group textarea {
    min-height: 100px;
    resize: vertical;
}
.form-row {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 15px;
}
.output-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 15px;
}
.output-header h4 {
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
}
.yaml-output {
    background: #1e1e1e;
    color: #d4d4d4;
    padding: 20px;
    border-radius: 4px;
    overflow-x: auto;
    overflow-y: auto;
    font-size: 12px;
    line-height: 1.5;
    margin: 0;
    max-height: 500px;
}
.tips-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    gap: 10px;
}
.tip-card {
    background: var(--md-code-bg-color);
    padding: 12px;
    border-radius: 4px;
}
.tip-card code {
    display: block;
    margin-bottom: 5px;
    color: var(--md-primary-fg-color);
}
.tip-card span {
    font-size: 12px;
    color: var(--md-default-fg-color--light);
}
.checkbox-row {
    display: flex;
    gap: 20px;
    flex-wrap: wrap;
    margin-top: 15px;
}
.checkbox-row label {
    display: flex;
    align-items: center;
    gap: 5px;
    cursor: pointer;
    font-size: 13px;
}
</style>

<script>
let currentType = 'deployment';

const CONFIGS = {
    deployment: {
        title: 'Deployment Configuration',
        fields: `
            <div class="form-row">
                <div class="form-group">
                    <label for="name">Nom</label>
                    <input type="text" id="name" value="my-app" oninput="generate()">
                </div>
                <div class="form-group">
                    <label for="namespace">Namespace</label>
                    <input type="text" id="namespace" value="default" oninput="generate()">
                </div>
                <div class="form-group">
                    <label for="replicas">Replicas</label>
                    <input type="number" id="replicas" value="3" min="1" oninput="generate()">
                </div>
            </div>
            <div class="form-row">
                <div class="form-group">
                    <label for="image">Image</label>
                    <input type="text" id="image" value="nginx:latest" oninput="generate()">
                </div>
                <div class="form-group">
                    <label for="port">Container Port</label>
                    <input type="number" id="port" value="80" oninput="generate()">
                </div>
                <div class="form-group">
                    <label for="pull-policy">Image Pull Policy</label>
                    <select id="pull-policy" onchange="generate()">
                        <option value="IfNotPresent">IfNotPresent</option>
                        <option value="Always">Always</option>
                        <option value="Never">Never</option>
                    </select>
                </div>
            </div>
            <div class="form-row">
                <div class="form-group">
                    <label for="cpu-request">CPU Request</label>
                    <input type="text" id="cpu-request" value="100m" oninput="generate()">
                </div>
                <div class="form-group">
                    <label for="cpu-limit">CPU Limit</label>
                    <input type="text" id="cpu-limit" value="500m" oninput="generate()">
                </div>
                <div class="form-group">
                    <label for="mem-request">Memory Request</label>
                    <input type="text" id="mem-request" value="128Mi" oninput="generate()">
                </div>
                <div class="form-group">
                    <label for="mem-limit">Memory Limit</label>
                    <input type="text" id="mem-limit" value="256Mi" oninput="generate()">
                </div>
            </div>
            <div class="checkbox-row">
                <label><input type="checkbox" id="add-probes" checked onchange="generate()"> Ajouter Health Probes</label>
                <label><input type="checkbox" id="add-security" onchange="generate()"> Security Context</label>
            </div>
        `
    },
    service: {
        title: 'Service Configuration',
        fields: `
            <div class="form-row">
                <div class="form-group">
                    <label for="name">Nom</label>
                    <input type="text" id="name" value="my-app-svc" oninput="generate()">
                </div>
                <div class="form-group">
                    <label for="namespace">Namespace</label>
                    <input type="text" id="namespace" value="default" oninput="generate()">
                </div>
                <div class="form-group">
                    <label for="svc-type">Type</label>
                    <select id="svc-type" onchange="generate()">
                        <option value="ClusterIP">ClusterIP</option>
                        <option value="NodePort">NodePort</option>
                        <option value="LoadBalancer">LoadBalancer</option>
                    </select>
                </div>
            </div>
            <div class="form-row">
                <div class="form-group">
                    <label for="selector">Selector (app)</label>
                    <input type="text" id="selector" value="my-app" oninput="generate()">
                </div>
                <div class="form-group">
                    <label for="port">Port</label>
                    <input type="number" id="port" value="80" oninput="generate()">
                </div>
                <div class="form-group">
                    <label for="target-port">Target Port</label>
                    <input type="number" id="target-port" value="80" oninput="generate()">
                </div>
            </div>
        `
    },
    ingress: {
        title: 'Ingress Configuration',
        fields: `
            <div class="form-row">
                <div class="form-group">
                    <label for="name">Nom</label>
                    <input type="text" id="name" value="my-app-ingress" oninput="generate()">
                </div>
                <div class="form-group">
                    <label for="namespace">Namespace</label>
                    <input type="text" id="namespace" value="default" oninput="generate()">
                </div>
                <div class="form-group">
                    <label for="ingress-class">Ingress Class</label>
                    <input type="text" id="ingress-class" value="nginx" oninput="generate()">
                </div>
            </div>
            <div class="form-row">
                <div class="form-group">
                    <label for="host">Host</label>
                    <input type="text" id="host" value="app.example.com" oninput="generate()">
                </div>
                <div class="form-group">
                    <label for="path">Path</label>
                    <input type="text" id="path" value="/" oninput="generate()">
                </div>
                <div class="form-group">
                    <label for="service-name">Service Name</label>
                    <input type="text" id="service-name" value="my-app-svc" oninput="generate()">
                </div>
                <div class="form-group">
                    <label for="service-port">Service Port</label>
                    <input type="number" id="service-port" value="80" oninput="generate()">
                </div>
            </div>
            <div class="checkbox-row">
                <label><input type="checkbox" id="add-tls" onchange="generate()"> TLS/HTTPS</label>
                <label><input type="checkbox" id="add-annotations" onchange="generate()"> Annotations communes</label>
            </div>
        `
    },
    configmap: {
        title: 'ConfigMap Configuration',
        fields: `
            <div class="form-row">
                <div class="form-group">
                    <label for="name">Nom</label>
                    <input type="text" id="name" value="my-app-config" oninput="generate()">
                </div>
                <div class="form-group">
                    <label for="namespace">Namespace</label>
                    <input type="text" id="namespace" value="default" oninput="generate()">
                </div>
            </div>
            <div class="form-group">
                <label for="config-data">Data (key=value, une par ligne)</label>
                <textarea id="config-data" oninput="generate()">APP_ENV=production
LOG_LEVEL=info
MAX_CONNECTIONS=100</textarea>
            </div>
        `
    },
    secret: {
        title: 'Secret Configuration',
        fields: `
            <div class="form-row">
                <div class="form-group">
                    <label for="name">Nom</label>
                    <input type="text" id="name" value="my-app-secret" oninput="generate()">
                </div>
                <div class="form-group">
                    <label for="namespace">Namespace</label>
                    <input type="text" id="namespace" value="default" oninput="generate()">
                </div>
                <div class="form-group">
                    <label for="secret-type">Type</label>
                    <select id="secret-type" onchange="generate()">
                        <option value="Opaque">Opaque</option>
                        <option value="kubernetes.io/dockerconfigjson">Docker Registry</option>
                        <option value="kubernetes.io/tls">TLS</option>
                    </select>
                </div>
            </div>
            <div class="form-group">
                <label for="secret-data">Data (key=value, une par ligne)</label>
                <textarea id="secret-data" oninput="generate()">DB_PASSWORD=supersecret
API_KEY=myapikey123</textarea>
            </div>
        `
    },
    pvc: {
        title: 'PersistentVolumeClaim Configuration',
        fields: `
            <div class="form-row">
                <div class="form-group">
                    <label for="name">Nom</label>
                    <input type="text" id="name" value="my-app-pvc" oninput="generate()">
                </div>
                <div class="form-group">
                    <label for="namespace">Namespace</label>
                    <input type="text" id="namespace" value="default" oninput="generate()">
                </div>
            </div>
            <div class="form-row">
                <div class="form-group">
                    <label for="storage-class">Storage Class</label>
                    <input type="text" id="storage-class" value="standard" oninput="generate()">
                </div>
                <div class="form-group">
                    <label for="access-mode">Access Mode</label>
                    <select id="access-mode" onchange="generate()">
                        <option value="ReadWriteOnce">ReadWriteOnce</option>
                        <option value="ReadOnlyMany">ReadOnlyMany</option>
                        <option value="ReadWriteMany">ReadWriteMany</option>
                    </select>
                </div>
                <div class="form-group">
                    <label for="storage-size">Size</label>
                    <input type="text" id="storage-size" value="10Gi" oninput="generate()">
                </div>
            </div>
        `
    }
};

function selectType(type) {
    currentType = type;
    document.querySelectorAll('.type-btn').forEach(btn => btn.classList.remove('active'));
    event.target.classList.add('active');
    renderConfig();
}

function renderConfig() {
    const config = CONFIGS[currentType];
    document.getElementById('config-section').innerHTML = `
        <h4>${config.title}</h4>
        ${config.fields}
    `;
    generate();
}

function getValue(id, defaultValue = '') {
    const el = document.getElementById(id);
    return el ? el.value : defaultValue;
}

function getChecked(id) {
    const el = document.getElementById(id);
    return el ? el.checked : false;
}

function generate() {
    let yaml = '';

    switch (currentType) {
        case 'deployment':
            yaml = generateDeployment();
            break;
        case 'service':
            yaml = generateService();
            break;
        case 'ingress':
            yaml = generateIngress();
            break;
        case 'configmap':
            yaml = generateConfigMap();
            break;
        case 'secret':
            yaml = generateSecret();
            break;
        case 'pvc':
            yaml = generatePVC();
            break;
    }

    document.getElementById('yaml-output').textContent = yaml;
}

function generateDeployment() {
    const name = getValue('name', 'my-app');
    const namespace = getValue('namespace', 'default');
    const replicas = getValue('replicas', '3');
    const image = getValue('image', 'nginx:latest');
    const port = getValue('port', '80');
    const pullPolicy = getValue('pull-policy', 'IfNotPresent');
    const cpuReq = getValue('cpu-request', '100m');
    const cpuLim = getValue('cpu-limit', '500m');
    const memReq = getValue('mem-request', '128Mi');
    const memLim = getValue('mem-limit', '256Mi');
    const addProbes = getChecked('add-probes');
    const addSecurity = getChecked('add-security');

    let yaml = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: ${name}
  namespace: ${namespace}
  labels:
    app: ${name}
spec:
  replicas: ${replicas}
  selector:
    matchLabels:
      app: ${name}
  template:
    metadata:
      labels:
        app: ${name}
    spec:
      containers:
        - name: ${name}
          image: ${image}
          imagePullPolicy: ${pullPolicy}
          ports:
            - containerPort: ${port}
          resources:
            requests:
              cpu: "${cpuReq}"
              memory: "${memReq}"
            limits:
              cpu: "${cpuLim}"
              memory: "${memLim}"`;

    if (addProbes) {
        yaml += `
          livenessProbe:
            httpGet:
              path: /health
              port: ${port}
            initialDelaySeconds: 30
            periodSeconds: 10
          readinessProbe:
            httpGet:
              path: /ready
              port: ${port}
            initialDelaySeconds: 5
            periodSeconds: 5`;
    }

    if (addSecurity) {
        yaml += `
          securityContext:
            runAsNonRoot: true
            runAsUser: 1000
            readOnlyRootFilesystem: true
            allowPrivilegeEscalation: false`;
    }

    return yaml;
}

function generateService() {
    const name = getValue('name', 'my-app-svc');
    const namespace = getValue('namespace', 'default');
    const svcType = getValue('svc-type', 'ClusterIP');
    const selector = getValue('selector', 'my-app');
    const port = getValue('port', '80');
    const targetPort = getValue('target-port', '80');

    return `apiVersion: v1
kind: Service
metadata:
  name: ${name}
  namespace: ${namespace}
spec:
  type: ${svcType}
  selector:
    app: ${selector}
  ports:
    - port: ${port}
      targetPort: ${targetPort}
      protocol: TCP`;
}

function generateIngress() {
    const name = getValue('name', 'my-app-ingress');
    const namespace = getValue('namespace', 'default');
    const ingressClass = getValue('ingress-class', 'nginx');
    const host = getValue('host', 'app.example.com');
    const path = getValue('path', '/');
    const serviceName = getValue('service-name', 'my-app-svc');
    const servicePort = getValue('service-port', '80');
    const addTls = getChecked('add-tls');
    const addAnnotations = getChecked('add-annotations');

    let yaml = `apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: ${name}
  namespace: ${namespace}`;

    if (addAnnotations) {
        yaml += `
  annotations:
    nginx.ingress.kubernetes.io/rewrite-target: /
    nginx.ingress.kubernetes.io/ssl-redirect: "true"`;
    }

    yaml += `
spec:
  ingressClassName: ${ingressClass}`;

    if (addTls) {
        yaml += `
  tls:
    - hosts:
        - ${host}
      secretName: ${name}-tls`;
    }

    yaml += `
  rules:
    - host: ${host}
      http:
        paths:
          - path: ${path}
            pathType: Prefix
            backend:
              service:
                name: ${serviceName}
                port:
                  number: ${servicePort}`;

    return yaml;
}

function generateConfigMap() {
    const name = getValue('name', 'my-app-config');
    const namespace = getValue('namespace', 'default');
    const data = getValue('config-data', '');

    let yaml = `apiVersion: v1
kind: ConfigMap
metadata:
  name: ${name}
  namespace: ${namespace}
data:`;

    data.split('\n').forEach(line => {
        const [key, ...valueParts] = line.split('=');
        if (key && valueParts.length) {
            yaml += `\n  ${key.trim()}: "${valueParts.join('=').trim()}"`;
        }
    });

    return yaml;
}

function generateSecret() {
    const name = getValue('name', 'my-app-secret');
    const namespace = getValue('namespace', 'default');
    const secretType = getValue('secret-type', 'Opaque');
    const data = getValue('secret-data', '');

    let yaml = `apiVersion: v1
kind: Secret
metadata:
  name: ${name}
  namespace: ${namespace}
type: ${secretType}
data:`;

    data.split('\n').forEach(line => {
        const [key, ...valueParts] = line.split('=');
        if (key && valueParts.length) {
            const value = valueParts.join('=').trim();
            const encoded = btoa(value);
            yaml += `\n  ${key.trim()}: ${encoded}`;
        }
    });

    return yaml;
}

function generatePVC() {
    const name = getValue('name', 'my-app-pvc');
    const namespace = getValue('namespace', 'default');
    const storageClass = getValue('storage-class', 'standard');
    const accessMode = getValue('access-mode', 'ReadWriteOnce');
    const size = getValue('storage-size', '10Gi');

    return `apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: ${name}
  namespace: ${namespace}
spec:
  storageClassName: ${storageClass}
  accessModes:
    - ${accessMode}
  resources:
    requests:
      storage: ${size}`;
}

function copyYaml() {
    const yaml = document.getElementById('yaml-output').textContent;
    navigator.clipboard.writeText(yaml);

    const btn = event.target;
    btn.textContent = 'Copie!';
    setTimeout(() => { btn.textContent = 'Copier'; }, 1000);
}

function downloadYaml() {
    const yaml = document.getElementById('yaml-output').textContent;
    const name = getValue('name', 'manifest');
    const blob = new Blob([yaml], { type: 'text/yaml' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${name}.yaml`;
    a.click();
    URL.revokeObjectURL(url);
}

// Initialize
renderConfig();
</script>
