---
tags:
  - tutos
  - security
  - wazuh
  - siem
  - xdr
  - ids
  - rocky
---

# Wazuh sur Rocky Linux 9

Installation de **Wazuh** - plateforme SIEM et XDR open source.

| Composant | Version |
|-----------|---------|
| Rocky Linux | 9.x |
| Wazuh | 4.7+ |
| Elasticsearch | 7.17+ |

**Durée estimée :** 45 minutes

---

## Fonctionnalités Wazuh

| Fonction | Description |
|----------|-------------|
| **SIEM** | Collecte et analyse des logs |
| **IDS/IPS** | Détection d'intrusion |
| **FIM** | Surveillance intégrité fichiers |
| **Vulnerability** | Scan vulnérabilités |
| **Compliance** | PCI-DSS, GDPR, HIPAA |
| **XDR** | Détection et réponse étendues |

---

## Architecture

```
Agents (endpoints) → Wazuh Manager → Wazuh Indexer → Wazuh Dashboard
```

---

## 1. Prérequis

```bash
# Ressources minimales
# - 4 CPU
# - 8 GB RAM
# - 50 GB disque

# Désactiver SELinux temporairement (ou configurer)
setenforce 0
sed -i 's/SELINUX=enforcing/SELINUX=permissive/' /etc/selinux/config
```

---

## 2. Installation tout-en-un

### Script d'installation officiel

```bash
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
curl -sO https://packages.wazuh.com/4.7/config.yml

# Éditer config.yml
cat > config.yml << 'EOF'
nodes:
  indexer:
    - name: wazuh-indexer
      ip: 127.0.0.1
  server:
    - name: wazuh-server
      ip: 127.0.0.1
  dashboard:
    - name: wazuh-dashboard
      ip: 127.0.0.1
EOF

# Installer
bash wazuh-install.sh -a
```

L'installation affiche les credentials admin à la fin.

---

## 3. Installation manuelle - Wazuh Indexer

### Repository

```bash
rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH

cat > /etc/yum.repos.d/wazuh.repo << 'EOF'
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL-$releasever - Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
EOF
```

### Installer l'indexer

```bash
dnf install -y wazuh-indexer

# Configurer
cat > /etc/wazuh-indexer/opensearch.yml << 'EOF'
network.host: 0.0.0.0
node.name: wazuh-indexer
cluster.initial_master_nodes:
  - wazuh-indexer
cluster.name: wazuh-cluster

path.data: /var/lib/wazuh-indexer
path.logs: /var/log/wazuh-indexer

plugins.security.ssl.http.enabled: true
plugins.security.ssl.http.pemcert_filepath: /etc/wazuh-indexer/certs/wazuh-indexer.pem
plugins.security.ssl.http.pemkey_filepath: /etc/wazuh-indexer/certs/wazuh-indexer-key.pem
plugins.security.ssl.http.pemtrustedcas_filepath: /etc/wazuh-indexer/certs/root-ca.pem
plugins.security.ssl.transport.pemcert_filepath: /etc/wazuh-indexer/certs/wazuh-indexer.pem
plugins.security.ssl.transport.pemkey_filepath: /etc/wazuh-indexer/certs/wazuh-indexer-key.pem
plugins.security.ssl.transport.pemtrustedcas_filepath: /etc/wazuh-indexer/certs/root-ca.pem
plugins.security.ssl.transport.enforce_hostname_verification: false

plugins.security.authcz.admin_dn:
  - "CN=admin,OU=Wazuh,O=Wazuh,L=California,C=US"
plugins.security.nodes_dn:
  - "CN=wazuh-indexer,OU=Wazuh,O=Wazuh,L=California,C=US"

plugins.security.allow_default_init_securityindex: true
plugins.security.restapi.roles_enabled:
  - "all_access"
  - "security_rest_api_access"

compatibility.override_main_response_version: true
EOF
```

---

## 4. Installation Wazuh Manager

```bash
dnf install -y wazuh-manager

systemctl daemon-reload
systemctl enable --now wazuh-manager
```

### Configuration manager

```bash
# /var/ossec/etc/ossec.conf
# Configuration par défaut généralement suffisante
```

---

## 5. Installation Wazuh Dashboard

```bash
dnf install -y wazuh-dashboard

# Configurer
cat > /etc/wazuh-dashboard/opensearch_dashboards.yml << 'EOF'
server.host: 0.0.0.0
server.port: 443
opensearch.hosts: ["https://127.0.0.1:9200"]
opensearch.ssl.verificationMode: certificate
opensearch.username: kibanaserver
opensearch.password: kibanaserver
opensearch.requestHeadersWhitelist: ["securitytenant","Authorization"]
opensearch_security.multitenancy.enabled: false
opensearch_security.readonly_mode.roles: ["kibana_read_only"]
server.ssl.enabled: true
server.ssl.key: "/etc/wazuh-dashboard/certs/wazuh-dashboard-key.pem"
server.ssl.certificate: "/etc/wazuh-dashboard/certs/wazuh-dashboard.pem"
uiSettings.overrides.defaultRoute: /app/wazuh
EOF

systemctl daemon-reload
systemctl enable --now wazuh-dashboard
```

---

## 6. Firewall

```bash
firewall-cmd --permanent --add-port=443/tcp    # Dashboard
firewall-cmd --permanent --add-port=1514/tcp   # Agent registration
firewall-cmd --permanent --add-port=1515/tcp   # Agent communication
firewall-cmd --permanent --add-port=55000/tcp  # API
firewall-cmd --permanent --add-port=9200/tcp   # Indexer
firewall-cmd --reload
```

---

## 7. Accès Dashboard

- URL: `https://IP:443`
- User: `admin`
- Password: (affiché à l'installation ou dans `/etc/wazuh-install-files/wazuh-passwords.txt`)

---

## 8. Installer un agent

### Sur le serveur à monitorer (Rocky/RHEL)

```bash
rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH

cat > /etc/yum.repos.d/wazuh.repo << 'EOF'
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL-$releasever - Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
EOF

WAZUH_MANAGER="wazuh.example.com" dnf install -y wazuh-agent

systemctl daemon-reload
systemctl enable --now wazuh-agent
```

### Sur Debian/Ubuntu

```bash
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor > /etc/apt/keyrings/wazuh.gpg
echo "deb [signed-by=/etc/apt/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list
apt update

WAZUH_MANAGER="wazuh.example.com" apt install -y wazuh-agent

systemctl daemon-reload
systemctl enable --now wazuh-agent
```

---

## 9. File Integrity Monitoring (FIM)

### Configurer sur l'agent

```xml
<!-- /var/ossec/etc/ossec.conf -->
<syscheck>
  <disabled>no</disabled>
  <frequency>43200</frequency>

  <!-- Répertoires à surveiller -->
  <directories check_all="yes" realtime="yes">/etc</directories>
  <directories check_all="yes" realtime="yes">/usr/bin</directories>
  <directories check_all="yes" realtime="yes">/usr/sbin</directories>
  <directories check_all="yes" realtime="yes">/bin</directories>
  <directories check_all="yes" realtime="yes">/sbin</directories>

  <!-- Fichiers à ignorer -->
  <ignore>/etc/mtab</ignore>
  <ignore>/etc/hosts.deny</ignore>
  <ignore>/etc/mail/statistics</ignore>

  <!-- Registre Windows -->
  <windows_registry>HKEY_LOCAL_MACHINE\Software</windows_registry>
</syscheck>
```

```bash
systemctl restart wazuh-agent
```

---

## 10. Vulnerability Detection

### Activer sur le manager

```xml
<!-- /var/ossec/etc/ossec.conf -->
<vulnerability-detector>
  <enabled>yes</enabled>
  <interval>5m</interval>
  <min_full_scan_interval>6h</min_full_scan_interval>
  <run_on_start>yes</run_on_start>

  <!-- Sources de vulnérabilités -->
  <provider name="nvd">
    <enabled>yes</enabled>
    <update_interval>1h</update_interval>
  </provider>

  <provider name="redhat">
    <enabled>yes</enabled>
    <update_interval>1h</update_interval>
  </provider>

  <provider name="debian">
    <enabled>yes</enabled>
    <update_interval>1h</update_interval>
  </provider>
</vulnerability-detector>
```

```bash
systemctl restart wazuh-manager
```

---

## 11. Active Response

### Bloquer IP après attaque brute-force

```xml
<!-- /var/ossec/etc/ossec.conf sur le manager -->
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>5710,5712</rules_id>
  <timeout>3600</timeout>
</active-response>
```

### Commande personnalisée

```xml
<command>
  <name>custom-block</name>
  <executable>custom-block.sh</executable>
  <timeout_allowed>yes</timeout_allowed>
</command>

<active-response>
  <command>custom-block</command>
  <location>local</location>
  <rules_id>100001</rules_id>
  <timeout>600</timeout>
</active-response>
```

---

## 12. Règles personnalisées

### Créer une règle

```bash
cat >> /var/ossec/etc/rules/local_rules.xml << 'EOF'
<group name="local,syslog,">
  <rule id="100001" level="10">
    <if_sid>5716</if_sid>
    <srcip>!192.168.1.0/24</srcip>
    <description>SSH brute force from external IP</description>
    <group>authentication_failures,</group>
  </rule>

  <rule id="100002" level="12">
    <if_sid>550</if_sid>
    <match>passwd</match>
    <description>Password file modified</description>
    <group>syscheck,</group>
  </rule>
</group>
EOF

# Vérifier la syntaxe
/var/ossec/bin/wazuh-logtest

systemctl restart wazuh-manager
```

---

## 13. Intégration SIEM

### Envoyer les alertes vers Syslog

```xml
<!-- /var/ossec/etc/ossec.conf -->
<syslog_output>
  <server>192.168.1.50</server>
  <port>514</port>
  <format>json</format>
</syslog_output>
```

### Intégration Slack

```xml
<integration>
  <name>slack</name>
  <hook_url>https://hooks.slack.com/services/XXX/YYY/ZZZ</hook_url>
  <level>10</level>
  <alert_format>json</alert_format>
</integration>
```

---

## 14. API Wazuh

```bash
# Obtenir un token
TOKEN=$(curl -u wazuh:wazuh -k -X GET "https://localhost:55000/security/user/authenticate?raw=true")

# Lister les agents
curl -k -X GET "https://localhost:55000/agents" \
  -H "Authorization: Bearer $TOKEN"

# Status du manager
curl -k -X GET "https://localhost:55000/manager/status" \
  -H "Authorization: Bearer $TOKEN"

# Dernières alertes
curl -k -X GET "https://localhost:55000/alerts?limit=10" \
  -H "Authorization: Bearer $TOKEN"
```

---

## Commandes utiles

```bash
# Status services
systemctl status wazuh-manager
systemctl status wazuh-indexer
systemctl status wazuh-dashboard

# Logs
tail -f /var/ossec/logs/ossec.log
tail -f /var/ossec/logs/alerts/alerts.json

# Agents connectés
/var/ossec/bin/agent_control -l

# Redémarrer un agent
/var/ossec/bin/agent_control -R 001

# Vérifier règles
/var/ossec/bin/wazuh-logtest
```

---

## Dépannage

```bash
# Vérifier la configuration
/var/ossec/bin/wazuh-control -t

# Statut cluster
curl -k -X GET "https://localhost:55000/cluster/status" \
  -H "Authorization: Bearer $TOKEN"

# Agent non connecté
# Sur l'agent :
cat /var/ossec/etc/ossec.conf | grep address
systemctl restart wazuh-agent
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
