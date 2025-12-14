---
tags:
  - tutos
  - security
  - wazuh
  - siem
  - xdr
  - ids
  - debian
---

# Wazuh sur Debian 12

Installation de **Wazuh** sur Debian 12 Bookworm.

| Composant | Version |
|-----------|---------|
| Debian | 12 Bookworm |
| Wazuh | 4.7+ |

**Durée estimée :** 40 minutes

---

## 1. Prérequis

```bash
apt update
apt install -y curl apt-transport-https gnupg

# Ressources recommandées : 4 CPU, 8 GB RAM, 50 GB disque
```

---

## 2. Installation tout-en-un

```bash
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
curl -sO https://packages.wazuh.com/4.7/config.yml

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

bash wazuh-install.sh -a
```

---

## 3. Installation manuelle

### Repository

```bash
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor > /etc/apt/keyrings/wazuh.gpg
echo "deb [signed-by=/etc/apt/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list
apt update
```

### Installer les composants

```bash
# Indexer
apt install -y wazuh-indexer

# Manager
apt install -y wazuh-manager

# Dashboard
apt install -y wazuh-dashboard

systemctl enable --now wazuh-indexer wazuh-manager wazuh-dashboard
```

---

## 4. Firewall

```bash
ufw allow 443/tcp    # Dashboard
ufw allow 1514/tcp   # Agent
ufw allow 1515/tcp   # Agent
ufw allow 55000/tcp  # API
ufw reload
```

---

## 5. Accès

- URL: `https://IP:443`
- Credentials dans `/etc/wazuh-install-files/wazuh-passwords.txt`

---

## 6. Installer un agent Debian

```bash
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor > /etc/apt/keyrings/wazuh.gpg
echo "deb [signed-by=/etc/apt/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list
apt update

WAZUH_MANAGER="wazuh.example.com" apt install -y wazuh-agent

systemctl daemon-reload
systemctl enable --now wazuh-agent
```

---

## 7. File Integrity Monitoring

```xml
<!-- /var/ossec/etc/ossec.conf -->
<syscheck>
  <disabled>no</disabled>
  <frequency>43200</frequency>
  <directories check_all="yes" realtime="yes">/etc</directories>
  <directories check_all="yes" realtime="yes">/usr/bin</directories>
  <directories check_all="yes" realtime="yes">/bin</directories>
  <ignore>/etc/mtab</ignore>
</syscheck>
```

---

## 8. Vulnerability Detection

```xml
<!-- /var/ossec/etc/ossec.conf sur manager -->
<vulnerability-detector>
  <enabled>yes</enabled>
  <interval>5m</interval>
  <provider name="nvd">
    <enabled>yes</enabled>
  </provider>
  <provider name="debian">
    <enabled>yes</enabled>
  </provider>
</vulnerability-detector>
```

---

## 9. Active Response

```xml
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>5710,5712</rules_id>
  <timeout>3600</timeout>
</active-response>
```

---

## Comparatif Rocky vs Debian

| Aspect | Rocky 9 | Debian 12 |
|--------|---------|-----------|
| Package manager | dnf | apt |
| Firewall | firewalld | ufw |
| SELinux | Oui | AppArmor |

---

## Commandes

```bash
# Status
systemctl status wazuh-manager wazuh-indexer wazuh-dashboard

# Logs
tail -f /var/ossec/logs/ossec.log

# Agents
/var/ossec/bin/agent_control -l

# Test règles
/var/ossec/bin/wazuh-logtest
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
