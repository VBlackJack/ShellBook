---
tags:
  - tutos
  - monitoring
  - elk
  - elasticsearch
  - kibana
  - debian
---

# ELK Stack sur Debian 12

Installation de la stack **ELK** sur Debian 12 Bookworm.

| Composant | Version |
|-----------|---------|
| Debian | 12 Bookworm |
| Elasticsearch | 8.x |
| Logstash | 8.x |
| Kibana | 8.x |

**Durée estimée :** 40 minutes

---

## 1. Prérequis

```bash
apt update
apt install -y apt-transport-https gnupg2

# Limites
cat >> /etc/security/limits.conf << 'EOF'
elasticsearch soft nofile 65536
elasticsearch hard nofile 65536
EOF

echo 'vm.max_map_count=262144' >> /etc/sysctl.d/99-elasticsearch.conf
sysctl -p /etc/sysctl.d/99-elasticsearch.conf
```

---

## 2. Repository Elastic

```bash
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg

echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" > /etc/apt/sources.list.d/elastic-8.x.list

apt update
```

---

## 3. Elasticsearch

```bash
apt install -y elasticsearch
```

### Configuration

```bash
vim /etc/elasticsearch/elasticsearch.yml
```

```yaml
cluster.name: elk-cluster
node.name: elk-node-1
network.host: 0.0.0.0
discovery.type: single-node
xpack.security.enabled: true
```

### JVM Heap

```bash
echo '-Xms4g' > /etc/elasticsearch/jvm.options.d/heap.options
echo '-Xmx4g' >> /etc/elasticsearch/jvm.options.d/heap.options
```

### Démarrer

```bash
systemctl enable --now elasticsearch

# Reset password
/usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic
```

---

## 4. Kibana

```bash
apt install -y kibana
```

### Configuration

```bash
vim /etc/kibana/kibana.yml
```

```yaml
server.port: 5601
server.host: "0.0.0.0"
elasticsearch.hosts: ["https://localhost:9200"]
elasticsearch.ssl.certificateAuthorities: ["/etc/kibana/certs/http_ca.crt"]
```

### Setup avec token

```bash
/usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana
/usr/share/kibana/bin/kibana-setup
```

### Démarrer

```bash
systemctl enable --now kibana
```

---

## 5. Logstash

```bash
apt install -y logstash
```

### Pipeline

```bash
vim /etc/logstash/conf.d/beats.conf
```

```conf
input {
  beats {
    port => 5044
  }
}

output {
  elasticsearch {
    hosts => ["https://localhost:9200"]
    user => "elastic"
    password => "PASSWORD"
    ssl_certificate_verification => false
    index => "logstash-%{+YYYY.MM.dd}"
  }
}
```

```bash
systemctl enable --now logstash
```

---

## 6. Filebeat (clients)

```bash
apt install -y filebeat
```

```yaml
# /etc/filebeat/filebeat.yml
filebeat.inputs:
  - type: log
    paths:
      - /var/log/syslog
      - /var/log/auth.log

output.logstash:
  hosts: ["elk-server:5044"]
```

```bash
filebeat modules enable system
systemctl enable --now filebeat
```

---

## 7. Firewall

```bash
ufw allow 9200/tcp
ufw allow 5601/tcp
ufw allow 5044/tcp
ufw reload
```

---

## Comparatif Rocky vs Debian

| Aspect | Rocky 9 | Debian 12 |
|--------|---------|-----------|
| Repo | yum/dnf | apt |
| GPG | rpm --import | gpg --dearmor |
| Logs | /var/log/messages | /var/log/syslog |

---

## Commandes

```bash
# Status
curl -k -u elastic:PASSWORD https://localhost:9200/_cluster/health

# Indices
curl -k -u elastic:PASSWORD https://localhost:9200/_cat/indices

# Nœuds
curl -k -u elastic:PASSWORD https://localhost:9200/_cat/nodes
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
