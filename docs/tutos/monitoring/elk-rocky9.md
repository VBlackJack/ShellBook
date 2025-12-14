---
tags:
  - tutos
  - monitoring
  - elk
  - elasticsearch
  - kibana
  - rocky
---

# ELK Stack sur Rocky Linux 9

Installation de la stack **Elasticsearch, Logstash, Kibana** (ELK).

| Composant | Version |
|-----------|---------|
| Rocky Linux | 9.x |
| Elasticsearch | 8.x |
| Logstash | 8.x |
| Kibana | 8.x |

**Durée estimée :** 45 minutes

---

## Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Serveurs  │     │  Logstash   │     │Elasticsearch│
│   (logs)    │────►│  (process)  │────►│  (store)    │
│             │     │  :5044      │     │  :9200      │
└─────────────┘     └─────────────┘     └─────────────┘
                                               │
                           ┌───────────────────┘
                           ▼
                    ┌─────────────┐
                    │   Kibana    │
                    │ (visualize) │
                    │   :5601     │
                    └─────────────┘
```

---

## 1. Prérequis

```bash
# Java (inclus avec Elastic)
# RAM recommandée : 8GB minimum

# Limites système
cat >> /etc/security/limits.conf << 'EOF'
elasticsearch soft nofile 65536
elasticsearch hard nofile 65536
elasticsearch soft memlock unlimited
elasticsearch hard memlock unlimited
EOF

# Mémoire virtuelle
echo 'vm.max_map_count=262144' >> /etc/sysctl.d/99-elasticsearch.conf
sysctl -p /etc/sysctl.d/99-elasticsearch.conf
```

---

## 2. Installation Elasticsearch

### Ajouter le repository

```bash
rpm --import https://artifacts.elastic.co/GPG-KEY-elasticsearch

cat > /etc/yum.repos.d/elasticsearch.repo << 'EOF'
[elasticsearch]
name=Elasticsearch repository for 8.x packages
baseurl=https://artifacts.elastic.co/packages/8.x/yum
gpgcheck=1
gpgkey=https://artifacts.elastic.co/GPG-KEY-elasticsearch
enabled=1
autorefresh=1
type=rpm-md
EOF
```

### Installer

```bash
dnf install -y elasticsearch

# Copier le mot de passe généré automatiquement
# Le mot de passe elastic est affiché lors de l'installation
```

### Configuration

```bash
vim /etc/elasticsearch/elasticsearch.yml
```

```yaml
# Cluster
cluster.name: elk-cluster
node.name: elk-node-1

# Réseau
network.host: 0.0.0.0
http.port: 9200

# Discovery
discovery.type: single-node

# Sécurité (déjà activée par défaut en 8.x)
xpack.security.enabled: true
xpack.security.enrollment.enabled: true

# Mémoire
# Configurer dans jvm.options
```

### Mémoire JVM

```bash
vim /etc/elasticsearch/jvm.options.d/heap.options
```

```
-Xms4g
-Xmx4g
```

### Démarrer

```bash
systemctl enable --now elasticsearch

# Vérifier
curl -k -u elastic:PASSWORD https://localhost:9200
```

### Réinitialiser le mot de passe

```bash
/usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic
```

---

## 3. Installation Kibana

```bash
dnf install -y kibana
```

### Configuration

```bash
vim /etc/kibana/kibana.yml
```

```yaml
server.port: 5601
server.host: "0.0.0.0"
server.name: "kibana"

elasticsearch.hosts: ["https://localhost:9200"]
elasticsearch.username: "kibana_system"
elasticsearch.password: "KIBANA_PASSWORD"

# SSL pour Elasticsearch
elasticsearch.ssl.certificateAuthorities: ["/etc/kibana/certs/http_ca.crt"]
```

### Générer le token d'enrollment

```bash
/usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana
```

### Configurer Kibana avec le token

```bash
/usr/share/kibana/bin/kibana-setup
# Coller le token
```

### Démarrer

```bash
systemctl enable --now kibana

# Accès : http://IP:5601
```

---

## 4. Installation Logstash

```bash
dnf install -y logstash
```

### Configuration pipeline

```bash
vim /etc/logstash/conf.d/beats.conf
```

```conf
input {
  beats {
    port => 5044
    ssl => false
  }
}

filter {
  if [type] == "syslog" {
    grok {
      match => { "message" => "%{SYSLOGBASE}" }
    }
    date {
      match => [ "timestamp", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss" ]
    }
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

### Pipeline Nginx

```bash
vim /etc/logstash/conf.d/nginx.conf
```

```conf
input {
  beats {
    port => 5045
  }
}

filter {
  grok {
    match => { "message" => "%{NGINXACCESS}" }
  }
  geoip {
    source => "clientip"
  }
}

output {
  elasticsearch {
    hosts => ["https://localhost:9200"]
    user => "elastic"
    password => "PASSWORD"
    ssl_certificate_verification => false
    index => "nginx-%{+YYYY.MM.dd}"
  }
}
```

### Démarrer

```bash
systemctl enable --now logstash
```

---

## 5. Installation Filebeat (sur les clients)

```bash
dnf install -y filebeat
```

### Configuration

```bash
vim /etc/filebeat/filebeat.yml
```

```yaml
filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /var/log/messages
      - /var/log/secure
    fields:
      type: syslog

  - type: log
    enabled: true
    paths:
      - /var/log/nginx/access.log
    fields:
      type: nginx-access

output.logstash:
  hosts: ["elk-server:5044"]

# Ou directement vers Elasticsearch
# output.elasticsearch:
#   hosts: ["https://elk-server:9200"]
#   username: "elastic"
#   password: "PASSWORD"
#   ssl.verification_mode: none
```

### Modules Filebeat

```bash
# Lister
filebeat modules list

# Activer
filebeat modules enable system nginx

# Setup (dashboards Kibana)
filebeat setup -e
```

### Démarrer

```bash
systemctl enable --now filebeat
```

---

## 6. Firewall

```bash
# Elasticsearch
firewall-cmd --permanent --add-port=9200/tcp

# Kibana
firewall-cmd --permanent --add-port=5601/tcp

# Logstash
firewall-cmd --permanent --add-port=5044/tcp

firewall-cmd --reload
```

---

## 7. Index Lifecycle Management (ILM)

### Dans Kibana

```
Management > Stack Management > Index Lifecycle Policies
```

### Via API

```bash
curl -k -u elastic:PASSWORD -X PUT "https://localhost:9200/_ilm/policy/logs-policy" -H 'Content-Type: application/json' -d'
{
  "policy": {
    "phases": {
      "hot": {
        "min_age": "0ms",
        "actions": {
          "rollover": {
            "max_size": "50gb",
            "max_age": "7d"
          }
        }
      },
      "delete": {
        "min_age": "30d",
        "actions": {
          "delete": {}
        }
      }
    }
  }
}'
```

---

## 8. Sécurité

### Créer des utilisateurs

```bash
/usr/share/elasticsearch/bin/elasticsearch-users useradd viewer -r viewer
/usr/share/elasticsearch/bin/elasticsearch-users useradd admin -r superuser
```

### HTTPS Kibana

```bash
vim /etc/kibana/kibana.yml
```

```yaml
server.ssl.enabled: true
server.ssl.certificate: /etc/kibana/certs/kibana.crt
server.ssl.key: /etc/kibana/certs/kibana.key
```

---

## 9. Monitoring cluster

```bash
# Status cluster
curl -k -u elastic:PASSWORD https://localhost:9200/_cluster/health?pretty

# Nœuds
curl -k -u elastic:PASSWORD https://localhost:9200/_cat/nodes?v

# Indices
curl -k -u elastic:PASSWORD https://localhost:9200/_cat/indices?v

# Shards
curl -k -u elastic:PASSWORD https://localhost:9200/_cat/shards?v
```

---

## 10. Kibana Discover & Dashboards

1. Ouvrir Kibana : `http://IP:5601`
2. **Management** > **Data Views** > Create
3. Pattern: `logstash-*` ou `filebeat-*`
4. **Discover** pour explorer les logs
5. **Dashboard** pour créer des visualisations

---

## Commandes utiles

```bash
# Status Elasticsearch
curl -k -u elastic:PASSWORD https://localhost:9200

# Cluster health
curl -k -u elastic:PASSWORD https://localhost:9200/_cluster/health

# Indices
curl -k -u elastic:PASSWORD https://localhost:9200/_cat/indices

# Supprimer un index
curl -k -u elastic:PASSWORD -X DELETE https://localhost:9200/logstash-2024.01.01
```

---

## Dépannage

```bash
# Logs
journalctl -u elasticsearch -f
journalctl -u kibana -f
journalctl -u logstash -f

# Test Logstash config
/usr/share/logstash/bin/logstash --config.test_and_exit -f /etc/logstash/conf.d/

# Elasticsearch
curl -k -u elastic:PASSWORD https://localhost:9200/_cluster/allocation/explain?pretty
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
