---
tags:
  - tutos
  - devops
  - jenkins
  - ci-cd
  - automation
  - rocky
---

# Jenkins sur Rocky Linux 9

Installation de **Jenkins** - serveur d'automatisation CI/CD.

| Composant | Version |
|-----------|---------|
| Rocky Linux | 9.x |
| Jenkins | LTS |
| Java | 17 |

**Durée estimée :** 30 minutes

---

## Fonctionnalités

| Fonction | Description |
|----------|-------------|
| **Pipelines** | Build, test, deploy automatisés |
| **Plugins** | +1800 plugins disponibles |
| **Distributed** | Agents multiples |
| **Intégrations** | Git, Docker, K8s, Cloud |

---

## 1. Prérequis Java

```bash
dnf install -y java-17-openjdk java-17-openjdk-devel
java -version

# Définir JAVA_HOME
echo 'export JAVA_HOME=/usr/lib/jvm/java-17-openjdk' >> /etc/profile.d/java.sh
source /etc/profile.d/java.sh
```

---

## 2. Installation Jenkins

### Repository officiel

```bash
wget -O /etc/yum.repos.d/jenkins.repo https://pkg.jenkins.io/redhat-stable/jenkins.repo
rpm --import https://pkg.jenkins.io/redhat-stable/jenkins.io-2023.key

dnf install -y jenkins
```

### Démarrer le service

```bash
systemctl enable --now jenkins
```

---

## 3. Firewall

```bash
firewall-cmd --permanent --add-port=8080/tcp
firewall-cmd --reload
```

---

## 4. Configuration initiale

### Récupérer le mot de passe admin

```bash
cat /var/lib/jenkins/secrets/initialAdminPassword
```

### Setup wizard

1. Ouvrir `http://IP:8080`
2. Entrer le mot de passe initial
3. Installer les plugins suggérés
4. Créer l'utilisateur admin
5. Configurer l'URL Jenkins

---

## 5. Configuration sécurité

### Désactiver l'inscription

Manage Jenkins → Security → Security Realm → Jenkins' own user database
- Décocher "Allow users to sign up"

### Autorisation

Manage Jenkins → Security → Authorization
- Matrix-based security ou Role-Based Strategy (plugin)

---

## 6. Installation Docker (optionnel)

```bash
dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
dnf install -y docker-ce docker-ce-cli containerd.io

systemctl enable --now docker
usermod -aG docker jenkins
systemctl restart jenkins
```

---

## 7. Premier Pipeline

### Créer un job Pipeline

1. New Item → Pipeline
2. Pipeline script:

```groovy
pipeline {
    agent any

    stages {
        stage('Checkout') {
            steps {
                git branch: 'main', url: 'https://github.com/user/repo.git'
            }
        }

        stage('Build') {
            steps {
                sh 'echo "Building..."'
                sh 'make build || echo "No Makefile"'
            }
        }

        stage('Test') {
            steps {
                sh 'echo "Testing..."'
                sh 'make test || echo "No tests"'
            }
        }

        stage('Deploy') {
            steps {
                sh 'echo "Deploying..."'
            }
        }
    }

    post {
        always {
            cleanWs()
        }
        success {
            echo 'Pipeline succeeded!'
        }
        failure {
            echo 'Pipeline failed!'
        }
    }
}
```

---

## 8. Jenkinsfile dans le repo

### Créer Jenkinsfile à la racine

```groovy
pipeline {
    agent any

    environment {
        DOCKER_IMAGE = 'myapp'
        DOCKER_TAG = "${BUILD_NUMBER}"
    }

    stages {
        stage('Build Docker') {
            steps {
                script {
                    docker.build("${DOCKER_IMAGE}:${DOCKER_TAG}")
                }
            }
        }

        stage('Push Registry') {
            steps {
                script {
                    docker.withRegistry('https://registry.example.com', 'registry-creds') {
                        docker.image("${DOCKER_IMAGE}:${DOCKER_TAG}").push()
                        docker.image("${DOCKER_IMAGE}:${DOCKER_TAG}").push('latest')
                    }
                }
            }
        }
    }
}
```

### Multibranch Pipeline

1. New Item → Multibranch Pipeline
2. Branch Sources → Git
3. Jenkinsfile path: `Jenkinsfile`

---

## 9. Agents (Nodes)

### Ajouter un agent SSH

Manage Jenkins → Nodes → New Node

```bash
# Sur l'agent
useradd -m jenkins
mkdir /home/jenkins/.ssh
# Ajouter la clé publique Jenkins
dnf install -y java-17-openjdk git docker-ce
usermod -aG docker jenkins
```

### Agent Docker

```groovy
pipeline {
    agent {
        docker {
            image 'node:18-alpine'
            args '-v /tmp:/tmp'
        }
    }
    stages {
        stage('Build') {
            steps {
                sh 'npm install'
                sh 'npm run build'
            }
        }
    }
}
```

---

## 10. Credentials

### Ajouter des credentials

Manage Jenkins → Credentials → System → Global credentials

Types disponibles :
- Username/Password
- SSH Username with private key
- Secret text
- Secret file
- Certificate

### Utiliser dans Pipeline

```groovy
pipeline {
    agent any
    stages {
        stage('Deploy') {
            steps {
                withCredentials([
                    usernamePassword(
                        credentialsId: 'deploy-creds',
                        usernameVariable: 'USER',
                        passwordVariable: 'PASS'
                    )
                ]) {
                    sh 'deploy.sh $USER $PASS'
                }
            }
        }
    }
}
```

---

## 11. Plugins essentiels

### Installation

Manage Jenkins → Plugins → Available plugins

Plugins recommandés :
- **Blue Ocean** : Interface moderne
- **Pipeline** : Pipelines as code
- **Git** : Intégration Git
- **Docker Pipeline** : Build Docker
- **Kubernetes** : Agents K8s
- **Slack Notification** : Alertes Slack
- **Role-based Authorization** : RBAC

---

## 12. Webhooks GitHub/GitLab

### GitHub

1. GitHub repo → Settings → Webhooks
2. Payload URL: `http://jenkins.example.com/github-webhook/`
3. Content type: `application/json`
4. Events: Push, Pull requests

### GitLab

1. GitLab project → Settings → Webhooks
2. URL: `http://jenkins.example.com/project/JOB_NAME`
3. Secret token: (généré dans Jenkins)
4. Triggers: Push, Merge request

---

## 13. Notifications

### Email

```groovy
post {
    failure {
        mail to: 'team@example.com',
             subject: "Failed: ${currentBuild.fullDisplayName}",
             body: "Build failed: ${env.BUILD_URL}"
    }
}
```

### Slack

```groovy
post {
    success {
        slackSend channel: '#builds',
                  color: 'good',
                  message: "Build succeeded: ${env.JOB_NAME} #${env.BUILD_NUMBER}"
    }
    failure {
        slackSend channel: '#builds',
                  color: 'danger',
                  message: "Build failed: ${env.JOB_NAME} #${env.BUILD_NUMBER}"
    }
}
```

---

## 14. Backup

```bash
# Script backup
cat > /opt/jenkins-backup.sh << 'EOF'
#!/bin/bash
BACKUP_DIR="/backup/jenkins"
JENKINS_HOME="/var/lib/jenkins"
DATE=$(date +%Y%m%d)

mkdir -p $BACKUP_DIR
tar -czf $BACKUP_DIR/jenkins-$DATE.tar.gz \
    --exclude='$JENKINS_HOME/workspace' \
    --exclude='$JENKINS_HOME/.cache' \
    $JENKINS_HOME

find $BACKUP_DIR -mtime +7 -delete
EOF

chmod +x /opt/jenkins-backup.sh

# Cron
echo "0 2 * * * root /opt/jenkins-backup.sh" >> /etc/crontab
```

---

## 15. Reverse Proxy Nginx

```bash
dnf install -y nginx

cat > /etc/nginx/conf.d/jenkins.conf << 'EOF'
upstream jenkins {
    server 127.0.0.1:8080 fail_timeout=0;
}

server {
    listen 80;
    server_name jenkins.example.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name jenkins.example.com;

    ssl_certificate /etc/letsencrypt/live/jenkins.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/jenkins.example.com/privkey.pem;

    location / {
        proxy_pass http://jenkins;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 90;
    }
}
EOF

# Configurer Jenkins URL
# /var/lib/jenkins/jenkins.model.JenkinsLocationConfiguration.xml
# <jenkinsUrl>https://jenkins.example.com/</jenkinsUrl>

systemctl enable --now nginx
```

---

## Commandes utiles

```bash
# Status
systemctl status jenkins

# Logs
journalctl -u jenkins -f
tail -f /var/log/jenkins/jenkins.log

# Redémarrer
systemctl restart jenkins

# CLI
java -jar /var/lib/jenkins/jenkins-cli.jar -s http://localhost:8080/ help
```

---

## Dépannage

```bash
# Réinitialiser admin
systemctl stop jenkins
rm /var/lib/jenkins/config.xml
sed -i 's/<useSecurity>true</<useSecurity>false</' /var/lib/jenkins/config.xml
systemctl start jenkins

# Mémoire
# /etc/sysconfig/jenkins
JENKINS_JAVA_OPTIONS="-Xmx2048m -Xms512m"

# Permissions
chown -R jenkins:jenkins /var/lib/jenkins
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
