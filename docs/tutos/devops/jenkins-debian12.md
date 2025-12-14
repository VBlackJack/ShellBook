---
tags:
  - tutos
  - devops
  - jenkins
  - ci-cd
  - automation
  - debian
---

# Jenkins sur Debian 12

Installation de **Jenkins** sur Debian 12 Bookworm.

| Composant | Version |
|-----------|---------|
| Debian | 12 Bookworm |
| Jenkins | LTS |
| Java | 17 |

**Durée estimée :** 25 minutes

---

## 1. Prérequis Java

```bash
apt update
apt install -y openjdk-17-jdk
java -version
```

---

## 2. Installation Jenkins

```bash
curl -fsSL https://pkg.jenkins.io/debian-stable/jenkins.io-2023.key | tee /usr/share/keyrings/jenkins-keyring.asc > /dev/null

echo "deb [signed-by=/usr/share/keyrings/jenkins-keyring.asc] https://pkg.jenkins.io/debian-stable binary/" > /etc/apt/sources.list.d/jenkins.list

apt update
apt install -y jenkins
systemctl enable --now jenkins
```

---

## 3. Firewall

```bash
ufw allow 8080/tcp
ufw reload
```

---

## 4. Configuration initiale

```bash
# Mot de passe admin
cat /var/lib/jenkins/secrets/initialAdminPassword
```

1. Ouvrir `http://IP:8080`
2. Entrer le mot de passe
3. Installer plugins suggérés
4. Créer admin

---

## 5. Docker (optionnel)

```bash
apt install -y ca-certificates curl gnupg
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" > /etc/apt/sources.list.d/docker.list
apt update
apt install -y docker-ce docker-ce-cli containerd.io

usermod -aG docker jenkins
systemctl restart jenkins
```

---

## 6. Pipeline exemple

```groovy
pipeline {
    agent any

    stages {
        stage('Build') {
            steps {
                sh 'echo "Building..."'
            }
        }
        stage('Test') {
            steps {
                sh 'echo "Testing..."'
            }
        }
        stage('Deploy') {
            steps {
                sh 'echo "Deploying..."'
            }
        }
    }

    post {
        always { cleanWs() }
    }
}
```

---

## 7. Pipeline Docker

```groovy
pipeline {
    agent {
        docker { image 'node:18-alpine' }
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

## 8. Credentials

```groovy
withCredentials([
    usernamePassword(
        credentialsId: 'my-creds',
        usernameVariable: 'USER',
        passwordVariable: 'PASS'
    )
]) {
    sh 'deploy.sh $USER $PASS'
}
```

---

## 9. Notifications

```groovy
post {
    failure {
        mail to: 'team@example.com',
             subject: "Failed: ${currentBuild.fullDisplayName}",
             body: "Build failed: ${env.BUILD_URL}"
    }
}
```

---

## Comparatif Rocky vs Debian

| Aspect | Rocky 9 | Debian 12 |
|--------|---------|-----------|
| Java | java-17-openjdk | openjdk-17-jdk |
| Repo key | rpm --import | apt keyrings |
| Firewall | firewalld | ufw |

---

## Commandes

```bash
# Status
systemctl status jenkins

# Logs
journalctl -u jenkins -f

# Mot de passe initial
cat /var/lib/jenkins/secrets/initialAdminPassword

# Redémarrer
systemctl restart jenkins
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
