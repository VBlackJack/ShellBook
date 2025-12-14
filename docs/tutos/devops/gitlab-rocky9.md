---
tags:
  - tutos
  - devops
  - gitlab
  - git
  - ci-cd
  - rocky
---

# GitLab CE sur Rocky Linux 9

Installation de **GitLab Community Edition** - plateforme DevOps complète.

| Composant | Version |
|-----------|---------|
| Rocky Linux | 9.x |
| GitLab CE | 16+ |

**Durée estimée :** 40 minutes

---

## Fonctionnalités

| Fonction | Description |
|----------|-------------|
| **Git** | Hébergement de repos |
| **CI/CD** | Pipelines intégrés |
| **Registry** | Container Registry |
| **Wiki** | Documentation |
| **Issues** | Gestion de projet |

---

## Prérequis

- 4 CPU minimum
- 8 GB RAM minimum (16 GB recommandé)
- 50 GB disque

---

## 1. Dépendances

```bash
dnf install -y curl policycoreutils openssh-server perl postfix

systemctl enable --now sshd
systemctl enable --now postfix
```

---

## 2. Installation GitLab

### Repository officiel

```bash
curl -sS https://packages.gitlab.com/install/repositories/gitlab/gitlab-ce/script.rpm.sh | bash
```

### Installer avec URL externe

```bash
EXTERNAL_URL="https://gitlab.example.com" dnf install -y gitlab-ce
```

Ou installer puis configurer :

```bash
dnf install -y gitlab-ce
```

---

## 3. Configuration

```bash
vim /etc/gitlab/gitlab.rb
```

```ruby
# URL externe
external_url 'https://gitlab.example.com'

# Email
gitlab_rails['smtp_enable'] = true
gitlab_rails['smtp_address'] = "smtp.example.com"
gitlab_rails['smtp_port'] = 587
gitlab_rails['smtp_user_name'] = "gitlab@example.com"
gitlab_rails['smtp_password'] = "password"
gitlab_rails['smtp_domain'] = "example.com"
gitlab_rails['smtp_authentication'] = "login"
gitlab_rails['smtp_enable_starttls_auto'] = true
gitlab_rails['gitlab_email_from'] = 'gitlab@example.com'

# Timezone
gitlab_rails['time_zone'] = 'Europe/Paris'

# Backup
gitlab_rails['backup_keep_time'] = 604800

# LDAP (optionnel)
# gitlab_rails['ldap_enabled'] = true
```

### Appliquer la configuration

```bash
gitlab-ctl reconfigure
```

---

## 4. Firewall

```bash
firewall-cmd --permanent --add-service=http
firewall-cmd --permanent --add-service=https
firewall-cmd --permanent --add-service=ssh
firewall-cmd --reload
```

---

## 5. Premier accès

### Mot de passe root initial

```bash
cat /etc/gitlab/initial_root_password
```

Ce fichier est supprimé automatiquement après 24h.

### Connexion

1. Ouvrir `https://gitlab.example.com`
2. User: `root`
3. Password: (du fichier ci-dessus)
4. Changer le mot de passe immédiatement

---

## 6. Let's Encrypt automatique

```ruby
# /etc/gitlab/gitlab.rb
external_url 'https://gitlab.example.com'
letsencrypt['enable'] = true
letsencrypt['contact_emails'] = ['admin@example.com']
letsencrypt['auto_renew'] = true
letsencrypt['auto_renew_hour'] = 2
letsencrypt['auto_renew_minute'] = 30
```

```bash
gitlab-ctl reconfigure
```

---

## 7. GitLab Runner

### Installation

```bash
curl -L "https://packages.gitlab.com/install/repositories/runner/gitlab-runner/script.rpm.sh" | bash
dnf install -y gitlab-runner
```

### Enregistrer le runner

```bash
gitlab-runner register
```

Répondre aux questions :
- URL GitLab
- Token (Admin → CI/CD → Runners)
- Description
- Tags
- Executor (shell, docker, kubernetes...)

### Runner Docker

```bash
gitlab-runner register \
  --non-interactive \
  --url "https://gitlab.example.com/" \
  --registration-token "PROJECT_TOKEN" \
  --executor "docker" \
  --docker-image alpine:latest \
  --description "docker-runner" \
  --tag-list "docker,linux"
```

---

## 8. Pipeline CI/CD

### .gitlab-ci.yml basique

```yaml
stages:
  - build
  - test
  - deploy

variables:
  APP_NAME: "myapp"

build:
  stage: build
  script:
    - echo "Building $APP_NAME..."
    - make build
  artifacts:
    paths:
      - build/

test:
  stage: test
  script:
    - echo "Testing..."
    - make test
  dependencies:
    - build

deploy:
  stage: deploy
  script:
    - echo "Deploying..."
    - ./deploy.sh
  only:
    - main
  environment:
    name: production
    url: https://app.example.com
```

### Pipeline Docker

```yaml
stages:
  - build
  - push
  - deploy

variables:
  DOCKER_IMAGE: $CI_REGISTRY_IMAGE
  DOCKER_TAG: $CI_COMMIT_SHA

build:
  stage: build
  image: docker:24
  services:
    - docker:24-dind
  script:
    - docker build -t $DOCKER_IMAGE:$DOCKER_TAG .
    - docker tag $DOCKER_IMAGE:$DOCKER_TAG $DOCKER_IMAGE:latest

push:
  stage: push
  image: docker:24
  services:
    - docker:24-dind
  before_script:
    - docker login -u $CI_REGISTRY_USER -p $CI_REGISTRY_PASSWORD $CI_REGISTRY
  script:
    - docker push $DOCKER_IMAGE:$DOCKER_TAG
    - docker push $DOCKER_IMAGE:latest
  only:
    - main

deploy:
  stage: deploy
  script:
    - kubectl set image deployment/myapp app=$DOCKER_IMAGE:$DOCKER_TAG
  environment:
    name: production
```

---

## 9. Container Registry

### Activer le registry

```ruby
# /etc/gitlab/gitlab.rb
registry_external_url 'https://registry.gitlab.example.com'
```

```bash
gitlab-ctl reconfigure
```

### Utiliser le registry

```bash
# Login
docker login registry.gitlab.example.com

# Push
docker tag myimage registry.gitlab.example.com/group/project/myimage:tag
docker push registry.gitlab.example.com/group/project/myimage:tag
```

---

## 10. Backup et Restore

### Backup manuel

```bash
gitlab-backup create
```

Les backups sont dans `/var/opt/gitlab/backups/`

### Backup automatique

```bash
# Cron
echo "0 2 * * * gitlab-backup create CRON=1" >> /etc/crontab
```

### Restore

```bash
# Arrêter les services
gitlab-ctl stop puma
gitlab-ctl stop sidekiq

# Restore (timestamp du backup)
gitlab-backup restore BACKUP=1702555200_2024_12_14_16.5.0

# Redémarrer
gitlab-ctl start
gitlab-ctl reconfigure
```

---

## 11. Monitoring intégré

### Prometheus et Grafana

```ruby
# /etc/gitlab/gitlab.rb
prometheus_monitoring['enable'] = true
grafana['enable'] = true
grafana['admin_password'] = 'secure_password'
```

```bash
gitlab-ctl reconfigure
```

Accès Grafana : `https://gitlab.example.com/-/grafana`

---

## 12. Intégration LDAP

```ruby
# /etc/gitlab/gitlab.rb
gitlab_rails['ldap_enabled'] = true
gitlab_rails['ldap_servers'] = {
  'main' => {
    'label' => 'LDAP',
    'host' =>  'ldap.example.com',
    'port' => 636,
    'uid' => 'sAMAccountName',
    'encryption' => 'simple_tls',
    'bind_dn' => 'CN=gitlab,OU=Service,DC=example,DC=com',
    'password' => 'password',
    'active_directory' => true,
    'base' => 'OU=Users,DC=example,DC=com',
    'user_filter' => '(memberOf=CN=GitLabUsers,OU=Groups,DC=example,DC=com)'
  }
}
```

```bash
gitlab-ctl reconfigure
gitlab-rake gitlab:ldap:check
```

---

## 13. Performances

### Puma workers

```ruby
# /etc/gitlab/gitlab.rb
puma['worker_processes'] = 4
puma['min_threads'] = 4
puma['max_threads'] = 4
```

### PostgreSQL

```ruby
postgresql['shared_buffers'] = "2GB"
postgresql['work_mem'] = "128MB"
```

### Redis

```ruby
redis['maxmemory'] = "2gb"
redis['maxmemory_policy'] = "allkeys-lru"
```

---

## Commandes utiles

```bash
# Status
gitlab-ctl status

# Logs
gitlab-ctl tail

# Reconfigurer
gitlab-ctl reconfigure

# Redémarrer
gitlab-ctl restart

# Console Rails
gitlab-rails console

# Vérifier la config
gitlab-rake gitlab:check SANITIZE=true

# Espace disque
gitlab-rake gitlab:cleanup:repos
gitlab-rake gitlab:cleanup:registry
```

---

## Dépannage

```bash
# Erreur 502
gitlab-ctl restart puma
gitlab-ctl restart sidekiq

# Vérifier les services
gitlab-ctl status

# Logs spécifiques
gitlab-ctl tail nginx
gitlab-ctl tail puma
gitlab-ctl tail sidekiq

# Réinitialiser root password
gitlab-rake "gitlab:password:reset[root]"
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
