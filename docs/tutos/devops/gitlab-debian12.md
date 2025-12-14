---
tags:
  - tutos
  - devops
  - gitlab
  - git
  - ci-cd
  - debian
---

# GitLab CE sur Debian 12

Installation de **GitLab CE** sur Debian 12 Bookworm.

| Composant | Version |
|-----------|---------|
| Debian | 12 Bookworm |
| GitLab CE | 16+ |

**Durée estimée :** 35 minutes

---

## Prérequis

- 4 CPU, 8 GB RAM minimum
- 50 GB disque

---

## 1. Dépendances

```bash
apt update
apt install -y curl openssh-server ca-certificates perl postfix

systemctl enable --now ssh postfix
```

---

## 2. Installation

```bash
curl -sS https://packages.gitlab.com/install/repositories/gitlab/gitlab-ce/script.deb.sh | bash

EXTERNAL_URL="https://gitlab.example.com" apt install -y gitlab-ce
```

---

## 3. Configuration

```bash
vim /etc/gitlab/gitlab.rb
```

```ruby
external_url 'https://gitlab.example.com'

# Email
gitlab_rails['smtp_enable'] = true
gitlab_rails['smtp_address'] = "smtp.example.com"
gitlab_rails['smtp_port'] = 587

# Timezone
gitlab_rails['time_zone'] = 'Europe/Paris'

# Let's Encrypt
letsencrypt['enable'] = true
letsencrypt['contact_emails'] = ['admin@example.com']
```

```bash
gitlab-ctl reconfigure
```

---

## 4. Firewall

```bash
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 22/tcp
ufw reload
```

---

## 5. Premier accès

```bash
# Mot de passe root
cat /etc/gitlab/initial_root_password
```

1. Ouvrir `https://gitlab.example.com`
2. User: `root` + mot de passe

---

## 6. GitLab Runner

```bash
curl -L "https://packages.gitlab.com/install/repositories/runner/gitlab-runner/script.deb.sh" | bash
apt install -y gitlab-runner

gitlab-runner register
```

---

## 7. Pipeline basique

```yaml
# .gitlab-ci.yml
stages:
  - build
  - test
  - deploy

build:
  stage: build
  script:
    - echo "Building..."

test:
  stage: test
  script:
    - echo "Testing..."

deploy:
  stage: deploy
  script:
    - echo "Deploying..."
  only:
    - main
```

---

## 8. Container Registry

```ruby
# /etc/gitlab/gitlab.rb
registry_external_url 'https://registry.gitlab.example.com'
```

```bash
gitlab-ctl reconfigure
```

---

## 9. Backup

```bash
# Backup
gitlab-backup create

# Cron automatique
echo "0 2 * * * gitlab-backup create CRON=1" >> /etc/crontab
```

---

## Comparatif Rocky vs Debian

| Aspect | Rocky 9 | Debian 12 |
|--------|---------|-----------|
| Script install | script.rpm.sh | script.deb.sh |
| Firewall | firewalld | ufw |
| Package | dnf | apt |

---

## Commandes

```bash
# Status
gitlab-ctl status

# Logs
gitlab-ctl tail

# Reconfigure
gitlab-ctl reconfigure

# Reset root password
gitlab-rake "gitlab:password:reset[root]"

# Vérifications
gitlab-rake gitlab:check
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
