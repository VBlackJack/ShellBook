# IT-Tools: The DevOps Swiss Army Knife

`#productivity` `#docker` `#tools` `#self-hosted` `#security`

Une suite d'outils web complète, auto-hébergée pour ne plus jamais coller de données sensibles sur des sites publics.

---

## Pourquoi IT-Tools ?

### Le Problème : Outils en Ligne Non Sécurisés

**Scénario classique :**

```
Dev  : "Je dois décoder ce JWT pour debug"
Dev  : *Ouvre jwt.io et colle le token*
Lead : "Tu viens d'envoyer un token de production sur Internet ?!"
Dev  : "Euh... oui"
Lead : "Regénère TOUS les tokens. Maintenant."
```

**Risques des outils publics :**
- **Fuite de données** : Tokens, clés privées, configs envoyées sur des serveurs tiers
- **Man-in-the-Middle** : Interception possible (HTTP non chiffré)
- **Logging** : Aucune garantie que les données ne soient pas stockées
- **Dépendance Internet** : Inutilisables en environnement air-gapped

### La Solution : Auto-Hébergement avec IT-Tools

```mermaid
flowchart LR
    A[Engineer] -->|1. Paste Sensitive Data| B[IT-Tools Local]
    B -->|2. Process Client-Side| C[JavaScript in Browser]
    C -->|3. Result| A
    B -.->|Never Leaves Network| D[Your Infrastructure]

    style B fill:#2ecc71
    style D fill:#3498db
```

**IT-Tools = 80+ outils dans un conteneur Docker**

!!! success "Bénéfices (SecNumCloud Compliant)"
    - **Privacy** : Toutes les opérations sont client-side (JavaScript)
    - **Security** : Données sensibles ne quittent jamais votre réseau
    - **Availability** : Fonctionne 100% hors ligne (air-gapped environments)
    - **Centralization** : Un seul onglet pour tous les outils du quotidien
    - **Performance** : Ultra-léger (~50Mo RAM, démarrage instantané)
    - **No Tracking** : Aucune télémétrie, analytics ou cookies

---

## Section 1 : Pourquoi l'Auto-Héberger ? (SecNumCloud Mindset)

### 1. Sécurité & Privacy

**Traitement Client-Side :**

Contrairement aux outils en ligne, IT-Tools exécute tout en JavaScript dans votre navigateur :

```
Données sensibles → Browser (IT-Tools UI) → JavaScript Processing → Résultat
                    ↓
              Jamais envoyé au serveur
```

**Exemples critiques :**
- **JWT Decoder** : Décode les tokens sans les envoyer sur Internet
- **Hash Calculator** : Hachage de mots de passe localement
- **Private Key Inspector** : Parse les clés SSH/TLS sans risque de fuite

### 2. Disponibilité (Air-Gapped Environments)

**Cas d'usage SecOps :**

```bash
# Datacenter isolé (pas d'accès Internet)
$ docker run -d -p 8080:80 corentinth/it-tools

# Tous les outils sont maintenant disponibles localement
# Pas besoin de connexion externe
```

**Industries concernées :**
- Finance (PCI-DSS compliance)
- Santé (HIPAA)
- Défense (Classified networks)
- Cloud souverain (SecNumCloud)

### 3. Centralisation : One Tool to Rule Them All

**Avant IT-Tools :**
```
Onglet 1 : jwt.io (JWT decode)
Onglet 2 : yamllint.com (YAML validation)
Onglet 3 : crontab.guru (Cron syntax)
Onglet 4 : subnet-calculator.com (CIDR)
Onglet 5 : base64decode.org (Base64)
... 20 onglets ouverts
```

**Avec IT-Tools :**
```
Onglet unique : http://localhost:8080
  → Search bar : "jwt" → JWT Decoder
  → Search bar : "yaml" → YAML to JSON
  → Search bar : "cron" → Crontab Generator
```

---

## Section 2 : Installation (Docker Compose)

### Méthode 1 : Docker Run (Quick Start)

```bash
# Lancement instantané
docker run -d \
  --name it-tools \
  --restart unless-stopped \
  -p 8080:80 \
  corentinth/it-tools:latest

# Accès immédiat
open http://localhost:8080  # macOS
xdg-open http://localhost:8080  # Linux
start http://localhost:8080  # Windows
```

### Méthode 2 : Docker Compose (Production)

**Fichier `docker-compose.yml` :**

```yaml
version: '3.8'

services:
  it-tools:
    image: corentinth/it-tools:latest
    container_name: it-tools
    restart: unless-stopped

    ports:
      - "8080:80"

    # Optionnel : Bind mount pour personnalisation
    # volumes:
    #   - ./custom-config.json:/app/config.json:ro

    # Ressources (très léger)
    deploy:
      resources:
        limits:
          memory: 128M
          cpus: '0.5'
        reservations:
          memory: 64M

    # Labels pour Traefik (si reverse proxy)
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.it-tools.rule=Host(`tools.internal.company.com`)"
      - "traefik.http.routers.it-tools.entrypoints=websecure"
      - "traefik.http.routers.it-tools.tls=true"

      # Basic Auth (si exposition interne)
      - "traefik.http.middlewares.it-tools-auth.basicauth.users=admin:$$apr1$$hash$$"
      - "traefik.http.routers.it-tools.middlewares=it-tools-auth"

networks:
  default:
    name: tools-network
```

**Déploiement :**

```bash
# Créer le répertoire
mkdir -p ~/docker/it-tools
cd ~/docker/it-tools

# Créer le fichier docker-compose.yml (voir ci-dessus)
nano docker-compose.yml

# Lancer le service
docker compose up -d

# Vérifier les logs
docker compose logs -f

# Tester l'accès
curl -I http://localhost:8080
```

### Méthode 3 : Avec Reverse Proxy (Traefik)

**Stack complète avec authentification :**

```yaml
version: '3.8'

services:
  traefik:
    image: traefik:v2.10
    container_name: traefik
    restart: unless-stopped
    command:
      - "--api.insecure=true"
      - "--providers.docker=true"
      - "--entrypoints.web.address=:80"
      - "--entrypoints.websecure.address=:443"
    ports:
      - "80:80"
      - "443:443"
      - "8081:8080"  # Dashboard Traefik
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./traefik/acme.json:/acme.json
    networks:
      - tools-network

  it-tools:
    image: corentinth/it-tools:latest
    container_name: it-tools
    restart: unless-stopped
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.it-tools.rule=Host(`tools.local`)"
      - "traefik.http.services.it-tools.loadbalancer.server.port=80"
    networks:
      - tools-network

networks:
  tools-network:
    driver: bridge
```

!!! warning "Sécurité : Ne PAS Exposer Publiquement"
    **IT-Tools ne possède pas d'authentification intégrée.**

    Si exposition nécessaire :
    - ✅ **Interne uniquement** : VPN, réseau privé
    - ✅ **Basic Auth** : Via Traefik, Nginx, Apache
    - ✅ **SSO** : Authelia, Keycloak, OAuth2 Proxy
    - ❌ **Internet public** : Risque d'abus (DDoS, data mining)

**Exemple Basic Auth avec Traefik :**

```bash
# Générer un hash bcrypt pour le mot de passe
htpasswd -nbB admin "SuperSecretPassword"
# Output: admin:$2y$05$hash...

# Ajouter dans docker-compose.yml labels:
- "traefik.http.middlewares.auth.basicauth.users=admin:$$2y$$05$$hash..."
- "traefik.http.routers.it-tools.middlewares=auth"
```

---

## Section 3 : Les "Killer Features" pour le SysOps

### Catégorie 1 : DevOps & Containers

#### 🔥 Docker Run ↔ Docker Compose Converter

!!! success "Outil le Plus Utile"
    **Gain de temps énorme : Convertir instantanément `docker run` en `docker-compose.yml`**

**Cas d'usage :**

```bash
# Documentation officielle fournit :
docker run -d \
  --name nginx \
  -p 80:80 \
  -v /data:/usr/share/nginx/html:ro \
  --restart unless-stopped \
  --memory 512m \
  -e NGINX_HOST=example.com \
  nginx:alpine

# IT-Tools génère automatiquement :
```

```yaml
version: '3.8'
services:
  nginx:
    image: nginx:alpine
    container_name: nginx
    restart: unless-stopped
    ports:
      - "80:80"
    volumes:
      - /data:/usr/share/nginx/html:ro
    environment:
      - NGINX_HOST=example.com
    deploy:
      resources:
        limits:
          memory: 512M
```

**Reverse :** Convertir `docker-compose.yml` en commande `docker run` pour debug.

#### YAML ↔ JSON Converter

**Scénario Kubernetes :**

```yaml
# Manifeste YAML
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
data:
  database_url: "postgres://db:5432"
```

**Converti en JSON pour traitement programmatique :**

```json
{
  "apiVersion": "v1",
  "kind": "ConfigMap",
  "metadata": {
    "name": "app-config"
  },
  "data": {
    "database_url": "postgres://db:5432"
  }
}
```

**Utilisation avec jq :**

```bash
# Pipeline de traitement
cat deployment.yaml | \
  # (Paste dans IT-Tools YAML→JSON) | \
  jq '.spec.replicas = 5' | \
  # (Paste dans IT-Tools JSON→YAML)
  kubectl apply -f -
```

#### JSON Viewer / Formatter

**Logs JSON difficiles à lire :**

```bash
# Output brut de kubectl
kubectl get pod -o json
# → 5000 lignes sur une seule ligne

# Coller dans IT-Tools JSON Viewer
# → Tree view avec collapse/expand
# → Syntax highlighting
# → Search dans le JSON
```

### Catégorie 2 : Réseau & Infrastructure

#### Calculateur CIDR (Subnet)

**Planification d'infrastructure AWS :**

```
Input : 10.0.0.0/16

Output :
├─ Network    : 10.0.0.0
├─ Netmask    : 255.255.0.0
├─ Broadcast  : 10.0.255.255
├─ Usable IPs : 10.0.0.1 - 10.0.255.254
├─ Total IPs  : 65,536
└─ Usable     : 65,534
```

**Découpage en subnets :**

```
VPC : 10.0.0.0/16

Subnets :
- Public  AZ-A : 10.0.0.0/24   (256 IPs)
- Public  AZ-B : 10.0.1.0/24   (256 IPs)
- Private AZ-A : 10.0.10.0/24  (256 IPs)
- Private AZ-B : 10.0.11.0/24  (256 IPs)
- RDS     AZ-A : 10.0.20.0/24  (256 IPs)
- RDS     AZ-B : 10.0.21.0/24  (256 IPs)
```

#### IPv4 ↔ IPv6 Converter

**Migration dual-stack :**

```
IPv4 : 192.168.1.100
IPv6 : ::ffff:192.168.1.100  (IPv4-mapped IPv6)

IPv6 : 2001:0db8:85a3:0000:0000:8a2e:0370:7334
Compressed : 2001:db8:85a3::8a2e:370:7334
```

### Catégorie 3 : Système & Scripting

#### Générateur / Validateur Crontab

**Interface visuelle pour cron :**

```
Selector:
- Minute   : */15  (Every 15 minutes)
- Hour     : 2     (At 2am)
- Day      : *     (Every day)
- Month    : *     (Every month)
- Weekday  : 1-5   (Monday to Friday)

Output :
*/15 2 * * 1-5 /usr/local/bin/backup.sh

Next runs:
- 2024-01-22 02:00:00 (Monday)
- 2024-01-22 02:15:00 (Monday)
- 2024-01-22 02:30:00 (Monday)
```

**Évite les erreurs classiques :**

```bash
# ❌ Erreur fréquente (s'exécute TOUTES les minutes de 2h à 3h)
0-59 2 * * * script.sh

# ✅ Correct (s'exécute UNE FOIS à 2h)
0 2 * * * script.sh
```

#### Chmod Calculator

**Permissions visuelles :**

```
User  : [✓] Read  [✓] Write  [✓] Execute  = 7
Group : [✓] Read  [✓] Write  [ ] Execute  = 6
Other : [✓] Read  [ ] Write  [ ] Execute  = 4

Command : chmod 764 file.sh

Symbolic : chmod u=rwx,g=rw,o=r file.sh
```

### Catégorie 4 : Sécurité & Cryptographie

#### Token Generator

**Générer des secrets sécurisés :**

```bash
# API Token (32 bytes, base64)
dGhpc2lzYXNlY3VyZXRva2VuZm9yYXBpYWNjZXNz

# Random Password (20 chars, symbols)
K#9mP$vL2@xQ8nR!7wT6

# UUID v4
550e8400-e29b-41d4-a716-446655440000

# Hex String (64 chars)
a3f5d9c1e8b2f7a4d6c9e1b8f3a5d2c7e9b4f6a1d3c8e5b7f9a2d4c6e8b1f3a5
```

**Usage :**

```bash
# Générer un token pour .env
API_SECRET=$(generate_token_via_it_tools)
echo "API_SECRET=$API_SECRET" >> .env
```

#### Hash Calculator

**Calculer des hashes sans envoyer sur Internet :**

```
Input : MySecretPassword

Algorithms:
├─ MD5     : 5f4dcc3b5aa765d61d8327deb882cf99
├─ SHA1    : 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8
├─ SHA256  : 2c6ee24b09816a6f14f95d1698b24ead...
├─ SHA512  : e9b8c9b2f5d6a3c1e8b7f4a9d2c5e8b1...
└─ bcrypt  : $2a$10$N9qo8uLOickgx2ZMRZoMye...
```

**Vérifier l'intégrité d'un fichier :**

```bash
# Télécharger un ISO
wget https://releases.ubuntu.com/22.04/ubuntu-22.04.3-live-server-amd64.iso

# Hash fourni par Ubuntu
sha256sum ubuntu-22.04.3-live-server-amd64.iso
# → Copier le hash dans IT-Tools pour comparaison visuelle
```

#### JWT Debugger

**Décoder un token sans l'envoyer sur jwt.io :**

```
Token : eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c

Decoded Header:
{
  "alg": "HS256",
  "typ": "JWT"
}

Decoded Payload:
{
  "sub": "1234567890",
  "name": "John Doe",
  "iat": 1516239022
}

Expiration: 2018-01-18 01:30:22 (EXPIRED)
```

**Validation de signature (local) :**

```
Secret : your-256-bit-secret
Signature Valid : ✅
```

### Catégorie 5 : Encodage & Formatage

#### Base64 Encoder / Decoder

**Kubernetes Secrets :**

```bash
# Encoder un secret
echo -n "my-database-password" | base64
# → bXktZGF0YWJhc2UtcGFzc3dvcmQ=

# Créer le secret K8s
kubectl create secret generic db-password \
  --from-literal=password=bXktZGF0YWJhc2UtcGFzc3dvcmQ=

# Décoder pour vérifier
echo "bXktZGF0YWJhc2UtcGFzc3dvcmQ=" | base64 -d
# → my-database-password
```

#### URL Encoder / Decoder

**Query parameters :**

```
Original : https://api.com/search?q=Hello World&filter=name:John Doe

Encoded  : https://api.com/search?q=Hello%20World&filter=name%3AJohn%20Doe
```

#### XML Formatter

**Formater des réponses SOAP :**

```xml
<!-- Input : une ligne illisible -->
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><GetUserResponse><User><ID>123</ID><Name>John</Name></User></GetUserResponse></soap:Body></soap:Envelope>

<!-- Output formaté : -->
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetUserResponse>
      <User>
        <ID>123</ID>
        <Name>John</Name>
      </User>
    </GetUserResponse>
  </soap:Body>
</soap:Envelope>
```

### Catégorie 6 : Autres Outils Utiles

| Outil | Usage SysOps |
|-------|--------------|
| **Case Converter** | `snake_case` ↔ `camelCase` ↔ `kebab-case` (variables) |
| **Lorem Ipsum Generator** | Générer du texte de test pour UI |
| **QR Code Generator** | Partager des URLs/configs (TOTP, WiFi) |
| **Color Converter** | HEX ↔ RGB ↔ HSL (dashboards Grafana) |
| **Temperature Converter** | Celsius ↔ Fahrenheit (monitoring hardware) |
| **Date Converter** | Unix timestamp ↔ ISO 8601 (logs analysis) |
| **Roman Numeral Converter** | Parce que pourquoi pas ? 😄 |

---

## Section 4 : Intégration Workflow

### 1. Windows Terminal (Web Tab)

**Ajouter IT-Tools comme onglet permanent :**

```json
// settings.json de Windows Terminal
{
  "profiles": {
    "list": [
      {
        "name": "IT-Tools",
        "commandline": "wt.exe",
        "startingDirectory": null,
        "tabTitle": "🔧 IT-Tools",
        "suppressApplicationTitle": true,
        "icon": "🛠️",

        // Ouvrir dans le navigateur par défaut
        "commandline": "cmd.exe /c start http://localhost:8080",
        "closeOnExit": "never"
      }
    ]
  }
}
```

**Raccourci clavier :**

```json
{
  "actions": [
    {
      "command": {
        "action": "newTab",
        "profile": "IT-Tools"
      },
      "keys": "ctrl+shift+t"
    }
  ]
}
```

### 2. Favori de Barre Personnelle (Browser)

**Chrome / Edge / Firefox :**

```
1. Accéder à http://localhost:8080
2. Bookmarks → Add Bookmark
3. Name : 🔧 IT-Tools
4. Folder : Bookmarks Bar
5. Keyboard Shortcut : Ctrl+Shift+I (Chrome extensions)
```

**Organisation recommandée :**

```
Bookmarks Bar/
├─ 🔧 IT-Tools (http://localhost:8080)
├─ 📊 Grafana (http://monitoring.local)
├─ 🐳 Portainer (http://docker.local)
└─ 📖 ShellBook (http://docs.local)
```

### 3. Alfred / Raycast (macOS)

**Workflow Alfred :**

```bash
# Créer un Web Search
Keyword : tools
URL     : http://localhost:8080/?search={query}

Usage :
  tools jwt → Ouvre directement JWT Decoder
  tools yaml → Ouvre YAML to JSON
```

### 4. KRunner (KDE Plasma)

```bash
# Ajouter un Web Shortcut
Settings → Search → Web Shortcuts

Name    : IT-Tools
Keyword : tools
URL     : http://localhost:8080/?search=\{@}
```

### 5. Script de Lancement Rapide

**Linux / macOS :**

```bash
#!/bin/bash
# ~/.local/bin/tools

# Vérifier si IT-Tools est lancé
if ! docker ps | grep -q it-tools; then
  echo "Starting IT-Tools..."
  docker start it-tools 2>/dev/null || \
    docker run -d --name it-tools -p 8080:80 corentinth/it-tools
  sleep 2
fi

# Ouvrir dans le navigateur
xdg-open http://localhost:8080  # Linux
# open http://localhost:8080    # macOS

echo "IT-Tools ready at http://localhost:8080"
```

**Windows (PowerShell) :**

```powershell
# ~\Documents\PowerShell\Scripts\tools.ps1

# Vérifier si IT-Tools est lancé
$running = docker ps --filter "name=it-tools" --format "{{.Names}}"

if (-not $running) {
  Write-Host "Starting IT-Tools..."
  docker start it-tools 2>$null
  if ($LASTEXITCODE -ne 0) {
    docker run -d --name it-tools -p 8080:80 corentinth/it-tools
  }
  Start-Sleep -Seconds 2
}

# Ouvrir dans le navigateur
Start-Process "http://localhost:8080"

Write-Host "IT-Tools ready at http://localhost:8080" -ForegroundColor Green
```

**Alias dans profile :**

```bash
# ~/.bashrc ou ~/.zshrc
alias tools='~/local/bin/tools'

# PowerShell Profile
Set-Alias tools ~\Documents\PowerShell\Scripts\tools.ps1
```

---

## Quick Reference

### Installation Rapide

```bash
# Docker Run (Instant)
docker run -d --name it-tools --restart unless-stopped -p 8080:80 corentinth/it-tools

# Docker Compose
cat > docker-compose.yml <<EOF
version: '3.8'
services:
  it-tools:
    image: corentinth/it-tools:latest
    container_name: it-tools
    restart: unless-stopped
    ports:
      - "8080:80"
    deploy:
      resources:
        limits:
          memory: 128M
EOF

docker compose up -d

# Accès
open http://localhost:8080
```

### Commandes Essentielles

```bash
# Démarrer IT-Tools
docker start it-tools

# Arrêter IT-Tools
docker stop it-tools

# Voir les logs
docker logs -f it-tools

# Mettre à jour vers la dernière version
docker pull corentinth/it-tools:latest
docker stop it-tools
docker rm it-tools
docker run -d --name it-tools --restart unless-stopped -p 8080:80 corentinth/it-tools

# Vérifier la consommation de ressources
docker stats it-tools
```

### Outils les Plus Utilisés

| Catégorie | Outil | Recherche |
|-----------|-------|-----------|
| **DevOps** | Docker Run → Compose | `docker` |
| **Format** | YAML ↔ JSON | `yaml` |
| **Format** | JSON Viewer | `json` |
| **Réseau** | CIDR Calculator | `cidr` ou `subnet` |
| **Système** | Crontab Generator | `cron` |
| **Système** | Chmod Calculator | `chmod` |
| **Sécurité** | JWT Decoder | `jwt` |
| **Sécurité** | Hash Calculator | `hash` |
| **Sécurité** | Token Generator | `token` |
| **Encodage** | Base64 Encoder | `base64` |
| **Encodage** | URL Encoder | `url` |

### Troubleshooting

| Problème | Solution |
|----------|----------|
| Port 8080 déjà utilisé | `docker run -p 8888:80 corentinth/it-tools` |
| Conteneur ne démarre pas | `docker logs it-tools` |
| Mise à jour non prise en compte | `docker pull corentinth/it-tools && docker restart it-tools` |
| Erreur "Cannot connect" | Vérifier que le conteneur est running : `docker ps` |

---

## Ressources

**Projet Officiel :**
- [GitHub : CorentinTh/it-tools](https://github.com/CorentinTh/it-tools)
- [Documentation](https://it-tools.tech/)

**Alternatives :**
- [CyberChef](https://gchq.github.io/CyberChef/) : Plus orienté forensics/CTF
- [DevToys](https://devtoys.app/) : Application Windows native
- [DevUtils](https://devutils.com/) : Application macOS native (payant)

**Intégrations :**
- Déployer sur Kubernetes avec Helm
- Intégrer dans une stack Homelab (Traefik, Portainer)
- Utiliser comme sidecar dans des pods de debug

---

**Next Steps :**
- Explorer tous les outils disponibles (80+)
- Créer des bookmarks pour les outils les plus utilisés
- Intégrer dans votre workflow quotidien (raccourcis clavier)
- Partager l'instance avec votre équipe (avec authentification !)
