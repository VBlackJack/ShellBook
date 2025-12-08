---
tags:
  - formation
  - docker
  - security
---

# Module 6 : Sécurité Docker

## Objectifs du Module

- Exécuter des containers en non-root
- Gérer les capabilities Linux
- Scanner les images pour vulnérabilités
- Gérer les secrets

**Durée :** 2 heures

---

## 1. User Non-Root

```dockerfile
# Dockerfile
FROM node:20-alpine

# Créer un utilisateur
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

WORKDIR /app
COPY --chown=appuser:appgroup . .

# Utiliser l'utilisateur non-root
USER appuser

CMD ["node", "app.js"]
```

```bash
# Ou au runtime
docker run --user 1000:1000 nginx
docker run --user nobody nginx
```

---

## 2. Capabilities

```bash
# Supprimer toutes les capabilities
docker run --cap-drop=ALL nginx

# Ajouter seulement ce qui est nécessaire
docker run --cap-drop=ALL --cap-add=NET_BIND_SERVICE nginx

# Lister les capabilities par défaut
docker run --rm alpine cat /proc/self/status | grep Cap
```

---

## 3. Read-Only et Security Options

```bash
# Filesystem read-only
docker run --read-only nginx

# Avec tmpfs pour /tmp
docker run --read-only --tmpfs /tmp:rw,noexec,nosuid nginx

# No new privileges
docker run --security-opt=no-new-privileges nginx

# Seccomp profile
docker run --security-opt seccomp=profile.json nginx
```

---

## 4. Scanning d'Images

```bash
# Docker Scout (intégré)
docker scout cves nginx:latest
docker scout quickview nginx:latest

# Trivy (recommandé)
trivy image nginx:latest
trivy image --severity HIGH,CRITICAL myapp:v1

# Grype
grype nginx:latest
```

---

## 5. Secrets

```yaml
# docker-compose.yml
services:
  api:
    image: myapi
    secrets:
      - db_password
      - api_key
    environment:
      DB_PASSWORD_FILE: /run/secrets/db_password

secrets:
  db_password:
    file: ./secrets/db_password.txt
  api_key:
    external: true  # Créé avec docker secret create
```

```bash
# Créer un secret (Swarm mode)
echo "mysecret" | docker secret create db_password -

# Lister
docker secret ls
```

---

## 6. Bonnes Pratiques

```dockerfile
# Dockerfile sécurisé
FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production

FROM node:20-alpine
# User non-root
RUN addgroup -S app && adduser -S app -G app

WORKDIR /app
COPY --from=builder --chown=app:app /app/node_modules ./node_modules
COPY --chown=app:app . .

USER app
EXPOSE 3000

# Healthcheck
HEALTHCHECK --interval=30s --timeout=3s \
  CMD wget --no-verbose --tries=1 --spider http://localhost:3000/health || exit 1

CMD ["node", "app.js"]
```

```yaml
# docker-compose.yml sécurisé
services:
  api:
    image: myapi
    read_only: true
    tmpfs:
      - /tmp
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
    user: "1000:1000"
```

---

## Exercice : À Vous de Jouer

!!! example "Mise en Pratique"
    **Objectif** : Sécuriser une application Docker en appliquant les meilleures pratiques de sécurité

    **Contexte** : Vous devez déployer une application web sensible qui nécessite un niveau de sécurité élevé. Vous allez transformer un déploiement Docker non sécurisé en un déploiement respectant toutes les bonnes pratiques de sécurité : utilisateur non-root, capabilities limitées, filesystem read-only, scanning de vulnérabilités, et gestion des secrets.

    **Tâches à réaliser** :

    1. Créer un Dockerfile sécurisé avec utilisateur non-root pour une application Node.js
    2. Scanner l'image pour détecter les vulnérabilités (avec Trivy ou Docker Scout)
    3. Déployer le container avec capabilities minimales et filesystem read-only
    4. Configurer Docker Compose avec toutes les options de sécurité
    5. Gérer les secrets sans les exposer dans les variables d'environnement
    6. Vérifier que le container ne peut pas obtenir de privilèges root
    7. Comparer les niveaux de sécurité avant/après optimisation

    **Critères de validation** :

    - [ ] Le container s'exécute avec un utilisateur non-root (UID != 0)
    - [ ] Le filesystem est en lecture seule (sauf /tmp)
    - [ ] Aucune capability dangereuse n'est active
    - [ ] Les secrets ne sont pas dans les variables d'environnement
    - [ ] Le scan de sécurité ne montre pas de vulnérabilités critiques
    - [ ] Le container ne peut pas escalader ses privilèges
    - [ ] Les logs montrent toutes les restrictions de sécurité actives

??? quote "Solution"
    **Étape 1 : Application de test**

    ```javascript
    // app.js
    const http = require('http');
    const fs = require('fs');

    const server = http.createServer((req, res) => {
        if (req.url === '/health') {
            res.writeHead(200);
            res.end(JSON.stringify({
                status: 'healthy',
                user: process.getuid(),
                pid: process.pid
            }));
        } else if (req.url === '/whoami') {
            const os = require('os');
            res.writeHead(200);
            res.end(JSON.stringify({
                user: os.userInfo(),
                hostname: os.hostname(),
                platform: os.platform()
            }));
        } else if (req.url === '/secret') {
            // Lire le secret depuis un fichier (pas env var)
            try {
                const secret = fs.readFileSync('/run/secrets/api_key', 'utf8');
                res.writeHead(200);
                res.end(JSON.stringify({ secret: secret.trim() }));
            } catch (err) {
                res.writeHead(500);
                res.end(JSON.stringify({ error: 'Secret not found' }));
            }
        } else {
            res.writeHead(200);
            res.end('Secure Docker App\n');
        }
    });

    server.listen(3000, () => {
        console.log('Server listening on port 3000');
    });
    ```

    **Étape 2 : Dockerfile NON sécurisé (baseline)**

    ```dockerfile
    # Dockerfile.insecure
    FROM node:20
    WORKDIR /app
    COPY app.js .
    EXPOSE 3000
    CMD ["node", "app.js"]
    ```

    ```bash
    # Build et test
    docker build -f Dockerfile.insecure -t myapp:insecure .
    docker run -d --name insecure -p 3000:3000 myapp:insecure

    # Vérifier l'utilisateur (problème!)
    docker exec insecure whoami
    # Affiche: root ❌

    # Vérifier les capabilities
    docker exec insecure cat /proc/1/status | grep Cap
    # Nombreuses capabilities actives ❌

    docker stop insecure && docker rm insecure
    ```

    **Étape 3 : Dockerfile SÉCURISÉ**

    ```dockerfile
    # Dockerfile
    # Utiliser une image slim ou alpine
    FROM node:20-alpine

    # Créer un utilisateur non-root dédié
    RUN addgroup -g 1001 -S appgroup && \
        adduser -u 1001 -S appuser -G appgroup

    # Définir le répertoire de travail
    WORKDIR /app

    # Copier l'application avec les bons ownership
    COPY --chown=appuser:appgroup app.js .

    # Créer un répertoire temporaire writable
    RUN mkdir -p /app/tmp && \
        chown -R appuser:appgroup /app/tmp

    # Basculer vers l'utilisateur non-root
    USER appuser

    # Exposer le port
    EXPOSE 3000

    # Healthcheck
    HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
      CMD wget --no-verbose --tries=1 --spider http://localhost:3000/health || exit 1

    # Commande de démarrage
    CMD ["node", "app.js"]
    ```

    **Étape 4 : Scanner l'image pour vulnérabilités**

    ```bash
    # Build l'image sécurisée
    docker build -t myapp:secure .

    # Option 1: Docker Scout (intégré)
    docker scout quickview myapp:secure
    docker scout cves myapp:secure

    # Option 2: Trivy (recommandé - installer d'abord)
    # Installation Trivy (Ubuntu/Debian)
    # wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
    # echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/trivy.list
    # sudo apt-get update && sudo apt-get install trivy

    trivy image myapp:secure
    trivy image --severity HIGH,CRITICAL myapp:secure

    # Comparer les tailles
    docker images | grep myapp
    # insecure: ~1GB (node:20)
    # secure: ~150MB (node:20-alpine)
    ```

    **Étape 5 : Déploiement sécurisé (Docker CLI)**

    ```bash
    # Créer un secret
    echo "super-secret-api-key-12345" > api_key.txt

    # Lancer avec toutes les options de sécurité
    docker run -d \
      --name secure-app \
      -p 3000:3000 \
      --read-only \
      --tmpfs /tmp:rw,noexec,nosuid,size=64m \
      --tmpfs /app/tmp:rw,noexec,nosuid,size=64m \
      --cap-drop=ALL \
      --cap-add=NET_BIND_SERVICE \
      --security-opt=no-new-privileges:true \
      --user 1001:1001 \
      -v $(pwd)/api_key.txt:/run/secrets/api_key:ro \
      myapp:secure

    # Vérifier les paramètres de sécurité
    docker inspect secure-app --format='{{json .HostConfig.SecurityOpt}}'
    docker inspect secure-app --format='{{.Config.User}}'
    ```

    **Étape 6 : Tests de sécurité**

    ```bash
    # Test 1: Vérifier l'utilisateur
    docker exec secure-app whoami
    # Devrait afficher: appuser ✓

    docker exec secure-app id
    # uid=1001(appuser) gid=1001(appgroup) ✓

    # Test 2: Vérifier qu'on ne peut pas écrire sur le filesystem
    docker exec secure-app touch /test.txt
    # Erreur: Read-only file system ✓

    # Test 3: Mais /tmp est writable
    docker exec secure-app touch /tmp/test.txt
    # Fonctionne ✓

    # Test 4: Vérifier les capabilities
    docker exec secure-app cat /proc/1/status | grep Cap
    # Capabilities très limitées ✓

    # Test 5: Accéder au secret
    curl http://localhost:3000/secret
    # {"secret":"super-secret-api-key-12345"} ✓

    # Test 6: Vérifier qu'on ne peut pas devenir root
    docker exec secure-app su -
    # Erreur: su not found ou permission denied ✓
    ```

    **Étape 7 : Docker Compose sécurisé**

    ```yaml
    # docker-compose.yml
    version: '3.8'

    services:
      app:
        build: .
        image: myapp:secure
        container_name: secure-app
        ports:
          - "3000:3000"

        # Utilisateur non-root
        user: "1001:1001"

        # Filesystem read-only
        read_only: true
        tmpfs:
          - /tmp:rw,noexec,nosuid,size=64m
          - /app/tmp:rw,noexec,nosuid,size=64m

        # Security options
        security_opt:
          - no-new-privileges:true

        # Capabilities
        cap_drop:
          - ALL
        cap_add:
          - NET_BIND_SERVICE

        # Secrets
        secrets:
          - api_key

        # Healthcheck
        healthcheck:
          test: ["CMD", "wget", "--no-verbose", "--tries=1", "--spider", "http://localhost:3000/health"]
          interval: 30s
          timeout: 10s
          retries: 3

        # Resource limits
        deploy:
          resources:
            limits:
              cpus: '0.5'
              memory: 256M
            reservations:
              cpus: '0.25'
              memory: 128M

        restart: unless-stopped

    secrets:
      api_key:
        file: ./api_key.txt
    ```

    ```bash
    # Démarrer avec Compose
    docker compose up -d

    # Vérifier
    docker compose ps
    curl http://localhost:3000/whoami
    curl http://localhost:3000/secret

    # Logs de sécurité
    docker compose logs
    ```

    **Étape 8 : Audit de sécurité complet**

    ```bash
    # Comparer les configurations
    echo "=== INSECURE ==="
    docker run --rm myapp:insecure id || echo "N/A"

    echo "=== SECURE ==="
    docker exec secure-app id

    # Benchmark Docker (si disponible)
    # docker run --rm --net host --pid host --userns host --cap-add audit_control \
    #   -v /etc:/etc:ro -v /var/lib:/var/lib:ro -v /var/run/docker.sock:/var/run/docker.sock:ro \
    #   docker/docker-bench-security

    # Analyse des secrets exposés
    docker inspect secure-app | grep -i password
    # Ne devrait rien afficher ✓

    # Vérifier que le secret n'est pas dans les env vars
    docker exec secure-app env | grep -i secret
    # Ne devrait rien afficher ✓
    ```

    **Étape 9 : Cleanup**

    ```bash
    docker compose down
    # Ou
    docker stop secure-app && docker rm secure-app

    # Nettoyer les fichiers
    rm -f api_key.txt
    ```

    **Points clés de sécurité** :

    ✅ **Utilisateur non-root** : Réduit l'impact en cas de compromission
    ✅ **Read-only filesystem** : Empêche la modification du container
    ✅ **Capabilities minimales** : Principe du moindre privilège
    ✅ **no-new-privileges** : Empêche l'escalade de privilèges
    ✅ **Secrets via fichiers** : Plus sécurisé que les variables d'environnement
    ✅ **Image Alpine** : Surface d'attaque réduite
    ✅ **Scanning régulier** : Détection des vulnérabilités
    ✅ **Resource limits** : Protection contre DoS
    ✅ **Healthcheck** : Détection rapide des problèmes

    **Checklist de sécurité Docker** :

    - [ ] Images officielles ou vérifiées uniquement
    - [ ] Scanning de vulnérabilités automatisé
    - [ ] Utilisateur non-root dans Dockerfile
    - [ ] Filesystem read-only quand possible
    - [ ] Capabilities limitées au strict minimum
    - [ ] Secrets jamais dans le code ou les env vars
    - [ ] Resource limits configurés
    - [ ] Healthchecks actifs
    - [ ] Logs centralisés et monitorés
    - [ ] Mises à jour régulières des images de base

---

## Quiz

1. **Comment supprimer toutes les capabilities ?**
   - [ ] A. --cap-remove=ALL
   - [ ] B. --cap-drop=ALL
   - [ ] C. --no-capabilities

**Réponse :** B

---

**Précédent :** [Module 5 - Volumes](05-module.md)

**Suivant :** [TP Final](07-tp-final.md)

---

## Navigation

| | |
|:---|---:|
| [← Module 5 : Volumes et Persistance](05-module.md) | [TP Final : Application Production-Ready →](07-tp-final.md) |

[Retour au Programme](index.md){ .md-button }
