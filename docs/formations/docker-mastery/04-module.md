---
tags:
  - formation
  - docker
  - networking
---

# Module 4 : Networking

## Objectifs du Module

- Comprendre les drivers réseau Docker
- Configurer la communication entre containers
- Exposer les services
- Gérer le DNS interne

**Durée :** 2 heures

---

## 1. Network Drivers

![Docker Networking Modes](../../assets/diagrams/docker-networking-modes.jpeg)

---

## 2. Commandes Réseau

```bash
# Lister les réseaux
docker network ls

# Créer un réseau
docker network create mynetwork
docker network create --driver bridge --subnet 172.20.0.0/16 mynetwork

# Inspecter
docker network inspect mynetwork

# Connecter/Déconnecter
docker network connect mynetwork container1
docker network disconnect mynetwork container1

# Supprimer
docker network rm mynetwork
docker network prune
```

---

## 3. DNS et Communication

```bash
# Les containers sur le même réseau peuvent se joindre par nom
docker network create app-network

docker run -d --name db --network app-network postgres
docker run -d --name api --network app-network myapi

# Depuis api:
# ping db           → fonctionne
# curl http://db:5432 → fonctionne

# Alias DNS
docker run -d --name db --network app-network --network-alias database postgres
# Accessible via "db" ET "database"
```

---

## 4. Ports et Exposition

```bash
# Publish ports
docker run -p 8080:80 nginx              # Toutes interfaces
docker run -p 127.0.0.1:8080:80 nginx    # Localhost only
docker run -p 8080-8090:80-90 nginx      # Range
docker run -P nginx                       # Ports aléatoires (EXPOSE)

# Voir les ports
docker port container_name
```

---

## 5. Exemple Pratique

```yaml
# docker-compose.yml
services:
  frontend:
    image: nginx
    ports:
      - "80:80"
    networks:
      - frontend-net

  api:
    image: myapi
    networks:
      - frontend-net
      - backend-net
    # Accessible par frontend et db

  db:
    image: postgres
    networks:
      - backend-net
    # NON accessible par frontend (isolation)

networks:
  frontend-net:
  backend-net:
    internal: true  # Pas d'accès internet
```

---

## Exercice : À Vous de Jouer

!!! example "Mise en Pratique"
    **Objectif** : Configurer une architecture réseau Docker complexe avec isolation et communication contrôlée

    **Contexte** : Vous devez mettre en place une infrastructure réseau pour une application web à trois niveaux (frontend, backend, database) avec des règles de communication strictes. Le frontend doit uniquement communiquer avec le backend, et le backend uniquement avec la database.

    **Tâches à réaliser** :

    1. Créer trois réseaux Docker personnalisés : `frontend-net`, `backend-net`, et `db-net`
    2. Configurer le réseau `db-net` comme réseau interne (sans accès internet)
    3. Déployer 4 containers : nginx (frontend), 2x api (backend avec load balancing), postgres (database)
    4. Connecter les containers aux réseaux appropriés pour respecter l'isolation
    5. Tester la communication entre services via les noms DNS
    6. Vérifier que l'isolation réseau fonctionne correctement
    7. Exposer uniquement le frontend sur le port 80 de l'hôte

    **Critères de validation** :

    - [ ] Le frontend (nginx) peut communiquer avec les deux instances de l'API
    - [ ] Les API peuvent communiquer avec la base de données
    - [ ] Le frontend ne peut PAS communiquer directement avec la database
    - [ ] La database n'a pas d'accès internet direct
    - [ ] Le DNS résout correctement les noms de containers
    - [ ] Seul le port 80 est exposé sur l'hôte

??? quote "Solution"
    **Étape 1 : Créer les réseaux**

    ```bash
    # Créer le réseau frontend
    docker network create frontend-net

    # Créer le réseau backend
    docker network create backend-net

    # Créer le réseau database (internal = pas d'accès internet)
    docker network create --internal db-net

    # Vérifier les réseaux créés
    docker network ls
    docker network inspect db-net
    ```

    **Étape 2 : Démarrer la database**

    ```bash
    # PostgreSQL sur le réseau database uniquement
    docker run -d \
      --name database \
      --network db-net \
      -e POSTGRES_PASSWORD=secretpass \
      -e POSTGRES_DB=appdb \
      postgres:15-alpine

    # Vérifier qu'elle n'a pas d'accès internet
    docker exec database ping -c 2 google.com
    # Devrait échouer
    ```

    **Étape 3 : Démarrer les API backends**

    ```bash
    # API 1 - Connectée aux réseaux backend et database
    docker run -d \
      --name api1 \
      --network backend-net \
      -e DATABASE_URL=postgres://postgres:secretpass@database:5432/appdb \
      hashicorp/http-echo:latest \
      -text="API Instance 1"

    # Connecter api1 au réseau database
    docker network connect db-net api1

    # API 2 - Même configuration
    docker run -d \
      --name api2 \
      --network backend-net \
      -e DATABASE_URL=postgres://postgres:secretpass@database:5432/appdb \
      hashicorp/http-echo:latest \
      -text="API Instance 2"

    docker network connect db-net api2

    # Vérifier la connexion aux réseaux
    docker inspect api1 --format='{{json .NetworkSettings.Networks}}' | jq
    ```

    **Étape 4 : Configuration nginx**

    ```bash
    # Créer la configuration nginx pour le load balancing
    cat > nginx.conf << 'EOF'
    events {
        worker_connections 1024;
    }

    http {
        upstream backend {
            server api1:5678;
            server api2:5678;
        }

        server {
            listen 80;

            location / {
                proxy_pass http://backend;
                proxy_set_header Host $host;
                proxy_set_header X-Real-IP $remote_addr;
                add_header X-Backend-Server $upstream_addr;
            }

            location /health {
                return 200 "Frontend OK\n";
            }
        }
    }
    EOF
    ```

    **Étape 5 : Démarrer le frontend**

    ```bash
    # Nginx sur le réseau frontend et backend
    docker run -d \
      --name frontend \
      --network frontend-net \
      -p 80:80 \
      -v $(pwd)/nginx.conf:/etc/nginx/nginx.conf:ro \
      nginx:alpine

    # Connecter au réseau backend pour atteindre les APIs
    docker network connect backend-net frontend
    ```

    **Étape 6 : Tests de communication**

    ```bash
    # Test 1: Accès depuis l'hôte au frontend
    curl http://localhost
    # Devrait afficher "API Instance 1" ou "API Instance 2"

    # Test 2: Load balancing (plusieurs requêtes)
    for i in {1..10}; do
      curl -s http://localhost
    done
    # Devrait alterner entre Instance 1 et 2

    # Test 3: Frontend peut atteindre les APIs
    docker exec frontend wget -qO- http://api1:5678
    docker exec frontend wget -qO- http://api2:5678
    # Devrait fonctionner

    # Test 4: API peut atteindre la database
    docker exec api1 ping -c 2 database
    # Devrait fonctionner

    # Test 5: Frontend NE PEUT PAS atteindre la database
    docker exec frontend ping -c 2 database
    # Devrait échouer (pas sur le même réseau)

    # Test 6: Vérifier l'isolation du réseau db-net
    docker exec database ping -c 2 8.8.8.8
    # Devrait échouer (réseau internal)
    ```

    **Étape 7 : Inspection et analyse**

    ```bash
    # Voir tous les containers et leurs réseaux
    docker ps --format "table {{.Names}}\t{{.Ports}}"

    # Inspecter les réseaux
    docker network inspect frontend-net
    docker network inspect backend-net
    docker network inspect db-net

    # Voir les connexions réseau d'un container
    docker inspect frontend \
      --format='{{range $net, $conf := .NetworkSettings.Networks}}{{$net}} {{end}}'

    # Résolution DNS
    docker exec frontend nslookup api1
    docker exec api1 nslookup database
    ```

    **Étape 8 : Version Docker Compose (équivalent)**

    ```yaml
    # docker-compose.yml
    version: '3.8'

    services:
      frontend:
        image: nginx:alpine
        ports:
          - "80:80"
        volumes:
          - ./nginx.conf:/etc/nginx/nginx.conf:ro
        networks:
          - frontend-net
          - backend-net

      api1:
        image: hashicorp/http-echo:latest
        command: ["-text=API Instance 1"]
        environment:
          DATABASE_URL: postgres://postgres:secretpass@database:5432/appdb
        networks:
          - backend-net
          - db-net

      api2:
        image: hashicorp/http-echo:latest
        command: ["-text=API Instance 2"]
        environment:
          DATABASE_URL: postgres://postgres:secretpass@database:5432/appdb
        networks:
          - backend-net
          - db-net

      database:
        image: postgres:15-alpine
        environment:
          POSTGRES_PASSWORD: secretpass
          POSTGRES_DB: appdb
        networks:
          - db-net

    networks:
      frontend-net:
        driver: bridge
      backend-net:
        driver: bridge
      db-net:
        driver: bridge
        internal: true
    ```

    ```bash
    # Démarrer avec Compose
    docker compose up -d

    # Tester
    curl http://localhost
    ```

    **Étape 9 : Cleanup**

    ```bash
    # Arrêter et supprimer les containers
    docker stop frontend api1 api2 database
    docker rm frontend api1 api2 database

    # Supprimer les réseaux
    docker network rm frontend-net backend-net db-net

    # Ou avec Compose
    docker compose down
    ```

    **Points clés** :

    - Un container peut être connecté à plusieurs réseaux
    - Les réseaux `internal: true` n'ont pas d'accès internet
    - Le DNS Docker résout automatiquement les noms de containers
    - Seuls les containers sur le même réseau peuvent communiquer
    - Le flag `-p` expose les ports uniquement là où c'est nécessaire
    - L'isolation réseau est essentielle pour la sécurité

---

## Quiz

1. **Quel driver pour multi-host ?**
   - [ ] A. bridge
   - [ ] B. overlay
   - [ ] C. macvlan

**Réponse :** B

---

**Précédent :** [Module 3 - Compose](03-module.md)

**Suivant :** [Module 5 - Volumes](05-module.md)

---

## Navigation

| | |
|:---|---:|
| [← Module 3 : Docker Compose](03-module.md) | [Module 5 : Volumes et Persistance →](05-module.md) |

[Retour au Programme](index.md){ .md-button }
