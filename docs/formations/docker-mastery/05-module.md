---
tags:
  - formation
  - docker
  - volumes
  - storage
---

# Module 5 : Volumes et Persistance

## Objectifs du Module

- Comprendre les types de stockage Docker
- Gérer les volumes
- Configurer les bind mounts
- Sauvegarder et migrer les données

**Durée :** 2 heures

---

## 1. Types de Stockage

```
TYPES DE STOCKAGE DOCKER
════════════════════════

Volumes (recommandé)
────────────────────
- Gérés par Docker
- Stockés dans /var/lib/docker/volumes/
- Portables et faciles à backup

Bind Mounts
───────────
- Chemins absolus de l'host
- Utile pour le développement
- Dépend du filesystem host

tmpfs Mounts
────────────
- En mémoire uniquement
- Non persistant
- Pour données sensibles temporaires
```

---

## 2. Commandes Volumes

```bash
# Créer un volume
docker volume create myvolume

# Lister
docker volume ls

# Inspecter
docker volume inspect myvolume

# Supprimer
docker volume rm myvolume
docker volume prune  # Non utilisés

# Utiliser un volume
docker run -v myvolume:/data nginx
docker run --mount source=myvolume,target=/data nginx
```

---

## 3. Bind Mounts

```bash
# Bind mount
docker run -v /host/path:/container/path nginx
docker run -v $(pwd)/src:/app/src nginx

# Read-only
docker run -v /host/path:/container/path:ro nginx

# Syntaxe --mount (recommandée)
docker run --mount type=bind,source=/host/path,target=/container/path nginx
```

---

## 4. Docker Compose

```yaml
services:
  db:
    image: postgres
    volumes:
      # Named volume
      - db_data:/var/lib/postgresql/data

      # Bind mount
      - ./init.sql:/docker-entrypoint-initdb.d/init.sql:ro

      # tmpfs
      - type: tmpfs
        target: /tmp
        tmpfs:
          size: 100M

volumes:
  db_data:
    # Options avancées
    driver: local
    driver_opts:
      type: nfs
      o: addr=10.0.0.1,rw
      device: ":/path/to/dir"
```

---

## 5. Backup et Restore

```bash
# Backup un volume
docker run --rm \
  -v myvolume:/data \
  -v $(pwd):/backup \
  alpine tar cvf /backup/backup.tar /data

# Restore un volume
docker run --rm \
  -v myvolume:/data \
  -v $(pwd):/backup \
  alpine sh -c "cd /data && tar xvf /backup/backup.tar --strip 1"

# Copier entre volumes
docker run --rm \
  -v source_vol:/from \
  -v dest_vol:/to \
  alpine cp -av /from/. /to/
```

---

## 6. Exercice : À Vous de Jouer

!!! example "Mise en Pratique"
    **Objectif** : Maîtriser la gestion des volumes Docker, la persistance des données et les stratégies de backup/restore

    **Contexte** : Vous gérez une base de données PostgreSQL en production. Vous devez configurer la persistance des données, effectuer des backups réguliers, tester la restauration, et migrer les données vers un nouveau container sans perte.

    **Tâches à réaliser** :

    1. Créer un volume nommé pour PostgreSQL et initialiser une base avec des données de test
    2. Vérifier que les données persistent après la destruction et recréation du container
    3. Effectuer un backup complet du volume dans une archive tar
    4. Créer un nouveau volume et restaurer le backup dedans
    5. Comparer les volumes (bind mount vs named volume) pour un environnement de développement
    6. Nettoyer et supprimer proprement tous les volumes créés

    **Critères de validation** :

    - [ ] Les données survivent à la suppression du container
    - [ ] Le backup tar contient toutes les données de la base
    - [ ] La restauration recrée exactement les mêmes données
    - [ ] Vous comprenez les différences entre bind mounts et volumes
    - [ ] Les volumes sont correctement nettoyés sans laisser d'orphelins
    - [ ] Le fichier de backup peut être versionné et archivé

??? quote "Solution"
    **Étape 1 : Créer un volume et initialiser la base**

    ```bash
    # Créer un volume nommé
    docker volume create postgres_data

    # Inspecter le volume
    docker volume inspect postgres_data

    # Créer un script d'initialisation
    cat > init.sql << 'EOF'
    CREATE TABLE users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        email VARCHAR(100) NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
    );

    INSERT INTO users (username, email) VALUES
        ('alice', 'alice@example.com'),
        ('bob', 'bob@example.com'),
        ('charlie', 'charlie@example.com');

    CREATE TABLE posts (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        title VARCHAR(200),
        content TEXT,
        created_at TIMESTAMP DEFAULT NOW()
    );

    INSERT INTO posts (user_id, title, content) VALUES
        (1, 'First Post', 'Hello from Alice!'),
        (2, 'Docker Volumes', 'Volumes are great for persistence'),
        (3, 'Backup Strategy', 'Always backup your data!');
    EOF

    # Lancer PostgreSQL avec le volume et le script d'init
    docker run -d \
      --name postgres_main \
      -e POSTGRES_PASSWORD=mypassword \
      -e POSTGRES_DB=myapp \
      -v postgres_data:/var/lib/postgresql/data \
      -v $(pwd)/init.sql:/docker-entrypoint-initdb.d/init.sql:ro \
      postgres:15-alpine

    # Attendre que la base soit prête
    sleep 10

    # Vérifier les données
    docker exec postgres_main psql -U postgres -d myapp -c "SELECT * FROM users;"
    docker exec postgres_main psql -U postgres -d myapp -c "SELECT COUNT(*) FROM posts;"
    ```

    **Étape 2 : Test de persistance**

    ```bash
    # Ajouter une nouvelle donnée
    docker exec postgres_main psql -U postgres -d myapp -c \
      "INSERT INTO users (username, email) VALUES ('david', 'david@example.com');"

    # Vérifier
    docker exec postgres_main psql -U postgres -d myapp -c "SELECT COUNT(*) FROM users;"
    # Devrait afficher 4

    # DÉTRUIRE le container
    docker stop postgres_main
    docker rm postgres_main

    # Vérifier que le volume existe toujours
    docker volume ls | grep postgres_data

    # Recréer un NOUVEAU container avec le MÊME volume
    docker run -d \
      --name postgres_restored \
      -e POSTGRES_PASSWORD=mypassword \
      -e POSTGRES_DB=myapp \
      -v postgres_data:/var/lib/postgresql/data \
      postgres:15-alpine

    # Attendre le démarrage
    sleep 5

    # Vérifier que les données sont TOUJOURS là
    docker exec postgres_restored psql -U postgres -d myapp -c "SELECT * FROM users;"
    # Les 4 utilisateurs doivent être présents!
    ```

    **Étape 3 : Backup du volume**

    ```bash
    # Créer un répertoire pour les backups
    mkdir -p backups

    # Méthode 1: Backup avec tar (recommandé)
    docker run --rm \
      -v postgres_data:/data:ro \
      -v $(pwd)/backups:/backup \
      alpine \
      tar czf /backup/postgres_backup_$(date +%Y%m%d_%H%M%S).tar.gz -C /data .

    # Vérifier le backup
    ls -lh backups/

    # Méthode 2: pg_dump (spécifique PostgreSQL)
    docker exec postgres_restored pg_dump -U postgres myapp > backups/myapp_dump.sql

    # Vérifier le contenu
    head -n 20 backups/myapp_dump.sql
    ```

    **Étape 4 : Restauration dans un nouveau volume**

    ```bash
    # Créer un nouveau volume vide
    docker volume create postgres_data_restored

    # Restaurer le backup tar dans le nouveau volume
    docker run --rm \
      -v postgres_data_restored:/data \
      -v $(pwd)/backups:/backup \
      alpine \
      sh -c "cd /data && tar xzf /backup/postgres_backup_*.tar.gz"

    # Démarrer un container avec le volume restauré
    docker run -d \
      --name postgres_from_backup \
      -e POSTGRES_PASSWORD=mypassword \
      -e POSTGRES_DB=myapp \
      -v postgres_data_restored:/var/lib/postgresql/data \
      postgres:15-alpine

    # Attendre le démarrage
    sleep 5

    # Vérifier que les données sont identiques
    docker exec postgres_from_backup psql -U postgres -d myapp -c "SELECT * FROM users;"
    docker exec postgres_from_backup psql -U postgres -d myapp -c "SELECT * FROM posts;"
    ```

    **Étape 5 : Comparaison bind mount vs volume**

    ```bash
    # Bind mount (développement)
    mkdir -p postgres_dev_data

    docker run -d \
      --name postgres_dev \
      -e POSTGRES_PASSWORD=dev \
      -v $(pwd)/postgres_dev_data:/var/lib/postgresql/data \
      postgres:15-alpine

    # Vous pouvez maintenant accéder aux fichiers directement
    ls -la postgres_dev_data/
    # Les fichiers PostgreSQL sont visibles sur l'hôte

    # Named volume (production)
    # Les fichiers sont dans /var/lib/docker/volumes/ (géré par Docker)
    # Plus sécurisé, portable, performant

    # Cleanup dev
    docker stop postgres_dev
    docker rm postgres_dev
    sudo rm -rf postgres_dev_data
    ```

    **Étape 6 : Copier des données entre volumes**

    ```bash
    # Copier d'un volume à un autre
    docker volume create postgres_copy

    docker run --rm \
      -v postgres_data:/source:ro \
      -v postgres_copy:/destination \
      alpine \
      sh -c "cp -av /source/. /destination/"

    # Vérifier
    docker run --rm \
      -v postgres_copy:/data \
      alpine \
      ls -la /data
    ```

    **Étape 7 : Nettoyage complet**

    ```bash
    # Arrêter tous les containers postgres
    docker stop postgres_restored postgres_from_backup
    docker rm postgres_restored postgres_from_backup

    # Lister tous les volumes
    docker volume ls

    # Supprimer les volumes spécifiques
    docker volume rm postgres_data
    docker volume rm postgres_data_restored
    docker volume rm postgres_copy

    # Ou supprimer tous les volumes non utilisés
    docker volume prune -f

    # Nettoyer les backups (optionnel)
    rm -rf backups/ init.sql
    ```

    **Étape 8 : Bonnes pratiques (résumé)**

    ```bash
    # Stratégie de backup automatisé (exemple avec cron)
    cat > backup_script.sh << 'EOF'
    #!/bin/bash
    BACKUP_DIR="/backups"
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)

    docker run --rm \
      -v postgres_data:/data:ro \
      -v ${BACKUP_DIR}:/backup \
      alpine \
      tar czf /backup/postgres_${TIMESTAMP}.tar.gz -C /data .

    # Garder seulement les 7 derniers backups
    ls -t ${BACKUP_DIR}/postgres_*.tar.gz | tail -n +8 | xargs rm -f
    EOF

    chmod +x backup_script.sh
    ```

    **Points clés** :

    - **Named volumes** : gérés par Docker, portables, recommandés pour la production
    - **Bind mounts** : chemins absolus de l'hôte, utiles pour le développement
    - Les données dans les volumes **survivent** à la suppression des containers
    - `docker volume prune` supprime uniquement les volumes non utilisés
    - Toujours tester la restauration des backups régulièrement
    - Les backups peuvent être versionnés, chiffrés et stockés à distance
    - `-v source:destination:ro` monte en lecture seule (sécurité)

---

## Quiz

1. **Quel type de stockage est géré par Docker ?**
   - [ ] A. Bind mount
   - [ ] B. Volume
   - [ ] C. tmpfs

**Réponse :** B

---

**Précédent :** [Module 4 - Networking](04-module.md)

**Suivant :** [Module 6 - Sécurité](06-module.md)

---

## Navigation

| | |
|:---|---:|
| [← Module 4 : Networking](04-module.md) | [Module 6 : Sécurité Docker →](06-module.md) |

[Retour au Programme](index.md){ .md-button }
