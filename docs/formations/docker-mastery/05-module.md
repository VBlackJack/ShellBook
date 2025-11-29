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

## 6. Exercice

```bash
# Créer une stack avec persistance
docker volume create pg_data

docker run -d \
  --name postgres \
  -e POSTGRES_PASSWORD=secret \
  -v pg_data:/var/lib/postgresql/data \
  postgres:15

# Vérifier la persistance
docker stop postgres
docker rm postgres
docker run -d --name postgres-new -v pg_data:/var/lib/postgresql/data postgres:15
# Les données sont conservées!
```

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
