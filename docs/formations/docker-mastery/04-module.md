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

```
DOCKER NETWORK DRIVERS
══════════════════════

bridge (défaut)
───────────────
- Réseau isolé sur l'host
- NAT pour accès externe
- DNS interne

host
────
- Partage le réseau de l'host
- Pas d'isolation
- Performance maximale

none
────
- Pas de réseau
- Container isolé

overlay
───────
- Multi-host (Swarm)
- Chiffrement optionnel

macvlan
───────
- Adresse MAC dédiée
- Apparaît comme device physique
```

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

## Quiz

1. **Quel driver pour multi-host ?**
   - [ ] A. bridge
   - [ ] B. overlay
   - [ ] C. macvlan

**Réponse :** B

---

**Précédent :** [Module 3 - Compose](03-module.md)

**Suivant :** [Module 5 - Volumes](05-module.md)
