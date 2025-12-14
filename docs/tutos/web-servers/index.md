---
tags:
  - tutos
  - web
  - apache
  - nginx
  - iis
---

# Tutoriels Serveurs Web

## LAMP Stack (Apache)

| Tutoriel | OS | Stack | Difficulté |
|----------|-----|-------|------------|
| [LAMP Rocky Linux 9](lamp-rocky9.md) | Rocky 9 | Apache + MariaDB + PHP 8.2 | Débutant |
| [LAMP Debian 12](lamp-debian12.md) | Debian 12 | Apache + MariaDB + PHP 8.2 | Débutant |
| [IIS + PHP](iis-windows2022.md) | Windows 2022 | IIS + PHP 8.2 | Débutant |

## LEMP Stack (Nginx)

| Tutoriel | OS | Stack | Difficulté |
|----------|-----|-------|------------|
| [LEMP Rocky 9](lemp-rocky9.md) | Rocky 9 | Nginx + MariaDB + PHP 8.2 | Débutant |
| [LEMP Debian 12](lemp-debian12.md) | Debian 12 | Nginx + MariaDB + PHP 8.2 | Débutant |

## Reverse Proxy & Load Balancer

| Tutoriel | OS | Outil | Difficulté |
|----------|-----|-------|------------|
| [Nginx Reverse Proxy Rocky 9](nginx-proxy-rocky9.md) | Rocky 9 | Nginx | Intermédiaire |
| [Nginx Reverse Proxy Debian 12](nginx-proxy-debian12.md) | Debian 12 | Nginx | Intermédiaire |
| [HAProxy Rocky 9](haproxy-rocky9.md) | Rocky 9 | HAProxy | Intermédiaire |
| [HAProxy Debian 12](haproxy-debian12.md) | Debian 12 | HAProxy | Intermédiaire |

## À venir

| Tutoriel | OS | Status |
|----------|-----|--------|
| IIS ARR Reverse Proxy | Windows 2022 | Planifié |

## Comparatif des stacks

| Critère | LAMP | LEMP | IIS |
|---------|------|------|-----|
| Serveur web | Apache | Nginx | IIS |
| Performance statique | Bonne | Excellente | Bonne |
| Consommation RAM | Moyenne | Faible | Élevée |
| Configuration | .htaccess | Centralisée | GUI + XML |
| Cas d'usage | CMS (WordPress) | API, haute charge | Environnement Microsoft |
