---
tags:
  - tutos
  - databases
  - mariadb
  - postgresql
---

# Tutoriels Bases de Données

## Installation Standalone

| Tutoriel | OS | SGBD | Status |
|----------|-----|------|--------|
| [MariaDB](mariadb-rocky9.md) | Rocky 9 | MariaDB 10.11 | Disponible |
| [MariaDB](mariadb-debian12.md) | Debian 12 | MariaDB 10.11 | Disponible |
| [PostgreSQL](postgresql-rocky9.md) | Rocky 9 | PostgreSQL 15 | Disponible |
| [PostgreSQL](postgresql-debian12.md) | Debian 12 | PostgreSQL 15 | Disponible |
| SQL Server Express | Windows 2022 | SQL Server 2022 | Planifié |

## Haute Disponibilité

| Tutoriel | OS | SGBD | Status |
|----------|-----|------|--------|
| MariaDB Replication | Rocky 9 | MariaDB 10.11 | Planifié |
| MariaDB Galera Cluster | Rocky 9 | MariaDB 10.11 | Planifié |
| PostgreSQL Streaming | Debian 12 | PostgreSQL 15 | Planifié |
| SQL Server AlwaysOn | Windows 2022 | SQL Server 2022 | Planifié |

## Backup & Restore

| Tutoriel | OS | SGBD | Status |
|----------|-----|------|--------|
| MariaDB Backup | Rocky 9 | mariabackup | Planifié |
| PostgreSQL Backup | Debian 12 | pg_dump | Planifié |
| SQL Server Backup | Windows 2022 | SQL Backup | Planifié |

## Comparatif

| Critère | MariaDB | PostgreSQL | SQL Server |
|---------|---------|------------|------------|
| Licence | GPL | PostgreSQL | Commercial |
| Performance | Excellente (OLTP) | Excellente (complexe) | Excellente |
| Réplication | Galera, async | Streaming, logical | AlwaysOn |
| JSON/NoSQL | Bon | Excellent | Bon |
| Windows | Via WSL | Natif | Natif |
