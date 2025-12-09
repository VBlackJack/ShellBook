---
tags:
  - scripts
  - bibliothèque
  - automation
---

# Bibliothèque de Scripts

Collection de scripts prêts à l'emploi pour l'administration système.

---

## Organisation

<div class="grid cards" markdown>

-   :simple-gnubash: **Bash**

    ---

    Scripts shell pour Linux/Unix

    [:octicons-arrow-right-24: Voir les scripts](bash/index.md)

-   :material-powershell: **PowerShell**

    ---

    Scripts pour Windows et cross-platform

    [:octicons-arrow-right-24: Voir les scripts](powershell/index.md)

-   :material-language-python: **Python**

    ---

    Scripts Python pour l'automatisation

    [:octicons-arrow-right-24: Voir les scripts](python/index.md)

</div>

---

## Catégories

| Catégorie | Description | Bash | PowerShell | Python |
|-----------|-------------|:----:|:----------:|:------:|
| Système | Info système, monitoring | ✓ | ✓ | ✓ |
| Réseau | Connectivité, DNS, ports | ✓ | ✓ | ✓ |
| Fichiers | Backup, nettoyage, sync | ✓ | ✓ | ✓ |
| Sécurité | Audit, permissions, logs | ✓ | ✓ | ✓ |
| Services | Gestion des services | ✓ | ✓ | ✓ |
| Users | Gestion utilisateurs | ✓ | ✓ | ✓ |

---

## Conventions

### Nommage

```xml
<action>-<cible>.<extension>
```

Exemples :
- `check-disk-space.sh`
- `Get-SystemInfo.ps1`
- `backup_database.py`

### Structure d'un Script

Chaque script doit inclure :

1. **Header** avec description et auteur
2. **Paramètres** documentés
3. **Validation** des entrées
4. **Gestion d'erreurs**
5. **Logging** optionnel

### Niveaux de Complexité

| Niveau | Description |
|--------|-------------|
| :material-star: | Débutant - Script simple, une seule tâche |
| :material-star::material-star: | Intermédiaire - Plusieurs fonctions, paramètres |
| :material-star::material-star::material-star: | Avancé - Gestion d'erreurs, logging, modularité |

---

## Contribution

Pour ajouter un script :

1. Choisir la catégorie appropriée
2. Suivre les conventions de nommage
3. Documenter le script
4. Tester sur plusieurs environnements
5. Soumettre une PR

---

## Voir Aussi

- [Formation Bash](../formations/linux-mastery/index.md)
- [Formation PowerShell](../formations/windows-mastery/index.md)
- [Formation Python](../formations/python-sysops/index.md)
