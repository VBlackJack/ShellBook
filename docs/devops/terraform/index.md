---
tags:
  - devops
  - terraform
  - iac
  - infrastructure
---

# Terraform

Infrastructure as Code avec HashiCorp Terraform.

---

## Guides Disponibles

| Guide | Description | Niveau |
|-------|-------------|--------|
| [Fundamentals](fundamentals.md) | Bases Terraform : providers, resources, state | :material-star: |

---

## Concepts Clés

### Infrastructure as Code

Terraform permet de décrire l'infrastructure sous forme de code déclaratif (HCL), offrant :

- **Versioning** - Historique des changements
- **Reproductibilité** - Environnements identiques
- **Collaboration** - Revue de code infrastructure
- **Automation** - Déploiement CI/CD

### Workflow Terraform

```mermaid
graph LR
    A[Write] --> B[Plan]
    B --> C[Apply]
    C --> D[Destroy]
```

---

## Voir Aussi

- [Formation Terraform ACI](../../formations/terraform-aci/index.md) - Formation spécialisée Cisco ACI
- [Ansible](../ansible/index.md) - Configuration Management
