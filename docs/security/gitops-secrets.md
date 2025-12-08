---
tags:
  - security
  - gitops
  - secrets
  - kubernetes
  - vault
---

# Secrets Management en GitOps

Le paradoxe du GitOps : "Tout doit être dans Git".
La règle de sécurité n°1 : "**Jamais** de mot de passe dans Git".

Comment réconcilier les deux ?

## 1. La Mauvaise Méthode (À bannir)

*   Mettre les secrets en clair dans Git (Même en repo privé !).
*   Mettre les secrets en base64 (Ce n'est pas du chiffrement, c'est de l'encodage).
*   Ignorer le fichier `secrets.yaml` et le copier à la main (Casse l'automatisation GitOps).

## 2. Méthode A : Secrets Chiffrés (Sealed Secrets / SOPS)

On stocke le secret dans Git, mais **chiffré**. Seul le cluster peut le déchiffrer.

### Sealed Secrets (Bitnami)
Le concept de chiffrement asymétrique appliqué à K8s.
1.  **Public Key** : Accessible à tous les dévs. Ils peuvent chiffrer un secret.
2.  **Private Key** : Stockée DANS le cluster (Secret K8s). Seul le contrôleur peut déchiffrer.

**Workflow :**
```bash
# 1. Créer un secret normal (localement)
kubectl create secret generic my-db-pass --from-literal=password=toto --dry-run=client -o yaml > secret.yaml

# 2. Le sceller (Chiffrement)
kubeseal --cert public-cert.pem < secret.yaml > sealed-secret.yaml

# 3. Commit dans Git
git add sealed-secret.yaml && git commit
```
*Le fichier `sealed-secret.yaml` est illisible sans la clé privée du cluster.*

## 3. Méthode B : Secrets Externes (External Secrets Operator)

On ne stocke **rien** dans Git (même pas chiffré). On stocke une **référence**.

**Concept :**
1.  Le secret est dans un coffre-fort externe (HashiCorp Vault, AWS Secrets Manager, Azure KeyVault).
2.  Dans Git, on met un objet `ExternalSecret` qui dit "Va chercher le secret `db-pass` dans le coffre `production`".
3.  L'opérateur (ESO) dans K8s s'authentifie auprès du coffre, récupère la valeur, et crée le Secret K8s natif.

**Exemple YAML :**
```yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: database-credentials
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: aws-secrets-manager
    kind: SecretStore
  target:
    name: db-secret-k8s # Le nom du secret final
  data:
  - secretKey: password
    remoteRef:
      key: prod/db/password
```

### Comparatif

| Critère | Sealed Secrets | External Secrets (ESO) |
|---------|----------------|------------------------|
| **Complexité** | Faible (Juste une clé) | Moyenne (Besoin d'un Vault externe) |
| **Coût** | Gratuit | Payant (AWS/Azure) ou lourd (Vault) |
| **Sécurité** | Bonne (si clé privée protégée) | Excellente (Rotation, Audit centralisé) |
| **Rotation** | Difficile (Re-commit nécessaire) | Automatique |
| **Usage** | PME / Projets simples | Entreprises / Banques |
