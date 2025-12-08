---
tags:
  - k8s
  - certification
  - cka
---

# Kubernetes CKA: Stratégie & Leçons

Retours d'expérience concrets sur la réussite de l'examen Certified Kubernetes Administrator.

![Kubernetes Deployment Strategies](../assets/infographics/kubernetes/kubernetes-deployment-strategies.jpeg)

---

## La Réalité de l'Examen CKA

### C'est Pratique, Pas Théorique

!!! warning "Pas de QCM"
    Le CKA est un **examen pratique**. Vous avez un terminal et de vrais clusters Kubernetes.

    - Vous tapez de vraies commandes `kubectl`
    - Vous éditez des manifests YAML
    - Vous dépannez des clusters cassés
    - Vous configurez le réseau, le stockage, RBAC

### La Gestion du Temps est Primordiale

| Fait | Impact |
|------|--------|
| Durée | 2 heures |
| Questions | ~17-20 tâches |
| Score de réussite | 66% |
| Environnement | Plusieurs clusters entre lesquels basculer |

**Stratégie:**

1. **Lire toutes les questions d'abord** - Identifier les gains rapides
2. **Faire les questions faciles en premier** - Construire la confiance, sécuriser des points
3. **Si bloqué > 5 min, passer à la suite** - Marquer et revenir plus tard
4. **Utiliser la documentation** - kubernetes.io est autorisé (mais lent à chercher)

!!! tip "Gain de Temps"
    ```bash
    # Configurer les alias immédiatement
    alias k=kubectl
    alias kn='kubectl config set-context --current --namespace'

    # Activer l'autocomplétion
    source <(kubectl completion bash)
    complete -F __start_kubectl k

    # Basculer rapidement de contexte
    kubectl config use-context <cluster-name>
    ```

---

## Leçons du Monde Réel

### Exigences de Haute Disponibilité

**Minimum pour une vraie HA en production:**

```
┌─────────────────────────────────────────┐
│       Configuration HA Production        │
├─────────────────────────────────────────┤
│  3x Control Plane (Masters)              │
│  3x nœuds ETCD (peuvent être sur masters)│
│  3+ nœuds Worker                         │
│  Load Balancer pour le serveur API      │
└─────────────────────────────────────────┘
```

| Composant | Minimum pour HA | Pourquoi |
|-----------|----------------|-----|
| Control Plane | 3 | Quorum (2/3 doivent être d'accord) |
| ETCD | 3 | Le consensus Raft nécessite une majorité |
| Workers | 3+ | Distribution de charge |
| Load Balancer | 1 (HA: 2) | Accès au serveur API |

**Total: 6-9 serveurs minimum pour une HA production**

!!! danger "Quorum ETCD"
    ETCD utilise le consensus Raft. Avec 3 nœuds, vous pouvez en perdre 1.
    Avec 5 nœuds, vous pouvez en perdre 2. Utilisez toujours des **nombres impairs**.

    ```
    Nœuds | Pannes Tolérables
    ------+-------------------
      1   |        0
      3   |        1
      5   |        2
      7   |        3
    ```

---

### L'Enfer de la Compatibilité

Les incompatibilités de versions sont une source courante de pannes de cluster.

```
┌──────────────────────────────────────────────┐
│  Vérifier la Compatibilité AVANT l'Install   │
├──────────────────────────────────────────────┤
│  Version OS        ←→  Container Runtime     │
│  Container Runtime ←→  Version Kubernetes    │
│  Kubernetes        ←→  Version Plugin CNI    │
│  Plugin CNI        ←→  Version Kernel        │
└──────────────────────────────────────────────┘
```

**Problèmes courants:**

| Problème | Cause |
|---------|-------|
| kubeadm échoue | OS trop récent/ancien pour la version K8s |
| Pods bloqués en Pending | CNI pas compatible |
| Problèmes réseau | Fonctionnalités manquantes dans le kernel |
| Erreurs containerd | Incompatibilité Cgroups v1 vs v2 |

**Toujours vérifier:**

```bash
# Politique de version skew Kubernetes
# Control plane: peut être +/- 1 version mineure
# kubelet: peut avoir jusqu'à 2 versions mineures de retard

kubectl version
kubeadm version
kubelet --version
containerd --version
```

---

### Gestion des Coûts

!!! warning "K8s dans le Cloud Coûte Cher"
    Un simple cluster à 3 nœuds peut coûter **200-500$/mois** sur les clouds majeurs.

    Une HA production (6+ nœuds) atteint facilement **1000+$/mois**.

**Stratégies d'Économie:**

| Stratégie | Économies | Compromis |
|----------|---------|-----------|
| Instances Spot/Preemptible | 60-80% | Peuvent être terminées |
| Cluster autoscaler | Variable | Latence de démarrage à froid |
| Dimensionnement optimal | 20-40% | Nécessite monitoring |
| Instances réservées | 30-50% | Engagement requis |
| Quotas par Namespace | Évite le gaspillage | Limite la flexibilité |

**Outils pour l'Optimisation des Coûts:**

- **Cast AI** - Optimisation automatisée des coûts
- **Kubecost** - Monitoring et allocation des coûts
- **Karpenter** - Provisionnement intelligent de nœuds (AWS)
- **Goldilocks** - Recommandations de dimensionnement

---

## Checklist des Sujets CKA

| Domaine | Poids | Compétences Clés |
|--------|--------|------------|
| Architecture de Cluster | 25% | Installation, mise à jour, backup ETCD |
| Workloads & Scheduling | 15% | Deployments, DaemonSets, taints |
| Services & Réseau | 20% | Services, Ingress, NetworkPolicy |
| Stockage | 10% | PV, PVC, StorageClass |
| Dépannage | 30% | Logs, events, problèmes de nœuds |

### Commandes Indispensables

```bash
# Infos cluster
kubectl cluster-info
kubectl get nodes -o wide
kubectl get componentstatuses

# Création rapide de pod
kubectl run nginx --image=nginx --port=80
kubectl run busybox --image=busybox --rm -it -- sh

# Exposer un service
kubectl expose pod nginx --port=80 --type=NodePort

# Générer du YAML (ne pas écrire from scratch!)
kubectl run nginx --image=nginx --dry-run=client -o yaml > pod.yaml
kubectl create deployment nginx --image=nginx --dry-run=client -o yaml

# Dépannage
kubectl describe pod <name>
kubectl logs <pod> -f
kubectl exec -it <pod> -- sh
kubectl get events --sort-by='.lastTimestamp'

# Backup ETCD (critique!)
ETCDCTL_API=3 etcdctl snapshot save /backup/etcd.db \
  --endpoints=https://127.0.0.1:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/server.crt \
  --key=/etc/kubernetes/pki/etcd/server.key
```

---

## Ressources d'Étude

| Ressource | Type | Coût |
|----------|------|------|
| Killer.sh | Examens pratiques (inclus avec CKA) | Gratuit avec l'examen |
| KodeKloud | Cours vidéo + labs | Payant |
| Documentation Kubernetes | Référence officielle | Gratuit |
| kubectl explain | Aide intégrée | Gratuit |

!!! tip "L'Astuce kubectl explain"
    ```bash
    # Ne pas mémoriser la structure YAML
    kubectl explain pod.spec.containers
    kubectl explain deployment.spec.strategy
    kubectl explain --recursive pod.spec
    ```
