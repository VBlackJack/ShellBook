# Kubernetes CKA: Strategy & Lessons

`#k8s` `#certification` `#cka`

Real-world insights from passing the Certified Kubernetes Administrator exam.

---

## The CKA Exam Reality

### It's Practical, Not Theory

!!! warning "No Multiple Choice"
    The CKA is a **hands-on exam**. You get a terminal and real Kubernetes clusters.

    - You type actual `kubectl` commands
    - You edit YAML manifests
    - You troubleshoot broken clusters
    - You configure networking, storage, RBAC

### Time Management is Everything

| Fact | Impact |
|------|--------|
| Duration | 2 hours |
| Questions | ~17-20 tasks |
| Passing score | 66% |
| Environment | Multiple clusters to switch between |

**Strategy:**

1. **Read all questions first** - Identify quick wins
2. **Do easy questions first** - Build confidence, secure points
3. **If stuck > 5 min, move on** - Flag and return later
4. **Use the docs** - kubernetes.io is allowed (but slow to search)

!!! tip "Time Savers"
    ```bash
    # Set up aliases immediately
    alias k=kubectl
    alias kn='kubectl config set-context --current --namespace'

    # Enable autocompletion
    source <(kubectl completion bash)
    complete -F __start_kubectl k

    # Quick context switch
    kubectl config use-context <cluster-name>
    ```

---

## Real-World Lessons

### High Availability Requirements

**Minimum for true production HA:**

```
┌─────────────────────────────────────────┐
│           Production HA Setup            │
├─────────────────────────────────────────┤
│  3x Control Plane (Masters)              │
│  3x ETCD nodes (can be on masters)       │
│  3+ Worker nodes                         │
│  Load Balancer for API server            │
└─────────────────────────────────────────┘
```

| Component | Minimum for HA | Why |
|-----------|----------------|-----|
| Control Plane | 3 | Quorum (2/3 must agree) |
| ETCD | 3 | Raft consensus requires majority |
| Workers | 3+ | Workload distribution |
| Load Balancer | 1 (HA: 2) | API server access |

**Total: 6-9 servers minimum for production-grade HA**

!!! danger "ETCD Quorum"
    ETCD uses Raft consensus. With 3 nodes, you can lose 1.
    With 5 nodes, you can lose 2. Always use **odd numbers**.

    ```
    Nodes | Tolerable Failures
    ------+-------------------
      1   |        0
      3   |        1
      5   |        2
      7   |        3
    ```

---

### Compatibility Hell

Version mismatches are a common source of cluster failures.

```
┌──────────────────────────────────────────────┐
│  Check Compatibility BEFORE Installation      │
├──────────────────────────────────────────────┤
│  OS Version        ←→  Container Runtime     │
│  Container Runtime ←→  Kubernetes Version    │
│  Kubernetes        ←→  CNI Plugin Version    │
│  CNI Plugin        ←→  Kernel Version        │
└──────────────────────────────────────────────┘
```

**Common Issues:**

| Problem | Cause |
|---------|-------|
| kubeadm fails | OS too new/old for K8s version |
| Pods stuck Pending | CNI not compatible |
| Network issues | Kernel missing features |
| containerd errors | Cgroups v1 vs v2 mismatch |

**Always check:**

```bash
# Kubernetes version skew policy
# Control plane: can be +/- 1 minor version
# kubelet: can be up to 2 minor versions behind

kubectl version
kubeadm version
kubelet --version
containerd --version
```

---

### Cost Management

!!! warning "Cloud K8s is Expensive"
    A simple 3-node cluster can cost **$200-500/month** on major clouds.

    Production HA (6+ nodes) easily reaches **$1000+/month**.

**Cost-Saving Strategies:**

| Strategy | Savings | Trade-off |
|----------|---------|-----------|
| Spot/Preemptible instances | 60-80% | Can be terminated |
| Cluster autoscaler | Variable | Cold start latency |
| Right-sizing | 20-40% | Requires monitoring |
| Reserved instances | 30-50% | Commitment required |
| Namespace quotas | Prevents waste | Limits flexibility |

**Tools for Cost Optimization:**

- **Cast AI** - Automated cost optimization
- **Kubecost** - Cost monitoring and allocation
- **Karpenter** - Smart node provisioning (AWS)
- **Goldilocks** - Right-sizing recommendations

---

## CKA Topics Checklist

| Domain | Weight | Key Skills |
|--------|--------|------------|
| Cluster Architecture | 25% | Install, upgrade, ETCD backup |
| Workloads & Scheduling | 15% | Deployments, DaemonSets, taints |
| Services & Networking | 20% | Services, Ingress, NetworkPolicy |
| Storage | 10% | PV, PVC, StorageClass |
| Troubleshooting | 30% | Logs, events, node issues |

### Must-Know Commands

```bash
# Cluster info
kubectl cluster-info
kubectl get nodes -o wide
kubectl get componentstatuses

# Quick pod creation
kubectl run nginx --image=nginx --port=80
kubectl run busybox --image=busybox --rm -it -- sh

# Expose service
kubectl expose pod nginx --port=80 --type=NodePort

# Generate YAML (don't write from scratch!)
kubectl run nginx --image=nginx --dry-run=client -o yaml > pod.yaml
kubectl create deployment nginx --image=nginx --dry-run=client -o yaml

# Troubleshooting
kubectl describe pod <name>
kubectl logs <pod> -f
kubectl exec -it <pod> -- sh
kubectl get events --sort-by='.lastTimestamp'

# ETCD backup (critical!)
ETCDCTL_API=3 etcdctl snapshot save /backup/etcd.db \
  --endpoints=https://127.0.0.1:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/server.crt \
  --key=/etc/kubernetes/pki/etcd/server.key
```

---

## Study Resources

| Resource | Type | Cost |
|----------|------|------|
| Killer.sh | Practice exams (included with CKA) | Free with exam |
| KodeKloud | Video course + labs | Paid |
| Kubernetes docs | Official reference | Free |
| kubectl explain | Built-in help | Free |

!!! tip "The kubectl explain Trick"
    ```bash
    # Don't memorize YAML structure
    kubectl explain pod.spec.containers
    kubectl explain deployment.spec.strategy
    kubectl explain --recursive pod.spec
    ```
