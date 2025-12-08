---
tags:
  - kernel
  - debugging
  - crash
  - performance
  - ebpf
---

# Kernel Debugging & Troubleshooting

Quand `top` et `htop` ne suffisent plus. Comment analyser un système qui freeze, qui panic, ou qui ralentit sans raison visible.

## 1. Magic SysRq Keys : Le Kit de Survie

Si le serveur est freezé (plus de SSH, plus de clavier), le noyau écoute peut-être encore. Les **Magic SysRq** permettent d'envoyer des commandes directement au kernel.

**Activation :**
```bash
# Vérifier si activé (1 = tout activé)
cat /proc/sys/kernel/sysrq

# Activer temporairement
echo 1 > /proc/sys/kernel/sysrq
```

**Utilisation :**
Appuyer sur `ALT` + `ImpÉcran` (SysRq) + `Lettre`.

| Lettre | Action | Mnémonique |
|--------|--------|------------|
| **R** | **R**aw | Reprendre le contrôle du clavier (si Xorg planté). |
| **E** | t**E**rminate | Envoie SIGTERM à tous les processus (sauf init). |
| **I** | k**I**ll | Envoie SIGKILL à tous les processus (brutal). |
| **S** | **S**ync | Écrit les données en cache sur le disque (Sauve les meubles !). |
| **U** | **U**nmount | Remonte les disques en lecture seule. |
| **B** | re**B**oot | Redémarre la machine immédiatement. |

> **Séquence REISUB** : La méthode propre pour redémarrer un serveur planté sans corrompre le disque ("Reboot Even If System Utterly Broken").

## 2. Kdump & Crash : Analyser un Kernel Panic

Pourquoi mon serveur a-t-il redémarré cette nuit ? Sans **kdump**, vous ne le saurez jamais.

### Principe
Kdump réserve un petit bout de RAM au démarrage. En cas de crash, un mini-kernel se lance dans cette RAM réservée pour copier la mémoire vive (le dump `vmcore`) sur le disque.

### Installation (RHEL/CentOS)
```bash
dnf install kexec-tools crash
systemctl enable --now kdump
```

### Analyse post-mortem
Une fois le fichier `vmcore` généré dans `/var/crash/`, on l'analyse avec l'outil `crash`.

```bash
crash /usr/lib/debug/lib/modules/$(uname -r)/vmlinux /var/crash/127.0.0.1-2024.../vmcore

# Dans le shell crash :
crash> log           # Voir les derniers logs avant la mort (dmesg)
crash> bt            # Backtrace (la pile d'appel qui a mené au crash)
crash> ps            # Liste des processus au moment du crash
```

## 3. Taint Kernel : "C'est pas ma faute"

Si vous voyez "Tainted: G" dans vos logs, le kernel vous dit qu'il n'est plus dans un état supporté.

*   `P` : Module propriétaire chargé (Nvidia, VMWare).
*   `F` : Module forcé (version incompatible).
*   `O` : Module out-of-tree (compilé à la main).
*   `E` : Un module non signé a été chargé.

```bash
# Vérifier l'état
cat /proc/sys/kernel/tainted
# 0 = Clean
```

## 4. eBPF : Le Futur du Tracing

Oubliez `strace` (qui ralentit l'application). **eBPF** (Extended Berkeley Packet Filter) permet d'exécuter du code sandboxé directement dans le kernel pour observer sans impacter.

**Outils BCC (BPF Compiler Collection) :**
Des scripts prêts à l'emploi pour tout analyser.

```bash
sudo apt install bpfcc-tools

# Qui ouvre quels fichiers ? (Top des I/O disque)
sudo opensnoop-bpfcc

# Quelle commande Bash est exécutée ? (Espionnage)
sudo execsnoop-bpfcc

# Latence des disques (Histogramme)
sudo biolatency-bpfcc

# Qui écoute sur le réseau ?
sudo solisten-bpfcc
```

> **Note** : Ces outils voient TOUT, même les conteneurs Docker et les processus éphémères.
