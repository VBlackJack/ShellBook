# Principes Fondamentaux du Matériel Serveur

`#hardware` `#bare-metal` `#power` `#acpi`

Comprendre le métal sous la virtualisation.

---

## Pourquoi le Matériel est Important

!!! info "Même pour les Admins Cloud"
    Comprendre le matériel vous aide à :

    - Diagnostiquer les goulots d'étranglement de performance
    - Dimensionner correctement les instances cloud
    - Comprendre pourquoi les "noisy neighbors" affectent les VMs
    - Optimiser pour le coût vs performance
    - Dépanner les déploiements bare-metal

---

## Alimentation & Énergie (PSU)

### Redondance (2x PSU)

Les serveurs de production ont des **alimentations doubles** pour la tolérance aux pannes.

```
┌─────────────────────────────────────────┐
│              SERVEUR                     │
│  ┌─────────┐           ┌─────────┐      │
│  │  PSU 1  │           │  PSU 2  │      │
│  └────┬────┘           └────┬────┘      │
│       │                     │           │
└───────┼─────────────────────┼───────────┘
        │                     │
        ▼                     ▼
   ┌─────────┐           ┌─────────┐
   │ PDU A   │           │ PDU B   │
   │(Circuit)│           │(Circuit)│
   └─────────┘           └─────────┘
```

**Pourquoi des PSU doubles :**

| Scénario | PSU Simple | PSU Double |
|----------|------------|----------|
| Panne de PSU | Serveur arrêté | Continue de fonctionner |
| Disjonction du circuit | Serveur arrêté | Continue de fonctionner |
| Maintenance | Temps d'arrêt requis | Remplacement à chaud possible |

!!! warning "Active-Active vs Active-Standby"
    - **Active-Active :** Les deux PSU partagent la charge (plus efficace)
    - **Active-Standby :** Un PSU inactif jusqu'à la panne (plus simple)

---

### Efficacité (Certification 80 Plus)

Les PSU gaspillent de l'énergie sous forme de chaleur. Les classifications d'efficacité indiquent quelle quantité d'énergie atteint les composants.

| Certification | Efficacité @ 50% de Charge | Usage Typique |
|---------------|----------------------|-------------|
| 80 Plus | 80% | Budget |
| Bronze | 85% | Serveurs d'entrée de gamme |
| Silver | 88% | Serveurs standard |
| Gold | 90% | Enterprise |
| Platinum | 92% | DC haute densité |
| Titanium | 94% | Premium/HPC |

**Exemple :** Serveur 1000W avec PSU Gold
- Consomme ~1111W du secteur (90% efficace)
- Gaspille 111W en chaleur

**À grande échelle (1000 serveurs) :**
- Bronze : 176kW gaspillés
- Titanium : 64kW gaspillés
- Économies : 112kW → ~100k$/an

---

### Connecteurs d'Alimentation

| Connecteur | Usage | Puissance Typique |
|-----------|---------|-----------------|
| **24-pin ATX** | Carte mère principale | N/A (requis) |
| **8-pin EPS** | Alimentation CPU | 150-300W par |
| **6-pin PCIe** | GPU | 75W |
| **8-pin PCIe** | GPU | 150W |
| **6+2 pin PCIe** | GPU (flexible) | 75-150W |

```bash
# Vérifier la consommation électrique sur Linux
cat /sys/class/power_supply/*/power_now  # Portables
ipmitool sensor | grep -i watt           # Serveurs avec IPMI
```

---

## Stratégies de Refroidissement

### Refroidissement par Air

Standard pour la plupart des serveurs. Les ventilateurs poussent l'air à travers les dissipateurs thermiques.

```
   ENTRÉE (Froid)              ÉCHAPPEMENT (Chaud)
      │                           │
      ▼                           ▼
┌─────────────────────────────────────────┐
│ ████  │ CPU  │ RAM │ RAM │ PSU │  ████  │
│ FANS  │ ▓▓▓  │     │     │     │  FANS  │
│ ████  │ ▓▓▓  │     │     │     │  ████  │
└─────────────────────────────────────────┘
          ──────────────────►
              FLUX D'AIR
```

**Push vs Pull :**

| Config | Description | Cas d'Usage |
|--------|-------------|----------|
| Push | Ventilateurs avant le dissipateur | Standard |
| Pull | Ventilateurs après le dissipateur | Espaces restreints |
| Push-Pull | Des deux côtés | CPU haute TDP |

---

### Refroidissement par Eau/Liquide

Utilisé pour les environnements haute densité et HPC.

**Avantages :**

- Transfert de chaleur 1000x meilleur que l'air
- Fonctionnement plus silencieux
- Densité plus élevée possible
- Peut gérer des CPU de 300W+

**Inconvénients :**

- Coût
- Complexité
- Risque de fuite
- Maintenance

---

### Échelle Datacenter (Allée Chaude/Froide)

```
       ALLÉE FROIDE            ALLÉE CHAUDE          ALLÉE FROIDE
┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐
│                  │    │                  │    │                  │
│  ┌────┐  ┌────┐  │    │  ┌────┐  ┌────┐  │    │  ┌────┐  ┌────┐  │
│  │RACK│  │RACK│  │    │  │RACK│  │RACK│  │    │  │RACK│  │RACK│  │
│  │    │  │    │  │    │  │ ◄──┼──┼──► │  │    │  │    │  │    │  │
│  │ ►  │  │ ►  │  │    │  │    │  │    │  │    │  │ ◄  │  │ ◄  │  │
│  └────┘  └────┘  │    │  └────┘  └────┘  │    │  └────┘  └────┘  │
│                  │    │                  │    │                  │
│   ▲ AIR FROID ▲  │    │   ▲ AIR CHAUD ▲  │    │   ▲ AIR FROID ▲  │
└──────────────────┘    └──────────────────┘    └──────────────────┘
        ▲                       │                       ▲
        │                       ▼                       │
        │                 ┌──────────┐                  │
        └─────────────────│   CRAC   │──────────────────┘
                          │  (A/C)   │
                          └──────────┘
```

**Stratégies de confinement :**

- Confinement d'allée froide (enfermer le froid)
- Confinement d'allée chaude (enfermer le chaud, plus courant)
- Armoires cheminées

---

## Performance vs Économie

### C-States (États de Veille CPU)

Les CPU peuvent entrer dans des états de veille pour économiser l'énergie—mais le réveil ajoute de la latence.

| État | Nom | Puissance | Latence de Réveil |
|-------|------|-------|--------------|
| C0 | Actif | 100% | 0 |
| C1 | Halt | ~70% | ~1μs |
| C1E | Enhanced Halt | ~60% | ~10μs |
| C3 | Sleep | ~30% | ~50μs |
| C6 | Deep Sleep | ~10% | ~100-200μs |

!!! warning "Charges de Travail Sensibles à la Latence"
    Les C-States profonds peuvent causer des pics de latence :

    - Systèmes de trading
    - Audio/vidéo en temps réel
    - Serveurs de jeux
    - Transactions de base de données

---

### ACPI (Advanced Configuration & Power Interface)

Le standard qui permet à Linux de contrôler la gestion d'alimentation du matériel.

```bash
# Vérifier la fréquence CPU actuelle
cat /proc/cpuinfo | grep MHz

# Voir les governors disponibles
cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_available_governors

# Governor actuel
cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor

# Définir le mode performance
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

# Vérifier la résidence des C-states
cat /sys/devices/system/cpu/cpu0/cpuidle/state*/name
cat /sys/devices/system/cpu/cpu0/cpuidle/state*/time
```

**Governors CPU :**

| Governor | Comportement | Cas d'Usage |
|----------|----------|----------|
| `performance` | Fréquence max toujours | Faible latence, HPC |
| `powersave` | Fréquence min toujours | Batterie/efficacité |
| `ondemand` | Échelle avec la charge (rapide) | Usage général |
| `conservative` | Échelle avec la charge (graduel) | Portables |
| `schedutil` | Basé sur le planificateur du noyau | Défaut moderne |

---

### Optimisation pour la Performance

**Désactiver les C-States (BIOS ou Kernel) :**

```bash
# Paramètre de démarrage du noyau (GRUB)
# Éditer /etc/default/grub
GRUB_CMDLINE_LINUX="intel_idle.max_cstate=0 processor.max_cstate=0"

# Appliquer
sudo update-grub
sudo reboot
```

**Forcer le Governor Performance :**

```bash
# Temporaire
sudo cpupower frequency-set -g performance

# Persistant (systemd)
# /etc/systemd/system/cpu-performance.service
[Unit]
Description=Set CPU Governor to Performance

[Service]
Type=oneshot
ExecStart=/usr/bin/cpupower frequency-set -g performance

[Install]
WantedBy=multi-user.target
```

**Désactiver le Turbo Boost (pour la cohérence) :**

```bash
# Intel
echo 1 | sudo tee /sys/devices/system/cpu/intel_pstate/no_turbo

# AMD
echo 0 | sudo tee /sys/devices/system/cpu/cpufreq/boost
```

---

### Outils de Surveillance

```bash
# Fréquence CPU et governor
cpupower frequency-info
watch -n1 "cat /proc/cpuinfo | grep MHz"

# Consommation électrique (Intel)
sudo turbostat --Summary --show Busy%,Bzy_MHz,PkgWatt

# Température
sensors                           # paquet lm-sensors
cat /sys/class/thermal/thermal_zone*/temp

# Capteurs IPMI (serveurs)
ipmitool sensor list
ipmitool sdr list
```

---

## Référence Rapide

| Tâche | Commande |
|------|---------|
| Vérifier fréquence CPU | `cat /proc/cpuinfo \| grep MHz` |
| Voir les governors | `cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_available_governors` |
| Définir performance | `echo performance \| sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor` |
| Vérifier température | `sensors` |
| Surveillance puissance | `sudo turbostat` |
| Capteurs IPMI | `ipmitool sensor list` |
| Désactiver turbo (Intel) | `echo 1 \| sudo tee /sys/devices/system/cpu/intel_pstate/no_turbo` |
