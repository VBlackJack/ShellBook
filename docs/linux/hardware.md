# Server Hardware Fundamentals

`#hardware` `#bare-metal` `#power` `#acpi`

Understanding the metal beneath the virtualization.

---

## Why Hardware Matters

!!! info "Even for Cloud Admins"
    Understanding hardware helps you:

    - Diagnose performance bottlenecks
    - Right-size cloud instances
    - Understand why "noisy neighbors" affect VMs
    - Optimize for cost vs performance
    - Troubleshoot bare-metal deployments

---

## Power & Energy (PSU)

### Redundancy (2x PSU)

Production servers have **dual power supplies** for fault tolerance.

```
┌─────────────────────────────────────────┐
│              SERVER                      │
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

**Why dual PSUs:**

| Scenario | Single PSU | Dual PSU |
|----------|------------|----------|
| PSU failure | Server down | Continues running |
| Circuit trip | Server down | Continues running |
| Maintenance | Downtime required | Hot-swap capable |

!!! warning "Active-Active vs Active-Standby"
    - **Active-Active:** Both PSUs share load (more efficient)
    - **Active-Standby:** One PSU idle until failure (simpler)

---

### Efficiency (80 Plus Certification)

PSUs waste energy as heat. Efficiency ratings indicate how much power reaches components.

| Certification | Efficiency @ 50% Load | Typical Use |
|---------------|----------------------|-------------|
| 80 Plus | 80% | Budget |
| Bronze | 85% | Entry-level servers |
| Silver | 88% | Standard servers |
| Gold | 90% | Enterprise |
| Platinum | 92% | High-density DC |
| Titanium | 94% | Premium/HPC |

**Example:** 1000W server with Gold PSU
- Draws ~1111W from wall (90% efficient)
- Wastes 111W as heat

**At scale (1000 servers):**
- Bronze: 176kW wasted
- Titanium: 64kW wasted
- Savings: 112kW → ~$100k/year

---

### Power Connectors

| Connector | Purpose | Typical Wattage |
|-----------|---------|-----------------|
| **24-pin ATX** | Motherboard main | N/A (required) |
| **8-pin EPS** | CPU power | 150-300W per |
| **6-pin PCIe** | GPU | 75W |
| **8-pin PCIe** | GPU | 150W |
| **6+2 pin PCIe** | GPU (flexible) | 75-150W |

```bash
# Check power consumption on Linux
cat /sys/class/power_supply/*/power_now  # Laptops
ipmitool sensor | grep -i watt           # Servers with IPMI
```

---

## Cooling Strategies

### Air Cooling

Standard for most servers. Fans push air through heatsinks.

```
   INTAKE (Cold)              EXHAUST (Hot)
      │                           │
      ▼                           ▼
┌─────────────────────────────────────────┐
│ ████  │ CPU  │ RAM │ RAM │ PSU │  ████  │
│ FANS  │ ▓▓▓  │     │     │     │  FANS  │
│ ████  │ ▓▓▓  │     │     │     │  ████  │
└─────────────────────────────────────────┘
          ──────────────────►
              AIRFLOW
```

**Push vs Pull:**

| Config | Description | Use Case |
|--------|-------------|----------|
| Push | Fans before heatsink | Standard |
| Pull | Fans after heatsink | Tight spaces |
| Push-Pull | Both sides | High TDP CPUs |

---

### Water/Liquid Cooling

Used for high-density and HPC environments.

**Advantages:**

- 1000x better heat transfer than air
- Quieter operation
- Higher density possible
- Can handle 300W+ CPUs

**Disadvantages:**

- Cost
- Complexity
- Leak risk
- Maintenance

---

### Datacenter Scale (Hot/Cold Aisle)

```
       COLD AISLE              HOT AISLE             COLD AISLE
┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐
│                  │    │                  │    │                  │
│  ┌────┐  ┌────┐  │    │  ┌────┐  ┌────┐  │    │  ┌────┐  ┌────┐  │
│  │RACK│  │RACK│  │    │  │RACK│  │RACK│  │    │  │RACK│  │RACK│  │
│  │    │  │    │  │    │  │ ◄──┼──┼──► │  │    │  │    │  │    │  │
│  │ ►  │  │ ►  │  │    │  │    │  │    │  │    │  │ ◄  │  │ ◄  │  │
│  └────┘  └────┘  │    │  └────┘  └────┘  │    │  └────┘  └────┘  │
│                  │    │                  │    │                  │
│   ▲ COLD AIR ▲   │    │   ▲ HOT AIR ▲    │    │   ▲ COLD AIR ▲   │
└──────────────────┘    └──────────────────┘    └──────────────────┘
        ▲                       │                       ▲
        │                       ▼                       │
        │                 ┌──────────┐                  │
        └─────────────────│   CRAC   │──────────────────┘
                          │  (A/C)   │
                          └──────────┘
```

**Containment strategies:**

- Cold aisle containment (enclose cold)
- Hot aisle containment (enclose hot, more common)
- Chimney cabinets

---

## Performance vs Economy

### C-States (CPU Sleep States)

CPUs can enter sleep states to save power—but wake-up adds latency.

| State | Name | Power | Wake Latency |
|-------|------|-------|--------------|
| C0 | Active | 100% | 0 |
| C1 | Halt | ~70% | ~1μs |
| C1E | Enhanced Halt | ~60% | ~10μs |
| C3 | Sleep | ~30% | ~50μs |
| C6 | Deep Sleep | ~10% | ~100-200μs |

!!! warning "Latency-Sensitive Workloads"
    Deep C-States can cause latency spikes:

    - Trading systems
    - Real-time audio/video
    - Gaming servers
    - Database transactions

---

### ACPI (Advanced Configuration & Power Interface)

The standard that lets Linux control hardware power management.

```bash
# Check current CPU frequency
cat /proc/cpuinfo | grep MHz

# View available governors
cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_available_governors

# Current governor
cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor

# Set performance mode
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

# Check C-state residency
cat /sys/devices/system/cpu/cpu0/cpuidle/state*/name
cat /sys/devices/system/cpu/cpu0/cpuidle/state*/time
```

**CPU Governors:**

| Governor | Behavior | Use Case |
|----------|----------|----------|
| `performance` | Max frequency always | Low-latency, HPC |
| `powersave` | Min frequency always | Battery/efficiency |
| `ondemand` | Scale with load (fast) | General purpose |
| `conservative` | Scale with load (gradual) | Laptops |
| `schedutil` | Kernel scheduler-based | Modern default |

---

### Tuning for Performance

**Disable C-States (BIOS or Kernel):**

```bash
# Kernel boot parameter (GRUB)
# Edit /etc/default/grub
GRUB_CMDLINE_LINUX="intel_idle.max_cstate=0 processor.max_cstate=0"

# Apply
sudo update-grub
sudo reboot
```

**Force Performance Governor:**

```bash
# Temporary
sudo cpupower frequency-set -g performance

# Persistent (systemd)
# /etc/systemd/system/cpu-performance.service
[Unit]
Description=Set CPU Governor to Performance

[Service]
Type=oneshot
ExecStart=/usr/bin/cpupower frequency-set -g performance

[Install]
WantedBy=multi-user.target
```

**Disable Turbo Boost (for consistency):**

```bash
# Intel
echo 1 | sudo tee /sys/devices/system/cpu/intel_pstate/no_turbo

# AMD
echo 0 | sudo tee /sys/devices/system/cpu/cpufreq/boost
```

---

### Monitoring Tools

```bash
# CPU frequency and governor
cpupower frequency-info
watch -n1 "cat /proc/cpuinfo | grep MHz"

# Power consumption (Intel)
sudo turbostat --Summary --show Busy%,Bzy_MHz,PkgWatt

# Temperature
sensors                           # lm-sensors package
cat /sys/class/thermal/thermal_zone*/temp

# IPMI sensors (servers)
ipmitool sensor list
ipmitool sdr list
```

---

## Quick Reference

| Task | Command |
|------|---------|
| Check CPU freq | `cat /proc/cpuinfo \| grep MHz` |
| View governors | `cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_available_governors` |
| Set performance | `echo performance \| sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor` |
| Check temperature | `sensors` |
| Power monitoring | `sudo turbostat` |
| IPMI sensors | `ipmitool sensor list` |
| Disable turbo (Intel) | `echo 1 \| sudo tee /sys/devices/system/cpu/intel_pstate/no_turbo` |
