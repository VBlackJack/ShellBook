---
tags:
  - windows
  - security
  - hardening
  - secnumcloud
---

# Windows Security

Sécurisation et audit des systèmes Windows (Blue Team).

---

## Vue d'Ensemble

![Windows Security Stack Layers](../../assets/diagrams/windows-security-stack-layers.jpeg)

---

## Guides de Sécurité

| Guide | Description | Niveau |
|-------|-------------|--------|
| [Firewall & Defender](firewall-defender.md) | Windows Firewall, Defender AV, règles et exclusions | Débutant |
| [LAPS](laps.md) | Local Administrator Password Solution - Rotation automatique | Intermédiaire |
| [BitLocker](bitlocker.md) | Chiffrement disque, TPM, Network Unlock | Intermédiaire |
| [PKI Bootstrap](pki-bootstrap.md) | Certificats machine offline, ECDSA P-384, VPN pre-join | Avancé |
| [Hardening ANSSI](hardening-anssi.md) | GPO hardening, audit, conformité SecNumCloud | Avancé |

---

## Checklist Rapide SecNumCloud

### Critique (P0)

- [ ] **SMBv1 désactivé** - `Disable-WindowsOptionalFeature -FeatureName SMB1Protocol`
- [ ] **LLMNR désactivé** - Registre `EnableMulticast=0`
- [ ] **NBT-NS désactivé** - `SetTcpipNetbios(2)` sur toutes interfaces
- [ ] **Print Spooler désactivé** - `Set-Service Spooler -StartupType Disabled`
- [ ] **LAPS déployé** - Rotation mots de passe Admin local

### Important (P1)

- [ ] **BitLocker activé** - Chiffrement AES-256 (XtsAes256)
- [ ] **TLS 1.0/1.1 désactivés** - Forcer TLS 1.2+
- [ ] **Kerberos AES-256** - Désactiver RC4/DES
- [ ] **Event ID 4688 activé** - Audit Process Creation avec ligne de commande

### Recommandé (P2)

- [ ] **Network Unlock** - BitLocker auto-unlock sur LAN
- [ ] **Session timeouts RDP** - 15 min inactivité max
- [ ] **Télémétrie désactivée** - Tâches CEIP désactivées

---

## Commandes Essentielles

```powershell
# === ÉTAT SÉCURITÉ ===
Get-MpComputerStatus                    # Defender status
Get-BitLockerVolume                     # BitLocker status
Get-NetFirewallProfile                  # Firewall status

# === AUDIT RAPIDE ===
Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol  # SMBv1 ?
Get-SmbServerConfiguration | Select EnableSMB1Protocol
auditpol /get /category:*               # Audit policies

# === EVENTS SÉCURITÉ ===
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 10  # Failed logons
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4720} -MaxEvents 10  # User created
```

---

## Ressources

- [ANSSI - Recommandations de sécurité Windows](https://www.ssi.gouv.fr/guide/recommandations-de-securite-relatives-a-active-directory/)
- [Microsoft Security Baselines](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-security-baselines)
- [CIS Benchmarks Windows](https://www.cisecurity.org/benchmark/microsoft_windows_server)
