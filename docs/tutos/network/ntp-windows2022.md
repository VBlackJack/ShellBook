---
tags:
  - tutos
  - ntp
  - time
  - windows
---

# Windows Time Service sur Windows Server 2022

Configuration du service **W32Time** pour la synchronisation NTP.

| Composant | Version |
|-----------|---------|
| Windows Server | 2022 |
| W32Time | Intégré |

**Durée estimée :** 15 minutes

---

## 1. Vérifier la configuration actuelle

```powershell
# Status du service
Get-Service W32Time

# Configuration actuelle
w32tm /query /status
w32tm /query /configuration

# Source NTP
w32tm /query /source
```

---

## 2. Configurer un client NTP

### Serveur standalone (non AD)

```powershell
# Configurer les serveurs NTP
w32tm /config /manualpeerlist:"pool.ntp.org time.windows.com" /syncfromflags:manual /reliable:no /update

# Redémarrer le service
Restart-Service W32Time

# Forcer la synchronisation
w32tm /resync /force
```

### Membre d'un domaine AD

```powershell
# Par défaut, synchronise avec le DC
# Vérifier
w32tm /query /source

# Devrait afficher le DC
```

---

## 3. Configurer un serveur NTP (DC)

### PDC Emulator (source de temps du domaine)

```powershell
# Sur le PDC Emulator uniquement
w32tm /config /manualpeerlist:"0.pool.ntp.org 1.pool.ntp.org 2.pool.ntp.org" /syncfromflags:manual /reliable:yes /update

Restart-Service W32Time
w32tm /resync /force
```

### Vérifier le PDC Emulator

```powershell
# Trouver le PDC Emulator
Get-ADDomain | Select-Object PDCEmulator

# Ou
netdom query fsmo
```

---

## 4. Serveur NTP standalone

Pour servir l'heure à des clients non-AD :

```powershell
# Activer le mode serveur NTP
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpServer" -Name "Enabled" -Value 1

# Configurer la source
w32tm /config /manualpeerlist:"pool.ntp.org" /syncfromflags:manual /reliable:yes /update

# Redémarrer
Restart-Service W32Time

# Ouvrir le firewall
New-NetFirewallRule -DisplayName "NTP Server" -Direction Inbound -Protocol UDP -LocalPort 123 -Action Allow
```

---

## 5. Commandes de diagnostic

```powershell
# Status détaillé
w32tm /query /status /verbose

# Configuration
w32tm /query /configuration

# Tester un serveur NTP
w32tm /stripchart /computer:pool.ntp.org /samples:5

# Monitorer la synchronisation
w32tm /monitor

# Resynchroniser
w32tm /resync /force

# Réenregistrer le service
w32tm /unregister
w32tm /register
```

---

## 6. Configuration via GPO

Pour les environnements AD, utiliser les GPO :

```
Computer Configuration
└── Administrative Templates
    └── System
        └── Windows Time Service
            └── Time Providers
                └── Configure Windows NTP Client
                    - NtpServer: pool.ntp.org,0x9
                    - Type: NTP
                    - CrossSiteSyncFlags: 2
                    - ResolvePeerBackoffMinutes: 15
                    - ResolvePeerBackoffMaxTimes: 7
```

---

## 7. Registre (configuration avancée)

```powershell
# Chemin registre
$path = "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time"

# Voir la configuration
Get-ItemProperty "$path\Config"
Get-ItemProperty "$path\Parameters"
Get-ItemProperty "$path\TimeProviders\NtpClient"
Get-ItemProperty "$path\TimeProviders\NtpServer"

# Intervalle de synchronisation (en secondes)
Set-ItemProperty -Path "$path\TimeProviders\NtpClient" -Name "SpecialPollInterval" -Value 3600
```

---

## 8. Logs et événements

```powershell
# Événements W32Time
Get-WinEvent -LogName "Microsoft-Windows-Time-Service/Operational" -MaxEvents 20

# Ou dans l'Event Viewer
# Applications and Services Logs > Microsoft > Windows > Time-Service
```

---

## 9. Bonnes pratiques AD

```
Internet ──► PDC Emulator (stratum 2)
                    │
                    ├──► DC2 (stratum 3)
                    ├──► DC3 (stratum 3)
                    │
                    └──► Membres du domaine (stratum 4)
```

- Seul le PDC Emulator synchronise avec l'extérieur
- Les autres DC synchronisent avec le PDC
- Les membres synchronisent avec n'importe quel DC

---

## Dépannage

| Problème | Solution |
|----------|----------|
| Time skew | `w32tm /resync /force` |
| Source: Free-running | Configurer les serveurs NTP |
| Service ne démarre pas | `w32tm /unregister && w32tm /register` |

```powershell
# Debug complet
w32tm /debug /enable /file:C:\temp\w32time.log /size:10000000 /entries:0-300

# Arrêter le debug
w32tm /debug /disable
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
