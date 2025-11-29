---
tags:
  - formation
  - windows-server
  - securite
  - hardening
  - checklist
---

# Checklist de Sécurisation Windows Server

Cette checklist couvre les points essentiels de hardening pour Windows Server 2022.

---

## Installation et Configuration Initiale

### Système

- [ ] Installer uniquement les rôles/features nécessaires
- [ ] Utiliser Server Core quand possible
- [ ] Configurer les mises à jour automatiques ou WSUS
- [ ] Activer le chiffrement BitLocker sur les volumes système
- [ ] Configurer un mot de passe BIOS/UEFI
- [ ] Activer Secure Boot

### Réseau

- [ ] Renommer le serveur avec convention de nommage
- [ ] Configurer une IP statique
- [ ] Désactiver IPv6 si non utilisé
- [ ] Désactiver NetBIOS over TCP/IP
- [ ] Désactiver LLMNR
- [ ] Configurer les serveurs DNS internes

---

## Comptes et Authentification

### Comptes Locaux

- [ ] Renommer le compte Administrator
- [ ] Désactiver le compte Guest
- [ ] Déployer LAPS pour les mots de passe admin locaux
- [ ] Limiter les membres du groupe Administrators local

### Politique de Mots de Passe

- [ ] Longueur minimale : 14 caractères
- [ ] Complexité activée
- [ ] Historique : 24 derniers mots de passe
- [ ] Âge maximum : 90 jours (ou moins)
- [ ] Verrouillage après 5 tentatives échouées
- [ ] Durée de verrouillage : 30 minutes minimum

### Authentification

- [ ] Désactiver NTLM v1
- [ ] Restreindre NTLM v2 au minimum nécessaire
- [ ] Activer Credential Guard (si supporté)
- [ ] Configurer les comptes de service gérés (gMSA)

---

## Active Directory (si DC)

### Structure

- [ ] Implémenter le Tiering Model (Tier 0/1/2)
- [ ] Séparer les comptes admin des comptes utilisateurs
- [ ] Créer des OUs dédiées par type d'objet
- [ ] Protéger les OUs contre la suppression accidentelle

### Comptes Privilégiés

- [ ] Ajouter les admins au groupe Protected Users
- [ ] Utiliser des Privileged Access Workstations (PAW)
- [ ] Implémenter Just-In-Time (JIT) access si possible
- [ ] Auditer régulièrement les membres de Domain Admins
- [ ] Limiter les Enterprise Admins et Schema Admins

### GPO de Sécurité

- [ ] Bloquer l'héritage avec parcimonie
- [ ] Utiliser le filtrage de sécurité WMI
- [ ] Tester les GPO avant déploiement
- [ ] Documenter toutes les GPO

---

## Services et Applications

### Services

- [ ] Désactiver les services non utilisés
- [ ] Configurer les services en démarrage manuel si rarement utilisés
- [ ] Utiliser des comptes de service dédiés (pas LocalSystem)

**Services à désactiver si non nécessaires :**

```
RemoteRegistry
Fax
XboxGipSvc / XblAuthManager / XblGameSave
RetailDemo
WMPNetworkSvc
```

### Applications

- [ ] Supprimer les applications/rôles inutiles
- [ ] Maintenir les applications à jour
- [ ] Configurer AppLocker ou WDAC
- [ ] Activer Windows Defender avec protection temps réel

---

## Protocoles et Communications

### SMB

- [ ] Désactiver SMBv1
- [ ] Activer le chiffrement SMB
- [ ] Activer la signature SMB (obligatoire pour DC)
- [ ] Restreindre les partages administratifs si possible

```powershell
# Désactiver SMBv1
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart

# Vérifier
Get-SmbServerConfiguration | Select EnableSMB1Protocol, EnableSMB2Protocol

# Activer signature et chiffrement
Set-SmbServerConfiguration -RequireSecuritySignature $true -EnableSecuritySignature $true
Set-SmbServerConfiguration -EncryptData $true
```

### RDP

- [ ] Activer NLA (Network Level Authentication)
- [ ] Limiter les utilisateurs autorisés RDP
- [ ] Configurer un timeout de session
- [ ] Utiliser des certificats TLS valides
- [ ] Changer le port par défaut (optionnel, sécurité par obscurité)

```powershell
# Activer NLA
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1

# Vérifier le niveau de chiffrement
Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name SecurityLayer
```

### WinRM

- [ ] Activer HTTPS uniquement en production
- [ ] Configurer TrustedHosts avec parcimonie
- [ ] Utiliser l'authentification Kerberos

---

## Pare-feu et Réseau

### Windows Firewall

- [ ] Activer sur tous les profils (Domain, Private, Public)
- [ ] Bloquer les connexions entrantes par défaut
- [ ] Autoriser uniquement les ports nécessaires
- [ ] Journaliser les connexions bloquées

```powershell
# Vérifier l'état
Get-NetFirewallProfile | Select Name, Enabled

# Activer tous les profils
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

# Configurer la journalisation
Set-NetFirewallProfile -Profile Domain -LogBlocked True -LogFileName %systemroot%\system32\LogFiles\Firewall\pfirewall.log
```

### Règles Recommandées

- [ ] Bloquer ICMP entrant (sauf diagnostic)
- [ ] Restreindre RDP aux IPs de gestion
- [ ] Bloquer SMB (445) depuis l'extérieur
- [ ] Restreindre WinRM aux IPs de gestion

---

## Audit et Journalisation

### Politique d'Audit

- [ ] Activer l'audit des connexions (succès/échec)
- [ ] Activer l'audit des modifications de comptes
- [ ] Activer l'audit de l'accès aux objets sensibles
- [ ] Activer l'audit des modifications de GPO

```powershell
# Configurer via GPO ou localement
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
auditpol /set /category:"Account Management" /success:enable /failure:enable
auditpol /set /category:"Object Access" /success:enable /failure:enable
auditpol /set /category:"Policy Change" /success:enable /failure:enable

# Vérifier
auditpol /get /category:*
```

### Journaux

- [ ] Augmenter la taille des journaux (min 1 GB)
- [ ] Configurer la rétention (écraser si nécessaire)
- [ ] Centraliser les logs (SIEM, Event Forwarding)
- [ ] Surveiller les événements critiques

**Événements à Surveiller :**

| Event ID | Description |
|----------|-------------|
| 4624 | Connexion réussie |
| 4625 | Échec de connexion |
| 4648 | Connexion avec identifiants explicites |
| 4720 | Compte utilisateur créé |
| 4732 | Membre ajouté à un groupe local |
| 4756 | Membre ajouté à un groupe universel |
| 4768 | Ticket Kerberos TGT demandé |
| 4769 | Ticket Kerberos service demandé |
| 4771 | Échec pré-authentification Kerberos |

---

## Mises à Jour et Maintenance

### Windows Update

- [ ] Configurer WSUS ou Windows Update for Business
- [ ] Appliquer les mises à jour de sécurité mensuellement
- [ ] Tester les mises à jour avant déploiement en production
- [ ] Planifier les redémarrages hors heures de travail

### Maintenance

- [ ] Planifier des analyses antivirus complètes hebdomadaires
- [ ] Vérifier l'espace disque régulièrement
- [ ] Nettoyer les fichiers temporaires
- [ ] Réviser les comptes/groupes trimestriellement

---

## Sauvegarde et Récupération

### Stratégie de Backup

- [ ] Sauvegarder le System State quotidiennement
- [ ] Sauvegarder les données critiques
- [ ] Stocker les backups hors site
- [ ] Chiffrer les backups

### Tests

- [ ] Tester la restauration trimestriellement
- [ ] Documenter les procédures de DR
- [ ] Valider les RPO/RTO

---

## Vérification Automatisée

### Script de Vérification

```powershell
# check-hardening.ps1
# Script de vérification rapide du hardening

$results = @()

# SMBv1
$smb1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
$results += [PSCustomObject]@{
    Check = "SMBv1 désactivé"
    Status = if ($smb1.State -eq "Disabled") { "OK" } else { "FAIL" }
}

# Firewall
$fw = Get-NetFirewallProfile | Where-Object { $_.Enabled -eq $false }
$results += [PSCustomObject]@{
    Check = "Firewall activé tous profils"
    Status = if ($fw.Count -eq 0) { "OK" } else { "FAIL" }
}

# NLA pour RDP
$nla = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -ErrorAction SilentlyContinue
$results += [PSCustomObject]@{
    Check = "NLA activé pour RDP"
    Status = if ($nla.UserAuthentication -eq 1) { "OK" } else { "FAIL" }
}

# Guest désactivé
$guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
$results += [PSCustomObject]@{
    Check = "Compte Guest désactivé"
    Status = if ($guest.Enabled -eq $false) { "OK" } else { "FAIL" }
}

# Windows Defender
$defender = Get-MpComputerStatus -ErrorAction SilentlyContinue
$results += [PSCustomObject]@{
    Check = "Windows Defender actif"
    Status = if ($defender.RealTimeProtectionEnabled) { "OK" } else { "FAIL" }
}

# Afficher les résultats
$results | Format-Table -AutoSize

# Résumé
$passed = ($results | Where-Object { $_.Status -eq "OK" }).Count
$total = $results.Count
Write-Host "`nRésultat: $passed/$total vérifications passées" -ForegroundColor $(if ($passed -eq $total) { "Green" } else { "Yellow" })
```

---

## Références

- [CIS Benchmarks for Windows Server](https://www.cisecurity.org/benchmark/microsoft_windows_server)
- [Microsoft Security Baselines](https://docs.microsoft.com/windows/security/threat-protection/windows-security-baselines)
- [ANSSI - Recommandations Windows](https://www.ssi.gouv.fr/guide/recommandations-de-securite-relatives-a-active-directory/)
- [NIST SP 800-123](https://csrc.nist.gov/publications/detail/sp/800-123/final)

---

**Retour au :** [Programme de la Formation](index.md)
