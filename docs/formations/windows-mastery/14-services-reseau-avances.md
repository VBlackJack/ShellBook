---
tags:
  - formation
  - windows-server
  - pki
  - radius
  - vpn
---

# Module 14 : Services Réseau Avancés

## Objectifs du Module

Ce module couvre les services réseau avancés Windows Server :

- Déployer une PKI (Public Key Infrastructure)
- Configurer NPS/RADIUS pour l'authentification réseau
- Implémenter DirectAccess/Always On VPN
- Configurer Web Application Proxy

**Durée :** 8 heures

**Niveau :** Ingénierie

---

## 1. PKI - Certificate Services

### 1.1 Architecture PKI

```
ARCHITECTURE PKI RECOMMANDÉE
────────────────────────────

Root CA (Offline)
├── Hors ligne, air-gapped
├── Durée de vie: 20 ans
└── Émet uniquement pour Subordinate CAs

Subordinate CA (Enterprise, Online)
├── Intégré à AD
├── Durée de vie: 10 ans
└── Émet les certificats pour:
    ├── Utilisateurs (Smart Card, Email)
    ├── Ordinateurs (IPsec, 802.1X)
    ├── Serveurs (Web, RDP)
    └── Services (Code Signing)
```

### 1.2 Installation CA Enterprise

```powershell
# Installer le rôle
Install-WindowsFeature -Name AD-Certificate, ADCS-Cert-Authority, ADCS-Web-Enrollment -IncludeManagementTools

# Configurer la CA
Install-AdcsCertificationAuthority `
    -CAType EnterpriseRootCA `
    -CryptoProviderName "RSA#Microsoft Software Key Storage Provider" `
    -KeyLength 4096 `
    -HashAlgorithmName SHA256 `
    -CACommonName "Corp Enterprise CA" `
    -ValidityPeriod Years `
    -ValidityPeriodUnits 10 `
    -Force

# Configurer l'inscription web
Install-AdcsWebEnrollment -Force

# Configurer les URLs de publication
# AIA (Authority Information Access)
# CDP (CRL Distribution Point)
```

### 1.3 Gestion des Certificats

```powershell
# Lister les templates
Get-CATemplate

# Publier un template
Add-CATemplate -Name "WebServer" -Force

# Demander un certificat
Get-Certificate -Template "WebServer" -DnsName "web.corp.local" -CertStoreLocation Cert:\LocalMachine\My

# Exporter un certificat
$cert = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object Subject -like "*web.corp.local*"
Export-PfxCertificate -Cert $cert -FilePath "C:\Certs\web.pfx" -Password (ConvertTo-SecureString "P@ss!" -AsPlainText -Force)

# Révoquer un certificat
# Via certsrv.msc ou GUI
```

---

## 2. NPS/RADIUS

### 2.1 Installation

```powershell
# Installer NPS
Install-WindowsFeature -Name NPAS -IncludeManagementTools

# Enregistrer dans AD
netsh ras add registeredserver

# Ou via PowerShell
$computer = Get-ADComputer -Identity $env:COMPUTERNAME
$group = Get-ADGroup "RAS and IAS Servers"
Add-ADGroupMember -Identity $group -Members $computer
```

### 2.2 Configuration RADIUS

```powershell
# Ajouter un client RADIUS (switch, AP WiFi)
New-NpsRadiusClient -Name "WiFi-AP-01" `
    -Address "192.168.1.100" `
    -SharedSecret "SuperSecretKey123!" `
    -VendorName "RADIUS Standard"

# Créer une politique de connexion
# Se fait généralement via la console NPS (nps.msc)

# Exemple de politique pour WiFi 802.1X:
# 1. Conditions: Windows Groups = "Domain Users", NAS Port Type = Wireless
# 2. Contraintes: Auth Methods = PEAP-MSCHAPv2
# 3. Settings: RADIUS Attributes selon le switch
```

### 2.3 Configuration 802.1X

```powershell
# Sur le serveur NPS, créer:
# 1. Connection Request Policy
# 2. Network Policy pour WiFi/Wired

# Template de politique réseau pour WiFi:
# Conditions:
#   - NAS Port Type: Wireless - IEEE 802.11
#   - Windows Groups: WiFi-Users
# Constraints:
#   - Authentication Methods: Microsoft: Protected EAP (PEAP)
# Settings:
#   - RADIUS Attributes: vendor-specific selon équipement
```

---

## 3. VPN et DirectAccess

### 3.1 Always On VPN (Recommandé)

```powershell
# Installer RRAS
Install-WindowsFeature -Name RemoteAccess -IncludeManagementTools
Install-WindowsFeature -Name DirectAccess-VPN -IncludeManagementTools

# Installer le module VPN
Install-RemoteAccess -VpnType VpnS2S

# Configurer IKEv2
Add-VpnS2SInterface -Name "HQ-Branch" `
    -Protocol IKEv2 `
    -Destination "vpn.corp.local" `
    -AdminStatus $true

# Configuration client (via GPO ou Intune)
# ProfileXML pour Always On VPN
$ProfileXML = @"
<VPNProfile>
    <NativeProfile>
        <Servers>vpn.corp.local</Servers>
        <NativeProtocolType>IKEv2</NativeProtocolType>
        <Authentication>
            <UserMethod>Eap</UserMethod>
        </Authentication>
    </NativeProfile>
    <AlwaysOn>true</AlwaysOn>
    <DeviceTunnel>true</DeviceTunnel>
</VPNProfile>
"@
```

### 3.2 DirectAccess (Legacy)

```powershell
# Installation
Install-WindowsFeature -Name DirectAccess-VPN -IncludeManagementTools

# Configuration initiale via GUI recommandée
# Remote Access Management Console (ramgmtui.exe)

# Vérifier l'état
Get-RemoteAccessHealth
Get-DAClientExperienceConfiguration
```

---

## 4. Web Application Proxy

### 4.1 Installation

```powershell
# Installer WAP
Install-WindowsFeature -Name Web-Application-Proxy -IncludeManagementTools

# Configurer WAP (nécessite ADFS)
Install-WebApplicationProxy `
    -FederationServiceName "adfs.corp.local" `
    -FederationServiceTrustCredential (Get-Credential)
```

### 4.2 Publier une Application

```powershell
# Publier une application web
Add-WebApplicationProxyApplication `
    -Name "OWA" `
    -ExternalUrl "https://mail.corp.com/owa" `
    -BackendServerUrl "https://exchange.corp.local/owa" `
    -ExternalPreAuthentication ADFS `
    -ADFSRelyingPartyName "OWA"

# Publier sans pré-authentification (pass-through)
Add-WebApplicationProxyApplication `
    -Name "InternalWeb" `
    -ExternalUrl "https://web.corp.com/" `
    -BackendServerUrl "https://web.corp.local/" `
    -ExternalPreAuthentication PassThrough
```

---

## 5. Exercice Pratique

### Déployer une PKI Simple

```powershell
# 1. Installer CA Enterprise
Install-WindowsFeature -Name AD-Certificate, ADCS-Cert-Authority -IncludeManagementTools

Install-AdcsCertificationAuthority `
    -CAType EnterpriseRootCA `
    -CryptoProviderName "RSA#Microsoft Software Key Storage Provider" `
    -KeyLength 2048 `
    -HashAlgorithmName SHA256 `
    -CACommonName "Lab CA" `
    -ValidityPeriod Years `
    -ValidityPeriodUnits 5 `
    -Force

# 2. Configurer auto-enrollment via GPO
# Computer Configuration → Policies → Windows Settings → Security Settings → Public Key Policies
# - Certificate Services Client - Auto-Enrollment: Enabled

# 3. Vérifier
certutil -CAInfo
Get-ChildItem Cert:\LocalMachine\My
```

---

## Quiz

1. **Quelle est la durée recommandée pour une Root CA ?**
   - [ ] A. 5 ans
   - [ ] B. 10 ans
   - [ ] C. 20 ans

2. **Quel protocole utilise NPS pour l'authentification réseau ?**
   - [ ] A. LDAP
   - [ ] B. RADIUS
   - [ ] C. Kerberos

**Réponses :** 1-C, 2-B

---

**Précédent :** [Module 13 : Sécurité & Hardening](13-securite-hardening.md)

**Suivant :** [Module 15 : Backup & Disaster Recovery](15-backup-disaster-recovery.md)
