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

## Exercice : À Vous de Jouer

!!! example "Mise en Pratique"
    **Objectif** : Déployer une PKI d'entreprise et configurer un serveur RADIUS pour l'authentification Wi-Fi

    **Contexte** : Votre entreprise souhaite sécuriser son réseau Wi-Fi avec une authentification 802.1X basée sur RADIUS/NPS. Vous devez également déployer une PKI pour émettre les certificats nécessaires aux utilisateurs et aux équipements réseau.

    **Tâches à réaliser** :

    1. Installer et configurer une CA Enterprise (Root CA)
    2. Configurer l'inscription web de certificats
    3. Créer un template de certificat pour l'authentification utilisateur
    4. Installer et configurer le rôle NPS (RADIUS)
    5. Créer un client RADIUS pour le point d'accès Wi-Fi (IP: 192.168.1.100)
    6. Configurer une politique réseau pour l'authentification 802.1X avec PEAP-MSCHAPv2
    7. Tester l'authentification et générer un rapport de configuration

    **Critères de validation** :

    - [ ] CA Enterprise installée et opérationnelle
    - [ ] Inscription web accessible via HTTPS
    - [ ] Template de certificat utilisateur créé et publié
    - [ ] NPS enregistré dans Active Directory
    - [ ] Client RADIUS configuré avec secret partagé
    - [ ] Politique réseau créée pour Wi-Fi avec groupe "Domain Users"
    - [ ] Test d'authentification réussi (simulation ou réel)

??? quote "Solution"
    **Étape 1 : Installation de la CA Enterprise**

    ```powershell
    # Installer le rôle AD CS
    Install-WindowsFeature -Name AD-Certificate, ADCS-Cert-Authority, ADCS-Web-Enrollment `
        -IncludeManagementTools

    # Configurer en tant que Root CA Enterprise
    $securePassword = Read-Host "Mot de passe pour la CA" -AsSecureString

    Install-AdcsCertificationAuthority `
        -CAType EnterpriseRootCA `
        -CryptoProviderName "RSA#Microsoft Software Key Storage Provider" `
        -KeyLength 4096 `
        -HashAlgorithmName SHA256 `
        -CACommonName "Corp Enterprise Root CA" `
        -ValidityPeriod Years `
        -ValidityPeriodUnits 10 `
        -Force

    Write-Host "✓ CA Enterprise installée"

    # Installer l'inscription web
    Install-AdcsWebEnrollment -Force
    Write-Host "✓ Inscription web configurée"
    Write-Host "URL: https://$(hostname)/certsrv"
    ```

    **Étape 2 : Création du template de certificat**

    ```powershell
    # Se connecter à la CA
    $ca = Connect-CertificationAuthority

    # Dupliquer un template existant (User) pour créer un custom template
    # Note: Cette opération se fait généralement via certtmpl.msc (GUI)
    # car les cmdlets PowerShell pour les templates sont limitées

    # Via GUI:
    # 1. Ouvrir certtmpl.msc
    # 2. Dupliquer le template "User"
    # 3. Renommer en "Corp-User-Auth"
    # 4. Onglet Nom du modèle: "CorpUserAuth"
    # 5. Onglet Extensions: Activer "Client Authentication"
    # 6. Onglet Sécurité: Ajouter "Domain Users" avec permissions "Read" et "Enroll"
    # 7. Publier le template

    # Publier le template via PowerShell
    Add-CATemplate -Name "CorpUserAuth" -Force
    Write-Host "✓ Template de certificat publié"

    # Vérifier les templates disponibles
    Get-CATemplate | Select-Object Name, DisplayName
    ```

    **Étape 3 : Configuration de NPS/RADIUS**

    ```powershell
    # Installer NPS
    Install-WindowsFeature -Name NPAS -IncludeManagementTools

    # Enregistrer le serveur NPS dans Active Directory
    $computer = Get-ADComputer -Identity $env:COMPUTERNAME
    $group = Get-ADGroup "RAS and IAS Servers"
    Add-ADGroupMember -Identity $group -Members $computer

    Write-Host "✓ NPS installé et enregistré dans AD"

    # Redémarrer le service NPS
    Restart-Service IAS
    ```

    **Étape 4 : Création du client RADIUS**

    ```powershell
    # Ajouter un client RADIUS (point d'accès Wi-Fi)
    $sharedSecret = "SuperSecret123!WiFi"

    New-NpsRadiusClient -Name "WiFi-AP-01" `
        -Address "192.168.1.100" `
        -SharedSecret $sharedSecret `
        -VendorName "RADIUS Standard"

    Write-Host "✓ Client RADIUS WiFi-AP-01 créé"

    # Vérifier les clients RADIUS
    Get-NpsRadiusClient | Select-Object Name, Address, VendorName
    ```

    **Étape 5 : Configuration de la politique réseau**

    ```powershell
    # Note: La configuration complète des politiques NPS se fait via nps.msc
    # Voici les paramètres à configurer:

    Write-Host "`n=== CONFIGURATION DE LA POLITIQUE RÉSEAU ===" -ForegroundColor Cyan
    Write-Host "1. Ouvrir nps.msc"
    Write-Host "2. Naviguer vers: Policies → Network Policies"
    Write-Host "3. Créer une nouvelle politique:"
    Write-Host ""
    Write-Host "Nom de la politique: WiFi-802.1X-Authentication"
    Write-Host ""
    Write-Host "CONDITIONS:"
    Write-Host "  - NAS Port Type: Wireless - IEEE 802.11"
    Write-Host "  - Windows Groups: Domain Users"
    Write-Host ""
    Write-Host "CONSTRAINTS (Contraintes):"
    Write-Host "  - Authentication Methods:"
    Write-Host "    * Microsoft: Protected EAP (PEAP)"
    Write-Host "    * Smart Card or other certificate: NON"
    Write-Host "    * PEAP Properties:"
    Write-Host "      - Certificate: (Sélectionner le certificat du serveur)"
    Write-Host "      - EAP Types: Secured password (EAP-MSCHAP v2)"
    Write-Host ""
    Write-Host "SETTINGS (Paramètres):"
    Write-Host "  - RADIUS Attributes:"
    Write-Host "    * Framed-Protocol = PPP"
    Write-Host "    * Service-Type = Framed"
    Write-Host "  - Encryption:"
    Write-Host "    * Strongest (MPPE 128-bit)"
    Write-Host ""

    # Vérifier les politiques réseau
    $policies = netsh nps show policy
    Write-Host "Politiques configurées:"
    $policies
    ```

    **Étape 6 : Génération de rapport**

    ```powershell
    # Script de rapport de configuration PKI/NPS
    $reportPath = "C:\Reports\PKI-NPS-Config-$(Get-Date -Format 'yyyyMMdd').html"

    $html = @"
    <html>
    <head>
        <title>Rapport de Configuration PKI/NPS</title>
        <style>
            body { font-family: Arial; margin: 20px; }
            h1 { color: #0066cc; }
            h2 { color: #0099cc; }
            table { border-collapse: collapse; width: 100%; margin: 10px 0; }
            th { background-color: #0066cc; color: white; padding: 10px; }
            td { border: 1px solid #ddd; padding: 8px; }
            .pass { color: green; }
            .info { background-color: #f0f0f0; padding: 10px; margin: 10px 0; }
        </style>
    </head>
    <body>
        <h1>Configuration PKI et NPS</h1>
        <p>Date: $(Get-Date -Format 'dd/MM/yyyy HH:mm')</p>

        <h2>1. Certificate Authority</h2>
        <table>
            <tr><th>Propriété</th><th>Valeur</th></tr>
            <tr><td>Nom de la CA</td><td>$(certutil -CAInfo name)</td></tr>
            <tr><td>Type</td><td>Enterprise Root CA</td></tr>
            <tr><td>Validité</td><td>10 ans</td></tr>
            <tr><td>Longueur de clé</td><td>4096 bits</td></tr>
        </table>

        <h2>2. Templates de Certificats</h2>
        <table>
            <tr><th>Nom du Template</th><th>Usage</th></tr>
"@

    # Ajouter les templates
    $templates = Get-CATemplate
    foreach ($template in $templates) {
        $html += "<tr><td>$($template.Name)</td><td>$($template.DisplayName)</td></tr>"
    }

    $html += @"
        </table>

        <h2>3. Clients RADIUS</h2>
        <table>
            <tr><th>Nom</th><th>Adresse IP</th><th>Vendor</th></tr>
"@

    # Ajouter les clients RADIUS
    $radiusClients = Get-NpsRadiusClient
    foreach ($client in $radiusClients) {
        $html += "<tr><td>$($client.Name)</td><td>$($client.Address)</td><td>$($client.VendorName)</td></tr>"
    }

    $html += @"
        </table>

        <h2>4. Validation</h2>
        <div class="info">
            <h3>Tests à effectuer</h3>
            <ul>
                <li>✓ CA accessible via https://$(hostname)/certsrv</li>
                <li>✓ Certificat utilisateur peut être demandé</li>
                <li>✓ Client RADIUS configuré sur l'AP</li>
                <li>✓ Politique réseau activée pour WiFi-802.1X</li>
                <li>⚠ Test de connexion Wi-Fi avec compte domaine</li>
            </ul>
        </div>

        <h2>5. Commandes de vérification</h2>
        <pre>
# Vérifier la CA
certutil -CAInfo

# Vérifier les templates
certutil -CATemplates

# Vérifier les clients RADIUS
Get-NpsRadiusClient

# Voir les logs NPS
Get-WinEvent -LogName "Security" -MaxEvents 20 | Where-Object Id -eq 6272
        </pre>
    </body>
    </html>
"@

    $html | Out-File $reportPath -Encoding UTF8
    Write-Host "`n✓ Rapport généré: $reportPath"
    ```

    **Étape 7 : Tests et validation**

    ```powershell
    # Script de validation finale
    function Test-PKINPSConfiguration {
        Write-Host "`n=== VALIDATION PKI/NPS ===" -ForegroundColor Cyan

        $results = @()

        # Test 1: CA installée
        $caInstalled = Get-WindowsFeature -Name ADCS-Cert-Authority
        $results += [PSCustomObject]@{
            Test = "CA installée"
            Status = if ($caInstalled.Installed) { "✓ PASS" } else { "✗ FAIL" }
        }

        # Test 2: Inscription web
        $webEnrollment = Get-WindowsFeature -Name ADCS-Web-Enrollment
        $results += [PSCustomObject]@{
            Test = "Inscription web installée"
            Status = if ($webEnrollment.Installed) { "✓ PASS" } else { "✗ FAIL" }
        }

        # Test 3: NPS installé
        $npsInstalled = Get-WindowsFeature -Name NPAS
        $results += [PSCustomObject]@{
            Test = "NPS installé"
            Status = if ($npsInstalled.Installed) { "✓ PASS" } else { "✗ FAIL" }
        }

        # Test 4: Client RADIUS configuré
        $radiusClient = Get-NpsRadiusClient -Name "WiFi-AP-01" -ErrorAction SilentlyContinue
        $results += [PSCustomObject]@{
            Test = "Client RADIUS WiFi-AP-01"
            Status = if ($radiusClient) { "✓ PASS" } else { "✗ FAIL" }
        }

        # Test 5: Service NPS en cours
        $npsService = Get-Service -Name IAS
        $results += [PSCustomObject]@{
            Test = "Service NPS actif"
            Status = if ($npsService.Status -eq "Running") { "✓ PASS" } else { "✗ FAIL" }
        }

        # Test 6: Enregistrement AD
        $iasGroup = Get-ADGroupMember "RAS and IAS Servers"
        $serverInGroup = $iasGroup | Where-Object { $_.Name -eq $env:COMPUTERNAME }
        $results += [PSCustomObject]@{
            Test = "NPS dans groupe AD"
            Status = if ($serverInGroup) { "✓ PASS" } else { "✗ FAIL" }
        }

        # Afficher les résultats
        $results | Format-Table -AutoSize

        $passed = ($results | Where-Object { $_.Status -like "*PASS*" }).Count
        $total = $results.Count
        Write-Host "`nScore: $passed/$total" -ForegroundColor $(if ($passed -eq $total) { "Green" } else { "Yellow" })

        if ($passed -eq $total) {
            Write-Host "`n✓ Configuration validée avec succès!" -ForegroundColor Green
            Write-Host "Prochaines étapes:"
            Write-Host "  1. Configurer le point d'accès Wi-Fi avec l'IP du serveur NPS"
            Write-Host "  2. Utiliser le secret partagé: SuperSecret123!WiFi"
            Write-Host "  3. Tester la connexion Wi-Fi avec un compte utilisateur du domaine"
        } else {
            Write-Host "`n⚠ Vérifier les tests en échec" -ForegroundColor Yellow
        }
    }

    # Exécuter la validation
    Test-PKINPSConfiguration
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
