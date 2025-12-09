---
tags:
  - pki
  - certificates
  - vpn
  - ecdsa
  - secnumcloud
---

# PKI : Bootstrap Certificat (Offline)

Génération de certificats machine pour VPN/802.1X avant la jointure domaine.

---

## Le Problème : "Chicken & Egg"

**Scénario classique dans les environnements SecNumCloud :**

![PKI Bootstrap Chicken-Egg Problem](../../assets/diagrams/pki-bootstrap-chicken-egg-problem.jpeg)

```
┌─────────────────────────────────────────────────────────────┐
│                    PROBLÈME "CHICKEN & EGG"                  │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  1. Nouvelle machine Windows (non jointe au domaine)        │
│  2. Pour rejoindre le domaine → Besoin de se connecter au VPN│
│  3. Pour se connecter au VPN → Besoin d'un certificat machine│
│  4. Pour obtenir un certificat → Besoin de l'auto-enrollment AD│
│  5. Pour l'auto-enrollment → Besoin d'être joint au domaine │
│                                                              │
│  ➜ Boucle impossible !                                      │
│                                                              │
├─────────────────────────────────────────────────────────────┤
│                      SOLUTION : BOOTSTRAP                    │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  1. Générer un CSR manuellement (certreq + fichier .inf)    │
│  2. Soumettre le CSR à la CA (via processus offline)        │
│  3. Installer le certificat signé sur la machine            │
│  4. La machine peut maintenant se connecter au VPN           │
│  5. Une fois connectée au VPN → Jointure au domaine         │
│  6. Auto-enrollment activé → Rotation automatique des certs │
│                                                              │
│  ✓ Le certificat "bootstrap" permet l'amorçage du cycle     │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

!!! tip "Cas d'usage typiques"
    - **Postes nomades** : Laptops devant se connecter au VPN avant la jointure domaine
    - **Serveurs DMZ** : Isolation réseau stricte (pas d'accès direct à l'AD)
    - **Zero Trust** : Authentification par certificat obligatoire (pas de VPN username/password)
    - **Provisioning automatique** : Scripts de déploiement Ansible/Terraform nécessitant un certificat initial

---

## Pourquoi ECDSA P-384 ?

| Critère | RSA 4096 | ECDSA P-384 (Recommandé ANSSI) |
|---------|----------|-------------------------------|
| **Sécurité équivalente** | 4096 bits | 384 bits (même niveau de sécurité) |
| **Taille de la clé** | 4096 bits | 384 bits (10x plus compact) |
| **Performance CPU** | Lent (génération & signature) | Rapide (moins de calculs) |
| **Taille du certificat** | ~2 KB | ~500 octets |
| **Support matériel** | Universel | TPM 2.0+ (natif) |
| **Standard ANSSI** | Acceptable | **Recommandé** (SecNumCloud) |

!!! success "ECDSA P-384 : Standard Moderne"
    ECDSA (Elliptic Curve Digital Signature Algorithm) avec courbe P-384 offre une sécurité équivalente à RSA 7680 bits avec une clé de seulement 384 bits. C'est le choix recommandé par l'ANSSI pour les infrastructures SecNumCloud.

---

## Template INF : ECDSA P-384

```ini
[Version]
Signature="$Windows NT$"

[NewRequest]
; === Informations du Sujet ===
; IMPORTANT : Le FQDN doit être ANTICIPÉ (la machine n'est pas encore jointe au domaine)
Subject = "CN=WKS-LAPTOP-01.corp.mycorp.internal,O=MyCorp,C=FR"

; === Algorithme de Clé : ECDSA P-384 (ANSSI) ===
KeyAlgorithm = ECDSA
KeyLength = 384
; Courbes supportées :
;   - ECDSA_P256 (256 bits) : Acceptable
;   - ECDSA_P384 (384 bits) : RECOMMANDÉ ANSSI
;   - ECDSA_P521 (521 bits) : Maximum (overkill)

; === Paramètres de la Clé Privée ===
Exportable = FALSE
; FALSE = La clé privée reste dans le TPM (sécurité maximale)
; TRUE  = Exportable en PFX (uniquement si migration nécessaire)

MachineKeySet = TRUE
; TRUE  = Certificat machine (stocké dans LocalMachine\My)
; FALSE = Certificat utilisateur (stocké dans CurrentUser\My)
; CRITIQUE : MachineKeySet=TRUE est OBLIGATOIRE pour :
;   - VPN Machine Authentication
;   - Services système (IIS, LDAPS, etc.)
;   - Authentification avant logon utilisateur

ProviderName = "Microsoft Software Key Storage Provider"
; Pour TPM 2.0, utiliser : "Microsoft Platform Crypto Provider"
; Cela force le stockage de la clé dans le TPM matériel

RequestType = PKCS10
; Format standard pour les CSR

KeyUsage = 0xa0
; 0xa0 = 0x80 (Digital Signature) + 0x20 (Key Encipherment)
; Requis pour l'authentification TLS/SSL client

; === Algorithme de Hachage ===
HashAlgorithm = SHA384
; SHA384 est recommandé avec ECDSA P-384 (cohérence de sécurité)
; SHA256 est acceptable mais SHA384 est préféré

; === Extensions : Enhanced Key Usage (EKU) ===
[EnhancedKeyUsageExtension]
OID=1.3.6.1.5.5.7.3.2     ; Client Authentication (VPN, 802.1X)
OID=1.3.6.1.5.5.7.3.1     ; Server Authentication (optionnel, si dual-use)

; Client Authentication (1.3.6.1.5.5.7.3.2) est OBLIGATOIRE pour :
;   - VPN Client (IPsec, SSL VPN, WireGuard)
;   - 802.1X Network Access Control (NAC)
;   - Mutual TLS (mTLS) authentication

; === Extensions : Subject Alternative Name (SAN) ===
[Extensions]
2.5.29.17 = "{text}"
_continue_ = "dns=WKS-LAPTOP-01.corp.mycorp.internal&"
_continue_ = "dns=WKS-LAPTOP-01&"

; Le SAN doit inclure :
;   - FQDN complet (dns=hostname.domain.com)
;   - Hostname court (dns=hostname) pour compatibilité

[RequestAttributes]
; Ne PAS spécifier de CertificateTemplate pour un bootstrap offline
; Le template sera appliqué par la CA lors de la signature manuelle
```

---

## Workflow PowerShell

### Bloc A : Génération du CSR

```powershell
function New-BootstrapCSR {
    <#
    .SYNOPSIS
        Génère un CSR bootstrap pour certificat machine (ECDSA P-384).

    .PARAMETER Hostname
        Nom court de la machine (ex: WKS-LAPTOP-01)

    .PARAMETER DomainFQDN
        FQDN du domaine (ex: corp.mycorp.internal)
        IMPORTANT : Doit être le domaine cible (même si la machine n'est pas encore jointe)

    .EXAMPLE
        New-BootstrapCSR -Hostname "WKS-LAPTOP-01" -DomainFQDN "corp.mycorp.internal"
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Hostname,

        [Parameter(Mandatory = $true)]
        [string]$DomainFQDN,

        [Parameter(Mandatory = $false)]
        [string]$OutputPath = "C:\Temp\Bootstrap"
    )

    # Créer le répertoire de sortie
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }

    # Construire le FQDN complet (ANTICIPÉ)
    $MachineFQDN = "$Hostname.$DomainFQDN"

    # Chemins des fichiers
    $InfFile = Join-Path $OutputPath "$Hostname-Bootstrap.inf"
    $ReqFile = Join-Path $OutputPath "$Hostname-Bootstrap.req"

    # Contenu du fichier .inf (ECDSA P-384)
    $InfContent = @"
[Version]
Signature="`$Windows NT`$"

[NewRequest]
Subject = "CN=$MachineFQDN,O=MyCorp,C=FR"
KeyAlgorithm = ECDSA
KeyLength = 384
Exportable = FALSE
MachineKeySet = TRUE
ProviderName = "Microsoft Software Key Storage Provider"
RequestType = PKCS10
KeyUsage = 0xa0
HashAlgorithm = SHA384

[EnhancedKeyUsageExtension]
OID=1.3.6.1.5.5.7.3.2
OID=1.3.6.1.5.5.7.3.1

[Extensions]
2.5.29.17 = "{text}"
_continue_ = "dns=$MachineFQDN&"
_continue_ = "dns=$Hostname&"
"@

    # Écrire le fichier .inf
    Set-Content -Path $InfFile -Value $InfContent -Encoding ASCII

    # Générer le CSR avec certreq
    $certreqOutput = certreq -new $InfFile $ReqFile 2>&1

    if ($LASTEXITCODE -eq 0) {
        Write-Host "[+] CSR généré : $ReqFile" -ForegroundColor Green
        Write-Host "`nProchaines étapes :" -ForegroundColor Cyan
        Write-Host "  1. Transférer le CSR vers une machine avec accès à la CA"
        Write-Host "  2. Soumettre : certreq -submit -config 'CA\Name' $ReqFile"
        Write-Host "  3. Installer : Install-BootstrapCertificate -CertificatePath <.cer>"
    } else {
        Write-Error "Échec de la génération du CSR"
    }
}

# Utilisation
New-BootstrapCSR -Hostname "WKS-LAPTOP-01" -DomainFQDN "corp.mycorp.internal"
```

### Bloc B : Installation du Certificat

```powershell
function Install-BootstrapCertificate {
    <#
    .SYNOPSIS
        Installe un certificat bootstrap et vérifie les EKU pour VPN.

    .PARAMETER CertificatePath
        Chemin vers le fichier .cer (certificat signé par la CA)

    .EXAMPLE
        Install-BootstrapCertificate -CertificatePath "C:\Temp\WKS-LAPTOP-01-Bootstrap.cer"
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({Test-Path $_})]
        [string]$CertificatePath
    )

    # Installer le certificat avec certreq -accept
    $certreqOutput = certreq -accept $CertificatePath 2>&1

    if ($LASTEXITCODE -eq 0) {
        Write-Host "[+] Certificat installé !" -ForegroundColor Green

        # Vérifier les EKU
        $Cert = Get-ChildItem Cert:\LocalMachine\My |
            Sort-Object NotBefore -Descending |
            Select-Object -First 1

        $ClientAuthOID = "1.3.6.1.5.5.7.3.2"
        $HasClientAuth = $Cert.EnhancedKeyUsageList |
            Where-Object { $_.ObjectId -eq $ClientAuthOID }

        if ($HasClientAuth) {
            Write-Host "[+] Client Authentication EKU présent - VPN ready" -ForegroundColor Green
        } else {
            Write-Warning "Client Authentication EKU manquant !"
        }

        # Vérifier la chaîne
        if ($Cert.Verify()) {
            Write-Host "[+] Chaîne de certification valide" -ForegroundColor Green
        } else {
            Write-Warning "Chaîne de certification invalide - Installer les CA Root/Intermediate"
        }
    } else {
        Write-Error "Échec de l'installation"
    }
}
```

---

## Workflow Complet

![PKI Bootstrap Workflow Complete](../../assets/diagrams/pki-bootstrap-workflow-complete.jpeg)

```
┌─────────────────────────────────────────────────────────────┐
│                   WORKFLOW BOOTSTRAP PKI                     │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  [ÉTAPE 1 : Génération CSR - Machine Offline]               │
│  PS> New-BootstrapCSR -Hostname "WKS-01" `                  │
│         -DomainFQDN "corp.mycorp.internal"                   │
│                                                              │
│  [ÉTAPE 2 : Transfert CSR - USB/Email Sécurisé]             │
│  Copier le fichier .req vers une machine avec accès CA      │
│                                                              │
│  [ÉTAPE 3 : Soumission CA]                                  │
│  PS> certreq -submit -config "srv-ca-01\MyCorp-CA" `        │
│         WKS-01-Bootstrap.req WKS-01-Bootstrap.cer            │
│                                                              │
│  [ÉTAPE 4 : Transfert Certificat]                           │
│  Copier le fichier .cer vers la machine offline             │
│                                                              │
│  [ÉTAPE 5 : Installation]                                   │
│  PS> Install-BootstrapCertificate `                          │
│         -CertificatePath "WKS-01-Bootstrap.cer"              │
│                                                              │
│  [ÉTAPE 6 : Configuration VPN]                              │
│  Client VPN → Utiliser "Machine Certificate"                │
│                                                              │
│  [ÉTAPE 7 : Jointure Domaine]                               │
│  PS> Add-Computer -DomainName "corp.mycorp.internal"        │
│                                                              │
│  [ÉTAPE 8 : Auto-Enrollment]                                │
│  GPO appliquée → Certificats futurs gérés automatiquement   │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Dépannage

**Erreur : "Keyset does not exist"**

```powershell
# Cause : Le CSR n'a pas été généré sur cette machine
# Solution : Le CSR et l'installation doivent être sur la MÊME machine

# Vérifier les requests en attente
certutil -store request

# Si la request n'existe pas : regénérer le CSR sur cette machine
```

**Le VPN refuse la connexion**

```powershell
# Vérifier que l'EKU "Client Authentication" est présent
$Cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object Subject -like "*WKS-01*"
$Cert.EnhancedKeyUsageList

# Output attendu :
# FriendlyName                  ObjectId
# ------------                  --------
# Client Authentication         1.3.6.1.5.5.7.3.2
```

---

## Checklist

- [ ] Planifier le FQDN complet (ex: `WKS-LAPTOP-01.corp.mycorp.internal`)
- [ ] Générer le CSR avec `New-BootstrapCSR` (ECDSA P-384)
- [ ] Vérifier le CSR avec `certutil -dump WKS-01-Bootstrap.req`
- [ ] Soumettre le CSR à la CA
- [ ] Installer avec `Install-BootstrapCertificate`
- [ ] Vérifier l'EKU "Client Authentication" (1.3.6.1.5.5.7.3.2)
- [ ] Configurer le client VPN
- [ ] Rejoindre le domaine Active Directory

!!! success "Production Ready"
    Avec ce workflow, vous pouvez provisionner des machines Windows dans des environnements Zero Trust sans aucun accès réseau initial.

---

## Référence Rapide

```powershell
# === CERTIFICATS ===
certreq -new request.inf request.req     # Générer CSR
certreq -accept certificate.crt          # Installer Certificat
Get-ChildItem Cert:\LocalMachine\My      # Lister Certs Machine
certutil -dump certificate.cer           # Vérifier Certificat
certutil -store request                  # Lister Requests Pending
```

---

!!! info "À lire aussi"
    - [BitLocker](bitlocker.md) - Chiffrement disque avec Network Unlock
    - [Hardening ANSSI](hardening-anssi.md) - Conformité SecNumCloud
