---
tags:
  - windows
  - pki
  - certificates
  - adcs
  - security
---

# Active Directory Certificate Services (AD CS)

Déploiement et gestion d'une PKI interne avec AD CS.

## Architecture PKI

```
ARCHITECTURE PKI ENTREPRISE
══════════════════════════════════════════════════════════

           ┌─────────────────┐
           │   ROOT CA       │  (Offline, air-gapped)
           │   Validity: 20y │
           └────────┬────────┘
                    │
        ┌───────────┴───────────┐
        │                       │
┌───────┴───────┐       ┌───────┴───────┐
│ ISSUING CA 1  │       │ ISSUING CA 2  │  (Online)
│ (Users/Certs) │       │ (Servers)     │
│ Validity: 10y │       │ Validity: 10y │
└───────────────┘       └───────────────┘
```

---

## Installation Root CA (Offline)

```powershell
# Sur une machine standalone (pas dans le domaine)
Install-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools

# Configurer la Root CA
Install-AdcsCertificationAuthority `
    -CAType StandaloneRootCA `
    -CACommonName "Corp Root CA" `
    -KeyLength 4096 `
    -HashAlgorithmName SHA256 `
    -CryptoProviderName "RSA#Microsoft Software Key Storage Provider" `
    -ValidityPeriod Years `
    -ValidityPeriodUnits 20

# Configurer les CRL
certutil -setreg CA\CRLPeriodUnits 52
certutil -setreg CA\CRLPeriod "Weeks"
certutil -setreg CA\CRLOverlapPeriodUnits 12
certutil -setreg CA\CRLOverlapPeriod "Hours"

# Publier la CRL
certutil -crl

# Exporter le certificat Root (pour distribution)
certutil -ca.cert C:\RootCA.cer
```

---

## Installation Issuing CA (Enterprise)

```powershell
# Sur un serveur membre du domaine
Install-WindowsFeature ADCS-Cert-Authority, ADCS-Web-Enrollment -IncludeManagementTools

# Soumettre une requête à la Root CA d'abord, puis :
Install-AdcsCertificationAuthority `
    -CAType EnterpriseSubordinateCA `
    -CACommonName "Corp Issuing CA" `
    -KeyLength 4096 `
    -HashAlgorithmName SHA256 `
    -CryptoProviderName "RSA#Microsoft Software Key Storage Provider" `
    -ValidityPeriod Years `
    -ValidityPeriodUnits 10

# Configurer l'enrollment Web
Install-AdcsWebEnrollment

# Configurer les points de distribution CDP et AIA
# Via certsrv.msc ou :
$crlPath = "http://pki.corp.local/CertEnroll/<CaName><CRLNameSuffix><DeltaCRLAllowed>.crl"
certutil -setreg CA\CRLPublicationURLs "1:$crlPath"
```

---

## Templates de Certificats

```powershell
# Lister les templates disponibles
Get-CATemplate

# Dupliquer un template (via GUI certtmpl.msc) puis publier :
Add-CATemplate -Name "Corp-WebServer"

# Supprimer un template de la CA
Remove-CATemplate -Name "WebServer"

# Voir les templates publiés
certutil -CATemplates
```

### Templates Courants

| Template | Usage |
|----------|-------|
| Web Server | SSL/TLS serveurs web |
| Computer | Authentification machine |
| User | Authentification utilisateur, S/MIME |
| Code Signing | Signature de code |
| OCSP Response Signing | Répondeur OCSP |

---

## Gestion des Certificats

### Demander un Certificat

```powershell
# Demande automatique (Auto-Enrollment GPO)
certreq -autoenroll

# Demande manuelle
$template = "Corp-WebServer"
$subject = "CN=www.corp.local"
Get-Certificate -Template $template -SubjectName $subject -CertStoreLocation Cert:\LocalMachine\My

# Demande via fichier INF
# request.inf :
# [NewRequest]
# Subject = "CN=www.corp.local"
# KeyLength = 2048
# Exportable = TRUE
# MachineKeySet = TRUE
# [RequestAttributes]
# CertificateTemplate = Corp-WebServer

certreq -new request.inf request.req
certreq -submit request.req
certreq -accept response.cer
```

### Lister et Exporter

```powershell
# Lister les certificats machine
Get-ChildItem Cert:\LocalMachine\My

# Lister avec détails
Get-ChildItem Cert:\LocalMachine\My | Select-Object Subject, NotAfter, Thumbprint

# Exporter un certificat (sans clé privée)
Export-Certificate -Cert (Get-ChildItem Cert:\LocalMachine\My\THUMBPRINT) -FilePath C:\cert.cer

# Exporter avec clé privée (PFX)
$pwd = ConvertTo-SecureString -String "P@ssw0rd" -Force -AsPlainText
Export-PfxCertificate -Cert (Get-ChildItem Cert:\LocalMachine\My\THUMBPRINT) -FilePath C:\cert.pfx -Password $pwd
```

### Révoquer un Certificat

```powershell
# Sur la CA
certutil -revoke SERIALNUMBER 1  # 1 = Key Compromise

# Publier une nouvelle CRL
certutil -crl
```

---

## Auto-Enrollment

```powershell
# Via GPO : Computer Configuration > Policies > Windows Settings >
#           Security Settings > Public Key Policies >
#           Certificate Services Client - Auto-Enrollment

# Activer : Enabled
# Options :
# - Renew expired certificates
# - Update certificates that use certificate templates
```

---

## OCSP Responder

```powershell
# Installer le rôle
Install-WindowsFeature ADCS-Online-Cert -IncludeManagementTools

# Configurer
Install-AdcsOnlineResponder

# Ajouter une configuration de révocation
# Via ocsp.msc
```

---

## Troubleshooting

```powershell
# Vérifier la chaîne de certificats
certutil -verify cert.cer

# Vérifier la CRL
certutil -URL cert.cer

# Tester l'OCSP
certutil -verify -urlfetch cert.cer

# Logs CA
Get-WinEvent -LogName "Application" | Where-Object { $_.ProviderName -eq "Microsoft-Windows-CertificationAuthority" }

# État de la CA
certutil -getreg CA
```

---

## Bonnes Pratiques

```yaml
Checklist PKI:
  Architecture:
    - [ ] Root CA offline (air-gapped)
    - [ ] Issuing CA Enterprise (online)
    - [ ] HSM pour clés si critique

  Sécurité:
    - [ ] Clés 4096 bits minimum
    - [ ] SHA256 ou supérieur
    - [ ] CRL et OCSP configurés
    - [ ] Backup des clés CA

  Opérations:
    - [ ] Auto-enrollment configuré
    - [ ] Templates personnalisés
    - [ ] Monitoring expiration
    - [ ] Procédure de révocation
```

---

**Voir aussi :**

- [PKI & Certificats (Formation)](../formations/pki-certificates/index.md) - Formation complète
- [Windows Security](windows-security.md) - Sécurité Windows
- [OpenSSL CLI](../security/openssl-cli.md) - Outils OpenSSL
