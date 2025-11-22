# PowerShell for Linux Admins

`#powershell` `#scripting` `#objects` `#pipeline`

Transition Bash → PowerShell : penser en objets, pas en texte.

---

## Le Choc Culturel : Objets vs Texte

### La Différence Fondamentale

```
┌─────────────────────────────────────────────────────────────┐
│                         BASH                                 │
│  Commande → Stream de TEXTE → Commande → Stream de TEXTE    │
│                                                              │
│  ls -l | grep "Dec" | awk '{print $9}'                      │
│         ↓           ↓                                       │
│      Texte       Parse du texte                             │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                      POWERSHELL                              │
│  Cmdlet → Stream d'OBJETS → Cmdlet → Stream d'OBJETS        │
│                                                              │
│  Get-ChildItem | Where-Object { $_.LastWriteTime.Month -eq 12 }
│                ↓                    ↓                       │
│            Objets .NET        Propriétés typées             │
└─────────────────────────────────────────────────────────────┘
```

### Exemple Frappant

**Objectif :** Lister les fichiers modifiés en décembre

=== "Bash"
    ```bash
    # Parse du texte (fragile si format change)
    ls -l | grep "Dec"

    # Plus robuste mais verbeux
    find . -type f -newermt "2024-12-01" ! -newermt "2025-01-01"
    ```

=== "PowerShell"
    ```powershell
    # Manipulation directe de propriétés (toujours fiable)
    Get-ChildItem | Where-Object { $_.LastWriteTime.Month -eq 12 }

    # Avec raccourcis
    gci | ? { $_.LastWriteTime.Month -eq 12 }
    ```

### Pourquoi C'est Puissant

```powershell
# L'objet FileInfo a des propriétés typées
$file = Get-Item "document.txt"

$file.Name              # String: "document.txt"
$file.Length            # Int64: 1024
$file.LastWriteTime     # DateTime: 2024-01-15 10:30:00
$file.Extension         # String: ".txt"
$file.Directory         # DirectoryInfo: C:\Users\...

# On peut appeler des méthodes
$file.CopyTo("backup.txt")
$file.Delete()
```

---

## La Grammaire (Verb-Noun)

### Structure Standardisée

Toutes les cmdlets suivent le pattern **Verbe-Nom** :

| Verbe | Action | Exemples |
|-------|--------|----------|
| `Get-` | Récupérer | `Get-Process`, `Get-Service`, `Get-Content` |
| `Set-` | Modifier | `Set-Location`, `Set-Content`, `Set-Variable` |
| `New-` | Créer | `New-Item`, `New-Object`, `New-Service` |
| `Remove-` | Supprimer | `Remove-Item`, `Remove-Service` |
| `Start-` | Démarrer | `Start-Process`, `Start-Service` |
| `Stop-` | Arrêter | `Stop-Process`, `Stop-Service` |
| `Restart-` | Redémarrer | `Restart-Service`, `Restart-Computer` |
| `Test-` | Tester | `Test-Path`, `Test-NetConnection` |
| `Invoke-` | Exécuter | `Invoke-Command`, `Invoke-WebRequest` |

```powershell
# Lister tous les verbes approuvés
Get-Verb

# Trouver les cmdlets pour les services
Get-Command -Noun Service
# Get-Service, Set-Service, Start-Service, Stop-Service, Restart-Service...

# Trouver les cmdlets "Get-*"
Get-Command -Verb Get
```

### Les Alias : Le Piège !

!!! danger "Attention : Ces commandes ne sont PAS les binaires Linux"
    PowerShell définit des alias qui ressemblent aux commandes Unix mais ont un comportement différent.

| Alias PS | Cmdlet réelle | Binaire Linux |
|----------|---------------|---------------|
| `ls` | `Get-ChildItem` | `/bin/ls` |
| `dir` | `Get-ChildItem` | - |
| `cat` | `Get-Content` | `/bin/cat` |
| `cp` | `Copy-Item` | `/bin/cp` |
| `mv` | `Move-Item` | `/bin/mv` |
| `rm` | `Remove-Item` | `/bin/rm` |
| `pwd` | `Get-Location` | `/bin/pwd` |
| `cd` | `Set-Location` | builtin |
| `curl` | `Invoke-WebRequest` | `/usr/bin/curl` |
| `wget` | `Invoke-WebRequest` | `/usr/bin/wget` |

```powershell
# Voir la vraie commande derrière un alias
Get-Alias ls
# Alias: ls -> Get-ChildItem

Get-Alias curl
# Alias: curl -> Invoke-WebRequest

# Piège : les options Linux ne marchent pas !
ls -la          # ERREUR
ls -Force       # OK (option PowerShell)
Get-ChildItem -Force  # Explicite et clair
```

!!! tip "Bonne pratique"
    En scripts, utilisez les noms complets des cmdlets, pas les alias.

    - Scripts : `Get-ChildItem`, `Get-Content`
    - Interactif : `ls`, `cat`, `gci` (OK pour taper vite)

---

## Le Pipeline & Filtrage

### Get-Member : Le "man" Interactif

`Get-Member` (alias `gm`) révèle la structure d'un objet : ses propriétés et méthodes.

```powershell
# Voir les membres d'un objet Process
Get-Process | Get-Member

# Output:
#    TypeName: System.Diagnostics.Process
#
# Name                       MemberType     Definition
# ----                       ----------     ----------
# Kill                       Method         void Kill()
# Start                      Method         bool Start()
# CPU                        Property       double CPU {get;}
# Id                         Property       int Id {get;}
# ProcessName                Property       string ProcessName {get;}
# WorkingSet64               Property       long WorkingSet64 {get;}

# Voir les propriétés uniquement
Get-Process | gm -MemberType Property

# Voir les méthodes
Get-Process | gm -MemberType Method
```

### Select-Object : Choisir des Colonnes

Équivalent de `awk '{print $1, $3}'` mais typé.

```powershell
# Sélectionner des propriétés
Get-Process | Select-Object Name, Id, CPU

# Alias court
Get-Process | select Name, Id, CPU

# Premiers/derniers éléments
Get-Process | Select-Object -First 5
Get-Process | Select-Object -Last 3

# Propriétés calculées
Get-Process | Select-Object Name, @{N='RAM_MB';E={$_.WorkingSet64/1MB}}
```

### Where-Object : Filtrer

Équivalent de `grep` mais sur les propriétés des objets.

```powershell
# Filtrer par condition
Get-Process | Where-Object { $_.CPU -gt 100 }

# Alias courts
Get-Process | ? { $_.CPU -gt 100 }
Get-Process | where CPU -gt 100    # Syntaxe simplifiée

# Conditions multiples
Get-Service | Where-Object { $_.Status -eq "Running" -and $_.Name -like "Win*" }

# Opérateurs de comparaison
# -eq    : Égal
# -ne    : Différent
# -gt    : Plus grand
# -lt    : Plus petit
# -ge    : Plus grand ou égal
# -le    : Plus petit ou égal
# -like  : Pattern matching (* et ?)
# -match : Regex
```

### Sort-Object : Trier

```powershell
# Trier par propriété
Get-Process | Sort-Object CPU

# Tri descendant
Get-Process | Sort-Object CPU -Descending

# Tri multiple
Get-ChildItem | Sort-Object Extension, Name

# Alias
Get-Process | sort CPU -Descending
```

### Enchaînement Complet

```powershell
# Processus utilisant le plus de CPU, top 5
Get-Process |
    Sort-Object CPU -Descending |
    Select-Object -First 5 Name, Id, CPU

# Services Windows en cours, triés par nom
Get-Service |
    Where-Object Status -eq "Running" |
    Sort-Object DisplayName |
    Select-Object DisplayName, Status
```

---

## One-Liners de Survie

### Fichiers et Dossiers

```powershell
# Top 5 des plus gros fichiers
Get-ChildItem -Recurse | Sort-Object Length -Descending | Select-Object -First 5

# Alias court
gci -Recurse | sort Length -Desc | select -First 5 Name, @{N='Size_MB';E={$_.Length/1MB}}

# Trouver les fichiers > 100MB
gci -Recurse | ? { $_.Length -gt 100MB }

# Fichiers modifiés ces 7 derniers jours
gci -Recurse | ? { $_.LastWriteTime -gt (Get-Date).AddDays(-7) }

# Supprimer les fichiers .tmp
gci -Recurse -Filter "*.tmp" | Remove-Item -Force
```

### Processus

```powershell
# Tuer un processus par nom
Stop-Process -Name notepad -Force

# Tuer par PID
Stop-Process -Id 1234 -Force

# Processus consommant > 500MB de RAM
Get-Process | ? { $_.WorkingSet64 -gt 500MB } | select Name, @{N='RAM_MB';E={[int]($_.WorkingSet64/1MB)}}

# Lancer un programme
Start-Process notepad
Start-Process "C:\Program Files\App\app.exe" -ArgumentList "-config", "file.conf"
```

### Réseau

```powershell
# Test de port (équivalent nc/telnet)
Test-NetConnection -ComputerName google.com -Port 443

# Output:
# ComputerName     : google.com
# RemoteAddress    : 142.250.179.110
# RemotePort       : 443
# TcpTestSucceeded : True

# Alias rapide
tnc google.com -Port 443

# Ping
Test-NetConnection google.com

# Résolution DNS
Resolve-DnsName google.com

# Connexions actives (comme netstat)
Get-NetTCPConnection | ? State -eq "Established"

# Ports en écoute
Get-NetTCPConnection -State Listen | select LocalPort, OwningProcess
```

### Services Windows

```powershell
# État d'un service
Get-Service -Name wuauserv

# Démarrer/Arrêter
Start-Service -Name wuauserv
Stop-Service -Name wuauserv
Restart-Service -Name wuauserv

# Services en échec
Get-Service | ? Status -eq "Stopped"
```

### Remote / Web

```powershell
# Télécharger un fichier (le "wget" de PowerShell)
Invoke-WebRequest -Uri "https://example.com/file.zip" -OutFile "file.zip"

# API REST
$response = Invoke-RestMethod -Uri "https://api.github.com/users/octocat"
$response.name

# Exécution distante (WinRM)
Invoke-Command -ComputerName Server01 -ScriptBlock { Get-Process }
```

---

## Référence Rapide

```powershell
# === DÉCOUVERTE ===
Get-Command *service*              # Chercher une cmdlet
Get-Help Get-Process -Examples     # Aide avec exemples
Get-Process | Get-Member           # Structure d'un objet

# === PIPELINE ===
| Select-Object Name, Id           # Choisir colonnes
| Where-Object { $_.CPU -gt 10 }   # Filtrer
| Sort-Object CPU -Descending      # Trier
| Select-Object -First 5           # Top N

# === FICHIERS ===
Get-ChildItem -Recurse             # ls -R
Get-Content file.txt               # cat
Set-Content file.txt "text"        # echo > file
Add-Content file.txt "more"        # echo >> file

# === PROCESS ===
Get-Process                        # ps
Stop-Process -Name notepad         # kill

# === RÉSEAU ===
Test-NetConnection host -Port 443  # nc -zv
Get-NetTCPConnection               # netstat

# === ALIAS COURANTS ===
gci    = Get-ChildItem
gc     = Get-Content
?      = Where-Object
%      = ForEach-Object
select = Select-Object
sort   = Sort-Object
gm     = Get-Member
```

---

## Scripting PKI & AD

### Contexte : Générer un CSR Manuellement

Dans certains environnements (SecNumCloud, réseaux isolés), **l'auto-enrollment de certificats** (via GPO et Active Directory Certificate Services) n'est pas toujours disponible ou souhaitable.

**Cas d'usage typiques :**

| Scénario | Raison |
|----------|--------|
| **LDAPS sur 389 Directory Server** | Serveur Linux n'ayant pas accès à ADCS |
| **Certificat pour serveur DMZ** | Isolation réseau stricte (pas de connectivité AD directe) |
| **Certificate Authority externe** | CSR doit être soumis à une CA publique (Sectigo, DigiCert) |
| **Certificat wildcard** | Auto-enrollment ne supporte pas les wildcards (*.mycorp.com) |
| **Validation manuelle** | Politique de sécurité exigeant une revue humaine de chaque CSR |

**Solution :** Générer un **CSR (Certificate Signing Request)** manuellement avec `certreq` et un fichier `.inf`.

!!! tip "Pépite pour admins Windows"
    `certreq` est **l'outil natif Windows** pour gérer les certificats sans installer OpenSSL.
    Il utilise le **Cryptographic API (CAPI)** de Windows et s'intègre parfaitement avec IIS, LDAP, et autres services.

---

### Script : Generate_LDAPS_CSR.ps1

**Objectif :** Générer un CSR pour activer LDAPS (LDAP over SSL) sur un contrôleur de domaine.

=== "Generate_LDAPS_CSR.ps1"

    ```powershell
    <#
    .SYNOPSIS
        Génère un CSR (Certificate Signing Request) pour LDAPS avec certreq.

    .DESCRIPTION
        Script pour créer un fichier de requête INF et générer un CSR
        sans utiliser l'auto-enrollment Active Directory.

    .PARAMETER ServerFQDN
        FQDN du serveur LDAP (ex: srv-dc-01.mycorp.internal)

    .PARAMETER OutputPath
        Répertoire de sortie pour les fichiers .inf et .csr

    .EXAMPLE
        .\Generate_LDAPS_CSR.ps1 -ServerFQDN "srv-dc-01.mycorp.internal" -OutputPath "C:\Temp"

    .NOTES
        Auteur : SysOps Team MyCorp
        Prérequis : Exécuter en tant qu'Administrateur local
        Le certificat résultant sera stocké dans LocalMachine\My
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ServerFQDN,

        [Parameter(Mandatory = $false)]
        [string]$OutputPath = "C:\Temp\PKI"
    )

    # Créer le répertoire de sortie si inexistant
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
        Write-Host "[+] Répertoire créé : $OutputPath" -ForegroundColor Green
    }

    # Extraire le hostname et domaine
    $Hostname = $ServerFQDN.Split('.')[0]
    $Domain = $ServerFQDN.Substring($ServerFQDN.IndexOf('.') + 1)

    # Chemins des fichiers
    $InfFile = Join-Path $OutputPath "$Hostname-LDAPS.inf"
    $CsrFile = Join-Path $OutputPath "$Hostname-LDAPS.csr"

    Write-Host "[*] Génération du fichier INF : $InfFile" -ForegroundColor Cyan

    # Contenu du fichier .inf
    $InfContent = @"
[Version]
Signature="`$Windows NT`$"

[NewRequest]
; === Informations du Sujet ===
Subject = "CN=$ServerFQDN,O=MyCorp,L=Paris,C=FR"

; === Paramètres de la Clé Privée ===
KeySpec = 1
KeyLength = 4096
Exportable = FALSE
MachineKeySet = TRUE
SMIME = FALSE
PrivateKeyArchive = FALSE
UserProtected = FALSE
UseExistingKeySet = FALSE
ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
ProviderType = 12
RequestType = PKCS10
KeyUsage = 0xa0

; KeyUsage = 0xa0 signifie :
;   CERT_DIGITAL_SIGNATURE_KEY_USAGE = 0x80
;   CERT_KEY_ENCIPHERMENT_KEY_USAGE = 0x20

; === Algorithme de Hachage ===
HashAlgorithm = SHA256

[EnhancedKeyUsageExtension]
OID=1.3.6.1.5.5.7.3.1     ; Server Authentication
OID=1.3.6.1.5.5.7.3.2     ; Client Authentication

[Extensions]
; === Subject Alternative Name (SAN) ===
2.5.29.17 = "{text}"
_continue_ = "dns=$ServerFQDN&"
_continue_ = "dns=$Hostname&"
_continue_ = "dns=crl.mycorp.com&"

; Ajouter l'adresse IP si nécessaire (décommenter et adapter)
; _continue_ = "ipaddress=10.0.1.10&"

[RequestAttributes]
CertificateTemplate = WebServer
; Alternative pour LDAPS : CertificateTemplate = DirectoryEmailReplication
"@

    # Écrire le fichier .inf
    Set-Content -Path $InfFile -Value $InfContent -Encoding ASCII
    Write-Host "[+] Fichier INF créé : $InfFile" -ForegroundColor Green

    # Générer le CSR avec certreq
    Write-Host "[*] Génération du CSR avec certreq..." -ForegroundColor Cyan
    $certreqOutput = certreq -new $InfFile $CsrFile 2>&1

    if ($LASTEXITCODE -eq 0) {
        Write-Host "[+] CSR généré avec succès : $CsrFile" -ForegroundColor Green

        # Afficher le contenu du CSR
        Write-Host "`n[*] Contenu du CSR (à soumettre à la CA) :" -ForegroundColor Cyan
        Get-Content $CsrFile | Write-Host -ForegroundColor Yellow

        # Vérifier le CSR
        Write-Host "`n[*] Vérification du CSR avec certutil..." -ForegroundColor Cyan
        certutil -dump $CsrFile

        Write-Host "`n[✓] Prochaines étapes :" -ForegroundColor Green
        Write-Host "  1. Soumettre le CSR ($CsrFile) à votre Certificate Authority (CA)"
        Write-Host "  2. Télécharger le certificat signé (format .cer ou .crt)"
        Write-Host "  3. Installer le certificat avec : certreq -accept <certificat.cer>"
        Write-Host "  4. Vérifier l'installation : Get-ChildItem Cert:\LocalMachine\My | Where-Object Subject -like '*$ServerFQDN*'"

    } else {
        Write-Error "❌ Échec de la génération du CSR"
        Write-Host "Sortie de certreq :" -ForegroundColor Red
        $certreqOutput | ForEach-Object { Write-Host $_ -ForegroundColor Red }
    }
    ```

=== "Fichier INF (Explication Détaillée)"

    ```ini
    [Version]
    Signature="$Windows NT$"
    # Signature obligatoire pour les fichiers INF Windows

    [NewRequest]
    # === Informations du Sujet (Distinguished Name) ===
    Subject = "CN=srv-dc-01.mycorp.internal,O=MyCorp,L=Paris,C=FR"
    # CN = Common Name (FQDN du serveur)
    # O  = Organization
    # L  = Locality (ville)
    # C  = Country (code ISO 2 lettres)

    # === Paramètres Cryptographiques ===
    KeySpec = 1
    # 1 = AT_KEYEXCHANGE (pour SSL/TLS)
    # 2 = AT_SIGNATURE (pour signatures numériques)

    KeyLength = 4096
    # Longueur de la clé RSA (minimum 2048, recommandé 4096 pour ANSSI)

    Exportable = FALSE
    # TRUE  = La clé privée peut être exportée (PFX)
    # FALSE = La clé reste dans le TPM/HSM (plus sécurisé)

    MachineKeySet = TRUE
    # TRUE  = Clé stockée au niveau machine (LocalMachine\My)
    # FALSE = Clé stockée pour l'utilisateur courant (CurrentUser\My)

    ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
    ProviderType = 12
    # Provider pour SSL/TLS (SChannel)
    # Autres options : "Microsoft Enhanced Cryptographic Provider v1.0"

    RequestType = PKCS10
    # Format standard pour les CSR

    KeyUsage = 0xa0
    # 0xa0 = 0x80 (Digital Signature) + 0x20 (Key Encipherment)
    # Requis pour SSL/TLS server authentication

    HashAlgorithm = SHA256
    # Minimum SHA256 (ANSSI), éviter SHA1 (déprécié)

    # === Extensions ===
    [EnhancedKeyUsageExtension]
    OID=1.3.6.1.5.5.7.3.1     ; Server Authentication (TLS/SSL Server)
    OID=1.3.6.1.5.5.7.3.2     ; Client Authentication (TLS/SSL Client)

    [Extensions]
    # Subject Alternative Name (SAN) - CRITIQUE pour SSL/TLS moderne
    2.5.29.17 = "{text}"
    _continue_ = "dns=srv-dc-01.mycorp.internal&"
    _continue_ = "dns=srv-dc-01&"
    _continue_ = "dns=crl.mycorp.com&"

    # Le SAN peut inclure :
    # - dns=hostname.domain.com    (noms DNS)
    # - ipaddress=10.0.1.10        (adresses IP)
    # - upn=user@domain.com        (User Principal Name)

    [RequestAttributes]
    CertificateTemplate = WebServer
    # Template de certificat (si utilisation d'une CA Microsoft interne)
    # Options courantes :
    #   - WebServer : Pour IIS, LDAPS, services HTTPS
    #   - DirectoryEmailReplication : Spécifique pour LDAPS sur DC
    #   - Computer : Certificat machine générique
    ```

---

### Utilisation Pratique

**1. Exécuter le script**

```powershell
# Générer un CSR pour srv-dc-01.mycorp.internal
.\Generate_LDAPS_CSR.ps1 -ServerFQDN "srv-dc-01.mycorp.internal" -OutputPath "C:\Temp\PKI"

# Sortie :
# [+] Répertoire créé : C:\Temp\PKI
# [*] Génération du fichier INF : C:\Temp\PKI\srv-dc-01-LDAPS.inf
# [+] Fichier INF créé : C:\Temp\PKI\srv-dc-01-LDAPS.inf
# [*] Génération du CSR avec certreq...
# [+] CSR généré avec succès : C:\Temp\PKI\srv-dc-01-LDAPS.csr
```

**2. Soumettre le CSR à la CA**

=== "CA Microsoft Interne (via Web Enrollment)"

    ```powershell
    # Méthode 1 : Interface Web
    # Aller sur https://srv-ca-01.mycorp.internal/certsrv
    # -> Request a certificate
    # -> Advanced certificate request
    # -> Coller le contenu de srv-dc-01-LDAPS.csr
    # -> Sélectionner template "Web Server"
    # -> Submit

    # Méthode 2 : Ligne de commande (sur le serveur CA)
    certreq -submit -config "srv-ca-01.mycorp.internal\MyCorp-CA" C:\Temp\PKI\srv-dc-01-LDAPS.csr
    ```

=== "CA Publique (Sectigo, DigiCert, Let's Encrypt)"

    ```powershell
    # 1. Copier le CSR
    Get-Content C:\Temp\PKI\srv-dc-01-LDAPS.csr | Set-Clipboard

    # 2. Soumettre via l'interface web de la CA publique
    # Sectigo : https://secure.sectigo.com/products/ssl
    # DigiCert : https://www.digicert.com/account/
    # Let's Encrypt : Utiliser win-acme ou certbot-win

    # 3. Télécharger le certificat signé (format .cer ou .crt)
    ```

**3. Installer le certificat signé**

```powershell
# Une fois le certificat reçu de la CA (ex: srv-dc-01-LDAPS.cer)
certreq -accept C:\Temp\PKI\srv-dc-01-LDAPS.cer

# Vérifier l'installation
Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -like "*srv-dc-01*" }

# Sortie attendue :
# Thumbprint                                Subject
# ----------                                -------
# A1B2C3D4E5F6...                           CN=srv-dc-01.mycorp.internal, O=MyCorp, L=Paris, C=FR

# Vérifier la chaîne de certification complète
$cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object Subject -like "*srv-dc-01*"
$cert | Select-Object Thumbprint, Subject, NotBefore, NotAfter, Issuer
```

**4. Configurer LDAPS avec le certificat**

```powershell
# Le certificat LDAPS doit répondre à ces critères :
# - Subject CN = FQDN du DC
# - Enhanced Key Usage : Server Authentication (1.3.6.1.5.5.7.3.1)
# - Stocké dans LocalMachine\My
# - Chaîne de certification complète installée (Root + Intermediate CA)

# Vérifier LDAPS
Test-NetConnection -ComputerName srv-dc-01.mycorp.internal -Port 636

# Si OK, tester avec ldp.exe (GUI)
ldp.exe
# Connection > Connect > srv-dc-01.mycorp.internal : 636 (cocher SSL)

# Ou avec PowerShell
$LDAPConnection = New-Object System.DirectoryServices.Protocols.LdapConnection("srv-dc-01.mycorp.internal:636")
$LDAPConnection.SessionOptions.SecureSocketLayer = $true
$LDAPConnection.Bind()
# Si succès : LDAPS fonctionne !
```

---

### Cas Avancés : CSR pour Wildcard et Multi-SAN

**CSR Wildcard (*.mycorp.com)**

```powershell
# Modifier la section Subject du fichier .inf
Subject = "CN=*.mycorp.com,O=MyCorp,L=Paris,C=FR"

# Dans [Extensions], ajouter le wildcard au SAN
[Extensions]
2.5.29.17 = "{text}"
_continue_ = "dns=*.mycorp.com&"
_continue_ = "dns=mycorp.com&"
```

!!! warning "Limitation Auto-Enrollment"
    Les certificats wildcard **ne peuvent PAS** être générés via auto-enrollment GPO.
    Il faut **obligatoirement** passer par un CSR manuel ou une API de CA.

**CSR Multi-SAN (Load Balancer, Proxy)**

```powershell
# Exemple : certificat pour HAProxy avec plusieurs backends
[Extensions]
2.5.29.17 = "{text}"
_continue_ = "dns=lb.mycorp.com&"
_continue_ = "dns=web01.mycorp.com&"
_continue_ = "dns=web02.mycorp.com&"
_continue_ = "dns=api.mycorp.com&"
_continue_ = "ipaddress=10.0.1.100&"
_continue_ = "ipaddress=10.0.1.101&"
```

---

### Dépannage

**Erreur : "The request contains no certificate template information"**

```powershell
# La CA nécessite un template, modifier [RequestAttributes]
[RequestAttributes]
CertificateTemplate = WebServer
# Ou retirer complètement si CA publique externe
```

**Erreur : "Keyset does not exist" lors de certreq -accept**

```powershell
# Le CSR n'a pas été généré sur cette machine ou a été supprimé
# Solution : Regénérer le CSR sur la machine cible (srv-dc-01)

# Vérifier les requests en attente
certutil -store -v request

# Supprimer une ancienne request orpheline
certutil -delstore request <RequestId>
```

**Le certificat n'apparaît pas dans LocalMachine\My**

```powershell
# Vérifier que le CSR a bien été généré sur cette machine
certutil -store request

# Forcer le refresh du magasin de certificats
certutil -pulse

# Vérifier manuellement
mmc
# File > Add/Remove Snap-in > Certificates > Computer Account > Local Computer
# Navigate to Personal > Certificates
```

**LDAPS ne fonctionne pas après installation du certificat**

```powershell
# 1. Vérifier que le certificat a les bons critères
$cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object Subject -like "*srv-dc-01*"
$cert.EnhancedKeyUsageList
# Doit contenir : Server Authentication (1.3.6.1.5.5.7.3.1)

# 2. Vérifier la chaîne de certification
certutil -verify $cert.Thumbprint

# 3. Redémarrer le service Active Directory Domain Services
Restart-Service NTDS -Force

# 4. Vérifier les logs Event Viewer
# Applications and Services Logs > Directory Service
# Event ID 1220 : LDAPS bind succeeded
# Event ID 1221 : LDAPS bind failed (voir détails de l'erreur)
```

---

### Checklist Déploiement LDAPS

- [ ] Générer le CSR avec `Generate_LDAPS_CSR.ps1`
- [ ] Vérifier le CSR avec `certutil -dump <csr-file>`
- [ ] Soumettre le CSR à la CA (interne ou publique)
- [ ] Télécharger le certificat signé (.cer)
- [ ] Installer le certificat avec `certreq -accept <cer-file>`
- [ ] Vérifier la présence dans `Cert:\LocalMachine\My`
- [ ] Vérifier la chaîne de certification complète (Root + Intermediate)
- [ ] Tester le port 636 avec `Test-NetConnection -Port 636`
- [ ] Tester LDAPS avec `ldp.exe` ou PowerShell
- [ ] Configurer les clients LDAP pour utiliser LDAPS (port 636)
- [ ] Documenter la date d'expiration et créer une alerte de renouvellement

!!! success "Production Ready"
    Avec cette méthode, vous pouvez générer des CSR pour **n'importe quel service Windows** :
    IIS, LDAPS, RDP, SQL Server, Exchange, etc.
    Le fichier `.inf` est **entièrement personnalisable** selon vos besoins PKI.
