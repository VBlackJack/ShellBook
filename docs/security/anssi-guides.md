---
tags:
  - security
  - anssi
  - hardening
  - compliance
  - best-practices
---

# Guides et Recommandations ANSSI

Synthèse des principales recommandations de l'ANSSI (Agence Nationale de la Sécurité des Systèmes d'Information) pour le durcissement des systèmes.

## Présentation ANSSI

```
ANSSI - AGENCE NATIONALE DE LA SÉCURITÉ DES SYSTÈMES D'INFORMATION
══════════════════════════════════════════════════════════════════════

Missions:
├── Défense des systèmes d'information de l'État
├── Conseil et soutien aux administrations et OIV
├── Veille, détection et réponse aux attaques
├── Développement de produits de sécurité
└── Formation et sensibilisation

Publications clés:
├── Guides techniques (recommandations)
├── Référentiels (SecNumCloud, PSSIE, RGS)
├── Alertes et avis de sécurité (CERT-FR)
├── Rapports de menaces
└── Bonnes pratiques sectorielles

Niveaux de recommandation:
┌─────────────────────────────────────────────────────────────────────┐
│  R   │ Recommandation    │ Doit être appliquée                     │
├──────┼───────────────────┼─────────────────────────────────────────┤
│  R+  │ Recommandation+   │ Renforce la sécurité, non obligatoire   │
├──────┼───────────────────┼─────────────────────────────────────────┤
│  R-  │ Alternative       │ Si R impossible, mesure compensatoire   │
└─────────────────────────────────────────────────────────────────────┘

Site officiel: https://www.ssi.gouv.fr
CERT-FR: https://www.cert.ssi.gouv.fr
```

---

## Guide d'Hygiène Informatique (42 Mesures)

### Les 42 Mesures Essentielles

```yaml
SENSIBILISER ET FORMER:
  1: Former les équipes aux risques et bonnes pratiques
  2: Sensibiliser régulièrement les utilisateurs
  3: Rédiger une charte informatique

CONNAITRE LE SYSTÈME D'INFORMATION:
  4: Identifier les informations et serveurs sensibles
  5: Disposer d'un inventaire exhaustif des comptes privilégiés
  6: Organiser les procédures d'arrivée/départ des utilisateurs
  7: Autoriser la connexion au réseau uniquement depuis des postes maîtrisés
  8: Identifier les actifs les plus critiques

AUTHENTIFIER ET CONTROLER LES ACCES:
  9: Définir une politique de mots de passe robuste
  10: Protéger les mots de passe stockés sur les systèmes
  11: Mettre en place une authentification forte (MFA)
  12: Distinguer les comptes à privilèges des comptes utilisateurs
  13: Utiliser des comptes nominatifs pour l'administration

SECURISER LES POSTES:
  14: Mettre à jour les systèmes d'exploitation
  15: Mettre à jour les applications
  16: Activer et configurer le pare-feu local
  17: Installer un antivirus et le maintenir à jour
  18: Chiffrer les postes nomades (laptops)
  19: Désactiver les services inutiles

SECURISER LE RESEAU:
  20: Segmenter le réseau et les systèmes sensibles
  21: Protéger le réseau interne vis-à-vis d'Internet
  22: Définir des zones de sécurité (DMZ)
  23: Filtrer les accès Internet (proxy, DNS)
  24: Cloisonner les services visibles depuis Internet
  25: Protéger les interconnexions réseau dédiées

SECURISER L'ADMINISTRATION:
  26: Utiliser un réseau dédié et cloisonné pour l'administration
  27: Limiter l'accès aux interfaces d'administration
  28: Utiliser des protocoles sécurisés (SSH, HTTPS)
  29: Mettre en place un bastion d'administration

GERER LE NOMADISME:
  30: Encadrer le BYOD
  31: Chiffrer les échanges sensibles (VPN)
  32: Renforcer la sécurité des accès distants

SUPERVISER ET AUDITER:
  33: Activer et configurer les journaux des équipements
  34: Centraliser et analyser les journaux
  35: Mettre en place une surveillance des événements de sécurité
  36: Protéger les journaux (intégrité, rétention)

REAGIR ET SE PREPARER:
  37: Définir une procédure de gestion des incidents
  38: Maintenir un plan de continuité informatique
  39: Prévoir des sauvegardes régulières
  40: Tester les sauvegardes et les procédures de restauration
  41: Vérifier la conformité régulièrement
  42: Effectuer des audits de sécurité
```

---

## Recommandations Linux

### Durcissement GNU/Linux (ANSSI-BP-028)

```bash
# Source: https://www.ssi.gouv.fr/guide/recommandations-de-securite-relatives-a-un-systeme-gnulinux/

# === R1-R5: INSTALLATION ===

# R1: Utiliser une distribution maintenue avec mises à jour de sécurité
# → RHEL, Rocky, Debian, Ubuntu LTS

# R2: Minimiser les paquets installés
dnf install @minimal-environment

# R3: Partitionnement avec options de sécurité
# /etc/fstab
/dev/sda2  /tmp     ext4  defaults,noexec,nosuid,nodev  0 2
/dev/sda3  /var     ext4  defaults,nosuid               0 2
/dev/sda4  /var/log ext4  defaults,noexec,nosuid,nodev  0 2
/dev/sda5  /home    ext4  defaults,noexec,nosuid,nodev  0 2

# R4: Restreindre les droits d'accès au bootloader
chmod 600 /boot/grub2/grub.cfg
grub2-setpassword  # Mot de passe GRUB

# R5: Désactiver les modules kernel inutiles
cat > /etc/modprobe.d/anssi-hardening.conf << 'EOF'
# Désactiver les protocoles réseau inutiles
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true

# Désactiver les systèmes de fichiers inutiles
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true
install vfat /bin/true

# Désactiver USB storage (si non nécessaire)
# install usb-storage /bin/true
EOF

# === R6-R15: CONFIGURATION SYSTÈME ===

# R6: Paramètres sysctl sécurisés
cat > /etc/sysctl.d/99-anssi-hardening.conf << 'EOF'
# Protection mémoire
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.perf_event_paranoid = 3
kernel.yama.ptrace_scope = 1

# Protection réseau
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_syncookies = 1

# Désactiver IPv6 si non utilisé
# net.ipv6.conf.all.disable_ipv6 = 1
EOF
sysctl --system

# R7: Permissions par défaut restrictives
echo "umask 027" >> /etc/profile.d/umask.sh

# R8: Supprimer les comptes inutiles
for user in games ftp news; do
    userdel -r $user 2>/dev/null
done

# R9: Verrouiller les comptes système
for user in $(awk -F: '($3 < 1000) && ($1 != "root") {print $1}' /etc/passwd); do
    usermod -L $user
    usermod -s /usr/sbin/nologin $user
done

# R10: Configurer PAM pour les mots de passe
# /etc/security/pwquality.conf
cat > /etc/security/pwquality.conf << 'EOF'
minlen = 14
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
minclass = 4
maxrepeat = 3
gecoscheck = 1
dictcheck = 1
EOF

# R11: Limiter su à un groupe
groupadd wheel 2>/dev/null
echo "auth required pam_wheel.so use_uid" >> /etc/pam.d/su

# R12: Configurer sudo
cat > /etc/sudoers.d/anssi-hardening << 'EOF'
Defaults    use_pty
Defaults    logfile="/var/log/sudo.log"
Defaults    log_input, log_output
Defaults    passwd_timeout=1
Defaults    timestamp_timeout=5
Defaults    !visiblepw
EOF

# R13-R15: Configurer les limites
cat > /etc/security/limits.d/99-anssi.conf << 'EOF'
*               hard    core            0
*               hard    nproc           1024
*               hard    nofile          65535
EOF
```

### Configuration SSH (ANSSI-BP-028)

```bash
# /etc/ssh/sshd_config - Recommandations ANSSI

# R20: Protocole et algorithmes
Protocol 2
KexAlgorithms curve25519-sha256@libssh.org,ecdh-sha2-nistp384,ecdh-sha2-nistp521
Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256

# R21: Authentification
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
AuthenticationMethods publickey
PermitEmptyPasswords no
MaxAuthTries 3

# R22: Restrictions d'accès
AllowGroups ssh-users
DenyGroups no-ssh

# R23: Configuration session
LoginGraceTime 60
ClientAliveInterval 300
ClientAliveCountMax 2
MaxSessions 2
MaxStartups 10:30:60

# R24: Restrictions diverses
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
PermitTunnel no
Banner /etc/issue.net

# R25: Journalisation
SyslogFacility AUTH
LogLevel VERBOSE

# Redémarrer SSH
systemctl restart sshd
```

---

## Recommandations Windows

### Durcissement Windows (ANSSI-BP-065)

```powershell
# Source: https://www.ssi.gouv.fr/guide/recommandations-de-securite-relatives-a-windows/

# === AUTHENTIFICATION ===

# R1: Politique de mots de passe
# Via GPO ou secpol.msc
# Minimum 14 caractères, complexité, historique 24, expiration 90j

# R2: Verrouillage de compte
net accounts /lockoutthreshold:5 /lockoutwindow:15 /lockoutduration:30

# R3: Désactiver les comptes par défaut
Disable-LocalUser -Name "Guest"
Rename-LocalUser -Name "Administrator" -NewName "LocalAdminRenamed"

# R4: Restreindre les comptes locaux
# GPO: Deny access to this computer from the network → Local accounts

# === CONFIGURATION SYSTÈME ===

# R5: Désactiver les services inutiles
$servicesToDisable = @(
    "RemoteRegistry",
    "XblAuthManager",
    "XblGameSave",
    "WMPNetworkSvc",
    "WerSvc"  # Rapport d'erreurs (sauf si nécessaire)
)
foreach ($svc in $servicesToDisable) {
    Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue
}

# R6: Désactiver SMBv1
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force

# R7: Sécuriser SMBv2/v3
Set-SmbServerConfiguration -EnableSMB2Protocol $true -Force
Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
Set-SmbServerConfiguration -EncryptData $true -Force

# R8: Configurer Windows Defender
Set-MpPreference -DisableRealtimeMonitoring $false
Set-MpPreference -DisableBehaviorMonitoring $false
Set-MpPreference -DisableIOAVProtection $false
Set-MpPreference -DisableScriptScanning $false
Set-MpPreference -SubmitSamplesConsent 2  # Never send

# R9: Activer et configurer le firewall
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block

# R10: Désactiver protocoles obsolètes
$protocols = @("SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1")
foreach ($protocol in $protocols) {
    $serverPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Server"
    $clientPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Client"

    New-Item -Path $serverPath -Force | Out-Null
    New-Item -Path $clientPath -Force | Out-Null

    Set-ItemProperty -Path $serverPath -Name "Enabled" -Value 0 -Type DWord
    Set-ItemProperty -Path $serverPath -Name "DisabledByDefault" -Value 1 -Type DWord
    Set-ItemProperty -Path $clientPath -Name "Enabled" -Value 0 -Type DWord
    Set-ItemProperty -Path $clientPath -Name "DisabledByDefault" -Value 1 -Type DWord
}

# R11: Désactiver NetBIOS over TCP/IP
$adapters = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }
foreach ($adapter in $adapters) {
    $adapter.SetTcpipNetbios(2)  # Disable
}

# R12: Désactiver LLMNR
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0 -Type DWord

# R13: Désactiver WPAD
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc" -Name "Start" -Value 4 -Type DWord

# === AUDIT ET JOURNALISATION ===

# R14: Configurer la politique d'audit
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Logoff" /success:enable
auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable
auditpol /set /subcategory:"Special Logon" /success:enable
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
auditpol /set /subcategory:"Process Creation" /success:enable
auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable

# R15: Command line dans les events 4688
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
    -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord

# R16: PowerShell Script Block Logging
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
    -Name "EnableScriptBlockLogging" -Value 1 -Type DWord

# R17: Taille des journaux (100 MB minimum)
wevtutil sl Security /ms:104857600
wevtutil sl System /ms:104857600
wevtutil sl Application /ms:104857600
wevtutil sl "Microsoft-Windows-PowerShell/Operational" /ms:104857600
```

### Active Directory (ANSSI-BP-065-AD)

```powershell
# Recommandations spécifiques Active Directory

# R1: Niveaux fonctionnels récents
# Forêt et domaine en niveau Windows Server 2016+

# R2: Comptes protégés (Protected Users)
Add-ADGroupMember -Identity "Protected Users" -Members "HighPrivAdmin1","HighPrivAdmin2"

# R3: Délégation Kerberos contrainte
# Éviter la délégation non contrainte

# R4: LAPS (Local Administrator Password Solution)
# Déployer LAPS pour les mots de passe locaux

# R5: Désactiver NTLM progressivement
# GPO: Network security: Restrict NTLM

# R6: Tiering Model (3 niveaux)
# Tier 0: Contrôleurs de domaine, PKI
# Tier 1: Serveurs d'application
# Tier 2: Postes de travail

# R7: Admin bastion / PAW (Privileged Access Workstations)
# Postes dédiés pour l'administration

# R8: Surveiller les groupes privilégiés
$privilegedGroups = @(
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators",
    "Account Operators",
    "Backup Operators"
)
foreach ($group in $privilegedGroups) {
    Get-ADGroupMember -Identity $group | Select-Object Name, SamAccountName
}

# R9: Auditer les modifications AD
# Activer l'audit sur les OUs et objets critiques

# R10: Durée de vie des tickets Kerberos
# GPO: Maximum lifetime for user ticket = 4 hours
# GPO: Maximum lifetime for service ticket = 4 hours
```

---

## Recommandations Réseau

### Architecture Sécurisée

```yaml
Principes ANSSI:
  Segmentation:
    - Zones de confiance définies
    - Filtrage inter-zones systématique
    - DMZ pour les services exposés
    - Zone d'administration dédiée

  Cloisonnement:
    - VLAN par type de flux
    - Micro-segmentation si possible
    - Pas de flux direct Internet → LAN
    - Proxy pour les accès Web

  Filtrage:
    - Politique par défaut: DENY
    - Règles explicites et documentées
    - Inspection applicative (WAF, IDS)
    - Logs de tous les flux bloqués

Architecture type:
  ┌─────────────────────────────────────────────────────────────┐
  │                        INTERNET                              │
  └───────────────────────────┬─────────────────────────────────┘
                              │
                    ┌─────────▼─────────┐
                    │   Firewall Edge   │
                    │   (Filtrage N3/4) │
                    └─────────┬─────────┘
                              │
               ┌──────────────┼──────────────┐
               │              │              │
        ┌──────▼──────┐ ┌─────▼─────┐ ┌──────▼──────┐
        │     DMZ     │ │   LAN     │ │   Admin     │
        │  (Serveurs  │ │(Utilisat.)│ │   (Bastion) │
        │   publics)  │ │           │ │             │
        └─────────────┘ └───────────┘ └─────────────┘
```

### VPN et Accès Distants

```yaml
Recommandations VPN ANSSI:
  Protocoles acceptés:
    - IPsec IKEv2 (recommandé)
    - OpenVPN (TLS 1.2+)
    - WireGuard (évaluation en cours)

  Interdit:
    - PPTP
    - L2TP sans IPsec
    - SSLv3, TLS 1.0/1.1

  Authentification:
    - Certificats (PKI)
    - MFA obligatoire
    - Pas de PSK en production

  Configuration:
    - Perfect Forward Secrecy (PFS)
    - Algorithmes approuvés (AES-256, SHA-256+)
    - Renouvellement régulier des clés
    - Logs des connexions
```

---

## Recommandations Cloud

### Sécurité Cloud (ANSSI)

```yaml
Principes généraux:
  Localisation:
    - Données sensibles en France/UE
    - Vérifier les clauses contractuelles
    - Attention aux transferts hors UE (support, backup)

  Responsabilité partagée:
    - Comprendre le modèle (IaaS/PaaS/SaaS)
    - Sécuriser sa partie (applications, données)
    - Ne pas faire confiance aveugle au provider

  Chiffrement:
    - Données au repos chiffrées
    - BYOK (Bring Your Own Key) si possible
    - TLS pour tous les flux

  Identité:
    - MFA obligatoire pour les admins
    - Fédération avec IdP interne si possible
    - Principe du moindre privilège

  Journalisation:
    - Activer tous les logs cloud
    - Centraliser vers SIEM interne
    - Rétention selon exigences

Guides spécifiques ANSSI:
  - Recommandations de sécurité pour AWS
  - Recommandations de sécurité pour Azure
  - Recommandations de sécurité pour GCP
  - Guide SecNumCloud (qualification)
```

---

## Veille et Alertes CERT-FR

### S'abonner aux Alertes

```yaml
CERT-FR (cert.ssi.gouv.fr):
  Types de publications:
    ALERTE: Vulnérabilité critique, action immédiate
    AVIS: Vulnérabilité importante, action recommandée
    BULLETIN: Information générale
    IOC: Indicateurs de compromission

  Abonnement:
    - RSS: https://www.cert.ssi.gouv.fr/feed/
    - Twitter: @ABORAT1ON
    - Mailing list: inscription sur le site

  Traitement:
    Alerte:
      - Évaluer l'impact immédiatement
      - Appliquer les mesures dans les 24-72h
      - Communiquer en interne

    Avis:
      - Planifier dans le cycle de patch
      - Prioriser selon criticité (CVSS)
      - Documenter les exceptions
```

### Script de Veille Automatisée

```python
#!/usr/bin/env python3
# veille_certfr.py - Surveillance des alertes CERT-FR

import feedparser
import smtplib
from email.mime.text import MIMEText
from datetime import datetime, timedelta
import json
import os

FEED_URL = "https://www.cert.ssi.gouv.fr/feed/"
STATE_FILE = "/var/lib/certfr/last_check.json"
SMTP_SERVER = "relay.corp.local"
RECIPIENTS = ["security@corp.com"]

def get_last_check():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE) as f:
            return datetime.fromisoformat(json.load(f)["last_check"])
    return datetime.now() - timedelta(days=1)

def save_last_check():
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    with open(STATE_FILE, "w") as f:
        json.dump({"last_check": datetime.now().isoformat()}, f)

def check_feed():
    feed = feedparser.parse(FEED_URL)
    last_check = get_last_check()
    new_alerts = []

    for entry in feed.entries:
        published = datetime(*entry.published_parsed[:6])
        if published > last_check:
            # Filtrer les ALERTES (critiques)
            if "CERTFR-" in entry.title and "ALE" in entry.title:
                new_alerts.append({
                    "title": entry.title,
                    "link": entry.link,
                    "summary": entry.summary[:500],
                    "published": published.isoformat()
                })

    return new_alerts

def send_notification(alerts):
    if not alerts:
        return

    body = "Nouvelles alertes CERT-FR:\n\n"
    for alert in alerts:
        body += f"📢 {alert['title']}\n"
        body += f"   {alert['link']}\n"
        body += f"   {alert['summary']}\n\n"

    msg = MIMEText(body)
    msg["Subject"] = f"[CERT-FR] {len(alerts)} nouvelle(s) alerte(s)"
    msg["From"] = "certfr-monitor@corp.local"
    msg["To"] = ", ".join(RECIPIENTS)

    with smtplib.SMTP(SMTP_SERVER) as server:
        server.send_message(msg)

if __name__ == "__main__":
    alerts = check_feed()
    send_notification(alerts)
    save_last_check()
```

---

## Ressources et Liens

### Guides Principaux

```yaml
Systèmes:
  Linux:
    - BP-028: Recommandations GNU/Linux
    - https://www.ssi.gouv.fr/guide/recommandations-de-securite-relatives-a-un-systeme-gnulinux/

  Windows:
    - BP-065: Recommandations Windows
    - https://www.ssi.gouv.fr/guide/recommandations-de-securite-relatives-aux-environnements-windows/

  Active Directory:
    - Points de contrôle AD
    - https://www.ssi.gouv.fr/guide/recommandations-de-securite-relatives-a-active-directory/

Réseau:
  - Architecture sécurisée
  - Cloisonnement réseau
  - Filtrage et proxy

Cloud:
  - SecNumCloud (qualification)
  - Guides AWS/Azure/GCP
  - Conteneurs et Kubernetes

Développement:
  - Développement sécurisé
  - Tests d'intrusion
  - Audit de code

Cryptographie:
  - RGS (Référentiel Général de Sécurité)
  - Mécanismes cryptographiques
  - PKI et certificats
```

### Outils ANSSI

```yaml
Outils disponibles:
  CLIP OS:
    - Système durci basé sur Linux
    - https://clip-os.org/

  OpenCTI:
    - Plateforme de Threat Intelligence
    - https://www.opencti.io/

  DFIR ORC:
    - Collecte forensique Windows
    - https://dfir-orc.github.io/

  Wookey:
    - Token USB sécurisé
    - https://wookey-project.github.io/
```

---

## Bonnes Pratiques

```yaml
Checklist ANSSI:
  Fondamentaux:
    - [ ] Guide d'hygiène appliqué
    - [ ] Inventaire des actifs à jour
    - [ ] Politique de mots de passe conforme
    - [ ] MFA déployé (admins minimum)

  Systèmes:
    - [ ] OS et applications à jour
    - [ ] Durcissement appliqué (Linux/Windows)
    - [ ] Services inutiles désactivés
    - [ ] Antivirus/EDR actif

  Réseau:
    - [ ] Segmentation en place
    - [ ] Firewall configuré (deny par défaut)
    - [ ] Protocoles obsolètes désactivés
    - [ ] VPN sécurisé pour accès distants

  Journalisation:
    - [ ] Logs centralisés
    - [ ] Events critiques capturés
    - [ ] Rétention conforme
    - [ ] Surveillance active

  Continuité:
    - [ ] Sauvegardes régulières
    - [ ] Tests de restauration
    - [ ] PCA/PRA documenté
    - [ ] Procédure incidents

  Veille:
    - [ ] Abonnement CERT-FR
    - [ ] Processus de patch management
    - [ ] Audits réguliers
```

---

**Voir aussi :**

- [SecNumCloud](secnumcloud.md) - Référentiel cloud
- [SSH Hardening](../linux/ssh-hardening.md) - Durcissement SSH
- [Windows Defender](../windows/windows-defender.md) - Protection Windows
- [NXLog](../windows/nxlog.md) - Centralisation logs
