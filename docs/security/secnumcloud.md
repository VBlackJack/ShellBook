---
tags:
  - security
  - compliance
  - secnumcloud
  - anssi
  - cloud
---

# SecNumCloud

Référentiel de sécurité de l'ANSSI pour les prestataires de services cloud. Guide des exigences et de leur mise en œuvre opérationnelle.

## Présentation

```text
SECNUMCLOUD - VUE D'ENSEMBLE
══════════════════════════════════════════════════════════════════════

Objectif:
├── Qualifier les prestataires cloud de confiance
├── Garantir un niveau de sécurité élevé
├── Protéger les données sensibles (OIV, administrations)
└── Souveraineté : données hébergées en France/UE

Versions:
├── SecNumCloud 3.1 (2022) - Version actuelle
├── SecNumCloud 3.2 (2024) - En cours de déploiement
└── Alignement EUCS (European Cybersecurity Certification Scheme)

Niveaux:
┌─────────────────────────────────────────────────────────────────────┐
│  ESSENTIEL    │  Exigences de base, PME, données peu sensibles     │
├───────────────┼─────────────────────────────────────────────────────┤
│  STANDARD     │  Niveau intermédiaire, entreprises                  │
├───────────────┼─────────────────────────────────────────────────────┤
│  AVANCÉ       │  Exigences maximales, OIV, données sensibles       │
│  (SecNumCloud)│  Qualification ANSSI obligatoire                    │
└─────────────────────────────────────────────────────────────────────┘

Périmètre:
├── IaaS (Infrastructure as a Service)
├── PaaS (Platform as a Service)
├── SaaS (Software as a Service)
└── Conteneurs / Kubernetes
```

---

## Structure du Référentiel

### Chapitres Principaux

```text
STRUCTURE SECNUMCLOUD 3.2
══════════════════════════════════════════════════════════════════════

1. GOUVERNANCE DE LA SÉCURITÉ
   ├── 1.1 Politique de sécurité (PSSI)
   ├── 1.2 Organisation de la sécurité
   ├── 1.3 Gestion des risques
   ├── 1.4 Conformité légale et réglementaire
   └── 1.5 Relations avec les autorités

2. PROTECTION DES DONNÉES
   ├── 2.1 Classification des données
   ├── 2.2 Localisation des données (France/UE)
   ├── 2.3 Chiffrement des données
   ├── 2.4 Gestion des clés
   └── 2.5 Droit d'accès et portabilité

3. SÉCURITÉ DES RESSOURCES HUMAINES
   ├── 3.1 Avant l'embauche (screening)
   ├── 3.2 Pendant l'emploi (sensibilisation)
   └── 3.3 Fin de contrat

4. GESTION DES ACTIFS
   ├── 4.1 Inventaire des actifs
   ├── 4.2 Classification
   └── 4.3 Gestion des supports amovibles

5. CONTRÔLE D'ACCÈS
   ├── 5.1 Politique d'accès
   ├── 5.2 Gestion des identités
   ├── 5.3 Authentification forte (MFA)
   ├── 5.4 Gestion des privilèges (PAM)
   └── 5.5 Revue des droits

6. CRYPTOGRAPHIE
   ├── 6.1 Politique cryptographique
   ├── 6.2 Algorithmes approuvés
   ├── 6.3 Gestion des clés (KMS)
   └── 6.4 PKI et certificats

7. SÉCURITÉ PHYSIQUE
   ├── 7.1 Périmètres de sécurité
   ├── 7.2 Contrôle d'accès physique
   ├── 7.3 Protection contre les menaces
   └── 7.4 Sécurité des équipements

8. SÉCURITÉ DES OPÉRATIONS
   ├── 8.1 Procédures d'exploitation
   ├── 8.2 Gestion des changements
   ├── 8.3 Séparation des environnements
   ├── 8.4 Protection malware
   ├── 8.5 Sauvegarde
   ├── 8.6 Journalisation et surveillance
   └── 8.7 Gestion des vulnérabilités

9. SÉCURITÉ DES COMMUNICATIONS
   ├── 9.1 Gestion du réseau
   ├── 9.2 Transferts d'information
   └── 9.3 Cloisonnement

10. ACQUISITION ET DÉVELOPPEMENT
    ├── 10.1 Exigences sécurité
    ├── 10.2 Développement sécurisé
    ├── 10.3 Tests de sécurité
    └── 10.4 Protection des environnements

11. RELATIONS FOURNISSEURS
    ├── 11.1 Politique fournisseurs
    ├── 11.2 Gestion des prestations
    └── 11.3 Chaîne d'approvisionnement

12. GESTION DES INCIDENTS
    ├── 12.1 Procédures de réponse
    ├── 12.2 Signalement des incidents
    ├── 12.3 Analyse et amélioration
    └── 12.4 Collecte de preuves

13. CONTINUITÉ D'ACTIVITÉ
    ├── 13.1 Planification (PCA/PRA)
    ├── 13.2 Redondance
    └── 13.3 Tests et exercices

14. CONFORMITÉ
    ├── 14.1 Exigences légales
    ├── 14.2 Revues de sécurité
    └── 14.3 Audits
```

---

## Exigences Clés par Domaine

### 1. Journalisation et Traçabilité

```yaml
Exigences Journalisation (8.6):
  Events obligatoires:
    Authentification:
      - Connexions réussies et échouées
      - Déconnexions
      - Verrouillages de comptes
      - Changements de mot de passe
      - Utilisation de privilèges élevés

    Gestion des comptes:
      - Création/modification/suppression utilisateurs
      - Modifications de groupes et privilèges
      - Modifications de politiques

    Actions administratives:
      - Modifications de configuration
      - Démarrage/arrêt de services
      - Modifications de règles firewall
      - Accès aux données sensibles

    Système:
      - Démarrage/arrêt système
      - Erreurs et alertes critiques
      - Modifications de l'heure système
      - Effacement de journaux

  Conservation:
    - Minimum 6 mois en ligne
    - Minimum 1 an en archive
    - 3 ans recommandé pour les OIV
    - Intégrité garantie (horodatage, signature)

  Centralisation:
    - SIEM ou concentrateur de logs
    - Corrélation des événements
    - Alerting en temps réel
    - Accès restreint aux logs

  Implémentation:
    Windows: NXLog → Concentrateur
    Linux: rsyslog/auditd → Concentrateur
    Applications: Logging applicatif → Concentrateur
```

### 2. Contrôle d'Accès et Authentification

```yaml
Exigences Authentification (5.3):
  MFA obligatoire pour:
    - Accès administrateurs
    - Accès VPN
    - Accès console cloud
    - Accès données sensibles

  Méthodes acceptées:
    - TOTP (Google Authenticator, etc.)
    - Clés physiques (YubiKey, FIDO2)
    - Certificats sur carte à puce
    - Push notification (avec PIN)

  Mots de passe:
    - Minimum 12 caractères (admin: 16)
    - Complexité (majuscules, chiffres, spéciaux)
    - Pas de réutilisation (historique 12)
    - Expiration 90 jours (ou monitoring compromission)
    - Verrouillage après 5 échecs

  Comptes privilégiés:
    - Comptes nominatifs (pas de comptes génériques)
    - PAM (Privileged Access Management)
    - Sessions enregistrées
    - Just-in-time access si possible
```

### 3. Chiffrement et Cryptographie

```yaml
Exigences Cryptographie (6):
  Données au repos:
    - Chiffrement AES-256 minimum
    - Gestion des clés séparée (KMS)
    - Clés sous contrôle du client (BYOK) si possible

  Données en transit:
    - TLS 1.2 minimum (TLS 1.3 recommandé)
    - Certificats valides et vérifiés
    - Perfect Forward Secrecy (PFS)
    - Désactivation protocoles obsolètes (SSLv3, TLS 1.0/1.1)

  Algorithmes approuvés ANSSI:
    Chiffrement symétrique:
      - AES-128, AES-256
    Chiffrement asymétrique:
      - RSA 2048+ (3072 recommandé)
      - ECDSA P-256, P-384
      - Ed25519
    Hash:
      - SHA-256, SHA-384, SHA-512
      - SHA-3
    Échange de clés:
      - ECDH P-256+
      - X25519

  Interdit:
    - MD5, SHA-1 (sauf compatibilité legacy documentée)
    - DES, 3DES
    - RSA < 2048 bits
    - RC4
```

### 4. Gestion des Vulnérabilités

```yaml
Exigences Vulnérabilités (8.7):
  Scan régulier:
    - Scan infrastructure mensuel minimum
    - Scan après tout changement majeur
    - Scan des images conteneurs avant déploiement

  Délais de correction:
    Critique (CVSS >= 9.0):
      - Évaluation: 24h
      - Correction: 72h
      - Mesure compensatoire si délai impossible

    Haute (CVSS 7.0-8.9):
      - Correction: 7 jours

    Moyenne (CVSS 4.0-6.9):
      - Correction: 30 jours

    Basse (CVSS < 4.0):
      - Correction: 90 jours

  Patch management:
    - Processus documenté
    - Tests avant déploiement production
    - Rollback possible
    - Traçabilité des patchs appliqués

  Veille sécurité:
    - Abonnement CERT-FR
    - Suivi CVE des composants utilisés
    - Notification des clients si impact
```

### 5. Sauvegarde et Continuité

```yaml
Exigences Sauvegarde (8.5):
  Politique:
    - RPO/RTO définis par criticité
    - Sauvegardes chiffrées
    - Stockage géographiquement séparé
    - Tests de restauration réguliers

  Fréquence minimale:
    - Données critiques: quotidien
    - Configurations: après chaque changement
    - Logs: temps réel vers concentrateur

  Rétention:
    - Selon classification des données
    - Minimum 30 jours opérationnel
    - Archive selon exigences légales

  Tests:
    - Test de restauration trimestriel
    - Test PRA annuel
    - Documentation des procédures

Exigences PCA/PRA (13):
  Plan de Continuité:
    - Scénarios de sinistre identifiés
    - Procédures de basculement
    - Communication de crise
    - Tests annuels minimum

  Redondance:
    - Pas de SPOF (Single Point of Failure)
    - Multi-datacenter si niveau avancé
    - Réplication des données critiques
```

### 6. Cloisonnement et Isolation

```yaml
Exigences Isolation (9.3):
  Multi-tenant:
    - Isolation stricte entre clients
    - Pas de fuite de données inter-tenant
    - Ressources dédiées ou isolation garantie

  Réseaux:
    - Segmentation par zone de sécurité
    - Filtrage inter-zones (firewall)
    - DMZ pour exposition externe
    - Micro-segmentation si possible

  Environnements:
    - Séparation dev/test/prod
    - Pas de données prod en dev/test
    - Anonymisation si nécessaire

  Conteneurs:
    - Isolation des namespaces
    - Politique réseau Kubernetes
    - Images de base durcies
    - Scan des vulnérabilités
```

---

## Mise en Œuvre Technique

### Checklist Serveurs Linux

```bash
# Conformité SecNumCloud - Serveur Linux RHEL/Rocky

# === JOURNALISATION ===

# Configurer auditd
cat > /etc/audit/rules.d/secnumcloud.rules << 'EOF'
# Suppression des règles existantes
-D

# Buffer et gestion des erreurs
-b 8192
-f 1

# Surveillance des fichiers critiques
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k privileged
-w /etc/sudoers.d/ -p wa -k privileged

# Surveillance des connexions
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock/ -p wa -k logins

# Commandes privilégiées
-a always,exit -F path=/usr/bin/sudo -F perm=x -k privileged
-a always,exit -F path=/usr/bin/su -F perm=x -k privileged

# Modifications système
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system
-a always,exit -F arch=b64 -S clock_settime -k time-change

# Modifications réseau
-w /etc/sysconfig/network-scripts/ -p wa -k network

# Chargement modules kernel
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules

# Immutabilité (à la fin)
-e 2
EOF

# Recharger auditd
augenrules --load

# === AUTHENTIFICATION ===

# Politique de mots de passe
cat > /etc/security/pwquality.conf << 'EOF'
minlen = 14
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
minclass = 4
maxrepeat = 3
maxclassrepeat = 4
EOF

# Verrouillage après échecs (faillock)
authselect select sssd with-faillock --force

# Configuration faillock
cat > /etc/security/faillock.conf << 'EOF'
deny = 5
unlock_time = 900
fail_interval = 900
EOF

# === CRYPTOGRAPHIE ===

# Désactiver les protocoles faibles SSH
cat >> /etc/ssh/sshd_config << 'EOF'
# SecNumCloud SSH Hardening
Protocol 2
KexAlgorithms curve25519-sha256@libssh.org,ecdh-sha2-nistp384
Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256

PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
MaxAuthTries 3
LoginGraceTime 60
ClientAliveInterval 300
ClientAliveCountMax 2
EOF

# Configuration TLS système (crypto-policies RHEL)
update-crypto-policies --set FUTURE

# === SERVICES ===

# Désactiver services inutiles
systemctl disable --now rpcbind cups avahi-daemon

# Vérifier les ports ouverts
ss -tulnp

# === FIREWALL ===

# Politique par défaut: deny
firewall-cmd --set-default-zone=drop
firewall-cmd --permanent --zone=drop --add-service=ssh
firewall-cmd --reload
```

### Checklist Serveurs Windows

```powershell
# Conformité SecNumCloud - Serveur Windows

# === JOURNALISATION ===

# Configurer la politique d'audit avancée
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Logoff" /success:enable
auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable
auditpol /set /subcategory:"Special Logon" /success:enable
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
auditpol /set /subcategory:"Computer Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Process Creation" /success:enable
auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable

# Command line dans les events 4688
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
    -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord

# PowerShell Script Block Logging
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
    -Name "EnableScriptBlockLogging" -Value 1 -Type DWord -Force

# Taille des journaux (minimum 100MB)
wevtutil sl Security /ms:104857600
wevtutil sl System /ms:104857600
wevtutil sl Application /ms:104857600

# === AUTHENTIFICATION ===

# Politique de mots de passe (via GPO ou secpol.msc)
# Minimum 14 caractères, complexité, historique 24, expiration 90j

# Verrouillage de compte
net accounts /lockoutthreshold:5 /lockoutwindow:15 /lockoutduration:30

# Désactiver NTLM si possible (progressivement)
# GPO: Network security: Restrict NTLM

# === CRYPTOGRAPHIE ===

# Désactiver protocoles TLS obsolètes
$protocols = @("SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1")
foreach ($protocol in $protocols) {
    $path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Server"
    New-Item -Path $path -Force | Out-Null
    Set-ItemProperty -Path $path -Name "Enabled" -Value 0 -Type DWord
    Set-ItemProperty -Path $path -Name "DisabledByDefault" -Value 1 -Type DWord
}

# Activer TLS 1.2 et 1.3
$protocols = @("TLS 1.2", "TLS 1.3")
foreach ($protocol in $protocols) {
    $serverPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Server"
    $clientPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Client"
    New-Item -Path $serverPath -Force | Out-Null
    New-Item -Path $clientPath -Force | Out-Null
    Set-ItemProperty -Path $serverPath -Name "Enabled" -Value 1 -Type DWord
    Set-ItemProperty -Path $clientPath -Name "Enabled" -Value 1 -Type DWord
}

# === SERVICES ===

# Désactiver services inutiles
$services = @("RemoteRegistry", "XblAuthManager", "XblGameSave")
foreach ($svc in $services) {
    Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue
}

# === FIREWALL ===

# Activer le firewall sur tous les profils
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

# Politique par défaut : bloquer entrant
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block
```

---

## Audit et Conformité

### Préparer un Audit SecNumCloud

```yaml
Documentation requise:
  Gouvernance:
    - [ ] PSSI (Politique de Sécurité)
    - [ ] Analyse de risques
    - [ ] Organigramme sécurité
    - [ ] Fiches de poste

  Technique:
    - [ ] Architecture réseau
    - [ ] Inventaire des actifs
    - [ ] Matrice des flux
    - [ ] Procédures d'exploitation

  Opérations:
    - [ ] Procédures de gestion des incidents
    - [ ] Plan de continuité (PCA/PRA)
    - [ ] Rapports de tests PRA
    - [ ] Logs des 6 derniers mois

  Fournisseurs:
    - [ ] Contrats avec clauses sécurité
    - [ ] Liste des sous-traitants
    - [ ] Évaluation des risques fournisseurs

Preuves techniques:
  - Screenshots des configurations
  - Exports de configurations (anonymisés)
  - Rapports de scan de vulnérabilités
  - Rapports de tests d'intrusion
  - Échantillons de logs
  - Preuves de chiffrement
```

### Points de Contrôle Courants

```yaml
Contrôles fréquemment audités:
  1. Localisation des données:
     - Prouver que les données restent en France/UE
     - Contrats hébergeurs avec clauses géographiques
     - Pas de transfert hors UE (y compris support)

  2. Journalisation:
     - Logs de 6 mois accessibles
     - Intégrité des logs prouvée
     - Couverture des events critiques

  3. Gestion des accès:
     - MFA activé pour les admins
     - Revue des droits documentée
     - Comptes génériques justifiés

  4. Chiffrement:
     - TLS 1.2+ vérifié
     - Données au repos chiffrées
     - Gestion des clés documentée

  5. Patch management:
     - Processus documenté
     - Délais de correction respectés
     - Vulnérabilités critiques traitées

  6. Sauvegarde:
     - Tests de restauration documentés
     - Sauvegardes chiffrées
     - Stockage séparé
```

---

## Ressources

### Liens Officiels

```yaml
ANSSI:
  Référentiel: https://www.ssi.gouv.fr/administration/qualifications/prestataires-de-services-de-confiance-qualifies/prestataires-de-service-informatique-en-nuage-secnumcloud/
  Guide: https://www.ssi.gouv.fr/uploads/2014/12/secnumcloud-referentiel-v3.2.pdf
  FAQ: https://www.ssi.gouv.fr/uploads/2023/06/secnumcloud-faq.pdf

Prestataires qualifiés:
  Liste: https://www.ssi.gouv.fr/entreprise/qualifications/prestataires-de-services-de-confiance-qualifies/

Guides complémentaires:
  - Guide d'hygiène informatique (42 mesures)
  - Recommandations de sécurité pour les architectures AWS/Azure/GCP
  - Guide de journalisation
```

### Correspondance avec Autres Référentiels

```text
MAPPING SECNUMCLOUD
══════════════════════════════════════════════════════════════════════

┌─────────────────┬─────────────────┬─────────────────┬───────────────┐
│ SecNumCloud     │ ISO 27001       │ SOC 2           │ RGPD          │
├─────────────────┼─────────────────┼─────────────────┼───────────────┤
│ Chap. 1 Gouv.   │ A.5, A.6        │ CC1             │ Art. 24       │
│ Chap. 2 Données │ A.8             │ CC6             │ Art. 5, 32    │
│ Chap. 5 Accès   │ A.9             │ CC6.1-6.3       │ Art. 32       │
│ Chap. 6 Crypto  │ A.10            │ CC6.7           │ Art. 32       │
│ Chap. 8 Ops     │ A.12            │ CC7, CC8        │ Art. 32       │
│ Chap. 12 Incid. │ A.16            │ CC7.4           │ Art. 33, 34   │
│ Chap. 13 Contin.│ A.17            │ A1              │ Art. 32       │
└─────────────────┴─────────────────┴─────────────────┴───────────────┘

Avantage SecNumCloud:
- Plus exigeant que ISO 27001 seul
- Adapté au contexte cloud
- Souveraineté intégrée
- Reconnaissance étatique (OIV, administrations)
```

---

## Bonnes Pratiques

```yaml
Checklist Conformité SecNumCloud:
  Préparation:
    - [ ] Gap analysis vs référentiel
    - [ ] Plan de remédiation priorisé
    - [ ] Budget et ressources alloués
    - [ ] Accompagnement expert si nécessaire

  Gouvernance:
    - [ ] RSSI nommé
    - [ ] Comité sécurité régulier
    - [ ] PSSI validée et diffusée
    - [ ] Analyse de risques à jour

  Technique:
    - [ ] Journalisation centralisée
    - [ ] MFA déployé
    - [ ] Chiffrement en place
    - [ ] Patch management opérationnel
    - [ ] Sauvegardes testées

  Opérationnel:
    - [ ] Procédures documentées
    - [ ] Équipes formées
    - [ ] Tests PRA effectués
    - [ ] Incidents tracés et analysés

  Audit:
    - [ ] Pré-audit interne
    - [ ] Remédiation des écarts
    - [ ] Documentation complète
    - [ ] Preuves techniques prêtes
```

---

**Voir aussi :**

- [ANSSI Guides](anssi-guides.md) - Recommandations ANSSI
- [NXLog](../windows/nxlog.md) - Centralisation logs Windows
- [SSH Hardening](../linux/ssh-hardening.md) - Durcissement SSH
- [Certificates](certificates.md) - PKI et certificats
