---
tags:
  - formation
  - glossaire
  - windows
  - hacking
  - active-directory
---

# Glossaire - Windows Hacking Mastery

Définitions des termes techniques utilisés dans cette formation.

---

## A

### ACL (Access Control List)
Liste définissant les permissions d'accès à un objet (fichier, dossier, objet AD). Composée d'ACE (Access Control Entries).

### ADCS (Active Directory Certificate Services)
Rôle Windows Server permettant de créer une PKI (Public Key Infrastructure). Souvent mal configuré et exploitable via les vulnérabilités ESC1-ESC8 (Enrollment, Template ACLs, NTLM Relay).

### AdminSDHolder
Objet AD spécial dont les ACLs sont copiées toutes les 60 minutes sur les groupes protégés (Domain Admins, etc.). Utilisé pour la persistence.

### AMSI (Antimalware Scan Interface)
Interface Windows permettant aux antivirus de scanner les scripts en mémoire (PowerShell, VBScript, JScript).

### AS-REP Roasting
Attaque ciblant les comptes avec l'option "Do not require Kerberos preauthentication". Permet d'obtenir un hash crackable offline.

---

## B

### BloodHound
Outil de visualisation des relations AD. Utilise Neo4j pour cartographier les chemins d'attaque vers Domain Admin.

### Blue Team
Équipe défensive responsable de la protection des systèmes et de la détection des attaques.

---

## C

### C2 (Command & Control)
Infrastructure de commande et contrôle permettant de piloter des machines compromises à distance.

### Beacon
Agent C2 qui communique périodiquement avec le serveur de commande. Contrairement à une session interactive, un beacon "dort" entre les check-ins pour réduire le trafic réseau et éviter la détection.

### BOF (Beacon Object File)
Code compilé en format COFF (Common Object File Format) exécutable en mémoire par un implant C2. Permet d'étendre les fonctionnalités sans déposer de fichiers sur disque.

### Certipy
Outil Python pour l'audit et l'exploitation d'Active Directory Certificate Services (ADCS). Permet d'identifier et exploiter les vulnérabilités ESC1-ESC8.

### Constrained Delegation
Configuration permettant à un service de s'authentifier auprès de services spécifiques au nom d'un utilisateur.

### Credential Dumping
Extraction de credentials (mots de passe, hashes, tickets) depuis la mémoire ou le stockage.

---

## D

### DCSync
Attaque simulant la réplication entre Domain Controllers pour extraire les hashes de n'importe quel compte, y compris krbtgt.

### DLL Hijacking
Technique exploitant l'ordre de recherche des DLL pour charger une DLL malveillante.

### DPAPI (Data Protection API)
API Windows pour le chiffrement des données sensibles utilisateur (mots de passe, cookies, etc.).

### DSRM (Directory Services Restore Mode)
Mode de récupération des Domain Controllers. Le compte DSRM peut être utilisé pour la persistence.

---

## E

### EDR (Endpoint Detection & Response)
Solution de sécurité avancée surveillant les endpoints pour détecter et répondre aux menaces.

### EKU (Extended Key Usage)
Extension des certificats X.509 définissant les usages autorisés (Client Authentication, Server Authentication, Code Signing, etc.). Crucial pour les attaques ADCS.

### ESC (Escalation)
Série de vulnérabilités ADCS (ESC1-ESC8) permettant l'escalade de privilèges via les certificats. Découvertes par SpecterOps en 2021.

### ETW (Event Tracing for Windows)
Mécanisme de logging Windows utilisé par les solutions de sécurité. Souvent bypassé par les attaquants.

---

## G

### Golden Ticket
Ticket Kerberos TGT forgé avec le hash krbtgt, permettant d'usurper n'importe quel utilisateur du domaine.

### GPO (Group Policy Object)
Objet AD contenant des paramètres de configuration appliqués aux utilisateurs et ordinateurs.

### gMSA (Group Managed Service Account)
Compte de service géré automatiquement par AD avec rotation de mot de passe (240 caractères). Protection efficace contre Kerberoasting.

---

## H

### Havoc
Framework C2 open-source avec interface graphique Qt, inspiré de Cobalt Strike. Utilise l'agent "Demon" avec évasion avancée (indirect syscalls, sleep obfuscation).

---

## K

### KDC (Key Distribution Center)
Service Kerberos sur le Domain Controller responsable de l'émission des tickets TGT et TGS.

### Kerberoasting
Attaque ciblant les comptes de service avec SPN. N'importe quel utilisateur authentifié peut demander un TGS crackable offline.

### Kerberos
Protocole d'authentification utilisé par Active Directory basé sur des tickets cryptographiques.

### krbtgt
Compte système AD dont le hash est utilisé pour signer tous les tickets Kerberos. Compromis = Golden Ticket possible.

---

## L

### LAPS (Local Administrator Password Solution)
Solution Microsoft pour gérer les mots de passe des comptes admin locaux de manière unique par machine.

### Lateral Movement
Mouvement d'une machine à une autre au sein d'un réseau après compromission initiale.

### LDAP (Lightweight Directory Access Protocol)
Protocole d'accès à l'annuaire Active Directory (port 389/636).

### LLMNR (Link-Local Multicast Name Resolution)
Protocole de résolution de noms local. Vulnérable au poisoning pour capturer des hashes NTLMv2.

### LOLBin (Living off the Land Binary)
Binaire Windows légitime utilisé à des fins offensives pour éviter la détection.

### LSASS (Local Security Authority Subsystem Service)
Processus Windows stockant les credentials des utilisateurs connectés. Cible prioritaire pour le credential dumping.

---

## M

### Mimikatz
Outil de référence pour l'extraction de credentials Windows (hashes, tickets Kerberos, secrets DPAPI).

### MITRE ATT&CK
Framework décrivant les tactiques, techniques et procédures (TTPs) utilisées par les attaquants.

---

## N

### NBT-NS (NetBIOS Name Service)
Protocole legacy de résolution de noms. Vulnérable au poisoning comme LLMNR.

### NTDS.dit
Base de données Active Directory contenant tous les objets du domaine, y compris les hashes des mots de passe.

### NTLM
Protocole d'authentification legacy Windows. Les hashes NTLMv2 peuvent être relayés ou crackés.

---

## O

### OpSec (Operational Security)
Ensemble de pratiques visant à éviter la détection lors d'une opération Red Team.

### Overpass-the-Hash
Technique utilisant un hash NTLM pour obtenir un ticket Kerberos TGT, combinant PtH et Kerberos.

---

## P

### Pass-the-Hash (PtH)
Technique d'authentification utilisant un hash NTLM au lieu du mot de passe en clair.

### Pass-the-Ticket (PtT)
Technique d'authentification utilisant un ticket Kerberos volé.

### Persistence
Mécanisme permettant de maintenir l'accès à un système après compromission initiale.

### PKINIT
Extension Kerberos permettant l'authentification via certificat X.509 au lieu d'un mot de passe. Utilisé pour convertir un certificat en TGT ou hash NTLM.

### Potato Attacks
Famille d'attaques (JuicyPotato, PrintSpoofer, GodPotato) exploitant SeImpersonatePrivilege pour obtenir SYSTEM.

### Privilege Escalation
Élévation de privilèges depuis un compte limité vers un compte plus privilégié (admin local, SYSTEM, Domain Admin).

### Purple Team
Approche combinant Red Team (attaque) et Blue Team (défense) pour améliorer la sécurité. Le Purple Team valide les détections et propose des remédiations.

---

## R

### RBCD (Resource-Based Constrained Delegation)
Variante de la delegation configurée sur la ressource cible plutôt que sur le compte de service.

### Red Team
Équipe offensive simulant des attaques réalistes pour tester la sécurité d'une organisation.

### ROE (Rules of Engagement)
Document définissant le périmètre, les contraintes et les autorisations d'un test d'intrusion.

---

## S

### SAM (Security Account Manager)
Base de données locale Windows contenant les hashes des comptes locaux.

### Sigma
Format standardisé de règles de détection pour SIEM. Permet de définir des signatures d'attaques portables entre différentes plateformes (Splunk, ELK, etc.).

### SID (Security Identifier)
Identifiant unique pour chaque objet de sécurité Windows (utilisateur, groupe, machine).

### Silver Ticket
Ticket Kerberos TGS forgé pour accéder à un service spécifique sans passer par le KDC.

### Skeleton Key
Technique de persistence injectant un mot de passe maître dans LSASS sur un Domain Controller.

### Sliver
Framework C2 open-source développé par BishopFox en Go. Supporte multiple protocoles (mTLS, HTTPS, DNS, WireGuard) et les extensions BOF/COFF.

### SMB Relay
Attaque relayant une authentification NTLM capturée vers un autre serveur.

### SPN (Service Principal Name)
Identifiant unique d'une instance de service dans AD. Les comptes avec SPN sont Kerberoastables.

### SSP (Security Support Provider)
Module d'authentification Windows. Un SSP malveillant peut capturer les credentials en clair.

---

## T

### TGS (Ticket Granting Service)
Ticket Kerberos permettant d'accéder à un service spécifique.

### TGT (Ticket Granting Ticket)
Ticket Kerberos initial obtenu lors de l'authentification, utilisé pour demander des TGS.

### Trust
Relation entre domaines AD permettant l'authentification cross-domain.

---

## U

### UAC (User Account Control)
Mécanisme Windows demandant une élévation pour les actions administratives.

### Unconstrained Delegation
Configuration permettant à un service de stocker le TGT des utilisateurs qui s'y connectent.

---

## W

### WinRM (Windows Remote Management)
Service de gestion à distance Windows utilisant le protocole WS-Management (ports 5985/5986).

### WMI (Windows Management Instrumentation)
Infrastructure de gestion Windows. Les Event Subscriptions WMI permettent la persistence.

---

[Retour au Programme](index.md){ .md-button }
