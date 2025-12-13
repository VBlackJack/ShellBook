---
tags:
  - formation
  - security
  - interview
  - career
  - pentest
---

# Interview Prep - Pentest & Red Team

Questions d'entretien courantes pour les postes de pentester et red teamer, avec réponses détaillées.

---

## 1. Questions Techniques Fondamentales

### 1.1 Networking

**Q: Expliquez le three-way handshake TCP.**

```
R: Le TCP three-way handshake établit une connexion fiable:

1. SYN: Le client envoie un paquet SYN avec un numéro de séquence initial
2. SYN-ACK: Le serveur répond avec SYN-ACK, son propre numéro de séquence, et ACK du numéro client +1
3. ACK: Le client envoie ACK du numéro serveur +1

En pentest, cela explique pourquoi:
- Les scans SYN (-sS) sont plus discrets (pas de connexion complète)
- Les scans connect (-sT) sont plus fiables mais loggés
- Les firewalls stateful suivent ces états
```

**Q: Quelle est la différence entre TCP et UDP?**

```
R:
TCP (Transmission Control Protocol):
- Orienté connexion (handshake)
- Fiable (accusé de réception, retransmission)
- Ordonné (les paquets arrivent dans l'ordre)
- Plus lent mais sûr
- Exemples: HTTP, SSH, SMB

UDP (User Datagram Protocol):
- Sans connexion
- Non fiable (pas d'accusé de réception)
- Plus rapide
- Utilisé quand la vitesse prime sur la fiabilité
- Exemples: DNS (53), SNMP (161), NTP (123)

En pentest: UDP est souvent oublié dans les scans, mais DNS et SNMP peuvent révéler beaucoup d'informations.
```

**Q: Comment fonctionne le NAT?**

```
R: Le NAT (Network Address Translation) traduit les adresses IP:

- NAT Source/PAT: Plusieurs IP privées partagent une IP publique
  - Le routeur maintient une table de traduction (IP:Port interne <-> IP:Port externe)

- NAT Destination (Port Forwarding): Redirige le trafic entrant vers des serveurs internes

Impact pentest:
- Les scans depuis Internet ne voient que l'IP publique
- Le pivoting est nécessaire pour atteindre les réseaux privés
- Les reverse shells doivent contourner le NAT
```

### 1.2 Active Directory

**Q: Qu'est-ce que Kerberos et comment fonctionne-t-il?**

```
R: Kerberos est le protocole d'authentification principal d'AD:

1. AS-REQ/AS-REP: L'utilisateur demande un TGT au KDC
   - Envoie son username, le KDC vérifie le mot de passe
   - Reçoit un TGT chiffré avec le hash krbtgt

2. TGS-REQ/TGS-REP: L'utilisateur demande un ticket de service
   - Présente son TGT au KDC
   - Reçoit un TGS chiffré avec le hash du compte de service

3. AP-REQ/AP-REP: L'utilisateur accède au service
   - Présente son TGS au service

Attaques associées:
- Kerberoasting: Demander des TGS et les cracker offline
- AS-REP Roasting: Comptes sans pré-authentification
- Golden Ticket: Forger des TGT avec le hash krbtgt
- Silver Ticket: Forger des TGS avec le hash du service
```

**Q: Expliquez la différence entre un Golden Ticket et un Silver Ticket.**

```
R:
Golden Ticket:
- Forgé avec le hash du compte krbtgt
- Permet de créer des TGT pour n'importe quel utilisateur
- Valide pour tout le domaine (tous les services)
- Survit aux changements de mot de passe (sauf krbtgt)
- Nécessite une rotation double de krbtgt pour invalider

Silver Ticket:
- Forgé avec le hash d'un compte de service
- Permet d'accéder à un service spécifique uniquement
- Plus discret (ne contacte pas le KDC)
- Limité au service dont on a le hash
- Plus facile à obtenir (hash de machine par exemple)

Usage: Golden Ticket pour persistence domain-wide, Silver Ticket pour accès ciblé discret.
```

**Q: Qu'est-ce que DCSync et pourquoi est-ce dangereux?**

```
R: DCSync simule le comportement de réplication entre Domain Controllers:

Mécanisme:
- Utilise le protocole DRSUAPI (Directory Replication Service)
- Demande les secrets de réplication pour n'importe quel compte
- Ne nécessite pas d'accès physique au DC

Droits requis:
- DS-Replication-Get-Changes
- DS-Replication-Get-Changes-All
- (Généralement: Domain Admins, Enterprise Admins)

Danger:
- Permet d'extraire le hash de n'importe quel compte (y compris krbtgt)
- Ne laisse pas de traces sur le DC cible
- Permet de forger des Golden Tickets

Détection: Event ID 4662 avec les GUIDs de réplication.
```

### 1.3 Windows Security

**Q: Qu'est-ce que LSASS et pourquoi est-il une cible prioritaire?**

```
R: LSASS (Local Security Authority Subsystem Service):

Rôle:
- Gère l'authentification locale et domaine
- Stocke les credentials des utilisateurs connectés
- Gère les tokens de sécurité

Ce qu'il contient en mémoire:
- Hashes NTLM des utilisateurs connectés
- Tickets Kerberos (TGT, TGS)
- Mots de passe en clair (si WDigest activé)
- Clés de session

Pourquoi c'est une cible:
- Un seul dump = tous les credentials des utilisateurs connectés
- Permet le lateral movement via Pass-the-Hash/Ticket
- Souvent des comptes admin connectés sur les serveurs

Protections:
- Credential Guard (isolation dans une VM)
- LSA Protection (RunAsPPL)
- Désactiver WDigest
```

**Q: Expliquez les différents types de tokens Windows.**

```
R: Windows utilise des Access Tokens pour le contrôle d'accès:

Types de tokens:
1. Primary Token:
   - Associé à un processus
   - Créé au logon
   - Définit l'identité du processus

2. Impersonation Token:
   - Associé à un thread
   - Permet d'agir temporairement comme un autre utilisateur
   - Niveaux d'impersonation:
     * Anonymous: Aucune info
     * Identification: Identifier, pas agir
     * Impersonation: Agir localement
     * Delegation: Agir sur le réseau

Abus en pentest:
- Token Stealing: Voler le token d'un autre processus
- Token Impersonation: Utiliser un token capturé
- Potato Attacks: Exploiter SeImpersonatePrivilege
```

---

## 2. Questions Méthodologiques

### 2.1 Processus de Pentest

**Q: Décrivez votre méthodologie pour un test d'intrusion réseau.**

```
R: Je suis une approche structurée en phases:

1. Reconnaissance (Passive)
   - OSINT: domaines, emails, employés
   - DNS: sous-domaines, records
   - Shodan/Censys: services exposés

2. Scanning & Enumeration (Active)
   - Scan de ports (Nmap)
   - Énumération de services
   - Identification des versions

3. Vulnerability Assessment
   - Recherche de CVE
   - Vérification manuelle des vulnérabilités
   - Priorisation des cibles

4. Exploitation
   - Exploitation des vulnérabilités identifiées
   - Obtention d'un accès initial

5. Post-Exploitation
   - Énumération interne
   - Privilege escalation
   - Lateral movement
   - Persistence (si dans le scope)

6. Reporting
   - Documentation des findings
   - Preuves de concept
   - Recommandations
```

**Q: Comment abordez-vous un environnement Active Directory?**

```
R:
Phase 1: Reconnaissance sans credentials
- Enumération anonyme LDAP
- Scan de ports AD (88, 389, 445, 3268)
- Capture de hashes (Responder)

Phase 2: Avec un compte utilisateur
- BloodHound pour cartographier les chemins d'attaque
- Énumération des users, groups, GPOs
- Identification des comptes Kerberoastables/AS-REP Roastables
- Recherche de shares accessibles

Phase 3: Escalade
- Kerberoasting/AS-REP Roasting
- Exploitation des ACLs faibles
- Abus de délégation
- Exploitation ADCS si présent

Phase 4: Domain Compromise
- DCSync si droits suffisants
- Accès au DC
- Extraction de secrets

Je documente chaque étape et cherche plusieurs chemins vers Domain Admin.
```

### 2.2 Situations Pratiques

**Q: Vous avez un shell sur une machine Windows. Quelles sont vos premières actions?**

```
R:
1. Situational Awareness (30 secondes)
   whoami /all
   hostname
   ipconfig /all
   net user

2. Vérifier l'AV/EDR
   Get-MpComputerStatus (Defender)
   tasklist (chercher les processus de sécurité)

3. Énumération locale
   systeminfo
   netstat -ano
   tasklist /v

4. Si admin local:
   - Dump des credentials (mimikatz, comsvcs.dll)
   - Vérifier les tokens disponibles

5. Si pas admin:
   - Énumérer les vecteurs de privesc (winPEAS)
   - Chercher des credentials stockés

6. Réseau
   - Identifier d'autres réseaux accessibles
   - Scanner le réseau interne
   - Identifier les DC et serveurs critiques
```

**Q: Comment contournez-vous les solutions EDR?**

```
R: Plusieurs techniques selon le contexte:

1. OPSEC de base
   - Éviter les outils connus (mimikatz.exe sur disque)
   - Exécution in-memory (Assembly.Load, BOFs)
   - Renommer les binaires, modifier les strings

2. Évasion technique
   - AMSI bypass pour PowerShell
   - Direct syscalls (éviter les hooks ntdll)
   - Unhooking des DLLs
   - Process injection dans des processus légitimes
   - Sleep obfuscation

3. Living off the Land
   - Utiliser des LOLBins (certutil, mshta, etc.)
   - WMI, PowerShell avec obfuscation
   - Exploitation de features légitimes

4. Adaptatif
   - Identifier quel EDR est présent
   - Tester sur un environnement similaire
   - Modifier les payloads jusqu'à ce qu'ils passent

L'important est de comprendre COMMENT l'EDR détecte, pas juste contourner aveuglément.
```

---

## 3. Questions Comportementales

### 3.1 Éthique & Professionnalisme

**Q: Vous découvrez une vulnérabilité critique hors scope. Que faites-vous?**

```
R:
1. Je STOPPE immédiatement l'exploitation
   - Ne pas aller plus loin que la découverte

2. Documentation
   - Noter exactement ce qui a été trouvé
   - Preuves minimales (pas d'exploitation complète)

3. Communication immédiate
   - Contacter le client/point de contact
   - Expliquer la gravité de la découverte
   - Demander une extension du scope si approprié

4. Attendre les instructions
   - Ne pas continuer sans autorisation écrite
   - Proposer de tester si le client le souhaite

L'intégrité professionnelle est non négociable. Un bon pentester sait quand s'arrêter.
```

**Q: Comment gérez-vous un désaccord avec le client sur une vulnérabilité?**

```
R:
1. Écouter leur perspective
   - Comprendre pourquoi ils ne sont pas d'accord
   - Peut-être ont-ils des infos que je n'ai pas

2. Expliquer clairement
   - Démontrer l'impact avec des preuves concrètes
   - Référencer les standards (CVSS, OWASP)
   - Fournir des exemples de compromissions similaires

3. Proposer des solutions
   - Si c'est une question de sévérité, trouver un compromis
   - Suggérer un test supplémentaire pour clarifier

4. Documenter
   - Noter le désaccord dans le rapport
   - Inclure les deux perspectives si nécessaire

5. Escalader si nécessaire
   - Impliquer les managers des deux côtés
   - Parfois un tiers peut aider

L'objectif est d'aider le client à être plus sécurisé, pas de "gagner" un argument.
```

### 3.2 Travail d'Équipe

**Q: Comment travaillez-vous avec une équipe Blue Team?**

```
R:
Collaboration Purple Team:
- Partager les techniques utilisées (après autorisation)
- Aider à identifier les gaps de détection
- Proposer des règles de détection
- Valider ensemble que les alertes fonctionnent

Communication:
- Briefings réguliers pendant l'engagement
- Débrief post-opération détaillé
- Documentation des IOCs générés
- Partage des timelines d'attaque

Approche:
- Voir le Blue Team comme des partenaires, pas des adversaires
- L'objectif commun est d'améliorer la sécurité
- Apprendre d'eux (comment ils ont détecté certaines choses)
```

---

## 4. Questions Techniques Avancées

### 4.1 Exploitation

**Q: Expliquez comment fonctionne un buffer overflow basique.**

```
R:
Concept:
Un buffer overflow se produit quand un programme écrit plus de données qu'un buffer ne peut en contenir, écrasant la mémoire adjacente.

Stack-based overflow classique:
1. Le programme alloue un buffer sur la stack
2. Une entrée utilisateur dépasse la taille du buffer
3. Les données écrasent:
   - Variables locales
   - Saved EBP (frame pointer)
   - Return address (EIP/RIP)

Exploitation:
1. Trouver l'offset exact pour écraser EIP
2. Rediriger EIP vers notre shellcode
3. Le shellcode s'exécute avec les privilèges du programme

Mitigations modernes:
- ASLR: Randomise les adresses mémoire
- DEP/NX: Empêche l'exécution sur la stack
- Stack Canaries: Détecte les overflows
- CFI: Contrôle l'intégrité du flow

Ces mitigations nécessitent des techniques avancées (ROP, leaks) pour être contournées.
```

**Q: Qu'est-ce que le ROP (Return-Oriented Programming)?**

```
R:
ROP contourne DEP/NX en réutilisant du code existant:

Concept:
- Au lieu d'exécuter notre shellcode, on chaîne des "gadgets"
- Gadgets = petites séquences d'instructions terminées par RET
- On construit notre payload en chaînant ces gadgets

Exemple simple:
1. Trouver: pop eax; ret
2. Trouver: mov [ecx], eax; ret
3. Chaîner pour écrire en mémoire

Process:
1. Identifier les gadgets utiles (ROPgadget, ropper)
2. Planifier la chaîne (ex: appeler mprotect puis shellcode)
3. Construire le payload avec les adresses des gadgets
4. Déclencher l'overflow avec notre ROP chain

Utilisé pour:
- Désactiver DEP via VirtualProtect/mprotect
- Exécuter une fonction système
- Préparer l'exécution de shellcode
```

### 4.2 Web Security

**Q: Expliquez la différence entre XSS stocké, réfléchi et DOM-based.**

```
R:
XSS Réfléchi (Reflected):
- Le payload est dans la requête (URL, paramètre)
- Le serveur le renvoie dans la réponse
- Nécessite que la victime clique sur un lien malveillant
- Exemple: search.php?q=<script>alert(1)</script>

XSS Stocké (Stored):
- Le payload est sauvegardé dans la base de données
- Tous les utilisateurs qui voient la page sont affectés
- Plus dangereux car persistant
- Exemple: commentaire contenant du JavaScript

XSS DOM-based:
- Le payload ne passe pas par le serveur
- Le JavaScript client-side traite l'input de manière dangereuse
- Plus difficile à détecter côté serveur
- Exemple: document.write(location.hash)

Impact: Vol de cookies/sessions, keylogging, defacement, phishing
```

---

## 5. Tips pour l'Entretien

### 5.1 Préparation

```markdown
# Avant l'entretien
- [ ] Revoir les fondamentaux (réseau, crypto, web, Windows)
- [ ] Préparer des exemples concrets de vos expériences
- [ ] Connaître les outils courants (pas juste les utiliser, les comprendre)
- [ ] Réviser les certifications obtenues
- [ ] Préparer des questions pour l'employeur

# Pendant l'entretien
- [ ] Si vous ne savez pas, dites-le honnêtement
- [ ] Expliquez votre raisonnement, pas juste la réponse
- [ ] Donnez des exemples concrets quand possible
- [ ] Montrez votre passion pour la sécurité
- [ ] Posez des questions sur l'équipe et les projets
```

### 5.2 Questions à Poser

```markdown
# Sur l'équipe
- Quelle est la taille de l'équipe?
- Comment sont répartis les engagements?
- Y a-t-il de la formation continue?

# Sur les projets
- Quel type de tests faites-vous le plus souvent?
- Utilisez-vous du Red Team ou principalement du pentest?
- Avez-vous des projets de recherche?

# Sur la culture
- Comment gérez-vous le stress des deadlines?
- Y a-t-il du temps pour la veille technologique?
- Participez-vous à des conférences?
```

---

[Retour au Programme](index.md){ .md-button }
[Certifications →](certifications.md){ .md-button .md-button--primary }
