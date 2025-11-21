# Introduction to CTF (Capture The Flag)

`#ctf` `#pwn` `#osint` `#hardware`

Your survival guide to legal hacking competitions.

---

## What is a CTF?

**Capture The Flag** competitions are legal hacking challenges where participants find hidden "flags" (text strings like `FLAG{y0u_found_m3}`) to score points.

**Types of CTF:**

| Type | Format |
|------|--------|
| **Jeopardy** | Individual challenges, pick what you want |
| **Attack-Defense** | Teams defend their servers while attacking others |
| **King of the Hill** | Maintain control of a target system |

**Where to practice:**

- [HackTheBox](https://hackthebox.com) - Realistic machines
- [TryHackMe](https://tryhackme.com) - Guided learning paths
- [PicoCTF](https://picoctf.org) - Beginner friendly
- [Root-Me](https://root-me.org) - French platform, great challenges
- [CTFtime](https://ctftime.org) - Live competition calendar

---

## Category 1: Pwn (Binary Exploitation)

**Goal:** Exploit memory corruption vulnerabilities in compiled programs (C/C++) to gain arbitrary code execution.

### The Trinity of Tools

| Role | Tool | Purpose |
|------|------|---------|
| **Disassembler** | Ghidra, IDA Pro | Reverse engineer binary → view assembly/pseudocode |
| **Debugger** | GDB + GEF/Pwndbg | Inspect memory, registers, step through execution |
| **Exploitation** | Pwntools (Python) | Script payload delivery and shell interaction |

### Common Vulnerabilities

| Vulnerability | Description |
|---------------|-------------|
| **Buffer Overflow** | Write beyond buffer bounds, overwrite return address |
| **Format String** | Abuse `printf(user_input)` to read/write memory |
| **Use After Free** | Access freed memory, corrupt heap structures |
| **ROP (Return Oriented Programming)** | Chain existing code gadgets to bypass NX |

### Quick Pwntools Example

```python
from pwn import *

# Connect to challenge
p = remote('ctf.example.com', 1337)
# Or local: p = process('./vulnerable')

# Craft payload
payload = b'A' * 64          # Fill buffer
payload += p64(0xdeadbeef)   # Overwrite return address

# Send and get shell
p.sendline(payload)
p.interactive()
```

### Essential GDB Commands (with GEF)

```bash
# Start debugging
gdb ./binary

# GEF/Pwndbg commands
checksec          # Check security mitigations (NX, ASLR, Canary)
vmmap             # View memory layout
pattern create 100  # Generate cyclic pattern
pattern offset 0x41414141  # Find offset

# Breakpoints and execution
b *main           # Break at main
b *0x401234       # Break at address
r                 # Run
c                 # Continue
ni                # Next instruction
si                # Step into

# Inspection
x/20x $rsp        # Examine 20 hex words at RSP
x/s 0x401234      # Examine as string
info registers    # Show all registers
```

!!! tip "Learn the Basics"
    Start with simple stack buffer overflows before tackling heap exploitation.

    Resources:

    - [Nightmare](https://guyinatuxedo.github.io/) - Binary exploitation course
    - [pwn.college](https://pwn.college/) - ASU's free course

---

## Category 2: Hardware Hacking

**Goal:** Intercept and decode physical signals between electronic components.

### Methodology

```
1. IDENTIFY    →    2. CONNECT    →    3. DECODE
   The chip          Logic Analyzer      Signal → Data
   (Datasheet)       (Saleae, etc.)      (CyberChef)
```

### Step 1: Identify the Chip

- Read markings on the chip
- Search for the **Datasheet** (pinout, protocols)
- Common protocols: UART, SPI, I2C, JTAG

### Step 2: Connect & Capture

| Tool | Purpose | Price Range |
|------|---------|-------------|
| **Logic Analyzer** | Capture digital signals | $10-$500 |
| **Saleae Logic** | Professional analyzer + software | $$$$ |
| **Bus Pirate** | Multi-protocol sniffer | $30 |
| **FTDI Adapter** | UART/Serial communication | $5-15 |
| **JTAGulator** | Auto-detect JTAG pinout | $150 |

### Step 3: Decode the Signal

```
Raw Signal → Binary → Hex → ASCII/Protocol Data
```

**Tools:**

- **Saleae Logic Software** - Protocol analyzers built-in
- **PulseView** - Open-source logic analyzer
- **CyberChef** - Swiss army knife for data transformation

### Common Protocols

| Protocol | Wires | Use Case |
|----------|-------|----------|
| **UART** | TX, RX, GND | Debug consoles, serial output |
| **SPI** | MOSI, MISO, CLK, CS | Flash memory, sensors |
| **I2C** | SDA, SCL | Low-speed peripherals |
| **JTAG** | TDI, TDO, TCK, TMS | Debugging, firmware extraction |

!!! example "CTF Scenario"
    Challenge gives you a logic analyzer capture file.

    1. Open in PulseView/Saleae
    2. Add protocol decoder (UART @ 115200 baud)
    3. Read the transmitted flag

---

## Category 3: OSINT (Open Source Intelligence)

**Goal:** Gather intelligence using publicly available information.

!!! tip "The Golden Rule"
    **Everything is a clue.**

    A photo of an employee badge on LinkedIn can reveal:

    - Badge ID format (sequential? random?)
    - Company logo version (timeline)
    - Building layout (background)
    - Access card technology (RFID type visible)

### OSINT Toolkit

| Tool | Purpose |
|------|---------|
| **Google Dorks** | Advanced search operators |
| **Maltego** | Visual link analysis |
| **Sherlock** | Username search across platforms |
| **theHarvester** | Email & subdomain enumeration |
| **Wayback Machine** | Historical website snapshots |
| **ExifTool** | Image metadata extraction |
| **GeoGuessr skills** | Location identification from photos |

### Google Dorks Cheatsheet

```
site:example.com              # Search within domain
filetype:pdf confidential     # Find specific file types
intitle:"index of"            # Directory listings
inurl:admin                   # URLs containing "admin"
"password" filetype:log       # Exposed log files
cache:example.com             # Google's cached version
```

### Image Analysis

```bash
# Extract metadata
exiftool image.jpg

# Look for:
# - GPS coordinates
# - Camera model
# - Creation date
# - Software used
# - Embedded thumbnails
```

### Social Media OSINT

- **LinkedIn:** Employee names, job titles, technologies used
- **Twitter/X:** Real-time events, opinions, slip-ups
- **GitHub:** Code, emails, API keys in commits
- **Instagram:** Location tags, background details

!!! warning "Ethics & Legality"
    OSINT uses **public** data only. Never access private accounts, hack systems, or impersonate people. Stay legal.

---

## Category 4: Lockpicking (Physical Security)

The physical side of hacking, often featured in onsite CTFs and security conferences.

### Basic Tools

| Tool | Purpose |
|------|---------|
| **Tension Wrench** | Apply rotational pressure |
| **Hook Pick** | Manipulate individual pins |
| **Rake** | Quickly set multiple pins |
| **Bump Key** | Strike-based opening |

### The Technique (Pin Tumbler Locks)

```
1. Insert tension wrench, apply light rotation
2. Insert pick, feel for binding pin
3. Push binding pin to shear line
4. Repeat for remaining pins
5. Lock opens when all pins set
```

### Practice Resources

- **Practice locks** - Clear/cutaway locks to see mechanism
- **Lock Sport** communities - Legal, educational focus
- **TOOOL** - The Open Organisation Of Lockpickers

!!! info "Why It Matters"
    Physical security is often the weakest link. Social engineering + physical access = game over for most organizations.

---

## CTF Toolkit Summary

```bash
# Must-have tools
sudo apt install -y \
    gdb \
    ghidra \
    binwalk \          # Firmware analysis
    steghide \         # Steganography
    exiftool \         # Metadata
    john \             # Password cracking
    hashcat \          # GPU cracking
    wireshark \        # Packet analysis
    burpsuite          # Web testing

# Python libraries
pip install pwntools pycryptodome requests
```

### CyberChef Recipes to Know

- **From Hex** / **To Hex**
- **Base64 Decode**
- **ROT13** / **ROT47**
- **XOR** with key
- **Magic** (auto-detect encoding)

---

!!! success "Pro Tips"
    1. **Read the challenge description carefully** - hints are often hidden
    2. **Check file signatures** - `file mystery.bin`, `binwalk mystery.bin`
    3. **Strings everything** - `strings -n 8 binary | grep -i flag`
    4. **Google error messages** - someone else probably solved it
    5. **Take breaks** - fresh eyes find flags faster
    6. **Document everything** - write notes as you go
