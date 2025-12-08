---
title: "Network Troubleshooting Cheatsheet"
description: "Essential commands for network diagnostics and troubleshooting on Linux"
tags: ["networking", "linux", "troubleshooting", "tcpdump", "cheatsheet"]
---

# Network Troubleshooting Cheatsheet

## Interface Management

### ip Command

#### Show Information

```bash
# Show all interfaces
ip link show
ip a                    # Short for 'ip address show'

# Show specific interface
ip link show eth0
ip addr show dev eth0

# Show only IPv4
ip -4 addr

# Show only IPv6
ip -6 addr

# Show interface statistics
ip -s link
ip -s -s link          # More detailed

# Show routing table
ip route
ip route show

# Show routing for specific destination
ip route get 8.8.8.8

# Show ARP table
ip neigh
ip neigh show
```

#### Configure Interfaces

```bash
# Bring interface up/down
ip link set eth0 up
ip link set eth0 down

# Set IP address
ip addr add 192.168.1.10/24 dev eth0

# Delete IP address
ip addr del 192.168.1.10/24 dev eth0

# Set MAC address
ip link set dev eth0 address 00:11:22:33:44:55

# Set MTU
ip link set dev eth0 mtu 9000

# Add alias interface
ip addr add 192.168.1.20/24 dev eth0 label eth0:0
```

#### Routing

```bash
# Add default gateway
ip route add default via 192.168.1.1

# Add static route
ip route add 10.0.0.0/8 via 192.168.1.254

# Add route through interface
ip route add 10.0.0.0/8 dev eth1

# Delete route
ip route del 10.0.0.0/8

# Replace route
ip route replace 10.0.0.0/8 via 192.168.1.254

# Flush routing table
ip route flush table main
```

### Legacy ifconfig/route

```bash
# Show interfaces
ifconfig
ifconfig eth0

# Configure IP
ifconfig eth0 192.168.1.10 netmask 255.255.255.0

# Bring interface up/down
ifconfig eth0 up
ifconfig eth0 down

# Show routing table
route -n
netstat -rn

# Add default gateway
route add default gw 192.168.1.1

# Add static route
route add -net 10.0.0.0/8 gw 192.168.1.254

# Delete route
route del -net 10.0.0.0/8
```

## Connection Monitoring

### ss (Socket Statistics)

```bash
# Show all connections
ss -a

# Show TCP connections
ss -t

# Show UDP connections
ss -u

# Show listening sockets
ss -l

# Show TCP listening sockets
ss -tl

# Show processes
ss -p

# Show numeric ports (no resolution)
ss -n

# Show summary
ss -s

# Common combinations
ss -tunlp              # TCP/UDP, numeric, listening, with processes
ss -tanp               # TCP, all, numeric, with processes

# Filter by state
ss state established
ss state syn-sent
ss state time-wait

# Filter by port
ss -t sport = :80
ss -t dport = :443
ss sport = :22 or sport = :80

# Filter by address
ss dst 192.168.1.100
ss src 10.0.0.0/8

# Show socket memory usage
ss -tm

# Show internal TCP information
ss -ti
```

### netstat (Legacy)

```bash
# Show all connections
netstat -a

# Show TCP connections
netstat -t

# Show UDP connections
netstat -u

# Show listening sockets
netstat -l

# Show numeric addresses
netstat -n

# Show programs
netstat -p

# Show routing table
netstat -r

# Show interface statistics
netstat -i

# Common combinations
netstat -tunlp         # TCP/UDP, numeric, listening, programs
netstat -anp           # All, numeric, programs

# Continuous monitoring
netstat -c

# Count connections by state
netstat -ant | awk '{print $6}' | sort | uniq -c
```

## DNS Diagnostics

### dig

```bash
# Basic query
dig example.com

# Short answer
dig example.com +short

# Specific record type
dig example.com A
dig example.com AAAA
dig example.com MX
dig example.com NS
dig example.com TXT
dig example.com SOA

# Query specific nameserver
dig @8.8.8.8 example.com

# Reverse DNS lookup
dig -x 8.8.8.8

# Trace query path
dig example.com +trace

# Show only answer section
dig example.com +noall +answer

# Query all records
dig example.com ANY

# Batch query from file
dig -f domains.txt

# Check DNSSEC
dig example.com +dnssec

# Show query time
dig example.com +stats

# TCP query
dig example.com +tcp
```

### nslookup

```bash
# Basic query
nslookup example.com

# Query specific nameserver
nslookup example.com 8.8.8.8

# Query specific record type
nslookup -query=MX example.com
nslookup -query=NS example.com

# Reverse lookup
nslookup 8.8.8.8

# Interactive mode
nslookup
> server 8.8.8.8
> set type=MX
> example.com
> exit
```

### host

```bash
# Basic query
host example.com

# Show all records
host -a example.com

# Query specific type
host -t MX example.com
host -t NS example.com

# Query specific nameserver
host example.com 8.8.8.8

# Reverse lookup
host 8.8.8.8

# Verbose output
host -v example.com
```

### systemd-resolve (systemd-based)

```bash
# Query DNS
resolvectl query example.com

# Show DNS settings
resolvectl status

# Show statistics
resolvectl statistics

# Flush DNS cache
resolvectl flush-caches

# Reset statistics
resolvectl reset-statistics
```

## Connectivity Testing

### ping

```bash
# Basic ping
ping example.com

# Ping with count
ping -c 4 example.com

# Ping with interval
ping -i 0.5 example.com      # 0.5 seconds

# Ping with timeout
ping -w 10 example.com       # 10 seconds

# Set packet size
ping -s 1000 example.com     # 1000 bytes

# Ping IPv6
ping6 example.com

# Flood ping (requires root)
ping -f example.com

# Audible ping
ping -a example.com

# Set TTL
ping -t 64 example.com

# Don't fragment
ping -M do -s 1472 example.com    # Path MTU discovery
```

### traceroute

```bash
# Basic traceroute
traceroute example.com

# Use ICMP instead of UDP
traceroute -I example.com

# Use TCP
traceroute -T example.com

# Set max hops
traceroute -m 20 example.com

# Set number of queries per hop
traceroute -q 2 example.com

# Show AS numbers
traceroute -A example.com

# IPv6 traceroute
traceroute6 example.com

# Don't resolve hostnames
traceroute -n example.com
```

### mtr (My Traceroute)

```bash
# Interactive mode
mtr example.com

# Report mode (10 cycles)
mtr -r -c 10 example.com

# Use TCP
mtr -T example.com

# Use ICMP
mtr -I example.com

# Show AS numbers
mtr -z example.com

# No DNS resolution
mtr -n example.com

# CSV output
mtr --csv example.com

# JSON output
mtr --json example.com
```

### nc (netcat)

```bash
# Test TCP connection
nc -zv example.com 80

# Test port range
nc -zv example.com 20-30

# Listen on port
nc -l 8080

# Transfer file
# Receiver:
nc -l 8080 > received_file
# Sender:
nc target_host 8080 < file_to_send

# Simple chat
# Server:
nc -l 8080
# Client:
nc server_host 8080

# Port scanning
nc -zv example.com 1-1000

# UDP mode
nc -u example.com 53

# Execute command on connect
nc -l 8080 -e /bin/bash    # Dangerous!
```

### telnet

```bash
# Connect to host/port
telnet example.com 80

# Test SMTP
telnet mail.example.com 25
EHLO example.com
QUIT

# Test HTTP
telnet example.com 80
GET / HTTP/1.1
Host: example.com

# Test POP3
telnet mail.example.com 110
USER username
PASS password
```

## Packet Capture

### tcpdump

#### Basic Capture

```bash
# Capture on default interface
tcpdump

# Capture on specific interface
tcpdump -i eth0

# Capture to file
tcpdump -w capture.pcap

# Read from file
tcpdump -r capture.pcap

# Capture n packets
tcpdump -c 100

# Don't convert addresses
tcpdump -n

# Don't convert ports
tcpdump -nn

# Verbose output
tcpdump -v
tcpdump -vv
tcpdump -vvv

# Show packet contents (hex)
tcpdump -X

# Show packet contents (hex + ASCII)
tcpdump -XX

# Show absolute sequence numbers
tcpdump -S
```

#### Filters

```bash
# Filter by host
tcpdump host 192.168.1.100
tcpdump src host 192.168.1.100
tcpdump dst host 192.168.1.100

# Filter by network
tcpdump net 192.168.1.0/24

# Filter by port
tcpdump port 80
tcpdump src port 80
tcpdump dst port 80
tcpdump portrange 20-30

# Filter by protocol
tcpdump tcp
tcpdump udp
tcpdump icmp
tcpdump ip6

# Combine filters
tcpdump 'host 192.168.1.100 and port 80'
tcpdump 'host 192.168.1.100 or host 192.168.1.101'
tcpdump 'port 80 and not host 192.168.1.100'

# TCP flags
tcpdump 'tcp[tcpflags] & (tcp-syn) != 0'    # SYN
tcpdump 'tcp[tcpflags] & (tcp-ack) != 0'    # ACK
tcpdump 'tcp[tcpflags] & (tcp-rst) != 0'    # RST

# HTTP GET requests
tcpdump -s 0 -A 'tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)' | grep GET

# DNS queries
tcpdump -i any -s0 port 53
```

#### Advanced Examples

```bash
# Capture HTTP traffic
tcpdump -i eth0 -s 0 -A 'tcp port 80'

# Capture HTTPS traffic
tcpdump -i eth0 'tcp port 443'

# Capture traffic to/from subnet
tcpdump -i eth0 'net 10.0.0.0/8'

# Capture with size and time
tcpdump -i eth0 -s 65535 -w capture_$(date +%Y%m%d_%H%M%S).pcap

# Rotating capture files
tcpdump -i eth0 -w capture.pcap -C 100 -W 10    # 100MB files, keep 10

# Filter by MAC address
tcpdump -i eth0 ether host 00:11:22:33:44:55

# Capture only SYN packets
tcpdump -i eth0 'tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack = 0'

# Capture packets larger than N bytes
tcpdump -i eth0 'greater 1000'

# Capture broadcast/multicast
tcpdump -i eth0 'broadcast or multicast'
```

### tshark (Wireshark CLI)

```bash
# Capture on interface
tshark -i eth0

# Capture to file
tshark -i eth0 -w capture.pcap

# Read from file
tshark -r capture.pcap

# Display filter
tshark -r capture.pcap -Y "http.request.method == GET"

# Show specific fields
tshark -r capture.pcap -T fields -e ip.src -e ip.dst -e tcp.port

# Capture with display filter
tshark -i eth0 -f "tcp port 80" -Y "http"

# Statistics
tshark -r capture.pcap -q -z io,stat,1    # I/O graph
tshark -r capture.pcap -q -z conv,tcp     # TCP conversations

# Export objects
tshark -r capture.pcap --export-objects http,/tmp/

# Follow TCP stream
tshark -r capture.pcap -q -z follow,tcp,ascii,0
```

## Port Scanning

### nmap

#### Basic Scans

```bash
# Scan single host
nmap 192.168.1.100

# Scan subnet
nmap 192.168.1.0/24

# Scan range
nmap 192.168.1.1-254

# Scan from list
nmap -iL hosts.txt

# Fast scan (100 most common ports)
nmap -F 192.168.1.100

# Scan all ports
nmap -p- 192.168.1.100

# Scan specific ports
nmap -p 22,80,443 192.168.1.100
nmap -p 1-1000 192.168.1.100
```

#### Scan Types

```bash
# TCP SYN scan (default, requires root)
nmap -sS 192.168.1.100

# TCP connect scan
nmap -sT 192.168.1.100

# UDP scan
nmap -sU 192.168.1.100

# Ping scan (no port scan)
nmap -sn 192.168.1.0/24

# No ping (assume host up)
nmap -Pn 192.168.1.100

# Version detection
nmap -sV 192.168.1.100

# OS detection
nmap -O 192.168.1.100

# Aggressive scan
nmap -A 192.168.1.100      # OS, version, script, traceroute
```

#### Output Options

```bash
# Normal output
nmap -oN output.txt 192.168.1.100

# XML output
nmap -oX output.xml 192.168.1.100

# Grepable output
nmap -oG output.txt 192.168.1.100

# All formats
nmap -oA output 192.168.1.100

# Verbose
nmap -v 192.168.1.100
nmap -vv 192.168.1.100
```

#### NSE Scripts

```bash
# Run default scripts
nmap -sC 192.168.1.100

# Run specific script
nmap --script=http-title 192.168.1.100

# Run script category
nmap --script=vuln 192.168.1.100

# Update script database
nmap --script-updatedb

# Get script help
nmap --script-help=http-title

# Multiple scripts
nmap --script=http-title,http-headers 192.168.1.100
```

#### Timing & Performance

```bash
# Timing templates (0-5, paranoid to insane)
nmap -T0 192.168.1.100     # Paranoid (slowest)
nmap -T4 192.168.1.100     # Aggressive (fast)

# Set max parallel connections
nmap --min-parallelism 100 192.168.1.100

# Set rate limit
nmap --max-rate 50 192.168.1.100
```

## Firewall Commands

### iptables

#### List Rules

```bash
# List all rules
iptables -L

# List with line numbers
iptables -L --line-numbers

# List with packet counts
iptables -L -v

# List INPUT chain
iptables -L INPUT

# List in raw format
iptables -S

# List NAT rules
iptables -t nat -L
```

#### Add Rules

```bash
# Allow incoming SSH
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Allow incoming HTTP/HTTPS
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Allow from specific IP
iptables -A INPUT -s 192.168.1.100 -j ACCEPT

# Allow established connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT

# Drop all other input
iptables -A INPUT -j DROP
```

#### Delete Rules

```bash
# Delete by line number
iptables -D INPUT 5

# Delete specific rule
iptables -D INPUT -p tcp --dport 80 -j ACCEPT

# Flush all rules
iptables -F

# Flush specific chain
iptables -F INPUT
```

#### Save/Restore

```bash
# Save rules (Debian/Ubuntu)
iptables-save > /etc/iptables/rules.v4

# Restore rules
iptables-restore < /etc/iptables/rules.v4

# Save (RHEL/CentOS)
service iptables save
```

### firewalld

```bash
# Show status
firewall-cmd --state

# List all
firewall-cmd --list-all

# List services
firewall-cmd --list-services

# List ports
firewall-cmd --list-ports

# Add service
firewall-cmd --add-service=http
firewall-cmd --add-service=http --permanent

# Add port
firewall-cmd --add-port=8080/tcp
firewall-cmd --add-port=8080/tcp --permanent

# Remove service
firewall-cmd --remove-service=http --permanent

# Reload
firewall-cmd --reload

# Get default zone
firewall-cmd --get-default-zone

# Set default zone
firewall-cmd --set-default-zone=public

# Add interface to zone
firewall-cmd --zone=public --add-interface=eth0

# Rich rules
firewall-cmd --add-rich-rule='rule family=ipv4 source address=192.168.1.0/24 accept'
```

### ufw (Uncomplicated Firewall)

```bash
# Enable/disable
ufw enable
ufw disable

# Show status
ufw status
ufw status verbose
ufw status numbered

# Default policies
ufw default deny incoming
ufw default allow outgoing

# Allow service
ufw allow ssh
ufw allow http
ufw allow https

# Allow port
ufw allow 8080/tcp

# Allow from specific IP
ufw allow from 192.168.1.100

# Allow from subnet
ufw allow from 192.168.1.0/24

# Allow to specific port from IP
ufw allow from 192.168.1.100 to any port 22

# Deny
ufw deny 23/tcp

# Delete rule
ufw delete allow 80/tcp
ufw delete 2        # By number

# Reset firewall
ufw reset
```

## Performance & Bandwidth

### iperf3

```bash
# Server mode
iperf3 -s

# Client mode
iperf3 -c server_ip

# Test for 30 seconds
iperf3 -c server_ip -t 30

# Reverse mode (server sends)
iperf3 -c server_ip -R

# UDP test
iperf3 -c server_ip -u

# Set bandwidth
iperf3 -c server_ip -u -b 100M

# Parallel streams
iperf3 -c server_ip -P 4

# JSON output
iperf3 -c server_ip -J

# IPv6
iperf3 -c server_ip -6
```

### iftop

```bash
# Monitor interface
iftop

# Specific interface
iftop -i eth0

# Show ports
iftop -P

# Show bars
iftop -b

# Text output
iftop -t

# Filter by network
iftop -F 192.168.1.0/24

# No DNS resolution
iftop -n
```

### nethogs

```bash
# Monitor all interfaces
nethogs

# Specific interface
nethogs eth0

# Update every N seconds
nethogs -d 5

# Trace mode
nethogs -t
```

## Tips & Common Tasks

### Find Which Process Uses Port

```bash
# Using lsof
lsof -i :80
lsof -i tcp:80
lsof -i udp:53

# Using ss
ss -tulpn | grep :80

# Using netstat
netstat -tulpn | grep :80

# Using fuser
fuser 80/tcp
```

### Test Network Throughput

```bash
# Using dd and nc
# Server:
nc -l 8080 > /dev/null
# Client:
dd if=/dev/zero bs=1M count=1000 | nc server_ip 8080

# Using pv
# Server:
nc -l 8080 > /dev/null
# Client:
cat /dev/zero | pv | nc server_ip 8080
```

### Monitor Traffic in Real-time

```bash
# Using iftop
iftop -i eth0

# Using nload
nload eth0

# Using bmon
bmon -p eth0

# Using iptraf-ng
iptraf-ng

# Using vnstat
vnstat -l -i eth0
```

### Check Network Latency

```bash
# Simple ping
ping -c 10 8.8.8.8 | tail -1

# Detailed with mtr
mtr -r -c 100 8.8.8.8

# Check jitter
ping -c 100 8.8.8.8 | awk '/time=/ {print $7}' | cut -d= -f2 | awk '{sum+=$1; sumsq+=$1*$1} END {print "Avg:", sum/NR, "StdDev:", sqrt(sumsq/NR - (sum/NR)^2)}'
```

## Resources

- [Linux Network Administrators Guide](https://www.tldp.org/LDP/nag2/index.html)
- [tcpdump Tutorial](https://danielmiessler.com/study/tcpdump/)
- [Nmap Reference Guide](https://nmap.org/book/man.html)
- [iptables Tutorial](https://www.frozentux.net/iptables-tutorial/iptables-tutorial.html)
- [Wireshark User Guide](https://www.wireshark.org/docs/wsug_html_chunked/)
