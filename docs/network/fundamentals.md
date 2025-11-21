# Network Survival Kit

`#cidr` `#tcp-ip` `#load-balancing`

Essential networking concepts every DevOps and SysAdmin must know.

---

## CIDR Cheat Sheet

| CIDR | Subnet Mask | Total IPs | Usable IPs | Use Case |
|------|-------------|-----------|------------|----------|
| `/32` | 255.255.255.255 | 1 | 1 | Single host (firewall rules) |
| `/31` | 255.255.255.254 | 2 | 2 | Point-to-point links |
| `/30` | 255.255.255.252 | 4 | 2 | Router interconnects |
| `/29` | 255.255.255.248 | 8 | 6 | Small office |
| `/28` | 255.255.255.240 | 16 | 14 | Small network |
| `/27` | 255.255.255.224 | 32 | 30 | Medium network |
| `/26` | 255.255.255.192 | 64 | 62 | Large subnet |
| `/25` | 255.255.255.128 | 128 | 126 | Half a /24 |
| `/24` | 255.255.255.0 | 256 | 254 | Standard LAN |
| `/16` | 255.255.0.0 | 65,536 | 65,534 | Large VPC/Corporate |
| `/8` | 255.0.0.0 | 16,777,216 | 16,777,214 | Massive networks |

!!! tip "Quick Math"
    Usable IPs = 2^(32-CIDR) - 2 (network + broadcast addresses)

    ```bash
    # Calculate subnet info
    ipcalc 192.168.1.0/24
    ```

---

## The "Weird" IPs

!!! info "127.0.0.1 - Localhost"
    The loopback address. Traffic never leaves your machine.

    - `127.0.0.1` - IPv4 loopback
    - `::1` - IPv6 loopback
    - Entire `127.0.0.0/8` range is reserved for loopback

!!! danger "169.254.x.x - APIPA (Your DHCP is Dead)"
    **Automatic Private IP Addressing** (Link-Local)

    If you see this IP, your device **failed to get an address from DHCP**.

    ```bash
    $ ip addr
    inet 169.254.47.123/16  # ← DHCP server is unreachable!
    ```

    **Debugging steps:**
    ```bash
    # Check DHCP service
    systemctl status dhcpd

    # Request new lease
    sudo dhclient -v eth0

    # Check network cable/connectivity
    ethtool eth0
    ```

!!! warning "100.64.0.0/10 - CGNAT (Carrier-Grade NAT)"
    Shared address space used by ISPs (RFC 6598).

    Common on:

    - Mobile networks (4G/5G)
    - Some residential ISPs
    - Cloud providers (internal)

    **Implication:** You're behind double NAT. Port forwarding won't work.

### Private IP Ranges (RFC 1918)

| Range | CIDR | Typical Use |
|-------|------|-------------|
| 10.0.0.0 - 10.255.255.255 | 10.0.0.0/8 | Large enterprises, AWS VPCs |
| 172.16.0.0 - 172.31.255.255 | 172.16.0.0/12 | Medium networks, Docker default |
| 192.168.0.0 - 192.168.255.255 | 192.168.0.0/16 | Home/small office LANs |

---

## Load Balancing: L4 vs L7

| Feature | Layer 4 (Transport) | Layer 7 (Application) |
|---------|---------------------|------------------------|
| **OSI Layer** | TCP/UDP | HTTP/HTTPS |
| **Speed** | Very fast | Slower (inspects content) |
| **Intelligence** | Dumb (IP + Port only) | Smart (URL, headers, cookies) |
| **SSL/TLS** | Passthrough (encrypted) | Termination (decrypted) |
| **Routing decisions** | Source IP, Dest Port | URL path, Host header, Cookies |
| **Use case** | Database, TCP services | Web apps, API gateways |
| **Examples** | HAProxy (TCP mode), NLB | Nginx, HAProxy (HTTP), ALB |

### L4 Load Balancer

```
Client → [L4 LB] → Server
         ↓
    Routes by IP:Port
    Cannot see HTTP content
    SSL passthrough
```

### L7 Load Balancer

```
Client → [L7 LB] → Server
         ↓
    SSL Termination
    Inspects HTTP headers
    Routes by URL: /api → backend-api
                   /web → backend-web
```

!!! example "When to use which?"
    - **L4:** MySQL, Redis, raw TCP, when you need SSL passthrough
    - **L7:** Web apps, REST APIs, when you need URL-based routing

---

## The Debugging Pyramid

Debug network issues layer by layer, from bottom to top.

=== "Layer 3 - ICMP (Is the host alive?)"

    ```bash
    # Basic connectivity test
    ping -c 4 google.com

    # With timeout
    ping -c 1 -W 2 192.168.1.1

    # Trace the route
    traceroute google.com
    mtr google.com  # Better interactive version
    ```

    **If ping fails:**

    - Host is down
    - Firewall blocking ICMP
    - Routing issue

=== "Layer 4 - TCP (Is the port open?)"

    ```bash
    # Test TCP port with nc (netcat)
    nc -zv google.com 443
    nc -zv 192.168.1.1 22

    # Using telnet
    telnet google.com 80

    # Test multiple ports
    nc -zv google.com 80 443 8080

    # With timeout
    nc -zv -w 3 google.com 443
    ```

    **If port is closed:**

    - Service not running
    - Firewall blocking port
    - Service bound to wrong interface

=== "Layer 7 - HTTP (Is the app responding?)"

    ```bash
    # Check HTTP response headers
    curl -I https://google.com

    # Full response with timing
    curl -w "@curl-format.txt" -o /dev/null -s https://google.com

    # Check specific endpoint
    curl -I https://api.example.com/health

    # With verbose SSL info
    curl -vI https://example.com
    ```

    **Response codes:**

    - `2xx` - Success
    - `3xx` - Redirect
    - `4xx` - Client error (check your request)
    - `5xx` - Server error (check backend logs)

### Quick Debug Flow

```
ping fails?     → Check routing, firewall, host status
  ↓ works
nc port fails?  → Check service, firewall rules, binding
  ↓ works
curl fails?     → Check app logs, config, SSL certs
  ↓ works
Problem is elsewhere (DNS, client-side, etc.)
```
