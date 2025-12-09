---
tags:
  - formation
  - python
  - réseau
  - sockets
  - tcp
  - udp
---

# Module 10 - Programmation Réseau

Comprendre et utiliser les sockets pour la communication réseau.

---

## Objectifs du Module

- Comprendre les concepts réseau (TCP, UDP)
- Utiliser le module socket
- Créer des clients et serveurs simples
- Scanner et diagnostiquer des réseaux

---

## 1. Concepts Fondamentaux

### Le Modèle TCP/IP

```text
Application (HTTP, SSH, DNS)
       ↓
Transport (TCP, UDP)
       ↓
Internet (IP)
       ↓
Accès réseau (Ethernet, WiFi)
```

### TCP vs UDP

| Caractéristique | TCP | UDP |
|-----------------|-----|-----|
| Connexion | Orienté connexion | Sans connexion |
| Fiabilité | Garantie de livraison | Pas de garantie |
| Ordre | Préservé | Non garanti |
| Usage | HTTP, SSH, FTP | DNS, DHCP, streaming |

---

## 2. Module socket

### Client TCP Simple

```python
import socket

def tcp_client(host, port, message):
    """Client TCP simple."""
    # Créer le socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        # Se connecter
        sock.connect((host, port))

        # Envoyer des données
        sock.sendall(message.encode())

        # Recevoir la réponse
        response = sock.recv(4096)
        return response.decode()

    finally:
        sock.close()

# Utilisation
response = tcp_client("example.com", 80, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
print(response)
```

### Client TCP avec Context Manager

```python
import socket

def tcp_request(host, port, data, timeout=10):
    """Requête TCP avec timeout et context manager."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.sendall(data.encode() if isinstance(data, str) else data)

        # Recevoir toute la réponse
        chunks = []
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)

        return b"".join(chunks)
```

### Serveur TCP Simple

```python
import socket

def tcp_server(host, port):
    """Serveur TCP echo simple."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        # Réutiliser l'adresse
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        server.bind((host, port))
        server.listen(5)
        print(f"Serveur en écoute sur {host}:{port}")

        while True:
            client, address = server.accept()
            print(f"Connexion de {address}")

            with client:
                while True:
                    data = client.recv(1024)
                    if not data:
                        break
                    # Echo : renvoie les données reçues
                    client.sendall(data)

            print(f"Déconnexion de {address}")

# Lancer le serveur
# tcp_server("0.0.0.0", 9999)
```

### Serveur Multi-clients (Threading)

```python
import socket
import threading

class ThreadedTCPServer:
    """Serveur TCP multi-clients."""

    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.server = None
        self.running = False

    def start(self):
        """Démarre le serveur."""
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((self.host, self.port))
        self.server.listen(5)
        self.running = True

        print(f"Serveur démarré sur {self.host}:{self.port}")

        while self.running:
            try:
                client, address = self.server.accept()
                thread = threading.Thread(
                    target=self.handle_client,
                    args=(client, address)
                )
                thread.daemon = True
                thread.start()
            except socket.error:
                break

    def handle_client(self, client, address):
        """Gère un client dans un thread séparé."""
        print(f"Nouveau client: {address}")
        try:
            while True:
                data = client.recv(1024)
                if not data:
                    break
                # Traiter les données
                response = self.process(data)
                client.sendall(response)
        finally:
            client.close()
            print(f"Client déconnecté: {address}")

    def process(self, data):
        """Traite les données reçues."""
        return data.upper()

    def stop(self):
        """Arrête le serveur."""
        self.running = False
        if self.server:
            self.server.close()
```

---

## 3. Client/Serveur UDP

### Client UDP

```python
import socket

def udp_client(host, port, message):
    """Client UDP simple."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(5)

        # Envoyer (pas de connexion préalable)
        sock.sendto(message.encode(), (host, port))

        # Recevoir la réponse
        data, server = sock.recvfrom(4096)
        return data.decode()

# Exemple : requête DNS simplifiée
response = udp_client("8.8.8.8", 53, dns_query)
```

### Serveur UDP

```python
import socket

def udp_server(host, port):
    """Serveur UDP simple."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((host, port))
        print(f"Serveur UDP en écoute sur {host}:{port}")

        while True:
            data, client = sock.recvfrom(1024)
            print(f"Reçu de {client}: {data}")

            # Répondre
            response = data.upper()
            sock.sendto(response, client)
```

---

## 4. Résolution DNS

```python
import socket

# Résolution simple
ip = socket.gethostbyname("google.com")
print(f"IP: {ip}")

# Résolution complète
info = socket.getaddrinfo("google.com", 443)
for family, socktype, proto, canonname, sockaddr in info:
    print(f"{family.name}: {sockaddr}")

# Résolution inverse
hostname = socket.gethostbyaddr("8.8.8.8")
print(f"Hostname: {hostname[0]}")

# Nom de la machine locale
print(socket.gethostname())
print(socket.getfqdn())
```

---

## 5. Outils Réseau SysOps

### Port Scanner

```python
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple

def scan_port(host: str, port: int, timeout: float = 1) -> Tuple[int, bool]:
    """Scan un port individuel."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            return port, result == 0
    except socket.error:
        return port, False

def scan_ports(host: str, ports: List[int], max_workers: int = 100) -> dict:
    """Scan plusieurs ports en parallèle."""
    open_ports = []
    closed_ports = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(scan_port, host, port): port
            for port in ports
        }

        for future in as_completed(futures):
            port, is_open = future.result()
            if is_open:
                open_ports.append(port)
            else:
                closed_ports.append(port)

    return {
        "host": host,
        "open": sorted(open_ports),
        "closed_count": len(closed_ports)
    }

# Utilisation
result = scan_ports("192.168.1.1", range(1, 1025))
print(f"Ports ouverts: {result['open']}")
```

### Vérification de Connectivité

```python
import socket
from dataclasses import dataclass
from typing import Optional

@dataclass
class ConnectivityResult:
    host: str
    port: int
    reachable: bool
    latency_ms: Optional[float]
    error: Optional[str]

def check_connectivity(host: str, port: int, timeout: float = 5) -> ConnectivityResult:
    """Vérifie la connectivité vers un host:port."""
    import time

    start = time.time()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((host, port))
            latency = (time.time() - start) * 1000

            return ConnectivityResult(
                host=host,
                port=port,
                reachable=True,
                latency_ms=round(latency, 2),
                error=None
            )
    except socket.timeout:
        return ConnectivityResult(host, port, False, None, "Timeout")
    except socket.error as e:
        return ConnectivityResult(host, port, False, None, str(e))

# Vérifier plusieurs endpoints
endpoints = [
    ("google.com", 443),
    ("github.com", 22),
    ("192.168.1.1", 80),
]

for host, port in endpoints:
    result = check_connectivity(host, port)
    status = "✓" if result.reachable else "✗"
    print(f"{status} {host}:{port} - {result.latency_ms or result.error}")
```

### Service Banner Grabbing

```python
import socket

def grab_banner(host: str, port: int, timeout: float = 3) -> str:
    """Récupère la bannière d'un service."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((host, port))

            # Certains services envoient une bannière immédiatement
            # Pour HTTP, il faut envoyer une requête
            if port in [80, 8080, 443]:
                sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")

            banner = sock.recv(1024)
            return banner.decode(errors="ignore").strip()
    except Exception as e:
        return f"Error: {e}"

# Récupérer les bannières
services = [
    ("192.168.1.1", 22),   # SSH
    ("192.168.1.1", 80),   # HTTP
    ("192.168.1.1", 21),   # FTP
]

for host, port in services:
    banner = grab_banner(host, port)
    print(f"{host}:{port} -> {banner[:50]}")
```

### Résolveur DNS Personnalisé

```python
import socket
import struct

def dns_query(domain: str, dns_server: str = "8.8.8.8") -> list:
    """Effectue une requête DNS simple."""

    # Construire la requête DNS
    transaction_id = b"\xaa\xbb"
    flags = b"\x01\x00"  # Standard query
    questions = b"\x00\x01"
    answer_rrs = b"\x00\x00"
    authority_rrs = b"\x00\x00"
    additional_rrs = b"\x00\x00"

    header = transaction_id + flags + questions + answer_rrs + authority_rrs + additional_rrs

    # Encoder le nom de domaine
    qname = b""
    for part in domain.split("."):
        qname += bytes([len(part)]) + part.encode()
    qname += b"\x00"

    qtype = b"\x00\x01"   # A record
    qclass = b"\x00\x01"  # IN class

    question = qname + qtype + qclass
    query = header + question

    # Envoyer la requête
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(5)
        sock.sendto(query, (dns_server, 53))
        response, _ = sock.recvfrom(512)

    # Parser la réponse (simplifié)
    answer_count = struct.unpack(">H", response[6:8])[0]
    print(f"Réponses: {answer_count}")

    # Les IPs sont à la fin de la réponse pour les A records
    ips = []
    pos = len(query)
    for _ in range(answer_count):
        # Skip name, type, class, ttl
        pos += 12
        data_len = struct.unpack(">H", response[pos-2:pos])[0]
        if data_len == 4:  # IPv4
            ip = ".".join(str(b) for b in response[pos:pos+4])
            ips.append(ip)
        pos += data_len

    return ips

# Utilisation
ips = dns_query("google.com")
print(f"IPs: {ips}")
```

---

## 6. Informations Réseau Locales

```python
import socket
import fcntl
import struct

def get_local_ip():
    """Obtient l'IP locale utilisée pour les connexions sortantes."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"

def get_interface_ip(interface: str) -> str:
    """Obtient l'IP d'une interface (Linux)."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ip = socket.inet_ntoa(fcntl.ioctl(
            sock.fileno(),
            0x8915,  # SIOCGIFADDR
            struct.pack('256s', interface.encode()[:15])
        )[20:24])
        return ip
    except Exception as e:
        return f"Error: {e}"

# Lister toutes les interfaces (avec netifaces)
def list_interfaces():
    """Liste les interfaces réseau (nécessite netifaces)."""
    try:
        import netifaces
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs:
                for addr in addrs[netifaces.AF_INET]:
                    print(f"{iface}: {addr['addr']}")
    except ImportError:
        print("Module netifaces non installé")

print(f"IP locale: {get_local_ip()}")
```

---

## 7. Patterns Avancés

### Timeout et Retry

```python
import socket
import time

def robust_connect(host: str, port: int, retries: int = 3, delay: float = 1) -> socket.socket:
    """Connexion avec retry automatique."""
    last_error = None

    for attempt in range(retries):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            return sock
        except socket.error as e:
            last_error = e
            if attempt < retries - 1:
                time.sleep(delay * (attempt + 1))
            sock.close()

    raise last_error
```

### Non-Blocking Sockets

```python
import socket
import select

def non_blocking_server(host, port):
    """Serveur non-bloquant avec select."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.setblocking(False)
    server.bind((host, port))
    server.listen(5)

    inputs = [server]
    outputs = []

    while inputs:
        readable, writable, exceptional = select.select(inputs, outputs, inputs)

        for sock in readable:
            if sock is server:
                # Nouvelle connexion
                client, addr = sock.accept()
                client.setblocking(False)
                inputs.append(client)
            else:
                # Données d'un client
                data = sock.recv(1024)
                if data:
                    # Traiter les données
                    if sock not in outputs:
                        outputs.append(sock)
                else:
                    # Client déconnecté
                    if sock in outputs:
                        outputs.remove(sock)
                    inputs.remove(sock)
                    sock.close()

        for sock in exceptional:
            inputs.remove(sock)
            if sock in outputs:
                outputs.remove(sock)
            sock.close()
```

---

## Exercices Pratiques

### Exercice 1 : Ping TCP

```python
# Créer une fonction tcp_ping() qui :
# - Mesure le temps de connexion TCP
# - Supporte plusieurs tentatives
# - Retourne min/max/avg latency
```

### Exercice 2 : Serveur de Monitoring

```python
# Créer un serveur TCP qui :
# - Accepte des connexions de clients
# - Répond aux commandes : STATUS, UPTIME, MEMORY
# - Log toutes les connexions
```

### Exercice 3 : Network Discovery

```python
# Créer un script qui :
# - Scanne un subnet (ex: 192.168.1.0/24)
# - Identifie les hôtes actifs (ping TCP port 22 ou 80)
# - Liste les services courants ouverts
```

---

## Points Clés à Retenir

!!! success "Bonnes Pratiques"
    - Toujours définir un timeout sur les sockets
    - Utiliser les context managers (`with`)
    - Gérer proprement les erreurs réseau
    - Fermer les connexions après usage

!!! warning "Sécurité"
    - Ne jamais exposer de sockets sans authentification
    - Valider toutes les données reçues
    - Utiliser SSL/TLS pour les données sensibles
    - Limiter le rate des connexions

---

## Voir Aussi

- [Module 11 - APIs REST](11-api-rest.md)
- [Module 12 - SSH & Automatisation](12-ssh.md)

---

## Navigation

| | |
|:---|---:|
| [← Module 09 - Gestion des Erreurs & Log...](09-erreurs.md) | [Module 11 - APIs REST & HTTP →](11-api-rest.md) |

[Retour au Programme](index.md){ .md-button }
