# Kit de Survie Réseau

`#cidr` `#tcp-ip` `#load-balancing`

Concepts réseau essentiels que tout DevOps et SysAdmin doit connaître.

---

## Aide-mémoire CIDR

| CIDR | Subnet Mask | Total IPs | IPs Utilisables | Cas d'Usage |
|------|-------------|-----------|------------|----------|
| `/32` | 255.255.255.255 | 1 | 1 | Hôte unique (règles firewall) |
| `/31` | 255.255.255.254 | 2 | 2 | Liens point-à-point |
| `/30` | 255.255.255.252 | 4 | 2 | Interconnexions de routeurs |
| `/29` | 255.255.255.248 | 8 | 6 | Petit bureau |
| `/28` | 255.255.255.240 | 16 | 14 | Petit réseau |
| `/27` | 255.255.255.224 | 32 | 30 | Réseau moyen |
| `/26` | 255.255.255.192 | 64 | 62 | Grand sous-réseau |
| `/25` | 255.255.255.128 | 128 | 126 | Moitié d'un /24 |
| `/24` | 255.255.255.0 | 256 | 254 | LAN standard |
| `/16` | 255.255.0.0 | 65,536 | 65,534 | Grand VPC/Entreprise |
| `/8` | 255.0.0.0 | 16,777,216 | 16,777,214 | Réseaux massifs |

!!! tip "Calcul Rapide"
    IPs utilisables = 2^(32-CIDR) - 2 (adresses réseau + broadcast)

    ```bash
    # Calculer les infos de sous-réseau
    ipcalc 192.168.1.0/24
    ```

---

## Les IPs "Bizarres"

!!! info "127.0.0.1 - Localhost"
    L'adresse de bouclage. Le trafic ne quitte jamais votre machine.

    - `127.0.0.1` - Bouclage IPv4
    - `::1` - Bouclage IPv6
    - La plage entière `127.0.0.0/8` est réservée pour le bouclage

!!! danger "169.254.x.x - APIPA (Votre DHCP est Mort)"
    **Automatic Private IP Addressing** (Link-Local)

    Si vous voyez cette IP, votre appareil **n'a pas réussi à obtenir une adresse depuis le DHCP**.

    ```bash
    $ ip addr
    inet 169.254.47.123/16  # ← Le serveur DHCP est injoignable !
    ```

    **Étapes de débogage :**
    ```bash
    # Vérifier le service DHCP
    systemctl status dhcpd

    # Demander un nouveau bail
    sudo dhclient -v eth0

    # Vérifier le câble réseau/connectivité
    ethtool eth0
    ```

!!! warning "100.64.0.0/10 - CGNAT (Carrier-Grade NAT)"
    Espace d'adressage partagé utilisé par les FAI (RFC 6598).

    Courant sur :

    - Réseaux mobiles (4G/5G)
    - Certains FAI résidentiels
    - Fournisseurs cloud (interne)

    **Implication :** Vous êtes derrière un double NAT. Le port forwarding ne fonctionnera pas.

### Plages IP Privées (RFC 1918)

| Plage | CIDR | Usage Typique |
|-------|------|-------------|
| 10.0.0.0 - 10.255.255.255 | 10.0.0.0/8 | Grandes entreprises, VPCs AWS |
| 172.16.0.0 - 172.31.255.255 | 172.16.0.0/12 | Réseaux moyens, Docker par défaut |
| 192.168.0.0 - 192.168.255.255 | 192.168.0.0/16 | LANs domestiques/petits bureaux |

---

## Load Balancing : L4 vs L7

| Fonctionnalité | Layer 4 (Transport) | Layer 7 (Application) |
|---------|---------------------|------------------------|
| **Couche OSI** | TCP/UDP | HTTP/HTTPS |
| **Vitesse** | Très rapide | Plus lent (inspecte le contenu) |
| **Intelligence** | Basique (IP + Port seulement) | Intelligent (URL, headers, cookies) |
| **SSL/TLS** | Passthrough (chiffré) | Termination (déchiffré) |
| **Décisions de routage** | IP source, Port destination | Chemin URL, Header Host, Cookies |
| **Cas d'usage** | Database, services TCP | Applications web, API gateways |
| **Exemples** | HAProxy (mode TCP), NLB | Nginx, HAProxy (HTTP), ALB |

### Load Balancer L4

```
Client → [L4 LB] → Serveur
         ↓
    Route par IP:Port
    Ne peut pas voir le contenu HTTP
    SSL passthrough
```

### Load Balancer L7

```
Client → [L7 LB] → Serveur
         ↓
    SSL Termination
    Inspecte les headers HTTP
    Route par URL : /api → backend-api
                    /web → backend-web
```

!!! example "Quand utiliser lequel ?"
    - **L4 :** MySQL, Redis, TCP brut, quand vous avez besoin de SSL passthrough
    - **L7 :** Applications web, APIs REST, quand vous avez besoin de routage basé sur URL

---

## La Pyramide de Débogage

Déboguer les problèmes réseau couche par couche, de bas en haut.

=== "Layer 3 - ICMP (L'hôte est-il vivant ?)"

    ```bash
    # Test de connectivité basique
    ping -c 4 google.com

    # Avec timeout
    ping -c 1 -W 2 192.168.1.1

    # Tracer la route
    traceroute google.com
    mtr google.com  # Meilleure version interactive
    ```

    **Si ping échoue :**

    - L'hôte est éteint
    - Firewall bloquant ICMP
    - Problème de routage

=== "Layer 4 - TCP (Le port est-il ouvert ?)"

    ```bash
    # Tester un port TCP avec nc (netcat)
    nc -zv google.com 443
    nc -zv 192.168.1.1 22

    # Utiliser telnet
    telnet google.com 80

    # Tester plusieurs ports
    nc -zv google.com 80 443 8080

    # Avec timeout
    nc -zv -w 3 google.com 443
    ```

    **Si le port est fermé :**

    - Service non démarré
    - Firewall bloquant le port
    - Service lié à la mauvaise interface

=== "Layer 7 - HTTP (L'application répond-elle ?)"

    ```bash
    # Vérifier les headers de réponse HTTP
    curl -I https://google.com

    # Réponse complète avec timing
    curl -w "@curl-format.txt" -o /dev/null -s https://google.com

    # Vérifier un endpoint spécifique
    curl -I https://api.example.com/health

    # Avec infos SSL verbose
    curl -vI https://example.com
    ```

    **Codes de réponse :**

    - `2xx` - Succès
    - `3xx` - Redirection
    - `4xx` - Erreur client (vérifier votre requête)
    - `5xx` - Erreur serveur (vérifier les logs backend)

### Flux de Débogage Rapide

```
ping échoue ?     → Vérifier routage, firewall, état de l'hôte
  ↓ fonctionne
nc port échoue ?  → Vérifier service, règles firewall, binding
  ↓ fonctionne
curl échoue ?     → Vérifier logs app, config, certificats SSL
  ↓ fonctionne
Le problème est ailleurs (DNS, côté client, etc.)
```
