---
tags:
  - windows
  - netsh
  - network
  - debug
  - firewall
---

# Netsh: Network Troubleshooting & Legacy Config

L'outil réseau en ligne de commande ultime de Windows. Indispensable pour le troubleshooting et Server Core.

---

## Pourquoi Netsh en 2025 ?

### Le Contexte : PowerShell vs Netsh

**Évolution des outils Windows :**

```
2000-2008 : Netsh (seul outil CLI réseau)
2012-2016 : Transition (Netsh + PowerShell coexistent)
2019+     : PowerShell recommandé (mais Netsh reste utile)
2025      : Netsh toujours présent (compatibilité & troubleshooting)
```

!!! info "Quand Utiliser Netsh ?"
    - **Server Core** : Interface minimale, netsh plus rapide que PowerShell
    - **Scripts legacy** : Compatibilité avec anciens scripts batch
    - **Troubleshooting réseau** : Commandes de reset/diagnostic uniques
    - **Firewall rapide** : Plus court que `New-NetFirewallRule`
    - **Capture de paquets** : Intégré, pas besoin de Wireshark

---

## Section 1 : Configuration IP & DNS

### Configuration IP Manuelle

**Scénario : Configurer une IP fixe sur un serveur.**

```cmd
# Lister les interfaces réseau
netsh interface show interface

# Définir une IP statique
netsh interface ip set address name="Ethernet" ^
  static 192.168.1.100 255.255.255.0 192.168.1.1

# Vérifier la configuration
netsh interface ip show config
```

**Équivalent PowerShell (pour comparaison) :**

```powershell
New-NetIPAddress -InterfaceAlias "Ethernet" `
  -IPAddress 192.168.1.100 `
  -PrefixLength 24 `
  -DefaultGateway 192.168.1.1
```

### Configuration DNS

```cmd
# Définir le DNS primaire
netsh interface ip set dns name="Ethernet" static 8.8.8.8

# Ajouter un DNS secondaire
netsh interface ip add dns name="Ethernet" 8.8.4.4 index=2

# Afficher la configuration DNS
netsh interface ip show dnsservers
```

**Revenir en DHCP :**

```cmd
# Activer DHCP pour l'IP
netsh interface ip set address name="Ethernet" dhcp

# Activer DHCP pour le DNS
netsh interface ip set dns name="Ethernet" dhcp
```

### Export/Import de Configuration

**Sauvegarder la configuration réseau complète :**

```cmd
# Exporter toute la config réseau
netsh -c interface dump > C:\backup\network-config.txt

# Restaurer la configuration
netsh -f C:\backup\network-config.txt
```

!!! tip "Astuce : Migration de Config"
    Utilisez `dump` pour cloner la configuration réseau d'un serveur à un autre :

    ```cmd
    # Sur le serveur source
    netsh -c interface dump > \\share\server01-network.txt

    # Sur le serveur cible
    netsh -f \\share\server01-network.txt
    ```

---

## Section 2 : Reset & Réparation (Le "Sauveur")

### Le Problème : Plus Rien ne Marche

**Scénario classique :**

```
User : "Je n'ai plus Internet depuis ce matin"
Admin: *ping 8.8.8.8* → Timeout
Admin: *ipconfig /all* → Adresse APIPA (169.254.x.x)
Admin: *Reboot* → Toujours rien
Admin: "Il est temps pour les commandes magiques..."
```

### Commande 1 : Reset IP Stack

**`netsh int ip reset` : Réinitialise la pile TCP/IP**

```cmd
# Réinitialiser la pile TCP/IP
netsh int ip reset

# Avec fichier de log
netsh int ip reset C:\logs\resetlog.txt
```

**Ce qui se passe :**
- Supprime toutes les routes statiques ajoutées manuellement
- Réinitialise les paramètres TCP/IP aux valeurs par défaut
- Recréé les clés de registre `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip`

!!! warning "Attention : Reboot Requis"
    Après `int ip reset`, un **redémarrage est obligatoire** pour appliquer les changements.

### Commande 2 : Reset Winsock Catalog

**`netsh winsock reset` : Réinitialise le catalogue Winsock**

```cmd
# Réinitialiser Winsock
netsh winsock reset

# Avec fichier de log
netsh winsock reset catalog
```

**Cas d'usage :**
- Malwares ayant modifié la pile réseau (LSP - Layered Service Providers)
- Logiciels antivirus/VPN mal désinstallés laissant des filtres
- Erreurs "Accès réseau bloqué" sans raison apparente

**Ce qui est réinitialisé :**
- Catalogue des fournisseurs Winsock (LSP)
- Namespace providers
- Protocoles réseau

### Commande 3 : Flush DNS Cache

```cmd
# Vider le cache DNS
ipconfig /flushdns

# Afficher le cache DNS (avant le flush)
ipconfig /displaydns
```

### Commande 4 : Renew DHCP Lease

```cmd
# Libérer l'adresse DHCP actuelle
ipconfig /release

# Demander une nouvelle adresse DHCP
ipconfig /renew

# Ou en une commande
ipconfig /release && ipconfig /renew
```

### Le "Nuclear Reset" (Tout Réinitialiser)

**Script complet de réinitialisation réseau :**

```cmd
@echo off
echo === RESET RESEAU COMPLET ===
echo.

echo [1/5] Flush DNS Cache...
ipconfig /flushdns

echo [2/5] Release/Renew DHCP...
ipconfig /release
ipconfig /renew

echo [3/5] Reset Winsock Catalog...
netsh winsock reset

echo [4/5] Reset TCP/IP Stack...
netsh int ip reset

echo [5/5] Reset Firewall (optional)...
netsh advfirewall reset

echo.
echo === TERMINE ===
echo REDEMARRAGE REQUIS pour appliquer les changements.
pause
shutdown /r /t 60 /c "Redemarrage pour appliquer le reset reseau"
```

!!! danger "Utilisation en Production"
    Ce script réinitialise TOUTE la configuration réseau. À utiliser uniquement :

    - Sur des postes clients (pas sur des serveurs critiques)
    - Après avoir tenté toutes les autres solutions
    - Avec une sauvegarde de la config (`netsh dump`)

---

## Section 3 : Firewall en CLI

### Pourquoi Utiliser `netsh advfirewall` ?

**Cas d'usage :**
- **Server Core** : Pas d'interface graphique
- **Scripts** : Automatisation du déploiement
- **GPO** : Configuration centralisée (via script de démarrage)
- **Rapidité** : Plus rapide que de cliquer dans `wf.msc`

### Afficher l'État du Firewall

```cmd
# État général du firewall
netsh advfirewall show allprofiles

# Afficher toutes les règles
netsh advfirewall firewall show rule name=all

# Afficher les règles actives uniquement
netsh advfirewall firewall show rule name=all | findstr "Activé"
```

### Ouvrir un Port (Exemple : RDP 3389)

```cmd
# Autoriser RDP (TCP 3389) entrant
netsh advfirewall firewall add rule ^
  name="Allow RDP" ^
  dir=in ^
  action=allow ^
  protocol=TCP ^
  localport=3389 ^
  enable=yes

# Vérifier que la règle existe
netsh advfirewall firewall show rule name="Allow RDP"
```

### Bloquer un Port ou une IP

```cmd
# Bloquer le port 445 (SMB) en entrée
netsh advfirewall firewall add rule ^
  name="Block SMB" ^
  dir=in ^
  action=block ^
  protocol=TCP ^
  localport=445

# Bloquer une IP spécifique
netsh advfirewall firewall add rule ^
  name="Block Attacker IP" ^
  dir=in ^
  action=block ^
  remoteip=203.0.113.42
```

### Règles Avancées (Application Spécifique)

```cmd
# Autoriser uniquement un programme spécifique
netsh advfirewall firewall add rule ^
  name="Allow MyApp" ^
  dir=in ^
  action=allow ^
  program="C:\Apps\MyApp.exe" ^
  enable=yes

# Autoriser un port uniquement pour un sous-réseau
netsh advfirewall firewall add rule ^
  name="Allow SQL from LAN" ^
  dir=in ^
  action=allow ^
  protocol=TCP ^
  localport=1433 ^
  remoteip=192.168.1.0/24
```

### Supprimer une Règle

```cmd
# Supprimer par nom
netsh advfirewall firewall delete rule name="Allow RDP"

# Supprimer toutes les règles d'un port
netsh advfirewall firewall delete rule name=all protocol=tcp localport=3389
```

### Reset Complet du Firewall

```cmd
# Réinitialiser le firewall aux paramètres par défaut
netsh advfirewall reset

# Désactiver complètement le firewall (NON RECOMMANDÉ)
netsh advfirewall set allprofiles state off

# Réactiver le firewall
netsh advfirewall set allprofiles state on
```

!!! warning "Sécurité : Désactiver le Firewall"
    Ne **JAMAIS** désactiver le firewall sur un serveur de production.
    Si nécessaire pour du troubleshooting, désactivez temporairement (5 min max) :

    ```cmd
    netsh advfirewall set allprofiles state off
    # Tester...
    netsh advfirewall set allprofiles state on
    ```

---

## Section 4 : Diagnostic Avancé (Trace)

### Capture de Paquets Sans Wireshark

**Problème :** Wireshark n'est pas installé sur Server Core ou interdit par la politique de sécurité.

**Solution :** `netsh trace` intégré nativement à Windows.

### Démarrer une Capture

```cmd
# Capture basique (tous les paquets)
netsh trace start capture=yes tracefile=C:\capture.etl

# Capture avec filtre (IP spécifique)
netsh trace start capture=yes ^
  Ethernet.Address=192.168.1.100 ^
  tracefile=C:\capture-filtered.etl

# Capture avec scénario pré-configuré
netsh trace start scenario=netconnection ^
  capture=yes ^
  tracefile=C:\netconnection.etl
```

**Scénarios disponibles :**
- `NetConnection` : Problèmes de connectivité générale
- `InternetClient` : Navigation web, DNS
- `FileSharing` : SMB, partages de fichiers
- `DirectAccess` : VPN DirectAccess
- `NDIS` : Drivers réseau (niveau bas)

### Arrêter la Capture

```cmd
# Arrêter la trace en cours
netsh trace stop

# Output
Merging traces ... done
Generating data collection ... done
The trace file and additional troubleshooting information have been compiled as "C:\capture.cab".
```

### Analyser le Fichier ETL

**Problème :** Le fichier `.etl` n'est pas lisible directement.

**Solution 1 : Convertir en PCAP (pour Wireshark)**

```powershell
# Utiliser etl2pcapng (Microsoft Message Analyzer)
# Télécharger: https://github.com/microsoft/etl2pcapng

etl2pcapng.exe C:\capture.etl C:\capture.pcapng

# Ouvrir avec Wireshark
wireshark C:\capture.pcapng
```

**Solution 2 : Event Viewer**

```cmd
# Le fichier .cab contient des fichiers ETL + HTML
expand C:\capture.cab -F:* C:\capture\

# Ouvrir le rapport HTML
start C:\capture\report.html
```

**Solution 3 : netsh trace convert**

```cmd
# Convertir en format texte
netsh trace convert input=C:\capture.etl output=C:\capture.txt
```

### Exemple : Troubleshooting Connexion SQL

```cmd
# Démarrer la capture
netsh trace start capture=yes ^
  Ethernet.Address=192.168.1.50 ^
  tracefile=C:\sql-trace.etl

# Reproduire le problème (tenter de se connecter au SQL Server)
sqlcmd -S 192.168.1.50 -U sa -P password

# Arrêter la capture
netsh trace stop

# Convertir et analyser
etl2pcapng.exe C:\sql-trace.etl C:\sql-trace.pcapng
```

!!! tip "Astuce : Filtres Avancés"
    Filtrer par port (ex: SQL Server 1433) :

    ```cmd
    netsh trace start capture=yes ^
      TCP.AnyPort=1433 ^
      tracefile=C:\sql-port.etl
    ```

---

## Section 5 : Diagnostic WiFi

### Le Problème : WiFi Instable

**Scénario :**
```
User : "Le WiFi se déconnecte toutes les 10 minutes"
Admin: "Quel canal utilise le routeur ?"
User : "Je ne sais pas..."
Admin: "Laisse-moi générer un rapport WiFi détaillé."
```

### Générer le Rapport WiFi

```cmd
# Générer le rapport (administrateur requis)
netsh wlan show wlanreport

# Output
Wireless LAN report created.
Report location: C:\ProgramData\Microsoft\Windows\WlanReport\wlan-report-latest.html
```

### Contenu du Rapport

**Le rapport HTML contient :**

| Section | Informations |
|---------|--------------|
| **Session Summary** | Nombre de connexions/déconnexions, durée totale |
| **Disconnect Reasons** | Raisons des déconnexions (timeout, signal faible, etc.) |
| **Network List** | Tous les réseaux WiFi détectés avec RSSI (force du signal) |
| **Radio Information** | Canaux utilisés, interférences, bande (2.4GHz/5GHz) |
| **Connection History** | Timeline graphique des connexions/déconnexions |

**Exemple de diagnostic :**

```
Disconnect Reason: Deauthentication (802.11 frame from AP)
Count: 47 in the last 3 days

→ Problème : Le point d'accès déconnecte activement les clients
→ Solution : Firmware AP obsolète ou interférences
```

### Lister les Réseaux WiFi Disponibles

```cmd
# Lister tous les SSID visibles
netsh wlan show networks

# Avec détails (canaux, type de sécurité)
netsh wlan show networks mode=bssid
```

**Output exemple :**

```
SSID 1 : CompanyWiFi
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption              : CCMP
    BSSID 1                 : 00:11:22:33:44:55
         Signal             : 90%
         Radio type         : 802.11ac
         Channel            : 36
```

### Afficher la Configuration WiFi Actuelle

```cmd
# Afficher les profils WiFi enregistrés
netsh wlan show profiles

# Afficher la clé WiFi en clair (admin requis)
netsh wlan show profile name="CompanyWiFi" key=clear
```

**Output (section Security settings) :**

```
Security settings
-----------------
    Authentication         : WPA2-Personal
    Cipher                 : CCMP
    Security key           : Present
    Key Content            : MyWiFiPassword123  ← Mot de passe en clair
```

### Export/Import de Profil WiFi

**Scénario : Déployer la config WiFi sur 50 postes.**

```cmd
# Exporter le profil WiFi
netsh wlan export profile name="CompanyWiFi" ^
  folder=C:\WiFi\ ^
  key=clear

# Distribuer le fichier XML via GPO/Script
copy \\server\share\CompanyWiFi.xml C:\Temp\

# Importer sur chaque poste
netsh wlan add profile filename="C:\Temp\CompanyWiFi.xml"

# Connexion automatique
netsh wlan connect name="CompanyWiFi"
```

!!! tip "Astuce : Déploiement WiFi en Entreprise"
    Créez un script batch pour automatiser :

    ```cmd
    @echo off
    # Télécharger le profil WiFi
    copy \\dc01\netlogon\wifi\CompanyWiFi.xml %TEMP%

    # Importer
    netsh wlan add profile filename="%TEMP%\CompanyWiFi.xml" user=all

    # Nettoyer
    del %TEMP%\CompanyWiFi.xml

    # Connexion
    netsh wlan connect name="CompanyWiFi"
    ```

    Déployer via GPO (Startup Script) pour tous les ordinateurs du domaine.

### Diagnostic : Signal WiFi en Temps Réel

```cmd
# Afficher la force du signal actuel
netsh wlan show interfaces

# Output
SSID                   : CompanyWiFi
State                  : connected
Signal                 : 84%  ← Force du signal
Receive rate (Mbps)    : 866
Transmit rate (Mbps)   : 866
Channel                : 36
```

**Analyser les problèmes de signal :**

| Force Signal | État | Action |
|--------------|------|--------|
| 90-100% | Excellent | RAS |
| 70-89% | Bon | Acceptable |
| 50-69% | Faible | Se rapprocher de l'AP |
| < 50% | Très faible | Changer d'AP ou vérifier interférences |

---

## Référence Rapide

### Commandes Essentielles

```cmd
# Configuration IP
netsh interface ip set address name="Ethernet" static 192.168.1.100 255.255.255.0 192.168.1.1
netsh interface ip set dns name="Ethernet" static 8.8.8.8

# Reset Réseau
netsh int ip reset
netsh winsock reset
ipconfig /flushdns

# Firewall
netsh advfirewall firewall add rule name="Allow Port" dir=in action=allow protocol=TCP localport=80
netsh advfirewall firewall show rule name=all
netsh advfirewall reset

# Capture de Paquets
netsh trace start capture=yes tracefile=C:\capture.etl
netsh trace stop

# WiFi
netsh wlan show networks mode=bssid
netsh wlan show wlanreport
netsh wlan show profile name="SSID" key=clear
netsh wlan export profile name="SSID" folder=C:\WiFi key=clear
```

### Troubleshooting Par Symptôme

| Symptôme | Commande de Diagnostic |
|----------|------------------------|
| Pas d'accès Internet | `netsh int ip reset && netsh winsock reset` |
| DNS ne résout pas | `ipconfig /flushdns && ipconfig /registerdns` |
| DHCP ne donne pas d'IP | `ipconfig /release && ipconfig /renew` |
| WiFi se déconnecte | `netsh wlan show wlanreport` |
| Port bloqué | `netsh advfirewall firewall show rule name=all` |
| Problème de connexion mystérieux | `netsh trace start scenario=netconnection` |

### PowerShell Équivalents (Moderne)

| netsh | PowerShell |
|-------|------------|
| `netsh interface ip set address` | `New-NetIPAddress` |
| `netsh interface ip set dns` | `Set-DnsClientServerAddress` |
| `netsh advfirewall firewall add rule` | `New-NetFirewallRule` |
| `netsh wlan show profiles` | `Get-NetConnectionProfile` |

---

## Ressources

**Documentation Officielle :**
- [Netsh Command Reference](https://learn.microsoft.com/en-us/windows-server/networking/technologies/netsh/netsh)
- [Netsh AdvFirewall](https://learn.microsoft.com/en-us/windows-server/networking/technologies/netsh/netsh-advfirewall)

**Outils Complémentaires :**
- `etl2pcapng` : [GitHub - microsoft/etl2pcapng](https://github.com/microsoft/etl2pcapng)
- Wireshark : Analyse de fichiers `.pcapng`

**Formations :**
- IT-Connect : Netsh & Troubleshooting Réseau Windows

---

**Next Steps :**
- Maîtriser PowerShell pour remplacer netsh (cmdlets `Net*`)
- Automatiser les diagnostics avec des scripts batch/PowerShell
- Implémenter Windows Admin Center pour la gestion GUI moderne
