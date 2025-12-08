---
tags:
  - ssh
  - network
  - tunnel
  - proxy
---

# SSH Tunnels & Port Forwarding

SSH n'est pas qu'un outil pour ouvrir un shell à distance. C'est un "couteau suisse" réseau capable de chiffrer et transporter n'importe quel flux TCP. C'est souvent la seule façon d'accéder à un service interne sans VPN.

## 1. Local Forwarding (`-L`)

**Cas d'usage** : Accéder à un service distant (bloqué par un firewall) depuis ma machine locale.
*   *Exemple* : Je veux accéder à la base de données MySQL (port 3306) du serveur de prod, qui n'écoute que sur `localhost`.

```mermaid
graph LR
    A[Mon PC] -->|SSH :22| B[Serveur Rebond]
    B -->|Local :3306| C[MySQL Serveur]
    
    linkStyle 0 stroke:green,stroke-width:4px;
    linkStyle 1 stroke:red,stroke-width:2px;
```

**Commande :**
```bash
# ssh -L [Port_Local]:[Cible]:[Port_Cible] [Utilisateur]@[Serveur_Rebond]
ssh -L 8080:127.0.0.1:3306 user@serveur-prod
```

*   Maintenant, si je connecte mon client MySQL sur `localhost:8080`, je suis en réalité connecté au `3306` du serveur de prod.

## 2. Remote Forwarding (`-R`)

**Cas d'usage** : Donner accès à un service local (mon PC) à quelqu'un de l'extérieur (Inverse du Local).
*   *Exemple* : Je développe une API sur mon PC (`localhost:3000`) et je veux la montrer à un collègue via un serveur public, sans ouvrir ma box internet.

**Commande (lancée depuis mon PC) :**
```bash
# ssh -R [Port_Distant]:[Local]:[Port_Local] [Utilisateur]@[Serveur_Public]
ssh -R 8080:127.0.0.1:3000 user@serveur-public
```

*   Maintenant, quiconque tape `http://serveur-public:8080` accède à mon API locale.

## 3. Dynamic Forwarding (`-D`) - Le Proxy SOCKS

**Cas d'usage** : Naviguer sur le web "comme si" j'étais sur le serveur distant. C'est un VPN du pauvre.
*   *Exemple* : Contourner un filtrage géographique ou accéder à tout un réseau interne sans mapper 50 ports.

**Commande :**
```bash
# ssh -D [Port_Socks_Local] [Utilisateur]@[Serveur]
ssh -D 9090 user@serveur-interne
```

*   Configuration du navigateur (Firefox/Chrome) : Proxy SOCKSv5 sur `localhost:9090`.
*   Tout votre trafic web passe par le tunnel SSH.

## 4. Options Utiles

Pour créer un tunnel stable, on ajoute souvent ces options :

*   `-N` : Ne pas exécuter de commande distante (pas de shell).
*   `-f` : Passer en arrière-plan (background).
*   `-C` : Compresser les données (utile pour les connexions lentes).

**La commande "Tunnel Perpétuel" :**
```bash
ssh -N -f -L 8080:127.0.0.1:80 user@serveur
```

### Persistence avec AutoSSH
Pour un tunnel qui doit rester ouvert 24/7 (et redémarrer s'il coupe) :
```bash
autossh -M 0 -f -N -L 8080:127.0.0.1:80 user@serveur
```
