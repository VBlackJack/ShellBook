---
tags:
  - tutos
  - network
  - openvpn
  - vpn
  - security
  - rocky
---

# OpenVPN sur Rocky Linux 9

Installation de **OpenVPN** - serveur VPN SSL/TLS.

| Composant | Version |
|-----------|---------|
| Rocky Linux | 9.x |
| OpenVPN | 2.5+ |
| Easy-RSA | 3.x |

**Durée estimée :** 30 minutes

---

## Fonctionnalités

| Caractéristique | Description |
|-----------------|-------------|
| **SSL/TLS** | Chiffrement fort |
| **Flexible** | Routé ou bridgé |
| **Cross-platform** | Clients multi-OS |
| **PKI** | Certificats X.509 |

---

## 1. Installation

```bash
dnf install -y epel-release
dnf install -y openvpn easy-rsa
```

---

## 2. Configuration PKI

### Initialiser Easy-RSA

```bash
mkdir -p /etc/openvpn/easy-rsa
cp -r /usr/share/easy-rsa/3/* /etc/openvpn/easy-rsa/
cd /etc/openvpn/easy-rsa
```

### Configuration PKI

```bash
cat > vars << 'EOF'
set_var EASYRSA_REQ_COUNTRY    "FR"
set_var EASYRSA_REQ_PROVINCE   "IDF"
set_var EASYRSA_REQ_CITY       "Paris"
set_var EASYRSA_REQ_ORG        "MyOrg"
set_var EASYRSA_REQ_EMAIL      "admin@example.com"
set_var EASYRSA_REQ_OU         "IT"
set_var EASYRSA_KEY_SIZE       2048
set_var EASYRSA_ALGO           rsa
set_var EASYRSA_CA_EXPIRE      3650
set_var EASYRSA_CERT_EXPIRE    365
EOF
```

### Créer l'autorité de certification

```bash
./easyrsa init-pki
./easyrsa build-ca nopass
```

---

## 3. Certificats serveur

```bash
# Certificat serveur
./easyrsa gen-req server nopass
./easyrsa sign-req server server

# Paramètres Diffie-Hellman
./easyrsa gen-dh

# TLS-Auth key
openvpn --genkey secret /etc/openvpn/ta.key
```

### Copier les fichiers

```bash
cp pki/ca.crt /etc/openvpn/
cp pki/issued/server.crt /etc/openvpn/
cp pki/private/server.key /etc/openvpn/
cp pki/dh.pem /etc/openvpn/
```

---

## 4. Configuration serveur

```bash
cat > /etc/openvpn/server.conf << 'EOF'
# Port et protocole
port 1194
proto udp
dev tun

# Certificats
ca ca.crt
cert server.crt
key server.key
dh dh.pem
tls-auth ta.key 0

# Réseau
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt

# Routes (LAN interne)
push "route 192.168.1.0 255.255.255.0"

# DNS
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"

# Redirect tout le trafic (optionnel)
# push "redirect-gateway def1 bypass-dhcp"

# Keep alive
keepalive 10 120

# Chiffrement
cipher AES-256-GCM
auth SHA256

# Compression (désactivée pour sécurité)
# compress lz4-v2
# push "compress lz4-v2"

# Utilisateur
user nobody
group nobody
persist-key
persist-tun

# Logs
status /var/log/openvpn-status.log
log-append /var/log/openvpn.log
verb 3

# Max clients
max-clients 100
EOF
```

---

## 5. IP Forwarding et NAT

```bash
# Activer le forwarding
echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
sysctl -p

# NAT (si redirect-gateway activé)
firewall-cmd --permanent --add-masquerade
```

---

## 6. Firewall

```bash
firewall-cmd --permanent --add-port=1194/udp
firewall-cmd --permanent --add-interface=tun0 --zone=trusted
firewall-cmd --reload
```

---

## 7. Démarrer le serveur

```bash
systemctl enable --now openvpn-server@server
```

---

## 8. Créer un certificat client

```bash
cd /etc/openvpn/easy-rsa

# Générer le certificat
./easyrsa gen-req client1 nopass
./easyrsa sign-req client client1

# Créer le répertoire client
mkdir -p /etc/openvpn/clients/client1
cp pki/ca.crt /etc/openvpn/clients/client1/
cp pki/issued/client1.crt /etc/openvpn/clients/client1/
cp pki/private/client1.key /etc/openvpn/clients/client1/
cp /etc/openvpn/ta.key /etc/openvpn/clients/client1/
```

---

## 9. Configuration client

```bash
cat > /etc/openvpn/clients/client1/client1.ovpn << 'EOF'
client
dev tun
proto udp
remote vpn.example.com 1194
resolv-retry infinite
nobind

user nobody
group nobody

persist-key
persist-tun

ca ca.crt
cert client1.crt
key client1.key
tls-auth ta.key 1

cipher AES-256-GCM
auth SHA256

verb 3
EOF
```

### Fichier unifié (inline)

```bash
cat > /etc/openvpn/clients/client1/client1-unified.ovpn << 'EOF'
client
dev tun
proto udp
remote vpn.example.com 1194
resolv-retry infinite
nobind
persist-key
persist-tun
cipher AES-256-GCM
auth SHA256
verb 3
key-direction 1

<ca>
EOF

cat /etc/openvpn/clients/client1/ca.crt >> /etc/openvpn/clients/client1/client1-unified.ovpn
echo "</ca>" >> /etc/openvpn/clients/client1/client1-unified.ovpn

echo "<cert>" >> /etc/openvpn/clients/client1/client1-unified.ovpn
cat /etc/openvpn/clients/client1/client1.crt >> /etc/openvpn/clients/client1/client1-unified.ovpn
echo "</cert>" >> /etc/openvpn/clients/client1/client1-unified.ovpn

echo "<key>" >> /etc/openvpn/clients/client1/client1-unified.ovpn
cat /etc/openvpn/clients/client1/client1.key >> /etc/openvpn/clients/client1/client1-unified.ovpn
echo "</key>" >> /etc/openvpn/clients/client1/client1-unified.ovpn

echo "<tls-auth>" >> /etc/openvpn/clients/client1/client1-unified.ovpn
cat /etc/openvpn/clients/client1/ta.key >> /etc/openvpn/clients/client1/client1-unified.ovpn
echo "</tls-auth>" >> /etc/openvpn/clients/client1/client1-unified.ovpn
```

---

## 10. Script de création client

```bash
cat > /etc/openvpn/create-client.sh << 'EOF'
#!/bin/bash
CLIENT=$1

if [ -z "$CLIENT" ]; then
    echo "Usage: $0 <client_name>"
    exit 1
fi

cd /etc/openvpn/easy-rsa
./easyrsa gen-req $CLIENT nopass
./easyrsa sign-req client $CLIENT

mkdir -p /etc/openvpn/clients/$CLIENT

# Créer fichier unifié
cat > /etc/openvpn/clients/$CLIENT/$CLIENT.ovpn << OVPN
client
dev tun
proto udp
remote vpn.example.com 1194
resolv-retry infinite
nobind
persist-key
persist-tun
cipher AES-256-GCM
auth SHA256
verb 3
key-direction 1

<ca>
$(cat /etc/openvpn/ca.crt)
</ca>

<cert>
$(cat pki/issued/$CLIENT.crt)
</cert>

<key>
$(cat pki/private/$CLIENT.key)
</key>

<tls-auth>
$(cat /etc/openvpn/ta.key)
</tls-auth>
OVPN

echo "Client config: /etc/openvpn/clients/$CLIENT/$CLIENT.ovpn"
EOF

chmod +x /etc/openvpn/create-client.sh
```

---

## 11. Révoquer un certificat

```bash
cd /etc/openvpn/easy-rsa
./easyrsa revoke client1
./easyrsa gen-crl

cp pki/crl.pem /etc/openvpn/
```

Ajouter dans server.conf :
```
crl-verify crl.pem
```

```bash
systemctl restart openvpn-server@server
```

---

## 12. Authentification utilisateur/mot de passe

### Script d'authentification

```bash
cat > /etc/openvpn/auth.sh << 'EOF'
#!/bin/bash
PASSFILE="/etc/openvpn/users.txt"
USER=$(head -1 $1)
PASS=$(tail -1 $1)

if grep -q "^$USER:$PASS$" $PASSFILE; then
    exit 0
else
    exit 1
fi
EOF

chmod +x /etc/openvpn/auth.sh
```

### Fichier utilisateurs

```bash
echo "user1:password1" > /etc/openvpn/users.txt
echo "user2:password2" >> /etc/openvpn/users.txt
chmod 600 /etc/openvpn/users.txt
```

### Modifier server.conf

```
auth-user-pass-verify /etc/openvpn/auth.sh via-file
script-security 2
verify-client-cert none
username-as-common-name
```

---

## 13. Monitoring

### Status

```bash
cat /var/log/openvpn-status.log
```

### Script monitoring

```bash
#!/bin/bash
CLIENTS=$(grep "^CLIENT_LIST" /var/log/openvpn-status.log | wc -l)
echo "Connected clients: $CLIENTS"
```

---

## Commandes utiles

```bash
# Status
systemctl status openvpn-server@server

# Logs
journalctl -u openvpn-server@server -f
tail -f /var/log/openvpn.log

# Redémarrer
systemctl restart openvpn-server@server

# Clients connectés
cat /var/log/openvpn-status.log
```

---

## Dépannage

```bash
# Test de connexion
openvpn --config client.ovpn --verb 5

# Vérifier le tunnel
ip addr show tun0

# Vérifier le routage
ip route

# Firewall
firewall-cmd --list-all
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
